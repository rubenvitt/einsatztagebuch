//! Offline-Kontinuität nach einer Escrow-Wiederherstellung (v1.1-Profil
//! §10.2, Scheibe f): Gate `recipient-grant` ordnet den eigenen Grant
//! ausschließlich über den KEM-Abdruck zu (`src/recipient.rs`, `own_grant`).
//!
//! Ein Grant, der VOR dem Verlust an den Reader-KEM gekapselt wurde, bleibt
//! deshalb dem wiederhergestellten Reader offline zuordenbar und öffnet —
//! ohne Zertifikat, ohne Serverdaten, allein mit dem Schlüssel, der aus dem
//! Escrow zurückkommt. Ein reiner Beobachtungszeuge: keine Produktänderung.
//!
//! Der Weg durch das Escrow ist derselbe wie beim Recovery-Schlüssel: der
//! Reader-KEM wird unter dem HPKE-Kontext des Escrow-Cores versiegelt
//! (`ea_testkit::reader_key_escrow_fixture::seal_reader_kem_key_for_escrow`)
//! und mit dem Kontext des GEFÜLLTEN Cores wieder geöffnet.
#[path = "support/mod.rs"]
mod support;

use ea_crypto::{HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, hpke_aad, hpke_info, hpke_open};
use ea_format::{ReaderKeyEscrowCoreV1, ReaderKeyEscrowHpkeContextV1};
use ea_testkit::reader_key_escrow_fixture::seal_reader_kem_key_for_escrow;
use ea_types::{CertificateHash, ChainSequence, Hash32, RegistryVersion, SubjectId, UnixMillis};
use ea_verify::{
    DECAPSULATION_EVENT_V1, GATE_ORDER_V1, RecordingObserver, VerificationReportV1, VerifyOptions,
    verify_archive_observed,
};

use support::{
    FIXTURE_OS_WALL_CLOCK_V1, complete_recipient_certificate_hash,
    complete_recipient_key_thumbprint, complete_recipient_secret_bytes, complete_valid_archive,
    key_thumbprint_of,
};

/// Der Recovery-Empfänger des Escrows — ein eigener Schlüssel, nicht der
/// des Readers.
const RECOVERY_KEM_SECRET: [u8; 32] = [0x7a; 32];
/// Ein NEU enrollter KEM ohne Escrow: er hat nie einen Grant bekommen.
const FRESH_KEM_SECRET: [u8; 32] = [0x3b; 32];

fn private_key(secret: [u8; 32]) -> HpkeRecipientPrivateKey {
    HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(secret)).unwrap()
}

/// Versiegelt den Reader-KEM des lückenfreien Bestands in ein Escrow und
/// öffnet ihn mit dem Recovery-Schlüssel wieder.
fn restored_reader_kem() -> HpkeRecipientPrivateKey {
    let archive = complete_valid_archive();
    let recovery = private_key(RECOVERY_KEM_SECRET);
    let mut core = ReaderKeyEscrowCoreV1 {
        organization_id: archive.anchor().organization_id(),
        reader_certificate_object_hash: complete_recipient_certificate_hash(),
        reader_subject_id: SubjectId::try_from([0x5c; 16].as_slice()).unwrap(),
        enrollment_registry_version: RegistryVersion::new(1),
        enrollment_registry_head_hash: Hash32::try_from([0x11; 32].as_slice()).unwrap(),
        enrollment_sequence: ChainSequence::new(0),
        recovery_certificate_object_hash: CertificateHash::try_from([0x7b; 32].as_slice()).unwrap(),
        recovery_kem_key_thumbprint: key_thumbprint_of(&recovery),
        encapsulated_key: [0; 32],
        encrypted_reader_kem_key: [0; 48],
        issued_at: UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1),
        root_key_thumbprint: key_thumbprint_of(&recovery),
    };
    let (encapsulated_key, encrypted) = seal_reader_kem_key_for_escrow(
        &SecretBytes::new(complete_recipient_secret_bytes()),
        *recovery.public_key().as_bytes(),
        &core,
    )
    .unwrap();
    core.encapsulated_key = encapsulated_key;
    core.encrypted_reader_kem_key = encrypted;

    let context = ReaderKeyEscrowHpkeContextV1::from_escrow_core(&core).encode();
    let sealed =
        HpkeSealed::from_parts(core.encapsulated_key, core.encrypted_reader_kem_key).unwrap();
    let restored = hpke_open(
        &recovery,
        &sealed,
        &hpke_info(&context),
        &hpke_aad(&context),
    )
    .unwrap();
    HpkeRecipientPrivateKey::from_bytes(restored).unwrap()
}

/// Prüft den lückenfreien Bestand mit `recipient` unter dem Abdruck, der
/// allein aus diesem Schlüssel gerechnet wird.
fn verified_with(recipient: &HpkeRecipientPrivateKey) -> (VerificationReportV1, Vec<&'static str>) {
    let archive = complete_valid_archive();
    let mut observer = RecordingObserver::new();
    let report = verify_archive_observed(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1))
            .with_recipient(key_thumbprint_of(recipient), recipient),
        &mut observer,
    )
    .unwrap();
    (report, observer.events().to_vec())
}

/// Der wiederhergestellte Reader-KEM öffnet den Grant, der vor dem Verlust an
/// ihn gekapselt wurde: Zuordnung allein über den KEM-Abdruck.
#[test]
fn a_grant_to_the_escrowed_reader_kem_opens_offline_with_the_restored_kem() {
    let restored = restored_reader_kem();
    assert!(
        key_thumbprint_of(&restored) == complete_recipient_key_thumbprint(),
        "der restaurierte KEM ist der des Readers"
    );

    let (report, events) = verified_with(&restored);
    let mut expected = GATE_ORDER_V1.to_vec();
    expected.push(DECAPSULATION_EVENT_V1);
    assert_eq!(
        events, expected,
        "der eigene Grant wird zugeordnet und geöffnet"
    );
    assert_eq!(report.decryption_errors().len(), 0);
    assert_eq!(report.signature_errors().len(), 0);
    assert!(report.is_fully_verified());
}

/// Kontrolle: ein neu enrollter KEM ohne Escrow findet im Altbestand keinen
/// eigenen Grant — der Eintrag bleibt gültig, nichts wird geöffnet, und es
/// entsteht kein Entschlüsselungsbefund. Die Kontinuität kommt also aus dem
/// KEM, nicht aus einem Zertifikat oder einer Zuordnung ohne Abdruck.
#[test]
fn a_freshly_enrolled_kem_without_escrow_is_attributed_no_old_grant() {
    let fresh = private_key(FRESH_KEM_SECRET);
    assert!(key_thumbprint_of(&fresh) != complete_recipient_key_thumbprint());

    let (report, events) = verified_with(&fresh);
    assert_eq!(
        report.decryption_errors().len(),
        0,
        "kein Grant, kein Befund"
    );
    assert_eq!(report.signature_errors().len(), 0);
    assert!(
        !events.contains(&DECAPSULATION_EVENT_V1),
        "ohne eigenen Grant wird nichts geöffnet"
    );
    assert_eq!(
        report.object_results().len(),
        1,
        "der Eintrag bleibt sichtbar"
    );
}
