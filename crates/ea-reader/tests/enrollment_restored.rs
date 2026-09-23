//! Zeremonie B, letzter Schritt: ein NEUER Tresor aus dem wiederhergestellten
//! KEM, mit neuem Ed25519-Schlüssel und zwei bestätigten unabhängigen
//! Authenticators — lokal, ohne Endpunkte (Profil §6 Schritt 6).
mod escrow_line;
#[path = "../../ea-trust/tests/escrow_support/mod.rs"]
mod escrow_support;
mod fixtures;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;

use ea_reader::{
    InMemoryReaderBlobStore, READER_VAULT_BLOB_KEY_V1, ReaderBlobKey, ReaderBlobStore,
    ReaderEnrollment, RestoredReaderKemV1, SealedVaultV1,
};
use ea_types::SubjectId;
use escrow_line::{AUDIT_SEED, line_with_escrow, restored_kem};
use escrow_support::{EscrowLine, READER_KEM_SEED, subject, x25519_key};

fn reader_subject() -> SubjectId {
    subject(0xc1)
}

fn restored() -> (EscrowLine, RestoredReaderKemV1) {
    let (escrow, escrow_hash) = line_with_escrow(reader_subject());
    let restored = restored_kem(&escrow, escrow_hash, reader_subject());
    (escrow, restored)
}

fn begin(
    store: &dyn ReaderBlobStore,
    restored: RestoredReaderKemV1,
) -> Result<ReaderEnrollment, ea_reader::EnrollmentError> {
    ReaderEnrollment::begin_restored(store, fixtures::bundle_fingerprint(), restored)
}

fn confirm_and_finish(
    enrollment: ReaderEnrollment,
    store: &mut dyn ReaderBlobStore,
) -> Result<ea_reader::EnrolledReaderV1, ea_reader::EnrollmentError> {
    let shown = enrollment.fingerprints();
    let confirmation = enrollment
        .confirm_fingerprints(
            &shown.key_fingerprint_hex(),
            &shown.bundle_fingerprint_hex(),
        )
        .unwrap();
    enrollment.finish_restored(confirmation, store)
}

#[test]
fn the_restored_vault_carries_the_escrowed_kem_a_new_signing_key_and_two_authenticators() {
    let (escrow, restored) = restored();
    let mut store = InMemoryReaderBlobStore::new();
    let mut enrollment = begin(&store, restored).unwrap();
    // Das Fingerprint-Gate zeigt den KEM des alten Zertifikats.
    assert!(
        enrollment.fingerprints().key_fingerprint() == x25519_key(READER_KEM_SEED).thumbprint()
    );
    enrollment
        .register_authenticator(fixtures::attested(1))
        .unwrap();
    enrollment
        .register_authenticator(fixtures::attested(2))
        .unwrap();
    let enrolled = confirm_and_finish(enrollment, &mut store).unwrap();
    assert_eq!(enrolled.envelopes().len(), 2);

    // Lokal geschrieben, unter dem Tresorschlüssel, und BEIDE Wege öffnen.
    let key = ReaderBlobKey::new(READER_VAULT_BLOB_KEY_V1).unwrap();
    let stored = store
        .get(&key)
        .unwrap()
        .expect("der neue Tresor liegt lokal");
    let sealed = SealedVaultV1::from_deterministic_cbor(&stored).unwrap();
    for index in [1, 2] {
        let vault =
            ea_reader::ReaderVault::unlock(&sealed, &fixtures::authenticator(index)).unwrap();
        assert!(vault.kem_key_thumbprint() == x25519_key(READER_KEM_SEED).thumbprint());
        assert_eq!(
            vault.pinned_anchor_bytes(),
            escrow.line.exact_anchor_bytes()
        );
        // Ein NEUER Ed25519-Schlüssel, nicht der des alten Tresors.
        vault
            .audit_signing_key()
            .with_exposed(|seed| assert_ne!(seed, &AUDIT_SEED));
    }
}

#[test]
fn two_restorations_draw_two_signing_keys() {
    let mut seeds = Vec::new();
    for _ in 0..2 {
        let (_, restored) = restored();
        let mut store = InMemoryReaderBlobStore::new();
        let mut enrollment = begin(&store, restored).unwrap();
        enrollment
            .register_authenticator(fixtures::attested(1))
            .unwrap();
        enrollment
            .register_authenticator(fixtures::attested(2))
            .unwrap();
        let enrolled = confirm_and_finish(enrollment, &mut store).unwrap();
        let vault = enrolled.unlock_with(&fixtures::authenticator(1)).unwrap();
        seeds.push(vault.audit_signing_key().with_exposed(|seed| *seed));
    }
    assert_ne!(seeds[0], seeds[1]);
}

#[test]
fn one_authenticator_is_not_enough() {
    let (_, restored) = restored();
    let mut store = InMemoryReaderBlobStore::new();
    let mut enrollment = begin(&store, restored).unwrap();
    enrollment
        .register_authenticator(fixtures::attested(1))
        .unwrap();
    assert_eq!(
        confirm_and_finish(enrollment, &mut store)
            .err()
            .map(|error| error.code()),
        Some("EA-READER-ENROLLMENT-SINGLE-AUTHENTICATOR")
    );
    assert!(store.keys().unwrap().is_empty(), "nichts geschrieben");
}

#[test]
fn a_device_that_still_carries_a_vault_refuses_the_restoration() {
    let (_, restored) = restored();
    let mut store = InMemoryReaderBlobStore::new();
    store
        .put(
            &ReaderBlobKey::new(READER_VAULT_BLOB_KEY_V1).unwrap(),
            b"old",
        )
        .unwrap();
    assert_eq!(
        begin(&store, restored).err().map(|error| error.code()),
        Some("EA-READER-ENROLLMENT-VAULT-PRESENT")
    );
}

#[test]
fn a_vault_written_between_begin_and_finish_is_not_overwritten() {
    let (_, restored) = restored();
    let mut store = InMemoryReaderBlobStore::new();
    let mut enrollment = begin(&store, restored).unwrap();
    enrollment
        .register_authenticator(fixtures::attested(1))
        .unwrap();
    enrollment
        .register_authenticator(fixtures::attested(2))
        .unwrap();
    let key = ReaderBlobKey::new(READER_VAULT_BLOB_KEY_V1).unwrap();
    store.put(&key, b"other").unwrap();
    assert_eq!(
        confirm_and_finish(enrollment, &mut store)
            .err()
            .map(|error| error.code()),
        Some("EA-READER-ENROLLMENT-VAULT-PRESENT")
    );
    assert_eq!(store.get(&key).unwrap().unwrap(), b"other");
}

/// Der Abschluss nimmt keinen Endpunktport: ein signierter Upload wäre ohne
/// neues Zertifikat unmöglich, und der nur einmal lieferbare KEM ginge bei
/// „Server vor lokal“ verloren. Die Aussage steht in der Signatur; dieser
/// Zeuge hält sie am Quelltext fest.
#[test]
fn the_restored_finish_takes_no_endpoints() {
    let source = include_str!("../src/enrollment.rs");
    let start = source.find("pub fn finish_restored(").unwrap();
    let signature = &source[start..start + source[start..].find('{').unwrap()];
    assert!(!signature.contains("EnrollmentEndpoints"), "{signature}");
    assert!(
        !signature.contains("EnrollmentRequestContextV1"),
        "{signature}"
    );
}

/// Organisation, Subject und Anker des neuen Tresors kommen aus dem geprüften
/// Transport (`RestoredReaderKemV1`), nie als freie Parameter — ein Aufrufer
/// kann keinen anderen Anker pinnen als den, gegen den das Escrow geprüft
/// wurde (review-e F2). Die Aussage steht in der Signatur; dieser Zeuge hält
/// sie am Quelltext fest.
#[test]
fn the_restored_begin_takes_no_organization_subject_or_anchor() {
    let source = include_str!("../src/enrollment.rs");
    let start = source.find("pub fn begin_restored(").unwrap();
    let signature = &source[start..start + source[start..].find('{').unwrap()];
    for free in ["OrganizationId", "SubjectId", "TrustAnchorV1"] {
        assert!(!signature.contains(free), "{free}: {signature}");
    }
}
