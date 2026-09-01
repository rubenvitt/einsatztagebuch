#![allow(dead_code)]

//! Die geteilten Zeugenwerte des Browser-Tresors.
//!
//! # Warum ein GETEILTES Modul und nicht drei inline-Bloecke
//!
//! `key_profile.rs`, `vault_envelope.rs` und `cache_canaries.rs` pruefen drei
//! verschiedene Zusagen an DENSELBEN Tresor: das Schluesselprofil, die
//! PRF-Envelopes und die verschluesselten Speicher darueber. Der Anker, der
//! KEM-Schluessel und die Authenticators muessen in allen dreien dieselben
//! sein — sonst prueft der Kanarienzeuge einen anderen Tresor als der
//! Envelope-Zeuge, und ein Bruch in der Ableitungskette faellt durch beide
//! Netze. `crates/ea-audit/tests/redaction.rs` und
//! `crates/ea-writer/tests/support/mod.rs` fuehren dieselbe Bauform.
//!
//! # Nichts hier taeuscht einen Wert vor
//!
//! Der gepinnte Anker wird MIT `ea_crypto::bootstrap_anchor_hash` gerechnet und
//! traegt sich damit selbst — genau die Rechnung, die `decode_trust_anchor`
//! beim Entsperren wiederholt. Der KEM-Punkt entsteht aus einem echten
//! X25519-Privatschluessel ueber `HpkeRecipientPrivateKey::public_key`, der
//! Ed25519-Punkt aus `ea_testkit::ed25519_public_key`. Ein erfundener
//! 32-Byte-Block waere an `CanonicalPublicCoseKey::ed25519` ohnehin
//! gescheitert, und ein erfundener Anker haette `EA-TRUST-ANCHOR-HASH`
//! ausgeloest — also genau den Fehler, den `foreign_anchor_exact_bytes`
//! ABSICHTLICH herbeifuehrt.
//!
//! # Der fremde Anker ist ein eingefrorener Vektor, kein Bastelwerk
//!
//! `vectors/trust/v1/anchor/rejected-wrong-bootstrap-anchor-hash/anchor.bin`
//! ist im Vektormanifest mit `EA-TRUST-ANCHOR-HASH` gefuehrt. Ein
//! VOLLSTAENDIG gueltiger Anker einer fremden Organisation waere hier der
//! falsche Zeuge: `decode_trust_anchor` wiese ihn NICHT ab, und
//! `a_flipped_envelope_byte_and_a_substituted_anchor_both_refuse` waere gruen
//! ohne Aussage. Stufe 4 friert keine Vektorfamilie ein; diese Datei wird
//! ausschliesslich GELESEN.

use ea_crypto::{
    CanonicalPublicCoseKey, HpkeRecipientPrivateKey, HpkeRecipientPublicKey, SecretBytes,
    bootstrap_anchor_hash,
};
use ea_format::{CertificateKindV1, DeviceCertificateFieldsV1, KeyProtectionProfileV1};
use ea_reader::{
    AuthenticatorPrfV1, ReaderEntryStateV1, ReaderVault, SealedVaultV1, UnlockedVault,
    VaultContentsV1,
};
use ea_trust::{RegistryHeadPin, TrustAnchorV1, decode_trust_anchor};
use ea_types::{
    ChainSequence, DeviceId, EntryHash, EntryStatus, ObjectHash, OrganizationId, RegistryVersion,
    VerificationStatus,
};
use ea_verify::ServerConfirmationV1;
use minicbor::Encoder;

/// Die Domaene der Ankervorstufe, zeichengleich zu `PRE_ANCHOR_DOMAIN` in
/// `crates/ea-trust/src/anchor.rs`.
const PRE_ANCHOR_DOMAIN_V1: &str = "EINSATZARCHIV-TRUST-ANCHOR-PRE-v1";
/// Die Domaene des fertigen Ankers, zeichengleich zu `FINAL_ANCHOR_DOMAIN`.
const FINAL_ANCHOR_DOMAIN_V1: &str = "EINSATZARCHIV-TRUST-ANCHOR-v1";

const ROOT_SIGNING_SEED: [u8; 32] = [0x11; 32];
const READER_KEM_SEED: [u8; 32] = [0x51; 32];
const READER_AUDIT_SEED: [u8; 32] = [0x52; 32];
const SECOND_READER_KEM_SEED: [u8; 32] = [0x53; 32];
const SECOND_READER_AUDIT_SEED: [u8; 32] = [0x54; 32];

/// Der eingefrorene Anker mit FALSCHEM Bootstrap-Hash.
const FOREIGN_ANCHOR_BYTES: &[u8] = include_bytes!(
    "../../../../vectors/trust/v1/anchor/rejected-wrong-bootstrap-anchor-hash/anchor.bin"
);

// ---------------------------------------------------------------------------
// Authenticators
// ---------------------------------------------------------------------------

/// Die `credentialId` des `index`-ten Authenticators.
///
/// Sie ist an das Envelope gebunden und unterscheidet die Entsperrwege; ein
/// Envelope ist deshalb nicht auf einen fremden Authenticator umhaengbar.
pub fn credential_id(index: u8) -> Vec<u8> {
    let mut id = b"ea-reader-passkey-".to_vec();
    id.push(b'0' + index);
    id
}

/// Die rohe PRF-Ausgabe des `index`-ten Authenticators.
///
/// Die Werte `0xa1` und `0xb2` sind dieselben, die
/// `the_prf_output_never_wraps_the_vault_and_each_authenticator_opens_it_alone`
/// woertlich fuehrt — der Kanarienvogel dieses Zeugen sucht GENAU diese Bytes
/// im umschlossenen Tresorschluessel.
pub fn prf_output(index: u8) -> [u8; 32] {
    match index {
        1 => [0xa1; 32],
        2 => [0xb2; 32],
        other => [other; 32],
    }
}

/// Der `index`-te Authenticator als Paar aus `credentialId` und PRF-Ausgabe.
pub fn authenticator(index: u8) -> AuthenticatorPrfV1 {
    AuthenticatorPrfV1::new(credential_id(index), SecretBytes::new(prf_output(index)))
}

// ---------------------------------------------------------------------------
// Der gepinnte Anker
// ---------------------------------------------------------------------------

fn root_public_cose_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(ea_testkit::ed25519_public_key(&ROOT_SIGNING_SEED))
        .expect("ein aus einem Seed abgeleiteter Ed25519-Punkt ist ein gueltiger Punkt")
}

/// Die EXAKTEN Bytes des gepinnten Ankers.
///
/// Gebaut wie `encode_pre_anchor` in `crates/ea-trust/src/anchor.rs`, weil der
/// eingebettete Bootstrap-Hash sonst nicht aufginge: `decode_trust_anchor`
/// rechnet die Vorstufe NEU und vergleicht. Genau diese Rechnung macht den
/// Anker im Tresor gueltig, weil er sich selbst traegt, und nicht deshalb, weil
/// er im Tresor lag.
pub fn pinned_anchor_exact_bytes() -> Vec<u8> {
    let root_key = root_public_cose_key();
    let root_key_bytes = root_key.to_deterministic_cbor();
    let root_key_thumbprint = root_key.thumbprint();
    let organization_id = [0x12_u8; 16];
    let chain_id = [0x13_u8; 16];
    let root_certificate_object_hash = [0x14_u8; 32];
    // Beide Listen sind streng sortiert und gleich lang; `validate_anchor_hash_lists`
    // verlangt mindestens zwei Eintraege je Liste.
    let certificates = [[0x21_u8; 32], [0x22_u8; 32]];
    let bindings = [[0x31_u8; 32], [0x32_u8; 32]];
    let genesis_entry_hash = [0x44_u8; 32];

    let mut pre_anchor = Vec::new();
    let mut encoder = Encoder::new(&mut pre_anchor);
    encoder
        .array(10)
        .and_then(|encoder| encoder.str(PRE_ANCHOR_DOMAIN_V1))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(&organization_id))
        .and_then(|encoder| encoder.bytes(&chain_id))
        .and_then(|encoder| encoder.bytes(&root_key_bytes))
        .and_then(|encoder| encoder.bytes(root_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(&root_certificate_object_hash))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.bytes(&certificates[0]))
        .and_then(|encoder| encoder.bytes(&certificates[1]))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.bytes(&bindings[0]))
        .and_then(|encoder| encoder.bytes(&bindings[1]))
        .and_then(|encoder| encoder.array(0))
        .expect("encoding a fixed-shape Pre-Anchor into Vec cannot fail");
    let embedded_bootstrap_hash = bootstrap_anchor_hash(&pre_anchor);

    let mut exact_bytes = Vec::new();
    let mut encoder = Encoder::new(&mut exact_bytes);
    encoder
        .array(12)
        .and_then(|encoder| encoder.str(FINAL_ANCHOR_DOMAIN_V1))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(embedded_bootstrap_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(&organization_id))
        .and_then(|encoder| encoder.bytes(&chain_id))
        .and_then(|encoder| encoder.bytes(&root_key_bytes))
        .and_then(|encoder| encoder.bytes(root_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(&root_certificate_object_hash))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.bytes(&certificates[0]))
        .and_then(|encoder| encoder.bytes(&certificates[1]))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.bytes(&bindings[0]))
        .and_then(|encoder| encoder.bytes(&bindings[1]))
        .and_then(|encoder| encoder.bytes(&genesis_entry_hash))
        .and_then(|encoder| encoder.array(0))
        .expect("encoding a fixed-shape Trust-Anchor into Vec cannot fail");
    exact_bytes
}

/// Der gepinnte Anker, bei JEDEM Aufruf frisch dekodiert.
///
/// `TrustAnchorV1` traegt weder `Clone` noch `Debug`; ein zwischengehaltener
/// Wert liesse sich also gar nicht herausgeben.
pub fn pinned_anchor() -> TrustAnchorV1 {
    decode_trust_anchor(&pinned_anchor_exact_bytes())
        .expect("der Fixture-Anker traegt seinen eigenen Bootstrap-Hash")
}

/// Ankerbytes, die sich selbst NICHT tragen — erwarteter Code
/// `EA-TRUST-ANCHOR-HASH`.
pub fn foreign_anchor_exact_bytes() -> Vec<u8> {
    FOREIGN_ANCHOR_BYTES.to_vec()
}

// ---------------------------------------------------------------------------
// Die Schluessel des Readers
// ---------------------------------------------------------------------------

/// Der oeffentliche X25519-Punkt zum privaten KEM-Schluessel des Tresors.
pub fn reader_kem_public_key() -> HpkeRecipientPublicKey {
    HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(READER_KEM_SEED))
        .expect("32 Byte sind ein gueltiger X25519-Privatschluessel")
        .public_key()
}

fn reader_kem_public_cose_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::x25519(*reader_kem_public_key().as_bytes())
        .expect("ein abgeleiteter X25519-Punkt ist nicht der Nullpunkt")
}

fn reader_signing_public_cose_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(ea_testkit::ed25519_public_key(&READER_AUDIT_SEED))
        .expect("ein aus einem Seed abgeleiteter Ed25519-Punkt ist ein gueltiger Punkt")
}

// ---------------------------------------------------------------------------
// Geraetezertifikate
// ---------------------------------------------------------------------------

fn device_certificate(
    certificate_kind: CertificateKindV1,
    signing: Option<CanonicalPublicCoseKey>,
    kem: Option<CanonicalPublicCoseKey>,
    capabilities: Vec<String>,
) -> DeviceCertificateFieldsV1 {
    DeviceCertificateFieldsV1 {
        organization_id: OrganizationId::try_from(&[0x12_u8; 16][..])
            .expect("16 Byte sind eine Organisationskennung"),
        device_id: DeviceId::try_from(&[0x15_u8; 16][..])
            .expect("16 Byte sind eine Geraetekennung"),
        certificate_kind,
        signing_key_thumbprint: signing.as_ref().map(CanonicalPublicCoseKey::thumbprint),
        kem_key_thumbprint: kem.as_ref().map(CanonicalPublicCoseKey::thumbprint),
        signing_public_cose_key: signing
            .as_ref()
            .map(CanonicalPublicCoseKey::to_deterministic_cbor),
        kem_public_cose_key: kem
            .as_ref()
            .map(CanonicalPublicCoseKey::to_deterministic_cbor),
        capabilities,
        key_protection_profile: KeyProtectionProfileV1::OsWrapped,
        effective_from_sequence: ChainSequence::new(1),
        revoked_from_sequence: None,
        authority_subject_id: None,
    }
}

/// Das regulaere Reader-Zertifikat: X25519 fuer die Entkapselung, Ed25519 fuer
/// Geraet und Audit, und KEINE Capability — ein Reader traegt keine
/// (`crates/ea-trust/tests/support/mod.rs`, `fn capabilities`).
pub fn reader_certificate() -> DeviceCertificateFieldsV1 {
    device_certificate(
        CertificateKindV1::Reader,
        Some(reader_signing_public_cose_key()),
        Some(reader_kem_public_cose_key()),
        Vec::new(),
    )
}

/// DIESELBEN 32 Bytes in beiden Rollen.
///
/// Der einzige Fall, den ein Abdruckvergleich NICHT faengt: `crv 6` und `crv 4`
/// gehen in `to_deterministic_cbor` mit ein, dieselben Rohbytes tragen also
/// zwei verschiedene Abdruecke und passierten jede Prueferei, die nur
/// Abdruecke vergleicht.
pub fn reader_certificate_with_one_key_in_both_roles() -> DeviceCertificateFieldsV1 {
    let shared = ea_testkit::ed25519_public_key(&READER_AUDIT_SEED);
    device_certificate(
        CertificateKindV1::Reader,
        Some(
            CanonicalPublicCoseKey::ed25519(shared)
                .expect("ein aus einem Seed abgeleiteter Ed25519-Punkt ist gueltig"),
        ),
        Some(
            CanonicalPublicCoseKey::x25519(shared)
                .expect("derselbe Punkt ist als X25519-Bytefolge kodierbar"),
        ),
        Vec::new(),
    )
}

/// Ein Reader ohne KEM-Schluessel — er koennte nie entkapseln.
pub fn reader_certificate_without_kem_key() -> DeviceCertificateFieldsV1 {
    device_certificate(
        CertificateKindV1::Reader,
        Some(reader_signing_public_cose_key()),
        None,
        Vec::new(),
    )
}

/// Ein Reader ohne Signaturschluessel — er koennte nie ein lokales Audit
/// signieren.
pub fn reader_certificate_without_signing_key() -> DeviceCertificateFieldsV1 {
    device_certificate(
        CertificateKindV1::Reader,
        None,
        Some(reader_kem_public_cose_key()),
        Vec::new(),
    )
}

/// Ein vollstaendig gueltiges WRITER-Zertifikat.
///
/// Es faellt an der ERSTEN Klausel und nicht an einem fehlenden Schluessel:
/// die Rolle entscheidet, nicht die Ausstattung.
pub fn writer_certificate() -> DeviceCertificateFieldsV1 {
    device_certificate(
        CertificateKindV1::Writer,
        Some(reader_signing_public_cose_key()),
        None,
        vec!["initialGrant".to_owned()],
    )
}

// ---------------------------------------------------------------------------
// Tresorinhalt und Tresor
// ---------------------------------------------------------------------------

/// Der zuletzt verifizierte Registry-Stand im Tresor.
pub fn last_registry_pin() -> RegistryHeadPin {
    RegistryHeadPin::new(
        RegistryVersion::new(7),
        ObjectHash::try_from(&[0x71_u8; 32][..]).expect("32 Byte sind ein Objekthash"),
    )
}

/// Der Tresorinhalt nach `web-reader-design.md` §6.1: KEM-Schluessel,
/// Audit-Schluessel, gepinnter Anker, zuletzt verifizierter Registry-Stand.
///
/// Wird bei JEDEM Aufruf neu gebaut. `SecretBytes` traegt bewusst kein `Clone`,
/// und `HpkeRecipientPrivateKey::from_bytes` KONSUMIERT sein Geheimnis — ein
/// zwischengehaltener Inhalt liesse sich nicht zweimal versiegeln.
pub fn vault_contents() -> VaultContentsV1 {
    VaultContentsV1::new(
        SecretBytes::new(READER_KEM_SEED),
        SecretBytes::new(READER_AUDIT_SEED),
        pinned_anchor_exact_bytes(),
        Some(last_registry_pin()),
    )
}

fn second_vault_contents() -> VaultContentsV1 {
    VaultContentsV1::new(
        SecretBytes::new(SECOND_READER_KEM_SEED),
        SecretBytes::new(SECOND_READER_AUDIT_SEED),
        pinned_anchor_exact_bytes(),
        Some(last_registry_pin()),
    )
}

/// Ein versiegelter Tresor mit zwei Entsperrwegen.
pub fn sealed_vault() -> SealedVaultV1 {
    ReaderVault::seal(vault_contents(), &[authenticator(1), authenticator(2)])
        .expect("zwei Authenticators genuegen zum Versiegeln")
}

/// Derselbe Tresor, ueber den ersten Authenticator entsperrt.
pub fn unlocked_vault() -> UnlockedVault {
    ReaderVault::unlock(&sealed_vault(), &authenticator(1))
        .expect("der erste Authenticator oeffnet seinen eigenen Envelope")
}

/// Ein ANDERER Tresor mit eigenem Tresorschluessel.
///
/// Er belegt, dass Cache und Zustandsspeicher an den Tresorschluessel gebunden
/// sind und nicht an den Bytespeicher: derselbe Speicher bleibt ihm
/// verschlossen.
pub fn second_unlocked_vault() -> UnlockedVault {
    let sealed = ReaderVault::seal(second_vault_contents(), &[authenticator(3)])
        .expect("ein Authenticator genuegt zum Versiegeln");
    ReaderVault::unlock(&sealed, &authenticator(3))
        .expect("der dritte Authenticator oeffnet seinen eigenen Envelope")
}

// ---------------------------------------------------------------------------
// Cache und Eintragszustand
// ---------------------------------------------------------------------------

/// Der `EntryHash`, unter dem [`missing_grant_state`] abgelegt wird.
pub fn entry_hash() -> EntryHash {
    EntryHash::try_from(&[0x61_u8; 32][..]).expect("32 Byte sind ein Eintragshash")
}

fn cached_object_hash() -> ObjectHash {
    ObjectHash::try_from(&[0x62_u8; 32][..]).expect("32 Byte sind ein Objekthash")
}

/// EXAKTE Objektbytes, die `marker` tragen.
///
/// Der Cache kodiert nichts um und liest nichts aus — er ist deshalb bewusst
/// mit einem OPAKEN Bytestrang bezeugt und nicht mit einem geparsten
/// Eintragspaket. Was der Zeuge belegen MUSS, ist allein: der Marker geht
/// hinein, kommt ueber den Tresor zurueck und steht dazwischen an keiner
/// Stelle im Klartext im Bytespeicher.
pub fn entry_package_bytes_carrying(marker: &[u8]) -> Vec<u8> {
    let mut bytes = b"EINSATZARCHIV-ENTRY-PACKAGE-FIXTURE-v1".to_vec();
    bytes.extend_from_slice(marker);
    bytes.extend_from_slice(&[0x00, 0xff, 0x00]);
    bytes
}

/// Ein Eintrag mit gueltiger technischer Kette und OHNE eigenen Grant.
///
/// Drei orthogonale Dimensionen, und keine wird in eine andere gefaltet:
/// `missingGrant` ist der Verifikationsbefund, `present` der Eintragszustand,
/// `notServerConfirmed` die eigene Spalte aus `design.md` §17.4.
/// `detail_code` bleibt `None`, weil ein fehlender Grant KEIN Objektfehler ist
/// — `ObjectErrorV1::code()`-Werte wie `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED`
/// gehoeren dem Zustand `unknownKey`.
pub fn missing_grant_state() -> ReaderEntryStateV1 {
    ReaderEntryStateV1::new(
        entry_hash(),
        cached_object_hash(),
        ChainSequence::new(12),
        VerificationStatus::MissingGrant,
        EntryStatus::Present,
        ServerConfirmationV1::NotServerConfirmed,
        None,
    )
}
