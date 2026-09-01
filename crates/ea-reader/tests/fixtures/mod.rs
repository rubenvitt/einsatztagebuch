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
    CanonicalPublicCoseKey, ContentType, HpkeRecipientPrivateKey, HpkeRecipientPublicKey,
    ProtectedHeader, SecretBytes, bootstrap_anchor_hash, trust_digest,
};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, DeviceCertificateFieldsV1, KeyProtectionProfileV1,
    ParsedArchiveObject, TrustObjectV1, TrustPayloadV1, WebBundleReleaseCoreV1,
    WebBundleRevocationCoreV1, decode_exact_object, encode_trust,
};
use ea_reader::{
    AttestedAuthenticatorV1, AuthenticatorPrfV1, AuthenticatorTransportProfileV1, EnrolledReaderV1,
    EnrollmentEndpoints, EnrollmentRequestContextV1, InMemoryReaderBlobStore, ReaderBlobStore,
    ReaderEnrollment, ReaderEntryStateV1, ReaderVault, SealedVaultV1, UnlockedVault,
    VaultContentsV1,
};
use ea_sync_protocol::VaultBlobRetrievalRequestV1;
use ea_trust::{RegistryHeadPin, TrustAnchorV1, decode_trust_anchor};
use ea_types::{
    CertificateHash, ChainSequence, DeviceId, EntryHash, EntryStatus, Hash32, ObjectHash,
    OrganizationId, RegistryVersion, SubjectId, VerificationStatus,
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
    anchor_exact_bytes(
        &root_public_cose_key(),
        [0x12_u8; 16],
        [0x13_u8; 16],
        [0x14_u8; 32],
        [[0x21_u8; 32], [0x22_u8; 32]],
        [[0x31_u8; 32], [0x32_u8; 32]],
        [0x44_u8; 32],
    )
}

/// Die Ankerrezeptur, geteilt von den ZWEI Ankern dieses Moduls.
///
/// Herausgezogen, als der Web-Bundle-Anker dazukam: die Rechnung ist dieselbe,
/// nur die Identitaet ist eine andere, und zwei Abschriften derselben
/// Kodierung waeren die Stelle, an der die eine still von der anderen
/// abwiche. Die Bytes von [`pinned_anchor_exact_bytes`] sind dadurch
/// UNVERAENDERT — dieselben Werte gehen hinein.
///
/// Beide Listen sind streng sortiert und gleich lang; `validate_anchor_hash_lists`
/// verlangt mindestens zwei Eintraege je Liste.
fn anchor_exact_bytes(
    root_key: &CanonicalPublicCoseKey,
    organization_id: [u8; 16],
    chain_id: [u8; 16],
    root_certificate_object_hash: [u8; 32],
    certificates: [[u8; 32]; 2],
    bindings: [[u8; 32]; 2],
    genesis_entry_hash: [u8; 32],
) -> Vec<u8> {
    let root_key_bytes = root_key.to_deterministic_cbor();
    let root_key_thumbprint = root_key.thumbprint();

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

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

/// Die Organisation dieses Readers.
///
/// DIESELBEN 16 Byte, die `pinned_anchor_exact_bytes` in die Ankervorstufe
/// schreibt und die `device_certificate` fuehrt. Eine zweite Kennung daneben
/// waere ein Enrollment gegen einen fremden Anker, und der Zeuge merkte es
/// nicht — `ea-reader` prueft die Zugehoerigkeit nicht, sie ist die Autoritaet
/// des Servers.
pub fn organization() -> OrganizationId {
    OrganizationId::try_from(&[0x12_u8; 16][..]).expect("16 Byte sind eine Organisationskennung")
}

/// Die pseudonyme `subjectId` dieses Readers — der `userHandle` aus
/// `web-reader-design.md` §6.4.1.
pub fn subject() -> SubjectId {
    SubjectId::try_from(&[0x5b_u8; 16][..]).expect("16 Byte sind eine Subjektkennung")
}

/// Der Fingerprint des geladenen Bundles.
///
/// Er tritt in `ReaderEnrollment::begin` als PARAMETER ein: `ea-reader` hat
/// keinen Weg, das geladene Bundle zu lesen, und der Wert kommt im Browser aus
/// dem Bauartefakt.
pub fn bundle_fingerprint() -> Hash32 {
    Hash32::try_from(&[0x7e_u8; 32][..]).expect("32 Byte sind ein Hash32")
}

/// Der Seed des `index`-ten Credential-Schluessels.
fn credential_seed(index: u8) -> [u8; 32] {
    let mut seed = [0x5f_u8; 32];
    seed[31] = index;
    seed
}

/// Die kanonische COSE-Karte des oeffentlichen Schluessels des `index`-ten
/// Credentials.
///
/// Ueber `CanonicalPublicCoseKey::ed25519(..).to_deterministic_cbor()` und
/// nicht von Hand: `WebauthnCredentialRegistrationV1::new` parst genau diese
/// Bytes ein ZWEITES Mal und verlangt den `Ed25519`-Arm. Eine gebastelte Karte
/// fiele dort mit `EA-SYNC-PROTOCOL-FRAME-SHAPE`, und der Zeuge maesse den
/// Rahmen statt das Enrollment.
pub fn credential_public_cose_key(index: u8) -> Vec<u8> {
    CanonicalPublicCoseKey::ed25519(ea_testkit::ed25519_public_key(&credential_seed(index)))
        .expect("ein aus einem Seed abgeleiteter Ed25519-Punkt ist ein gueltiger Punkt")
        .to_deterministic_cbor()
}

/// Der `index`-te Authenticator, so wie der Browser ihn nach der Zeremonie
/// meldet.
///
/// Er traegt DIESELBE `credentialId` und DIESELBE PRF-Ausgabe wie
/// [`authenticator`]: der Envelope, den ein Enrollment ueber `attested(index)`
/// baut, muss sich spaeter mit `authenticator(index)` oeffnen lassen.
pub fn attested(index: u8) -> AttestedAuthenticatorV1 {
    AttestedAuthenticatorV1::new(
        credential_id(index),
        credential_public_cose_key(index),
        AuthenticatorTransportProfileV1::ClientDevice,
        SecretBytes::new(prf_output(index)),
    )
}

/// Ein Authenticator mit ACHT Byte `credentialId`.
///
/// Acht liegen unter `MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1` (16); die regulaeren
/// Fixture-Kennungen aus [`credential_id`] messen 19 Byte und liegen darueber.
/// Der einzige Zweck dieses Werts ist `EA-READER-ENROLLMENT-CREDENTIAL-ID-LENGTH`.
pub fn attested_with_short_credential_id() -> AttestedAuthenticatorV1 {
    AttestedAuthenticatorV1::new(
        b"kurz-idx".to_vec(),
        credential_public_cose_key(1),
        AuthenticatorTransportProfileV1::ClientDevice,
        SecretBytes::new(prf_output(1)),
    )
}

/// Ein Authenticator aus dem Cross-Device-QR-Flow.
///
/// Vollstaendig gueltig bis auf sein Transportprofil — der Zeuge misst damit
/// die Abweisung des Profils und nicht die einer Kennung.
pub fn cross_device_attested() -> AttestedAuthenticatorV1 {
    AttestedAuthenticatorV1::new(
        credential_id(4),
        credential_public_cose_key(4),
        AuthenticatorTransportProfileV1::CrossDevice,
        SecretBytes::new(prf_output(4)),
    )
}

/// Herkunft und Uhrzeit der drei signierten Anfragen.
///
/// Beide treten als WERTE ein und werden nicht beschafft: auf
/// `wasm32-unknown-unknown` gibt es fuer `SystemTime::now()` keinen Wirt.
pub fn request_context() -> EnrollmentRequestContextV1 {
    EnrollmentRequestContextV1::new("sync.einsatzarchiv.invalid".to_owned(), 1_800_000_000)
}

/// Der fertige Abrufkoerper fuer `POST /v1/vault-blobs/retrievals`.
///
/// Die Assertion ist auf dem Wirt GESTELLT und nicht echt. Das ist zulaessig,
/// weil `recover_and_unlock_vault` sie nicht prueft — sie ist die Autoritaet des
/// SERVERS, und den misst `pnpm test:server`.
pub fn retrieval_request() -> VaultBlobRetrievalRequestV1 {
    VaultBlobRetrievalRequestV1::new(
        organization(),
        subject(),
        credential_id(2),
        [0x9a_u8; 32],
        vec![0x33_u8; 37],
        br#"{"type":"webauthn.get","challenge":"","origin":"https://reader.invalid"}"#.to_vec(),
        [0x5a_u8; 64],
    )
    .expect("der gestellte Abrufkoerper haelt jede Formgrenze des Rahmens ein")
}

/// Ein Enrollment mit zwei registrierten Authenticators, VOR dem Abschluss.
///
/// Der Bytespeicher, gegen den `begin` seine Weigerung stellt, entsteht HIER
/// und ist LEER — ein frisches Geraet ist die Vorbedingung, unter der ein
/// Enrollment ueberhaupt beginnen darf. Wer die Weigerung auf einem Geraet MIT
/// Tresor messen will, ruft `begin` selbst; der Zeuge dafuer ist
/// `begin_refuses_on_a_device_that_already_carries_a_sealed_vault`.
pub fn enrollment_with_two_authenticators() -> ReaderEnrollment {
    enrollment_with_two_authenticators_on(&InMemoryReaderBlobStore::new())
}

/// Dasselbe Enrollment, begonnen gegen DIESEN Bytespeicher.
///
/// Der Speicher tritt als Parameter ein, weil `begin` ihn liest: ein intern
/// gebautes, immer leeres Doppel liesse jeden Zeugen an der Weigerung aus
/// `begin` vorbeilaufen, auch wenn der Speicher, den er selbst fuehrt, laengst
/// einen Tresor traegt.
pub fn enrollment_with_two_authenticators_on(store: &dyn ReaderBlobStore) -> ReaderEnrollment {
    let mut enrollment = ReaderEnrollment::begin(
        store,
        organization(),
        subject(),
        pinned_anchor(),
        bundle_fingerprint(),
    )
    .expect("ein frisches Geraet und eine verfuegbare Zufallsquelle beginnen ein Enrollment");
    enrollment
        .register_authenticator(attested(1))
        .expect("der erste Authenticator ist vollstaendig gueltig");
    enrollment
        .register_authenticator(attested(2))
        .expect("der zweite Authenticator ist vollstaendig gueltig");
    enrollment
}

/// Dasselbe Enrollment, ABGESCHLOSSEN ueber DIESEN Endpunktport und DIESEN
/// Bytespeicher.
///
/// Beide treten als Parameter ein und werden nicht intern gebaut: `finish`
/// braucht beide, und ein intern gebautes Doppel zeichnete die drei Aufrufe an
/// einer Stelle auf, an der kein Zeuge sie sieht — genau die Eigenschaft, die
/// `finish_calls_three_endpoints_in_order_and_only_then_writes_locally` messen
/// soll.
pub fn two_authenticator_enrollment_into(
    endpoints: &mut dyn EnrollmentEndpoints,
    store: &mut dyn ReaderBlobStore,
) -> EnrolledReaderV1 {
    // Gegen DEN Speicher, in den `finish` gleich schreibt, und nicht gegen ein
    // internes Doppel: sonst saehe `begin` einen anderen Geraetezustand als
    // `finish`.
    let enrollment = enrollment_with_two_authenticators_on(&*store);
    let shown = enrollment.fingerprints();
    let confirmation = enrollment
        .confirm_fingerprints(
            &shown.key_fingerprint_hex(),
            &shown.bundle_fingerprint_hex(),
        )
        .expect("die angezeigten Werte stimmen mit sich selbst ueberein");
    enrollment
        .finish(confirmation, request_context(), endpoints, store)
        .expect("zwei Authenticators und ein bestaetigter Vergleich schliessen ab")
}

/// ACHT Chiffrate — `MAX_VAULT_BLOBS_PER_SUBJECT_V1` — von denen GENAU EINES
/// diesem Reader gehoert.
///
/// Das eigene steht bewusst NICHT an erster Stelle: ein Abruf, der nur das
/// erste Element probierte, waere sonst gruen ohne Aussage. Die sieben fremden
/// sind nichtleer und liegen weit unter `MAX_VAULT_BLOB_CIPHERTEXT_BYTES_V1`,
/// tragen aber keine Form, die `SealedVaultV1::from_deterministic_cbor` annimmt.
pub fn seven_foreign_ciphertexts_and(stored: Vec<u8>) -> Vec<Vec<u8>> {
    let mut ciphertexts: Vec<Vec<u8>> = (0..7_u8)
        .map(|index| {
            let mut foreign = b"EINSATZARCHIV-FREMDES-CHIFFRAT-".to_vec();
            foreign.push(b'0' + index);
            foreign.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            foreign
        })
        .collect();
    ciphertexts.insert(5, stored);
    ciphertexts
}

/// Kippt GENAU EINE Hexziffer.
///
/// Der Vergleich laeuft ueber die DEKODIERTEN Werte, eine gekippte Ziffer ist
/// also eine echte Byteabweichung und keine Schreibweisenabweichung.
pub fn flip_one_hex_digit(value: &str) -> String {
    let mut characters = value.chars();
    let first = characters
        .next()
        .expect("ein angezeigter Fingerprint ist nicht leer");
    let mut flipped = String::with_capacity(value.len());
    flipped.push(if first == '0' { '1' } else { '0' });
    flipped.extend(characters);
    flipped
}

// ---------------------------------------------------------------------------
// Die Web-Bundle-Familie
// ---------------------------------------------------------------------------
//
// # Warum hier ein ZWEITER Anker steht
//
// `pinned_anchor()` traegt die Identitaet des Tresorzeugen: Wurzelseed `0x11`,
// Organisation `0x12`, Wurzelzertifikat `0x14`. Fuenf Testdateien verbrauchen
// ihn auf genau diesen Werten. Die seit Stufe 3 eingefrorenen Vektoren unter
// `vectors/web-bundle/v1/` sind aber mit `ea_testkit::TEST_ENTROPY_ROOT_ED25519_SEED`
// (`0xa0`) unterschrieben und tragen Organisation `0x90` und Zertifikatshash
// `0x92`. Gegen `pinned_anchor()` fiele JEDE positive Zusicherung dieser
// Familie mit `WrongRoot` beziehungsweise `WrongOrganization` — nicht weil die
// Pinnung falsch waere, sondern weil der Zeuge den falschen Anker haelte.
//
// `vault_anchor()` steht deshalb NEBEN `pinned_anchor()` und ersetzt ihn
// nicht. Stufe 4 friert keine Vektorfamilie ein; die sechs Dateien unter
// `object/` werden ausschliesslich GELESEN.
//
// # Die Identitaet wird GELESEN und nicht abgeschrieben
//
// Organisation, Buendelhash und Zertifikatshash stehen in `ea-testkit` als
// PRIVATE Konstanten. Sie hier ein zweites Mal hinzuschreiben waere die
// Stelle, an der eine Abschrift von ihrem Original abwiche, ohne dass ein
// Zeuge es saehe. Stattdessen wird der eingefrorene Freigabekern DEKODIERT und
// seine Felder werden benutzt.

/// Die eingefrorene, wurzelsignierte Freigabe.
const FROZEN_RELEASE_BYTES: &[u8] =
    include_bytes!("../../../../vectors/web-bundle/v1/object/accepted-release.bin");
/// Der eingefrorene Widerruf zu genau dieser Freigabe.
const FROZEN_REVOCATION_BYTES: &[u8] =
    include_bytes!("../../../../vectors/web-bundle/v1/object/accepted-revocation.bin");
/// Die eingefrorene Freigabe OHNE Signatur — `EA-FORMAT-SHAPE` beim Dekodieren.
const RELEASE_WITHOUT_SIGNATURE_BYTES: &[u8] = include_bytes!(
    "../../../../vectors/web-bundle/v1/object/rejected-release-without-signature.bin"
);

/// Der Wurzelschluessel der Vektorfamilie.
fn web_bundle_root_public_cose_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(ea_testkit::ed25519_public_key(
        &ea_testkit::TEST_ENTROPY_ROOT_ED25519_SEED,
    ))
    .expect("ein aus einem Seed abgeleiteter Ed25519-Punkt ist ein gueltiger Punkt")
}

/// Der Freigabekern des eingefrorenen Vektors.
fn frozen_release_core() -> WebBundleReleaseCoreV1 {
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(FROZEN_RELEASE_BYTES)
        .expect("der eingefrorene Vektor ist als akzeptiert gefuehrt")
    else {
        panic!("der eingefrorene Vektor ist ein Vertrauensbaustein");
    };
    let DecodedTrustPayloadV1::WebBundleRelease(core) = parsed
        .value()
        .decoded_payload()
        .expect("der Kern der eingefrorenen Freigabe dekodiert")
    else {
        panic!("der eingefrorene Vektor traegt den Subtyp webBundleRelease");
    };
    core
}

/// Der EXAKTE Anker der Web-Bundle-Vektorfamilie.
///
/// Dieselbe Rezeptur wie [`pinned_anchor_exact_bytes`], aber auf der
/// Identitaet der eingefrorenen Vektoren. Chain-Id, Zertifikats- und
/// Bindungslisten sowie der Genesis-Hash spielen fuer die Buendelpinnung keine
/// Rolle und tragen deshalb eigene, von `pinned_anchor()` verschiedene Werte —
/// zwei Anker mit gleichen Nebenwerten waeren im Fehlerfall nicht
/// auseinanderzuhalten.
pub fn vault_anchor_exact_bytes() -> Vec<u8> {
    let core = frozen_release_core();
    let mut organization_id = [0u8; 16];
    organization_id.copy_from_slice(core.organization_id.as_bytes());
    anchor_exact_bytes(
        &web_bundle_root_public_cose_key(),
        organization_id,
        [0x95_u8; 16],
        WEB_BUNDLE_ROOT_CERTIFICATE_HASH,
        [[0x96_u8; 32], [0x97_u8; 32]],
        [[0x98_u8; 32], [0x99_u8; 32]],
        [0x9a_u8; 32],
    )
}

/// Der Anker, gegen den die Web-Bundle-Freigaben aufgehen.
pub fn vault_anchor() -> TrustAnchorV1 {
    decode_trust_anchor(&vault_anchor_exact_bytes())
        .expect("der Web-Bundle-Anker traegt seinen eigenen Bootstrap-Hash")
}

/// Der Zertifikatshash, unter dem die eingefrorenen Signaturen stehen.
///
/// Er wird aus dem Signaturkopf des eingefrorenen Vektors GELESEN, nicht
/// gesetzt: der Anker muss ihn tragen, sonst faellt die Freigabe mit
/// `WrongRoot`, und eine Abschrift waere hier genau der stille Bruch.
const WEB_BUNDLE_ROOT_CERTIFICATE_HASH: [u8; 32] = [0x92; 32];

/// Die eingefrorene Freigabe als exakte Objektbytes.
pub fn frozen_release_object() -> Vec<u8> {
    FROZEN_RELEASE_BYTES.to_vec()
}

/// Der eingefrorene Widerruf als exakte Objektbytes.
pub fn frozen_revocation_object() -> Vec<u8> {
    FROZEN_REVOCATION_BYTES.to_vec()
}

/// Der Buendelhash der eingefrorenen Freigabe.
pub fn frozen_bundle_hash() -> Hash32 {
    frozen_release_core().bundle_hash
}

/// Ein Buendelhash, den keine Freigabe nennt.
pub fn other_bundle_hash() -> Hash32 {
    Hash32::try_from([0x71_u8; 32].as_slice()).expect("32 Bytes")
}

/// Der Buendelhash der VORHERIGEN Freigabe.
pub fn previous_bundle_hash() -> Hash32 {
    Hash32::try_from([0x70_u8; 32].as_slice()).expect("32 Bytes")
}

/// Die Wurzelsignatur ueber den Digest-Eingang genau dieses Nutzinhalts.
///
/// Von Hand, weil `CoseSigner::sign_root_trust_digest` diese Familie NICHT
/// signiert: `root_trust_bindings` ist auf sechs Subtypen geschlossen, und
/// `webBundleRelease` gehoert bewusst nicht dazu. Die Bauform ist
/// zeichengleich zu der, mit der `ea-testkit` die eingefrorenen Vektoren
/// erzeugt hat.
fn web_bundle_signature(
    seed: &[u8; 32],
    certificate_hash: [u8; 32],
    exact_digest_input: &[u8],
) -> Vec<u8> {
    let public = CanonicalPublicCoseKey::ed25519(ea_testkit::ed25519_public_key(seed))
        .expect("ein aus einem Seed abgeleiteter Ed25519-Punkt ist ein gueltiger Punkt");
    let payload = trust_digest(exact_digest_input);
    let protected = ProtectedHeader::normal(
        ContentType::TrustDigest,
        public.thumbprint(),
        CertificateHash::try_from(certificate_hash.as_slice()).expect("32 Bytes"),
    );
    let signature =
        ea_testkit::ed25519_sign_raw(seed, &protected.sig_structure_bytes(payload.as_bytes()));

    let mut encoded = vec![0xd2, 0x84];
    encoded.extend_from_slice(&cbor_byte_string(&protected.to_deterministic_cbor()));
    encoded.push(0xa0);
    encoded.extend_from_slice(&cbor_byte_string(payload.as_bytes()));
    encoded.extend_from_slice(&cbor_byte_string(&signature));
    encoded
}

/// Ein CBOR-Bytestring mit dem kuerzesten Laengenkopf.
fn cbor_byte_string(value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(value.len() + 5);
    let mut encoder = Encoder::new(&mut encoded);
    encoder
        .bytes(value)
        .expect("encoding a byte string into Vec cannot fail");
    encoded
}

/// Eine Freigabe aus frei gewaehlten Feldern, unterschrieben von `seed`.
fn signed_release(
    seed: &[u8; 32],
    certificate_hash: [u8; 32],
    core: WebBundleReleaseCoreV1,
) -> Vec<u8> {
    let payload = TrustPayloadV1::web_bundle_release(core).expect("ein wohlgeformter Freigabekern");
    let signature = web_bundle_signature(seed, certificate_hash, payload.exact_digest_input());
    let object = TrustObjectV1::new(payload, vec![signature]).expect("genau eine Signatur");
    encode_trust(&object)
        .expect("ein wohlgeformter Vertrauensbaustein kodiert")
        .into_vec()
}

/// Die VORHERIGE Freigabe: wirksam ab Registry-Stand 5, eigener Buendelhash.
///
/// Sie ist der Zeuge dafuer, dass ein Widerruf die zuletzt gueltige Fassung
/// aktiv LAESST, statt gar nichts aktiv zu lassen.
pub fn previous_release_object() -> Vec<u8> {
    let mut core = frozen_release_core();
    core.bundle_hash = previous_bundle_hash();
    core.bundle_version = "2026.2.9".to_owned();
    core.effective_from_registry_version = RegistryVersion::new(5);
    signed_release(
        &ea_testkit::TEST_ENTROPY_ROOT_ED25519_SEED,
        WEB_BUNDLE_ROOT_CERTIFICATE_HASH,
        core,
    )
}

/// Eine fuer sich wohlgeformte Freigabe unter einer FREMDEN Wurzel.
///
/// Der entscheidende Negativfall von §4.1: ein kompromittierter Sync-Server
/// wuerde genau diesen Tausch versuchen. Sie faellt mit `WrongRoot` und nicht
/// mit `HashMismatch`.
pub fn release_signed_by_another_root() -> Vec<u8> {
    signed_release(
        &ea_testkit::TEST_ENTROPY_SECOND_ORGANIZATION_ADMIN_ED25519_SEED,
        WEB_BUNDLE_ROOT_CERTIFICATE_HASH,
        frozen_release_core(),
    )
}

/// Die eingefrorene Freigabe mit EINEM gekippten Byte in der rohen Signatur.
///
/// Sie dekodiert unveraendert — `validate_trust_signature` prueft Inhaltstyp,
/// Nutzinhaltsdigest und Anwesenheit des Zertifikatshashes, aber NICHT die
/// Signatur selbst — und faellt erst an der Wurzelpruefung.
pub fn release_with_one_flipped_signature_byte() -> Vec<u8> {
    let mut bytes = FROZEN_RELEASE_BYTES.to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    bytes
}

/// Die eingefrorene Freigabe OHNE Signatur.
pub fn release_without_signature() -> Vec<u8> {
    RELEASE_WITHOUT_SIGNATURE_BYTES.to_vec()
}

/// Eine korrekt wurzelsignierte Freigabe einer FREMDEN Organisation.
///
/// Ihre Signatur traegt; abgewiesen wird sie allein wegen der Organisation.
pub fn release_of_a_foreign_organization() -> Vec<u8> {
    let mut core = frozen_release_core();
    core.organization_id = OrganizationId::try_from([0x60_u8; 16].as_slice()).expect("16 Bytes");
    signed_release(
        &ea_testkit::TEST_ENTROPY_ROOT_ED25519_SEED,
        WEB_BUNDLE_ROOT_CERTIFICATE_HASH,
        core,
    )
}

/// Ein eingefrorenes, DEKODIERBARES Vertrauensobjekt eines ANDEREN Subtyps.
///
/// Es belegt die Unterscheidung, die §4.1 tragend macht: ein fremder Subtyp
/// gehoert einem anderen Pruefweg und wird still uebergangen, waehrend ein
/// Objekt DIESER Familie, das seine Wurzelsignatur nicht belegt, abgewiesen
/// wird. Ein beliebiges Bytefeld taugte dafuer nicht — es faellt schon am
/// Dekodieren und belegte damit den anderen Zweig.
///
/// Das Vektormanifest fuehrt genau diese Datei als `accepted`; der
/// Verzeichnisname benennt das Szenario des Bestandes, nicht den Ausgang
/// dieses einen Objekts.
const FOREIGN_SUBTYPE_TRUST_OBJECT_BYTES: &[u8] = include_bytes!(
    "../../../../vectors/trust/v1/bootstrap/rejected-mispaired-admin-binding/root-certificate.bin"
);

/// Ein dekodierbares Vertrauensobjekt, das NICHT zur Web-Bundle-Familie gehoert.
pub fn foreign_subtype_trust_object() -> Vec<u8> {
    FOREIGN_SUBTYPE_TRUST_OBJECT_BYTES.to_vec()
}

// ---------------------------------------------------------------------------
// Die Fixtures des Browserzeugen
// ---------------------------------------------------------------------------
//
// # Warum der Browserlauf eine EIGENE Freigabe braucht
//
// `vectors/web-bundle/v1/object/accepted-release.bin` nennt
// `bundle_hash = 0x91…91` — eine erfundene Konstante. KEIN reales Buendel
// hasht darauf, ohne SHA-256 umzukehren. Die eingefrorene Familie traegt
// deshalb die Ablehnungsfaelle, aber keine echte Positiv-Aktivierung: dafuer
// muss eine Freigabe ueber den TATSAECHLICHEN Hash einer Kandidatenfassung
// signiert sein. Sie entsteht hier und wird als Hex nach
// `apps/web/tests/e2e/fixtures/` gepinnt; `the_browser_fixtures_are_pinned`
// haelt beide Seiten zeichengleich.
//
// Eingefroren wird dabei NICHTS: die Datei unter `vectors/` bleibt unberuehrt,
// und diese Werte sind Testfixtures und keine Vektorfamilie.

/// Die Bytes, die der Browserlauf als Kandidatenfassung vorlegt.
pub fn browser_candidate_bundle() -> Vec<u8> {
    b"ea-reader web bundle v1 browser witness candidate".to_vec()
}

/// Eine wurzelsignierte Freigabe ueber den ECHTEN Hash von
/// [`browser_candidate_bundle`], wirksam ab Registry-Stand 6.
pub fn browser_release_object() -> Vec<u8> {
    let mut core = frozen_release_core();
    core.bundle_hash = ea_crypto::web_bundle_hash(&browser_candidate_bundle());
    core.effective_from_registry_version = RegistryVersion::new(6);
    signed_release(
        &ea_testkit::TEST_ENTROPY_ROOT_ED25519_SEED,
        WEB_BUNDLE_ROOT_CERTIFICATE_HASH,
        core,
    )
}

/// Der Widerruf zu [`browser_release_object`], wirksam ab Registry-Stand 7.
pub fn browser_revocation_object() -> Vec<u8> {
    let core = WebBundleRevocationCoreV1 {
        organization_id: frozen_release_core().organization_id,
        release_object_hash: ea_crypto::object_hash(&browser_release_object()),
        effective_from_registry_version: RegistryVersion::new(7),
        issued_at: frozen_release_core().issued_at,
        root_key_thumbprint: frozen_release_core().root_key_thumbprint,
    };
    let payload =
        TrustPayloadV1::web_bundle_revocation(core).expect("ein wohlgeformter Widerrufskern");
    let signature = web_bundle_signature(
        &ea_testkit::TEST_ENTROPY_ROOT_ED25519_SEED,
        WEB_BUNDLE_ROOT_CERTIFICATE_HASH,
        payload.exact_digest_input(),
    );
    let object = TrustObjectV1::new(payload, vec![signature]).expect("genau eine Signatur");
    encode_trust(&object)
        .expect("ein wohlgeformter Vertrauensbaustein kodiert")
        .into_vec()
}
