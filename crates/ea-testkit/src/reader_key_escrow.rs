//! Die drei Vektorfamilien des Reader-Key-Escrows (v1.1-Profil §9,
//! Entscheidung 11).
//!
//! `vectors/reader-key-escrow/v1/`, `vectors/reader-key-escrow-approval/v1/`
//! und `vectors/reader-key-escrow-recovery/v1/` liegen NEBEN
//! `vectors/trust/v1/`, nach dem Vorbild `vectors/web-bundle/v1/`: die
//! Reserved-Pins der Trust-Familie sind Substring-Prüfungen über den ganzen
//! Manifesttext, und jeder Eintrag dort drehte sie rot. Die Subtyp-Literale
//! stehen AUSSCHLIESSLICH in den hexkodierten Objektbytes; Eintragsnamen und
//! Notizen sind kebab-case bzw. Prosa ohne die Literale.
//!
//! # Bauordnung
//!
//! Core → Freigabe (bindet `escrow-core-hash`) → Escrow (bindet den
//! Objekthash der Freigabe) → Öffnung (bindet den Objekthash des Escrows) →
//! Öffnungskontext (bindet Escrow- und Autorisierungshash). Eine Zirkularität
//! gibt es nicht: die Freigabe hasht den Core, nicht die Nutzlast.
//!
//! # Zwei Sorten Bytes
//!
//! Alles bis auf die beiden HPKE-Kapselungen ist deterministisch: Ed25519
//! signiert deterministisch, alle Felder sind Konstanten. Die Kapselungen
//! ziehen frische Entropie (`hpke_seal`), stehen deshalb als EINMAL erzeugte
//! Konstanten hier ([`VectorSource::FrozenOnce`]) und werden ausschließlich
//! über `hpke_open` nachgeprüft. Weil der Öffnungskontext die Objekthashes
//! bindet, hängt die zweite Kapselung an JEDER deterministischen Konstante
//! dieser Datei: wer eine ändert, muss `freeze_reader_key_escrow_encapsulations`
//! neu laufen lassen und alle vier Werte ersetzen.
//!
//! # Grenze
//!
//! Diese Vektoren sind Codec- und Kryptovektoren. Sie belegen Gestalt,
//! Kardinalität, Digest- und HPKE-Bindung. Sie belegen NICHT die Prüfungen des
//! Trust-Kerns (Freigabe aktiv und gleiche Organisation, Enrollment-Bindung,
//! Eindeutigkeit, Randsemantik `now > expiresAt`, Schwelle zweier Personen);
//! die Zertifikatshashes sind erklärte Testkonstanten und werden gegen keinen
//! Katalog aufgelöst. Es gibt keine `CoseSigner`-Methode für diese Familien:
//! die Signaturen entstehen über [`super::trust_signed_normal`].

use std::collections::BTreeMap;

use ea_crypto::{
    CanonicalPublicCoseKey, HpkeRecipientPrivateKey, SecretBytes, hpke_aad, hpke_info, object_hash,
    reader_key_escrow_core_hash, trust_digest,
};
use ea_format::{
    READER_KEY_ESCROW_RESTORE_SUITE_ID, READER_KEY_ESCROW_SUITE_ID, ReaderKeyEscrowApprovalCoreV1,
    ReaderKeyEscrowCoreV1, ReaderKeyEscrowHpkeContextV1,
    ReaderKeyEscrowRecoveryAuthorizationCoreV1, ReaderKeyEscrowRestoreContextV1, TrustPayloadV1,
    TrustSubtypeV1,
};
use ea_types::{
    AuthorizationId, CertificateHash, ChainSequence, Hash32, KeyThumbprint, ObjectHash,
    OrganizationId, RegistryVersion, SubjectId, UnixMillis,
};

use super::{
    ExpectedOutcome, TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
    TEST_ENTROPY_RECIPIENT_X25519_SEED, TEST_ENTROPY_ROOT_ED25519_SEED, VectorEntry,
    VectorManifest, VectorSource, digest_map, sha256, trust_cbor_array, trust_cbor_text,
    trust_exact_object, trust_public_key, trust_signed_normal,
};

/// Der Familienname der Escrow-Objekte.
pub const READER_KEY_ESCROW_FAMILY: &str = "reader-key-escrow";

/// Der Familienname der Publikationsfreigaben.
pub const READER_KEY_ESCROW_APPROVAL_FAMILY: &str = "reader-key-escrow-approval";

/// Der Familienname der Öffnungsautorisierungen.
pub const READER_KEY_ESCROW_RECOVERY_FAMILY: &str = "reader-key-escrow-recovery";

/// Der Versionsordner aller drei Familien.
pub const READER_KEY_ESCROW_V1_VERSION: &str = "v1";

/// Die Wurzel der Escrow-Vektoren, relativ zur Arbeitsbaumwurzel.
pub const READER_KEY_ESCROW_V1_ROOT: &str = "vectors/reader-key-escrow/v1";

/// Die Wurzel der Freigabevektoren, relativ zur Arbeitsbaumwurzel.
pub const READER_KEY_ESCROW_APPROVAL_V1_ROOT: &str = "vectors/reader-key-escrow-approval/v1";

/// Die Wurzel der Öffnungsvektoren, relativ zur Arbeitsbaumwurzel.
pub const READER_KEY_ESCROW_RECOVERY_V1_ROOT: &str = "vectors/reader-key-escrow-recovery/v1";

/// Deklarierte Testentropie: der PRIVATE Reader-KEM-Schlüssel, den das Escrow
/// versiegelt und die Öffnung an den Transportschlüssel weiterreicht.
///
/// Keine Standardkonstante, sondern ein erklärtes Füllbyte wie die übrige
/// Testentropie dieser Kiste; `reader_key_escrow_seeds_are_distinct` misst,
/// dass es mit keiner anderen Rolle zusammenfällt.
pub const READER_KEY_ESCROW_READER_KEM_X25519_SEED: [u8; 32] = [0xe0; 32];

/// Deklarierte Testentropie: der flüchtige Ziel-Transportschlüssel der
/// Öffnung (Profil §7).
pub const READER_KEY_ESCROW_TRANSPORT_X25519_SEED: [u8; 32] = [0xe1; 32];

/// Deklarierte Testentropie: der ERSTE Approver der Öffnung.
pub const READER_KEY_ESCROW_FIRST_APPROVER_ED25519_SEED: [u8; 32] = [0xe2; 32];

/// Deklarierte Testentropie: der ZWEITE Approver der Öffnung.
pub const READER_KEY_ESCROW_SECOND_APPROVER_ED25519_SEED: [u8; 32] = [0xe3; 32];

/// Die Herkunftsangabe der deterministischen Vektoren.
const GENERATOR: &str = "ea-testkit::reader_key_escrow";

/// Der Suite-Identifikator der Objektvektoren, wie bei `web-bundle/v1`.
const SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";

/// Die Schema-Identifikatoren. Freie Zeichenketten des Manifests; die Grammatik
/// steht in `schemas/archive/v1/trust.cddl`.
const OBJECT_SCHEMA_ID: &str = "etb-v1";
const HPKE_CONTEXT_SCHEMA_ID: &str = "reader-key-escrow-hpke-context-v1";
const RESTORE_CONTEXT_SCHEMA_ID: &str = "reader-key-escrow-restore-context-v1";
const SUITE_ID_SCHEMA_ID: &str = "reader-key-escrow-suite-id-v1";
const HPKE_SEALED_SCHEMA_ID: &str = "reader-key-escrow-hpke-sealed-v1";

const SHAPE: &str = "EA-FORMAT-SHAPE";
const TAG_MISMATCH: &str = "EA-FORMAT-TAG-MISMATCH";
const COSE: &str = "EA-FORMAT-COSE";
const HPKE_OPEN: &str = "EA-CRYPTO-HPKE-OPEN";

// Feste Feldwerte. Die Zertifikatshashes sind erklärte Testkonstanten und
// keine Objekthashes: ein Objektvektor wird gegen keinen Katalog aufgelöst.
const ORGANIZATION_ID: [u8; 16] = [0x70; 16];
const READER_CERTIFICATE_OBJECT_HASH: [u8; 32] = [0x71; 32];
const READER_SUBJECT_ID: [u8; 16] = [0x72; 16];
const ENROLLMENT_REGISTRY_VERSION: u64 = 4;
const ENROLLMENT_REGISTRY_HEAD_HASH: [u8; 32] = [0x73; 32];
const ENROLLMENT_SEQUENCE: u64 = 9;
const RECOVERY_CERTIFICATE_OBJECT_HASH: [u8; 32] = [0x74; 32];
const ROOT_CERTIFICATE_HASH: [u8; 32] = [0x75; 32];
const SECOND_ROOT_CERTIFICATE_HASH: [u8; 32] = [0x7f; 32];
const ADMIN_CERTIFICATE_HASH: [u8; 32] = [0x76; 32];
const ADMIN_OPERATOR_BINDING_OBJECT_HASH: [u8; 32] = [0x77; 32];
const FIRST_APPROVER_CERTIFICATE_HASH: [u8; 32] = [0x78; 32];
const SECOND_APPROVER_CERTIFICATE_HASH: [u8; 32] = [0x79; 32];
const ESCROW_ISSUED_AT_MS: i64 = 1_700_000_010_000;
const APPROVAL_AUTHORIZATION_ID: [u8; 16] = [0x7a; 16];
const APPROVAL_REGISTRY_VERSION: u64 = 5;
const APPROVAL_REGISTRY_HEAD_HASH: [u8; 32] = [0x7b; 32];
const APPROVAL_AUTHORIZATION_SEQUENCE: u64 = 10;
const APPROVAL_ISSUED_AT_MS: i64 = 1_700_000_009_000;
const APPROVAL_LIFETIME_MS: i64 = 120_000;
const APPROVAL_NONCE: [u8; 32] = [0x7c; 32];
const RECOVERY_AUTHORIZATION_ID: [u8; 16] = [0x7d; 16];
const RECOVERY_REGISTRY_VERSION: u64 = 6;
const RECOVERY_REGISTRY_HEAD_HASH: [u8; 32] = [0x7e; 32];
const RECOVERY_AUTHORIZATION_SEQUENCE: u64 = 11;
const RECOVERY_ISSUED_AT_MS: i64 = 1_700_000_020_000;
const RECOVERY_LIFETIME_MS: i64 = 600_000;
const RECOVERY_NONCE: [u8; 32] = [0x6f; 32];

/// Kapselungswert der Escrow-Versiegelung, EINMALIG erzeugt und eingefroren.
///
/// `hpke_seal` zieht frische Entropie. Erzeugungslauf:
/// `cargo test -p ea-testkit -- --ignored --nocapture freeze_reader_key_escrow_encapsulations`.
/// Nachgeprüft wird ausschließlich über `hpke_open` mit dem Recovery-Schlüssel
/// [`TEST_ENTROPY_RECIPIENT_X25519_SEED`].
const ESCROW_ENCAPSULATED_KEY: &str =
    "11031dc54d7c60bd19b5659c34cf6bfce925a5bb20af5536d4ac52ae98fa0d7b";

/// Der versiegelte Reader-KEM-Schlüssel zum eingefrorenen Kapselungswert.
const ESCROW_ENCRYPTED_READER_KEM_KEY: &str = concat!(
    "a530d6eff9406e42bcfe68747735deebe44d608ca49590bf",
    "0bdafb07830e63bffd8d5702b63b667d40e93822c14be19d",
);

/// Kapselungswert der Öffnungsantwort, im SELBEN Lauf eingefroren.
const RESTORE_ENCAPSULATED_KEY: &str =
    "6cbd88fb5da3c1d18a06f16da73109e9bf9d7d3d6835d94d673cfed1c4cd8368";

/// Das Chiffrat der Öffnungsantwort zum eingefrorenen Kapselungswert.
const RESTORE_CIPHERTEXT: &str = concat!(
    "738cdc2ddba7fe5667daf34ac68b3f8e2c90ad6216e504c1",
    "460f4ac27f8d7996de11badd859065b77a5a914037920085",
);

fn fixed<const N: usize>(hex_text: &str) -> [u8; N] {
    hex::decode(hex_text)
        .expect("a frozen constant is hexadecimal")
        .try_into()
        .expect("a frozen constant has its declared length")
}

fn organization_id() -> OrganizationId {
    OrganizationId::try_from(ORGANIZATION_ID.as_slice()).expect("16 bytes")
}

fn subject_id() -> SubjectId {
    SubjectId::try_from(READER_SUBJECT_ID.as_slice()).expect("16 bytes")
}

fn certificate(bytes: [u8; 32]) -> CertificateHash {
    CertificateHash::try_from(bytes.as_slice()).expect("32 bytes")
}

fn hash32(bytes: [u8; 32]) -> Hash32 {
    Hash32::try_from(bytes.as_slice()).expect("32 bytes")
}

/// Der öffentliche X25519-Schlüssel zu einem deklarierten Seed.
fn x25519_public(seed: [u8; 32]) -> [u8; 32] {
    *HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(seed))
        .expect("a declared X25519 seed loads")
        .public_key()
        .as_bytes()
}

/// Der Schlüsselabdruck nach RFC 9679 zu einem X25519-Seed.
fn x25519_thumbprint(seed: [u8; 32]) -> KeyThumbprint {
    CanonicalPublicCoseKey::x25519(x25519_public(seed))
        .expect("a derived X25519 key is canonical")
        .thumbprint()
}

/// Alle deterministischen Bausteine der drei Familien zu gegebenen
/// Escrow-Kapselungswerten.
pub(crate) struct EscrowChain {
    pub(crate) core: ReaderKeyEscrowCoreV1,
    pub(crate) escrow_core_hash: Hash32,
    pub(crate) approval_payload: TrustPayloadV1,
    pub(crate) approval_signature: Vec<u8>,
    pub(crate) approval_bytes: Vec<u8>,
    pub(crate) escrow_payload: TrustPayloadV1,
    pub(crate) escrow_signature: Vec<u8>,
    pub(crate) escrow_bytes: Vec<u8>,
    pub(crate) recovery_core: ReaderKeyEscrowRecoveryAuthorizationCoreV1,
    pub(crate) recovery_payload: TrustPayloadV1,
    pub(crate) recovery_signatures: Vec<Vec<u8>>,
    pub(crate) recovery_bytes: Vec<u8>,
    pub(crate) hpke_context: Vec<u8>,
    pub(crate) restore_context: Vec<u8>,
}

fn escrow_core(encapsulated_key: [u8; 32], encrypted: [u8; 48]) -> ReaderKeyEscrowCoreV1 {
    ReaderKeyEscrowCoreV1 {
        organization_id: organization_id(),
        reader_certificate_object_hash: certificate(READER_CERTIFICATE_OBJECT_HASH),
        reader_subject_id: subject_id(),
        enrollment_registry_version: RegistryVersion::new(ENROLLMENT_REGISTRY_VERSION),
        enrollment_registry_head_hash: hash32(ENROLLMENT_REGISTRY_HEAD_HASH),
        enrollment_sequence: ChainSequence::new(ENROLLMENT_SEQUENCE),
        recovery_certificate_object_hash: certificate(RECOVERY_CERTIFICATE_OBJECT_HASH),
        recovery_kem_key_thumbprint: x25519_thumbprint(TEST_ENTROPY_RECIPIENT_X25519_SEED),
        encapsulated_key,
        encrypted_reader_kem_key: encrypted,
        issued_at: UnixMillis::new(ESCROW_ISSUED_AT_MS),
        root_key_thumbprint: trust_public_key(TEST_ENTROPY_ROOT_ED25519_SEED).thumbprint(),
    }
}

fn approval_core(escrow_core_hash: Hash32, lifetime_ms: i64) -> ReaderKeyEscrowApprovalCoreV1 {
    ReaderKeyEscrowApprovalCoreV1 {
        authorization_id: AuthorizationId::try_from(APPROVAL_AUTHORIZATION_ID.as_slice())
            .expect("16 bytes"),
        organization_id: organization_id(),
        registry_version: RegistryVersion::new(APPROVAL_REGISTRY_VERSION),
        registry_head_hash: hash32(APPROVAL_REGISTRY_HEAD_HASH),
        authorization_sequence: APPROVAL_AUTHORIZATION_SEQUENCE,
        admin_key_thumbprint: trust_public_key(TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED)
            .thumbprint(),
        admin_certificate_object_hash: certificate(ADMIN_CERTIFICATE_HASH),
        admin_operator_binding_object_hash: ObjectHash::try_from(
            ADMIN_OPERATOR_BINDING_OBJECT_HASH.as_slice(),
        )
        .expect("32 bytes"),
        escrow_core_hash,
        reader_certificate_object_hash: certificate(READER_CERTIFICATE_OBJECT_HASH),
        reader_subject_id: subject_id(),
        issued_at: UnixMillis::new(APPROVAL_ISSUED_AT_MS),
        expires_at: UnixMillis::new(APPROVAL_ISSUED_AT_MS + lifetime_ms),
        nonce: APPROVAL_NONCE,
    }
}

fn recovery_core(escrow_object_hash: ObjectHash) -> ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
    ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
        authorization_id: AuthorizationId::try_from(RECOVERY_AUTHORIZATION_ID.as_slice())
            .expect("16 bytes"),
        organization_id: organization_id(),
        registry_version: RegistryVersion::new(RECOVERY_REGISTRY_VERSION),
        registry_head_hash: hash32(RECOVERY_REGISTRY_HEAD_HASH),
        authorization_sequence: RECOVERY_AUTHORIZATION_SEQUENCE,
        escrow_object_hash,
        reader_certificate_object_hash: certificate(READER_CERTIFICATE_OBJECT_HASH),
        reader_subject_id: subject_id(),
        enrollment_registry_version: RegistryVersion::new(ENROLLMENT_REGISTRY_VERSION),
        enrollment_registry_head_hash: hash32(ENROLLMENT_REGISTRY_HEAD_HASH),
        target_transport_key_thumbprint: x25519_thumbprint(READER_KEY_ESCROW_TRANSPORT_X25519_SEED),
        issued_at: UnixMillis::new(RECOVERY_ISSUED_AT_MS),
        expires_at: UnixMillis::new(RECOVERY_ISSUED_AT_MS + RECOVERY_LIFETIME_MS),
        nonce: RECOVERY_NONCE,
    }
}

/// Eine Normalprofil-Signatur über `trust_digest(input)`.
fn signature(seed: [u8; 32], certificate_hash: [u8; 32], exact_digest_input: &[u8]) -> Vec<u8> {
    trust_signed_normal(
        seed,
        certificate(certificate_hash),
        trust_digest(exact_digest_input).as_bytes(),
    )
}

/// Baut die ganze Kette zu gegebenen Escrow-Kapselungswerten.
pub(crate) fn escrow_chain(encapsulated_key: [u8; 32], encrypted: [u8; 48]) -> EscrowChain {
    let core = escrow_core(encapsulated_key, encrypted);
    let escrow_for_core = TrustPayloadV1::reader_key_escrow(
        core.clone(),
        ObjectHash::try_from([0; 32].as_slice()).expect("32 bytes"),
    )
    .expect("the escrow core is well formed");
    let exact_core = exact_core_of(escrow_for_core.exact_payload()).to_vec();
    let escrow_core_hash = reader_key_escrow_core_hash(&exact_core);

    let approval_payload = TrustPayloadV1::reader_key_escrow_approval(approval_core(
        escrow_core_hash,
        APPROVAL_LIFETIME_MS,
    ))
    .expect("the approval core is well formed");
    let approval_signature = signature(
        TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
        ADMIN_CERTIFICATE_HASH,
        approval_payload.exact_digest_input(),
    );
    let approval_bytes =
        trust_exact_object(approval_payload.clone(), vec![approval_signature.clone()]);

    let escrow_payload =
        TrustPayloadV1::reader_key_escrow(core.clone(), object_hash(&approval_bytes))
            .expect("the escrow payload is well formed");
    let escrow_signature = signature(
        TEST_ENTROPY_ROOT_ED25519_SEED,
        ROOT_CERTIFICATE_HASH,
        escrow_payload.exact_digest_input(),
    );
    let escrow_bytes = trust_exact_object(escrow_payload.clone(), vec![escrow_signature.clone()]);

    let recovery_core = recovery_core(object_hash(&escrow_bytes));
    let recovery_payload =
        TrustPayloadV1::reader_key_escrow_recovery_authorization(recovery_core.clone())
            .expect("the recovery authorization core is well formed");
    // Aufsteigend nach Zertifikatshash, damit die Reihenfolge nicht zufällig
    // ist.
    let recovery_signatures = vec![
        signature(
            READER_KEY_ESCROW_FIRST_APPROVER_ED25519_SEED,
            FIRST_APPROVER_CERTIFICATE_HASH,
            recovery_payload.exact_digest_input(),
        ),
        signature(
            READER_KEY_ESCROW_SECOND_APPROVER_ED25519_SEED,
            SECOND_APPROVER_CERTIFICATE_HASH,
            recovery_payload.exact_digest_input(),
        ),
    ];
    let recovery_bytes = trust_exact_object(recovery_payload.clone(), recovery_signatures.clone());

    let hpke_context = ReaderKeyEscrowHpkeContextV1::from_escrow_core(&core).encode();
    let restore_context = ReaderKeyEscrowRestoreContextV1::from_recovery_authorization(
        &recovery_core,
        object_hash(&recovery_bytes),
    )
    .encode();

    EscrowChain {
        core,
        escrow_core_hash,
        approval_payload,
        approval_signature,
        approval_bytes,
        escrow_payload,
        escrow_signature,
        escrow_bytes,
        recovery_core,
        recovery_payload,
        recovery_signatures,
        recovery_bytes,
        hpke_context,
        restore_context,
    }
}

/// Die Kette mit den eingefrorenen Kapselungswerten.
pub(crate) fn frozen_escrow_chain() -> EscrowChain {
    escrow_chain(
        fixed(ESCROW_ENCAPSULATED_KEY),
        fixed(ESCROW_ENCRYPTED_READER_KEM_KEY),
    )
}

/// Der exakte Core-Slice einer Escrow-Nutzlast `[core, bstr .size 32]`:
/// ein Kopfbyte vorn, 34 Byte Hash hinten.
fn exact_core_of(exact_payload: &[u8]) -> &[u8] {
    assert_eq!(
        exact_payload[0], 0x82,
        "the escrow payload has two elements"
    );
    let tail = exact_payload.len() - 34;
    assert_eq!(&exact_payload[tail..tail + 2], &[0x58, 0x20]);
    &exact_payload[1..tail]
}

/// Ein Vertrauensbaustein von Hand: `präfix || [subtype, nutzlast, [sig*]]`.
fn handmade_object(subtype: &str, exact_payload: &[u8], signatures: &[Vec<u8>]) -> Vec<u8> {
    let mut object = vec![0x85, 0x44, b'E', b'A', b'1', 0, 5, 1, 0x80];
    object.extend_from_slice(&trust_cbor_array(3));
    object.extend_from_slice(&trust_cbor_text(subtype));
    object.extend_from_slice(exact_payload);
    object.extend_from_slice(&trust_cbor_array(
        u64::try_from(signatures.len()).expect("fewer than 24 signatures"),
    ));
    for signature in signatures {
        object.extend_from_slice(signature);
    }
    object
}

/// Der Digest-Eingang `[subtype, nutzlast]` von Hand.
fn digest_input(subtype: &str, exact_payload: &[u8]) -> Vec<u8> {
    let mut input = trust_cbor_array(2);
    input.extend_from_slice(&trust_cbor_text(subtype));
    input.extend_from_slice(exact_payload);
    input
}

/// Ein Kern `[ … , []]` ohne seinen Extension-Slot: ein Element weniger.
fn without_extension_slot(exact_core: &[u8]) -> Vec<u8> {
    assert_eq!(exact_core[exact_core.len() - 1], 0x80, "a core ends on []");
    let mut shortened = vec![exact_core[0] - 1];
    shortened.extend_from_slice(&exact_core[1..exact_core.len() - 1]);
    shortened
}

/// Ein Kern mit einer zusätzlichen Position `0` vor dem Extension-Slot.
fn with_extra_position(exact_core: &[u8]) -> Vec<u8> {
    assert_eq!(exact_core[exact_core.len() - 1], 0x80, "a core ends on []");
    let mut longer = vec![exact_core[0] + 1];
    longer.extend_from_slice(&exact_core[1..exact_core.len() - 1]);
    longer.push(0x00);
    longer.push(0x80);
    longer
}

/// Ersetzt genau ein Vorkommen von `from` durch `to`.
fn replace_once(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = bytes
        .windows(from.len())
        .position(|window| window == from)
        .expect("the field to mutate is present");
    assert!(
        bytes[at + 1..]
            .windows(from.len())
            .all(|window| window != from),
        "the field to mutate is unique"
    );
    let mut mutated = bytes[..at].to_vec();
    mutated.extend_from_slice(to);
    mutated.extend_from_slice(&bytes[at + from.len()..]);
    mutated
}

fn rejected(code: &str) -> ExpectedOutcome {
    ExpectedOutcome::Rejected {
        error_code: code.to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn entry(
    name: &str,
    schema_id: &str,
    source: VectorSource,
    input_bytes: Vec<u8>,
    intermediate_digests: BTreeMap<String, [u8; 32]>,
    object_bytes: Vec<u8>,
    expected_outcome: ExpectedOutcome,
    scope_note: Option<&str>,
) -> VectorEntry {
    VectorEntry {
        name: name.to_owned(),
        schema_id: schema_id.to_owned(),
        suite_id: SUITE_ID.to_owned(),
        source,
        input_bytes,
        intermediate_digests,
        object_bytes,
        expected_outcome,
        file: format!("{name}.bin"),
        scope_note: scope_note.map(ToOwned::to_owned),
    }
}

fn generator() -> VectorSource {
    VectorSource::GeneratorCommit(GENERATOR.to_owned())
}

fn frozen_once() -> VectorSource {
    VectorSource::FrozenOnce {
        verified_via: "hpke_open".to_owned(),
    }
}

fn object_entry(name: &str, object_bytes: Vec<u8>, outcome: ExpectedOutcome) -> VectorEntry {
    entry(
        name,
        OBJECT_SCHEMA_ID,
        generator(),
        Vec::new(),
        BTreeMap::new(),
        object_bytes,
        outcome,
        None,
    )
}

/// Ein Objekt der Escrow-Familie. Es trägt die EINMAL eingefrorene Kapselung
/// des Cores (bzw. eine Mutation davon), deshalb [`VectorSource::FrozenOnce`]
/// wie die Grant-Objekte der Familie `grants`: nachgeprüft wird die Kapselung
/// über `hpke_open` unter dem aus dem Core abgeleiteten Kontext.
fn escrow_object_entry(name: &str, object_bytes: Vec<u8>, outcome: ExpectedOutcome) -> VectorEntry {
    entry(
        name,
        OBJECT_SCHEMA_ID,
        frozen_once(),
        Vec::new(),
        BTreeMap::new(),
        object_bytes,
        outcome,
        None,
    )
}

/// Die Grenze jedes angenommenen Objektvektors, als Notiz im Manifest.
const ACCEPTED_OBJECT_SCOPE: &str = "Codec-Vektor: belegt Gestalt, Kardinalität und \
     Trust-Digest. Die Zertifikatshashes sind erklärte Testkonstanten und werden gegen keinen \
     Katalog aufgelöst; Freigabe-, Enrollment-, Eindeutigkeits- und Fristprüfung sind \
     Trust-Kern und hier NICHT belegt.";

/// Das Manifest der Familie `reader-key-escrow/v1`.
///
/// # Panics
///
/// Wenn eine Konstruktion fehlschlägt. Das wäre ein Programmierfehler dieser
/// Kiste, kein Laufzeitzustand.
#[must_use]
pub fn reader_key_escrow_v1_manifest() -> VectorManifest {
    let chain = frozen_escrow_chain();
    let subtype = TrustSubtypeV1::ReaderKeyEscrow.as_str();
    let payload = chain.escrow_payload.exact_payload().to_vec();
    let exact_core = exact_core_of(&payload).to_vec();
    let approval_hash = &payload[payload.len() - 32..];
    let second_root = signature(
        TEST_ENTROPY_ROOT_ED25519_SEED,
        SECOND_ROOT_CERTIFICATE_HASH,
        chain.escrow_payload.exact_digest_input(),
    );
    let rewrap = |core: &[u8]| {
        let mut rewrapped = vec![0x82];
        rewrapped.extend_from_slice(core);
        rewrapped.extend_from_slice(&payload[payload.len() - 34..]);
        rewrapped
    };
    let signed = |exact_payload: &[u8]| {
        handmade_object(
            subtype,
            exact_payload,
            &[signature(
                TEST_ENTROPY_ROOT_ED25519_SEED,
                ROOT_CERTIFICATE_HASH,
                &digest_input(subtype, exact_payload),
            )],
        )
    };

    let mut three = vec![0x83];
    three.extend_from_slice(&payload[1..]);
    three.extend_from_slice(&[0x58, 0x20]);
    three.extend_from_slice(approval_hash);

    let mut short_ciphertext = chain.core.encrypted_reader_kem_key.to_vec();
    short_ciphertext.pop();
    let mut full_field = vec![0x58, 0x30];
    full_field.extend_from_slice(&chain.core.encrypted_reader_kem_key);
    let mut short_field = vec![0x58, 0x2f];
    short_field.extend_from_slice(&short_ciphertext);

    let info = hpke_info(&chain.hpke_context);
    let aad = hpke_aad(&chain.hpke_context);
    let mut sealed = chain.core.encapsulated_key.to_vec();
    sealed.extend_from_slice(&chain.core.encrypted_reader_kem_key);
    let changed_subject = replace_once(
        &chain.hpke_context,
        &{
            let mut field = vec![0x50];
            field.extend_from_slice(&READER_SUBJECT_ID);
            field
        },
        &{
            let mut field = vec![0x50];
            field.extend_from_slice(&[0x6e; 16]);
            field
        },
    );

    let entries = vec![
        entry(
            "object/accepted-escrow",
            OBJECT_SCHEMA_ID,
            frozen_once(),
            Vec::new(),
            digest_map(&[
                (
                    "trust-digest",
                    *trust_digest(chain.escrow_payload.exact_digest_input()).as_bytes(),
                ),
                ("escrow-core-hash", *chain.escrow_core_hash.as_bytes()),
            ]),
            chain.escrow_bytes.clone(),
            ExpectedOutcome::Accepted,
            Some(ACCEPTED_OBJECT_SCOPE),
        ),
        escrow_object_entry(
            "object/rejected-escrow-without-signature",
            handmade_object(subtype, &payload, &[]),
            rejected(SHAPE),
        ),
        escrow_object_entry(
            "object/rejected-escrow-with-two-signatures",
            handmade_object(
                subtype,
                &payload,
                &[chain.escrow_signature.clone(), second_root],
            ),
            rejected(SHAPE),
        ),
        escrow_object_entry(
            "object/rejected-escrow-core-without-extension-array",
            signed(&rewrap(&without_extension_slot(&exact_core))),
            rejected(SHAPE),
        ),
        escrow_object_entry(
            "object/rejected-escrow-core-with-fifteen-elements",
            signed(&rewrap(&with_extra_position(&exact_core))),
            rejected(SHAPE),
        ),
        escrow_object_entry(
            "object/rejected-escrow-payload-with-three-elements",
            signed(&three),
            rejected(SHAPE),
        ),
        escrow_object_entry(
            "object/rejected-escrow-encrypted-key-short",
            signed(&rewrap(&replace_once(
                &exact_core,
                &full_field,
                &short_field,
            ))),
            rejected(SHAPE),
        ),
        // Die Signatur trägt den Digest-Eingang mit dem Literal der Freigabe:
        // derselbe Nutzinhalt, ein anderer Kontext. `validate_trust_signature`
        // vergleicht den Digest und weist ab.
        escrow_object_entry(
            "object/rejected-escrow-signature-over-neighbour-subtype",
            handmade_object(
                subtype,
                &payload,
                &[signature(
                    TEST_ENTROPY_ROOT_ED25519_SEED,
                    ROOT_CERTIFICATE_HASH,
                    &digest_input(TrustSubtypeV1::ReaderKeyEscrowApproval.as_str(), &payload),
                )],
            ),
            rejected(COSE),
        ),
        entry(
            "context/hpke-info",
            HPKE_CONTEXT_SCHEMA_ID,
            generator(),
            chain.hpke_context.clone(),
            digest_map(&[("context", sha256(&chain.hpke_context))]),
            info.clone(),
            ExpectedOutcome::Accepted,
            None,
        ),
        entry(
            "context/hpke-aad",
            HPKE_CONTEXT_SCHEMA_ID,
            generator(),
            chain.hpke_context.clone(),
            digest_map(&[("context", sha256(&chain.hpke_context))]),
            aad.clone(),
            ExpectedOutcome::Accepted,
            None,
        ),
        entry(
            "suite/escrow-suite-identifier",
            SUITE_ID_SCHEMA_ID,
            generator(),
            Vec::new(),
            BTreeMap::new(),
            READER_KEY_ESCROW_SUITE_ID.as_bytes().to_vec(),
            ExpectedOutcome::Accepted,
            None,
        ),
        entry(
            "suite/restore-suite-identifier",
            SUITE_ID_SCHEMA_ID,
            generator(),
            Vec::new(),
            BTreeMap::new(),
            READER_KEY_ESCROW_RESTORE_SUITE_ID.as_bytes().to_vec(),
            ExpectedOutcome::Accepted,
            None,
        ),
        entry(
            "hpke/accepted-escrow-opens",
            HPKE_SEALED_SCHEMA_ID,
            frozen_once(),
            READER_KEY_ESCROW_READER_KEM_X25519_SEED.to_vec(),
            digest_map(&[
                ("infoDigest", sha256(&info)),
                ("aadDigest", sha256(&aad)),
                (
                    "recipientPublicKeyThumbprint",
                    *chain.core.recovery_kem_key_thumbprint.as_bytes(),
                ),
            ]),
            sealed.clone(),
            ExpectedOutcome::Accepted,
            Some(
                "Kapselungswert und versiegelter Schlüssel des Escrow-Cores, einmal erzeugt; \
                 nachgeprüft über hpke_open mit dem Recovery-Schlüssel und dem aus dem Core \
                 abgeleiteten Kontext.",
            ),
        ),
        entry(
            "hpke/rejected-escrow-with-changed-subject",
            HPKE_SEALED_SCHEMA_ID,
            frozen_once(),
            changed_subject,
            BTreeMap::new(),
            sealed,
            rejected(HPKE_OPEN),
            Some(
                "Die Eingabebytes sind der Kontext mit einer anderen Subject-ID; dieselbe \
                 Versiegelung darf unter ihm nicht öffnen.",
            ),
        ),
    ];

    VectorManifest {
        family: READER_KEY_ESCROW_FAMILY.to_owned(),
        version: READER_KEY_ESCROW_V1_VERSION.to_owned(),
        entries,
    }
}

/// Das Manifest der Familie `reader-key-escrow-approval/v1`.
///
/// # Panics
///
/// Wie [`reader_key_escrow_v1_manifest`].
#[must_use]
pub fn reader_key_escrow_approval_v1_manifest() -> VectorManifest {
    let chain = frozen_escrow_chain();
    let subtype = TrustSubtypeV1::ReaderKeyEscrowApproval.as_str();
    let payload = chain.approval_payload.exact_payload().to_vec();
    let admin = |exact_payload: &[u8]| {
        signature(
            TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
            ADMIN_CERTIFICATE_HASH,
            &digest_input(subtype, exact_payload),
        )
    };
    let signed =
        |exact_payload: &[u8]| handmade_object(subtype, exact_payload, &[admin(exact_payload)]);

    let at_limit = TrustPayloadV1::reader_key_escrow_approval(approval_core(
        chain.escrow_core_hash,
        ea_crypto::READER_KEY_ESCROW_APPROVAL_MAX_LIFETIME_MS,
    ))
    .expect("the lifetime limit itself is admissible");
    let at_limit_signature = admin(at_limit.exact_payload());
    let at_limit_bytes = trust_exact_object(at_limit.clone(), vec![at_limit_signature]);

    let expires_field = |lifetime: i64| {
        let mut field = vec![0x1b];
        field.extend_from_slice(&(APPROVAL_ISSUED_AT_MS + lifetime).to_be_bytes());
        field
    };
    let mut before_field = vec![0x1b];
    before_field.extend_from_slice(&(APPROVAL_ISSUED_AT_MS - 1).to_be_bytes());
    let mut short_hash_from = vec![0x58, 0x20];
    short_hash_from.extend_from_slice(chain.escrow_core_hash.as_bytes());
    let mut short_hash_to = vec![0x58, 0x1f];
    short_hash_to.extend_from_slice(&chain.escrow_core_hash.as_bytes()[..31]);

    let entries = vec![
        entry(
            "object/accepted-approval",
            OBJECT_SCHEMA_ID,
            generator(),
            Vec::new(),
            digest_map(&[(
                "trust-digest",
                *trust_digest(chain.approval_payload.exact_digest_input()).as_bytes(),
            )]),
            chain.approval_bytes.clone(),
            ExpectedOutcome::Accepted,
            Some(ACCEPTED_OBJECT_SCOPE),
        ),
        entry(
            "object/accepted-approval-lifetime-at-limit",
            OBJECT_SCHEMA_ID,
            generator(),
            Vec::new(),
            digest_map(&[(
                "trust-digest",
                *trust_digest(at_limit.exact_digest_input()).as_bytes(),
            )]),
            at_limit_bytes,
            ExpectedOutcome::Accepted,
            Some(
                "Die Frist ist genau die Höchstdauer von 300 000 ms. Die Randsemantik gegen die \
                 Uhr (now > expiresAt) ist Trust-Kern und hier NICHT belegt.",
            ),
        ),
        object_entry(
            "object/rejected-approval-without-signature",
            handmade_object(subtype, &payload, &[]),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-approval-with-two-signatures",
            handmade_object(
                subtype,
                &payload,
                &[
                    chain.approval_signature.clone(),
                    signature(
                        TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
                        SECOND_ROOT_CERTIFICATE_HASH,
                        chain.approval_payload.exact_digest_input(),
                    ),
                ],
            ),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-approval-core-with-fifteen-elements",
            signed(&without_extension_slot(&payload)),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-approval-core-with-seventeen-elements",
            signed(&with_extra_position(&payload)),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-approval-expires-before-issued",
            signed(&replace_once(
                &payload,
                &expires_field(APPROVAL_LIFETIME_MS),
                &before_field,
            )),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-approval-lifetime-zero",
            signed(&replace_once(
                &payload,
                &expires_field(APPROVAL_LIFETIME_MS),
                &expires_field(0),
            )),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-approval-lifetime-over-limit",
            signed(&replace_once(
                &payload,
                &expires_field(APPROVAL_LIFETIME_MS),
                &expires_field(ea_crypto::READER_KEY_ESCROW_APPROVAL_MAX_LIFETIME_MS + 1),
            )),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-approval-escrow-core-hash-short",
            signed(&replace_once(&payload, &short_hash_from, &short_hash_to)),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-approval-signature-over-neighbour-subtype",
            handmade_object(
                subtype,
                &payload,
                &[signature(
                    TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
                    ADMIN_CERTIFICATE_HASH,
                    &digest_input(
                        TrustSubtypeV1::ReaderKeyEscrowRecoveryAuthorization.as_str(),
                        &payload,
                    ),
                )],
            ),
            rejected(COSE),
        ),
    ];

    VectorManifest {
        family: READER_KEY_ESCROW_APPROVAL_FAMILY.to_owned(),
        version: READER_KEY_ESCROW_V1_VERSION.to_owned(),
        entries,
    }
}

/// Das Manifest der Familie `reader-key-escrow-recovery/v1`.
///
/// # Panics
///
/// Wie [`reader_key_escrow_v1_manifest`].
#[must_use]
pub fn reader_key_escrow_recovery_v1_manifest() -> VectorManifest {
    let chain = frozen_escrow_chain();
    let subtype = TrustSubtypeV1::ReaderKeyEscrowRecoveryAuthorization.as_str();
    let payload = chain.recovery_payload.exact_payload().to_vec();
    let approvers = |exact_payload: &[u8]| {
        let input = digest_input(subtype, exact_payload);
        vec![
            signature(
                READER_KEY_ESCROW_FIRST_APPROVER_ED25519_SEED,
                FIRST_APPROVER_CERTIFICATE_HASH,
                &input,
            ),
            signature(
                READER_KEY_ESCROW_SECOND_APPROVER_ED25519_SEED,
                SECOND_APPROVER_CERTIFICATE_HASH,
                &input,
            ),
        ]
    };
    let signed =
        |exact_payload: &[u8]| handmade_object(subtype, exact_payload, &approvers(exact_payload));

    // `purpose` steht als `0x00` direkt vor `issued-at` (`0x1b` + 8 Byte).
    let mut issued_field = vec![0x1b];
    issued_field.extend_from_slice(&RECOVERY_ISSUED_AT_MS.to_be_bytes());
    let mut purpose_zero = vec![0x00];
    purpose_zero.extend_from_slice(&issued_field);
    let mut purpose_one = vec![0x01];
    purpose_one.extend_from_slice(&issued_field);
    let expires_field = |lifetime: i64| {
        let mut field = vec![0x1b];
        field.extend_from_slice(&(RECOVERY_ISSUED_AT_MS + lifetime).to_be_bytes());
        field
    };
    let mut short_escrow_hash_from = vec![0x58, 0x20];
    short_escrow_hash_from.extend_from_slice(chain.recovery_core.escrow_object_hash.as_bytes());
    let mut short_escrow_hash_to = vec![0x58, 0x1f];
    short_escrow_hash_to
        .extend_from_slice(&chain.recovery_core.escrow_object_hash.as_bytes()[..31]);

    let restore_info = hpke_info(&chain.restore_context);
    let restore_aad = hpke_aad(&chain.restore_context);
    let mut restore_sealed = fixed::<32>(RESTORE_ENCAPSULATED_KEY).to_vec();
    restore_sealed.extend_from_slice(&fixed::<48>(RESTORE_CIPHERTEXT));
    let mut transport_from = vec![0x58, 0x20];
    transport_from.extend_from_slice(
        chain
            .recovery_core
            .target_transport_key_thumbprint
            .as_bytes(),
    );
    let mut transport_to = vec![0x58, 0x20];
    transport_to.extend_from_slice(x25519_thumbprint([0xe4; 32]).as_bytes());
    let changed_transport = replace_once(&chain.restore_context, &transport_from, &transport_to);

    let entries = vec![
        entry(
            "object/accepted-recovery-authorization",
            OBJECT_SCHEMA_ID,
            generator(),
            Vec::new(),
            digest_map(&[(
                "trust-digest",
                *trust_digest(chain.recovery_payload.exact_digest_input()).as_bytes(),
            )]),
            chain.recovery_bytes.clone(),
            ExpectedOutcome::Accepted,
            Some(ACCEPTED_OBJECT_SCOPE),
        ),
        object_entry(
            "object/rejected-recovery-authorization-with-one-signature",
            handmade_object(subtype, &payload, &chain.recovery_signatures[..1]),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-recovery-authorization-core-with-sixteen-elements",
            signed(&without_extension_slot(&payload)),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-recovery-authorization-purpose-one",
            signed(&replace_once(&payload, &purpose_zero, &purpose_one)),
            rejected(TAG_MISMATCH),
        ),
        object_entry(
            "object/rejected-recovery-authorization-lifetime-over-limit",
            signed(&replace_once(
                &payload,
                &expires_field(RECOVERY_LIFETIME_MS),
                &expires_field(
                    ea_crypto::READER_KEY_ESCROW_RECOVERY_AUTHORIZATION_MAX_LIFETIME_MS + 1,
                ),
            )),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-recovery-authorization-lifetime-zero",
            signed(&replace_once(
                &payload,
                &expires_field(RECOVERY_LIFETIME_MS),
                &expires_field(0),
            )),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-recovery-authorization-escrow-object-hash-short",
            signed(&replace_once(
                &payload,
                &short_escrow_hash_from,
                &short_escrow_hash_to,
            )),
            rejected(SHAPE),
        ),
        object_entry(
            "object/rejected-recovery-authorization-signature-over-neighbour-subtype",
            handmade_object(
                subtype,
                &payload,
                &[
                    signature(
                        READER_KEY_ESCROW_FIRST_APPROVER_ED25519_SEED,
                        FIRST_APPROVER_CERTIFICATE_HASH,
                        &digest_input(TrustSubtypeV1::ReaderKeyEscrow.as_str(), &payload),
                    ),
                    signature(
                        READER_KEY_ESCROW_SECOND_APPROVER_ED25519_SEED,
                        SECOND_APPROVER_CERTIFICATE_HASH,
                        &digest_input(TrustSubtypeV1::ReaderKeyEscrow.as_str(), &payload),
                    ),
                ],
            ),
            rejected(COSE),
        ),
        entry(
            "context/restore-hpke-info",
            RESTORE_CONTEXT_SCHEMA_ID,
            generator(),
            chain.restore_context.clone(),
            digest_map(&[("context", sha256(&chain.restore_context))]),
            restore_info.clone(),
            ExpectedOutcome::Accepted,
            None,
        ),
        entry(
            "context/restore-hpke-aad",
            RESTORE_CONTEXT_SCHEMA_ID,
            generator(),
            chain.restore_context.clone(),
            digest_map(&[("context", sha256(&chain.restore_context))]),
            restore_aad.clone(),
            ExpectedOutcome::Accepted,
            None,
        ),
        entry(
            "hpke/accepted-restore-opens",
            HPKE_SEALED_SCHEMA_ID,
            frozen_once(),
            READER_KEY_ESCROW_READER_KEM_X25519_SEED.to_vec(),
            digest_map(&[
                ("infoDigest", sha256(&restore_info)),
                ("aadDigest", sha256(&restore_aad)),
                (
                    "recipientPublicKeyThumbprint",
                    *chain
                        .recovery_core
                        .target_transport_key_thumbprint
                        .as_bytes(),
                ),
            ]),
            restore_sealed.clone(),
            ExpectedOutcome::Accepted,
            Some(
                "Die Öffnungsantwort an den Ziel-Transportschlüssel, einmal erzeugt; \
                 nachgeprüft über hpke_open mit dem aus Autorisierung und Objekthash \
                 abgeleiteten Kontext. Die Antwort ist keine Trust-Familie.",
            ),
        ),
        entry(
            "hpke/rejected-restore-with-changed-transport-key",
            HPKE_SEALED_SCHEMA_ID,
            frozen_once(),
            changed_transport,
            BTreeMap::new(),
            restore_sealed,
            rejected(HPKE_OPEN),
            Some(
                "Die Eingabebytes sind der Kontext mit einem anderen \
                 Transportschlüsselabdruck; dieselbe Antwort darf unter ihm nicht öffnen.",
            ),
        ),
    ];

    VectorManifest {
        family: READER_KEY_ESCROW_RECOVERY_FAMILY.to_owned(),
        version: READER_KEY_ESCROW_V1_VERSION.to_owned(),
        entries,
    }
}

/// Versiegelt `plaintext` an `recipient` unter `context` in der Hausform.
///
/// Nur für den Einfrierlauf: `hpke_seal` zieht frische Entropie.
#[cfg(test)]
fn seal_under(recipient_seed: [u8; 32], plaintext: [u8; 32], context: &[u8]) -> [u8; 80] {
    let recipient = ea_crypto::HpkeRecipientPublicKey::from_bytes(x25519_public(recipient_seed))
        .expect("a derived X25519 key loads");
    let sealed = ea_crypto::hpke_seal(
        &recipient,
        &SecretBytes::new(plaintext),
        &hpke_info(context),
        &hpke_aad(context),
    )
    .expect("sealing a declared key cannot fail");
    let mut bytes = [0; 80];
    bytes[..32].copy_from_slice(sealed.encapsulated_key());
    bytes[32..].copy_from_slice(sealed.wrapped_cek());
    bytes
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, path::Path};

    use ea_crypto::{
        HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, hpke_aad, hpke_info, hpke_open,
    };

    use super::{
        EscrowChain, READER_KEY_ESCROW_APPROVAL_V1_ROOT,
        READER_KEY_ESCROW_FIRST_APPROVER_ED25519_SEED, READER_KEY_ESCROW_READER_KEM_X25519_SEED,
        READER_KEY_ESCROW_RECOVERY_V1_ROOT, READER_KEY_ESCROW_SECOND_APPROVER_ED25519_SEED,
        READER_KEY_ESCROW_TRANSPORT_X25519_SEED, READER_KEY_ESCROW_V1_ROOT, escrow_chain,
        frozen_escrow_chain, reader_key_escrow_approval_v1_manifest,
        reader_key_escrow_recovery_v1_manifest, reader_key_escrow_v1_manifest, seal_under,
    };
    use crate::{
        DECLARED_TEST_ENTROPY, ExpectedOutcome, MANIFEST_FILE_NAME,
        TEST_ENTROPY_RECIPIENT_X25519_SEED, VectorManifest, verify_manifest_at,
    };

    fn workspace_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// Eine Familie: ihre Wurzel und ihr Erzeuger.
    type Family = (&'static str, fn() -> VectorManifest);

    fn families() -> [Family; 3] {
        [
            (READER_KEY_ESCROW_V1_ROOT, reader_key_escrow_v1_manifest),
            (
                READER_KEY_ESCROW_APPROVAL_V1_ROOT,
                reader_key_escrow_approval_v1_manifest,
            ),
            (
                READER_KEY_ESCROW_RECOVERY_V1_ROOT,
                reader_key_escrow_recovery_v1_manifest,
            ),
        ]
    }

    /// Erzeugt die beiden HPKE-Kapselungen EINMAL und druckt die vier Werte.
    ///
    /// `#[ignore]`, weil `hpke_seal` frische Entropie zieht: jeder Lauf liefert
    /// andere Bytes. Der dokumentierte Erzeugungslauf ist
    /// `cargo test -p ea-testkit -- --ignored --nocapture freeze_reader_key_escrow_encapsulations`;
    /// seine Ausgabe wird in die vier Konstanten übernommen und danach NIE
    /// wieder erzeugt. Die Öffnungsantwort bindet die Objekthashes, deshalb
    /// entsteht sie aus der Kette DIESES Laufs.
    #[test]
    #[ignore = "draws fresh entropy; run deliberately to freeze the encapsulations"]
    fn freeze_reader_key_escrow_encapsulations() {
        let context = escrow_chain([0; 32], [0; 48]).hpke_context;
        let escrow = seal_under(
            TEST_ENTROPY_RECIPIENT_X25519_SEED,
            READER_KEY_ESCROW_READER_KEM_X25519_SEED,
            &context,
        );
        let chain = escrow_chain(
            escrow[..32].try_into().unwrap(),
            escrow[32..].try_into().unwrap(),
        );
        assert_eq!(
            chain.hpke_context, context,
            "the context ignores enc and ct"
        );
        let restore = seal_under(
            READER_KEY_ESCROW_TRANSPORT_X25519_SEED,
            READER_KEY_ESCROW_READER_KEM_X25519_SEED,
            &chain.restore_context,
        );
        println!("ESCROW_ENCAPSULATED_KEY = {}", hex::encode(&escrow[..32]));
        println!(
            "ESCROW_ENCRYPTED_READER_KEM_KEY = {}",
            hex::encode(&escrow[32..])
        );
        println!("RESTORE_ENCAPSULATED_KEY = {}", hex::encode(&restore[..32]));
        println!("RESTORE_CIPHERTEXT = {}", hex::encode(&restore[32..]));
    }

    /// Die eingefrorenen Kapselungen öffnen unter der AKTUELLEN Kette. Fällt
    /// dieser Test, hat jemand eine deterministische Konstante geändert, ohne
    /// neu einzufrieren.
    #[test]
    fn the_frozen_encapsulations_open_under_the_current_chain() {
        let chain: EscrowChain = frozen_escrow_chain();
        let recovery = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(
            TEST_ENTROPY_RECIPIENT_X25519_SEED,
        ))
        .unwrap();
        let sealed = HpkeSealed::from_parts(
            chain.core.encapsulated_key,
            chain.core.encrypted_reader_kem_key,
        )
        .unwrap();
        let opened = hpke_open(
            &recovery,
            &sealed,
            &hpke_info(&chain.hpke_context),
            &hpke_aad(&chain.hpke_context),
        )
        .expect("the frozen escrow opens under its derived context");
        assert!(opened.matches(&READER_KEY_ESCROW_READER_KEM_X25519_SEED));

        let transport = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(
            READER_KEY_ESCROW_TRANSPORT_X25519_SEED,
        ))
        .unwrap();
        let manifest = reader_key_escrow_recovery_v1_manifest();
        let restore = manifest
            .entries
            .iter()
            .find(|entry| entry.name == "hpke/accepted-restore-opens")
            .unwrap();
        let sealed = HpkeSealed::from_parts(
            restore.object_bytes[..32].try_into().unwrap(),
            restore.object_bytes[32..].try_into().unwrap(),
        )
        .unwrap();
        let opened = hpke_open(
            &transport,
            &sealed,
            &hpke_info(&chain.restore_context),
            &hpke_aad(&chain.restore_context),
        )
        .expect("the frozen restore answer opens under its derived context");
        assert!(opened.matches(&READER_KEY_ESCROW_READER_KEM_X25519_SEED));
    }

    /// Schreibt die drei Familien in den Arbeitsbaum.
    ///
    /// `#[ignore]`, weil dieser Test SCHREIBT:
    /// `cargo test -p ea-testkit -- --ignored emit_reader_key_escrow_vectors`.
    /// Ab dem Einfriercommit sind die eingecheckten Bytes die Autorität; eine
    /// spätere Verhaltensänderung legt `v2/` DANEBEN.
    #[test]
    #[ignore = "writes into the working tree; run deliberately to regenerate"]
    fn emit_reader_key_escrow_vectors() {
        for (relative, manifest) in families() {
            let root = workspace_root().join(relative);
            manifest().emit(&root).unwrap();
            assert!(verify_manifest_at(&root).unwrap().is_clean());
        }
    }

    /// Jedes eingecheckte Manifest ist genau die Ausgabe seines Erzeugers.
    #[test]
    fn the_committed_reader_key_escrow_families_match_their_generators() {
        for (relative, manifest) in families() {
            let root = workspace_root().join(relative);
            let text = fs::read_to_string(root.join(MANIFEST_FILE_NAME))
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", root.display()));
            assert_eq!(
                text,
                manifest().to_json().unwrap(),
                "{relative}: the committed manifest must be byte-identical to the generator output"
            );
            let report = verify_manifest_at(&root).unwrap();
            assert!(report.is_clean(), "{relative}: {:?}", report.mismatches);
        }
    }

    /// Die Vektorhygiene, die die eigenen Familien begründet: kein
    /// Eintragsname und keine Notiz trägt eines der drei Literale. Dazu
    /// Anzahl, kebab-case und Determinismus.
    #[test]
    fn the_reader_key_escrow_generators_keep_their_names_free_of_the_subtype_literals() {
        for ((relative, manifest), (family, count, accepted)) in families().into_iter().zip([
            ("reader-key-escrow", 14, 6),
            ("reader-key-escrow-approval", 11, 2),
            ("reader-key-escrow-recovery", 12, 4),
        ]) {
            let generated = manifest();
            assert_eq!(generated.family, family, "{relative}");
            assert_eq!(generated.version, "v1");
            assert_eq!(generated.entries.len(), count, "{relative}");
            let names = generated
                .entries
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<BTreeSet<_>>();
            assert_eq!(names.len(), count, "{relative}");
            assert_eq!(
                generated
                    .entries
                    .iter()
                    .filter(|entry| entry.expected_outcome == ExpectedOutcome::Accepted)
                    .count(),
                accepted,
                "{relative}"
            );
            for entry in &generated.entries {
                assert_eq!(entry.file, format!("{}.bin", entry.name));
                assert!(
                    entry.name.chars().all(|value| value.is_ascii_lowercase()
                        || value.is_ascii_digit()
                        || value == '-'
                        || value == '/'),
                    "{} must stay kebab-case",
                    entry.name
                );
            }
            let text = generated.to_json().unwrap();
            assert!(
                !text.contains("readerKeyEscrow"),
                "{relative}: the subtype literals live in the hex recorded object bytes only"
            );
            assert_eq!(
                text,
                manifest().to_json().unwrap(),
                "{relative} is deterministic"
            );
        }
    }

    /// Die deklarierte Testentropie dieser Familien fällt mit keiner anderen
    /// Rolle zusammen.
    #[test]
    fn reader_key_escrow_seeds_are_distinct() {
        let local: [&[u8]; 4] = [
            &READER_KEY_ESCROW_READER_KEM_X25519_SEED,
            &READER_KEY_ESCROW_TRANSPORT_X25519_SEED,
            &READER_KEY_ESCROW_FIRST_APPROVER_ED25519_SEED,
            &READER_KEY_ESCROW_SECOND_APPROVER_ED25519_SEED,
        ];
        let mut seen = BTreeSet::new();
        for material in local
            .into_iter()
            .chain(DECLARED_TEST_ENTROPY.iter().map(|(_, material)| *material))
        {
            assert!(seen.insert(material.to_vec()), "declared entropy repeats");
        }
    }
}
