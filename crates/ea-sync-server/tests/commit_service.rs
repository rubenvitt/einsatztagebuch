//! Die neun Schritte gegen Attrappen der Ports.
//!
//! # Was hier ECHT ist
//!
//! Alles, was der Commit-Pfad selbst entscheidet. Der Eintrag ist ein echtes
//! `.eip` mit echter Ed25519-Schreibersignatur, jeder Grant ein echtes `.eag`
//! mit echter Ausstellersignatur, der Plan ein echter `ea_format::GrantPlanV1`,
//! die Quittung eine echte `esr-v1` mit echter Serversignatur — und die
//! Signaturpruefung laeuft durch [`ea_crypto::verify_cose_sign1`], also durch
//! genau denselben Kode wie in der Produktion.
//!
//! # Was hier ATTRAPPE ist
//!
//! Die Ports: Uhr, Object Store, Commit-Transaktion, Security-Event-Senke und
//! die Kopfauswahl. Genau diese Attrappen sind der Zweck des Ziels — eine
//! Nebenlaeufigkeits- und Ausfallmatrix laesst sich gegen eine echte Datenbank
//! nicht in jeder Zwischenlage anhalten. Der Vertrag der echten
//! Commit-Transaktion steht in `apps/server/tests/migrations.rs` und wird hier
//! nicht ersetzt, sondern NACHGEBILDET; die Zusicherungen dieses Ziels gelten
//! dem Dienst darueber.
//!
//! # Warum die Zertifikatsbytes von Hand entstehen
//!
//! [`ea_crypto::verify_cose_sign1`] loest den Signierer ueber den Kopf auf und
//! braucht dafuer die exakten Bytes seines `deviceCertificate`. Die
//! VERTRAUENSKETTE dieses Zertifikats prueft ausschliesslich `ea-trust` — die
//! Aufloesung selbst ueberspringt die Zertifikatssignaturen ausdruecklich
//! (`crates/ea-crypto/src/cose.rs`, `parse_signer_certificate`). Ein
//! vollstaendiger Vertrauensabschluss waere hier deshalb Aufwand ohne Aussage:
//! er wird in `crates/ea-trust/tests` geprueft, und die Attrappe steht an
//! genau der Stelle, an der die Produktion den bereits GEPRUEFTEN Kopf
//! einsetzt. Was hier geprueft wird, sind die Schluessel und Rollen, die aus
//! diesen Bytes gelesen werden — und die sind echt.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use aws_sdk_s3::primitives::ByteStream;
use ea_crypto::{
    CanonicalPublicCoseKey, CoseSigner, CryptoError, HpkeRecipientPrivateKey, ResolvedSigner,
    SecretBytes, SignerCertificateResolver,
};
use ea_format::{
    CertificateKindV1, DeviceCertificateFieldsV1, GrantBodyFieldsV1, GrantBodyV1, GrantKindV1,
    GrantPlanItemV1, GrantPlanV1, GrantPurposeV1, GrantV1, KeyProtectionProfileV1,
    ManifestCoreFieldsV1, ManifestCoreV1, ObjectTypeV1, PolicyFieldsV1, SignedManifestV1,
    TrustPayloadV1, encode_grant,
};
use ea_sync_protocol::{EntryCommitRequestV1, TechnicalCursorSigner, TechnicalCursorVerifier};
use ea_sync_server::{
    ActiveRegistryHeadV1, ChainHeadStateV1, CommitDbCommand, CommitRepository, CommittedDbState,
    ObjectStore, ObjectTypeDirectory, RegistryHeadDirectory, RegistryHeadSelectionV1,
    RepositoryError, SecurityEventV1, ServerClock, ServerSigner, StagedObject, StoreError,
    StoredObject,
    commit::{CommitOutcome, CommitPorts, CommitServiceError, commit_entry},
    reconcile::{ReconcileOutcomeV1, ReconcilePorts, reconcile_object},
    validation::CommitValidationError,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, Id16, KeyThumbprint, ObjectHash,
    OrganizationId, RegistryVersion, UnixMillis,
};

// ---------------------------------------------------------------------------
// Deklarierte Testentropie. Jede Rolle traegt ein eigenes Fuellbyte, damit eine
// Verwechslung sofort sichtbar wird statt still durchzulaufen.
// ---------------------------------------------------------------------------
const WRITER_SEED: [u8; 32] = [0x11; 32];
const SERVER_SEED: [u8; 32] = [0x12; 32];
const READER_KEM_SEED: [u8; 32] = [0x13; 32];
const RECOVERY_KEM_SEED: [u8; 32] = [0x14; 32];
const SECOND_READER_KEM_SEED: [u8; 32] = [0x15; 32];

const ORGANIZATION_ID: [u8; 16] = [0x21; 16];
const CHAIN_ID: [u8; 16] = [0x22; 16];
const WRITER_DEVICE_ID: [u8; 16] = [0x23; 16];
const READER_DEVICE_ID: [u8; 16] = [0x24; 16];
const RECOVERY_DEVICE_ID: [u8; 16] = [0x25; 16];
const SECOND_READER_DEVICE_ID: [u8; 16] = [0x26; 16];

const REGISTRY_VERSION: u64 = 3;
const REGISTRY_HEAD_HASH: [u8; 32] = [0x30; 32];
const POLICY_OBJECT_HASH: [u8; 32] = [0x31; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x32; 32];
const ADMIN_AUTHORIZATION_HASH: [u8; 32] = [0x33; 32];

fn organization_id() -> OrganizationId {
    OrganizationId::from(Id16::try_from(&ORGANIZATION_ID[..]).expect("16 bytes"))
}

fn chain_id() -> ChainId {
    ChainId::from(Id16::try_from(&CHAIN_ID[..]).expect("16 bytes"))
}

fn device_id(bytes: [u8; 16]) -> DeviceId {
    DeviceId::from(Id16::try_from(&bytes[..]).expect("16 bytes"))
}

fn hash32(bytes: [u8; 32]) -> ea_types::Hash32 {
    ea_types::Hash32::try_from(bytes.as_slice()).expect("32 bytes")
}

fn object_hash_of(bytes: [u8; 32]) -> ObjectHash {
    ObjectHash::try_from(bytes.as_slice()).expect("32 bytes")
}

fn signer(seed: [u8; 32]) -> CoseSigner {
    CoseSigner::from_secret(SecretBytes::new(seed))
}

fn signing_key(seed: [u8; 32]) -> CanonicalPublicCoseKey {
    signer(seed)
        .public_key()
        .expect("a declared Ed25519 seed yields a canonical public key")
}

fn kem_key(seed: [u8; 32]) -> CanonicalPublicCoseKey {
    let private =
        HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(seed)).expect("the seed loads");
    CanonicalPublicCoseKey::x25519(*private.public_key().as_bytes())
        .expect("a declared X25519 seed yields a canonical public key")
}

// ---------------------------------------------------------------------------
// Zertifikate
// ---------------------------------------------------------------------------

/// Die exakten `.etb`-Bytes eines `deviceCertificate`.
///
/// Die NUTZLAST entsteht ueber [`ea_format::TrustPayloadV1`] und wird nicht
/// nachgebaut — sie traegt die Felder, aus denen `ea-crypto` Rolle,
/// Capabilities und oeffentlichen Schluessel liest. Die Huelle ist das
/// Exact-Object-Praefix samt der Signaturliste, und die Signatur ist eine
/// leere Bytefolge: die Aufloesung ueberspringt sie, und ein
/// Vertrauensabschluss ist hier ausdruecklich nicht die Aussage (siehe
/// Modulkopf).
fn certificate_bytes(fields: &DeviceCertificateFieldsV1) -> Vec<u8> {
    let payload = TrustPayloadV1::authorized_device_certificate(
        fields.clone(),
        object_hash_of(ADMIN_AUTHORIZATION_HASH),
    )
    .expect("the device certificate payload is well formed");
    let mut bytes = Vec::with_capacity(payload.exact_payload().len() + 64);
    bytes.extend_from_slice(&ea_format::ETB_PREFIX_V1);
    bytes.push(0x83);
    // Der Subtyp als CBOR-Textkette fester Laenge.
    let subtype = b"deviceCertificate";
    bytes.push(0x60 | u8::try_from(subtype.len()).expect("the subtype is short"));
    bytes.extend_from_slice(subtype);
    bytes.extend_from_slice(payload.exact_payload());
    // Genau eine Signatur; die Aufloesung zaehlt sie und ueberspringt sie.
    bytes.push(0x81);
    bytes.push(0x40);
    bytes
}

fn writer_certificate_fields() -> DeviceCertificateFieldsV1 {
    DeviceCertificateFieldsV1 {
        organization_id: organization_id(),
        device_id: device_id(WRITER_DEVICE_ID),
        certificate_kind: CertificateKindV1::Writer,
        signing_public_cose_key: Some(signing_key(WRITER_SEED).to_deterministic_cbor()),
        kem_public_cose_key: None,
        signing_key_thumbprint: Some(signing_key(WRITER_SEED).thumbprint()),
        kem_key_thumbprint: None,
        capabilities: vec!["initialGrant".to_owned()],
        key_protection_profile: KeyProtectionProfileV1::OsWrapped,
        effective_from_sequence: ChainSequence::new(0),
        revoked_from_sequence: None,
        authority_subject_id: None,
    }
}

fn recipient_certificate_fields(
    kind: CertificateKindV1,
    device: [u8; 16],
    kem_seed: [u8; 32],
) -> DeviceCertificateFieldsV1 {
    DeviceCertificateFieldsV1 {
        organization_id: organization_id(),
        device_id: device_id(device),
        certificate_kind: kind,
        signing_public_cose_key: None,
        kem_public_cose_key: Some(kem_key(kem_seed).to_deterministic_cbor()),
        signing_key_thumbprint: None,
        kem_key_thumbprint: Some(kem_key(kem_seed).thumbprint()),
        capabilities: Vec::new(),
        key_protection_profile: KeyProtectionProfileV1::OsWrapped,
        effective_from_sequence: ChainSequence::new(0),
        revoked_from_sequence: None,
        authority_subject_id: None,
    }
}

fn reader_fields() -> DeviceCertificateFieldsV1 {
    recipient_certificate_fields(CertificateKindV1::Reader, READER_DEVICE_ID, READER_KEM_SEED)
}

fn second_reader_fields() -> DeviceCertificateFieldsV1 {
    recipient_certificate_fields(
        CertificateKindV1::Reader,
        SECOND_READER_DEVICE_ID,
        SECOND_READER_KEM_SEED,
    )
}

fn recovery_fields() -> DeviceCertificateFieldsV1 {
    recipient_certificate_fields(
        CertificateKindV1::RecoveryRecipient,
        RECOVERY_DEVICE_ID,
        RECOVERY_KEM_SEED,
    )
}

// ---------------------------------------------------------------------------
// Der Kopf
// ---------------------------------------------------------------------------

/// Ein Registry-Head, dessen aktive Menge der Test vorgibt.
///
/// Er steht an der Stelle, an der die Produktion
/// [`ea_trust::SelectedRegistryHead`] einsetzt, und antwortet mit derselben
/// Form. Er trifft KEINE Entscheidung: die Aussage, WELCHE Zertifikate aktiv
/// sind, gehoert dem Test, weil genau sie die Vollstaendigkeitspruefung
/// herausfordern soll.
struct FakeHead {
    certificates: Vec<(CertificateHash, DeviceCertificateFieldsV1, Vec<u8>)>,
    policy: PolicyFieldsV1,
}

impl FakeHead {
    fn new(fields: Vec<DeviceCertificateFieldsV1>, policy: PolicyFieldsV1) -> Self {
        let mut certificates: Vec<_> = fields
            .into_iter()
            .map(|fields| {
                let bytes = certificate_bytes(&fields);
                let hash = CertificateHash::from(ea_crypto::object_hash(&bytes));
                (hash, fields, bytes)
            })
            .collect();
        // Aufsteigend nach `CertificateHash` — dieselbe Ordnung, die
        // `SelectedRegistryHead::active_certificates` zusagt.
        certificates.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        Self {
            certificates,
            policy,
        }
    }

    fn certificate_hash_of(&self, device: [u8; 16]) -> CertificateHash {
        self.certificates
            .iter()
            .find(|(_, fields, _)| fields.device_id == device_id(device))
            .map(|(hash, _, _)| *hash)
            .expect("the fixture head carries this certificate")
    }
}

impl SignerCertificateResolver for FakeHead {
    fn resolve(
        &self,
        certificate_hash: CertificateHash,
        _bound_registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        let (_, fields, bytes) = self
            .certificates
            .iter()
            .find(|(hash, _, _)| *hash == certificate_hash)
            .ok_or(CryptoError::SignerUnauthorized)?;
        Ok(ResolvedSigner {
            exact_certificate_bytes: bytes,
            registry_effective_from_sequence: fields.effective_from_sequence,
            registry_revoked_from_sequence: fields.revoked_from_sequence,
            registry_revoked: false,
            root_line_accepted: true,
        })
    }
}

impl ActiveRegistryHeadV1 for FakeHead {
    fn registry_version(&self) -> RegistryVersion {
        RegistryVersion::new(REGISTRY_VERSION)
    }

    fn registry_head_hash(&self) -> ObjectHash {
        object_hash_of(REGISTRY_HEAD_HASH)
    }

    fn chain_id(&self) -> ChainId {
        chain_id()
    }

    fn policy_object_hash(&self) -> ObjectHash {
        object_hash_of(POLICY_OBJECT_HASH)
    }

    fn policy_fields(&self) -> &PolicyFieldsV1 {
        &self.policy
    }

    fn active_certificates(&self) -> Vec<(CertificateHash, &DeviceCertificateFieldsV1)> {
        self.certificates
            .iter()
            .map(|(hash, fields, _)| (*hash, fields))
            .collect()
    }
}

fn policy(operating_profile: u8, evidence_max_delay_ms: u64) -> PolicyFieldsV1 {
    PolicyFieldsV1 {
        organization_id: organization_id(),
        policy_version: 1,
        previous_policy_object_hash: None,
        operating_profile,
        max_registry_age_ms: 86_400_000,
        max_future_clock_skew_ms: 60_000,
        registry_expiry_behavior: 0,
        evidence_max_delay_ms,
        reader_inactivity_ms: 900_000,
        reader_trust_refresh_ms: 3_600_000,
        reader_history_access_allowed: false,
        allowed_archive_profile_hashes: Vec::new(),
        backup_frequency_ms: 86_400_000,
        restore_test_interval_ms: 2_592_000_000,
        retention_policy: ea_format::RetentionPolicyFieldsV1 {
            minimum_retention_ms: None,
            destruction_enabled: false,
            eds_privacy_decision_document_hash: None,
        },
        free_text_policy: ea_format::FreeTextPolicyFieldsV1 {
            free_text_allowed: false,
            rule_set_version: "1".to_owned(),
            local_pattern_warning_enabled: true,
        },
        allowed_crypto_suite_ids: vec![ea_crypto::SUITE_ID.to_owned()],
        allowed_format_versions: vec![1],
        effective_from_sequence: ChainSequence::new(0),
    }
}

/// Der Kopf des glueklichen Pfades: ein Writer, ein Reader, ein
/// Recovery-Empfaenger.
fn standard_head() -> Arc<FakeHead> {
    Arc::new(FakeHead::new(
        vec![
            writer_certificate_fields(),
            reader_fields(),
            recovery_fields(),
        ],
        policy(0, 500),
    ))
}

// ---------------------------------------------------------------------------
// Eintrag, Grants und Commit-Request
// ---------------------------------------------------------------------------

/// Ein Empfaenger des Plans: Abdruck, Zertifikat, Zweck.
#[derive(Clone, Copy)]
struct Recipient {
    kem_seed: [u8; 32],
    device: [u8; 16],
    purpose: GrantPurposeV1,
}

fn plan_of(head: &FakeHead, recipients: &[Recipient]) -> GrantPlanV1 {
    GrantPlanV1::new(
        recipients
            .iter()
            .map(|recipient| {
                GrantPlanItemV1::new(
                    kem_key(recipient.kem_seed).thumbprint(),
                    head.certificate_hash_of(recipient.device),
                    recipient.purpose,
                )
            })
            .collect(),
    )
    .expect("the fixture plan is well formed")
}

/// Ein echtes `.eip` mit echter Schreibersignatur.
fn entry_bytes(
    head: &FakeHead,
    sequence: u64,
    previous: Option<EntryHash>,
    plan: &GrantPlanV1,
    ciphertext_marker: u8,
) -> Vec<u8> {
    entry_bytes_with(
        head,
        sequence,
        previous,
        plan,
        ciphertext_marker,
        (RegistryVersion::new(REGISTRY_VERSION), REGISTRY_HEAD_HASH),
    )
}

/// Dasselbe `.eip`, aber mit ausdruecklich gesetztem Registry-Head.
fn entry_bytes_with(
    head: &FakeHead,
    sequence: u64,
    previous: Option<EntryHash>,
    plan: &GrantPlanV1,
    ciphertext_marker: u8,
    registry: (RegistryVersion, [u8; 32]),
) -> Vec<u8> {
    let ciphertext = vec![ciphertext_marker; 32];
    let manifest = ManifestCoreV1::new(
        ManifestCoreFieldsV1 {
            organization_id: organization_id(),
            chain_id: chain_id(),
            chain_sequence: ChainSequence::new(sequence),
            previous_entry_hash: previous,
            writer_certificate_hash: head.certificate_hash_of(WRITER_DEVICE_ID),
            writer_transition_event_hash: None,
            registry_version: registry.0,
            registry_head_hash: registry.1,
            initial_grant_plan_hash: *plan.hash().as_bytes(),
            nonce: [0x40; 12],
        },
        &ciphertext,
    )
    .expect("the fixture manifest is well formed");
    let signed = SignedManifestV1::new(manifest, &ciphertext)
        .expect("the fixture signed manifest is well formed");
    let signature = signer(WRITER_SEED)
        .sign_record(signed.exact_bytes())
        .expect("signing the fixture manifest cannot fail");
    let package = ea_format::EntryPackageV1::new(signed, ciphertext, signature)
        .expect("the fixture entry package is well formed");
    ea_format::encode_entry_package(&package)
        .expect("encoding the fixture entry cannot fail")
        .into_vec()
}

/// Ein echtes `.eag` mit echter Ausstellersignatur.
fn grant_bytes(head: &FakeHead, entry_hash: EntryHash, recipient: Recipient) -> Vec<u8> {
    let body = GrantBodyV1::new(GrantBodyFieldsV1 {
        organization_id: organization_id(),
        chain_id: chain_id(),
        entry_hash,
        kind: GrantKindV1::Initial,
        purpose: recipient.purpose,
        recipient_key_thumbprint: kem_key(recipient.kem_seed).thumbprint(),
        recipient_certificate_hash: head.certificate_hash_of(recipient.device),
        issuer_key_thumbprint: signing_key(WRITER_SEED).thumbprint(),
        issuer_certificate_hash: head.certificate_hash_of(WRITER_DEVICE_ID),
        registry_version: RegistryVersion::new(REGISTRY_VERSION),
        registry_head_hash: hash32(REGISTRY_HEAD_HASH),
        created_at_device: UnixMillis::new(1_700_000_000_000),
        original_recovery_grant_object_hash: None,
        grant_authorization_object_hash: None,
        // Kapselung und umschlossener CEK werden auf diesem Pfad NIE
        // geoeffnet: der Server ist blind. Sie sind hier deshalb Fuellbytes
        // fester Groesse und keine echte HPKE-Versiegelung.
        encapsulated_key: [recipient.device[0]; ea_crypto::HPKE_ENCAPSULATED_KEY_SIZE],
        wrapped_cek: [recipient.device[0]; ea_crypto::HPKE_WRAPPED_CEK_SIZE],
    })
    .expect("the fixture grant body is well formed");
    let signature = signer(WRITER_SEED)
        .sign_initial_grant(body.exact_bytes())
        .expect("signing the fixture grant cannot fail");
    let grant = GrantV1::new(body, signature).expect("the fixture grant is well formed");
    encode_grant(&grant)
        .expect("encoding the fixture grant cannot fail")
        .into_vec()
}

fn reader_recipient() -> Recipient {
    Recipient {
        kem_seed: READER_KEM_SEED,
        device: READER_DEVICE_ID,
        purpose: GrantPurposeV1::Reader,
    }
}

fn second_reader_recipient() -> Recipient {
    Recipient {
        kem_seed: SECOND_READER_KEM_SEED,
        device: SECOND_READER_DEVICE_ID,
        purpose: GrantPurposeV1::Reader,
    }
}

fn recovery_recipient() -> Recipient {
    Recipient {
        kem_seed: RECOVERY_KEM_SEED,
        device: RECOVERY_DEVICE_ID,
        purpose: GrantPurposeV1::Recovery,
    }
}

/// Ein Commit ueber genau diese Empfaengermenge.
fn commit_request(
    head: &FakeHead,
    sequence: u64,
    previous: Option<EntryHash>,
    recipients: &[Recipient],
    ciphertext_marker: u8,
) -> EntryCommitRequestV1 {
    let plan = plan_of(head, recipients);
    let entry = entry_bytes(head, sequence, previous, &plan, ciphertext_marker);
    let ea_format::ParsedArchiveObject::Entry(parsed) =
        ea_format::decode_exact_object(&entry).expect("the fixture entry parses")
    else {
        panic!("the fixture entry is an entry package");
    };
    let entry_hash = parsed.value().entry_hash();
    let grants = recipients
        .iter()
        .map(|recipient| grant_bytes(head, entry_hash, *recipient))
        .collect();
    EntryCommitRequestV1::new(entry, plan, grants).expect("the fixture commit request is valid")
}

/// Derselbe Commit, aber mit ausdruecklich gesetztem Registry-Head.
fn commit_request_with_registry(
    head: &FakeHead,
    sequence: u64,
    previous: Option<EntryHash>,
    recipients: &[Recipient],
    ciphertext_marker: u8,
    registry: (RegistryVersion, [u8; 32]),
) -> EntryCommitRequestV1 {
    let plan = plan_of(head, recipients);
    let entry = entry_bytes_with(head, sequence, previous, &plan, ciphertext_marker, registry);
    let ea_format::ParsedArchiveObject::Entry(parsed) =
        ea_format::decode_exact_object(&entry).expect("the fixture entry parses")
    else {
        panic!("the fixture entry is an entry package");
    };
    let entry_hash = parsed.value().entry_hash();
    let grants = recipients
        .iter()
        .map(|recipient| grant_bytes(head, entry_hash, *recipient))
        .collect();
    EntryCommitRequestV1::new(entry, plan, grants).expect("the fixture commit request is valid")
}

/// Der glueckliche Pfad: ein Reader und der verpflichtende Recovery-Empfaenger.
fn valid_commit(head: &FakeHead) -> EntryCommitRequestV1 {
    commit_request(
        head,
        0,
        None,
        &[reader_recipient(), recovery_recipient()],
        0xaa,
    )
}

// ---------------------------------------------------------------------------
// Die Attrappen der Ports
// ---------------------------------------------------------------------------

/// Eine Uhr, die der Test stellt.
struct FakeClock(Mutex<i64>);

impl FakeClock {
    fn at(millis: i64) -> Self {
        Self(Mutex::new(millis))
    }

    fn set(&self, millis: i64) {
        *self.0.lock().expect("the fixture clock is not poisoned") = millis;
    }
}

impl ServerClock for FakeClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(*self.0.lock().expect("the fixture clock is not poisoned"))
    }
}

/// Welcher Ausfall der Object Store gerade vortaeuscht.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum StoreFault {
    #[default]
    None,
    /// `put_if_absent` faellt aus — der Zustand VOR dem Commit.
    PutUnavailable,
    /// `get_exact` faellt aus — der Zustand NACH dem Commit.
    GetUnavailable,
    /// Die zurueckgelesenen Bytes sind andere als die abgelegten.
    CorruptOnRead,
}

/// Ein content-addressed Object Store im Speicher.
#[derive(Default)]
struct FakeObjectStore {
    objects: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
    staged: Mutex<BTreeMap<String, Vec<u8>>>,
    fault: Mutex<StoreFault>,
    /// Eine Adresse, unter der bereits ANDERE Bytes liegen sollen.
    planted_conflict: Mutex<Option<Vec<u8>>>,
}

impl FakeObjectStore {
    fn set_fault(&self, fault: StoreFault) {
        *self.fault.lock().expect("not poisoned") = fault;
    }

    fn fault(&self) -> StoreFault {
        *self.fault.lock().expect("not poisoned")
    }

    /// Legt unter der Adresse dieser Bytes ANDERE Bytes ab.
    fn plant_byte_conflict(&self, hash: ObjectHash) {
        *self.planted_conflict.lock().expect("not poisoned") = Some(hash.as_bytes().to_vec());
    }

    fn contains(&self, hash: ObjectHash) -> bool {
        self.objects
            .lock()
            .expect("not poisoned")
            .contains_key(hash.as_bytes().as_slice())
    }
}

#[async_trait::async_trait]
impl ObjectStore for FakeObjectStore {
    async fn stage_stream(
        &self,
        kind: ObjectTypeV1,
        body: ByteStream,
        limit: u64,
    ) -> Result<StagedObject, StoreError> {
        let bytes = body
            .collect()
            .await
            .map_err(|_| StoreError::Unavailable)?
            .into_bytes()
            .to_vec();
        let length = u64::try_from(bytes.len()).map_err(|_| StoreError::LimitExceeded)?;
        if length > limit {
            return Err(StoreError::LimitExceeded);
        }
        let hash = ea_crypto::object_hash(&bytes);
        let key = format!("staging/{}", hex::encode(hash.as_bytes()));
        self.staged
            .lock()
            .expect("not poisoned")
            .insert(key.clone(), bytes);
        Ok(StagedObject::new(kind, hash, length, key))
    }

    async fn put_if_absent(&self, staged: StagedObject) -> Result<StoredObject, StoreError> {
        if self.fault() == StoreFault::PutUnavailable {
            return Err(StoreError::Unavailable);
        }
        let bytes = self
            .staged
            .lock()
            .expect("not poisoned")
            .remove(staged.staging_key())
            .ok_or(StoreError::NotFound)?;
        let address = staged.object_hash().as_bytes().to_vec();
        if self
            .planted_conflict
            .lock()
            .expect("not poisoned")
            .as_ref()
            .is_some_and(|planted| *planted == address)
        {
            return Err(StoreError::HashConflict);
        }
        let mut objects = self.objects.lock().expect("not poisoned");
        match objects.get(&address) {
            Some(existing) if *existing != bytes => Err(StoreError::HashConflict),
            Some(_) => Ok(StoredObject::new(
                staged.kind(),
                staged.object_hash(),
                staged.size_bytes(),
                false,
            )),
            None => {
                objects.insert(address, bytes);
                Ok(StoredObject::new(
                    staged.kind(),
                    staged.object_hash(),
                    staged.size_bytes(),
                    true,
                ))
            }
        }
    }

    async fn get_exact(&self, hash: ObjectHash) -> Result<ByteStream, StoreError> {
        match self.fault() {
            StoreFault::GetUnavailable => return Err(StoreError::Unavailable),
            StoreFault::CorruptOnRead => return Ok(ByteStream::from(b"corrupt".to_vec())),
            _ => {}
        }
        let bytes = self
            .objects
            .lock()
            .expect("not poisoned")
            .get(hash.as_bytes().as_slice())
            .cloned()
            .ok_or(StoreError::NotFound)?;
        Ok(ByteStream::from(bytes))
    }

    /// Aus dem Namensraum, OHNE den Index zu befragen — genau wie der echte
    /// Adapter. Die Attrappe darf hier nicht bequemer sein als er: der echte
    /// `get_exact` loest die Art ueber den Index auf, und eine Waise hat dort
    /// keine Zeile.
    async fn get_exact_in(
        &self,
        _kind: ObjectTypeV1,
        hash: ObjectHash,
    ) -> Result<ByteStream, StoreError> {
        self.get_exact(hash).await
    }
}

/// Welcher Ausfall die Commit-Transaktion gerade vortaeuscht.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum CommitFault {
    #[default]
    None,
    /// Die Datenbank bricht ab, bevor irgendetwas sichtbar wird.
    Abort,
    /// Der Kopf hat sich unter der Sperre bewegt.
    HeadRace,
}

/// Ein sichtbar geschalteter Commit.
#[derive(Clone)]
struct StoredCommit {
    sequence: u64,
    entry_object_hash: ObjectHash,
    plan_hash: ea_types::Hash32,
    grants: Vec<ObjectHash>,
    receipt_object_hash: ObjectHash,
    accepted_at_server: UnixMillis,
}

/// Die Commit-Transaktion im Speicher.
///
/// Sie bildet den Vertrag von `commit_locked_head` NACH — Identitaetssuche VOR
/// der Sequenzpruefung, gemeinsame Sichtbarkeit, Rollback ohne Rest. Der
/// Vertrag selbst ist in `apps/server/tests/migrations.rs` gegen die echte
/// Datenbank geprueft; hier wird der DIENST DARUEBER geprueft.
#[derive(Default)]
struct FakeCommits {
    entries: Mutex<BTreeMap<Vec<u8>, StoredCommit>>,
    head: Mutex<Option<ChainHeadStateV1>>,
    fault: Mutex<CommitFault>,
    /// Gestellte Antworten fuer die naechsten SPERRFREIEN Kopfabfragen.
    ///
    /// Nur so laesst sich das Fenster zwischen Schritt 4 und der Sperre
    /// ueberhaupt betreten: der Dienst liest den Kopf ohne Sperre, und
    /// zwischen diesem Lesen und der Transaktion kann ein anderer Commit ihn
    /// vorziehen. Ohne diese Kulisse saehen Lesen und Transaktion IMMER
    /// denselben Stand, und die beiden Faelle waeren unerreichbar.
    staged_head_reads: Mutex<std::collections::VecDeque<Option<ChainHeadStateV1>>>,
}

impl FakeCommits {
    fn set_fault(&self, fault: CommitFault) {
        *self.fault.lock().expect("not poisoned") = fault;
    }

    fn visible_entry_count(&self) -> usize {
        self.entries.lock().expect("not poisoned").len()
    }

    /// Die naechste sperrfreie Kopfabfrage bekommt DIESEN Stand.
    fn stage_head_read(&self, state: Option<ChainHeadStateV1>) {
        self.staged_head_reads
            .lock()
            .expect("not poisoned")
            .push_back(state);
    }

    fn set_head(&self, state: Option<ChainHeadStateV1>) {
        *self.head.lock().expect("not poisoned") = state;
    }
}

#[async_trait::async_trait]
impl CommitRepository for FakeCommits {
    async fn head_state(
        &self,
        _organization_id: OrganizationId,
        _chain_id: ChainId,
    ) -> Result<Option<ChainHeadStateV1>, RepositoryError> {
        if let Some(staged) = self
            .staged_head_reads
            .lock()
            .expect("not poisoned")
            .pop_front()
        {
            return Ok(staged);
        }
        Ok(*self.head.lock().expect("not poisoned"))
    }

    async fn commit_locked_head(
        &self,
        command: CommitDbCommand,
    ) -> Result<CommittedDbState, RepositoryError> {
        match *self.fault.lock().expect("not poisoned") {
            CommitFault::Abort => return Err(RepositoryError::Unavailable),
            CommitFault::HeadRace => return Err(RepositoryError::HeadConflict),
            CommitFault::None => {}
        }
        let mut entries = self.entries.lock().expect("not poisoned");
        let mut head = self.head.lock().expect("not poisoned");

        // Die Identitaetssuche steht VOR jeder Sequenzpruefung — genau so wie
        // im Adapter. Ohne diese Reihenfolge waere kein Replay moeglich.
        if let Some(existing) = entries.get(command.identity.entry_hash.as_bytes().as_slice()) {
            if existing.entry_object_hash != command.identity.entry_object_hash
                || existing.plan_hash != command.identity.initial_grant_plan_hash
                || existing.grants != command.identity.initial_grant_object_hashes
                || existing.sequence != command.sequence.get()
            {
                return Err(RepositoryError::CommitIdentityConflict);
            }
            return Ok(CommittedDbState {
                sequence: ChainSequence::new(existing.sequence),
                entry_hash: command.identity.entry_hash,
                receipt_object_hash: existing.receipt_object_hash,
                accepted_at_server: existing.accepted_at_server,
                newly_committed: false,
            });
        }

        let expected_sequence = head.map_or(0, |state| state.sequence.get() + 1);
        if command.sequence.get() != expected_sequence
            || command.previous_entry_hash != head.map(|state| state.entry_hash)
            // Die Monotonie der Annahmezeit, unter derselben Sperre wie im
            // Adapter: ein Nachzuegler mit einer Zeit UNTER der des neuen
            // Vorgaengers hat ein Rennen verloren und darf nicht signiert
            // sichtbar werden.
            || head.is_some_and(|state| {
                command.accepted_at_server.get() < state.accepted_at_server.get()
            })
        {
            return Err(RepositoryError::HeadConflict);
        }

        entries.insert(
            command.identity.entry_hash.as_bytes().to_vec(),
            StoredCommit {
                sequence: command.sequence.get(),
                entry_object_hash: command.identity.entry_object_hash,
                plan_hash: command.identity.initial_grant_plan_hash,
                grants: command.identity.initial_grant_object_hashes.clone(),
                receipt_object_hash: command.receipt_object_hash,
                accepted_at_server: command.accepted_at_server,
            },
        );
        *head = Some(ChainHeadStateV1 {
            sequence: command.sequence,
            entry_hash: command.identity.entry_hash,
            accepted_at_server: command.accepted_at_server,
        });
        Ok(CommittedDbState {
            sequence: command.sequence,
            entry_hash: command.identity.entry_hash,
            receipt_object_hash: command.receipt_object_hash,
            accepted_at_server: command.accepted_at_server,
            newly_committed: true,
        })
    }
}

/// Die Security-Event-Senke im Speicher.
#[derive(Default)]
struct FakeSecurity(Mutex<Vec<(String, String)>>);

impl FakeSecurity {
    fn codes(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("not poisoned")
            .iter()
            .map(|(code, _)| code.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl ea_sync_server::SecurityEventSink for FakeSecurity {
    async fn record(&self, event: SecurityEventV1) -> Result<(), RepositoryError> {
        self.0
            .lock()
            .expect("not poisoned")
            .push((event.kind.code().to_owned(), event.subject));
        Ok(())
    }
}

/// Die Kopfauswahl im Speicher.
struct FakeHeads {
    outcome: Mutex<HeadOutcome>,
    /// Der Zeitpunkt, mit dem zuletzt gewaehlt wurde.
    last_instant: Mutex<Option<i64>>,
}

enum HeadOutcome {
    Selected(Arc<FakeHead>),
    /// Vor `at` der eine Kopf, ab `at` der andere.
    ///
    /// Die Kulisse fuer die Frage, WELCHEN Zeitpunkt Schritt 5 der Auswahl
    /// gibt: die rohe Serveruhr oder die Annahmezeit, die er gerade festgelegt
    /// hat. Ein Kopf, der erst ab einer Zeit gilt, ist in der Produktion nichts
    /// Exotisches — `not-before` steht in jedem `registryEvent`.
    Switching {
        before: Arc<FakeHead>,
        from: i64,
        after: Arc<FakeHead>,
    },
    PendingFuture,
    None,
}

impl FakeHeads {
    fn selecting(head: Arc<FakeHead>) -> Self {
        Self {
            outcome: Mutex::new(HeadOutcome::Selected(head)),
            last_instant: Mutex::new(None),
        }
    }

    fn last_instant(&self) -> Option<i64> {
        *self.last_instant.lock().expect("not poisoned")
    }

    fn set(&self, outcome: HeadOutcome) {
        *self.outcome.lock().expect("not poisoned") = outcome;
    }
}

#[async_trait::async_trait]
impl RegistryHeadDirectory for FakeHeads {
    async fn select_head_for_sequence(
        &self,
        _organization_id: OrganizationId,
        _proposed_sequence: ChainSequence,
        _now: UnixMillis,
    ) -> Result<RegistryHeadSelectionV1, ea_sync_server::AuthorityError> {
        *self.last_instant.lock().expect("not poisoned") = Some(_now.get());
        Ok(match &*self.outcome.lock().expect("not poisoned") {
            HeadOutcome::Selected(head) => {
                RegistryHeadSelectionV1::Selected(Arc::clone(head) as Arc<dyn ActiveRegistryHeadV1>)
            }
            HeadOutcome::Switching {
                before,
                from,
                after,
            } => {
                let chosen = if _now.get() < *from { before } else { after };
                RegistryHeadSelectionV1::Selected(
                    Arc::clone(chosen) as Arc<dyn ActiveRegistryHeadV1>
                )
            }
            HeadOutcome::PendingFuture => RegistryHeadSelectionV1::PendingFuture {
                required_registry_version: RegistryVersion::new(REGISTRY_VERSION + 1),
                required_registry_head_hash: object_hash_of([0x77; 32]),
            },
            HeadOutcome::None => RegistryHeadSelectionV1::NoApplicableHead,
        })
    }
}

/// Der Serverschluessel der Attrappe.
struct FakeSigner {
    signer: CoseSigner,
    public_key: CanonicalPublicCoseKey,
}

impl FakeSigner {
    fn new() -> Self {
        let signer = signer(SERVER_SEED);
        let public_key = signer.public_key().expect("the declared seed loads");
        Self { signer, public_key }
    }
}

impl ServerSigner for FakeSigner {
    fn certificate_hash(&self) -> CertificateHash {
        CertificateHash::try_from(SERVER_CERTIFICATE_HASH.as_slice()).expect("32 bytes")
    }

    fn key_thumbprint(&self) -> KeyThumbprint {
        self.public_key.thumbprint()
    }

    fn key_generation(&self) -> u32 {
        1
    }

    fn sign_receipt(&self, exact_receipt_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer.sign_receipt(exact_receipt_core)
    }

    fn sign_checkpoint(&self, exact_checkpoint_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer
            .sign_checkpoint(self.certificate_hash(), exact_checkpoint_core)
    }

    fn sign_challenge_response(&self, exact_challenge_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer.sign_challenge_response(exact_challenge_core)
    }
}

impl TechnicalCursorSigner for FakeSigner {
    fn sign_technical_cursor_digest(
        &self,
        digest: ea_types::Hash32,
    ) -> Result<Vec<u8>, CryptoError> {
        self.signer
            .sign_technical_cursor(self.certificate_hash(), digest)
    }
}

impl TechnicalCursorVerifier for FakeSigner {
    fn verify_technical_cursor_digest(
        &self,
        digest: ea_types::Hash32,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        ea_crypto::verify_technical_cursor(
            signature,
            &self.public_key,
            self.certificate_hash(),
            digest,
        )
    }
}

/// Alles, was ein Testfall an Attrappen haelt.
struct Harness {
    head: Arc<FakeHead>,
    clock: FakeClock,
    signer: FakeSigner,
    objects: FakeObjectStore,
    commits: FakeCommits,
    heads: FakeHeads,
    security: FakeSecurity,
}

impl Harness {
    fn new() -> Self {
        Self::with_head(standard_head())
    }

    fn with_head(head: Arc<FakeHead>) -> Self {
        Self {
            heads: FakeHeads::selecting(Arc::clone(&head)),
            head,
            clock: FakeClock::at(1_700_000_000_000),
            signer: FakeSigner::new(),
            objects: FakeObjectStore::default(),
            commits: FakeCommits::default(),
            security: FakeSecurity::default(),
        }
    }

    fn ports(&self) -> CommitPorts<'_> {
        CommitPorts {
            clock: &self.clock,
            signer: &self.signer,
            objects: &self.objects,
            commits: &self.commits,
            heads: &self.heads,
            security: &self.security,
        }
    }

    async fn commit(
        &self,
        request: &EntryCommitRequestV1,
    ) -> Result<CommitOutcome, ea_sync_server::commit::CommitFailure> {
        let ports = self.ports();
        commit_entry(
            request,
            organization_id(),
            chain_id(),
            self.head.certificate_hash_of(WRITER_DEVICE_ID),
            &ports,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Die Zusicherungen
// ---------------------------------------------------------------------------

/// Der glueckliche Pfad: Eintrag, Grants und Quittung werden angenommen, und
/// die ausgelieferte Quittung ist die ZURUECKGELESENE.
#[tokio::test]
async fn a_complete_commit_is_accepted_and_returns_the_stored_receipt() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);
    let outcome = harness
        .commit(&request)
        .await
        .expect("a complete commit must be accepted");

    assert!(matches!(outcome, CommitOutcome::Accepted { .. }));
    assert_eq!(harness.commits.visible_entry_count(), 1);
    assert!(harness.security.codes().is_empty());

    // Die ausgelieferten Bytes sind ein gueltiges `.esr`, und sie stehen unter
    // ihrer eigenen Adresse im Object Store.
    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(outcome.receipt_bytes()).expect("the receipt parses")
    else {
        panic!("the response carries a receipt");
    };
    assert!(harness.objects.contains(receipt.object_hash()));
    assert!(receipt.value().core().fields().entry_hash == request.identity().entry_hash());
    // Standardprofil: keine Evidence-Frist.
    assert_eq!(receipt.value().core().fields().evidence_due_at, None);
}

/// Die EXAKTE aktive Empfaengermenge ist unteilbar: ein fehlender Reader und
/// ein ueberzaehliger werden beide abgewiesen, und nichts wird sichtbar.
///
/// Der ueberzaehlige Fall wird gemessen, indem DERSELBE Commit gegen einen
/// Kopf gefuehrt wird, der den zweiten Reader nicht mehr fuehrt. Ein Grant an
/// einen Empfaenger, den der Kopf gar nicht kennt, waere sonst gar nicht
/// baubar — und genau das ist der Punkt: die Menge gehoert dem Kopf.
#[tokio::test]
async fn exact_active_recipient_set_is_atomic() {
    // Der Kopf traegt ZWEI Reader; ein vollstaendiger Commit bedient beide.
    let wide = Arc::new(FakeHead::new(
        vec![
            writer_certificate_fields(),
            reader_fields(),
            second_reader_fields(),
            recovery_fields(),
        ],
        policy(0, 500),
    ));
    let narrow = Arc::new(FakeHead::new(
        vec![
            writer_certificate_fields(),
            reader_fields(),
            recovery_fields(),
        ],
        policy(0, 500),
    ));

    // 1. Ein FEHLENDER Reader: nur der erste Reader plus Recovery, gegen den
    //    breiten Kopf.
    let harness = Harness::with_head(Arc::clone(&wide));
    let missing = commit_request(
        &harness.head,
        0,
        None,
        &[reader_recipient(), recovery_recipient()],
        0xb1,
    );
    let failure = harness
        .commit(&missing)
        .await
        .expect_err("a missing reader grant must be rejected");
    assert_eq!(
        failure.error,
        CommitServiceError::Validation(CommitValidationError::GrantSetIncomplete)
    );
    assert_eq!(harness.commits.visible_entry_count(), 0);

    // 2. Der VOLLSTAENDIGE Satz gegen denselben Kopf traegt.
    let harness = Harness::with_head(Arc::clone(&wide));
    let complete = commit_request(
        &harness.head,
        0,
        None,
        &[
            reader_recipient(),
            second_reader_recipient(),
            recovery_recipient(),
        ],
        0xb2,
    );
    harness
        .commit(&complete)
        .await
        .expect("the complete recipient set must be accepted");

    // 3. Derselbe vollstaendige Satz gegen den SCHMALEN Kopf ist ein
    //    ueberzaehliger Grant.
    let harness = Harness::with_head(Arc::clone(&narrow));
    let request = commit_request(
        &wide,
        0,
        None,
        &[
            reader_recipient(),
            second_reader_recipient(),
            recovery_recipient(),
        ],
        0xb3,
    );
    let ports = harness.ports();
    let failure = commit_entry(
        &request,
        organization_id(),
        chain_id(),
        wide.certificate_hash_of(WRITER_DEVICE_ID),
        &ports,
    )
    .await
    .expect_err("a superfluous grant must be rejected");
    // Der schmale Kopf traegt DASSELBE Writer-Zertifikat — die Zertifikatsbytes
    // haengen nicht an der Kopfzusammensetzung —, also scheitert der Commit an
    // der Empfaengermenge und nicht am Schreiber.
    assert_eq!(
        failure.error,
        CommitServiceError::Validation(CommitValidationError::GrantSetIncomplete)
    );
    assert_eq!(harness.commits.visible_entry_count(), 0);

    // 4. Ein Kopf OHNE Recovery-Empfaenger ergibt gar keinen Plan: die Regel
    //    gehoert dem eingefrorenen Konstruktor und wird hier nicht
    //    zweitgeprueft.
    let head_without_recovery = FakeHead::new(
        vec![writer_certificate_fields(), reader_fields()],
        policy(0, 500),
    );
    assert!(
        GrantPlanV1::new(vec![GrantPlanItemV1::new(
            kem_key(READER_KEM_SEED).thumbprint(),
            head_without_recovery.certificate_hash_of(READER_DEVICE_ID),
            GrantPurposeV1::Reader,
        )])
        .is_err(),
        "a plan without a recovery recipient never comes into being"
    );
}

/// Faellt der Object Store NACH dem Commit aus, wird die Quittung NICHT
/// ausgeliefert — Schritt 9 ist keine Formsache.
#[tokio::test]
async fn an_object_store_fault_after_the_commit_withholds_the_receipt() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);
    harness.objects.set_fault(StoreFault::GetUnavailable);
    let failure = harness
        .commit(&request)
        .await
        .expect_err("a read-back fault must be reported");
    assert_eq!(failure.error, CommitServiceError::DependencyUnavailable);
    assert!(failure.error.retryable());
}

/// Derselbe Commit ein zweites Mal liefert BYTEGLEICH dieselbe Quittung — auch
/// wenn die Serveruhr inzwischen weitergelaufen ist.
#[tokio::test]
async fn identical_replay_returns_same_receipt_bytes() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);

    harness.clock.set(1_000);
    let first = harness
        .commit(&request)
        .await
        .expect("the first commit must be accepted");

    harness.clock.set(9_000);
    let second = harness
        .commit(&request)
        .await
        .expect("the identical commit must replay instead of failing");

    assert_eq!(first.receipt_bytes(), second.receipt_bytes());
    assert!(matches!(first, CommitOutcome::Accepted { .. }));
    assert!(matches!(second, CommitOutcome::IdempotentReplay { .. }));
    assert_eq!(harness.commits.visible_entry_count(), 1);
    // Ein Replay ist KEIN Security Event.
    assert!(harness.security.codes().is_empty());
}

/// Die Annahmezeit faellt je Kette nie zurueck, auch wenn die Serveruhr es
/// tut.
#[tokio::test]
async fn accepted_time_never_moves_backwards_along_the_chain() {
    let harness = Harness::new();
    harness.clock.set(5_000);
    let first = valid_commit(&harness.head);
    harness
        .commit(&first)
        .await
        .expect("the first commit must be accepted");

    // Die Uhr laeuft zurueck; der zweite Eintrag darf trotzdem nicht vor dem
    // ersten angenommen worden sein.
    harness.clock.set(1_000);
    let head_entry = harness
        .commits
        .head
        .lock()
        .expect("not poisoned")
        .expect("the head exists");
    let second = commit_request(
        &harness.head,
        1,
        Some(head_entry.entry_hash),
        &[reader_recipient(), recovery_recipient()],
        0xcc,
    );
    let outcome = harness
        .commit(&second)
        .await
        .expect("the successor must be accepted");
    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(outcome.receipt_bytes()).expect("the receipt parses")
    else {
        panic!("the response carries a receipt");
    };
    assert_eq!(
        receipt.value().core().fields().accepted_at_server,
        UnixMillis::new(5_000)
    );
}

/// Gleiche Sequenz mit anderem Eintrag: ein Fork, ein Security Event, und
/// nichts wird sichtbar.
#[tokio::test]
async fn a_fork_on_the_same_sequence_is_a_security_event() {
    let harness = Harness::new();
    harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect("the first commit must be accepted");

    // Ein ANDERER Eintrag auf derselben Sequenz null.
    let fork = commit_request(
        &harness.head,
        0,
        None,
        &[reader_recipient(), recovery_recipient()],
        0xdd,
    );
    let failure = harness
        .commit(&fork)
        .await
        .expect_err("a fork must be rejected");
    assert_eq!(failure.error, CommitServiceError::SequenceFork);
    assert_eq!(failure.error.code(), "EA-COMMIT-SEQUENCE-FORK");
    assert_eq!(failure.error.http_status(), 409);
    assert_eq!(harness.security.codes(), vec!["sequence-fork".to_owned()]);
    assert_eq!(harness.commits.visible_entry_count(), 1);
}

/// Der falsche Vorgaenger ist ein eigener Befund mit eigenem Security Event.
#[tokio::test]
async fn a_wrong_predecessor_is_its_own_security_event() {
    let harness = Harness::new();
    harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect("the first commit must be accepted");

    let wrong_predecessor = commit_request(
        &harness.head,
        1,
        Some(EntryHash::try_from(&[0x99; 32][..]).expect("32 bytes")),
        &[reader_recipient(), recovery_recipient()],
        0xee,
    );
    let failure = harness
        .commit(&wrong_predecessor)
        .await
        .expect_err("a wrong predecessor must be rejected");
    assert_eq!(failure.error, CommitServiceError::PredecessorMismatch);
    assert_eq!(failure.error.http_status(), 409);
    assert_eq!(
        harness.security.codes(),
        vec!["predecessor-mismatch".to_owned()]
    );
    assert_eq!(harness.commits.visible_entry_count(), 1);
}

/// Ein anderer Aufrufer als der im Manifest benannte Writer ist unzulaessig —
/// Security Event, `409`, und nichts wird sichtbar.
#[tokio::test]
async fn an_unauthorized_writer_is_a_security_event() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);
    let ports = harness.ports();
    let failure = commit_entry(
        &request,
        organization_id(),
        chain_id(),
        // Der Reader ist kein Writer.
        harness.head.certificate_hash_of(READER_DEVICE_ID),
        &ports,
    )
    .await
    .expect_err("a foreign writer must be rejected");

    assert_eq!(
        failure.error,
        CommitServiceError::Validation(CommitValidationError::WriterUnauthorized)
    );
    assert_eq!(failure.error.http_status(), 409);
    assert_eq!(
        harness.security.codes(),
        vec!["writer-unauthorized".to_owned()]
    );
    assert_eq!(harness.commits.visible_entry_count(), 0);
}

/// Ein Bytekonflikt im Object Store ist ein Security Event, und der Commit
/// bricht ab, bevor irgendetwas sichtbar wird.
#[tokio::test]
async fn a_byte_conflict_under_the_same_address_is_a_security_event() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);
    harness
        .objects
        .plant_byte_conflict(request.identity().entry_object_hash());

    let failure = harness
        .commit(&request)
        .await
        .expect_err("a byte conflict must be rejected");
    assert_eq!(failure.error, CommitServiceError::ObjectConflict);
    assert_eq!(failure.error.http_status(), 409);
    assert_eq!(
        harness.security.codes(),
        vec!["object-hash-conflict".to_owned()]
    );
    assert_eq!(harness.commits.visible_entry_count(), 0);
}

/// Ein Datenbankabbruch laesst NICHTS Sichtbares zurueck — und ist keine
/// Aussage ueber den Aufrufer.
#[tokio::test]
async fn a_database_abort_leaves_nothing_visible() {
    let harness = Harness::new();
    harness.commits.set_fault(CommitFault::Abort);
    let failure = harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect_err("an aborted transaction must be reported");
    assert_eq!(failure.error, CommitServiceError::DependencyUnavailable);
    assert_eq!(failure.error.http_status(), 503);
    assert!(failure.error.retryable());
    assert_eq!(harness.commits.visible_entry_count(), 0);
    assert!(harness.security.codes().is_empty());
}

/// Ein verlorenes Rennen um den Kopf ist `409` — und ausdruecklich KEIN
/// Security Event.
#[tokio::test]
async fn a_lost_head_race_is_a_conflict_without_a_security_event() {
    let harness = Harness::new();
    harness.commits.set_fault(CommitFault::HeadRace);
    let failure = harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect_err("a lost race must be reported");
    assert_eq!(failure.error, CommitServiceError::HeadConflict);
    assert_eq!(failure.error.http_status(), 409);
    assert!(
        harness.security.codes().is_empty(),
        "losing a race is not an accusation"
    );
    assert_eq!(harness.commits.visible_entry_count(), 0);
}

/// Ein Ausfall des Object Stores VOR dem Commit laesst nichts Sichtbares
/// zurueck.
#[tokio::test]
async fn an_object_store_fault_before_the_commit_leaves_nothing_visible() {
    let harness = Harness::new();
    harness.objects.set_fault(StoreFault::PutUnavailable);
    let failure = harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect_err("an object store fault must be reported");
    assert_eq!(failure.error, CommitServiceError::DependencyUnavailable);
    assert_eq!(harness.commits.visible_entry_count(), 0);
}

/// Schritt 9 ist keine Formsache: abweichende Bytes beim Zuruecklesen weisen
/// die Antwort ab, statt sie auszuliefern.
#[tokio::test]
async fn a_receipt_that_does_not_read_back_is_never_delivered() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);
    // Der Fehler tritt erst beim Zuruecklesen auf; alles davor gelingt.
    harness.objects.set_fault(StoreFault::CorruptOnRead);
    let failure = harness
        .commit(&request)
        .await
        .expect_err("a corrupt read-back must not be delivered");
    assert_eq!(
        failure.error,
        CommitServiceError::Receipt(ea_sync_server::receipt::ReceiptError::ReadBack)
    );
    assert_eq!(failure.error.code(), "EA-RECEIPT-READ-BACK");
}

/// Ein noch nicht anwendbarer Kopf ist `409` MIT der erforderlichen Version.
#[tokio::test]
async fn a_pending_future_head_names_the_required_registry_version() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);
    harness.heads.set(HeadOutcome::PendingFuture);
    let failure = harness
        .commit(&request)
        .await
        .expect_err("a pending future head must be reported");
    assert_eq!(failure.error, CommitServiceError::RegistryHeadRequired);
    assert_eq!(failure.error.http_status(), 409);
    assert_eq!(
        failure.required_registry_version,
        Some(RegistryVersion::new(REGISTRY_VERSION + 1))
    );
    assert!(failure.required_registry_head_hash.is_some());
    assert_eq!(harness.commits.visible_entry_count(), 0);
}

/// Ohne anwendbaren Kopf gibt es keine aktive Empfaengermenge — und damit
/// keinen Commit.
#[tokio::test]
async fn without_an_applicable_head_nothing_is_committed() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);
    harness.heads.set(HeadOutcome::None);
    let failure = harness
        .commit(&request)
        .await
        .expect_err("a missing head must be reported");
    assert_eq!(failure.error, CommitServiceError::NoApplicableRegistryHead);
    assert_eq!(failure.error.http_status(), 422);
    assert_eq!(harness.commits.visible_entry_count(), 0);
}

/// Ein Commit in eine ANDERE Kette als die des Pfades wird abgewiesen.
#[tokio::test]
async fn a_foreign_chain_in_the_path_is_rejected() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);
    let ports = harness.ports();
    let failure = commit_entry(
        &request,
        organization_id(),
        ChainId::from(Id16::try_from(&[0x7f; 16][..]).expect("16 bytes")),
        harness.head.certificate_hash_of(WRITER_DEVICE_ID),
        &ports,
    )
    .await
    .expect_err("a foreign chain must be rejected");
    assert_eq!(
        failure.error,
        CommitServiceError::Validation(CommitValidationError::ChainMismatch)
    );
    assert_eq!(harness.commits.visible_entry_count(), 0);
}

/// Das Evidence-Grade-Profil signiert die Frist EINMAL in die Quittung.
#[tokio::test]
async fn evidence_grade_binds_the_due_time_into_the_receipt() {
    let head = Arc::new(FakeHead::new(
        vec![
            writer_certificate_fields(),
            reader_fields(),
            recovery_fields(),
        ],
        policy(1, 600_000),
    ));
    let harness = Harness::with_head(head);
    harness.clock.set(1_700_000_000_000);
    let outcome = harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect("the commit must be accepted");
    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(outcome.receipt_bytes()).expect("the receipt parses")
    else {
        panic!("the response carries a receipt");
    };
    assert_eq!(
        receipt.value().core().fields().evidence_due_at,
        Some(UnixMillis::new(1_700_000_600_000))
    );
}

/// ECHT nebenlaeufig: vier gleichzeitige Erstcommits, und genau EINER gewinnt.
///
/// `tokio::spawn` und nicht eine Schleife mit `await`: eine Schleife misst
/// „ein zweiter Erstcommit wird abgewiesen", und das steht schon in
/// `a_fork_on_the_same_sequence_is_a_security_event`. Die Zusage dieses Falls
/// ist die NEBENLAEUFIGKEIT, und die entsteht nur, wenn die Aufgaben
/// tatsaechlich gleichzeitig laufen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_first_commits_leave_exactly_one_entry() {
    let harness = Arc::new(Harness::new());
    let requests: Vec<_> = (0..4)
        .map(|marker| {
            commit_request(
                &harness.head,
                0,
                None,
                &[reader_recipient(), recovery_recipient()],
                0xf0 + marker,
            )
        })
        .collect();

    let mut tasks = Vec::with_capacity(requests.len());
    for request in requests {
        let harness = Arc::clone(&harness);
        tasks.push(tokio::spawn(async move {
            harness.commit(&request).await.is_ok()
        }));
    }
    let mut accepted = 0;
    for task in tasks {
        if task.await.expect("no commit task may panic") {
            accepted += 1;
        }
    }

    assert_eq!(accepted, 1, "exactly one first commit wins the head");
    assert_eq!(harness.commits.visible_entry_count(), 1);
}

/// Ein VERALTETER Kopfstand kann niemals eine Quittung signieren, deren
/// Annahmezeit unter der ihres Vorgaengers liegt.
///
/// Der Fall, den Sequenz- und Vorgaengerpruefung allein NICHT fangen: der
/// Nachzuegler sitzt korrekt hinter dem Kopf, hat dessen Annahmezeit aber vor
/// dem Vorziehen gelesen. Die Monotonie wird deshalb unter der Sperre
/// geprueft, und der Verlierer bekommt ein RENNEN — keinen Vorwurf.
#[tokio::test]
async fn a_stale_head_read_can_never_sign_a_receipt_that_moves_time_backwards() {
    let harness = Harness::new();
    harness.clock.set(5_000);
    harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect("the first commit must be accepted");

    let stale = harness
        .commits
        .head
        .lock()
        .expect("not poisoned")
        .expect("the head exists");
    // Ein anderer Commit hat den Kopf inzwischen mit einer SPAETEREN
    // Annahmezeit vorgezogen — der Nachzuegler hier hat den alten Stand
    // gelesen und rechnet daraus eine zu kleine Zeit.
    harness.commits.set_head(Some(ChainHeadStateV1 {
        accepted_at_server: UnixMillis::new(12_000),
        ..stale
    }));
    harness.commits.stage_head_read(Some(stale));

    harness.clock.set(3_000);
    let successor = commit_request(
        &harness.head,
        1,
        Some(stale.entry_hash),
        &[reader_recipient(), recovery_recipient()],
        0xc1,
    );
    let failure = harness
        .commit(&successor)
        .await
        .expect_err("a receipt below the predecessor's accepted time must never be committed");
    assert_eq!(failure.error, CommitServiceError::HeadConflict);
    assert_eq!(failure.error.http_status(), 409);
    assert!(
        harness.security.codes().is_empty(),
        "losing this race is not an accusation"
    );
    assert_eq!(harness.commits.visible_entry_count(), 1);
}

/// Ein VERALTETER Kopfstand fuehrt zu keinem falschen Fork-Ereignis.
///
/// Bewegt sich der Kopf zwischen dem Lesen aus Schritt 4 und der Sperre, ist
/// jeder Vergleich gegen den alten Stand eine Anschuldigung ueber einen
/// Zustand, den es nicht mehr gibt. Die Zerlegung liest deshalb erneut und
/// faellt auf „Rennen verloren" zurueck.
#[tokio::test]
async fn a_head_that_moved_under_the_caller_is_a_race_and_not_a_fork() {
    let harness = Harness::new();
    // Der ECHTE Kopf steht weit vorn; der Aufrufer liest einen leeren Stand
    // und haelt sich fuer den Erstcommit.
    harness.commits.set_head(Some(ChainHeadStateV1 {
        sequence: ChainSequence::new(7),
        entry_hash: EntryHash::try_from(&[0x88; 32][..]).expect("32 bytes"),
        accepted_at_server: UnixMillis::new(20_000),
    }));
    harness.commits.stage_head_read(None);

    let failure = harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect_err("a moved head must be reported");
    assert_eq!(failure.error, CommitServiceError::HeadConflict);
    assert_eq!(failure.error.code(), "EA-COMMIT-HEAD-CONFLICT");
    assert!(
        harness.security.codes().is_empty(),
        "a moved head is a lost race, never a fork"
    );
    assert_eq!(harness.commits.visible_entry_count(), 0);
}

/// Kein Befund traegt einen fachlichen Wert, und die Codes sind stabil.
#[test]
fn every_service_code_is_stable_and_free_of_domain_values() {
    for error in CommitServiceError::ALL {
        let code = error.code();
        assert!(
            code.starts_with("EA-COMMIT-") || code.starts_with("EA-TRUST-"),
            "{code} must carry a stable technical prefix"
        );
        assert_eq!(
            error.retryable(),
            matches!(error.http_status(), 429 | 500 | 503)
        );
    }
    for error in CommitValidationError::ALL {
        assert!(error.code().starts_with("EA-COMMIT-"));
    }
}

/// Ein verworfener Receipt bleibt UNSICHTBAR: der Replay liefert den
/// gespeicherten, und der eben gebildete steht ohne Commit-Referenz da.
#[tokio::test]
async fn the_discarded_replay_receipt_stays_invisible() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);

    harness.clock.set(1_000);
    let first = harness.commit(&request).await.expect("accepted");
    harness.clock.set(9_000);
    let second = harness.commit(&request).await.expect("replayed");

    // Beide Antworten tragen dieselbe Quittung.
    assert_eq!(first.receipt_bytes(), second.receipt_bytes());
    // Und im Object Store liegen ZWEI Quittungen: die angenommene und die
    // verworfene. Die zweite ist eine zulaessige, unsichtbare Waise.
    let receipts = harness
        .objects
        .objects
        .lock()
        .expect("not poisoned")
        .values()
        .filter(|bytes| bytes.starts_with(&ea_format::ESR_PREFIX_V1))
        .count();
    assert_eq!(receipts, 2, "the discarded receipt stays as an orphan");
}

// ---------------------------------------------------------------------------
// Die unsichtbaren Waisen (`design.md` §13.3, vorletzter Absatz)
// ---------------------------------------------------------------------------

/// Der technische Objektindex als Attrappe.
///
/// Eine Zeile darin IST die atomare Commit-Referenz: sie entsteht in der
/// Produktion ausschliesslich in der Transaktion von Schritt 8.
#[derive(Default)]
struct FakeObjectTypes(Mutex<BTreeMap<Vec<u8>, ObjectTypeV1>>);

impl FakeObjectTypes {
    fn reference(&self, hash: ObjectHash, kind: ObjectTypeV1) {
        self.0
            .lock()
            .expect("not poisoned")
            .insert(hash.as_bytes().to_vec(), kind);
    }
}

#[async_trait::async_trait]
impl ObjectTypeDirectory for FakeObjectTypes {
    async fn object_type_of(
        &self,
        hash: ObjectHash,
    ) -> Result<Option<ObjectTypeV1>, RepositoryError> {
        Ok(self
            .0
            .lock()
            .expect("not poisoned")
            .get(hash.as_bytes().as_slice())
            .copied())
    }
}

/// Ein Objekt, dessen Bytes tragen und das eine Commit-Referenz nennt, wird
/// UEBERNOMMEN.
#[tokio::test]
async fn a_referenced_object_with_matching_bytes_is_adopted() {
    let harness = Harness::new();
    let outcome = harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect("the commit must be accepted");
    let hash = ea_crypto::object_hash(outcome.receipt_bytes());

    let types = FakeObjectTypes::default();
    types.reference(hash, ObjectTypeV1::Receipt);
    let ports = ReconcilePorts {
        clock: &harness.clock,
        objects: &harness.objects,
        object_types: &types,
        security: &harness.security,
    };
    assert_eq!(
        reconcile_object(hash, ObjectTypeV1::Receipt, organization_id(), &ports)
            .await
            .expect("the object is readable"),
        ReconcileOutcomeV1::Adopted
    );
    assert!(harness.security.codes().is_empty());
}

/// Ein Objekt OHNE Commit-Referenz bleibt eine unsichtbare Waise — und wird
/// ausdruecklich NICHT als angenommen ausgegeben.
#[tokio::test]
async fn an_unreferenced_object_stays_an_invisible_orphan() {
    let harness = Harness::new();
    let outcome = harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect("the commit must be accepted");
    let hash = ea_crypto::object_hash(outcome.receipt_bytes());

    // Der Index kennt das Objekt NICHT: genau der Zustand nach einem Absturz
    // vor dem Datenbank-Commit.
    let types = FakeObjectTypes::default();
    let ports = ReconcilePorts {
        clock: &harness.clock,
        objects: &harness.objects,
        object_types: &types,
        security: &harness.security,
    };
    assert_eq!(
        reconcile_object(hash, ObjectTypeV1::Receipt, organization_id(), &ports)
            .await
            .expect("the object is readable"),
        ReconcileOutcomeV1::InvisibleOrphan
    );
    // Eine Waise ist kein Angriff.
    assert!(harness.security.codes().is_empty());
}

/// Ein Objekt, dessen Inhalt seine Adresse NICHT traegt, wird
/// quarantaenisiert — und nie uebernommen, auch nicht mit Commit-Referenz.
#[tokio::test]
async fn bytes_that_do_not_carry_their_address_are_quarantined() {
    let harness = Harness::new();
    let outcome = harness
        .commit(&valid_commit(&harness.head))
        .await
        .expect("the commit must be accepted");
    let hash = ea_crypto::object_hash(outcome.receipt_bytes());

    let types = FakeObjectTypes::default();
    types.reference(hash, ObjectTypeV1::Receipt);
    harness.objects.set_fault(StoreFault::CorruptOnRead);
    let ports = ReconcilePorts {
        clock: &harness.clock,
        objects: &harness.objects,
        object_types: &types,
        security: &harness.security,
    };
    assert_eq!(
        reconcile_object(hash, ObjectTypeV1::Receipt, organization_id(), &ports)
            .await
            .expect("the object is readable"),
        ReconcileOutcomeV1::Quarantined
    );
    assert_eq!(
        harness.security.codes(),
        vec!["object-hash-conflict".to_owned()]
    );
}

/// Ein Objekt der FALSCHEN Familie wird quarantaenisiert, auch wenn seine
/// Bytes ihre Adresse tragen.
#[tokio::test]
async fn an_object_of_the_wrong_family_is_quarantined() {
    let harness = Harness::new();
    let request = valid_commit(&harness.head);
    harness
        .commit(&request)
        .await
        .expect("the commit must be accepted");

    let types = FakeObjectTypes::default();
    let ports = ReconcilePorts {
        clock: &harness.clock,
        objects: &harness.objects,
        object_types: &types,
        security: &harness.security,
    };
    // Der Eintrag liegt im Store, wird aber als Quittung erwartet.
    assert_eq!(
        reconcile_object(
            request.identity().entry_object_hash(),
            ObjectTypeV1::Receipt,
            organization_id(),
            &ports
        )
        .await
        .expect("the object is readable"),
        ReconcileOutcomeV1::Quarantined
    );
    assert_eq!(
        harness.security.codes(),
        vec!["object-hash-conflict".to_owned()]
    );
}

/// Ein Objekt, das gar nicht da ist, ist KEIN Urteil: der Befund ist ein
/// eigener Fehler und keine Quarantaene.
#[tokio::test]
async fn a_missing_object_is_a_finding_and_not_a_verdict() {
    let harness = Harness::new();
    let types = FakeObjectTypes::default();
    let ports = ReconcilePorts {
        clock: &harness.clock,
        objects: &harness.objects,
        object_types: &types,
        security: &harness.security,
    };
    let failure = reconcile_object(
        object_hash_of([0x5a; 32]),
        ObjectTypeV1::Receipt,
        organization_id(),
        &ports,
    )
    .await
    .expect_err("a missing object is a finding");
    assert_eq!(failure.code(), "EA-RECONCILE-NOT-FOUND");
    assert!(harness.security.codes().is_empty());
}

/// Schritt 5 waehlt den Kopf fuer die ANNAHMEZEIT, nicht fuer die rohe
/// Serveruhr.
///
/// `design.md`:1545 sagt „fuer diese Zeit und Sequenz", und „diese Zeit" ist
/// das `acceptedAtServer`, das derselbe Schritt gerade festgelegt hat. Die
/// beiden fallen genau dann auseinander, wenn die Annahmezeit des Vorgaengers
/// VOR der Uhr liegt — und dann waehlte die Uhr einen Kopf fuer einen
/// Zeitpunkt, den keine Quittung je traegt.
///
/// Gemessen wird die Wirkung und nicht nur der Parameter: die Kulisse fuehrt
/// ZWEI Koepfe mit verschiedenen Registry-Versionen, und der Eintrag bindet
/// den, der ab der Annahmezeit gilt. Waehlte der Dienst nach der Uhr, kaeme
/// der andere heraus und der Commit scheiterte an `RegistryMismatch`.
#[tokio::test]
async fn the_head_is_selected_for_the_accepted_time_and_not_the_raw_clock() {
    let early = standard_head();
    let late = Arc::new(FakeHead::new(
        vec![
            writer_certificate_fields(),
            reader_fields(),
            recovery_fields(),
        ],
        policy(0, 500),
    ));
    // Der spaetere Kopf traegt eine ANDERE Registry-Version, damit die Wahl
    // sichtbar wird.
    let harness = Harness::with_head(Arc::clone(&late));
    harness.heads.set(HeadOutcome::Switching {
        before: Arc::clone(&early),
        from: 8_000,
        after: Arc::clone(&late),
    });

    // Die Uhr steht VOR dem Umschaltpunkt; die Annahmezeit des Vorgaengers
    // liegt dahinter.
    harness.clock.set(3_000);
    harness.commits.set_head(Some(ChainHeadStateV1 {
        sequence: ChainSequence::new(0),
        entry_hash: EntryHash::try_from(&[0x66; 32][..]).expect("32 bytes"),
        accepted_at_server: UnixMillis::new(9_000),
    }));

    let request = commit_request(
        &harness.head,
        1,
        Some(EntryHash::try_from(&[0x66; 32][..]).expect("32 bytes")),
        &[reader_recipient(), recovery_recipient()],
        0xd1,
    );
    let outcome = harness
        .commit(&request)
        .await
        .expect("the commit binds the head that holds at the accepted time");

    assert_eq!(
        harness.heads.last_instant(),
        Some(9_000),
        "the selection ran at the accepted time, not at the clock"
    );
    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(outcome.receipt_bytes()).expect("the receipt parses")
    else {
        panic!("the response carries a receipt");
    };
    assert_eq!(
        receipt.value().core().fields().accepted_at_server,
        UnixMillis::new(9_000)
    );
}

/// Ein Paket, das einen NEUEREN Kopf bindet als der Server kennt, wird nicht
/// rueckwaerts geschickt.
///
/// Der Nachtrag fuehrt „erforderlicher neuerer Registry-Head" in der
/// 409-Zeile, und `required-registry-version` nennt die Version, die gelten
/// MUSS. Hinkt der SERVER, ist das die des Pakets: er muss sie erst lernen.
/// Ihm die eigene, aeltere zu nennen hiesse, den Aufrufer zu einem Kopf zu
/// schicken, den er nachweislich schon ueberholt hat.
#[tokio::test]
async fn a_bound_head_newer_than_the_server_knows_never_points_backwards() {
    let harness = Harness::new();
    let newer = REGISTRY_VERSION + 5;
    let request = commit_request_with_registry(
        &harness.head,
        0,
        None,
        &[reader_recipient(), recovery_recipient()],
        0xd2,
        (RegistryVersion::new(newer), [0x7e; 32]),
    );
    let failure = harness
        .commit(&request)
        .await
        .expect_err("a head the server does not know is never committed");

    assert_eq!(failure.error, CommitServiceError::RegistryHeadRequired);
    assert_eq!(failure.error.http_status(), 409);
    assert_eq!(
        failure.required_registry_version.map(RegistryVersion::get),
        Some(newer),
        "the caller is never told to go backwards"
    );
    assert_eq!(
        failure
            .required_registry_head_hash
            .map(|hash| hash.as_bytes().to_vec()),
        Some([0x7e; 32].to_vec())
    );
    assert_eq!(harness.commits.visible_entry_count(), 0);
}

/// Ein Paket, das einen AELTEREN Kopf bindet, bekommt den des Servers genannt
/// — und zwar mit `409`, nicht `422`.
#[tokio::test]
async fn a_bound_head_older_than_the_selected_one_names_the_servers_head() {
    let harness = Harness::new();
    let request = commit_request_with_registry(
        &harness.head,
        0,
        None,
        &[reader_recipient(), recovery_recipient()],
        0xd3,
        (RegistryVersion::new(REGISTRY_VERSION - 1), [0x7f; 32]),
    );
    let failure = harness
        .commit(&request)
        .await
        .expect_err("an older bound head is never committed");

    assert_eq!(
        failure.error,
        CommitServiceError::Validation(CommitValidationError::RegistryMismatch)
    );
    assert_eq!(
        failure.error.http_status(),
        409,
        "the addendum lists the required newer registry head in the 409 row"
    );
    assert_eq!(
        failure.required_registry_version.map(RegistryVersion::get),
        Some(REGISTRY_VERSION)
    );
    assert_eq!(
        failure
            .required_registry_head_hash
            .map(|hash| hash.as_bytes().to_vec()),
        Some(REGISTRY_HEAD_HASH.to_vec())
    );
    assert_eq!(harness.commits.visible_entry_count(), 0);
}
