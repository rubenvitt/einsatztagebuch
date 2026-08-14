mod support;

use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, CoseSigner, ProtectedHeader, SecretBytes, object_hash,
};
use ea_format::{
    CertificateKindV1, CheckpointCoreFieldsV1, CheckpointCoreV1, DecodedTrustPayloadV1,
    EvidenceObjectV1, Parsed, ParsedArchiveObject, ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1,
    decode_clock_release_audit, decode_exact_object, encode_evidence, encode_receipt,
};
use ea_time::{IndependentTimeInput, IndependentTimeKind, TrustedTimeState};
use ea_trust::{
    ClockReleaseError, ClockReleaseReplayKey, IndependentTimeCommit, LocalTimeBlock,
    PersistedTrustRecord, RegistryCandidate, RegistryHeadPin, RegistrySelectionCommit,
    StateStoreError, TrustError, TrustStateKey, TrustStateStore, VerifiedClockRelease,
    VerifiedSignedTime, prepare_local_time, verify_checkpoint_time, verify_clock_release,
    verify_receipt_time, verify_registry_candidate,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, Hash32, ObjectHash,
    OrganizationId, RegistryVersion, UnixMillis,
};
use ed25519_dalek::{Signer as _, SigningKey};
use minicbor::{Encoder, data::Tag};

use support::{ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder};

const INITIAL_REVISION: u64 = 17;
const ADMIN_ONE_SECRET: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];
const ADMIN_TWO_SECRET: [u8; 32] = [
    0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
    0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
];
const NEW_ADMIN_AND_SERVER_SECRET: [u8; 32] = [
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
];

#[derive(Clone, Copy)]
enum AuditSigner {
    First,
    Second,
    New,
}

impl AuditSigner {
    const fn secret(self) -> [u8; 32] {
        match self {
            Self::First => ADMIN_ONE_SECRET,
            Self::Second => ADMIN_TWO_SECRET,
            Self::New => NEW_ADMIN_AND_SERVER_SECRET,
        }
    }
}

#[derive(Clone)]
struct AuditFields {
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    admin_binding_hash: Option<ObjectHash>,
    signer_certificate_hash: ObjectHash,
    action: u8,
    outcome: u8,
    effective_now: UnixMillis,
    trusted_time_floor: UnixMillis,
    observed_os_wall_clock: UnixMillis,
    max_future_clock_skew_ms: u64,
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    guard_policy_object_hash: ObjectHash,
    independent_reference_kind: u8,
    independent_reference_hash: ObjectHash,
    independent_reference_time: UnixMillis,
    justification: u8,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    nonce: [u8; 32],
}

fn encode_clock_release_core(fields: &AuditFields) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(12)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&[0x01; 16])
        .unwrap()
        .bytes(fields.organization_id.as_bytes())
        .unwrap()
        .bytes(fields.target_device_id.as_bytes())
        .unwrap();
    if let Some(binding) = fields.admin_binding_hash {
        encoder.bytes(binding.as_bytes()).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder
        .bytes(fields.signer_certificate_hash.as_bytes())
        .unwrap()
        .u8(fields.action)
        .unwrap()
        .u8(fields.outcome)
        .unwrap()
        .i64(fields.effective_now.get())
        .unwrap()
        .array(2)
        .unwrap()
        .u8(2)
        .unwrap()
        .array(10)
        .unwrap()
        .i64(fields.trusted_time_floor.get())
        .unwrap()
        .i64(fields.observed_os_wall_clock.get())
        .unwrap()
        .u64(fields.max_future_clock_skew_ms)
        .unwrap()
        .u64(fields.registry_version.get())
        .unwrap()
        .bytes(fields.registry_head_hash.as_bytes())
        .unwrap()
        .bytes(fields.guard_policy_object_hash.as_bytes())
        .unwrap()
        .array(3)
        .unwrap()
        .u8(fields.independent_reference_kind)
        .unwrap()
        .bytes(fields.independent_reference_hash.as_bytes())
        .unwrap()
        .i64(fields.independent_reference_time.get())
        .unwrap()
        .u8(fields.justification)
        .unwrap()
        .i64(fields.issued_at.get())
        .unwrap()
        .i64(fields.expires_at.get())
        .unwrap()
        .bytes(&fields.nonce)
        .unwrap()
        .array(0)
        .unwrap();
    bytes
}

fn wrap_clock_release(exact_core: &[u8], exact_cose: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes).array(2).unwrap();
    bytes.extend_from_slice(exact_core);
    bytes.extend_from_slice(exact_cose);
    bytes
}

fn signed_clock_release(fields: &AuditFields, signer: AuditSigner) -> Vec<u8> {
    let exact_core = encode_clock_release_core(fields);
    let exact_cose = CoseSigner::from_secret(SecretBytes::new(signer.secret()))
        .sign_local_audit(&exact_core)
        .unwrap();
    wrap_clock_release(&exact_core, &exact_cose)
}

fn signed_with_content_type(
    fields: &AuditFields,
    signer: AuditSigner,
    content_type: ContentType,
) -> Vec<u8> {
    let exact_core = encode_clock_release_core(fields);
    let signing_key = SigningKey::from_bytes(&signer.secret());
    let public_key = CanonicalPublicCoseKey::ed25519(*signing_key.verifying_key().as_bytes())
        .expect("the fixture Ed25519 key must remain canonical");
    let protected = ProtectedHeader::normal(
        content_type,
        public_key.thumbprint(),
        CertificateHash::from(fields.signer_certificate_hash),
    );
    let signature = signing_key
        .sign(&protected.sig_structure_bytes(&exact_core))
        .to_bytes();
    let mut exact_cose = Vec::new();
    Encoder::new(&mut exact_cose)
        .tag(Tag::new(18))
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(&protected.to_deterministic_cbor())
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(&exact_core)
        .unwrap()
        .bytes(&signature)
        .unwrap();
    wrap_clock_release(&exact_core, &exact_cose)
}

fn raw_signed_wire_invalid_clock_release(fields: &AuditFields, signer: AuditSigner) -> Vec<u8> {
    signed_with_content_type(fields, signer, ContentType::LocalAuditCbor)
}

fn corrupt_signature(mut exact_audit: Vec<u8>) -> Vec<u8> {
    *exact_audit
        .last_mut()
        .expect("the signed audit wrapper cannot be empty") ^= 0x80;
    exact_audit
}

#[derive(Clone)]
struct ModelRecord {
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
}

impl ModelRecord {
    fn persisted(&self) -> PersistedTrustRecord {
        PersistedTrustRecord::new(self.revision, self.trusted_time.clone(), self.pinned_head)
    }
}

struct ModelStore {
    key: TrustStateKey,
    record: ModelRecord,
    consumed: bool,
    query_error: Option<StateStoreError>,
    independent_commits: usize,
    replay_queries: Vec<(OrganizationId, DeviceId, [u8; 32])>,
    registry_commits: usize,
}

impl ModelStore {
    fn new(
        key: TrustStateKey,
        trusted_time: TrustedTimeState,
        pinned_head: Option<RegistryHeadPin>,
    ) -> Self {
        Self {
            key,
            record: ModelRecord {
                revision: INITIAL_REVISION,
                trusted_time,
                pinned_head,
            },
            consumed: false,
            query_error: None,
            independent_commits: 0,
            replay_queries: Vec::new(),
            registry_commits: 0,
        }
    }
}

impl TrustStateStore for ModelStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(self.record.persisted())
    }

    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.independent_commits += 1;
        if key != self.key || expected_revision != self.record.revision {
            return Err(StateStoreError::Conflict);
        }
        self.record = ModelRecord {
            revision: expected_revision
                .checked_add(1)
                .ok_or(StateStoreError::MonotonicityViolation)?,
            trusted_time: commit.next_trusted_time().clone(),
            pinned_head: self.record.pinned_head,
        };
        Ok(self.record.persisted())
    }

    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.replay_queries
            .push((key.organization_id(), key.target_device_id(), *key.nonce()));
        if let Some(error) = self.query_error {
            return Err(error);
        }
        Ok(self.consumed)
    }

    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.registry_commits += 1;
        Err(StateStoreError::Unavailable)
    }
}

#[derive(Clone, Copy)]
enum SignedReferenceKind {
    Receipt,
    Checkpoint,
}

struct FlowFixture {
    candidate: RegistryCandidate,
    key: TrustStateKey,
    initial_time: TrustedTimeState,
    original_pin: RegistryHeadPin,
    sources: Vec<VerifiedSignedTime>,
    audit: AuditFields,
    signer: AuditSigner,
    candidate_core_hash: ObjectHash,
    guard_policy_core_hash: ObjectHash,
    independent_reference_core_hash: ObjectHash,
}

impl FlowFixture {
    fn store(&self) -> ModelStore {
        ModelStore::new(self.key, self.initial_time.clone(), Some(self.original_pin))
    }
}

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

fn device_id(marker: u8) -> DeviceId {
    DeviceId::try_from(&[marker; 16][..]).unwrap()
}

fn state_key(device: DeviceId) -> TrustStateKey {
    TrustStateKey {
        organization_id: support::organization(),
        device_id: device,
    }
}

fn chain_id() -> ChainId {
    ChainId::try_from(&[0x31; 16][..]).unwrap()
}

fn hash32_from_object(hash: ObjectHash) -> Hash32 {
    Hash32::try_from(hash.as_bytes().as_slice()).unwrap()
}

fn exact_trust_core_hash(line: &RegistryLineBuilder, outer_hash: ObjectHash) -> ObjectHash {
    let parsed = match decode_exact_object(line.exact_object_bytes(outer_hash)).unwrap() {
        ParsedArchiveObject::Trust(parsed) => parsed,
        _ => panic!("the fixture hash must address an exact Trust object"),
    };
    match parsed.value().decoded_payload().unwrap() {
        DecodedTrustPayloadV1::RegistryEvent(core) => object_hash(core.exact_core()),
        DecodedTrustPayloadV1::Policy(core) => object_hash(core.exact_core()),
        _ => panic!("the fixture hash must address a Registry Event or Policy"),
    }
}

fn server_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(
        *SigningKey::from_bytes(&NEW_ADMIN_AND_SERVER_SECRET)
            .verifying_key()
            .as_bytes(),
    )
    .unwrap()
}

fn receipt_source(
    candidate: &RegistryCandidate,
    authority_head: BuiltHead,
    server_certificate_hash: CertificateHash,
    verified_time: UnixMillis,
) -> (VerifiedSignedTime, ObjectHash, ObjectHash) {
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: support::organization(),
        chain_id: chain_id(),
        chain_sequence: authority_head.effective_from,
        entry_hash: EntryHash::from(support::hash32(0x61)),
        entry_object_hash: ObjectHash::from(support::hash32(0x62)),
        previous_entry_hash: Some(EntryHash::from(support::hash32(0x60))),
        registry_version: authority_head.version,
        registry_head_hash: hash32_from_object(authority_head.object_hash),
        policy_object_hash: ObjectHash::from(support::hash32(0x63)),
        initial_grant_plan_hash: support::hash32(0x64),
        initial_grant_object_hashes: vec![ObjectHash::from(support::hash32(0x65))],
        accepted_at_server: verified_time,
        evidence_due_at: None,
        server_key_thumbprint: server_key().thumbprint(),
        server_certificate_hash,
    })
    .unwrap();
    let core_hash = object_hash(core.exact_bytes());
    let signature = CoseSigner::from_secret(SecretBytes::new(NEW_ADMIN_AND_SERVER_SECRET))
        .sign_receipt(core.exact_bytes())
        .unwrap();
    let exact = encode_receipt(&ReceiptV1::new(core, signature).unwrap()).unwrap();
    let receipt: Parsed<ReceiptV1> = match decode_exact_object(exact.as_bytes()).unwrap() {
        ParsedArchiveObject::Receipt(receipt) => receipt,
        _ => panic!("the Clock Release fixture must retain an exact Receipt object"),
    };
    let object_hash = receipt.object_hash();
    let proof = verify_receipt_time(
        candidate
            .preexisting_authority()
            .expect("H4 must expose only its H3 authority"),
        &receipt,
    )
    .unwrap();
    (proof, object_hash, core_hash)
}

fn checkpoint_source(
    candidate: &RegistryCandidate,
    authority_head: BuiltHead,
    server_certificate_hash: CertificateHash,
    verified_time: UnixMillis,
) -> (VerifiedSignedTime, ObjectHash, ObjectHash) {
    let core = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: support::organization(),
        chain_id: chain_id(),
        covered_from_sequence: ChainSequence::new(0),
        covered_through_sequence: authority_head.effective_from,
        head_entry_hash: EntryHash::from(support::hash32(0x71)),
        registry_head_hash: hash32_from_object(authority_head.object_hash),
        issued_at_server: verified_time,
        previous_evidence_hash: Some(ObjectHash::from(support::hash32(0x72))),
    })
    .unwrap();
    let core_hash = object_hash(core.exact_bytes());
    let signature = CoseSigner::from_secret(SecretBytes::new(NEW_ADMIN_AND_SERVER_SECRET))
        .sign_checkpoint(server_certificate_hash, core.exact_bytes())
        .unwrap();
    let exact = encode_evidence(&EvidenceObjectV1::standard(core, signature).unwrap()).unwrap();
    let checkpoint: Parsed<EvidenceObjectV1> = match decode_exact_object(exact.as_bytes()).unwrap()
    {
        ParsedArchiveObject::Evidence(checkpoint) => checkpoint,
        _ => panic!("the Clock Release fixture must retain an exact Checkpoint object"),
    };
    let object_hash = checkpoint.object_hash();
    let proof = verify_checkpoint_time(
        candidate
            .preexisting_authority()
            .expect("H4 must expose only its H3 authority"),
        &checkpoint,
    )
    .unwrap();
    (proof, object_hash, core_hash)
}

fn successor_fixture(reference_kind: SignedReferenceKind, signer: AuditSigner) -> FlowFixture {
    successor_fixture_with(
        reference_kind,
        signer,
        100,
        UnixMillis::new(1_000),
        UnixMillis::new(900),
        UnixMillis::new(1_100),
        [0xd0; 32],
    )
}

fn successor_fixture_with(
    reference_kind: SignedReferenceKind,
    signer: AuditSigner,
    guard_skew: u64,
    floor: UnixMillis,
    verified_time: UnixMillis,
    os_wall_clock: UnixMillis,
    nonce: [u8; 32],
) -> FlowFixture {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    let server_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x66,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    let authority_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(39),
            policy_max_future_clock_skew_ms_override: Some(guard_skew),
            ..HeadOptions::default()
        },
    );
    let guard_policy_hash = line.current_policy_hash().unwrap();
    let candidate_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(30),
            valid_through: Some(49),
            policy_max_future_clock_skew_ms_override: Some(9_999),
            ..HeadOptions::default()
        },
    );
    let candidate_core_hash = exact_trust_core_hash(&line, candidate_head.object_hash);
    let guard_policy_core_hash = exact_trust_core_hash(&line, guard_policy_hash);
    let (target_device, admin_hash, binding_hash) = match signer {
        AuditSigner::First => (
            device_id(0x51),
            line.bootstrap_admin_hash(),
            line.bootstrap_admin_binding_hash(),
        ),
        AuditSigner::Second => (
            device_id(0x52),
            line.second_bootstrap_admin_hash(),
            line.second_bootstrap_admin_binding_hash(),
        ),
        AuditSigner::New => panic!("the ordinary successor uses only bootstrap Admins"),
    };
    let key = state_key(target_device);
    let initial_time = TrustedTimeState::initial(floor);
    let trust = line.verified_with_time_and_key(Pin::Head(2), initial_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(30)).unwrap();
    assert_eq!(candidate.registry_version(), RegistryVersion::new(4));
    assert!(candidate.registry_head_hash() == candidate_head.object_hash);
    let server_certificate_hash = CertificateHash::from(server_head.direct_object_hash.unwrap());
    let (proof, reference_hash, reference_core_hash, reference_tag) = match reference_kind {
        SignedReferenceKind::Receipt => {
            let (proof, hash, core_hash) = receipt_source(
                &candidate,
                authority_head,
                server_certificate_hash,
                verified_time,
            );
            (proof, hash, core_hash, 0)
        }
        SignedReferenceKind::Checkpoint => {
            let (proof, hash, core_hash) = checkpoint_source(
                &candidate,
                authority_head,
                server_certificate_hash,
                verified_time,
            );
            (proof, hash, core_hash, 1)
        }
    };
    FlowFixture {
        candidate,
        key,
        initial_time,
        original_pin: RegistryHeadPin::new(authority_head.version, authority_head.object_hash),
        sources: vec![proof],
        audit: AuditFields {
            organization_id: support::organization(),
            target_device_id: target_device,
            admin_binding_hash: Some(binding_hash),
            signer_certificate_hash: admin_hash,
            action: 6,
            outcome: 1,
            effective_now: os_wall_clock.max(floor),
            trusted_time_floor: floor,
            observed_os_wall_clock: os_wall_clock,
            max_future_clock_skew_ms: guard_skew,
            registry_version: candidate_head.version,
            registry_head_hash: candidate_head.object_hash,
            guard_policy_object_hash: guard_policy_hash,
            independent_reference_kind: reference_tag,
            independent_reference_hash: reference_hash,
            independent_reference_time: verified_time,
            justification: 0,
            issued_at: UnixMillis::new(os_wall_clock.max(floor).get() - 100),
            expires_at: UnixMillis::new(os_wall_clock.max(floor).get() + 100),
            nonce,
        },
        signer,
        candidate_core_hash,
        guard_policy_core_hash,
        independent_reference_core_hash: reference_core_hash,
    }
}

#[derive(Clone, Copy)]
struct PersistedClock {
    reference_time: UnixMillis,
    floor: UnixMillis,
    os_wall_clock: UnixMillis,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    nonce: [u8; 32],
}

impl PersistedClock {
    const fn standard() -> Self {
        Self {
            reference_time: UnixMillis::new(3_000),
            floor: UnixMillis::new(3_100),
            os_wall_clock: UnixMillis::new(3_201),
            issued_at: UnixMillis::new(3_150),
            expires_at: UnixMillis::new(3_250),
            nonce: [0xc7; 32],
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn persisted_reference_fixture(
    line: &RegistryLineBuilder,
    pin_index: usize,
    proposed_sequence: ChainSequence,
    candidate_head: BuiltHead,
    guard_policy_hash: ObjectHash,
    target_device: DeviceId,
    admin_hash: ObjectHash,
    binding_hash: ObjectHash,
    signer: AuditSigner,
    guard_skew: u64,
) -> FlowFixture {
    persisted_reference_fixture_with_clock(
        line,
        pin_index,
        proposed_sequence,
        candidate_head,
        guard_policy_hash,
        target_device,
        admin_hash,
        binding_hash,
        signer,
        guard_skew,
        PersistedClock::standard(),
    )
}

#[allow(clippy::too_many_arguments)]
fn persisted_reference_fixture_with_clock(
    line: &RegistryLineBuilder,
    pin_index: usize,
    proposed_sequence: ChainSequence,
    candidate_head: BuiltHead,
    guard_policy_hash: ObjectHash,
    target_device: DeviceId,
    admin_hash: ObjectHash,
    binding_hash: ObjectHash,
    signer: AuditSigner,
    guard_skew: u64,
    clock: PersistedClock,
) -> FlowFixture {
    let key = state_key(target_device);
    let reference_hash = ObjectHash::from(support::hash32(0xc5));
    let initial_time = TrustedTimeState::from_persisted(
        clock.floor,
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            reference_hash,
            clock.reference_time,
        )),
    )
    .unwrap();
    let trust = line.verified_with_time_and_key(Pin::Head(pin_index), initial_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, proposed_sequence).unwrap();
    assert!(candidate.registry_head_hash() == candidate_head.object_hash);
    let original_head = line.heads()[pin_index];
    FlowFixture {
        candidate,
        key,
        initial_time,
        original_pin: RegistryHeadPin::new(original_head.version, original_head.object_hash),
        sources: Vec::new(),
        audit: AuditFields {
            organization_id: support::organization(),
            target_device_id: target_device,
            admin_binding_hash: Some(binding_hash),
            signer_certificate_hash: admin_hash,
            action: 6,
            outcome: 1,
            effective_now: clock.os_wall_clock.max(clock.floor),
            trusted_time_floor: clock.floor,
            observed_os_wall_clock: clock.os_wall_clock,
            max_future_clock_skew_ms: guard_skew,
            registry_version: candidate_head.version,
            registry_head_hash: candidate_head.object_hash,
            guard_policy_object_hash: guard_policy_hash,
            independent_reference_kind: 0,
            independent_reference_hash: reference_hash,
            independent_reference_time: clock.reference_time,
            justification: 1,
            issued_at: clock.issued_at,
            expires_at: clock.expires_at,
            nonce: clock.nonce,
        },
        signer,
        candidate_core_hash: exact_trust_core_hash(line, candidate_head.object_hash),
        guard_policy_core_hash: exact_trust_core_hash(line, guard_policy_hash),
        independent_reference_core_hash: ObjectHash::from(support::hash32(0xc6)),
    }
}

fn active_non_admin_reader_fixture() -> FlowFixture {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    let reader = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x11,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    let reader_binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: reader.direct_object_hash.unwrap(),
            role: ea_format::OperatorRoleV1::Reader,
            marker: 0x11,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(29),
            ..HeadOptions::default()
        },
    );
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(30),
            valid_through: Some(49),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let guard_policy_hash = line.current_policy_hash().unwrap();
    let candidate_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(40),
            valid_through: Some(59),
            policy_max_future_clock_skew_ms_override: Some(9_999),
            ..HeadOptions::default()
        },
    );

    persisted_reference_fixture(
        &line,
        3,
        ChainSequence::new(40),
        candidate_head,
        guard_policy_hash,
        device_id(0x51),
        reader.direct_object_hash.unwrap(),
        reader_binding.direct_object_hash.unwrap(),
        AuditSigner::New,
        50,
    )
}

fn candidate_only_admin_fixture() -> FlowFixture {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    let new_admin = line.push(
        ActionSpec::AdminIssue {
            marker: 0x11,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(39),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let guard_policy_hash = line.current_policy_hash().unwrap();
    let candidate_head = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: new_admin.direct_object_hash.unwrap(),
            role: ea_format::OperatorRoleV1::OrganizationAdmin,
            marker: 0x11,
            effective_from: None,
        },
        HeadOptions {
            // Deliberate overlap: preTransitionSequence is 30, so the binding
            // would be active if an implementation incorrectly used H4 state.
            effective_from: Some(30),
            valid_through: Some(49),
            ..HeadOptions::default()
        },
    );
    persisted_reference_fixture(
        &line,
        2,
        ChainSequence::new(30),
        candidate_head,
        guard_policy_hash,
        device_id(0x51),
        new_admin.direct_object_hash.unwrap(),
        candidate_head.direct_object_hash.unwrap(),
        AuditSigner::New,
        50,
    )
}

fn inactive_bootstrap_admin_fixture() -> FlowFixture {
    let mut line = RegistryLineBuilder::with_first_admin_revoked_from(Some(ChainSequence::new(25)));
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    let current_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(39),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let policy_hash = line.current_policy_hash().unwrap();
    persisted_reference_fixture(
        &line,
        2,
        ChainSequence::new(30),
        current_head,
        policy_hash,
        device_id(0x51),
        line.bootstrap_admin_hash(),
        line.bootstrap_admin_binding_hash(),
        AuditSigner::First,
        50,
    )
}

fn inactive_new_admin_binding_fixture() -> FlowFixture {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let new_admin = line.push(
        ActionSpec::AdminIssue {
            marker: 0x11,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    let current_head = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: new_admin.direct_object_hash.unwrap(),
            role: ea_format::OperatorRoleV1::OrganizationAdmin,
            marker: 0x11,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(39),
            revoked_from_sequence: Some(ChainSequence::new(30)),
            ..HeadOptions::default()
        },
    );
    let policy_hash = line.current_policy_hash().unwrap();
    persisted_reference_fixture(
        &line,
        2,
        ChainSequence::new(30),
        current_head,
        policy_hash,
        device_id(0x51),
        new_admin.direct_object_hash.unwrap(),
        current_head.direct_object_hash.unwrap(),
        AuditSigner::New,
        50,
    )
}

fn current_head_fixture() -> FlowFixture {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    let current_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(39),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let policy_hash = line.current_policy_hash().unwrap();
    persisted_reference_fixture(
        &line,
        2,
        ChainSequence::new(25),
        current_head,
        policy_hash,
        device_id(0x51),
        line.bootstrap_admin_hash(),
        line.bootstrap_admin_binding_hash(),
        AuditSigner::First,
        50,
    )
}

fn immediate_successor_admin_boundary_fixture() -> FlowFixture {
    let mut line = RegistryLineBuilder::with_first_admin_revoked_from(Some(ChainSequence::new(40)));
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(39),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let guard_policy_hash = line.current_policy_hash().unwrap();
    let candidate_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(40),
            valid_through: Some(49),
            ..HeadOptions::default()
        },
    );
    persisted_reference_fixture(
        &line,
        2,
        ChainSequence::new(40),
        candidate_head,
        guard_policy_hash,
        device_id(0x51),
        line.bootstrap_admin_hash(),
        line.bootstrap_admin_binding_hash(),
        AuditSigner::First,
        50,
    )
}

fn rollback_floor_dominates_fixture() -> FlowFixture {
    let mut line = RegistryLineBuilder::new();
    let current_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(39),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let policy_hash = line.current_policy_hash().unwrap();
    persisted_reference_fixture_with_clock(
        &line,
        0,
        ChainSequence::new(20),
        current_head,
        policy_hash,
        device_id(0x51),
        line.bootstrap_admin_hash(),
        line.bootstrap_admin_binding_hash(),
        AuditSigner::First,
        50,
        PersistedClock {
            reference_time: UnixMillis::new(1_000),
            floor: UnixMillis::new(1_200),
            os_wall_clock: UnixMillis::new(1_100),
            issued_at: UnixMillis::new(1_150),
            expires_at: UnixMillis::new(1_250),
            nonce: [0xb7; 32],
        },
    )
}

fn candidate_revokes_signing_admin_fixture() -> FlowFixture {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(39),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let guard_policy_hash = line.current_policy_hash().unwrap();
    let second_admin = line.second_bootstrap_admin_hash();
    let second_binding = line.second_bootstrap_admin_binding_hash();
    let candidate_head = line.push(
        ActionSpec::AdminRevoke {
            object_hash: second_admin,
        },
        HeadOptions {
            effective_from: Some(30),
            valid_through: Some(49),
            ..HeadOptions::default()
        },
    );
    persisted_reference_fixture(
        &line,
        2,
        ChainSequence::new(30),
        candidate_head,
        guard_policy_hash,
        device_id(0x52),
        second_admin,
        second_binding,
        AuditSigner::Second,
        50,
    )
}

fn newly_activated_admin_boundary_fixture() -> FlowFixture {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let new_admin = line.push(
        ActionSpec::AdminIssue {
            marker: 0x11,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    let current_head = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: new_admin.direct_object_hash.unwrap(),
            role: ea_format::OperatorRoleV1::OrganizationAdmin,
            marker: 0x11,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(39),
            ..HeadOptions::default()
        },
    );
    let policy_hash = line.current_policy_hash().unwrap();
    persisted_reference_fixture(
        &line,
        2,
        ChainSequence::new(20),
        current_head,
        policy_hash,
        device_id(0x51),
        new_admin.direct_object_hash.unwrap(),
        current_head.direct_object_hash.unwrap(),
        AuditSigner::New,
        50,
    )
}

fn verify_bytes_once(
    fixture: &FlowFixture,
    bytes: &[u8],
    configure: impl FnOnce(&mut ModelStore),
) -> (Result<VerifiedClockRelease, ClockReleaseError>, ModelStore) {
    let mut store = fixture.store();
    configure(&mut store);
    let result = {
        let mut local_time = prepare_local_time(
            &mut store,
            &fixture.candidate,
            fixture.audit.observed_os_wall_clock,
            &fixture.sources,
        )
        .unwrap();
        verify_clock_release(&fixture.candidate, &mut local_time, bytes)
    };
    (result, store)
}

fn verify_fields_once(
    fixture: &FlowFixture,
    fields: &AuditFields,
    signer: AuditSigner,
    configure: impl FnOnce(&mut ModelStore),
) -> (Result<VerifiedClockRelease, ClockReleaseError>, ModelStore) {
    let bytes = signed_clock_release(fields, signer);
    verify_bytes_once(fixture, &bytes, configure)
}

fn verify_with_foreign_block(
    block_fixture: &FlowFixture,
    candidate_fixture: &FlowFixture,
    bytes: &[u8],
) -> (Result<VerifiedClockRelease, ClockReleaseError>, ModelStore) {
    let mut store = block_fixture.store();
    let result = {
        let mut local_time = prepare_local_time(
            &mut store,
            &block_fixture.candidate,
            block_fixture.audit.observed_os_wall_clock,
            &block_fixture.sources,
        )
        .unwrap();
        verify_clock_release(&candidate_fixture.candidate, &mut local_time, bytes)
    };
    (result, store)
}

fn assert_clock_error(
    result: Result<VerifiedClockRelease, ClockReleaseError>,
    expected: ClockReleaseError,
) {
    let error = result
        .err()
        .expect("the invalid Clock Release must fail closed");
    assert_eq!(error.code(), expected.code());
    assert_eq!(error.to_string(), expected.code());
    assert_eq!(format!("{error:?}"), expected.code());
}

fn assert_only_task9_time_was_committed(fixture: &FlowFixture, store: &ModelStore) {
    let expected_independent_commits = usize::from(!fixture.sources.is_empty());
    assert_eq!(store.independent_commits, expected_independent_commits);
    assert_eq!(
        store.record.revision,
        INITIAL_REVISION + u64::try_from(expected_independent_commits).unwrap()
    );
    assert!(store.record.pinned_head == Some(fixture.original_pin));
    assert!(store.record.trusted_time.floor() == fixture.audit.trusted_time_floor);
    let Some(reference) = store.record.trusted_time.independent_reference() else {
        assert!(fixture.sources.is_empty());
        assert!(fixture.initial_time.independent_reference().is_none());
        assert_eq!(store.registry_commits, 0);
        return;
    };
    let expected_kind = match fixture.audit.independent_reference_kind {
        0 => IndependentTimeKind::Receipt,
        1 => IndependentTimeKind::Checkpoint,
        _ => panic!("the baseline fixture itself must use Receipt or Checkpoint"),
    };
    assert_eq!(reference.kind(), expected_kind);
    assert!(reference.object_hash() == fixture.audit.independent_reference_hash);
    assert!(reference.verified_time() == fixture.audit.independent_reference_time);
    assert_eq!(store.registry_commits, 0);
}

fn assert_signed_error_before_replay(
    fixture: &FlowFixture,
    fields: &AuditFields,
    signer: AuditSigner,
    expected: ClockReleaseError,
) {
    let (result, store) = verify_fields_once(fixture, fields, signer, |_| {});
    assert_clock_error(result, expected);
    assert!(store.replay_queries.is_empty());
    assert_only_task9_time_was_committed(fixture, &store);
}

fn assert_wire_invalid_before_replay(
    fixture: &FlowFixture,
    fields: &AuditFields,
    signer: AuditSigner,
) {
    let exact = raw_signed_wire_invalid_clock_release(fields, signer);
    assert!(
        decode_clock_release_audit(&exact).is_err(),
        "the deliberately wire-invalid core must fail exact decoding"
    );
    let (result, store) = verify_bytes_once(fixture, &exact, |_| {});
    assert_clock_error(result, ClockReleaseError::Mismatch);
    assert!(store.replay_queries.is_empty());
    assert_only_task9_time_was_committed(fixture, &store);
}

type VerifyClockRelease =
    for<'candidate, 'block, 'store, 'bytes> fn(
        &'candidate RegistryCandidate,
        &'block mut LocalTimeBlock<'store>,
        &'bytes [u8],
    )
        -> Result<VerifiedClockRelease, ClockReleaseError>;

#[test]
fn public_api_is_exact_and_clock_release_errors_are_stable_and_code_only() {
    let _: VerifyClockRelease = verify_clock_release;

    assert_eq!(
        ClockReleaseError::Mismatch.code(),
        "EA-TRUST-CLOCK-RELEASE-MISMATCH"
    );
    assert_eq!(
        ClockReleaseError::Expired.code(),
        "EA-TRUST-CLOCK-RELEASE-EXPIRED"
    );
    assert_eq!(
        ClockReleaseError::Trust(TrustError::ClockReleaseReplay).code(),
        "EA-TRUST-CLOCK-RELEASE-REPLAY"
    );
}

#[test]
fn h3_previous_head_admin_verifies_the_exact_h4_release_after_real_receipt_time() {
    let fixture = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);
    let (result, store) = verify_fields_once(&fixture, &fixture.audit, fixture.signer, |_| {});
    let _proof = result.expect("the exact H3-authorized H4 release must verify");

    assert_eq!(store.independent_commits, 1);
    assert_eq!(store.registry_commits, 0);
    assert_eq!(store.replay_queries.len(), 1);
    assert!(
        store.replay_queries[0]
            == (
                fixture.audit.organization_id,
                fixture.audit.target_device_id,
                fixture.audit.nonce,
            )
    );
}

#[test]
fn checkpoint_reference_is_an_equally_exact_but_distinct_positive_path() {
    let fixture = successor_fixture_with(
        SignedReferenceKind::Checkpoint,
        AuditSigner::Second,
        37,
        UnixMillis::new(2_000),
        UnixMillis::new(1_900),
        UnixMillis::new(2_038),
        [0xe1; 32],
    );
    let (result, store) = verify_fields_once(&fixture, &fixture.audit, fixture.signer, |_| {});
    let _proof = result.expect("the exact Checkpoint-bound release must verify");
    assert_eq!(store.independent_commits, 1);
    assert_eq!(store.replay_queries.len(), 1);
    assert!(fixture.audit.target_device_id == device_id(0x52));
    assert!(fixture.audit.nonce == [0xe1; 32]);
    assert!(
        store.replay_queries[0] == (fixture.audit.organization_id, device_id(0x52), [0xe1; 32],)
    );
    assert_eq!(store.registry_commits, 0);
}

#[test]
fn an_exact_blocked_current_head_release_uses_its_current_admin_and_policy() {
    let fixture = current_head_fixture();
    let (result, store) = verify_fields_once(&fixture, &fixture.audit, fixture.signer, |_| {});
    let _proof = result.expect("the exact current-Head release must verify");
    assert_eq!(store.independent_commits, 0);
    assert_eq!(store.replay_queries.len(), 1);
    assert_eq!(store.registry_commits, 0);
}

#[test]
fn immediate_successor_checks_admin_activity_at_previous_valid_through() {
    let fixture = immediate_successor_admin_boundary_fixture();
    let (result, store) = verify_fields_once(&fixture, &fixture.audit, fixture.signer, |_| {});
    let _proof = result
        .expect("an Admin revoked at candidate effective must remain active at H3 validThrough");
    assert_eq!(store.replay_queries.len(), 1);
    assert_only_task9_time_was_committed(&fixture, &store);
}

#[test]
fn rollback_uses_floor_as_raw_now_and_preserves_the_prepared_state() {
    let fixture = rollback_floor_dominates_fixture();
    assert!(
        fixture.audit.observed_os_wall_clock < fixture.audit.trusted_time_floor,
        "the positive control must exercise ClockRollback"
    );
    assert!(fixture.audit.issued_at > fixture.audit.observed_os_wall_clock);
    assert!(fixture.audit.effective_now == fixture.audit.trusted_time_floor);
    let (result, store) = verify_fields_once(&fixture, &fixture.audit, fixture.signer, |_| {});
    let _proof = result.expect("release interval must use TimeEvaluation.raw_now, not raw OS");
    assert_eq!(store.replay_queries.len(), 1);
    assert_only_task9_time_was_committed(&fixture, &store);
}

#[test]
fn decoder_crypto_and_outcome_fail_closed_before_any_replay_lookup() {
    let fixture = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);

    let wrong_content =
        signed_with_content_type(&fixture.audit, fixture.signer, ContentType::CheckpointCbor);
    let (result, store) = verify_bytes_once(&fixture, &wrong_content, |_| {});
    assert_clock_error(result, ClockReleaseError::Mismatch);
    assert!(store.replay_queries.is_empty());
    assert_only_task9_time_was_committed(&fixture, &store);

    let mut wrong_action = fixture.audit.clone();
    wrong_action.action = 5;
    assert_wire_invalid_before_replay(&fixture, &wrong_action, fixture.signer);

    let mut null_binding = fixture.audit.clone();
    null_binding.admin_binding_hash = None;
    assert_signed_error_before_replay(
        &fixture,
        &null_binding,
        fixture.signer,
        ClockReleaseError::Mismatch,
    );

    for outcome in [0, 2] {
        let mut wrong_outcome = fixture.audit.clone();
        wrong_outcome.outcome = outcome;
        assert_signed_error_before_replay(
            &fixture,
            &wrong_outcome,
            fixture.signer,
            ClockReleaseError::Mismatch,
        );
    }

    let mut expired_tsa = fixture.audit.clone();
    expired_tsa.independent_reference_kind = 2;
    expired_tsa.expires_at = UnixMillis::new(1_099);
    let corrupt = corrupt_signature(signed_clock_release(&expired_tsa, fixture.signer));
    let (result, store) = verify_bytes_once(&fixture, &corrupt, |store| store.consumed = true);
    assert_clock_error(result, ClockReleaseError::Trust(TrustError::Signature));
    assert!(store.replay_queries.is_empty());
    assert_only_task9_time_was_committed(&fixture, &store);
}

#[test]
fn every_signed_candidate_block_and_outer_object_correlation_is_exact() {
    let fixture = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);

    let mut changed = fixture.audit.clone();
    changed.organization_id = OrganizationId::try_from(&[0x22; 16][..]).unwrap();
    assert_signed_error_before_replay(
        &fixture,
        &changed,
        fixture.signer,
        ClockReleaseError::Trust(TrustError::SignerInactive),
    );

    changed = fixture.audit.clone();
    changed.target_device_id = device_id(0x52);
    let second = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::Second);
    changed.signer_certificate_hash = second.audit.signer_certificate_hash;
    changed.admin_binding_hash = second.audit.admin_binding_hash;
    assert_signed_error_before_replay(
        &fixture,
        &changed,
        AuditSigner::Second,
        ClockReleaseError::Mismatch,
    );

    changed = fixture.audit.clone();
    changed.registry_version = RegistryVersion::new(3);
    assert_signed_error_before_replay(
        &fixture,
        &changed,
        fixture.signer,
        ClockReleaseError::Mismatch,
    );

    for wrong_head in [
        fixture.candidate_core_hash,
        ObjectHash::from(support::hash32(0xa1)),
    ] {
        changed = fixture.audit.clone();
        changed.registry_head_hash = wrong_head;
        assert_signed_error_before_replay(
            &fixture,
            &changed,
            fixture.signer,
            ClockReleaseError::Mismatch,
        );
    }

    for wrong_policy in [
        fixture.guard_policy_core_hash,
        ObjectHash::from(support::hash32(0xa2)),
    ] {
        changed = fixture.audit.clone();
        changed.guard_policy_object_hash = wrong_policy;
        assert_signed_error_before_replay(
            &fixture,
            &changed,
            fixture.signer,
            ClockReleaseError::Mismatch,
        );
    }

    changed = fixture.audit.clone();
    changed.trusted_time_floor = UnixMillis::new(999);
    assert_signed_error_before_replay(
        &fixture,
        &changed,
        fixture.signer,
        ClockReleaseError::Mismatch,
    );

    changed = fixture.audit.clone();
    changed.observed_os_wall_clock = UnixMillis::new(1_099);
    changed.effective_now = UnixMillis::new(1_099);
    assert_signed_error_before_replay(
        &fixture,
        &changed,
        fixture.signer,
        ClockReleaseError::Mismatch,
    );

    changed = fixture.audit.clone();
    changed.max_future_clock_skew_ms = 101;
    assert_signed_error_before_replay(
        &fixture,
        &changed,
        fixture.signer,
        ClockReleaseError::Mismatch,
    );

    changed = fixture.audit.clone();
    changed.independent_reference_kind = 1;
    assert_signed_error_before_replay(
        &fixture,
        &changed,
        fixture.signer,
        ClockReleaseError::Mismatch,
    );

    for wrong_reference_hash in [
        fixture.independent_reference_core_hash,
        ObjectHash::from(support::hash32(0xa3)),
    ] {
        changed = fixture.audit.clone();
        changed.independent_reference_hash = wrong_reference_hash;
        assert_signed_error_before_replay(
            &fixture,
            &changed,
            fixture.signer,
            ClockReleaseError::Mismatch,
        );
    }

    changed = fixture.audit.clone();
    changed.independent_reference_time = UnixMillis::new(901);
    assert_signed_error_before_replay(
        &fixture,
        &changed,
        fixture.signer,
        ClockReleaseError::Mismatch,
    );

    changed = fixture.audit.clone();
    changed.admin_binding_hash = Some(fixture.audit.signer_certificate_hash);
    assert_signed_error_before_replay(
        &fixture,
        &changed,
        fixture.signer,
        ClockReleaseError::Mismatch,
    );
}

#[test]
fn wire_effective_now_justification_and_interval_boundaries_are_closed_and_inclusive() {
    let fixture = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);

    let mut wrong_effective_now = fixture.audit.clone();
    wrong_effective_now.effective_now = UnixMillis::new(1_099);
    assert_wire_invalid_before_replay(&fixture, &wrong_effective_now, fixture.signer);

    for justification in 0..=2 {
        let mut accepted = fixture.audit.clone();
        accepted.justification = justification;
        let (result, store) = verify_fields_once(&fixture, &accepted, fixture.signer, |_| {});
        let _proof = result.expect("every closed justification code must verify");
        assert_eq!(store.replay_queries.len(), 1);
    }
    let mut open_justification = fixture.audit.clone();
    open_justification.justification = 3;
    assert_wire_invalid_before_replay(&fixture, &open_justification, fixture.signer);

    let mut at_issued = fixture.audit.clone();
    at_issued.issued_at = at_issued.effective_now;
    let (result, _) = verify_fields_once(&fixture, &at_issued, fixture.signer, |_| {});
    let _proof = result.expect("issuedAt is inclusive");

    let mut at_expiry = fixture.audit.clone();
    at_expiry.expires_at = at_expiry.effective_now;
    let (result, _) = verify_fields_once(&fixture, &at_expiry, fixture.signer, |_| {});
    let _proof = result.expect("expiresAt is inclusive");

    for (issued_at, expires_at) in [(1_100, 1_100), (1_101, 1_100)] {
        let mut invalid_shape = fixture.audit.clone();
        invalid_shape.issued_at = UnixMillis::new(issued_at);
        invalid_shape.expires_at = UnixMillis::new(expires_at);
        assert_wire_invalid_before_replay(&fixture, &invalid_shape, fixture.signer);
    }

    let mut not_yet_issued = fixture.audit.clone();
    not_yet_issued.issued_at = UnixMillis::new(1_101);
    assert_signed_error_before_replay(
        &fixture,
        &not_yet_issued,
        fixture.signer,
        ClockReleaseError::Expired,
    );

    let mut expired = fixture.audit.clone();
    expired.expires_at = UnixMillis::new(1_099);
    assert_signed_error_before_replay(
        &fixture,
        &expired,
        fixture.signer,
        ClockReleaseError::Expired,
    );
}

#[test]
fn tsa_within_limit_and_unprovable_time_never_mint_a_release() {
    let fixture = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);
    let mut tsa = fixture.audit.clone();
    tsa.independent_reference_kind = 2;
    assert_signed_error_before_replay(
        &fixture,
        &tsa,
        fixture.signer,
        ClockReleaseError::Trust(TrustError::TimeSourceUnsupported),
    );

    let mut within = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);
    within.audit.observed_os_wall_clock = UnixMillis::new(1_000);
    within.audit.effective_now = UnixMillis::new(1_000);
    within.audit.issued_at = UnixMillis::new(900);
    within.audit.expires_at = UnixMillis::new(1_100);
    assert_signed_error_before_replay(
        &within,
        &within.audit,
        within.signer,
        ClockReleaseError::Mismatch,
    );

    let mut unprovable = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);
    unprovable.sources.clear();
    assert_signed_error_before_replay(
        &unprovable,
        &unprovable.audit,
        unprovable.signer,
        ClockReleaseError::Mismatch,
    );
}

#[test]
fn replay_is_queried_last_with_the_exact_key_and_never_committed_in_task_10() {
    let fixture = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);
    let (result, store) = verify_fields_once(&fixture, &fixture.audit, fixture.signer, |store| {
        store.consumed = true
    });
    assert_clock_error(
        result,
        ClockReleaseError::Trust(TrustError::ClockReleaseReplay),
    );
    assert_eq!(store.replay_queries.len(), 1);
    assert!(
        store.replay_queries[0]
            == (
                fixture.audit.organization_id,
                fixture.audit.target_device_id,
                fixture.audit.nonce,
            )
    );
    assert_eq!(store.independent_commits, 1);
    assert_only_task9_time_was_committed(&fixture, &store);

    for (store_error, trust_error) in [
        (StateStoreError::Conflict, TrustError::StateConflict),
        (
            StateStoreError::ReplayAlreadyConsumed,
            TrustError::ClockReleaseReplay,
        ),
        (
            StateStoreError::MonotonicityViolation,
            TrustError::StateMonotonicity,
        ),
        (StateStoreError::Unavailable, TrustError::StateUnavailable),
    ] {
        let (result, store) =
            verify_fields_once(&fixture, &fixture.audit, fixture.signer, |store| {
                store.query_error = Some(store_error)
            });
        assert_clock_error(result, ClockReleaseError::Trust(trust_error));
        assert_eq!(store.replay_queries.len(), 1);
        assert_only_task9_time_was_committed(&fixture, &store);
    }
}

#[test]
fn invalid_signature_wins_over_expiry_tsa_and_replayed_nonce_without_a_replay_oracle() {
    let fixture = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);
    let mut semantically_invalid = fixture.audit.clone();
    semantically_invalid.independent_reference_kind = 2;
    semantically_invalid.expires_at = UnixMillis::new(1_099);
    let corrupt = corrupt_signature(signed_clock_release(&semantically_invalid, fixture.signer));
    let (result, store) = verify_bytes_once(&fixture, &corrupt, |store| {
        store.consumed = true;
        store.query_error = Some(StateStoreError::Unavailable);
    });
    assert_clock_error(result, ClockReleaseError::Trust(TrustError::Signature));
    assert!(store.replay_queries.is_empty());
    assert_only_task9_time_was_committed(&fixture, &store);
}

#[test]
fn only_previous_head_admin_authority_may_verify_a_successor_release() {
    let candidate_only = candidate_only_admin_fixture();
    assert_signed_error_before_replay(
        &candidate_only,
        &candidate_only.audit,
        candidate_only.signer,
        ClockReleaseError::Mismatch,
    );

    let inactive_certificate = inactive_bootstrap_admin_fixture();
    assert_signed_error_before_replay(
        &inactive_certificate,
        &inactive_certificate.audit,
        inactive_certificate.signer,
        ClockReleaseError::Trust(TrustError::SignerInactive),
    );

    let inactive_binding = inactive_new_admin_binding_fixture();
    assert_signed_error_before_replay(
        &inactive_binding,
        &inactive_binding.audit,
        inactive_binding.signer,
        ClockReleaseError::Trust(TrustError::SignerInactive),
    );

    let candidate_revocation = candidate_revokes_signing_admin_fixture();
    let (result, store) = verify_fields_once(
        &candidate_revocation,
        &candidate_revocation.audit,
        candidate_revocation.signer,
        |_| {},
    );
    let _proof =
        result.expect("H4 may revoke its signer only after the H3-authorized release is checked");
    assert_eq!(store.replay_queries.len(), 1);
    assert_only_task9_time_was_committed(&candidate_revocation, &store);

    let newly_active = newly_activated_admin_boundary_fixture();
    let (result, store) = verify_fields_once(
        &newly_active,
        &newly_active.audit,
        newly_active.signer,
        |_| {},
    );
    let _proof = result.expect("Admin certificate and Binding are active at their inclusive start");
    assert_eq!(store.replay_queries.len(), 1);
    assert_only_task9_time_was_committed(&newly_active, &store);
}

#[test]
fn signer_role_device_and_exact_active_binding_are_independent_checks() {
    let first = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);
    let second = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::Second);

    let mut wrong_signer_for_device = second.audit.clone();
    wrong_signer_for_device.signer_certificate_hash = first.audit.signer_certificate_hash;
    wrong_signer_for_device.admin_binding_hash = first.audit.admin_binding_hash;
    assert_signed_error_before_replay(
        &second,
        &wrong_signer_for_device,
        AuditSigner::First,
        ClockReleaseError::Trust(TrustError::SignerInactive),
    );

    let mut wrong_but_active_binding = first.audit.clone();
    wrong_but_active_binding.admin_binding_hash = second.audit.admin_binding_hash;
    assert_signed_error_before_replay(
        &first,
        &wrong_but_active_binding,
        AuditSigner::First,
        ClockReleaseError::Mismatch,
    );

    let wrong_role = active_non_admin_reader_fixture();
    assert_signed_error_before_replay(
        &wrong_role,
        &wrong_role.audit,
        wrong_role.signer,
        ClockReleaseError::Trust(TrustError::SignerInactive),
    );
}

#[test]
fn a_fresh_resigned_nonce_changes_only_the_exact_replay_lookup_key() {
    let fixture = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);
    let mut fresh = fixture.audit.clone();
    fresh.nonce = [0xd1; 32];
    let (result, store) = verify_fields_once(&fixture, &fresh, fixture.signer, |_| {});
    let _proof = result.expect("a fresh signed nonce must mint a distinct proof");
    assert_eq!(store.replay_queries.len(), 1);
    assert!(
        store.replay_queries[0] == (fresh.organization_id, fresh.target_device_id, fresh.nonce,)
    );
    assert!(store.replay_queries[0].2 != fixture.audit.nonce);
    assert_eq!(store.registry_commits, 0);
}

#[test]
fn candidate_and_local_time_block_must_come_from_the_same_exact_flow() {
    let block_fixture = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::First);
    let different_baseline = successor_fixture_with(
        SignedReferenceKind::Receipt,
        AuditSigner::First,
        100,
        UnixMillis::new(999),
        UnixMillis::new(900),
        UnixMillis::new(1_100),
        [0xd0; 32],
    );
    assert!(block_fixture.key == different_baseline.key);
    assert!(block_fixture.original_pin == different_baseline.original_pin);
    assert!(
        block_fixture.candidate.registry_version()
            == different_baseline.candidate.registry_version()
    );
    assert!(
        block_fixture.candidate.registry_head_hash()
            == different_baseline.candidate.registry_head_hash()
    );
    assert!(block_fixture.initial_time != different_baseline.initial_time);

    let block_audit = signed_clock_release(&block_fixture.audit, block_fixture.signer);
    let (result, store) =
        verify_with_foreign_block(&block_fixture, &different_baseline, &block_audit);
    assert_clock_error(result, ClockReleaseError::Mismatch);
    assert!(store.replay_queries.is_empty());
    assert_only_task9_time_was_committed(&block_fixture, &store);

    let (result, store) = verify_fields_once(
        &block_fixture,
        &block_fixture.audit,
        block_fixture.signer,
        |_| {},
    );
    let _proof = result.expect("the same candidate must accept its own prepared block and audit");
    assert_eq!(store.replay_queries.len(), 1);

    let foreign_device = successor_fixture(SignedReferenceKind::Receipt, AuditSigner::Second);
    let foreign_device_bytes = signed_clock_release(&foreign_device.audit, foreign_device.signer);
    let (result, store) =
        verify_with_foreign_block(&block_fixture, &foreign_device, &foreign_device_bytes);
    assert_clock_error(result, ClockReleaseError::Mismatch);
    assert!(store.replay_queries.is_empty());
    assert_only_task9_time_was_committed(&block_fixture, &store);

    let foreign_head = successor_fixture_with(
        SignedReferenceKind::Receipt,
        AuditSigner::First,
        37,
        UnixMillis::new(1_000),
        UnixMillis::new(900),
        UnixMillis::new(1_100),
        [0xd8; 32],
    );
    let foreign_head_bytes = signed_clock_release(&foreign_head.audit, foreign_head.signer);
    let (result, store) =
        verify_with_foreign_block(&block_fixture, &foreign_head, &foreign_head_bytes);
    assert_clock_error(result, ClockReleaseError::Mismatch);
    assert!(store.replay_queries.is_empty());
    assert_only_task9_time_was_committed(&block_fixture, &store);

    let (result, store) = verify_with_foreign_block(&block_fixture, &foreign_head, &[0x00]);
    assert_clock_error(result, ClockReleaseError::Mismatch);
    assert!(store.replay_queries.is_empty());
    assert_only_task9_time_was_committed(&block_fixture, &store);
}
