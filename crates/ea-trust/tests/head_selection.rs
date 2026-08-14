mod support;

use std::{cell::RefCell, rc::Rc};

use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, SecretBytes};
use ea_format::{
    CertificateKindV1, Parsed, ParsedArchiveObject, ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1,
    decode_exact_object, encode_receipt,
};
use ea_time::{
    IndependentTimeInput, IndependentTimeKind, TrustedTimeState, advance_registry_floor,
};
use ea_trust::{
    AdvancedRegistryHead, ClockReleaseReplayKey, IndependentTimeCommit, LocalTimeBlock,
    PendingFutureSuccessor, PersistedTrustRecord, PreexistingEffectiveNow, RegistryCandidate,
    RegistryError, RegistryHeadPin, RegistrySelectionCommit, RegistrySelectionOutcome,
    SelectedRegistryHead, StateStoreError, TrustError, TrustStateKey, TrustStateStore,
    VerifiedClockRelease, VerifiedSignedTime, VerifiedTrust, prepare_local_time,
    select_registry_head, verify_clock_release, verify_current_head_fallback, verify_receipt_time,
    verify_registry_candidate,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, Hash32, ObjectHash,
    OrganizationId, RegistryVersion, UnixMillis,
};
use ed25519_dalek::SigningKey;
use minicbor::Encoder;

use support::{ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder, RootSigner};

const INITIAL_REVISION: u64 = 17;
const SERVER_SECRET: [u8; 32] = [
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
];
const ADMIN_ONE_SECRET: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];

#[derive(Clone, Eq, PartialEq)]
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

#[derive(Clone, Eq, PartialEq)]
struct ReplayTuple {
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    nonce: [u8; 32],
}

impl ReplayTuple {
    fn from_key(key: &ClockReleaseReplayKey) -> Self {
        Self {
            organization_id: key.organization_id(),
            target_device_id: key.target_device_id(),
            nonce: *key.nonce(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ObservedSelectionCommit {
    key: TrustStateKey,
    expected_revision: u64,
    next_trusted_time: TrustedTimeState,
    next_head: RegistryHeadPin,
    replay_key: Option<ReplayTuple>,
}

#[derive(Clone)]
enum SelectionFault {
    None,
    BeforeReplay(StateStoreError),
    AfterTentativeReplay(StateStoreError),
    BeforeHeadAndFloor(StateStoreError),
    ConcurrentCommit(ModelRecord),
    ConcurrentReplay(ReplayTuple),
    ReturnRecord(ModelRecord),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CommitPhase {
    Entered,
    ReplayStaged,
    HeadAndFloorStaged,
}

struct ModelStore {
    key: TrustStateKey,
    record: ModelRecord,
    next_revision: u64,
    revision_after_independent: Option<u64>,
    independent_commits: usize,
    replay_queries: usize,
    selection_commits: Vec<ObservedSelectionCommit>,
    commit_phases: Vec<CommitPhase>,
    consumed_replays: Vec<ReplayTuple>,
    fault: SelectionFault,
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
            next_revision: 29,
            revision_after_independent: None,
            independent_commits: 0,
            replay_queries: 0,
            selection_commits: Vec::new(),
            commit_phases: Vec::new(),
            consumed_replays: Vec::new(),
            fault: SelectionFault::None,
        }
    }

    fn set_fault(&mut self, fault: SelectionFault) {
        self.fault = fault;
    }

    fn set_next_revision(&mut self, revision: u64) {
        self.next_revision = revision;
        self.revision_after_independent = None;
    }

    fn set_revision_sequence(&mut self, independent: u64, selection: u64) {
        self.next_revision = independent;
        self.revision_after_independent = Some(selection);
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
        if commit.next_trusted_time().floor() < self.record.trusted_time.floor() {
            return Err(StateStoreError::MonotonicityViolation);
        }
        let committed_revision = self.next_revision;
        if let Some(selection_revision) = self.revision_after_independent.take() {
            self.next_revision = selection_revision;
        }
        self.record = ModelRecord {
            revision: committed_revision,
            trusted_time: commit.next_trusted_time().clone(),
            pinned_head: self.record.pinned_head,
        };
        Ok(self.record.persisted())
    }

    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.replay_queries += 1;
        Ok(self.consumed_replays.contains(&ReplayTuple::from_key(key)))
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        let replay_key = commit.replay_key().map(ReplayTuple::from_key);
        self.selection_commits.push(ObservedSelectionCommit {
            key,
            expected_revision,
            next_trusted_time: commit.next_trusted_time().clone(),
            next_head: *commit.next_head(),
            replay_key: replay_key.clone(),
        });

        self.commit_phases.push(CommitPhase::Entered);
        if let SelectionFault::BeforeReplay(error) = &self.fault {
            return Err(*error);
        }
        if let SelectionFault::ConcurrentCommit(record) = &self.fault {
            self.record = record.clone();
        }
        if key != self.key || expected_revision != self.record.revision {
            return Err(StateStoreError::Conflict);
        }
        if let SelectionFault::ConcurrentReplay(key) = &self.fault
            && !self.consumed_replays.contains(key)
        {
            self.consumed_replays.push(key.clone());
        }
        if replay_key
            .as_ref()
            .is_some_and(|key| self.consumed_replays.contains(key))
        {
            return Err(StateStoreError::ReplayAlreadyConsumed);
        }
        let mut staged_replays = self.consumed_replays.clone();
        if let Some(key) = replay_key.clone() {
            staged_replays.push(key);
            self.commit_phases.push(CommitPhase::ReplayStaged);
        }
        if let SelectionFault::AfterTentativeReplay(error) = &self.fault {
            return Err(*error);
        }
        if commit.next_trusted_time().floor() < self.record.trusted_time.floor()
            || commit.next_trusted_time().independent_reference()
                != self.record.trusted_time.independent_reference()
        {
            return Err(StateStoreError::MonotonicityViolation);
        }
        let staged_record = ModelRecord {
            revision: self.next_revision,
            trusted_time: commit.next_trusted_time().clone(),
            pinned_head: Some(*commit.next_head()),
        };
        self.commit_phases.push(CommitPhase::HeadAndFloorStaged);
        if let SelectionFault::BeforeHeadAndFloor(error) = &self.fault {
            return Err(*error);
        }
        if let SelectionFault::ReturnRecord(record) = &self.fault {
            self.consumed_replays = staged_replays;
            self.record = record.clone();
            return Ok(self.record.persisted());
        }

        self.consumed_replays = staged_replays;
        self.record = staged_record;
        Ok(self.record.persisted())
    }
}

#[derive(Clone)]
struct SharedStore {
    inner: Rc<RefCell<ModelStore>>,
}

impl SharedStore {
    fn new(store: ModelStore) -> Self {
        Self {
            inner: Rc::new(RefCell::new(store)),
        }
    }
}

impl TrustStateStore for SharedStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        self.inner.borrow_mut().load(key)
    }

    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.inner
            .borrow_mut()
            .commit_independent_time(key, expected_revision, commit)
    }

    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.inner.borrow_mut().clock_release_consumed(key)
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.inner
            .borrow_mut()
            .commit_registry_selection(key, expected_revision, commit)
    }
}

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

fn persisted_time(floor: i64, reference_time: i64, marker: u8) -> TrustedTimeState {
    TrustedTimeState::from_persisted(
        UnixMillis::new(floor),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            ObjectHash::from(support::hash32(marker)),
            UnixMillis::new(reference_time),
        )),
    )
    .unwrap()
}

fn with_floor_and_same_reference(state: &TrustedTimeState, floor: UnixMillis) -> TrustedTimeState {
    let reference = state.independent_reference().map(|reference| {
        IndependentTimeInput::new(
            reference.kind(),
            reference.object_hash(),
            reference.verified_time(),
        )
    });
    TrustedTimeState::from_persisted(floor, reference).unwrap()
}

fn pin(head: BuiltHead) -> RegistryHeadPin {
    RegistryHeadPin::new(head.version, head.object_hash)
}

fn chain_id() -> ChainId {
    ChainId::try_from(&[0x31; 16][..]).unwrap()
}

fn hash32_from_object(hash: ObjectHash) -> Hash32 {
    Hash32::try_from(hash.as_bytes().as_slice()).unwrap()
}

fn server_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(
        *SigningKey::from_bytes(&SERVER_SECRET)
            .verifying_key()
            .as_bytes(),
    )
    .unwrap()
}

fn receipt_source(
    candidate: &RegistryCandidate,
    authority_head: BuiltHead,
    authority_policy_hash: ObjectHash,
    server_certificate_hash: CertificateHash,
    verified_time: UnixMillis,
) -> VerifiedSignedTime {
    receipt_source_with_hash(
        candidate,
        authority_head,
        authority_policy_hash,
        server_certificate_hash,
        verified_time,
    )
    .0
}

fn receipt_source_with_hash(
    candidate: &RegistryCandidate,
    authority_head: BuiltHead,
    authority_policy_hash: ObjectHash,
    server_certificate_hash: CertificateHash,
    verified_time: UnixMillis,
) -> (VerifiedSignedTime, ObjectHash) {
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: support::organization(),
        chain_id: chain_id(),
        chain_sequence: authority_head.effective_from,
        entry_hash: EntryHash::from(support::hash32(0x61)),
        entry_object_hash: ObjectHash::from(support::hash32(0x62)),
        previous_entry_hash: Some(EntryHash::from(support::hash32(0x60))),
        registry_version: authority_head.version,
        registry_head_hash: hash32_from_object(authority_head.object_hash),
        policy_object_hash: authority_policy_hash,
        initial_grant_plan_hash: support::hash32(0x64),
        initial_grant_object_hashes: vec![ObjectHash::from(support::hash32(0x65))],
        accepted_at_server: verified_time,
        evidence_due_at: None,
        server_key_thumbprint: server_key().thumbprint(),
        server_certificate_hash,
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
        .sign_receipt(core.exact_bytes())
        .unwrap();
    let exact = encode_receipt(&ReceiptV1::new(core, signature).unwrap()).unwrap();
    let receipt: Parsed<ReceiptV1> = match decode_exact_object(exact.as_bytes()).unwrap() {
        ParsedArchiveObject::Receipt(receipt) => receipt,
        _ => panic!("the signed-time fixture must retain an exact Receipt"),
    };
    let object_hash = receipt.object_hash();
    let proof = verify_receipt_time(
        candidate
            .preexisting_authority()
            .expect("the current Head must expose its exact authority"),
        &receipt,
    )
    .unwrap();
    (proof, object_hash)
}

struct ReleaseAuditFields {
    target_device_id: DeviceId,
    admin_binding_hash: ObjectHash,
    signer_certificate_hash: ObjectHash,
    effective_now: UnixMillis,
    trusted_time_floor: UnixMillis,
    observed_os_wall_clock: UnixMillis,
    max_future_clock_skew_ms: u64,
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    guard_policy_object_hash: ObjectHash,
    independent_reference_hash: ObjectHash,
    independent_reference_time: UnixMillis,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    nonce: [u8; 32],
}

fn signed_clock_release(fields: &ReleaseAuditFields) -> Vec<u8> {
    let mut core = Vec::new();
    Encoder::new(&mut core)
        .array(12)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&[0x01; 16])
        .unwrap()
        .bytes(support::organization().as_bytes())
        .unwrap()
        .bytes(fields.target_device_id.as_bytes())
        .unwrap()
        .bytes(fields.admin_binding_hash.as_bytes())
        .unwrap()
        .bytes(fields.signer_certificate_hash.as_bytes())
        .unwrap()
        .u8(6)
        .unwrap()
        .u8(1)
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
        .u8(0)
        .unwrap()
        .bytes(fields.independent_reference_hash.as_bytes())
        .unwrap()
        .i64(fields.independent_reference_time.get())
        .unwrap()
        .u8(1)
        .unwrap()
        .i64(fields.issued_at.get())
        .unwrap()
        .i64(fields.expires_at.get())
        .unwrap()
        .bytes(&fields.nonce)
        .unwrap()
        .array(0)
        .unwrap();
    let cose = CoseSigner::from_secret(SecretBytes::new(ADMIN_ONE_SECRET))
        .sign_local_audit(&core)
        .unwrap();
    let mut exact = Vec::new();
    Encoder::new(&mut exact).array(2).unwrap();
    exact.extend_from_slice(&core);
    exact.extend_from_slice(&cose);
    exact
}

fn standard_release_audit(
    line: &RegistryLineBuilder,
    target_device_id: DeviceId,
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    guard_policy_object_hash: ObjectHash,
    nonce: [u8; 32],
) -> Vec<u8> {
    signed_clock_release(&ReleaseAuditFields {
        target_device_id,
        admin_binding_hash: line.bootstrap_admin_binding_hash(),
        signer_certificate_hash: line.bootstrap_admin_hash(),
        effective_now: UnixMillis::new(1_000),
        trusted_time_floor: UnixMillis::new(1_000),
        observed_os_wall_clock: UnixMillis::new(1_000),
        max_future_clock_skew_ms: 37,
        registry_version,
        registry_head_hash,
        guard_policy_object_hash,
        independent_reference_hash: ObjectHash::from(support::hash32(0xc5)),
        independent_reference_time: UnixMillis::new(900),
        issued_at: UnixMillis::new(950),
        expires_at: UnixMillis::new(1_050),
        nonce,
    })
}

struct ReleaseFixture {
    candidate: RegistryCandidate,
    key: TrustStateKey,
    trusted_time: TrustedTimeState,
    previous_head: BuiltHead,
    candidate_head: BuiltHead,
    os_wall_clock: UnixMillis,
    exact_audit: Vec<u8>,
    expected_replay: ReplayTuple,
}

fn device_id(marker: u8) -> DeviceId {
    DeviceId::try_from(&[marker; 16][..]).unwrap()
}

fn release_fixture(
    nonce: u8,
    candidate_not_after: i64,
    candidate_valid_through: u64,
) -> ReleaseFixture {
    release_fixture_with_times(
        nonce,
        800,
        700,
        candidate_not_after,
        candidate_valid_through,
    )
}

fn release_fixture_with_times(
    nonce: u8,
    candidate_issued_at: i64,
    candidate_not_before: i64,
    candidate_not_after: i64,
    candidate_valid_through: u64,
) -> ReleaseFixture {
    release_fixture_full(
        nonce,
        candidate_issued_at,
        candidate_not_before,
        candidate_not_after,
        candidate_valid_through,
        1_000,
        900,
        1_000,
        37,
    )
}

#[allow(clippy::too_many_arguments)]
fn release_fixture_full(
    nonce: u8,
    candidate_issued_at: i64,
    candidate_not_before: i64,
    candidate_not_after: i64,
    candidate_valid_through: u64,
    floor: i64,
    reference_time: i64,
    os_wall_clock: i64,
    guard_skew: u64,
) -> ReleaseFixture {
    let mut line = RegistryLineBuilder::new();
    let previous_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(guard_skew),
            ..HeadOptions::default()
        },
    );
    let guard_policy_hash = line.current_policy_hash().unwrap();
    let candidate_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(candidate_valid_through),
            issued_at: UnixMillis::new(candidate_issued_at),
            not_before: UnixMillis::new(candidate_not_before),
            not_after: UnixMillis::new(candidate_not_after),
            policy_max_future_clock_skew_ms_override: Some(9_999),
            ..HeadOptions::default()
        },
    );
    let target_device_id = device_id(0x51);
    let key = TrustStateKey {
        organization_id: support::organization(),
        device_id: target_device_id,
    };
    let reference_hash = ObjectHash::from(support::hash32(0xc5));
    let trusted_time = TrustedTimeState::from_persisted(
        UnixMillis::new(floor),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            reference_hash,
            UnixMillis::new(reference_time),
        )),
    )
    .unwrap();
    let trust = line.verified_with_time_and_key(Pin::Head(0), trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    let effective_now = UnixMillis::new(os_wall_clock).max(UnixMillis::new(floor));
    let nonce = [nonce; 32];
    let exact_audit = signed_clock_release(&ReleaseAuditFields {
        target_device_id,
        admin_binding_hash: line.bootstrap_admin_binding_hash(),
        signer_certificate_hash: line.bootstrap_admin_hash(),
        effective_now,
        trusted_time_floor: UnixMillis::new(floor),
        observed_os_wall_clock: UnixMillis::new(os_wall_clock),
        max_future_clock_skew_ms: guard_skew,
        registry_version: candidate_head.version,
        registry_head_hash: candidate_head.object_hash,
        guard_policy_object_hash: guard_policy_hash,
        independent_reference_hash: reference_hash,
        independent_reference_time: UnixMillis::new(reference_time),
        issued_at: UnixMillis::new(effective_now.get() - 50),
        expires_at: UnixMillis::new(effective_now.get() + 50),
        nonce,
    });
    ReleaseFixture {
        candidate,
        key,
        trusted_time,
        previous_head,
        candidate_head,
        os_wall_clock: UnixMillis::new(os_wall_clock),
        exact_audit,
        expected_replay: ReplayTuple {
            organization_id: support::organization(),
            target_device_id,
            nonce,
        },
    }
}

fn prepare_release<'store>(
    fixture: &ReleaseFixture,
    store: &'store mut dyn TrustStateStore,
) -> (LocalTimeBlock<'store>, VerifiedClockRelease) {
    let mut local_time =
        prepare_local_time(store, &fixture.candidate, fixture.os_wall_clock, &[]).unwrap();
    let release =
        verify_clock_release(&fixture.candidate, &mut local_time, &fixture.exact_audit).unwrap();
    (local_time, release)
}

fn detached_release(fixture: &ReleaseFixture) -> VerifiedClockRelease {
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    let mut local_time =
        prepare_local_time(&mut store, &fixture.candidate, fixture.os_wall_clock, &[]).unwrap();
    verify_clock_release(&fixture.candidate, &mut local_time, &fixture.exact_audit).unwrap()
}

fn current_release_fixture(nonce: u8, not_after: i64) -> ReleaseFixture {
    let mut line = RegistryLineBuilder::new();
    let head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            issued_at: UnixMillis::new(100),
            not_before: UnixMillis::new(90),
            not_after: UnixMillis::new(not_after),
            policy_max_future_clock_skew_ms_override: Some(37),
            ..HeadOptions::default()
        },
    );
    let policy_hash = line.current_policy_hash().unwrap();
    let target_device_id = device_id(0x51);
    let key = TrustStateKey {
        organization_id: support::organization(),
        device_id: target_device_id,
    };
    let reference_hash = ObjectHash::from(support::hash32(0xc5));
    let trusted_time = TrustedTimeState::from_persisted(
        UnixMillis::new(1_000),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            reference_hash,
            UnixMillis::new(900),
        )),
    )
    .unwrap();
    let trust = line.verified_with_time_and_key(Pin::Head(0), trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    let nonce = [nonce; 32];
    let exact_audit = signed_clock_release(&ReleaseAuditFields {
        target_device_id,
        admin_binding_hash: line.bootstrap_admin_binding_hash(),
        signer_certificate_hash: line.bootstrap_admin_hash(),
        effective_now: UnixMillis::new(1_000),
        trusted_time_floor: UnixMillis::new(1_000),
        observed_os_wall_clock: UnixMillis::new(1_000),
        max_future_clock_skew_ms: 37,
        registry_version: head.version,
        registry_head_hash: head.object_hash,
        guard_policy_object_hash: policy_hash,
        independent_reference_hash: reference_hash,
        independent_reference_time: UnixMillis::new(900),
        issued_at: UnixMillis::new(950),
        expires_at: UnixMillis::new(1_050),
        nonce,
    });
    ReleaseFixture {
        candidate,
        key,
        trusted_time,
        previous_head: head,
        candidate_head: head,
        os_wall_clock: UnixMillis::new(1_000),
        exact_audit,
        expected_replay: ReplayTuple {
            organization_id: support::organization(),
            target_device_id,
            nonce,
        },
    }
}

struct DirectFixture {
    line: RegistryLineBuilder,
    candidate: RegistryCandidate,
    previous_head: BuiltHead,
    candidate_head: BuiltHead,
    target_policy_hash: ObjectHash,
    key: TrustStateKey,
    trusted_time: TrustedTimeState,
}

#[allow(clippy::too_many_arguments)]
fn direct_fixture(
    previous_valid_through: u64,
    candidate_effective_from: u64,
    candidate_valid_through: u64,
    candidate_issued_at: i64,
    candidate_not_before: i64,
    candidate_not_after: i64,
    proposed_sequence: u64,
    trusted_time: TrustedTimeState,
    guard_skew: u64,
    target_skew: u64,
) -> DirectFixture {
    let mut line = RegistryLineBuilder::new();
    let previous_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(previous_valid_through),
            issued_at: UnixMillis::new(100),
            not_before: UnixMillis::new(90),
            not_after: UnixMillis::new(10_000),
            policy_max_future_clock_skew_ms_override: Some(guard_skew),
            ..HeadOptions::default()
        },
    );
    let candidate_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(candidate_effective_from),
            valid_through: Some(candidate_valid_through),
            issued_at: UnixMillis::new(candidate_issued_at),
            not_before: UnixMillis::new(candidate_not_before),
            not_after: UnixMillis::new(candidate_not_after),
            policy_max_future_clock_skew_ms_override: Some(target_skew),
            ..HeadOptions::default()
        },
    );
    let target_policy_hash = line.current_policy_hash().unwrap();
    let key = support::state_key();
    let proposed_sequence = ChainSequence::new(proposed_sequence);
    let trust = line.verified_with_time(Pin::Head(0), trusted_time.clone());
    let candidate = verify_registry_candidate(&trust, proposed_sequence).unwrap();
    assert_eq!(candidate.registry_version(), candidate_head.version);
    assert!(candidate.registry_head_hash() == candidate_head.object_hash);
    DirectFixture {
        line,
        candidate,
        previous_head,
        candidate_head,
        target_policy_hash,
        key,
        trusted_time,
    }
}

fn prepare<'store>(
    fixture: &DirectFixture,
    store: &'store mut ModelStore,
    os_wall_clock: i64,
) -> LocalTimeBlock<'store> {
    prepare_local_time(
        store,
        &fixture.candidate,
        UnixMillis::new(os_wall_clock),
        &[] as &[VerifiedSignedTime],
    )
    .unwrap()
}

fn assert_blocked_before_later_classification(fixture: DirectFixture) {
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    let before = store.record.clone();
    let local_time = prepare(&fixture, &mut store, 1_000);
    let Err(error) = select_registry_head(fixture.candidate, local_time, None) else {
        panic!("an unresolved skew block cannot produce a later selection outcome");
    };
    assert_eq!(error, RegistryError::FutureSkew);
    assert!(store.record == before);
    assert!(store.selection_commits.is_empty());
    assert_eq!(store.replay_queries, 0);
}

struct SingleHeadFixture {
    candidate: RegistryCandidate,
    head: BuiltHead,
    policy_hash: ObjectHash,
    key: TrustStateKey,
    trusted_time: TrustedTimeState,
    original_pin: Option<RegistryHeadPin>,
}

struct PendingSetup {
    line: RegistryLineBuilder,
    pending: PendingFutureSuccessor,
    previous_head: BuiltHead,
    successor_head: BuiltHead,
    key: TrustStateKey,
    trusted_time: TrustedTimeState,
}

struct ReceiptPendingSetup {
    line: RegistryLineBuilder,
    pending: PendingFutureSuccessor,
    current_head: BuiltHead,
    key: TrustStateKey,
    initial_time: TrustedTimeState,
    committed_time: TrustedTimeState,
    committed_revision: u64,
}

fn pending_after_real_receipt() -> ReceiptPendingSetup {
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
    let current_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(100),
            ..HeadOptions::default()
        },
    );
    let current_policy_hash = line.current_policy_hash().unwrap();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_400),
            not_before: UnixMillis::new(1_300),
            not_after: UnixMillis::new(3_000),
            ..HeadOptions::default()
        },
    );

    let key = support::state_key();
    let initial_time = persisted_time(900, 850, 0x82);
    let trust =
        line.verified_with_record(Pin::Head(2), INITIAL_REVISION, initial_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    let source = receipt_source(
        &candidate,
        current_head,
        current_policy_hash,
        CertificateHash::from(server_head.direct_object_hash.unwrap()),
        UnixMillis::new(950),
    );
    let mut store = ModelStore::new(key, initial_time.clone(), Some(pin(current_head)));
    store.set_next_revision(29);
    let local_time = prepare_local_time(
        &mut store,
        &candidate,
        UnixMillis::new(950),
        core::slice::from_ref(&source),
    )
    .unwrap();
    let RegistrySelectionOutcome::PendingFuture(pending) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the successor must remain future after the real Receipt commit");
    };
    assert_eq!(store.independent_commits, 1);
    assert_eq!(store.record.revision, 29);
    assert!(store.record.trusted_time != initial_time);
    assert!(store.selection_commits.is_empty());

    ReceiptPendingSetup {
        line,
        pending,
        current_head,
        key,
        initial_time,
        committed_time: store.record.trusted_time,
        committed_revision: store.record.revision,
    }
}

fn pending_setup() -> PendingSetup {
    let fixture = direct_fixture(
        100,
        50,
        200,
        1_200,
        1_100,
        2_000,
        60,
        persisted_time(900, 900, 0x41),
        50,
        5_000,
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    let before = store.record.clone();
    let local_time = prepare(&fixture, &mut store, 950);
    let RegistrySelectionOutcome::PendingFuture(pending) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("the direct successor must produce the fallback proof");
    };
    assert!(store.record == before);
    assert!(store.selection_commits.is_empty());

    PendingSetup {
        line: fixture.line,
        pending,
        previous_head: fixture.previous_head,
        successor_head: fixture.candidate_head,
        key: fixture.key,
        trusted_time: fixture.trusted_time,
    }
}

fn pending_setup_with_guard_and_current_expiry(
    guard_skew: u64,
    current_not_after: i64,
) -> PendingSetup {
    let mut line = RegistryLineBuilder::new();
    let previous_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            issued_at: UnixMillis::new(100),
            not_before: UnixMillis::new(90),
            not_after: UnixMillis::new(current_not_after),
            policy_max_future_clock_skew_ms_override: Some(guard_skew),
            ..HeadOptions::default()
        },
    );
    let successor_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_200),
            not_before: UnixMillis::new(1_100),
            not_after: UnixMillis::new(2_000),
            ..HeadOptions::default()
        },
    );
    let key = support::state_key();
    let trusted_time = persisted_time(900, 900, 0x7c);
    let trust = line.verified_with_time(Pin::Head(0), trusted_time.clone());
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    let mut store = ModelStore::new(key, trusted_time.clone(), Some(pin(previous_head)));
    let local_time = prepare_local_time(&mut store, &candidate, UnixMillis::new(950), &[]).unwrap();
    let RegistrySelectionOutcome::PendingFuture(pending) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the custom direct successor must initially be PendingFuture");
    };
    assert!(store.selection_commits.is_empty());
    PendingSetup {
        line,
        pending,
        previous_head,
        successor_head,
        key,
        trusted_time,
    }
}

struct FallbackContext {
    line: RegistryLineBuilder,
    previous_head: BuiltHead,
    successor_head: BuiltHead,
    key: TrustStateKey,
    trusted_time: TrustedTimeState,
}

fn fallback_candidate(setup: PendingSetup) -> (RegistryCandidate, FallbackContext) {
    let PendingSetup {
        line,
        pending,
        previous_head,
        successor_head,
        key,
        trusted_time,
    } = setup;
    let trust =
        line.verified_with_record(Pin::Head(0), INITIAL_REVISION, trusted_time.clone(), key);
    let candidate = verify_current_head_fallback(&trust, pending);
    let Ok(candidate) = candidate else {
        panic!("the exact pending snapshot and topology must permit fallback");
    };
    assert_eq!(candidate.registry_version(), previous_head.version);
    assert!(candidate.registry_head_hash() == previous_head.object_hash);
    (
        candidate,
        FallbackContext {
            line,
            previous_head,
            successor_head,
            key,
            trusted_time,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn single_head_fixture(
    pinned: bool,
    effective_from: u64,
    valid_through: u64,
    issued_at: i64,
    not_before: i64,
    not_after: i64,
    proposed_sequence: u64,
    trusted_time: TrustedTimeState,
    max_future_skew: u64,
) -> SingleHeadFixture {
    let mut line = RegistryLineBuilder::new();
    let head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(effective_from),
            valid_through: Some(valid_through),
            issued_at: UnixMillis::new(issued_at),
            not_before: UnixMillis::new(not_before),
            not_after: UnixMillis::new(not_after),
            policy_max_future_clock_skew_ms_override: Some(max_future_skew),
            ..HeadOptions::default()
        },
    );
    let policy_hash = line.current_policy_hash().unwrap();
    let key = support::state_key();
    let trust = line.verified_with_time(
        if pinned { Pin::Head(0) } else { Pin::None },
        trusted_time.clone(),
    );
    let candidate =
        verify_registry_candidate(&trust, ChainSequence::new(proposed_sequence)).unwrap();
    assert_eq!(candidate.registry_version(), head.version);
    assert!(candidate.registry_head_hash() == head.object_hash);
    SingleHeadFixture {
        candidate,
        head,
        policy_hash,
        key,
        trusted_time,
        original_pin: pinned.then(|| pin(head)),
    }
}

#[test]
fn public_selection_api_and_stable_error_codes_are_pinned() {
    let _: for<'a> fn(
        RegistryCandidate,
        LocalTimeBlock<'a>,
        Option<VerifiedClockRelease>,
    ) -> Result<RegistrySelectionOutcome, RegistryError> = select_registry_head;
    let _: fn(&VerifiedTrust, PendingFutureSuccessor) -> Result<RegistryCandidate, RegistryError> =
        verify_current_head_fallback;

    let _ = core::any::type_name::<PreexistingEffectiveNow>();
    let _ = core::any::type_name::<SelectedRegistryHead>();
    let _ = core::any::type_name::<AdvancedRegistryHead>();

    assert_eq!(
        RegistryError::PendingFuture.code(),
        "EA-TRUST-PENDING-FUTURE"
    );
    assert_eq!(
        RegistryError::SuccessorReady.code(),
        "EA-TRUST-SUCCESSOR-READY"
    );
    assert_eq!(RegistryError::Stale.code(), "EA-TRUST-STALE");
    assert_eq!(RegistryError::FutureSkew.code(), "EA-TRUST-FUTURE-SKEW");
}

#[test]
fn applicable_direct_successor_is_selected_and_committed_atomically() {
    let fixture = direct_fixture(
        100,
        50,
        200,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 970, 0x31),
        37,
        9_999,
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    store.set_next_revision(41);
    let local_time = prepare(&fixture, &mut store, 1_000);

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("an applicable direct successor must authorize the operation");
    };

    assert_eq!(selected.registry_version(), fixture.candidate_head.version);
    assert!(selected.registry_head_hash() == fixture.candidate_head.object_hash);
    assert!(selected.policy_object_hash() == fixture.target_policy_hash);
    assert_eq!(selected.policy_fields().max_future_clock_skew_ms, 9_999);
    assert_eq!(
        selected.effective_from_sequence(),
        fixture.candidate_head.effective_from
    );
    assert_eq!(
        selected.valid_through_sequence(),
        fixture.candidate_head.valid_through
    );
    assert_eq!(
        selected.preexisting_effective_now().value(),
        UnixMillis::new(1_000)
    );
    assert!(!selected.warnings().clock_rollback());
    assert!(!selected.warnings().independent_time_unavailable());

    assert_eq!(store.selection_commits.len(), 1);
    let observed = &store.selection_commits[0];
    assert!(observed.key == fixture.key);
    assert_eq!(observed.expected_revision, INITIAL_REVISION);
    assert!(observed.next_trusted_time == fixture.trusted_time);
    assert!(observed.next_head == pin(fixture.candidate_head));
    assert!(observed.replay_key.is_none());
    assert_eq!(store.record.revision, 41);
    assert!(store.record.trusted_time == fixture.trusted_time);
    assert!(store.record.pinned_head == Some(pin(fixture.candidate_head)));
    assert_eq!(store.replay_queries, 0);
}

#[test]
fn current_head_selection_compare_and_affirms_the_exact_state() {
    let fixture = single_head_fixture(
        true,
        1,
        100,
        100,
        90,
        2_000,
        60,
        persisted_time(1_000, 970, 0x32),
        41,
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        fixture.original_pin,
    );
    store.set_next_revision(53);
    let local_time =
        prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(1_000), &[]).unwrap();

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("a fresh current Head must authorize the operation");
    };

    assert_eq!(selected.registry_version(), fixture.head.version);
    assert!(selected.registry_head_hash() == fixture.head.object_hash);
    assert!(selected.policy_object_hash() == fixture.policy_hash);
    assert_eq!(store.selection_commits.len(), 1);
    assert_eq!(
        store.selection_commits[0].expected_revision,
        INITIAL_REVISION
    );
    assert!(store.selection_commits[0].next_trusted_time == fixture.trusted_time);
    assert!(store.selection_commits[0].next_head == pin(fixture.head));
    assert_eq!(store.record.revision, 53);
    assert!(store.record.pinned_head == fixture.original_pin);
}

#[test]
fn bootstrap_head_uses_its_verified_initial_policy_and_commits_the_first_pin() {
    let fixture = single_head_fixture(
        false,
        1,
        100,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 970, 0x33),
        43,
    );
    let mut store = ModelStore::new(fixture.key, fixture.trusted_time.clone(), None);
    store.set_next_revision(67);
    let local_time =
        prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(1_000), &[]).unwrap();

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("the verified Bootstrap Head must be selectable");
    };

    assert!(selected.policy_object_hash() == fixture.policy_hash);
    assert_eq!(selected.policy_fields().max_future_clock_skew_ms, 43);
    assert_eq!(store.selection_commits.len(), 1);
    assert!(store.selection_commits[0].next_head == pin(fixture.head));
    assert_eq!(store.record.revision, 67);
    assert!(store.record.pinned_head == Some(pin(fixture.head)));
}

#[test]
fn future_successor_cannot_self_activate_from_its_own_event_times() {
    let fixture = direct_fixture(
        100,
        50,
        200,
        1_200,
        1_100,
        2_000,
        60,
        persisted_time(900, 900, 0x34),
        50,
        5_000,
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    let before = store.record.clone();
    let local_time = prepare(&fixture, &mut store, 950);

    let RegistrySelectionOutcome::PendingFuture(_pending) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("the direct successor must remain PendingFuture");
    };

    assert!(store.record == before);
    assert!(store.selection_commits.is_empty());
    assert_eq!(store.replay_queries, 0);
}

#[test]
fn future_successor_without_a_covering_predecessor_is_an_error() {
    let fixture = direct_fixture(
        55,
        50,
        200,
        1_200,
        1_100,
        2_000,
        60,
        persisted_time(900, 900, 0x35),
        50,
        5_000,
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    let before = store.record.clone();
    let local_time = prepare(&fixture, &mut store, 950);

    let Err(error) = select_registry_head(fixture.candidate, local_time, None) else {
        panic!("an uncovered future successor cannot produce an outcome");
    };

    assert_eq!(error, RegistryError::PendingFuture);
    assert!(store.record == before);
    assert!(store.selection_commits.is_empty());
    assert_eq!(store.replay_queries, 0);
}

#[test]
fn future_bootstrap_head_has_no_predecessor_fallback() {
    let fixture = single_head_fixture(
        false,
        1,
        100,
        1_200,
        1_100,
        2_000,
        60,
        persisted_time(900, 900, 0x36),
        50,
    );
    let mut store = ModelStore::new(fixture.key, fixture.trusted_time.clone(), None);
    let before = store.record.clone();
    let local_time =
        prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(950), &[]).unwrap();

    let Err(error) = select_registry_head(fixture.candidate, local_time, None) else {
        panic!("a future Bootstrap Head cannot produce an outcome");
    };

    assert_eq!(error, RegistryError::PendingFuture);
    assert!(store.record == before);
    assert!(store.selection_commits.is_empty());
}

#[test]
fn reached_successor_raises_only_the_registry_floor_and_retains_the_reference() {
    let initial_time = persisted_time(700, 650, 0x37);
    let fixture = direct_fixture(
        100,
        50,
        200,
        850,
        800,
        2_000,
        60,
        initial_time.clone(),
        300,
        7_000,
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    store.set_next_revision(79);
    let local_time = prepare(&fixture, &mut store, 900);

    let RegistrySelectionOutcome::Selected(_) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("the reached direct successor must be selected");
    };

    assert_eq!(store.selection_commits.len(), 1);
    let committed_time = &store.selection_commits[0].next_trusted_time;
    assert_eq!(committed_time.floor(), UnixMillis::new(850));
    assert!(committed_time.independent_reference() == initial_time.independent_reference());
    assert_eq!(
        committed_time
            .independent_reference()
            .expect("the Registry floor cannot replace the reference")
            .verified_time(),
        UnixMillis::new(650)
    );
    assert!(store.record.trusted_time == *committed_time);
    assert!(store.record.pinned_head == Some(pin(fixture.candidate_head)));
    assert_eq!(store.record.revision, 79);
}

#[test]
fn exact_pending_fallback_selects_the_still_covering_current_head() {
    let (candidate, context) = fallback_candidate(pending_setup());
    let mut store = ModelStore::new(
        context.key,
        context.trusted_time.clone(),
        Some(pin(context.previous_head)),
    );
    store.set_next_revision(83);
    let local_time = prepare_local_time(&mut store, &candidate, UnixMillis::new(950), &[]).unwrap();

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the still-future direct successor must leave the predecessor usable");
    };

    assert_eq!(selected.registry_version(), context.previous_head.version);
    assert!(selected.registry_head_hash() == context.previous_head.object_hash);
    assert_eq!(
        selected.preexisting_effective_now().value(),
        UnixMillis::new(950)
    );
    assert_eq!(store.selection_commits.len(), 1);
    assert!(store.selection_commits[0].next_head == pin(context.previous_head));
    assert!(store.selection_commits[0].next_trusted_time == context.trusted_time);
    assert_eq!(store.record.revision, 83);
}

#[test]
fn pending_proof_binds_the_post_task9_revision_and_full_trusted_time() {
    let exact = pending_after_real_receipt();
    assert_eq!(exact.committed_revision, 29);
    assert!(exact.committed_time != exact.initial_time);
    assert_eq!(
        exact
            .committed_time
            .independent_reference()
            .expect("the real Receipt must become the retained reference")
            .verified_time(),
        UnixMillis::new(950)
    );
    let exact_trust = exact.line.verified_with_record(
        Pin::Head(2),
        exact.committed_revision,
        exact.committed_time,
        exact.key,
    );
    let exact_candidate = verify_current_head_fallback(&exact_trust, exact.pending).unwrap();
    assert_eq!(
        exact_candidate.registry_version(),
        exact.current_head.version
    );
    assert!(exact_candidate.registry_head_hash() == exact.current_head.object_hash);

    let stale = pending_after_real_receipt();
    let stale_trust = stale.line.verified_with_record(
        Pin::Head(2),
        INITIAL_REVISION,
        stale.initial_time,
        stale.key,
    );
    let Err(error) = verify_current_head_fallback(&stale_trust, stale.pending) else {
        panic!("a pre-Task9 snapshot cannot consume a post-Task9 pending proof");
    };
    assert_eq!(error, RegistryError::Trust(TrustError::StateConflict));
}

#[test]
fn same_flow_receipt_commit_can_activate_and_select_the_direct_successor() {
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
    let current_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(100),
            ..HeadOptions::default()
        },
    );
    let current_policy_hash = line.current_policy_hash().unwrap();
    let successor_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_200),
            not_before: UnixMillis::new(1_200),
            not_after: UnixMillis::new(3_000),
            ..HeadOptions::default()
        },
    );
    let key = support::state_key();
    let initial_time = persisted_time(900, 850, 0x83);
    let trust =
        line.verified_with_record(Pin::Head(2), INITIAL_REVISION, initial_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    assert!(initial_time.floor() < UnixMillis::new(1_200));
    let (source, receipt_hash) = receipt_source_with_hash(
        &candidate,
        current_head,
        current_policy_hash,
        CertificateHash::from(server_head.direct_object_hash.unwrap()),
        UnixMillis::new(1_200),
    );
    let mut store = ModelStore::new(key, initial_time, Some(pin(current_head)));
    store.set_revision_sequence(29, 47);
    let local_time = prepare_local_time(
        &mut store,
        &candidate,
        UnixMillis::new(950),
        core::slice::from_ref(&source),
    )
    .unwrap();

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the real Receipt must make the exact-boundary successor selectable");
    };

    assert_eq!(selected.registry_version(), successor_head.version);
    assert!(selected.registry_head_hash() == successor_head.object_hash);
    assert_eq!(
        selected.preexisting_effective_now().value(),
        UnixMillis::new(1_200)
    );
    assert!(selected.warnings().clock_rollback());
    assert!(!selected.warnings().independent_time_unavailable());
    assert_eq!(store.independent_commits, 1);
    assert_eq!(store.selection_commits.len(), 1);
    let selection = &store.selection_commits[0];
    assert_eq!(selection.expected_revision, 29);
    assert_eq!(selection.next_trusted_time.floor(), UnixMillis::new(1_200));
    let reference = selection
        .next_trusted_time
        .independent_reference()
        .expect("the selected state must retain the exact Receipt reference");
    assert_eq!(reference.kind(), IndependentTimeKind::Receipt);
    assert!(reference.object_hash() == receipt_hash);
    assert_eq!(reference.verified_time(), UnixMillis::new(1_200));
    assert!(selection.next_head == pin(successor_head));
    assert_eq!(store.record.revision, 47);
    assert!(store.record.trusted_time == selection.next_trusted_time);
}

#[test]
fn same_flow_receipt_commit_is_used_by_current_compare_and_affirm() {
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
    let current_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(100),
            not_after: UnixMillis::new(3_000),
            policy_max_future_clock_skew_ms_override: Some(100),
            ..HeadOptions::default()
        },
    );
    let current_policy_hash = line.current_policy_hash().unwrap();
    let key = support::state_key();
    let initial_time = persisted_time(900, 850, 0x84);
    let trust =
        line.verified_with_record(Pin::Head(2), INITIAL_REVISION, initial_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    let (source, receipt_hash) = receipt_source_with_hash(
        &candidate,
        current_head,
        current_policy_hash,
        CertificateHash::from(server_head.direct_object_hash.unwrap()),
        UnixMillis::new(1_200),
    );
    let mut store = ModelStore::new(key, initial_time, Some(pin(current_head)));
    store.set_revision_sequence(29, 47);
    let local_time = prepare_local_time(
        &mut store,
        &candidate,
        UnixMillis::new(950),
        core::slice::from_ref(&source),
    )
    .unwrap();

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the current compare-and-affirm path must consume the post-Task9 state");
    };

    assert_eq!(selected.registry_version(), current_head.version);
    assert!(selected.registry_head_hash() == current_head.object_hash);
    assert_eq!(
        selected.preexisting_effective_now().value(),
        UnixMillis::new(1_200)
    );
    assert!(selected.warnings().clock_rollback());
    assert_eq!(store.independent_commits, 1);
    assert_eq!(store.selection_commits.len(), 1);
    let selection = &store.selection_commits[0];
    assert_eq!(selection.expected_revision, 29);
    assert!(selection.next_head == pin(current_head));
    assert_eq!(selection.next_trusted_time.floor(), UnixMillis::new(1_200));
    let reference = selection
        .next_trusted_time
        .independent_reference()
        .expect("the current commit must retain the exact Receipt");
    assert!(reference.object_hash() == receipt_hash);
    assert_eq!(reference.verified_time(), UnixMillis::new(1_200));
    assert_eq!(store.record.revision, 47);
    assert!(store.record.trusted_time == selection.next_trusted_time);
    assert!(store.record.pinned_head == Some(pin(current_head)));
}

#[test]
fn same_flow_receipt_commit_is_used_by_advanced_catch_up() {
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
    let current_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(100),
            ..HeadOptions::default()
        },
    );
    let current_policy_hash = line.current_policy_hash().unwrap();
    let successor_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_200),
            not_before: UnixMillis::new(1_100),
            not_after: UnixMillis::new(1_250),
            ..HeadOptions::default()
        },
    );
    let key = support::state_key();
    let initial_time = persisted_time(900, 850, 0x85);
    let trust =
        line.verified_with_record(Pin::Head(2), INITIAL_REVISION, initial_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    let (source, receipt_hash) = receipt_source_with_hash(
        &candidate,
        current_head,
        current_policy_hash,
        CertificateHash::from(server_head.direct_object_hash.unwrap()),
        UnixMillis::new(1_300),
    );
    let mut store = ModelStore::new(key, initial_time, Some(pin(current_head)));
    store.set_revision_sequence(29, 47);
    let local_time = prepare_local_time(
        &mut store,
        &candidate,
        UnixMillis::new(950),
        core::slice::from_ref(&source),
    )
    .unwrap();

    let RegistrySelectionOutcome::Advanced(advanced) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the Receipt-reached stale successor must remain non-authoritative");
    };

    assert_eq!(advanced.registry_version(), successor_head.version);
    assert!(advanced.registry_head_hash() == successor_head.object_hash);
    assert_eq!(advanced.committed_revision(), 47);
    assert_eq!(store.independent_commits, 1);
    assert_eq!(store.selection_commits.len(), 1);
    let selection = &store.selection_commits[0];
    assert_eq!(selection.expected_revision, 29);
    assert!(selection.next_head == pin(successor_head));
    assert_eq!(selection.next_trusted_time.floor(), UnixMillis::new(1_300));
    let reference = selection
        .next_trusted_time
        .independent_reference()
        .expect("the Advanced commit must retain the exact Receipt");
    assert!(reference.object_hash() == receipt_hash);
    assert_eq!(reference.verified_time(), UnixMillis::new(1_300));
    assert_eq!(store.record.revision, 47);
    assert!(store.record.trusted_time == selection.next_trusted_time);
    assert!(store.record.pinned_head == Some(pin(successor_head)));
}

#[test]
fn fallback_staleness_and_successor_ready_have_exact_precedence() {
    let (stale_candidate, stale_context) =
        fallback_candidate(pending_setup_with_guard_and_current_expiry(300, 975));
    let mut stale_store = ModelStore::new(
        stale_context.key,
        stale_context.trusted_time.clone(),
        Some(pin(stale_context.previous_head)),
    );
    let stale_before = stale_store.record.clone();
    let stale_time = prepare_local_time(
        &mut stale_store,
        &stale_candidate,
        UnixMillis::new(1_000),
        &[],
    )
    .unwrap();
    let Err(stale_error) = select_registry_head(stale_candidate, stale_time, None) else {
        panic!("a stale fallback Head cannot authorize while the successor remains future");
    };
    assert_eq!(stale_error, RegistryError::Stale);
    assert!(stale_store.record == stale_before);
    assert!(stale_store.selection_commits.is_empty());

    let (ready_candidate, ready_context) =
        fallback_candidate(pending_setup_with_guard_and_current_expiry(300, 975));
    let mut ready_store = ModelStore::new(
        ready_context.key,
        ready_context.trusted_time.clone(),
        Some(pin(ready_context.previous_head)),
    );
    let ready_before = ready_store.record.clone();
    let ready_time = prepare_local_time(
        &mut ready_store,
        &ready_candidate,
        UnixMillis::new(1_200),
        &[],
    )
    .unwrap();
    let Err(ready_error) = select_registry_head(ready_candidate, ready_time, None) else {
        panic!("a reached successor must defeat fallback before current staleness");
    };
    assert_eq!(ready_error, RegistryError::SuccessorReady);
    assert!(ready_store.record == ready_before);
    assert!(ready_store.selection_commits.is_empty());

    let (blocked_candidate, blocked_context) =
        fallback_candidate(pending_setup_with_guard_and_current_expiry(100, 10_000));
    let mut blocked_store = ModelStore::new(
        blocked_context.key,
        blocked_context.trusted_time.clone(),
        Some(pin(blocked_context.previous_head)),
    );
    let blocked_before = blocked_store.record.clone();
    let blocked_time = prepare_local_time(
        &mut blocked_store,
        &blocked_candidate,
        UnixMillis::new(1_200),
        &[],
    )
    .unwrap();
    let Err(blocked_error) = select_registry_head(blocked_candidate, blocked_time, None) else {
        panic!("unreleased blocked skew must fail before a ready fallback barrier");
    };
    assert_eq!(blocked_error, RegistryError::FutureSkew);
    assert!(blocked_store.record == blocked_before);
    assert!(blocked_store.selection_commits.is_empty());
    assert_eq!(blocked_store.replay_queries, 0);

    let (paired_candidate, paired_context) =
        fallback_candidate(pending_setup_with_guard_and_current_expiry(300, 10_000));
    let mut paired_store = ModelStore::new(
        paired_context.key,
        paired_context.trusted_time.clone(),
        Some(pin(paired_context.previous_head)),
    );
    let paired_before = paired_store.record.clone();
    let paired_time = prepare_local_time(
        &mut paired_store,
        &paired_candidate,
        UnixMillis::new(1_200),
        &[],
    )
    .unwrap();
    let foreign_release = detached_release(&release_fixture(0xf4, 2_000, 200));
    let Err(paired_error) =
        select_registry_head(paired_candidate, paired_time, Some(foreign_release))
    else {
        panic!("an unnecessary or foreign Release must fail before the ready barrier");
    };
    assert_eq!(paired_error, RegistryError::FutureSkew);
    assert!(paired_store.record == paired_before);
    assert!(paired_store.selection_commits.is_empty());
}

#[test]
fn pending_fallback_current_head_accepts_only_its_own_exact_release() {
    let mut line = RegistryLineBuilder::new();
    let current_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(37),
            ..HeadOptions::default()
        },
    );
    let guard_policy_hash = line.current_policy_hash().unwrap();
    let successor_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_200),
            not_before: UnixMillis::new(1_100),
            not_after: UnixMillis::new(2_000),
            ..HeadOptions::default()
        },
    );
    let target_device_id = device_id(0x51);
    let key = TrustStateKey {
        organization_id: support::organization(),
        device_id: target_device_id,
    };
    let trusted_time = TrustedTimeState::from_persisted(
        UnixMillis::new(1_000),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            ObjectHash::from(support::hash32(0xc5)),
            UnixMillis::new(900),
        )),
    )
    .unwrap();
    let trust = line.verified_with_time_and_key(Pin::Head(0), trusted_time.clone(), key);
    let successor = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    let successor_audit = standard_release_audit(
        &line,
        target_device_id,
        successor_head.version,
        successor_head.object_hash,
        guard_policy_hash,
        [0xe1; 32],
    );
    let mut store = ModelStore::new(key, trusted_time.clone(), Some(pin(current_head)));
    let mut successor_time =
        prepare_local_time(&mut store, &successor, UnixMillis::new(1_000), &[]).unwrap();
    let successor_release =
        verify_clock_release(&successor, &mut successor_time, &successor_audit).unwrap();
    let RegistrySelectionOutcome::PendingFuture(pending) =
        select_registry_head(successor, successor_time, Some(successor_release)).unwrap()
    else {
        panic!("a Release cannot lift the proof-bound successor's future timing");
    };
    assert_eq!(store.replay_queries, 1);
    assert!(store.selection_commits.is_empty());
    assert!(store.consumed_replays.is_empty());

    let reloaded =
        line.verified_with_record(Pin::Head(0), INITIAL_REVISION, trusted_time.clone(), key);
    let current = verify_current_head_fallback(&reloaded, pending);
    let Ok(current) = current else {
        panic!("the exact Pending proof must reconstruct the current Head");
    };
    let current_audit = standard_release_audit(
        &line,
        target_device_id,
        current_head.version,
        current_head.object_hash,
        guard_policy_hash,
        [0xe2; 32],
    );
    store.set_next_revision(113);
    let mut current_time =
        prepare_local_time(&mut store, &current, UnixMillis::new(1_000), &[]).unwrap();
    let current_release =
        verify_clock_release(&current, &mut current_time, &current_audit).unwrap();
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(current, current_time, Some(current_release)).unwrap()
    else {
        panic!("the exact current fallback Release must lift only its skew block");
    };

    assert_eq!(selected.registry_version(), current_head.version);
    assert_eq!(store.replay_queries, 2);
    assert_eq!(store.selection_commits.len(), 1);
    let expected = ReplayTuple {
        organization_id: support::organization(),
        target_device_id,
        nonce: [0xe2; 32],
    };
    assert!(store.selection_commits[0].replay_key.as_ref() == Some(&expected));
    assert!(store.consumed_replays == vec![expected]);
    assert!(store.record.pinned_head == Some(pin(current_head)));
    assert_eq!(store.record.revision, 113);
}

#[test]
fn exact_current_release_lifts_skew_before_the_ready_successor_barrier() {
    let mut line = RegistryLineBuilder::new();
    let current_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            not_after: UnixMillis::new(10_000),
            policy_max_future_clock_skew_ms_override: Some(100),
            ..HeadOptions::default()
        },
    );
    let guard_policy_hash = line.current_policy_hash().unwrap();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_200),
            not_before: UnixMillis::new(1_100),
            not_after: UnixMillis::new(2_000),
            ..HeadOptions::default()
        },
    );
    let target_device_id = device_id(0x51);
    let key = TrustStateKey {
        organization_id: support::organization(),
        device_id: target_device_id,
    };
    let reference_hash = ObjectHash::from(support::hash32(0xc6));
    let trusted_time = TrustedTimeState::from_persisted(
        UnixMillis::new(900),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            reference_hash,
            UnixMillis::new(900),
        )),
    )
    .unwrap();
    let trust = line.verified_with_time_and_key(Pin::Head(0), trusted_time.clone(), key);
    let successor = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    let mut store = ModelStore::new(key, trusted_time.clone(), Some(pin(current_head)));
    let successor_time =
        prepare_local_time(&mut store, &successor, UnixMillis::new(950), &[]).unwrap();
    let RegistrySelectionOutcome::PendingFuture(pending) =
        select_registry_head(successor, successor_time, None).unwrap()
    else {
        panic!("the successor must initially be future with no skew defect");
    };

    let reloaded = line.verified_with_record(Pin::Head(0), INITIAL_REVISION, trusted_time, key);
    let current = verify_current_head_fallback(&reloaded, pending).unwrap();
    let audit = signed_clock_release(&ReleaseAuditFields {
        target_device_id,
        admin_binding_hash: line.bootstrap_admin_binding_hash(),
        signer_certificate_hash: line.bootstrap_admin_hash(),
        effective_now: UnixMillis::new(1_200),
        trusted_time_floor: UnixMillis::new(900),
        observed_os_wall_clock: UnixMillis::new(1_200),
        max_future_clock_skew_ms: 100,
        registry_version: current_head.version,
        registry_head_hash: current_head.object_hash,
        guard_policy_object_hash: guard_policy_hash,
        independent_reference_hash: reference_hash,
        independent_reference_time: UnixMillis::new(900),
        issued_at: UnixMillis::new(1_150),
        expires_at: UnixMillis::new(1_250),
        nonce: [0xe3; 32],
    });
    let before = store.record.clone();
    let mut current_time =
        prepare_local_time(&mut store, &current, UnixMillis::new(1_200), &[]).unwrap();
    let release = verify_clock_release(&current, &mut current_time, &audit).unwrap();
    let Err(error) = select_registry_head(current, current_time, Some(release)) else {
        panic!("a valid Release cannot retain current authority after H2 becomes ready");
    };

    assert_eq!(error, RegistryError::SuccessorReady);
    assert_eq!(store.replay_queries, 1);
    assert!(store.selection_commits.is_empty());
    assert!(store.consumed_replays.is_empty());
    assert!(store.record == before);
}

#[test]
fn pending_fallback_rejects_any_reload_snapshot_drift() {
    let revision = pending_setup();
    let revision_trust = revision.line.verified_with_record(
        Pin::Head(0),
        INITIAL_REVISION + 1,
        revision.trusted_time.clone(),
        revision.key,
    );
    let Err(revision_error) = verify_current_head_fallback(&revision_trust, revision.pending)
    else {
        panic!("a revision drift cannot yield a fallback candidate");
    };
    assert_eq!(
        revision_error,
        RegistryError::Trust(TrustError::StateConflict)
    );

    let time = pending_setup();
    let changed_time = persisted_time(901, 900, 0x41);
    let time_trust =
        time.line
            .verified_with_record(Pin::Head(0), INITIAL_REVISION, changed_time, time.key);
    let Err(time_error) = verify_current_head_fallback(&time_trust, time.pending) else {
        panic!("a trusted-time drift cannot yield a fallback candidate");
    };
    assert_eq!(time_error, RegistryError::Trust(TrustError::StateConflict));

    let reference = pending_setup();
    let changed_reference = TrustedTimeState::from_persisted(
        UnixMillis::new(900),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Checkpoint,
            ObjectHash::from(support::hash32(0x42)),
            UnixMillis::new(900),
        )),
    )
    .unwrap();
    let reference_trust = reference.line.verified_with_record(
        Pin::Head(0),
        INITIAL_REVISION,
        changed_reference,
        reference.key,
    );
    let Err(reference_error) = verify_current_head_fallback(&reference_trust, reference.pending)
    else {
        panic!("an independent-reference identity drift cannot yield a fallback candidate");
    };
    assert_eq!(
        reference_error,
        RegistryError::Trust(TrustError::StateConflict)
    );

    let key = pending_setup();
    let foreign_key = TrustStateKey {
        organization_id: key.key.organization_id,
        device_id: DeviceId::try_from(&[0x77; 16][..]).unwrap(),
    };
    let key_trust = key.line.verified_with_record(
        Pin::Head(0),
        INITIAL_REVISION,
        key.trusted_time.clone(),
        foreign_key,
    );
    let Err(key_error) = verify_current_head_fallback(&key_trust, key.pending) else {
        panic!("a state-key drift cannot yield a fallback candidate");
    };
    assert_eq!(key_error, RegistryError::Trust(TrustError::StateConflict));

    let pin_setup = pending_setup();
    let foreign_pin = Pin::Exact(
        pin_setup.previous_head.version,
        ObjectHash::from(support::hash32(0xe7)),
    );
    let pin_trust = pin_setup.line.verified_with_record(
        foreign_pin,
        INITIAL_REVISION,
        pin_setup.trusted_time.clone(),
        pin_setup.key,
    );
    let Err(pin_error) = verify_current_head_fallback(&pin_trust, pin_setup.pending) else {
        panic!("a pinned-Head drift cannot yield a fallback candidate");
    };
    assert_eq!(pin_error, RegistryError::Trust(TrustError::StateConflict));

    let missing_pin = pending_setup();
    let missing_pin_trust = missing_pin.line.verified_with_record(
        Pin::None,
        INITIAL_REVISION,
        missing_pin.trusted_time.clone(),
        missing_pin.key,
    );
    let Err(missing_pin_error) =
        verify_current_head_fallback(&missing_pin_trust, missing_pin.pending)
    else {
        panic!("removing the bound pin cannot yield a fallback candidate");
    };
    assert_eq!(
        missing_pin_error,
        RegistryError::Trust(TrustError::StateConflict)
    );

    let version_pin = pending_setup();
    let version_only_pin = Pin::Exact(
        RegistryVersion::new(version_pin.previous_head.version.get() + 1),
        version_pin.previous_head.object_hash,
    );
    let version_pin_trust = version_pin.line.verified_with_record(
        version_only_pin,
        INITIAL_REVISION,
        version_pin.trusted_time.clone(),
        version_pin.key,
    );
    let Err(version_pin_error) =
        verify_current_head_fallback(&version_pin_trust, version_pin.pending)
    else {
        panic!("changing only the bound pin version cannot yield a fallback candidate");
    };
    assert_eq!(
        version_pin_error,
        RegistryError::Trust(TrustError::StateConflict)
    );
}

#[test]
fn pending_fallback_rejects_a_missing_or_substituted_bound_successor() {
    let missing = pending_setup();
    let mut missing_line = missing.line.clone();
    missing_line.remove_object(missing.successor_head.object_hash);
    let missing_trust = missing_line.verified_with_record(
        Pin::Head(0),
        INITIAL_REVISION,
        missing.trusted_time.clone(),
        missing.key,
    );
    let Err(missing_error) = verify_current_head_fallback(&missing_trust, missing.pending) else {
        panic!("removing the proof-bound successor cannot enable fallback");
    };
    assert_eq!(
        missing_error,
        RegistryError::Trust(TrustError::StateConflict)
    );

    let substituted = pending_setup();
    let mut substituted_line = RegistryLineBuilder::new();
    substituted_line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            issued_at: UnixMillis::new(100),
            not_before: UnixMillis::new(90),
            not_after: UnixMillis::new(10_000),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let alternative = substituted_line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_200),
            not_before: UnixMillis::new(1_100),
            not_after: UnixMillis::new(2_000),
            policy_max_future_clock_skew_ms_override: Some(5_001),
            ..HeadOptions::default()
        },
    );
    assert!(alternative.object_hash != substituted.successor_head.object_hash);
    let substituted_trust = substituted_line.verified_with_record(
        Pin::Head(0),
        INITIAL_REVISION,
        substituted.trusted_time.clone(),
        substituted.key,
    );
    let Err(substituted_error) =
        verify_current_head_fallback(&substituted_trust, substituted.pending)
    else {
        panic!("a same-version replacement cannot enable fallback");
    };
    assert_eq!(substituted_error, RegistryError::Fork);

    let additional = pending_setup();
    let mut alternative_line = RegistryLineBuilder::new();
    alternative_line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            issued_at: UnixMillis::new(100),
            not_before: UnixMillis::new(90),
            not_after: UnixMillis::new(10_000),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let alternative = alternative_line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_200),
            not_before: UnixMillis::new(1_100),
            not_after: UnixMillis::new(2_000),
            policy_max_future_clock_skew_ms_override: Some(5_002),
            ..HeadOptions::default()
        },
    );
    assert!(alternative.object_hash != additional.successor_head.object_hash);
    let mut forked_line = additional.line.clone();
    forked_line.merge_catalog_from(&alternative_line);
    let forked_trust = forked_line.verified_with_record(
        Pin::Head(0),
        INITIAL_REVISION,
        additional.trusted_time,
        additional.key,
    );
    let Err(forked_error) = verify_current_head_fallback(&forked_trust, additional.pending) else {
        panic!("an additional same-version successor cannot enable fallback");
    };
    assert_eq!(forked_error, RegistryError::Fork);

    let drift_and_fork = pending_setup();
    let mut drift_and_fork_line = drift_and_fork.line.clone();
    drift_and_fork_line.merge_catalog_from(&alternative_line);
    let drift_and_fork_trust = drift_and_fork_line.verified_with_record(
        Pin::Head(0),
        INITIAL_REVISION + 1,
        drift_and_fork.trusted_time,
        drift_and_fork.key,
    );
    let Err(drift_and_fork_error) =
        verify_current_head_fallback(&drift_and_fork_trust, drift_and_fork.pending)
    else {
        panic!("snapshot drift must fail before inspecting a simultaneous fork");
    };
    assert_eq!(
        drift_and_fork_error,
        RegistryError::Trust(TrustError::StateConflict)
    );
}

#[test]
fn pending_fallback_ignores_only_later_versions_after_exact_corroboration() {
    let setup = pending_setup();
    let mut line_with_later = setup.line.clone();
    line_with_later.push(
        policy(),
        HeadOptions {
            effective_from: Some(70),
            valid_through: Some(250),
            issued_at: UnixMillis::new(500),
            not_before: UnixMillis::new(400),
            not_after: UnixMillis::new(3_000),
            root_signer: RootSigner::Corrupt,
            ..HeadOptions::default()
        },
    );
    let trust = line_with_later.verified_with_record(
        Pin::Head(0),
        INITIAL_REVISION,
        setup.trusted_time,
        setup.key,
    );

    let candidate = verify_current_head_fallback(&trust, setup.pending);

    let Ok(candidate) = candidate else {
        panic!("later successors cannot replace the exact direct barrier");
    };
    assert_eq!(candidate.registry_version(), setup.previous_head.version);
    assert!(candidate.registry_head_hash() == setup.previous_head.object_hash);
}

#[test]
fn reached_stale_or_lease_exhausted_direct_successor_advances_without_authority() {
    let stale = direct_fixture(
        100,
        50,
        200,
        850,
        800,
        875,
        60,
        persisted_time(700, 650, 0x51),
        300,
        500,
    );
    let mut stale_store = ModelStore::new(
        stale.key,
        stale.trusted_time.clone(),
        Some(pin(stale.previous_head)),
    );
    stale_store.set_next_revision(97);
    let stale_time = prepare(&stale, &mut stale_store, 900);
    let RegistrySelectionOutcome::Advanced(advanced) =
        select_registry_head(stale.candidate, stale_time, None).unwrap()
    else {
        panic!("a reached expired intermediate must only advance the pin");
    };
    assert_eq!(advanced.registry_version(), stale.candidate_head.version);
    assert!(advanced.registry_head_hash() == stale.candidate_head.object_hash);
    assert_eq!(advanced.committed_revision(), 97);
    assert_eq!(stale_store.selection_commits.len(), 1);
    assert_eq!(
        stale_store.record.trusted_time.floor(),
        UnixMillis::new(850)
    );
    assert!(
        stale_store.record.trusted_time.independent_reference()
            == stale.trusted_time.independent_reference()
    );
    assert!(stale_store.record.pinned_head == Some(pin(stale.candidate_head)));

    let lease = direct_fixture(
        100,
        50,
        55,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 970, 0x52),
        50,
        500,
    );
    let mut lease_store = ModelStore::new(
        lease.key,
        lease.trusted_time.clone(),
        Some(pin(lease.previous_head)),
    );
    lease_store.set_next_revision(101);
    let lease_time = prepare(&lease, &mut lease_store, 1_000);
    let RegistrySelectionOutcome::Advanced(advanced) =
        select_registry_head(lease.candidate, lease_time, None).unwrap()
    else {
        panic!("a reached lease-exhausted intermediate must only advance the pin");
    };
    assert_eq!(advanced.registry_version(), lease.candidate_head.version);
    assert!(advanced.registry_head_hash() == lease.candidate_head.object_hash);
    assert_eq!(advanced.committed_revision(), 101);
    assert_eq!(lease_store.selection_commits.len(), 1);
    assert!(lease_store.record.pinned_head == Some(pin(lease.candidate_head)));
}

#[test]
fn temporal_future_is_classified_before_direct_successor_lease_exhaustion() {
    let fixture = direct_fixture(
        100,
        50,
        55,
        1_200,
        1_100,
        2_000,
        60,
        persisted_time(900, 900, 0x53),
        50,
        500,
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    let before = store.record.clone();
    let local_time = prepare(&fixture, &mut store, 950);

    let RegistrySelectionOutcome::PendingFuture(_) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("future timing must precede historical-advance classification");
    };
    assert!(store.record == before);
    assert!(store.selection_commits.is_empty());
}

#[test]
fn stale_current_head_fails_but_the_not_after_boundary_is_inclusive() {
    let stale = single_head_fixture(
        true,
        1,
        100,
        100,
        90,
        999,
        60,
        persisted_time(1_000, 970, 0x54),
        50,
    );
    let mut stale_store =
        ModelStore::new(stale.key, stale.trusted_time.clone(), stale.original_pin);
    let stale_before = stale_store.record.clone();
    let stale_time = prepare_local_time(
        &mut stale_store,
        &stale.candidate,
        UnixMillis::new(1_000),
        &[],
    )
    .unwrap();
    let Err(stale_error) = select_registry_head(stale.candidate, stale_time, None) else {
        panic!("an expired current Head cannot authorize an operation");
    };
    assert_eq!(stale_error, RegistryError::Stale);
    assert!(stale_store.record == stale_before);
    assert!(stale_store.selection_commits.is_empty());

    let boundary = single_head_fixture(
        true,
        1,
        100,
        100,
        90,
        1_000,
        60,
        persisted_time(1_000, 970, 0x55),
        50,
    );
    let mut boundary_store = ModelStore::new(
        boundary.key,
        boundary.trusted_time.clone(),
        boundary.original_pin,
    );
    let boundary_time = prepare_local_time(
        &mut boundary_store,
        &boundary.candidate,
        UnixMillis::new(1_000),
        &[],
    )
    .unwrap();
    let RegistrySelectionOutcome::Selected(_) =
        select_registry_head(boundary.candidate, boundary_time, None).unwrap()
    else {
        panic!("notAfter is an inclusive validity boundary");
    };
    assert_eq!(boundary_store.selection_commits.len(), 1);
}

#[test]
fn only_the_previous_guard_policy_controls_successor_future_skew() {
    let blocked = direct_fixture(
        100,
        50,
        200,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 900, 0x56),
        37,
        9_999,
    );
    let mut blocked_store = ModelStore::new(
        blocked.key,
        blocked.trusted_time.clone(),
        Some(pin(blocked.previous_head)),
    );
    let blocked_before = blocked_store.record.clone();
    let blocked_time = prepare(&blocked, &mut blocked_store, 1_000);
    let Err(blocked_error) = select_registry_head(blocked.candidate, blocked_time, None) else {
        panic!("the successor cannot use its own larger skew limit");
    };
    assert_eq!(blocked_error, RegistryError::FutureSkew);
    assert!(blocked_store.record == blocked_before);
    assert!(blocked_store.selection_commits.is_empty());

    let allowed = direct_fixture(
        100,
        50,
        200,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 900, 0x57),
        101,
        1,
    );
    let mut allowed_store = ModelStore::new(
        allowed.key,
        allowed.trusted_time.clone(),
        Some(pin(allowed.previous_head)),
    );
    let allowed_time = prepare(&allowed, &mut allowed_store, 1_000);
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(allowed.candidate, allowed_time, None).unwrap()
    else {
        panic!("the successor cannot impose its own smaller skew limit early");
    };
    assert_eq!(selected.policy_fields().max_future_clock_skew_ms, 1);
    assert_eq!(allowed_store.selection_commits.len(), 1);
}

#[test]
fn unresolved_skew_precedes_pending_stale_and_advanced_classification() {
    assert_blocked_before_later_classification(direct_fixture(
        100,
        50,
        200,
        1_200,
        1_100,
        2_000,
        60,
        persisted_time(1_000, 900, 0x77),
        37,
        9_999,
    ));
    assert_blocked_before_later_classification(direct_fixture(
        100,
        50,
        200,
        800,
        700,
        900,
        60,
        persisted_time(1_000, 900, 0x78),
        37,
        9_999,
    ));
    assert_blocked_before_later_classification(direct_fixture(
        100,
        50,
        55,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 900, 0x79),
        37,
        9_999,
    ));
}

#[test]
fn reached_stale_bootstrap_head_is_first_pinned_only_as_advanced() {
    let fixture = single_head_fixture(
        false,
        1,
        100,
        850,
        800,
        875,
        60,
        persisted_time(700, 650, 0x53),
        300,
    );
    let mut store = ModelStore::new(fixture.key, fixture.trusted_time.clone(), None);
    store.set_next_revision(89);
    let local_time =
        prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(900), &[]).unwrap();

    let RegistrySelectionOutcome::Advanced(advanced) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("a reached stale Bootstrap Head must never expose authority");
    };

    assert_eq!(advanced.registry_version(), fixture.head.version);
    assert!(advanced.registry_head_hash() == fixture.head.object_hash);
    assert_eq!(advanced.committed_revision(), 89);
    assert_eq!(store.selection_commits.len(), 1);
    assert!(store.selection_commits[0].next_head == pin(fixture.head));
    assert_eq!(
        store.selection_commits[0].next_trusted_time.floor(),
        UnixMillis::new(850)
    );
    assert!(store.record.pinned_head == Some(pin(fixture.head)));
}

#[test]
fn missing_independent_time_is_visible_but_does_not_invent_a_skew_block() {
    let fixture = direct_fixture(
        100,
        50,
        200,
        800,
        700,
        10_000,
        60,
        TrustedTimeState::initial(UnixMillis::new(900)),
        1,
        1,
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    let local_time = prepare(&fixture, &mut store, 5_000);

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("unprovable skew is a warning, not an invented block");
    };
    assert!(selected.warnings().independent_time_unavailable());
    assert!(!selected.warnings().clock_rollback());
    assert_eq!(
        selected.preexisting_effective_now().value(),
        UnixMillis::new(5_000)
    );
    assert_eq!(store.selection_commits.len(), 1);
    assert!(
        store.selection_commits[0]
            .next_trusted_time
            .independent_reference()
            .is_none()
    );

    let lease = direct_fixture(
        100,
        50,
        55,
        800,
        700,
        10_000,
        60,
        TrustedTimeState::initial(UnixMillis::new(900)),
        1,
        1,
    );
    let mut lease_store = ModelStore::new(
        lease.key,
        lease.trusted_time.clone(),
        Some(pin(lease.previous_head)),
    );
    let lease_time = prepare(&lease, &mut lease_store, 5_000);
    let RegistrySelectionOutcome::Advanced(advanced) =
        select_registry_head(lease.candidate, lease_time, None).unwrap()
    else {
        panic!("unprovable skew cannot bypass the successor sequence Lease");
    };
    assert_eq!(advanced.registry_version(), lease.candidate_head.version);
    assert_eq!(lease_store.selection_commits.len(), 1);
    assert!(
        lease_store.selection_commits[0]
            .next_trusted_time
            .independent_reference()
            .is_none()
    );
}

#[test]
fn os_clock_rollback_keeps_the_persisted_floor_and_warning() {
    let fixture = single_head_fixture(
        true,
        1,
        100,
        100,
        90,
        2_000,
        60,
        persisted_time(1_000, 970, 0x58),
        50,
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        fixture.original_pin,
    );
    let local_time =
        prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(900), &[]).unwrap();

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("rollback protection must use the persisted floor");
    };
    assert_eq!(
        selected.preexisting_effective_now().value(),
        UnixMillis::new(1_000)
    );
    assert!(selected.warnings().clock_rollback());
    assert!(!selected.warnings().independent_time_unavailable());
    assert!(store.selection_commits[0].next_trusted_time == fixture.trusted_time);
}

#[test]
fn pending_direct_successor_stops_the_temporal_prefix() {
    let mut line = RegistryLineBuilder::new();
    let previous = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let barrier = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_200),
            not_before: UnixMillis::new(1_100),
            not_after: UnixMillis::new(2_000),
            ..HeadOptions::default()
        },
    );
    let later = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(70),
            valid_through: Some(250),
            issued_at: UnixMillis::new(500),
            not_before: UnixMillis::new(400),
            not_after: UnixMillis::new(3_000),
            ..HeadOptions::default()
        },
    );
    let trusted_time = persisted_time(900, 900, 0x59);
    let trust = line.verified_with_time(Pin::Head(0), trusted_time.clone());
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(80)).unwrap();
    assert_eq!(candidate.registry_version(), barrier.version);
    assert!(candidate.registry_head_hash() == barrier.object_hash);
    assert!(candidate.registry_head_hash() != later.object_hash);
    let key = support::state_key();
    let mut store = ModelStore::new(key, trusted_time, Some(pin(previous)));
    let before = store.record.clone();
    let local_time = prepare_local_time(&mut store, &candidate, UnixMillis::new(950), &[]).unwrap();

    let RegistrySelectionOutcome::PendingFuture(_) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the exact direct temporal barrier must stop the prefix");
    };
    assert!(store.record == before);
    assert!(store.selection_commits.is_empty());
}

#[test]
fn fallback_recheck_rejects_a_successor_made_ready_by_fresh_independent_time() {
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
    let current_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(100),
            ..HeadOptions::default()
        },
    );
    let current_policy_hash = line.current_policy_hash().unwrap();
    let successor_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_200),
            not_before: UnixMillis::new(1_100),
            not_after: UnixMillis::new(2_000),
            ..HeadOptions::default()
        },
    );
    let key = support::state_key();
    let trusted_time = persisted_time(900, 900, 0x5a);
    let trust = line.verified_with_time(Pin::Head(2), trusted_time.clone());
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    assert_eq!(candidate.registry_version(), successor_head.version);
    let mut pending_store = ModelStore::new(key, trusted_time.clone(), Some(pin(current_head)));
    let pending_time =
        prepare_local_time(&mut pending_store, &candidate, UnixMillis::new(950), &[]).unwrap();
    let RegistrySelectionOutcome::PendingFuture(pending) =
        select_registry_head(candidate, pending_time, None).unwrap()
    else {
        panic!("the exact successor must first be pending");
    };
    assert_eq!(pending_store.independent_commits, 0);
    assert!(pending_store.selection_commits.is_empty());

    let reloaded =
        line.verified_with_record(Pin::Head(2), INITIAL_REVISION, trusted_time.clone(), key);
    let current = verify_current_head_fallback(&reloaded, pending);
    let Ok(current) = current else {
        panic!("the exact unchanged snapshot must reconstruct the current Head");
    };
    assert_eq!(current.registry_version(), current_head.version);
    let source = receipt_source(
        &current,
        current_head,
        current_policy_hash,
        CertificateHash::from(server_head.direct_object_hash.unwrap()),
        UnixMillis::new(1_200),
    );
    let mut final_store = ModelStore::new(key, trusted_time, Some(pin(current_head)));
    final_store.set_next_revision(29);
    let final_time =
        prepare_local_time(&mut final_store, &current, UnixMillis::new(950), &[source]).unwrap();

    let Err(error) = select_registry_head(current, final_time, None) else {
        panic!("a newly reached bound successor must defeat current fallback");
    };

    assert_eq!(error, RegistryError::SuccessorReady);
    assert_eq!(final_store.independent_commits, 1);
    assert_eq!(final_store.record.revision, 29);
    assert_eq!(
        final_store.record.trusted_time.floor(),
        UnixMillis::new(1_200)
    );
    assert_eq!(
        final_store
            .record
            .trusted_time
            .independent_reference()
            .expect("the fresh Receipt must persist")
            .verified_time(),
        UnixMillis::new(1_200)
    );
    assert!(final_store.record.pinned_head == Some(pin(current_head)));
    assert!(final_store.selection_commits.is_empty());
    assert_eq!(final_store.replay_queries, 0);
}

#[test]
fn candidate_and_local_time_from_distinct_verified_flows_cannot_be_spliced() {
    let first = direct_fixture(
        100,
        50,
        200,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 900, 0x5b),
        37,
        9_999,
    );
    let second = direct_fixture(
        100,
        50,
        200,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 900, 0x5b),
        37,
        9_999,
    );
    assert_eq!(
        first.candidate.registry_version(),
        second.candidate.registry_version()
    );
    assert!(first.candidate.registry_head_hash() == second.candidate.registry_head_hash());
    let mut store = ModelStore::new(
        second.key,
        second.trusted_time.clone(),
        Some(pin(second.previous_head)),
    );
    let before = store.record.clone();
    let local_time = prepare(&second, &mut store, 1_000);

    let Err(error) = select_registry_head(first.candidate, local_time, None) else {
        panic!("a LocalTimeBlock cannot cross verified candidate ownership");
    };

    assert_eq!(error, RegistryError::Trust(TrustError::StateConflict));
    assert!(store.record == before);
    assert!(store.selection_commits.is_empty());
    assert_eq!(store.replay_queries, 0);

    let foreign = release_fixture(0xe0, 2_000, 200);
    let foreign_release = detached_release(&foreign);
    let first = direct_fixture(
        100,
        50,
        200,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 900, 0x5b),
        37,
        9_999,
    );
    let second = direct_fixture(
        100,
        50,
        200,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 900, 0x5b),
        37,
        9_999,
    );
    let mut store = ModelStore::new(
        second.key,
        second.trusted_time.clone(),
        Some(pin(second.previous_head)),
    );
    let before = store.record.clone();
    let local_time = prepare(&second, &mut store, 1_000);
    let Err(error) = select_registry_head(first.candidate, local_time, Some(foreign_release))
    else {
        panic!("candidate/local preflight must precede Release pairing");
    };
    assert_eq!(error, RegistryError::Trust(TrustError::StateConflict));
    assert!(store.record == before);
    assert!(store.selection_commits.is_empty());
}

#[test]
fn current_head_compare_and_affirm_loses_an_ordinary_concurrent_cas() {
    let fixture = single_head_fixture(
        true,
        1,
        100,
        100,
        90,
        2_000,
        60,
        persisted_time(1_000, 970, 0x5c),
        50,
    );
    let concurrent = ModelRecord {
        revision: 23,
        trusted_time: fixture.trusted_time.clone(),
        pinned_head: fixture.original_pin,
    };
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        fixture.original_pin,
    );
    store.set_fault(SelectionFault::ConcurrentCommit(concurrent.clone()));
    let local_time =
        prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(1_000), &[]).unwrap();

    let Err(error) = select_registry_head(fixture.candidate, local_time, None) else {
        panic!("only one consumer at the prior revision may authorize");
    };

    assert_eq!(error, RegistryError::Trust(TrustError::StateConflict));
    assert_eq!(store.selection_commits.len(), 1);
    assert_eq!(
        store.selection_commits[0].expected_revision,
        INITIAL_REVISION
    );
    assert!(store.record == concurrent);
}

#[test]
fn pending_fallback_compare_and_affirm_loses_a_concurrent_successor_commit() {
    let (candidate, context) = fallback_candidate(pending_setup());
    let successor_time = TrustedTimeState::from_persisted(
        UnixMillis::new(1_200),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            ObjectHash::from(support::hash32(0x41)),
            UnixMillis::new(900),
        )),
    )
    .unwrap();
    let concurrent = ModelRecord {
        revision: 31,
        trusted_time: successor_time,
        pinned_head: Some(pin(context.successor_head)),
    };
    let mut store = ModelStore::new(
        context.key,
        context.trusted_time.clone(),
        Some(pin(context.previous_head)),
    );
    store.set_fault(SelectionFault::ConcurrentCommit(concurrent.clone()));
    let local_time = prepare_local_time(&mut store, &candidate, UnixMillis::new(950), &[]).unwrap();

    let Err(error) = select_registry_head(candidate, local_time, None) else {
        panic!("the successor commit must defeat old-Head fallback linearization");
    };

    assert_eq!(error, RegistryError::Trust(TrustError::StateConflict));
    assert_eq!(store.selection_commits.len(), 1);
    assert!(store.record == concurrent);
}

#[test]
fn real_successor_handle_wins_before_fallback_current_compare_and_affirm() {
    let (current, context) =
        fallback_candidate(pending_setup_with_guard_and_current_expiry(300, 10_000));
    let reloaded = context.line.verified_with_record(
        Pin::Head(0),
        INITIAL_REVISION,
        context.trusted_time.clone(),
        context.key,
    );
    let successor = verify_registry_candidate(&reloaded, ChainSequence::new(60)).unwrap();
    assert_eq!(successor.registry_version(), context.successor_head.version);
    let shared = SharedStore::new(ModelStore::new(
        context.key,
        context.trusted_time.clone(),
        Some(pin(context.previous_head)),
    ));
    shared.inner.borrow_mut().set_next_revision(127);
    let mut current_handle = shared.clone();
    let mut successor_handle = shared.clone();
    let current_time =
        prepare_local_time(&mut current_handle, &current, UnixMillis::new(950), &[]).unwrap();
    let successor_time = prepare_local_time(
        &mut successor_handle,
        &successor,
        UnixMillis::new(1_200),
        &[],
    )
    .unwrap();

    let successor_outcome = select_registry_head(successor, successor_time, None);
    let current_outcome = select_registry_head(current, current_time, None);

    let Ok(RegistrySelectionOutcome::Selected(_)) = successor_outcome else {
        panic!("the reached successor handle must win the shared transaction");
    };
    let Err(current_error) = current_outcome else {
        panic!("the fallback current handle cannot authorize after that commit");
    };
    assert_eq!(
        current_error,
        RegistryError::Trust(TrustError::StateConflict)
    );
    let store = shared.inner.borrow();
    assert_eq!(store.selection_commits.len(), 2);
    assert_eq!(store.record.revision, 127);
    assert!(store.record.pinned_head == Some(pin(context.successor_head)));
}

#[test]
fn failed_selection_transactions_leave_head_floor_and_replay_unchanged() {
    for fault in [
        SelectionFault::BeforeReplay(StateStoreError::Unavailable),
        SelectionFault::BeforeHeadAndFloor(StateStoreError::Unavailable),
    ] {
        let fixture = direct_fixture(
            100,
            50,
            200,
            850,
            800,
            2_000,
            60,
            persisted_time(700, 650, 0x5d),
            300,
            500,
        );
        let mut store = ModelStore::new(
            fixture.key,
            fixture.trusted_time.clone(),
            Some(pin(fixture.previous_head)),
        );
        let before = store.record.clone();
        let replay_before = store.consumed_replays.clone();
        store.set_fault(fault);
        let local_time = prepare(&fixture, &mut store, 900);

        let Err(error) = select_registry_head(fixture.candidate, local_time, None) else {
            panic!("an atomic store failure cannot return operation authority");
        };

        assert_eq!(error, RegistryError::Trust(TrustError::StateUnavailable));
        assert_eq!(store.selection_commits.len(), 1);
        assert!(store.record == before);
        assert!(store.consumed_replays == replay_before);
        assert!(store.commit_phases.contains(&CommitPhase::Entered));
    }
}

#[test]
fn temporal_activation_is_inclusive_and_issued_at_future_is_pending() {
    let reached = direct_fixture(
        100,
        50,
        200,
        1_000,
        1_000,
        2_000,
        60,
        persisted_time(1_000, 970, 0x5e),
        50,
        500,
    );
    let mut reached_store = ModelStore::new(
        reached.key,
        reached.trusted_time.clone(),
        Some(pin(reached.previous_head)),
    );
    let reached_time = prepare(&reached, &mut reached_store, 1_000);
    let RegistrySelectionOutcome::Selected(_) =
        select_registry_head(reached.candidate, reached_time, None).unwrap()
    else {
        panic!("issuedAt and notBefore equal to rawNow are reached inclusively");
    };
    assert_eq!(reached_store.selection_commits.len(), 1);

    let future = direct_fixture(
        100,
        50,
        200,
        1_001,
        900,
        2_000,
        60,
        persisted_time(1_000, 970, 0x5f),
        50,
        500,
    );
    let mut future_store = ModelStore::new(
        future.key,
        future.trusted_time.clone(),
        Some(pin(future.previous_head)),
    );
    let before = future_store.record.clone();
    let future_time = prepare(&future, &mut future_store, 1_000);
    let RegistrySelectionOutcome::PendingFuture(_) =
        select_registry_head(future.candidate, future_time, None).unwrap()
    else {
        panic!("issuedAt one millisecond after rawNow remains pending");
    };
    assert!(future_store.record == before);
    assert!(future_store.selection_commits.is_empty());
}

#[test]
fn direct_lease_and_time_endpoints_are_inclusive_for_selected_and_pending() {
    let selected = direct_fixture(
        100,
        50,
        60,
        900,
        800,
        1_000,
        60,
        persisted_time(1_000, 970, 0x7a),
        50,
        500,
    );
    let mut selected_store = ModelStore::new(
        selected.key,
        selected.trusted_time.clone(),
        Some(pin(selected.previous_head)),
    );
    let selected_time = prepare(&selected, &mut selected_store, 1_000);
    let RegistrySelectionOutcome::Selected(_) =
        select_registry_head(selected.candidate, selected_time, None).unwrap()
    else {
        panic!("validThrough==proposed and notAfter==rawNow remain Selected");
    };
    assert_eq!(selected_store.selection_commits.len(), 1);

    let pending = direct_fixture(
        60,
        50,
        200,
        1_200,
        1_100,
        2_000,
        60,
        persisted_time(900, 900, 0x7b),
        50,
        500,
    );
    let mut pending_store = ModelStore::new(
        pending.key,
        pending.trusted_time.clone(),
        Some(pin(pending.previous_head)),
    );
    let before = pending_store.record.clone();
    let pending_time = prepare(&pending, &mut pending_store, 950);
    let RegistrySelectionOutcome::PendingFuture(_) =
        select_registry_head(pending.candidate, pending_time, None).unwrap()
    else {
        panic!("previous validThrough==proposed still permits Pending fallback");
    };
    assert!(pending_store.record == before);
    assert!(pending_store.selection_commits.is_empty());
}

#[test]
fn formerly_pending_successor_is_selected_after_full_reload_and_time_advance() {
    let setup = pending_setup();
    let advanced_time = persisted_time(1_200, 1_200, 0x60);
    let trust = setup
        .line
        .verified_with_record(Pin::Head(0), 29, advanced_time.clone(), setup.key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    assert_eq!(candidate.registry_version(), setup.successor_head.version);
    assert!(candidate.registry_head_hash() == setup.successor_head.object_hash);
    let mut store = ModelStore::new(
        setup.key,
        advanced_time.clone(),
        Some(pin(setup.previous_head)),
    );
    store.record.revision = 29;
    store.set_next_revision(43);
    let local_time = prepare_local_time(&mut store, &candidate, UnixMillis::new(950), &[]).unwrap();

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the caller rerun must select the now-reached successor");
    };

    assert_eq!(selected.registry_version(), setup.successor_head.version);
    assert!(selected.registry_head_hash() == setup.successor_head.object_hash);
    assert_eq!(store.selection_commits.len(), 1);
    assert_eq!(store.selection_commits[0].expected_revision, 29);
    assert!(store.record.pinned_head == Some(pin(setup.successor_head)));
    assert_eq!(store.record.revision, 43);
}

#[test]
fn advanced_intermediate_reloads_into_the_next_direct_selected_head() {
    let mut line = RegistryLineBuilder::new();
    let first = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(50),
            ..HeadOptions::default()
        },
    );
    let intermediate = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(55),
            issued_at: UnixMillis::new(800),
            not_before: UnixMillis::new(700),
            not_after: UnixMillis::new(900),
            policy_max_future_clock_skew_ms_override: Some(100),
            ..HeadOptions::default()
        },
    );
    let final_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(56),
            valid_through: Some(200),
            issued_at: UnixMillis::new(850),
            not_before: UnixMillis::new(800),
            not_after: UnixMillis::new(2_000),
            ..HeadOptions::default()
        },
    );
    let key = support::state_key();
    let trusted_time = persisted_time(1_000, 970, 0x61);
    let initial = line.verified_with_time(Pin::Head(0), trusted_time.clone());
    let intermediate_candidate =
        verify_registry_candidate(&initial, ChainSequence::new(80)).unwrap();
    assert_eq!(
        intermediate_candidate.registry_version(),
        intermediate.version
    );
    let mut first_store = ModelStore::new(key, trusted_time, Some(pin(first)));
    first_store.set_next_revision(29);
    let first_time = prepare_local_time(
        &mut first_store,
        &intermediate_candidate,
        UnixMillis::new(1_000),
        &[],
    )
    .unwrap();
    let RegistrySelectionOutcome::Advanced(advanced) =
        select_registry_head(intermediate_candidate, first_time, None).unwrap()
    else {
        panic!("the expired short-lease intermediate must only advance");
    };
    assert_eq!(advanced.registry_version(), intermediate.version);
    assert_eq!(advanced.committed_revision(), 29);
    let committed_time = first_store.record.trusted_time.clone();

    let reloaded = line.verified_with_record(Pin::Head(1), 29, committed_time.clone(), key);
    let final_candidate = verify_registry_candidate(&reloaded, ChainSequence::new(80)).unwrap();
    assert_eq!(final_candidate.registry_version(), final_head.version);
    assert!(final_candidate.registry_head_hash() == final_head.object_hash);
    let mut second_store = ModelStore::new(key, committed_time, Some(pin(intermediate)));
    second_store.record.revision = 29;
    second_store.set_next_revision(47);
    let second_time = prepare_local_time(
        &mut second_store,
        &final_candidate,
        UnixMillis::new(1_000),
        &[],
    )
    .unwrap();

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(final_candidate, second_time, None).unwrap()
    else {
        panic!("the next direct fresh Head must authorize only after the reload");
    };
    assert_eq!(selected.registry_version(), final_head.version);
    assert!(second_store.record.pinned_head == Some(pin(final_head)));
    assert_eq!(second_store.record.revision, 47);
}

#[test]
fn exact_blocked_release_is_consumed_only_in_the_atomic_selected_commit() {
    let fixture = release_fixture(0xd0, 2_000, 200);
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    store.set_next_revision(61);
    let (local_time, release) = prepare_release(&fixture, &mut store);

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(fixture.candidate, local_time, Some(release)).unwrap()
    else {
        panic!("the exact verified Release must lift only the skew block");
    };

    assert_eq!(selected.registry_version(), fixture.candidate_head.version);
    assert_eq!(store.replay_queries, 1);
    assert_eq!(store.selection_commits.len(), 1);
    assert!(store.selection_commits[0].replay_key.as_ref() == Some(&fixture.expected_replay));
    assert!(store.consumed_replays == vec![fixture.expected_replay]);
    assert!(store.record.pinned_head == Some(pin(fixture.candidate_head)));
    assert_eq!(store.record.revision, 61);
}

#[test]
fn bootstrap_and_current_heads_apply_their_own_verified_skew_policy() {
    let bootstrap_blocked = single_head_fixture(
        false,
        1,
        100,
        100,
        90,
        2_000,
        60,
        persisted_time(1_000, 900, 0x75),
        37,
    );
    let mut bootstrap_blocked_store = ModelStore::new(
        bootstrap_blocked.key,
        bootstrap_blocked.trusted_time.clone(),
        None,
    );
    let bootstrap_blocked_time = prepare_local_time(
        &mut bootstrap_blocked_store,
        &bootstrap_blocked.candidate,
        UnixMillis::new(1_000),
        &[],
    )
    .unwrap();
    let Err(bootstrap_error) =
        select_registry_head(bootstrap_blocked.candidate, bootstrap_blocked_time, None)
    else {
        panic!("Bootstrap must enforce its verified initial Policy skew bound");
    };
    assert_eq!(bootstrap_error, RegistryError::FutureSkew);
    assert!(bootstrap_blocked_store.selection_commits.is_empty());

    let bootstrap_allowed = single_head_fixture(
        false,
        1,
        100,
        100,
        90,
        2_000,
        60,
        persisted_time(1_000, 900, 0x76),
        101,
    );
    let mut bootstrap_allowed_store = ModelStore::new(
        bootstrap_allowed.key,
        bootstrap_allowed.trusted_time.clone(),
        None,
    );
    let bootstrap_allowed_time = prepare_local_time(
        &mut bootstrap_allowed_store,
        &bootstrap_allowed.candidate,
        UnixMillis::new(1_000),
        &[],
    )
    .unwrap();
    let RegistrySelectionOutcome::Selected(_) =
        select_registry_head(bootstrap_allowed.candidate, bootstrap_allowed_time, None).unwrap()
    else {
        panic!("Bootstrap must also honor a distinct permissive initial Policy");
    };

    let current_blocked = current_release_fixture(0xdb, 2_000);
    let mut current_blocked_store = ModelStore::new(
        current_blocked.key,
        current_blocked.trusted_time.clone(),
        Some(pin(current_blocked.previous_head)),
    );
    let current_blocked_time = prepare_local_time(
        &mut current_blocked_store,
        &current_blocked.candidate,
        current_blocked.os_wall_clock,
        &[],
    )
    .unwrap();
    let Err(current_error) =
        select_registry_head(current_blocked.candidate, current_blocked_time, None)
    else {
        panic!("the current Head must enforce its own Policy skew bound");
    };
    assert_eq!(current_error, RegistryError::FutureSkew);
    assert!(current_blocked_store.selection_commits.is_empty());

    let current_allowed = single_head_fixture(
        true,
        1,
        100,
        100,
        90,
        2_000,
        60,
        persisted_time(1_000, 900, 0x77),
        101,
    );
    let mut current_allowed_store = ModelStore::new(
        current_allowed.key,
        current_allowed.trusted_time.clone(),
        current_allowed.original_pin,
    );
    let current_allowed_time = prepare_local_time(
        &mut current_allowed_store,
        &current_allowed.candidate,
        UnixMillis::new(1_000),
        &[],
    )
    .unwrap();
    let RegistrySelectionOutcome::Selected(current_selected) =
        select_registry_head(current_allowed.candidate, current_allowed_time, None).unwrap()
    else {
        panic!("the same current-Head skew delta must pass its verified limit of 101");
    };
    assert_eq!(
        current_selected.policy_fields().max_future_clock_skew_ms,
        101
    );
    assert!(current_selected.policy_object_hash() == current_allowed.policy_hash);

    let current_released = current_release_fixture(0xdc, 2_000);
    let mut current_released_store = ModelStore::new(
        current_released.key,
        current_released.trusted_time.clone(),
        Some(pin(current_released.previous_head)),
    );
    current_released_store.set_next_revision(107);
    let (current_time, release) = prepare_release(&current_released, &mut current_released_store);
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(current_released.candidate, current_time, Some(release)).unwrap()
    else {
        panic!("an exact current-Head Release may lift only its skew block");
    };
    assert_eq!(
        selected.registry_version(),
        current_released.candidate_head.version
    );
    assert_eq!(current_released_store.selection_commits.len(), 1);
    assert!(
        current_released_store.selection_commits[0]
            .replay_key
            .as_ref()
            == Some(&current_released.expected_replay)
    );
    assert!(
        current_released_store.record.pinned_head == Some(pin(current_released.candidate_head))
    );
    assert_eq!(current_released_store.record.revision, 107);
}

#[test]
fn current_staleness_is_never_waived_by_an_exact_release() {
    let fixture = current_release_fixture(0xdd, 999);
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    let before = store.record.clone();
    let (local_time, release) = prepare_release(&fixture, &mut store);

    let Err(error) = select_registry_head(fixture.candidate, local_time, Some(release)) else {
        panic!("a stale current Head cannot be released into authority");
    };

    assert_eq!(error, RegistryError::Stale);
    assert!(store.record == before);
    assert!(store.selection_commits.is_empty());
    assert!(store.consumed_replays.is_empty());
    assert_eq!(store.replay_queries, 1);
}

#[test]
fn one_release_transaction_advances_floor_head_and_replay_together() {
    let fixture = release_fixture_full(0xde, 850, 800, 2_000, 200, 700, 650, 900, 37);
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    store.set_next_revision(109);
    let (local_time, release) = prepare_release(&fixture, &mut store);

    let RegistrySelectionOutcome::Selected(_) =
        select_registry_head(fixture.candidate, local_time, Some(release)).unwrap()
    else {
        panic!("the exact Release transaction must select the reached successor");
    };

    assert_eq!(store.selection_commits.len(), 1);
    let commit = &store.selection_commits[0];
    assert_eq!(commit.next_trusted_time.floor(), UnixMillis::new(850));
    assert!(commit.next_head == pin(fixture.candidate_head));
    assert!(commit.replay_key.as_ref() == Some(&fixture.expected_replay));
    assert_eq!(store.record.revision, 109);
    assert_eq!(store.record.trusted_time.floor(), UnixMillis::new(850));
    assert!(
        store.record.trusted_time.independent_reference()
            == fixture.trusted_time.independent_reference()
    );
    assert!(store.record.pinned_head == Some(pin(fixture.candidate_head)));
    assert!(store.consumed_replays == vec![fixture.expected_replay]);
}

#[test]
fn release_presence_and_private_pairing_violations_are_future_skew_errors() {
    let foreign = release_fixture(0xd1, 2_000, 200);
    let foreign_release = detached_release(&foreign);
    let within = direct_fixture(
        100,
        50,
        200,
        800,
        700,
        2_000,
        60,
        persisted_time(1_000, 970, 0x71),
        50,
        500,
    );
    let mut within_store = ModelStore::new(
        within.key,
        within.trusted_time.clone(),
        Some(pin(within.previous_head)),
    );
    let within_before = within_store.record.clone();
    let within_time = prepare(&within, &mut within_store, 1_000);
    let Err(within_error) =
        select_registry_head(within.candidate, within_time, Some(foreign_release))
    else {
        panic!("WithinLimit must reject an unnecessary Release");
    };
    assert_eq!(within_error, RegistryError::FutureSkew);
    assert!(within_store.record == within_before);
    assert!(within_store.selection_commits.is_empty());

    let foreign = release_fixture(0xd2, 2_000, 200);
    let foreign_release = detached_release(&foreign);
    let unprovable = direct_fixture(
        100,
        50,
        200,
        800,
        700,
        10_000,
        60,
        TrustedTimeState::initial(UnixMillis::new(1_000)),
        1,
        1,
    );
    let mut unprovable_store = ModelStore::new(
        unprovable.key,
        unprovable.trusted_time.clone(),
        Some(pin(unprovable.previous_head)),
    );
    let unprovable_before = unprovable_store.record.clone();
    let unprovable_time = prepare(&unprovable, &mut unprovable_store, 5_000);
    let Err(unprovable_error) =
        select_registry_head(unprovable.candidate, unprovable_time, Some(foreign_release))
    else {
        panic!("unprovable skew must reject every Release");
    };
    assert_eq!(unprovable_error, RegistryError::FutureSkew);
    assert!(unprovable_store.record == unprovable_before);
    assert!(unprovable_store.selection_commits.is_empty());

    let own = release_fixture(0xd3, 2_000, 200);
    let foreign = release_fixture(0xd4, 2_000, 200);
    let foreign_release = detached_release(&foreign);
    let mut own_store = ModelStore::new(
        own.key,
        own.trusted_time.clone(),
        Some(pin(own.previous_head)),
    );
    let own_before = own_store.record.clone();
    let own_time =
        prepare_local_time(&mut own_store, &own.candidate, UnixMillis::new(1_000), &[]).unwrap();
    let Err(pairing_error) = select_registry_head(own.candidate, own_time, Some(foreign_release))
    else {
        panic!("a Release from a distinct exact flow cannot be paired");
    };
    assert_eq!(pairing_error, RegistryError::FutureSkew);
    assert!(own_store.record == own_before);
    assert!(own_store.selection_commits.is_empty());
    assert_eq!(own_store.replay_queries, 0);
}

#[test]
fn release_never_waives_future_activation_staleness_or_sequence_lease() {
    let future = release_fixture_with_times(0xd5, 1_200, 1_100, 2_000, 200);
    let mut future_store = ModelStore::new(
        future.key,
        future.trusted_time.clone(),
        Some(pin(future.previous_head)),
    );
    let future_before = future_store.record.clone();
    let (future_time, future_release) = prepare_release(&future, &mut future_store);
    let RegistrySelectionOutcome::PendingFuture(_) =
        select_registry_head(future.candidate, future_time, Some(future_release)).unwrap()
    else {
        panic!("a Release cannot make a future event active");
    };
    assert!(future_store.record == future_before);
    assert!(future_store.selection_commits.is_empty());
    assert_eq!(future_store.replay_queries, 1);

    let stale = release_fixture(0xd6, 900, 200);
    let mut stale_store = ModelStore::new(
        stale.key,
        stale.trusted_time.clone(),
        Some(pin(stale.previous_head)),
    );
    let (stale_time, stale_release) = prepare_release(&stale, &mut stale_store);
    let RegistrySelectionOutcome::Advanced(advanced) =
        select_registry_head(stale.candidate, stale_time, Some(stale_release)).unwrap()
    else {
        panic!("a stale direct Head may only advance even with a Release");
    };
    assert_eq!(advanced.registry_version(), stale.candidate_head.version);
    assert_eq!(stale_store.selection_commits.len(), 1);
    assert!(stale_store.selection_commits[0].replay_key.as_ref() == Some(&stale.expected_replay));
    assert!(stale_store.record.pinned_head == Some(pin(stale.candidate_head)));

    let lease = release_fixture(0xd7, 2_000, 55);
    let mut lease_store = ModelStore::new(
        lease.key,
        lease.trusted_time.clone(),
        Some(pin(lease.previous_head)),
    );
    let (lease_time, lease_release) = prepare_release(&lease, &mut lease_store);
    let RegistrySelectionOutcome::Advanced(advanced) =
        select_registry_head(lease.candidate, lease_time, Some(lease_release)).unwrap()
    else {
        panic!("a lease-exhausted direct Head may only advance even with a Release");
    };
    assert_eq!(advanced.registry_version(), lease.candidate_head.version);
    assert_eq!(lease_store.selection_commits.len(), 1);
    assert!(lease_store.selection_commits[0].replay_key.as_ref() == Some(&lease.expected_replay));
}

#[test]
fn replay_staging_and_head_staging_failures_roll_back_the_whole_selection() {
    for (fault, replay_staged, head_staged) in [
        (
            SelectionFault::BeforeReplay(StateStoreError::Unavailable),
            false,
            false,
        ),
        (
            SelectionFault::AfterTentativeReplay(StateStoreError::Unavailable),
            true,
            false,
        ),
        (
            SelectionFault::BeforeHeadAndFloor(StateStoreError::Unavailable),
            true,
            true,
        ),
    ] {
        let fixture = release_fixture(0xd8, 2_000, 200);
        let mut store = ModelStore::new(
            fixture.key,
            fixture.trusted_time.clone(),
            Some(pin(fixture.previous_head)),
        );
        let before = store.record.clone();
        store.set_fault(fault);
        let (local_time, release) = prepare_release(&fixture, &mut store);

        let Err(error) = select_registry_head(fixture.candidate, local_time, Some(release)) else {
            panic!("no transaction fault may return Registry authority");
        };

        assert_eq!(error, RegistryError::Trust(TrustError::StateUnavailable));
        assert!(store.record == before);
        assert!(store.consumed_replays.is_empty());
        assert_eq!(store.selection_commits.len(), 1);
        assert_eq!(
            store.commit_phases.contains(&CommitPhase::ReplayStaged),
            replay_staged
        );
        assert_eq!(
            store
                .commit_phases
                .contains(&CommitPhase::HeadAndFloorStaged),
            head_staged
        );
    }
}

#[test]
fn concurrent_replay_insertion_rejects_selection_without_partial_head_or_floor() {
    let fixture = release_fixture(0xd9, 2_000, 200);
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    let before = store.record.clone();
    let concurrent_replay = fixture.expected_replay.clone();
    store.set_fault(SelectionFault::ConcurrentReplay(concurrent_replay.clone()));
    let (local_time, release) = prepare_release(&fixture, &mut store);

    let Err(error) = select_registry_head(fixture.candidate, local_time, Some(release)) else {
        panic!("a concurrent replay consumer must defeat the selection");
    };

    assert_eq!(error, RegistryError::Trust(TrustError::ClockReleaseReplay));
    assert!(store.record == before);
    assert!(store.consumed_replays == vec![concurrent_replay]);
    assert_eq!(store.selection_commits.len(), 1);
}

#[test]
fn two_real_consumers_from_one_revision_have_exactly_one_atomic_winner() {
    let first = release_fixture(0xda, 2_000, 200);
    let second = release_fixture(0xda, 2_000, 200);
    assert!(first.key == second.key);
    assert!(first.trusted_time == second.trusted_time);
    assert!(first.candidate_head.object_hash == second.candidate_head.object_hash);
    let shared = SharedStore::new(ModelStore::new(
        first.key,
        first.trusted_time.clone(),
        Some(pin(first.previous_head)),
    ));
    shared.inner.borrow_mut().set_next_revision(73);
    let mut first_handle = shared.clone();
    let mut second_handle = shared.clone();
    let (first_time, first_release) = prepare_release(&first, &mut first_handle);
    let (second_time, second_release) = prepare_release(&second, &mut second_handle);

    let first_outcome = select_registry_head(first.candidate, first_time, Some(first_release));
    let second_outcome = select_registry_head(second.candidate, second_time, Some(second_release));

    let Ok(RegistrySelectionOutcome::Selected(_)) = first_outcome else {
        panic!("the first exact consumer must win the shared CAS");
    };
    let Err(second_error) = second_outcome else {
        panic!("the second exact consumer cannot also win the prior revision");
    };
    assert_eq!(
        second_error,
        RegistryError::Trust(TrustError::StateConflict)
    );
    let store = shared.inner.borrow();
    assert_eq!(store.replay_queries, 2);
    assert_eq!(store.selection_commits.len(), 2);
    assert_eq!(store.consumed_replays.len(), 1);
    assert!(store.consumed_replays[0] == first.expected_replay);
    assert_eq!(store.record.revision, 73);
    assert!(store.record.pinned_head == Some(pin(first.candidate_head)));
}

#[derive(Clone, Copy)]
enum MaliciousReturnKind {
    NonAdvancingRevision,
    LowerRevision,
    WrongFullTime,
    HigherFloor,
    MissingReference,
    WrongHead,
    MissingHead,
    HeadVersionOnly,
}

fn malicious_return(
    kind: MaliciousReturnKind,
    expected_revision: u64,
    expected_time: &TrustedTimeState,
    expected_head: RegistryHeadPin,
    wrong_head: RegistryHeadPin,
) -> ModelRecord {
    let accepted_revision = expected_revision + 72;
    let pinned_head = match kind {
        MaliciousReturnKind::WrongHead => Some(wrong_head),
        MaliciousReturnKind::MissingHead => None,
        MaliciousReturnKind::HeadVersionOnly => Some(RegistryHeadPin::new(
            RegistryVersion::new(expected_head.registry_version().get() + 1),
            expected_head.registry_head_hash(),
        )),
        _ => Some(expected_head),
    };
    let trusted_time = match kind {
        MaliciousReturnKind::WrongFullTime => {
            let reference = expected_time
                .independent_reference()
                .expect("the malicious response fixtures retain a reference");
            TrustedTimeState::from_persisted(
                expected_time.floor(),
                Some(IndependentTimeInput::new(
                    IndependentTimeKind::Checkpoint,
                    ObjectHash::from(support::hash32(0xf1)),
                    reference.verified_time(),
                )),
            )
            .unwrap()
        }
        MaliciousReturnKind::HigherFloor => with_floor_and_same_reference(
            expected_time,
            UnixMillis::new(expected_time.floor().get() + 1),
        ),
        MaliciousReturnKind::MissingReference => TrustedTimeState::initial(expected_time.floor()),
        _ => expected_time.clone(),
    };
    let revision = match kind {
        MaliciousReturnKind::NonAdvancingRevision => expected_revision,
        MaliciousReturnKind::LowerRevision => expected_revision - 1,
        _ => accepted_revision,
    };
    ModelRecord {
        revision,
        trusted_time,
        pinned_head,
    }
}

fn assert_malicious_return_rejected(kind: MaliciousReturnKind) {
    let fixture = direct_fixture(
        100,
        50,
        200,
        850,
        800,
        2_000,
        60,
        persisted_time(700, 650, 0x72),
        300,
        500,
    );
    let expected_time = advance_registry_floor(
        &fixture.trusted_time,
        UnixMillis::new(850),
        UnixMillis::new(800),
    );
    let returned = malicious_return(
        kind,
        INITIAL_REVISION,
        &expected_time,
        pin(fixture.candidate_head),
        pin(fixture.previous_head),
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    store.set_fault(SelectionFault::ReturnRecord(returned));
    let local_time = prepare(&fixture, &mut store, 900);

    let Err(error) = select_registry_head(fixture.candidate, local_time, None) else {
        panic!("a malformed successful store response cannot create a proof");
    };

    assert_eq!(error, RegistryError::Trust(TrustError::StateConflict));
    assert_eq!(store.selection_commits.len(), 1);
}

#[test]
fn malformed_selection_store_success_responses_never_create_authority() {
    assert_malicious_return_rejected(MaliciousReturnKind::NonAdvancingRevision);
    assert_malicious_return_rejected(MaliciousReturnKind::LowerRevision);
    assert_malicious_return_rejected(MaliciousReturnKind::WrongFullTime);
    assert_malicious_return_rejected(MaliciousReturnKind::HigherFloor);
    assert_malicious_return_rejected(MaliciousReturnKind::MissingReference);
    assert_malicious_return_rejected(MaliciousReturnKind::WrongHead);
    assert_malicious_return_rejected(MaliciousReturnKind::MissingHead);
    assert_malicious_return_rejected(MaliciousReturnKind::HeadVersionOnly);
}

fn assert_current_malicious_return_rejected(kind: MaliciousReturnKind) {
    let fixture = single_head_fixture(
        true,
        1,
        100,
        100,
        90,
        2_000,
        60,
        persisted_time(1_000, 970, 0x7d),
        50,
    );
    let returned = malicious_return(
        kind,
        INITIAL_REVISION,
        &fixture.trusted_time,
        pin(fixture.head),
        RegistryHeadPin::new(
            fixture.head.version,
            ObjectHash::from(support::hash32(0x7f)),
        ),
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        fixture.original_pin,
    );
    store.set_fault(SelectionFault::ReturnRecord(returned));
    let local_time =
        prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(1_000), &[]).unwrap();
    let Err(error) = select_registry_head(fixture.candidate, local_time, None) else {
        panic!("a malformed current compare-and-affirm response cannot create authority");
    };
    assert_eq!(error, RegistryError::Trust(TrustError::StateConflict));
}

fn assert_advanced_malicious_return_rejected(kind: MaliciousReturnKind) {
    let fixture = direct_fixture(
        100,
        50,
        200,
        850,
        800,
        875,
        60,
        persisted_time(700, 650, 0x80),
        300,
        500,
    );
    let expected_time = advance_registry_floor(
        &fixture.trusted_time,
        UnixMillis::new(850),
        UnixMillis::new(800),
    );
    let returned = malicious_return(
        kind,
        INITIAL_REVISION,
        &expected_time,
        pin(fixture.candidate_head),
        pin(fixture.previous_head),
    );
    let mut store = ModelStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
    );
    store.set_fault(SelectionFault::ReturnRecord(returned));
    let local_time = prepare(&fixture, &mut store, 900);
    let Err(error) = select_registry_head(fixture.candidate, local_time, None) else {
        panic!("a malformed Advanced commit response cannot create diagnostics");
    };
    assert_eq!(error, RegistryError::Trust(TrustError::StateConflict));
}

#[test]
fn malformed_store_success_is_rejected_in_current_and_advanced_branches() {
    for kind in [
        MaliciousReturnKind::NonAdvancingRevision,
        MaliciousReturnKind::LowerRevision,
        MaliciousReturnKind::WrongFullTime,
        MaliciousReturnKind::HigherFloor,
        MaliciousReturnKind::MissingReference,
        MaliciousReturnKind::WrongHead,
        MaliciousReturnKind::MissingHead,
        MaliciousReturnKind::HeadVersionOnly,
    ] {
        assert_current_malicious_return_rejected(kind);
        assert_advanced_malicious_return_rejected(kind);
    }
}

#[test]
fn independently_committed_time_survives_a_later_selection_transaction_failure() {
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
    let previous_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(100),
            ..HeadOptions::default()
        },
    );
    let previous_policy_hash = line.current_policy_hash().unwrap();
    let candidate_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(850),
            not_before: UnixMillis::new(800),
            not_after: UnixMillis::new(2_000),
            ..HeadOptions::default()
        },
    );
    let key = support::state_key();
    let initial_time = persisted_time(700, 650, 0x74);
    let trust = line.verified_with_time(Pin::Head(2), initial_time.clone());
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    assert_eq!(candidate.registry_version(), candidate_head.version);
    let source = receipt_source(
        &candidate,
        previous_head,
        previous_policy_hash,
        CertificateHash::from(server_head.direct_object_hash.unwrap()),
        UnixMillis::new(900),
    );
    let mut store = ModelStore::new(key, initial_time, Some(pin(previous_head)));
    store.set_next_revision(29);
    store.set_fault(SelectionFault::BeforeHeadAndFloor(
        StateStoreError::Unavailable,
    ));
    let local_time =
        prepare_local_time(&mut store, &candidate, UnixMillis::new(900), &[source]).unwrap();

    let Err(error) = select_registry_head(candidate, local_time, None) else {
        panic!("the later Registry transaction fault cannot yield authority");
    };

    assert_eq!(error, RegistryError::Trust(TrustError::StateUnavailable));
    assert_eq!(store.independent_commits, 1);
    assert_eq!(store.selection_commits.len(), 1);
    assert_eq!(store.record.revision, 29);
    assert_eq!(store.record.trusted_time.floor(), UnixMillis::new(900));
    assert_eq!(
        store
            .record
            .trusted_time
            .independent_reference()
            .expect("the verified Receipt commit must survive")
            .verified_time(),
        UnixMillis::new(900)
    );
    assert!(store.record.pinned_head == Some(pin(previous_head)));
}
