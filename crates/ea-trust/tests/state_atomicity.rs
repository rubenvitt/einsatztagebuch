mod support;

use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, SecretBytes};
use ea_format::{
    CertificateKindV1, CheckpointCoreFieldsV1, CheckpointCoreV1, EvidenceObjectV1, Parsed,
    ParsedArchiveObject, ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1, decode_exact_object,
    encode_evidence, encode_receipt,
};
use ea_time::{
    IndependentTimeInput, IndependentTimeKind, IndependentTimeReference, TrustedTimeState,
};
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, LocalTimeBlock, PersistedTrustRecord,
    RegistryCandidate, RegistryHeadPin, RegistrySelectionCommit, StateStoreError, TrustError,
    TrustStateKey, TrustStateStore, VerifiedSignedTime, load_trust_state, prepare_local_time,
    verify_checkpoint_time, verify_receipt_time, verify_registry_candidate,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, Hash32, ObjectHash,
    RegistryVersion, UnixMillis,
};

use support::{ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder};

const INITIAL_REVISION: u64 = 17;
const SERVER_SECRET: [u8; 32] = [
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
];

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

#[derive(Clone, Copy)]
enum StoreFault {
    None,
    Load(StateStoreError),
    Commit(StateStoreError),
    RaceBeforeCommit,
}

struct ModelStore {
    key: TrustStateKey,
    record: ModelRecord,
    fault: StoreFault,
    forced_return: Option<ModelRecord>,
    revision_step: u64,
    load_count: usize,
    independent_commit_count: usize,
    clock_release_query_count: usize,
    registry_selection_commit_count: usize,
    requested_load_key: Option<TrustStateKey>,
    requested_commit_key: Option<TrustStateKey>,
    requested_expected_revision: Option<u64>,
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
            fault: StoreFault::None,
            forced_return: None,
            revision_step: 1,
            load_count: 0,
            independent_commit_count: 0,
            clock_release_query_count: 0,
            registry_selection_commit_count: 0,
            requested_load_key: None,
            requested_commit_key: None,
            requested_expected_revision: None,
        }
    }

    fn with_fault(mut self, fault: StoreFault) -> Self {
        self.fault = fault;
        self
    }

    fn with_forced_return(mut self, record: ModelRecord) -> Self {
        self.forced_return = Some(record);
        self
    }

    fn with_revision_step(mut self, step: u64) -> Self {
        self.revision_step = step;
        self
    }
}

impl TrustStateStore for ModelStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        self.load_count += 1;
        self.requested_load_key = Some(key);
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        if let StoreFault::Load(error) = self.fault {
            return Err(error);
        }
        Ok(self.record.persisted())
    }

    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.independent_commit_count += 1;
        self.requested_commit_key = Some(key);
        self.requested_expected_revision = Some(expected_revision);
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        if let StoreFault::RaceBeforeCommit = self.fault {
            self.record.revision = self
                .record
                .revision
                .checked_add(1)
                .ok_or(StateStoreError::MonotonicityViolation)?;
            return Err(StateStoreError::Conflict);
        }
        if let StoreFault::Commit(error) = self.fault {
            return Err(error);
        }
        if expected_revision != self.record.revision {
            return Err(StateStoreError::Conflict);
        }
        let next = commit.next_trusted_time();
        if !time_state_is_monotonic(&self.record.trusted_time, next) {
            return Err(StateStoreError::MonotonicityViolation);
        }
        if let Some(record) = self.forced_return.take() {
            return Ok(record.persisted());
        }
        let revision = self
            .record
            .revision
            .checked_add(self.revision_step)
            .ok_or(StateStoreError::MonotonicityViolation)?;
        self.record = ModelRecord {
            revision,
            trusted_time: next.clone(),
            pinned_head: self.record.pinned_head,
        };
        Ok(self.record.persisted())
    }

    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.clock_release_query_count += 1;
        let _storage_key = (key.organization_id(), key.target_device_id(), *key.nonce());
        Ok(false)
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.registry_selection_commit_count += 1;
        let _store_dto = (
            key,
            expected_revision,
            commit.next_trusted_time().floor(),
            commit.next_head().registry_version(),
            commit.next_head().registry_head_hash(),
            commit.replay_key().map(|replay| {
                (
                    replay.organization_id(),
                    replay.target_device_id(),
                    *replay.nonce(),
                )
            }),
        );
        Err(StateStoreError::Unavailable)
    }
}

fn time_state_is_monotonic(current: &TrustedTimeState, next: &TrustedTimeState) -> bool {
    if next.floor() < current.floor()
        || next
            .independent_reference()
            .is_some_and(|reference| reference.verified_time() > next.floor())
    {
        return false;
    }
    match (
        current.independent_reference(),
        next.independent_reference(),
    ) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(current), Some(next)) => next == current || reference_preferred(next, current),
    }
}

fn reference_preferred(
    candidate: &IndependentTimeReference,
    current: &IndependentTimeReference,
) -> bool {
    candidate.verified_time() > current.verified_time()
        || (candidate.verified_time() == current.verified_time()
            && ((candidate.kind() as u8) < (current.kind() as u8)
                || (candidate.kind() == current.kind()
                    && candidate.object_hash() < current.object_hash())))
}

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

struct FlowFixture {
    candidate: RegistryCandidate,
    authority_head: BuiltHead,
    server_certificate_hash: CertificateHash,
    key: TrustStateKey,
    initial_time: TrustedTimeState,
    pin: RegistryHeadPin,
}

fn current_fixture(initial_time: TrustedTimeState) -> FlowFixture {
    fixture(initial_time, None)
}

fn successor_fixture(
    initial_time: TrustedTimeState,
    guard_skew: u64,
    target_skew: u64,
) -> FlowFixture {
    fixture(initial_time, Some((guard_skew, target_skew)))
}

fn fixture(initial_time: TrustedTimeState, successor_skews: Option<(u64, u64)>) -> FlowFixture {
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
            valid_through: Some(29),
            policy_max_future_clock_skew_ms_override: successor_skews.map(|value| value.0),
            ..HeadOptions::default()
        },
    );
    let proposed_sequence = if let Some((_, target_skew)) = successor_skews {
        line.push(
            policy(),
            HeadOptions {
                effective_from: Some(30),
                valid_through: Some(39),
                policy_max_future_clock_skew_ms_override: Some(target_skew),
                ..HeadOptions::default()
            },
        );
        ChainSequence::new(30)
    } else {
        ChainSequence::new(25)
    };
    let trust = line.verified_with_time(Pin::Head(2), initial_time.clone());
    let candidate = verify_registry_candidate(&trust, proposed_sequence).unwrap();
    let pin = RegistryHeadPin::new(authority_head.version, authority_head.object_hash);
    FlowFixture {
        candidate,
        authority_head,
        server_certificate_hash: CertificateHash::from(
            server_head
                .direct_object_hash
                .expect("the fixture activates one ServerReceipt certificate"),
        ),
        key: support::state_key(),
        initial_time,
        pin,
    }
}

fn earlier_authority_fixture(initial_time: TrustedTimeState) -> FlowFixture {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    let authority_head = line.push(
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
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(29),
            ..HeadOptions::default()
        },
    );
    let trust = line.verified_with_time(Pin::Head(1), initial_time.clone());
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(15)).unwrap();
    let pin = RegistryHeadPin::new(authority_head.version, authority_head.object_hash);
    FlowFixture {
        candidate,
        authority_head,
        server_certificate_hash: CertificateHash::from(
            authority_head
                .direct_object_hash
                .expect("the earlier authority activates the ServerReceipt certificate"),
        ),
        key: support::state_key(),
        initial_time,
        pin,
    }
}

fn alternate_same_version_authority_fixture(initial_time: TrustedTimeState) -> FlowFixture {
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
            valid_through: Some(29),
            policy_max_future_clock_skew_ms_override: Some(299_999),
            ..HeadOptions::default()
        },
    );
    let trust = line.verified_with_time(Pin::Head(2), initial_time.clone());
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(25)).unwrap();
    let pin = RegistryHeadPin::new(authority_head.version, authority_head.object_hash);
    FlowFixture {
        candidate,
        authority_head,
        server_certificate_hash: CertificateHash::from(
            server_head
                .direct_object_hash
                .expect("the alternate line retains its ServerReceipt certificate"),
        ),
        key: support::state_key(),
        initial_time,
        pin,
    }
}

fn chain_id() -> ChainId {
    ChainId::try_from(&[0x31; 16][..]).unwrap()
}

fn hash32_from_object(hash: ObjectHash) -> Hash32 {
    Hash32::try_from(hash.as_bytes().as_slice()).unwrap()
}

fn server_key() -> CanonicalPublicCoseKey {
    use ed25519_dalek::SigningKey;

    CanonicalPublicCoseKey::ed25519(
        *SigningKey::from_bytes(&SERVER_SECRET)
            .verifying_key()
            .as_bytes(),
    )
    .unwrap()
}

fn parsed_receipt(
    fixture: &FlowFixture,
    verified_time: UnixMillis,
    marker: u8,
) -> Parsed<ReceiptV1> {
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: support::organization(),
        chain_id: chain_id(),
        chain_sequence: fixture.authority_head.effective_from,
        entry_hash: EntryHash::from(support::hash32(marker)),
        entry_object_hash: ObjectHash::from(support::hash32(marker.wrapping_add(1))),
        previous_entry_hash: Some(EntryHash::from(support::hash32(marker.wrapping_sub(1)))),
        registry_version: fixture.authority_head.version,
        registry_head_hash: hash32_from_object(fixture.authority_head.object_hash),
        policy_object_hash: ObjectHash::from(support::hash32(marker.wrapping_add(2))),
        initial_grant_plan_hash: support::hash32(marker.wrapping_add(3)),
        initial_grant_object_hashes: vec![ObjectHash::from(support::hash32(
            marker.wrapping_add(4),
        ))],
        accepted_at_server: verified_time,
        evidence_due_at: None,
        server_key_thumbprint: server_key().thumbprint(),
        server_certificate_hash: fixture.server_certificate_hash,
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
        .sign_receipt(core.exact_bytes())
        .unwrap();
    let exact = encode_receipt(&ReceiptV1::new(core, signature).unwrap()).unwrap();
    match decode_exact_object(exact.as_bytes()).unwrap() {
        ParsedArchiveObject::Receipt(receipt) => receipt,
        _ => panic!("the model-store fixture must remain an exact Receipt"),
    }
}

fn parsed_checkpoint(
    fixture: &FlowFixture,
    verified_time: UnixMillis,
    marker: u8,
) -> Parsed<EvidenceObjectV1> {
    let core = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: support::organization(),
        chain_id: chain_id(),
        covered_from_sequence: ChainSequence::new(0),
        covered_through_sequence: fixture.authority_head.effective_from,
        head_entry_hash: EntryHash::from(support::hash32(marker)),
        registry_head_hash: hash32_from_object(fixture.authority_head.object_hash),
        issued_at_server: verified_time,
        previous_evidence_hash: Some(ObjectHash::from(support::hash32(marker.wrapping_add(1)))),
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
        .sign_checkpoint(fixture.server_certificate_hash, core.exact_bytes())
        .unwrap();
    let exact = encode_evidence(&EvidenceObjectV1::standard(core, signature).unwrap()).unwrap();
    match decode_exact_object(exact.as_bytes()).unwrap() {
        ParsedArchiveObject::Evidence(evidence) => evidence,
        _ => panic!("the model-store fixture must remain exact Checkpoint evidence"),
    }
}

fn receipt_proof(
    fixture: &FlowFixture,
    verified_time: UnixMillis,
    marker: u8,
) -> (VerifiedSignedTime, ObjectHash) {
    let receipt = parsed_receipt(fixture, verified_time, marker);
    let object_hash = receipt.object_hash();
    let proof = verify_receipt_time(
        fixture
            .candidate
            .preexisting_authority()
            .expect("the fixture is pinned to a preexisting Head"),
        &receipt,
    )
    .unwrap();
    (proof, object_hash)
}

fn checkpoint_proof(
    fixture: &FlowFixture,
    verified_time: UnixMillis,
    marker: u8,
) -> (VerifiedSignedTime, ObjectHash) {
    let checkpoint = parsed_checkpoint(fixture, verified_time, marker);
    let object_hash = checkpoint.object_hash();
    let proof = verify_checkpoint_time(
        fixture
            .candidate
            .preexisting_authority()
            .expect("the fixture is pinned to a preexisting Head"),
        &checkpoint,
    )
    .unwrap();
    (proof, object_hash)
}

fn model_store(fixture: &FlowFixture) -> ModelStore {
    ModelStore::new(fixture.key, fixture.initial_time.clone(), Some(fixture.pin))
}

fn expect_error(
    result: Result<LocalTimeBlock<'_>, TrustError>,
    expected: TrustError,
) -> TrustError {
    let error = result
        .err()
        .expect("the invalid persistent-time transition must fail closed");
    assert_eq!(error.code(), expected.code());
    assert_eq!(error.to_string(), expected.code());
    assert_eq!(format!("{error:?}"), expected.code());
    error
}

fn expect_local_time(result: Result<LocalTimeBlock<'_>, TrustError>) {
    let _block = result.expect("the valid persistent-time transition must produce one block");
}

fn assert_reference(
    state: &TrustedTimeState,
    kind: IndependentTimeKind,
    object_hash: ObjectHash,
    verified_time: UnixMillis,
) {
    let reference = state
        .independent_reference()
        .expect("the committed state must retain its exact independent reference");
    assert_eq!(reference.kind(), kind);
    assert!(reference.object_hash() == object_hash);
    assert!(reference.verified_time() == verified_time);
    assert!(state.floor() >= verified_time);
}

#[test]
fn public_api_requires_a_candidate_verified_sources_and_an_exclusive_store_borrow() {
    assert_eq!(
        TrustError::TimeOverflow.code(),
        "EA-TIME-OVERFLOW",
        "ea-time arithmetic overflow must retain its exact stable family",
    );
}

#[test]
fn load_validates_monotonic_state_and_preserves_every_store_error_family() {
    let key = support::state_key();
    let valid_time = TrustedTimeState::initial(UnixMillis::new(100));
    let mut valid = ModelStore::new(key, valid_time.clone(), None);
    let snapshot = load_trust_state(&mut valid, key).unwrap();
    assert!(snapshot.key() == key);
    assert_eq!(snapshot.revision(), INITIAL_REVISION);
    assert!(snapshot.trusted_time() == &valid_time);
    assert!(snapshot.pinned_head().is_none());

    let invalid_time = TrustedTimeState::from_persisted(
        UnixMillis::new(100),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            ObjectHash::from(support::hash32(0x91)),
            UnixMillis::new(101),
        )),
    );
    assert_eq!(
        invalid_time.err().unwrap().code(),
        "EA-TIME-STATE-MONOTONICITY"
    );

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
        let mut store = ModelStore::new(key, valid_time.clone(), None)
            .with_fault(StoreFault::Load(store_error));
        let error = load_trust_state(&mut store, key).err().unwrap();
        assert_eq!(error.code(), trust_error.code());
    }
}

#[test]
fn prepare_reloads_the_exact_key_revision_pin_and_complete_time_state() {
    let fixture = current_fixture(TrustedTimeState::initial(UnixMillis::new(100)));

    let mut exact = model_store(&fixture);
    expect_local_time(prepare_local_time(
        &mut exact,
        &fixture.candidate,
        UnixMillis::new(100),
        &[],
    ));
    assert_eq!(exact.load_count, 1);
    assert!(exact.requested_load_key == Some(fixture.key));
    assert_eq!(exact.independent_commit_count, 0);
    assert_eq!(exact.clock_release_query_count, 0);
    assert_eq!(exact.registry_selection_commit_count, 0);

    let mut changed_revision = model_store(&fixture);
    changed_revision.record.revision = INITIAL_REVISION + 1;
    expect_error(
        prepare_local_time(
            &mut changed_revision,
            &fixture.candidate,
            UnixMillis::new(100),
            &[],
        ),
        TrustError::StateConflict,
    );

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
        let mut store = model_store(&fixture).with_fault(StoreFault::Load(store_error));
        expect_error(
            prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(100), &[]),
            trust_error,
        );
        assert_eq!(store.independent_commit_count, 0);
    }

    for changed_pin in [
        RegistryHeadPin::new(
            RegistryVersion::new(fixture.pin.registry_version().get() + 1),
            fixture.pin.registry_head_hash(),
        ),
        RegistryHeadPin::new(
            fixture.pin.registry_version(),
            ObjectHash::from(support::hash32(0xb1)),
        ),
    ] {
        let mut store = model_store(&fixture);
        store.record.pinned_head = Some(changed_pin);
        expect_error(
            prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(100), &[]),
            TrustError::StateConflict,
        );
    }
    let mut removed_pin = model_store(&fixture);
    removed_pin.record.pinned_head = None;
    expect_error(
        prepare_local_time(
            &mut removed_pin,
            &fixture.candidate,
            UnixMillis::new(100),
            &[],
        ),
        TrustError::StateConflict,
    );

    for changed_time in [
        TrustedTimeState::initial(UnixMillis::new(101)),
        TrustedTimeState::from_persisted(
            UnixMillis::new(100),
            Some(IndependentTimeInput::new(
                IndependentTimeKind::Checkpoint,
                ObjectHash::from(support::hash32(0xb2)),
                UnixMillis::new(100),
            )),
        )
        .unwrap(),
    ] {
        let mut store = model_store(&fixture);
        store.record.trusted_time = changed_time;
        expect_error(
            prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(100), &[]),
            TrustError::StateConflict,
        );
    }

    let mut changed_key = model_store(&fixture);
    changed_key.key = TrustStateKey {
        organization_id: fixture.key.organization_id,
        device_id: DeviceId::try_from(&[0xee; 16][..]).unwrap(),
    };
    expect_error(
        prepare_local_time(
            &mut changed_key,
            &fixture.candidate,
            UnixMillis::new(100),
            &[],
        ),
        TrustError::StateConflict,
    );

    let persisted_reference = IndependentTimeInput::new(
        IndependentTimeKind::Receipt,
        ObjectHash::from(support::hash32(0xc1)),
        UnixMillis::new(100),
    );
    let referenced_time =
        TrustedTimeState::from_persisted(UnixMillis::new(100), Some(persisted_reference)).unwrap();
    let referenced_fixture = current_fixture(referenced_time);
    for changed_reference in [
        IndependentTimeInput::new(
            IndependentTimeKind::Checkpoint,
            ObjectHash::from(support::hash32(0xc1)),
            UnixMillis::new(100),
        ),
        IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            ObjectHash::from(support::hash32(0xc2)),
            UnixMillis::new(100),
        ),
        IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            ObjectHash::from(support::hash32(0xc1)),
            UnixMillis::new(99),
        ),
    ] {
        let mut store = model_store(&referenced_fixture);
        store.record.trusted_time =
            TrustedTimeState::from_persisted(UnixMillis::new(100), Some(changed_reference))
                .unwrap();
        expect_error(
            prepare_local_time(
                &mut store,
                &referenced_fixture.candidate,
                UnixMillis::new(100),
                &[],
            ),
            TrustError::StateConflict,
        );
    }
}

#[test]
fn bootstrap_accepts_empty_sources_but_rejects_any_preexisting_authority_proof() {
    let initial = TrustedTimeState::initial(UnixMillis::new(100));
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    let trust = line.verified_with_time(Pin::None, initial.clone());
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(1)).unwrap();
    assert!(candidate.preexisting_authority().is_none());
    let key = support::state_key();
    let mut empty = ModelStore::new(key, initial.clone(), None);
    expect_local_time(prepare_local_time(
        &mut empty,
        &candidate,
        UnixMillis::new(100),
        &[],
    ));
    assert_eq!(empty.independent_commit_count, 0);
    assert!(empty.record.pinned_head.is_none());

    let mut with_source = ModelStore::new(key, initial.clone(), None);
    let authority_fixture = current_fixture(initial);
    let (proof, _) = receipt_proof(&authority_fixture, UnixMillis::new(200), 0x33);
    expect_error(
        prepare_local_time(&mut with_source, &candidate, UnixMillis::new(100), &[proof]),
        TrustError::StateConflict,
    );
    assert_eq!(with_source.independent_commit_count, 0);
}

#[test]
fn every_source_authority_pin_is_checked_before_any_reference_is_committed() {
    let initial = TrustedTimeState::initial(UnixMillis::new(100));
    let fixture = current_fixture(initial.clone());
    let earlier = earlier_authority_fixture(initial);
    let (valid, _) = receipt_proof(&fixture, UnixMillis::new(200), 0x31);
    let (wrong_head, _) = receipt_proof(&earlier, UnixMillis::new(300), 0x32);
    let sources = [valid, wrong_head];
    let mut store = model_store(&fixture);

    expect_error(
        prepare_local_time(
            &mut store,
            &fixture.candidate,
            UnixMillis::new(100),
            &sources,
        ),
        TrustError::StateConflict,
    );

    assert_eq!(store.independent_commit_count, 0);
    assert_eq!(store.record.revision, INITIAL_REVISION);
    assert!(store.record.trusted_time == fixture.initial_time);

    let alternate =
        alternate_same_version_authority_fixture(TrustedTimeState::initial(UnixMillis::new(100)));
    assert!(alternate.pin.registry_version() == fixture.pin.registry_version());
    assert!(alternate.pin.registry_head_hash() != fixture.pin.registry_head_hash());
    let (wrong_hash, _) = receipt_proof(&alternate, UnixMillis::new(400), 0x34);
    let mut store = model_store(&fixture);
    expect_error(
        prepare_local_time(
            &mut store,
            &fixture.candidate,
            UnixMillis::new(100),
            &[wrong_hash],
        ),
        TrustError::StateConflict,
    );
    assert_eq!(store.independent_commit_count, 0);
    assert!(store.record.trusted_time == fixture.initial_time);

    let (overflowing_wrong_head, _) =
        receipt_proof(&earlier, UnixMillis::new(i64::MAX - 100), 0x35);
    let mut store = model_store(&fixture);
    expect_error(
        prepare_local_time(
            &mut store,
            &fixture.candidate,
            UnixMillis::new(i64::MAX - 100),
            &[overflowing_wrong_head],
        ),
        TrustError::StateConflict,
    );
    assert_eq!(store.independent_commit_count, 0);

    let (wrong_head, _) = receipt_proof(&earlier, UnixMillis::new(300), 0x36);
    let mut unavailable =
        model_store(&fixture).with_fault(StoreFault::Load(StateStoreError::Unavailable));
    expect_error(
        prepare_local_time(
            &mut unavailable,
            &fixture.candidate,
            UnixMillis::new(100),
            &[wrong_head],
        ),
        TrustError::StateUnavailable,
    );
    assert_eq!(unavailable.independent_commit_count, 0);
}

#[test]
fn reload_conflict_precedes_time_arithmetic_overflow() {
    let near_max = UnixMillis::new(i64::MAX - 100);
    let time = TrustedTimeState::from_persisted(
        near_max,
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            ObjectHash::from(support::hash32(0xd1)),
            near_max,
        )),
    )
    .unwrap();
    let fixture = current_fixture(time);
    let mut store = model_store(&fixture);
    store.record.revision += 1;
    expect_error(
        prepare_local_time(&mut store, &fixture.candidate, near_max, &[]),
        TrustError::StateConflict,
    );
    assert_eq!(store.independent_commit_count, 0);
}

#[test]
fn changed_independent_time_commits_once_with_exact_cas_and_store_dto_values() {
    let fixture = current_fixture(TrustedTimeState::initial(UnixMillis::new(100)));
    let verified_time = UnixMillis::new(250);
    let (proof, object_hash) = receipt_proof(&fixture, verified_time, 0x41);
    let mut store = model_store(&fixture);

    expect_local_time(prepare_local_time(
        &mut store,
        &fixture.candidate,
        UnixMillis::new(200),
        &[proof],
    ));

    assert_eq!(store.load_count, 1);
    assert_eq!(store.independent_commit_count, 1);
    assert_eq!(store.clock_release_query_count, 0);
    assert_eq!(store.registry_selection_commit_count, 0);
    assert!(store.requested_commit_key == Some(fixture.key));
    assert_eq!(store.requested_expected_revision, Some(INITIAL_REVISION));
    assert_eq!(store.record.revision, INITIAL_REVISION + 1);
    assert!(store.record.pinned_head == Some(fixture.pin));
    assert_reference(
        &store.record.trusted_time,
        IndependentTimeKind::Receipt,
        object_hash,
        verified_time,
    );
}

#[test]
fn stale_cas_and_store_failures_do_not_apply_the_attempted_reference() {
    let fixture = current_fixture(TrustedTimeState::initial(UnixMillis::new(100)));
    let (proof, _) = receipt_proof(&fixture, UnixMillis::new(250), 0x42);
    let mut raced = model_store(&fixture).with_fault(StoreFault::RaceBeforeCommit);
    expect_error(
        prepare_local_time(
            &mut raced,
            &fixture.candidate,
            UnixMillis::new(100),
            &[proof],
        ),
        TrustError::StateConflict,
    );
    assert_eq!(raced.record.revision, INITIAL_REVISION + 1);
    assert!(raced.record.trusted_time == fixture.initial_time);

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
        let (proof, _) = receipt_proof(&fixture, UnixMillis::new(251), 0x43);
        let mut store = model_store(&fixture).with_fault(StoreFault::Commit(store_error));
        expect_error(
            prepare_local_time(
                &mut store,
                &fixture.candidate,
                UnixMillis::new(100),
                &[proof],
            ),
            trust_error,
        );
        assert_eq!(store.record.revision, INITIAL_REVISION);
        assert!(store.record.trusted_time == fixture.initial_time);
    }
}

#[test]
fn successful_store_response_must_have_a_new_revision_exact_state_and_unchanged_pin() {
    let fixture = current_fixture(TrustedTimeState::initial(UnixMillis::new(100)));
    let verified_time = UnixMillis::new(250);
    let (proof, object_hash) = receipt_proof(&fixture, verified_time, 0x51);
    let expected_time = TrustedTimeState::from_persisted(
        verified_time,
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            object_hash,
            verified_time,
        )),
    )
    .unwrap();
    let invalid_returns = [
        ModelRecord {
            revision: INITIAL_REVISION,
            trusted_time: expected_time.clone(),
            pinned_head: Some(fixture.pin),
        },
        ModelRecord {
            revision: INITIAL_REVISION - 1,
            trusted_time: expected_time.clone(),
            pinned_head: Some(fixture.pin),
        },
        ModelRecord {
            revision: INITIAL_REVISION + 1,
            trusted_time: expected_time.clone(),
            pinned_head: Some(RegistryHeadPin::new(
                fixture.pin.registry_version(),
                ObjectHash::from(support::hash32(0xb3)),
            )),
        },
        ModelRecord {
            revision: INITIAL_REVISION + 1,
            trusted_time: expected_time.clone(),
            pinned_head: Some(RegistryHeadPin::new(
                RegistryVersion::new(fixture.pin.registry_version().get() + 1),
                fixture.pin.registry_head_hash(),
            )),
        },
        ModelRecord {
            revision: INITIAL_REVISION + 1,
            trusted_time: TrustedTimeState::from_persisted(
                UnixMillis::new(verified_time.get() + 1),
                Some(IndependentTimeInput::new(
                    IndependentTimeKind::Receipt,
                    object_hash,
                    verified_time,
                )),
            )
            .unwrap(),
            pinned_head: Some(fixture.pin),
        },
        ModelRecord {
            revision: INITIAL_REVISION + 1,
            trusted_time: TrustedTimeState::from_persisted(
                verified_time,
                Some(IndependentTimeInput::new(
                    IndependentTimeKind::Checkpoint,
                    object_hash,
                    verified_time,
                )),
            )
            .unwrap(),
            pinned_head: Some(fixture.pin),
        },
        ModelRecord {
            revision: INITIAL_REVISION + 1,
            trusted_time: TrustedTimeState::from_persisted(
                verified_time,
                Some(IndependentTimeInput::new(
                    IndependentTimeKind::Receipt,
                    ObjectHash::from(support::hash32(0xb4)),
                    verified_time,
                )),
            )
            .unwrap(),
            pinned_head: Some(fixture.pin),
        },
        ModelRecord {
            revision: INITIAL_REVISION + 1,
            trusted_time: TrustedTimeState::from_persisted(
                verified_time,
                Some(IndependentTimeInput::new(
                    IndependentTimeKind::Receipt,
                    object_hash,
                    UnixMillis::new(verified_time.get() - 1),
                )),
            )
            .unwrap(),
            pinned_head: Some(fixture.pin),
        },
        ModelRecord {
            revision: INITIAL_REVISION + 1,
            trusted_time: expected_time.clone(),
            pinned_head: None,
        },
    ];
    for returned in invalid_returns {
        let mut store = model_store(&fixture).with_forced_return(returned);
        expect_error(
            prepare_local_time(
                &mut store,
                &fixture.candidate,
                UnixMillis::new(100),
                std::slice::from_ref(&proof),
            ),
            TrustError::StateConflict,
        );
        assert_eq!(store.record.revision, INITIAL_REVISION);
        assert!(store.record.trusted_time == fixture.initial_time);
    }

    let mut jumping_revision = model_store(&fixture).with_revision_step(7);
    expect_local_time(prepare_local_time(
        &mut jumping_revision,
        &fixture.candidate,
        UnixMillis::new(100),
        &[proof],
    ));
    assert_eq!(jumping_revision.record.revision, INITIAL_REVISION + 7);
    assert!(jumping_revision.record.trusted_time == expected_time);
}

#[test]
fn deterministic_merge_is_order_independent_and_uses_kind_then_hash_ties() {
    let tied_time = UnixMillis::new(500);
    let initial = TrustedTimeState::from_persisted(
        tied_time,
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Tsa,
            ObjectHash::from(support::hash32(0xe1)),
            tied_time,
        )),
    )
    .unwrap();
    let fixture = current_fixture(initial);
    let (receipt_a, hash_a) = receipt_proof(&fixture, tied_time, 0x61);
    let (receipt_b, hash_b) = receipt_proof(&fixture, tied_time, 0x62);
    let (checkpoint, _) = checkpoint_proof(&fixture, tied_time, 0x63);
    let expected_hash = hash_a.min(hash_b);
    let sources = [receipt_b, checkpoint, receipt_a];
    let mut first = model_store(&fixture);
    expect_local_time(prepare_local_time(
        &mut first,
        &fixture.candidate,
        tied_time,
        &sources,
    ));
    assert_reference(
        &first.record.trusted_time,
        IndependentTimeKind::Receipt,
        expected_hash,
        tied_time,
    );

    let (receipt_a, _) = receipt_proof(&fixture, tied_time, 0x61);
    let (receipt_b, _) = receipt_proof(&fixture, tied_time, 0x62);
    let (checkpoint, _) = checkpoint_proof(&fixture, tied_time, 0x63);
    let sources = [receipt_a, checkpoint, receipt_b];
    let mut reverse = model_store(&fixture);
    expect_local_time(prepare_local_time(
        &mut reverse,
        &fixture.candidate,
        tied_time,
        &sources,
    ));
    assert!(reverse.record.trusted_time == first.record.trusted_time);
}

#[test]
fn duplicate_or_older_reference_is_a_noop_while_newer_time_advances_the_floor() {
    let persisted_time = UnixMillis::new(500);
    let persisted_hash = ObjectHash::from(support::hash32(0xe2));
    let initial = TrustedTimeState::from_persisted(
        persisted_time,
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            persisted_hash,
            persisted_time,
        )),
    )
    .unwrap();
    let fixture = current_fixture(initial);

    let temporary = current_fixture(TrustedTimeState::initial(persisted_time));
    let (duplicate, duplicate_hash) = receipt_proof(&temporary, persisted_time, 0x70);
    let exact_duplicate_state = TrustedTimeState::from_persisted(
        persisted_time,
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            duplicate_hash,
            persisted_time,
        )),
    )
    .unwrap();
    let duplicate_fixture = current_fixture(exact_duplicate_state);
    let mut duplicate_store = model_store(&duplicate_fixture);
    expect_local_time(prepare_local_time(
        &mut duplicate_store,
        &duplicate_fixture.candidate,
        persisted_time,
        &[duplicate],
    ));
    assert_eq!(duplicate_store.independent_commit_count, 0);
    assert_eq!(duplicate_store.clock_release_query_count, 0);
    assert_eq!(duplicate_store.registry_selection_commit_count, 0);
    assert_reference(
        &duplicate_store.record.trusted_time,
        IndependentTimeKind::Receipt,
        duplicate_hash,
        persisted_time,
    );

    let (older, _) = receipt_proof(&fixture, UnixMillis::new(499), 0x71);
    let mut no_op = model_store(&fixture);
    expect_local_time(prepare_local_time(
        &mut no_op,
        &fixture.candidate,
        persisted_time,
        &[older],
    ));
    assert_eq!(no_op.independent_commit_count, 0);
    assert_reference(
        &no_op.record.trusted_time,
        IndependentTimeKind::Receipt,
        persisted_hash,
        persisted_time,
    );

    let newer_time = UnixMillis::new(501);
    let (newer, newer_hash) = receipt_proof(&fixture, newer_time, 0x72);
    let mut advanced = model_store(&fixture);
    expect_local_time(prepare_local_time(
        &mut advanced,
        &fixture.candidate,
        persisted_time,
        &[newer],
    ));
    assert_eq!(advanced.independent_commit_count, 1);
    assert_reference(
        &advanced.record.trusted_time,
        IndependentTimeKind::Receipt,
        newer_hash,
        newer_time,
    );
}

#[test]
fn candidate_event_times_never_persist_during_local_time_preparation() {
    let fixture = current_fixture(TrustedTimeState::initial(UnixMillis::new(0)));
    let mut store = model_store(&fixture);
    expect_local_time(prepare_local_time(
        &mut store,
        &fixture.candidate,
        UnixMillis::new(50),
        &[],
    ));
    assert_eq!(store.independent_commit_count, 0);
    assert_eq!(store.record.trusted_time.floor().get(), 0);
    assert!(store.record.trusted_time.independent_reference().is_none());
}

#[test]
fn independent_commit_survives_guard_policy_evaluation_overflow_and_target_policy_is_ignored() {
    let fixture = successor_fixture(TrustedTimeState::initial(UnixMillis::new(0)), 300, 0);
    let verified_time = UnixMillis::new(i64::MAX - 100);
    let (proof, object_hash) = receipt_proof(&fixture, verified_time, 0x81);
    let mut store = model_store(&fixture);

    expect_error(
        prepare_local_time(&mut store, &fixture.candidate, verified_time, &[proof]),
        TrustError::TimeOverflow,
    );

    assert_eq!(store.independent_commit_count, 1);
    assert_eq!(store.record.revision, INITIAL_REVISION + 1);
    assert_eq!(store.clock_release_query_count, 0);
    assert_eq!(store.registry_selection_commit_count, 0);
    assert_reference(
        &store.record.trusted_time,
        IndependentTimeKind::Receipt,
        object_hash,
        verified_time,
    );

    let reverse = successor_fixture(TrustedTimeState::initial(UnixMillis::new(0)), 0, 300);
    let (proof, object_hash) = receipt_proof(&reverse, verified_time, 0x82);
    let mut store = model_store(&reverse);
    expect_local_time(prepare_local_time(
        &mut store,
        &reverse.candidate,
        UnixMillis::new(verified_time.get() + 1),
        &[proof],
    ));
    assert_eq!(store.independent_commit_count, 1);
    assert_reference(
        &store.record.trusted_time,
        IndependentTimeKind::Receipt,
        object_hash,
        verified_time,
    );
    assert_eq!(store.clock_release_query_count, 0);
    assert_eq!(store.registry_selection_commit_count, 0);
}
