#[path = "../../../crates/ea-trust/tests/support/mod.rs"]
mod support;

use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, SecretBytes, SignerCertificateResolver};
use ea_format::{
    CertificateKindV1, CheckpointCoreFieldsV1, CheckpointCoreV1, EvidenceObjectV1, Parsed,
    ParsedArchiveObject, ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1, decode_exact_object,
    encode_evidence, encode_receipt,
};
use ea_time::{IndependentTimeKind, TrustedTimeState};
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError,
    TrustStateKey, TrustStateStore, VerifiedTrust, decode_trust_anchor, load_trust_state,
    prepare_local_time, select_registry_head, verify_checkpoint_time, verify_clock_release,
    verify_receipt_time, verify_registry_candidate, verify_trust,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, Hash32, ObjectHash,
    RegistryVersion, UnixMillis,
};
use ed25519_dalek::SigningKey;
use minicbor::{Decoder, Encoder};

use support::{ActionSpec, BuiltHead, HeadOptions, RegistryLineBuilder, RootSigner};

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
    organization_id: ea_types::OrganizationId,
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

struct ModelStore {
    key: TrustStateKey,
    record: ModelRecord,
    next_revision: u64,
    independent_commits: usize,
    selection_commits: usize,
    replay_queries: usize,
    consumed_replays: Vec<ReplayTuple>,
}

impl ModelStore {
    fn new(key: TrustStateKey) -> Self {
        Self {
            key,
            record: ModelRecord {
                revision: INITIAL_REVISION,
                trusted_time: TrustedTimeState::initial(UnixMillis::new(800)),
                pinned_head: None,
            },
            next_revision: 29,
            independent_commits: 0,
            selection_commits: 0,
            replay_queries: 0,
            consumed_replays: Vec::new(),
        }
    }

    fn allocate_revision(&mut self) -> u64 {
        let revision = self.next_revision;
        self.next_revision = self
            .next_revision
            .checked_add(12)
            .expect("the bounded system fixture revision must not overflow");
        revision
    }

    fn durable_state(&self) -> (ModelRecord, Vec<ReplayTuple>) {
        (self.record.clone(), self.consumed_replays.clone())
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
        if key != self.key || expected_revision != self.record.revision {
            return Err(StateStoreError::Conflict);
        }
        if commit.next_trusted_time().floor() < self.record.trusted_time.floor() {
            return Err(StateStoreError::MonotonicityViolation);
        }
        self.independent_commits += 1;
        self.record = ModelRecord {
            revision: self.allocate_revision(),
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
        if key != self.key || expected_revision != self.record.revision {
            return Err(StateStoreError::Conflict);
        }
        if commit.next_trusted_time().floor() < self.record.trusted_time.floor()
            || commit.next_trusted_time().independent_reference()
                != self.record.trusted_time.independent_reference()
        {
            return Err(StateStoreError::MonotonicityViolation);
        }
        let replay = commit.replay_key().map(ReplayTuple::from_key);
        if replay
            .as_ref()
            .is_some_and(|candidate| self.consumed_replays.contains(candidate))
        {
            return Err(StateStoreError::ReplayAlreadyConsumed);
        }
        if let Some(replay) = replay {
            self.consumed_replays.push(replay);
        }
        self.selection_commits += 1;
        self.record = ModelRecord {
            revision: self.allocate_revision(),
            trusted_time: commit.next_trusted_time().clone(),
            pinned_head: Some(*commit.next_head()),
        };
        Ok(self.record.persisted())
    }
}

fn state_key() -> TrustStateKey {
    TrustStateKey {
        organization_id: support::organization(),
        device_id: DeviceId::try_from(&[0x51; 16][..]).unwrap(),
    }
}

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
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

fn signed_receipt(
    authority_head: BuiltHead,
    policy_object_hash: ObjectHash,
    server_certificate_hash: CertificateHash,
    verified_time: UnixMillis,
) -> Parsed<ReceiptV1> {
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: support::organization(),
        chain_id: chain_id(),
        chain_sequence: authority_head.effective_from,
        entry_hash: EntryHash::from(support::hash32(0x61)),
        entry_object_hash: ObjectHash::from(support::hash32(0x62)),
        previous_entry_hash: Some(EntryHash::from(support::hash32(0x60))),
        registry_version: authority_head.version,
        registry_head_hash: hash32_from_object(authority_head.object_hash),
        policy_object_hash,
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
    match decode_exact_object(exact.as_bytes()).unwrap() {
        ParsedArchiveObject::Receipt(receipt) => receipt,
        _ => panic!("the system Receipt must retain its exact outer object"),
    }
}

fn signed_checkpoint(
    authority_head: BuiltHead,
    server_certificate_hash: CertificateHash,
    verified_time: UnixMillis,
) -> Parsed<EvidenceObjectV1> {
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
    let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
        .sign_checkpoint(server_certificate_hash, core.exact_bytes())
        .unwrap();
    let exact = encode_evidence(&EvidenceObjectV1::standard(core, signature).unwrap()).unwrap();
    match decode_exact_object(exact.as_bytes()).unwrap() {
        ParsedArchiveObject::Evidence(checkpoint) => checkpoint,
        _ => panic!("the system Checkpoint must retain its exact outer object"),
    }
}

struct ReleaseAuditFields {
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    guard_policy_object_hash: ObjectHash,
    independent_reference_hash: ObjectHash,
    nonce: [u8; 32],
}

fn signed_clock_release(line: &RegistryLineBuilder, fields: ReleaseAuditFields) -> Vec<u8> {
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
        .bytes(state_key().device_id.as_bytes())
        .unwrap()
        .bytes(line.bootstrap_admin_binding_hash().as_bytes())
        .unwrap()
        .bytes(line.bootstrap_admin_hash().as_bytes())
        .unwrap()
        .u8(6)
        .unwrap()
        .u8(1)
        .unwrap()
        .i64(1_050)
        .unwrap()
        .array(2)
        .unwrap()
        .u8(2)
        .unwrap()
        .array(10)
        .unwrap()
        .i64(950)
        .unwrap()
        .i64(1_050)
        .unwrap()
        .u64(37)
        .unwrap()
        .u64(fields.registry_version.get())
        .unwrap()
        .bytes(fields.registry_head_hash.as_bytes())
        .unwrap()
        .bytes(fields.guard_policy_object_hash.as_bytes())
        .unwrap()
        .array(3)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(fields.independent_reference_hash.as_bytes())
        .unwrap()
        .i64(950)
        .unwrap()
        .u8(1)
        .unwrap()
        .i64(1_000)
        .unwrap()
        .i64(1_100)
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

fn reload_verified(line: &RegistryLineBuilder, store: &mut ModelStore) -> VerifiedTrust {
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let source = line.source();
    let key = store.key;
    let snapshot = load_trust_state(store, key).unwrap();
    verify_trust(&anchor, &source, snapshot).unwrap()
}

fn select_plain(
    line: &RegistryLineBuilder,
    store: &mut ModelStore,
    proposed_sequence: ChainSequence,
    os_wall_clock: UnixMillis,
) -> SelectedRegistryHead {
    let trust = reload_verified(line, store);
    let candidate = verify_registry_candidate(&trust, proposed_sequence).unwrap();
    let local_time = prepare_local_time(store, &candidate, os_wall_clock, &[]).unwrap();
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("each stable system iteration must select exactly one Head");
    };
    selected
}

fn push_and_select_plain(
    line: &mut RegistryLineBuilder,
    store: &mut ModelStore,
    action: ActionSpec,
    options: HeadOptions,
    os_wall_clock: UnixMillis,
) -> (BuiltHead, SelectedRegistryHead) {
    let head = line.push(action, options);
    let selected = select_plain(line, store, head.effective_from, os_wall_clock);
    assert!(selected.registry_version() == head.version);
    assert!(selected.registry_head_hash() == head.object_hash);
    (head, selected)
}

fn mutate_embedded_anchor_hash(exact_anchor: &[u8]) -> Vec<u8> {
    let mut decoder = Decoder::new(exact_anchor);
    assert_eq!(decoder.array().unwrap(), Some(12));
    assert_eq!(decoder.str().unwrap(), "EINSATZARCHIV-TRUST-ANCHOR-v1");
    assert_eq!(decoder.u8().unwrap(), 1);
    let embedded_hash = decoder.bytes().unwrap();
    assert_eq!(embedded_hash.len(), 32);
    let hash_start = decoder.position() - embedded_hash.len();
    let mut mutated = exact_anchor.to_vec();
    mutated[hash_start] ^= 1;
    mutated
}

#[derive(Clone, Copy)]
enum TransitionMutation {
    AdminAuthorization,
    DirectTarget,
    ActivationEvent,
}

#[test]
fn one_byte_anchor_and_transition_mutations_fail_without_persistent_change() {
    let mut line = RegistryLineBuilder::new();
    let mut store = ModelStore::new(state_key());
    let initial_durable = store.durable_state();
    let mutated_anchor = mutate_embedded_anchor_hash(line.exact_anchor_bytes());
    assert_eq!(
        decode_trust_anchor(&mutated_anchor)
            .err()
            .expect("the embedded Anchor hash mutation must fail")
            .code(),
        "EA-TRUST-ANCHOR-HASH"
    );
    assert!(store.durable_state() == initial_durable);

    let base_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(10),
            policy_max_future_clock_skew_ms_override: Some(37),
            ..HeadOptions::default()
        },
    );
    let selected = select_plain(
        &line,
        &mut store,
        base_head.effective_from,
        UnixMillis::new(800),
    );
    assert!(selected.registry_head_hash() == base_head.object_hash);
    let durable_prefix = store.durable_state();

    for mutation in [
        TransitionMutation::AdminAuthorization,
        TransitionMutation::DirectTarget,
        TransitionMutation::ActivationEvent,
    ] {
        let mut branch = line.clone();
        let mut options = HeadOptions {
            effective_from: Some(11),
            valid_through: Some(20),
            ..HeadOptions::default()
        };
        match mutation {
            TransitionMutation::AdminAuthorization => {
                options.corrupt_direct_authorization_signature = true;
            }
            TransitionMutation::DirectTarget => {
                options.corrupt_direct_signature = true;
            }
            TransitionMutation::ActivationEvent => {
                options.root_signer = RootSigner::Corrupt;
            }
        }
        branch.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Reader,
                marker: 0x63,
                effective_from: None,
            },
            options,
        );
        let trust = reload_verified(&branch, &mut store);
        assert_eq!(
            verify_registry_candidate(&trust, ChainSequence::new(11))
                .err()
                .expect("the one-byte transition mutation must fail")
                .code(),
            "EA-TRUST-SIGNATURE"
        );
        assert!(store.durable_state() == durable_prefix);
    }
}

#[test]
fn exact_anchor_catalog_and_store_advance_one_singular_transition_per_reload() {
    let mut line = RegistryLineBuilder::new();
    let mut store = ModelStore::new(state_key());
    push_and_select_plain(
        &mut line,
        &mut store,
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(10),
            policy_max_future_clock_skew_ms_override: Some(37),
            ..HeadOptions::default()
        },
        UnixMillis::new(800),
    );
    let initial_policy = line.current_policy_hash().unwrap();
    let (reader_head, _) = push_and_select_plain(
        &mut line,
        &mut store,
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x63,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(11),
            valid_through: Some(20),
            ..HeadOptions::default()
        },
        UnixMillis::new(800),
    );
    let reader = CertificateHash::from(reader_head.direct_object_hash.unwrap());
    push_and_select_plain(
        &mut line,
        &mut store,
        ActionSpec::OperatorBinding {
            certificate_hash: reader_head.direct_object_hash.unwrap(),
            role: ea_format::OperatorRoleV1::Reader,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(21),
            valid_through: Some(30),
            ..HeadOptions::default()
        },
        UnixMillis::new(800),
    );
    let (receipt_authority_head, _) = push_and_select_plain(
        &mut line,
        &mut store,
        ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x67,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(31),
            valid_through: Some(40),
            ..HeadOptions::default()
        },
        UnixMillis::new(800),
    );
    let server = CertificateHash::from(receipt_authority_head.direct_object_hash.unwrap());

    let time_advanced_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(41),
            valid_through: Some(50),
            policy_max_future_clock_skew_ms_override: Some(37),
            ..HeadOptions::default()
        },
    );
    let trust = reload_verified(&line, &mut store);
    let candidate = verify_registry_candidate(&trust, time_advanced_head.effective_from).unwrap();
    let receipt = signed_receipt(
        receipt_authority_head,
        initial_policy,
        server,
        UnixMillis::new(900),
    );
    let checkpoint = signed_checkpoint(receipt_authority_head, server, UnixMillis::new(950));
    let durable_before_invalid_time = store.durable_state();
    let mut corrupt_receipt = receipt.exact_bytes().as_bytes().to_vec();
    *corrupt_receipt.last_mut().unwrap() ^= 1;
    let corrupt_receipt = match decode_exact_object(corrupt_receipt.as_slice()).unwrap() {
        ParsedArchiveObject::Receipt(receipt) => receipt,
        _ => panic!("the one-byte mutation must remain an exact Receipt"),
    };
    assert_eq!(
        verify_receipt_time(candidate.preexisting_authority().unwrap(), &corrupt_receipt)
            .err()
            .expect("the one-byte Receipt signature mutation must fail")
            .code(),
        "EA-TRUST-SIGNATURE"
    );
    assert!(store.durable_state() == durable_before_invalid_time);

    let receipt_proof =
        verify_receipt_time(candidate.preexisting_authority().unwrap(), &receipt).unwrap();
    let checkpoint_proof =
        verify_checkpoint_time(candidate.preexisting_authority().unwrap(), &checkpoint).unwrap();
    let local_time = prepare_local_time(
        &mut store,
        &candidate,
        UnixMillis::new(950),
        &[receipt_proof, checkpoint_proof],
    )
    .unwrap();
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the real Receipt and Checkpoint must select the next Policy Head");
    };
    assert!(selected.registry_version() == time_advanced_head.version);
    assert!(selected.registry_head_hash() == time_advanced_head.object_hash);
    let reference = store
        .record
        .trusted_time
        .independent_reference()
        .expect("the later Checkpoint must become the deterministic reference");
    assert!(reference.kind() == IndependentTimeKind::Checkpoint);
    assert!(reference.object_hash() == checkpoint.object_hash());
    assert!(reference.verified_time() == UnixMillis::new(950));
    assert!(store.record.trusted_time.floor() == UnixMillis::new(950));
    assert_eq!(store.independent_commits, 1);

    push_and_select_plain(
        &mut line,
        &mut store,
        ActionSpec::RootRotate {
            previous_root_hash: None,
            effective_version: None,
        },
        HeadOptions {
            effective_from: Some(51),
            valid_through: Some(60),
            ..HeadOptions::default()
        },
        UnixMillis::new(950),
    );
    let (guard_head, _) = push_and_select_plain(
        &mut line,
        &mut store,
        policy(),
        HeadOptions {
            effective_from: Some(61),
            valid_through: Some(70),
            policy_max_future_clock_skew_ms_override: Some(37),
            ..HeadOptions::default()
        },
        UnixMillis::new(950),
    );
    let guard_policy = line.current_policy_hash().unwrap();
    let current_audit = signed_clock_release(
        &line,
        ReleaseAuditFields {
            registry_version: guard_head.version,
            registry_head_hash: guard_head.object_hash,
            guard_policy_object_hash: guard_policy,
            independent_reference_hash: checkpoint.object_hash(),
            nonce: [0xd0; 32],
        },
    );
    let mut corrupt_audit = current_audit.clone();
    *corrupt_audit.last_mut().unwrap() ^= 1;
    let durable_after_task9 = store.durable_state();
    {
        let trust = reload_verified(&line, &mut store);
        let candidate = verify_registry_candidate(&trust, ChainSequence::new(65)).unwrap();
        let mut local_time =
            prepare_local_time(&mut store, &candidate, UnixMillis::new(1_050), &[]).unwrap();
        assert_eq!(
            verify_clock_release(&candidate, &mut local_time, &corrupt_audit)
                .err()
                .expect("the one-byte Clock Release signature mutation must fail")
                .code(),
            "EA-TRUST-SIGNATURE"
        );
    }
    assert!(store.durable_state() == durable_after_task9);

    let trust = reload_verified(&line, &mut store);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(65)).unwrap();
    let mut local_time =
        prepare_local_time(&mut store, &candidate, UnixMillis::new(1_050), &[]).unwrap();
    let release = verify_clock_release(&candidate, &mut local_time, &current_audit).unwrap();
    let RegistrySelectionOutcome::Selected(current_selected) =
        select_registry_head(candidate, local_time, Some(release)).unwrap()
    else {
        panic!("the exact current-Head Release must select that current Head");
    };
    assert!(current_selected.registry_head_hash() == guard_head.object_hash);
    assert_eq!(store.consumed_replays.len(), 1);

    let durable_after_current_release = store.durable_state();
    {
        let trust = reload_verified(&line, &mut store);
        let candidate = verify_registry_candidate(&trust, ChainSequence::new(65)).unwrap();
        let mut local_time =
            prepare_local_time(&mut store, &candidate, UnixMillis::new(1_050), &[]).unwrap();
        assert_eq!(
            verify_clock_release(&candidate, &mut local_time, &current_audit)
                .err()
                .expect("the exact same audit must be rejected from persistent replay state")
                .code(),
            "EA-TRUST-CLOCK-RELEASE-REPLAY"
        );
    }
    assert!(store.durable_state() == durable_after_current_release);

    let successor_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(71),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(37),
            ..HeadOptions::default()
        },
    );
    let successor_audit = signed_clock_release(
        &line,
        ReleaseAuditFields {
            registry_version: successor_head.version,
            registry_head_hash: successor_head.object_hash,
            guard_policy_object_hash: guard_policy,
            independent_reference_hash: checkpoint.object_hash(),
            nonce: [0xe1; 32],
        },
    );
    let durable_before_successor_release = store.durable_state();
    let trust = reload_verified(&line, &mut store);
    let candidate = verify_registry_candidate(&trust, successor_head.effective_from).unwrap();
    let local_time =
        prepare_local_time(&mut store, &candidate, UnixMillis::new(1_050), &[]).unwrap();
    assert_eq!(
        select_registry_head(candidate, local_time, None)
            .err()
            .expect("the independent reference must block H8 without a Release")
            .code(),
        "EA-TRUST-FUTURE-SKEW"
    );
    assert!(store.durable_state() == durable_before_successor_release);

    let expected_final_revision = store.next_revision;
    let expected_final_time = store.record.trusted_time.clone();
    let trust = reload_verified(&line, &mut store);
    let candidate = verify_registry_candidate(&trust, successor_head.effective_from).unwrap();
    let mut local_time =
        prepare_local_time(&mut store, &candidate, UnixMillis::new(1_050), &[]).unwrap();
    let release = verify_clock_release(&candidate, &mut local_time, &successor_audit).unwrap();
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, Some(release)).unwrap()
    else {
        panic!("the exact successor Release must select only its bound Head");
    };

    assert_eq!(selected.proposed_sequence(), ChainSequence::new(71));
    let resolved =
        SignerCertificateResolver::resolve(&selected, reader, RegistryVersion::new(8)).unwrap();
    assert_eq!(
        resolved.registry_effective_from_sequence,
        ChainSequence::new(71)
    );
    assert_eq!(store.independent_commits, 1);
    assert_eq!(store.selection_commits, 9);
    assert_eq!(store.replay_queries, 3);
    assert_eq!(store.consumed_replays.len(), 2);
    let final_persisted = store.load(state_key()).unwrap();
    assert!(
        final_persisted.pinned_head().copied()
            == Some(RegistryHeadPin::new(
                successor_head.version,
                successor_head.object_hash,
            ))
    );
    assert_eq!(final_persisted.revision(), expected_final_revision);
    assert!(final_persisted.trusted_time() == &expected_final_time);
    assert!(final_persisted.trusted_time().floor() == UnixMillis::new(950));
    let final_reference = final_persisted
        .trusted_time()
        .independent_reference()
        .expect("the H8 Release commit must preserve the Checkpoint reference");
    assert!(final_reference.kind() == IndependentTimeKind::Checkpoint);
    assert!(final_reference.object_hash() == checkpoint.object_hash());
    assert!(final_reference.verified_time() == UnixMillis::new(950));
    assert!(
        store.consumed_replays[0]
            == ReplayTuple {
                organization_id: support::organization(),
                target_device_id: state_key().device_id,
                nonce: [0xd0; 32],
            }
    );
    assert!(
        store.consumed_replays[1]
            == ReplayTuple {
                organization_id: support::organization(),
                target_device_id: state_key().device_id,
                nonce: [0xe1; 32],
            }
    );
}
