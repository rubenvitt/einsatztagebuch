use std::sync::Arc;

use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, SecretBytes};
use ea_format::{
    CertificateKindV1, OperatorRoleV1, Parsed, ParsedArchiveObject, ReceiptCoreFieldsV1,
    ReceiptCoreV1, ReceiptV1, decode_exact_object, encode_receipt,
};
use ea_time::{
    FutureSkew, IndependentTimeInput, IndependentTimeKind, TimeWarnings, TrustedTimeState,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, RegistryVersion,
    UnixMillis,
};
use ed25519_dalek::SigningKey;

use super::{
    AdvancedRegistryHead, CommittedCatchUpProof, PendingFutureSuccessor, PendingSuccessorProof,
    RegistryCandidate, RegistrySelectionOutcome, SelectedHeadInner, SelectedRegistryHead,
    select_registry_head, verify_registry_candidate,
};
use crate::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, StateStoreError, TrustStateKey, TrustStateStore, prepare_local_time,
    verify_receipt_time,
};

#[allow(clippy::duplicate_mod)]
#[path = "../../tests/support/mod.rs"]
mod support;

use support::{ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder};

const INITIAL_REVISION: u64 = 17;
const SERVER_SECRET: [u8; 32] = [
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
];

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
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

fn receipt_source(
    candidate: &RegistryCandidate,
    authority_head: BuiltHead,
    authority_policy_hash: ObjectHash,
    server_certificate_hash: CertificateHash,
    verified_time: UnixMillis,
) -> (crate::VerifiedSignedTime, ObjectHash) {
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
        _ => panic!("the private Pending fixture must retain an exact Receipt"),
    };
    let object_hash = receipt.object_hash();
    let proof = verify_receipt_time(
        candidate
            .preexisting_authority()
            .expect("the direct successor must retain its exact time authority"),
        &receipt,
    )
    .unwrap();
    (proof, object_hash)
}

struct ObservedCommit {
    key: TrustStateKey,
    expected_revision: u64,
    next_trusted_time: TrustedTimeState,
    next_head: RegistryHeadPin,
    had_replay_key: bool,
}

struct TestStore {
    key: TrustStateKey,
    record: PersistedTrustRecord,
    next_revision: u64,
    independent_next_revision: Option<u64>,
    independent_commits: usize,
    commits: Vec<ObservedCommit>,
}

impl TestStore {
    fn new(
        key: TrustStateKey,
        trusted_time: TrustedTimeState,
        pinned_head: Option<RegistryHeadPin>,
        next_revision: u64,
    ) -> Self {
        Self {
            key,
            record: PersistedTrustRecord::new(INITIAL_REVISION, trusted_time, pinned_head),
            next_revision,
            independent_next_revision: None,
            independent_commits: 0,
            commits: Vec::new(),
        }
    }

    fn set_independent_next_revision(&mut self, revision: u64) {
        self.independent_next_revision = Some(revision);
    }

    fn record_copy(&self) -> PersistedTrustRecord {
        PersistedTrustRecord::new(
            self.record.revision(),
            self.record.trusted_time().clone(),
            self.record.pinned_head().copied(),
        )
    }
}

impl TrustStateStore for TestStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(self.record_copy())
    }

    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.independent_commits += 1;
        if key != self.key || expected_revision != self.record.revision() {
            return Err(StateStoreError::Conflict);
        }
        let revision = self
            .independent_next_revision
            .take()
            .ok_or(StateStoreError::Unavailable)?;
        self.record = PersistedTrustRecord::new(
            revision,
            commit.next_trusted_time().clone(),
            self.record.pinned_head().copied(),
        );
        Ok(self.record_copy())
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Ok(false)
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.commits.push(ObservedCommit {
            key,
            expected_revision,
            next_trusted_time: commit.next_trusted_time().clone(),
            next_head: *commit.next_head(),
            had_replay_key: commit.replay_key().is_some(),
        });
        if key != self.key || expected_revision != self.record.revision() {
            return Err(StateStoreError::Conflict);
        }
        self.record = PersistedTrustRecord::new(
            self.next_revision,
            commit.next_trusted_time().clone(),
            Some(*commit.next_head()),
        );
        Ok(self.record_copy())
    }
}

struct DirectFixture {
    candidate: RegistryCandidate,
    previous_head: BuiltHead,
    candidate_head: BuiltHead,
    key: TrustStateKey,
    trusted_time: TrustedTimeState,
}

#[allow(clippy::too_many_arguments)]
fn direct_fixture(
    issued_at: i64,
    not_before: i64,
    not_after: i64,
    valid_through: u64,
    proposed_sequence: u64,
    floor: i64,
    reference_time: i64,
    marker: u8,
) -> DirectFixture {
    let mut line = RegistryLineBuilder::new();
    let previous_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            policy_max_future_clock_skew_ms_override: Some(300),
            ..HeadOptions::default()
        },
    );
    let candidate_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(valid_through),
            issued_at: UnixMillis::new(issued_at),
            not_before: UnixMillis::new(not_before),
            not_after: UnixMillis::new(not_after),
            policy_max_future_clock_skew_ms_override: Some(9_999),
            ..HeadOptions::default()
        },
    );
    let key = support::state_key();
    let trusted_time = persisted_time(floor, reference_time, marker);
    let trust =
        line.verified_with_record(Pin::Head(0), INITIAL_REVISION, trusted_time.clone(), key);
    let candidate =
        verify_registry_candidate(&trust, ChainSequence::new(proposed_sequence)).unwrap();
    DirectFixture {
        candidate,
        previous_head,
        candidate_head,
        key,
        trusted_time,
    }
}

fn assert_selected_type_contract(_: &SelectedRegistryHead) {}
fn assert_pending_type_contract(_: &PendingFutureSuccessor) {}
fn assert_advanced_type_contract(_: &AdvancedRegistryHead) {}

#[test]
fn real_selected_path_retains_only_the_exact_authority_and_committed_view() {
    let fixture = direct_fixture(850, 800, 2_000, 200, 60, 700, 650, 0x91);
    let expected_candidate_state = Arc::clone(&fixture.candidate.candidate_state);
    let expected_policy = fixture.candidate.target_policy.clone();
    let expected_event = fixture.candidate.head_event.clone();
    let mut store = TestStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
        41,
    );
    let local_time =
        prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(900), &[]).unwrap();
    let expected_now = local_time.evaluation.raw_now();
    let expected_warnings = *local_time.evaluation.warnings();

    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("the private Selected contract requires the real selection path");
    };
    assert_selected_type_contract(&selected);

    let SelectedHeadInner {
        candidate_state,
        chain_id: selected_chain_id,
        registry_version,
        registry_head_hash,
        policy,
        effective_from_sequence,
        valid_through_sequence,
        proposed_sequence,
        head_event_not_after,
        head_event_issued_at,
        preexisting_effective_now,
        warnings,
        committed_revision,
    } = selected.inner.as_ref();
    assert!(Arc::ptr_eq(candidate_state, &expected_candidate_state));
    // Die Kettenkennung DES ANKERS, unveraendert durchgereicht. Sie ist die
    // einzige Autoritaet fuer die Frage „in welche Kette schreibe ich hier":
    // ein Verbraucher auf einem LEEREN Bestand hat keinen Knoten, an dem eine
    // fremde Kennung auffiele.
    assert!(*selected_chain_id == chain_id());
    assert!(*registry_version == fixture.candidate_head.version);
    assert!(*registry_head_hash == fixture.candidate_head.object_hash);
    assert!(policy.object_hash == expected_policy.object_hash);
    assert!(policy.fields == expected_policy.fields);
    assert!(*effective_from_sequence == expected_event.effective_from_sequence);
    assert!(*valid_through_sequence == expected_event.valid_through_sequence);
    assert!(*proposed_sequence == ChainSequence::new(60));
    // Das `notAfter` des Head-Ereignisses, UNVERAENDERT durchgereicht. Der
    // Wert ist die Zeitgrenze, gegen die eine spaetere Veralterung festgestellt
    // wird; kaeme er aus einer anderen Quelle als dem gewaehlten Ereignis,
    // waere jede solche Feststellung ueber den falschen Head.
    assert!(*head_event_not_after == expected_event.not_after);
    // Und `issuedAt` DESSELBEN Ereignisses, ebenso unveraendert durchgereicht.
    // Es ist der Bezugspunkt des Vertrauensalters; kaeme es aus einer anderen
    // Quelle als dem gewaehlten Ereignis, waere jede Altersangabe ueber den
    // falschen Head.
    assert!(*head_event_issued_at == expected_event.issued_at);
    assert!(preexisting_effective_now.value() == expected_now);
    assert!(*warnings == expected_warnings);
    assert_eq!(*committed_revision, 41);

    assert_eq!(store.commits.len(), 1);
    let commit = &store.commits[0];
    assert!(commit.key == fixture.key);
    assert_eq!(commit.expected_revision, INITIAL_REVISION);
    assert!(commit.next_head == pin(fixture.candidate_head));
    assert_eq!(commit.next_trusted_time.floor(), UnixMillis::new(850));
    assert!(
        commit.next_trusted_time.independent_reference()
            == fixture.trusted_time.independent_reference()
    );
    assert!(!commit.had_replay_key);
    assert_eq!(store.record.revision(), 41);
    assert!(store.record.trusted_time() == &commit.next_trusted_time);
    assert!(store.record.pinned_head() == Some(&pin(fixture.candidate_head)));
}

#[test]
fn real_pending_path_owns_the_post_time_snapshot_and_exact_direct_barrier() {
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
            policy_max_future_clock_skew_ms_override: Some(300),
            ..HeadOptions::default()
        },
    );
    let previous_policy_hash = line.current_policy_hash().unwrap();
    let candidate_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(200),
            issued_at: UnixMillis::new(1_400),
            not_before: UnixMillis::new(1_300),
            not_after: UnixMillis::new(2_000),
            policy_max_future_clock_skew_ms_override: Some(9_999),
            ..HeadOptions::default()
        },
    );
    let key = support::state_key();
    let candidate_time = persisted_time(900, 850, 0x92);
    let trust =
        line.verified_with_record(Pin::Head(2), INITIAL_REVISION, candidate_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(60)).unwrap();
    let (source, receipt_hash) = receipt_source(
        &candidate,
        previous_head,
        previous_policy_hash,
        CertificateHash::from(server_head.direct_object_hash.unwrap()),
        UnixMillis::new(950),
    );
    let expected_candidate_state = Arc::clone(&candidate.candidate_state);
    let expected_preexisting_state = Arc::clone(
        &candidate
            .preexisting_authority()
            .expect("the pending successor must retain its exact predecessor")
            .inner,
    );
    let expected_event = candidate.head_event.clone();
    let expected_guard_hash = candidate.guard_policy.object_hash;
    let candidate_revision = candidate.state_revision;
    let candidate_time = candidate.trusted_time.clone();
    let mut store = TestStore::new(key, candidate_time.clone(), Some(pin(previous_head)), 97);
    store.set_independent_next_revision(43);
    let local_time = prepare_local_time(
        &mut store,
        &candidate,
        UnixMillis::new(950),
        core::slice::from_ref(&source),
    )
    .unwrap();
    let expected_revision = local_time.expected_revision;
    let expected_time = local_time.trusted_time.clone();
    let expected_pin = local_time.pinned_head;
    let expected_os = local_time.observed_os_wall_clock;
    let expected_raw_now = local_time.evaluation.raw_now();
    let expected_warnings = *local_time.evaluation.warnings();
    let expected_skew = local_time.evaluation.future_skew();
    assert_eq!(candidate_revision, INITIAL_REVISION);
    assert_eq!(expected_revision, 43);
    assert!(expected_time != candidate_time);
    let reference = expected_time
        .independent_reference()
        .expect("the post-Task9 Pending snapshot must retain the real Receipt");
    assert!(reference.object_hash() == receipt_hash);
    assert_eq!(reference.verified_time(), UnixMillis::new(950));

    let RegistrySelectionOutcome::PendingFuture(pending) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the private Pending contract requires the real future path");
    };
    assert_pending_type_contract(&pending);

    let PendingSuccessorProof {
        candidate_state,
        preexisting_state,
        state_key,
        expected_revision: retained_revision,
        trusted_time,
        pinned_head,
        observed_os_wall_clock,
        candidate_registry_version,
        candidate_registry_head_hash,
        guard_policy_object_hash,
        proposed_sequence,
        pre_transition_sequence,
        raw_now,
        warnings,
        future_skew,
        successor_event,
    } = pending.inner.as_ref();
    assert!(Arc::ptr_eq(candidate_state, &expected_candidate_state));
    assert!(Arc::ptr_eq(preexisting_state, &expected_preexisting_state));
    assert!(*state_key == key);
    assert_eq!(*retained_revision, expected_revision);
    assert!(trusted_time == &expected_time);
    assert!(*pinned_head == expected_pin);
    assert!(*observed_os_wall_clock == expected_os);
    assert!(*candidate_registry_version == candidate_head.version);
    assert!(*candidate_registry_head_hash == candidate_head.object_hash);
    assert!(*guard_policy_object_hash == expected_guard_hash);
    assert!(*proposed_sequence == ChainSequence::new(60));
    assert!(*pre_transition_sequence == ChainSequence::new(50));
    assert!(*raw_now == expected_raw_now);
    assert!(*warnings == expected_warnings);
    assert!(*future_skew == expected_skew);
    assert!(*future_skew == FutureSkew::WithinLimit);
    assert!(successor_event == &expected_event);
    assert!(successor_event.registry_version == candidate_head.version);
    assert!(successor_event.previous_registry_hash == expected_event.previous_registry_hash);
    assert_eq!(store.commits.len(), 0);
    assert_eq!(store.independent_commits, 1);
    assert_eq!(store.record.revision(), 43);
    assert!(store.record.trusted_time() == &expected_time);
    assert!(store.record.pinned_head() == Some(&pin(previous_head)));
}

#[test]
fn real_advanced_path_is_exhaustively_scalar_only_and_committed() {
    let fixture = direct_fixture(850, 800, 875, 200, 60, 700, 650, 0x93);
    let mut store = TestStore::new(
        fixture.key,
        fixture.trusted_time.clone(),
        Some(pin(fixture.previous_head)),
        47,
    );
    let local_time =
        prepare_local_time(&mut store, &fixture.candidate, UnixMillis::new(900), &[]).unwrap();

    let RegistrySelectionOutcome::Advanced(advanced) =
        select_registry_head(fixture.candidate, local_time, None).unwrap()
    else {
        panic!("the private Advanced contract requires the real stale catch-up path");
    };
    assert_advanced_type_contract(&advanced);

    let CommittedCatchUpProof {
        registry_version,
        registry_head_hash,
        committed_revision,
    } = &advanced.inner;
    assert!(*registry_version == fixture.candidate_head.version);
    assert!(*registry_head_hash == fixture.candidate_head.object_hash);
    assert_eq!(*committed_revision, 47);
    assert_eq!(store.commits.len(), 1);
    assert!(store.commits[0].next_head == pin(fixture.candidate_head));
    assert_eq!(store.record.revision(), 47);
}

#[test]
fn selected_binding_view_rechecks_private_role_correlation() {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(10),
            ..HeadOptions::default()
        },
    );
    let reader_head = line.push(
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
    );
    let reader_hash = CertificateHash::from(
        reader_head
            .direct_object_hash
            .expect("Reader certificate object"),
    );
    let binding_head = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: reader_head.direct_object_hash.unwrap(),
            role: OperatorRoleV1::Reader,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(21),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    let binding_hash = binding_head
        .direct_object_hash
        .expect("Reader Binding object");
    let key = support::state_key();
    let trusted_time = persisted_time(900, 850, 0xa1);
    let trust =
        line.verified_with_record(Pin::Head(2), INITIAL_REVISION, trusted_time.clone(), key);
    let mut candidate = verify_registry_candidate(&trust, ChainSequence::new(25)).unwrap();
    let mut malformed = (*candidate.candidate_state).clone();
    malformed
        .admin_bindings
        .get_mut(&binding_hash)
        .expect("the selected state must retain the active Reader Binding")
        .fields
        .operator_role = OperatorRoleV1::Writer;
    let malformed = Arc::new(malformed);
    candidate.candidate_state = Arc::clone(&malformed);
    candidate
        .preexisting_authority
        .as_mut()
        .expect("a current Head must retain its exact authority")
        .inner = Arc::clone(&malformed);
    let mut store = TestStore::new(key, trusted_time, Some(pin(binding_head)), 53);
    let local_time = prepare_local_time(&mut store, &candidate, UnixMillis::new(900), &[]).unwrap();
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the private role-correlation fixture must select its current Head");
    };

    assert!(selected.active_certificate_fields(reader_hash).is_some());
    assert!(
        selected
            .active_operator_binding_fields(binding_hash)
            .is_none()
    );
}

#[test]
fn consuming_proof_types_are_owned_and_not_zero_sized() {
    assert!(core::mem::needs_drop::<SelectedRegistryHead>());
    assert!(core::mem::needs_drop::<PendingFutureSuccessor>());
    assert!(!core::mem::needs_drop::<AdvancedRegistryHead>());
    assert!(core::mem::size_of::<SelectedRegistryHead>() > 0);
    assert!(core::mem::size_of::<PendingFutureSuccessor>() > 0);
    assert!(core::mem::size_of::<AdvancedRegistryHead>() > 0);
    assert!(core::mem::size_of::<RegistryVersion>() > 0);
    assert!(core::mem::size_of::<TimeWarnings>() > 0);
}

// When this body is wired by the first production skeleton, public rustdoc
// must additionally contain real `compile_fail` examples whose failures hinge
// on private-field construction for Pending and Advanced, and on both types
// lacking `Clone`. Selected remains getter-only; no proof exposes raw authority
// fields or a public constructor.
