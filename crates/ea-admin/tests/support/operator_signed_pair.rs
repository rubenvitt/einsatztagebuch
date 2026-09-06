use super::*;
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, RegistrySelectionOutcome, StateStoreError, TrustStateKey,
    prepare_local_time, select_registry_head, verify_registry_candidate,
};

use crate::test_support::trust_support;
use trust_support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

struct SelectionStore {
    record: PersistedTrustRecord,
}
impl TrustStateStore for SelectionStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != trust_support::state_key() {
            return Err(StateStoreError::Conflict);
        }
        Ok(PersistedTrustRecord::new(
            self.record.revision(),
            self.record.trusted_time().clone(),
            self.record.pinned_head().copied(),
        ))
    }
    fn commit_independent_time(
        &mut self,
        _: TrustStateKey,
        _: u64,
        _: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
    fn clock_release_consumed(
        &mut self,
        _: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != trust_support::state_key() || revision != self.record.revision() {
            return Err(StateStoreError::Conflict);
        }
        self.record = PersistedTrustRecord::new(
            revision + 1,
            commit.next_trusted_time().clone(),
            Some(*commit.next_head()),
        );
        self.load(key)
    }
}

fn fixture() -> (RegistryLineBuilder, SelectedRegistryHead) {
    let mut line = RegistryLineBuilder::new();
    let built = line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let time = TrustedTimeState::initial(UnixMillis::new(1_000));
    let trust = line.verified_with_time(Pin::Head(0), time.clone());
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(50)).unwrap();
    let mut store = SelectionStore {
        record: PersistedTrustRecord::new(
            17,
            time,
            Some(RegistryHeadPin::new(built.version, built.object_hash)),
        ),
    };
    let local = prepare_local_time(&mut store, &candidate, UnixMillis::new(1_000), &[]).unwrap();
    let RegistrySelectionOutcome::Selected(head) =
        select_registry_head(candidate, local, None).unwrap()
    else {
        panic!("fixture head must be selected")
    };
    (line, head)
}

fn revocation_pair(
    line: &mut RegistryLineBuilder,
    target_kind: u8,
    action: u8,
) -> (Vec<u8>, Vec<u8>) {
    let built = line.add_branch(
        ActionSpec::Revoke {
            target_kind,
            object_hash: line.second_bootstrap_admin_binding_hash(),
        },
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(100),
            event_authorization_action: Some(action),
            ..HeadOptions::default()
        },
    );
    let target = line.exact_object_bytes(built.object_hash).to_vec();
    let DecodedTrustPayloadV1::RegistryEvent(event) =
        exact(&target).unwrap().decoded_payload().unwrap()
    else {
        panic!("fixture target must be a registry event")
    };
    let auth = line
        .exact_object_bytes(event.authorization_object_hash())
        .to_vec();
    (target, auth)
}

#[test]
fn signed_pair_accepts_exact_binding_revocation_at_original_issue_time() {
    let (mut line, head) = fixture();
    let (target, auth) = revocation_pair(&mut line, 1, 1);
    verify_signed_pair(
        &head,
        &target,
        &auth,
        ChainSequence::new(50),
        UnixMillis::new(100),
    )
    .unwrap();
    assert!(
        verify_signed_pair(
            &head,
            &target,
            &auth,
            ChainSequence::new(50),
            UnixMillis::new(1_101),
        )
        .is_err()
    );
}

#[test]
fn signed_pair_rejects_wrong_action_and_non_binding_revocation_shapes() {
    let (mut line, head) = fixture();
    for (target_kind, action) in [(1, 4), (1, 5), (0, 1), (2, 1)] {
        let (target, auth) = revocation_pair(&mut line, target_kind, action);
        assert!(
            verify_signed_pair(
                &head,
                &target,
                &auth,
                ChainSequence::new(50),
                UnixMillis::new(100),
            )
            .is_err(),
            "target kind {target_kind}, action {action} must be rejected"
        );
    }
}
