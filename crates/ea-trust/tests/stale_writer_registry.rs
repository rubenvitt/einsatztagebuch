#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
mod support;
use ea_trust::*;
use ea_types::*;
use support::{ActionSpec, HeadOptions, RegistryLineBuilder};

fn line(profile: u8, behavior: u8) -> RegistryLineBuilder {
    let mut line = RegistryLineBuilder::new();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions {
            not_after: UnixMillis::new(500),
            policy_operating_profile_override: Some(profile),
            policy_registry_expiry_behavior_override: Some(behavior),
            ..Default::default()
        },
    );
    line.push(
        ActionSpec::Device {
            kind: ea_format::CertificateKindV1::Writer,
            marker: 0x76,
            effective_from: None,
        },
        HeadOptions {
            not_after: UnixMillis::new(500),
            valid_through: Some(1000),
            ..Default::default()
        },
    );
    line
}
fn current_stale(
    line: &RegistryLineBuilder,
) -> (
    TrustAnchorV1,
    TrustStateKey,
    state::EphemeralTrustStateStore,
) {
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let key = state::verification_state_key(anchor.organization_id());
    let mut store = state::EphemeralTrustStateStore::new(key, UnixMillis::new(800));
    for _ in 0..=line.heads().len() + 1 {
        let trust = verify_trust(
            &anchor,
            &line.source(),
            load_trust_state(&mut store, key).unwrap(),
        )
        .unwrap();
        let candidate = verify_registry_candidate(&trust, ChainSequence::new(250)).unwrap();
        let time = prepare_local_time(&mut store, &candidate, UnixMillis::new(800), &[]).unwrap();
        match select_registry_head(candidate, time, None) {
            Err(RegistryError::Stale) => return (anchor, key, store),
            Ok(RegistrySelectionOutcome::Advanced(_)) => {}
            _ => panic!("ordinary selection must not release expired authority"),
        }
    }
    panic!("current stale pin");
}
#[test]
fn persistent_current_pin_can_supply_only_a_writer_view_at_actual_expired_time() {
    let line = line(0, 0);
    let (anchor, key, mut store) = current_stale(&line);
    let trust = verify_trust(
        &anchor,
        &line.source(),
        load_trust_state(&mut store, key).unwrap(),
    )
    .unwrap();
    let expected = *trust.pinned_head().unwrap();
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(250)).unwrap();
    let time = prepare_local_time(&mut store, &candidate, UnixMillis::new(900), &[]).unwrap();
    let stale = select_stale_writer_registry_head(candidate, time)
        .expect("signed Standard/warn enables the separate Writer context");
    let view = stale.as_writer();
    assert_eq!(
        view.registry_head_hash().as_bytes(),
        expected.registry_head_hash().as_bytes()
    );
    assert_eq!(view.preexisting_effective_now().value().get(), 900);
    assert_eq!(view.not_after().get(), 500);
    assert!(view.current_writer_certificate_hash().is_some());
}
#[test]
fn evidence_grade_and_signed_block_do_not_get_a_stale_writer_exception() {
    for (profile, behavior) in [(1, 0), (0, 1)] {
        let line = line(profile, behavior);
        let (anchor, key, mut store) = current_stale(&line);
        let trust = verify_trust(
            &anchor,
            &line.source(),
            load_trust_state(&mut store, key).unwrap(),
        )
        .unwrap();
        let candidate = verify_registry_candidate(&trust, ChainSequence::new(250)).unwrap();
        let time = prepare_local_time(&mut store, &candidate, UnixMillis::new(900), &[]).unwrap();
        assert!(select_stale_writer_registry_head(candidate, time).is_err());
    }
}

#[test]
fn stale_exception_cannot_skip_catch_up_or_an_expired_sequence_lease() {
    let line = line(0, 0);
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let key = state::verification_state_key(anchor.organization_id());
    let mut store = state::EphemeralTrustStateStore::new(key, UnixMillis::new(800));
    let trust = verify_trust(
        &anchor,
        &line.source(),
        load_trust_state(&mut store, key).unwrap(),
    )
    .unwrap();
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(250)).unwrap();
    let time = prepare_local_time(&mut store, &candidate, UnixMillis::new(900), &[]).unwrap();
    assert!(select_stale_writer_registry_head(candidate, time).is_err());
    assert!(
        load_trust_state(&mut store, key)
            .unwrap()
            .pinned_head()
            .is_none()
    );

    let (anchor, key, mut store) = current_stale(&line);
    let trust = verify_trust(
        &anchor,
        &line.source(),
        load_trust_state(&mut store, key).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        verify_registry_candidate(&trust, ChainSequence::new(1001)),
        Err(RegistryError::SequenceLease)
    ));
}

#[test]
fn a_known_successor_has_priority_and_fallback_stops_at_its_ready_boundary() {
    for now in [949, 950] {
        let mut line = line(0, 0);
        let (anchor, key, mut store) = current_stale(&line);
        line.push(
            ActionSpec::Device {
                kind: ea_format::CertificateKindV1::Reader,
                marker: 0x77,
                effective_from: Some(250),
            },
            HeadOptions {
                effective_from: Some(250),
                valid_through: Some(1000),
                issued_at: UnixMillis::new(950),
                not_before: UnixMillis::new(950),
                not_after: UnixMillis::new(1500),
                ..Default::default()
            },
        );
        let trust = verify_trust(
            &anchor,
            &line.source(),
            load_trust_state(&mut store, key).unwrap(),
        )
        .unwrap();
        let candidate = verify_registry_candidate(&trust, ChainSequence::new(250)).unwrap();
        let time = prepare_local_time(&mut store, &candidate, UnixMillis::new(900), &[]).unwrap();
        let RegistrySelectionOutcome::PendingFuture(pending) =
            select_registry_head(candidate, time, None).unwrap()
        else {
            panic!("future successor");
        };
        let trust = verify_trust(
            &anchor,
            &line.source(),
            load_trust_state(&mut store, key).unwrap(),
        )
        .unwrap();
        let candidate = verify_current_head_fallback(&trust, pending).unwrap();
        let time = prepare_local_time(&mut store, &candidate, UnixMillis::new(now), &[]).unwrap();
        let result = select_stale_writer_registry_head(candidate, time);
        if now == 949 {
            let stale = result.expect("fallback is still pending");
            assert_eq!(
                stale
                    .as_writer()
                    .preexisting_effective_now()
                    .successor_ready_at()
                    .unwrap()
                    .get(),
                950
            );
        } else {
            assert!(
                result.is_err(),
                "old Writer context must not cross the exact successor boundary"
            );
        }
    }
}

struct RejectSelection(state::EphemeralTrustStateStore);
impl TrustStateStore for RejectSelection {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        self.0.load(key)
    }
    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.0.commit_independent_time(key, revision, commit)
    }
    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.0.clock_release_consumed(key)
    }
    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Conflict)
    }
}
#[test]
fn failed_persistent_affirmation_cannot_release_a_stale_writer_context() {
    let line = line(0, 0);
    let (anchor, key, store) = current_stale(&line);
    let mut store = RejectSelection(store);
    let trust = verify_trust(
        &anchor,
        &line.source(),
        load_trust_state(&mut store, key).unwrap(),
    )
    .unwrap();
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(250)).unwrap();
    let time = prepare_local_time(&mut store, &candidate, UnixMillis::new(900), &[]).unwrap();
    assert!(matches!(
        select_stale_writer_registry_head(candidate, time),
        Err(RegistryError::Trust(TrustError::StateConflict))
    ));
}
