use ea_destruction::transition_allowed;
#[test]
fn exactly_eight_normative_edges_and_no_cancel_are_accepted() {
    let edges = [
        (None, 0),
        (Some(0), 1),
        (Some(1), 2),
        (Some(1), 3),
        (Some(1), 4),
        (Some(2), 3),
        (Some(2), 4),
        (Some(4), 1),
    ];
    for from in [None, Some(0), Some(1), Some(2), Some(3), Some(4), Some(5)] {
        for to in 0..=5 {
            assert_eq!(
                transition_allowed(from, to),
                edges.contains(&(from, to)),
                "{from:?}->{to}"
            );
        }
    }
}

mod support;
use ea_destruction::{
    ApplyOutcome, DestructionState, DestructionStateMachine, verify_authorization, verify_event,
};
#[test]
fn signed_events_advance_only_their_predecessor_and_exact_replay_is_idempotent() {
    let f = support::Fixture::new(true, true, false);
    let bytes = f.authorization();
    let head = f.head();
    let auth = verify_authorization(&bytes, &head).unwrap();
    let fields = support::event_fields(&f, &bytes, 1, None, 0, None);
    let exact = support::event(&f, &bytes, fields.clone());
    let first = verify_event(&exact, &auth, &head).unwrap();
    let mut machine = DestructionStateMachine::new(&auth);
    assert_eq!(machine.apply(&first).unwrap(), ApplyOutcome::Advanced);
    assert_eq!(machine.state(), Some(DestructionState::Requested));
    assert_eq!(machine.apply(&first).unwrap(), ApplyOutcome::Replay);
    let mut conflict = fields;
    conflict.executed_at = ea_types::UnixMillis::new(999);
    let conflict = verify_event(&support::event(&f, &bytes, conflict), &auth, &head).unwrap();
    assert_eq!(
        machine.apply(&conflict).unwrap_err().code(),
        "EA-DESTRUCTION-SECURITY-CONFLICT"
    );
    let second = support::event_fields(&f, &bytes, 2, Some(0), 1, Some(first.object_hash()));
    let second = verify_event(&support::event(&f, &bytes, second), &auth, &head).unwrap();
    assert_eq!(machine.apply(&second).unwrap(), ApplyOutcome::Advanced);
    assert_eq!(machine.state(), Some(DestructionState::InProgress));
    assert_eq!(machine.apply(&first).unwrap(), ApplyOutcome::Replay);
}
#[test]
fn wrong_trigger_future_execution_signature_and_fork_are_rejected() {
    let f = support::Fixture::new(true, true, false);
    let bytes = f.authorization();
    let head = f.head();
    let auth = verify_authorization(&bytes, &head).unwrap();
    for kind in 0..3 {
        let mut fields = support::event_fields(&f, &bytes, 1, None, 0, None);
        if kind == 0 {
            fields.trigger_code = 99;
        }
        if kind == 1 {
            fields.executed_at = ea_types::UnixMillis::new(1001);
        }
        let mut exact = support::event(&f, &bytes, fields);
        if kind == 2 {
            let last = exact.len() - 1;
            exact[last] ^= 1;
        }
        assert!(verify_event(&exact, &auth, &head).is_err());
    }
    let first = verify_event(
        &support::event(
            &f,
            &bytes,
            support::event_fields(&f, &bytes, 1, None, 0, None),
        ),
        &auth,
        &head,
    )
    .unwrap();
    let mut machine = DestructionStateMachine::new(&auth);
    machine.apply(&first).unwrap();
    let fork = verify_event(
        &support::event(
            &f,
            &bytes,
            support::event_fields(&f, &bytes, 2, None, 0, None),
        ),
        &auth,
        &head,
    )
    .unwrap();
    assert!(machine.apply(&fork).is_err());
}

#[test]
fn every_valid_signed_history_path_reduces_and_backward_time_or_foreign_authorization_does_not() {
    for states in [
        vec![0],
        vec![0, 1],
        vec![0, 1, 2],
        vec![0, 1, 3],
        vec![0, 1, 4],
        vec![0, 1, 2, 3],
        vec![0, 1, 2, 4],
        vec![0, 1, 4, 1],
    ] {
        let f = support::Fixture::new(true, true, false);
        let bytes = f.authorization();
        let head = f.head();
        let auth = verify_authorization(&bytes, &head).unwrap();
        let mut machine = DestructionStateMachine::new(&auth);
        let mut previous = None;
        let mut from = None;
        for (i, to) in states.iter().enumerate() {
            let exact = support::event(
                &f,
                &bytes,
                support::event_fields(
                    &f,
                    &bytes,
                    u8::try_from(i + 1).unwrap(),
                    from,
                    *to,
                    previous,
                ),
            );
            let event = verify_event(&exact, &auth, &head).unwrap();
            machine.apply(&event).unwrap();
            previous = Some(event.object_hash());
            from = Some(*to);
        }
        assert_eq!(
            machine.state().map(DestructionState::code),
            states.last().copied()
        );
    }
    let f = support::Fixture::new(true, true, false);
    let bytes = f.authorization();
    let head = f.head();
    let auth = verify_authorization(&bytes, &head).unwrap();
    let first = verify_event(
        &support::event(
            &f,
            &bytes,
            support::event_fields(&f, &bytes, 1, None, 0, None),
        ),
        &auth,
        &head,
    )
    .unwrap();
    let mut machine = DestructionStateMachine::new(&auth);
    machine.apply(&first).unwrap();
    let mut backwards = support::event_fields(&f, &bytes, 2, Some(0), 1, Some(first.object_hash()));
    backwards.executed_at = ea_types::UnixMillis::new(999);
    let backwards = verify_event(&support::event(&f, &bytes, backwards), &auth, &head).unwrap();
    assert!(machine.apply(&backwards).is_err());
    assert_eq!(machine.state(), Some(DestructionState::Requested));
    let mut other_fields = f.fields();
    other_fields.legal_reason_code = 1;
    let other_bytes = f.sign(other_fields, f.approvers.to_vec());
    let other_auth = verify_authorization(&other_bytes, &head).unwrap();
    let other = verify_event(
        &support::event(
            &f,
            &other_bytes,
            support::event_fields(&f, &other_bytes, 1, None, 0, None),
        ),
        &other_auth,
        &head,
    )
    .unwrap();
    assert_eq!(
        machine.apply(&other).unwrap_err().code(),
        "EA-DESTRUCTION-SECURITY-CONFLICT"
    );
}

#[test]
fn immutable_authorization_and_event_survive_lease_expiry_without_current_authority() {
    let fixture = support::Fixture::new(true, true, false);
    let exact_auth = fixture.authorization();
    let exact_event = support::event(
        &fixture,
        &exact_auth,
        support::event_fields(&fixture, &exact_auth, 0x44, None, 0, None),
    );
    let original = fixture.head();
    let late = ea_types::UnixMillis::new(20_000_000);
    assert!(support::try_selected(&fixture.line, late.get()).is_err());
    let trust = fixture.line.verified_with_floor(
        support::trust::Pin::Exact(original.registry_version(), original.registry_head_hash()),
        late,
    );
    let history = ea_trust::verify_historical_registry_authority(
        &trust,
        original.registry_version(),
        original.registry_head_hash(),
        original.proposed_sequence(),
    )
    .unwrap();
    let auth = ea_destruction::verify_authorization_historical(&exact_auth, &history).unwrap();
    let event =
        ea_destruction::verify_event_historical(&exact_event, &auth, &history, late).unwrap();
    let mut reducer = ea_destruction::DestructionStateMachine::new(&auth);
    reducer.apply(&event).unwrap();
    assert_eq!(
        reducer.state(),
        Some(ea_destruction::DestructionState::Requested)
    );
    let mut changed = exact_event;
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(ea_destruction::verify_event_historical(&changed, &auth, &history, late).is_err());
    assert!(
        ea_destruction::verify_event_historical(
            event.exact_bytes(),
            &auth,
            &history,
            ea_types::UnixMillis::new(999)
        )
        .is_err()
    );
}

/// Web-Reader-Design §3: the reader signs no state transition. Its own
/// `deletionAttest` certificate (for its cache attestation) sits on a Reader
/// device, and a transition signed under it is refused locally, current and
/// historical, while the same fields under the desktop component pass.
#[test]
fn a_transition_signed_by_a_reader_deletion_attest_key_is_refused_locally() {
    refuses_reader_device_transitions(false);
}

/// Revocation cannot turn a Reader device into a transition signer.
#[test]
fn a_revoked_reader_certificate_still_marks_its_device_as_a_reader() {
    refuses_reader_device_transitions(true);
}

fn refuses_reader_device_transitions(reader_revoked: bool) {
    let mut f = support::Fixture::new(true, true, false);
    let reader_deletion = support::with_reader_deletion_attest(&mut f, reader_revoked);
    let bytes = f.authorization();
    let head = f.head();
    let auth = verify_authorization(&bytes, &head).unwrap();
    let reader_device = ea_types::DeviceId::try_from(&[0xa5; 16][..]).unwrap();
    assert_eq!(
        head.known_certificate_fields()
            .any(|(hash, cert)| cert.device_id == reader_device
                && cert.certificate_kind == ea_format::CertificateKindV1::Reader
                && head.active_certificate_fields(hash).is_none()),
        reader_revoked,
        "fixture: Reader certificate revoked at the authorization head",
    );
    let history = {
        let trust = f.line.verified_with_floor(
            support::trust::Pin::Exact(head.registry_version(), head.registry_head_hash()),
            ea_types::UnixMillis::new(support::NOW),
        );
        ea_trust::verify_historical_registry_authority(
            &trust,
            head.registry_version(),
            head.registry_head_hash(),
            head.proposed_sequence(),
        )
        .unwrap()
    };
    let historical_auth =
        ea_destruction::verify_authorization_historical(&bytes, &history).unwrap();
    let observed = ea_types::UnixMillis::new(support::NOW);

    // Positive control: the desktop component on the Writer-side device.
    let request = support::event_fields(&f, &bytes, 1, None, 0, None);
    let accepted = verify_event(
        &support::event_signed_by(&bytes, request.clone(), f.deletion),
        &auth,
        &head,
    )
    .unwrap();
    ea_destruction::verify_event_historical(
        accepted.exact_bytes(),
        &historical_auth,
        &history,
        observed,
    )
    .unwrap();

    let start = support::event_fields(&f, &bytes, 2, Some(0), 1, Some(accepted.object_hash()));
    for fields in [request, start] {
        let exact = support::event_signed_by(&bytes, fields, reader_deletion);
        let current = verify_event(&exact, &auth, &head).err().map(|e| e.code());
        let historical =
            ea_destruction::verify_event_historical(&exact, &historical_auth, &history, observed)
                .err()
                .map(|e| e.code());
        assert_eq!(
            (current, historical),
            (
                Some("EA-DESTRUCTION-SIGNATURE"),
                Some("EA-DESTRUCTION-SIGNATURE")
            ),
        );
    }
}
