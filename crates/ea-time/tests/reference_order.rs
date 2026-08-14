use ea_time::{
    IndependentTimeInput, IndependentTimeKind, IndependentTimeReference, TimeError,
    TrustedTimeState, advance_registry_floor, merge_independent_references,
};
use ea_types::{ObjectHash, UnixMillis};

fn object_hash(byte: u8) -> ObjectHash {
    ObjectHash::try_from(&[byte; 32][..]).unwrap()
}

fn input(kind: IndependentTimeKind, hash_byte: u8, time: i64) -> IndependentTimeInput {
    IndependentTimeInput::new(kind, object_hash(hash_byte), UnixMillis::new(time))
}

fn persisted(
    floor: i64,
    reference: Option<IndependentTimeInput>,
) -> Result<TrustedTimeState, TimeError> {
    TrustedTimeState::from_persisted(UnixMillis::new(floor), reference)
}

fn reference(state: &TrustedTimeState) -> &IndependentTimeReference {
    state
        .independent_reference()
        .expect("test state must contain an independent reference")
}

#[test]
fn largest_verified_time_wins() {
    let state = TrustedTimeState::initial(UnixMillis::new(10));
    let advance = merge_independent_references(
        &state,
        &[
            input(IndependentTimeKind::Receipt, 9, 59),
            input(IndependentTimeKind::Tsa, 1, 60),
            input(IndependentTimeKind::Checkpoint, 2, 58),
        ],
    )
    .unwrap();

    assert!(advance.changed());
    let selected = reference(advance.state());
    assert_eq!(selected.kind(), IndependentTimeKind::Tsa);
    assert_eq!(selected.verified_time(), UnixMillis::new(60));
    assert_eq!(selected.object_hash().as_bytes(), &[1; 32]);
}

#[test]
fn equal_time_prefers_the_smaller_kind_tag() {
    let state = persisted(100, Some(input(IndependentTimeKind::Tsa, 0, 100))).unwrap();
    let advance = merge_independent_references(
        &state,
        &[
            input(IndependentTimeKind::Checkpoint, 1, 100),
            input(IndependentTimeKind::Receipt, u8::MAX, 100),
        ],
    )
    .unwrap();

    assert!(advance.changed());
    let selected = reference(advance.state());
    assert_eq!(selected.kind(), IndependentTimeKind::Receipt);
    assert_eq!(selected.object_hash().as_bytes(), &[u8::MAX; 32]);
}

#[test]
fn equal_time_and_kind_prefer_the_bytewise_smaller_object_hash() {
    let state = persisted(100, Some(input(IndependentTimeKind::Checkpoint, 9, 100))).unwrap();
    let advance =
        merge_independent_references(&state, &[input(IndependentTimeKind::Checkpoint, 3, 100)])
            .unwrap();

    assert!(advance.changed());
    assert_eq!(
        reference(advance.state()).object_hash().as_bytes(),
        &[3; 32]
    );
}

#[test]
fn exact_duplicate_reference_is_a_no_op() {
    let state = persisted(100, Some(input(IndependentTimeKind::Checkpoint, 3, 100))).unwrap();
    let advance =
        merge_independent_references(&state, &[input(IndependentTimeKind::Checkpoint, 3, 100)])
            .unwrap();

    assert!(!advance.changed());
    assert_eq!(advance.state().floor(), UnixMillis::new(100));
    assert_eq!(
        reference(advance.state()).object_hash().as_bytes(),
        &[3; 32]
    );
}

#[test]
fn selection_is_independent_of_input_order() {
    let state = TrustedTimeState::initial(UnixMillis::new(0));
    let forward = merge_independent_references(
        &state,
        &[
            input(IndependentTimeKind::Checkpoint, 8, 200),
            input(IndependentTimeKind::Receipt, 9, 200),
            input(IndependentTimeKind::Receipt, 2, 200),
        ],
    )
    .unwrap();
    let reverse = merge_independent_references(
        &state,
        &[
            input(IndependentTimeKind::Receipt, 2, 200),
            input(IndependentTimeKind::Receipt, 9, 200),
            input(IndependentTimeKind::Checkpoint, 8, 200),
        ],
    )
    .unwrap();

    let forward_reference = reference(forward.state());
    let reverse_reference = reference(reverse.state());
    assert_eq!(forward_reference.kind(), reverse_reference.kind());
    assert_eq!(
        forward_reference.verified_time(),
        reverse_reference.verified_time()
    );
    assert_eq!(
        forward_reference.object_hash().as_bytes(),
        reverse_reference.object_hash().as_bytes()
    );
}

#[test]
fn persisted_newer_reference_is_retained() {
    let state = persisted(100, Some(input(IndependentTimeKind::Receipt, 4, 100))).unwrap();
    let advance = merge_independent_references(
        &state,
        &[
            input(IndependentTimeKind::Tsa, 1, 99),
            input(IndependentTimeKind::Checkpoint, 2, 98),
        ],
    )
    .unwrap();

    assert!(!advance.changed());
    assert_eq!(advance.state().floor(), UnixMillis::new(100));
    let selected = reference(advance.state());
    assert_eq!(selected.kind(), IndependentTimeKind::Receipt);
    assert_eq!(selected.verified_time(), UnixMillis::new(100));
    assert_eq!(selected.object_hash().as_bytes(), &[4; 32]);
}

#[test]
fn newer_reference_raises_both_reference_and_general_floor() {
    let state = persisted(50, Some(input(IndependentTimeKind::Receipt, 1, 40))).unwrap();
    let advance =
        merge_independent_references(&state, &[input(IndependentTimeKind::Checkpoint, 2, 60)])
            .unwrap();

    assert!(advance.changed());
    assert_eq!(advance.state().floor(), UnixMillis::new(60));
    let selected = reference(advance.state());
    assert_eq!(selected.kind(), IndependentTimeKind::Checkpoint);
    assert_eq!(selected.verified_time(), UnixMillis::new(60));
    assert_eq!(selected.object_hash().as_bytes(), &[2; 32]);
}

#[test]
fn registry_floor_uses_all_registry_times_without_changing_the_reference() {
    let state = persisted(100, Some(input(IndependentTimeKind::Checkpoint, 7, 90))).unwrap();

    for (issued_at, not_before, expected_floor) in [(150, 200, 200), (250, 200, 250), (90, 80, 100)]
    {
        let advanced = advance_registry_floor(
            &state,
            UnixMillis::new(issued_at),
            UnixMillis::new(not_before),
        );

        assert_eq!(advanced.floor(), UnixMillis::new(expected_floor));
        let selected = reference(&advanced);
        assert_eq!(selected.kind(), IndependentTimeKind::Checkpoint);
        assert_eq!(selected.verified_time(), UnixMillis::new(90));
        assert_eq!(selected.object_hash().as_bytes(), &[7; 32]);
    }
}

#[test]
fn persisted_reference_newer_than_floor_is_rejected_without_leaking_values() {
    let error = match persisted(100, Some(input(IndependentTimeKind::Receipt, 0xab, 200))) {
        Ok(_) => panic!("reference newer than the persisted floor must fail closed"),
        Err(error) => error,
    };

    assert_eq!(error, TimeError::StateMonotonicity);
    assert_eq!(error.code(), "EA-TIME-STATE-MONOTONICITY");
    assert_eq!(error.to_string(), "EA-TIME-STATE-MONOTONICITY");
    assert_eq!(format!("{error:?}"), "EA-TIME-STATE-MONOTONICITY");
    assert!(!error.to_string().contains("171"));
    assert!(!error.to_string().contains("200"));
}

#[test]
fn persisted_reference_equal_to_floor_is_valid() {
    let state = persisted(100, Some(input(IndependentTimeKind::Receipt, 5, 100))).unwrap();

    assert_eq!(state.floor(), UnixMillis::new(100));
    assert_eq!(reference(&state).verified_time(), UnixMillis::new(100));
}
