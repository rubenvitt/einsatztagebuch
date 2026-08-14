use ea_time::{
    FutureSkew, IndependentTimeInput, IndependentTimeKind, TimeError, TrustedTimeState,
    evaluate_preexisting_time,
};
use ea_types::{ObjectHash, UnixMillis};

fn object_hash(byte: u8) -> ObjectHash {
    ObjectHash::try_from(&[byte; 32][..]).unwrap()
}

fn with_reference(floor: i64, reference_time: i64) -> TrustedTimeState {
    TrustedTimeState::from_persisted(
        UnixMillis::new(floor),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            object_hash(1),
            UnixMillis::new(reference_time),
        )),
    )
    .unwrap()
}

#[test]
fn os_clock_below_floor_uses_floor_and_reports_clock_rollback() {
    let state = with_reference(100, 90);
    let evaluation = evaluate_preexisting_time(UnixMillis::new(80), &state, 100).unwrap();

    assert_eq!(evaluation.raw_now(), UnixMillis::new(100));
    assert!(evaluation.warnings().clock_rollback());
    assert!(!evaluation.warnings().independent_time_unavailable());
    assert_eq!(evaluation.future_skew(), FutureSkew::WithinLimit);
}

#[test]
fn no_independent_reference_is_reported_as_unprovable() {
    let state = TrustedTimeState::initial(UnixMillis::new(100));
    let evaluation = evaluate_preexisting_time(UnixMillis::new(100), &state, 50).unwrap();

    assert_eq!(evaluation.raw_now(), UnixMillis::new(100));
    assert!(!evaluation.warnings().clock_rollback());
    assert!(evaluation.warnings().independent_time_unavailable());
    assert_eq!(
        evaluation.future_skew(),
        FutureSkew::UnprovableWithoutIndependentReference
    );
}

#[test]
fn rollback_without_an_independent_reference_reports_both_warnings() {
    let state = TrustedTimeState::initial(UnixMillis::new(100));
    let evaluation = evaluate_preexisting_time(UnixMillis::new(99), &state, 50).unwrap();

    assert_eq!(evaluation.raw_now(), UnixMillis::new(100));
    assert!(evaluation.warnings().clock_rollback());
    assert!(evaluation.warnings().independent_time_unavailable());
    assert_eq!(
        evaluation.future_skew(),
        FutureSkew::UnprovableWithoutIndependentReference
    );
}

#[test]
fn os_clock_exactly_at_reference_plus_limit_is_within_limit() {
    let state = with_reference(100, 100);
    let evaluation = evaluate_preexisting_time(UnixMillis::new(150), &state, 50).unwrap();

    assert_eq!(evaluation.future_skew(), FutureSkew::WithinLimit);
}

#[test]
fn os_clock_one_millisecond_above_reference_plus_limit_is_blocked() {
    let state = with_reference(100, 100);
    let evaluation = evaluate_preexisting_time(UnixMillis::new(151), &state, 50).unwrap();

    assert_eq!(evaluation.future_skew(), FutureSkew::Blocked);
}

#[test]
fn skew_compares_os_clock_instead_of_floor_adjusted_raw_now() {
    let state = with_reference(1_000, 100);
    let evaluation = evaluate_preexisting_time(UnixMillis::new(120), &state, 50).unwrap();

    assert_eq!(evaluation.raw_now(), UnixMillis::new(1_000));
    assert!(evaluation.warnings().clock_rollback());
    assert_eq!(evaluation.future_skew(), FutureSkew::WithinLimit);
}

#[test]
fn checked_add_overflow_returns_code_only_error() {
    let state = with_reference(i64::MAX, i64::MAX);
    let error = match evaluate_preexisting_time(UnixMillis::new(i64::MAX), &state, 1) {
        Ok(_) => panic!("unrepresentable reference plus limit must fail closed"),
        Err(error) => error,
    };

    assert_eq!(error, TimeError::Overflow);
    assert_eq!(error.code(), "EA-TIME-OVERFLOW");
    assert_eq!(error.to_string(), "EA-TIME-OVERFLOW");
    assert_eq!(format!("{error:?}"), "EA-TIME-OVERFLOW");
    assert!(!error.to_string().contains(&i64::MAX.to_string()));
}

#[test]
fn mixed_signed_unsigned_boundary_is_evaluated_without_false_overflow() {
    let state = with_reference(i64::MIN, i64::MIN);
    let evaluation =
        evaluate_preexisting_time(UnixMillis::new(i64::MAX), &state, u64::MAX).unwrap();

    assert_eq!(evaluation.raw_now(), UnixMillis::new(i64::MAX));
    assert_eq!(evaluation.future_skew(), FutureSkew::WithinLimit);
}

#[test]
fn no_reference_remains_unprovable_even_with_an_unrepresentable_limit() {
    let state = TrustedTimeState::initial(UnixMillis::new(0));
    let evaluation =
        evaluate_preexisting_time(UnixMillis::new(i64::MAX), &state, u64::MAX).unwrap();

    assert!(evaluation.warnings().independent_time_unavailable());
    assert_eq!(
        evaluation.future_skew(),
        FutureSkew::UnprovableWithoutIndependentReference
    );
}
