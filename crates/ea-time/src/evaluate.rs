use ea_types::UnixMillis;

use crate::{
    FutureSkew, IndependentTimeReference, TimeAdvance, TimeError, TimeEvaluation, TimeWarnings,
    TrustedTimeState,
};

pub fn merge_independent_references(
    persisted: &TrustedTimeState,
    verified_inputs: &[crate::IndependentTimeInput],
) -> Result<TimeAdvance, TimeError> {
    persisted.validate()?;

    let mut selected = persisted.independent_reference().copied();
    for input in verified_inputs {
        let candidate = IndependentTimeReference::from_input(*input);
        if selected
            .as_ref()
            .is_none_or(|current| candidate.is_preferred_to(current))
        {
            selected = Some(candidate);
        }
    }

    let floor = selected.as_ref().map_or(persisted.floor(), |reference| {
        persisted.floor().max(reference.verified_time())
    });
    let changed = selected.as_ref() != persisted.independent_reference();

    Ok(TimeAdvance::new(
        TrustedTimeState::from_parts(floor, selected),
        changed,
    ))
}

pub fn evaluate_preexisting_time(
    os_wall_clock: UnixMillis,
    state: &TrustedTimeState,
    max_future_clock_skew_ms: u64,
) -> Result<TimeEvaluation, TimeError> {
    state.validate()?;

    let raw_now = os_wall_clock.max(state.floor());
    let clock_rollback = os_wall_clock < state.floor();
    let (independent_time_unavailable, future_skew) = match state.independent_reference() {
        None => (true, FutureSkew::UnprovableWithoutIndependentReference),
        Some(reference) => {
            let future_limit =
                checked_add_millis(reference.verified_time(), max_future_clock_skew_ms)?;
            let skew = if os_wall_clock <= future_limit {
                FutureSkew::WithinLimit
            } else {
                FutureSkew::Blocked
            };
            (false, skew)
        }
    };

    Ok(TimeEvaluation::new(
        raw_now,
        TimeWarnings::new(clock_rollback, independent_time_unavailable),
        future_skew,
    ))
}

#[must_use]
pub fn advance_registry_floor(
    state: &TrustedTimeState,
    issued_at: UnixMillis,
    not_before: UnixMillis,
) -> TrustedTimeState {
    let floor = state.floor().max(issued_at).max(not_before);
    TrustedTimeState::from_parts(floor, state.independent_reference().copied())
}

fn checked_add_millis(time: UnixMillis, delta: u64) -> Result<UnixMillis, TimeError> {
    let sum = i128::from(time.get())
        .checked_add(i128::from(delta))
        .ok_or(TimeError::Overflow)?;
    let sum = i64::try_from(sum).map_err(|_| TimeError::Overflow)?;
    Ok(UnixMillis::new(sum))
}
