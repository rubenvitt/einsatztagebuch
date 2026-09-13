//! Private decision data derived only after the existing original verifier.
//! These values grant no signing, native, delivery or execution authority.
use ea_destruction::DestructionError;
use ea_types::{DeviceId, ObjectHash, UnixMillis};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClaimResult {
    Successful,
    Pending,
    Unconfirmed,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ClaimFact {
    pub device: DeviceId,
    pub exact_hash: ObjectHash,
    pub result: ClaimResult,
    pub executed_at: UnixMillis,
    pub backup_expiry_at: Option<UnixMillis>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DutyState {
    Confirmed,
    RunningBackup,
    Unconfirmed,
    OverdueUnconfirmed,
}
#[derive(Clone, Eq, PartialEq)]
pub(super) struct DutyDecision {
    pub device: DeviceId,
    pub latest: Option<ClaimFact>,
    pub max_deadline: Option<UnixMillis>,
    pub state: DutyState,
}
#[derive(Clone, Eq, PartialEq)]
pub(super) struct ClaimDecision {
    pub duties: Vec<DutyDecision>,
}
impl ClaimDecision {
    pub fn has_failure(&self) -> bool {
        self.duties.iter().any(|duty| {
            matches!(
                duty.state,
                DutyState::Unconfirmed | DutyState::OverdueUnconfirmed
            )
        })
    }
}

/// Existing original verification is mandatory before deriving these facts.
/// The second pass is solely the current conservative Failure decision.
pub(super) fn decide(
    expected: &[DeviceId],
    claims: &[ClaimFact],
    decision_time: UnixMillis,
) -> Result<ClaimDecision, DestructionError> {
    use std::collections::BTreeMap;
    if expected.is_empty() || decision_time.get() < 0 {
        return Err(DestructionError::Event);
    }
    let mut duties = BTreeMap::new();
    for device in expected {
        if duties
            .insert(
                *device,
                DutyDecision {
                    device: *device,
                    latest: None,
                    max_deadline: None,
                    state: DutyState::Unconfirmed,
                },
            )
            .is_some()
        {
            return Err(DestructionError::SecurityConflict);
        }
    }
    let mut seen = BTreeMap::new();
    for claim in claims {
        let duty = duties
            .get_mut(&claim.device)
            .ok_or(DestructionError::SecurityConflict)?;
        if claim.executed_at.get() < 0
            || claim
                .backup_expiry_at
                .is_some_and(|expiry| expiry.get() < 0)
            || (claim.result == ClaimResult::Pending && claim.backup_expiry_at.is_none())
        {
            return Err(DestructionError::Event);
        }
        if seen
            .insert((claim.device, claim.executed_at), *claim)
            .is_some_and(|previous| previous != *claim)
        {
            return Err(DestructionError::SecurityConflict);
        }
        if claim.executed_at > decision_time {
            continue;
        }
        if let Some(expiry) = claim.backup_expiry_at {
            duty.max_deadline = Some(duty.max_deadline.map_or(expiry, |old| old.max(expiry)));
        }
        if duty
            .latest
            .is_none_or(|old| old.executed_at <= claim.executed_at)
        {
            duty.latest = Some(*claim);
        }
    }
    for duty in duties.values_mut() {
        duty.state = match duty.latest {
            None => DutyState::Unconfirmed,
            Some(latest) => match latest.result {
                ClaimResult::Unconfirmed => DutyState::Unconfirmed,
                ClaimResult::Successful
                    if duty
                        .max_deadline
                        .is_none_or(|deadline| latest.executed_at >= deadline) =>
                {
                    DutyState::Confirmed
                }
                ClaimResult::Successful | ClaimResult::Pending => {
                    let deadline = duty.max_deadline.ok_or(DestructionError::Event)?;
                    if deadline > decision_time {
                        DutyState::RunningBackup
                    } else {
                        DutyState::OverdueUnconfirmed
                    }
                }
            },
        };
    }
    Ok(ClaimDecision {
        duties: duties.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn device(n: u8) -> DeviceId {
        DeviceId::try_from(&[n; 16][..]).unwrap()
    }
    fn claim(
        replica: u8,
        hash: u8,
        result: ClaimResult,
        time: i64,
        expiry: Option<i64>,
    ) -> ClaimFact {
        ClaimFact {
            device: device(replica),
            exact_hash: ObjectHash::try_from(&[hash; 32][..]).unwrap(),
            result,
            executed_at: UnixMillis::new(time),
            backup_expiry_at: expiry.map(UnixMillis::new),
        }
    }
    fn single(claims: &[ClaimFact], time: i64) -> ClaimDecision {
        decide(&[device(1)], claims, UnixMillis::new(time)).unwrap()
    }
    #[test]
    fn early_success_does_not_erase_maximum_or_attest_later_removal() {
        let pending = claim(1, 1, ClaimResult::Pending, 1000, Some(2000));
        let early = claim(1, 2, ClaimResult::Successful, 1999, None);
        let running = single(&[pending, early], 1999);
        assert_eq!(running.duties[0].state, DutyState::RunningBackup);
        assert!(!running.has_failure());
        let overdue = single(&[pending, early], 2000);
        assert_eq!(overdue.duties[0].state, DutyState::OverdueUnconfirmed);
        assert_eq!(overdue.duties[0].max_deadline, Some(UnixMillis::new(2000)));
        assert!(overdue.duties[0].latest == Some(early));
        assert!(overdue.has_failure());
        let removed = claim(1, 3, ClaimResult::Successful, 2000, None);
        let confirmed = single(&[pending, early, removed], 2000);
        assert_eq!(confirmed.duties[0].state, DutyState::Confirmed);
        assert!(!confirmed.has_failure());
    }
    #[test]
    fn shorter_newer_deadline_and_delivery_order_do_not_change_decision() {
        let original = claim(1, 1, ClaimResult::Pending, 1000, Some(2000));
        let shorter = claim(1, 2, ClaimResult::Pending, 1100, Some(1500));
        let early = claim(1, 3, ClaimResult::Successful, 1600, None);
        let expected = single(&[original, shorter, early], 1999);
        assert_eq!(expected.duties[0].state, DutyState::RunningBackup);
        for claims in [
            vec![early, shorter, original],
            vec![shorter, original, early],
            vec![original, early, shorter, original],
        ] {
            assert!(single(&claims, 1999) == expected);
        }
        assert_eq!(
            single(&[early, shorter, original], 2000).duties[0].state,
            DutyState::OverdueUnconfirmed
        );
    }
    #[test]
    fn later_deadline_of_other_duty_cannot_hide_overdue_duty() {
        let first = claim(1, 1, ClaimResult::Pending, 1000, Some(2000));
        let second = claim(2, 2, ClaimResult::Pending, 1000, Some(3000));
        let result = decide(
            &[device(2), device(1)],
            &[second, first],
            UnixMillis::new(2000),
        )
        .unwrap();
        assert_eq!(result.duties.len(), 2);
        assert!(result.duties[0].device == device(1));
        assert_eq!(result.duties[0].state, DutyState::OverdueUnconfirmed);
        assert_eq!(result.duties[1].state, DutyState::RunningBackup);
        assert!(result.has_failure());
    }
    #[test]
    fn later_executed_success_cannot_justify_earlier_decision() {
        let pending = claim(1, 1, ClaimResult::Pending, 1000, Some(2000));
        let future = claim(1, 2, ClaimResult::Successful, 2001, None);
        let before = single(&[pending, future], 2000);
        assert_eq!(before.duties[0].state, DutyState::OverdueUnconfirmed);
        assert!(before.duties[0].latest == Some(pending));
        assert!(!single(&[pending, future], 2001).has_failure());
    }
    #[test]
    fn missing_confirmation_and_latest_negative_are_not_network_measurements() {
        let absent = single(&[], 2000);
        assert_eq!(absent.duties[0].state, DutyState::Unconfirmed);
        assert!(absent.duties[0].latest.is_none());
        let removed = claim(1, 1, ClaimResult::Successful, 1000, None);
        let negative = claim(1, 2, ClaimResult::Unconfirmed, 1100, None);
        let result = single(&[negative, removed], 2000);
        assert_eq!(result.duties[0].state, DutyState::Unconfirmed);
        assert!(result.duties[0].latest == Some(negative));
        assert!(result.has_failure());
    }
    #[test]
    fn missing_expiry_is_refusal_not_invented_overdue_claim() {
        let pending = claim(1, 1, ClaimResult::Pending, 1000, None);
        assert!(
            decide(&[device(1)], &[pending], UnixMillis::new(2000)) == Err(DestructionError::Event)
        );
    }
    #[test]
    fn unknown_or_conflicting_fact_refuses_even_behind_a_newer_claim() {
        let a = claim(1, 1, ClaimResult::Pending, 1000, Some(2000));
        let conflict = claim(1, 2, ClaimResult::Pending, 1000, Some(3000));
        let newest = claim(1, 3, ClaimResult::Successful, 4000, None);
        for facts in [vec![a, conflict, newest], vec![newest, conflict, a]] {
            assert!(
                decide(&[device(1)], &facts, UnixMillis::new(4000))
                    == Err(DestructionError::SecurityConflict)
            );
        }
        assert!(
            decide(&[device(2)], &[a], UnixMillis::new(2000))
                == Err(DestructionError::SecurityConflict)
        );
    }
}
