//! Private decision data derived only after the existing original verifier.
//! These values grant no signing, native, delivery or execution authority.
//! Shared by the conservative Failure producer and the server-bound Retry.
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
        self.duties.iter().any(DutyDecision::is_open)
    }
    /// Earliest still running backup deadline. A decision without failure
    /// holds only strictly before it; this is no advance of any clock.
    pub fn running_cutoff(&self) -> Option<UnixMillis> {
        self.duties
            .iter()
            .filter(|duty| duty.state == DutyState::RunningBackup)
            .filter_map(|duty| duty.max_deadline)
            .min()
    }
}
impl DutyDecision {
    fn is_open(&self) -> bool {
        matches!(
            self.state,
            DutyState::Unconfirmed | DutyState::OverdueUnconfirmed
        )
    }
}

/// Existing original verification is mandatory before deriving these facts.
/// Used by the conservative Failure decision and the server-bound Retry.
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

/// Duty class from the signed job denominator (certificate kinds 0, 1, 6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DutyKind {
    Writer,
    Reader,
    Server,
}
/// Why a 4→1 re-entry is refused although every original verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RetryRefusal {
    /// The signed job has no Server duty: no server-bound retry exists.
    NoServer,
    /// A Reader duty was open at t4, is open now, or is confirmed only by an
    /// original imported at/after the retained state4 (Ruling G1/G4).
    Reader,
    /// Some other duty still lacks confirmation at the decision time (G4).
    StillOpen,
}

/// Server-bound 4→1 admission over the unchanged original claim set.
///
/// `claims` carry their local import-batch index (`None`: own local Writer
/// attestation without a batch); `retained_position` is the batch index of the
/// retained state4 and `retained_time` its signed `executed_at`. The retained
/// state4 is never re-justified: only Reader duties are additionally judged
/// on the originals imported strictly before it, at t4 and at now, so a late
/// original can neither confirm a Reader nor hide that it was the open duty.
pub(super) fn decide_retry(
    duties: &[(DeviceId, DutyKind)],
    claims: &[(ClaimFact, Option<usize>)],
    retained_position: usize,
    retained_time: UnixMillis,
    decision_time: UnixMillis,
) -> Result<Result<ClaimDecision, RetryRefusal>, DestructionError> {
    use std::collections::BTreeSet;
    if !duties.iter().any(|(_, kind)| *kind == DutyKind::Server) {
        return Ok(Err(RetryRefusal::NoServer));
    }
    if decision_time < retained_time {
        return Err(DestructionError::Event);
    }
    let expected = duties.iter().map(|(device, _)| *device).collect::<Vec<_>>();
    let readers = duties
        .iter()
        .filter(|(_, kind)| *kind == DutyKind::Reader)
        .map(|(device, _)| *device)
        .collect::<BTreeSet<_>>();
    let all = claims.iter().map(|(claim, _)| *claim).collect::<Vec<_>>();
    let before = claims
        .iter()
        .filter(|(claim, position)| {
            !readers.contains(&claim.device)
                || position.is_some_and(|position| position < retained_position)
        })
        .map(|(claim, _)| *claim)
        .collect::<Vec<_>>();
    let now = decide(&expected, &all, decision_time)?;
    let known_at_now = decide(&expected, &before, decision_time)?;
    let known_at_t4 = decide(&expected, &before, retained_time)?;
    if [&now, &known_at_now, &known_at_t4].iter().any(|decision| {
        decision
            .duties
            .iter()
            .any(|duty| readers.contains(&duty.device) && duty.is_open())
    }) {
        return Ok(Err(RetryRefusal::Reader));
    }
    if now.has_failure() {
        return Ok(Err(RetryRefusal::StillOpen));
    }
    Ok(Ok(now))
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

    // --- Retry 4→1 admission (DRK-319 S1). Positions are import-batch
    // indexes; `None` is the own local Writer attestation without a batch.
    const W: u8 = 1;
    const R: u8 = 2;
    const S: u8 = 3;
    fn duties(kinds: &[(u8, DutyKind)]) -> Vec<(DeviceId, DutyKind)> {
        kinds.iter().map(|(n, kind)| (device(*n), *kind)).collect()
    }
    fn full() -> Vec<(DeviceId, DutyKind)> {
        duties(&[
            (W, DutyKind::Writer),
            (R, DutyKind::Reader),
            (S, DutyKind::Server),
        ])
    }
    fn retry(
        duties: &[(DeviceId, DutyKind)],
        claims: &[(ClaimFact, Option<usize>)],
        retained_position: usize,
        retained_time: i64,
        now: i64,
    ) -> Result<Result<ClaimDecision, RetryRefusal>, DestructionError> {
        decide_retry(
            duties,
            claims,
            retained_position,
            UnixMillis::new(retained_time),
            UnixMillis::new(now),
        )
    }
    #[test]
    fn retry_admits_only_when_every_duty_is_confirmed_at_now() {
        let writer = (claim(W, 1, ClaimResult::Successful, 1000, None), None);
        let reader = (claim(R, 2, ClaimResult::Successful, 1000, None), Some(0));
        // The Server original arrived only after state4 (batch 2 > batch 1)
        // and is dated before t4: it confirms the Server duty today.
        let server = (claim(S, 3, ClaimResult::Successful, 1500, None), Some(2));
        let decision = retry(&full(), &[writer, reader, server], 1, 2000, 3000)
            .unwrap()
            .unwrap();
        assert!(!decision.has_failure());
        assert!(
            decision
                .duties
                .iter()
                .all(|duty| duty.state == DutyState::Confirmed)
        );
    }
    #[test]
    fn retry_refuses_an_open_server_duty_at_now() {
        let writer = (claim(W, 1, ClaimResult::Successful, 1000, None), None);
        let reader = (claim(R, 2, ClaimResult::Successful, 1000, None), Some(0));
        assert_eq!(
            retry(&full(), &[writer, reader], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::StillOpen)
        );
        // A negative Server result is not a confirmation either.
        let negative = (claim(S, 3, ClaimResult::Unconfirmed, 2500, None), Some(2));
        assert_eq!(
            retry(&full(), &[writer, reader, negative], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::StillOpen)
        );
        // An expired backup deadline without removal at/after it stays open.
        let pending = (claim(S, 4, ClaimResult::Pending, 1500, Some(2500)), Some(0));
        assert_eq!(
            retry(&full(), &[writer, reader, pending], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::StillOpen)
        );
    }
    #[test]
    fn retry_refuses_a_reader_confirmed_only_after_state4() {
        let writer = (claim(W, 1, ClaimResult::Successful, 1000, None), None);
        let server = (claim(S, 3, ClaimResult::Successful, 1500, None), Some(0));
        // Original dated before t4, but imported in the batch AFTER state4.
        let late = (claim(R, 2, ClaimResult::Successful, 1000, None), Some(2));
        assert_eq!(
            retry(&full(), &[writer, server, late], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::Reader)
        );
        // In the SAME batch as the retained state4 is not "before" either.
        let same = (late.0, Some(1));
        assert_eq!(
            retry(&full(), &[writer, server, same], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::Reader)
        );
        // Still missing today: the Reader explanation wins over StillOpen.
        assert_eq!(
            retry(&full(), &[writer, server], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::Reader)
        );
        // A Reader claim without any import batch cannot be ordered at all.
        let unordered = (late.0, None);
        assert_eq!(
            retry(&full(), &[writer, server, unordered], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::Reader)
        );
    }
    #[test]
    fn retry_refuses_a_reader_that_was_open_at_t4_or_is_refuted_later() {
        let writer = (claim(W, 1, ClaimResult::Successful, 1000, None), None);
        let server = (claim(S, 3, ClaimResult::Successful, 1500, None), Some(0));
        // Imported before state4 but executed only after t4: at t4 the
        // Reader duty was the open one.
        let after_t4 = (claim(R, 2, ClaimResult::Successful, 2100, None), Some(0));
        assert_eq!(
            retry(&full(), &[writer, server, after_t4], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::Reader)
        );
        // A later negative Reader result refutes an earlier confirmation.
        let before = (claim(R, 2, ClaimResult::Successful, 1000, None), Some(0));
        let refuted = (claim(R, 4, ClaimResult::Unconfirmed, 2500, None), Some(2));
        assert_eq!(
            retry(&full(), &[writer, server, before, refuted], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::Reader)
        );
        // A running Reader backup known before state4 is not an open duty.
        let running = (claim(R, 5, ClaimResult::Pending, 1000, Some(9000)), Some(0));
        let decision = retry(&full(), &[writer, server, running], 1, 2000, 3000)
            .unwrap()
            .unwrap();
        assert_eq!(decision.running_cutoff(), Some(UnixMillis::new(9000)));
    }
    #[test]
    fn retry_requires_a_server_duty_and_never_runs_backwards() {
        let local = duties(&[(W, DutyKind::Writer), (R, DutyKind::Reader)]);
        let writer = (claim(W, 1, ClaimResult::Successful, 1000, None), None);
        let reader = (claim(R, 2, ClaimResult::Successful, 1000, None), Some(0));
        assert_eq!(
            retry(&local, &[writer, reader], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::NoServer)
        );
        let server = (claim(S, 3, ClaimResult::Successful, 1500, None), Some(0));
        assert!(
            retry(&full(), &[writer, reader, server], 1, 2000, 1999)
                == Err(DestructionError::Event)
        );
    }
    #[test]
    fn retry_ignores_claims_executed_after_now() {
        let writer = (claim(W, 1, ClaimResult::Successful, 1000, None), None);
        let reader = (claim(R, 2, ClaimResult::Successful, 1000, None), Some(0));
        let future = (claim(S, 3, ClaimResult::Successful, 3001, None), Some(2));
        assert_eq!(
            retry(&full(), &[writer, reader, future], 1, 2000, 3000)
                .unwrap()
                .err(),
            Some(RetryRefusal::StillOpen)
        );
    }
}
