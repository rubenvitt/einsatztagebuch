//! Explicit conservative failure history, never a physical execution permit.
mod claims;
use super::status::SavedDestruction;
use super::*;
use claims::{ClaimDecision, ClaimFact, ClaimResult};
use ea_archive::ArchiveBackend;
use ea_destruction::{
    LocalActionAuthorityGuard, VerifiedDestructionEvidence, project_imported_evidence,
    reconstruct_imported_history,
};
use ea_local_store::StoreTransaction;
use ea_types::UnixMillis;

pub(super) struct FailureCommitFence {
    snapshot: ObjectHash,
    authorization: ObjectHash,
    job: ObjectHash,
    started: ObjectHash,
    source_state: DestructionState,
    source_last: ObjectHash,
    from: u8,
    previous: ObjectHash,
    event_time: UnixMillis,
    decision_time: UnixMillis,
    decision: ClaimDecision,
    local_successes: Vec<ObjectHash>,
    exact_event: Option<ObjectHash>,
}
impl FailureCommitFence {
    pub(super) fn snapshot(&self) -> ObjectHash {
        self.snapshot
    }
}
struct FailureObservation {
    decision: ClaimDecision,
    projection: VerifiedDestructionEvidence,
    local_successes: Vec<ObjectHash>,
}
impl DestructionRuntime {
    /// Record missing confirmation of the unchanged original obligation set.
    /// No delivery success, actual removal or current reachability is implied.
    pub fn mark_incomplete_progress(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<NativeDestructionStatus, Error> {
        self.mark_incomplete_impl(id, expected_preflight_hash, || {})
    }
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn mark_incomplete_progress_with_test_before_sign(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        before_sign: impl FnOnce(),
    ) -> Result<NativeDestructionStatus, Error> {
        self.mark_incomplete_impl(id, expected_preflight_hash, before_sign)
    }
    fn mark_incomplete_impl(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        before_sign: impl FnOnce(),
    ) -> Result<NativeDestructionStatus, Error> {
        self.unlock()?;
        let admission = self.read_saved(id)?;
        if admission
            .job
            .as_ref()
            .ok_or(DestructionError::Storage)?
            .job_hash()
            != expected_preflight_hash
        {
            return Err(DestructionError::SecurityConflict.into());
        }
        // This existing admission validates native/original/custody/job scope;
        // it neither requests nor substitutes successful network delivery.
        self.validate_import_scope(&admission)?;
        let snapshot = self.import_snapshot()?;
        let saved = self.read_saved(id)?;
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        if job.job_hash() != expected_preflight_hash {
            return Err(DestructionError::SecurityConflict.into());
        }
        let started = original_started(&saved)?;
        let rebuilt = reconstruct_imported_history(job, &saved.events, &saved.attestations)?;
        let decision_time = self.controller.head().preexisting_effective_now().value();
        let observation = self.failure_observation(&saved, decision_time)?;
        let (from, previous, event_time, replay) = match rebuilt.state() {
            DestructionState::InProgress | DestructionState::PendingBackupExpiry => (
                rebuilt.state().code(),
                rebuilt.last_event_hash(),
                decision_time,
                None,
            ),
            DestructionState::IncompleteUnreachableReplica => {
                let event = saved
                    .events
                    .iter()
                    .find(|event| event.object_hash() == rebuilt.last_event_hash())
                    .ok_or(DestructionError::Event)?;
                let fields = event.fields();
                if !matches!(fields.from_state, Some(1 | 2))
                    || fields.to_state != 4
                    || fields.trigger_code != 4
                {
                    return Err(DestructionError::Event.into());
                }
                (
                    fields.from_state.ok_or(DestructionError::Event)?,
                    fields
                        .previous_event_object_hash
                        .ok_or(DestructionError::Event)?,
                    fields.executed_at,
                    Some(event.exact_bytes().to_vec()),
                )
            }
            _ => return Err(DestructionError::Event.into()),
        };
        let mut fence = FailureCommitFence {
            snapshot,
            authorization: saved.auth.object_hash(),
            job: job.job_hash(),
            started,
            source_state: rebuilt.state(),
            source_last: rebuilt.last_event_hash(),
            from,
            previous,
            event_time,
            decision_time,
            decision: observation.decision,
            local_successes: observation.local_successes,
            exact_event: replay.as_deref().map(object_hash),
        };
        // Deterministic per-call checkpoint only; no lock or transaction held.
        before_sign();
        self.failure_commit(&saved, &fence, false, |_| Ok(()))?;
        let exact = {
            let mut guard = self.action_guard()?;
            guard.check_before_effect()?;
            let exact = match replay {
                Some(exact) => exact,
                None => self.event(&saved.auth, Some(from), 4, Some(previous))?,
            };
            guard.check_before_effect()?;
            exact
        };
        fence.exact_event = Some(object_hash(&exact));
        self.import_failure_progress(id, expected_preflight_hash, &exact, fence)
    }
    fn failure_observation(
        &self,
        saved: &SavedDestruction,
        decision_time: UnixMillis,
    ) -> Result<FailureObservation, Error> {
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        // The existing complete original verifier retains scope/kind/target and
        // contradictory same-time claim checks. Facts confer no new authority.
        let projection = project_imported_evidence(job, &saved.attestations)?;
        let expected = projection
            .replicas()
            .iter()
            .map(|(device, _)| *device)
            .collect::<Vec<_>>();
        let facts = saved
            .attestations
            .iter()
            .map(|claim| {
                let fields = claim.fields();
                Ok(ClaimFact {
                    device: DeviceId::try_from(fields.replica_id.as_slice())
                        .map_err(|_| DestructionError::Format)?,
                    exact_hash: claim.object_hash(),
                    result: match fields.result {
                        0 => ClaimResult::Successful,
                        1 => ClaimResult::Pending,
                        2 => ClaimResult::Unconfirmed,
                        _ => return Err(DestructionError::Event),
                    },
                    executed_at: fields.executed_at,
                    backup_expiry_at: fields.backup_expiry_at,
                })
            })
            .collect::<Result<Vec<_>, DestructionError>>()?;
        let decision = claims::decide(&expected, &facts, decision_time)?;
        if !decision.has_failure() {
            return Err(DestructionError::Event.into());
        }
        let device = self
            .custodian
            .head()
            .active_certificate_fields(self.custodian.config().device_certificate_hash)
            .ok_or(Error::Configuration)?
            .device_id;
        // ANY existing local success retains its real-file obligation, even if
        // the newest projection is negative or an early success is still Pending.
        let mut local_successes = facts
            .iter()
            .filter(|claim| {
                claim.device == device
                    && claim.result == ClaimResult::Successful
                    && claim.executed_at <= decision_time
            })
            .map(|claim| claim.exact_hash)
            .collect::<Vec<_>>();
        local_successes.sort();
        local_successes.dedup();
        Ok(FailureObservation {
            decision,
            projection,
            local_successes,
        })
    }
    pub(super) fn with_failure_commit(
        &self,
        saved: &SavedDestruction,
        fence: &FailureCommitFence,
        write: impl FnOnce(&StoreTransaction<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.failure_commit(saved, fence, true, write)
    }
    fn failure_commit(
        &self,
        saved: &SavedDestruction,
        fence: &FailureCommitFence,
        final_event: bool,
        write: impl FnOnce(&StoreTransaction<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        if saved.auth.object_hash() != fence.authorization
            || job.job_hash() != fence.job
            || original_started(saved)? != fence.started
        {
            return Err(DestructionError::SecurityConflict.into());
        }
        let rebuilt = reconstruct_imported_history(job, &saved.events, &saved.attestations)?;
        if final_event {
            let event = saved
                .events
                .iter()
                .find(|event| Some(event.object_hash()) == fence.exact_event)
                .ok_or(DestructionError::Event)?;
            let fields = event.fields();
            if rebuilt.state() != DestructionState::IncompleteUnreachableReplica
                || Some(rebuilt.last_event_hash()) != fence.exact_event
                || fields.from_state != Some(fence.from)
                || fields.to_state != 4
                || fields.trigger_code != 4
                || fields.previous_event_object_hash != Some(fence.previous)
                || fields.executed_at != fence.event_time
            {
                return Err(DestructionError::Event.into());
            }
        } else if rebuilt.state() != fence.source_state
            || rebuilt.last_event_hash() != fence.source_last
        {
            return Err(DestructionError::SecurityConflict.into());
        }
        // Today's decision remains separate from the retained replay's event
        // time; no newly delivered original retroactively re-justifies that event.
        let observation = self.failure_observation(saved, fence.decision_time)?;
        if observation.decision != fence.decision
            || observation.local_successes != fence.local_successes
        {
            return Err(DestructionError::SecurityConflict.into());
        }
        self.require_same_fresh_action()?;
        let mut holders = self
            .holders
            .iter()
            .map(|holder| {
                std::fs::canonicalize(holder.backend.root())
                    .map(|root| (root, holder))
                    .map_err(|_| Error::Configuration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        holders.sort_by(|a, b| a.0.cmp(&b.0));
        let mut guard = self.action_guard()?;
        let _locks = holders
            .iter()
            .map(|(_, holder)| {
                holder
                    .backend
                    .acquire_writer_lock()
                    .map_err(|_| Error::Core(DestructionError::Storage))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.custodian.database().transaction(|tx| {
            guard.check_in(tx)?;
            if super::import::storage::snapshot_in(tx)? != fence.snapshot {
                return Err(DestructionError::SecurityConflict.into());
            }
            for (_, holder) in &holders {
                super::observations::validate_failure_holder(
                    job,
                    &observation.projection,
                    !observation.local_successes.is_empty(),
                    holder,
                )?;
            }
            guard.check_in(tx)?;
            write(tx)?;
            guard.check_in(tx)?;
            Ok(())
        })
    }
}
fn original_started(saved: &SavedDestruction) -> Result<ObjectHash, Error> {
    let mut starts = saved
        .events
        .iter()
        .filter(|event| event.fields().from_state == Some(0) && event.fields().to_state == 1);
    let start = starts.next().ok_or(DestructionError::Event)?;
    if starts.next().is_some() {
        return Err(DestructionError::Event.into());
    }
    Ok(start.object_hash())
}
