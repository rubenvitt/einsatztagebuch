//! Signed 4→1 re-entry of the same authorized operation (DRK-319, Part S).
//!
//! Server-bound only: every configured original server is read through the
//! actual per-call reservation port before signing and again after the
//! blocking signing work. The retained 1/2→4 original is bound through its
//! signed fields and never re-justified. No physical execution, no statement
//! about Reader reachability and no substitute for the later 1→2 / 1→3.
use super::claims::{self, ClaimDecision, ClaimFact, ClaimResult, DutyKind, RetryRefusal};
use super::failure::original_started;
use super::status::SavedDestruction;
use super::*;
use ea_archive::ArchiveBackend;
use ea_destruction::{
    LocalActionAuthorityGuard, VerifiedDestructionEvidence, project_imported_evidence,
    reconstruct_imported_history,
};
use ea_local_store::StoreTransaction;
use ea_types::UnixMillis;

/// Private commit binding constructed before component signing. It is never
/// a signing, delivery or execution capability.
pub(super) struct RetryCommitFence {
    snapshot: ObjectHash,
    authorization: ObjectHash,
    job: ObjectHash,
    started: ObjectHash,
    source_state: DestructionState,
    source_last: ObjectHash,
    retained: ObjectHash,
    retained_from: u8,
    retained_previous: ObjectHash,
    retained_time: UnixMillis,
    event_time: UnixMillis,
    decision_time: UnixMillis,
    decision: ClaimDecision,
    exact_event: Option<ObjectHash>,
}
impl RetryCommitFence {
    pub(super) fn snapshot(&self) -> ObjectHash {
        self.snapshot
    }
}
struct RetryObservation {
    decision: ClaimDecision,
    projection: VerifiedDestructionEvidence,
    local_success: bool,
}
impl DestructionRuntime {
    /// Signed re-entry 4→1 after a per-call authenticated server reservation.
    ///
    /// `retained_incomplete_event` is the exact object hash of the current
    /// 1/2→4 original (the last event of the history, e.g. the last entry of
    /// `NativeDestructionExchange::events()`). Only
    /// `NativeDestructionDelivery::AuthenticatedServer` is admitted. A second
    /// call with the same retained event replays the existing 4→1 exactly.
    ///
    /// Order: local refusals (`RETRY-NO-SERVER-DUTY`, `RETRY-READER-DUTY`)
    /// before any network read; first reservation read; decision; component
    /// signature; both native audit signatures; second reservation read;
    /// commit transaction. Publication is the caller's step after the commit.
    pub fn resume_incomplete_progress(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        retained_incomplete_event: ObjectHash,
        delivery: NativeDestructionDelivery<'_>,
    ) -> Result<NativeDestructionStatus, Error> {
        self.resume_incomplete_impl(
            id,
            expected_preflight_hash,
            retained_incomplete_event,
            delivery,
            || {},
        )
    }
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn resume_incomplete_progress_with_test_before_sign(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        retained_incomplete_event: ObjectHash,
        delivery: NativeDestructionDelivery<'_>,
        before_sign: impl FnOnce(),
    ) -> Result<NativeDestructionStatus, Error> {
        self.resume_incomplete_impl(
            id,
            expected_preflight_hash,
            retained_incomplete_event,
            delivery,
            before_sign,
        )
    }
    fn resume_incomplete_impl(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        retained: ObjectHash,
        delivery: NativeDestructionDelivery<'_>,
        before_sign: impl FnOnce(),
    ) -> Result<NativeDestructionStatus, Error> {
        self.unlock()?;
        let admission = self.read_saved(id)?;
        let job = admission.job.as_ref().ok_or(DestructionError::Storage)?;
        if job.job_hash() != expected_preflight_hash {
            return Err(DestructionError::SecurityConflict.into());
        }
        // Local refusals precede any network read. No absence proof or caller
        // flag may stand in for the actual per-call server reservation.
        let NativeDestructionDelivery::AuthenticatedServer(port) = delivery else {
            return Err(Error::RetryNoServerDuty);
        };
        if !duties(job)?
            .iter()
            .any(|(_, kind)| *kind == DutyKind::Server)
        {
            return Err(Error::RetryNoServerDuty);
        }
        // Local pre-decision (G2): a Reader case is refused with its permanent
        // explanation even while no server is reachable. It grants nothing;
        // the decision after the actual admission below remains binding.
        if self.local_reader_refusal(&admission, retained) {
            return Err(Error::RetryReaderDuty);
        }
        // First actual admission: original authority, custody freeze, durable
        // job, authenticated reservation and the exact existing Start replay.
        self.with_started(
            &admission,
            NativeDestructionDelivery::AuthenticatedServer(&mut *port),
            |_, _, _, _| Ok(()),
        )?;
        let snapshot = self.import_snapshot()?;
        let saved = self.read_saved(id)?;
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        if job.job_hash() != expected_preflight_hash {
            return Err(DestructionError::SecurityConflict.into());
        }
        let started = original_started(&saved)?;
        let rebuilt = reconstruct_imported_history(job, &saved.events, &saved.attestations)?;
        let decision_time = self.controller.head().preexisting_effective_now().value();
        let replay = match rebuilt.state() {
            DestructionState::IncompleteUnreachableReplica => {
                if rebuilt.last_event_hash() != retained {
                    return Err(DestructionError::SecurityConflict.into());
                }
                None
            }
            DestructionState::InProgress => {
                let last = event_by_hash(&saved, rebuilt.last_event_hash())?;
                let fields = last.fields();
                if fields.from_state != Some(4) || fields.to_state != 1 || fields.trigger_code != 5
                {
                    return Err(DestructionError::Event.into());
                }
                if fields.previous_event_object_hash != Some(retained) {
                    return Err(DestructionError::SecurityConflict.into());
                }
                Some((last.exact_bytes().to_vec(), fields.executed_at))
            }
            _ => return Err(DestructionError::Event.into()),
        };
        let (retained_from, retained_previous, retained_time) = retained_fields(&saved, retained)?;
        let observation = self.retry_observation(&saved, retained, retained_time, decision_time)?;
        let event_time = replay.as_ref().map_or(decision_time, |(_, at)| *at);
        if event_time < retained_time {
            return Err(DestructionError::Event.into());
        }
        let mut fence = RetryCommitFence {
            snapshot,
            authorization: saved.auth.object_hash(),
            job: job.job_hash(),
            started,
            source_state: rebuilt.state(),
            source_last: rebuilt.last_event_hash(),
            retained,
            retained_from,
            retained_previous,
            retained_time,
            event_time,
            decision_time,
            decision: observation.decision,
            exact_event: replay.as_ref().map(|(exact, _)| object_hash(exact)),
        };
        // Deterministic per-call checkpoint only; no lock or transaction held.
        before_sign();
        self.retry_commit(&saved, &fence, false, |_| Ok(()))?;
        let exact = {
            let mut guard = self.retry_guard(&fence.decision)?;
            guard.check_before_effect()?;
            let exact = match replay {
                Some((exact, _)) => exact,
                None => self.event(&saved.auth, Some(4), 1, Some(retained))?,
            };
            guard.check_before_effect()?;
            exact
        };
        fence.exact_event = Some(object_hash(&exact));
        // The second actual admission runs inside the bound import after the
        // component signature AND both blocking native audit signatures,
        // immediately before (never inside) the commit transaction. A failed
        // read refuses; the signed, unimported 4→1 is then never published.
        // The barrier carries no time: "successfully addressed per call" only.
        self.import_retry_progress(id, expected_preflight_hash, &exact, fence, port)
    }

    /// True only if the already verified local history is exactly in the
    /// retained state4 and its Reader question is decidably refused. Any other
    /// outcome (including errors) defers to the authoritative admitted path.
    fn local_reader_refusal(&self, saved: &SavedDestruction, retained: ObjectHash) -> bool {
        let Some(job) = saved.job.as_ref() else {
            return false;
        };
        let Ok(rebuilt) = reconstruct_imported_history(job, &saved.events, &saved.attestations)
        else {
            return false;
        };
        if rebuilt.state() != DestructionState::IncompleteUnreachableReplica
            || rebuilt.last_event_hash() != retained
        {
            return false;
        }
        let Ok((_, _, retained_time)) = retained_fields(saved, retained) else {
            return false;
        };
        let now = self.controller.head().preexisting_effective_now().value();
        matches!(
            self.retry_observation(saved, retained, retained_time, now),
            Err(Error::RetryReaderDuty)
        )
    }
    /// Current decision over the unchanged verified claim set. The retained
    /// state4 is bound by its signed fields only; see `claims::decide_retry`.
    fn retry_observation(
        &self,
        saved: &SavedDestruction,
        retained: ObjectHash,
        retained_time: UnixMillis,
        decision_time: UnixMillis,
    ) -> Result<RetryObservation, Error> {
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        let projection = project_imported_evidence(job, &saved.attestations)?;
        let kinds = duties(job)?;
        let duties = projection
            .replicas()
            .iter()
            .map(|(device, _)| {
                kinds
                    .iter()
                    .find(|(known, _)| known == device)
                    .map(|(_, kind)| (*device, *kind))
                    .ok_or(DestructionError::Target)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let positions = self.import_positions(saved)?;
        let retained_position = *positions.get(&retained).ok_or(DestructionError::Event)?;
        let facts = saved
            .attestations
            .iter()
            .map(|claim| {
                let fields = claim.fields();
                Ok((
                    ClaimFact {
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
                    },
                    positions.get(&claim.object_hash()).copied(),
                ))
            })
            .collect::<Result<Vec<_>, DestructionError>>()?;
        let decision = match claims::decide_retry(
            &duties,
            &facts,
            retained_position,
            retained_time,
            decision_time,
        )? {
            Ok(decision) => decision,
            Err(RetryRefusal::NoServer) => return Err(Error::RetryNoServerDuty),
            Err(RetryRefusal::Reader) => return Err(Error::RetryReaderDuty),
            Err(RetryRefusal::StillOpen) => return Err(Error::RetryDutyOpen),
        };
        let device = self
            .custodian
            .head()
            .active_certificate_fields(self.custodian.config().device_certificate_hash)
            .ok_or(Error::Configuration)?
            .device_id;
        // The own Writer duty is confirmed here, so its real-file absence is
        // rechecked under all holder locks in the final transaction.
        let local_success = facts.iter().any(|(claim, _)| {
            claim.device == device
                && claim.result == ClaimResult::Successful
                && claim.executed_at <= decision_time
        });
        Ok(RetryObservation {
            decision,
            projection,
            local_success,
        })
    }
    /// A decision without failure holds only before the earliest running
    /// backup deadline; crossing it during the action refuses.
    fn retry_guard(
        &self,
        decision: &ClaimDecision,
    ) -> Result<super::guard::RuntimeActionGuard<'_>, Error> {
        match decision.running_cutoff() {
            Some(cutoff) => self.action_guard_before(cutoff),
            None => self.action_guard(),
        }
    }
    pub(super) fn with_retry_commit(
        &self,
        saved: &SavedDestruction,
        fence: &RetryCommitFence,
        write: impl FnOnce(&StoreTransaction<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.retry_commit(saved, fence, true, write)
    }
    fn retry_commit(
        &self,
        saved: &SavedDestruction,
        fence: &RetryCommitFence,
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
            let exact = fence.exact_event.ok_or(DestructionError::Event)?;
            let fields = event_by_hash(saved, exact)?.fields();
            if rebuilt.state() != DestructionState::InProgress
                || rebuilt.last_event_hash() != exact
                || fields.from_state != Some(4)
                || fields.to_state != 1
                || fields.trigger_code != 5
                || fields.previous_event_object_hash != Some(fence.retained)
                || fields.executed_at != fence.event_time
            {
                return Err(DestructionError::Event.into());
            }
        } else if rebuilt.state() != fence.source_state
            || rebuilt.last_event_hash() != fence.source_last
        {
            return Err(DestructionError::SecurityConflict.into());
        }
        // The retained original is bound through its signed fields, never
        // recomputed from claims that may have arrived after it.
        if retained_fields(saved, fence.retained)?
            != (
                fence.retained_from,
                fence.retained_previous,
                fence.retained_time,
            )
        {
            return Err(DestructionError::Event.into());
        }
        let observation = self.retry_observation(
            saved,
            fence.retained,
            fence.retained_time,
            fence.decision_time,
        )?;
        if observation.decision != fence.decision {
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
        let mut guard = self.retry_guard(&fence.decision)?;
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
            // Pure filesystem checks only: no nested archive lock or DB entry.
            for (_, holder) in &holders {
                super::observations::validate_failure_holder(
                    job,
                    &observation.projection,
                    observation.local_success,
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
/// Duty classes of the signed job denominator, one kind per device.
fn duties(
    job: &ea_destruction::VerifiedImportedPreflight,
) -> Result<Vec<(DeviceId, DutyKind)>, Error> {
    let mut duties: Vec<(DeviceId, DutyKind)> = Vec::new();
    for (_, device, certificate_kind) in job.replicas() {
        let kind = match certificate_kind {
            0 => DutyKind::Writer,
            1 => DutyKind::Reader,
            6 => DutyKind::Server,
            _ => return Err(DestructionError::Target.into()),
        };
        match duties.iter().find(|(known, _)| known == device) {
            Some((_, existing)) if *existing != kind => {
                return Err(DestructionError::Target.into());
            }
            Some(_) => {}
            None => duties.push((*device, kind)),
        }
    }
    Ok(duties)
}
fn event_by_hash(
    saved: &SavedDestruction,
    hash: ObjectHash,
) -> Result<&ea_destruction::VerifiedDestructionEvent, Error> {
    saved
        .events
        .iter()
        .find(|event| event.object_hash() == hash)
        .ok_or(DestructionError::Event.into())
}
/// The retained original must be a conservative 1/2→4 with trigger 4.
fn retained_fields(
    saved: &SavedDestruction,
    retained: ObjectHash,
) -> Result<(u8, ObjectHash, UnixMillis), Error> {
    let fields = event_by_hash(saved, retained)?.fields();
    if !matches!(fields.from_state, Some(1 | 2)) || fields.to_state != 4 || fields.trigger_code != 4
    {
        return Err(DestructionError::Event.into());
    }
    Ok((
        fields.from_state.ok_or(DestructionError::Event)?,
        fields
            .previous_event_object_hash
            .ok_or(DestructionError::Event)?,
        fields.executed_at,
    ))
}
