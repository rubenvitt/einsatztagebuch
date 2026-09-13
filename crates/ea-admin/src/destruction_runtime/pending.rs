//! Explicit Pending progress for the unchanged original managed scope.
use super::status::SavedDestruction;
use super::*;
use ea_archive::ArchiveBackend;
use ea_destruction::{
    EvidenceReplicaStatus, LocalActionAuthorityGuard, VerifiedDestructionEvidence,
    project_imported_evidence, reconstruct_imported_history,
};
use ea_local_store::StoreTransaction;
use ea_types::UnixMillis;
use std::collections::BTreeMap;

/// Constructed only from verified original claims before component signing.
/// This is a private commit binding, never a signing or execution capability.
pub(super) struct PendingCommitFence {
    snapshot: ObjectHash,
    job: ObjectHash,
    authorization: ObjectHash,
    previous: ObjectHash,
    source_last: ObjectHash,
    source_state: DestructionState,
    event_time: UnixMillis,
    deadlines: BTreeMap<DeviceId, UnixMillis>,
    cutoff: UnixMillis,
    exact_event: Option<ObjectHash>,
}
impl PendingCommitFence {
    pub(super) fn snapshot(&self) -> ObjectHash {
        self.snapshot
    }
}
impl DestructionRuntime {
    /// Explicit current native action. Remote backup claims remain attestations
    /// supplied by their certified original signer; none are manufactured here.
    pub fn mark_pending_backup_progress(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        delivery: NativeDestructionDelivery<'_>,
    ) -> Result<NativeDestructionStatus, Error> {
        self.mark_pending_impl(id, expected_preflight_hash, delivery, || {})
    }
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn mark_pending_backup_progress_with_test_before_sign(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        delivery: NativeDestructionDelivery<'_>,
        before_sign: impl FnOnce(),
    ) -> Result<NativeDestructionStatus, Error> {
        self.mark_pending_impl(id, expected_preflight_hash, delivery, before_sign)
    }
    fn mark_pending_impl(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        delivery: NativeDestructionDelivery<'_>,
        before_sign: impl FnOnce(),
    ) -> Result<NativeDestructionStatus, Error> {
        self.project_writer_evidence(id, delivery)?;
        let snapshot = self.import_snapshot()?;
        let saved = self.read_saved(id)?;
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        if job.job_hash() != expected_preflight_hash {
            return Err(DestructionError::SecurityConflict.into());
        }
        let rebuilt = reconstruct_imported_history(job, &saved.events, &saved.attestations)?;
        let now = self.controller.head().preexisting_effective_now().value();
        let (_, deadlines) = self.pending_evidence(&saved, now)?;
        let cutoff = *deadlines.values().min().ok_or(DestructionError::Event)?;
        let (previous, event_time, replay) = match rebuilt.state() {
            DestructionState::InProgress => (rebuilt.last_event_hash(), now, None),
            DestructionState::PendingBackupExpiry => {
                let event = saved
                    .events
                    .iter()
                    .find(|e| e.object_hash() == rebuilt.last_event_hash())
                    .ok_or(DestructionError::Event)?;
                if event.fields().from_state != Some(1) || event.fields().to_state != 2 {
                    return Err(DestructionError::Event.into());
                }
                (
                    event
                        .fields()
                        .previous_event_object_hash
                        .ok_or(DestructionError::Event)?,
                    event.fields().executed_at,
                    Some(event.exact_bytes().to_vec()),
                )
            }
            _ => return Err(DestructionError::Event.into()),
        };
        let mut fence = PendingCommitFence {
            snapshot,
            job: job.job_hash(),
            authorization: saved.auth.object_hash(),
            previous,
            source_last: rebuilt.last_event_hash(),
            source_state: rebuilt.state(),
            event_time,
            deadlines,
            cutoff,
            exact_event: replay.as_deref().map(object_hash),
        };
        // No lock or DB transaction is held at this deterministic test seam.
        before_sign();
        self.pending_commit(&saved, &fence, false, |_| Ok(()))?;
        let exact = {
            let mut guard = self.action_guard_before(fence.cutoff)?;
            guard.check_before_effect()?;
            let exact = match replay {
                Some(exact) => exact,
                None => self.event(&saved.auth, Some(1), 2, Some(fence.previous))?,
            };
            guard.check_before_effect()?;
            exact
        };
        // This binds only the newly returned exact object; none of the
        // pre-sign snapshot, predecessor or cutoff values are replaced.
        fence.exact_event = Some(object_hash(&exact));
        self.import_pending_progress(id, expected_preflight_hash, &exact, fence)
    }

    /// Original verification is performed by the shared reducer first. This
    /// predicate adds current Pending admission, not another claim verifier.
    fn pending_evidence(
        &self,
        saved: &SavedDestruction,
        time: UnixMillis,
    ) -> Result<(VerifiedDestructionEvidence, BTreeMap<DeviceId, UnixMillis>), Error> {
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        let claims = saved
            .attestations
            .iter()
            .filter(|a| a.fields().executed_at <= time)
            .cloned()
            .collect::<Vec<_>>();
        let evidence = project_imported_evidence(job, &claims)?;
        if job.targets().is_empty() || evidence.replicas().is_empty() {
            return Err(DestructionError::Event.into());
        }
        let writer = self
            .custodian
            .head()
            .active_certificate_fields(self.custodian.config().device_certificate_hash)
            .ok_or(Error::Configuration)?
            .device_id;
        if !evidence.replicas().iter().any(|(device, result)| {
            *device == writer && matches!(result, EvidenceReplicaStatus::Successful(_))
        }) {
            return Err(DestructionError::Event.into());
        }
        let mut deadlines = BTreeMap::new();
        for (device, result) in evidence.replicas() {
            match result {
                EvidenceReplicaStatus::Successful(_) => {}
                EvidenceReplicaStatus::Unreachable => return Err(DestructionError::Event.into()),
                EvidenceReplicaStatus::PendingBackup => {
                    let kinds = job
                        .replicas()
                        .iter()
                        .filter(|(_, id, _)| id == device)
                        .map(|(_, _, kind)| *kind)
                        .collect::<BTreeSet<_>>();
                    if *device == writer
                        || kinds.len() != 1
                        || !kinds.iter().all(|kind| matches!(kind, 1 | 6))
                    {
                        return Err(DestructionError::Event.into());
                    }
                    let expiry = claims
                        .iter()
                        .filter(|a| a.fields().replica_id == *device.as_bytes())
                        .filter_map(|a| a.fields().backup_expiry_at)
                        .max()
                        .ok_or(DestructionError::Event)?;
                    if expiry <= time {
                        return Err(DestructionError::Event.into());
                    }
                    deadlines.insert(*device, expiry);
                }
            }
        }
        if deadlines.is_empty() {
            return Err(DestructionError::Event.into());
        }
        Ok((evidence, deadlines))
    }
    pub(super) fn with_pending_backup_commit(
        &self,
        saved: &SavedDestruction,
        fence: &PendingCommitFence,
        write: impl FnOnce(&StoreTransaction<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.pending_commit(saved, fence, true, write)
    }
    fn pending_commit(
        &self,
        saved: &SavedDestruction,
        fence: &PendingCommitFence,
        final_event: bool,
        write: impl FnOnce(&StoreTransaction<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        if job.job_hash() != fence.job || saved.auth.object_hash() != fence.authorization {
            return Err(DestructionError::SecurityConflict.into());
        }
        let rebuilt = reconstruct_imported_history(job, &saved.events, &saved.attestations)?;
        if final_event {
            let event = saved
                .events
                .iter()
                .find(|e| Some(e.object_hash()) == fence.exact_event)
                .ok_or(DestructionError::Event)?;
            if rebuilt.state() != DestructionState::PendingBackupExpiry
                || Some(rebuilt.last_event_hash()) != fence.exact_event
                || event.fields().from_state != Some(1)
                || event.fields().to_state != 2
                || event.fields().previous_event_object_hash != Some(fence.previous)
                || event.fields().executed_at != fence.event_time
            {
                return Err(DestructionError::Event.into());
            }
        } else if rebuilt.state() != fence.source_state
            || rebuilt.last_event_hash() != fence.source_last
        {
            return Err(DestructionError::SecurityConflict.into());
        }
        let (evidence, deadlines) = self.pending_evidence(
            saved,
            self.controller.head().preexisting_effective_now().value(),
        )?;
        if deadlines != fence.deadlines {
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
        let mut guard = self.action_guard_before(fence.cutoff)?;
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
                evidence.validate_archive(&holder.backend.as_archive_source())?;
                evidence.validate_managed_archive(&holder.backend)?;
            }
            guard.check_in(tx)?;
            write(tx)?;
            guard.check_in(tx)?;
            Ok(())
        })
    }
}
