//! Certified append-only completion of the original immutable managed scope.
use super::status::SavedDestruction;
use super::*;
use ea_archive::ArchiveBackend;
use ea_destruction::{LocalActionAuthorityGuard, reconstruct_imported_history};
use ea_local_store::StoreTransaction;

impl DestructionRuntime {
    /// Explicit native action. Complete evidence is necessary, but only the
    /// durably signed transition advances state. No remote claim is invented.
    pub fn complete_verified_progress(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        delivery: NativeDestructionDelivery<'_>,
    ) -> Result<NativeDestructionStatus, Error> {
        // Reuses current/original native authority, actual delivery admission,
        // custody observation and the durable original job/existing Started.
        let evidence = self.project_writer_evidence(id, delivery)?;
        if !evidence.all_managed_replicas_confirmed() {
            return Err(DestructionError::Event.into());
        }
        // This bound precedes component signing, not merely the later audits.
        let before = self.import_snapshot()?;
        let saved = self.read_saved(id)?;
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        if job.job_hash() != expected_preflight_hash {
            return Err(DestructionError::SecurityConflict.into());
        }
        let rebuilt = reconstruct_imported_history(job, &saved.events, &saved.attestations)?;
        if !rebuilt.evidence().all_managed_replicas_confirmed() {
            return Err(DestructionError::Event.into());
        }
        let exact = match rebuilt.state() {
            DestructionState::InProgress | DestructionState::PendingBackupExpiry => self.event(
                &saved.auth,
                Some(rebuilt.state().code()),
                DestructionState::CompleteManagedScope.code(),
                Some(rebuilt.last_event_hash()),
            )?,
            DestructionState::CompleteManagedScope => saved
                .events
                .iter()
                .find(|event| event.object_hash() == rebuilt.last_event_hash())
                .ok_or(DestructionError::Event)?
                .exact_bytes()
                .to_vec(),
            _ => return Err(DestructionError::Event.into()),
        };
        // Existing import verification checks the signature and evidence at
        // this actual effective time. It must never advance time to fit a claim.
        self.import_completion_progress(id, expected_preflight_hash, &exact, before)
    }

    /// Private completion-only commit fence. Archive locks follow a stable
    /// canonical order and end before any mirror/read/publication takes locks.
    pub(super) fn with_completion_commit(
        &self,
        saved: &SavedDestruction,
        before: ObjectHash,
        write: impl FnOnce(&StoreTransaction<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let rebuilt = reconstruct_imported_history(
            saved.job.as_ref().ok_or(DestructionError::Storage)?,
            &saved.events,
            &saved.attestations,
        )?;
        if rebuilt.state() != DestructionState::CompleteManagedScope
            || !rebuilt.evidence().all_managed_replicas_confirmed()
        {
            return Err(DestructionError::Event.into());
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
            if super::import::storage::snapshot_in(tx)? != before {
                return Err(DestructionError::SecurityConflict.into());
            }
            // Pure filesystem checks only: no nested archive lock or DB entry.
            // Signed local success cannot hide reintroduced originals/stubs.
            for (_, holder) in &holders {
                rebuilt
                    .evidence()
                    .validate_archive(&holder.backend.as_archive_source())?;
                rebuilt
                    .evidence()
                    .validate_managed_archive(&holder.backend)?;
            }
            guard.check_in(tx)?;
            write(tx)?;
            guard.check_in(tx)?;
            Ok(())
        })
    }
}
