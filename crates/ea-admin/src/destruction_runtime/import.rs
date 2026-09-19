//! Exact historical claims, admitted today by the actual native Admin.
//! Internal deterministic batch bytes are bound by an existing Login audit;
//! the separate Destruction audit references the actual last state event.
mod codec;
pub(super) mod storage;
use super::status::SavedDestruction;
use super::*;
use ea_audit::{AuditActorProof, SqliteLocalAuditRepository, TypedLocalAuditEvent};
use ea_destruction::{
    LocalActionAuthorityGuard, VerifiedDeletionAttestation, VerifiedDestructionEvent,
    reconstruct_imported_history,
};
use ea_format::{
    DestructionContextV1, GenericAuditContextV1, LocalAuditActionV1, LocalAuditOutcomeV1,
};
use std::collections::BTreeMap;
pub const MAX_NATIVE_DESTRUCTION_IMPORT_OBJECTS: usize = 256;
pub const MAX_NATIVE_DESTRUCTION_IMPORT_TOTAL_BYTES: usize = 16_777_216;
enum CommitBinding {
    Complete(ObjectHash),
    Pending(Box<super::pending::PendingCommitFence>),
    Failure(Box<super::failure::FailureCommitFence>),
    Retry(Box<super::retry::RetryCommitFence>),
}
impl CommitBinding {
    fn snapshot(&self) -> ObjectHash {
        match self {
            Self::Complete(snapshot) => *snapshot,
            Self::Pending(fence) => fence.snapshot(),
            Self::Failure(fence) => fence.snapshot(),
            Self::Retry(fence) => fence.snapshot(),
        }
    }
}
impl DestructionRuntime {
    pub fn import_signed_progress(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        exact_etb_objects: &[Vec<u8>],
    ) -> Result<NativeDestructionStatus, Error> {
        self.import_progress_bound(id, expected_preflight_hash, exact_etb_objects, None, None)
    }
    pub(super) fn import_completion_progress(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        exact_event: &[u8],
        before_signing: ObjectHash,
    ) -> Result<NativeDestructionStatus, Error> {
        self.import_progress_bound(
            id,
            expected_preflight_hash,
            &[exact_event.to_vec()],
            Some(CommitBinding::Complete(before_signing)),
            None,
        )
    }
    pub(super) fn import_pending_progress(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        exact_event: &[u8],
        fence: super::pending::PendingCommitFence,
    ) -> Result<NativeDestructionStatus, Error> {
        self.import_progress_bound(
            id,
            expected_preflight_hash,
            &[exact_event.to_vec()],
            Some(CommitBinding::Pending(Box::new(fence))),
            None,
        )
    }
    pub(super) fn import_failure_progress(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        exact_event: &[u8],
        fence: super::failure::FailureCommitFence,
    ) -> Result<NativeDestructionStatus, Error> {
        self.import_progress_bound(
            id,
            expected_preflight_hash,
            &[exact_event.to_vec()],
            Some(CommitBinding::Failure(Box::new(fence))),
            None,
        )
    }
    pub(super) fn import_retry_progress(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        exact_event: &[u8],
        fence: super::retry::RetryCommitFence,
        server: &mut dyn ServerReservationPort,
    ) -> Result<NativeDestructionStatus, Error> {
        self.import_progress_bound(
            id,
            expected_preflight_hash,
            &[exact_event.to_vec()],
            Some(CommitBinding::Retry(Box::new(fence))),
            Some(server),
        )
    }
    /// Actual delivery re-admission after all blocking signing work (component
    /// and both native audits) and immediately before the commit transaction,
    /// never inside it. Only the Retry binding supplies a port.
    fn readmit<'p>(
        &self,
        saved: &SavedDestruction,
        server: Option<&mut (dyn ServerReservationPort + 'p)>,
    ) -> Result<(), Error> {
        match server {
            Some(port) => self.with_started(
                saved,
                NativeDestructionDelivery::AuthenticatedServer(port),
                |_, _, _, _| Ok(()),
            ),
            None => Ok(()),
        }
    }
    fn commit_progress(
        &self,
        saved: &SavedDestruction,
        before: ObjectHash,
        binding: Option<&CommitBinding>,
        write: impl FnOnce(&ea_local_store::StoreTransaction<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match binding {
            Some(CommitBinding::Complete(_)) => self.with_completion_commit(saved, before, write),
            Some(CommitBinding::Pending(fence)) => {
                self.with_pending_backup_commit(saved, fence, write)
            }
            Some(CommitBinding::Failure(fence)) => self.with_failure_commit(saved, fence, write),
            Some(CommitBinding::Retry(fence)) => self.with_retry_commit(saved, fence, write),
            None => self.custodian.database().transaction(write),
        }
    }
    fn import_progress_bound(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        exact_etb_objects: &[Vec<u8>],
        binding: Option<CommitBinding>,
        mut server: Option<&mut dyn ServerReservationPort>,
    ) -> Result<NativeDestructionStatus, Error> {
        let objects = bounded_set(exact_etb_objects)?;
        self.unlock()?;
        let saved = self.read_saved(id)?;
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        if job.job_hash() != expected_preflight_hash {
            return Err(DestructionError::SecurityConflict.into());
        }
        self.validate_import_scope(&saved)?;
        let before = self.import_snapshot()?;
        if binding
            .as_ref()
            .is_some_and(|expected| expected.snapshot() != before)
        {
            return Err(DestructionError::SecurityConflict.into());
        }
        let mut saved = self.read_saved(id)?;
        if binding.is_some()
            && objects
                .values()
                .all(|exact| saved.events.iter().any(|e| e.exact_bytes() == exact))
        {
            // A bound last event may have arrived in a larger historical batch.
            // Reuse its exact event without adding a second batch or audit.
            self.readmit(&saved, server.as_deref_mut())?;
            self.commit_progress(&saved, before, binding.as_ref(), |_| Ok(()))?;
            self.publish_progress(&saved)?;
            return self.project_status(&saved);
        }
        let set = codec::encode_set(&saved, &objects)?;
        let set_hash = object_hash(&set);
        let key = [
            blob(saved.auth.fields().organization_id.as_bytes()),
            blob(id.as_bytes()),
            blob(set_hash.as_bytes()),
        ];
        if self.custodian.database().query_row("SELECT exact_context FROM destruction_import_batch WHERE organization_id=?1 AND destruction_id=?2 AND set_hash=?3",&key)?.is_some(){
            // read_saved checked the exact signed set and repaired both audit
            // mirrors. No second audit, fresh timestamp, or event is invented.
            if binding.is_some() {
                self.readmit(&saved, server.as_deref_mut())?;
                self.commit_progress(&saved, before, binding.as_ref(), |_| Ok(()))?;
            }
            self.publish_progress(&saved)?;
            return self.project_status(&saved)
        }
        self.add_import_claims(&mut saved, &objects)?;
        let rebuilt = reconstruct_imported_history(
            saved.job.as_ref().ok_or(DestructionError::Storage)?,
            &saved.events,
            &saved.attestations,
        )?;
        if rebuilt.state() == DestructionState::CompleteManagedScope
            && !rebuilt.evidence().all_managed_replicas_confirmed()
        {
            return Err(DestructionError::Event.into());
        }
        // In particular, a signature attributed to our own component cannot
        // hide actual retained local bytes.
        self.observe_artifacts(&saved)?;
        let head = self.controller.head();
        let exact_context = codec::encode_context(&set, head, rebuilt.last_event_hash())?;
        let context_hash = object_hash(&exact_context);
        let audit = self.controller.audit_service();
        let actor = self.require_session()?.proof();
        let login = audit
            .prepare_signed(
                AuditActorProof::OperatorSession(actor),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::Login(GenericAuditContextV1::new(Some(
                        context_hash,
                    ))),
                    outcome: LocalAuditOutcomeV1::Accepted,
                },
            )
            .map_err(|_| DestructionError::Audit)?;
        let state = audit
            .prepare_signed(
                AuditActorProof::OperatorSession(actor),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::Destruction(DestructionContextV1::new(
                        saved.auth.object_hash(),
                        rebuilt.last_event_hash(),
                    )),
                    outcome: LocalAuditOutcomeV1::Accepted,
                },
            )
            .map_err(|_| DestructionError::Audit)?;
        let signed_actor = ea_format::decode_local_audit_event(login.exact_bytes())?;
        if signed_actor.signer_certificate_object_hash().as_bytes()
            != self.controller.config().device_certificate_hash.as_bytes()
            || signed_actor.operator_binding_object_hash() != Some(actor.binding_object_hash())
            || signed_actor.device_id() != actor.device_id()
        {
            return Err(DestructionError::Audit.into());
        }
        // Audit signing can block on the actual native helper. Re-open selected
        // authority AND durable time bounds afterwards, then use the same Tx.
        self.require_same_fresh_action()?;
        self.verify_import_audits(
            &exact_context,
            login.exact_bytes(),
            state.exact_bytes(),
            &saved,
        )?;
        self.readmit(&saved, server)?;
        let mut guard = self.action_guard()?;
        let commit = |tx: &ea_local_store::StoreTransaction<'_>| {
            guard.check_in(tx)?;
            if storage::snapshot_in(tx)? != before {
                return Err(Error::Core(DestructionError::SecurityConflict));
            }
            SqliteLocalAuditRepository::append_prepared_in(tx, &login)
                .map_err(|_| DestructionError::Audit)?;
            SqliteLocalAuditRepository::append_prepared_in(tx, &state)
                .map_err(|_| DestructionError::Audit)?;
            tx.execute("INSERT INTO destruction_import_batch(organization_id,destruction_id,set_hash,context_hash,exact_context,login_audit_id,state_audit_id) VALUES(?1,?2,?3,?4,?5,?6,?7)",&[
                key[0].clone(),key[1].clone(),key[2].clone(),blob(context_hash.as_bytes()),blob(&exact_context),blob(login.id().as_bytes()),blob(state.id().as_bytes()),
            ])?;
            guard.check_in(tx)?;
            Ok::<_, Error>(())
        };
        self.commit_progress(&saved, before, binding.as_ref(), commit)?;
        self.mirror_audit(login.exact_bytes())?;
        self.mirror_audit(state.exact_bytes())?;
        let saved = self.read_saved(id)?;
        self.publish_progress(&saved)?;
        self.project_status(&saved)
    }
    pub(super) fn validate_import_scope(&self, saved: &SavedDestruction) -> Result<(), Error> {
        let repository = self.repository();
        let audit = self.controller.audit_service();
        let native = self.native(&audit, &repository);
        let resumed = native.resume_historical(
            &saved.auth,
            &saved.original,
            self.require_session()?.proof(),
        )?;
        let custody = self.custody();
        custody.observe_catalog(
            &ea_trust::verify_catalog_custody_authority(self.controller.trust())
                .map_err(|_| DestructionError::Registry)?,
        )?;
        for holder in &self.holders {
            custody.observe_local_archive(
                self.controller.head(),
                holder.custody_certificate,
                &holder.backend,
            )?;
        }
        let frozen = custody.freeze(&resumed)?;
        let durable = self
            .jobs()
            .load(&resumed, &frozen, self.controller.trust())?
            .ok_or(DestructionError::Storage)?;
        if object_hash(durable.preflight().exact_core_bytes())
            != saved
                .job
                .as_ref()
                .ok_or(DestructionError::Storage)?
                .job_hash()
        {
            return Err(DestructionError::SecurityConflict.into());
        }
        Ok(())
    }
    pub(super) fn add_import_claims(
        &self,
        saved: &mut SavedDestruction,
        objects: &BTreeMap<ObjectHash, Vec<u8>>,
    ) -> Result<(), Error> {
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        let start = saved
            .events
            .iter()
            .find(|e| e.fields().from_state == Some(0) && e.fields().to_state == 1)
            .ok_or(DestructionError::Event)?
            .fields()
            .executed_at;
        let preflight =
            ea_crypto::decode_destruction_preflight_core(job.core_bytes())?.observed_effective_now;
        let now = self.controller.head().preexisting_effective_now().value();
        for exact in objects.values() {
            let ea_format::ParsedArchiveObject::Trust(parsed) =
                ea_format::decode_exact_object(exact)?
            else {
                return Err(DestructionError::Format.into());
            };
            match parsed.value().decoded_payload()? {
                ea_format::DecodedTrustPayloadV1::DestructionTransition(_) => {
                    let claim = ea_destruction::verify_event_historical(
                        exact,
                        &saved.auth,
                        &saved.original,
                        now,
                    )?;
                    if !saved.events.iter().any(|e| e.exact_bytes() == exact) {
                        saved.events.push(claim);
                    }
                }
                ea_format::DecodedTrustPayloadV1::DeletionAttestation(_) => {
                    let claim = ea_destruction::verify_attestation_historical(
                        exact,
                        &saved.auth,
                        &saved.original,
                        now,
                    )?;
                    if claim.fields().executed_at < start
                        || claim.fields().executed_at.get() < preflight
                    {
                        return Err(DestructionError::Event.into());
                    }
                    if !saved.attestations.iter().any(|a| a.exact_bytes() == exact) {
                        saved.attestations.push(claim);
                    }
                }
                _ => return Err(DestructionError::Format.into()),
            }
        }
        let rebuilt = reconstruct_imported_history(job, &saved.events, &saved.attestations)?;
        if rebuilt.state() == DestructionState::CompleteManagedScope
            && !rebuilt.evidence().all_managed_replicas_confirmed()
        {
            return Err(DestructionError::Event.into());
        }
        Ok(())
    }
    pub(super) fn load_imports(&self, saved: &mut SavedDestruction) -> Result<(), Error> {
        let key = [
            blob(saved.auth.fields().organization_id.as_bytes()),
            blob(saved.auth.fields().destruction_id.as_bytes()),
        ];
        for row in self.rows("SELECT b.set_hash,b.context_hash,b.exact_context,l.exact_bytes,s.exact_bytes FROM destruction_import_batch b JOIN local_audit_event l ON l.event_id=b.login_audit_id JOIN local_audit_event s ON s.event_id=b.state_audit_id WHERE b.organization_id=?1 AND b.destruction_id=?2 ORDER BY b.insertion_sequence",&key)?{
            if object_hash(row.blob(2)?).as_bytes()!=row.blob(1)?{return Err(DestructionError::SecurityConflict.into())}
            let context=codec::decode_context(row.blob(2)?)?;
            let objects=codec::decode_set(context.set,saved)?;
            if object_hash(context.set).as_bytes()!=row.blob(0)?{return Err(DestructionError::SecurityConflict.into())}
            self.add_import_claims(saved,&objects)?;
            self.verify_import_audits(row.blob(2)?,row.blob(3)?,row.blob(4)?,saved)?;
            self.mirror_audit(row.blob(3)?)?;
            self.mirror_audit(row.blob(4)?)?;
        }
        Ok(())
    }
    /// Local, audit-bound arrival order of the already verified import batches
    /// (`insertion_sequence`): the first batch index of every exact object.
    /// Covered by the snapshot hash; confers no authority of its own.
    pub(super) fn import_positions(
        &self,
        saved: &SavedDestruction,
    ) -> Result<BTreeMap<ObjectHash, usize>, Error> {
        let key = [
            blob(saved.auth.fields().organization_id.as_bytes()),
            blob(saved.auth.fields().destruction_id.as_bytes()),
        ];
        let mut positions = BTreeMap::new();
        for (index, row) in self.rows("SELECT exact_context FROM destruction_import_batch WHERE organization_id=?1 AND destruction_id=?2 ORDER BY insertion_sequence",&key)?.iter().enumerate() {
            let context = codec::decode_context(row.blob(0)?)?;
            for hash in codec::decode_set(context.set, saved)?.into_keys() {
                positions.entry(hash).or_insert(index);
            }
        }
        Ok(positions)
    }
    pub(super) fn publish_progress(&self, saved: &SavedDestruction) -> Result<(), Error> {
        use ea_archive::{ArchiveBackend, ArchivePath};
        let objects = std::iter::once(saved.auth.exact_bytes())
            .chain(
                saved
                    .events
                    .iter()
                    .map(VerifiedDestructionEvent::exact_bytes),
            )
            .chain(
                saved
                    .attestations
                    .iter()
                    .map(VerifiedDeletionAttestation::exact_bytes),
            );
        let objects = objects.collect::<Vec<_>>();
        for holder in &self.holders {
            let mut guard = self.action_guard()?;
            let _lock = holder
                .backend
                .acquire_writer_lock()
                .map_err(|_| DestructionError::Storage)?;
            for exact in &objects {
                guard.check_before_effect()?;
                let path = ArchivePath::in_dir(
                    ea_archive::DESTRUCTIONS_DIR_V1,
                    &format!("{}.etb", hex_hash(object_hash(exact).as_bytes())),
                )
                .map_err(|_| DestructionError::Storage)?;
                let ea_format::ParsedArchiveObject::Trust(parsed) =
                    ea_format::decode_exact_object(exact)?
                else {
                    return Err(DestructionError::Format.into());
                };
                holder
                    .backend
                    .create_if_absent(&path, parsed.exact_bytes())
                    .map_err(|_| DestructionError::Storage)?;
                holder
                    .backend
                    .sync_file(&path)
                    .map_err(|_| DestructionError::Storage)?;
                holder
                    .backend
                    .sync_directory(&path)
                    .map_err(|_| DestructionError::Storage)?;
                if std::fs::read(holder.backend.root().join(path.as_str()))
                    .map_err(|_| DestructionError::Storage)?
                    != *exact
                {
                    return Err(DestructionError::SecurityConflict.into());
                }
            }
        }
        self.check_host()
    }
}
fn bounded_set(input: &[Vec<u8>]) -> Result<BTreeMap<ObjectHash, Vec<u8>>, Error> {
    if input.is_empty() || input.len() > MAX_NATIVE_DESTRUCTION_IMPORT_OBJECTS {
        return Err(DestructionError::Format.into());
    }
    let mut total = 0usize;
    let mut objects = BTreeMap::new();
    for exact in input {
        total = total
            .checked_add(exact.len())
            .ok_or(DestructionError::Format)?;
        if exact.is_empty()
            || exact.len() > ea_format::ETB_MAX_RAW_BYTES_V1
            || total > MAX_NATIVE_DESTRUCTION_IMPORT_TOTAL_BYTES
        {
            return Err(DestructionError::Format.into());
        }
        let hash = object_hash(exact);
        if let Some(old) = objects.insert(hash, exact.clone())
            && old != *exact
        {
            return Err(DestructionError::SecurityConflict.into());
        }
    }
    Ok(objects)
}
fn hex_hash(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
