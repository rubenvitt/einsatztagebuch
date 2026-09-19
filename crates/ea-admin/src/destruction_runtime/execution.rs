use super::*;
impl DestructionRuntime {
    /// Opaque evidence only; a separate normal Writer must obtain its own
    /// Finalize presence and retain the existing publication/recovery fence.
    pub fn project_writer_evidence(
        &mut self,
        id: DestructionId,
        delivery: NativeDestructionDelivery<'_>,
    ) -> Result<ea_destruction::VerifiedDestructionEvidence, Error> {
        self.unlock()?;
        let saved = self.read_saved(id)?;
        if !saved
            .events
            .iter()
            .any(|event| event.fields().from_state == Some(0) && event.fields().to_state == 1)
        {
            return Err(DestructionError::Event.into());
        }
        let mut result = None;
        self.with_started(&saved, delivery, |context, start, _, _| {
            let evidence = self
                .jobs()
                .project_evidence(context, start, &saved.attestations)?;
            evidence.validate_archive(&self.primary()?.as_archive_source())?;
            evidence.validate_managed_archive(self.primary()?)?;
            result = Some(evidence);
            Ok(())
        })?;
        self.check_host()?;
        result.ok_or(DestructionError::Storage.into())
    }

    /// Exact irreversible start. Physical deletion is a separate resumable call.
    pub fn start(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
        delivery: NativeDestructionDelivery<'_>,
    ) -> Result<NativeDestructionStatus, Error> {
        self.unlock()?;
        let saved = self.read_saved(id)?;
        let imported = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        if imported.job_hash() != expected_preflight_hash {
            return Err(DestructionError::SecurityConflict.into());
        }
        self.with_started(&saved, delivery, |_, _, _, _| Ok(()))?;
        self.status_saved(&saved.auth)
    }
    pub fn resume_local(
        &mut self,
        id: DestructionId,
        delivery: NativeDestructionDelivery<'_>,
    ) -> Result<NativeDestructionStatus, Error> {
        self.unlock()?;
        let saved = self.read_saved(id)?;
        if !saved
            .events
            .iter()
            .any(|e| e.fields().from_state == Some(0) && e.fields().to_state == 1)
        {
            return Err(DestructionError::Event.into());
        }
        self.with_started(&saved, delivery, |context, start, native, proof| {
            let jobs = self.jobs();
            let locations = self
                .holders
                .iter()
                .map(|holder| ea_destruction::LocalDestructionExecution {
                    backend: &holder.backend,
                    custody_certificate: holder.custody_certificate,
                    component_certificate: self.component,
                    signer: &self.signer,
                })
                .collect::<Vec<_>>();
            let mut guard = self.action_guard()?;
            jobs.attest_local_replica_guarded(
                context,
                start,
                native,
                proof,
                &locations,
                &mut |_| Ok(()),
                &mut guard,
            )?;
            Ok(())
        })?;
        self.status_saved(&saved.auth)
    }
    pub(super) fn with_started(
        &self,
        saved: &super::status::SavedDestruction,
        delivery: NativeDestructionDelivery<'_>,
        operation: impl FnOnce(
            &ea_destruction::DestructionExecutionContext<'_, '_>,
            &ea_destruction::DurableDestructionStart,
            &ea_destruction::DestructionRequestService<'_>,
            &ea_operator::OperatorSessionProof,
        ) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let imported = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        let session = self.require_session()?;
        let repository = self.repository();
        let audit = self.controller.audit_service();
        let native = self.native(&audit, &repository);
        let resumed = native.resume_historical(&saved.auth, &saved.original, session.proof())?;
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
        let jobs = self.jobs();
        let job = jobs
            .load(&resumed, &frozen, self.controller.trust())?
            .ok_or(DestructionError::Storage)?;
        if object_hash(job.preflight().exact_core_bytes()) != imported.job_hash() {
            return Err(DestructionError::SecurityConflict.into());
        }
        let barrier = match delivery {
            NativeDestructionDelivery::AuthenticatedServer(port) => {
                ea_destruction::confirm_delivery_barrier(&saved.auth, port)?
            }
            NativeDestructionDelivery::NoRegisteredServer => {
                ea_destruction::confirm_no_registered_server(
                    &saved.auth,
                    &saved.original,
                    self.controller.head(),
                    &ea_trust::verify_catalog_custody_authority(self.controller.trust())
                        .map_err(|_| DestructionError::Registry)?,
                    imported,
                    &frozen,
                )?
            }
        };
        // An authenticated network exchange is blocking and cannot preserve an
        // obsolete native context. Compare persisted bounds as well as Head.
        self.require_same_fresh_action()?;
        let context = ea_destruction::DestructionExecutionContext {
            resumed: &resumed,
            job: &job,
            custody: &frozen,
            barrier: &barrier,
            trust: self.controller.trust(),
        };
        let existing = saved
            .events
            .iter()
            .find(|e| e.fields().from_state == Some(0) && e.fields().to_state == 1);
        let exact = match existing {
            Some(event) => event.exact_bytes().to_vec(),
            None => self.event(
                &saved.auth,
                Some(0),
                1,
                Some(resumed.request().event().object_hash()),
            )?,
        };
        let start = jobs.start_execution_guarded(
            &context,
            &exact,
            &native,
            session.proof(),
            &mut self.action_guard()?,
        )?;
        // Writer's atomic request/event/audit transaction is authoritative.
        // Failure copying the same exact audit to Admin prevents success and
        // any physical action; retry repairs the identical row.
        self.mirror_audit(start.exact_audit_bytes())?;
        self.check_host()?;
        operation(&context, &start, &native, session.proof())
    }
    pub fn administration(&mut self) -> Result<NativeDestructionAdministration, Error> {
        self.refresh()?;
        self.require_session()?;
        let mut ids = Vec::new();
        for row in self.rows("SELECT destruction_id FROM destruction_request WHERE organization_id=?1 ORDER BY destruction_id",&[blob(self.controller.anchor().organization_id().as_bytes())])?{
            let id=DestructionId::try_from(row.blob(0)?).map_err(|_|DestructionError::Format)?;
            let saved=self.read_saved(id)?;
            // Never list an apparently valid process whose signed chain conflicts.
            self.project_status(&saved)?;
            ids.push(id);
        }
        let policy = &self.controller.head().policy_fields().retention_policy;
        Ok(NativeDestructionAdministration {
            privacy_decision_enabled: policy.destruction_enabled
                && policy.eds_privacy_decision_document_hash.is_some(),
            policy_hash: self.controller.head().policy_object_hash(),
            known_destruction_ids: ids,
        })
    }
}
