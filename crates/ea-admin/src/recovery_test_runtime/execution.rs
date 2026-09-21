//! Reopens the actual restored sources and keeps all authority in the separate
//! current native installation. No caller-supplied completeness or identity.
use super::*;
use ea_operator::OsAccountProvider;
use ea_recovery::VerifiedCompletedRecoveryReport;
use ea_types::{ChainSequence, RegistryVersion, UnixMillis};

impl RecoveryTestRuntime {
    fn reauthenticate_observed(
        &self,
        context: Option<ea_types::Hash32>,
        guide: &dyn RecoveryTestGuide,
        observer: &mut dyn RecoverySessionObserver,
    ) -> Result<std::sync::Arc<ea_operator::OperatorSessionProof>, RecoveryRuntimeError> {
        guide.ensure_active()?;
        let session = match context {
            Some(context) => self
                .runtime
                .reauthenticate_for_context(ReauthPurpose::RecoveryTest, context),
            None => self.runtime.reauthenticate_for(ReauthPurpose::RecoveryTest),
        }?;
        // A successful return includes native presence, the durable Login and
        // final current gates. Move the unique proof; never clone its fields or
        // retain the operator profile in a host progress/session mailbox.
        let (profile, proof) = session.into_parts();
        drop(profile);
        let proof = std::sync::Arc::new(proof);
        guide.ensure_active()?;
        observer.verified_session(std::sync::Arc::clone(&proof))?;
        guide.ensure_active()?;
        self.runtime.ensure_current()?;
        Ok(proof)
    }

    /// The immutable opening snapshot binds the report, never a new action.
    /// A user wait may outlive that snapshot's runtime lifetime; a provider
    /// operation may not outlive its separately refreshed action context.
    fn refresh_after_guided_wait(
        &mut self,
        opening: &OperatorRuntime,
    ) -> Result<(), RecoveryRuntimeError> {
        let fresh = self.runtime.reopened_for_action()?;
        fresh.ensure_current()?;
        let crate::operator_runtime::OperatorRuntimeConfig {
            archive_directory,
            database_path,
            device_certificate_hash,
            binding_object_hash,
            role,
            purpose,
            admin_certificate_hash,
            admin_binding_object_hash,
            ceremony_exchange_directory,
            authority,
            target_certificate_hash,
        } = opening.config();
        let config = fresh.config();
        if config.archive_directory != *archive_directory
            || config.database_path != *database_path
            || config.device_certificate_hash != *device_certificate_hash
            || config.binding_object_hash != *binding_object_hash
            || config.role != *role
            || config.purpose != *purpose
            || config.admin_certificate_hash != *admin_certificate_hash
            || config.admin_binding_object_hash != *admin_binding_object_hash
            || config.ceremony_exchange_directory != *ceremony_exchange_directory
            || config.authority != *authority
            || config.target_certificate_hash != *target_certificate_hash
            || !std::sync::Arc::ptr_eq(fresh.native(), opening.native())
            || fresh.anchor().trust_anchor_hash() != opening.anchor().trust_anchor_hash()
            || fresh.head().registry_head_hash() != opening.head().registry_head_hash()
            || fresh.head().registry_version() != opening.head().registry_version()
            || fresh.next_sequence() != opening.next_sequence()
            || !fresh
                .head()
                .preexisting_effective_now()
                .has_same_persisted_bounds(opening.head().preexisting_effective_now())
        {
            return Err(RecoveryTestError::Source.into());
        }
        let certificate = opening
            .head()
            .active_certificate_fields(*device_certificate_hash)
            .ok_or(RecoveryTestError::Operator)?;
        let binding = opening
            .head()
            .active_operator_binding_fields(*binding_object_hash)
            .ok_or(RecoveryTestError::Operator)?;
        let account = fresh
            .native()
            .os_account_binding_hash(fresh.anchor().organization_id(), certificate.device_id)
            .map_err(OperatorRuntimeError::from)?;
        if account != binding.os_account_binding_hash {
            return Err(RecoveryTestError::Operator.into());
        }
        self.runtime = fresh;
        Ok(())
    }

    pub(super) fn open_bound_sources(
        &self,
        inventory: &KeyInventory,
        path: &Path,
    ) -> Result<RestoredRecoverySource, RecoveryRuntimeError> {
        let (binding, scope) = self.checked_restore_binding(inventory)?;
        let provider = self.runtime.signing_provider();
        let database = ea_local_store::EncryptedDatabase::open_recovery_source_exact(
            path,
            binding.migrations_hash,
            provider.as_ref(),
            &provider.handle(ea_key_provider::SecretPurpose::LocalDatabaseKey),
        )?;
        if database.recovery_source_content_hash()? != binding.content_hash {
            return Err(RecoveryTestError::Source.into());
        }
        Ok(RestoredRecoverySource {
            database,
            scope,
            content_hash: binding.content_hash,
        })
    }

    fn checked_restore_binding(
        &self,
        inventory: &KeyInventory,
    ) -> Result<(RestoreBinding, VerifiedRecoverySource), RecoveryRuntimeError> {
        self.runtime.ensure_current()?;
        let row = self.runtime.database().query_row(
            "SELECT r.source_hash,r.snapshot_hash,r.migrations_hash,r.target_machine,r.target_installation,r.restored_content_hash,r.registry_version,r.registry_head,r.proposed_sequence,r.exact_envelope,a.exact_bytes FROM recovery_restore_binding r JOIN local_audit_event a ON a.event_id=r.restore_audit_event_id WHERE r.singleton=0",
            &[],
        )?.ok_or(RecoveryTestError::Incomplete)?;
        let hash = |i| -> Result<[u8; 32], RecoveryRuntimeError> {
            row.blob(i)?
                .try_into()
                .map_err(|_| RecoveryTestError::Source.into())
        };
        let number = |i| -> Result<u64, RecoveryRuntimeError> {
            u64::try_from(row.integer(i)?).map_err(|_| RecoveryTestError::Source.into())
        };
        let binding = RestoreBinding {
            source_hash: hash(0)?,
            snapshot_hash: hash(1)?,
            migrations_hash: hash(2)?,
            machine: hash(3)?,
            installation: hash(4)?,
            content_hash: hash(5)?,
            registry_version: number(6)?,
            registry_head: hash(7)?,
            sequence: number(8)?,
        };
        let machine = ea_key_provider::measure_native_machine_identity()
            .map_err(|_| RecoveryTestError::Machine)?;
        if binding.machine != *machine.fingerprint().as_bytes()
            || binding.installation != *self.runtime.native().installation_id().as_bytes()
            || binding.registry_version != self.runtime.head().registry_version().get()
            || binding.registry_head != *self.runtime.head().registry_head_hash().as_bytes()
            || binding.sequence != self.runtime.next_sequence().get()
        {
            return Err(RecoveryTestError::Source.into());
        }
        let source = self.archive_source()?;
        let scope = ea_recovery::verify_recovery_source(
            row.blob(9)?,
            &source,
            self.runtime.anchor(),
            inventory,
            self.runtime.head().preexisting_effective_now().value(),
        )?;
        let f = scope.core().fields();
        if scope.envelope_hash().as_bytes() != &binding.source_hash
            || f.snapshot_hash != binding.snapshot_hash
            || f.migrations_hash != binding.migrations_hash
            || f.source_machine == binding.machine
            || f.source_installation == binding.installation
        {
            return Err(RecoveryTestError::Source.into());
        }
        let historical = ea_verify::historical_registry_head(
            self.runtime.inventory(),
            self.runtime.anchor(),
            RegistryVersion::new(binding.registry_version),
            ObjectHash::try_from(binding.registry_head.as_slice())
                .map_err(|_| RecoveryTestError::Source)?,
            ChainSequence::new(binding.sequence),
            self.runtime.head().preexisting_effective_now().value(),
        )
        .ok_or(RecoveryTestError::Source)?;
        let audit = ea_format::decode_local_audit_event(row.blob(10)?)
            .map_err(|_| RecoveryTestError::Audit)?;
        if audit.effective_now() > self.runtime.head().preexisting_effective_now().value() {
            return Err(RecoveryTestError::Audit.into());
        }
        ea_recovery::verify_recovery_audit_context(
            row.blob(10)?,
            &historical,
            binding.context_hash()?,
            audit.effective_now(),
            LocalAuditOutcomeV1::Accepted,
        )?;
        Ok((binding, scope))
    }

    pub fn run_restored_test(
        &mut self,
        restored: &RestoredRecoverySource,
        inventory: &KeyInventory,
        media: &[RecoveryTestMediumSource],
    ) -> Result<VerifiedCompletedRecoveryReport, RecoveryRuntimeError> {
        match self.run_restored_test_report(restored, inventory, media)? {
            RecoveryTestOutcome::Completed(report) => Ok(report),
            RecoveryTestOutcome::Failed(_) => Err(RecoveryTestError::Incomplete.into()),
        }
    }

    pub fn run_restored_test_report(
        &mut self,
        restored: &RestoredRecoverySource,
        inventory: &KeyInventory,
        media: &[RecoveryTestMediumSource],
    ) -> Result<RecoveryTestOutcome, RecoveryRuntimeError> {
        let mut ids = std::collections::BTreeSet::new();
        for row in media {
            if !ids.insert(row.medium_id_hash)
                || !inventory
                    .media()
                    .iter()
                    .any(|m| m.pseudonymous_id_hash() == row.medium_id_hash)
            {
                return Err(RecoveryTestError::Inventory.into());
            }
        }
        self.run_restored_test_guided(restored, inventory, &mut guided::BatchGuide { media })
    }

    pub fn run_restored_test_guided(
        &mut self,
        restored: &RestoredRecoverySource,
        inventory: &KeyInventory,
        guide: &mut dyn RecoveryTestGuide,
    ) -> Result<RecoveryTestOutcome, RecoveryRuntimeError> {
        self.run_restored_test_guided_with_session_observer(
            restored,
            inventory,
            guide,
            &mut guided::NoopSessionObserver,
        )
    }

    pub fn run_restored_test_guided_with_session_observer(
        &mut self,
        restored: &RestoredRecoverySource,
        inventory: &KeyInventory,
        guide: &mut dyn RecoveryTestGuide,
        observer: &mut dyn RecoverySessionObserver,
    ) -> Result<RecoveryTestOutcome, RecoveryRuntimeError> {
        guide.ensure_active()?;
        let _locks = self.archive_locks()?;
        self.runtime.refresh_for_action()?;
        let (binding, scope) = self.checked_restore_binding(inventory)?;
        if scope.envelope_hash() != restored.scope.envelope_hash()
            || binding.content_hash != restored.content_hash
        {
            return Err(RecoveryTestError::Source.into());
        }
        restored.verify_unchanged()?;
        guide.ensure_active()?;
        let mut native_slots = std::collections::BTreeSet::new();
        let source = self.archive_source()?;
        let opening = self.runtime.reopened_for_action()?;
        let mut run = ea_recovery::RecoveryTestRun::new(
            &scope,
            &source,
            opening.anchor(),
            inventory,
            opening.head(),
            opening.native().installation_id(),
        )?;
        for (index, medium) in inventory.media().iter().enumerate() {
            guide.ensure_active()?;
            let request = RecoveryMediumRequest::new(
                run.run_id(),
                medium,
                index + 1,
                inventory.media().len(),
            );
            let input = guide.request_medium(&request)?;
            // Waiting never retains a SQLCipher transaction. A host epoch can
            // only cancel; actual native authority and source are independent.
            guide.ensure_active()?;
            self.refresh_after_guided_wait(&opening)?;
            restored.verify_unchanged()?;
            let after_wait = self.archive_source()?;
            if ea_recovery::recovery_archive_inventory_hash(&after_wait)?
                != scope.core().fields().archive_inventory_hash
            {
                return Err(RecoveryTestError::Source.into());
            }
            if let Some(input) = input {
                if let RecoveryMediumInput::NativeSigningSlot(slot) = &input
                    && !native_slots.insert(*slot)
                {
                    return Err(RecoveryTestError::Inventory.into());
                }
                if let Err(error) = inputs::require_medium_source(medium, &input) {
                    run.record_medium_failure(request.medium_id_hash(), error, None)?;
                } else {
                    guide.ensure_active()?;
                    self.reauthenticate_observed(None, guide, observer)?;
                    guide.ensure_active()?;
                    let result = match &input {
                        RecoveryMediumInput::Offline(source)
                            if medium.role() == ea_recovery::RecoveryKeyRole::RecoveryRecipient =>
                        {
                            match ea_recovery::resolve_recipient_key(source) {
                                Ok(key) => run.test_recovery(request.medium_id_hash(), &key),
                                Err(_) => Err(RecoveryTestError::Key),
                            }
                        }
                        RecoveryMediumInput::Offline(source) => {
                            match ea_recovery::resolve_signing_key(source) {
                                Ok(key) => run.test_signing(request.medium_id_hash(), &key),
                                Err(_) => Err(RecoveryTestError::Key),
                            }
                        }
                        RecoveryMediumInput::NativeSigningSlot(slot) => {
                            match self.native_recovery_adapter(medium, *slot) {
                                Ok(adapter) => run.test_signing(request.medium_id_hash(), &adapter),
                                Err(RecoveryRuntimeError::Test(error)) => Err(error),
                                Err(error) => return Err(error),
                            }
                        }
                    };
                    // Key handles and decrypted protected buffers have dropped
                    // before host progress or another medium can be requested.
                    guide.ensure_active()?;
                    self.runtime.ensure_same_action_authority()?;
                    if let Err(error) = result {
                        run.record_medium_failure(request.medium_id_hash(), error, None)?;
                    }
                    self.reauthenticate_observed(None, guide, observer)?;
                    guide.ensure_active()?;
                }
            }
            // The owned private routing input has dropped at this boundary.
            self.runtime.ensure_same_action_authority()?;
            restored.verify_unchanged()?;
            let after = self.archive_source()?;
            if ea_recovery::recovery_archive_inventory_hash(&after)?
                != scope.core().fields().archive_inventory_hash
            {
                return Err(RecoveryTestError::Source.into());
            }
            guide.ensure_active()?;
            guide.medium_result(&RecoveryMediumObservation::new(
                &request,
                run.medium_check(request.medium_id_hash())?,
            ))?;
            guide.ensure_active()?;
            self.refresh_after_guided_wait(&opening)?;
        }
        guide.ensure_active()?;
        let outcome = run.finish_report()?;
        // The borrowed run used the opening selection for its sample report.
        // Completion needs a new actual native wall-clock selection after all
        // media are consumed, with identical scope and current authority.
        self.runtime.refresh_for_action()?;
        let (finished_binding, finished_scope) = self.checked_restore_binding(inventory)?;
        if finished_binding.content_hash != binding.content_hash
            || finished_scope.envelope_hash() != scope.envelope_hash()
        {
            return Err(RecoveryTestError::Source.into());
        }
        restored.verify_unchanged()?;
        guide.ensure_active()?;
        self.runtime.ensure_current()?;
        let machine = match &outcome {
            ea_recovery::RecoveryRunOutcome::Completed(run) => run.machine_fingerprint(),
            ea_recovery::RecoveryRunOutcome::Failed(run) => run.machine_fingerprint(),
        };
        if machine.as_bytes() != &binding.machine {
            return Err(RecoveryTestError::Machine.into());
        }
        let now = self.runtime.head().preexisting_effective_now().value();
        let completed = match outcome {
            ea_recovery::RecoveryRunOutcome::Completed(run) => run,
            ea_recovery::RecoveryRunOutcome::Failed(run) => {
                let core = ea_recovery::RecoveryFailureCore::new(&run, binding.content_hash, now)?;
                guide.ensure_active()?;
                let session =
                    self.reauthenticate_observed(Some(core.context_hash()), guide, observer)?;
                restored.verify_unchanged()?;
                let after = self.archive_source()?;
                if ea_recovery::recovery_archive_inventory_hash(&after)?
                    != scope.core().fields().archive_inventory_hash
                {
                    return Err(RecoveryTestError::Source.into());
                }
                guide.ensure_active()?;
                let audit = self
                    .runtime
                    .audit_service()
                    .prepare_signed(
                        AuditActorProof::OperatorSession(session.as_ref()),
                        TypedLocalAuditEvent {
                            action: LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(
                                Some(ObjectHash::from(core.context_hash())),
                            )),
                            outcome: LocalAuditOutcomeV1::Failed,
                        },
                    )
                    .map_err(|_| RecoveryTestError::Audit)?;
                let exact = ea_recovery::recovery_failure_envelope(&core, audit.exact_bytes())?;
                let report = ea_recovery::verify_failed_recovery_report(
                    &exact,
                    &scope,
                    &source,
                    self.runtime.anchor(),
                    inventory,
                    now,
                )?;
                guide.ensure_active()?;
                self.runtime.ensure_current()?;
                self.runtime.database().transaction::<_,RecoveryRuntimeError>(|tx|{
                    guide.ensure_active()?;
                    SqliteLocalAuditRepository::append_prepared_in(tx,&audit).map_err(|_|RecoveryTestError::Audit)?;
                    tx.execute("INSERT INTO recovery_test_failure(failure_hash,source_hash,context_hash,exact_report,failure_audit_event_id,failed_at) VALUES(?1,?2,?3,?4,?5,?6)",&[
                        StoreValue::Blob(report.envelope_hash().as_bytes().to_vec()),
                        StoreValue::Blob(scope.envelope_hash().as_bytes().to_vec()),
                        StoreValue::Blob(report.context_hash().as_bytes().to_vec()),
                        StoreValue::Blob(exact),StoreValue::Blob(audit.id().as_bytes().to_vec()),
                        StoreValue::Integer(now.get()),
                    ])?;
                    guide.ensure_active()?;
                    Ok(())
                })?;
                // The successful durable commit is the terminal point. Late
                // cancellation cannot revoke its signed historical result;
                // readiness and host visibility retain their own fresh gates.
                return Ok(RecoveryTestOutcome::Failed(report));
            }
        };
        let interval = i64::try_from(self.runtime.head().policy_fields().restore_test_interval_ms)
            .map_err(|_| RecoveryTestError::Source)?;
        let next_due = UnixMillis::new(
            now.get()
                .checked_add(interval)
                .ok_or(RecoveryTestError::Source)?,
        );
        let core = ea_recovery::RecoveryCompletionCore::new(
            &completed,
            binding.content_hash,
            now,
            next_due,
        )?;
        guide.ensure_active()?;
        let session = self.reauthenticate_observed(Some(core.context_hash()), guide, observer)?;
        restored.verify_unchanged()?;
        let after = self.archive_source()?;
        if ea_recovery::recovery_archive_inventory_hash(&after)?
            != scope.core().fields().archive_inventory_hash
        {
            return Err(RecoveryTestError::Source.into());
        }
        guide.ensure_active()?;
        let audit = self
            .runtime
            .audit_service()
            .prepare_signed(
                AuditActorProof::OperatorSession(session.as_ref()),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(
                        ObjectHash::from(core.context_hash()),
                    ))),
                    outcome: LocalAuditOutcomeV1::Completed,
                },
            )
            .map_err(|_| RecoveryTestError::Audit)?;
        let exact = ea_recovery::recovery_completion_envelope(&core, audit.exact_bytes())?;
        let report = ea_recovery::verify_completed_recovery_report(
            &exact,
            &scope,
            &source,
            self.runtime.anchor(),
            inventory,
            now,
        )?;
        guide.ensure_active()?;
        self.runtime.ensure_current()?;
        self.runtime.database().transaction::<_,RecoveryRuntimeError>(|tx| {
            guide.ensure_active()?;
            SqliteLocalAuditRepository::append_prepared_in(tx,&audit).map_err(|_|RecoveryTestError::Audit)?;
            tx.execute("INSERT INTO recovery_test_report(report_hash,source_hash,exact_report,completion_audit_event_id,completed_at,next_due_at) VALUES(?1,?2,?3,?4,?5,?6)",&[
                StoreValue::Blob(report.envelope_hash().as_bytes().to_vec()),StoreValue::Blob(scope.envelope_hash().as_bytes().to_vec()),
                StoreValue::Blob(exact.clone()),StoreValue::Blob(audit.id().as_bytes().to_vec()),
                StoreValue::Integer(now.get()),StoreValue::Integer(next_due.get()),
            ])?;
            guide.ensure_active()?;
            Ok(())
        })?;
        // All abort/current checks precede the irreversible durable commit.
        // A later host denial must not turn its completed report into an error.
        Ok(RecoveryTestOutcome::Completed(report))
    }

    pub fn read_completed_report(
        &mut self,
        inventory: &KeyInventory,
        restored: &Path,
    ) -> Result<Option<VerifiedCompletedRecoveryReport>, RecoveryRuntimeError> {
        let _locks = self.archive_locks()?;
        self.runtime.refresh_for_action()?;
        let restored = self.open_bound_sources(inventory, restored)?;
        let row = self.runtime.database().query_row(
            "SELECT r.report_hash,r.source_hash,r.exact_report,r.completion_audit_event_id,r.completed_at,r.next_due_at,a.exact_bytes FROM recovery_test_report r JOIN local_audit_event a ON a.event_id=r.completion_audit_event_id ORDER BY r.completed_at DESC,r.report_hash LIMIT 1",&[],
        )?;
        let Some(row) = row else {
            return Ok(None);
        };
        let source = self.archive_source()?;
        let report = ea_recovery::verify_completed_recovery_report(
            row.blob(2)?,
            &restored.scope,
            &source,
            self.runtime.anchor(),
            inventory,
            self.runtime.head().preexisting_effective_now().value(),
        )?;
        if report.envelope_hash().as_bytes() != row.blob(0)?
            || report.source_envelope_hash().as_bytes() != row.blob(1)?
            || report.audit_id().as_bytes() != row.blob(3)?
            || report.completed_at().get() != row.integer(4)?
            || report.next_due_at().get() != row.integer(5)?
            || report.restored_content_hash() != &restored.content_hash
            || report.target_installation() != self.runtime.native().installation_id()
            || report.target_machine()
                != ea_key_provider::measure_native_machine_identity()
                    .map_err(|_| RecoveryTestError::Machine)?
                    .fingerprint()
        {
            return Err(RecoveryTestError::Source.into());
        }
        let mut d = minicbor::Decoder::new(report.exact_envelope());
        d.array().map_err(|_| RecoveryTestError::Audit)?;
        d.bytes().map_err(|_| RecoveryTestError::Audit)?;
        if d.bytes().map_err(|_| RecoveryTestError::Audit)? != row.blob(6)? {
            return Err(RecoveryTestError::Audit.into());
        }
        Ok(Some(report))
    }
    pub fn read_failed_report(
        &mut self,
        inventory: &KeyInventory,
        restored: &Path,
    ) -> Result<Option<ea_recovery::VerifiedFailedRecoveryReport>, RecoveryRuntimeError> {
        let _locks = self.archive_locks()?;
        self.runtime.refresh_for_action()?;
        let restored = self.open_bound_sources(inventory, restored)?;
        let row = self.runtime.database().query_row(
            "SELECT r.failure_hash,r.source_hash,r.exact_report,r.failure_audit_event_id,r.failed_at,r.context_hash,a.exact_bytes FROM recovery_test_failure r JOIN local_audit_event a ON a.event_id=r.failure_audit_event_id ORDER BY r.failed_at DESC,r.failure_hash LIMIT 1",&[],
        )?;
        let Some(row) = row else {
            return Ok(None);
        };
        let source = self.archive_source()?;
        let report = ea_recovery::verify_failed_recovery_report(
            row.blob(2)?,
            &restored.scope,
            &source,
            self.runtime.anchor(),
            inventory,
            self.runtime.head().preexisting_effective_now().value(),
        )?;
        if report.envelope_hash().as_bytes() != row.blob(0)?
            || report.source_envelope_hash().as_bytes() != row.blob(1)?
            || report.audit_id().as_bytes() != row.blob(3)?
            || report.failed_at().get() != row.integer(4)?
            || report.context_hash().as_bytes() != row.blob(5)?
            || report.restored_content_hash() != &restored.content_hash
            || report.target_installation() != self.runtime.native().installation_id()
            || report.target_machine()
                != ea_key_provider::measure_native_machine_identity()
                    .map_err(|_| RecoveryTestError::Machine)?
                    .fingerprint()
        {
            return Err(RecoveryTestError::Source.into());
        }
        let mut d = minicbor::Decoder::new(report.exact_envelope());
        d.array().map_err(|_| RecoveryTestError::Audit)?;
        d.bytes().map_err(|_| RecoveryTestError::Audit)?;
        if d.bytes().map_err(|_| RecoveryTestError::Audit)? != row.blob(6)? {
            return Err(RecoveryTestError::Audit.into());
        }
        Ok(Some(report))
    }
}
