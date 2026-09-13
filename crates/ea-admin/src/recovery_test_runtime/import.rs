//! A fresh native Source installation accepts only verified durable evidence.
//! Importing a test report is never an active archive import or Writer permit.
use super::*;
use ea_recovery::VerifiedCompletedRecoveryReport;
use ea_types::Hash32;

impl RecoveryTestRuntime {
    /// Read-only native diagnosis without opening an archive backend. No
    /// inventory or recovery freshness proof exists on this path. Unknown raw
    /// posture remains visible; native Admin/account/source checks still apply.
    pub fn evaluate_go_live_without_inventory(
        runtime: OperatorRuntime,
        build: impl FnOnce(&OperatorRuntime) -> crate::GoLiveChecklist,
    ) -> Result<crate::GoLiveChecklist, RecoveryRuntimeError> {
        if runtime.config().role != OperatorRoleV1::OrganizationAdmin {
            return Err(RecoveryTestError::Operator.into());
        }
        let current = runtime.reopened_for_action()?;
        let admitted = current.go_live_report()?;
        let checklist = build(&current);
        let after = current.reopened_for_action()?;
        let checked = after.go_live_report()?;
        if after.head().registry_head_hash() != current.head().registry_head_hash()
            || after.head().registry_version() != current.head().registry_version()
            || after.next_sequence() != current.next_sequence()
            || !after
                .head()
                .preexisting_effective_now()
                .has_same_persisted_bounds(current.head().preexisting_effective_now())
            || admitted.os_account_binding_hash != checked.os_account_binding_hash
            || admitted.productive_binding_hashes != checked.productive_binding_hashes
        {
            return Err(RecoveryTestError::Source.into());
        }
        Ok(checklist)
    }

    /// Builds an owned diagnostic checklist from one freshly opened runtime.
    /// The callback cannot return the borrowed evidence as a detached proof.
    pub fn evaluate_current_go_live(
        &mut self,
        inventory: Option<&KeyInventory>,
        build: impl for<'a> FnOnce(
            &'a OperatorRuntime,
            Option<crate::RecoveryTestFreshness<'a>>,
        ) -> crate::GoLiveChecklist,
    ) -> Result<crate::GoLiveChecklist, RecoveryRuntimeError> {
        self.runtime.refresh_for_action()?;
        let report = inventory
            .map(|keys| self.load_imported_completed_report(keys))
            .transpose()?
            .flatten();
        let evidence = match (inventory, report.as_ref()) {
            (Some(keys), Some(report)) => Some(crate::RecoveryTestFreshness::from_current(
                self,
                keys,
                report.envelope_hash(),
            )),
            _ => None,
        };
        let checklist = build(&self.runtime, evidence);
        // Reading raw posture remains possible without productive admission.
        // Any actual recovery evidence still invokes the full current guard.
        let fresh = self.runtime.reopened_for_action()?;
        if fresh.head().registry_head_hash() != self.runtime.head().registry_head_hash()
            || fresh.head().registry_version() != self.runtime.head().registry_version()
            || fresh.next_sequence() != self.runtime.next_sequence()
            || !fresh
                .head()
                .preexisting_effective_now()
                .has_same_persisted_bounds(self.runtime.head().preexisting_effective_now())
        {
            return Err(RecoveryTestError::Source.into());
        }
        Ok(checklist)
    }

    fn source_admission(&self, scope: &VerifiedRecoverySource) -> Result<(), RecoveryRuntimeError> {
        self.runtime.ensure_same_action_authority()?;
        let f = scope.core().fields();
        if f.source_machine
            != *ea_key_provider::measure_native_machine_identity()
                .map_err(|_| RecoveryTestError::Machine)?
                .fingerprint()
                .as_bytes()
            || f.source_installation != *self.runtime.native().installation_id().as_bytes()
            || f.registry_version != self.runtime.head().registry_version().get()
            || f.registry_head != *self.runtime.head().registry_head_hash().as_bytes()
            || f.proposed_sequence != self.runtime.next_sequence().get()
        {
            return Err(RecoveryTestError::Source.into());
        }
        Ok(())
    }

    pub fn import_completed_report(
        &mut self,
        inventory: &KeyInventory,
        exact_source: &[u8],
        exact_report: &[u8],
    ) -> Result<VerifiedCompletedRecoveryReport, RecoveryRuntimeError> {
        let _writer = self.backend.acquire_writer_lock()?;
        self.runtime.refresh_for_action()?;
        let source = FsArchiveSource::open(&self.runtime.config().archive_directory)
            .map_err(|_| RecoveryTestError::Source)?;
        let now = self.runtime.head().preexisting_effective_now().value();
        let scope = ea_recovery::verify_recovery_source(
            exact_source,
            &source,
            self.runtime.anchor(),
            inventory,
            now,
        )?;
        self.source_admission(&scope)?;
        let report = ea_recovery::verify_completed_recovery_report(
            exact_report,
            &scope,
            &source,
            self.runtime.anchor(),
            inventory,
            now,
        )?;
        if now >= report.next_due_at() {
            return Err(RecoveryTestError::Incomplete.into());
        }
        let mut context = minicbor::Encoder::new(Vec::new());
        context
            .array(4)
            .and_then(|e| e.str("EINSATZARCHIV-RECOVERY-SOURCE-IMPORT-v1"))
            .and_then(|e| e.u8(1))
            .and_then(|e| e.bytes(scope.envelope_hash().as_bytes()))
            .and_then(|e| e.bytes(report.envelope_hash().as_bytes()))
            .map_err(|_| RecoveryTestError::Source)?;
        let context = Hash32::try_from(object_hash(&context.into_writer()).as_bytes().as_slice())
            .map_err(|_| RecoveryTestError::Source)?;
        let session = self
            .runtime
            .reauthenticate_for_context(ReauthPurpose::RecoveryTest, context)?;
        self.source_admission(&scope)?;
        let after = FsArchiveSource::open(&self.runtime.config().archive_directory)
            .map_err(|_| RecoveryTestError::Source)?;
        if ea_recovery::recovery_archive_inventory_hash(&after)?
            != scope.core().fields().archive_inventory_hash
        {
            return Err(RecoveryTestError::Source.into());
        }
        let accepted = self
            .runtime
            .audit_service()
            .prepare_signed(
                AuditActorProof::OperatorSession(session.proof()),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(
                        ObjectHash::from(context),
                    ))),
                    outcome: LocalAuditOutcomeV1::Accepted,
                },
            )
            .map_err(|_| RecoveryTestError::Audit)?;
        // Both foreign signed events were authenticated above. Their exact bytes
        // and identities are preserved, not re-signed as locally completed work.
        let source_audit = envelope_audit(scope.exact_envelope())?;
        let completed_audit = envelope_audit(report.exact_envelope())?;
        let source_event = ea_format::decode_local_audit_event(source_audit)
            .map_err(|_| RecoveryTestError::Audit)?;
        self.runtime.database().transaction::<_,RecoveryRuntimeError>(|tx|{
            append_verified_event(tx,source_audit)?;
            append_verified_event(tx,completed_audit)?;
            SqliteLocalAuditRepository::append_prepared_in(tx,&accepted).map_err(|_|RecoveryTestError::Audit)?;
            tx.execute("INSERT INTO recovery_source_scope(source_hash,exact_envelope,capture_audit_event_id) VALUES(?1,?2,?3) ON CONFLICT(source_hash) DO NOTHING",&[
                StoreValue::Blob(scope.envelope_hash().as_bytes().to_vec()),StoreValue::Blob(scope.exact_envelope().to_vec()),StoreValue::Blob(source_event.event_id().as_bytes().to_vec()),
            ])?;
            tx.execute("INSERT INTO recovery_test_report(report_hash,source_hash,exact_report,completion_audit_event_id,completed_at,next_due_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(report_hash) DO NOTHING",&[
                StoreValue::Blob(report.envelope_hash().as_bytes().to_vec()),StoreValue::Blob(scope.envelope_hash().as_bytes().to_vec()),
                StoreValue::Blob(report.exact_envelope().to_vec()),StoreValue::Blob(report.audit_id().as_bytes().to_vec()),
                StoreValue::Integer(report.completed_at().get()),StoreValue::Integer(report.next_due_at().get()),
            ])?;
            Ok(())
        })?;
        self.source_admission(&scope)?;
        Ok(report)
    }

    pub fn read_imported_completed_report(
        &mut self,
        inventory: &KeyInventory,
    ) -> Result<Option<VerifiedCompletedRecoveryReport>, RecoveryRuntimeError> {
        let _writer = self.backend.acquire_writer_lock()?;
        self.runtime.refresh_for_action()?;
        self.load_imported_completed_report(inventory)
    }

    fn load_imported_completed_report(
        &self,
        inventory: &KeyInventory,
    ) -> Result<Option<VerifiedCompletedRecoveryReport>, RecoveryRuntimeError> {
        self.runtime.ensure_same_action_authority()?;
        let row=self.runtime.database().query_row(
            "SELECT r.report_hash,r.source_hash,r.exact_report,r.completion_audit_event_id,r.completed_at,r.next_due_at,s.exact_envelope,a.exact_bytes,c.exact_bytes FROM recovery_test_report r JOIN recovery_source_scope s ON s.source_hash=r.source_hash JOIN local_audit_event a ON a.event_id=r.completion_audit_event_id JOIN local_audit_event c ON c.event_id=s.capture_audit_event_id ORDER BY r.completed_at DESC,r.report_hash LIMIT 1",&[],
        )?;
        let Some(row) = row else { return Ok(None) };
        let source = FsArchiveSource::open(&self.runtime.config().archive_directory)
            .map_err(|_| RecoveryTestError::Source)?;
        let native_wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| RecoveryTestError::Source)?;
        let native_wall =
            i64::try_from(native_wall.as_millis()).map_err(|_| RecoveryTestError::Source)?;
        let now = ea_types::UnixMillis::new(
            native_wall.max(
                self.runtime
                    .head()
                    .preexisting_effective_now()
                    .value()
                    .get(),
            ),
        );
        let scope = ea_recovery::verify_recovery_source(
            row.blob(6)?,
            &source,
            self.runtime.anchor(),
            inventory,
            now,
        )?;
        self.source_admission(&scope)?;
        let report = ea_recovery::verify_completed_recovery_report(
            row.blob(2)?,
            &scope,
            &source,
            self.runtime.anchor(),
            inventory,
            now,
        )?;
        if row.blob(0)? != report.envelope_hash().as_bytes()
            || row.blob(1)? != scope.envelope_hash().as_bytes()
            || row.blob(3)? != report.audit_id().as_bytes()
            || row.integer(4)? != report.completed_at().get()
            || row.integer(5)? != report.next_due_at().get()
            || row.blob(7)? != envelope_audit(report.exact_envelope())?
            || row.blob(8)? != envelope_audit(scope.exact_envelope())?
        {
            return Err(RecoveryTestError::Audit.into());
        }
        Ok(Some(report))
    }

    pub(crate) fn current_completed_report_matches(
        &self,
        inventory: &KeyInventory,
        hash: ObjectHash,
    ) -> Result<(), RecoveryRuntimeError> {
        let report = self
            .load_imported_completed_report(inventory)?
            .ok_or(RecoveryTestError::Incomplete)?;
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| RecoveryTestError::Source)?;
        let now = i64::try_from(wall.as_millis())
            .map_err(|_| RecoveryTestError::Source)?
            .max(
                self.runtime
                    .head()
                    .preexisting_effective_now()
                    .value()
                    .get(),
            );
        if report.envelope_hash() != hash
            || now < report.completed_at().get()
            || now >= report.next_due_at().get()
        {
            return Err(RecoveryTestError::Incomplete.into());
        }
        Ok(())
    }

    pub fn recovery_test_freshness<'a>(
        &'a mut self,
        inventory: &'a KeyInventory,
    ) -> Result<crate::RecoveryTestFreshness<'a>, RecoveryRuntimeError> {
        let report = self
            .read_imported_completed_report(inventory)?
            .ok_or(RecoveryTestError::Incomplete)?;
        let context = Hash32::try_from(report.envelope_hash().as_bytes().as_slice())
            .map_err(|_| RecoveryTestError::Source)?;
        self.runtime
            .reauthenticate_for_context(ReauthPurpose::RecoveryTest, context)?;
        self.current_completed_report_matches(inventory, report.envelope_hash())?;
        Ok(crate::RecoveryTestFreshness::from_current(
            self,
            inventory,
            report.envelope_hash(),
        ))
    }

    pub fn fresh_machine_recovery_proof<'a>(
        &'a mut self,
        inventory: &'a KeyInventory,
    ) -> Result<crate::FreshMachineRecoveryProof<'a>, RecoveryRuntimeError> {
        let report = self
            .read_imported_completed_report(inventory)?
            .ok_or(RecoveryTestError::Incomplete)?;
        if self.runtime.head().preexisting_effective_now().value() >= report.next_due_at() {
            return Err(RecoveryTestError::Incomplete.into());
        }
        let context = Hash32::try_from(report.envelope_hash().as_bytes().as_slice())
            .map_err(|_| RecoveryTestError::Source)?;
        self.runtime
            .reauthenticate_for_context(ReauthPurpose::RecoveryTest, context)?;
        self.current_completed_report_matches(inventory, report.envelope_hash())?;
        let admission =
            crate::RecoveryTestFreshness::from_current(self, inventory, report.envelope_hash());
        Ok(crate::FreshMachineRecoveryProof::from_verified_completed(
            &report, admission,
        ))
    }
}

/// Only called with exact envelopes already returned by the source/completion
/// verifiers. The generic audit table grants no readiness on its own.
fn append_verified_event(
    tx: &ea_local_store::StoreTransaction<'_>,
    exact: &[u8],
) -> Result<(), RecoveryRuntimeError> {
    let event = ea_format::decode_local_audit_event(exact).map_err(|_| RecoveryTestError::Audit)?;
    if let Some(row) = tx.query_row(
        "SELECT exact_bytes,object_hash FROM local_audit_event WHERE event_id=?1",
        &[StoreValue::Blob(event.event_id().as_bytes().to_vec())],
    )? {
        if row.blob(0)? != exact || row.blob(1)? != object_hash(exact).as_bytes() {
            return Err(RecoveryTestError::Audit.into());
        }
    } else {
        tx.execute(
            "INSERT INTO local_audit_event(event_id,exact_bytes,object_hash) VALUES(?1,?2,?3)",
            &[
                StoreValue::Blob(event.event_id().as_bytes().to_vec()),
                StoreValue::Blob(exact.to_vec()),
                StoreValue::Blob(object_hash(exact).as_bytes().to_vec()),
            ],
        )?;
    }
    Ok(())
}
fn envelope_audit(exact: &[u8]) -> Result<&[u8], RecoveryTestError> {
    let mut d = minicbor::Decoder::new(exact);
    if d.array().map_err(|_| RecoveryTestError::Audit)? != Some(2) {
        return Err(RecoveryTestError::Audit);
    }
    d.bytes().map_err(|_| RecoveryTestError::Audit)?;
    let audit = d.bytes().map_err(|_| RecoveryTestError::Audit)?;
    if d.position() != exact.len() {
        return Err(RecoveryTestError::Audit);
    }
    Ok(audit)
}
