use super::*;
use ea_archive::ArchiveInventory;
use ea_destruction::{prepare_preflight, verify_authorization};
impl DestructionRuntime {
    /// The exact imported object already contains both independent Approver signatures.
    /// This creates requested and its signed report; it performs no removal.
    pub fn prepare(&mut self, exact: &[u8]) -> Result<NativeDestructionStatus, Error> {
        self.refresh()?;
        let (auth, _, _) = self.prepare_authorization(exact)?;
        let policy = &self.controller.head().policy_fields().retention_policy;
        if !policy.destruction_enabled || policy.eds_privacy_decision_document_hash.is_none() {
            return Err(DestructionError::PrivacyGate.into());
        }
        let source = self.primary()?.as_archive_source();
        let report = ea_verify::verify_archive(
            &source,
            self.controller.anchor(),
            ea_verify::VerifyOptions::new(
                self.controller.head().preexisting_effective_now().value(),
            ),
        )
        .map_err(|_| DestructionError::Target)?;
        if !report.is_fully_verified() {
            return Err(DestructionError::Target.into());
        }
        let inventory = ArchiveInventory::build(&source).map_err(|_| DestructionError::Target)?;
        let mut targets = Vec::new();
        for target in &auth.fields().targets {
            let entry = inventory
                .entries()
                .iter()
                .find(|p| p.value().entry_hash().as_bytes() == target.entry_hash())
                .ok_or(DestructionError::Target)?;
            let fields = entry.value().manifest().fields();
            let historical = ea_trust::verify_historical_registry_authority(
                self.controller.trust(),
                fields.registry_version,
                ObjectHash::try_from(fields.registry_head_hash.as_slice())
                    .map_err(|_| DestructionError::Target)?,
                fields.chain_sequence,
            )
            .map_err(|_| DestructionError::Registry)?;
            targets.push(auth.verify_target_historical(entry.value(), &historical)?);
        }
        // Native presence is purpose-bound and refreshes authority before/after
        // its real dialog. Reconstruct an existing exact request historically;
        // a new request still requires the actual current authorization head.
        self.unlock()?;
        let (auth, original, existing) = self.prepare_authorization(exact)?;
        let session = self.require_session()?;
        let repository = self.repository();
        let audit = self.controller.audit_service();
        let native = self.native(&audit, &repository);
        let requested = match existing {
            Some(request) => request,
            None => {
                let event = self.event(&auth, None, 0, None)?;
                native.request_guarded(
                    exact,
                    &event,
                    &targets,
                    session.proof(),
                    &mut self.action_guard()?,
                )?
            }
        };
        self.mirror_audit(requested.audit_exact_bytes())?;
        let resumed = native.resume_historical(&auth, &original, session.proof())?;
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
        if jobs
            .load(&resumed, &frozen, self.controller.trust())?
            .is_none()
        {
            let source = self.primary()?.as_archive_source();
            let preflight = prepare_preflight(
                &resumed,
                &frozen,
                &source,
                self.controller.anchor(),
                self.component,
                &self.signer,
            )?;
            self.require_same_fresh_action()?;
            jobs.persist_guarded(
                &preflight,
                &resumed,
                &frozen,
                self.controller.trust(),
                &mut self.action_guard()?,
            )?;
        }
        self.status_saved(&auth)
    }
    // An untrusted id is routing only. Historical admission requires the exact
    // immutable request AND its original event/audit signatures in our Writer DB.
    // No caller-selected old authorization may create a new request.
    fn prepare_authorization(
        &self,
        exact: &[u8],
    ) -> Result<
        (
            ea_destruction::VerifiedDestructionAuthorization,
            ea_trust::HistoricalRegistryAuthority,
            Option<ea_destruction::RequestedDestruction>,
        ),
        Error,
    > {
        let ea_format::ParsedArchiveObject::Trust(parsed) = ea_format::decode_exact_object(exact)?
        else {
            return Err(DestructionError::Format.into());
        };
        let ea_format::DecodedTrustPayloadV1::DestructionAuthorization(route) =
            parsed.value().decoded_payload()?
        else {
            return Err(DestructionError::Format.into());
        };
        let existing = self.custodian.database().query_row(
            "SELECT exact_authorization FROM destruction_request WHERE organization_id=?1 AND destruction_id=?2",
            &[blob(self.controller.anchor().organization_id().as_bytes()), blob(route.destruction_id.as_bytes())],
        )?;
        let auth = if let Some(row) = &existing {
            if row.blob(0)? != exact {
                return Err(DestructionError::SecurityConflict.into());
            }
            let original = self.historical(
                route.registry_version.get(),
                route.registry_head_hash.as_bytes(),
                route.authorization_sequence,
            )?;
            ea_destruction::verify_authorization_historical(exact, &original)?
        } else {
            verify_authorization(exact, self.controller.head())?
        };
        let original = self.historical(
            auth.fields().registry_version.get(),
            auth.fields().registry_head_hash.as_bytes(),
            auth.fields().authorization_sequence,
        )?;
        let requested = if existing.is_some() {
            Some(
                self.repository()
                    .reconstruct_historical(
                        &auth,
                        &original,
                        self.controller.head().preexisting_effective_now().value(),
                    )?
                    .ok_or(DestructionError::Storage)?,
            )
        } else {
            None
        };
        Ok((auth, original, requested))
    }
    pub(super) fn mirror_audit(&self, exact: &[u8]) -> Result<(), Error> {
        let decoded = ea_format::decode_local_audit_event(exact)?;
        if decoded.organization_id() != self.controller.anchor().organization_id() {
            return Err(DestructionError::Audit.into());
        }
        let key = [blob(decoded.event_id().as_bytes())];
        self.check_host()?;
        self.controller.database().transaction(|tx|{
            self.check_host()?;
            let sync=tx.query_row("PRAGMA synchronous",&[])?.ok_or(DestructionError::Storage)?.integer(0)?;
            if !matches!(sync,2|3){return Err(Error::Core(DestructionError::Storage))}
            if let Some(row)=tx.query_row("SELECT exact_bytes,object_hash FROM local_audit_event WHERE event_id=?1",&key)?{
                if row.blob(0)?!=exact || row.blob(1)?!=object_hash(exact).as_bytes(){return Err(DestructionError::SecurityConflict.into())}
            }else{
                tx.execute("INSERT INTO local_audit_event(event_id,exact_bytes,object_hash) VALUES(?1,?2,?3)",&[key[0].clone(),blob(exact),blob(object_hash(exact).as_bytes())])?;
            }
            self.check_host()?;
            Ok::<_,Error>(())
        })?;
        let row = self
            .controller
            .database()
            .query_row(
                "SELECT exact_bytes FROM local_audit_event WHERE event_id=?1",
                &key,
            )?
            .ok_or(DestructionError::Storage)?;
        if row.blob(0)? != exact {
            return Err(DestructionError::SecurityConflict.into());
        }
        self.check_host()
    }
}
