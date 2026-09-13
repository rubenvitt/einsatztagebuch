use super::*;
use ea_destruction::{
    VerifiedDeletionAttestation, VerifiedDestructionAuthorization, VerifiedDestructionEvent,
    VerifiedImportedPreflight, preflight_target_contexts, reconstruct_imported_history,
    verify_attestation_historical, verify_authorization_historical, verify_event_historical,
};
use ea_trust::HistoricalRegistryAuthority;
use ea_types::{ChainSequence, RegistryVersion};

pub(super) struct SavedDestruction {
    pub auth: VerifiedDestructionAuthorization,
    pub original: HistoricalRegistryAuthority,
    pub job: Option<VerifiedImportedPreflight>,
    pub events: Vec<VerifiedDestructionEvent>,
    pub attestations: Vec<VerifiedDeletionAttestation>,
}
impl DestructionRuntime {
    /// Signed history is readable only inside a presently valid native Admin session.
    pub fn status(&mut self, id: DestructionId) -> Result<NativeDestructionStatus, Error> {
        self.refresh()?;
        self.require_session()?;
        let saved = self.read_saved(id)?;
        self.project_status(&saved)
    }
    pub(super) fn status_saved(
        &self,
        auth: &VerifiedDestructionAuthorization,
    ) -> Result<NativeDestructionStatus, Error> {
        self.require_session()?;
        let saved = self.read_saved(auth.fields().destruction_id)?;
        if saved.auth.exact_bytes() != auth.exact_bytes() {
            return Err(DestructionError::SecurityConflict.into());
        }
        self.project_status(&saved)
    }
    pub(super) fn historical(
        &self,
        version: u64,
        head: &[u8],
        sequence: u64,
    ) -> Result<HistoricalRegistryAuthority, Error> {
        ea_trust::verify_historical_registry_authority(
            self.controller.trust(),
            RegistryVersion::new(version),
            ObjectHash::try_from(head).map_err(|_| DestructionError::Registry)?,
            ChainSequence::new(sequence),
        )
        .map_err(|_| DestructionError::Registry.into())
    }
    pub(super) fn read_saved(&self, id: DestructionId) -> Result<SavedDestruction, Error> {
        self.require_session()?;
        let key = [
            blob(self.controller.anchor().organization_id().as_bytes()),
            blob(id.as_bytes()),
        ];
        let row=self.custodian.database().query_row("SELECT exact_authorization FROM destruction_request WHERE organization_id=?1 AND destruction_id=?2",&key)?.ok_or(DestructionError::Storage)?;
        let exact = row.blob(0)?;
        let ea_format::ParsedArchiveObject::Trust(parsed) = ea_format::decode_exact_object(exact)?
        else {
            return Err(DestructionError::Format.into());
        };
        let ea_format::DecodedTrustPayloadV1::DestructionAuthorization(route) =
            parsed.value().decoded_payload()?
        else {
            return Err(DestructionError::Format.into());
        };
        let original = self.historical(
            route.registry_version.get(),
            route.registry_head_hash.as_bytes(),
            route.authorization_sequence,
        )?;
        let auth = verify_authorization_historical(exact, &original)?;
        if auth.fields().destruction_id != id
            || auth.fields().organization_id != self.controller.anchor().organization_id()
        {
            return Err(DestructionError::SecurityConflict.into());
        }
        let now = self.controller.head().preexisting_effective_now().value();
        let request = self
            .repository()
            .reconstruct_historical(&auth, &original, now)?
            .ok_or(DestructionError::Storage)?;
        self.mirror_audit(request.audit_exact_bytes())?;
        let mut events = vec![request.event().clone()];
        for row in self.rows("SELECT e.exact_event,a.exact_bytes,e.execution_registry_version,e.execution_registry_head_hash,e.execution_sequence FROM destruction_job_event e JOIN local_audit_event a ON a.event_id=e.audit_event_id WHERE e.organization_id=?1 AND e.destruction_id=?2 ORDER BY e.insertion_sequence",&key)?{
            let event=verify_event_historical(row.blob(0)?,&auth,&original,now)?;
            let historical=self.historical(u64::try_from(row.integer(2)?).map_err(|_|DestructionError::Storage)?,row.blob(3)?,u64::try_from(row.integer(4)?).map_err(|_|DestructionError::Storage)?)?;
            self.verify_event_audit(row.blob(1)?,&event,auth.object_hash(),&historical)?;
            self.mirror_audit(row.blob(1)?)?;
            events.push(event);
        }
        let job=self.custodian.database().query_row("SELECT exact_core,exact_signature,exact_inventory,signer_certificate_hash FROM destruction_job WHERE organization_id=?1 AND destruction_id=?2",&key)?.map(|row| {
            let upload=ea_sync_protocol::DestructionJobUploadV1::new(row.blob(0)?,row.blob(1)?,row.blob(2)?,CertificateHash::try_from(row.blob(3)?).map_err(|_|DestructionError::Format)?).map_err(|_|DestructionError::Format)?;
            let core=ea_crypto::decode_destruction_preflight_core(upload.core_bytes())?;
            let execution=self.historical(core.execution_registry,&core.execution_head,core.execution_sequence)?;
            let targets=preflight_target_contexts(&upload)?.into_iter().map(|route|self.historical(route.registry.get(),route.head.as_bytes(),route.sequence.get())).collect::<Result<Vec<_>,Error>>()?;
            VerifiedImportedPreflight::verify(&upload,&auth,&original,&execution,&targets).map_err(Error::from)
        }).transpose()?;
        let mut attestations = Vec::new();
        for row in self.rows("SELECT exact_attestation FROM destruction_local_attestation WHERE organization_id=?1 AND destruction_id=?2",&key)?{
            attestations.push(verify_attestation_historical(row.blob(0)?,&auth,&original,now)?);
        }
        let mut saved = SavedDestruction {
            auth,
            original,
            job,
            events,
            attestations,
        };
        self.load_imports(&mut saved)?;
        Ok(saved)
    }
    pub(super) fn project_status(
        &self,
        saved: &SavedDestruction,
    ) -> Result<NativeDestructionStatus, Error> {
        let f = saved.auth.fields();
        let (state, preflight_hash, preflight_report_json, replicas) = if let Some(job) = &saved.job
        {
            let reconstructed =
                reconstruct_imported_history(job, &saved.events, &saved.attestations)?;
            let core = ea_crypto::decode_destruction_preflight_core(job.core_bytes())?;
            let mut replicas = Vec::new();
            for (device, result) in reconstructed.evidence().replicas() {
                let mut kinds = BTreeSet::new();
                for (_, id, certificate_kind) in
                    job.replicas().iter().filter(|(_, id, _)| id == device)
                {
                    let kind = match certificate_kind {
                        0 => ea_destruction::ManagedReplicaKind::Writer,
                        1 => ea_destruction::ManagedReplicaKind::Reader,
                        6 => ea_destruction::ManagedReplicaKind::SyncServer,
                        _ => return Err(DestructionError::Target.into()),
                    };
                    let _ = id;
                    kinds.insert(kind);
                }
                if kinds.len() != 1 {
                    return Err(DestructionError::Target.into());
                }
                let kind = *kinds.first().ok_or(DestructionError::Target)?;
                let latest = saved
                    .attestations
                    .iter()
                    .filter(|a| a.fields().replica_id == *device.as_bytes())
                    .max_by_key(|a| a.fields().executed_at);
                replicas.push(NativeDestructionReplica {
                    device_id: *device,
                    kind,
                    attestation_hash: latest.map(|a| a.object_hash()),
                    result: *result,
                    backup_expiry_at: if *result
                        == ea_destruction::EvidenceReplicaStatus::PendingBackup
                    {
                        saved
                            .attestations
                            .iter()
                            .filter(|a| a.fields().replica_id == *device.as_bytes())
                            .filter_map(|a| a.fields().backup_expiry_at)
                            .max()
                    } else {
                        latest.and_then(|a| a.fields().backup_expiry_at)
                    },
                });
            }
            (
                reconstructed.state(),
                Some(job.job_hash()),
                Some(
                    std::str::from_utf8(core.report_json)
                        .map_err(|_| DestructionError::Format)?
                        .to_owned(),
                ),
                replicas,
            )
        } else {
            if saved.events.len() != 1 || !saved.attestations.is_empty() {
                return Err(DestructionError::Event.into());
            }
            (DestructionState::Requested, None, None, Vec::new())
        };
        let ea_format::ParsedArchiveObject::Trust(parsed) =
            ea_format::decode_exact_object(saved.auth.exact_bytes())?
        else {
            return Err(DestructionError::Format.into());
        };
        let approver_certificate_hashes = parsed
            .value()
            .signatures()
            .iter()
            .map(|s| {
                ea_crypto::parse_cose_sign1(s, &[])?
                    .certificate_hash()
                    .ok_or(DestructionError::Signature)
                    .map_err(Error::from)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let (observed_stubs, evidence_entry_hash) = self.observe_artifacts(saved)?;
        let retention = &self.controller.head().policy_fields().retention_policy;
        let view = NativeDestructionStatus {
            destruction_id: f.destruction_id,
            authorization_hash: saved.auth.object_hash(),
            state,
            scope_code: f.scope_code,
            legal_reason_code: f.legal_reason_code,
            targets: f
                .targets
                .iter()
                .map(|t| {
                    Ok(NativeDestructionTarget {
                        entry_hash: ea_types::EntryHash::try_from(t.entry_hash().as_slice())
                            .map_err(|_| DestructionError::Format)?,
                        chain_sequence: ea_types::ChainSequence::new(t.chain_sequence()),
                        stub_object_hash: observed_stubs
                            .get(
                                &ea_types::EntryHash::try_from(t.entry_hash().as_slice())
                                    .map_err(|_| DestructionError::Format)?,
                            )
                            .copied(),
                    })
                })
                .collect::<Result<_, Error>>()?,
            controller_device_id: self
                .controller
                .head()
                .active_certificate_fields(self.controller.config().device_certificate_hash)
                .ok_or(Error::Configuration)?
                .device_id,
            custodian_device_id: self
                .custodian
                .head()
                .active_certificate_fields(self.custodian.config().device_certificate_hash)
                .ok_or(Error::Configuration)?
                .device_id,
            preflight_hash,
            evidence_entry_hash,
            preflight_report_json,
            replicas,
            approver_certificate_hashes,
            privacy_decision_enabled: retention.destruction_enabled
                && retention.eds_privacy_decision_document_hash.is_some(),
            policy_hash: self.controller.head().policy_object_hash(),
        };
        self.check_host()?;
        Ok(view)
    }
    pub(super) fn rows(
        &self,
        sql: &str,
        key: &[ea_local_store::StoreValue],
    ) -> Result<Vec<ea_local_store::StoreRow>, Error> {
        self.custodian.database().transaction(|tx| {
            let mut rows = Vec::new();
            for offset in 0..=10_000 {
                let row = tx.query_row(&format!("{sql} LIMIT 1 OFFSET {offset}"), key)?;
                let Some(row) = row else { return Ok(rows) };
                if offset == 10_000 {
                    return Err(DestructionError::Storage.into());
                }
                rows.push(row);
            }
            Err(DestructionError::Storage.into())
        })
    }
    fn verify_event_audit(
        &self,
        exact: &[u8],
        event: &VerifiedDestructionEvent,
        authorization: ObjectHash,
        head: &HistoricalRegistryAuthority,
    ) -> Result<(), Error> {
        use ea_crypto::{SignerRole, VerificationContext, verify_cose_sign1};
        use ea_format::{LocalAuditActionV1, LocalAuditOutcomeV1};
        let audit = ea_format::decode_local_audit_event(exact)?;
        let certificate = CertificateHash::from(audit.signer_certificate_object_hash());
        let binding = head
            .active_operator_binding_fields(
                audit
                    .operator_binding_object_hash()
                    .ok_or(DestructionError::Audit)?,
            )
            .ok_or(DestructionError::Audit)?;
        let fields = head
            .active_certificate_fields(certificate)
            .ok_or(DestructionError::Audit)?;
        if audit.organization_id() != head.organization_id()
            || audit.effective_now() != event.fields().executed_at
            || audit.outcome() != LocalAuditOutcomeV1::Completed
            || !matches!(audit.action(),LocalAuditActionV1::Destruction(c) if c.destruction_authorization_object_hash()==authorization && c.state_event_object_hash()==event.object_hash())
            || binding.device_certificate_hash != certificate
            || fields.device_id != audit.device_id()
            || binding.organization_id != audit.organization_id()
            || fields.certificate_kind != CertificateKindV1::OrganizationAdmin
        {
            return Err(DestructionError::Audit.into());
        }
        let context = VerificationContext::local_audit(
            audit.exact_core(),
            head.proposed_sequence(),
            SignerRole::OrganizationAdmin,
            head.registry_version(),
        )?;
        let mut d = minicbor::Decoder::new(exact);
        d.array().map_err(|_| DestructionError::Audit)?;
        d.skip().map_err(|_| DestructionError::Audit)?;
        verify_cose_sign1(&exact[d.position()..], head, &context)?;
        Ok(())
    }
}
