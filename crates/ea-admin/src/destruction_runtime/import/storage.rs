use super::*;
use ea_local_store::StoreTransaction;
impl DestructionRuntime {
    pub(in crate::destruction_runtime) fn import_snapshot(&self) -> Result<ObjectHash, Error> {
        self.custodian.database().transaction(snapshot_in)
    }
    pub(super) fn verify_import_audits(
        &self,
        exact_context: &[u8],
        login_exact: &[u8],
        state_exact: &[u8],
        saved: &SavedDestruction,
    ) -> Result<(), Error> {
        use ea_crypto::{SignerRole, VerificationContext, verify_cose_sign1};
        let context = codec::decode_context(exact_context)?;
        let objects = codec::decode_set(context.set, saved)?;
        let head = self.historical(context.version, context.head, context.sequence)?;
        let now = self.controller.head().preexisting_effective_now().value();
        if context.now > now.get() {
            return Err(DestructionError::Audit.into());
        }
        let rebuilt = reconstruct_imported_history(
            saved.job.as_ref().ok_or(DestructionError::Storage)?,
            &saved.events,
            &saved.attestations,
        )?;
        if rebuilt.last_event_hash() != context.last {
            return Err(DestructionError::Audit.into());
        }
        for exact in objects.values() {
            let ea_format::ParsedArchiveObject::Trust(parsed) =
                ea_format::decode_exact_object(exact)?
            else {
                return Err(DestructionError::Format.into());
            };
            let at = match parsed.value().decoded_payload()? {
                ea_format::DecodedTrustPayloadV1::DestructionTransition(f) => f.executed_at,
                ea_format::DecodedTrustPayloadV1::DeletionAttestation(f) => f.executed_at,
                _ => return Err(DestructionError::Format.into()),
            };
            if at.get() > context.now {
                return Err(DestructionError::Audit.into());
            }
        }
        let login = ea_format::decode_local_audit_event(login_exact)?;
        let state = ea_format::decode_local_audit_event(state_exact)?;
        if login.event_id() == state.event_id()
            || !matches!(login.action(),LocalAuditActionV1::Login(c) if c.subject_object_hash()==Some(object_hash(exact_context)))
            || !matches!(state.action(),LocalAuditActionV1::Destruction(c) if c.destruction_authorization_object_hash()==saved.auth.object_hash()&&c.state_event_object_hash()==context.last)
            || login.signer_certificate_object_hash() != state.signer_certificate_object_hash()
            || login.operator_binding_object_hash() != state.operator_binding_object_hash()
            || login.device_id() != state.device_id()
        {
            return Err(DestructionError::Audit.into());
        }
        for (exact, audit) in [(login_exact, login), (state_exact, state)] {
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
            if audit.organization_id() != saved.auth.fields().organization_id
                || audit.effective_now().get() != context.now
                || audit.outcome() != LocalAuditOutcomeV1::Accepted
                || binding.device_certificate_hash != certificate
                || fields.device_id != audit.device_id()
                || binding.organization_id != audit.organization_id()
                || fields.certificate_kind != CertificateKindV1::OrganizationAdmin
            {
                return Err(DestructionError::Audit.into());
            }
            let verify = VerificationContext::local_audit(
                audit.exact_core(),
                head.proposed_sequence(),
                SignerRole::OrganizationAdmin,
                head.registry_version(),
            )?;
            let mut decoder = minicbor::Decoder::new(exact);
            decoder.array().map_err(|_| DestructionError::Audit)?;
            decoder.skip().map_err(|_| DestructionError::Audit)?;
            verify_cose_sign1(&exact[decoder.position()..], &head, &verify)?;
        }
        Ok(())
    }
}
pub(in crate::destruction_runtime) fn snapshot_in(
    tx: &StoreTransaction<'_>,
) -> Result<ObjectHash, Error> {
    let sync = tx
        .query_row("PRAGMA synchronous", &[])?
        .ok_or(DestructionError::Storage)?
        .integer(0)?;
    if !matches!(sync, 2 | 3) {
        return Err(DestructionError::Storage.into());
    }
    let sources = [
        (
            "SELECT exact_authorization,exact_event FROM destruction_request ORDER BY organization_id,destruction_id",
            2,
        ),
        (
            "SELECT exact_core,exact_signature,exact_inventory FROM destruction_job ORDER BY organization_id,destruction_id",
            3,
        ),
        (
            "SELECT exact_bytes FROM managed_custody ORDER BY organization_id,record_hash",
            1,
        ),
        (
            "SELECT exact_bytes FROM destruction_inventory ORDER BY organization_id,destruction_id",
            1,
        ),
        (
            "SELECT exact_event FROM destruction_job_event ORDER BY insertion_sequence",
            1,
        ),
        (
            "SELECT exact_attestation FROM destruction_local_attestation ORDER BY job_hash,replica_id",
            1,
        ),
        (
            "SELECT exact_context FROM destruction_import_batch ORDER BY insertion_sequence",
            1,
        ),
    ];
    let mut bytes = Vec::new();
    let mut e = minicbor::Encoder::new(&mut bytes);
    e.array(sources.len() as u64)
        .map_err(|_| DestructionError::Format)?;
    for (sql, columns) in sources {
        let mut records = Vec::new();
        for offset in 0..=10_000 {
            let Some(row) = tx.query_row(&format!("{sql} LIMIT 1 OFFSET {offset}"), &[])? else {
                break;
            };
            if offset == 10_000 {
                return Err(DestructionError::Storage.into());
            }
            let mut record = Vec::new();
            for column in 0..columns {
                record.push(row.blob(column)?.to_vec());
            }
            records.push(record);
        }
        e.array(records.len() as u64)
            .map_err(|_| DestructionError::Format)?;
        for record in records {
            e.array(record.len() as u64)
                .map_err(|_| DestructionError::Format)?;
            for field in record {
                e.bytes(&field).map_err(|_| DestructionError::Format)?;
            }
        }
    }
    Ok(object_hash(&bytes))
}
