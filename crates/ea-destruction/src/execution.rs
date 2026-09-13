//! Native signed start admission. No physical removal occurs here.
use crate::{
    ConfirmedDeliveryBarrier, DestructionError as Error, DestructionRequestService,
    DurableDestructionJob, DurableManagedInventory, ResumedDestruction, SqliteDestructionJobs,
    VerifiedDestructionEvent,
};
use ea_audit::{AuditActorProof, SqliteLocalAuditRepository, TypedLocalAuditEvent};
use ea_crypto::{SignerRole, VerificationContext, object_hash, verify_cose_sign1};
use ea_format::{
    CertificateKindV1, DestructionContextV1, LocalAuditActionV1, LocalAuditOutcomeV1,
    decode_local_audit_event,
};
use ea_local_store::{StoreRow, StoreValue};
use ea_operator::OperatorSessionProof;
use ea_trust::VerifiedTrust;
use ea_trust::{HistoricalRegistryAuthority, verify_historical_registry_authority};
use ea_types::ObjectHash;
use ea_types::{CertificateHash, ChainSequence, RegistryVersion};

const READ_START: &str = "SELECT e.exact_event,a.exact_bytes,e.execution_registry_version,e.execution_registry_head_hash,e.execution_sequence FROM destruction_job_event e JOIN local_audit_event a ON a.event_id=e.audit_event_id WHERE e.organization_id=?1 AND e.destruction_id=?2 ORDER BY e.insertion_sequence LIMIT 1";
pub struct DestructionExecutionContext<'a, 'head> {
    pub resumed: &'a ResumedDestruction<'head>,
    pub job: &'a DurableDestructionJob,
    pub custody: &'a DurableManagedInventory,
    pub barrier: &'a ConfirmedDeliveryBarrier,
    pub trust: &'a VerifiedTrust,
}
pub struct DurableDestructionStart {
    job: ObjectHash,
    event: VerifiedDestructionEvent,
    audit: Vec<u8>,
}
impl DurableDestructionStart {
    pub const fn job_hash(&self) -> ObjectHash {
        self.job
    }
    pub fn event(&self) -> &VerifiedDestructionEvent {
        &self.event
    }
    pub fn exact_audit_bytes(&self) -> &[u8] {
        &self.audit
    }
}
impl SqliteDestructionJobs {
    pub fn start_execution(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        exact_event: &[u8],
        native: &DestructionRequestService<'_>,
        proof: &OperatorSessionProof,
    ) -> Result<DurableDestructionStart, Error> {
        self.start_execution_guarded(
            context,
            exact_event,
            native,
            proof,
            &mut crate::local::NoAdditionalAuthorityGuard,
        )
    }
    pub fn start_execution_guarded(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        exact_event: &[u8],
        native: &DestructionRequestService<'_>,
        proof: &OperatorSessionProof,
        guard: &mut dyn crate::LocalActionAuthorityGuard,
    ) -> Result<DurableDestructionStart, Error> {
        let resumed = native.resume_original(
            context.resumed.request().authorization(),
            context.resumed.authorization_head(),
            proof,
        )?;
        let auth = resumed.request().authorization();
        if context.barrier.authorization_hash() != auth.object_hash()
            || context.barrier.destruction_id() != auth.fields().destruction_id
        {
            return Err(Error::SecurityConflict);
        }
        let job = self
            .load(&resumed, context.custody, context.trust)?
            .ok_or(Error::Storage)?;
        if job.preflight().exact_core_bytes() != context.job.preflight().exact_core_bytes() {
            return Err(Error::SecurityConflict);
        }
        let key = [
            blob(auth.fields().organization_id.as_bytes()),
            blob(auth.fields().destruction_id.as_bytes()),
        ];
        self.database.transaction(|tx| {
            guard.check_in(tx)?;
            crate::inventory::require_durable(tx)?;
            crate::inventory::require_unchanged_in(tx,context.custody)?;
            let request = tx.query_row("SELECT exact_authorization,exact_event FROM destruction_request WHERE organization_id=?1 AND destruction_id=?2",&key)?.ok_or(Error::Storage)?;
            if request.blob(0)?!=auth.exact_bytes() || request.blob(1)?!=resumed.request().event().exact_bytes() { return Err(Error::SecurityConflict); }
            if let Some(row) = tx.query_row(READ_START,&key)? {
                if row.blob(0)?!=exact_event { return Err(Error::SecurityConflict); }
                read_started(row,&resumed,&job,context.trust)?;
                return Ok::<_,Error>(());
            }
            let event = resumed.verify_event(exact_event)?;
            let mut machine = crate::DestructionStateMachine::new(auth);
            machine.apply(resumed.request().event())?;
            machine.apply(&event)?;
            if event.fields().from_state!=Some(0) || event.fields().to_state!=1 { return Err(Error::Event); }
            let audit = native.audit.prepare_signed(AuditActorProof::OperatorSession(proof),TypedLocalAuditEvent {
                action:LocalAuditActionV1::Destruction(DestructionContextV1::new(auth.object_hash(),event.object_hash())),outcome:LocalAuditOutcomeV1::Completed,
            })?;
            let head = resumed.current_head();
            let historical = verify_historical_registry_authority(context.trust,head.registry_version(),head.registry_head_hash(),head.proposed_sequence()).map_err(|_| Error::Registry)?;
            verify_audit(audit.exact_bytes(),&event,auth.object_hash(),&historical)?;
            let decoded = decode_local_audit_event(audit.exact_bytes())?;
            if decoded.signer_certificate_object_hash().as_bytes()!=native.certificate.as_bytes()
                || decoded.operator_binding_object_hash()!=Some(proof.binding_object_hash()) || decoded.device_id()!=proof.device_id() { return Err(Error::Audit); }
            guard.check_in(tx)?;
            SqliteLocalAuditRepository::append_prepared_in(tx,&audit)?;
            tx.execute("INSERT INTO destruction_job_event(organization_id,destruction_id,event_id,event_hash,exact_event,audit_event_id,execution_registry_version,execution_registry_head_hash,execution_sequence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",&[
                key[0].clone(),key[1].clone(),blob(event.fields().event_id.as_bytes()),blob(event.object_hash().as_bytes()),blob(exact_event),blob(audit.id().as_bytes()),
                integer(head.registry_version().get())?,blob(head.registry_head_hash().as_bytes()),integer(head.proposed_sequence().get())?,
            ])?;
            Ok(())
        })?;
        let row = self
            .database
            .query_row(READ_START, &key)?
            .ok_or(Error::Storage)?;
        read_started(row, &resumed, &job, context.trust)
    }
}

fn read_started(
    row: StoreRow,
    resumed: &ResumedDestruction<'_>,
    job: &DurableDestructionJob,
    trust: &VerifiedTrust,
) -> Result<DurableDestructionStart, Error> {
    let auth = resumed.request().authorization();
    let event = resumed.authorization_head().event(
        row.blob(0)?,
        auth,
        resumed.current_head().preexisting_effective_now().value(),
    )?;
    let mut machine = crate::DestructionStateMachine::new(auth);
    machine.apply(resumed.request().event())?;
    machine.apply(&event)?;
    if event.fields().from_state != Some(0) || event.fields().to_state != 1 {
        return Err(Error::Event);
    }
    let version = u64::try_from(row.integer(2)?).map_err(|_| Error::Registry)?;
    let head = ObjectHash::try_from(row.blob(3)?).map_err(|_| Error::Registry)?;
    let sequence = u64::try_from(row.integer(4)?).map_err(|_| Error::Registry)?;
    let historical = verify_historical_registry_authority(
        trust,
        RegistryVersion::new(version),
        head,
        ChainSequence::new(sequence),
    )
    .map_err(|_| Error::Registry)?;
    verify_audit(row.blob(1)?, &event, auth.object_hash(), &historical)?;
    Ok(DurableDestructionStart {
        job: object_hash(job.preflight().exact_core_bytes()),
        event,
        audit: row.blob(1)?.to_vec(),
    })
}
fn verify_audit(
    exact: &[u8],
    event: &VerifiedDestructionEvent,
    authorization: ObjectHash,
    head: &HistoricalRegistryAuthority,
) -> Result<(), Error> {
    let audit = decode_local_audit_event(exact).map_err(|_| Error::Audit)?;
    if audit.organization_id() != head.organization_id()
        || audit.effective_now() != event.fields().executed_at
        || audit.outcome() != LocalAuditOutcomeV1::Completed
        || !matches!(audit.action(),LocalAuditActionV1::Destruction(c) if c.destruction_authorization_object_hash()==authorization && c.state_event_object_hash()==event.object_hash())
    {
        return Err(Error::Audit);
    }
    let certificate = CertificateHash::from(audit.signer_certificate_object_hash());
    let binding = head
        .active_operator_binding_fields(audit.operator_binding_object_hash().ok_or(Error::Audit)?)
        .ok_or(Error::Audit)?;
    let fields = head
        .active_certificate_fields(certificate)
        .ok_or(Error::Audit)?;
    if binding.device_certificate_hash != certificate
        || fields.device_id != audit.device_id()
        || binding.organization_id != audit.organization_id()
    {
        return Err(Error::Audit);
    }
    let role = match fields.certificate_kind {
        CertificateKindV1::Writer => SignerRole::Writer,
        CertificateKindV1::Reader => SignerRole::Reader,
        CertificateKindV1::OrganizationAdmin => SignerRole::OrganizationAdmin,
        _ => return Err(Error::Audit),
    };
    let context = VerificationContext::local_audit(
        audit.exact_core(),
        head.proposed_sequence(),
        role,
        head.registry_version(),
    )
    .map_err(|_| Error::Audit)?;
    let mut d = minicbor::Decoder::new(exact);
    d.array().map_err(|_| Error::Audit)?;
    d.skip().map_err(|_| Error::Audit)?;
    verify_cose_sign1(&exact[d.position()..], head, &context).map_err(|_| Error::Audit)?;
    Ok(())
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
fn integer(value: u64) -> Result<StoreValue, Error> {
    Ok(StoreValue::Integer(
        i64::try_from(value).map_err(|_| Error::Format)?,
    ))
}
