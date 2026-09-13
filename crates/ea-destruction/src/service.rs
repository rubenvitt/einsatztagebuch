use crate::original_authority::OriginalAuthority;
use crate::{
    DestructionError as Error, DestructionState, DestructionStateMachine,
    VerifiedDestructionAuthorization, VerifiedDestructionEvent, VerifiedDestructionTarget,
    verify_authorization, verify_event,
};
use ea_audit::{
    AuditActorProof, SignedLocalAuditService, SqliteLocalAuditRepository, TypedLocalAuditEvent,
};
use ea_crypto::{SignerRole, VerificationContext, parse_cose_sign1, verify_cose_sign1};
use ea_format::{
    CertificateKindV1, DestructionContextV1, LocalAuditActionV1, LocalAuditOutcomeV1,
    OperatorRoleV1, decode_local_audit_event,
};
use ea_local_store::{EncryptedDatabase, StoreRow, StoreValue};
use ea_operator::{OperatorSessionProof, OsAccountProvider, ReauthPurpose, verify_current_session};
use ea_trust::SelectedRegistryHead;
use ea_types::{CertificateHash, EventId};
use std::{collections::BTreeSet, sync::Arc};

/// Production SQLCipher adapter. Immutable exact bytes are the state source.
/// No mutable state flag exists. The audit and request share a transaction.
pub struct SqliteDestructionRepository {
    database: Arc<EncryptedDatabase>,
}
const READ_REQUEST: &str = "SELECT d.exact_authorization,d.exact_event,a.exact_bytes FROM destruction_request d JOIN local_audit_event a ON a.event_id=d.audit_event_id WHERE d.organization_id=?1 AND d.destruction_id=?2";
impl SqliteDestructionRepository {
    pub fn new(database: Arc<EncryptedDatabase>) -> Self {
        Self { database }
    }
    /// Reconstruct the immutable request with its ORIGINAL authorization head.
    /// This is historical evidence only, never current execution authority.
    /// A host must use `DestructionRequestService::resume` with a freshly
    /// selected current head and native proof before admitting continuation.
    pub fn reconstruct(
        &self,
        auth: &VerifiedDestructionAuthorization,
        head: &SelectedRegistryHead,
    ) -> Result<Option<RequestedDestruction>, Error> {
        // Recheck original policy, approvers, event and signed audit in their
        // historical context. Progress/revocation cannot rewrite past evidence.
        self.reconstruct_original(
            auth,
            OriginalAuthority::Selected(head),
            head.preexisting_effective_now().value(),
        )
    }
    pub fn reconstruct_historical(
        &self,
        auth: &VerifiedDestructionAuthorization,
        head: &ea_trust::HistoricalRegistryAuthority,
        observed_at: ea_types::UnixMillis,
    ) -> Result<Option<RequestedDestruction>, Error> {
        self.reconstruct_original(auth, OriginalAuthority::Historical(head), observed_at)
    }
    fn reconstruct_original(
        &self,
        auth: &VerifiedDestructionAuthorization,
        head: OriginalAuthority<'_>,
        observed: ea_types::UnixMillis,
    ) -> Result<Option<RequestedDestruction>, Error> {
        let auth = head.authorization(auth.exact_bytes())?;
        self.database
            .query_row(READ_REQUEST, &request_key(&auth))?
            .map(|row| read_request(row, &auth, head, observed))
            .transpose()
    }
}
/// Native service; the host refreshes the selected Head immediately before
/// invocation, as required by verify_current_session. Event signing belongs to
/// the Root-certified deletionAttest component; submitted bytes are untrusted
/// until this service verifies them.
pub struct DestructionRequestService<'a> {
    pub head: &'a SelectedRegistryHead,
    pub certificate: CertificateHash,
    pub role: OperatorRoleV1,
    pub account: &'a dyn OsAccountProvider,
    pub audit: &'a SignedLocalAuditService,
    pub repository: &'a SqliteDestructionRepository,
}
/// Only issued after the signed native audit AND event have committed.
/// This is request admission, not executor preflight/completion authority.
pub struct RequestedDestruction {
    authorization: VerifiedDestructionAuthorization,
    event: VerifiedDestructionEvent,
    audit_event_id: EventId,
    audit_bytes: Vec<u8>,
}
impl RequestedDestruction {
    pub const fn state(&self) -> DestructionState {
        DestructionState::Requested
    }
    pub const fn audit_event_id(&self) -> EventId {
        self.audit_event_id
    }
    pub const fn authorization(&self) -> &VerifiedDestructionAuthorization {
        &self.authorization
    }
    pub const fn event(&self) -> &VerifiedDestructionEvent {
        &self.event
    }
    pub fn audit_exact_bytes(&self) -> &[u8] {
        &self.audit_bytes
    }
}
impl DestructionRequestService<'_> {
    /// Resume an expired original context as history, with separate current
    /// native authority. No historical head becomes a selected head.
    pub fn resume_historical<'a>(
        &'a self,
        authorization: &VerifiedDestructionAuthorization,
        original: &'a ea_trust::HistoricalRegistryAuthority,
        proof: &OperatorSessionProof,
    ) -> Result<ResumedDestruction<'a>, Error> {
        self.resume_original(
            authorization,
            OriginalAuthority::Historical(original),
            proof,
        )
    }
    /// Resume the same durable operation. Historical authorization/audit and
    /// current native authority deliberately have separate inputs. This emits
    /// no state event and grants no physical deletion capability.
    pub fn resume<'a>(
        &'a self,
        authorization: &VerifiedDestructionAuthorization,
        authorization_head: &'a SelectedRegistryHead,
        proof: &OperatorSessionProof,
    ) -> Result<ResumedDestruction<'a>, Error> {
        self.resume_original(
            authorization,
            OriginalAuthority::Selected(authorization_head),
            proof,
        )
    }
    pub(crate) fn resume_original<'a>(
        &'a self,
        authorization: &VerifiedDestructionAuthorization,
        authorization_head: OriginalAuthority<'a>,
        proof: &OperatorSessionProof,
    ) -> Result<ResumedDestruction<'a>, Error> {
        let request = self
            .repository
            .reconstruct_original(
                authorization,
                authorization_head,
                self.head.preexisting_effective_now().value(),
            )?
            .ok_or(Error::Storage)?;
        if self.head.policy_fields().organization_id != authorization.fields().organization_id
            || self.head.chain_id() != authorization_head.chain_id()
            || self.head.registry_version() < authorization_head.registry_version()
            || self.head.proposed_sequence() < authorization_head.proposed_sequence()
            || self.head.preexisting_effective_now().value() < request.event.fields().executed_at
            || self.head.preexisting_effective_now().value() > self.head.not_after()
        {
            return Err(Error::Registry);
        }
        let policy = &self.head.policy_fields().retention_policy;
        if !policy.destruction_enabled || policy.eds_privacy_decision_document_hash.is_none() {
            return Err(Error::PrivacyGate);
        }
        verify_current_session(
            self.head,
            self.certificate,
            self.role,
            proof,
            ReauthPurpose::Destruction,
            self.account,
        )
        .map_err(|_| Error::Operator)?;
        Ok(ResumedDestruction {
            request,
            authorization_head,
            current_head: self.head,
        })
    }

    pub fn request(
        &self,
        auth_bytes: &[u8],
        event_bytes: &[u8],
        targets: &[VerifiedDestructionTarget],
        proof: &OperatorSessionProof,
    ) -> Result<RequestedDestruction, Error> {
        self.request_guarded(
            auth_bytes,
            event_bytes,
            targets,
            proof,
            &mut crate::local::NoAdditionalAuthorityGuard,
        )
    }
    pub fn request_guarded(
        &self,
        auth_bytes: &[u8],
        event_bytes: &[u8],
        targets: &[VerifiedDestructionTarget],
        proof: &OperatorSessionProof,
        guard: &mut dyn crate::LocalActionAuthorityGuard,
    ) -> Result<RequestedDestruction, Error> {
        let auth = verify_authorization(auth_bytes, self.head)?;
        verify_current_session(
            self.head,
            self.certificate,
            self.role,
            proof,
            ReauthPurpose::Destruction,
            self.account,
        )
        .map_err(|_| Error::Operator)?;
        let target_hashes: BTreeSet<_> = targets.iter().map(|target| target.entry_hash()).collect();
        if target_hashes.len() != auth.fields().targets.len()
            || targets.len() != target_hashes.len()
            || targets
                .iter()
                .any(|target| target.authorization_hash() != auth.object_hash())
            || auth.fields().targets.iter().any(|target| {
                !target_hashes
                    .iter()
                    .any(|hash| hash.as_bytes() == target.entry_hash())
            })
        {
            return Err(Error::Target);
        }
        let event = verify_event(event_bytes, &auth, self.head)?;
        let mut machine = DestructionStateMachine::new(&auth);
        machine.apply(&event)?;
        if machine.state() != Some(DestructionState::Requested) {
            return Err(Error::Event);
        }
        self.repository.database.transaction(|tx| {
            guard.check_in(tx)?;
            // SQLite NORMAL/OFF may acknowledge a commit that power loss can
            // remove. Check while holding the same connection transaction;
            // the setting cannot change between audit and event persistence.
            let sync = tx.query_row("PRAGMA synchronous", &[])?
                .ok_or(Error::Storage)?.integer(0)?;
            if !matches!(sync, 2 | 3) { return Err(Error::Storage); }
            if let Some(row)=tx.query_row(READ_REQUEST,&request_key(&auth))? {
                let saved=read_request(row,&auth,OriginalAuthority::Selected(self.head),self.head.preexisting_effective_now().value())?;
                if saved.event.exact_bytes()!=event_bytes {return Err(Error::SecurityConflict)}
                return Ok(saved)
            }
            // Retry may use its old, exactly matching event; a NEW request
            // must bind the current selected trusted time.
            if event.fields().executed_at!=self.head.preexisting_effective_now().value() {return Err(Error::Event)}
            if tx.query_row("SELECT event_id FROM destruction_request WHERE event_id=?1 OR event_hash=?2",&[
                blob(event.fields().event_id.as_bytes()),blob(event.object_hash().as_bytes())
            ])?.is_some() {return Err(Error::SecurityConflict)}
            let audit=self.audit.prepare_signed(AuditActorProof::OperatorSession(proof),TypedLocalAuditEvent {
                action:LocalAuditActionV1::Destruction(DestructionContextV1::new(auth.object_hash(),event.object_hash())),
                outcome:LocalAuditOutcomeV1::Completed,
            })?;
            let result=verify_request(auth.clone(),event.clone(),audit.exact_bytes(),OriginalAuthority::Selected(self.head))?;
            if result.audit_event_id!=audit.id() {return Err(Error::Audit)}
            let decoded=decode_local_audit_event(audit.exact_bytes())?;
            if decoded.signer_certificate_object_hash().as_bytes()!=self.certificate.as_bytes()
                || decoded.operator_binding_object_hash()!=Some(proof.binding_object_hash())
                || decoded.device_id()!=proof.device_id() {return Err(Error::Audit)}
            guard.check_in(tx)?;
            SqliteLocalAuditRepository::append_prepared_in(tx,&audit)?;
            tx.execute("INSERT INTO destruction_request (organization_id,destruction_id,event_id,event_hash,exact_authorization,exact_event,audit_event_id) VALUES (?1,?2,?3,?4,?5,?6,?7)",&[
                blob(auth.fields().organization_id.as_bytes()),blob(auth.fields().destruction_id.as_bytes()),
                blob(event.fields().event_id.as_bytes()),blob(event.object_hash().as_bytes()),blob(auth_bytes),blob(event_bytes),blob(audit.id().as_bytes())
            ])?;
            Ok(result)
        })
    }
}

/// Fresh native admission around an immutable request. The host refreshes the
/// current selected head and obtains this short-lived scope for each invocation.
/// The executor still must persist a signed audit/event before advancing state.
pub struct ResumedDestruction<'a> {
    request: RequestedDestruction,
    authorization_head: OriginalAuthority<'a>,
    current_head: &'a SelectedRegistryHead,
}
impl ResumedDestruction<'_> {
    pub(crate) fn current_head(&self) -> &SelectedRegistryHead {
        self.current_head
    }

    pub(crate) fn authorization_head(&self) -> OriginalAuthority<'_> {
        self.authorization_head
    }

    pub const fn request(&self) -> &RequestedDestruction {
        &self.request
    }

    /// Verify a new signed claim at the current trusted time. v1 deliberately
    /// retains the ORIGINAL authorization-sequence signer profile used by the
    /// offline verifier. A component enrolled only afterwards is ineligible.
    /// Current revocation also refuses continuation by an original component.
    pub fn verify_event(&self, exact: &[u8]) -> Result<VerifiedDestructionEvent, Error> {
        let event = self.authorization_head.event(
            exact,
            self.request.authorization(),
            self.current_head.preexisting_effective_now().value(),
        )?;
        if event.fields().executed_at != self.current_head.preexisting_effective_now().value()
            || event.fields().from_state.is_none()
        {
            return Err(Error::Event);
        }
        let ea_format::ParsedArchiveObject::Trust(parsed) = ea_format::decode_exact_object(exact)?
        else {
            return Err(Error::Format);
        };
        let signature = &parsed.value().signatures()[0];
        let certificate = parse_cose_sign1(signature, &[])?
            .certificate_hash()
            .ok_or(Error::Signature)?;
        let fields = self
            .current_head
            .active_certificate_fields(certificate)
            .ok_or(Error::Signature)?;
        if fields.certificate_kind != CertificateKindV1::DeletionAttest
            || !fields
                .capabilities
                .iter()
                .any(|capability| capability == "deletionAttest")
        {
            return Err(Error::Signature);
        }
        Ok(event)
    }
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
fn request_key(auth: &VerifiedDestructionAuthorization) -> [StoreValue; 2] {
    [
        blob(auth.fields().organization_id.as_bytes()),
        blob(auth.fields().destruction_id.as_bytes()),
    ]
}
fn read_request(
    row: StoreRow,
    auth: &VerifiedDestructionAuthorization,
    head: OriginalAuthority<'_>,
    observed: ea_types::UnixMillis,
) -> Result<RequestedDestruction, Error> {
    if row.blob(0)? != auth.exact_bytes() {
        return Err(Error::SecurityConflict);
    }
    let event = head.event(row.blob(1)?, auth, observed)?;
    verify_request(auth.clone(), event, row.blob(2)?, head)
}
fn verify_request(
    auth: VerifiedDestructionAuthorization,
    event: VerifiedDestructionEvent,
    audit_bytes: &[u8],
    head: OriginalAuthority<'_>,
) -> Result<RequestedDestruction, Error> {
    let mut machine = DestructionStateMachine::new(&auth);
    machine.apply(&event)?;
    if machine.state() != Some(DestructionState::Requested) {
        return Err(Error::Event);
    }
    let audit = decode_local_audit_event(audit_bytes).map_err(|_| Error::Audit)?;
    if audit.organization_id() != auth.fields().organization_id
        || audit.effective_now() != event.fields().executed_at
        || audit.outcome() != LocalAuditOutcomeV1::Completed
        || !matches!(audit.action(),LocalAuditActionV1::Destruction(context) if context.destruction_authorization_object_hash()==auth.object_hash() && context.state_event_object_hash()==event.object_hash())
    {
        return Err(Error::Audit);
    }
    let cert = CertificateHash::from(audit.signer_certificate_object_hash());
    let binding_hash = audit.operator_binding_object_hash().ok_or(Error::Audit)?;
    head.require_binding(binding_hash)?;
    let binding = head
        .active_operator_binding_fields(binding_hash)
        .ok_or(Error::Audit)?;
    let fields = head.active_certificate_fields(cert).ok_or(Error::Audit)?;
    if binding.device_certificate_hash != cert
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
    // decode_local_audit_event checked the complete canonical pair. Extract
    // the exact second item rather than re-encoding its COSE signature.
    let mut decoder = minicbor::Decoder::new(audit_bytes);
    decoder.array().map_err(|_| Error::Audit)?;
    decoder.skip().map_err(|_| Error::Audit)?;
    verify_cose_sign1(&audit_bytes[decoder.position()..], &head, &context)
        .map_err(|_| Error::Audit)?;
    Ok(RequestedDestruction {
        authorization: auth,
        event,
        audit_event_id: audit.event_id(),
        audit_bytes: audit_bytes.to_vec(),
    })
}
