//! Exclusive durable audits for purpose-limited Clock repair.
use crate::{AuditError, LocalAuditRepository, SignedLocalAuditEvent};
use ea_crypto::{CanonicalPublicCoseKey, ContentType};
use ea_format::{
    ClockReleaseJustificationV1, GenericAuditContextV1, LocalAuditActionV1,
    LocalAuditEventCoreFieldsV1, LocalAuditOutcomeV1, encode_local_audit_core,
    encode_local_audit_event,
};
use ea_key_provider::{KeyHandle, KeyProvider};
use ea_operator::ClockRepairSession;
use ea_types::{EventId, ObjectHash, UnixMillis};
use std::sync::Arc;

/// Evidence of a durably stored Login/Completed from this exact presence.
/// There is no public constructor or conversion to a generic audit actor.
pub struct ClockRepairLogin {
    event: SignedLocalAuditEvent,
    subject: ObjectHash,
}
impl ClockRepairLogin {
    pub fn event(&self) -> &SignedLocalAuditEvent {
        &self.event
    }
}
pub struct ClockRepairAuditService {
    repository: Arc<dyn LocalAuditRepository>,
    provider: Arc<dyn KeyProvider>,
    handle: KeyHandle,
}
impl ClockRepairAuditService {
    pub fn new(
        repository: Arc<dyn LocalAuditRepository>,
        provider: Arc<dyn KeyProvider>,
        handle: KeyHandle,
    ) -> Self {
        Self {
            repository,
            provider,
            handle,
        }
    }

    /// The supplied time is for already bounded callers. Native hosts use the
    /// checked variant to revalidate their actual context around blocking work.
    pub fn record_login(
        &self,
        session: &ClockRepairSession<'_>,
        now: UnixMillis,
    ) -> Result<ClockRepairLogin, AuditError> {
        self.record_login_checked(session, || Ok(now))
    }

    /// Revalidates actual host context before signing, before durable append,
    /// and after reread. Signed time remains the sealed original observation.
    pub fn record_login_checked(
        &self,
        session: &ClockRepairSession<'_>,
        mut check: impl FnMut() -> Result<UnixMillis, AuditError>,
    ) -> Result<ClockRepairLogin, AuditError> {
        let subject = session.login_subject_hash();
        let event = self.sign_and_append(
            session,
            LocalAuditActionV1::Login(GenericAuditContextV1::new(Some(subject))),
            LocalAuditOutcomeV1::Completed,
            &mut check,
        )?;
        Ok(ClockRepairLogin { event, subject })
    }

    /// Consumes presence by value: one native presence cannot issue a second
    /// release. The original v1 selector still consumes the release by value.
    pub fn record_release(
        &self,
        session: ClockRepairSession<'_>,
        login: &ClockRepairLogin,
        justification: ClockReleaseJustificationV1,
        now: UnixMillis,
    ) -> Result<SignedLocalAuditEvent, AuditError> {
        self.record_release_checked(session, login, justification, || Ok(now))
    }

    /// A changing native context suppresses both append before commit and byte
    /// release after commit; it cannot renew the original purpose proof.
    pub fn record_release_checked(
        &self,
        session: ClockRepairSession<'_>,
        login: &ClockRepairLogin,
        justification: ClockReleaseJustificationV1,
        mut check: impl FnMut() -> Result<UnixMillis, AuditError>,
    ) -> Result<SignedLocalAuditEvent, AuditError> {
        if !session.is_valid_at(check()?) || login.subject != session.login_subject_hash() {
            return Err(AuditError::SessionExpired);
        }
        let stored = self.repository.event(login.event.id())?;
        if stored.exact_bytes() != login.event.exact_bytes() {
            return Err(AuditError::Encoding);
        }
        let context = session
            .authority()
            .release_context(justification, session.expires_at())
            .map_err(|_| AuditError::SessionExpired)?;
        self.sign_and_append(
            &session,
            LocalAuditActionV1::ClockSkewRelease(context),
            LocalAuditOutcomeV1::Accepted,
            &mut check,
        )
    }

    fn sign_and_append(
        &self,
        session: &ClockRepairSession<'_>,
        action: LocalAuditActionV1,
        outcome: LocalAuditOutcomeV1,
        check: &mut impl FnMut() -> Result<UnixMillis, AuditError>,
    ) -> Result<SignedLocalAuditEvent, AuditError> {
        require_valid(session, check)?;
        let authority = session.authority();
        let event_id =
            EventId::try_from(fresh::<16>()?.as_slice()).map_err(|_| AuditError::Encoding)?;
        let fields = LocalAuditEventCoreFieldsV1 {
            event_id,
            organization_id: authority.organization_id(),
            device_id: authority.device_id(),
            operator_binding_object_hash: Some(authority.binding_hash()),
            signer_certificate_object_hash: ObjectHash::try_from(
                authority.certificate_hash().as_bytes().as_slice(),
            )
            .map_err(|_| AuditError::Encoding)?,
            action,
            outcome,
            effective_now: authority.raw_now(),
            nonce: fresh::<32>()?,
        };
        let core = encode_local_audit_core(&fields)?;
        let cose = self.provider.sign(
            &self.handle,
            ContentType::LocalAuditCbor,
            authority.certificate_hash(),
            &core,
        )?;
        let exact = encode_local_audit_event(&core, cose.as_bytes())?;
        // Encoding checks exact content type, core and certificate correlation.
        // The already verified certificate supplies the actual signing key;
        // no generic resolver or caller-provided certificate can replace it.
        let public = CanonicalPublicCoseKey::from_deterministic_cbor(
            authority
                .certificate_fields()
                .signing_public_cose_key
                .as_deref()
                .ok_or(AuditError::Encoding)?,
        )?;
        public.verify_strict(cose.as_bytes())?;
        let event = SignedLocalAuditEvent::sealed(event_id, exact);
        require_valid(session, check)?;
        self.repository.append(&event)?;
        let stored = self.repository.event(event_id)?;
        if stored.exact_bytes() != event.exact_bytes() {
            return Err(AuditError::Encoding);
        }
        require_valid(session, check)?;
        Ok(event)
    }
}
fn require_valid(
    session: &ClockRepairSession<'_>,
    check: &mut impl FnMut() -> Result<UnixMillis, AuditError>,
) -> Result<(), AuditError> {
    if !session.is_valid_at(check()?) {
        return Err(AuditError::SessionExpired);
    }
    Ok(())
}
fn fresh<const N: usize>() -> Result<[u8; N], AuditError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| AuditError::LocalRng)?;
    Ok(bytes)
}
