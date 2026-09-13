//! Local Admin authorization. Root signatures are produced only on the offline station.
use super::{
    ceremony::{self, AdministrationCeremony},
    views::current_view,
};
use crate::{
    AdminError, OperatorLifecycleError, TrustCeremonyStep, VerifiedOperatorSession,
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
};
use ea_audit::{AuditActorProof, SqliteLocalAuditRepository, TypedLocalAuditEvent};
use ea_crypto::{ContentType, SignerRole, VerificationContext, object_hash, trust_digest};
use ea_format::{
    DecodedTrustPayloadV1, GenericAuditContextV1, LocalAuditActionV1, LocalAuditOutcomeV1,
    OrganizationAdminAuthorizationFieldsV1, TrustObjectV1, TrustPayloadV1,
};
use ea_key_provider::{KeyProvider, SecretPurpose};
use ea_local_store::StoreValue;
use ea_operator::{MAX_INACTIVITY_MS, ReauthPurpose, verify_current_session};
use ea_trust::{
    RegistrySelectionOutcome, load_trust_state, prepare_local_time, select_registry_head,
    verify_intended_trust_target, verify_registry_candidate, verify_trust,
};
use ea_types::{AuthorizationId, Hash32, ObjectHash, UnixMillis};

fn conflict() -> OperatorRuntimeError {
    OperatorLifecycleError::JournalConflict.into()
}
fn audit_error() -> OperatorRuntimeError {
    OperatorLifecycleError::Ceremony(AdminError::AuditFailed).into()
}
fn format_error(_: ea_format::FormatError) -> OperatorRuntimeError {
    conflict()
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}

pub(crate) fn action_now(
    runtime: &OperatorRuntime,
    session: &VerifiedOperatorSession,
) -> Result<UnixMillis, OperatorRuntimeError> {
    runtime.ensure_same_action_authority()?;
    let fresh = runtime.reopened_for_action()?;
    fresh.ensure_current()?;
    if fresh.head().registry_head_hash() != runtime.head().registry_head_hash()
        || !fresh
            .head()
            .preexisting_effective_now()
            .has_same_persisted_bounds(runtime.head().preexisting_effective_now())
        || fresh.next_sequence() != runtime.next_sequence()
    {
        return Err(conflict());
    }
    verify_current_session(
        fresh.head(),
        fresh.config().device_certificate_hash,
        ea_format::OperatorRoleV1::OrganizationAdmin,
        session.proof(),
        ReauthPurpose::AdminRootCeremony,
        fresh.native().as_ref(),
    )?;
    if session.profile().operator_binding_object_hash() != fresh.config().binding_object_hash {
        return Err(conflict());
    }
    Ok(fresh.head().preexisting_effective_now().value())
}
pub fn authorize(
    runtime: &mut OperatorRuntime,
    id: ObjectHash,
    session: &VerifiedOperatorSession,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    current_view(runtime)?;
    action_now(runtime, session)?;
    let pending = ceremony::load(runtime, id)?;
    if pending.step() == TrustCeremonyStep::AdminAuthorized {
        return Ok(pending);
    }
    let expected = if pending.kind() == crate::TrustCeremonyKind::DeviceApprove {
        TrustCeremonyStep::FingerprintConfirmed
    } else {
        TrustCeremonyStep::PendingRequest
    };
    if pending.step() != expected {
        return Err(conflict());
    }
    let now = action_now(runtime, session)?;
    let provisional = finish_registry_time(pending.exact_target_payload(), now)?;
    let description = ea_trust::describe_intended_trust_target(
        runtime.trust(),
        Some(runtime.head()),
        &provisional,
        runtime.next_sequence(),
    )?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| conflict())?;
    let expiry = now
        .get()
        .checked_add(MAX_INACTIVITY_MS)
        .ok_or_else(conflict)?
        .min(runtime.head().not_after().get())
        .min(
            runtime
                .head()
                .preexisting_effective_now()
                .wall_clock_ceiling()
                .map(|n| n.get().saturating_add(1))
                .unwrap_or(i64::MAX),
        )
        .min(
            runtime
                .head()
                .preexisting_effective_now()
                .successor_ready_at()
                .map(|n| n.get())
                .unwrap_or(i64::MAX),
        );
    if expiry <= now.get() {
        return Err(OperatorRuntimeError::Expired);
    }
    let certificate = runtime.config().device_certificate_hash;
    let fields = runtime
        .head()
        .active_certificate_fields(certificate)
        .ok_or_else(conflict)?;
    let authorization_payload =
        TrustPayloadV1::organization_admin_authorization(OrganizationAdminAuthorizationFieldsV1 {
            authorization_id: AuthorizationId::try_from(&nonce[..16]).map_err(|_| conflict())?,
            organization_id: description.organization_id(),
            registry_version: runtime.head().registry_version(),
            registry_head_hash: Hash32::try_from(
                runtime.head().registry_head_hash().as_bytes().as_slice(),
            )
            .map_err(|_| conflict())?,
            admin_key_thumbprint: fields.signing_key_thumbprint.ok_or_else(conflict)?,
            admin_certificate_hash: certificate,
            admin_operator_binding_object_hash: runtime.config().binding_object_hash,
            action_code: description.action_code(),
            target_trust_subtype: provisional.subtype(),
            authorized_trust_core_hash: description.authorized_core_hash(),
            issued_at: now,
            expires_at: UnixMillis::new(expiry),
            nonce,
        })
        .map_err(format_error)?;
    VerificationContext::organization_admin_trust_digest(
        authorization_payload.exact_digest_input(),
    )
    .map_err(|_| conflict())?;
    action_now(runtime, session)?;
    let provider = runtime.signing_provider();
    let signature = provider.sign(
        &provider.handle(SecretPurpose::WriterSigningKey),
        ContentType::TrustDigest,
        certificate,
        trust_digest(authorization_payload.exact_digest_input()).as_bytes(),
    )?;
    let current = action_now(runtime, session)?;
    let authorization = ea_format::encode_trust(
        &TrustObjectV1::new(authorization_payload, vec![signature.as_bytes().to_vec()])
            .map_err(format_error)?,
    )
    .map_err(format_error)?
    .into_vec();
    let target =
        super::target::UntrustedAdministrationTarget::parse(provisional.exact_digest_input())
            .map_err(format_error)?
            .payload(object_hash(&authorization))
            .map_err(format_error)?;
    verify_authorization(runtime, &target, &authorization, current)?;
    let audit_time = action_now(runtime, session)?;
    let audit_service = ea_audit::SignedLocalAuditService::new(
        std::sync::Arc::new(SqliteLocalAuditRepository::new(runtime.database().clone())),
        provider.clone(),
        provider.handle(SecretPurpose::WriterSigningKey),
        ObjectHash::try_from(certificate.as_bytes().as_slice()).map_err(|_| conflict())?,
        audit_time,
    );
    let audit = audit_service
        .prepare_signed(
            AuditActorProof::OperatorSession(session.proof()),
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::Login(GenericAuditContextV1::new(Some(object_hash(
                    &authorization,
                )))),
                outcome: LocalAuditOutcomeV1::Accepted,
            },
        )
        .map_err(|_| audit_error())?;
    action_now(runtime, session)?;
    verify_audit(runtime, audit.exact_bytes(), object_hash(&authorization))?;
    let record = encode_record(&authorization, target.exact_digest_input())?;
    runtime.database().transaction(|tx| {
        ceremony::affirm_persisted(runtime,tx)?;
        if tx.query_row("SELECT stage FROM administration_ceremony_record WHERE intent_hash=?1 AND stage!=0 LIMIT 1",&[blob(id.as_bytes())])?.is_some(){return Err(conflict())}
        SqliteLocalAuditRepository::append_prepared_in(tx,&audit).map_err(|_|audit_error())?;
        tx.execute("INSERT INTO administration_ceremony_record(intent_hash,stage,exact_record,audit_event_id) VALUES(?1,1,?2,?3)",&[blob(id.as_bytes()),blob(&record),blob(audit.id().as_bytes())])?;
        Ok::<(),OperatorRuntimeError>(())
    })?;
    action_now(runtime, session)?;
    ceremony::load(runtime, id)
}
fn finish_registry_time(
    exact: &[u8],
    now: UnixMillis,
) -> Result<TrustPayloadV1, OperatorRuntimeError> {
    let original = TrustPayloadV1::from_exact_digest_input(exact).map_err(format_error)?;
    let DecodedTrustPayloadV1::RegistryEvent(core) =
        original.decoded_payload().map_err(format_error)?
    else {
        let target =
            super::target::UntrustedAdministrationTarget::parse(exact).map_err(format_error)?;
        if target
            .payload(ObjectHash::from(Hash32::ZERO))
            .map_err(format_error)?
            .exact_digest_input()
            != exact
        {
            return Err(conflict());
        }
        return Ok(original);
    };
    if core.authorization_object_hash() != ObjectHash::from(Hash32::ZERO)
        || core.fields().issued_at > now
    {
        return Err(conflict());
    }
    let mut fields = core.fields().clone();
    fields.issued_at = now;
    fields.not_before = now;
    TrustPayloadV1::registry_event(fields, ObjectHash::from(Hash32::ZERO)).map_err(format_error)
}
fn encode_record(authorization: &[u8], target: &[u8]) -> Result<Vec<u8>, OperatorRuntimeError> {
    let mut encoded = minicbor::Encoder::new(Vec::new());
    encoded
        .array(2)
        .and_then(|e| e.bytes(authorization))
        .and_then(|e| e.bytes(target))
        .map_err(|_| conflict())?;
    Ok(encoded.into_writer())
}
pub(crate) fn restore(
    runtime: &OperatorRuntime,
    id: ObjectHash,
    provisional: &[u8],
) -> Result<Option<Vec<u8>>, OperatorRuntimeError> {
    if runtime.database().query_row("SELECT stage FROM administration_ceremony_record WHERE intent_hash=?1 AND stage NOT IN (0,1,2,3) LIMIT 1",&[blob(id.as_bytes())])?.is_some(){return Err(conflict())}
    let Some(row)=runtime.database().query_row("SELECT r.exact_record,a.exact_bytes FROM administration_ceremony_record r LEFT JOIN local_audit_event a ON a.event_id=r.audit_event_id WHERE r.intent_hash=?1 AND r.stage=1",&[blob(id.as_bytes())])? else{
        if runtime.database().query_row("SELECT stage FROM administration_ceremony_record WHERE intent_hash=?1 AND stage!=0 LIMIT 1",&[blob(id.as_bytes())])?.is_some(){return Err(conflict())}
        return Ok(None)
    };
    let exact = row.blob(0)?;
    let mut decoder = minicbor::Decoder::new(exact);
    if decoder.array().map_err(|_| conflict())? != Some(2) {
        return Err(conflict());
    }
    let authorization = decoder.bytes().map_err(|_| conflict())?;
    let target_bytes = decoder.bytes().map_err(|_| conflict())?;
    if decoder.position() != exact.len() || encode_record(authorization, target_bytes)? != exact {
        return Err(conflict());
    }
    let target = TrustPayloadV1::from_exact_digest_input(target_bytes).map_err(format_error)?;
    let issued = match target.decoded_payload().map_err(format_error)? {
        DecodedTrustPayloadV1::RegistryEvent(core) => core.fields().issued_at,
        _ => runtime.head().preexisting_effective_now().value(),
    };
    let expected = finish_registry_time(provisional, issued)?;
    let expected =
        super::target::UntrustedAdministrationTarget::parse(expected.exact_digest_input())
            .map_err(format_error)?
            .payload(object_hash(authorization))
            .map_err(format_error)?;
    if expected.exact_digest_input() != target_bytes {
        return Err(conflict());
    }
    verify_authorization(
        runtime,
        &target,
        authorization,
        runtime.head().preexisting_effective_now().value(),
    )?;
    verify_audit(runtime, row.blob(1)?, object_hash(authorization))?;
    Ok(Some(target_bytes.to_vec()))
}
pub(crate) fn verify_authorization(
    runtime: &OperatorRuntime,
    target: &TrustPayloadV1,
    authorization: &[u8],
    now: UnixMillis,
) -> Result<ea_trust::VerifiedAdminAuthorizationIntent, OperatorRuntimeError> {
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(authorization).map_err(format_error)?
    else {
        return Err(conflict());
    };
    let DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) =
        parsed.value().decoded_payload().map_err(format_error)?
    else {
        return Err(conflict());
    };
    if fields.admin_certificate_hash != runtime.config().device_certificate_hash
        || fields.admin_operator_binding_object_hash != runtime.config().binding_object_hash
        || fields.registry_version != runtime.head().registry_version()
        || fields.registry_head_hash.as_bytes() != runtime.head().registry_head_hash().as_bytes()
    {
        return Err(conflict());
    }
    // Registry authorization use is the exact signed event time. Current
    // action admission remains independently bound to actual verified time.
    if now < fields.issued_at || now > fields.expires_at {
        return Err(OperatorRuntimeError::Expired);
    }
    let use_time = match target.decoded_payload().map_err(format_error)? {
        DecodedTrustPayloadV1::RegistryEvent(core) => core.fields().issued_at,
        _ => now,
    };
    let objects = vec![authorization.to_vec()];
    let source = crate::operator_remote::ObjectOverlay::new(runtime.inventory(), &objects);
    let mut store = runtime.trust_store().clone();
    let trust = verify_trust(
        runtime.anchor(),
        &source,
        load_trust_state(&mut store, runtime.trust().state_key())?,
    )?;
    let candidate = verify_registry_candidate(&trust, runtime.next_sequence())?;
    let time = prepare_local_time(&mut store, &candidate, now, &[])?;
    let RegistrySelectionOutcome::Selected(head) = select_registry_head(candidate, time, None)?
    else {
        return Err(conflict());
    };
    if head.registry_head_hash() != runtime.head().registry_head_hash()
        || !head
            .preexisting_effective_now()
            .has_same_persisted_bounds(runtime.head().preexisting_effective_now())
    {
        return Err(conflict());
    }
    Ok(verify_intended_trust_target(
        &trust,
        Some(&head),
        target,
        use_time,
        runtime.next_sequence(),
    )?)
}
fn verify_audit(
    runtime: &OperatorRuntime,
    exact: &[u8],
    authorization: ObjectHash,
) -> Result<(), OperatorRuntimeError> {
    let audit = ea_format::decode_local_audit_event(exact).map_err(|_| audit_error())?;
    if audit.organization_id() != runtime.anchor().organization_id()
        || audit.signer_certificate_object_hash().as_bytes()
            != runtime.config().device_certificate_hash.as_bytes()
        || audit.operator_binding_object_hash() != Some(runtime.config().binding_object_hash)
        || audit.outcome() != LocalAuditOutcomeV1::Accepted
        || !matches!(audit.action(),LocalAuditActionV1::Login(c) if c.subject_object_hash()==Some(authorization))
    {
        return Err(audit_error());
    }
    let mut decoder = minicbor::Decoder::new(exact);
    decoder.array().map_err(|_| audit_error())?;
    decoder.skip().map_err(|_| audit_error())?;
    let start = decoder.position();
    decoder.skip().map_err(|_| audit_error())?;
    let context = VerificationContext::local_audit(
        audit.exact_core(),
        runtime.next_sequence(),
        SignerRole::OrganizationAdmin,
        runtime.head().registry_version(),
    )
    .map_err(|_| audit_error())?;
    ea_crypto::verify_cose_sign1(&exact[start..decoder.position()], runtime.head(), &context)
        .map_err(|_| audit_error())?;
    Ok(())
}
