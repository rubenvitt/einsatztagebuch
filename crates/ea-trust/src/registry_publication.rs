//! An exact Registry transition's local publication audit, never live authority.
use crate::{RegistryError, TrustError, VerifiedTrust, resolver::PreviousHeadState};
use ea_crypto::{
    CryptoError, ResolvedSigner, SignerCertificateResolver, SignerRole, VerificationContext,
};
use ea_format::{
    DecodedTrustPayloadV1, LocalAuditActionV1, LocalAuditOutcomeV1,
    OrganizationAdminAuthorizationFieldsV1, RegistryChangeV1, RegistryEventFieldsV1,
};
use ea_types::{CertificateHash, ChainSequence, EventId, ObjectHash, RegistryVersion};

/// This proof cannot verify any unrelated signature or authorize a new action.
/// It preserves exactly the audit of an already verified Registry transition.
///
/// ```compile_fail
/// fn generic(value: &impl ea_crypto::SignerCertificateResolver) {}
/// fn cannot_substitute(proof: &ea_trust::VerifiedRegistryPublicationAudit) { generic(proof); }
/// ```
pub struct VerifiedRegistryPublicationAudit {
    authorization: OrganizationAdminAuthorizationFieldsV1,
    authorization_hash: ObjectHash,
    target_hash: ObjectHash,
    target: RegistryEventFieldsV1,
    sequence: ChainSequence,
    audit_id: EventId,
}
impl VerifiedRegistryPublicationAudit {
    pub fn authorization_fields(&self) -> &OrganizationAdminAuthorizationFieldsV1 {
        &self.authorization
    }
    pub fn authorization_hash(&self) -> ObjectHash {
        self.authorization_hash
    }
    pub fn target_hash(&self) -> ObjectHash {
        self.target_hash
    }
    pub fn target_fields(&self) -> &RegistryEventFieldsV1 {
        &self.target
    }
    pub fn original_sequence(&self) -> ChainSequence {
        self.sequence
    }
    pub fn audit_event_id(&self) -> EventId {
        self.audit_id
    }
}
struct PublicationResolver<'a> {
    state: &'a PreviousHeadState,
    sequence: ChainSequence,
}
impl SignerCertificateResolver for PublicationResolver<'_> {
    fn resolve(
        &self,
        certificate: CertificateHash,
        registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        self.state
            .resolve_selected(certificate, registry, self.sequence)
    }
}
/// Replay the ordinary exact Registry transition, then check only its original
/// authorizing Admin's corresponding completed local publication audit.
/// No wall clock, pin update, SelectedHead or historical authority is produced.
pub fn verify_registry_publication_audit(
    trust: &VerifiedTrust,
    target_hash: ObjectHash,
    exact_audit: &[u8],
) -> Result<VerifiedRegistryPublicationAudit, RegistryError> {
    let (state, sequence, target, authorization_hash) =
        crate::registry::registry_publication_predecessor(trust, target_hash)?;
    if !matches!(
        target.change,
        RegistryChangeV1::Certificate { .. }
            | RegistryChangeV1::Target { .. }
            | RegistryChangeV1::Policy { .. }
            | RegistryChangeV1::WriterTransition { .. }
    ) {
        return Err(TrustError::ActionMismatch.into());
    }
    let record = state
        .catalog_object(authorization_hash)
        .ok_or(RegistryError::ActivationMissing)?;
    let DecodedTrustPayloadV1::OrganizationAdminAuthorization(authorization) = record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::ActionMismatch.into());
    };
    let audit_id = verify_exact_audit(
        &state,
        sequence,
        &authorization,
        authorization_hash,
        target_hash,
        target.issued_at,
        exact_audit,
    )?;
    Ok(VerifiedRegistryPublicationAudit {
        authorization,
        authorization_hash,
        target_hash,
        target,
        sequence,
        audit_id,
    })
}

/// Exact historical publication only; never a certificate activation or action authority.
pub struct VerifiedDirectTargetPublicationAudit {
    authorization: OrganizationAdminAuthorizationFieldsV1,
    authorization_hash: ObjectHash,
    target_hash: ObjectHash,
    sequence: ChainSequence,
    audit_id: EventId,
}
impl VerifiedDirectTargetPublicationAudit {
    pub fn authorization_fields(&self) -> &OrganizationAdminAuthorizationFieldsV1 {
        &self.authorization
    }
    pub fn authorization_hash(&self) -> ObjectHash {
        self.authorization_hash
    }
    pub fn target_hash(&self) -> ObjectHash {
        self.target_hash
    }
    pub fn original_sequence(&self) -> ChainSequence {
        self.sequence
    }
    pub fn audit_event_id(&self) -> EventId {
        self.audit_id
    }
}
/// The exact Root-signed target binds its effective sequence and authorization.
/// The local audit binds final object hash, authorization, action and signed time.
/// This function does not select an old head, mutate pins or grant current authority.
pub fn verify_direct_target_publication_audit(
    trust: &VerifiedTrust,
    target_hash: ObjectHash,
    exact_audit: &[u8],
) -> Result<VerifiedDirectTargetPublicationAudit, RegistryError> {
    let (state, sequence, authorization_hash) =
        crate::registry::direct_publication_authority(trust, target_hash)?;
    let audit =
        ea_format::decode_local_audit_event(exact_audit).map_err(|_| TrustError::Signature)?;
    crate::admin_authorization::verify_admin_authorization(
        &state,
        authorization_hash,
        target_hash,
        audit.effective_now(),
        sequence,
        &mut crate::admin_authorization::AdminAuthorizationReplay::default(),
    )?;
    let record = state
        .catalog_object(authorization_hash)
        .ok_or(TrustError::Source)?;
    let DecodedTrustPayloadV1::OrganizationAdminAuthorization(authorization) = record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::ActionMismatch.into());
    };
    let audit_id = verify_exact_audit(
        &state,
        sequence,
        &authorization,
        authorization_hash,
        target_hash,
        authorization.issued_at,
        exact_audit,
    )?;
    Ok(VerifiedDirectTargetPublicationAudit {
        authorization,
        authorization_hash,
        target_hash,
        sequence,
        audit_id,
    })
}

fn verify_exact_audit(
    state: &PreviousHeadState,
    sequence: ChainSequence,
    authorization: &OrganizationAdminAuthorizationFieldsV1,
    authorization_hash: ObjectHash,
    target_hash: ObjectHash,
    earliest: ea_types::UnixMillis,
    exact_audit: &[u8],
) -> Result<EventId, RegistryError> {
    let audit =
        ea_format::decode_local_audit_event(exact_audit).map_err(|_| TrustError::Signature)?;
    let binding = state
        .active_operator_binding(authorization.admin_operator_binding_object_hash, sequence)
        .ok_or(TrustError::ActionMismatch)?;
    let certificate = state
        .active_certificate(authorization.admin_certificate_hash, sequence)
        .ok_or(TrustError::ActionMismatch)?;
    if audit.organization_id() != authorization.organization_id
        || audit.device_id() != certificate.fields.device_id
        || audit.signer_certificate_object_hash().as_bytes()
            != authorization.admin_certificate_hash.as_bytes()
        || audit.operator_binding_object_hash()
            != Some(authorization.admin_operator_binding_object_hash)
        || binding.fields.device_certificate_hash != authorization.admin_certificate_hash
        || audit.outcome() != LocalAuditOutcomeV1::Completed
        || audit.effective_now() < authorization.issued_at
        || audit.effective_now() < earliest
        || audit.effective_now() > authorization.expires_at
        || state.head_event.as_ref().is_none_or(|head| {
            audit.effective_now() < head.not_before
                || audit.effective_now() < head.issued_at
                || audit.effective_now() >= head.not_after
        })
        || !matches!(audit.action(), LocalAuditActionV1::AdminRootCeremony(context)
            if context.authorization_object_hash() == authorization_hash
            && context.target_object_hash() == target_hash
            && context.action_code() == u64::from(authorization.action_code))
    {
        return Err(TrustError::ActionMismatch.into());
    }
    let context = VerificationContext::local_audit(
        audit.exact_core(),
        sequence,
        SignerRole::OrganizationAdmin,
        state.registry_version,
    )
    .map_err(|_| TrustError::Signature)?;
    let mut decoder = minicbor::Decoder::new(exact_audit);
    decoder.array().map_err(|_| TrustError::Signature)?;
    decoder.skip().map_err(|_| TrustError::Signature)?;
    let start = decoder.position();
    decoder.skip().map_err(|_| TrustError::Signature)?;
    ea_crypto::verify_cose_sign1(
        &exact_audit[start..decoder.position()],
        &PublicationResolver {
            state,
            sequence,
        },
        &context,
    )
    .map_err(|_| TrustError::Signature)?;
    Ok(audit.event_id())
}
