use std::sync::Arc;

use ea_crypto::{CoseVerifier, CryptoError, SignerRole, VerificationContext, VerifiedSigner};
use ea_format::{
    CertificateKindV1, ClockReleaseAuditV1, IndependentTimeKindV1, LocalAuditOutcomeV1,
    OperatorRoleV1,
};
use ea_time::{
    FutureSkew, IndependentTimeKind, TimeWarnings, TrustedTimeState, evaluate_preexisting_time,
};
use ea_types::{CertificateHash, ChainSequence, UnixMillis};

use crate::{
    ClockReleaseError, ClockReleaseReplayKey, LocalTimeBlock, RegistryCandidate, RegistryHeadPin,
    TrustError, TrustStateKey,
    resolver::{PreviousHeadResolver, PreviousHeadState},
    state::map_store_error,
};

#[cfg_attr(not(test), allow(dead_code))]
struct ClockReleaseProof {
    candidate_state: Arc<PreviousHeadState>,
    state_key: TrustStateKey,
    expected_revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
    observed_os_wall_clock: UnixMillis,
    proposed_sequence: ChainSequence,
    pre_transition_sequence: ChainSequence,
    raw_now: UnixMillis,
    warnings: TimeWarnings,
    future_skew: FutureSkew,
    audit: ClockReleaseAuditV1,
    replay_key: ClockReleaseReplayKey,
}

/// Proof that an exact signed Clock Release authorizes one blocked local-time
/// evaluation. The proof is opaque and deliberately non-clonable.
///
/// Its private state cannot be constructed by callers:
///
/// ```compile_fail
/// use ea_trust::VerifiedClockRelease;
/// let _ = VerifiedClockRelease { inner: panic!() };
/// ```
///
/// It cannot be duplicated:
///
/// ```compile_fail
/// use ea_trust::VerifiedClockRelease;
/// fn require_clone<T: Clone>() {}
/// require_clone::<VerifiedClockRelease>();
/// ```
///
/// Raw audit bytes cannot substitute for a verified proof:
///
/// ```compile_fail
/// use ea_trust::VerifiedClockRelease;
/// fn consume(_: VerifiedClockRelease) {}
/// consume(Vec::<u8>::new());
/// ```
pub struct VerifiedClockRelease {
    #[cfg_attr(not(test), allow(dead_code))]
    inner: ClockReleaseProof,
}

pub fn verify_clock_release(
    candidate: &RegistryCandidate,
    local_time: &mut LocalTimeBlock<'_>,
    exact_audit_bytes: &[u8],
) -> Result<VerifiedClockRelease, ClockReleaseError> {
    require_candidate_block_preflight(candidate, local_time)?;

    let audit = ea_format::decode_clock_release_audit(exact_audit_bytes)
        .map_err(|_| ClockReleaseError::Mismatch)?;
    let previous = candidate
        .preexisting_authority()
        .ok_or(ClockReleaseError::Mismatch)?;
    let context = VerificationContext::local_audit(
        audit.exact_core(),
        local_time.pre_transition_sequence,
        SignerRole::OrganizationAdmin,
        previous.inner.registry_version,
    )
    .map_err(|_| ClockReleaseError::Trust(TrustError::Signature))?;
    let verified_signer = CoseVerifier::verify_normal(
        audit.exact_cose(),
        &PreviousHeadResolver::new(&previous.inner),
        &context,
    )
    .map_err(map_clock_release_crypto_error)?;

    require_previous_admin(
        &previous.inner,
        &audit,
        &verified_signer,
        local_time.pre_transition_sequence,
    )?;
    require_signed_correlations(candidate, local_time, &audit)?;

    let replay_key = ClockReleaseReplayKey::from_verified_audit(&audit);
    let consumed = local_time
        .store
        .clock_release_consumed(&replay_key)
        .map_err(map_store_error)
        .map_err(ClockReleaseError::Trust)?;
    if consumed {
        return Err(ClockReleaseError::Trust(TrustError::ClockReleaseReplay));
    }

    Ok(VerifiedClockRelease {
        inner: ClockReleaseProof {
            candidate_state: Arc::clone(&candidate.candidate_state),
            state_key: local_time.state_key,
            expected_revision: local_time.expected_revision,
            trusted_time: local_time.trusted_time.clone(),
            pinned_head: local_time.pinned_head,
            observed_os_wall_clock: local_time.observed_os_wall_clock,
            proposed_sequence: local_time.proposed_sequence,
            pre_transition_sequence: local_time.pre_transition_sequence,
            raw_now: local_time.evaluation.raw_now(),
            warnings: *local_time.evaluation.warnings(),
            future_skew: local_time.evaluation.future_skew(),
            audit,
            replay_key,
        },
    })
}

pub(crate) fn into_selection_replay_key(
    release: VerifiedClockRelease,
    candidate: &RegistryCandidate,
    local_time: &LocalTimeBlock<'_>,
) -> Result<ClockReleaseReplayKey, ()> {
    let proof = release.inner;
    let context = proof.audit.context();
    if !Arc::ptr_eq(&proof.candidate_state, &candidate.candidate_state)
        || !Arc::ptr_eq(&proof.candidate_state, &local_time.candidate_state)
        || proof.state_key != candidate.state_key
        || proof.state_key != local_time.state_key
        || proof.expected_revision != local_time.expected_revision
        || proof.trusted_time != local_time.trusted_time
        || proof.pinned_head != local_time.pinned_head
        || proof.observed_os_wall_clock != local_time.observed_os_wall_clock
        || proof.proposed_sequence != local_time.proposed_sequence
        || proof.pre_transition_sequence != local_time.pre_transition_sequence
        || proof.raw_now != local_time.evaluation.raw_now()
        || proof.warnings != *local_time.evaluation.warnings()
        || proof.future_skew != local_time.evaluation.future_skew()
        || proof.future_skew != FutureSkew::Blocked
        || proof.audit.organization_id() != candidate.state_key.organization_id
        || proof.audit.target_device_id() != candidate.state_key.device_id
        || proof.audit.effective_now() != local_time.evaluation.raw_now()
        || context.registry_version() != local_time.candidate_registry_version
        || context.registry_head_hash() != local_time.candidate_registry_head_hash
        || context.guard_policy_object_hash() != local_time.guard_policy_object_hash
        || context.trusted_time_floor() != local_time.trusted_time.floor()
        || context.observed_os_wall_clock() != local_time.observed_os_wall_clock
    {
        return Err(());
    }
    Ok(proof.replay_key)
}

fn require_candidate_block_preflight(
    candidate: &RegistryCandidate,
    local_time: &LocalTimeBlock<'_>,
) -> Result<(), ClockReleaseError> {
    let expected_evaluation = evaluate_preexisting_time(
        local_time.observed_os_wall_clock,
        &local_time.trusted_time,
        candidate.guard_policy.fields.max_future_clock_skew_ms,
    )
    .map_err(|_| ClockReleaseError::Mismatch)?;

    if !Arc::ptr_eq(&local_time.candidate_state, &candidate.candidate_state)
        || local_time.state_key != candidate.state_key
        || local_time.expected_revision < candidate.state_revision
        || local_time.pinned_head != candidate.original_pin
        || local_time.candidate_registry_version != candidate.registry_version()
        || local_time.candidate_registry_head_hash != candidate.registry_head_hash()
        || local_time.guard_policy_object_hash != candidate.guard_policy.object_hash
        || local_time.proposed_sequence != candidate.proposed_sequence
        || local_time.pre_transition_sequence != candidate.pre_transition_sequence
        || local_time.evaluation.raw_now() != expected_evaluation.raw_now()
        || local_time.evaluation.warnings() != expected_evaluation.warnings()
        || local_time.evaluation.future_skew() != expected_evaluation.future_skew()
    {
        return Err(ClockReleaseError::Mismatch);
    }
    Ok(())
}

fn require_previous_admin(
    previous: &PreviousHeadState,
    audit: &ClockReleaseAuditV1,
    verified_signer: &VerifiedSigner,
    pre_transition_sequence: ChainSequence,
) -> Result<(), ClockReleaseError> {
    let certificate_hash = CertificateHash::from(audit.signer_certificate_object_hash());
    let certificate = previous
        .admin_certificates
        .get(&certificate_hash)
        .ok_or(ClockReleaseError::Trust(TrustError::Signature))?;
    if CertificateHash::from(certificate.object_hash) != certificate_hash
        || certificate.fields.organization_id != audit.organization_id()
        || certificate.fields.device_id != audit.target_device_id()
        || certificate.fields.certificate_kind != CertificateKindV1::OrganizationAdmin
        || certificate.fields.signing_key_thumbprint != Some(verified_signer.key_thumbprint())
        || !certificate
            .fields
            .capabilities
            .iter()
            .any(|capability| capability == "organizationAdminApprove")
    {
        return Err(ClockReleaseError::Trust(TrustError::Signature));
    }
    if !is_active(
        certificate.fields.effective_from_sequence,
        certificate.fields.revoked_from_sequence,
        pre_transition_sequence,
    ) {
        return Err(ClockReleaseError::Trust(TrustError::SignerInactive));
    }

    let signer_subject = verified_signer
        .authority_subject_id()
        .ok_or(ClockReleaseError::Mismatch)?;
    if certificate.fields.authority_subject_id != Some(signer_subject) {
        return Err(ClockReleaseError::Mismatch);
    }

    let binding_hash = audit.admin_operator_binding_object_hash();
    let binding = previous
        .admin_bindings
        .get(&binding_hash)
        .ok_or(ClockReleaseError::Mismatch)?;
    if binding.object_hash != binding_hash
        || binding.fields.organization_id != audit.organization_id()
        || binding.fields.operator_role != OperatorRoleV1::OrganizationAdmin
        || binding.fields.device_certificate_hash != certificate_hash
        || binding.fields.operator_subject_id.as_bytes() != signer_subject.as_bytes()
    {
        return Err(ClockReleaseError::Mismatch);
    }
    if !is_active(
        binding.fields.effective_from_sequence,
        binding.fields.revoked_from_sequence,
        pre_transition_sequence,
    ) {
        return Err(ClockReleaseError::Trust(TrustError::SignerInactive));
    }
    Ok(())
}

fn require_signed_correlations(
    candidate: &RegistryCandidate,
    local_time: &LocalTimeBlock<'_>,
    audit: &ClockReleaseAuditV1,
) -> Result<(), ClockReleaseError> {
    let context = audit.context();
    if audit.organization_id() != candidate.state_key.organization_id
        || audit.target_device_id() != candidate.state_key.device_id
        || audit.outcome() != LocalAuditOutcomeV1::Accepted
        || audit.effective_now() != local_time.evaluation.raw_now()
        || context.trusted_time_floor() != local_time.trusted_time.floor()
        || context.observed_os_wall_clock() != local_time.observed_os_wall_clock
        || context.max_future_clock_skew_ms()
            != candidate.guard_policy.fields.max_future_clock_skew_ms
        || context.registry_version() != candidate.registry_version()
        || context.registry_head_hash() != candidate.registry_head_hash()
        || context.guard_policy_object_hash() != candidate.guard_policy.object_hash
        || local_time.evaluation.future_skew() != FutureSkew::Blocked
    {
        return Err(ClockReleaseError::Mismatch);
    }

    let signed_reference = context.independent_reference();
    let expected_kind = match signed_reference.kind() {
        IndependentTimeKindV1::Receipt => IndependentTimeKind::Receipt,
        IndependentTimeKindV1::Checkpoint => IndependentTimeKind::Checkpoint,
        IndependentTimeKindV1::Tsa => {
            return Err(ClockReleaseError::Trust(TrustError::TimeSourceUnsupported));
        }
    };
    let reference = local_time
        .trusted_time
        .independent_reference()
        .ok_or(ClockReleaseError::Mismatch)?;
    if reference.kind() != expected_kind
        || signed_reference.object_hash() != reference.object_hash()
        || signed_reference.verified_time() != reference.verified_time()
    {
        return Err(ClockReleaseError::Mismatch);
    }

    let raw_now = local_time.evaluation.raw_now();
    if raw_now < context.issued_at() || raw_now > context.expires_at() {
        return Err(ClockReleaseError::Expired);
    }
    Ok(())
}

fn is_active(
    effective_from: ChainSequence,
    revoked_from: Option<ChainSequence>,
    sequence: ChainSequence,
) -> bool {
    effective_from <= sequence && revoked_from.is_none_or(|revoked| sequence < revoked)
}

const fn map_clock_release_crypto_error(error: CryptoError) -> ClockReleaseError {
    match error {
        CryptoError::SignerUnresolved | CryptoError::SignerUnauthorized => {
            ClockReleaseError::Trust(TrustError::SignerInactive)
        }
        _ => ClockReleaseError::Trust(TrustError::Signature),
    }
}

#[cfg(test)]
mod tests;
