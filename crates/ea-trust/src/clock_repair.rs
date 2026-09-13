//! Purpose-limited admission for issuing the existing one-use Clock Release.
use crate::{ClockReleaseError, LocalTimeBlock, RegistryCandidate, TrustError};
use ea_format::{
    CertificateKindV1, DeviceCertificateFieldsV1, OperatorBindingFieldsV1, OperatorRoleV1,
    PolicyFieldsV1, RegistryEventFieldsV1,
};
use ea_time::{FutureSkew, IndependentTimeKind, TrustedTimeState};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};

/// No current, historical, Writer or generic signer authority can be obtained
/// from this purpose-specific proof.
#[derive(Eq, PartialEq)]
struct RepairState {
    key: crate::TrustStateKey,
    chain: ChainId,
    registry_version: RegistryVersion,
    registry_hash: ObjectHash,
    revision: u64,
    pin: crate::RegistryHeadPin,
    sequence: ChainSequence,
    pre_sequence: ChainSequence,
    time: TrustedTimeState,
    guard_hash: ObjectHash,
    target_hash: ObjectHash,
    guard_event: RegistryEventFieldsV1,
    target_event: RegistryEventFieldsV1,
    guard_policy: PolicyFieldsV1,
    target_policy: PolicyFieldsV1,
    certificate: CertificateHash,
    binding: ObjectHash,
    certificate_fields: DeviceCertificateFieldsV1,
    binding_fields: OperatorBindingFieldsV1,
    valid_until: UnixMillis,
}
pub struct ClockRepairRegistryAuthority {
    state: RepairState,
    observed_wall: UnixMillis,
    raw_now: UnixMillis,
    context: Hash32,
}
impl ClockRepairRegistryAuthority {
    pub fn organization_id(&self) -> OrganizationId {
        self.state.key.organization_id
    }
    pub fn device_id(&self) -> DeviceId {
        self.state.key.device_id
    }
    pub fn registry_head_hash(&self) -> ObjectHash {
        self.state.registry_hash
    }
    pub fn raw_now(&self) -> UnixMillis {
        self.raw_now
    }
    pub fn context_hash(&self) -> Hash32 {
        self.context
    }

    pub fn certificate_hash(&self) -> CertificateHash {
        self.state.certificate
    }
    pub fn binding_hash(&self) -> ObjectHash {
        self.state.binding
    }
    pub fn certificate_fields(&self) -> &DeviceCertificateFieldsV1 {
        &self.state.certificate_fields
    }
    pub fn binding_fields(&self) -> &OperatorBindingFieldsV1 {
        &self.state.binding_fields
    }
    pub fn valid_until(&self) -> UnixMillis {
        self.state.valid_until
    }

    /// Build only the existing release context from these verified frozen
    /// inputs. A caller-supplied deadline can shorten, never extend authority.
    pub fn release_context(
        &self,
        justification: ea_format::ClockReleaseJustificationV1,
        expires_at: UnixMillis,
    ) -> Result<ea_format::ClockReleaseContextV1, ClockReleaseError> {
        if expires_at <= self.raw_now || expires_at > self.state.valid_until {
            return Err(ClockReleaseError::Expired);
        }
        let reference = self
            .state
            .time
            .independent_reference()
            .ok_or(ClockReleaseError::Mismatch)?;
        let kind = match reference.kind() {
            IndependentTimeKind::Receipt => ea_format::IndependentTimeKindV1::Receipt,
            IndependentTimeKind::Checkpoint => ea_format::IndependentTimeKindV1::Checkpoint,
            IndependentTimeKind::Tsa => return Err(ClockReleaseError::Mismatch),
        };
        Ok(ea_format::ClockReleaseContextV1::new(
            self.state.time.floor(),
            self.observed_wall,
            self.state.guard_policy.max_future_clock_skew_ms,
            self.state.registry_version,
            self.state.registry_hash,
            self.state.guard_hash,
            ea_format::IndependentTimeReferenceV1::new(
                kind,
                reference.object_hash(),
                reference.verified_time(),
            ),
            justification,
            self.raw_now,
            expires_at,
        ))
    }

    /// Recheck current signed inputs and exact durable bounds, without renewing
    /// this proof's original observation or native challenge.
    pub fn require_same_state(
        &self,
        candidate: &RegistryCandidate,
        block: &LocalTimeBlock<'_>,
    ) -> Result<(), ClockReleaseError> {
        let fresh = verify_clock_repair_authority(
            candidate,
            block,
            self.state.certificate,
            self.state.binding,
        )?;
        if self.state != fresh.state
            || fresh.observed_wall < self.observed_wall
            || fresh.raw_now < self.raw_now
            || fresh.raw_now >= self.state.valid_until
        {
            return Err(ClockReleaseError::Mismatch);
        }
        Ok(())
    }
}

/// Issuance is stricter than historical verification of an already signed
/// release. Both original and target contexts must authorize this Admin now.
pub fn verify_clock_repair_authority(
    candidate: &RegistryCandidate,
    block: &LocalTimeBlock<'_>,
    certificate: CertificateHash,
    binding: ObjectHash,
) -> Result<ClockRepairRegistryAuthority, ClockReleaseError> {
    crate::clock_release::require_candidate_block_preflight(candidate, block)?;
    if block.evaluation.future_skew() != FutureSkew::Blocked {
        return Err(ClockReleaseError::Mismatch);
    }
    let reference = block
        .trusted_time
        .independent_reference()
        .ok_or(ClockReleaseError::Mismatch)?;
    if !matches!(
        reference.kind(),
        IndependentTimeKind::Receipt | IndependentTimeKind::Checkpoint
    ) {
        return Err(ClockReleaseError::Trust(TrustError::TimeSourceUnsupported));
    }
    let previous = &candidate
        .preexisting_authority()
        .ok_or(ClockReleaseError::Mismatch)?
        .inner;
    let raw_now = block.evaluation.raw_now();
    require_fresh_event(
        previous
            .head_event
            .as_ref()
            .ok_or(ClockReleaseError::Mismatch)?,
        &candidate.guard_policy.fields,
        candidate.pre_transition_sequence,
        raw_now,
    )?;
    require_fresh_event(
        &candidate.head_event,
        &candidate.target_policy.fields,
        candidate.proposed_sequence,
        raw_now,
    )?;
    if candidate
        .candidate_state
        .has_later_clock_registry(candidate.registry_version(), candidate.proposed_sequence)?
    {
        return Err(ClockReleaseError::Mismatch);
    }
    if let Some(barrier) = &candidate.fallback_barrier {
        barrier
            .require_pending(
                candidate.registry_version(),
                candidate.registry_head_hash(),
                raw_now,
            )
            .map_err(|_| ClockReleaseError::Mismatch)?;
    }
    for (state, sequence) in [
        (previous.as_ref(), candidate.pre_transition_sequence),
        (
            candidate.candidate_state.as_ref(),
            candidate.proposed_sequence,
        ),
    ] {
        let cert = state
            .active_certificate(certificate, sequence)
            .ok_or(ClockReleaseError::Trust(TrustError::SignerInactive))?;
        let operator = state
            .active_operator_binding(binding, sequence)
            .ok_or(ClockReleaseError::Trust(TrustError::SignerInactive))?;
        if cert.fields.organization_id != candidate.state_key.organization_id
            || cert.fields.device_id != candidate.state_key.device_id
            || cert.fields.certificate_kind != CertificateKindV1::OrganizationAdmin
            || !cert
                .fields
                .capabilities
                .iter()
                .any(|cap| cap == "organizationAdminApprove")
            || operator.fields.organization_id != candidate.state_key.organization_id
            || operator.fields.operator_role != OperatorRoleV1::OrganizationAdmin
            || operator.fields.device_certificate_hash != certificate
            || cert
                .fields
                .authority_subject_id
                .as_ref()
                .map(|id| id.as_bytes())
                != Some(operator.fields.operator_subject_id.as_bytes())
        {
            return Err(ClockReleaseError::Mismatch);
        }
    }
    let cert = candidate
        .candidate_state
        .active_certificate(certificate, candidate.proposed_sequence)
        .ok_or(ClockReleaseError::Mismatch)?;
    let operator = candidate
        .candidate_state
        .active_operator_binding(binding, candidate.proposed_sequence)
        .ok_or(ClockReleaseError::Mismatch)?;
    let guard_event = previous
        .head_event
        .as_ref()
        .ok_or(ClockReleaseError::Mismatch)?;
    let mut valid_until = guard_event.not_after.min(candidate.head_event.not_after);
    if let Some(barrier) = &candidate.fallback_barrier {
        valid_until = valid_until.min(barrier.ready_at());
    }
    let state = RepairState {
        key: candidate.state_key,
        chain: candidate.chain_id,
        registry_version: candidate.registry_version(),
        registry_hash: candidate.registry_head_hash(),
        revision: block.expected_revision,
        pin: block.pinned_head.ok_or(ClockReleaseError::Mismatch)?,
        sequence: candidate.proposed_sequence,
        pre_sequence: candidate.pre_transition_sequence,
        time: block.trusted_time.clone(),
        guard_hash: candidate.guard_policy.object_hash,
        target_hash: candidate.target_policy.object_hash,
        guard_event: guard_event.clone(),
        target_event: candidate.head_event.clone(),
        guard_policy: candidate.guard_policy.fields.clone(),
        target_policy: candidate.target_policy.fields.clone(),
        certificate,
        binding,
        certificate_fields: cert.fields.clone(),
        binding_fields: operator.fields.clone(),
        valid_until,
    };
    let context = context_hash(&state, block.observed_os_wall_clock, raw_now)?;
    Ok(ClockRepairRegistryAuthority {
        state,
        observed_wall: block.observed_os_wall_clock,
        raw_now,
        context,
    })
}

fn require_fresh_event(
    event: &RegistryEventFieldsV1,
    policy: &PolicyFieldsV1,
    sequence: ChainSequence,
    now: UnixMillis,
) -> Result<(), ClockReleaseError> {
    if now < event.issued_at
        || now < event.not_before
        || now > event.not_after
        || sequence < event.effective_from_sequence
        || sequence > event.valid_through_sequence
        || i128::from(now.get()) - i128::from(event.issued_at.get())
            > i128::from(policy.max_registry_age_ms)
    {
        return Err(ClockReleaseError::Expired);
    }
    Ok(())
}

/// Internal local-presence context only. It is never persisted or transported
/// as a new trust document; the existing v1 audit and challenge families remain.
fn context_hash(
    state: &RepairState,
    wall: UnixMillis,
    raw: UnixMillis,
) -> Result<Hash32, ClockReleaseError> {
    let reference = state
        .time
        .independent_reference()
        .ok_or(ClockReleaseError::Mismatch)?;
    let mut e = minicbor::Encoder::new(Vec::new());
    let encoded = (|| {
        e.array(21)?
            .bytes(b"EINSATZARCHIV-CLOCK-REPAIR-CONTEXT-v1")?
            .bytes(state.key.organization_id.as_bytes())?
            .bytes(state.key.device_id.as_bytes())?
            .bytes(state.chain.as_bytes())?
            .bytes(state.certificate.as_bytes())?
            .bytes(state.binding.as_bytes())?
            .u64(state.registry_version.get())?
            .bytes(state.registry_hash.as_bytes())?
            .bytes(state.guard_hash.as_bytes())?
            .bytes(state.target_hash.as_bytes())?
            .u64(state.revision)?
            .array(2)?
            .u64(state.pin.registry_version().get())?
            .bytes(state.pin.registry_head_hash().as_bytes())?
            .u64(state.sequence.get())?
            .u64(state.pre_sequence.get())?
            .i64(state.time.floor().get())?
            .array(3)?
            .u8(reference.kind() as u8)?
            .bytes(reference.object_hash().as_bytes())?
            .i64(reference.verified_time().get())?
            .i64(wall.get())?
            .i64(raw.get())?
            .u64(state.guard_policy.max_future_clock_skew_ms)?
            .i64(state.valid_until.get())?;
        Ok::<(), minicbor::encode::Error<std::convert::Infallible>>(())
    })();
    encoded.map_err(|_| ClockReleaseError::Mismatch)?;
    let hash = ea_crypto::object_hash(&e.into_writer());
    Hash32::try_from(hash.as_bytes().as_slice()).map_err(|_| ClockReleaseError::Mismatch)
}
