use ea_cbor::{ParserLimits, validate};
use ea_crypto::{ContentType, parse_cose_sign1, validate_unsigned_protocol_core};
use ea_types::{DeviceId, EventId, ObjectHash, OrganizationId, RegistryVersion, UnixMillis};
use minicbor::Decoder;

use crate::object::{
    FormatError, bytes_exact, exact_item, expect_array_length, expect_empty_array, finish,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IndependentTimeKindV1 {
    Receipt = 0,
    Checkpoint = 1,
    Tsa = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ClockReleaseJustificationV1 {
    OperatorVerifiedWallClock = 0,
    PlatformTimeSourceRecovery = 1,
    HardwareClockMaintenance = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LocalAuditOutcomeV1 {
    Failed = 0,
    Accepted = 1,
    Completed = 2,
}

pub struct IndependentTimeReferenceV1 {
    kind: IndependentTimeKindV1,
    object_hash: ObjectHash,
    verified_time: UnixMillis,
}

impl IndependentTimeReferenceV1 {
    #[must_use]
    pub const fn kind(&self) -> IndependentTimeKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn verified_time(&self) -> UnixMillis {
        self.verified_time
    }
}

pub struct ClockReleaseContextV1 {
    trusted_time_floor: UnixMillis,
    observed_os_wall_clock: UnixMillis,
    max_future_clock_skew_ms: u64,
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    guard_policy_object_hash: ObjectHash,
    independent_reference: IndependentTimeReferenceV1,
    justification: ClockReleaseJustificationV1,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClockReleaseContextV1 {
    #[must_use]
    pub const fn trusted_time_floor(&self) -> UnixMillis {
        self.trusted_time_floor
    }

    #[must_use]
    pub const fn observed_os_wall_clock(&self) -> UnixMillis {
        self.observed_os_wall_clock
    }

    #[must_use]
    pub const fn max_future_clock_skew_ms(&self) -> u64 {
        self.max_future_clock_skew_ms
    }

    #[must_use]
    pub const fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }

    #[must_use]
    pub const fn registry_head_hash(&self) -> ObjectHash {
        self.registry_head_hash
    }

    #[must_use]
    pub const fn guard_policy_object_hash(&self) -> ObjectHash {
        self.guard_policy_object_hash
    }

    #[must_use]
    pub const fn independent_reference(&self) -> &IndependentTimeReferenceV1 {
        &self.independent_reference
    }

    #[must_use]
    pub const fn justification(&self) -> ClockReleaseJustificationV1 {
        self.justification
    }

    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

pub struct ClockReleaseAuditV1 {
    event_id: EventId,
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    admin_operator_binding_object_hash: ObjectHash,
    signer_certificate_object_hash: ObjectHash,
    outcome: LocalAuditOutcomeV1,
    effective_now: UnixMillis,
    context: ClockReleaseContextV1,
    nonce: [u8; 32],
    exact_core: Vec<u8>,
    exact_cose: Vec<u8>,
    signature: Vec<u8>,
}

impl ClockReleaseAuditV1 {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    #[must_use]
    pub const fn admin_operator_binding_object_hash(&self) -> ObjectHash {
        self.admin_operator_binding_object_hash
    }

    #[must_use]
    pub const fn signer_certificate_object_hash(&self) -> ObjectHash {
        self.signer_certificate_object_hash
    }

    #[must_use]
    pub const fn outcome(&self) -> LocalAuditOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub const fn effective_now(&self) -> UnixMillis {
        self.effective_now
    }

    #[must_use]
    pub const fn context(&self) -> &ClockReleaseContextV1 {
        &self.context
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    #[must_use]
    pub fn exact_core(&self) -> &[u8] {
        &self.exact_core
    }

    #[must_use]
    pub fn exact_cose(&self) -> &[u8] {
        &self.exact_cose
    }

    #[must_use]
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }
}

pub fn decode_clock_release_audit(exact_bytes: &[u8]) -> Result<ClockReleaseAuditV1, FormatError> {
    validate(exact_bytes, ParserLimits::V1)?;
    let mut decoder = Decoder::new(exact_bytes);
    expect_array_length(&mut decoder, 2)?;
    let exact_core = exact_item(exact_bytes, &mut decoder)?;
    let core = decode_clock_release_core(exact_core)?;
    let exact_cose = exact_item(exact_bytes, &mut decoder)?;
    finish(&decoder, exact_bytes)?;

    let parsed = parse_cose_sign1(exact_cose, &[]).map_err(|_| FormatError::Cose)?;
    if parsed.content_type() != ContentType::LocalAuditCbor
        || parsed.payload() != exact_core
        || parsed
            .certificate_hash()
            .is_none_or(|hash| hash.as_bytes() != core.signer_certificate_object_hash.as_bytes())
    {
        return Err(FormatError::Cose);
    }

    Ok(ClockReleaseAuditV1 {
        event_id: core.event_id,
        organization_id: core.organization_id,
        target_device_id: core.target_device_id,
        admin_operator_binding_object_hash: core.admin_operator_binding_object_hash,
        signer_certificate_object_hash: core.signer_certificate_object_hash,
        outcome: core.outcome,
        effective_now: core.effective_now,
        context: core.context,
        nonce: core.nonce,
        exact_core: exact_core.to_vec(),
        exact_cose: exact_cose.to_vec(),
        signature: parsed.signature_bytes().to_vec(),
    })
}

struct DecodedClockReleaseCore {
    event_id: EventId,
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    admin_operator_binding_object_hash: ObjectHash,
    signer_certificate_object_hash: ObjectHash,
    outcome: LocalAuditOutcomeV1,
    effective_now: UnixMillis,
    context: ClockReleaseContextV1,
    nonce: [u8; 32],
}

fn decode_clock_release_core(input: &[u8]) -> Result<DecodedClockReleaseCore, FormatError> {
    validate_unsigned_protocol_core(ContentType::LocalAuditCbor, input)
        .map_err(|_| FormatError::Shape)?;
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 12)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
        return Err(FormatError::UnknownVersion);
    }
    let event_id = typed_bytes(&mut decoder, 16)?;
    let organization_id = typed_bytes(&mut decoder, 16)?;
    let target_device_id = typed_bytes(&mut decoder, 16)?;
    let admin_operator_binding_object_hash = typed_bytes(&mut decoder, 32)?;
    let signer_certificate_object_hash = typed_bytes(&mut decoder, 32)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 6 {
        return Err(FormatError::TagMismatch);
    }
    let outcome = decode_outcome(decoder.u64().map_err(|_| FormatError::Shape)?)?;
    let effective_now = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    expect_array_length(&mut decoder, 2)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 2 {
        return Err(FormatError::TagMismatch);
    }
    let context = decode_clock_release_context(&mut decoder, effective_now)?;
    let nonce = bytes_exact(&mut decoder, 32)?
        .try_into()
        .map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)?;
    Ok(DecodedClockReleaseCore {
        event_id,
        organization_id,
        target_device_id,
        admin_operator_binding_object_hash,
        signer_certificate_object_hash,
        outcome,
        effective_now,
        context,
        nonce,
    })
}

fn decode_clock_release_context(
    decoder: &mut Decoder<'_>,
    effective_now: UnixMillis,
) -> Result<ClockReleaseContextV1, FormatError> {
    expect_array_length(decoder, 10)?;
    let trusted_time_floor = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    let observed_os_wall_clock = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    let max_future_clock_skew_ms = decoder.u64().map_err(|_| FormatError::Shape)?;
    let registry_version = RegistryVersion::new(decoder.u64().map_err(|_| FormatError::Shape)?);
    let registry_head_hash = typed_bytes(decoder, 32)?;
    let guard_policy_object_hash = typed_bytes(decoder, 32)?;
    expect_array_length(decoder, 3)?;
    let independent_reference = IndependentTimeReferenceV1 {
        kind: decode_independent_time_kind(decoder.u64().map_err(|_| FormatError::Shape)?)?,
        object_hash: typed_bytes(decoder, 32)?,
        verified_time: UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?),
    };
    let justification = decode_justification(decoder.u64().map_err(|_| FormatError::Shape)?)?;
    let issued_at = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    let expires_at = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    if issued_at.get() >= expires_at.get()
        || effective_now.get() != trusted_time_floor.get().max(observed_os_wall_clock.get())
    {
        return Err(FormatError::Shape);
    }
    Ok(ClockReleaseContextV1 {
        trusted_time_floor,
        observed_os_wall_clock,
        max_future_clock_skew_ms,
        registry_version,
        registry_head_hash,
        guard_policy_object_hash,
        independent_reference,
        justification,
        issued_at,
        expires_at,
    })
}

fn decode_independent_time_kind(value: u64) -> Result<IndependentTimeKindV1, FormatError> {
    match value {
        0 => Ok(IndependentTimeKindV1::Receipt),
        1 => Ok(IndependentTimeKindV1::Checkpoint),
        2 => Ok(IndependentTimeKindV1::Tsa),
        _ => Err(FormatError::TagMismatch),
    }
}

fn decode_justification(value: u64) -> Result<ClockReleaseJustificationV1, FormatError> {
    match value {
        0 => Ok(ClockReleaseJustificationV1::OperatorVerifiedWallClock),
        1 => Ok(ClockReleaseJustificationV1::PlatformTimeSourceRecovery),
        2 => Ok(ClockReleaseJustificationV1::HardwareClockMaintenance),
        _ => Err(FormatError::TagMismatch),
    }
}

fn decode_outcome(value: u64) -> Result<LocalAuditOutcomeV1, FormatError> {
    match value {
        0 => Ok(LocalAuditOutcomeV1::Failed),
        1 => Ok(LocalAuditOutcomeV1::Accepted),
        2 => Ok(LocalAuditOutcomeV1::Completed),
        _ => Err(FormatError::TagMismatch),
    }
}

fn typed_bytes<'a, T>(decoder: &mut Decoder<'a>, length: usize) -> Result<T, FormatError>
where
    T: TryFrom<&'a [u8]>,
{
    T::try_from(bytes_exact(decoder, length)?).map_err(|_| FormatError::Shape)
}
