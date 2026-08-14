use ea_crypto::{ContentType, parse_cose_sign1, validate_unsigned_protocol_core};
use ea_types::{ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId, UnixMillis};
use minicbor::{Decoder, Encoder};

use crate::object::{FormatError, exact_array_length, exact_item, expect_array_length, finish};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceKindV1 {
    StandardCheckpoint,
    Timestamp,
    Renewal,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CheckpointCoreFieldsV1 {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub covered_from_sequence: ChainSequence,
    pub covered_through_sequence: ChainSequence,
    pub head_entry_hash: EntryHash,
    pub registry_head_hash: Hash32,
    pub issued_at_server: UnixMillis,
    pub previous_evidence_hash: Option<ObjectHash>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CheckpointCoreV1 {
    fields: CheckpointCoreFieldsV1,
    exact: Vec<u8>,
}

impl CheckpointCoreV1 {
    pub fn new(fields: CheckpointCoreFieldsV1) -> Result<Self, FormatError> {
        let exact = encode_checkpoint_core(&fields)?;
        validate_unsigned_protocol_core(ContentType::CheckpointCbor, &exact)
            .map_err(|_| FormatError::Shape)?;
        Ok(Self { fields, exact })
    }

    #[must_use]
    pub const fn fields(&self) -> &CheckpointCoreFieldsV1 {
        &self.fields
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RenewalCoreFieldsV1 {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub current_entry_hash: EntryHash,
    pub previous_renewal_hash: Option<ObjectHash>,
    pub renewal_input_hashes: Vec<Hash32>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RenewalCoreV1 {
    fields: RenewalCoreFieldsV1,
    exact: Vec<u8>,
}

impl RenewalCoreV1 {
    pub fn new(fields: RenewalCoreFieldsV1) -> Result<Self, FormatError> {
        let exact = encode_renewal_core(&fields)?;
        validate_unsigned_protocol_core(ContentType::EvidenceRenewalCbor, &exact)
            .map_err(|_| FormatError::Shape)?;
        Ok(Self { fields, exact })
    }

    #[must_use]
    pub const fn fields(&self) -> &RenewalCoreFieldsV1 {
        &self.fields
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Rfc3161EvidenceFieldsV1 {
    pub rfc3161_response_der: Vec<u8>,
    pub request_nonce: Vec<u8>,
    pub policy_oid_der: Vec<u8>,
    pub tsa_certificate_chain_der: Vec<Vec<u8>>,
    pub revocation_data_der: Vec<Vec<u8>>,
    pub validation_data_der: Vec<Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct EvidenceObjectV1 {
    kind: EvidenceKindV1,
    exact_body: Vec<u8>,
}

impl EvidenceObjectV1 {
    pub fn standard(
        core: CheckpointCoreV1,
        server_signature: Vec<u8>,
    ) -> Result<Self, FormatError> {
        let evidence = encode_standard(&core, &server_signature)?;
        validate_standard(&evidence)?;
        let exact_body = encode_evidence_variant(0, &evidence)?;
        Ok(Self {
            kind: EvidenceKindV1::StandardCheckpoint,
            exact_body,
        })
    }

    pub fn timestamp(
        core: CheckpointCoreV1,
        server_signature: Vec<u8>,
        evidence_fields: Rfc3161EvidenceFieldsV1,
    ) -> Result<Self, FormatError> {
        let evidence =
            encode_rfc3161_evidence(core.exact_bytes(), &server_signature, &evidence_fields)?;
        validate_timestamp(&evidence)?;
        let exact_body = encode_evidence_variant(1, &evidence)?;
        Ok(Self {
            kind: EvidenceKindV1::Timestamp,
            exact_body,
        })
    }

    pub fn renewal(
        core: RenewalCoreV1,
        renewal_signature: Vec<u8>,
        evidence_fields: Rfc3161EvidenceFieldsV1,
    ) -> Result<Self, FormatError> {
        let evidence =
            encode_rfc3161_evidence(core.exact_bytes(), &renewal_signature, &evidence_fields)?;
        validate_renewal(&evidence)?;
        let exact_body = encode_evidence_variant(2, &evidence)?;
        Ok(Self {
            kind: EvidenceKindV1::Renewal,
            exact_body,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> EvidenceKindV1 {
        self.kind
    }

    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.exact_body
    }
}

fn encode_checkpoint_core(fields: &CheckpointCoreFieldsV1) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(320);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(11)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.str("EINSATZARCHIV-CHECKPOINT-v1"))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.chain_id.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.covered_from_sequence.get()))
        .and_then(|encoder| encoder.u64(fields.covered_through_sequence.get()))
        .and_then(|encoder| encoder.bytes(fields.head_entry_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.i64(fields.issued_at_server.get()))
        .map_err(|_| FormatError::Shape)?;
    if let Some(hash) = fields.previous_evidence_hash {
        encoder
            .bytes(hash.as_bytes())
            .map_err(|_| FormatError::Shape)?;
    } else {
        encoder.null().map_err(|_| FormatError::Shape)?;
    }
    encoder.array(0).map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_renewal_core(fields: &RenewalCoreFieldsV1) -> Result<Vec<u8>, FormatError> {
    let hash_count =
        u64::try_from(fields.renewal_input_hashes.len()).map_err(|_| FormatError::Shape)?;
    let mut exact = Vec::with_capacity(
        fields
            .renewal_input_hashes
            .len()
            .saturating_mul(36)
            .saturating_add(256),
    );
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(8)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.str("EINSATZARCHIV-EVIDENCE-RENEWAL-v1"))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.chain_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.current_entry_hash.as_bytes()))
        .map_err(|_| FormatError::Shape)?;
    if let Some(hash) = fields.previous_renewal_hash {
        encoder
            .bytes(hash.as_bytes())
            .map_err(|_| FormatError::Shape)?;
    } else {
        encoder.null().map_err(|_| FormatError::Shape)?;
    }
    encoder.array(hash_count).map_err(|_| FormatError::Shape)?;
    for hash in &fields.renewal_input_hashes {
        encoder
            .bytes(hash.as_bytes())
            .map_err(|_| FormatError::Shape)?;
    }
    encoder.array(0).map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_standard(
    core: &CheckpointCoreV1,
    server_signature: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(
        core.exact
            .len()
            .saturating_add(server_signature.len())
            .saturating_add(8),
    );
    Encoder::new(&mut exact)
        .array(2)
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(core.exact_bytes());
    exact.extend_from_slice(server_signature);
    Ok(exact)
}

fn encode_rfc3161_evidence(
    core: &[u8],
    signature: &[u8],
    fields: &Rfc3161EvidenceFieldsV1,
) -> Result<Vec<u8>, FormatError> {
    let tsa_count =
        u64::try_from(fields.tsa_certificate_chain_der.len()).map_err(|_| FormatError::Shape)?;
    let revocation_count =
        u64::try_from(fields.revocation_data_der.len()).map_err(|_| FormatError::Shape)?;
    let validation_count =
        u64::try_from(fields.validation_data_der.len()).map_err(|_| FormatError::Shape)?;
    let mut exact = Vec::with_capacity(
        core.len()
            .saturating_add(signature.len())
            .saturating_add(fields.rfc3161_response_der.len())
            .saturating_add(fields.request_nonce.len())
            .saturating_add(fields.policy_oid_der.len())
            .saturating_add(256),
    );
    Encoder::new(&mut exact)
        .array(9)
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(core);
    exact.extend_from_slice(signature);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .bytes(&fields.rfc3161_response_der)
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.bytes(&fields.request_nonce))
        .and_then(|encoder| encoder.bytes(&fields.policy_oid_der))
        .and_then(|encoder| encoder.array(tsa_count))
        .map_err(|_| FormatError::Shape)?;
    for certificate in &fields.tsa_certificate_chain_der {
        encoder.bytes(certificate).map_err(|_| FormatError::Shape)?;
    }
    encoder
        .array(revocation_count)
        .map_err(|_| FormatError::Shape)?;
    for item in &fields.revocation_data_der {
        encoder.bytes(item).map_err(|_| FormatError::Shape)?;
    }
    encoder
        .array(validation_count)
        .map_err(|_| FormatError::Shape)?;
    for item in &fields.validation_data_der {
        encoder.bytes(item).map_err(|_| FormatError::Shape)?;
    }
    Ok(exact)
}

fn encode_evidence_variant(variant: u8, evidence: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(evidence.len().saturating_add(4));
    Encoder::new(&mut exact)
        .array(2)
        .and_then(|encoder| encoder.u8(variant))
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(evidence);
    Ok(exact)
}

pub(crate) fn parse_body(input: &[u8]) -> Result<EvidenceObjectV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 2)?;
    let variant = decoder.u64().map_err(|_| FormatError::Shape)?;
    let evidence = exact_item(input, &mut decoder)?;
    finish(&decoder, input)?;
    let kind = match variant {
        0 => {
            validate_standard(evidence)?;
            EvidenceKindV1::StandardCheckpoint
        }
        1 => {
            validate_timestamp(evidence)?;
            EvidenceKindV1::Timestamp
        }
        2 => {
            validate_renewal(evidence)?;
            EvidenceKindV1::Renewal
        }
        _ => return Err(FormatError::TagMismatch),
    };
    Ok(EvidenceObjectV1 {
        kind,
        exact_body: input.to_vec(),
    })
}

fn validate_standard(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 2)?;
    let core = exact_item(input, &mut decoder)?;
    validate_unsigned_protocol_core(ContentType::CheckpointCbor, core)
        .map_err(|_| FormatError::Shape)?;
    let signature = exact_item(input, &mut decoder)?;
    finish(&decoder, input)?;
    let parsed = parse_cose_sign1(signature, &[]).map_err(|_| FormatError::Cose)?;
    if parsed.content_type() != ContentType::CheckpointCbor
        || parsed.payload() != core
        || parsed.timestamp_token().is_some()
    {
        return Err(FormatError::Cose);
    }
    Ok(())
}

fn validate_timestamp(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 9)?;
    let core = exact_item(input, &mut decoder)?;
    validate_unsigned_protocol_core(ContentType::CheckpointCbor, core)
        .map_err(|_| FormatError::Shape)?;
    let signature = exact_item(input, &mut decoder)?;
    let parsed = parse_cose_sign1(signature, &[]).map_err(|_| FormatError::Cose)?;
    if parsed.content_type() != ContentType::CheckpointCbor
        || parsed.payload() != core
        || parsed.timestamp_token().is_none()
    {
        return Err(FormatError::Cose);
    }
    decoder.bytes().map_err(|_| FormatError::Shape)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 0 {
        return Err(FormatError::TagMismatch);
    }
    decoder.bytes().map_err(|_| FormatError::Shape)?;
    decoder.bytes().map_err(|_| FormatError::Shape)?;
    validate_bstr_array(&mut decoder, true)?;
    validate_bstr_array(&mut decoder, false)?;
    validate_bstr_array(&mut decoder, false)?;
    finish(&decoder, input)
}

fn validate_renewal(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 9)?;
    let core = exact_item(input, &mut decoder)?;
    validate_unsigned_protocol_core(ContentType::EvidenceRenewalCbor, core)
        .map_err(|_| FormatError::Shape)?;
    let signature = exact_item(input, &mut decoder)?;
    let parsed = parse_cose_sign1(signature, &[]).map_err(|_| FormatError::Cose)?;
    if parsed.content_type() != ContentType::EvidenceRenewalCbor
        || parsed.payload() != core
        || parsed.timestamp_token().is_none()
    {
        return Err(FormatError::Cose);
    }
    decoder.bytes().map_err(|_| FormatError::Shape)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 0 {
        return Err(FormatError::TagMismatch);
    }
    decoder.bytes().map_err(|_| FormatError::Shape)?;
    decoder.bytes().map_err(|_| FormatError::Shape)?;
    validate_bstr_array(&mut decoder, true)?;
    validate_bstr_array(&mut decoder, false)?;
    validate_bstr_array(&mut decoder, false)?;
    finish(&decoder, input)
}

fn validate_bstr_array(
    decoder: &mut Decoder<'_>,
    require_nonempty: bool,
) -> Result<(), FormatError> {
    let length = exact_array_length(decoder)?;
    if require_nonempty && length == 0 {
        return Err(FormatError::Shape);
    }
    for _ in 0..length {
        decoder.bytes().map_err(|_| FormatError::Shape)?;
    }
    Ok(())
}
