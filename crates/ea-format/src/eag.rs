use core::{cmp::Ordering, fmt};
use std::collections::BTreeSet;

use ea_crypto::{ContentType, grant_digest, grant_plan_digest, parse_cose_sign1};
use ea_types::{
    CertificateHash, ChainId, EntryHash, Hash32, KeyThumbprint, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};
use minicbor::{Decoder, Encoder};

use crate::object::{
    FormatError, bytes_exact, exact_item, expect_array_length, finish, optional_bytes_exact,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GrantPurposeV1 {
    Recovery = 0,
    Reader = 1,
}

impl TryFrom<u64> for GrantPurposeV1 {
    type Error = FormatError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Recovery),
            1 => Ok(Self::Reader),
            _ => Err(FormatError::Shape),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantKindV1 {
    Initial,
    Historical,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GrantPlanItemV1 {
    recipient_key_thumbprint: KeyThumbprint,
    recipient_certificate_hash: CertificateHash,
    purpose: GrantPurposeV1,
}

impl GrantPlanItemV1 {
    #[must_use]
    pub const fn new(
        recipient_key_thumbprint: KeyThumbprint,
        recipient_certificate_hash: CertificateHash,
        purpose: GrantPurposeV1,
    ) -> Self {
        Self {
            recipient_key_thumbprint,
            recipient_certificate_hash,
            purpose,
        }
    }

    #[must_use]
    pub const fn recipient_key_thumbprint(&self) -> KeyThumbprint {
        self.recipient_key_thumbprint
    }

    #[must_use]
    pub const fn recipient_certificate_hash(&self) -> CertificateHash {
        self.recipient_certificate_hash
    }

    #[must_use]
    pub const fn grant_suite_id(&self) -> &'static str {
        ea_crypto::GRANT_SUITE_ID
    }

    #[must_use]
    pub const fn purpose(&self) -> GrantPurposeV1 {
        self.purpose
    }

    fn tuple_cmp(&self, other: &Self) -> Ordering {
        self.recipient_key_thumbprint
            .as_bytes()
            .cmp(other.recipient_key_thumbprint.as_bytes())
            .then_with(|| {
                self.recipient_certificate_hash
                    .as_bytes()
                    .cmp(other.recipient_certificate_hash.as_bytes())
            })
            .then_with(|| self.purpose.cmp(&other.purpose))
    }
}

impl fmt::Debug for GrantPlanItemV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GrantPlanItemV1(<bound>)")
    }
}

pub struct GrantPlanV1 {
    items: Vec<GrantPlanItemV1>,
    hash: Hash32,
}

impl GrantPlanV1 {
    pub fn new(mut items: Vec<GrantPlanItemV1>) -> Result<Self, FormatError> {
        let recovery_count = items
            .iter()
            .filter(|item| item.purpose == GrantPurposeV1::Recovery)
            .count();
        match recovery_count {
            0 => return Err(FormatError::MissingRecovery),
            1 => {}
            _ => return Err(FormatError::DuplicateRecovery),
        }
        let mut recipient_keys = BTreeSet::new();
        let mut recipient_certificates = BTreeSet::new();
        for item in &items {
            if !recipient_keys.insert(*item.recipient_key_thumbprint.as_bytes()) {
                return Err(FormatError::DuplicateRecipientKey);
            }
            if !recipient_certificates.insert(*item.recipient_certificate_hash.as_bytes()) {
                return Err(FormatError::DuplicateRecipientCertificate);
            }
        }
        items.sort_by(GrantPlanItemV1::tuple_cmp);
        let exact = encode_plan_items(&items)?;
        let hash = grant_plan_digest(&exact);
        Ok(Self { items, hash })
    }

    #[must_use]
    pub fn items(&self) -> &[GrantPlanItemV1] {
        &self.items
    }

    #[must_use]
    pub const fn hash(&self) -> Hash32 {
        self.hash
    }
}

impl fmt::Debug for GrantPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GrantPlanV1(<bound>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GrantBodyFieldsV1 {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub entry_hash: EntryHash,
    pub kind: GrantKindV1,
    pub purpose: GrantPurposeV1,
    pub recipient_key_thumbprint: KeyThumbprint,
    pub recipient_certificate_hash: CertificateHash,
    pub issuer_key_thumbprint: KeyThumbprint,
    pub issuer_certificate_hash: CertificateHash,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: Hash32,
    pub created_at_device: UnixMillis,
    pub original_recovery_grant_object_hash: Option<ObjectHash>,
    pub grant_authorization_object_hash: Option<ObjectHash>,
    pub encapsulated_key: [u8; ea_crypto::HPKE_ENCAPSULATED_KEY_SIZE],
    pub wrapped_cek: [u8; ea_crypto::HPKE_WRAPPED_CEK_SIZE],
}

#[derive(Clone, Eq, PartialEq)]
pub struct GrantBodyV1 {
    fields: GrantBodyFieldsV1,
    exact: Vec<u8>,
}

impl GrantBodyV1 {
    pub fn new(fields: GrantBodyFieldsV1) -> Result<Self, FormatError> {
        validate_grant_field_correlations(&fields)?;
        let exact = encode_grant_body(&fields)?;
        Ok(Self { fields, exact })
    }

    #[must_use]
    pub const fn fields(&self) -> &GrantBodyFieldsV1 {
        &self.fields
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    fn from_exact(input: &[u8]) -> Result<Self, FormatError> {
        let fields = decode_grant_body(input)?;
        Ok(Self {
            fields,
            exact: input.to_vec(),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GrantV1 {
    kind: GrantKindV1,
    purpose: GrantPurposeV1,
    exact_grant_body: Vec<u8>,
    issuer_signature: Vec<u8>,
    exact_body: Vec<u8>,
}

impl GrantV1 {
    pub fn new(grant_body: GrantBodyV1, issuer_signature: Vec<u8>) -> Result<Self, FormatError> {
        validate_issuer_signature(&grant_body, &issuer_signature)?;
        let exact_body = encode_grant_wrapper(grant_body.exact_bytes(), &issuer_signature)?;
        Ok(Self {
            kind: grant_body.fields.kind,
            purpose: grant_body.fields.purpose,
            exact_grant_body: grant_body.exact,
            issuer_signature,
            exact_body,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> GrantKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn purpose(&self) -> GrantPurposeV1 {
        self.purpose
    }

    #[must_use]
    pub fn exact_grant_body(&self) -> &[u8] {
        &self.exact_grant_body
    }

    #[must_use]
    pub fn issuer_signature(&self) -> &[u8] {
        &self.issuer_signature
    }

    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.exact_body
    }
}

pub(crate) fn parse_body(input: &[u8]) -> Result<GrantV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 2)?;
    let exact_grant_body = exact_item(input, &mut decoder)?;
    let grant_body = GrantBodyV1::from_exact(exact_grant_body)?;
    let issuer_signature = exact_item(input, &mut decoder)?;
    finish(&decoder, input)?;
    validate_issuer_signature(&grant_body, issuer_signature)?;
    Ok(GrantV1 {
        kind: grant_body.fields.kind,
        purpose: grant_body.fields.purpose,
        exact_grant_body: exact_grant_body.to_vec(),
        issuer_signature: issuer_signature.to_vec(),
        exact_body: input.to_vec(),
    })
}

fn validate_issuer_signature(
    grant_body: &GrantBodyV1,
    issuer_signature: &[u8],
) -> Result<(), FormatError> {
    let cose = parse_cose_sign1(issuer_signature, &[]).map_err(|_| FormatError::Cose)?;
    if cose.content_type() != ContentType::GrantDigest
        || cose.key_thumbprint() != grant_body.fields.issuer_key_thumbprint
        || cose.certificate_hash() != Some(grant_body.fields.issuer_certificate_hash)
        || cose.payload() != grant_digest(grant_body.exact_bytes()).as_bytes()
    {
        return Err(FormatError::Cose);
    }
    Ok(())
}

fn decode_grant_body(input: &[u8]) -> Result<GrantBodyFieldsV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 3)?;
    expect_array_length(&mut decoder, 17)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
        return Err(FormatError::UnknownVersion);
    }
    let organization_id =
        OrganizationId::try_from(bytes_exact(&mut decoder, 16)?).map_err(|_| FormatError::Shape)?;
    let chain_id =
        ChainId::try_from(bytes_exact(&mut decoder, 16)?).map_err(|_| FormatError::Shape)?;
    let entry_hash =
        EntryHash::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    let kind = match decoder.u64().map_err(|_| FormatError::Shape)? {
        0 => GrantKindV1::Initial,
        1 => GrantKindV1::Historical,
        _ => return Err(FormatError::Shape),
    };
    let purpose = GrantPurposeV1::try_from(decoder.u64().map_err(|_| FormatError::Shape)?)?;
    let recipient_key_thumbprint =
        KeyThumbprint::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    let recipient_certificate_hash = CertificateHash::try_from(bytes_exact(&mut decoder, 32)?)
        .map_err(|_| FormatError::Shape)?;
    let issuer_key_thumbprint =
        KeyThumbprint::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    let issuer_certificate_hash = CertificateHash::try_from(bytes_exact(&mut decoder, 32)?)
        .map_err(|_| FormatError::Shape)?;
    let capability = decoder.str().map_err(|_| FormatError::Shape)?;
    let registry_version = RegistryVersion::new(decoder.u64().map_err(|_| FormatError::Shape)?);
    let registry_head_hash =
        Hash32::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    if decoder.str().map_err(|_| FormatError::Shape)? != ea_crypto::GRANT_SUITE_ID {
        return Err(FormatError::TagMismatch);
    }
    let created_at_device = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    let original_recovery_grant_object_hash = optional_bytes_exact(&mut decoder, 32)?
        .map(ObjectHash::try_from)
        .transpose()
        .map_err(|_| FormatError::Shape)?;
    let grant_authorization_object_hash = optional_bytes_exact(&mut decoder, 32)?
        .map(ObjectHash::try_from)
        .transpose()
        .map_err(|_| FormatError::Shape)?;
    let encapsulated_key = bytes_exact(&mut decoder, ea_crypto::HPKE_ENCAPSULATED_KEY_SIZE)?
        .try_into()
        .map_err(|_| FormatError::Shape)?;
    let wrapped_cek = bytes_exact(&mut decoder, ea_crypto::HPKE_WRAPPED_CEK_SIZE)?
        .try_into()
        .map_err(|_| FormatError::Shape)?;
    finish(&decoder, input)?;
    let fields = GrantBodyFieldsV1 {
        organization_id,
        chain_id,
        entry_hash,
        kind,
        purpose,
        recipient_key_thumbprint,
        recipient_certificate_hash,
        issuer_key_thumbprint,
        issuer_certificate_hash,
        registry_version,
        registry_head_hash,
        created_at_device,
        original_recovery_grant_object_hash,
        grant_authorization_object_hash,
        encapsulated_key,
        wrapped_cek,
    };
    let expected_capability = match kind {
        GrantKindV1::Initial => "initialGrant",
        GrantKindV1::Historical => "historicalGrant",
    };
    if capability != expected_capability {
        return Err(FormatError::Shape);
    }
    validate_grant_field_correlations(&fields)?;
    Ok(fields)
}

fn validate_grant_field_correlations(fields: &GrantBodyFieldsV1) -> Result<(), FormatError> {
    match fields.kind {
        GrantKindV1::Initial
            if fields.original_recovery_grant_object_hash.is_some()
                || fields.grant_authorization_object_hash.is_some() =>
        {
            Err(FormatError::Shape)
        }
        GrantKindV1::Historical
            if fields.purpose != GrantPurposeV1::Reader
                || fields.original_recovery_grant_object_hash.is_none()
                || fields.grant_authorization_object_hash.is_none() =>
        {
            Err(FormatError::Shape)
        }
        _ => Ok(()),
    }
}

fn encode_grant_body(fields: &GrantBodyFieldsV1) -> Result<Vec<u8>, FormatError> {
    let capability = match fields.kind {
        GrantKindV1::Initial => "initialGrant",
        GrantKindV1::Historical => "historicalGrant",
    };
    let mut exact = Vec::with_capacity(512);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(3)
        .and_then(|encoder| encoder.array(17))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.chain_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.entry_hash.as_bytes()))
        .and_then(|encoder| encoder.u8(fields.kind as u8))
        .and_then(|encoder| encoder.u8(fields.purpose as u8))
        .and_then(|encoder| encoder.bytes(fields.recipient_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.recipient_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.issuer_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.issuer_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.str(capability))
        .and_then(|encoder| encoder.u64(fields.registry_version.get()))
        .and_then(|encoder| encoder.bytes(fields.registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.str(ea_crypto::GRANT_SUITE_ID))
        .and_then(|encoder| encoder.i64(fields.created_at_device.get()))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_object_hash(&mut encoder, fields.original_recovery_grant_object_hash)?;
    encode_optional_object_hash(&mut encoder, fields.grant_authorization_object_hash)?;
    encoder
        .bytes(&fields.encapsulated_key)
        .and_then(|encoder| encoder.bytes(&fields.wrapped_cek))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_optional_object_hash(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<ObjectHash>,
) -> Result<(), FormatError> {
    if let Some(value) = value {
        encoder
            .bytes(value.as_bytes())
            .map_err(|_| FormatError::Shape)?;
    } else {
        encoder.null().map_err(|_| FormatError::Shape)?;
    }
    Ok(())
}

fn encode_grant_wrapper(
    exact_grant_body: &[u8],
    issuer_signature: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(
        exact_grant_body
            .len()
            .saturating_add(issuer_signature.len())
            .saturating_add(8),
    );
    Encoder::new(&mut exact)
        .array(2)
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(exact_grant_body);
    exact.extend_from_slice(issuer_signature);
    Ok(exact)
}

fn encode_plan_items(items: &[GrantPlanItemV1]) -> Result<Vec<u8>, FormatError> {
    let length = u64::try_from(items.len()).map_err(|_| FormatError::Shape)?;
    let mut bytes = Vec::with_capacity(items.len().saturating_mul(100).saturating_add(8));
    let mut encoder = Encoder::new(&mut bytes);
    encoder.array(length).map_err(|_| FormatError::Shape)?;
    for item in items {
        encoder
            .array(4)
            .and_then(|encoder| encoder.bytes(item.recipient_key_thumbprint.as_bytes()))
            .and_then(|encoder| encoder.bytes(item.recipient_certificate_hash.as_bytes()))
            .and_then(|encoder| encoder.str(ea_crypto::GRANT_SUITE_ID))
            .and_then(|encoder| encoder.u8(item.purpose as u8))
            .map_err(|_| FormatError::Shape)?;
    }
    Ok(bytes)
}
