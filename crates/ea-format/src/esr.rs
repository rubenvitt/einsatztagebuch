use ea_crypto::{ContentType, parse_cose_sign1, receipt_digest};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, KeyThumbprint, ObjectHash,
    OrganizationId, RegistryVersion, UnixMillis,
};
use minicbor::{Decoder, Encoder};

use crate::object::{
    FormatError, bytes_exact, exact_array_length, exact_item, expect_array_length,
    expect_empty_array, finish, optional_bytes_exact,
};

#[derive(Clone, Eq, PartialEq)]
pub struct ReceiptCoreFieldsV1 {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub chain_sequence: ChainSequence,
    pub entry_hash: EntryHash,
    pub entry_object_hash: ObjectHash,
    pub previous_entry_hash: Option<EntryHash>,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: Hash32,
    pub policy_object_hash: ObjectHash,
    pub initial_grant_plan_hash: Hash32,
    pub initial_grant_object_hashes: Vec<ObjectHash>,
    pub accepted_at_server: UnixMillis,
    pub evidence_due_at: Option<UnixMillis>,
    pub server_key_thumbprint: KeyThumbprint,
    pub server_certificate_hash: CertificateHash,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReceiptCoreV1 {
    fields: ReceiptCoreFieldsV1,
    exact: Vec<u8>,
}

impl ReceiptCoreV1 {
    pub fn new(fields: ReceiptCoreFieldsV1) -> Result<Self, FormatError> {
        validate_receipt_fields(&fields)?;
        let exact = encode_receipt_core(&fields)?;
        Ok(Self { fields, exact })
    }

    #[must_use]
    pub const fn fields(&self) -> &ReceiptCoreFieldsV1 {
        &self.fields
    }

    #[must_use]
    pub const fn chain_sequence(&self) -> ChainSequence {
        self.fields.chain_sequence
    }

    #[must_use]
    pub fn initial_grant_object_hashes(&self) -> &[ObjectHash] {
        &self.fields.initial_grant_object_hashes
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    fn from_exact(input: &[u8]) -> Result<Self, FormatError> {
        let mut decoder = Decoder::new(input);
        expect_array_length(&mut decoder, 17)?;
        if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
            return Err(FormatError::UnknownVersion);
        }
        let organization_id = OrganizationId::try_from(bytes_exact(&mut decoder, 16)?)
            .map_err(|_| FormatError::Shape)?;
        let chain_id =
            ChainId::try_from(bytes_exact(&mut decoder, 16)?).map_err(|_| FormatError::Shape)?;
        let chain_sequence = ChainSequence::new(decoder.u64().map_err(|_| FormatError::Shape)?);
        let entry_hash =
            EntryHash::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
        let entry_object_hash =
            ObjectHash::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
        let previous_entry_hash = optional_bytes_exact(&mut decoder, 32)?
            .map(EntryHash::try_from)
            .transpose()
            .map_err(|_| FormatError::Shape)?;
        let registry_version = RegistryVersion::new(decoder.u64().map_err(|_| FormatError::Shape)?);
        let registry_head_hash =
            Hash32::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
        let policy_object_hash =
            ObjectHash::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
        let initial_grant_plan_hash =
            Hash32::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
        let grant_count = exact_array_length(&mut decoder)?;
        if grant_count == 0 {
            return Err(FormatError::Shape);
        }
        let capacity = usize::try_from(grant_count).map_err(|_| FormatError::Shape)?;
        let mut hashes: Vec<ObjectHash> = Vec::with_capacity(capacity);
        for _ in 0..grant_count {
            let hash = ObjectHash::try_from(bytes_exact(&mut decoder, 32)?)
                .map_err(|_| FormatError::Shape)?;
            if let Some(previous) = hashes.last() {
                match previous.as_bytes().cmp(hash.as_bytes()) {
                    core::cmp::Ordering::Equal => return Err(FormatError::Duplicate),
                    core::cmp::Ordering::Greater => return Err(FormatError::Unsorted),
                    core::cmp::Ordering::Less => {}
                }
            }
            hashes.push(hash);
        }
        let accepted_at_server = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
        let evidence_due_at = match decoder.datatype().map_err(|_| FormatError::Shape)? {
            minicbor::data::Type::Null => {
                decoder.null().map_err(|_| FormatError::Shape)?;
                None
            }
            _ => Some(UnixMillis::new(
                decoder.i64().map_err(|_| FormatError::Shape)?,
            )),
        };
        let server_key_thumbprint = KeyThumbprint::try_from(bytes_exact(&mut decoder, 32)?)
            .map_err(|_| FormatError::Shape)?;
        let server_certificate_hash = CertificateHash::try_from(bytes_exact(&mut decoder, 32)?)
            .map_err(|_| FormatError::Shape)?;
        expect_empty_array(&mut decoder)?;
        finish(&decoder, input)?;
        let fields = ReceiptCoreFieldsV1 {
            organization_id,
            chain_id,
            chain_sequence,
            entry_hash,
            entry_object_hash,
            previous_entry_hash,
            registry_version,
            registry_head_hash,
            policy_object_hash,
            initial_grant_plan_hash,
            initial_grant_object_hashes: hashes,
            server_key_thumbprint,
            server_certificate_hash,
            accepted_at_server,
            evidence_due_at,
        };
        validate_receipt_fields(&fields)?;
        Ok(Self {
            fields,
            exact: input.to_vec(),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReceiptV1 {
    core: ReceiptCoreV1,
    server_signature: Vec<u8>,
    exact_body: Vec<u8>,
}

impl ReceiptV1 {
    pub fn new(core: ReceiptCoreV1, server_signature: Vec<u8>) -> Result<Self, FormatError> {
        validate_server_signature(&core, &server_signature)?;
        let exact_body = encode_receipt_wrapper(core.exact_bytes(), &server_signature)?;
        Ok(Self {
            core,
            server_signature,
            exact_body,
        })
    }

    #[must_use]
    pub const fn core(&self) -> &ReceiptCoreV1 {
        &self.core
    }

    #[must_use]
    pub fn server_signature(&self) -> &[u8] {
        &self.server_signature
    }

    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.exact_body
    }
}

pub(crate) fn parse_body(input: &[u8]) -> Result<ReceiptV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 2)?;
    let core_exact = exact_item(input, &mut decoder)?;
    let core = ReceiptCoreV1::from_exact(core_exact)?;
    let signature = exact_item(input, &mut decoder)?;
    finish(&decoder, input)?;
    validate_server_signature(&core, signature)?;
    Ok(ReceiptV1 {
        core,
        server_signature: signature.to_vec(),
        exact_body: input.to_vec(),
    })
}

fn validate_server_signature(core: &ReceiptCoreV1, signature: &[u8]) -> Result<(), FormatError> {
    let cose = parse_cose_sign1(signature, &[]).map_err(|_| FormatError::Cose)?;
    if cose.content_type() != ContentType::ReceiptDigest
        || cose.key_thumbprint() != core.fields.server_key_thumbprint
        || cose.certificate_hash() != Some(core.fields.server_certificate_hash)
        || cose.payload() != receipt_digest(core.exact_bytes()).as_bytes()
    {
        return Err(FormatError::Cose);
    }
    Ok(())
}

fn validate_receipt_fields(fields: &ReceiptCoreFieldsV1) -> Result<(), FormatError> {
    if fields.initial_grant_object_hashes.is_empty()
        || (fields.chain_sequence.get() == 0) == fields.previous_entry_hash.is_some()
    {
        return Err(FormatError::Shape);
    }
    for pair in fields.initial_grant_object_hashes.windows(2) {
        match pair[0].as_bytes().cmp(pair[1].as_bytes()) {
            core::cmp::Ordering::Equal => return Err(FormatError::Duplicate),
            core::cmp::Ordering::Greater => return Err(FormatError::Unsorted),
            core::cmp::Ordering::Less => {}
        }
    }
    Ok(())
}

fn encode_receipt_core(fields: &ReceiptCoreFieldsV1) -> Result<Vec<u8>, FormatError> {
    let grant_count =
        u64::try_from(fields.initial_grant_object_hashes.len()).map_err(|_| FormatError::Shape)?;
    let mut exact = Vec::with_capacity(768);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(17)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.chain_id.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.chain_sequence.get()))
        .and_then(|encoder| encoder.bytes(fields.entry_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.entry_object_hash.as_bytes()))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_entry_hash(&mut encoder, fields.previous_entry_hash)?;
    encoder
        .u64(fields.registry_version.get())
        .and_then(|encoder| encoder.bytes(fields.registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.policy_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.initial_grant_plan_hash.as_bytes()))
        .and_then(|encoder| encoder.array(grant_count))
        .map_err(|_| FormatError::Shape)?;
    for hash in &fields.initial_grant_object_hashes {
        encoder
            .bytes(hash.as_bytes())
            .map_err(|_| FormatError::Shape)?;
    }
    encoder
        .i64(fields.accepted_at_server.get())
        .map_err(|_| FormatError::Shape)?;
    if let Some(value) = fields.evidence_due_at {
        encoder.i64(value.get()).map_err(|_| FormatError::Shape)?;
    } else {
        encoder.null().map_err(|_| FormatError::Shape)?;
    }
    encoder
        .bytes(fields.server_key_thumbprint.as_bytes())
        .and_then(|encoder| encoder.bytes(fields.server_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_optional_entry_hash(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<EntryHash>,
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

fn encode_receipt_wrapper(core: &[u8], signature: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut exact =
        Vec::with_capacity(core.len().saturating_add(signature.len()).saturating_add(8));
    Encoder::new(&mut exact)
        .array(2)
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(core);
    exact.extend_from_slice(signature);
    Ok(exact)
}
