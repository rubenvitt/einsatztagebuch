use ea_crypto::{ContentType, ciphertext_digest, entry_hash, parse_cose_sign1, record_digest};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId,
    RegistryVersion,
};
use minicbor::{Decoder, Encoder};

use crate::object::{
    FormatError, bytes_exact, exact_item, expect_array_length, expect_empty_array, finish,
    optional_bytes_exact,
};

pub const MIN_CIPHERTEXT_BYTES_V1: usize = 16;
pub const MAX_CIPHERTEXT_BYTES_V1: usize = 1_048_592;

#[derive(Clone, Eq, PartialEq)]
pub struct ManifestCoreFieldsV1 {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub chain_sequence: ChainSequence,
    pub previous_entry_hash: Option<EntryHash>,
    pub writer_certificate_hash: CertificateHash,
    pub writer_transition_event_hash: Option<ObjectHash>,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: [u8; 32],
    pub initial_grant_plan_hash: [u8; 32],
    pub nonce: [u8; 12],
}

#[derive(Clone, Eq, PartialEq)]
pub struct ManifestCoreV1 {
    fields: ManifestCoreFieldsV1,
    ciphertext_length: usize,
    exact: Vec<u8>,
}

impl ManifestCoreV1 {
    pub fn new(fields: ManifestCoreFieldsV1, exact_ciphertext: &[u8]) -> Result<Self, FormatError> {
        validate_ciphertext_length(exact_ciphertext.len())?;
        validate_sequence_predecessor(fields.chain_sequence, fields.previous_entry_hash)?;
        let ciphertext_length = exact_ciphertext.len();
        let exact = encode_manifest_core(&fields, ciphertext_length)?;
        Ok(Self {
            fields,
            ciphertext_length,
            exact,
        })
    }

    #[must_use]
    pub const fn fields(&self) -> &ManifestCoreFieldsV1 {
        &self.fields
    }

    #[must_use]
    pub const fn ciphertext_length(&self) -> usize {
        self.ciphertext_length
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    pub(crate) fn from_exact(input: &[u8]) -> Result<Self, FormatError> {
        let mut decoder = Decoder::new(input);
        expect_array_length(&mut decoder, 16)?;
        if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
            return Err(FormatError::TagMismatch);
        }
        if decoder.u64().map_err(|_| FormatError::Shape)? != 1
            || decoder.u64().map_err(|_| FormatError::Shape)? != 1
        {
            return Err(FormatError::UnknownVersion);
        }
        let organization_id = OrganizationId::try_from(bytes_exact(&mut decoder, 16)?)
            .map_err(|_| FormatError::Shape)?;
        let chain_id =
            ChainId::try_from(bytes_exact(&mut decoder, 16)?).map_err(|_| FormatError::Shape)?;
        let chain_sequence = ChainSequence::new(decoder.u64().map_err(|_| FormatError::Shape)?);
        let previous_entry_hash = optional_bytes_exact(&mut decoder, 32)?
            .map(EntryHash::try_from)
            .transpose()
            .map_err(|_| FormatError::Shape)?;
        let writer_certificate_hash = CertificateHash::try_from(bytes_exact(&mut decoder, 32)?)
            .map_err(|_| FormatError::Shape)?;
        let writer_transition_event_hash = optional_bytes_exact(&mut decoder, 32)?
            .map(ObjectHash::try_from)
            .transpose()
            .map_err(|_| FormatError::Shape)?;
        let registry_version = RegistryVersion::new(decoder.u64().map_err(|_| FormatError::Shape)?);
        let registry_head_hash = bytes_exact(&mut decoder, 32)?
            .try_into()
            .map_err(|_| FormatError::Shape)?;
        let initial_grant_plan_hash = bytes_exact(&mut decoder, 32)?
            .try_into()
            .map_err(|_| FormatError::Shape)?;
        if decoder.str().map_err(|_| FormatError::Shape)? != ea_crypto::SUITE_ID {
            return Err(FormatError::TagMismatch);
        }
        let nonce = bytes_exact(&mut decoder, 12)?
            .try_into()
            .map_err(|_| FormatError::Shape)?;
        let ciphertext_length =
            usize::try_from(decoder.u64().map_err(|_| FormatError::CiphertextLength)?)
                .map_err(|_| FormatError::CiphertextLength)?;
        validate_ciphertext_length(ciphertext_length)?;
        expect_empty_array(&mut decoder)?;
        finish(&decoder, input)?;
        validate_sequence_predecessor(chain_sequence, previous_entry_hash)?;
        Ok(Self {
            fields: ManifestCoreFieldsV1 {
                organization_id,
                chain_id,
                chain_sequence,
                previous_entry_hash,
                writer_certificate_hash,
                writer_transition_event_hash,
                registry_version,
                registry_head_hash,
                initial_grant_plan_hash,
                nonce,
            },
            ciphertext_length,
            exact: input.to_vec(),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SignedManifestV1 {
    manifest: ManifestCoreV1,
    ciphertext_hash: Hash32,
    exact: Vec<u8>,
}

impl SignedManifestV1 {
    pub fn new(manifest: ManifestCoreV1, exact_ciphertext: &[u8]) -> Result<Self, FormatError> {
        if manifest.ciphertext_length != exact_ciphertext.len() {
            return Err(FormatError::CiphertextLength);
        }
        let ciphertext_hash = ciphertext_digest(exact_ciphertext);
        let exact = encode_signed_manifest(&manifest, ciphertext_hash)?;
        Ok(Self {
            manifest,
            ciphertext_hash,
            exact,
        })
    }

    #[must_use]
    pub const fn manifest(&self) -> &ManifestCoreV1 {
        &self.manifest
    }

    #[must_use]
    pub const fn ciphertext_hash(&self) -> Hash32 {
        self.ciphertext_hash
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    pub(crate) fn from_exact(input: &[u8]) -> Result<Self, FormatError> {
        let mut decoder = Decoder::new(input);
        expect_array_length(&mut decoder, 2)?;
        let manifest_exact = exact_item(input, &mut decoder)?;
        let manifest = ManifestCoreV1::from_exact(manifest_exact)?;
        let ciphertext_hash =
            Hash32::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
        finish(&decoder, input)?;
        Ok(Self {
            manifest,
            ciphertext_hash,
            exact: input.to_vec(),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EntryPackageV1 {
    signed_manifest: SignedManifestV1,
    ciphertext: Vec<u8>,
    writer_signature: Vec<u8>,
    entry_hash: EntryHash,
}

impl EntryPackageV1 {
    pub fn new(
        signed_manifest: SignedManifestV1,
        ciphertext: Vec<u8>,
        writer_signature: Vec<u8>,
    ) -> Result<Self, FormatError> {
        validate_entry_parts(&signed_manifest, &ciphertext, &writer_signature)?;
        let digest = record_digest(signed_manifest.exact_bytes());
        let entry_hash = entry_hash(digest, &writer_signature);
        Ok(Self {
            signed_manifest,
            ciphertext,
            writer_signature,
            entry_hash,
        })
    }

    #[must_use]
    pub const fn signed_manifest(&self) -> &SignedManifestV1 {
        &self.signed_manifest
    }

    #[must_use]
    pub const fn manifest(&self) -> &ManifestCoreV1 {
        self.signed_manifest.manifest()
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    #[must_use]
    pub fn writer_signature(&self) -> &[u8] {
        &self.writer_signature
    }

    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    pub(crate) fn body_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let mut body = Vec::with_capacity(
            self.signed_manifest
                .exact
                .len()
                .saturating_add(self.ciphertext.len())
                .saturating_add(self.writer_signature.len())
                .saturating_add(16),
        );
        body.push(0x83);
        body.extend_from_slice(self.signed_manifest.exact_bytes());
        Encoder::new(&mut body)
            .bytes(&self.ciphertext)
            .map_err(|_| FormatError::Shape)?;
        body.extend_from_slice(&self.writer_signature);
        Ok(body)
    }
}

pub(crate) fn parse_body(input: &[u8]) -> Result<EntryPackageV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 3)?;
    let signed_exact = exact_item(input, &mut decoder)?;
    let signed_manifest = SignedManifestV1::from_exact(signed_exact)?;
    let ciphertext = decoder.bytes().map_err(|_| FormatError::Shape)?.to_vec();
    let signature = exact_item(input, &mut decoder)?.to_vec();
    finish(&decoder, input)?;
    EntryPackageV1::new(signed_manifest, ciphertext, signature)
}

fn validate_ciphertext_length(length: usize) -> Result<(), FormatError> {
    if !(MIN_CIPHERTEXT_BYTES_V1..=MAX_CIPHERTEXT_BYTES_V1).contains(&length) {
        return Err(FormatError::CiphertextLength);
    }
    Ok(())
}

fn validate_sequence_predecessor(
    sequence: ChainSequence,
    predecessor: Option<EntryHash>,
) -> Result<(), FormatError> {
    if (sequence.get() == 0) != predecessor.is_none() {
        return Err(FormatError::Shape);
    }
    Ok(())
}

fn validate_entry_parts(
    signed_manifest: &SignedManifestV1,
    ciphertext: &[u8],
    writer_signature: &[u8],
) -> Result<(), FormatError> {
    validate_ciphertext_length(ciphertext.len())?;
    if signed_manifest.manifest.ciphertext_length != ciphertext.len() {
        return Err(FormatError::CiphertextLength);
    }
    if signed_manifest.ciphertext_hash != ciphertext_digest(ciphertext) {
        return Err(FormatError::Shape);
    }
    let cose = parse_cose_sign1(writer_signature, &[]).map_err(|_| FormatError::Cose)?;
    if cose.content_type() != ContentType::RecordDigest
        || cose.certificate_hash() != Some(signed_manifest.manifest.fields.writer_certificate_hash)
        || cose.payload() != record_digest(signed_manifest.exact_bytes()).as_bytes()
    {
        return Err(FormatError::Cose);
    }
    Ok(())
}

fn encode_manifest_core(
    fields: &ManifestCoreFieldsV1,
    ciphertext_length: usize,
) -> Result<Vec<u8>, FormatError> {
    let length = u64::try_from(ciphertext_length).map_err(|_| FormatError::CiphertextLength)?;
    let mut bytes = Vec::with_capacity(256);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(16)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.chain_id.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.chain_sequence.get()))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_hash(
        &mut encoder,
        fields.previous_entry_hash.map(|value| *value.as_bytes()),
    )?;
    encoder
        .bytes(fields.writer_certificate_hash.as_bytes())
        .map_err(|_| FormatError::Shape)?;
    encode_optional_hash(
        &mut encoder,
        fields
            .writer_transition_event_hash
            .map(|value| *value.as_bytes()),
    )?;
    encoder
        .u64(fields.registry_version.get())
        .and_then(|encoder| encoder.bytes(&fields.registry_head_hash))
        .and_then(|encoder| encoder.bytes(&fields.initial_grant_plan_hash))
        .and_then(|encoder| encoder.str(ea_crypto::SUITE_ID))
        .and_then(|encoder| encoder.bytes(&fields.nonce))
        .and_then(|encoder| encoder.u64(length))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(bytes)
}

fn encode_optional_hash(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<[u8; 32]>,
) -> Result<(), FormatError> {
    match value {
        Some(value) => {
            encoder.bytes(&value).map_err(|_| FormatError::Shape)?;
        }
        None => {
            encoder.null().map_err(|_| FormatError::Shape)?;
        }
    }
    Ok(())
}

fn encode_signed_manifest(
    manifest: &ManifestCoreV1,
    ciphertext_hash: Hash32,
) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::with_capacity(manifest.exact.len().saturating_add(36));
    bytes.push(0x82);
    bytes.extend_from_slice(&manifest.exact);
    Encoder::new(&mut bytes)
        .bytes(ciphertext_hash.as_bytes())
        .map_err(|_| FormatError::Shape)?;
    Ok(bytes)
}
