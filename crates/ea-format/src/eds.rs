use ea_crypto::{ContentType, entry_hash, parse_cose_sign1, record_digest};
use ea_types::{DestructionId, EntryHash, Hash32, ObjectHash};
use minicbor::{Decoder, Encoder};

use crate::{
    SignedManifestV1,
    object::{
        FormatError, bytes_exact, exact_item, expect_array_length, expect_empty_array, finish,
    },
};

#[derive(Clone, Eq, PartialEq)]
pub struct DestroyedEntryStubV1 {
    signed_manifest: SignedManifestV1,
    writer_signature: Vec<u8>,
    entry_hash: EntryHash,
    ciphertext_hash: Hash32,
    original_eip_object_hash: ObjectHash,
    destruction_id: DestructionId,
    destruction_authorization_object_hash: ObjectHash,
    exact_body: Vec<u8>,
}

impl DestroyedEntryStubV1 {
    pub fn new(
        signed_manifest: SignedManifestV1,
        writer_signature: Vec<u8>,
        original_eip_object_hash: ObjectHash,
        destruction_id: DestructionId,
        destruction_authorization_object_hash: ObjectHash,
    ) -> Result<Self, FormatError> {
        let digest = record_digest(signed_manifest.exact_bytes());
        let entry_hash = entry_hash(digest, &writer_signature);
        let ciphertext_hash = signed_manifest.ciphertext_hash();
        validate_writer_binding(&signed_manifest, &writer_signature)?;
        let exact_body = encode_destroyed_body(
            &signed_manifest,
            &writer_signature,
            entry_hash,
            ciphertext_hash,
            original_eip_object_hash,
            destruction_id,
            destruction_authorization_object_hash,
        )?;
        Ok(Self {
            signed_manifest,
            writer_signature,
            entry_hash,
            ciphertext_hash,
            original_eip_object_hash,
            destruction_id,
            destruction_authorization_object_hash,
            exact_body,
        })
    }

    #[must_use]
    pub const fn signed_manifest(&self) -> &SignedManifestV1 {
        &self.signed_manifest
    }

    #[must_use]
    pub fn writer_signature(&self) -> &[u8] {
        &self.writer_signature
    }

    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    #[must_use]
    pub const fn ciphertext_hash(&self) -> Hash32 {
        self.ciphertext_hash
    }

    #[must_use]
    pub const fn original_eip_object_hash(&self) -> ObjectHash {
        self.original_eip_object_hash
    }

    #[must_use]
    pub const fn destruction_id(&self) -> DestructionId {
        self.destruction_id
    }

    #[must_use]
    pub const fn destruction_authorization_object_hash(&self) -> ObjectHash {
        self.destruction_authorization_object_hash
    }

    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.exact_body
    }
}

pub(crate) fn parse_body(input: &[u8]) -> Result<DestroyedEntryStubV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 9)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
        return Err(FormatError::UnknownVersion);
    }
    let signed_exact = exact_item(input, &mut decoder)?;
    let signed_manifest = SignedManifestV1::from_exact(signed_exact)?;
    let signature = exact_item(input, &mut decoder)?;
    let carried_entry_hash =
        EntryHash::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    let ciphertext_hash =
        Hash32::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    let original_eip_object_hash =
        ObjectHash::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    let destruction_id =
        DestructionId::try_from(bytes_exact(&mut decoder, 16)?).map_err(|_| FormatError::Shape)?;
    let destruction_authorization_object_hash =
        ObjectHash::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)?;

    validate_writer_binding(&signed_manifest, signature)?;
    let digest = record_digest(signed_exact);
    if carried_entry_hash != entry_hash(digest, signature)
        || ciphertext_hash != signed_manifest.ciphertext_hash()
    {
        return Err(FormatError::Shape);
    }

    Ok(DestroyedEntryStubV1 {
        signed_manifest,
        writer_signature: signature.to_vec(),
        entry_hash: carried_entry_hash,
        ciphertext_hash,
        original_eip_object_hash,
        destruction_id,
        destruction_authorization_object_hash,
        exact_body: input.to_vec(),
    })
}

fn validate_writer_binding(
    signed_manifest: &SignedManifestV1,
    signature: &[u8],
) -> Result<(), FormatError> {
    let parsed = parse_cose_sign1(signature, &[]).map_err(|_| FormatError::Cose)?;
    if parsed.content_type() != ContentType::RecordDigest
        || parsed.certificate_hash()
            != Some(signed_manifest.manifest().fields().writer_certificate_hash)
        || parsed.payload() != record_digest(signed_manifest.exact_bytes()).as_bytes()
    {
        return Err(FormatError::Cose);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_destroyed_body(
    signed_manifest: &SignedManifestV1,
    writer_signature: &[u8],
    entry_hash: EntryHash,
    ciphertext_hash: Hash32,
    original_eip_object_hash: ObjectHash,
    destruction_id: DestructionId,
    destruction_authorization_object_hash: ObjectHash,
) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(
        signed_manifest
            .exact_bytes()
            .len()
            .saturating_add(writer_signature.len())
            .saturating_add(192),
    );
    Encoder::new(&mut exact)
        .array(9)
        .and_then(|encoder| encoder.u8(1))
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(signed_manifest.exact_bytes());
    exact.extend_from_slice(writer_signature);
    Encoder::new(&mut exact)
        .bytes(entry_hash.as_bytes())
        .and_then(|encoder| encoder.bytes(ciphertext_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(original_eip_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(destruction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(destruction_authorization_object_hash.as_bytes()))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}
