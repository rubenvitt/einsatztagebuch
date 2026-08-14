use ea_cbor::ParserLimits;
use ea_crypto::{CanonicalPublicCoseKey, bootstrap_anchor_hash, trust_anchor_hash};
use ea_types::{ChainId, EntryHash, Hash32, KeyThumbprint, ObjectHash, OrganizationId};
use minicbor::{Decoder, Encoder};

use crate::TrustError;

const PRE_ANCHOR_DOMAIN: &str = "EINSATZARCHIV-TRUST-ANCHOR-PRE-v1";
const FINAL_ANCHOR_DOMAIN: &str = "EINSATZARCHIV-TRUST-ANCHOR-v1";

pub struct TrustAnchorV1 {
    bootstrap_anchor_hash: Hash32,
    organization_id: OrganizationId,
    chain_id: ChainId,
    root_public_cose_key: CanonicalPublicCoseKey,
    exact_root_public_cose_key: Vec<u8>,
    root_key_thumbprint: KeyThumbprint,
    root_certificate_object_hash: ObjectHash,
    initial_admin_certificate_object_hashes: Vec<ObjectHash>,
    initial_admin_operator_binding_object_hashes: Vec<ObjectHash>,
    genesis_entry_hash: EntryHash,
    exact_pre_anchor_bytes: Vec<u8>,
    exact_bytes: Vec<u8>,
    trust_anchor_hash: Hash32,
}

impl TrustAnchorV1 {
    #[must_use]
    pub const fn bootstrap_anchor_hash(&self) -> Hash32 {
        self.bootstrap_anchor_hash
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn root_public_cose_key(&self) -> &CanonicalPublicCoseKey {
        &self.root_public_cose_key
    }

    #[must_use]
    pub fn root_public_cose_key_bytes(&self) -> &[u8] {
        &self.exact_root_public_cose_key
    }

    #[must_use]
    pub const fn root_key_thumbprint(&self) -> KeyThumbprint {
        self.root_key_thumbprint
    }

    #[must_use]
    pub const fn root_certificate_object_hash(&self) -> ObjectHash {
        self.root_certificate_object_hash
    }

    #[must_use]
    pub fn initial_admin_certificate_object_hashes(&self) -> &[ObjectHash] {
        &self.initial_admin_certificate_object_hashes
    }

    #[must_use]
    pub fn initial_admin_operator_binding_object_hashes(&self) -> &[ObjectHash] {
        &self.initial_admin_operator_binding_object_hashes
    }

    #[must_use]
    pub const fn genesis_entry_hash(&self) -> EntryHash {
        self.genesis_entry_hash
    }

    #[must_use]
    pub fn exact_pre_anchor_bytes(&self) -> &[u8] {
        &self.exact_pre_anchor_bytes
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    #[must_use]
    pub const fn trust_anchor_hash(&self) -> Hash32 {
        self.trust_anchor_hash
    }
}

pub fn decode_trust_anchor(exact_bytes: &[u8]) -> Result<TrustAnchorV1, TrustError> {
    preflight_flat_anchor(exact_bytes)?;
    ea_cbor::validate(exact_bytes, ParserLimits::V1).map_err(|_| TrustError::AnchorShape)?;

    let mut decoder = Decoder::new(exact_bytes);
    expect_array(&mut decoder, 12)?;
    expect_text(&mut decoder, FINAL_ANCHOR_DOMAIN)?;
    expect_u64(&mut decoder, 1)?;
    let embedded_bootstrap_hash = hash32(read_exact_bytes(&mut decoder, 32)?)?;
    let organization_id = OrganizationId::try_from(read_exact_bytes(&mut decoder, 16)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let chain_id = ChainId::try_from(read_exact_bytes(&mut decoder, 16)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let exact_root_public_cose_key = decoder
        .bytes()
        .map_err(|_| TrustError::AnchorShape)?
        .to_vec();
    let root_key_thumbprint = KeyThumbprint::try_from(read_exact_bytes(&mut decoder, 32)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let root_certificate_object_hash = ObjectHash::try_from(read_exact_bytes(&mut decoder, 32)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let initial_admin_certificate_object_hashes = read_hash_list(&mut decoder)?;
    let initial_admin_operator_binding_object_hashes = read_hash_list(&mut decoder)?;
    let genesis_entry_hash = EntryHash::try_from(read_exact_bytes(&mut decoder, 32)?)
        .map_err(|_| TrustError::AnchorShape)?;
    expect_array(&mut decoder, 0)?;
    if decoder.position() != exact_bytes.len() {
        return Err(TrustError::AnchorShape);
    }

    validate_anchor_hash_lists(
        &initial_admin_certificate_object_hashes,
        &initial_admin_operator_binding_object_hashes,
    )?;

    let root_public_cose_key =
        CanonicalPublicCoseKey::from_deterministic_cbor(&exact_root_public_cose_key)
            .map_err(|_| TrustError::AnchorPin)?;
    if !matches!(&root_public_cose_key, CanonicalPublicCoseKey::Ed25519(_)) {
        return Err(TrustError::AnchorPin);
    }
    if root_public_cose_key.thumbprint() != root_key_thumbprint {
        return Err(TrustError::AnchorPin);
    }

    let exact_pre_anchor_bytes = encode_pre_anchor(
        organization_id,
        chain_id,
        &exact_root_public_cose_key,
        root_key_thumbprint,
        root_certificate_object_hash,
        &initial_admin_certificate_object_hashes,
        &initial_admin_operator_binding_object_hashes,
    );
    if bootstrap_anchor_hash(&exact_pre_anchor_bytes) != embedded_bootstrap_hash {
        return Err(TrustError::AnchorHash);
    }

    Ok(TrustAnchorV1 {
        bootstrap_anchor_hash: embedded_bootstrap_hash,
        organization_id,
        chain_id,
        root_public_cose_key,
        exact_root_public_cose_key,
        root_key_thumbprint,
        root_certificate_object_hash,
        initial_admin_certificate_object_hashes,
        initial_admin_operator_binding_object_hashes,
        genesis_entry_hash,
        exact_pre_anchor_bytes,
        exact_bytes: exact_bytes.to_vec(),
        trust_anchor_hash: trust_anchor_hash(exact_bytes),
    })
}

fn preflight_flat_anchor(exact_bytes: &[u8]) -> Result<(), TrustError> {
    // This pass checks the complete flat wire shape using borrowed slices only.
    // Canonical validation and all owned allocations happen after this boundary.
    let mut decoder = Decoder::new(exact_bytes);
    expect_array(&mut decoder, 12)?;
    expect_text(&mut decoder, FINAL_ANCHOR_DOMAIN)?;
    expect_u64(&mut decoder, 1)?;
    read_exact_bytes(&mut decoder, 32)?;
    read_exact_bytes(&mut decoder, 16)?;
    read_exact_bytes(&mut decoder, 16)?;
    let root_key = decoder.bytes().map_err(|_| TrustError::AnchorShape)?;
    if root_key.len() != 40 {
        return Err(TrustError::AnchorShape);
    }
    read_exact_bytes(&mut decoder, 32)?;
    read_exact_bytes(&mut decoder, 32)?;
    let certificate_count = preflight_hash_list(&mut decoder)?;
    let binding_count = preflight_hash_list(&mut decoder)?;
    if certificate_count != binding_count {
        return Err(TrustError::AnchorShape);
    }
    read_exact_bytes(&mut decoder, 32)?;
    expect_array(&mut decoder, 0)?;
    if decoder.position() != exact_bytes.len() {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

fn preflight_hash_list(decoder: &mut Decoder<'_>) -> Result<usize, TrustError> {
    let count = exact_array_length(decoder)?;
    let count = usize::try_from(count).map_err(|_| TrustError::AnchorShape)?;
    if !(2..=ParserLimits::V1.max_container_items).contains(&count) {
        return Err(TrustError::AnchorShape);
    }
    for _ in 0..count {
        read_exact_bytes(decoder, 32)?;
    }
    Ok(count)
}

fn read_hash_list(decoder: &mut Decoder<'_>) -> Result<Vec<ObjectHash>, TrustError> {
    let count =
        usize::try_from(exact_array_length(decoder)?).map_err(|_| TrustError::AnchorShape)?;
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        hashes.push(
            ObjectHash::try_from(read_exact_bytes(decoder, 32)?)
                .map_err(|_| TrustError::AnchorShape)?,
        );
    }
    Ok(hashes)
}

fn validate_anchor_hash_lists(
    certificates: &[ObjectHash],
    bindings: &[ObjectHash],
) -> Result<(), TrustError> {
    if certificates.len() != bindings.len()
        || certificates.len() < 2
        || !is_strictly_sorted(certificates)
        || !is_strictly_sorted(bindings)
    {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

fn is_strictly_sorted(hashes: &[ObjectHash]) -> bool {
    hashes.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_pre_anchor(
    organization_id: OrganizationId,
    chain_id: ChainId,
    exact_root_public_cose_key: &[u8],
    root_key_thumbprint: KeyThumbprint,
    root_certificate_object_hash: ObjectHash,
    certificates: &[ObjectHash],
    bindings: &[ObjectHash],
) -> Vec<u8> {
    let certificate_count =
        u64::try_from(certificates.len()).expect("validated Anchor list length fits u64");
    let binding_count =
        u64::try_from(bindings.len()).expect("validated Anchor list length fits u64");
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(10)
        .and_then(|encoder| encoder.str(PRE_ANCHOR_DOMAIN))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(chain_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(exact_root_public_cose_key))
        .and_then(|encoder| encoder.bytes(root_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(root_certificate_object_hash.as_bytes()))
        .and_then(|encoder| encoder.array(certificate_count))
        .expect("encoding a validated fixed-shape Pre-Anchor into Vec cannot fail");
    for hash in certificates {
        encoder
            .bytes(hash.as_bytes())
            .expect("encoding a validated fixed-size certificate hash cannot fail");
    }
    encoder
        .array(binding_count)
        .expect("encoding a validated Binding list into Vec cannot fail");
    for hash in bindings {
        encoder
            .bytes(hash.as_bytes())
            .expect("encoding a validated fixed-size Binding hash cannot fail");
    }
    encoder
        .array(0)
        .expect("encoding closed empty critical extensions cannot fail");
    bytes
}

fn expect_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), TrustError> {
    if exact_array_length(decoder)? != expected {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

fn exact_array_length(decoder: &mut Decoder<'_>) -> Result<u64, TrustError> {
    decoder
        .array()
        .map_err(|_| TrustError::AnchorShape)?
        .ok_or(TrustError::AnchorShape)
}

fn expect_text(decoder: &mut Decoder<'_>, expected: &str) -> Result<(), TrustError> {
    if decoder.str().map_err(|_| TrustError::AnchorShape)? != expected {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

fn expect_u64(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), TrustError> {
    if decoder.u64().map_err(|_| TrustError::AnchorShape)? != expected {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

fn read_exact_bytes<'a>(
    decoder: &mut Decoder<'a>,
    expected_length: usize,
) -> Result<&'a [u8], TrustError> {
    let bytes = decoder.bytes().map_err(|_| TrustError::AnchorShape)?;
    if bytes.len() != expected_length {
        return Err(TrustError::AnchorShape);
    }
    Ok(bytes)
}

fn hash32(bytes: &[u8]) -> Result<Hash32, TrustError> {
    Hash32::try_from(bytes).map_err(|_| TrustError::AnchorShape)
}
