#![allow(dead_code)]

use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, CoseSigner, ProtectedHeader, SecretBytes,
    UnverifiedRfc3161TimeStampToken, attach_rfc3161_ctt, record_digest,
};
use ea_format::{
    CertificateKindV1, CheckpointCoreFieldsV1, CheckpointCoreV1, DeletionAttestationFieldsV1,
    DestructionAuthorizationFieldsV1, DestructionTargetV1, DestructionTransitionFieldsV1,
    DeviceCertificateFieldsV1, EntryPackageV1, EvidenceKindV1, EvidenceObjectV1,
    FreeTextPolicyFieldsV1, GrantAuthorizationFieldsV1, GrantPlanItemV1, GrantPurposeV1,
    KeyProtectionProfileV1, ManifestCoreFieldsV1, ManifestCoreV1, OperatorBindingFieldsV1,
    OperatorRoleV1, OrganizationAdminAuthorizationFieldsV1, ParsedArchiveObject, PolicyFieldsV1,
    RegistryChangeV1, RegistryEventFieldsV1, RenewalCoreFieldsV1, RenewalCoreV1,
    RetentionPolicyFieldsV1, Rfc3161EvidenceFieldsV1, RootCertificateFieldsV1, SignedManifestV1,
    TrustObjectV1, TrustPayloadV1, TrustSubtypeV1, WriterTransitionFieldsV1, decode_exact_object,
    encode_entry_package,
};
use ea_types::{
    AuthorizationId, CertificateHash, ChainId, ChainSequence, DestructionId, DeviceId, EntryHash,
    EventId, Hash32, KeyThumbprint, ObjectHash, OperatorSubjectId, OrganizationId, RegistryVersion,
    UnixMillis,
};
use minicbor::{Decoder, Encoder};

pub fn id16(value: u8) -> [u8; 16] {
    [value; 16]
}

pub fn hash32(value: u8) -> [u8; 32] {
    [value; 32]
}

pub fn organization(value: u8) -> OrganizationId {
    OrganizationId::try_from(id16(value).as_slice()).unwrap()
}

pub fn chain(value: u8) -> ChainId {
    ChainId::try_from(id16(value).as_slice()).unwrap()
}

pub fn certificate(value: u8) -> CertificateHash {
    CertificateHash::try_from(hash32(value).as_slice()).unwrap()
}

pub fn signer() -> CoseSigner {
    CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)))
}

pub fn signer_thumbprint() -> KeyThumbprint {
    CanonicalPublicCoseKey::ed25519(
        hex::decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
    .thumbprint()
}

pub fn authorization_id(value: u8) -> AuthorizationId {
    AuthorizationId::try_from(id16(value).as_slice()).unwrap()
}

pub fn destruction_id(value: u8) -> DestructionId {
    DestructionId::try_from(id16(value).as_slice()).unwrap()
}

pub fn entry_hash(value: u8) -> EntryHash {
    EntryHash::try_from(hash32(value).as_slice()).unwrap()
}

pub fn key_thumbprint(value: u8) -> KeyThumbprint {
    KeyThumbprint::try_from(hash32(value).as_slice()).unwrap()
}

pub fn typed_hash(value: u8) -> Hash32 {
    Hash32::try_from(hash32(value).as_slice()).unwrap()
}

pub fn typed_object_hash(value: u8) -> ObjectHash {
    ObjectHash::try_from(hash32(value).as_slice()).unwrap()
}

fn device_id(value: u8) -> DeviceId {
    DeviceId::try_from(id16(value).as_slice()).unwrap()
}

fn event_id(value: u8) -> EventId {
    EventId::try_from(id16(value).as_slice()).unwrap()
}

fn operator_subject_id(value: u8) -> OperatorSubjectId {
    OperatorSubjectId::try_from(id16(value).as_slice()).unwrap()
}

pub fn grant_plan_item(key: u8, certificate_hash: u8, purpose: GrantPurposeV1) -> GrantPlanItemV1 {
    GrantPlanItemV1::new(
        KeyThumbprint::try_from(hash32(key).as_slice()).unwrap(),
        certificate(certificate_hash),
        purpose,
    )
}

pub fn valid_eip(ciphertext: Vec<u8>) -> Vec<u8> {
    let manifest = manifest_for_ciphertext(&ciphertext).unwrap();
    let signed = SignedManifestV1::new(manifest, &ciphertext).unwrap();
    let signature = signer().sign_record(signed.exact_bytes()).unwrap();
    let entry = EntryPackageV1::new(signed, ciphertext, signature).unwrap();
    encode_entry_package(&entry).unwrap().into_vec()
}

pub fn manifest_for_ciphertext(
    ciphertext: &[u8],
) -> Result<ManifestCoreV1, ea_format::FormatError> {
    ManifestCoreV1::new(
        ManifestCoreFieldsV1 {
            organization_id: organization(1),
            chain_id: chain(2),
            chain_sequence: ChainSequence::new(0),
            previous_entry_hash: None,
            writer_certificate_hash: certificate(3),
            writer_transition_event_hash: None,
            registry_version: RegistryVersion::new(4),
            registry_head_hash: hash32(5),
            initial_grant_plan_hash: hash32(6),
            nonce: [7; 12],
        },
        ciphertext,
    )
}

pub fn top_level_type(bytes: &[u8]) -> u8 {
    let mut decoder = Decoder::new(bytes);
    assert_eq!(decoder.array().unwrap(), Some(5));
    assert_eq!(decoder.bytes().unwrap(), b"EA1\0");
    decoder.u8().unwrap()
}

pub fn manifest_ciphertext_length(bytes: &[u8]) -> u64 {
    let mut decoder = eip_decoder(bytes);
    for _ in 0..14 {
        decoder.skip().unwrap();
    }
    decoder.u64().unwrap()
}

pub fn exact_ciphertext_bstr(bytes: &[u8]) -> &[u8] {
    let mut decoder = Decoder::new(bytes);
    decoder.array().unwrap();
    for _ in 0..3 {
        decoder.skip().unwrap();
    }
    decoder.array().unwrap();
    decoder.array().unwrap();
    decoder.skip().unwrap();
    decoder.bytes().unwrap()
}

fn eip_decoder(bytes: &[u8]) -> Decoder<'_> {
    let mut decoder = Decoder::new(bytes);
    decoder.array().unwrap();
    for _ in 0..4 {
        decoder.skip().unwrap();
    }
    decoder.array().unwrap();
    decoder.array().unwrap();
    decoder.array().unwrap();
    decoder
}

pub fn eip_with_declared_and_actual_ciphertext_lengths(declared: u64, actual: usize) -> Vec<u8> {
    let valid = valid_eip(vec![0x55; actual]);
    replace_manifest_scalar(&valid, 14, declared)
}

pub fn eip_with_manifest_object_type(object_type: u64) -> Vec<u8> {
    let valid = valid_eip(vec![0x55; 16]);
    replace_manifest_scalar(&valid, 0, object_type)
}

pub fn eip_with_nonempty_manifest_extensions() -> Vec<u8> {
    let valid = valid_eip(vec![0x55; 16]);
    replace_manifest_extensions(&valid)
}

pub fn replace_outer_extensions(bytes: &[u8]) -> Vec<u8> {
    let mut output = bytes.to_vec();
    output[8] = 0x81;
    output.insert(9, 0);
    output
}

pub fn eip_with_overflowing_manifest_integer() -> Vec<u8> {
    let valid = valid_eip(vec![0x55; 16]);
    replace_manifest_raw(
        &valid,
        5,
        &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    )
}

pub fn eip_with_same_length_ciphertext_tamper() -> Vec<u8> {
    let mut bytes = valid_eip(vec![0x55; 16]);
    let range = ciphertext_range(&bytes);
    bytes[range.start] ^= 1;
    bytes
}

pub fn eip_with_stale_signed_manifest_signature() -> Vec<u8> {
    let valid = valid_eip(vec![0x55; 16]);
    let mut decoder = eip_decoder(&valid);
    for _ in 0..10 {
        decoder.skip().unwrap();
    }
    let start = decoder.position();
    let mut bytes = valid;
    bytes[start + 2] ^= 1;
    bytes
}

pub fn eip_with_wrong_cose_content_type() -> Vec<u8> {
    replace_eip_signature_with_profile(ContentType::ReceiptDigest, certificate(3))
}

pub fn eip_with_wrong_cose_certificate_hash() -> Vec<u8> {
    replace_eip_signature_with_profile(ContentType::RecordDigest, certificate(0x99))
}

pub fn eip_with_sequence_and_predecessor(sequence: u64, predecessor: Option<[u8; 32]>) -> Vec<u8> {
    let valid = valid_eip(vec![0x55; 16]);
    let with_sequence = replace_manifest_scalar(&valid, 5, sequence);
    let replacement = match predecessor {
        Some(value) => {
            let mut encoded = Vec::new();
            Encoder::new(&mut encoded).bytes(&value).unwrap();
            encoded
        }
        None => vec![0xf6],
    };
    replace_manifest_raw(&with_sequence, 6, &replacement)
}

pub fn eip_with_different_opaque_signature(input: &[u8]) -> Vec<u8> {
    let mut output = input.to_vec();
    let range = signature_range(input);
    output[range.end - 1] ^= 1;
    output
}

fn replace_eip_signature_with_profile(
    content_type: ContentType,
    certificate_hash: CertificateHash,
) -> Vec<u8> {
    let valid = valid_eip(vec![0x55; 16]);
    let signed = signed_manifest_range(&valid);
    let payload = record_digest(&valid[signed]);
    let signature = structural_cose(content_type, certificate_hash, payload.as_bytes(), 0x5a);
    replace_range(&valid, signature_range(&valid), &signature)
}

fn structural_cose(
    content_type: ContentType,
    certificate_hash: CertificateHash,
    payload: &[u8],
    signature_byte: u8,
) -> Vec<u8> {
    structural_cose_with_key(
        content_type,
        signer_thumbprint(),
        certificate_hash,
        payload,
        signature_byte,
    )
}

fn structural_cose_with_key(
    content_type: ContentType,
    key_thumbprint: KeyThumbprint,
    certificate_hash: CertificateHash,
    payload: &[u8],
    signature_byte: u8,
) -> Vec<u8> {
    let protected = ProtectedHeader::normal(content_type, key_thumbprint, certificate_hash)
        .to_deterministic_cbor();
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .tag(minicbor::data::Tag::new(18))
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(&protected)
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(payload)
        .unwrap()
        .bytes(&[signature_byte; 64])
        .unwrap();
    bytes
}

fn signed_manifest_range(bytes: &[u8]) -> std::ops::Range<usize> {
    let mut decoder = Decoder::new(bytes);
    decoder.array().unwrap();
    for _ in 0..4 {
        decoder.skip().unwrap();
    }
    decoder.array().unwrap();
    let start = decoder.position();
    decoder.skip().unwrap();
    start..decoder.position()
}

fn ciphertext_range(bytes: &[u8]) -> std::ops::Range<usize> {
    let mut decoder = Decoder::new(bytes);
    decoder.array().unwrap();
    for _ in 0..4 {
        decoder.skip().unwrap();
    }
    decoder.array().unwrap();
    decoder.skip().unwrap();
    let item_start = decoder.position();
    let payload = decoder.bytes().unwrap();
    let payload_start = decoder.position() - payload.len();
    assert!(payload_start > item_start);
    payload_start..decoder.position()
}

fn signature_range(bytes: &[u8]) -> std::ops::Range<usize> {
    let mut decoder = Decoder::new(bytes);
    decoder.array().unwrap();
    for _ in 0..4 {
        decoder.skip().unwrap();
    }
    decoder.array().unwrap();
    decoder.skip().unwrap();
    decoder.skip().unwrap();
    let start = decoder.position();
    decoder.skip().unwrap();
    start..decoder.position()
}

fn replace_range(bytes: &[u8], range: std::ops::Range<usize>, replacement: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len() - range.len() + replacement.len());
    output.extend_from_slice(&bytes[..range.start]);
    output.extend_from_slice(replacement);
    output.extend_from_slice(&bytes[range.end..]);
    output
}

fn replace_manifest_scalar(bytes: &[u8], index: usize, value: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded).u64(value).unwrap();
    replace_manifest_raw(bytes, index, &encoded)
}

fn replace_manifest_extensions(bytes: &[u8]) -> Vec<u8> {
    replace_manifest_raw(bytes, 15, &[0x81, 0x00])
}

fn replace_manifest_raw(bytes: &[u8], index: usize, replacement: &[u8]) -> Vec<u8> {
    let mut decoder = eip_decoder(bytes);
    for _ in 0..index {
        decoder.skip().unwrap();
    }
    let start = decoder.position();
    decoder.skip().unwrap();
    let end = decoder.position();
    let mut output = Vec::with_capacity(bytes.len() - (end - start) + replacement.len());
    output.extend_from_slice(&bytes[..start]);
    output.extend_from_slice(replacement);
    output.extend_from_slice(&bytes[end..]);
    output
}

pub fn malformed_at_raw_length(prefix: [u8; 9], length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    bytes[..prefix.len()].copy_from_slice(&prefix);
    bytes
}

pub fn all_valid_objects() -> Vec<Vec<u8>> {
    let eip = valid_eip(vec![0x5a; 16]);
    vec![
        eip.clone(),
        valid_initial_eag(),
        valid_esr(),
        valid_ecp(),
        valid_etb(),
        valid_eds_from_eip(&eip),
    ]
}

pub fn valid_eds_from_entry(entry: &EntryPackageV1, eip: &[u8]) -> Vec<u8> {
    build_eds(entry, eip)
}

pub fn eds_with_stale_entry_hash_after_signature_mutation() -> Vec<u8> {
    let eip = valid_eip(vec![0x47; 16]);
    let mut eds = valid_eds_from_eip(&eip);
    let signature = eds_signature_range(&eds);
    eds[signature.end - 1] ^= 1;
    eds
}

pub fn eds_with_mismatched_carried_entry_hash() -> Vec<u8> {
    let eip = valid_eip(vec![0x47; 16]);
    let mut eds = valid_eds_from_eip(&eip);
    let range = eds_carried_hash_range(&eds, 0);
    eds[range.start] ^= 1;
    eds
}

pub fn eds_with_mismatched_duplicate_ciphertext_hash() -> Vec<u8> {
    let eip = valid_eip(vec![0x47; 16]);
    let mut eds = valid_eds_from_eip(&eip);
    let range = eds_carried_hash_range(&eds, 1);
    eds[range.start] ^= 1;
    eds
}

pub fn invalid_eds_cose_bindings() -> Vec<Vec<u8>> {
    vec![
        eds_with_signature_binding(ContentType::ReceiptDigest, certificate(3), None),
        eds_with_signature_binding(ContentType::RecordDigest, certificate(0x99), None),
        eds_with_signature_binding(
            ContentType::RecordDigest,
            certificate(3),
            Some(hash32(0x99)),
        ),
    ]
}

fn valid_eds_from_eip(eip: &[u8]) -> Vec<u8> {
    let parsed = match decode_exact_object(eip).unwrap() {
        ParsedArchiveObject::Entry(value) => value,
        _ => unreachable!(),
    };
    build_eds(parsed.value(), eip)
}

fn build_eds(entry: &EntryPackageV1, eip: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut encoder = Encoder::new(&mut body);
    encoder.array(9).unwrap().u8(1).unwrap();
    body.extend_from_slice(entry.signed_manifest().exact_bytes());
    body.extend_from_slice(entry.writer_signature());
    let mut encoder = Encoder::new(&mut body);
    encoder
        .bytes(entry.entry_hash().as_bytes())
        .unwrap()
        .bytes(entry.signed_manifest().ciphertext_hash().as_bytes())
        .unwrap()
        .bytes(ea_crypto::object_hash(eip).as_bytes())
        .unwrap()
        .bytes(&id16(9))
        .unwrap()
        .bytes(&hash32(10))
        .unwrap()
        .array(0)
        .unwrap();
    wrap(6, &body)
}

fn eds_with_signature_binding(
    content_type: ContentType,
    certificate_hash: CertificateHash,
    payload_override: Option<[u8; 32]>,
) -> Vec<u8> {
    let eip = valid_eip(vec![0x47; 16]);
    let parsed = match decode_exact_object(&eip).unwrap() {
        ParsedArchiveObject::Entry(value) => value,
        _ => unreachable!(),
    };
    let mut eds = build_eds(parsed.value(), &eip);
    let payload = payload_override.unwrap_or_else(|| {
        *record_digest(parsed.value().signed_manifest().exact_bytes()).as_bytes()
    });
    let replacement = structural_cose(content_type, certificate_hash, &payload, 0x52);
    eds = replace_range(&eds, eds_signature_range(&eds), &replacement);
    eds
}

fn eds_signature_range(bytes: &[u8]) -> std::ops::Range<usize> {
    let mut decoder = Decoder::new(bytes);
    decoder.array().unwrap();
    for _ in 0..4 {
        decoder.skip().unwrap();
    }
    decoder.array().unwrap();
    decoder.skip().unwrap();
    decoder.skip().unwrap();
    let start = decoder.position();
    decoder.skip().unwrap();
    start..decoder.position()
}

fn eds_carried_hash_range(bytes: &[u8], index: usize) -> std::ops::Range<usize> {
    let mut decoder = Decoder::new(bytes);
    decoder.array().unwrap();
    for _ in 0..4 {
        decoder.skip().unwrap();
    }
    decoder.array().unwrap();
    for _ in 0..3 + index {
        decoder.skip().unwrap();
    }
    let hash = decoder.bytes().unwrap();
    let end = decoder.position();
    end - hash.len()..end
}

pub fn valid_initial_eag() -> Vec<u8> {
    build_eag(
        0,
        1,
        "initialGrant",
        None,
        None,
        "EINSATZARCHIV-HPKE-1",
        32,
        48,
        ContentType::GrantDigest,
        signer_thumbprint(),
        certificate(3),
    )
}

pub fn valid_historical_eag() -> Vec<u8> {
    build_eag(
        1,
        1,
        "historicalGrant",
        Some(hash32(0x70)),
        Some(hash32(0x71)),
        "EINSATZARCHIV-HPKE-1",
        32,
        48,
        ContentType::GrantDigest,
        signer_thumbprint(),
        certificate(3),
    )
}

pub fn invalid_grant_correlations() -> Vec<Vec<u8>> {
    vec![
        build_eag(
            2,
            1,
            "initialGrant",
            None,
            None,
            "EINSATZARCHIV-HPKE-1",
            32,
            48,
            ContentType::GrantDigest,
            signer_thumbprint(),
            certificate(3),
        ),
        build_eag(
            0,
            2,
            "initialGrant",
            None,
            None,
            "EINSATZARCHIV-HPKE-1",
            32,
            48,
            ContentType::GrantDigest,
            signer_thumbprint(),
            certificate(3),
        ),
        build_eag(
            0,
            1,
            "historicalGrant",
            None,
            None,
            "EINSATZARCHIV-HPKE-1",
            32,
            48,
            ContentType::GrantDigest,
            signer_thumbprint(),
            certificate(3),
        ),
        build_eag(
            0,
            1,
            "initialGrant",
            Some(hash32(0x70)),
            None,
            "EINSATZARCHIV-HPKE-1",
            32,
            48,
            ContentType::GrantDigest,
            signer_thumbprint(),
            certificate(3),
        ),
        build_eag(
            0,
            1,
            "initialGrant",
            None,
            Some(hash32(0x71)),
            "EINSATZARCHIV-HPKE-1",
            32,
            48,
            ContentType::GrantDigest,
            signer_thumbprint(),
            certificate(3),
        ),
        build_eag(
            0,
            1,
            "initialGrant",
            Some(hash32(0x70)),
            Some(hash32(0x71)),
            "EINSATZARCHIV-HPKE-1",
            32,
            48,
            ContentType::GrantDigest,
            signer_thumbprint(),
            certificate(3),
        ),
        build_eag(
            1,
            0,
            "historicalGrant",
            Some(hash32(0x70)),
            Some(hash32(0x71)),
            "EINSATZARCHIV-HPKE-1",
            32,
            48,
            ContentType::GrantDigest,
            signer_thumbprint(),
            certificate(3),
        ),
        build_eag(
            1,
            1,
            "historicalGrant",
            None,
            Some(hash32(0x71)),
            "EINSATZARCHIV-HPKE-1",
            32,
            48,
            ContentType::GrantDigest,
            signer_thumbprint(),
            certificate(3),
        ),
        build_eag(
            1,
            1,
            "historicalGrant",
            Some(hash32(0x70)),
            None,
            "EINSATZARCHIV-HPKE-1",
            32,
            48,
            ContentType::GrantDigest,
            signer_thumbprint(),
            certificate(3),
        ),
    ]
}

pub fn invalid_grant_wire_cases() -> Vec<(Vec<u8>, &'static str)> {
    let mut stale_encapsulated_key = valid_initial_eag();
    let offset = stale_encapsulated_key
        .windows(32)
        .position(|window| window == [7; 32])
        .expect("encapsulated-key fixture must exist");
    stale_encapsulated_key[offset] ^= 1;
    let mut stale_wrapped_cek = valid_initial_eag();
    let offset = stale_wrapped_cek
        .windows(48)
        .position(|window| window == [8; 48])
        .expect("wrapped-CEK fixture must exist");
    stale_wrapped_cek[offset] ^= 1;
    vec![
        (
            build_eag(
                0,
                1,
                "initialGrant",
                None,
                None,
                "EINSATZARCHIV-HPKE-1",
                31,
                48,
                ContentType::GrantDigest,
                signer_thumbprint(),
                certificate(3),
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            build_eag(
                0,
                1,
                "initialGrant",
                None,
                None,
                "EINSATZARCHIV-HPKE-1",
                33,
                48,
                ContentType::GrantDigest,
                signer_thumbprint(),
                certificate(3),
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            build_eag(
                0,
                1,
                "initialGrant",
                None,
                None,
                "EINSATZARCHIV-HPKE-1",
                32,
                47,
                ContentType::GrantDigest,
                signer_thumbprint(),
                certificate(3),
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            build_eag(
                0,
                1,
                "initialGrant",
                None,
                None,
                "EINSATZARCHIV-HPKE-1",
                32,
                49,
                ContentType::GrantDigest,
                signer_thumbprint(),
                certificate(3),
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            build_eag(
                0,
                1,
                "initialGrant",
                None,
                None,
                "EINSATZARCHIV-HPKE-X",
                32,
                48,
                ContentType::GrantDigest,
                signer_thumbprint(),
                certificate(3),
            ),
            "EA-FORMAT-TAG-MISMATCH",
        ),
        (stale_encapsulated_key, "EA-FORMAT-COSE"),
        (stale_wrapped_cek, "EA-FORMAT-COSE"),
        (
            build_eag(
                0,
                1,
                "initialGrant",
                None,
                None,
                "EINSATZARCHIV-HPKE-1",
                32,
                48,
                ContentType::RecordDigest,
                signer_thumbprint(),
                certificate(3),
            ),
            "EA-FORMAT-COSE",
        ),
        (
            build_eag(
                0,
                1,
                "initialGrant",
                None,
                None,
                "EINSATZARCHIV-HPKE-1",
                32,
                48,
                ContentType::GrantDigest,
                KeyThumbprint::try_from(hash32(0x99).as_slice()).unwrap(),
                certificate(3),
            ),
            "EA-FORMAT-COSE",
        ),
        (
            build_eag(
                0,
                1,
                "initialGrant",
                None,
                None,
                "EINSATZARCHIV-HPKE-1",
                32,
                48,
                ContentType::GrantDigest,
                signer_thumbprint(),
                certificate(0x99),
            ),
            "EA-FORMAT-COSE",
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn build_eag(
    kind: u8,
    purpose: u8,
    capability: &str,
    original: Option<[u8; 32]>,
    authorization: Option<[u8; 32]>,
    suite: &str,
    encapsulated_length: usize,
    wrapped_length: usize,
    cose_content_type: ContentType,
    cose_key_thumbprint: KeyThumbprint,
    cose_certificate_hash: CertificateHash,
) -> Vec<u8> {
    let mut context = Vec::new();
    let mut encoder = Encoder::new(&mut context);
    encoder
        .array(17)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&id16(2))
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .u8(kind)
        .unwrap()
        .u8(purpose)
        .unwrap()
        .bytes(signer_thumbprint().as_bytes())
        .unwrap()
        .bytes(&hash32(4))
        .unwrap()
        .bytes(signer_thumbprint().as_bytes())
        .unwrap()
        .bytes(certificate(3).as_bytes())
        .unwrap()
        .str(capability)
        .unwrap()
        .u8(4)
        .unwrap()
        .bytes(&hash32(5))
        .unwrap()
        .str(suite)
        .unwrap()
        .i64(6)
        .unwrap();
    encode_optional_hash_for_fixture(&mut encoder, original);
    encode_optional_hash_for_fixture(&mut encoder, authorization);
    let mut grant_body = Vec::new();
    grant_body.push(0x83);
    grant_body.extend_from_slice(&context);
    Encoder::new(&mut grant_body)
        .bytes(&vec![7; encapsulated_length])
        .unwrap()
        .bytes(&vec![8; wrapped_length])
        .unwrap();
    let digest = ea_crypto::grant_digest(&grant_body);
    let signature = structural_cose_with_key(
        cose_content_type,
        cose_key_thumbprint,
        cose_certificate_hash,
        digest.as_bytes(),
        0x5a,
    );
    let mut body = Vec::new();
    body.push(0x82);
    body.extend_from_slice(&grant_body);
    body.extend_from_slice(&signature);
    wrap(2, &body)
}

fn encode_optional_hash_for_fixture(encoder: &mut Encoder<&mut Vec<u8>>, value: Option<[u8; 32]>) {
    if let Some(value) = value {
        encoder.bytes(&value).unwrap();
    } else {
        encoder.null().unwrap();
    }
}

pub fn valid_esr() -> Vec<u8> {
    build_esr(
        &[hash32(8)],
        ContentType::ReceiptDigest,
        signer_thumbprint(),
        certificate(3),
    )
}

pub fn invalid_receipt_grant_hash_lists() -> Vec<(Vec<u8>, &'static str)> {
    vec![
        (
            build_esr(
                &[],
                ContentType::ReceiptDigest,
                signer_thumbprint(),
                certificate(3),
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            build_esr(
                &[hash32(8), hash32(8)],
                ContentType::ReceiptDigest,
                signer_thumbprint(),
                certificate(3),
            ),
            "EA-FORMAT-DUPLICATE",
        ),
        (
            build_esr(
                &[hash32(9), hash32(8)],
                ContentType::ReceiptDigest,
                signer_thumbprint(),
                certificate(3),
            ),
            "EA-FORMAT-UNSORTED",
        ),
    ]
}

pub fn invalid_receipt_cose_bindings() -> Vec<Vec<u8>> {
    let mut stale = valid_esr();
    let offset = stale
        .windows(32)
        .position(|window| window == hash32(3))
        .expect("entry-hash fixture must exist");
    stale[offset] ^= 1;
    vec![
        stale,
        build_esr(
            &[hash32(8)],
            ContentType::GrantDigest,
            signer_thumbprint(),
            certificate(3),
        ),
        build_esr(
            &[hash32(8)],
            ContentType::ReceiptDigest,
            KeyThumbprint::try_from(hash32(0x99).as_slice()).unwrap(),
            certificate(3),
        ),
        build_esr(
            &[hash32(8)],
            ContentType::ReceiptDigest,
            signer_thumbprint(),
            certificate(0x99),
        ),
    ]
}

pub fn esr_with_received_time_raw(raw: &[u8]) -> Vec<u8> {
    let mut bytes = valid_esr();
    let mut decoder = Decoder::new(&bytes);
    decoder.array().unwrap();
    for _ in 0..4 {
        decoder.skip().unwrap();
    }
    decoder.array().unwrap();
    decoder.array().unwrap();
    for _ in 0..12 {
        decoder.skip().unwrap();
    }
    let start = decoder.position();
    decoder.skip().unwrap();
    let end = decoder.position();
    bytes.splice(start..end, raw.iter().copied());
    bytes
}

fn build_esr(
    grant_hashes: &[[u8; 32]],
    content_type: ContentType,
    cose_key_thumbprint: KeyThumbprint,
    cose_certificate_hash: CertificateHash,
) -> Vec<u8> {
    let mut core = Vec::new();
    let mut encoder = Encoder::new(&mut core);
    encoder
        .array(17)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&id16(2))
        .unwrap()
        .u8(0)
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .bytes(&hash32(4))
        .unwrap()
        .null()
        .unwrap()
        .u8(4)
        .unwrap()
        .bytes(&hash32(5))
        .unwrap()
        .bytes(&hash32(6))
        .unwrap()
        .bytes(&hash32(7))
        .unwrap()
        .array(u64::try_from(grant_hashes.len()).unwrap())
        .unwrap();
    for hash in grant_hashes {
        encoder.bytes(hash).unwrap();
    }
    encoder
        .i64(9)
        .unwrap()
        .null()
        .unwrap()
        .bytes(signer_thumbprint().as_bytes())
        .unwrap()
        .bytes(certificate(3).as_bytes())
        .unwrap()
        .array(0)
        .unwrap();
    let digest = ea_crypto::receipt_digest(&core);
    let signature = structural_cose_with_key(
        content_type,
        cose_key_thumbprint,
        cose_certificate_hash,
        digest.as_bytes(),
        0x4b,
    );
    let mut body = Vec::new();
    body.push(0x82);
    body.extend_from_slice(&core);
    body.extend_from_slice(&signature);
    wrap(3, &body)
}

pub fn valid_ecp() -> Vec<u8> {
    build_standard_ecp(checkpoint_core("EINSATZARCHIV-CHECKPOINT-v1"), false)
}

pub fn valid_timestamp_ecp() -> Vec<u8> {
    build_timestamp_like_ecp(
        1,
        checkpoint_core("EINSATZARCHIV-CHECKPOINT-v1"),
        ContentType::CheckpointCbor,
        true,
        0,
        &[vec![0x30, 0]],
    )
}

pub fn valid_renewal_ecp() -> Vec<u8> {
    build_timestamp_like_ecp(
        2,
        renewal_core("EINSATZARCHIV-EVIDENCE-RENEWAL-v1", &[hash32(8), hash32(9)]),
        ContentType::EvidenceRenewalCbor,
        true,
        0,
        &[vec![0x30, 0]],
    )
}

pub fn constructed_evidence_objects() -> Vec<(EvidenceKindV1, EvidenceObjectV1)> {
    let checkpoint = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: organization(1),
        chain_id: chain(2),
        covered_from_sequence: ChainSequence::new(0),
        covered_through_sequence: ChainSequence::new(0),
        head_entry_hash: entry_hash(3),
        registry_head_hash: typed_hash(4),
        issued_at_server: UnixMillis::new(5),
        previous_evidence_hash: None,
    })
    .unwrap();
    let standard_signature = signer()
        .sign_checkpoint(certificate(3), checkpoint.exact_bytes())
        .unwrap();
    let standard = EvidenceObjectV1::standard(checkpoint.clone(), standard_signature).unwrap();

    let timestamp_signature = timestamped_signature(
        signer()
            .sign_checkpoint(certificate(3), checkpoint.exact_bytes())
            .unwrap(),
    );
    let timestamp =
        EvidenceObjectV1::timestamp(checkpoint, timestamp_signature, rfc3161_evidence_fields())
            .unwrap();

    let renewal = RenewalCoreV1::new(RenewalCoreFieldsV1 {
        organization_id: organization(1),
        chain_id: chain(2),
        current_entry_hash: entry_hash(3),
        previous_renewal_hash: None,
        renewal_input_hashes: vec![typed_hash(8), typed_hash(9)],
    })
    .unwrap();
    let renewal_signature = timestamped_signature(
        signer()
            .sign_evidence_renewal(certificate(3), renewal.exact_bytes())
            .unwrap(),
    );
    let renewal =
        EvidenceObjectV1::renewal(renewal, renewal_signature, rfc3161_evidence_fields()).unwrap();

    vec![
        (EvidenceKindV1::StandardCheckpoint, standard),
        (EvidenceKindV1::Timestamp, timestamp),
        (EvidenceKindV1::Renewal, renewal),
    ]
}

pub fn constructed_timestamp_with_response_length(length: usize) -> EvidenceObjectV1 {
    let checkpoint = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: organization(1),
        chain_id: chain(2),
        covered_from_sequence: ChainSequence::new(0),
        covered_through_sequence: ChainSequence::new(0),
        head_entry_hash: entry_hash(3),
        registry_head_hash: typed_hash(4),
        issued_at_server: UnixMillis::new(5),
        previous_evidence_hash: None,
    })
    .unwrap();
    let signature = timestamped_signature(
        signer()
            .sign_checkpoint(certificate(3), checkpoint.exact_bytes())
            .unwrap(),
    );
    let mut fields = rfc3161_evidence_fields();
    fields.rfc3161_response_der = vec![0; length];
    EvidenceObjectV1::timestamp(checkpoint, signature, fields).unwrap()
}

fn timestamped_signature(signature: Vec<u8>) -> Vec<u8> {
    let token_der = hex::decode(include_str!("../fixtures/rfc9921-token.hex").trim()).unwrap();
    let token = UnverifiedRfc3161TimeStampToken::from_der(&token_der).unwrap();
    attach_rfc3161_ctt(&signature, &token).unwrap()
}

fn rfc3161_evidence_fields() -> Rfc3161EvidenceFieldsV1 {
    Rfc3161EvidenceFieldsV1 {
        rfc3161_response_der: vec![0x30, 0],
        request_nonce: vec![0x44; 16],
        policy_oid_der: vec![0x06, 1, 0x2a],
        tsa_certificate_chain_der: vec![vec![0x30, 0]],
        revocation_data_der: Vec::new(),
        validation_data_der: Vec::new(),
    }
}

pub fn invalid_evidence_structural_cases() -> Vec<(Vec<u8>, &'static str)> {
    vec![
        (
            build_standard_ecp(checkpoint_core("EINSATZARCHIV-CHECKPOINT-vX"), false),
            "EA-FORMAT-SHAPE",
        ),
        (
            build_timestamp_like_ecp(
                1,
                checkpoint_core("EINSATZARCHIV-CHECKPOINT-v1"),
                ContentType::CheckpointCbor,
                true,
                1,
                &[vec![0x30, 0]],
            ),
            "EA-FORMAT-TAG-MISMATCH",
        ),
        (
            build_timestamp_like_ecp(
                1,
                checkpoint_core("EINSATZARCHIV-CHECKPOINT-v1"),
                ContentType::CheckpointCbor,
                true,
                0,
                &[],
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            build_timestamp_like_ecp(
                2,
                renewal_core("EINSATZARCHIV-EVIDENCE-RENEWAL-v1", &[]),
                ContentType::EvidenceRenewalCbor,
                false,
                0,
                &[vec![0x30, 0]],
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            build_timestamp_like_ecp(
                2,
                renewal_core("EINSATZARCHIV-EVIDENCE-RENEWAL-v1", &[hash32(8), hash32(8)]),
                ContentType::EvidenceRenewalCbor,
                false,
                0,
                &[vec![0x30, 0]],
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            build_timestamp_like_ecp(
                2,
                renewal_core("EINSATZARCHIV-EVIDENCE-RENEWAL-v1", &[hash32(9), hash32(8)]),
                ContentType::EvidenceRenewalCbor,
                false,
                0,
                &[vec![0x30, 0]],
            ),
            "EA-FORMAT-SHAPE",
        ),
    ]
}

pub fn evidence_ctt_correlation_cases() -> Vec<(Vec<u8>, &'static str)> {
    vec![
        (
            build_standard_ecp(checkpoint_core("EINSATZARCHIV-CHECKPOINT-v1"), true),
            "EA-FORMAT-COSE",
        ),
        (
            build_timestamp_like_ecp(
                1,
                checkpoint_core("EINSATZARCHIV-CHECKPOINT-v1"),
                ContentType::CheckpointCbor,
                false,
                0,
                &[vec![0x30, 0]],
            ),
            "EA-FORMAT-COSE",
        ),
        (
            build_timestamp_like_ecp(
                2,
                renewal_core("EINSATZARCHIV-EVIDENCE-RENEWAL-v1", &[hash32(8)]),
                ContentType::EvidenceRenewalCbor,
                false,
                0,
                &[vec![0x30, 0]],
            ),
            "EA-FORMAT-COSE",
        ),
    ]
}

fn checkpoint_core(domain: &str) -> Vec<u8> {
    let mut core = Vec::new();
    Encoder::new(&mut core)
        .array(11)
        .unwrap()
        .u8(1)
        .unwrap()
        .str(domain)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&id16(2))
        .unwrap()
        .u8(0)
        .unwrap()
        .u8(0)
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .bytes(&hash32(4))
        .unwrap()
        .i64(5)
        .unwrap()
        .null()
        .unwrap()
        .array(0)
        .unwrap();
    core
}

fn renewal_core(domain: &str, hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut core = Vec::new();
    let mut encoder = Encoder::new(&mut core);
    encoder
        .array(8)
        .unwrap()
        .u8(1)
        .unwrap()
        .str(domain)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&id16(2))
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .null()
        .unwrap()
        .array(u64::try_from(hashes.len()).unwrap())
        .unwrap();
    for hash in hashes {
        encoder.bytes(hash).unwrap();
    }
    encoder.array(0).unwrap();
    core
}

fn build_standard_ecp(core: Vec<u8>, with_ctt: bool) -> Vec<u8> {
    let signature = evidence_cose(ContentType::CheckpointCbor, &core, with_ctt);
    let mut standard = Vec::new();
    standard.push(0x82);
    standard.extend_from_slice(&core);
    standard.extend_from_slice(&signature);
    let mut body = vec![0x82, 0x00];
    body.extend_from_slice(&standard);
    wrap(4, &body)
}

#[allow(clippy::too_many_arguments)]
fn build_timestamp_like_ecp(
    variant: u8,
    core: Vec<u8>,
    content_type: ContentType,
    with_ctt: bool,
    hash_algorithm: u8,
    tsa_chain: &[Vec<u8>],
) -> Vec<u8> {
    let signature = evidence_cose(content_type, &core, with_ctt);
    let mut evidence = Vec::new();
    let mut encoder = Encoder::new(&mut evidence);
    encoder.array(9).unwrap();
    evidence.extend_from_slice(&core);
    evidence.extend_from_slice(&signature);
    let mut encoder = Encoder::new(&mut evidence);
    encoder
        .bytes(&[0x30, 0])
        .unwrap()
        .u8(hash_algorithm)
        .unwrap()
        .bytes(&[0x44; 16])
        .unwrap()
        .bytes(&[0x06, 1, 0x2a])
        .unwrap()
        .array(u64::try_from(tsa_chain.len()).unwrap())
        .unwrap();
    for certificate in tsa_chain {
        encoder.bytes(certificate).unwrap();
    }
    encoder.array(0).unwrap().array(0).unwrap();
    let mut body = Vec::new();
    Encoder::new(&mut body)
        .array(2)
        .unwrap()
        .u8(variant)
        .unwrap();
    body.extend_from_slice(&evidence);
    wrap(4, &body)
}

fn evidence_cose(content_type: ContentType, core: &[u8], with_ctt: bool) -> Vec<u8> {
    let cose = structural_cose_with_key(
        content_type,
        signer_thumbprint(),
        certificate(3),
        core,
        0x39,
    );
    if !with_ctt {
        return cose;
    }
    let token_der = hex::decode(include_str!("../fixtures/rfc9921-token.hex").trim()).unwrap();
    let token = UnverifiedRfc3161TimeStampToken::from_der(&token_der).unwrap();
    attach_rfc3161_ctt(&cose, &token).unwrap()
}

fn valid_etb() -> Vec<u8> {
    trust_object(
        "organizationAdminAuthorization",
        admin_authorization_core(),
        1,
    )
}

pub fn valid_etb_objects() -> Vec<(TrustSubtypeV1, Vec<u8>)> {
    vec![
        (
            TrustSubtypeV1::RootCertificate,
            initial_root_trust_object(root_core(None)),
        ),
        (
            TrustSubtypeV1::DeviceCertificate,
            trust_object("deviceCertificate", device_core(2, &["decrypt", "sign"]), 1),
        ),
        (
            TrustSubtypeV1::OperatorBinding,
            trust_object("operatorBinding", operator_core(2), 1),
        ),
        (TrustSubtypeV1::OrganizationAdminAuthorization, valid_etb()),
        (
            TrustSubtypeV1::RegistryEvent,
            trust_object(
                "registryEvent",
                authorized_payload(registry_event_core()),
                1,
            ),
        ),
        (
            TrustSubtypeV1::Policy,
            trust_object(
                "policy",
                authorized_payload(policy_core(&[hash32(1), hash32(2)], &["A", "B"], &[1, 2])),
                1,
            ),
        ),
        (
            TrustSubtypeV1::WriterTransition,
            trust_object(
                "writerTransition",
                authorized_payload(writer_transition_core()),
                1,
            ),
        ),
        (
            TrustSubtypeV1::GrantAuthorization,
            trust_object(
                "grantAuthorization",
                grant_authorization_core(&[hash32(1), hash32(2)]),
                2,
            ),
        ),
        (
            TrustSubtypeV1::DestructionAuthorization,
            trust_object(
                "destructionAuthorization",
                destruction_authorization_core(&[(hash32(1), 9), (hash32(2), 9)]),
                2,
            ),
        ),
        (
            TrustSubtypeV1::DestructionTransition,
            trust_object("destructionTransition", destruction_transition_core(), 1),
        ),
        (
            TrustSubtypeV1::DeletionAttestation,
            trust_object(
                "deletionAttestation",
                deletion_attestation_core(&[hash32(1), hash32(2)]),
                1,
            ),
        ),
    ]
}

pub fn trust_profile_correlation_cases() -> (Vec<u8>, Vec<u8>) {
    (
        initial_root_trust_object(root_core(None)),
        initial_root_profile_trust_object(
            "organizationAdminAuthorization",
            admin_authorization_core(),
        ),
    )
}

pub fn direct_initial_root_with_normal_trust_profile() -> Vec<u8> {
    trust_object("rootCertificate", root_core(None), 1)
}

pub fn valid_authorized_root_device_and_operator_objects() -> Vec<(TrustSubtypeV1, Vec<u8>)> {
    vec![
        (
            TrustSubtypeV1::RootCertificate,
            trust_object(
                "rootCertificate",
                authorized_payload(root_core(Some(hash32(9)))),
                1,
            ),
        ),
        (
            TrustSubtypeV1::DeviceCertificate,
            trust_object(
                "deviceCertificate",
                authorized_payload(device_core(0, &["sign"])),
                2,
            ),
        ),
        (
            TrustSubtypeV1::OperatorBinding,
            trust_object("operatorBinding", authorized_payload(operator_core(0)), 2),
        ),
    ]
}

pub fn constructed_trust_objects() -> Vec<(TrustSubtypeV1, TrustObjectV1)> {
    let initial_root = TrustPayloadV1::initial_root_certificate(RootCertificateFieldsV1 {
        organization_id: organization(1),
        root_public_cose_key: vec![0xa1, 0x01],
        root_key_thumbprint: signer_thumbprint(),
        previous_root_certificate_object_hash: None,
        effective_from_registry_version: RegistryVersion::new(1),
    })
    .unwrap();
    let authorized_root = TrustPayloadV1::authorized_root_certificate(
        RootCertificateFieldsV1 {
            organization_id: organization(1),
            root_public_cose_key: vec![0xa1, 0x01],
            root_key_thumbprint: key_thumbprint(2),
            previous_root_certificate_object_hash: Some(typed_object_hash(3)),
            effective_from_registry_version: RegistryVersion::new(2),
        },
        typed_object_hash(0xf0),
    )
    .unwrap();
    let initial_device =
        TrustPayloadV1::initial_admin_device_certificate(DeviceCertificateFieldsV1 {
            organization_id: organization(1),
            device_id: device_id(2),
            certificate_kind: CertificateKindV1::OrganizationAdmin,
            signing_public_cose_key: Some(vec![0xa1, 0x01]),
            kem_public_cose_key: None,
            signing_key_thumbprint: Some(key_thumbprint(3)),
            kem_key_thumbprint: None,
            capabilities: vec!["decrypt".into(), "sign".into()],
            key_protection_profile: KeyProtectionProfileV1::OsWrapped,
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence: None,
        })
        .unwrap();
    let authorized_device = TrustPayloadV1::authorized_device_certificate(
        DeviceCertificateFieldsV1 {
            organization_id: organization(1),
            device_id: device_id(2),
            certificate_kind: CertificateKindV1::Writer,
            signing_public_cose_key: Some(vec![0xa1, 0x01]),
            kem_public_cose_key: None,
            signing_key_thumbprint: Some(key_thumbprint(3)),
            kem_key_thumbprint: None,
            capabilities: vec!["sign".into()],
            key_protection_profile: KeyProtectionProfileV1::OsWrapped,
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence: None,
        },
        typed_object_hash(0xf0),
    )
    .unwrap();
    let initial_operator =
        TrustPayloadV1::initial_admin_operator_binding(OperatorBindingFieldsV1 {
            organization_id: organization(1),
            operator_subject_id: operator_subject_id(2),
            operator_profile_commitment: typed_hash(3),
            device_certificate_hash: certificate(4),
            operator_role: OperatorRoleV1::OrganizationAdmin,
            os_account_binding_hash: typed_hash(5),
            operator_instance_key_thumbprint: key_thumbprint(6),
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence: None,
        })
        .unwrap();
    let authorized_operator = TrustPayloadV1::authorized_operator_binding(
        OperatorBindingFieldsV1 {
            organization_id: organization(1),
            operator_subject_id: operator_subject_id(2),
            operator_profile_commitment: typed_hash(3),
            device_certificate_hash: certificate(4),
            operator_role: OperatorRoleV1::Writer,
            os_account_binding_hash: typed_hash(5),
            operator_instance_key_thumbprint: key_thumbprint(6),
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence: None,
        },
        typed_object_hash(0xf0),
    )
    .unwrap();
    let admin =
        TrustPayloadV1::organization_admin_authorization(OrganizationAdminAuthorizationFieldsV1 {
            authorization_id: authorization_id(1),
            organization_id: organization(2),
            registry_version: RegistryVersion::new(1),
            registry_head_hash: typed_hash(3),
            admin_key_thumbprint: signer_thumbprint(),
            admin_certificate_hash: certificate(3),
            admin_operator_binding_object_hash: typed_object_hash(4),
            action_code: 0,
            target_trust_subtype: TrustSubtypeV1::DeviceCertificate,
            authorized_trust_core_hash: typed_hash(5),
            issued_at: UnixMillis::new(6),
            expires_at: UnixMillis::new(7),
            nonce: hash32(8),
        })
        .unwrap();
    let registry = TrustPayloadV1::registry_event(
        RegistryEventFieldsV1 {
            organization_id: organization(1),
            registry_version: RegistryVersion::new(1),
            previous_registry_hash: None,
            effective_from_sequence: ChainSequence::new(0),
            valid_through_sequence: ChainSequence::new(100),
            issued_at: UnixMillis::new(1),
            not_before: UnixMillis::new(0),
            not_after: UnixMillis::new(100),
            policy_object_hash: typed_object_hash(2),
            change: RegistryChangeV1::Certificate {
                object_hash: typed_object_hash(3),
            },
            root_key_thumbprint: key_thumbprint(4),
        },
        typed_object_hash(0xf0),
    )
    .unwrap();
    let policy = TrustPayloadV1::policy(
        PolicyFieldsV1 {
            organization_id: organization(1),
            policy_version: 1,
            previous_policy_object_hash: None,
            operating_profile: 0,
            max_registry_age_ms: 1,
            max_future_clock_skew_ms: 2,
            registry_expiry_behavior: 0,
            evidence_max_delay_ms: 3,
            reader_inactivity_ms: 4,
            reader_history_access_allowed: true,
            allowed_archive_profile_hashes: vec![typed_hash(1), typed_hash(2)],
            backup_frequency_ms: 5,
            restore_test_interval_ms: 6,
            retention_policy: RetentionPolicyFieldsV1 {
                minimum_retention_ms: None,
                destruction_enabled: true,
                eds_privacy_decision_document_hash: Some(typed_hash(3)),
            },
            free_text_policy: FreeTextPolicyFieldsV1 {
                free_text_allowed: true,
                rule_set_version: "v1".into(),
                local_pattern_warning_enabled: true,
            },
            allowed_crypto_suite_ids: vec!["A".into(), "B".into()],
            allowed_format_versions: vec![1, 2],
            effective_from_sequence: ChainSequence::new(0),
        },
        typed_object_hash(0xf0),
    )
    .unwrap();
    let writer = TrustPayloadV1::writer_transition(
        WriterTransitionFieldsV1 {
            organization_id: organization(1),
            chain_id: chain(2),
            old_writer_certificate_hash: certificate(3),
            new_writer_certificate_hash: certificate(4),
            effective_from_sequence: ChainSequence::new(5),
            previous_entry_hash: entry_hash(6),
            reason_code: 0,
        },
        typed_object_hash(0xf0),
    )
    .unwrap();
    let grant = TrustPayloadV1::grant_authorization(GrantAuthorizationFieldsV1 {
        authorization_id: authorization_id(1),
        organization_id: organization(2),
        registry_version: RegistryVersion::new(1),
        registry_head_hash: typed_hash(3),
        authorization_sequence: 4,
        entry_hashes: vec![entry_hash(1), entry_hash(2)],
        recipient_key_thumbprint: key_thumbprint(5),
        recipient_certificate_hash: certificate(6),
        expires_at: UnixMillis::new(100),
    })
    .unwrap();
    let destruction = TrustPayloadV1::destruction_authorization(DestructionAuthorizationFieldsV1 {
        destruction_id: destruction_id(1),
        organization_id: organization(2),
        registry_version: RegistryVersion::new(1),
        registry_head_hash: typed_hash(3),
        authorization_sequence: 4,
        targets: vec![
            DestructionTargetV1::new(hash32(1), 9),
            DestructionTargetV1::new(hash32(2), 9),
        ],
        scope_code: 0,
        legal_reason_code: 0,
    })
    .unwrap();
    let transition = TrustPayloadV1::destruction_transition(DestructionTransitionFieldsV1 {
        destruction_id: destruction_id(1),
        destruction_authorization_object_hash: typed_object_hash(2),
        event_id: event_id(3),
        previous_event_object_hash: None,
        from_state: None,
        to_state: 0,
        trigger_code: 0,
        executed_at: UnixMillis::new(1),
    })
    .unwrap();
    let deletion = TrustPayloadV1::deletion_attestation(DeletionAttestationFieldsV1 {
        destruction_id: destruction_id(1),
        destruction_authorization_object_hash: typed_object_hash(2),
        replica_id: id16(3),
        replica_kind: 0,
        removed_object_hashes: vec![typed_object_hash(1), typed_object_hash(2)],
        result: 0,
        backup_expiry_at: None,
        executed_at: UnixMillis::new(1),
    })
    .unwrap();

    vec![
        constructed_trust(initial_root, 1, true),
        constructed_trust(authorized_root, 1, false),
        constructed_trust(initial_device, 1, false),
        constructed_trust(authorized_device, 2, false),
        constructed_trust(initial_operator, 1, false),
        constructed_trust(authorized_operator, 2, false),
        constructed_trust(admin, 1, false),
        constructed_trust(registry, 1, false),
        constructed_trust(policy, 1, false),
        constructed_trust(writer, 1, false),
        constructed_trust(grant, 2, false),
        constructed_trust(destruction, 2, false),
        constructed_trust(transition, 1, false),
        constructed_trust(deletion, 1, false),
    ]
}

pub fn constructed_policy_with_format_version_count(count: usize) -> TrustObjectV1 {
    let payload = TrustPayloadV1::policy(
        PolicyFieldsV1 {
            organization_id: organization(1),
            policy_version: 1,
            previous_policy_object_hash: None,
            operating_profile: 0,
            max_registry_age_ms: 1,
            max_future_clock_skew_ms: 2,
            registry_expiry_behavior: 0,
            evidence_max_delay_ms: 3,
            reader_inactivity_ms: 4,
            reader_history_access_allowed: true,
            allowed_archive_profile_hashes: vec![typed_hash(1)],
            backup_frequency_ms: 5,
            restore_test_interval_ms: 6,
            retention_policy: RetentionPolicyFieldsV1 {
                minimum_retention_ms: None,
                destruction_enabled: true,
                eds_privacy_decision_document_hash: Some(typed_hash(3)),
            },
            free_text_policy: FreeTextPolicyFieldsV1 {
                free_text_allowed: true,
                rule_set_version: "v1".into(),
                local_pattern_warning_enabled: true,
            },
            allowed_crypto_suite_ids: vec!["A".into()],
            allowed_format_versions: (0..u64::try_from(count).unwrap()).collect(),
            effective_from_sequence: ChainSequence::new(0),
        },
        typed_object_hash(0xf0),
    )
    .unwrap();
    constructed_trust(payload, 1, false).1
}

fn constructed_trust(
    payload: TrustPayloadV1,
    signature_count: usize,
    initial_root: bool,
) -> (TrustSubtypeV1, TrustObjectV1) {
    let subtype = payload.subtype();
    let digest = ea_crypto::trust_digest(payload.exact_digest_input());
    let signatures = (0..signature_count)
        .map(|index| {
            if initial_root {
                structural_initial_root_cose(digest.as_bytes(), 0x40)
            } else {
                structural_cose(
                    ContentType::TrustDigest,
                    certificate(3),
                    digest.as_bytes(),
                    0x40_u8.wrapping_add(u8::try_from(index).unwrap()),
                )
            }
        })
        .collect();
    (subtype, TrustObjectV1::new(payload, signatures).unwrap())
}

fn structural_initial_root_cose(payload: &[u8], signature_byte: u8) -> Vec<u8> {
    let protected = ProtectedHeader::initial_root(signer_thumbprint()).to_deterministic_cbor();
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .tag(minicbor::data::Tag::new(18))
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(&protected)
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(payload)
        .unwrap()
        .bytes(&[signature_byte; 64])
        .unwrap();
    bytes
}

pub fn invalid_trust_wrapper_and_cardinality_cases() -> Vec<Vec<u8>> {
    vec![
        trust_object("rootCertificate", root_core(Some(hash32(9))), 1),
        trust_object("rootCertificate", authorized_payload(root_core(None)), 1),
        trust_object("deviceCertificate", device_core(1, &["sign"]), 1),
        trust_object("operatorBinding", operator_core(1), 1),
        trust_object("registryEvent", registry_event_core(), 1),
        trust_object("rootCertificate", root_core(None), 0),
        trust_object("rootCertificate", root_core(None), 2),
        trust_object("deviceCertificate", device_core(2, &["sign"]), 2),
        trust_object("operatorBinding", operator_core(2), 0),
        trust_object(
            "organizationAdminAuthorization",
            admin_authorization_core(),
            2,
        ),
        trust_object(
            "registryEvent",
            authorized_payload(registry_event_core()),
            0,
        ),
        trust_object(
            "grantAuthorization",
            grant_authorization_core(&[hash32(1)]),
            1,
        ),
        trust_object(
            "destructionAuthorization",
            destruction_authorization_core(&[(hash32(1), 1)]),
            1,
        ),
    ]
}

pub fn invalid_trust_sorted_and_target_cases() -> Vec<(Vec<u8>, &'static str)> {
    vec![
        (
            trust_object("deviceCertificate", device_core(2, &["sign", "decrypt"]), 1),
            "EA-FORMAT-UNSORTED",
        ),
        (
            trust_object("deviceCertificate", device_core(2, &["sign", "sign"]), 1),
            "EA-FORMAT-DUPLICATE",
        ),
        (
            trust_object(
                "policy",
                authorized_payload(policy_core(&[], &["A"], &[1])),
                1,
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            trust_object(
                "policy",
                authorized_payload(policy_core(&[hash32(2), hash32(1)], &["A"], &[1])),
                1,
            ),
            "EA-FORMAT-UNSORTED",
        ),
        (
            trust_object(
                "policy",
                authorized_payload(policy_core(&[hash32(1), hash32(1)], &["A"], &[1])),
                1,
            ),
            "EA-FORMAT-DUPLICATE",
        ),
        (
            trust_object(
                "policy",
                authorized_payload(policy_core(&[hash32(1)], &["B", "A"], &[1])),
                1,
            ),
            "EA-FORMAT-UNSORTED",
        ),
        (
            trust_object(
                "policy",
                authorized_payload(policy_core(&[hash32(1)], &[], &[1])),
                1,
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            trust_object(
                "policy",
                authorized_payload(policy_core(&[hash32(1)], &["A", "A"], &[1])),
                1,
            ),
            "EA-FORMAT-DUPLICATE",
        ),
        (
            trust_object(
                "policy",
                authorized_payload(policy_core(&[hash32(1)], &["A"], &[1, 1])),
                1,
            ),
            "EA-FORMAT-DUPLICATE",
        ),
        (
            trust_object(
                "policy",
                authorized_payload(policy_core(&[hash32(1)], &["A"], &[])),
                1,
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            trust_object(
                "policy",
                authorized_payload(policy_core(&[hash32(1)], &["A"], &[2, 1])),
                1,
            ),
            "EA-FORMAT-UNSORTED",
        ),
        (
            trust_object("grantAuthorization", grant_authorization_core(&[]), 2),
            "EA-FORMAT-SHAPE",
        ),
        (
            trust_object(
                "grantAuthorization",
                grant_authorization_core(&[hash32(2), hash32(1)]),
                2,
            ),
            "EA-FORMAT-UNSORTED",
        ),
        (
            trust_object(
                "grantAuthorization",
                grant_authorization_core(&[hash32(1), hash32(1)]),
                2,
            ),
            "EA-FORMAT-DUPLICATE",
        ),
        (
            trust_object(
                "destructionAuthorization",
                destruction_authorization_core(&[]),
                2,
            ),
            "EA-FORMAT-SHAPE",
        ),
        (
            trust_object(
                "destructionAuthorization",
                destruction_authorization_core(&[(hash32(2), 1), (hash32(1), 2)]),
                2,
            ),
            "EA-FORMAT-UNSORTED",
        ),
        (
            trust_object(
                "destructionAuthorization",
                destruction_authorization_core(&[(hash32(1), 1), (hash32(1), 2)]),
                2,
            ),
            "EA-FORMAT-DUPLICATE",
        ),
        (
            trust_object(
                "deletionAttestation",
                deletion_attestation_core(&[hash32(2), hash32(1)]),
                1,
            ),
            "EA-FORMAT-UNSORTED",
        ),
        (
            trust_object(
                "deletionAttestation",
                deletion_attestation_core(&[hash32(1), hash32(1)]),
                1,
            ),
            "EA-FORMAT-DUPLICATE",
        ),
    ]
}

pub fn trust_with_wrong_content_type() -> Vec<u8> {
    trust_object_with_content_type(
        "organizationAdminAuthorization",
        admin_authorization_core(),
        1,
        ContentType::ReceiptDigest,
    )
}

pub fn trust_with_different_opaque_signature(bytes: &[u8]) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    *changed.last_mut().expect("trust fixture is nonempty") ^= 1;
    changed
}

fn admin_authorization_core() -> Vec<u8> {
    let mut payload = Vec::new();
    Encoder::new(&mut payload)
        .array(15)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&id16(2))
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .bytes(signer_thumbprint().as_bytes())
        .unwrap()
        .bytes(certificate(3).as_bytes())
        .unwrap()
        .bytes(&hash32(4))
        .unwrap()
        .u8(0)
        .unwrap()
        .str("deviceCertificate")
        .unwrap()
        .bytes(&hash32(5))
        .unwrap()
        .i64(6)
        .unwrap()
        .i64(7)
        .unwrap()
        .bytes(&hash32(8))
        .unwrap()
        .array(0)
        .unwrap();
    payload
}

fn root_core(previous: Option<[u8; 32]>) -> Vec<u8> {
    let mut core = Vec::new();
    let mut encoder = Encoder::new(&mut core);
    encoder
        .array(7)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&[0xa1, 0x01])
        .unwrap()
        .bytes(&hash32(2))
        .unwrap();
    encode_optional_hash_for_fixture(&mut encoder, previous);
    encoder.u8(1).unwrap().array(0).unwrap();
    core
}

fn device_core(kind: u8, capabilities: &[&str]) -> Vec<u8> {
    let mut core = Vec::new();
    let mut encoder = Encoder::new(&mut core);
    encoder
        .array(13)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&id16(2))
        .unwrap()
        .u8(kind)
        .unwrap()
        .bytes(&[0xa1, 0x01])
        .unwrap()
        .null()
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .null()
        .unwrap()
        .array(u64::try_from(capabilities.len()).unwrap())
        .unwrap();
    for capability in capabilities {
        encoder.str(capability).unwrap();
    }
    encoder
        .u8(0)
        .unwrap()
        .u8(0)
        .unwrap()
        .null()
        .unwrap()
        .array(0)
        .unwrap();
    core
}

fn operator_core(role: u8) -> Vec<u8> {
    let mut core = Vec::new();
    Encoder::new(&mut core)
        .array(11)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&id16(2))
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .bytes(&hash32(4))
        .unwrap()
        .u8(role)
        .unwrap()
        .bytes(&hash32(5))
        .unwrap()
        .bytes(&hash32(6))
        .unwrap()
        .u8(0)
        .unwrap()
        .null()
        .unwrap()
        .array(0)
        .unwrap();
    core
}

fn authorized_payload(core: Vec<u8>) -> Vec<u8> {
    let mut payload = Vec::new();
    Encoder::new(&mut payload).array(2).unwrap();
    payload.extend_from_slice(&core);
    Encoder::new(&mut payload).bytes(&hash32(0xf0)).unwrap();
    payload
}

fn registry_event_core() -> Vec<u8> {
    let mut core = Vec::new();
    Encoder::new(&mut core)
        .array(13)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .u8(1)
        .unwrap()
        .null()
        .unwrap()
        .u8(0)
        .unwrap()
        .u8(100)
        .unwrap()
        .i64(1)
        .unwrap()
        .i64(0)
        .unwrap()
        .i64(100)
        .unwrap()
        .bytes(&hash32(2))
        .unwrap()
        .array(2)
        .unwrap()
        .u8(0)
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .bytes(&hash32(4))
        .unwrap()
        .array(0)
        .unwrap();
    core
}

fn policy_core(hashes: &[[u8; 32]], suites: &[&str], versions: &[u64]) -> Vec<u8> {
    let mut core = Vec::new();
    let mut encoder = Encoder::new(&mut core);
    encoder
        .array(21)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .u8(1)
        .unwrap()
        .null()
        .unwrap()
        .u8(0)
        .unwrap()
        .u8(1)
        .unwrap()
        .u8(2)
        .unwrap()
        .u8(0)
        .unwrap()
        .u8(3)
        .unwrap()
        .u8(4)
        .unwrap()
        .bool(true)
        .unwrap()
        .array(u64::try_from(hashes.len()).unwrap())
        .unwrap();
    for hash in hashes {
        encoder.bytes(hash).unwrap();
    }
    encoder
        .u8(0)
        .unwrap()
        .u8(5)
        .unwrap()
        .u8(6)
        .unwrap()
        .array(3)
        .unwrap()
        .null()
        .unwrap()
        .bool(true)
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .array(3)
        .unwrap()
        .bool(true)
        .unwrap()
        .str("v1")
        .unwrap()
        .bool(true)
        .unwrap()
        .array(u64::try_from(suites.len()).unwrap())
        .unwrap();
    for suite in suites {
        encoder.str(suite).unwrap();
    }
    encoder
        .array(u64::try_from(versions.len()).unwrap())
        .unwrap();
    for version in versions {
        encoder.u64(*version).unwrap();
    }
    encoder.u8(0).unwrap().array(0).unwrap();
    core
}

fn writer_transition_core() -> Vec<u8> {
    let mut core = Vec::new();
    Encoder::new(&mut core)
        .array(9)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&id16(2))
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .bytes(&hash32(4))
        .unwrap()
        .u8(5)
        .unwrap()
        .bytes(&hash32(6))
        .unwrap()
        .u8(0)
        .unwrap()
        .array(0)
        .unwrap();
    core
}

fn grant_authorization_core(hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut core = Vec::new();
    let mut encoder = Encoder::new(&mut core);
    encoder
        .array(12)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&id16(2))
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .u8(4)
        .unwrap()
        .array(u64::try_from(hashes.len()).unwrap())
        .unwrap();
    for hash in hashes {
        encoder.bytes(hash).unwrap();
    }
    encoder
        .bytes(&hash32(5))
        .unwrap()
        .bytes(&hash32(6))
        .unwrap()
        .u8(1)
        .unwrap()
        .i64(100)
        .unwrap()
        .array(0)
        .unwrap();
    core
}

fn destruction_authorization_core(targets: &[([u8; 32], u64)]) -> Vec<u8> {
    let mut core = Vec::new();
    let mut encoder = Encoder::new(&mut core);
    encoder
        .array(10)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&id16(2))
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&hash32(3))
        .unwrap()
        .u8(4)
        .unwrap()
        .array(u64::try_from(targets.len()).unwrap())
        .unwrap();
    for (hash, sequence) in targets {
        encoder
            .array(2)
            .unwrap()
            .bytes(hash)
            .unwrap()
            .u64(*sequence)
            .unwrap();
    }
    encoder.u8(0).unwrap().u8(0).unwrap().array(0).unwrap();
    core
}

fn destruction_transition_core() -> Vec<u8> {
    let mut core = Vec::new();
    Encoder::new(&mut core)
        .array(10)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&hash32(2))
        .unwrap()
        .bytes(&id16(3))
        .unwrap()
        .null()
        .unwrap()
        .null()
        .unwrap()
        .u8(0)
        .unwrap()
        .u8(0)
        .unwrap()
        .i64(1)
        .unwrap()
        .array(0)
        .unwrap();
    core
}

fn deletion_attestation_core(hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut core = Vec::new();
    let mut encoder = Encoder::new(&mut core);
    encoder
        .array(10)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&id16(1))
        .unwrap()
        .bytes(&hash32(2))
        .unwrap()
        .bytes(&id16(3))
        .unwrap()
        .u8(0)
        .unwrap()
        .array(u64::try_from(hashes.len()).unwrap())
        .unwrap();
    for hash in hashes {
        encoder.bytes(hash).unwrap();
    }
    encoder
        .u8(0)
        .unwrap()
        .null()
        .unwrap()
        .i64(1)
        .unwrap()
        .array(0)
        .unwrap();
    core
}

fn trust_object(subtype: &str, payload: Vec<u8>, signature_count: usize) -> Vec<u8> {
    trust_object_with_content_type(subtype, payload, signature_count, ContentType::TrustDigest)
}

fn initial_root_trust_object(payload: Vec<u8>) -> Vec<u8> {
    initial_root_profile_trust_object("rootCertificate", payload)
}

fn initial_root_profile_trust_object(subtype: &str, payload: Vec<u8>) -> Vec<u8> {
    let mut digest_input = Vec::new();
    Encoder::new(&mut digest_input)
        .array(2)
        .unwrap()
        .str(subtype)
        .unwrap();
    digest_input.extend_from_slice(&payload);
    let digest = ea_crypto::trust_digest(&digest_input);
    let protected = ProtectedHeader::initial_root(signer_thumbprint()).to_deterministic_cbor();
    let mut signature = Vec::new();
    Encoder::new(&mut signature)
        .tag(minicbor::data::Tag::new(18))
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(&protected)
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(digest.as_bytes())
        .unwrap()
        .bytes(&[0x41; 64])
        .unwrap();

    let mut body = Vec::new();
    Encoder::new(&mut body)
        .array(3)
        .unwrap()
        .str(subtype)
        .unwrap();
    body.extend_from_slice(&payload);
    Encoder::new(&mut body).array(1).unwrap();
    body.extend_from_slice(&signature);
    wrap(5, &body)
}

fn trust_object_with_content_type(
    subtype: &str,
    payload: Vec<u8>,
    signature_count: usize,
    content_type: ContentType,
) -> Vec<u8> {
    let mut digest_input = Vec::new();
    Encoder::new(&mut digest_input)
        .array(2)
        .unwrap()
        .str(subtype)
        .unwrap();
    digest_input.extend_from_slice(&payload);
    let digest = ea_crypto::trust_digest(&digest_input);
    let mut body = Vec::new();
    Encoder::new(&mut body)
        .array(3)
        .unwrap()
        .str(subtype)
        .unwrap();
    body.extend_from_slice(&payload);
    Encoder::new(&mut body)
        .array(u64::try_from(signature_count).unwrap())
        .unwrap();
    for index in 0..signature_count {
        body.extend_from_slice(&structural_cose(
            content_type,
            certificate(3),
            digest.as_bytes(),
            0x40_u8.wrapping_add(u8::try_from(index).unwrap()),
        ));
    }
    wrap(5, &body)
}

fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x85, 0x44, b'E', b'A', b'1', 0, tag, 1, 0x80];
    bytes.extend_from_slice(body);
    bytes
}

pub fn evidence_with_unknown_variant() -> Vec<u8> {
    let mut wrong_ecp = valid_ecp();
    wrong_ecp[10] = 3;
    wrong_ecp
}

pub fn trust_with_stale_payload_digest() -> Vec<u8> {
    let mut wrong_etb = valid_etb();
    let offset = wrong_etb
        .windows(16)
        .position(|window| window == id16(2))
        .expect("authorization id fixture must exist");
    wrong_etb[offset] ^= 1;
    wrong_etb
}

#[allow(dead_code)]
fn _typed_hashes(
    entry: EntryHash,
    object: ObjectHash,
    hash: Hash32,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    (*entry.as_bytes(), *object.as_bytes(), *hash.as_bytes())
}
