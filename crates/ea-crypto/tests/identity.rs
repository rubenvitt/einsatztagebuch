use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, CoseSigner, CoseVerifier, CryptoError,
    RecoveryVerificationContext, ResolvedSigner, SecretBytes, SignerCertificateResolver,
    SignerRole, VerificationContext, VerifiedSigner, authorized_trust_digest,
    linux_os_account_binding_hash, macos_os_account_binding_hash, object_hash, verify_cose_sign1,
    verify_recovery_test, windows_os_account_binding_hash,
};
use ea_types::{CertificateHash, ChainSequence, OrganizationId, RegistryVersion, SubjectId};
use ed25519_dalek::{Signer as _, SigningKey};
use minicbor::Encoder;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use zeroize::Zeroizing;

const REGISTRATION_CORE_HEX: &str = "890150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f005828a30101200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8f68101817545494e5341545a4152434849562d53554954452d3180";

struct FixtureResolver {
    requested_hash: CertificateHash,
    exact_certificate_bytes: Vec<u8>,
    registry_effective_from_sequence: ChainSequence,
    registry_revoked_from_sequence: Option<ChainSequence>,
    registry_revoked: bool,
    result_error: Option<CryptoError>,
    calls: Cell<usize>,
}

struct BootstrapRootResolver {
    requested_hash: CertificateHash,
    exact_certificate_bytes: Vec<u8>,
    calls: Cell<usize>,
}

impl SignerCertificateResolver for BootstrapRootResolver {
    fn resolve(
        &self,
        certificate_hash: CertificateHash,
        registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        self.calls.set(self.calls.get() + 1);
        if registry != RegistryVersion::new(0) || certificate_hash != self.requested_hash {
            return Err(CryptoError::SignerUnresolved);
        }
        Ok(ResolvedSigner {
            exact_certificate_bytes: &self.exact_certificate_bytes,
            registry_effective_from_sequence: ChainSequence::new(0),
            registry_revoked_from_sequence: None,
            registry_revoked: false,
            root_line_accepted: true,
        })
    }
}

impl SignerCertificateResolver for FixtureResolver {
    fn resolve(
        &self,
        certificate_hash: CertificateHash,
        registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        self.calls.set(self.calls.get() + 1);
        if registry != RegistryVersion::new(3) || certificate_hash != self.requested_hash {
            return Err(CryptoError::SignerUnresolved);
        }
        if let Some(error) = self.result_error {
            return Err(error);
        }
        Ok(ResolvedSigner {
            exact_certificate_bytes: &self.exact_certificate_bytes,
            registry_effective_from_sequence: self.registry_effective_from_sequence,
            registry_revoked_from_sequence: self.registry_revoked_from_sequence,
            registry_revoked: self.registry_revoked,
            root_line_accepted: true,
        })
    }
}

fn fixture_organization() -> OrganizationId {
    OrganizationId::try_from([0x11; 16].as_slice()).unwrap()
}

fn fixture_public_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(
        hex::decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
}

fn fixture_authority_subject(byte: u8) -> SubjectId {
    SubjectId::try_from([byte; 16].as_slice()).unwrap()
}

fn authority_subject_id_for_kind(kind: u8) -> Option<SubjectId> {
    matches!(kind, 2 | 3).then(|| fixture_authority_subject(0x70 + kind))
}

fn fixture_certificate_hash() -> CertificateHash {
    CertificateHash::from(object_hash(
        &device_certificate_bytes(&fixture_public_key()),
    ))
}

fn device_certificate_bytes(public_key: &CanonicalPublicCoseKey) -> Vec<u8> {
    device_certificate_bytes_with_profile(public_key, 0, &[])
}

fn device_certificate_bytes_with_profile(
    public_key: &CanonicalPublicCoseKey,
    kind: u8,
    capabilities: &[&str],
) -> Vec<u8> {
    device_certificate_bytes_with_profile_and_authority(
        public_key,
        kind,
        capabilities,
        authority_subject_id_for_kind(kind),
    )
}

fn device_certificate_bytes_with_profile_and_authority(
    public_key: &CanonicalPublicCoseKey,
    kind: u8,
    capabilities: &[&str],
    authority_subject_id: Option<SubjectId>,
) -> Vec<u8> {
    let root_signature = CoseSigner::from_secret(SecretBytes::new([0x55; 32]))
        .sign_initial_root(&[0x77; 32])
        .unwrap();
    let public_key_bytes = public_key.to_deterministic_cbor();
    let thumbprint = public_key.thumbprint();
    let mut certificate = Vec::new();
    let mut encoder = Encoder::new(&mut certificate);
    encoder
        .array(5)
        .and_then(|encoder| encoder.bytes(b"EA1\0"))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.array(3))
        .and_then(|encoder| encoder.str("deviceCertificate"))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.array(14))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0x22; 16]))
        .and_then(|encoder| encoder.u8(kind))
        .and_then(|encoder| encoder.bytes(&public_key_bytes))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.bytes(thumbprint.as_bytes()))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.array(capabilities.len() as u64))
        .unwrap();
    for capability in capabilities {
        encoder.str(capability).unwrap();
    }
    encoder
        .u8(0)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.null())
        .unwrap();
    match authority_subject_id {
        Some(subject_id) => encoder.bytes(subject_id.as_bytes()).unwrap(),
        None => encoder.null().unwrap(),
    };
    encoder
        .array(0)
        .and_then(|encoder| encoder.bytes(&[0x33; 32]))
        .and_then(|encoder| encoder.array(1))
        .unwrap();
    certificate.extend_from_slice(&root_signature);
    certificate
}

#[derive(Clone, Copy)]
enum OptionalKey<'a> {
    Null,
    Value(&'a CanonicalPublicCoseKey),
}

#[derive(Clone, Copy)]
enum AuthoritySubjectField {
    Omitted,
    Null,
    Value(SubjectId),
}

fn valid_authority_subject_field(kind: u8) -> AuthoritySubjectField {
    match authority_subject_id_for_kind(kind) {
        Some(subject_id) => AuthoritySubjectField::Value(subject_id),
        None => AuthoritySubjectField::Null,
    }
}

fn device_certificate_bytes_with_keys(
    kind: u8,
    signing_key: OptionalKey<'_>,
    kem_key: OptionalKey<'_>,
    corrupt_signing_thumbprint: bool,
    corrupt_kem_thumbprint: bool,
    authority_subject: AuthoritySubjectField,
) -> Vec<u8> {
    let root_signature = CoseSigner::from_secret(SecretBytes::new([0x55; 32]))
        .sign_initial_root(&[0x77; 32])
        .unwrap();
    let mut certificate = Vec::new();
    let mut encoder = Encoder::new(&mut certificate);
    encoder
        .array(5)
        .and_then(|encoder| encoder.bytes(b"EA1\0"))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.array(3))
        .and_then(|encoder| encoder.str("deviceCertificate"))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| {
            encoder.array(match authority_subject {
                AuthoritySubjectField::Omitted => 13,
                AuthoritySubjectField::Null | AuthoritySubjectField::Value(_) => 14,
            })
        })
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0x22; 16]))
        .and_then(|encoder| encoder.u8(kind))
        .unwrap();
    for key in [signing_key, kem_key] {
        match key {
            OptionalKey::Null => encoder.null().unwrap(),
            OptionalKey::Value(key) => encoder.bytes(&key.to_deterministic_cbor()).unwrap(),
        };
    }
    for (key, corrupt) in [
        (signing_key, corrupt_signing_thumbprint),
        (kem_key, corrupt_kem_thumbprint),
    ] {
        match key {
            OptionalKey::Null => encoder.null().unwrap(),
            OptionalKey::Value(key) => {
                let mut thumbprint = *key.thumbprint().as_bytes();
                if corrupt {
                    thumbprint[0] ^= 1;
                }
                encoder.bytes(&thumbprint).unwrap()
            }
        };
    }
    encoder
        .array(0)
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.null())
        .unwrap();
    match authority_subject {
        AuthoritySubjectField::Omitted => {}
        AuthoritySubjectField::Null => {
            encoder.null().unwrap();
        }
        AuthoritySubjectField::Value(subject_id) => {
            encoder.bytes(subject_id.as_bytes()).unwrap();
        }
    }
    encoder
        .array(0)
        .and_then(|encoder| encoder.bytes(&[0x33; 32]))
        .and_then(|encoder| encoder.array(1))
        .unwrap();
    certificate.extend_from_slice(&root_signature);
    certificate
}

fn x25519_fixture_public_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::x25519([0x99; 32]).unwrap()
}

fn root_certificate_bytes(authorized_rotation: bool, previous_is_hash: bool) -> Vec<u8> {
    let key = fixture_public_key();
    let key_bytes = key.to_deterministic_cbor();
    let root_signature = CoseSigner::from_secret(SecretBytes::new([0x55; 32]))
        .sign_initial_root(&[0x77; 32])
        .unwrap();
    let mut certificate = Vec::new();
    let mut encoder = Encoder::new(&mut certificate);
    encoder
        .array(5)
        .and_then(|encoder| encoder.bytes(b"EA1\0"))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.array(3))
        .and_then(|encoder| encoder.str("rootCertificate"))
        .unwrap();
    if authorized_rotation {
        encoder.array(2).unwrap();
    }
    encoder
        .array(7)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&key_bytes))
        .and_then(|encoder| encoder.bytes(key.thumbprint().as_bytes()))
        .unwrap();
    if previous_is_hash {
        encoder.bytes(&[0xa1; 32]).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder.u8(3).and_then(|encoder| encoder.array(0)).unwrap();
    if authorized_rotation {
        encoder.bytes(&[0xa2; 32]).unwrap();
    }
    encoder.array(1).unwrap();
    certificate.extend_from_slice(&root_signature);
    certificate
}

fn challenge_core(certificate_hash: CertificateHash) -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(7)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0x44; 32]))
        .and_then(|encoder| encoder.i64(1_000))
        .and_then(|encoder| encoder.i64(1_060))
        .and_then(|encoder| encoder.bytes(certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn trust_digest_input(subtype: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(2)
        .and_then(|encoder| encoder.str(subtype))
        .unwrap();
    bytes.extend_from_slice(payload);
    bytes
}

fn device_certificate_core() -> Vec<u8> {
    device_certificate_core_with_kind(0)
}

fn device_certificate_core_with_kind(kind: u8) -> Vec<u8> {
    device_certificate_core_with_activation(kind, 7, None)
}

fn device_certificate_core_with_activation(
    kind: u8,
    effective_from_sequence: u64,
    revoked_from_sequence: Option<u64>,
) -> Vec<u8> {
    let key = fixture_public_key();
    let key_bytes = key.to_deterministic_cbor();
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(14)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0x22; 16]))
        .and_then(|encoder| encoder.u8(kind))
        .and_then(|encoder| encoder.bytes(&key_bytes))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.bytes(key.thumbprint().as_bytes()))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u64(effective_from_sequence))
        .unwrap();
    match revoked_from_sequence {
        Some(sequence) => encoder.u64(sequence).unwrap(),
        None => encoder.null().unwrap(),
    };
    match authority_subject_id_for_kind(kind) {
        Some(subject_id) => encoder.bytes(subject_id.as_bytes()).unwrap(),
        None => encoder.null().unwrap(),
    };
    encoder.array(0).unwrap();
    bytes
}

fn root_authorized_device_certificate_input(kind: u8, action: u8) -> (Vec<u8>, Vec<u8>) {
    let core = device_certificate_core_with_kind(kind);
    let authorized_input = trust_digest_input("deviceCertificate", &core);
    let authorization = organization_admin_authorization_object_with_action(
        action,
        "deviceCertificate",
        authorized_trust_digest(&authorized_input).as_bytes(),
    );
    let mut payload = Vec::new();
    Encoder::new(&mut payload).array(2).unwrap();
    payload.extend_from_slice(&core);
    Encoder::new(&mut payload)
        .bytes(object_hash(&authorization).as_bytes())
        .unwrap();
    (
        trust_digest_input("deviceCertificate", &payload),
        authorization,
    )
}

fn grant_authorization_core() -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(12)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(&[0x51; 16]))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.bytes(&[0x52; 32]))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.bytes(&[0x53; 32]))
        .and_then(|encoder| encoder.bytes(&[0x54; 32]))
        .and_then(|encoder| encoder.bytes(&[0x55; 32]))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.i64(2_000))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn organization_admin_authorization_core() -> Vec<u8> {
    organization_admin_authorization_core_for(fixture_certificate_hash())
}

fn organization_admin_authorization_core_for(certificate_hash: CertificateHash) -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(15)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(&[0x61; 16]))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.bytes(&[0x62; 32]))
        .and_then(|encoder| encoder.bytes(fixture_public_key().thumbprint().as_bytes()))
        .and_then(|encoder| encoder.bytes(certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0x63; 32]))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.str("deviceCertificate"))
        .and_then(|encoder| encoder.bytes(&[0x64; 32]))
        .and_then(|encoder| encoder.i64(1_000))
        .and_then(|encoder| encoder.i64(2_000))
        .and_then(|encoder| encoder.bytes(&[0x65; 32]))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn organization_admin_authorization_object(
    target_subtype: &str,
    authorized_core_hash: &[u8; 32],
) -> Vec<u8> {
    let action = match target_subtype {
        "deviceCertificate" => 0,
        "registryEvent" => 2,
        "policy" => 2,
        "writerTransition" => 3,
        "operatorBinding" => 4,
        "rootCertificate" => 6,
        _ => panic!("unsupported authorization target fixture"),
    };
    organization_admin_authorization_object_with_action(
        action,
        target_subtype,
        authorized_core_hash,
    )
}

fn organization_admin_authorization_object_with_action(
    action: u8,
    target_subtype: &str,
    authorized_core_hash: &[u8; 32],
) -> Vec<u8> {
    organization_admin_authorization_object_with_previous_head(
        action,
        target_subtype,
        authorized_core_hash,
        3,
        [0x62; 32],
    )
}

fn organization_admin_authorization_object_with_previous_head(
    action: u8,
    target_subtype: &str,
    authorized_core_hash: &[u8; 32],
    registry_version: u64,
    registry_head_hash: [u8; 32],
) -> Vec<u8> {
    let mut core = Vec::new();
    Encoder::new(&mut core)
        .array(15)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(&[0x61; 16]))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.u64(registry_version))
        .and_then(|encoder| encoder.bytes(&registry_head_hash))
        .and_then(|encoder| encoder.bytes(fixture_public_key().thumbprint().as_bytes()))
        .and_then(|encoder| encoder.bytes(fixture_certificate_hash().as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0x63; 32]))
        .and_then(|encoder| encoder.u8(action))
        .and_then(|encoder| encoder.str(target_subtype))
        .and_then(|encoder| encoder.bytes(authorized_core_hash))
        .and_then(|encoder| encoder.i64(1_000))
        .and_then(|encoder| encoder.i64(2_000))
        .and_then(|encoder| encoder.bytes(&[0x65; 32]))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    let input = trust_digest_input("organizationAdminAuthorization", &core);
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let signature = signer
        .sign_organization_admin_trust_digest(&input)
        .unwrap_or_else(|_| signer.sign_initial_root(&[0x77; 32]).unwrap());
    let mut object = Vec::new();
    Encoder::new(&mut object)
        .array(5)
        .and_then(|encoder| encoder.bytes(b"EA1\0"))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.array(3))
        .and_then(|encoder| encoder.str("organizationAdminAuthorization"))
        .unwrap();
    object.extend_from_slice(&core);
    Encoder::new(&mut object).array(1).unwrap();
    object.extend_from_slice(&signature);
    object
}

fn operator_binding_core() -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(11)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0xb1; 16]))
        .and_then(|encoder| encoder.bytes(&[0xb2; 32]))
        .and_then(|encoder| encoder.bytes(fixture_certificate_hash().as_bytes()))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.bytes(&[0xb3; 32]))
        .and_then(|encoder| encoder.bytes(fixture_public_key().thumbprint().as_bytes()))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn initial_admin_operator_binding_core(
    role: u8,
    effective_from_sequence: u64,
    revoked_from_sequence: Option<u64>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(11)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0x72; 16]))
        .and_then(|encoder| encoder.bytes(&[0x73; 32]))
        .and_then(|encoder| encoder.bytes(fixture_certificate_hash().as_bytes()))
        .and_then(|encoder| encoder.u8(role))
        .and_then(|encoder| encoder.bytes(&[0x74; 32]))
        .and_then(|encoder| encoder.bytes(&[0x75; 32]))
        .and_then(|encoder| encoder.u64(effective_from_sequence))
        .unwrap();
    match revoked_from_sequence {
        Some(sequence) => encoder.u64(sequence).unwrap(),
        None => encoder.null().unwrap(),
    };
    encoder.array(0).unwrap();
    bytes
}

fn authorized_wrapper(core: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes).array(2).unwrap();
    bytes.extend_from_slice(core);
    Encoder::new(&mut bytes).bytes(&[0x76; 32]).unwrap();
    bytes
}

fn policy_core() -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(21)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u16(100))
        .and_then(|encoder| encoder.u8(10))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u16(100))
        .and_then(|encoder| encoder.u16(100))
        .and_then(|encoder| encoder.bool(true))
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.bytes(&[0xb4; 32]))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u16(1_000))
        .and_then(|encoder| encoder.u16(2_000))
        .and_then(|encoder| encoder.array(3))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.bool(false))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.array(3))
        .and_then(|encoder| encoder.bool(true))
        .and_then(|encoder| encoder.str("v1"))
        .and_then(|encoder| encoder.bool(true))
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.str("EINSATZARCHIV-SUITE-1"))
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn writer_transition_core() -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(9)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0xb5; 16]))
        .and_then(|encoder| encoder.bytes(&[0xb6; 32]))
        .and_then(|encoder| encoder.bytes(&[0xb7; 32]))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.bytes(&[0xb8; 32]))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn root_rotation_core(previous_root_certificate_hash: CertificateHash) -> Vec<u8> {
    let key = fixture_public_key();
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(7)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&key.to_deterministic_cbor()))
        .and_then(|encoder| encoder.bytes(key.thumbprint().as_bytes()))
        .and_then(|encoder| encoder.bytes(previous_root_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.u8(4))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn registry_event_core() -> Vec<u8> {
    registry_event_core_with_transition(4, Some([0x62; 32]), 2, 0)
}

fn registry_event_core_with_transition(
    registry_version: u64,
    previous_registry_hash: Option<[u8; 32]>,
    change_kind: u8,
    change_effect: u8,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(13)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.u64(registry_version))
        .unwrap();
    match previous_registry_hash {
        Some(hash) => encoder.bytes(&hash).unwrap(),
        None => encoder.null().unwrap(),
    };
    encoder
        .u8(7)
        .and_then(|encoder| encoder.u8(9))
        .and_then(|encoder| encoder.i64(900))
        .and_then(|encoder| encoder.i64(950))
        .and_then(|encoder| encoder.i64(2_000))
        .and_then(|encoder| encoder.bytes(&[0x91; 32]))
        .unwrap();
    match change_kind {
        0 | 2 | 3 | 4 | 6 => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u8(change_kind))
                .and_then(|encoder| encoder.bytes(&[0x91; 32]))
                .unwrap();
        }
        1 => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u8(change_kind))
                .and_then(|encoder| encoder.u8(change_effect))
                .and_then(|encoder| encoder.bytes(&[0x91; 32]))
                .unwrap();
        }
        5 => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u8(change_kind))
                .and_then(|encoder| encoder.bytes(&[0x91; 32]))
                .and_then(|encoder| encoder.u8(change_effect))
                .unwrap();
        }
        _ => panic!("unsupported Registry change fixture"),
    }
    encoder
        .bytes(fixture_public_key().thumbprint().as_bytes())
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn root_authorized_trust_input(
    subtype: &str,
    core: &[u8],
    action: u8,
    authorization_registry_version: u64,
    authorization_registry_head_hash: [u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    let authorized_input = trust_digest_input(subtype, core);
    let authorization = organization_admin_authorization_object_with_previous_head(
        action,
        subtype,
        authorized_trust_digest(&authorized_input).as_bytes(),
        authorization_registry_version,
        authorization_registry_head_hash,
    );
    let mut payload = Vec::new();
    Encoder::new(&mut payload).array(2).unwrap();
    payload.extend_from_slice(core);
    Encoder::new(&mut payload)
        .bytes(object_hash(&authorization).as_bytes())
        .unwrap();
    (trust_digest_input(subtype, &payload), authorization)
}

fn destruction_authorization_core() -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(10)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(&[0x71; 16]))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.bytes(&[0x72; 32]))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.bytes(&[0x73; 32]))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn destruction_authorization_object() -> Vec<u8> {
    let input = trust_digest_input(
        "destructionAuthorization",
        &destruction_authorization_core(),
    );
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let signature = signer
        .sign_destruction_approval_digest(fixture_certificate_hash(), &input)
        .unwrap();
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(5)
        .and_then(|encoder| encoder.bytes(b"EA1\0"))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.array(3))
        .and_then(|encoder| encoder.str("destructionAuthorization"))
        .unwrap();
    bytes.extend_from_slice(&destruction_authorization_core());
    Encoder::new(&mut bytes).array(2).unwrap();
    bytes.extend_from_slice(&signature);
    bytes.extend_from_slice(&signature);
    bytes
}

fn deletion_attestation_core(authorization_hash: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(10)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(&[0x71; 16]))
        .and_then(|encoder| encoder.bytes(authorization_hash))
        .and_then(|encoder| encoder.bytes(&[0x81; 16]))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.bytes(&[0x82; 32]))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.i64(2_100))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn destruction_transition_core(authorization_hash: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(10)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(&[0x71; 16]))
        .and_then(|encoder| encoder.bytes(authorization_hash))
        .and_then(|encoder| encoder.bytes(&[0x83; 16]))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.i64(2_050))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    bytes
}

fn resolver_for_certificate(exact_certificate_bytes: Vec<u8>) -> FixtureResolver {
    let requested_hash = CertificateHash::from(object_hash(&exact_certificate_bytes));
    FixtureResolver {
        requested_hash,
        exact_certificate_bytes,
        registry_effective_from_sequence: ChainSequence::new(1),
        registry_revoked_from_sequence: None,
        registry_revoked: false,
        result_error: None,
        calls: Cell::new(0),
    }
}

fn base_resolver() -> FixtureResolver {
    resolver_for_certificate(device_certificate_bytes(&fixture_public_key()))
}

fn signed_manifest(
    certificate_hash: CertificateHash,
    organization_id: OrganizationId,
    registry: RegistryVersion,
    ciphertext_hash_byte: u8,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(2)
        .and_then(|encoder| encoder.array(16))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0x31; 16]))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.bytes(certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.u64(registry.get()))
        .and_then(|encoder| encoder.bytes(&[0x32; 32]))
        .and_then(|encoder| encoder.bytes(&[0x33; 32]))
        .and_then(|encoder| encoder.str("EINSATZARCHIV-SUITE-1"))
        .and_then(|encoder| encoder.bytes(&[0x34; 12]))
        .and_then(|encoder| encoder.u8(48))
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.bytes(&[ciphertext_hash_byte; 32]))
        .unwrap();
    bytes
}

fn verification_context() -> VerificationContext {
    VerificationContext::record(&signed_manifest(
        fixture_certificate_hash(),
        fixture_organization(),
        RegistryVersion::new(3),
        0x41,
    ))
    .unwrap()
}

fn initial_grant_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes)
        .array(3)
        .and_then(|encoder| encoder.array(17))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0x31; 16]))
        .and_then(|encoder| encoder.bytes(&[0x32; 32]))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(&[0x33; 32]))
        .and_then(|encoder| encoder.bytes(&[0x34; 32]))
        .and_then(|encoder| encoder.bytes(fixture_public_key().thumbprint().as_bytes()))
        .and_then(|encoder| encoder.bytes(fixture_certificate_hash().as_bytes()))
        .and_then(|encoder| encoder.str("initialGrant"))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.bytes(&[0x35; 32]))
        .and_then(|encoder| encoder.str("EINSATZARCHIV-HPKE-1"))
        .and_then(|encoder| encoder.i8(0))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.bytes(&[0x36; 32]))
        .and_then(|encoder| encoder.bytes(&[0x37; 48]))
        .unwrap();
    bytes
}

#[test]
fn normal_verification_returns_the_one_atomically_bound_identity() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let signed_manifest = signed_manifest(
        fixture_certificate_hash(),
        fixture_organization(),
        RegistryVersion::new(3),
        0x41,
    );
    let signed = signer.sign_record(&signed_manifest).unwrap();
    let resolver = base_resolver();
    let verified = verify_cose_sign1(&signed, &resolver, &verification_context()).unwrap();
    let verifier_resolver = base_resolver();
    CoseVerifier::verify_normal(&signed, &verifier_resolver, &verification_context()).unwrap();
    assert_eq!(resolver.calls.get(), 1);
    assert!(verified.certificate_hash() == fixture_certificate_hash());
    assert!(verified.key_thumbprint() == fixture_public_key().thumbprint());
    assert!(verified.organization_id() == fixture_organization());
    assert_eq!(verified.role(), SignerRole::Writer);
}

#[test]
fn certificate_authority_subject_id_is_closed_and_propagated() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));

    let writer_certificate =
        device_certificate_bytes_with_profile_and_authority(&fixture_public_key(), 0, &[], None);
    let writer_certificate_hash = CertificateHash::from(object_hash(&writer_certificate));
    let writer_manifest = signed_manifest(
        writer_certificate_hash,
        fixture_organization(),
        RegistryVersion::new(3),
        0x41,
    );
    let writer_signature = signer.sign_record(&writer_manifest).unwrap();
    let writer_resolver = resolver_for_certificate(writer_certificate);
    let verified_writer: VerifiedSigner = verify_cose_sign1(
        &writer_signature,
        &writer_resolver,
        &VerificationContext::record(&writer_manifest).unwrap(),
    )
    .unwrap();

    let admin_subject = fixture_authority_subject(0xa2);
    let admin_certificate = device_certificate_bytes_with_profile_and_authority(
        &fixture_public_key(),
        2,
        &["organizationAdminApprove"],
        Some(admin_subject),
    );
    let admin_certificate_hash = CertificateHash::from(object_hash(&admin_certificate));
    let admin_authorization = trust_digest_input(
        "organizationAdminAuthorization",
        &organization_admin_authorization_core_for(admin_certificate_hash),
    );
    let admin_signature = signer
        .sign_organization_admin_trust_digest(&admin_authorization)
        .unwrap();
    let admin_resolver = resolver_for_certificate(admin_certificate);
    let verified_admin: VerifiedSigner = verify_cose_sign1(
        &admin_signature,
        &admin_resolver,
        &VerificationContext::organization_admin_trust_digest(&admin_authorization).unwrap(),
    )
    .unwrap();

    let approver_subject = fixture_authority_subject(0xa3);
    let approver_certificate = device_certificate_bytes_with_profile_and_authority(
        &fixture_public_key(),
        3,
        &["historicalGrantApprove"],
        Some(approver_subject),
    );
    let approver_certificate_hash = CertificateHash::from(object_hash(&approver_certificate));
    let grant_authorization = trust_digest_input("grantAuthorization", &grant_authorization_core());
    let approver_signature = signer
        .sign_historical_grant_approval_digest(approver_certificate_hash, &grant_authorization)
        .unwrap();
    let approver_resolver = resolver_for_certificate(approver_certificate);
    let verified_approver: VerifiedSigner = verify_cose_sign1(
        &approver_signature,
        &approver_resolver,
        &VerificationContext::historical_grant_approval_trust_digest(
            &grant_authorization,
            approver_certificate_hash,
        )
        .unwrap(),
    )
    .unwrap();

    assert!(verified_writer.authority_subject_id().is_none());
    assert!(verified_admin.authority_subject_id() == Some(admin_subject));
    assert!(verified_approver.authority_subject_id() == Some(approver_subject));
}

#[test]
fn every_certificate_identity_and_authority_mix_fails_closed() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let signed_manifest = signed_manifest(
        fixture_certificate_hash(),
        fixture_organization(),
        RegistryVersion::new(3),
        0x41,
    );
    let signed = signer.sign_record(&signed_manifest).unwrap();

    for (case, expected_code) in [
        ("certificate-bytes", "EA-TRUST-SIGNER-MISMATCH"),
        ("not-effective", "EA-TRUST-SIGNER-UNAUTHORIZED"),
        ("revoked-at-sequence", "EA-TRUST-SIGNER-UNAUTHORIZED"),
        ("revoked", "EA-TRUST-SIGNER-UNAUTHORIZED"),
        ("ambiguous", "EA-TRUST-SIGNER-UNRESOLVED"),
    ] {
        let mut resolver = base_resolver();
        match case {
            "certificate-bytes" => resolver.exact_certificate_bytes.push(0),
            "not-effective" => resolver.registry_effective_from_sequence = ChainSequence::new(8),
            "revoked-at-sequence" => {
                resolver.registry_revoked_from_sequence = Some(ChainSequence::new(7));
            }
            "revoked" => resolver.registry_revoked = true,
            "ambiguous" => resolver.result_error = Some(CryptoError::SignerUnresolved),
            _ => unreachable!(),
        }
        let context = verification_context();
        let error = verify_cose_sign1(&signed, &resolver, &context).unwrap_err();
        assert_eq!(error.code(), expected_code, "case {case}");
        assert_eq!(resolver.calls.get(), 1, "case {case}");
    }
}

#[test]
fn coordinated_key_substitution_cannot_mix_certificate_a_with_signer_b() {
    let certificate_a = device_certificate_bytes(&fixture_public_key());
    let certificate_a_hash = CertificateHash::from(object_hash(&certificate_a));
    let signer_b = CoseSigner::from_secret(SecretBytes::new([0x42; 32]));
    let manifest = signed_manifest(
        certificate_a_hash,
        fixture_organization(),
        RegistryVersion::new(3),
        0x41,
    );
    let signed_by_b = signer_b.sign_record(&manifest).unwrap();
    let mut mixed_resolver = base_resolver();
    mixed_resolver.requested_hash = certificate_a_hash;
    mixed_resolver.exact_certificate_bytes = certificate_a;

    assert_eq!(
        verify_cose_sign1(
            &signed_by_b,
            &mixed_resolver,
            &VerificationContext::record(&manifest).unwrap(),
        )
        .unwrap_err()
        .code(),
        "EA-TRUST-SIGNER-MISMATCH"
    );
}

#[test]
fn normal_verification_rejects_a_valid_signature_over_the_wrong_expected_digest() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let wrong_manifest = signed_manifest(
        fixture_certificate_hash(),
        fixture_organization(),
        RegistryVersion::new(3),
        0x42,
    );
    let signed_wrong_digest = signer.sign_record(&wrong_manifest).unwrap();

    assert_eq!(
        verify_cose_sign1(
            &signed_wrong_digest,
            &base_resolver(),
            &verification_context(),
        )
        .unwrap_err()
        .code(),
        "EA-TRUST-SIGNER-MISMATCH"
    );
}

#[test]
fn grant_content_cannot_reuse_writer_record_authority() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let grant_body = initial_grant_body();
    let signed_grant = signer.sign_initial_grant(&grant_body).unwrap();

    assert_eq!(
        verify_cose_sign1(
            &signed_grant,
            &base_resolver(),
            &VerificationContext::initial_grant(&grant_body, ChainSequence::new(7)).unwrap(),
        )
        .unwrap_err()
        .code(),
        "EA-TRUST-SIGNER-UNAUTHORIZED"
    );
}

#[test]
fn challenge_response_requires_the_normative_server_receipt_capability() {
    let exact_certificate_bytes =
        device_certificate_bytes_with_profile(&fixture_public_key(), 6, &[]);
    let requested_hash = CertificateHash::from(object_hash(&exact_certificate_bytes));
    let resolver = FixtureResolver {
        requested_hash,
        exact_certificate_bytes,
        registry_effective_from_sequence: ChainSequence::new(1),
        registry_revoked_from_sequence: None,
        registry_revoked: false,
        result_error: None,
        calls: Cell::new(0),
    };
    let core = challenge_core(requested_hash);
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let signed = signer.sign_challenge_response(&core).unwrap();
    let context = VerificationContext::challenge_response(
        &core,
        ChainSequence::new(7),
        RegistryVersion::new(3),
    )
    .unwrap();

    assert_eq!(
        verify_cose_sign1(&signed, &resolver, &context)
            .unwrap_err()
            .code(),
        "EA-TRUST-SIGNER-UNAUTHORIZED"
    );
}

#[test]
fn recovery_verification_binds_the_expected_challenge_and_returns_a_nonproductive_proof() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let certificate_hash = fixture_certificate_hash();
    let signed = signer
        .sign_recovery_test(certificate_hash, SecretBytes::new([0xa5; 32]))
        .unwrap();
    let context = RecoveryVerificationContext::new(
        certificate_hash,
        fixture_organization(),
        SignerRole::Writer,
        ChainSequence::new(7),
        RegistryVersion::new(3),
        SecretBytes::new([0xa5; 32]),
    );
    let proof = verify_recovery_test(&signed, &base_resolver(), &context).unwrap();
    assert!(proof.certificate_hash() == certificate_hash);
    assert!(proof.key_thumbprint() == fixture_public_key().thumbprint());
    assert_eq!(proof.certificate_kind(), SignerRole::Writer);

    let wrong_challenge = RecoveryVerificationContext::new(
        certificate_hash,
        fixture_organization(),
        SignerRole::Writer,
        ChainSequence::new(7),
        RegistryVersion::new(3),
        SecretBytes::new([0xa4; 32]),
    );
    let error = match verify_recovery_test(&signed, &base_resolver(), &wrong_challenge) {
        Ok(_) => panic!("a wrong recovery challenge must not verify"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "EA-TRUST-SIGNER-MISMATCH");
}

#[test]
fn historical_grant_approval_context_derives_and_closes_its_trust_subtype() {
    let certificate_hash = fixture_certificate_hash();
    let grant = trust_digest_input("grantAuthorization", &grant_authorization_core());
    assert!(
        VerificationContext::historical_grant_approval_trust_digest(&grant, certificate_hash)
            .is_ok()
    );

    let device = trust_digest_input("deviceCertificate", &device_certificate_core());
    let error = match VerificationContext::historical_grant_approval_trust_digest(
        &device,
        certificate_hash,
    ) {
        Ok(_) => panic!("a device certificate must not enter grant approval"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "EA-CRYPTO-INVALID-PROTOCOL-CORE");
}

#[test]
fn organization_admin_context_derives_its_embedded_signer_and_closes_its_subtype() {
    let authorization = trust_digest_input(
        "organizationAdminAuthorization",
        &organization_admin_authorization_core(),
    );
    assert!(VerificationContext::organization_admin_trust_digest(&authorization).is_ok());

    let grant = trust_digest_input("grantAuthorization", &grant_authorization_core());
    assert!(VerificationContext::organization_admin_trust_digest(&grant).is_err());
}

#[test]
fn destruction_approval_context_derives_and_closes_its_trust_subtype() {
    let certificate_hash = fixture_certificate_hash();
    let destruction = trust_digest_input(
        "destructionAuthorization",
        &destruction_authorization_core(),
    );
    assert!(
        VerificationContext::destruction_approval_trust_digest(&destruction, certificate_hash,)
            .is_ok()
    );

    let grant = trust_digest_input("grantAuthorization", &grant_authorization_core());
    assert!(
        VerificationContext::destruction_approval_trust_digest(&grant, certificate_hash).is_err()
    );
}

#[test]
fn deletion_attestation_context_binds_its_referenced_authorization_object() {
    let authorization_object = destruction_authorization_object();
    let authorization_hash = *object_hash(&authorization_object).as_bytes();
    let attestation = trust_digest_input(
        "deletionAttestation",
        &deletion_attestation_core(&authorization_hash),
    );
    assert!(
        VerificationContext::deletion_attestation_trust_digest(
            &attestation,
            &authorization_object,
            fixture_certificate_hash(),
        )
        .is_ok()
    );

    let wrong_authorization = destruction_authorization_object()
        .into_iter()
        .enumerate()
        .map(|(index, byte)| if index == 20 { byte ^ 1 } else { byte })
        .collect::<Vec<_>>();
    assert!(
        VerificationContext::deletion_attestation_trust_digest(
            &attestation,
            &wrong_authorization,
            fixture_certificate_hash(),
        )
        .is_err()
    );
}

#[test]
fn destruction_transition_is_a_separate_correlated_deletion_attest_operation() {
    let authorization_object = destruction_authorization_object();
    let authorization_hash = *object_hash(&authorization_object).as_bytes();
    let transition = trust_digest_input(
        "destructionTransition",
        &destruction_transition_core(&authorization_hash),
    );
    assert!(
        VerificationContext::destruction_transition_trust_digest(
            &transition,
            &authorization_object,
            fixture_certificate_hash(),
        )
        .is_ok()
    );
    assert!(
        VerificationContext::deletion_attestation_trust_digest(
            &transition,
            &authorization_object,
            fixture_certificate_hash(),
        )
        .is_err()
    );
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    assert!(
        signer
            .sign_destruction_transition_digest(
                fixture_certificate_hash(),
                &transition,
                &authorization_object,
            )
            .is_ok()
    );
}

#[test]
fn root_registry_authorization_binds_previous_head_and_successor() {
    const ZERO_HEAD: [u8; 32] = [0; 32];
    const HEAD_THREE: [u8; 32] = [0x73; 32];
    const WRONG_HEAD: [u8; 32] = [0x74; 32];

    struct RegistryCase {
        name: &'static str,
        authorization_version: u64,
        authorization_head: [u8; 32],
        event_version: u64,
        event_previous: Option<[u8; 32]>,
        action: u8,
        change_kind: u8,
        change_effect: u8,
        accepted: bool,
    }

    let cases = [
        RegistryCase {
            name: "bootstrap-successor",
            authorization_version: 0,
            authorization_head: ZERO_HEAD,
            event_version: 1,
            event_previous: None,
            action: 2,
            change_kind: 2,
            change_effect: 0,
            accepted: true,
        },
        RegistryCase {
            name: "ordinary-successor",
            authorization_version: 3,
            authorization_head: HEAD_THREE,
            event_version: 4,
            event_previous: Some(HEAD_THREE),
            action: 2,
            change_kind: 2,
            change_effect: 0,
            accepted: true,
        },
        RegistryCase {
            name: "operator-binding-change",
            authorization_version: 3,
            authorization_head: HEAD_THREE,
            event_version: 4,
            event_previous: Some(HEAD_THREE),
            action: 4,
            change_kind: 4,
            change_effect: 0,
            accepted: true,
        },
        RegistryCase {
            name: "root-rotation-change",
            authorization_version: 3,
            authorization_head: HEAD_THREE,
            event_version: 4,
            event_previous: Some(HEAD_THREE),
            action: 6,
            change_kind: 6,
            change_effect: 0,
            accepted: true,
        },
        RegistryCase {
            name: "same-version",
            authorization_version: 3,
            authorization_head: HEAD_THREE,
            event_version: 3,
            event_previous: Some(HEAD_THREE),
            action: 2,
            change_kind: 2,
            change_effect: 0,
            accepted: false,
        },
        RegistryCase {
            name: "version-jump",
            authorization_version: 3,
            authorization_head: HEAD_THREE,
            event_version: 5,
            event_previous: Some(HEAD_THREE),
            action: 2,
            change_kind: 2,
            change_effect: 0,
            accepted: false,
        },
        RegistryCase {
            name: "authorization-version-overflow",
            authorization_version: u64::MAX,
            authorization_head: HEAD_THREE,
            event_version: u64::MAX,
            event_previous: Some(HEAD_THREE),
            action: 2,
            change_kind: 2,
            change_effect: 0,
            accepted: false,
        },
        RegistryCase {
            name: "bootstrap-non-null-previous",
            authorization_version: 0,
            authorization_head: ZERO_HEAD,
            event_version: 1,
            event_previous: Some(ZERO_HEAD),
            action: 2,
            change_kind: 2,
            change_effect: 0,
            accepted: false,
        },
        RegistryCase {
            name: "successor-null-previous",
            authorization_version: 3,
            authorization_head: HEAD_THREE,
            event_version: 4,
            event_previous: None,
            action: 2,
            change_kind: 2,
            change_effect: 0,
            accepted: false,
        },
        RegistryCase {
            name: "successor-wrong-previous",
            authorization_version: 3,
            authorization_head: HEAD_THREE,
            event_version: 4,
            event_previous: Some(WRONG_HEAD),
            action: 2,
            change_kind: 2,
            change_effect: 0,
            accepted: false,
        },
        RegistryCase {
            name: "operator-action-root-change",
            authorization_version: 3,
            authorization_head: HEAD_THREE,
            event_version: 4,
            event_previous: Some(HEAD_THREE),
            action: 4,
            change_kind: 6,
            change_effect: 0,
            accepted: false,
        },
        RegistryCase {
            name: "root-action-operator-change",
            authorization_version: 3,
            authorization_head: HEAD_THREE,
            event_version: 4,
            event_previous: Some(HEAD_THREE),
            action: 6,
            change_kind: 4,
            change_effect: 0,
            accepted: false,
        },
    ];

    for case in cases {
        let core = registry_event_core_with_transition(
            case.event_version,
            case.event_previous,
            case.change_kind,
            case.change_effect,
        );
        let (input, authorization) = root_authorized_trust_input(
            "registryEvent",
            &core,
            case.action,
            case.authorization_version,
            case.authorization_head,
        );
        let result = VerificationContext::root_trust_digest(
            &input,
            fixture_certificate_hash(),
            Some(&authorization),
        );
        assert_eq!(result.is_ok(), case.accepted, "case {}", case.name);
        if let Err(error) = result {
            assert_eq!(
                error.code(),
                "EA-CRYPTO-INVALID-PROTOCOL-CORE",
                "case {}",
                case.name
            );
        }
    }

    for (subtype, core, action) in [
        ("operatorBinding", operator_binding_core(), 4),
        (
            "rootCertificate",
            root_rotation_core(fixture_certificate_hash()),
            6,
        ),
    ] {
        let (input, authorization) =
            root_authorized_trust_input(subtype, &core, action, 3, HEAD_THREE);
        assert!(
            VerificationContext::root_trust_digest(
                &input,
                fixture_certificate_hash(),
                Some(&authorization),
            )
            .is_ok(),
            "direct target {subtype}"
        );
    }

    let root_certificate = root_certificate_bytes(false, false);
    let root_certificate_hash = CertificateHash::from(object_hash(&root_certificate));
    let core = registry_event_core_with_transition(4, Some(HEAD_THREE), 2, 0);
    let (input, authorization) =
        root_authorized_trust_input("registryEvent", &core, 2, 3, HEAD_THREE);
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let signed = signer
        .sign_root_trust_digest(root_certificate_hash, &input, Some(&authorization))
        .unwrap();
    let context =
        VerificationContext::root_trust_digest(&input, root_certificate_hash, Some(&authorization))
            .unwrap();
    assert!(
        verify_cose_sign1(
            &signed,
            &resolver_for_certificate(root_certificate),
            &context,
        )
        .is_ok(),
        "the Root signer must resolve against authorization Registry v3"
    );
}

#[test]
fn accepted_root_context_derives_registry_event_correlations_and_rejects_other_subtypes() {
    let core = registry_event_core();
    let authorized_input = trust_digest_input("registryEvent", &core);
    let authorized_hash = *authorized_trust_digest(&authorized_input).as_bytes();
    let authorization =
        organization_admin_authorization_object_with_action(2, "registryEvent", &authorized_hash);
    let mut payload = Vec::new();
    Encoder::new(&mut payload).array(2).unwrap();
    payload.extend_from_slice(&core);
    Encoder::new(&mut payload)
        .bytes(object_hash(&authorization).as_bytes())
        .unwrap();
    let root_input = trust_digest_input("registryEvent", &payload);
    assert!(
        VerificationContext::root_trust_digest(
            &root_input,
            fixture_certificate_hash(),
            Some(&authorization),
        )
        .is_ok()
    );

    let wrong_effect_authorization =
        organization_admin_authorization_object_with_action(1, "registryEvent", &authorized_hash);
    let mut wrong_effect_payload = Vec::new();
    Encoder::new(&mut wrong_effect_payload).array(2).unwrap();
    wrong_effect_payload.extend_from_slice(&core);
    Encoder::new(&mut wrong_effect_payload)
        .bytes(object_hash(&wrong_effect_authorization).as_bytes())
        .unwrap();
    let wrong_effect_input = trust_digest_input("registryEvent", &wrong_effect_payload);
    assert!(
        VerificationContext::root_trust_digest(
            &wrong_effect_input,
            fixture_certificate_hash(),
            Some(&wrong_effect_authorization),
        )
        .is_err(),
        "deviceRevoke authorization must not approve a policy-activation registry change"
    );

    let grant = trust_digest_input("grantAuthorization", &grant_authorization_core());
    assert!(
        VerificationContext::root_trust_digest(
            &grant,
            fixture_certificate_hash(),
            Some(&authorization),
        )
        .is_err()
    );
}

#[test]
fn accepted_root_context_supports_only_hash_correlated_authorized_device_certificates() {
    let core = device_certificate_core();
    let authorized_input = trust_digest_input("deviceCertificate", &core);
    let authorization = organization_admin_authorization_object(
        "deviceCertificate",
        authorized_trust_digest(&authorized_input).as_bytes(),
    );
    let mut payload = Vec::new();
    Encoder::new(&mut payload).array(2).unwrap();
    payload.extend_from_slice(&core);
    Encoder::new(&mut payload)
        .bytes(object_hash(&authorization).as_bytes())
        .unwrap();
    let input = trust_digest_input("deviceCertificate", &payload);
    assert!(
        VerificationContext::root_trust_digest(
            &input,
            fixture_certificate_hash(),
            Some(&authorization),
        )
        .is_ok()
    );

    let wrong_authorization = organization_admin_authorization_object(
        "registryEvent",
        authorized_trust_digest(&trust_digest_input("registryEvent", &registry_event_core()))
            .as_bytes(),
    );
    assert!(
        VerificationContext::root_trust_digest(
            &input,
            fixture_certificate_hash(),
            Some(&wrong_authorization),
        )
        .is_err()
    );

    let wrong_action = organization_admin_authorization_object_with_action(
        4,
        "deviceCertificate",
        authorized_trust_digest(&authorized_input).as_bytes(),
    );
    let mut wrong_action_payload = Vec::new();
    Encoder::new(&mut wrong_action_payload).array(2).unwrap();
    wrong_action_payload.extend_from_slice(&core);
    Encoder::new(&mut wrong_action_payload)
        .bytes(object_hash(&wrong_action).as_bytes())
        .unwrap();
    let wrong_action_input = trust_digest_input("deviceCertificate", &wrong_action_payload);
    assert!(
        VerificationContext::root_trust_digest(
            &wrong_action_input,
            fixture_certificate_hash(),
            Some(&wrong_action),
        )
        .is_err()
    );
}

#[test]
fn device_approve_accepts_writer_and_rejects_organization_admin_certificate() {
    for (kind, accepted) in [(0, true), (2, false)] {
        let (input, authorization) = root_authorized_device_certificate_input(kind, 0);
        let result = VerificationContext::root_trust_digest(
            &input,
            fixture_certificate_hash(),
            Some(&authorization),
        );
        if accepted {
            assert!(
                result.is_ok(),
                "deviceApprove must accept a Writer certificate"
            );
        } else {
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("deviceApprove accepted an OrganizationAdmin certificate"),
            };
            assert_eq!(
                error.code(),
                "EA-CRYPTO-INVALID-PROTOCOL-CORE",
                "deviceApprove must reject an OrganizationAdmin certificate",
            );
        }
    }
}

#[test]
fn admin_key_change_accepts_organization_admin_and_rejects_writer_certificate() {
    for (kind, accepted) in [(2, true), (0, false)] {
        let (input, authorization) = root_authorized_device_certificate_input(kind, 5);
        let result = VerificationContext::root_trust_digest(
            &input,
            fixture_certificate_hash(),
            Some(&authorization),
        );
        if accepted {
            assert!(
                result.is_ok(),
                "adminKeyChange must accept an OrganizationAdmin certificate"
            );
        } else {
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("adminKeyChange accepted a Writer certificate"),
            };
            assert_eq!(
                error.code(),
                "EA-CRYPTO-INVALID-PROTOCOL-CORE",
                "adminKeyChange must reject a Writer certificate",
            );
        }
    }
}

#[test]
fn accepted_root_context_parses_each_authorized_sequence_bearing_subtype() {
    for (subtype, core) in [
        ("operatorBinding", operator_binding_core()),
        ("policy", policy_core()),
        ("writerTransition", writer_transition_core()),
    ] {
        let authorized_input = trust_digest_input(subtype, &core);
        let authorization = organization_admin_authorization_object(
            subtype,
            authorized_trust_digest(&authorized_input).as_bytes(),
        );
        let mut payload = Vec::new();
        Encoder::new(&mut payload).array(2).unwrap();
        payload.extend_from_slice(&core);
        Encoder::new(&mut payload)
            .bytes(object_hash(&authorization).as_bytes())
            .unwrap();
        let input = trust_digest_input(subtype, &payload);
        assert!(
            VerificationContext::root_trust_digest(
                &input,
                fixture_certificate_hash(),
                Some(&authorization),
            )
            .is_ok(),
            "valid root subtype {subtype}"
        );
    }
}

#[test]
fn root_rotation_binds_declared_predecessor_to_signing_certificate_hash() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let signing_certificate_hash = fixture_certificate_hash();

    for (previous_root_certificate_hash, accepted) in [
        (signing_certificate_hash, true),
        (
            CertificateHash::from(object_hash(b"unrelated previous root certificate")),
            false,
        ),
    ] {
        let core = root_rotation_core(previous_root_certificate_hash);
        let authorized_input = trust_digest_input("rootCertificate", &core);
        let authorization = organization_admin_authorization_object(
            "rootCertificate",
            authorized_trust_digest(&authorized_input).as_bytes(),
        );
        let mut payload = Vec::new();
        Encoder::new(&mut payload).array(2).unwrap();
        payload.extend_from_slice(&core);
        Encoder::new(&mut payload)
            .bytes(object_hash(&authorization).as_bytes())
            .unwrap();
        let input = trust_digest_input("rootCertificate", &payload);

        assert_eq!(
            signer
                .sign_root_trust_digest(signing_certificate_hash, &input, Some(&authorization),)
                .is_ok(),
            accepted,
            "signing must bind the declared predecessor to the protected certificate hash",
        );
        assert_eq!(
            VerificationContext::root_trust_digest(
                &input,
                signing_certificate_hash,
                Some(&authorization),
            )
            .is_ok(),
            accepted,
            "verification must bind the declared predecessor to the protected certificate hash",
        );
    }
}

#[test]
fn trust_signing_paths_derive_their_exact_subtype_payloads() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let certificate_hash = fixture_certificate_hash();
    let grant = trust_digest_input("grantAuthorization", &grant_authorization_core());
    let device = trust_digest_input("deviceCertificate", &device_certificate_core());
    assert!(
        signer
            .sign_historical_grant_approval_digest(certificate_hash, &grant)
            .is_ok()
    );
    assert!(
        signer
            .sign_historical_grant_approval_digest(certificate_hash, &device)
            .is_err()
    );

    let destruction = trust_digest_input(
        "destructionAuthorization",
        &destruction_authorization_core(),
    );
    assert!(
        signer
            .sign_destruction_approval_digest(certificate_hash, &destruction)
            .is_ok()
    );
    assert!(
        signer
            .sign_destruction_approval_digest(certificate_hash, &grant)
            .is_err()
    );
}

#[test]
fn remaining_trust_signing_paths_bind_embedded_and_referenced_objects() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let certificate_hash = fixture_certificate_hash();
    let admin = trust_digest_input(
        "organizationAdminAuthorization",
        &organization_admin_authorization_core(),
    );
    assert!(signer.sign_organization_admin_trust_digest(&admin).is_ok());
    let grant = trust_digest_input("grantAuthorization", &grant_authorization_core());
    assert!(signer.sign_organization_admin_trust_digest(&grant).is_err());

    let authorization_object = destruction_authorization_object();
    let authorization_hash = *object_hash(&authorization_object).as_bytes();
    let deletion = trust_digest_input(
        "deletionAttestation",
        &deletion_attestation_core(&authorization_hash),
    );
    assert!(
        signer
            .sign_deletion_attestation_digest(certificate_hash, &deletion, &authorization_object,)
            .is_ok()
    );
    assert!(
        signer
            .sign_deletion_attestation_digest(certificate_hash, &grant, &authorization_object)
            .is_err()
    );

    let registry_core = registry_event_core();
    let authorized_input = trust_digest_input("registryEvent", &registry_core);
    let authorization = organization_admin_authorization_object(
        "registryEvent",
        authorized_trust_digest(&authorized_input).as_bytes(),
    );
    let mut payload = Vec::new();
    Encoder::new(&mut payload).array(2).unwrap();
    payload.extend_from_slice(&registry_core);
    Encoder::new(&mut payload)
        .bytes(object_hash(&authorization).as_bytes())
        .unwrap();
    let registry = trust_digest_input("registryEvent", &payload);
    assert!(
        signer
            .sign_root_trust_digest(certificate_hash, &registry, Some(&authorization))
            .is_ok()
    );
    assert!(
        signer
            .sign_root_trust_digest(certificate_hash, &grant, Some(&authorization))
            .is_err()
    );
}

#[test]
fn certificate_kind_key_and_thumbprint_matrix_is_enforced() {
    let signing = fixture_public_key();
    let kem = x25519_fixture_public_key();
    let matrix = [
        (0_u8, true, false),
        (1, true, true),
        (2, true, false),
        (3, true, false),
        (4, false, true),
        (5, true, false),
        (6, true, false),
        (7, true, false),
    ];
    for (kind, has_signing, has_kem) in matrix {
        let valid = device_certificate_bytes_with_keys(
            kind,
            if has_signing {
                OptionalKey::Value(&signing)
            } else {
                OptionalKey::Null
            },
            if has_kem {
                OptionalKey::Value(&kem)
            } else {
                OptionalKey::Null
            },
            false,
            false,
            valid_authority_subject_field(kind),
        );
        assert!(
            ea_crypto::validate_signer_certificate(&valid).is_ok(),
            "valid kind {kind}"
        );

        let crossed = device_certificate_bytes_with_keys(
            kind,
            if has_signing {
                OptionalKey::Null
            } else {
                OptionalKey::Value(&signing)
            },
            if has_kem {
                OptionalKey::Null
            } else {
                OptionalKey::Value(&kem)
            },
            false,
            false,
            valid_authority_subject_field(kind),
        );
        assert!(
            ea_crypto::validate_signer_certificate(&crossed).is_err(),
            "crossed kind {kind}"
        );
    }

    for (corrupt_signing, corrupt_kem) in [(true, false), (false, true)] {
        let mismatch = device_certificate_bytes_with_keys(
            1,
            OptionalKey::Value(&signing),
            OptionalKey::Value(&kem),
            corrupt_signing,
            corrupt_kem,
            AuthoritySubjectField::Null,
        );
        assert!(ea_crypto::validate_signer_certificate(&mismatch).is_err());
    }

    let legacy_length = device_certificate_bytes_with_keys(
        0,
        OptionalKey::Value(&signing),
        OptionalKey::Null,
        false,
        false,
        AuthoritySubjectField::Omitted,
    );
    assert_eq!(
        ea_crypto::validate_signer_certificate(&legacy_length)
            .unwrap_err()
            .code(),
        "EA-TRUST-SIGNER-MISMATCH"
    );

    for (kind, authority_subject) in [
        (2, AuthoritySubjectField::Null),
        (
            0,
            AuthoritySubjectField::Value(fixture_authority_subject(0x7f)),
        ),
    ] {
        let invalid = device_certificate_bytes_with_keys(
            kind,
            OptionalKey::Value(&signing),
            OptionalKey::Null,
            false,
            false,
            authority_subject,
        );
        assert_eq!(
            ea_crypto::validate_signer_certificate(&invalid)
                .unwrap_err()
                .code(),
            "EA-TRUST-SIGNER-MISMATCH",
            "authoritySubjectId nullability for kind {kind}"
        );
    }
}

#[test]
fn initial_and_rotated_root_previous_hash_forms_cannot_be_crossed() {
    assert!(ea_crypto::validate_signer_certificate(&root_certificate_bytes(false, false)).is_ok());
    assert!(ea_crypto::validate_signer_certificate(&root_certificate_bytes(true, true)).is_ok());
    assert!(ea_crypto::validate_signer_certificate(&root_certificate_bytes(false, true)).is_err());
    assert!(ea_crypto::validate_signer_certificate(&root_certificate_bytes(true, false)).is_err());
}

#[test]
fn initial_root_and_enrollment_pop_never_enter_the_certificate_resolver() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let root = signer.sign_initial_root(&[0x55; 32]).unwrap();
    let enrollment = signer
        .sign_enrollment(&hex::decode(REGISTRATION_CORE_HEX).unwrap())
        .unwrap();
    let resolver = base_resolver();
    for (bytes, _content_type) in [
        (root.as_slice(), ContentType::TrustDigest),
        (
            enrollment.as_slice(),
            ContentType::DeviceRegistrationRequestCbor,
        ),
    ] {
        let error = verify_cose_sign1(bytes, &resolver, &verification_context()).unwrap_err();
        assert_eq!(error.code(), "EA-CRYPTO-INVALID-COSE");
    }
    assert_eq!(resolver.calls.get(), 0);
}

#[test]
fn direct_initial_admin_trust_signatures_use_only_the_root_bootstrap_context() {
    let exact_root_certificate = root_certificate_bytes(false, false);
    let root_certificate_hash = CertificateHash::from(object_hash(&exact_root_certificate));
    let resolver = BootstrapRootResolver {
        requested_hash: root_certificate_hash,
        exact_certificate_bytes: exact_root_certificate,
        calls: Cell::new(0),
    };
    let root_signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let direct_device =
        trust_digest_input("deviceCertificate", &device_certificate_core_with_kind(2));
    let direct_binding = trust_digest_input(
        "operatorBinding",
        &initial_admin_operator_binding_core(2, 0, None),
    );

    for (label, input) in [
        ("direct Admin certificate", direct_device.as_slice()),
        ("direct Admin Binding", direct_binding.as_slice()),
    ] {
        let signed = root_signer
            .sign_initial_admin_trust_digest(root_certificate_hash, input)
            .unwrap_or_else(|error| panic!("{label} signing failed: {}", error.code()));
        let parsed = ea_crypto::parse_cose_sign1(&signed, &[]).unwrap();
        assert_eq!(parsed.content_type(), ContentType::TrustDigest, "{label}");
        assert!(
            parsed.certificate_hash() == Some(root_certificate_hash),
            "{label}"
        );
        let context = VerificationContext::initial_admin_trust_digest(input, root_certificate_hash)
            .unwrap_or_else(|error| panic!("{label} context failed: {}", error.code()));
        let verified = CoseVerifier::verify_normal(&signed, &resolver, &context)
            .unwrap_or_else(|error| panic!("{label} verification failed: {}", error.code()));
        assert_eq!(verified.role(), SignerRole::Root, "{label}");
    }
    assert_eq!(resolver.calls.get(), 2);

    let authorized_device = trust_digest_input(
        "deviceCertificate",
        &authorized_wrapper(&device_certificate_core_with_kind(2)),
    );
    let invalid_inputs = [
        (
            "non-Admin direct certificate",
            trust_digest_input("deviceCertificate", &device_certificate_core_with_kind(0)),
        ),
        (
            "non-Admin direct Binding",
            trust_digest_input(
                "operatorBinding",
                &initial_admin_operator_binding_core(0, 0, None),
            ),
        ),
        (
            "Admin certificate revoked at its effective sequence",
            trust_digest_input(
                "deviceCertificate",
                &device_certificate_core_with_activation(2, 0, Some(0)),
            ),
        ),
        (
            "Admin certificate revoked before its effective sequence",
            trust_digest_input(
                "deviceCertificate",
                &device_certificate_core_with_activation(2, 1, Some(0)),
            ),
        ),
        (
            "Admin Binding revoked at its effective sequence",
            trust_digest_input(
                "operatorBinding",
                &initial_admin_operator_binding_core(2, 0, Some(0)),
            ),
        ),
        (
            "Admin Binding revoked before its effective sequence",
            trust_digest_input(
                "operatorBinding",
                &initial_admin_operator_binding_core(2, 1, Some(0)),
            ),
        ),
        ("authorized wrapper", authorized_device),
        (
            "wrong subtype",
            trust_digest_input("policy", &device_certificate_core_with_kind(2)),
        ),
    ];
    for (label, input) in invalid_inputs {
        let sign_error =
            match root_signer.sign_initial_admin_trust_digest(root_certificate_hash, &input) {
                Ok(_) => panic!("{label}"),
                Err(error) => error,
            };
        assert_eq!(
            sign_error.code(),
            "EA-CRYPTO-INVALID-PROTOCOL-CORE",
            "{label}"
        );
        let context_error =
            match VerificationContext::initial_admin_trust_digest(&input, root_certificate_hash) {
                Ok(_) => panic!("{label}"),
                Err(error) => error,
            };
        assert_eq!(
            context_error.code(),
            "EA-CRYPTO-INVALID-PROTOCOL-CORE",
            "{label}"
        );
    }

    let device_signature = root_signer
        .sign_initial_admin_trust_digest(root_certificate_hash, &direct_device)
        .unwrap();
    let binding_context =
        VerificationContext::initial_admin_trust_digest(&direct_binding, root_certificate_hash)
            .unwrap();
    assert_eq!(
        CoseVerifier::verify_normal(&device_signature, &resolver, &binding_context)
            .unwrap_err()
            .code(),
        "EA-TRUST-SIGNER-MISMATCH"
    );

    let different_root_certificate_hash = CertificateHash::from(object_hash(b"another Root"));
    let wrong_hash_context = VerificationContext::initial_admin_trust_digest(
        &direct_device,
        different_root_certificate_hash,
    )
    .unwrap();
    assert_eq!(
        CoseVerifier::verify_normal(&device_signature, &resolver, &wrong_hash_context)
            .unwrap_err()
            .code(),
        "EA-TRUST-SIGNER-MISMATCH"
    );

    let mut mutated_signature = device_signature;
    *mutated_signature
        .last_mut()
        .expect("COSE fixture contains a signature") ^= 1;
    let correct_context =
        VerificationContext::initial_admin_trust_digest(&direct_device, root_certificate_hash)
            .unwrap();
    assert_eq!(
        CoseVerifier::verify_normal(&mutated_signature, &resolver, &correct_context)
            .unwrap_err()
            .code(),
        "EA-TRUST-SIGNATURE-INVALID"
    );
}

#[test]
fn wrong_bound_registry_is_unresolved_not_silently_substituted() {
    let manifest = signed_manifest(
        fixture_certificate_hash(),
        fixture_organization(),
        RegistryVersion::new(4),
        0x41,
    );
    let context = VerificationContext::record(&manifest).unwrap();
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let signed = signer.sign_record(&manifest).unwrap();
    assert_eq!(
        verify_cose_sign1(&signed, &base_resolver(), &context)
            .unwrap_err()
            .code(),
        "EA-TRUST-SIGNER-UNRESOLVED"
    );
}

#[test]
fn exact_os_account_kats_and_context_hashes_are_pinned() {
    let windows_sid =
        hex::decode("010500000000000515000000010000000200000003000000e8030000").unwrap();
    let organization =
        OrganizationId::try_from(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()[..])
            .unwrap();
    let device =
        ea_types::DeviceId::try_from(&hex::decode("202122232425262728292a2b2c2d2e2f").unwrap()[..])
            .unwrap();
    assert_eq!(
        hex::encode(
            windows_os_account_binding_hash(
                organization,
                device,
                &windows_sid,
                [0, 0, 0, 0, 0, 5],
                &[21, 1, 2, 3, 1000],
            )
            .unwrap()
            .as_bytes()
        ),
        "fcbb2ccb141966c57146aa6e578f56550bf86670ee9b31dea90f5a99b9f26220"
    );
    assert_eq!(
        hex::encode(
            macos_os_account_binding_hash(
                organization,
                device,
                &["f81d4fae-7dec-11d0-a765-00a0c91e6bf6"],
                &["501"],
                501,
            )
            .unwrap()
            .as_bytes()
        ),
        "0f4ed54a0330ed2bdbb5228d192d4dfa3a0853dae98aba3091f0c7c5f29fde7a"
    );
    assert_eq!(
        hex::encode(
            linux_os_account_binding_hash(
                organization,
                device,
                b"0123456789abcdef0123456789abcdef\n",
                1000,
            )
            .unwrap()
            .as_bytes()
        ),
        "bbca2d7b508415aed456efd6fc5499ddda65759250f6c8b5a1c2edd23a7883e4"
    );

    let mut changed_sid = windows_sid;
    changed_sid[8] ^= 1;
    assert_ne!(
        windows_os_account_binding_hash(
            organization,
            device,
            &changed_sid,
            [0, 0, 0, 0, 0, 5],
            &[20, 1, 2, 3, 1000],
        )
        .unwrap()
        .as_bytes(),
        windows_os_account_binding_hash(
            organization,
            device,
            &hex::decode("010500000000000515000000010000000200000003000000e8030000").unwrap(),
            [0, 0, 0, 0, 0, 5],
            &[21, 1, 2, 3, 1000],
        )
        .unwrap()
        .as_bytes()
    );
}

#[test]
fn os_account_sources_fail_closed_before_hashing() {
    let organization = fixture_organization();
    let device = ea_types::DeviceId::try_from([0x22; 16].as_slice()).unwrap();
    assert!(
        windows_os_account_binding_hash(
            organization,
            device,
            b"S-1-5-21-1-2-3-1000",
            [0, 0, 0, 0, 0, 5],
            &[21, 1, 2, 3, 1000],
        )
        .is_err()
    );
    let valid_sid =
        hex::decode("010500000000000515000000010000000200000003000000e8030000").unwrap();
    for invalid in [
        [&[0, 5][..], &valid_sid[2..]].concat(),
        [&[2, 5][..], &valid_sid[2..]].concat(),
        [&[1, 0][..], &valid_sid[2..]].concat(),
        [&[1, 16][..], &valid_sid[2..]].concat(),
        valid_sid[..valid_sid.len() - 1].to_vec(),
        [valid_sid.as_slice(), &[0][..]].concat(),
    ] {
        assert!(
            windows_os_account_binding_hash(
                organization,
                device,
                &invalid,
                [0, 0, 0, 0, 0, 5],
                &[21, 1, 2, 3, 1000],
            )
            .is_err()
        );
    }
    let mut big_endian_sid =
        hex::decode("010500000000000500000015000000010000000200000003000003e8").unwrap();
    assert!(
        windows_os_account_binding_hash(
            organization,
            device,
            &big_endian_sid,
            [0, 0, 0, 0, 0, 5],
            &[21, 1, 2, 3, 1000],
        )
        .is_err()
    );
    big_endian_sid.push(0);
    assert!(
        windows_os_account_binding_hash(
            organization,
            device,
            &big_endian_sid,
            [0, 0, 0, 0, 0, 5],
            &[21, 1, 2, 3, 1000],
        )
        .is_err()
    );

    for guid in [
        "",
        "00000000-0000-0000-0000-000000000000",
        "{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}",
        "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        "f81d4fae7dec11d0a76500a0c91e6bf6",
        "f81d4fag-7dec-11d0-a765-00a0c91e6bf6",
    ] {
        assert!(
            macos_os_account_binding_hash(organization, device, &[guid], &["501"], 501).is_err()
        );
    }
    for (guids, unique_ids, actual_uid) in [
        (vec![], vec!["501"], 501),
        (
            vec![
                "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            ],
            vec!["501"],
            501,
        ),
        (vec!["f81d4fae-7dec-11d0-a765-00a0c91e6bf6"], vec![], 501),
        (
            vec!["f81d4fae-7dec-11d0-a765-00a0c91e6bf6"],
            vec!["0501"],
            501,
        ),
        (
            vec!["f81d4fae-7dec-11d0-a765-00a0c91e6bf6"],
            vec!["501"],
            502,
        ),
    ] {
        assert!(
            macos_os_account_binding_hash(organization, device, &guids, &unique_ids, actual_uid,)
                .is_err()
        );
    }
    assert!(
        macos_os_account_binding_hash(
            organization,
            device,
            &["f81d4fae-7dec-11d0-a765-00a0c91e6bf6"],
            &["4294967295"],
            u32::MAX,
        )
        .is_err()
    );

    for source in [
        b"".as_slice(),
        b"0123456789ABCDEF0123456789ABCDEF\n".as_slice(),
        b"00000000000000000000000000000000\n".as_slice(),
        b"uninitialized\n".as_slice(),
        b"0123456789abcdef0123456789abcdef".as_slice(),
        b"0123456789abcdef0123456789abcdef\r\n".as_slice(),
    ] {
        assert!(linux_os_account_binding_hash(organization, device, source, 1000).is_err());
    }
    assert!(
        linux_os_account_binding_hash(
            organization,
            device,
            b"0123456789abcdef0123456789abcdef\n",
            u32::MAX
        )
        .is_err()
    );
}

#[test]
fn rfc9679_okp_thumbprint_uses_only_required_public_parameters() {
    let key = CanonicalPublicCoseKey::ed25519(
        hex::decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(key.to_deterministic_cbor()),
        "a30101200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    );
    assert_eq!(
        hex::encode(key.thumbprint().as_bytes()),
        "be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f49"
    );
}

#[test]
fn rfc8032_ed25519_vector_signs_and_verifies_strictly() {
    let seed: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
    let seed = Zeroizing::new(seed);
    let expected_public: [u8; 32] =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_signature: [u8; 64] = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )
    .unwrap()
    .try_into()
    .unwrap();

    let signing = SigningKey::from_bytes(&seed);
    assert_eq!(signing.verifying_key().as_bytes(), &expected_public);
    assert_eq!(signing.sign(b"").to_bytes(), expected_signature);

    let public = CanonicalPublicCoseKey::ed25519(expected_public).unwrap();
    public
        .verify_ed25519_strict(b"", &expected_signature)
        .unwrap();
    for index in 0..expected_signature.len() {
        let mut mutation = expected_signature;
        mutation[index] ^= 1;
        assert!(public.verify_ed25519_strict(b"", &mutation).is_err());
    }
    assert!(
        public
            .verify_ed25519_strict(b"changed", &expected_signature)
            .is_err()
    );
}

#[test]
fn rfc9679_published_p256_and_local_suite_okp_thumbprints_are_exact() {
    let published_p256_required_key = hex::decode(
        "a40102200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c",
    )
    .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&published_p256_required_key)),
        "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec"
    );

    let x25519 = CanonicalPublicCoseKey::x25519(
        hex::decode("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(x25519.to_deterministic_cbor()),
        "a3010120042158204310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"
    );
    assert_eq!(
        hex::encode(x25519.thumbprint().as_bytes()),
        "4c3144bb6e6af74b3c180f0a80c621a08eb820917e04515c7bcd5827a5331013"
    );
    assert_eq!(
        CanonicalPublicCoseKey::from_deterministic_cbor(&x25519.to_deterministic_cbor())
            .unwrap()
            .to_deterministic_cbor(),
        x25519.to_deterministic_cbor()
    );
}
