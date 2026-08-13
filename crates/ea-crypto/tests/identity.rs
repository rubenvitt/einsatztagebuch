use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, CoseSigner, CoseVerifier, CryptoError, ResolvedSigner,
    SecretBytes, SignerCertificateResolver, SignerRole, VerificationContext,
    linux_os_account_binding_hash, macos_os_account_binding_hash, object_hash, verify_cose_sign1,
    windows_os_account_binding_hash,
};
use ea_types::{CertificateHash, ChainSequence, OrganizationId, RegistryVersion};
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

fn fixture_certificate_hash() -> CertificateHash {
    CertificateHash::from(object_hash(
        &device_certificate_bytes(&fixture_public_key()),
    ))
}

fn device_certificate_bytes(public_key: &CanonicalPublicCoseKey) -> Vec<u8> {
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
        .and_then(|encoder| encoder.array(13))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fixture_organization().as_bytes()))
        .and_then(|encoder| encoder.bytes(&[0x22; 16]))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.bytes(&public_key_bytes))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.bytes(thumbprint.as_bytes()))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.bytes(&[0x33; 32]))
        .and_then(|encoder| encoder.array(1))
        .unwrap();
    certificate.extend_from_slice(&root_signature);
    certificate
}

fn base_resolver() -> FixtureResolver {
    let exact_certificate_bytes = device_certificate_bytes(&fixture_public_key());
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
