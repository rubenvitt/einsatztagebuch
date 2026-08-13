use ea_crypto::{
    CanonicalOsAccountId, CanonicalPublicCoseKey, ContentType, CoseSigner, CoseVerifier,
    CryptoError, ExpectedSigner, ResolvedSigner, SecretBytes, SignerCapability,
    SignerCertificateResolver, SignerRole, VerificationContext, object_hash,
    os_account_binding_hash, verify_cose_sign1,
};
use ea_types::{CertificateHash, ChainSequence, OrganizationId, RegistryVersion};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use zeroize::Zeroizing;

const CERTIFICATE_BYTES: &[u8] = b"EA-LOCAL-KAT-v1 writer certificate exact bytes";
const REGISTRATION_CORE_HEX: &str = "890150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f005828a30101200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8f68101817545494e5341545a4152434849562d53554954452d3180";

struct FixtureResolver {
    requested_hash: CertificateHash,
    exact_certificate_bytes: Vec<u8>,
    resolved_hash: CertificateHash,
    public_key: CanonicalPublicCoseKey,
    role: SignerRole,
    organization_id: OrganizationId,
    effective_from_sequence: ChainSequence,
    revoked_from_sequence: Option<ChainSequence>,
    capabilities: Vec<SignerCapability>,
    revoked: bool,
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
            certificate_hash: self.resolved_hash,
            public_key: &self.public_key,
            role: self.role,
            organization_id: self.organization_id,
            effective_from_sequence: self.effective_from_sequence,
            revoked_from_sequence: self.revoked_from_sequence,
            capabilities: &self.capabilities,
            revoked: self.revoked,
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

fn other_public_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(
        hex::decode("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
}

fn fixture_certificate_hash() -> CertificateHash {
    CertificateHash::from(object_hash(CERTIFICATE_BYTES))
}

fn base_resolver() -> FixtureResolver {
    FixtureResolver {
        requested_hash: fixture_certificate_hash(),
        exact_certificate_bytes: CERTIFICATE_BYTES.to_vec(),
        resolved_hash: fixture_certificate_hash(),
        public_key: fixture_public_key(),
        role: SignerRole::Writer,
        organization_id: fixture_organization(),
        effective_from_sequence: ChainSequence::new(1),
        revoked_from_sequence: None,
        capabilities: vec![SignerCapability::EntryWrite],
        revoked: false,
        result_error: None,
        calls: Cell::new(0),
    }
}

fn verification_context(content_type: ContentType) -> VerificationContext {
    VerificationContext::digest(
        content_type,
        ExpectedSigner {
            organization_id: fixture_organization(),
            sequence: ChainSequence::new(7),
            role: SignerRole::Writer,
            capability: SignerCapability::EntryWrite,
        },
        RegistryVersion::new(3),
    )
}

#[test]
fn normal_verification_returns_the_one_atomically_bound_identity() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let signed = signer
        .sign_normal(
            ContentType::RecordDigest,
            fixture_certificate_hash(),
            &[0x41; 32],
        )
        .unwrap();
    let resolver = base_resolver();
    let verified = verify_cose_sign1(
        &signed,
        &resolver,
        &verification_context(ContentType::RecordDigest),
    )
    .unwrap();
    let verifier_resolver = base_resolver();
    CoseVerifier::verify_normal(
        &signed,
        &verifier_resolver,
        &verification_context(ContentType::RecordDigest),
    )
    .unwrap();
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
    let signed = signer
        .sign_normal(
            ContentType::RecordDigest,
            fixture_certificate_hash(),
            &[0x41; 32],
        )
        .unwrap();

    for (case, expected_code) in [
        ("certificate-bytes", "EA-TRUST-SIGNER-MISMATCH"),
        ("certificate-hash", "EA-TRUST-SIGNER-MISMATCH"),
        ("key-thumbprint", "EA-TRUST-SIGNER-MISMATCH"),
        ("organization", "EA-TRUST-SIGNER-UNAUTHORIZED"),
        ("role", "EA-TRUST-SIGNER-UNAUTHORIZED"),
        ("capability", "EA-TRUST-SIGNER-UNAUTHORIZED"),
        ("not-effective", "EA-TRUST-SIGNER-UNAUTHORIZED"),
        ("revoked-at-sequence", "EA-TRUST-SIGNER-UNAUTHORIZED"),
        ("revoked", "EA-TRUST-SIGNER-UNAUTHORIZED"),
        ("ambiguous", "EA-TRUST-SIGNER-UNRESOLVED"),
    ] {
        let mut resolver = base_resolver();
        match case {
            "certificate-bytes" => resolver.exact_certificate_bytes.push(0),
            "certificate-hash" => {
                resolver.resolved_hash = CertificateHash::from(object_hash(b"another certificate"));
            }
            "key-thumbprint" => resolver.public_key = other_public_key(),
            "organization" => {
                resolver.organization_id = OrganizationId::try_from([0x22; 16].as_slice()).unwrap();
            }
            "role" => resolver.role = SignerRole::Reader,
            "capability" => resolver.capabilities.clear(),
            "not-effective" => resolver.effective_from_sequence = ChainSequence::new(8),
            "revoked-at-sequence" => {
                resolver.revoked_from_sequence = Some(ChainSequence::new(7));
            }
            "revoked" => resolver.revoked = true,
            "ambiguous" => resolver.result_error = Some(CryptoError::SignerUnresolved),
            _ => unreachable!(),
        }
        let error = verify_cose_sign1(
            &signed,
            &resolver,
            &verification_context(ContentType::RecordDigest),
        )
        .unwrap_err();
        assert_eq!(error.code(), expected_code, "case {case}");
        assert_eq!(resolver.calls.get(), 1, "case {case}");
    }
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
    for (bytes, content_type) in [
        (root.as_slice(), ContentType::TrustDigest),
        (
            enrollment.as_slice(),
            ContentType::DeviceRegistrationRequestCbor,
        ),
    ] {
        let error =
            verify_cose_sign1(bytes, &resolver, &verification_context(content_type)).unwrap_err();
        assert_eq!(error.code(), "EA-CRYPTO-INVALID-COSE");
    }
    assert_eq!(resolver.calls.get(), 0);
}

#[test]
fn wrong_bound_registry_is_unresolved_not_silently_substituted() {
    let expected = ExpectedSigner {
        organization_id: fixture_organization(),
        sequence: ChainSequence::new(7),
        role: SignerRole::Writer,
        capability: SignerCapability::EntryWrite,
    };
    let context =
        VerificationContext::digest(ContentType::RecordDigest, expected, RegistryVersion::new(4));
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let signed = signer
        .sign_normal(
            ContentType::RecordDigest,
            fixture_certificate_hash(),
            &[0x41; 32],
        )
        .unwrap();
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
    let windows = CanonicalOsAccountId::windows_sid_source(
        &windows_sid,
        [0, 0, 0, 0, 0, 5],
        &[21, 1, 2, 3, 1000],
    )
    .unwrap();
    let macos = CanonicalOsAccountId::macos_open_directory(
        &["f81d4fae-7dec-11d0-a765-00a0c91e6bf6"],
        &["501"],
        501,
    )
    .unwrap();
    let linux =
        CanonicalOsAccountId::linux_machine_id_file(b"0123456789abcdef0123456789abcdef\n", 1000)
            .unwrap();

    let organization =
        OrganizationId::try_from(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()[..])
            .unwrap();
    let device =
        ea_types::DeviceId::try_from(&hex::decode("202122232425262728292a2b2c2d2e2f").unwrap()[..])
            .unwrap();
    let cases = [
        (
            windows,
            "830100581c010500000000000515000000010000000200000003000000e8030000",
            "8350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f830100581c010500000000000515000000010000000200000003000000e8030000",
            "45494e5341545a4152434849562d4f532d4143434f554e542d76318350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f830100581c010500000000000515000000010000000200000003000000e8030000",
            "fcbb2ccb141966c57146aa6e578f56550bf86670ee9b31dea90f5a99b9f26220",
        ),
        (
            macos,
            "84010150f81d4fae7dec11d0a76500a0c91e6bf61901f5",
            "8350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f84010150f81d4fae7dec11d0a76500a0c91e6bf61901f5",
            "45494e5341545a4152434849562d4f532d4143434f554e542d76318350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f84010150f81d4fae7dec11d0a76500a0c91e6bf61901f5",
            "0f4ed54a0330ed2bdbb5228d192d4dfa3a0853dae98aba3091f0c7c5f29fde7a",
        ),
        (
            linux,
            "840102500123456789abcdef0123456789abcdef1903e8",
            "8350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f840102500123456789abcdef0123456789abcdef1903e8",
            "45494e5341545a4152434849562d4f532d4143434f554e542d76318350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f840102500123456789abcdef0123456789abcdef1903e8",
            "bbca2d7b508415aed456efd6fc5499ddda65759250f6c8b5a1c2edd23a7883e4",
        ),
    ];
    for (account, account_hex, context_hex, preimage_hex, digest_hex) in cases {
        let account_bytes = account.to_deterministic_cbor();
        assert_eq!(hex::encode(&account_bytes), account_hex);
        let decoded = CanonicalOsAccountId::from_deterministic_cbor(&account_bytes).unwrap();
        assert_eq!(decoded.to_deterministic_cbor(), account_bytes);

        let context = hex::decode(context_hex).unwrap();
        assert_eq!(
            context,
            [
                &[0x83, 0x50][..],
                organization.as_bytes(),
                &[0x50][..],
                device.as_bytes(),
                account_bytes.as_slice(),
            ]
            .concat()
        );
        assert_eq!(
            hex::decode(preimage_hex).unwrap(),
            [
                b"EINSATZARCHIV-OS-ACCOUNT-v1".as_slice(),
                context.as_slice()
            ]
            .concat()
        );
        assert_eq!(
            hex::encode(os_account_binding_hash(organization, device, &account).as_bytes()),
            digest_hex
        );

        let mut changed_identifier = account_bytes;
        changed_identifier[8] ^= 1;
        if let Ok(changed) = CanonicalOsAccountId::from_deterministic_cbor(&changed_identifier) {
            assert_ne!(
                os_account_binding_hash(organization, device, &changed).as_bytes(),
                os_account_binding_hash(organization, device, &account).as_bytes()
            );
        }
    }
}

#[test]
fn os_account_sources_fail_closed_before_hashing() {
    assert!(CanonicalOsAccountId::windows_sid(b"S-1-5-21-1-2-3-1000").is_err());
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
        assert!(CanonicalOsAccountId::windows_sid(&invalid).is_err());
    }
    let mut big_endian_sid =
        hex::decode("010500000000000500000015000000010000000200000003000003e8").unwrap();
    assert!(
        CanonicalOsAccountId::windows_sid_source(
            &big_endian_sid,
            [0, 0, 0, 0, 0, 5],
            &[21, 1, 2, 3, 1000],
        )
        .is_err()
    );
    big_endian_sid.push(0);
    assert!(CanonicalOsAccountId::windows_sid(&big_endian_sid).is_err());

    for guid in [
        "",
        "00000000-0000-0000-0000-000000000000",
        "{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}",
        "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        "f81d4fae7dec11d0a76500a0c91e6bf6",
        "f81d4fag-7dec-11d0-a765-00a0c91e6bf6",
    ] {
        assert!(CanonicalOsAccountId::macos_guid(guid, 501).is_err());
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
            CanonicalOsAccountId::macos_open_directory(&guids, &unique_ids, actual_uid).is_err()
        );
    }
    assert!(
        CanonicalOsAccountId::macos_guid("f81d4fae-7dec-11d0-a765-00a0c91e6bf6", u32::MAX).is_err()
    );

    for source in [
        b"".as_slice(),
        b"0123456789ABCDEF0123456789ABCDEF\n".as_slice(),
        b"00000000000000000000000000000000\n".as_slice(),
        b"uninitialized\n".as_slice(),
        b"0123456789abcdef0123456789abcdef".as_slice(),
        b"0123456789abcdef0123456789abcdef\r\n".as_slice(),
    ] {
        assert!(CanonicalOsAccountId::linux_machine_id_file(source, 1000).is_err());
    }
    assert!(
        CanonicalOsAccountId::linux_machine_id_file(
            b"0123456789abcdef0123456789abcdef\n",
            u32::MAX
        )
        .is_err()
    );
}

#[test]
fn os_account_wire_decoder_is_exact_closed_and_uid_bounded() {
    for uid in [0, 23, 24, 255, 256, u32::MAX - 1] {
        let account = CanonicalOsAccountId::linux_machine_id([0x42; 16], uid).unwrap();
        let bytes = account.to_deterministic_cbor();
        assert_eq!(
            CanonicalOsAccountId::from_deterministic_cbor(&bytes)
                .unwrap()
                .to_deterministic_cbor(),
            bytes
        );
    }

    let invalid_hex = [
        "840102500123456789abcdef0123456789abcdef1affffffff",
        "840102500123456789abcdef0123456789abcdef6431303030",
        "840102500123456789abcdef0123456789abcdeff903e8",
        "840102500123456789abcdef0123456789abcdefc24903e8",
        "840102700123456789abcdef0123456789abcdef1903e8",
        "840102d8500123456789abcdef0123456789abcdef1903e8",
        "840102500123456789abcdef0123456789abcdef1903e800",
        "840002500123456789abcdef0123456789abcdef1903e8",
        "840103500123456789abcdef0123456789abcdef1903e8",
        "830102500123456789abcdef0123456789abcdef",
        "9f0102500123456789abcdef0123456789abcdef1903e8ff",
    ];
    for encoded in invalid_hex {
        assert!(
            CanonicalOsAccountId::from_deterministic_cbor(&hex::decode(encoded).unwrap()).is_err(),
            "invalid fixture {encoded}"
        );
    }
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
