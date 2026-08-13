use ea_crypto::{
    AEAD_NONCE_SIZE, AEAD_OVERHEAD, CEK_SIZE, CryptoRandomSource, HPKE_AEAD_ID,
    HPKE_ENCAPSULATED_KEY_SIZE, HPKE_KDF_ID, HPKE_KEM_ID, HPKE_MODE, HPKE_WRAPPED_CEK_SIZE,
    HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, SecretVec, aead_open, aead_seal,
    checked_ciphertext_length, hpke_open, hpke_seal, hpke_seal_with_random_source,
};
use hpke::rand_core::{Infallible, TryCryptoRng, TryRng};
use hpke::{
    Deserializable, Kem as _, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open, single_shot_seal_with_rng,
};
use zeroize::Zeroizing;

struct FixedSecretRng {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
}

impl FixedSecretRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            offset: 0,
        }
    }
}

impl TryRng for FixedSecretRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        hpke::rand_core::utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        hpke::rand_core::utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        let end = self
            .offset
            .checked_add(destination.len())
            .expect("fixed test-vector offset must fit usize");
        destination.copy_from_slice(
            self.bytes
                .get(self.offset..end)
                .expect("RFC 9180 fixture supplies exactly the requested entropy"),
        );
        self.offset = end;
        Ok(())
    }
}

impl TryCryptoRng for FixedSecretRng {}

impl CryptoRandomSource for FixedSecretRng {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), ea_crypto::CryptoError> {
        let end = self
            .offset
            .checked_add(destination.len())
            .ok_or(ea_crypto::CryptoError::SizeLimit)?;
        destination.copy_from_slice(
            self.bytes
                .get(self.offset..end)
                .ok_or(ea_crypto::CryptoError::SizeLimit)?,
        );
        self.offset = end;
        Ok(())
    }
}

struct FailingRandomSource;

impl CryptoRandomSource for FailingRandomSource {
    fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), ea_crypto::CryptoError> {
        Err(ea_crypto::CryptoError::LocalRng)
    }
}

#[test]
fn suite_sizes_and_checked_overflow_are_fixed() {
    assert_eq!((CEK_SIZE, AEAD_NONCE_SIZE, AEAD_OVERHEAD), (32, 12, 16));
    assert_eq!(
        (HPKE_MODE, HPKE_KEM_ID, HPKE_KDF_ID, HPKE_AEAD_ID),
        (0, 0x0020, 0x0001, 0x0003)
    );
    assert_eq!(
        (HPKE_ENCAPSULATED_KEY_SIZE, HPKE_WRAPPED_CEK_SIZE),
        (32, 48)
    );
    assert_eq!(checked_ciphertext_length(0).unwrap(), 16);
    assert!(checked_ciphertext_length(usize::MAX).is_err());
}

#[test]
fn rfc8439_chacha20_poly1305_vector_and_misuse_rejection() {
    let key: [u8; 32] =
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap()
            .try_into()
            .unwrap();
    let nonce: [u8; 12] = hex::decode("070000004041424344454647")
        .unwrap()
        .try_into()
        .unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let plaintext = hex::decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();
    let expected = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691";
    let ciphertext = aead_seal(
        &SecretBytes::new(key),
        &SecretBytes::new(nonce),
        SecretVec::new(plaintext.clone()),
        &aad,
    )
    .unwrap();
    assert_eq!(hex::encode(&ciphertext), expected);
    assert!(
        aead_open(
            &SecretBytes::new(key),
            &SecretBytes::new(nonce),
            &ciphertext,
            &aad
        )
        .unwrap()
        .matches(&plaintext)
    );
    let mut altered = ciphertext;
    altered[0] ^= 1;
    assert_eq!(
        aead_open(
            &SecretBytes::new(key),
            &SecretBytes::new(nonce),
            &altered,
            &aad
        )
        .err()
        .unwrap()
        .code(),
        "EA-CRYPTO-AEAD-OPEN"
    );
}

#[test]
fn hpke_base_round_trip_has_fixed_lengths_and_context_binding() {
    let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x42; 32])).unwrap();
    let public = recipient.public_key();
    let cek = SecretBytes::new([0x60; 32]);
    let sealed = hpke_seal(&public, &cek, b"info", b"aad").unwrap();
    assert_eq!(sealed.encapsulated_key().len(), 32);
    assert_eq!(sealed.wrapped_cek().len(), 48);
    assert!(
        hpke_open(&recipient, &sealed, b"info", b"aad")
            .unwrap()
            .matches(&[0x60; 32])
    );
    assert_eq!(
        hpke_open(&recipient, &sealed, b"other", b"aad")
            .err()
            .unwrap()
            .code(),
        "EA-CRYPTO-HPKE-OPEN"
    );
}

#[test]
fn rfc9180_appendix_a2_base_x25519_sha256_chacha_vector_is_exact() {
    type Kem = X25519HkdfSha256;
    type Kdf = HkdfSha256;
    type Aead = ChaCha20Poly1305;

    let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
    let ikm_recip = Zeroizing::new(
        hex::decode("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df").unwrap(),
    );
    let expected_sk =
        hex::decode("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb").unwrap();
    let expected_pk =
        hex::decode("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a").unwrap();
    let ikm_eph =
        hex::decode("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b").unwrap();
    let expected_enc =
        hex::decode("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a").unwrap();
    let aad = hex::decode("436f756e742d30").unwrap();
    let plaintext = Zeroizing::new(
        hex::decode("4265617574792069732074727574682c20747275746820626561757479").unwrap(),
    );
    let expected_ciphertext = hex::decode(
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
    )
    .unwrap();

    let (sk_recip, pk_recip) = Kem::derive_keypair(ikm_recip.as_slice());
    assert_eq!(sk_recip.to_bytes().as_slice(), expected_sk);
    assert_eq!(pk_recip.to_bytes().as_slice(), expected_pk);

    let mut rng = FixedSecretRng::new(ikm_eph);
    let (encapped, ciphertext) = single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk_recip,
        &info,
        plaintext.as_slice(),
        &aad,
        &mut rng,
    )
    .unwrap();
    assert_eq!(encapped.to_bytes().as_slice(), expected_enc);
    assert_eq!(ciphertext, expected_ciphertext);

    let recovered = single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk_recip,
        &<Kem as hpke::Kem>::EncappedKey::from_bytes(&expected_enc).unwrap(),
        &info,
        &expected_ciphertext,
        &aad,
    )
    .unwrap();
    assert_eq!(recovered, plaintext.as_slice());
}

#[test]
fn application_hpke_wrapper_matches_independently_calculated_exact_wire() {
    let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x42; 32])).unwrap();
    let info = hex::decode("45494e5341545a4152434849562d48504b452d494e464f2d76318101").unwrap();
    let aad = hex::decode("45494e5341545a4152434849562d48504b452d4141442d76318101").unwrap();
    let mut random = FixedSecretRng::new(vec![0x24; 32]);
    let sealed = hpke_seal_with_random_source(
        &recipient.public_key(),
        &SecretBytes::new([0x60; 32]),
        &info,
        &aad,
        &mut random,
    )
    .unwrap();

    assert_eq!(
        hex::encode(sealed.encapsulated_key()),
        "083f7859feb58bd62e43682c35a9936668e96c103e74e25530134e2dc6419758"
    );
    assert_eq!(
        hex::encode(sealed.wrapped_cek()),
        "4e62b6d7e5687cb98df9bd00ab0a1523b7b08b4135726cf24343d29c646ede252078a7a40a8c79d065ea59beb8a9353a"
    );
    assert!(
        hpke_open(&recipient, &sealed, &info, &aad)
            .unwrap()
            .matches(&[0x60; 32])
    );
}

#[test]
fn every_hpke_wire_or_context_mutation_fails_without_returning_a_cek() {
    let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x42; 32])).unwrap();
    let sealed = hpke_seal(
        &recipient.public_key(),
        &SecretBytes::new([0x60; 32]),
        b"bound info",
        b"bound aad",
    )
    .unwrap();

    for index in 0..HPKE_ENCAPSULATED_KEY_SIZE {
        let mut enc = *sealed.encapsulated_key();
        enc[index] ^= 1;
        if let Ok(mutated) = HpkeSealed::from_parts(enc, *sealed.wrapped_cek()) {
            assert_eq!(
                hpke_open(&recipient, &mutated, b"bound info", b"bound aad")
                    .err()
                    .unwrap()
                    .code(),
                "EA-CRYPTO-HPKE-OPEN"
            );
        }
    }
    for index in 0..HPKE_WRAPPED_CEK_SIZE {
        let mut ciphertext = *sealed.wrapped_cek();
        ciphertext[index] ^= 1;
        let mutated = HpkeSealed::from_parts(*sealed.encapsulated_key(), ciphertext).unwrap();
        assert_eq!(
            hpke_open(&recipient, &mutated, b"bound info", b"bound aad")
                .err()
                .unwrap()
                .code(),
            "EA-CRYPTO-HPKE-OPEN"
        );
    }
    for (info, aad) in [
        (b"Bound info".as_slice(), b"bound aad".as_slice()),
        (b"bound info".as_slice(), b"Bound aad".as_slice()),
    ] {
        assert_eq!(
            hpke_open(&recipient, &sealed, info, aad)
                .err()
                .unwrap()
                .code(),
            "EA-CRYPTO-HPKE-OPEN"
        );
    }
}

#[test]
fn hpke_rng_failure_is_a_stable_error_and_never_panics_or_returns_wire_bytes() {
    let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x42; 32])).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        hpke_seal_with_random_source(
            &recipient.public_key(),
            &SecretBytes::new([0x60; 32]),
            b"info",
            b"aad",
            &mut FailingRandomSource,
        )
    }));
    let error = match result.expect("fallible RNG errors must not panic") {
        Ok(_) => panic!("a failed RNG must not return HPKE wire bytes"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "EA-LOCAL-CRYPTO-RNG");
}
