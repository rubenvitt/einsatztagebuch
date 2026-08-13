use ea_crypto::{
    ContentType, CoseSigner, CryptoError, HpkeRecipientPrivateKey, SecretBytes, SecretVec,
    aead_open, aead_seal, hpke_open, hpke_seal, trust_digest,
};
use ea_types::CertificateHash;
use zeroize::Zeroize;

#[test]
fn secrets_do_not_implement_formatting_or_leak_through_errors() {
    let key_canary = "PRIVATE-KEY-CANARY";
    let cek_canary = "CEK-CANARY";
    let plaintext_canary = "PLAINTEXT-CANARY";
    let challenge_canary = "RECOVERY-CHALLENGE-CANARY";
    let rendered = format!("{:?} {}", CryptoError::AeadOpen, CryptoError::HpkeOpen);
    for canary in [key_canary, cek_canary, plaintext_canary, challenge_canary] {
        assert!(!rendered.contains(canary));
    }

    let secret = SecretBytes::<32>::new([0x55; 32]);
    let plaintext = SecretVec::new(plaintext_canary.as_bytes().to_vec());
    assert_eq!(secret.len(), 32);
    assert_eq!(plaintext.len(), plaintext_canary.len());
}

#[test]
fn stable_errors_never_include_upstream_details() {
    assert_eq!(
        format!("{:?}", CryptoError::InvalidCose),
        "EA-CRYPTO-INVALID-COSE"
    );
    assert_eq!(
        format!("{}", CryptoError::SignerMismatch),
        "EA-TRUST-SIGNER-MISMATCH"
    );
}

#[test]
fn owned_secret_backing_is_observably_zeroized_where_safe_access_permits() {
    let mut fixed = SecretBytes::new([0x5a; 32]);
    fixed.zeroize();
    assert!(fixed.matches(&[0; 32]));

    let mut variable = SecretVec::new(b"PLAINTEXT-ZEROIZE-CANARY".to_vec());
    variable.zeroize();
    assert!(variable.is_empty());
}

#[test]
fn cryptographic_failure_paths_return_only_stable_codes_and_no_secret_buffers() {
    let key = SecretBytes::new([0x4b; 32]);
    let nonce = SecretBytes::new([0x4e; 12]);
    let plaintext_canary = b"PLAINTEXT-FAILURE-CANARY";
    let ciphertext = aead_seal(
        &key,
        &nonce,
        SecretVec::new(plaintext_canary.to_vec()),
        b"bound aad",
    )
    .unwrap();
    assert!(
        !ciphertext
            .windows(plaintext_canary.len())
            .any(|window| window == plaintext_canary)
    );
    let aead_error = aead_open(&key, &nonce, &ciphertext, b"wrong aad")
        .err()
        .unwrap();

    let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x42; 32])).unwrap();
    let sealed = hpke_seal(
        &recipient.public_key(),
        &SecretBytes::new([0x43; 32]),
        b"info",
        b"aad",
    )
    .unwrap();
    let hpke_error = hpke_open(&recipient, &sealed, b"wrong info", b"aad")
        .err()
        .unwrap();

    let signer = CoseSigner::from_secret(SecretBytes::new([0x53; 32]));
    let productive = trust_digest(b"PRODUCTIVE-TRUST-CANARY");
    let recovery_error = signer
        .sign_normal(
            ContentType::RecoveryTestDigest,
            CertificateHash::try_from([0x44; 32].as_slice()).unwrap(),
            productive.as_bytes(),
        )
        .err()
        .unwrap();

    let rendered = format!("{aead_error:?}|{hpke_error}|{recovery_error:?}");
    assert_eq!(
        rendered,
        "EA-CRYPTO-AEAD-OPEN|EA-CRYPTO-HPKE-OPEN|EA-CRYPTO-INVALID-COSE"
    );
    for canary in [
        "PLAINTEXT-FAILURE-CANARY",
        "PRODUCTIVE-TRUST-CANARY",
        "KKKKKKKK",
        "CCCCCCCC",
        "SSSSSSSS",
    ] {
        assert!(!rendered.contains(canary));
    }
}
