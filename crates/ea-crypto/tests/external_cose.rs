use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, ExternalCoseSigningRequest, SecretBytes};
use ea_types::CertificateHash;
use ed25519_dalek::{Signer as _, SigningKey};

fn historical_body(key: &CanonicalPublicCoseKey, kind: u8) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .array(17)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .bytes(&[2; 16])
        .unwrap()
        .bytes(&[3; 32])
        .unwrap()
        .u8(kind)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&[4; 32])
        .unwrap()
        .bytes(&[5; 32])
        .unwrap()
        .bytes(key.thumbprint().as_bytes())
        .unwrap()
        .bytes(&[6; 32])
        .unwrap()
        .str("historicalGrant")
        .unwrap()
        .u8(7)
        .unwrap()
        .bytes(&[8; 32])
        .unwrap()
        .str(ea_crypto::GRANT_SUITE_ID)
        .unwrap()
        .i64(1000)
        .unwrap()
        .bytes(&[9; 32])
        .unwrap()
        .bytes(&[10; 32])
        .unwrap()
        .bytes(&[11; 32])
        .unwrap()
        .bytes(&[12; 48])
        .unwrap();
    e.into_writer()
}

#[test]
fn external_hga_matches_software_exact_bytes_and_checks_returned_signature() {
    let native = SigningKey::from_bytes(&[0x42; 32]);
    let software = CoseSigner::from_secret(SecretBytes::new([0x42; 32]));
    let public = software.public_key().unwrap();
    let body = historical_body(&public, 1);
    let request = ExternalCoseSigningRequest::historical_grant(public.clone(), &body).unwrap();
    let signature = native.sign(&request.sig_structure_bytes()).to_bytes();
    assert_eq!(
        request.complete(signature).unwrap(),
        software.sign_historical_grant(&body).unwrap()
    );
    let request = ExternalCoseSigningRequest::historical_grant(public.clone(), &body).unwrap();
    assert!(request.complete([0; 64]).is_err());
    let other = CoseSigner::from_secret(SecretBytes::new([0x43; 32]))
        .public_key()
        .unwrap();
    assert!(ExternalCoseSigningRequest::historical_grant(other, &body).is_err());
    assert!(
        ExternalCoseSigningRequest::historical_grant(public.clone(), &historical_body(&public, 0))
            .is_err()
    );
}

#[test]
fn external_recovery_proof_preserves_certificate_and_challenge_domain() {
    let native = SigningKey::from_bytes(&[0x42; 32]);
    let software = CoseSigner::from_secret(SecretBytes::new([0x42; 32]));
    let certificate = CertificateHash::try_from(&[0x66; 32][..]).unwrap();
    let request = ExternalCoseSigningRequest::recovery_test(
        software.public_key().unwrap(),
        certificate,
        SecretBytes::new([0x55; 32]),
    )
    .unwrap();
    let signature = native.sign(&request.sig_structure_bytes()).to_bytes();
    assert_eq!(
        request.complete(signature).unwrap(),
        software
            .sign_recovery_test(certificate, SecretBytes::new([0x55; 32]))
            .unwrap()
    );
    let request = ExternalCoseSigningRequest::recovery_test(
        software.public_key().unwrap(),
        certificate,
        SecretBytes::new([0x56; 32]),
    )
    .unwrap();
    assert!(request.complete(signature).is_err());
}
