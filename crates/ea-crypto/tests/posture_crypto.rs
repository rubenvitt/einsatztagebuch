use ea_crypto::{CoseSigner, SecretBytes, VerificationContext, object_hash, parse_cose_sign1};
use ea_types::CertificateHash;

fn core(cert: CertificateHash, mask: u64, issued: i64, until: i64) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(20)
        .unwrap()
        .str("EINSATZARCHIV-GOLIVE-POSTURE-v1")
        .unwrap()
        .u8(1)
        .unwrap();
    e.bytes(&[1; 16]).unwrap().bytes(&[2; 16]).unwrap();
    e.bytes(&[3; 32]).unwrap().bytes(&[4; 32]).unwrap();
    e.bytes(&[5; 16])
        .unwrap()
        .bytes(&[6; 32])
        .unwrap()
        .bytes(&[7; 32])
        .unwrap();
    e.u8(1).unwrap().bytes(&[8; 32]).unwrap().u64(mask).unwrap();
    e.bytes(object_hash(b"public documented prerequisites").as_bytes())
        .unwrap();
    e.bytes(cert.as_bytes()).unwrap().bytes(&[9; 32]).unwrap();
    e.u8(10).unwrap().bytes(&[11; 32]).unwrap().u8(12).unwrap();
    e.i64(issued).unwrap().i64(until).unwrap();
    e.into_writer()
}
#[test]
fn posture_document_signature_is_fixed_and_binds_the_explicit_admin_certificate() {
    let signer = CoseSigner::from_secret(SecretBytes::new([0x42; 32]));
    let cert = CertificateHash::try_from(&[0x43; 32][..]).unwrap();
    let bytes = core(cert, 14, 1000, 86_401_000);
    let signature = signer.sign_go_live_posture_document(&bytes).unwrap();
    let parsed = parse_cose_sign1(&signature, &[]).unwrap();
    assert_eq!(
        parsed.content_type().as_str(),
        "application/vnd.einsatzarchiv.go-live-posture-digest"
    );
    assert!(parsed.certificate_hash() == Some(cert));
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let header = ea_crypto::ProtectedHeader::normal(
        parsed.content_type(),
        signer.public_key().unwrap().thumbprint(),
        cert,
    );
    key.verifying_key()
        .verify_strict(
            &header.sig_structure_bytes(parsed.payload()),
            &ed25519_dalek::Signature::from_bytes(parsed.signature_bytes()),
        )
        .unwrap();
    VerificationContext::go_live_posture_document(&bytes).unwrap();
    let changed = core(cert, 6, 1000, 86_401_000);
    let changed_signature = signer.sign_go_live_posture_document(&changed).unwrap();
    assert_ne!(
        parse_cose_sign1(&changed_signature, &[]).unwrap().payload(),
        parsed.payload()
    );
}
#[test]
fn posture_document_rejects_empty_or_unknown_masks_and_nonpositive_or_overlong_lifetime() {
    let cert = CertificateHash::try_from(&[0x43; 32][..]).unwrap();
    let signer = CoseSigner::from_secret(SecretBytes::new([0x42; 32]));
    for bytes in [
        core(cert, 0, 1000, 2000),
        core(cert, 16, 1000, 2000),
        core(cert, 1, 1000, 1000),
        core(cert, 1, 1001, 1000),
        core(cert, 1, 1000, 86_401_001),
    ] {
        assert!(signer.sign_go_live_posture_document(&bytes).is_err());
        assert!(VerificationContext::go_live_posture_document(&bytes).is_err());
    }
}
