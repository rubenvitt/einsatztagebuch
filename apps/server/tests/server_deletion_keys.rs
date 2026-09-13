use ea_crypto::SecretBytes;
use ea_sync_server::{ServerSigner, managed_destruction::ServerDeletionComponent};
use ea_types::CertificateHash;
use einsatzarchiv_server::adapters::{
    deletion_key::ServerDeletionKeyStore, server_keys::ServerKeyStore,
};
#[test]
fn dedicated_service_credential_refuses_receipt_key_or_certificate_reuse() {
    let receipt = ServerKeyStore::new(
        SecretBytes::new([1; 32]),
        CertificateHash::try_from(&[2; 32][..]).unwrap(),
        1,
    )
    .unwrap();
    let deletion = CertificateHash::try_from(&[3; 32][..]).unwrap();
    assert!(ServerDeletionKeyStore::new(SecretBytes::new([1; 32]), deletion, &receipt).is_err());
    assert!(
        ServerDeletionKeyStore::new(
            SecretBytes::new([4; 32]),
            receipt.certificate_hash(),
            &receipt
        )
        .is_err()
    );
    let dedicated =
        ServerDeletionKeyStore::new(SecretBytes::new([4; 32]), deletion, &receipt).unwrap();
    assert!(dedicated.public_key().thumbprint() != receipt.key_thumbprint());
}
