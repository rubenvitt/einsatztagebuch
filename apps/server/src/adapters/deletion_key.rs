//! Separate configured service secret, without any hardware/posture claim.
use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, CryptoError, SecretBytes};
use ea_sync_server::{
    ServerSigner,
    managed_destruction::{ServerAttestationRequest, ServerDeletionComponent},
};
use ea_types::CertificateHash;
pub struct ServerDeletionKeyStore {
    signer: CoseSigner,
    public: CanonicalPublicCoseKey,
    certificate: CertificateHash,
}
impl ServerDeletionKeyStore {
    pub fn new(
        secret: SecretBytes<32>,
        certificate: CertificateHash,
        receipt: &dyn ServerSigner,
    ) -> Result<Self, CryptoError> {
        let signer = CoseSigner::from_secret(secret);
        let public = signer.public_key()?;
        if certificate == receipt.certificate_hash()
            || public.thumbprint() == receipt.key_thumbprint()
        {
            return Err(CryptoError::InvalidProtocolCore);
        }
        Ok(Self {
            signer,
            public,
            certificate,
        })
    }
}
impl ServerDeletionComponent for ServerDeletionKeyStore {
    fn certificate_hash(&self) -> CertificateHash {
        self.certificate
    }
    fn public_key(&self) -> &CanonicalPublicCoseKey {
        &self.public
    }
    fn sign_attestation(&self, request: &ServerAttestationRequest) -> Result<Vec<u8>, CryptoError> {
        self.signer.sign_deletion_attestation_digest(
            self.certificate,
            request.exact_payload_digest_input(),
            request.exact_authorization_bytes(),
        )
    }
}
