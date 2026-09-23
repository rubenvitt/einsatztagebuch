//! Resolved offline operations; token keys never become private key bytes.
use crate::{
    ConsumedEscrowOpening, HistoricalGrantSigner, Pkcs11RecipientKey, Pkcs11SigningKey,
    ReaderKeyEscrowKem, RecoveryKem, reader_key_escrow_envelope,
};
use ea_crypto::{
    CanonicalPublicCoseKey, CoseSigner, CryptoError, HpkeRecipient, HpkeRecipientPrivateKey,
    HpkeRecipientPublicKey, HpkeSealed, SecretBytes, hpke_aad, hpke_info, hpke_open,
};
use ea_types::{CertificateHash, KeyThumbprint};

pub enum ResolvedRecipientKey {
    Software(HpkeRecipientPrivateKey),
    Pkcs11(Pkcs11RecipientKey),
}
impl ResolvedRecipientKey {
    #[must_use]
    pub fn public_key(&self) -> HpkeRecipientPublicKey {
        match self {
            Self::Software(key) => key.public_key(),
            Self::Pkcs11(key) => key.public_key(),
        }
    }
}
impl HpkeRecipient for ResolvedRecipientKey {
    fn public_key(&self) -> HpkeRecipientPublicKey {
        Self::public_key(self)
    }
    fn open_envelope(
        &self,
        sealed: &HpkeSealed,
        info: &[u8],
        aad: &[u8],
    ) -> Result<SecretBytes<32>, CryptoError> {
        match self {
            Self::Software(key) => hpke_open(key, sealed, info, aad),
            Self::Pkcs11(key) => key
                .open_envelope(sealed, info, aad)
                .map_err(|_| CryptoError::HpkeOpen),
        }
    }
}
impl RecoveryKem for ResolvedRecipientKey {
    fn key_thumbprint(&self) -> Result<KeyThumbprint, CryptoError> {
        Ok(CanonicalPublicCoseKey::x25519(*self.public_key().as_bytes())?.thumbprint())
    }
    fn decapsulate(&self, original: &ea_format::GrantV1) -> Result<SecretBytes<32>, CryptoError> {
        let body = original.grant_body();
        let fields = body.fields();
        let context = body.exact_grant_context().ok_or(CryptoError::InvalidCose)?;
        hpke_open(
            self,
            &HpkeSealed::from_parts(fields.encapsulated_key, fields.wrapped_cek)?,
            &hpke_info(context),
            &hpke_aad(context),
        )
    }
}

/// Dasselbe Routing für die zweite getypte Operation: Software und PKCS#11
/// öffnen über [`HpkeRecipient::open_envelope`] mit derselben Kontextbildung
/// ([`reader_key_escrow_envelope`]). Der Token gibt nie Schlüsselbytes heraus.
impl ReaderKeyEscrowKem for ResolvedRecipientKey {
    fn key_thumbprint(&self) -> Result<KeyThumbprint, CryptoError> {
        Ok(CanonicalPublicCoseKey::x25519(*self.public_key().as_bytes())?.thumbprint())
    }
    fn open_reader_key_escrow(
        &self,
        opening: &ConsumedEscrowOpening<'_>,
    ) -> Result<SecretBytes<32>, CryptoError> {
        let (sealed, info, aad) = reader_key_escrow_envelope(opening.escrow())?;
        hpke_open(self, &sealed, &info, &aad)
    }
}

pub enum ResolvedSigningKey {
    Software(CoseSigner),
    Pkcs11(Pkcs11SigningKey),
}
impl ResolvedSigningKey {
    pub fn public_key(&self) -> Result<CanonicalPublicCoseKey, CryptoError> {
        match self {
            Self::Software(key) => key.public_key(),
            Self::Pkcs11(key) => Ok(key.public_key().clone()),
        }
    }
    pub fn sign_recovery_test(
        &self,
        certificate: CertificateHash,
        challenge: SecretBytes<32>,
    ) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Software(key) => key.sign_recovery_test(certificate, challenge),
            Self::Pkcs11(key) => key
                .sign_recovery_test(certificate, challenge)
                .map_err(|_| CryptoError::InvalidCose),
        }
    }
}
impl HistoricalGrantSigner for ResolvedSigningKey {
    fn key_thumbprint(&self) -> Result<KeyThumbprint, CryptoError> {
        Ok(self.public_key()?.thumbprint())
    }
    fn sign_historical_grant(&self, body: &ea_format::GrantBodyV1) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Software(key) => key.sign_historical_grant(body.exact_bytes()),
            Self::Pkcs11(key) => key
                .sign_historical_grant(body.exact_bytes())
                .map_err(|_| CryptoError::InvalidCose),
        }
    }
}
