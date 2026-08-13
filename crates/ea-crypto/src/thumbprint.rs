use ea_cbor::{ParserLimits, validate};
use ea_types::KeyThumbprint;
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder};

use crate::{CryptoError, digest::sha256_parts};

#[derive(Clone, Eq, PartialEq)]
pub enum CanonicalPublicCoseKey {
    Ed25519([u8; 32]),
    X25519([u8; 32]),
}

impl CanonicalPublicCoseKey {
    pub fn ed25519(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self::Ed25519(bytes))
    }

    pub fn x25519(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        if bytes == [0; 32] {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self::X25519(bytes))
    }

    pub fn from_deterministic_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        validate(bytes, ParserLimits::V1).map_err(|_| CryptoError::InvalidPublicKey)?;
        let mut decoder = Decoder::new(bytes);
        if decoder.map().map_err(|_| CryptoError::InvalidPublicKey)? != Some(3) {
            return Err(CryptoError::InvalidPublicKey);
        }
        if decoder.i64().map_err(|_| CryptoError::InvalidPublicKey)? != 1
            || decoder.i64().map_err(|_| CryptoError::InvalidPublicKey)? != 1
            || decoder.i64().map_err(|_| CryptoError::InvalidPublicKey)? != -1
        {
            return Err(CryptoError::InvalidPublicKey);
        }
        let curve = decoder.i64().map_err(|_| CryptoError::InvalidPublicKey)?;
        if decoder.i64().map_err(|_| CryptoError::InvalidPublicKey)? != -2 {
            return Err(CryptoError::InvalidPublicKey);
        }
        let public: [u8; 32] = decoder
            .bytes()
            .map_err(|_| CryptoError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        if decoder.position() != bytes.len() {
            return Err(CryptoError::InvalidPublicKey);
        }
        let key = match curve {
            6 => Self::ed25519(public)?,
            4 => Self::x25519(public)?,
            _ => return Err(CryptoError::UnsupportedSuite),
        };
        if key.to_deterministic_cbor() != bytes {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(key)
    }

    #[must_use]
    pub fn to_deterministic_cbor(&self) -> Vec<u8> {
        let (curve, public) = match self {
            Self::Ed25519(public) => (6_i64, public),
            Self::X25519(public) => (4_i64, public),
        };
        let mut bytes = Vec::with_capacity(40);
        let mut encoder = Encoder::new(&mut bytes);
        encoder
            .map(3)
            .and_then(|encoder| encoder.i64(1))
            .and_then(|encoder| encoder.i64(1))
            .and_then(|encoder| encoder.i64(-1))
            .and_then(|encoder| encoder.i64(curve))
            .and_then(|encoder| encoder.i64(-2))
            .and_then(|encoder| encoder.bytes(public))
            .expect("encoding fixed-size canonical COSE key into Vec cannot fail");
        debug_assert!(validate(&bytes, ParserLimits::V1).is_ok());
        bytes
    }

    #[must_use]
    pub fn thumbprint(&self) -> KeyThumbprint {
        KeyThumbprint::from(sha256_parts(&[&self.to_deterministic_cbor()]))
    }

    pub(crate) fn ed25519_bytes(&self) -> Result<&[u8; 32], CryptoError> {
        match self {
            Self::Ed25519(bytes) => Ok(bytes),
            Self::X25519(_) => Err(CryptoError::UnsupportedSuite),
        }
    }

    pub fn verify_strict(&self, cose_sign1: &[u8]) -> Result<(), CryptoError> {
        let parsed = crate::parse_cose_sign1(cose_sign1, &[])?;
        parsed.verify_with_key(self)
    }

    pub fn verify_ed25519_strict(
        &self,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CryptoError> {
        let key = VerifyingKey::from_bytes(self.ed25519_bytes()?)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        key.verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| CryptoError::SignatureInvalid)
    }
}
