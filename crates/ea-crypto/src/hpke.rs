use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    rand_core::{Infallible, TryCryptoRng, TryRng},
    single_shot_open, single_shot_seal_with_rng,
};
use zeroize::Zeroize;

use crate::{CryptoError, SecretBytes};

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

pub const HPKE_MODE: u8 = 0;
pub const HPKE_KEM_ID: u16 = 0x0020;
pub const HPKE_KDF_ID: u16 = 0x0001;
pub const HPKE_AEAD_ID: u16 = 0x0003;
pub const HPKE_ENCAPSULATED_KEY_SIZE: usize = 32;
pub const HPKE_WRAPPED_CEK_SIZE: usize = 48;

trait CryptoRandomSource {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), CryptoError>;
}

struct SystemRandomSource;

impl CryptoRandomSource for SystemRandomSource {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(destination).map_err(|_| CryptoError::LocalRng)
    }
}

struct InfallibleRandomAdapter<'a, R: ?Sized> {
    source: &'a mut R,
    error: Option<CryptoError>,
}

impl<R: CryptoRandomSource + ?Sized> TryRng for InfallibleRandomAdapter<'_, R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        if self.error.is_some() {
            destination.zeroize();
        } else if let Err(error) = self.source.fill_bytes(destination) {
            destination.zeroize();
            self.error = Some(error);
        }
        Ok(())
    }
}

impl<R: CryptoRandomSource + ?Sized> TryCryptoRng for InfallibleRandomAdapter<'_, R> {}

pub struct HpkeRecipientPrivateKey(<Kem as KemTrait>::PrivateKey);

impl HpkeRecipientPrivateKey {
    pub fn from_bytes(bytes: SecretBytes<32>) -> Result<Self, CryptoError> {
        let private = <Kem as KemTrait>::PrivateKey::from_bytes(bytes.expose())
            .map_err(|_| CryptoError::HpkeKey)?;
        Ok(Self(private))
    }

    #[must_use]
    pub fn public_key(&self) -> HpkeRecipientPublicKey {
        let public = Kem::sk_to_pk(&self.0).to_bytes();
        let mut bytes = [0_u8; HPKE_ENCAPSULATED_KEY_SIZE];
        bytes.copy_from_slice(&public);
        HpkeRecipientPublicKey(bytes)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HpkeRecipientPublicKey([u8; HPKE_ENCAPSULATED_KEY_SIZE]);

impl HpkeRecipientPublicKey {
    pub fn from_bytes(bytes: [u8; HPKE_ENCAPSULATED_KEY_SIZE]) -> Result<Self, CryptoError> {
        <Kem as KemTrait>::PublicKey::from_bytes(&bytes).map_err(|_| CryptoError::HpkeKey)?;
        if bytes == [0; HPKE_ENCAPSULATED_KEY_SIZE] {
            return Err(CryptoError::HpkeKey);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HPKE_ENCAPSULATED_KEY_SIZE] {
        &self.0
    }
}

pub struct HpkeSealed {
    encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_SIZE],
    wrapped_cek: [u8; HPKE_WRAPPED_CEK_SIZE],
}

impl HpkeSealed {
    pub fn from_parts(
        encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_SIZE],
        wrapped_cek: [u8; HPKE_WRAPPED_CEK_SIZE],
    ) -> Result<Self, CryptoError> {
        <Kem as KemTrait>::EncappedKey::from_bytes(&encapsulated_key)
            .map_err(|_| CryptoError::HpkeKey)?;
        Ok(Self {
            encapsulated_key,
            wrapped_cek,
        })
    }

    #[must_use]
    pub const fn encapsulated_key(&self) -> &[u8; HPKE_ENCAPSULATED_KEY_SIZE] {
        &self.encapsulated_key
    }

    #[must_use]
    pub const fn wrapped_cek(&self) -> &[u8; HPKE_WRAPPED_CEK_SIZE] {
        &self.wrapped_cek
    }
}

/// Seals with fresh operating-system entropy. Entropy injection is not a public API.
///
/// ```compile_fail
/// use ea_crypto::hpke_seal_with_random_source;
/// ```
pub fn hpke_seal(
    recipient: &HpkeRecipientPublicKey,
    cek: &SecretBytes<32>,
    info: &[u8],
    aad: &[u8],
) -> Result<HpkeSealed, CryptoError> {
    hpke_seal_with_random_source(recipient, cek, info, aad, &mut SystemRandomSource)
}

fn hpke_seal_with_random_source(
    recipient: &HpkeRecipientPublicKey,
    cek: &SecretBytes<32>,
    info: &[u8],
    aad: &[u8],
    random_source: &mut (impl CryptoRandomSource + ?Sized),
) -> Result<HpkeSealed, CryptoError> {
    let public =
        <Kem as KemTrait>::PublicKey::from_bytes(&recipient.0).map_err(|_| CryptoError::HpkeKey)?;
    let mut adapter = InfallibleRandomAdapter {
        source: random_source,
        error: None,
    };
    let mut result = single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &public,
        info,
        cek.expose(),
        aad,
        &mut adapter,
    );
    if let Some(error) = adapter.error {
        if let Ok((_, ciphertext)) = &mut result {
            ciphertext.zeroize();
        }
        let _ = error;
        return Err(CryptoError::LocalRng);
    }
    let (encapsulated, ciphertext) = result.map_err(|_| CryptoError::HpkeKey)?;
    let serialized_encapsulated = encapsulated.to_bytes();
    let mut encapsulated_key = [0_u8; HPKE_ENCAPSULATED_KEY_SIZE];
    encapsulated_key.copy_from_slice(&serialized_encapsulated);
    let wrapped_cek: [u8; HPKE_WRAPPED_CEK_SIZE] =
        ciphertext.try_into().map_err(|_| CryptoError::SizeLimit)?;
    Ok(HpkeSealed {
        encapsulated_key,
        wrapped_cek,
    })
}

pub fn hpke_open(
    recipient: &HpkeRecipientPrivateKey,
    sealed: &HpkeSealed,
    info: &[u8],
    aad: &[u8],
) -> Result<SecretBytes<32>, CryptoError> {
    let encapsulated = <Kem as KemTrait>::EncappedKey::from_bytes(&sealed.encapsulated_key)
        .map_err(|_| CryptoError::HpkeOpen)?;
    let mut plaintext = single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &recipient.0,
        &encapsulated,
        info,
        &sealed.wrapped_cek,
        aad,
    )
    .map_err(|_| CryptoError::HpkeOpen)?;
    if plaintext.len() != 32 {
        plaintext.zeroize();
        return Err(CryptoError::HpkeOpen);
    }
    let mut cek = [0_u8; 32];
    cek.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(SecretBytes::new(cek))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    struct FixedSecretSource {
        bytes: Zeroizing<Vec<u8>>,
        offset: usize,
    }

    impl CryptoRandomSource for FixedSecretSource {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            let end = self
                .offset
                .checked_add(destination.len())
                .ok_or(CryptoError::SizeLimit)?;
            destination.copy_from_slice(
                self.bytes
                    .get(self.offset..end)
                    .ok_or(CryptoError::SizeLimit)?,
            );
            self.offset = end;
            Ok(())
        }
    }

    struct FailingSource;

    impl CryptoRandomSource for FailingSource {
        fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::SizeLimit)
        }
    }

    #[test]
    fn application_wrapper_matches_independently_calculated_exact_wire() {
        let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x42; 32])).unwrap();
        let info = hex::decode("45494e5341545a4152434849562d48504b452d494e464f2d76318101").unwrap();
        let aad = hex::decode("45494e5341545a4152434849562d48504b452d4141442d76318101").unwrap();
        let mut random = FixedSecretSource {
            bytes: Zeroizing::new(vec![0x24; 32]),
            offset: 0,
        };
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
    }

    #[test]
    fn every_source_error_is_normalized_without_returning_wire_bytes() {
        let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x42; 32])).unwrap();
        let result = hpke_seal_with_random_source(
            &recipient.public_key(),
            &SecretBytes::new([0x60; 32]),
            b"info",
            b"aad",
            &mut FailingSource,
        );
        let error = match result {
            Ok(_) => panic!("failed entropy must not return HPKE wire bytes"),
            Err(error) => error,
        };
        assert_eq!(error, CryptoError::LocalRng);
    }
}
