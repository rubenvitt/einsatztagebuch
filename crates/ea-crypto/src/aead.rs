use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use zeroize::Zeroize;

use crate::{CryptoError, SecretBytes, SecretVec};

pub const CEK_SIZE: usize = 32;
pub const AEAD_NONCE_SIZE: usize = 12;
pub const AEAD_OVERHEAD: usize = 16;

pub fn checked_ciphertext_length(plaintext_length: usize) -> Result<usize, CryptoError> {
    plaintext_length
        .checked_add(AEAD_OVERHEAD)
        .ok_or(CryptoError::SizeLimit)
}

pub fn aead_seal(
    cek: &SecretBytes<CEK_SIZE>,
    nonce: &SecretBytes<AEAD_NONCE_SIZE>,
    plaintext: SecretVec,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let expected_length = checked_ciphertext_length(plaintext.len())?;
    let mut key = Array(*cek.expose());
    let cipher = ChaCha20Poly1305::new(&key);
    key.0.zeroize();
    let mut nonce = Array(*nonce.expose());
    let result = cipher.encrypt(
        &nonce,
        Payload {
            msg: plaintext.expose(),
            aad,
        },
    );
    nonce.0.zeroize();
    let ciphertext = result.map_err(|_| CryptoError::SizeLimit)?;
    if ciphertext.len() != expected_length {
        return Err(CryptoError::SizeLimit);
    }
    Ok(ciphertext)
}

pub fn aead_open(
    cek: &SecretBytes<CEK_SIZE>,
    nonce: &SecretBytes<AEAD_NONCE_SIZE>,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<SecretVec, CryptoError> {
    if ciphertext.len() < AEAD_OVERHEAD {
        return Err(CryptoError::AeadOpen);
    }
    let mut key = Array(*cek.expose());
    let cipher = ChaCha20Poly1305::new(&key);
    key.0.zeroize();
    let mut nonce = Array(*nonce.expose());
    let result = cipher.decrypt(
        &nonce,
        Payload {
            msg: ciphertext,
            aad,
        },
    );
    nonce.0.zeroize();
    let plaintext = result.map_err(|_| CryptoError::AeadOpen)?;
    Ok(SecretVec::new(plaintext))
}
