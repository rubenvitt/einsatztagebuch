//! Separately encrypted local expiry floor. Public vault/archive bytes stay unchanged.
use crate::{ReaderBlobKey, ReaderBlobStore, ReaderVaultError, UnlockedVault};
use ea_types::UnixMillis;
pub struct ReaderGrantTimeStore;
impl ReaderGrantTimeStore {
    pub fn blob_key(vault: &UnlockedVault) -> Result<ReaderBlobKey, ReaderVaultError> {
        let thumb: String = vault
            .kem_key_thumbprint()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(ReaderBlobKey::new(&format!("grant-time/v1/{thumb}"))?)
    }
    /// The host holds its exclusive blob handle across read/merge/write. A
    /// failed or corrupt store releases no usable time and permits no opening.
    pub fn observe(
        vault: &UnlockedVault,
        store: &mut dyn ReaderBlobStore,
        now: UnixMillis,
    ) -> Result<UnixMillis, ReaderVaultError> {
        use ea_crypto::{AEAD_NONCE_SIZE, SecretBytes, SecretVec, aead_open, aead_seal};
        let key = Self::blob_key(vault)?;
        let encryption = vault.grant_time_key()?;
        let aad = crate::envelope::blob_aad(key.as_str().as_bytes());
        let mut floor = now;
        if let Some(bytes) = store.get(&key)? {
            if bytes.len() < AEAD_NONCE_SIZE {
                return Err(ReaderVaultError::Contents);
            }
            let (nonce, ciphertext) = bytes.split_at(AEAD_NONCE_SIZE);
            let nonce: [u8; AEAD_NONCE_SIZE] =
                nonce.try_into().map_err(|_| ReaderVaultError::Contents)?;
            let opened = aead_open(&encryption, &SecretBytes::new(nonce), ciphertext, &aad)?;
            let previous =
                opened.with_exposed(|bytes| -> Result<UnixMillis, ReaderVaultError> {
                    Ok(UnixMillis::new(i64::from_be_bytes(
                        bytes.try_into().map_err(|_| ReaderVaultError::Contents)?,
                    )))
                })?;
            floor = floor.max(previous);
        }
        floor = vault.observe_effective_time(floor);
        let mut nonce = [0; AEAD_NONCE_SIZE];
        getrandom::fill(&mut nonce)
            .map_err(|_| ReaderVaultError::Crypto(ea_crypto::CryptoError::LocalRng))?;
        let ciphertext = aead_seal(
            &encryption,
            &SecretBytes::new(nonce),
            SecretVec::new(floor.get().to_be_bytes().to_vec()),
            &aad,
        )?;
        let mut bytes = nonce.to_vec();
        bytes.extend_from_slice(&ciphertext);
        store.put(&key, &bytes)?;
        vault.affirm_durable_grant_time(floor);
        Ok(floor)
    }
}
