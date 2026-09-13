//! A separate SQLCipher backup key. This is not a signing/KEM key container.
use crate::{
    RecoveryTestError,
    encrypted_container::{
        ARGON2ID_ITERATIONS_V1, ARGON2ID_MEMORY_KIB_V1, ARGON2ID_PARALLELISM_V1, derive_key,
    },
};
use ea_crypto::{SecretBytes, SecretVec};

pub struct RecoveryBackupKdf {
    salt: [u8; 16],
    exact: Vec<u8>,
}
impl RecoveryBackupKdf {
    pub fn fresh() -> Result<Self, RecoveryTestError> {
        let mut salt = [0; 16];
        getrandom::fill(&mut salt).map_err(|_| RecoveryTestError::Entropy)?;
        Self::new(salt)
    }
    fn new(salt: [u8; 16]) -> Result<Self, RecoveryTestError> {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(8)
            .and_then(|e| e.str("EINSATZARCHIV-SOURCE-BACKUP-KDF-v1"))
            .and_then(|e| e.u8(1))
            .and_then(|e| e.u32(ARGON2ID_MEMORY_KIB_V1))
            .and_then(|e| e.u32(ARGON2ID_ITERATIONS_V1))
            .and_then(|e| e.u32(ARGON2ID_PARALLELISM_V1))
            .and_then(|e| e.u8(0x13))
            .and_then(|e| e.u8(32))
            .and_then(|e| e.bytes(&salt))
            .map_err(|_| RecoveryTestError::Source)?;
        Ok(Self {
            salt,
            exact: e.into_writer(),
        })
    }
    /// Untrusted parameters are never negotiated. The signed source envelope
    /// must also be verified before deriving or opening a snapshot.
    pub fn from_exact(exact: &[u8]) -> Result<Self, RecoveryTestError> {
        let mut d = minicbor::Decoder::new(exact);
        let invalid = || RecoveryTestError::Source;
        if d.array().map_err(|_| invalid())? != Some(8)
            || d.str().map_err(|_| invalid())? != "EINSATZARCHIV-SOURCE-BACKUP-KDF-v1"
            || d.u8().map_err(|_| invalid())? != 1
            || d.u32().map_err(|_| invalid())? != ARGON2ID_MEMORY_KIB_V1
            || d.u32().map_err(|_| invalid())? != ARGON2ID_ITERATIONS_V1
            || d.u32().map_err(|_| invalid())? != ARGON2ID_PARALLELISM_V1
            || d.u8().map_err(|_| invalid())? != 0x13
            || d.u8().map_err(|_| invalid())? != 32
        {
            return Err(invalid());
        }
        let salt = d
            .bytes()
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?;
        let result = Self::new(salt)?;
        if d.position() != exact.len() || result.exact != exact {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub fn derive(&self, passphrase: &SecretVec) -> Result<SecretBytes<32>, RecoveryTestError> {
        if passphrase.is_empty() {
            return Err(RecoveryTestError::Key);
        }
        derive_key(passphrase, &self.salt).map_err(|_| RecoveryTestError::Key)
    }
}
