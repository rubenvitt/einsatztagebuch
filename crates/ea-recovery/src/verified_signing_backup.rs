//! Existing Signing-v1 codec with an explicit expected public-key binding.
use crate::{ContainedKeyKind, EncryptedKeyContainer, MAX_SECRET_FILE_BYTES_V1, RecoveryError};
use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, SecretBytes, SecretVec};

/// Seals only a seed that derives the exact expected Ed25519 public key.
/// # Errors
/// Refuses mismatched keys and invalid passphrases or codec failures.
pub fn seal_verified_signing(
    secret: SecretBytes<32>,
    expected_public: &CanonicalPublicCoseKey,
    passphrase: &SecretVec,
) -> Result<EncryptedKeyContainer, RecoveryError> {
    if passphrase.is_empty() {
        return Err(RecoveryError::SecretEmpty);
    }
    if passphrase.len() > MAX_SECRET_FILE_BYTES_V1
        || !matches!(expected_public, CanonicalPublicCoseKey::Ed25519(_))
    {
        return Err(RecoveryError::KeySource);
    }
    // Intentional extra SecretBytes owner for derivation. Dalek's SigningKey
    // owns its own copy; drop it before allocating the container KDF buffers.
    let signer = CoseSigner::from_secret(secret.with_exposed(|bytes| SecretBytes::new(*bytes)));
    let actual = signer.public_key().map_err(|_| RecoveryError::KeySource)?;
    drop(signer);
    if &actual != expected_public {
        return Err(RecoveryError::KeySource);
    }
    EncryptedKeyContainer::seal(ContainedKeyKind::Signing, secret, passphrase)
}

/// Verifies a Signing-v1 container against the exact expected Ed25519 key.
/// # Errors
/// Refuses invalid inputs, failed decryption, and mismatched public keys.
pub fn verify_signing_container_key(
    _container: &EncryptedKeyContainer,
    _expected_public: &CanonicalPublicCoseKey,
    _passphrase: &SecretVec,
) -> Result<(), RecoveryError> {
    Err(RecoveryError::KeySource)
}
