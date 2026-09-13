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
    refuse_unless_derives(
        secret.with_exposed(|bytes| SecretBytes::new(*bytes)),
        expected_public,
    )?;
    EncryptedKeyContainer::seal(ContainedKeyKind::Signing, secret, passphrase)
}

/// Verifies a Signing-v1 container against the exact expected Ed25519 key.
///
/// Order: container kind and expected key family, then the existing
/// passphrase bounds, all before the KDF runs; only then the existing v1
/// open. The opened seed and the temporary signer are dropped before return.
/// # Errors
/// [`RecoveryError::KeySource`] for a non-Signing container, a non-Ed25519
/// expected key, an oversize passphrase or a mismatched public key;
/// [`RecoveryError::SecretEmpty`] for an empty passphrase;
/// [`RecoveryError::ContainerOpen`] when the AEAD does not open.
pub fn verify_signing_container_key(
    container: &EncryptedKeyContainer,
    expected_public: &CanonicalPublicCoseKey,
    passphrase: &SecretVec,
) -> Result<(), RecoveryError> {
    if container.kind() != ContainedKeyKind::Signing
        || !matches!(expected_public, CanonicalPublicCoseKey::Ed25519(_))
    {
        return Err(RecoveryError::KeySource);
    }
    if passphrase.is_empty() {
        return Err(RecoveryError::SecretEmpty);
    }
    if passphrase.len() > MAX_SECRET_FILE_BYTES_V1 {
        return Err(RecoveryError::KeySource);
    }
    let opened = container.open(ContainedKeyKind::Signing, passphrase)?;
    refuse_unless_derives(opened, expected_public)
}

/// Derives the Ed25519 public key from exactly this seed and compares it
/// with the expected canonical key. Consumes the seed; the temporary signer
/// ends inside this call.
fn refuse_unless_derives(
    secret: SecretBytes<32>,
    expected_public: &CanonicalPublicCoseKey,
) -> Result<(), RecoveryError> {
    let signer = CoseSigner::from_secret(secret);
    let actual = signer.public_key().map_err(|_| RecoveryError::KeySource);
    drop(signer);
    if &actual? != expected_public {
        return Err(RecoveryError::KeySource);
    }
    Ok(())
}
