//! Closed bootstrap Signing-v1 container hosts. No media or ceremony transition.
use crate::{
    AdminError, FileBootstrapStore, OperatorLifecycleError,
    native_bootstrap_admin_participant::ParticipantBackupContext,
    native_provider::{
        NativeBackupBinding, NativeOperatorProvider, NativeProviderError, NativeSigningBackupSlot,
        NativeSigningSlot,
    },
};
use ea_crypto::{CanonicalPublicCoseKey, SecretVec};
use ea_key_provider::SecretPurpose;
use ea_recovery::{EncryptedKeyContainer, MAX_SECRET_FILE_BYTES_V1, RecoveryError};
use std::{path::Path, sync::Arc};

/// Static technical failure only; never carries a request, frame or secret.
#[derive(Clone, Copy)]
pub enum NativeSigningBackupError {
    Ceremony(AdminError),
    Participant(OperatorLifecycleError),
    Native(NativeProviderError),
    Recovery(RecoveryError),
}
impl NativeSigningBackupError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Ceremony(e) => e.code(),
            Self::Participant(e) => e.code(),
            Self::Native(e) => e.code(),
            Self::Recovery(e) => e.code(),
        }
    }
}
impl std::fmt::Debug for NativeSigningBackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::fmt::Display for NativeSigningBackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for NativeSigningBackupError {}
impl From<AdminError> for NativeSigningBackupError {
    fn from(e: AdminError) -> Self {
        Self::Ceremony(e)
    }
}
impl From<OperatorLifecycleError> for NativeSigningBackupError {
    fn from(e: OperatorLifecycleError) -> Self {
        Self::Participant(e)
    }
}
impl From<NativeProviderError> for NativeSigningBackupError {
    fn from(e: NativeProviderError) -> Self {
        Self::Native(e)
    }
}
impl From<RecoveryError> for NativeSigningBackupError {
    fn from(e: RecoveryError) -> Self {
        Self::Recovery(e)
    }
}
fn passphrase_admission(passphrase: &SecretVec) -> Result<(), NativeSigningBackupError> {
    if passphrase.is_empty() {
        return Err(RecoveryError::SecretEmpty.into());
    }
    if passphrase.len() > MAX_SECRET_FILE_BYTES_V1 {
        return Err(RecoveryError::KeySource.into());
    }
    Ok(())
}
fn confirm_ceremony(
    ceremony: &FileBootstrapStore,
    expected: &[u8],
) -> Result<(), NativeSigningBackupError> {
    if crate::native_bootstrap_root::read_participant_context(ceremony)?.persisted_image()
        != expected
    {
        return Err(AdminError::BootstrapContextMismatch.into());
    }
    Ok(())
}

/// Seals the already bound native Root under the held early Step-2 ceremony.
/// # Errors
/// Refuses unavailable or inconsistent ceremony/native authority and invalid passphrases.
pub fn seal_native_bootstrap_root_backup(
    ceremony: &mut FileBootstrapStore,
    native: &Arc<NativeOperatorProvider>,
    passphrase: &SecretVec,
) -> Result<EncryptedKeyContainer, NativeSigningBackupError> {
    let state = crate::native_bootstrap_root::read_participant_context(ceremony)?;
    passphrase_admission(passphrase)?;
    let root = state
        .root_material()
        .ok_or(AdminError::BootstrapContextMismatch)?;
    let expected_handle = native
        .signing_provider(NativeSigningSlot::Root)
        .handle(SecretPurpose::WriterSigningKey);
    if root.signing_handle != expected_handle {
        return Err(AdminError::BootstrapContextMismatch.into());
    }
    let public = CanonicalPublicCoseKey::from_deterministic_cbor(&root.exact_public_cose_key)
        .map_err(|_| NativeProviderError::Protocol)?;
    if public.thumbprint() != root.key_thumbprint {
        return Err(AdminError::BootstrapContextMismatch.into());
    }
    let binding = NativeBackupBinding::capture(native, NativeSigningBackupSlot::Root, &public)?;
    let container = binding.seal(passphrase)?;
    confirm_ceremony(ceremony, &state.persisted_image())?;
    binding.confirm()?;
    ceremony.ensure_lease()?;
    native.ensure_session_active()?;
    Ok(container)
}

/// Seals only the fully prepared participant's current native Admin key.
/// # Errors
/// Refuses unavailable or inconsistent ceremony, journal or native authority.
pub fn seal_native_bootstrap_admin_backup(
    ceremony: &mut FileBootstrapStore,
    participant_database_path: &Path,
    native: &Arc<NativeOperatorProvider>,
    passphrase: &SecretVec,
) -> Result<EncryptedKeyContainer, NativeSigningBackupError> {
    let state = crate::native_bootstrap_root::read_participant_context(ceremony)?;
    passphrase_admission(passphrase)?;
    let participant = ParticipantBackupContext::open(&state, participant_database_path, native)?;
    let binding =
        NativeBackupBinding::capture(native, NativeSigningBackupSlot::Admin, participant.public())?;
    let container = binding.seal(passphrase)?;
    confirm_ceremony(ceremony, &state.persisted_image())?;
    participant.confirm()?;
    // Recheck native binding AFTER the potentially blocking DB/journal work,
    // then the actual lease, and finally the live watch immediately before return.
    binding.confirm()?;
    ceremony.ensure_lease()?;
    native.ensure_session_active()?;
    Ok(container)
}
