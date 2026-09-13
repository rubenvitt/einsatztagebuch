//! Recovery-only access to an actually restored native slot. This is not an
//! encrypted backup-file test and can never certify that such a file exists.
use super::*;
use crate::native_provider::{NativeOperatorProvider, NativeSigningSlot};
use ea_crypto::{CanonicalPublicCoseKey, CryptoError, ExternalCoseSigningRequest, SecretBytes};
use ea_recovery::{RecoveryKeyRole, RecoveryMedium, RecoverySigningBackup, RecoveryTestKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RecoveryNativeSigningSlot {
    Admin,
    Writer,
    Root,
}
impl RecoveryNativeSigningSlot {
    fn native(self) -> NativeSigningSlot {
        match self {
            Self::Admin => NativeSigningSlot::Admin,
            Self::Writer => NativeSigningSlot::Writer,
            Self::Root => NativeSigningSlot::Root,
        }
    }
    fn role(self) -> RecoveryKeyRole {
        match self {
            Self::Admin => RecoveryKeyRole::OrganizationAdmin,
            Self::Writer => RecoveryKeyRole::Writer,
            Self::Root => RecoveryKeyRole::Root,
        }
    }
    pub(super) fn accepts(self, medium: &RecoveryMedium) -> bool {
        medium.protection() == ea_format::KeyProtectionProfileV1::OsWrapped
            && medium.test_kind() == RecoveryTestKind::ProviderPresence
            && medium.role() == self.role()
    }
}

pub(super) struct NativeRecoverySigningBackup<'a> {
    native: &'a NativeOperatorProvider,
    slot: RecoveryNativeSigningSlot,
}
impl RecoverySigningBackup for NativeRecoverySigningBackup<'_> {
    fn public_key(&self) -> Result<CanonicalPublicCoseKey, CryptoError> {
        self.native
            .public_key(self.slot.native())
            .map_err(|_| CryptoError::SignerUnresolved)?
            .ok_or(CryptoError::SignerUnresolved)
    }
    fn sign_recovery_test(
        &self,
        certificate: ea_types::CertificateHash,
        challenge: SecretBytes<32>,
    ) -> Result<Vec<u8>, CryptoError> {
        let request =
            ExternalCoseSigningRequest::recovery_test(self.public_key()?, certificate, challenge)?;
        let signature = self
            .native
            .sign_raw(self.slot.native(), &request.sig_structure_bytes(), true)
            .map_err(|_| CryptoError::SignatureInvalid)?;
        request.complete(signature)
    }
}

impl RecoveryTestRuntime {
    pub(super) fn native_recovery_adapter<'a>(
        &'a self,
        medium: &RecoveryMedium,
        slot: RecoveryNativeSigningSlot,
    ) -> Result<NativeRecoverySigningBackup<'a>, RecoveryRuntimeError> {
        use ea_key_provider::{KeyProvider, SecretPurpose};
        self.runtime.ensure_current()?;
        if !slot.accepts(medium) {
            return Err(RecoveryTestError::Role.into());
        }
        let provider = self.runtime.native().signing_provider(slot.native());
        if provider
            .reached_protection_profile(&provider.handle(SecretPurpose::WriterSigningKey))
            .map_err(|_| RecoveryTestError::Key)?
            != medium.protection()
        {
            return Err(RecoveryTestError::Key.into());
        }
        let adapter = NativeRecoverySigningBackup {
            native: self.runtime.native(),
            slot,
        };
        if adapter
            .public_key()
            .map_err(|_| RecoveryTestError::Key)?
            .thumbprint()
            != medium.expected_thumbprint()
        {
            return Err(RecoveryTestError::Key.into());
        }
        Ok(adapter)
    }

    pub fn test_native_medium(
        &mut self,
        medium: &RecoveryMedium,
        slot: RecoveryNativeSigningSlot,
    ) -> Result<ea_recovery::VerifiedBackupChallenge, RecoveryRuntimeError> {
        let _writer = self.backend.acquire_writer_lock()?;
        self.runtime.refresh_for_action()?;
        self.runtime
            .reauthenticate_for(ReauthPurpose::RecoveryTest)?;
        let adapter = self.native_recovery_adapter(medium, slot)?;
        let proof = ea_recovery::verify_signing_backup(self.runtime.head(), medium, &adapter)?;
        self.runtime
            .reauthenticate_for(ReauthPurpose::RecoveryTest)?;
        self.runtime.ensure_current()?;
        Ok(proof)
    }
}
