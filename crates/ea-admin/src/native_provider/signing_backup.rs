//! Closed native-to-container composition. No raw seed port leaves this module.
mod transport;
use super::*;
use crate::NativeSigningBackupError;
use ea_recovery::EncryptedKeyContainer;

#[derive(Clone, Copy)]
pub(crate) enum NativeSigningBackupSlot {
    Admin,
    Root,
}
impl NativeSigningBackupSlot {
    fn native(self) -> NativeSigningSlot {
        match self {
            Self::Admin => NativeSigningSlot::Admin,
            Self::Root => NativeSigningSlot::Root,
        }
    }
    fn role(self) -> u8 {
        match self {
            Self::Admin => 1,
            Self::Root => 2,
        }
    }
}

// Direct comparison of the same existing OS fields, not a new persisted account hash.
struct AccountSnapshot(OsAccountInputs);
impl AccountSnapshot {
    fn same(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (
                OsAccountInputs::Windows {
                    sid: a,
                    identifier_authority: b,
                    subauthorities: c,
                },
                OsAccountInputs::Windows {
                    sid: x,
                    identifier_authority: y,
                    subauthorities: z,
                },
            ) => a == x && b == y && c == z,
            (
                OsAccountInputs::MacOs {
                    guid_values: a,
                    unique_id_values: b,
                    actual_uid: c,
                },
                OsAccountInputs::MacOs {
                    guid_values: x,
                    unique_id_values: y,
                    actual_uid: z,
                },
            ) => a == x && b == y && c == z,
            (
                OsAccountInputs::Linux {
                    machine_id_file: a,
                    uid: b,
                },
                OsAccountInputs::Linux {
                    machine_id_file: x,
                    uid: y,
                },
            ) => a == x && b == y,
            _ => false,
        }
    }
}
impl Drop for AccountSnapshot {
    fn drop(&mut self) {
        match &mut self.0 {
            OsAccountInputs::Windows {
                sid,
                identifier_authority,
                subauthorities,
            } => {
                sid.zeroize();
                identifier_authority.zeroize();
                subauthorities.zeroize();
            }
            OsAccountInputs::MacOs {
                guid_values,
                unique_id_values,
                actual_uid,
            } => {
                guid_values.zeroize();
                unique_id_values.zeroize();
                actual_uid.zeroize();
            }
            OsAccountInputs::Linux {
                machine_id_file,
                uid,
            } => {
                machine_id_file.zeroize();
                uid.zeroize();
            }
        }
    }
}

/// Only capture can construct this private live binding; no caller-made DTO or seed.
pub(crate) struct NativeBackupBinding {
    native: Arc<NativeOperatorProvider>,
    slot: NativeSigningBackupSlot,
    account: AccountSnapshot,
    public: CanonicalPublicCoseKey,
    installation: [u8; 32],
}
impl NativeBackupBinding {
    pub(crate) fn capture(
        native: &Arc<NativeOperatorProvider>,
        slot: NativeSigningBackupSlot,
        expected: &CanonicalPublicCoseKey,
    ) -> Result<Self, NativeSigningBackupError> {
        native.ensure_session_active()?;
        if !matches!(expected, CanonicalPublicCoseKey::Ed25519(_)) {
            return Err(NativeProviderError::Protocol.into());
        }
        let account = AccountSnapshot(native.account()?);
        let binding = Self {
            native: Arc::clone(native),
            slot,
            account,
            public: expected.clone(),
            installation: native.installation,
        };
        binding.confirm()?;
        Ok(binding)
    }
    pub(crate) fn confirm(&self) -> Result<(), NativeSigningBackupError> {
        self.native.ensure_session_active()?;
        let provider = self.native.signing_provider(self.slot.native());
        let handle = provider.handle(SecretPurpose::WriterSigningKey);
        if self.native.installation != self.installation
            || provider
                .reached_protection_profile(&handle)
                .map_err(|_| NativeProviderError::Denied)?
                != KeyProtectionProfileV1::OsWrapped
            || self.native.public_key(self.slot.native())?.as_ref() != Some(&self.public)
            || !self.account.same(&AccountSnapshot(self.native.account()?))
        {
            return Err(NativeProviderError::InstallationChanged.into());
        }
        // All native calls above can block. Nothing blocking follows this fresh check.
        self.native.ensure_session_active()?;
        Ok(())
    }
    pub(crate) fn seal(
        &self,
        passphrase: &SecretVec,
    ) -> Result<EncryptedKeyContainer, NativeSigningBackupError> {
        self.confirm()?;
        let CanonicalPublicCoseKey::Ed25519(public) = &self.public else {
            return Err(NativeProviderError::Protocol.into());
        };
        let request = serde_json::to_vec(&json!({"op":"backup-signing-seed", "slot":self.slot.native().name(),
            "installation_id":hex::encode(self.installation), "expected_public_key":hex::encode(public), "presence":true}))
            .map_err(|_| NativeProviderError::Protocol)?;
        let identity_native = Arc::clone(&self.native);
        let watch_native = Arc::clone(&self.native);
        let frame = transport::run(
            helper_command(&self.native.helper, std::env::vars_os()),
            request,
            Duration::from_secs(300),
            move |pid| {
                identity_native
                    .identity
                    .verify_child(&identity_native.helper, pid)
            },
            move || watch_native.ensure_session_active(),
        )?;
        let seed = frame.take_seed(&transport::FrameBinding {
            role: self.slot.role(),
            installation: self.installation,
            public: *public,
        })?;
        let container = ea_recovery::seal_verified_signing(seed, &self.public, passphrase)?;
        self.confirm()?;
        Ok(container)
    }
}
