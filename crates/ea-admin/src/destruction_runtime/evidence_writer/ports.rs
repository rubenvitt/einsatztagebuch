//! Refusal around every synchronous port boundary; authority stays native.
use super::*;
use ea_archive::*;
use ea_crypto::{ContentType, SecretBytes, SecretVec};
use ea_draft::*;
use ea_format::{ExactObjectBytes, KeyProtectionProfileV1};
use ea_key_provider::*;
use ea_types::CertificateHash;
#[derive(Clone)]
pub(super) struct Boundary {
    pub native: Arc<crate::native_provider::NativeOperatorProvider>,
    pub host: Option<Arc<dyn DestructionHostGuard>>,
    pub locked: bool,
}
impl Boundary {
    pub fn check(&self) -> Result<(), NativeDestructionError> {
        if self.locked {
            return Err(NativeDestructionError::Session);
        }
        if let Some(h) = &self.host {
            h.require_open()?;
        }
        self.native
            .ensure_session_active()
            .map_err(|_| NativeDestructionError::Session)?;
        if let Some(h) = &self.host {
            h.require_open()?;
        }
        Ok(())
    }
}
pub(super) struct Guarded<T> {
    pub inner: T,
    pub boundary: Boundary,
}
impl KeyProvider for Guarded<Arc<crate::native_provider::NativeKeyProvider>> {
    fn generate(
        &self,
        purpose: SecretPurpose,
        protection: KeyProtectionProfileV1,
    ) -> Result<KeyHandle, KeyError> {
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        let result = self.inner.generate(purpose, protection)?;
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        Ok(result)
    }
    fn sign(
        &self,
        handle: &KeyHandle,
        content_type: ContentType,
        certificate_hash: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        let result = self
            .inner
            .sign(handle, content_type, certificate_hash, payload)?;
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        Ok(result)
    }
    fn wrap_secret(
        &self,
        purpose: SecretPurpose,
        secret: SecretBytes<32>,
    ) -> Result<KeyHandle, KeyError> {
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        let result = self.inner.wrap_secret(purpose, secret)?;
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        Ok(result)
    }
    fn unwrap_secret(&self, handle: &KeyHandle) -> Result<SecretBytes<32>, KeyError> {
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        let result = self.inner.unwrap_secret(handle)?;
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        Ok(result)
    }
    fn unwrap_database_key(&self, handle: &KeyHandle) -> Result<SecretVec, KeyError> {
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        let result = self.inner.unwrap_database_key(handle)?;
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        Ok(result)
    }
    fn delete(&self, handle: &KeyHandle) -> Result<(), KeyError> {
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        self.inner.delete(handle)?;
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        Ok(())
    }
    fn contains(&self, handle: &KeyHandle) -> Result<bool, KeyError> {
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        let result = self.inner.contains(handle)?;
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        Ok(result)
    }
    fn reached_protection_profile(
        &self,
        handle: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, KeyError> {
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        let result = self.inner.reached_protection_profile(handle)?;
        self.boundary
            .check()
            .map_err(|_| KeyError::ProviderUnavailable)?;
        Ok(result)
    }
}
impl DraftRepository for Guarded<AutosaveDraftRepository> {
    fn evidence_draft_source(&self) -> Result<Option<EvidenceDraftSource>, DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        let result = self.inner.evidence_draft_source()?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(result)
    }
    fn load_or_create(&self) -> Result<Draft, DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        let result = self.inner.load_or_create()?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(result)
    }
    fn save(&self, draft: Draft) -> Result<SavedDraft, DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        let result = self.inner.save(draft)?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(result)
    }
    fn draft_dek_handle(&self, draft: &SavedDraft) -> Result<KeyHandle, DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        let result = self.inner.draft_dek_handle(draft)?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(result)
    }
    fn commit_discard_intent(&self, draft: &SavedDraft) -> Result<DiscardIntent, DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        let result = self.inner.commit_discard_intent(draft)?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(result)
    }
    fn pending_discard(&self) -> Result<Option<DiscardIntent>, DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        let result = self.inner.pending_discard()?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(result)
    }
    fn replace_with_blank(&self) -> Result<SavedDraft, DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        let result = self.inner.replace_with_blank()?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(result)
    }
    fn remove_ciphertext_and_intent_create_blank(
        &self,
        intent: &DiscardIntent,
    ) -> Result<DiscardOutcome, DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        let result = self
            .inner
            .remove_ciphertext_and_intent_create_blank(intent)?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(result)
    }
    fn prepared_finalization_marker(
        &self,
    ) -> Result<Option<PreparedFinalizationMarker>, DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        let result = self.inner.prepared_finalization_marker()?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(result)
    }
    fn replace_prepared_finalization_marker(
        &self,
        marker: Option<PreparedFinalizationMarker>,
    ) -> Result<(), DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        self.inner.replace_prepared_finalization_marker(marker)?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(())
    }
    fn acquire_draft_lock(&self) -> Result<DraftLock, DraftError> {
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        let result = self.inner.acquire_draft_lock()?;
        self.boundary
            .check()
            .map_err(|_| DraftError::ReauthRequired)?;
        Ok(result)
    }
}
impl ArchiveBackend for Guarded<&ea_archive_fs::LocalPathBackend> {
    fn create_if_absent(
        &self,
        relative: &ArchivePath,
        bytes: &ExactObjectBytes,
    ) -> Result<(), ArchiveBackendError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        self.inner.create_if_absent(relative, bytes)?;
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        Ok(())
    }
    fn create_non_object_if_absent(
        &self,
        relative: &ArchivePath,
        bytes: &[u8],
    ) -> Result<(), ArchiveBackendError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        self.inner.create_non_object_if_absent(relative, bytes)?;
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        Ok(())
    }
    fn staged_paths(&self) -> Result<Vec<String>, ArchiveBackendError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        let result = self.inner.staged_paths()?;
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        Ok(result)
    }
    fn remove_if_present(&self, relative: &ArchivePath) -> Result<(), ArchiveBackendError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        self.inner.remove_if_present(relative)?;
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        Ok(())
    }
    fn sync_file(&self, relative: &ArchivePath) -> Result<(), ArchiveBackendError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        self.inner.sync_file(relative)?;
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        Ok(())
    }
    fn sync_directory(&self, relative: &ArchivePath) -> Result<(), ArchiveBackendError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        self.inner.sync_directory(relative)?;
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        Ok(())
    }
    fn atomic_rename_same_fs(
        &self,
        from: &ArchivePath,
        to: &ArchivePath,
    ) -> Result<(), ArchiveBackendError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        self.inner.atomic_rename_same_fs(from, to)?;
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        Ok(())
    }
    fn create_directory_if_absent(&self, directory: &str) -> Result<(), ArchiveBackendError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        self.inner.create_directory_if_absent(directory)?;
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        Ok(())
    }
    fn acquire_writer_lock(&self) -> Result<WriterLock, ArchiveBackendError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        let result = self.inner.acquire_writer_lock()?;
        self.boundary
            .check()
            .map_err(|_| ArchiveBackendError::ReauthMismatch)?;
        Ok(result)
    }
    fn visit_managed_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveError::Unavailable)?;
        self.inner.visit_managed_blobs(&mut |blob| {
            self.boundary
                .check()
                .map_err(|_| ArchiveError::Unavailable)?;
            visitor(blob)
        })?;
        self.boundary.check().map_err(|_| ArchiveError::Unavailable)
    }
}
impl<T: ArchiveSource> ArchiveSource for Guarded<T> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        self.boundary
            .check()
            .map_err(|_| ArchiveError::Unavailable)?;
        self.inner.visit_blobs(&mut |blob| {
            self.boundary
                .check()
                .map_err(|_| ArchiveError::Unavailable)?;
            visitor(blob)
        })?;
        self.boundary.check().map_err(|_| ArchiveError::Unavailable)
    }
}
