//! Durable local Step 2. Original bytes precede the separate state commit.

use super::{AdminError, NativeInitialRootV1, NativeOperatorProvider, RegistryVersion};
use crate::{BootstrapStateV1, FileBootstrapStore};
use std::sync::Arc;

/// Completes only the existing native Root step under a retained store lease.
/// Exact public certificate bytes live beside the state at the full state
/// filename plus `.root-certificate.etb`. Existing originals are never replaced
/// or re-signed. A successful result is still BlockedRecoveryTest.
///
/// Certificate retention and state commit are separate durable operations.
/// An error may leave the original or committed step 2 on disk; callers must
/// reopen under the lease, never infer rollback or remove retained bytes.
///
/// # Errors
/// Refuses missing/invalid leases, missing or inconsistent predecessors,
/// unavailable original files, mismatched certificates and invalid native
/// authority. Unsupported lease platforms cannot fall back to unleased work.
pub fn complete_native_root_step(
    store: &mut FileBootstrapStore,
    native: &Arc<NativeOperatorProvider>,
    initial_effective_version: RegistryVersion,
) -> Result<NativeInitialRootV1, AdminError> {
    complete_with_opener(store, initial_effective_version, || Ok(Arc::clone(native)))
        .map(|(certificate, _)| certificate)
}

/// Certifies the existing installed Root and returns only the persisted step status.
/// Never initializes a helper installation or generates a key. The installed
/// provider is opened only after predecessor/file admission, and for existing
/// originals only after their public InitialRoot PoP has been checked.
///
/// # Errors
/// The same fail-closed errors as [`complete_native_root_step`].
pub fn complete_installed_native_root_step(
    store: &mut FileBootstrapStore,
    initial_effective_version: RegistryVersion,
) -> Result<BootstrapStateV1, AdminError> {
    complete_with_opener(store, initial_effective_version, || {
        NativeOperatorProvider::open_installed(false).map_err(super::native_error)
    })
    .map(|(_, state)| state)
}

/// Separate test executable only; production always selects the installed opener.
///
/// # Errors
/// The same admission, native and persistence errors as the installed entry.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn complete_native_root_step_with_test_opener(
    store: &mut FileBootstrapStore,
    initial_effective_version: RegistryVersion,
    open: impl FnOnce() -> Result<Arc<NativeOperatorProvider>, super::NativeProviderError>,
) -> Result<BootstrapStateV1, AdminError> {
    complete_with_opener(store, initial_effective_version, || {
        open().map_err(super::native_error)
    })
    .map(|(_, state)| state)
}

fn complete_with_opener(
    store: &mut FileBootstrapStore,
    initial_effective_version: RegistryVersion,
    open: impl FnOnce() -> Result<Arc<NativeOperatorProvider>, AdminError>,
) -> Result<(NativeInitialRootV1, BootstrapStateV1), AdminError> {
    store.ensure_lease()?;
    #[cfg(any(
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(
            target_os = "linux",
            target_env = "gnu",
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        supported::complete(store, initial_effective_version, open)
    }
    #[cfg(not(any(
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(
            target_os = "linux",
            target_env = "gnu",
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (initial_effective_version, open);
        Err(AdminError::BootstrapStoreUnavailable)
    }
}

#[cfg(any(
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub(crate) use supported::read_participant_context;

#[cfg(not(any(
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
pub(crate) fn read_participant_context(
    store: &FileBootstrapStore,
) -> Result<BootstrapStateV1, AdminError> {
    store.ensure_lease()?;
    Err(AdminError::BootstrapStoreUnavailable)
}

#[cfg(any(
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod supported {
    use super::super::{
        BootstrapCoordinator, BootstrapStep, CanonicalPublicCoseKey, DecodedTrustPayloadV1,
        NativeSigningSlot, ParsedArchiveObject, ProductionState, RootKeyMaterialV1, SecretPurpose,
        decode_exact_object, native_error, object_hash, prepare_native_root_for_ceremony,
        require_root_key, trust_digest, verify_initial_root_pop,
    };
    use super::*;
    use crate::{BootstrapStateV1, BootstrapStore as _};
    use ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1;
    use std::{
        fs::{self, File, Metadata, OpenOptions},
        io::{self, Read as _, Write as _},
        os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
        path::{Path, PathBuf},
    };

    #[cfg(target_os = "macos")]
    const NOFOLLOW_NONBLOCK: i32 = 0x100 | 0x4;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const NOFOLLOW_NONBLOCK: i32 = 0x20000 | 2048;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const NOFOLLOW_NONBLOCK: i32 = 0x8000 | 2048;

    struct LazyNative<F> {
        native: Option<Arc<NativeOperatorProvider>>,
        open: Option<F>,
    }

    impl<F: FnOnce() -> Result<Arc<NativeOperatorProvider>, AdminError>> LazyNative<F> {
        fn get(&mut self) -> Result<&Arc<NativeOperatorProvider>, AdminError> {
            if self.native.is_none() {
                let open = self
                    .open
                    .take()
                    .ok_or(AdminError::BootstrapContextMismatch)?;
                self.native = Some(open()?);
            }
            self.native
                .as_ref()
                .ok_or(AdminError::BootstrapContextMismatch)
        }
    }

    pub(super) fn complete(
        store: &mut FileBootstrapStore,
        version: RegistryVersion,
        open: impl FnOnce() -> Result<Arc<NativeOperatorProvider>, AdminError>,
    ) -> Result<(NativeInitialRootV1, BootstrapStateV1), AdminError> {
        let mut native = LazyNative {
            native: None,
            open: Some(open),
        };
        let initial = store.load()?.ok_or(AdminError::BootstrapContextMismatch)?;
        admissible(&initial)?;
        let mut original_path = store.path().as_os_str().to_os_string();
        original_path.push(".root-certificate.etb");
        let original_path = PathBuf::from(original_path);
        let original = match Original::read(&original_path)? {
            Some(original) => original,
            None => {
                if initial.step() != BootstrapStep::GenerateIds {
                    return Err(AdminError::RootCertificateMismatch);
                }
                let coordinator = BootstrapCoordinator::resume(store)?
                    .ok_or(AdminError::BootstrapContextMismatch)?;
                unchanged(coordinator.state(), &initial)?;
                let prepared =
                    prepare_native_root_for_ceremony(&coordinator, native.get()?, version)?;
                drop(coordinator);
                store.ensure_lease()?;
                publish(&original_path, prepared.exact_certificate().as_bytes())?;
                let original =
                    Original::read(&original_path)?.ok_or(AdminError::BootstrapStoreUnavailable)?;
                if original.bytes != prepared.exact_certificate().as_bytes() {
                    return Err(AdminError::RootCertificateMismatch);
                }
                original
            }
        };
        let verified = verify_original(&original.bytes, &initial, &mut native, version)?;
        // Reconfirm this on both step 1 and step 2. The original path appends
        // only a filename suffix to the state path, so both share this parent.
        // FileBootstrapStore synced its state file before rename; a successful
        // shared-parent flush here also confirms an earlier uncertain state
        // rename, without rewriting either file or claiming joint atomicity.
        original.sync()?;
        if initial.step() == BootstrapStep::GenerateIds {
            require_current(native.get()?, &verified)?;
            store.ensure_lease()?;
            let mut coordinator =
                BootstrapCoordinator::resume(store)?.ok_or(AdminError::BootstrapContextMismatch)?;
            unchanged(coordinator.state(), &initial)?;
            coordinator.generate_offline_root(verified.material.clone())?;
            drop(coordinator);
        }
        // No claim of a joint transaction: commit errors above return as errors,
        // even if rename already left step 2 on disk. Reentry reloads that state.
        store.ensure_lease()?;
        let final_state = store.load()?.ok_or(AdminError::BootstrapContextMismatch)?;
        admissible(&final_state)?;
        if final_state.step() != BootstrapStep::GenerateOfflineRoot
            || final_state.organization_id() != initial.organization_id()
            || final_state.chain_id() != initial.chain_id()
            || final_state.ceremony_machine() != initial.ceremony_machine()
            || !final_state
                .root_material()
                .is_some_and(|root| same_root(root, &verified.material))
        {
            return Err(AdminError::BootstrapContextMismatch);
        }
        let final_original =
            Original::read(&original_path)?.ok_or(AdminError::BootstrapStoreUnavailable)?;
        if final_original.bytes != original.bytes {
            return Err(AdminError::RootCertificateMismatch);
        }
        let output = verify_original(&final_original.bytes, &final_state, &mut native, version)?;
        original.ensure_unchanged()?;
        final_original.ensure_unchanged()?;
        require_current(native.get()?, &output)?;
        store.ensure_lease()?;
        Ok((output, final_state))
    }

    fn admissible(state: &BootstrapStateV1) -> Result<(), AdminError> {
        if state.is_aborted() {
            return Err(AdminError::AnchorPreFieldChanged);
        }
        if !matches!(
            state.step(),
            BootstrapStep::GenerateIds | BootstrapStep::GenerateOfflineRoot
        ) || !state.has_only_early_root_fields()
            || state.production_state() != ProductionState::BlockedRecoveryTest
            || state.exact_pre_anchor_bytes().is_some()
            || state.sealed_pre_anchor_fingerprint().is_some()
            || state.exact_final_anchor_bytes().is_some()
            || state.has_root_material() != (state.step() == BootstrapStep::GenerateOfflineRoot)
        {
            return Err(AdminError::BootstrapContextMismatch);
        }
        Ok(())
    }

    fn unchanged(actual: &BootstrapStateV1, expected: &BootstrapStateV1) -> Result<(), AdminError> {
        if actual.persisted_image() != expected.persisted_image() {
            return Err(AdminError::BootstrapContextMismatch);
        }
        Ok(())
    }

    fn same_root(left: &RootKeyMaterialV1, right: &RootKeyMaterialV1) -> bool {
        left.signing_handle == right.signing_handle
            && left.exact_public_cose_key == right.exact_public_cose_key
            && left.key_thumbprint == right.key_thumbprint
            && left.certificate_object_hash == right.certificate_object_hash
    }

    fn verify_original(
        bytes: &[u8],
        state: &BootstrapStateV1,
        native: &mut LazyNative<impl FnOnce() -> Result<Arc<NativeOperatorProvider>, AdminError>>,
        version: RegistryVersion,
    ) -> Result<NativeInitialRootV1, AdminError> {
        let (certificate, fields) = verify_public_original(bytes, state, Some(version))?;
        let public = CanonicalPublicCoseKey::from_deterministic_cbor(&fields.root_public_cose_key)?;
        // Public exact bytes and PoP are admitted before even opening a helper.
        let native = native.get()?;
        let material = RootKeyMaterialV1 {
            signing_handle: native
                .signing_provider(NativeSigningSlot::Root)
                .handle(SecretPurpose::WriterSigningKey),
            exact_public_cose_key: fields.root_public_cose_key,
            key_thumbprint: public.thumbprint(),
            certificate_object_hash: object_hash(bytes),
        };
        if state
            .root_material()
            .is_some_and(|root| !same_root(root, &material))
        {
            return Err(AdminError::RootCertificateMismatch);
        }
        let output = NativeInitialRootV1 {
            certificate,
            material,
        };
        require_current(native, &output)?;
        Ok(output)
    }

    // Shared public Original admission. This checks the retained local ceremony
    // context; it does not give that context independently pinned trust authority.
    fn verify_public_original(
        bytes: &[u8],
        state: &BootstrapStateV1,
        version: Option<RegistryVersion>,
    ) -> Result<
        (
            ea_format::ExactObjectBytes,
            ea_format::RootCertificateFieldsV1,
        ),
        AdminError,
    > {
        let ParsedArchiveObject::Trust(parsed) = decode_exact_object(bytes)? else {
            return Err(AdminError::RootCertificateMismatch);
        };
        let DecodedTrustPayloadV1::InitialRoot(fields) = parsed.value().decoded_payload()? else {
            return Err(AdminError::RootCertificateMismatch);
        };
        if fields.organization_id != state.organization_id()
            || version.is_some_and(|version| fields.effective_from_registry_version != version)
            || fields.previous_root_certificate_object_hash.is_some()
            || parsed.value().signatures().len() != 1
        {
            return Err(AdminError::RootCertificateMismatch);
        }
        let public = CanonicalPublicCoseKey::from_deterministic_cbor(&fields.root_public_cose_key)?;
        if !matches!(public, CanonicalPublicCoseKey::Ed25519(_))
            || public.thumbprint() != fields.root_key_thumbprint
        {
            return Err(AdminError::RootCertificateMismatch);
        }
        let digest = trust_digest(parsed.value().exact_digest_input());
        verify_initial_root_pop(&parsed.value().signatures()[0], &public, digest.as_bytes())
            .map_err(|_| AdminError::RootSignatureMismatch)?;
        if state.root_material().is_some_and(|root| {
            root.exact_public_cose_key != fields.root_public_cose_key
                || root.key_thumbprint != public.thumbprint()
                || root.certificate_object_hash != object_hash(bytes)
        }) {
            return Err(AdminError::RootCertificateMismatch);
        }
        Ok((parsed.exact_bytes().clone(), fields))
    }

    pub(crate) fn read_participant_context(
        store: &FileBootstrapStore,
    ) -> Result<BootstrapStateV1, AdminError> {
        store.ensure_lease()?;
        let state = store.load()?.ok_or(AdminError::BootstrapContextMismatch)?;
        admissible(&state)?;
        if state.step() != BootstrapStep::GenerateOfflineRoot {
            return Err(AdminError::BootstrapContextMismatch);
        }
        let mut path = store.path().as_os_str().to_os_string();
        path.push(".root-certificate.etb");
        let original =
            Original::read(Path::new(&path))?.ok_or(AdminError::RootCertificateMismatch)?;
        verify_public_original(&original.bytes, &state, None)?;
        // Same parent as the already-file-synced state: reconfirms an earlier
        // uncertain rename without rewriting either file or reading a Root key.
        original.sync()?;
        let reloaded = store.load()?.ok_or(AdminError::BootstrapContextMismatch)?;
        unchanged(&reloaded, &state)?;
        original.ensure_unchanged()?;
        store.ensure_lease()?;
        Ok(reloaded)
    }

    fn require_current(
        native: &NativeOperatorProvider,
        output: &NativeInitialRootV1,
    ) -> Result<(), AdminError> {
        native.ensure_session_active().map_err(native_error)?;
        let public = CanonicalPublicCoseKey::from_deterministic_cbor(
            &output.material.exact_public_cose_key,
        )?;
        require_root_key(native, &public)?;
        native.ensure_session_active().map_err(native_error)
    }

    fn unavailable(_: io::Error) -> AdminError {
        AdminError::BootstrapStoreUnavailable
    }

    fn same_identity(left: &Metadata, right: &Metadata) -> bool {
        left.dev() == right.dev() && left.ino() == right.ino()
    }

    fn valid_file(metadata: &Metadata) -> bool {
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.len() > 0
            && metadata.len() <= MAX_ARCHIVE_OBJECT_BYTES_V1 as u64
    }

    struct Original {
        path: PathBuf,
        file: File,
        metadata: Metadata,
        bytes: Vec<u8>,
    }

    impl Original {
        fn read(path: &Path) -> Result<Option<Self>, AdminError> {
            let metadata = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(unavailable(error)),
            };
            if !valid_file(&metadata) {
                return Err(AdminError::BootstrapStoreUnavailable);
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(NOFOLLOW_NONBLOCK)
                .open(path)
                .map_err(unavailable)?;
            let mut result = Self {
                path: path.into(),
                file,
                metadata,
                bytes: Vec::new(),
            };
            result.ensure_unchanged()?;
            (&result.file)
                .take(MAX_ARCHIVE_OBJECT_BYTES_V1 as u64 + 1)
                .read_to_end(&mut result.bytes)
                .map_err(unavailable)?;
            result.ensure_unchanged()?;
            if result.bytes.len() as u64 != result.metadata.len() {
                return Err(AdminError::BootstrapStoreUnavailable);
            }
            Ok(Some(result))
        }

        fn ensure_unchanged(&self) -> Result<(), AdminError> {
            let opened = self.file.metadata().map_err(unavailable)?;
            let named = fs::symlink_metadata(&self.path).map_err(unavailable)?;
            if !valid_file(&opened)
                || !valid_file(&named)
                || !same_identity(&self.metadata, &opened)
                || !same_identity(&opened, &named)
                || opened.len() != self.metadata.len()
                || named.len() != self.metadata.len()
                || opened.mtime() != self.metadata.mtime()
                || opened.mtime_nsec() != self.metadata.mtime_nsec()
                || opened.ctime() != self.metadata.ctime()
                || opened.ctime_nsec() != self.metadata.ctime_nsec()
            {
                return Err(AdminError::BootstrapStoreUnavailable);
            }
            Ok(())
        }

        fn sync(&self) -> Result<(), AdminError> {
            self.ensure_unchanged()?;
            self.file.sync_all().map_err(unavailable)?;
            sync_parent(&self.path)?;
            self.ensure_unchanged()
        }
    }

    fn publish(path: &Path, bytes: &[u8]) -> Result<(), AdminError> {
        if bytes.is_empty() || bytes.len() > MAX_ARCHIVE_OBJECT_BYTES_V1 {
            return Err(AdminError::RootCertificateMismatch);
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(NOFOLLOW_NONBLOCK)
            .open(path)
            .map_err(unavailable)?;
        // Never unlink or overwrite even a partially written original. An
        // uncertain publication is evidence to inspect on the next entry.
        file.write_all(bytes).map_err(unavailable)?;
        file.sync_all().map_err(unavailable)?;
        sync_parent(path)
    }

    fn sync_parent(path: &Path) -> Result<(), AdminError> {
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let before = fs::symlink_metadata(parent).map_err(unavailable)?;
        if !before.is_dir() {
            return Err(AdminError::BootstrapStoreUnavailable);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW_NONBLOCK)
            .open(parent)
            .map_err(unavailable)?;
        let opened = file.metadata().map_err(unavailable)?;
        if !opened.is_dir() || !same_identity(&before, &opened) {
            return Err(AdminError::BootstrapStoreUnavailable);
        }
        file.sync_all().map_err(unavailable)?;
        let named = fs::symlink_metadata(parent).map_err(unavailable)?;
        if !named.is_dir() || !same_identity(&opened, &named) {
            return Err(AdminError::BootstrapStoreUnavailable);
        }
        Ok(())
    }
}
