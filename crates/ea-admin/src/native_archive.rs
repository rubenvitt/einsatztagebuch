//! Native local storage admission. Paths are not authority or evidence.
use crate::operator_runtime::{
    OperatorRuntime, OperatorRuntimeError, writer::InteractiveOperatorRuntime,
};
use ea_archive::{
    ArchiveBackend, ArchiveBackendError, ArchiveBackendProfileV1, BoundArchiveProfilePolicyV1,
};
use ea_archive_fs::{
    ControlledNetworkBackend, ControlledNetworkLocalComponentV1, LocalCommitComponentV1,
    LocalPathBackend, SqlcipherArchiveBackend, SqliteCommitStore,
};
use ea_local_store::{EncryptedDatabase, StoreError, StoreValue};
use ea_types::Hash32;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

pub struct NativeArchiveConfig {
    pub profile: ArchiveBackendProfileV1,
    pub local_commit_database_path: Option<PathBuf>,
}

/// Errors retain the authority/backend boundary without disclosing host paths.
#[derive(Debug)]
pub enum NativeArchiveOpenError {
    Config,
    Runtime(OperatorRuntimeError),
    Backend(ArchiveBackendError),
}
impl From<OperatorRuntimeError> for NativeArchiveOpenError {
    fn from(error: OperatorRuntimeError) -> Self {
        Self::Runtime(error)
    }
}
impl From<ArchiveBackendError> for NativeArchiveOpenError {
    fn from(error: ArchiveBackendError) -> Self {
        Self::Backend(error)
    }
}
impl From<StoreError> for NativeArchiveOpenError {
    fn from(_: StoreError) -> Self {
        Self::Backend(ArchiveBackendError::Io)
    }
}

/// An existing local storage handle, never an active-profile pointer, complete
/// archive source, signature authority or permission to publish to a target.
/// The measured network carrier remains private: reconnect requires a separate
/// activation-pointer contract which this type deliberately does not provide.
pub struct NativeArchiveExistingComponent {
    backend: Box<dyn ArchiveBackend>,
    _component: Option<ControlledNetworkLocalComponentV1>,
    profile_hash: Hash32,
}
impl NativeArchiveExistingComponent {
    /// Uses actual Current readiness both before admission and before return.
    pub fn open_current(
        runtime: &OperatorRuntime,
        config: NativeArchiveConfig,
    ) -> Result<Self, NativeArchiveOpenError> {
        runtime.ensure_current()?;
        let opened = Self::open(
            runtime.database(),
            &runtime.config().archive_directory,
            runtime.anchor().trust_anchor_hash(),
            BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields()),
            config,
        )?;
        runtime.ensure_current()?;
        Ok(opened)
    }

    /// Preserves the Interactive runtime's Writer-only stale exception. This
    /// does not convert StaleWriter into general Current/admin authority.
    pub fn open_writer(
        runtime: &InteractiveOperatorRuntime,
        config: NativeArchiveConfig,
    ) -> Result<Self, NativeArchiveOpenError> {
        runtime.ensure_current()?;
        let opened = Self::open(
            runtime.database(),
            &runtime.config().archive_directory,
            runtime.anchor().trust_anchor_hash(),
            BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields()),
            config,
        )?;
        runtime.ensure_current()?;
        Ok(opened)
    }

    /// Only local storage primitives. Each later privileged operation still
    /// needs its own current authority; this handle grants none.
    pub fn local_backend(&self) -> &dyn ArchiveBackend {
        self.backend.as_ref()
    }
    pub fn profile_hash(&self) -> Hash32 {
        self.profile_hash
    }

    fn open(
        database: &Arc<EncryptedDatabase>,
        archive_directory: &Path,
        anchor: Hash32,
        policy: BoundArchiveProfilePolicyV1,
        config: NativeArchiveConfig,
    ) -> Result<Self, NativeArchiveOpenError> {
        let network = matches!(
            &config.profile,
            ArchiveBackendProfileV1::ControlledNetworkPath(_)
        );
        if network != config.local_commit_database_path.is_some() {
            return Err(NativeArchiveOpenError::Config);
        }
        let exact_profile = ea_format::encode_archive_backend_profile_core(&config.profile.core()?)
            .map_err(ArchiveBackendError::Format)?;
        let profile_hash = ea_crypto::archive_profile_digest(&exact_profile);
        policy.require(profile_hash)?;
        let ArchiveBackendProfileV1::ControlledNetworkPath(profile) = &config.profile else {
            // Compatible LocalPath behavior: this may materialize local format
            // files after policy admission, as the existing backend does.
            let backend =
                LocalPathBackend::open(archive_directory.to_owned(), config.profile, &policy)?;
            return Ok(Self {
                backend: Box::new(backend),
                _component: None,
                profile_hash,
            });
        };
        let configured_path = config
            .local_commit_database_path
            .as_ref()
            .ok_or(NativeArchiveOpenError::Config)?;
        let actual = std::fs::canonicalize(database.path()).map_err(|_| ArchiveBackendError::Io)?;
        let configured =
            std::fs::canonicalize(configured_path).map_err(|_| ArchiveBackendError::Io)?;
        if actual != configured {
            return Err(NativeArchiveOpenError::Config);
        }
        let namespace = ea_crypto::native_archive_component_namespace(anchor, profile_hash);
        let objects = i64::try_from(profile.queue_max_objects)
            .map_err(|_| ArchiveBackendError::MissingLocalCommitComponent)?;
        let bytes = i64::try_from(profile.queue_max_bytes)
            .map_err(|_| ArchiveBackendError::MissingLocalCommitComponent)?;
        // This transaction only reads. Never register a scope/binding or infer
        // first-use authority from absence, even under the stale Writer entry.
        database.transaction::<_, NativeArchiveOpenError>(|tx| {
            let migration = tx.query_row("SELECT count(*) FROM schema_migration WHERE version IN (16,26)", &[])?
                .ok_or(StoreError::Shape)?;
            if migration.integer(0)? != 2 { return Err(ArchiveBackendError::MissingLocalCommitComponent.into()); }
            let row = tx.query_row("SELECT profile_hash,namespace,exact_profile FROM native_archive_component WHERE anchor_hash=?1",
                &[StoreValue::Blob(anchor.as_bytes().to_vec())])?
                .ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
            if row.blob(0)? != profile_hash.as_bytes() || row.blob(1)? != namespace.as_bytes() || row.blob(2)? != exact_profile {
                return Err(ArchiveBackendError::ByteConflict.into());
            }
            let scope = tx.query_row("SELECT object_limit,byte_limit FROM local_commit_scope WHERE namespace=?1",
                &[StoreValue::Blob(namespace.as_bytes().to_vec())])?
                .ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
            if scope.integer(0)? != objects || scope.integer(1)? != bytes {
                return Err(ArchiveBackendError::ByteConflict.into());
            }
            Ok(())
        })?;
        let measurement = SqliteCommitStore::open_existing(
            database.clone(),
            namespace,
            profile.queue_max_objects,
            profile.queue_max_bytes,
        )?;
        let store = SqliteCommitStore::open_existing(
            database.clone(),
            namespace,
            profile.queue_max_objects,
            profile.queue_max_bytes,
        )?;
        // Validate the actual backend's durability before measuring at rest.
        let backend = SqlcipherArchiveBackend::open(store)?;
        let component = ControlledNetworkBackend::open_local_component(
            archive_directory.to_owned(),
            Some(LocalCommitComponentV1::new(actual, Box::new(measurement))),
            config.profile,
            &policy,
        )?;
        Ok(Self {
            backend: Box::new(backend),
            _component: Some(component),
            profile_hash,
        })
    }
}
