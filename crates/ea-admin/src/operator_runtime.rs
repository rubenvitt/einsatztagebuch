//! Native operator composition from one frozen, completely verified archive.
mod acquisition;
pub mod clock_repair;
pub(crate) mod destruction_authority;
pub mod prepared_diagnosis;
pub mod writer;
use crate::clock_release::{
    ClockReleaseAvailability, ClockReleaseService, ClockReleaseWorkflowError,
};
use crate::operator_exchange::ExchangeError;
use crate::{
    OperatorBindingService, OperatorLifecycleError, OperatorPresence, VerifiedLocalDeviceIdentity,
    VerifiedOperatorSession, VerifySessionRequest,
    native_provider::{
        NativeKeyProvider, NativeOperatorProvider, NativeProviderError, NativeSigningSlot,
    },
    operator_trust_store::OperatorTrustStateStore,
};
use ea_archive::{ArchiveBackendError, ArchiveInventory, ArchiveSource};
use ea_archive_fs::{SqlcipherArchiveBackend, SqliteCommitStore};
use ea_audit::{SignedLocalAuditService, SqliteLocalAuditRepository};
use ea_crypto::CanonicalPublicCoseKey;
use ea_format::{CertificateKindV1, DecodedTrustPayloadV1, KeyProtectionProfileV1, OperatorRoleV1};
use ea_key_provider::{
    DevicePostureProvider, DevicePostureReport, KeyError, KeyProvider, PostureRequirement,
    SecretPurpose, SupportMatrixRow,
};
use ea_local_store::{EncryptedDatabase, StoreError};
use ea_operator::{MAX_INACTIVITY_MS, OperatorError, OsAccountProvider, ReauthPurpose};
use ea_recovery::{ExitCode, FsArchiveSource, RecoveryError, exit_code_for, load_trust_anchor};
use ea_trust::{
    RegistryError, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError, TrustAnchorV1,
    TrustError, TrustStateKey, VerifiedTrust, load_trust_state, prepare_local_time,
    select_registry_head, verify_checkpoint_time, verify_receipt_time, verify_registry_candidate,
    verify_trust,
};
use ea_types::{CertificateHash, ChainSequence, DeviceId, Hash32, ObjectHash, UnixMillis};
use ea_verify::{VerificationReportV1, VerifyOptions, verify_archive};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CONFIG_LIMIT: usize = 65_536;

/// Errors expose stable codes only, never host paths, names, or helper responses.
pub enum OperatorRuntimeError {
    Config,
    Io,
    Archive,
    Sequence,
    SignerMismatch,
    Expired,
    DatabaseMissing,
    Posture,
    Recovery(RecoveryError),
    Verification(ExitCode),
    Trust(TrustError),
    Registry(RegistryError),
    State(StateStoreError),
    Store(StoreError),
    Key(KeyError),
    Native(NativeProviderError),
    Operator(OperatorError),
    Lifecycle(OperatorLifecycleError),
    Exchange(ExchangeError),
    /// Kaltstart eines registrierten Netzprofils ohne lesbares Netzziel
    /// (EA-CNA-SRC-4).
    NetworkArchiveUnavailable,
    /// Netzziel und lokale Komponente lassen sich nicht vereinigen
    /// (EA-CNA-SRC-2).
    NetworkArchiveConflict,
}
impl OperatorRuntimeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config => "EA-OPERATOR-CONFIG",
            Self::Io => "EA-OPERATOR-IO",
            Self::Archive => "EA-OPERATOR-ARCHIVE",
            Self::Sequence => "EA-OPERATOR-CHAIN-SEQUENCE",
            Self::SignerMismatch => "EA-OPERATOR-SIGNER-MISMATCH",
            Self::Expired => "EA-OPERATOR-RUNTIME-EXPIRED",
            Self::DatabaseMissing => "EA-OPERATOR-DATABASE-REQUIRED",
            Self::Posture => "EA-OPERATOR-POSTURE",
            Self::Verification(_) => "EA-OPERATOR-ARCHIVE-VERIFICATION",
            Self::Recovery(e) => e.code(),
            Self::Trust(e) => e.code(),
            Self::Registry(e) => e.code(),
            Self::State(e) => e.code(),
            Self::Store(e) => e.code(),
            Self::Key(e) => e.code(),
            Self::Exchange(e) => e.code(),
            Self::Native(e) => e.code(),
            Self::Operator(e) => e.code(),
            Self::Lifecycle(e) => e.code(),
            Self::NetworkArchiveUnavailable => "EA-OPERATOR-NETWORK-ARCHIVE-UNAVAILABLE",
            Self::NetworkArchiveConflict => "EA-OPERATOR-NETWORK-ARCHIVE-CONFLICT",
        }
    }
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Config => ExitCode::Usage,
            Self::DatabaseMissing
            | Self::Key(_)
            | Self::Store(StoreError::KeyRequired | StoreError::Key(_)) => ExitCode::Key,
            Self::Io
            | Self::Store(_)
            | Self::State(StateStoreError::Unavailable)
            | Self::NetworkArchiveUnavailable
            | Self::Exchange(ExchangeError::Io | ExchangeError::Timeout) => ExitCode::Io,
            Self::Sequence => ExitCode::Chain,
            Self::Archive | Self::NetworkArchiveConflict => ExitCode::Integrity,
            Self::Recovery(e) => ea_recovery::exit_code_for_error(e),
            Self::Verification(code) => *code,
            _ => ExitCode::Trust,
        }
    }
}
impl fmt::Display for OperatorRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl fmt::Debug for OperatorRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for OperatorRuntimeError {}
macro_rules! error_from { ($($ty:ty => $variant:ident),* $(,)?) => { $(impl From<$ty> for OperatorRuntimeError { fn from(e: $ty) -> Self { Self::$variant(e) } })* }; }
error_from!(RecoveryError => Recovery, TrustError => Trust, RegistryError => Registry,
    StateStoreError => State, StoreError => Store, KeyError => Key, NativeProviderError => Native,
    OperatorError => Operator, OperatorLifecycleError => Lifecycle, ExchangeError => Exchange);

/// Public references only. Relative paths in a file resolve beside that file.
#[derive(Clone)]
pub struct OperatorRuntimeConfig {
    pub archive_directory: PathBuf,
    pub database_path: PathBuf,
    pub device_certificate_hash: CertificateHash,
    pub binding_object_hash: ObjectHash,
    pub role: OperatorRoleV1,
    pub purpose: ReauthPurpose,
    pub admin_certificate_hash: Option<CertificateHash>,
    pub admin_binding_object_hash: Option<ObjectHash>,
    pub ceremony_exchange_directory: Option<PathBuf>,
    pub authority: bool,
    pub target_certificate_hash: Option<CertificateHash>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfig {
    archive_directory: PathBuf,
    database_path: PathBuf,
    device_certificate_hash: String,
    binding_object_hash: String,
    role: String,
    purpose: String,
    admin_certificate_hash: Option<String>,
    admin_binding_object_hash: Option<String>,
    ceremony_exchange_directory: Option<PathBuf>,
    #[serde(default)]
    authority: bool,
    target_certificate_hash: Option<String>,
}
impl OperatorRuntimeConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self, OperatorRuntimeError> {
        if bytes.len() > CONFIG_LIMIT {
            return Err(OperatorRuntimeError::Config);
        }
        let wire: WireConfig =
            serde_json::from_slice(bytes).map_err(|_| OperatorRuntimeError::Config)?;
        let role = match wire.role.as_str() {
            "writer" => OperatorRoleV1::Writer,
            "organization-admin" => OperatorRoleV1::OrganizationAdmin,
            _ => return Err(OperatorRuntimeError::Config),
        };
        let purpose = ReauthPurpose::ALL
            .into_iter()
            .find(|p| p.label() == wire.purpose)
            .ok_or(OperatorRuntimeError::Config)?;
        if wire.archive_directory.as_os_str().is_empty()
            || wire.database_path.as_os_str().is_empty()
            || wire
                .ceremony_exchange_directory
                .as_ref()
                .is_some_and(|p| p.as_os_str().is_empty())
            || wire.admin_certificate_hash.is_some() != wire.admin_binding_object_hash.is_some()
            || (wire.authority
                && (role != OperatorRoleV1::OrganizationAdmin
                    || wire.target_certificate_hash.is_none()))
        {
            return Err(OperatorRuntimeError::Config);
        }
        Ok(Self {
            archive_directory: wire.archive_directory,
            database_path: wire.database_path,
            device_certificate_hash: CertificateHash::from(parse_hash(
                &wire.device_certificate_hash,
            )?),
            binding_object_hash: parse_hash(&wire.binding_object_hash)?,
            role,
            purpose,
            admin_certificate_hash: wire
                .admin_certificate_hash
                .as_deref()
                .map(parse_hash)
                .transpose()?
                .map(CertificateHash::from),
            admin_binding_object_hash: wire
                .admin_binding_object_hash
                .as_deref()
                .map(parse_hash)
                .transpose()?,
            ceremony_exchange_directory: wire.ceremony_exchange_directory,
            authority: wire.authority,
            target_certificate_hash: wire
                .target_certificate_hash
                .as_deref()
                .map(parse_hash)
                .transpose()?
                .map(CertificateHash::from),
        })
    }
    pub fn load(path: &Path) -> Result<Self, OperatorRuntimeError> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| OperatorRuntimeError::Io)?
            .take((CONFIG_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| OperatorRuntimeError::Io)?;
        let mut config = Self::from_json(&bytes)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for item in [&mut config.archive_directory, &mut config.database_path] {
            if item.is_relative() {
                *item = base.join(&*item);
            }
        }
        if let Some(path) = &mut config.ceremony_exchange_directory
            && path.is_relative()
        {
            *path = base.join(&*path);
        }
        Ok(config)
    }
}
fn parse_hash(value: &str) -> Result<ObjectHash, OperatorRuntimeError> {
    if value.len() != 64 {
        return Err(OperatorRuntimeError::Config);
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| OperatorRuntimeError::Config)?;
    ObjectHash::try_from(bytes.as_slice()).map_err(|_| OperatorRuntimeError::Config)
}

/// One immutable input: report, chain head, inventory and subsequent trust
/// resolution all read these exact bytes, even if the directory changes later.
pub struct OperatorArchiveSnapshot {
    source: FsArchiveSource,
    anchor: TrustAnchorV1,
    inventory: ArchiveInventory,
    report: VerificationReportV1,
    next_sequence: ChainSequence,
    remote_baseline: Option<Arc<FsArchiveSource>>,
    /// Nur wahr, wenn DIESE Öffnung das Netzziel live gelesen hat — nie für
    /// eine geerbte Grundlinie (EA-CNA-SRC-4/5).
    remote_read_live: bool,
}
impl OperatorArchiveSnapshot {
    pub fn open(
        directory: &Path,
        anchor_path: &Path,
        now: UnixMillis,
    ) -> Result<Self, OperatorRuntimeError> {
        let anchor = load_trust_anchor(anchor_path)?;
        let (_, directory) = anchor_outside_archive(directory, anchor_path)?;
        let directory = directory.ok_or(OperatorRuntimeError::Io)?;
        Self::open_with_anchor(&directory, anchor, now, None, None)
    }

    /// Ohne `component` wie bisher genau das committed Netz- bzw. lokale
    /// Verzeichnis. Mit `component` die Vereinigung aus dem Netzziel und der
    /// committed Sicht der lokalen Komponente (EA-CNA-SRC-2); ist das
    /// Netzziel nicht lesbar, tritt nur eine übergebene Grundlinie an seine
    /// Stelle (EA-CNA-SRC-4). Beides ist ungeprüfte Eingabe desselben
    /// Verifiers (EA-CNA-SRC-3); eine Policy wird hier bewusst nicht geprüft.
    pub(crate) fn open_with_anchor(
        directory: &Path,
        anchor: TrustAnchorV1,
        now: UnixMillis,
        component: Option<&dyn ArchiveSource>,
        baseline: Option<Arc<FsArchiveSource>>,
    ) -> Result<Self, OperatorRuntimeError> {
        let mut remote_read_live = false;
        let (source, remote_baseline) = match component {
            None => (FsArchiveSource::open_committed(directory)?, None),
            Some(component) => {
                let remote = match FsArchiveSource::open_committed(directory) {
                    Ok(remote) => {
                        remote_read_live = true;
                        Arc::new(remote)
                    }
                    // EA-CNA-SRC-4: nur eine Grundlinie DESSELBEN kanonischen
                    // Ziels tritt an seine Stelle.
                    Err(_) => baseline
                        .filter(|baseline| baseline.root() == directory)
                        .ok_or(OperatorRuntimeError::NetworkArchiveUnavailable)?,
                };
                // Die Grundlinie bleibt die unveränderte Netzsicht; vereinigt
                // wird eine Kopie, nie die Grundlinie selbst.
                let union = remote
                    .committed_view()
                    .with_exact_component(component)
                    .map_err(|error| match error {
                        ArchiveBackendError::ByteConflict
                        | ArchiveBackendError::Path
                        | ArchiveBackendError::InventoryMismatch => {
                            OperatorRuntimeError::NetworkArchiveConflict
                        }
                        _ => OperatorRuntimeError::Archive,
                    })?;
                (union, Some(remote))
            }
        };
        let report = verify_archive(&source, &anchor, VerifyOptions::new(now))
            .map_err(|_| OperatorRuntimeError::Archive)?;
        // Operator authority needs authenticated public manifest progression.
        // Destruction completion additionally needs encrypted Evidence and is
        // deliberately not inferred from this narrow verifier proof.
        let chain_head = report
            .verified_public_chain_head()
            .ok_or_else(|| OperatorRuntimeError::Verification(exit_code_for(&report)))?;
        if chain_head.entry_hash().as_bytes() == &[0; 32]
            || report.entry_package_count() + report.destroyed_entry_count() == 0
        {
            return Err(OperatorRuntimeError::Sequence);
        }
        let next_sequence = ChainSequence::new(
            chain_head
                .sequence()
                .get()
                .checked_add(1)
                .ok_or(OperatorRuntimeError::Sequence)?,
        );
        let inventory =
            ArchiveInventory::build(&source).map_err(|_| OperatorRuntimeError::Archive)?;
        Ok(Self {
            source,
            anchor,
            inventory,
            report,
            next_sequence,
            remote_baseline,
            remote_read_live,
        })
    }
    pub fn next_sequence(&self) -> ChainSequence {
        self.next_sequence
    }
    pub fn inventory(&self) -> &ArchiveInventory {
        &self.inventory
    }
    pub fn anchor(&self) -> &TrustAnchorV1 {
        &self.anchor
    }
    pub fn report(&self) -> &VerificationReportV1 {
        &self.report
    }
    pub fn source(&self) -> &FsArchiveSource {
        &self.source
    }
    /// Remote committed view actually used (live or baseline); None for LocalPath.
    pub fn remote_baseline(&self) -> Option<&Arc<FsArchiveSource>> {
        self.remote_baseline.as_ref()
    }
}

/// EA-CNA-SRC-5 mit den Regeln der Fix-Runde 1 zu Task 8.
///
/// Bereinigt wird nur nach bestandener Verifikation, nur wenn DIESE Öffnung
/// das Netzziel live gelesen hat, nur unter dem per `try_lock` erlangten
/// SQLCipher-Writer-Lock und nur, was
///
/// - (i) live UND in der GEERBTEN Grundlinie dieser Öffnung bytegleich liegt.
///   Die geerbte Grundlinie ist die der Laufzeit, die der Aufrufer behält,
///   falls er diese Öffnung verwirft (`NativeState::refresh` tut das im
///   Vorschau-Zweig und bei jedem späteren Fehler). Ein Kaltstart erbt keine
///   Grundlinie und bereinigt deshalb nie;
/// - (ii) nicht der lokal höchste `.eip` oder einer seiner Grants ist (im
///   Primitiv `prune_published` durchgesetzt).
///
/// Die Bereinigung ist Aufräumen: jeder Fehler lässt sie ausfallen, nie die
/// Öffnung.
fn prune_published_rows(
    component: &SqlcipherArchiveBackend,
    snapshot: &OperatorArchiveSnapshot,
    inherited: Option<&FsArchiveSource>,
) {
    let (true, Some(live), Some(inherited)) = (
        snapshot.remote_read_live,
        snapshot.remote_baseline(),
        inherited,
    ) else {
        return;
    };
    let mut live_hashes = std::collections::HashMap::new();
    if live
        .visit_blobs(&mut |blob| {
            live_hashes.insert(
                blob.path_hint().to_owned(),
                ea_crypto::object_hash(blob.bytes()),
            );
            Ok(())
        })
        .is_err()
    {
        return;
    }
    let kept = KeptBaselineView {
        inherited,
        live: live_hashes,
    };
    if let Ok(Some(lock)) = component.try_writer_lock() {
        let _ = component.prune_published(&kept, &lock);
    }
}

/// Die geerbte Grundlinie, eingeschränkt auf das, was das Netzziel in dieser
/// Öffnung live bytegleich trägt.
struct KeptBaselineView<'a> {
    inherited: &'a FsArchiveSource,
    live: std::collections::HashMap<String, ObjectHash>,
}
impl ArchiveSource for KeptBaselineView<'_> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(
            ea_archive::ArchiveBlob<'_>,
        ) -> Result<(), ea_archive::ArchiveError>,
    ) -> Result<(), ea_archive::ArchiveError> {
        self.inherited.visit_blobs(&mut |blob| {
            if self
                .live
                .get(blob.path_hint())
                .is_some_and(|hash| *hash == ea_crypto::object_hash(blob.bytes()))
            {
                visitor(blob)
            } else {
                Ok(())
            }
        })
    }
}

/// Der kanonische Anker darf nicht im Archiv liegen. Das Verzeichnis wird nur
/// geliefert, wenn es sich kanonisieren lässt: ob ein fehlendes Verzeichnis
/// ein Fehler ist, entscheidet erst die Registrierung (EA-CNA-SRC-4).
fn anchor_outside_archive(
    directory: &Path,
    anchor_path: &Path,
) -> Result<(PathBuf, Option<PathBuf>), OperatorRuntimeError> {
    let directory = directory.canonicalize();
    let anchor_path = anchor_path
        .canonicalize()
        .map_err(|_| OperatorRuntimeError::Io)?;
    let directory = directory.ok();
    if directory
        .as_ref()
        .is_some_and(|directory| anchor_path.starts_with(directory))
    {
        return Err(OperatorRuntimeError::Config);
    }
    Ok((anchor_path, directory))
}

pub mod posture;

/// Runtime keys and local data are deliberately absent from Debug/Serialize.
pub struct OperatorRuntime {
    config: OperatorRuntimeConfig,
    snapshot: OperatorArchiveSnapshot,
    native: Arc<NativeOperatorProvider>,
    database: Arc<EncryptedDatabase>,
    store: OperatorTrustStateStore,
    head: SelectedRegistryHead,
    trust: VerifiedTrust,
    signer: Arc<NativeKeyProvider>,
    local_device: VerifiedLocalDeviceIdentity,
    device_id: DeviceId,
    account_hash: Hash32,
    opened: Instant,
    anchor_path: PathBuf,
    posture: Arc<dyn DevicePostureProvider>,
}
impl OperatorRuntime {
    /// Only provision may initialize native installation state and an absent DB.
    /// Existing DBs and every login require an existing native database key.
    pub fn open(
        config: OperatorRuntimeConfig,
        anchor_path: &Path,
        now: UnixMillis,
        initialize_native: bool,
    ) -> Result<Self, OperatorRuntimeError> {
        Self::open_using(
            config,
            anchor_path,
            now,
            initialize_native,
            NativeOperatorProvider::open_installed,
            Arc::from(
                SupportMatrixRow::current_host()
                    .ok_or(OperatorRuntimeError::Posture)?
                    .posture_provider(),
            ),
        )
    }

    /// Explicit composition port for a separate fixture executable. The normal
    /// CLI always calls `open`, including builds with unified test features.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_with_test_native(
        config: OperatorRuntimeConfig,
        anchor_path: &Path,
        now: UnixMillis,
        initialize_native: bool,
        native: Arc<NativeOperatorProvider>,
    ) -> Result<Self, OperatorRuntimeError> {
        Self::open_with_test_native_and_posture(
            config,
            anchor_path,
            now,
            initialize_native,
            native,
            Arc::new(FixturePassingPosture),
        )
    }

    /// Fixture-only injection. The installed production path always chooses the
    /// actual host adapter and cannot select a report from config or environment.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_with_test_native_and_posture(
        config: OperatorRuntimeConfig,
        anchor_path: &Path,
        now: UnixMillis,
        initialize_native: bool,
        native: Arc<NativeOperatorProvider>,
        posture: Arc<dyn DevicePostureProvider>,
    ) -> Result<Self, OperatorRuntimeError> {
        Self::open_using(
            config,
            anchor_path,
            now,
            initialize_native,
            |_| Ok(native),
            posture,
        )
    }

    fn open_using(
        config: OperatorRuntimeConfig,
        anchor_path: &Path,
        now: UnixMillis,
        initialize_native: bool,
        open_native: impl FnOnce(bool) -> Result<Arc<NativeOperatorProvider>, NativeProviderError>,
        posture: Arc<dyn DevicePostureProvider>,
    ) -> Result<Self, OperatorRuntimeError> {
        Self::acquire_using(
            config,
            anchor_path,
            acquisition::AcquisitionTime::Explicit(now),
            initialize_native,
            open_native,
            posture,
            None,
        )
    }

    fn acquire_using(
        config: OperatorRuntimeConfig,
        anchor_path: &Path,
        time: acquisition::AcquisitionTime,
        initialize_native: bool,
        open_native: impl FnOnce(bool) -> Result<Arc<NativeOperatorProvider>, NativeProviderError>,
        posture: Arc<dyn DevicePostureProvider>,
        baseline: Option<Arc<FsArchiveSource>>,
    ) -> Result<Self, OperatorRuntimeError> {
        // Provisioning can create keys with native presence. It retains its
        // existing explicit-time path outside this pure read/acquire gate.
        if initialize_native {
            return Self::open_without_acquisition(
                config,
                anchor_path,
                time.value()?,
                true,
                open_native,
                posture,
                baseline,
            );
        }
        let path = config.database_path.clone();
        acquisition::acquire(&path, time, |now| {
            Self::open_without_acquisition(
                config,
                anchor_path,
                now,
                false,
                open_native,
                posture,
                baseline,
            )
        })
    }

    fn open_without_acquisition(
        config: OperatorRuntimeConfig,
        anchor_path: &Path,
        now: UnixMillis,
        initialize_native: bool,
        open_native: impl FnOnce(bool) -> Result<Arc<NativeOperatorProvider>, NativeProviderError>,
        posture: Arc<dyn DevicePostureProvider>,
        baseline: Option<Arc<FsArchiveSource>>,
    ) -> Result<Self, OperatorRuntimeError> {
        #[cfg(feature = "test-support")]
        let profile = runtime_profile::Span::start("acquire", config.role, None);
        let RuntimeResources {
            config,
            snapshot,
            native,
            database,
            mut store,
            signer,
            device_id,
            opened,
            anchor_path: owned_anchor_path,
            posture,
        } = open_resources(
            config,
            anchor_path,
            now,
            initialize_native,
            open_native,
            posture,
            baseline,
        )?;
        #[cfg(feature = "test-support")]
        if let Some(profile) = &profile {
            profile.mark("resources-return");
        }
        let key = TrustStateKey {
            organization_id: snapshot.anchor.organization_id(),
            device_id,
        };
        let slot = role_slot(config.role)?;
        let (head, trust) = select_current(&snapshot, &mut store, key, now)?;
        #[cfg(feature = "test-support")]
        if let Some(profile) = &profile {
            profile.mark("select-return");
        }
        let public = native
            .public_key(slot)?
            .ok_or(OperatorRuntimeError::SignerMismatch)?;
        let local_device = verify_local_signing_identity(
            &head,
            config.device_certificate_hash,
            config.role,
            &public,
        )?;
        let account_hash = native.os_account_binding_hash(key.organization_id, device_id)?;
        let runtime = Self {
            config,
            snapshot,
            native,
            database,
            store,
            head,
            trust,
            signer,
            local_device,
            device_id,
            account_hash,
            opened,
            anchor_path: owned_anchor_path,
            posture,
        };
        // Opening a read-only diagnostic context must remain possible when the
        // measured posture is unresolved. Privileged consumers use ensure_current.
        runtime.ensure_fresh_context()?;
        #[cfg(feature = "test-support")]
        if let Some(profile) = &profile {
            profile.mark("identity-return");
        }
        Ok(runtime)
    }
    pub fn config(&self) -> &OperatorRuntimeConfig {
        &self.config
    }
    pub fn native(&self) -> &Arc<NativeOperatorProvider> {
        &self.native
    }
    pub fn database(&self) -> &Arc<EncryptedDatabase> {
        &self.database
    }
    pub fn head(&self) -> &SelectedRegistryHead {
        &self.head
    }
    pub fn trust(&self) -> &VerifiedTrust {
        &self.trust
    }
    pub fn trust_store_mut(&mut self) -> &mut OperatorTrustStateStore {
        &mut self.store
    }
    pub fn trust_store(&self) -> &OperatorTrustStateStore {
        &self.store
    }
    pub fn inventory(&self) -> &ArchiveInventory {
        self.snapshot.inventory()
    }
    pub fn anchor(&self) -> &TrustAnchorV1 {
        self.snapshot.anchor()
    }
    pub fn next_sequence(&self) -> ChainSequence {
        self.snapshot.next_sequence()
    }
    pub fn archive_snapshot(&self) -> &OperatorArchiveSnapshot {
        &self.snapshot
    }
    pub fn signing_provider(&self) -> &Arc<NativeKeyProvider> {
        &self.signer
    }
    pub fn local_device(&self) -> VerifiedLocalDeviceIdentity {
        self.local_device
    }
    /// Native presence bounded before and after the OS dialog, so a caller's
    /// lifecycle service cannot write a successful audit after this head expires.
    pub fn presence(&self) -> impl OperatorPresence + '_ {
        BoundedPresence(self)
    }
    pub fn trust_and_store(&mut self) -> (&VerifiedTrust, &mut OperatorTrustStateStore) {
        (&self.trust, &mut self.store)
    }

    /// Call before/after every blocking exchange or privileged operation. Expired
    /// contexts must be reopened and reauthenticated; old frozen time is not renewed.
    pub fn ensure_current(&self) -> Result<(), OperatorRuntimeError> {
        self.posture_admission()?;
        self.ensure_fresh_context()?;
        Ok(())
    }

    pub(crate) fn ensure_same_action_authority(&self) -> Result<(), OperatorRuntimeError> {
        self.ensure_current()?;
        let fresh = self.reopened_for_action()?;
        fresh.ensure_current()?;
        self.ensure_same_authority_as(&fresh)
    }

    pub(crate) fn ensure_same_authority_as(
        &self,
        fresh: &Self,
    ) -> Result<(), OperatorRuntimeError> {
        if fresh.head.registry_head_hash() != self.head.registry_head_hash()
            || fresh.head.registry_version() != self.head.registry_version()
            || fresh.next_sequence() != self.next_sequence()
            || fresh.account_hash != self.account_hash
            || !fresh
                .head
                .preexisting_effective_now()
                .has_same_persisted_bounds(self.head.preexisting_effective_now())
        {
            return Err(OperatorError::ProofMismatch.into());
        }
        Ok(())
    }

    pub fn device_posture_report(&self) -> Result<DevicePostureReport, OperatorRuntimeError> {
        self.posture
            .report()
            .map_err(|_| OperatorRuntimeError::Posture)
    }

    fn ensure_fresh_context(&self) -> Result<(), OperatorRuntimeError> {
        let fresh = fresh_wall_clock()?;
        validate_freshness(
            self.opened.elapsed(),
            fresh,
            self.head.preexisting_effective_now().value(),
            self.head.not_after(),
        )?;
        if self
            .native
            .os_account_binding_hash(self.anchor().organization_id(), self.device_id)?
            != self.account_hash
        {
            return Err(OperatorError::AccountMismatch.into());
        }
        Ok(())
    }
    pub fn audit_service(&self) -> SignedLocalAuditService {
        SignedLocalAuditService::new(
            Arc::new(SqliteLocalAuditRepository::new(Arc::clone(&self.database))),
            self.signer.clone(),
            self.signer.handle(SecretPurpose::WriterSigningKey),
            ObjectHash::try_from(self.config.device_certificate_hash.as_bytes().as_slice())
                .expect("certificate hashes are 32 bytes"),
            self.head.preexisting_effective_now().value(),
        )
    }
    /// The three clock-release availabilities, asked instead of inferred.
    ///
    /// This is the only entry point to `ClockReleaseService::availability` from
    /// outside this crate. That call needs an `ea_time::TrustedTimeState`, and
    /// the persisted state is reachable only through
    /// `ea_trust::TrustStateStore`; a caller without an `ea-trust` edge — the
    /// recovery CLI, deliberately — cannot name either type. The read therefore
    /// happens here, and only the three-variant
    /// [`ClockReleaseAvailability`] leaves the crate. No `ea-trust` or
    /// `ea-time` type appears in this signature.
    ///
    /// The mapping from the time evaluation stays where it already is; this
    /// method adds no second reading of a clock and no threshold of its own.
    ///
    /// The store clone shares this runtime's `Arc<EncryptedDatabase>` and so
    /// reads the live row. It exists only because `TrustStateStore::load` takes
    /// `&mut self` for the sake of its committing siblings; the load itself is
    /// a SELECT and commits nothing.
    ///
    /// A `&self` accessor carries no freshness gate, exactly like `head` and
    /// `trust`. Callers that act on the answer must bracket it with
    /// [`Self::ensure_current`].
    ///
    /// # Errors
    ///
    /// The pass-through code of the persisted trust state (`EA-TRUST-STATE-*`)
    /// or of the time evaluation.
    pub fn clock_release_availability(
        &self,
        now: UnixMillis,
    ) -> Result<ClockReleaseAvailability, ClockReleaseWorkflowError> {
        let mut store = self.store.clone();
        let snapshot = load_trust_state(
            &mut store,
            TrustStateKey {
                organization_id: self.anchor().organization_id(),
                device_id: self.device_id,
            },
        )?;
        let audit = self.audit_service();
        ClockReleaseService::new(&self.head, &audit, self.config.binding_object_hash)
            .availability(snapshot.trusted_time(), now)
    }
    pub fn reauthenticate(&self) -> Result<VerifiedOperatorSession, OperatorRuntimeError> {
        self.reauthenticate_for(self.config.purpose)
    }

    /// Re-resolve current archive authority without renewing the native watcher.
    /// A locked provider still fails; only an explicit new login may replace it.
    pub fn refresh_for_action(&mut self) -> Result<(), OperatorRuntimeError> {
        *self = self.reopened_for_action()?;
        Ok(())
    }

    /// Fresh independent authority check while a host retains an exact preview
    /// and its original selected time. This never renews the native watcher.
    #[cfg_attr(feature = "test-support", track_caller)]
    pub fn reopened_for_action(&self) -> Result<Self, OperatorRuntimeError> {
        #[cfg(feature = "test-support")]
        let _profile = runtime_profile::Span::start(
            "reopen",
            self.config.role,
            Some(std::panic::Location::caller()),
        );
        self.native.ensure_session_active()?;
        Self::acquire_using(
            self.config.clone(),
            &self.anchor_path,
            acquisition::AcquisitionTime::FreshWallClock,
            false,
            |_| Ok(Arc::clone(&self.native)),
            Arc::clone(&self.posture),
            // EA-CNA-SRC-4: nur diese Wiederöffnung darf die zuletzt live
            // gelesene Netzsicht statt eines unlesbaren Netzziels nehmen.
            self.archive_snapshot().remote_baseline().cloned(),
        )
    }

    /// The action selects its exact existing purpose; configuration cannot
    /// substitute a proof for another action.
    pub fn reauthenticate_for(
        &self,
        purpose: ReauthPurpose,
    ) -> Result<VerifiedOperatorSession, OperatorRuntimeError> {
        self.reauthenticate_with_context(purpose, None)
    }

    pub fn reauthenticate_for_context(
        &self,
        purpose: ReauthPurpose,
        context: Hash32,
    ) -> Result<VerifiedOperatorSession, OperatorRuntimeError> {
        self.reauthenticate_with_context(purpose, Some(context))
    }

    fn reauthenticate_with_context(
        &self,
        purpose: ReauthPurpose,
        context: Option<Hash32>,
    ) -> Result<VerifiedOperatorSession, OperatorRuntimeError> {
        if purpose == ReauthPurpose::GoLivePostureDocumentation {
            return Err(OperatorRuntimeError::Posture);
        }
        // AK 53 (DRK-282): eine abgelaufene Sitzung wird VOR der Abweisung
        // klartextfrei gebucht. Nur hier und nicht in `ensure_current` selbst:
        // das läuft je Aktion mehrfach (auch zweimal in der Präsenzfrist) und
        // buchte sonst mehrere Zeilen für eine einzige Abweisung.
        refuse_expired_after_audit(self.ensure_current(), || {
            // Fail-closed: scheitert die Buchung, bleibt es bei der Abweisung
            // mit ihrem unveränderten Code.
            let _ = self.record_session_expired();
        })?;
        let audit = self.audit_service();
        let presence = BoundedPresence(self);
        let service = OperatorBindingService::new(&self.head, &audit, self.local_device);
        let request = VerifySessionRequest {
            database: &self.database,
            binding_object_hash: self.config.binding_object_hash,
            device_certificate_hash: self.config.device_certificate_hash,
            role: self.config.role,
            purpose,
            account: self.native.clone(),
            authenticator: &presence,
        };
        let session = match context {
            Some(context) => service.verify_session_for_context(request, context),
            None => service.verify_session(request),
        }?;
        self.ensure_same_action_authority()?;
        self.native.record_verified_session(&session)?;
        Ok(session)
    }
    /// Bucht `sessionExpired` unter dem geprüften Gerät, am gewählten Kopf und
    /// mit der Gerätesignatur dieser Laufzeit (DRK-282, AK 53).
    fn record_session_expired(&self) -> Result<(), OperatorLifecycleError> {
        let audit = self.audit_service();
        OperatorBindingService::new(&self.head, &audit, self.local_device).record_session_expired(
            self.config.binding_object_hash,
            self.config.device_certificate_hash,
        )
    }
    /// Reload published bytes with the same independent anchor and persistent
    /// database. Previous session proofs are not reused; call verify_session next.
    pub fn refresh_with_binding(
        &mut self,
        binding: ObjectHash,
    ) -> Result<(), OperatorRuntimeError> {
        self.ensure_current()?;
        let mut config = self.config.clone();
        config.binding_object_hash = binding;
        let now = fresh_wall_clock()?;
        // Preserve the validated native provider and its continuous watcher.
        // Reopening a snapshot cannot clear an invalidated native session.
        let refreshed = Self::open_using(
            config,
            &self.anchor_path,
            now,
            false,
            |_| Ok(Arc::clone(&self.native)),
            Arc::clone(&self.posture),
        )?;
        *self = refreshed;
        Ok(())
    }
    pub fn go_live_report(&self) -> Result<OperatorGoLiveReport, OperatorRuntimeError> {
        self.go_live_report_for(self.config.binding_object_hash)
    }
    pub fn verify_session(&self) -> Result<OperatorGoLiveReport, OperatorRuntimeError> {
        let session = self.reauthenticate()?;
        self.go_live_report_for(session.proof().binding_object_hash())
    }
    fn verify_bound_operator_identity(
        &self,
        binding: ObjectHash,
    ) -> Result<&ea_format::OperatorBindingFieldsV1, OperatorRuntimeError> {
        let fields = self
            .head
            .active_operator_binding_fields(binding)
            .ok_or(OperatorError::BindingNotActive)?;
        if fields.device_certificate_hash != self.config.device_certificate_hash
            || fields.operator_role != self.config.role
        {
            return Err(OperatorRuntimeError::SignerMismatch);
        }
        let account_hash = self
            .native
            .os_account_binding_hash(self.anchor().organization_id(), self.device_id)?;
        if account_hash != fields.os_account_binding_hash {
            return Err(OperatorError::AccountMismatch.into());
        }
        let instance_key = self
            .native
            .operator_instance_public_key()?
            .ok_or(OperatorError::InstanceKeyMissing)?;
        if instance_key.thumbprint() != fields.operator_instance_key_thumbprint {
            return Err(OperatorError::InstanceKeyMismatch.into());
        }
        Ok(fields)
    }
    fn go_live_report_for(
        &self,
        binding: ObjectHash,
    ) -> Result<OperatorGoLiveReport, OperatorRuntimeError> {
        self.ensure_fresh_context()?;
        let fields = self.verify_bound_operator_identity(binding)?;
        let account_hash = fields.os_account_binding_hash;
        let profile = crate::operator_profile::load(&self.database)?
            .ok_or(OperatorLifecycleError::ProfileMissing)?;
        if profile.operator_binding_object_hash() != binding {
            return Err(OperatorLifecycleError::ProfileCommitment.into());
        }
        crate::verify_operator_snapshot(&profile, fields)?;
        self.ensure_fresh_context()?;
        let posture = self.device_posture_report()?;
        let admission = self.posture_admission_for_report().ok();
        Ok(OperatorGoLiveReport {
            device_posture_evidence: PostureRequirement::ALL
                .into_iter()
                .map(|requirement| posture.check(requirement).evidence_code())
                .collect(),
            session_admitted: admission.is_some(),
            documented_posture: admission
                .as_ref()
                .and_then(PostureDocumentationReport::from_admission),
            binding_state: "active",
            productive_binding_hashes: vec![hex::encode(binding.as_bytes())],
            revoked_binding_hashes: Vec::new(),
            device_certificate_hash: hex::encode(self.config.device_certificate_hash.as_bytes()),
            role: role_label(self.config.role),
            os_account_binding_hash: hex::encode(account_hash.as_bytes()),
            current_native_account_match: true,
            registry_head_hash: hex::encode(self.head.registry_head_hash().as_bytes()),
            next_sequence: self.next_sequence().get(),
            revocation_procedure: "Run operator revoke with the independently verified anchor and this public operator config; complete the authenticated offline Admin/Root exchange, publish its signed registry event, and verify that this binding is inactive before replacement.",
        })
    }
    /// Confirms this device's revocation from the fresh, selected registry head.
    /// This result makes no assertion that a session or binding is active.
    pub fn revocation_report(
        &self,
        binding: ObjectHash,
    ) -> Result<OperatorGoLiveReport, OperatorRuntimeError> {
        self.ensure_fresh_context()?;
        let fields = self
            .head
            .revoked_operator_binding_fields(binding)
            .ok_or(OperatorError::BindingNotActive)?;
        if fields.device_certificate_hash != self.config.device_certificate_hash
            || fields.operator_role != self.config.role
        {
            return Err(OperatorRuntimeError::SignerMismatch);
        }
        let account_hash = self
            .native
            .os_account_binding_hash(self.anchor().organization_id(), self.device_id)?;
        self.ensure_fresh_context()?;
        let posture = self.device_posture_report()?;
        Ok(OperatorGoLiveReport {
            device_posture_evidence: PostureRequirement::ALL
                .into_iter()
                .map(|requirement| posture.check(requirement).evidence_code())
                .collect(),
            session_admitted: false,
            documented_posture: None,
            binding_state: "revoked",
            productive_binding_hashes: Vec::new(),
            revoked_binding_hashes: vec![hex::encode(binding.as_bytes())],
            device_certificate_hash: hex::encode(self.config.device_certificate_hash.as_bytes()),
            role: role_label(self.config.role),
            os_account_binding_hash: hex::encode(account_hash.as_bytes()),
            current_native_account_match: account_hash == fields.os_account_binding_hash,
            registry_head_hash: hex::encode(self.head.registry_head_hash().as_bytes()),
            next_sequence: self.next_sequence().get(),
            revocation_procedure: "The selected registry head confirms this binding is revoked. Distribute the signed revocation to all archive replicas and complete the authenticated offline Admin/Root ceremony before activating a replacement binding.",
        })
    }
}

struct BoundedPresence<'a>(&'a OperatorRuntime);
impl OperatorPresence for BoundedPresence<'_> {
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        prove_with_deadline(self.0.native.as_ref(), challenge, || {
            self.0.ensure_same_action_authority()
        })
    }
}
fn prove_with_deadline(
    presence: &dyn OperatorPresence,
    challenge: &[u8],
    check: impl Fn() -> Result<(), OperatorRuntimeError>,
) -> Result<[u8; 64], OperatorError> {
    check().map_err(|_| OperatorError::ProofMismatch)?;
    let signature = presence.prove_presence_and_sign(challenge)?;
    // Runs before the service can emit a successful Login audit.
    check().map_err(|_| OperatorError::ProofMismatch)?;
    Ok(signature)
}
pub(crate) fn fresh_wall_clock() -> Result<UnixMillis, OperatorRuntimeError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OperatorRuntimeError::Expired)?;
    Ok(UnixMillis::new(
        i64::try_from(now.as_millis()).map_err(|_| OperatorRuntimeError::Expired)?,
    ))
}
/// Bucht genau dann, wenn die Prüfung einen ABLAUF meldet, und genau einmal;
/// danach wird das unveränderte Ergebnis zurückgegeben. Andere Befunde
/// (Haltung, Kontowechsel, Konfiguration) sind kein Ablauf und werden hier
/// nicht als solcher beschriftet.
fn refuse_expired_after_audit(
    checked: Result<(), OperatorRuntimeError>,
    book: impl FnOnce(),
) -> Result<(), OperatorRuntimeError> {
    if matches!(checked, Err(OperatorRuntimeError::Expired)) {
        book();
    }
    checked
}
fn validate_freshness(
    elapsed: Duration,
    fresh: UnixMillis,
    opened: UnixMillis,
    not_after: UnixMillis,
) -> Result<(), OperatorRuntimeError> {
    let elapsed_ms =
        i64::try_from(elapsed.as_millis()).map_err(|_| OperatorRuntimeError::Expired)?;
    let monotonic_now = opened
        .get()
        .checked_add(elapsed_ms)
        .ok_or(OperatorRuntimeError::Expired)?;
    let expires = opened
        .get()
        .checked_add(MAX_INACTIVITY_MS)
        .ok_or(OperatorRuntimeError::Expired)?;
    if elapsed_ms >= MAX_INACTIVITY_MS
        || fresh.get().max(monotonic_now) >= expires.min(not_after.get())
    {
        return Err(OperatorRuntimeError::Expired);
    }
    Ok(())
}
fn role_slot(role: OperatorRoleV1) -> Result<NativeSigningSlot, OperatorRuntimeError> {
    match role {
        OperatorRoleV1::Writer => Ok(NativeSigningSlot::Writer),
        OperatorRoleV1::OrganizationAdmin => Ok(NativeSigningSlot::Admin),
        _ => Err(OperatorRuntimeError::Config),
    }
}
fn role_label(role: OperatorRoleV1) -> &'static str {
    match role {
        OperatorRoleV1::Writer => "writer",
        OperatorRoleV1::OrganizationAdmin => "organization-admin",
        _ => "invalid",
    }
}
/// Match the actual native signing key and active certificate before attributing audits.
pub fn verify_local_signing_identity(
    head: &SelectedRegistryHead,
    certificate: CertificateHash,
    role: OperatorRoleV1,
    public: &CanonicalPublicCoseKey,
) -> Result<VerifiedLocalDeviceIdentity, OperatorRuntimeError> {
    let fields = head
        .active_certificate_fields(certificate)
        .ok_or(OperatorError::DeviceCertificateNotActive)?;
    let expected_kind = match role {
        OperatorRoleV1::Writer => CertificateKindV1::Writer,
        OperatorRoleV1::OrganizationAdmin => CertificateKindV1::OrganizationAdmin,
        _ => return Err(OperatorRuntimeError::Config),
    };
    if fields.certificate_kind != expected_kind
        || fields.signing_key_thumbprint != Some(public.thumbprint())
        || fields.signing_public_cose_key.as_deref()
            != Some(public.to_deterministic_cbor().as_slice())
    {
        return Err(OperatorRuntimeError::SignerMismatch);
    }
    Ok(VerifiedLocalDeviceIdentity::verify(
        head,
        certificate,
        fields.device_id,
    )?)
}
fn select_current(
    snapshot: &OperatorArchiveSnapshot,
    store: &mut OperatorTrustStateStore,
    key: TrustStateKey,
    now: UnixMillis,
) -> Result<(SelectedRegistryHead, VerifiedTrust), OperatorRuntimeError> {
    for _ in 0..=snapshot.inventory.trust().len() {
        let trust = verify_trust(
            &snapshot.anchor,
            &snapshot.inventory,
            load_trust_state(store, key)?,
        )?;
        let previous_pin = trust.pinned_head().copied();
        let candidate = verify_registry_candidate(&trust, snapshot.next_sequence)?;
        let mut sources = Vec::new();
        if let Some(authority) = candidate.preexisting_authority() {
            for receipt in snapshot.inventory.receipts() {
                if let Ok(source) = verify_receipt_time(authority, receipt) {
                    sources.push(source);
                }
            }
            for evidence in snapshot.inventory.evidence() {
                if let Ok(source) = verify_checkpoint_time(authority, evidence) {
                    sources.push(source);
                }
            }
        }
        let time = prepare_local_time(store, &candidate, now, &sources)?;
        match select_registry_head(candidate, time, None)? {
            RegistrySelectionOutcome::Selected(head) => {
                // A usable successor is still only one committed transition.
                // Continue until the verifier affirms the same pin, so later
                // ready binding/revocation events in this snapshot are applied.
                if previous_pin.is_some_and(|pin| {
                    pin.registry_version() == head.registry_version()
                        && pin.registry_head_hash() == head.registry_head_hash()
                }) {
                    let trust = verify_trust(
                        &snapshot.anchor,
                        &snapshot.inventory,
                        load_trust_state(store, key)?,
                    )?;
                    return Ok((head, trust));
                }
            }
            RegistrySelectionOutcome::Advanced(_) => {}
            RegistrySelectionOutcome::PendingFuture(_) => {
                return Err(OperatorRuntimeError::Expired);
            }
        }
    }
    Err(OperatorRuntimeError::Sequence)
}

/// Public operational supplement. Never contains a name, profile salt, account
/// identifier, private key, file path, or plaintext report of personal data.
#[derive(Serialize)]
pub struct OperatorGoLiveReport {
    /// Verified documentation is separate from the unchanged raw measurement codes.
    pub documented_posture: Option<PostureDocumentationReport>,
    pub device_posture_evidence: Vec<&'static str>,
    /// Wahr heißt: Eine Sitzung darf öffnen (Pass oder dokumentiertes
    /// Unknown). Das ist KEINE Go-live-Produktionsreife — ein dokumentiertes
    /// Unknown ist im Go-live nie grün; die Reife rechnet allein
    /// [`crate::go_live::GoLiveChecklist::production_ready`].
    pub session_admitted: bool,
    pub binding_state: &'static str,
    pub productive_binding_hashes: Vec<String>,
    pub revoked_binding_hashes: Vec<String>,
    pub device_certificate_hash: String,
    pub role: &'static str,
    pub os_account_binding_hash: String,
    pub current_native_account_match: bool,
    pub registry_head_hash: String,
    pub next_sequence: u64,
    pub revocation_procedure: &'static str,
}

#[derive(Serialize)]
pub struct PostureDocumentationReport {
    pub documented_unknown_mask: u8,
    pub document_hash: String,
    pub evidence_reference_hash: String,
    pub valid_until_exclusive: i64,
}
impl PostureDocumentationReport {
    fn from_admission(value: &posture::VerifiedPostureAdmission<'_>) -> Option<Self> {
        Some(Self {
            documented_unknown_mask: value.documented_unknown_mask(),
            document_hash: hex::encode(value.document_hash()?.as_bytes()),
            evidence_reference_hash: hex::encode(value.evidence_reference_hash()?.as_bytes()),
            valid_until_exclusive: value.valid_until()?.get(),
        })
    }
}

#[cfg(feature = "test-support")]
struct FixturePassingPosture;
#[cfg(feature = "test-support")]
impl DevicePostureProvider for FixturePassingPosture {
    fn report(&self) -> Result<DevicePostureReport, KeyError> {
        Ok(DevicePostureReport {
            full_disk_encryption: PostureRequirement::FullDiskEncryption.pass(),
            locked_non_shared_account: PostureRequirement::LockedNonSharedAccount.pass(),
            automatic_screen_lock: PostureRequirement::AutomaticScreenLock.pass(),
            supported_os_patch_level: PostureRequirement::SupportedOsPatchLevel.pass(),
        })
    }
}
impl OperatorGoLiveReport {
    pub fn to_json(&self) -> Result<String, OperatorRuntimeError> {
        serde_json::to_string(self).map_err(|_| OperatorRuntimeError::Config)
    }
}

struct RuntimeResources {
    config: OperatorRuntimeConfig,
    snapshot: OperatorArchiveSnapshot,
    native: Arc<NativeOperatorProvider>,
    database: Arc<EncryptedDatabase>,
    store: OperatorTrustStateStore,
    signer: Arc<NativeKeyProvider>,
    device_id: DeviceId,
    opened: Instant,
    anchor_path: PathBuf,
    posture: Arc<dyn DevicePostureProvider>,
}
fn open_resources(
    config: OperatorRuntimeConfig,
    anchor_path: &Path,
    now: UnixMillis,
    initialize_native: bool,
    open_native: impl FnOnce(bool) -> Result<Arc<NativeOperatorProvider>, NativeProviderError>,
    posture: Arc<dyn DevicePostureProvider>,
    baseline: Option<Arc<FsArchiveSource>>,
) -> Result<RuntimeResources, OperatorRuntimeError> {
    #[cfg(feature = "test-support")]
    let profile = runtime_profile::Span::start("resources", config.role, None);
    let opened = Instant::now();
    // EA-CNA-SRC-1: zuerst der unabhängige Anker.
    let anchor = load_trust_anchor(anchor_path)?;
    let (canonical_anchor, directory) =
        anchor_outside_archive(&config.archive_directory, anchor_path)?;
    if baseline
        .as_ref()
        .is_some_and(|baseline| canonical_anchor.starts_with(baseline.root()))
    {
        return Err(OperatorRuntimeError::Config);
    }
    let exists = config
        .database_path
        .try_exists()
        .map_err(|_| OperatorRuntimeError::Io)?;
    // Ohne Datenbank kann es keine Registrierung geben: dann bleibt die
    // Reihenfolge wie vor DRK-320 — Snapshot und Zertifikat VOR nativem
    // Anbieter, Schlüssel und Datenbank. Eine Bereitstellung gegen ein
    // fehlendes Archiv hinterlässt so weder Datenbank noch Schlüssel. Nur mit
    // vorhandener Datenbank folgen Anbieter und Datenbank, dann die
    // Registrierung, erst danach der Snapshot.
    let cold = if exists {
        Err(anchor)
    } else {
        let snapshot = OperatorArchiveSnapshot::open_with_anchor(
            &directory.clone().ok_or(OperatorRuntimeError::Io)?,
            anchor,
            now,
            None,
            None,
        )?;
        #[cfg(feature = "test-support")]
        if let Some(profile) = &profile {
            profile.mark("snapshot-return");
        }
        let device_id = certificate_device_id(&snapshot, &config)?;
        Ok((snapshot, device_id))
    };
    let slot = role_slot(config.role)?;
    let native = open_native(initialize_native)?;
    let signer = Arc::new(native.signing_provider(slot));
    let key = signer.handle(SecretPurpose::LocalDatabaseKey);
    if !exists && !initialize_native {
        return Err(OperatorRuntimeError::DatabaseMissing);
    }
    if !exists && !signer.contains(&key)? {
        signer.generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )?;
    }
    #[cfg(feature = "test-support")]
    if let Some(profile) = &profile {
        profile.mark("database-begin");
    }
    let database = Arc::new(if exists {
        EncryptedDatabase::open_existing(&config.database_path, signer.as_ref(), &key)?
    } else {
        EncryptedDatabase::open(&config.database_path, signer.as_ref(), &key)?
    });
    #[cfg(feature = "test-support")]
    if let Some(profile) = &profile {
        profile.mark("database-return");
    }
    let (snapshot, device_id) = match cold {
        Ok(cold) => cold,
        Err(anchor) => {
            let snapshot = registered_snapshot(
                &database,
                anchor,
                directory,
                &config.archive_directory,
                now,
                baseline,
            )?;
            #[cfg(feature = "test-support")]
            if let Some(profile) = &profile {
                profile.mark("snapshot-return");
            }
            let device_id = certificate_device_id(&snapshot, &config)?;
            (snapshot, device_id)
        }
    };
    let key = TrustStateKey {
        organization_id: snapshot.anchor.organization_id(),
        device_id,
    };
    let store = OperatorTrustStateStore::open(
        Arc::clone(&database),
        key,
        snapshot.anchor.chain_id(),
        snapshot.anchor.trust_anchor_hash(),
        UnixMillis::new(0),
    )?;
    #[cfg(feature = "test-support")]
    if let Some(profile) = &profile {
        profile.mark("store-return");
    }
    Ok(RuntimeResources {
        config,
        snapshot,
        native,
        database,
        store,
        signer,
        device_id,
        opened,
        anchor_path: anchor_path.to_path_buf(),
        posture,
    })
}

/// The hash identifies exact parsed bytes; device/role become authoritative
/// only after their active certificate and native signing key are checked.
fn certificate_device_id(
    snapshot: &OperatorArchiveSnapshot,
    config: &OperatorRuntimeConfig,
) -> Result<DeviceId, OperatorRuntimeError> {
    let certificate = snapshot
        .inventory
        .trust()
        .iter()
        .find(|p| p.object_hash().as_bytes() == config.device_certificate_hash.as_bytes())
        .ok_or(OperatorRuntimeError::SignerMismatch)?;
    let fields = match certificate
        .value()
        .decoded_payload()
        .map_err(|_| OperatorRuntimeError::Archive)?
    {
        DecodedTrustPayloadV1::InitialAdminDevice(fields) => fields,
        DecodedTrustPayloadV1::AuthorizedDevice(fields) => fields.fields().clone(),
        _ => return Err(OperatorRuntimeError::SignerMismatch),
    };
    Ok(fields.device_id)
}

/// Der Snapshot bei vorhandener Datenbank: ohne Registrierung unverändert das
/// kanonische Verzeichnis; mit Registrierung die Vereinigung aus Netzziel
/// (oder einer Grundlinie desselben kanonischen Ziels) und der committed
/// Lesesicht der lokalen Komponente (EA-CNA-SRC-1 … SRC-5).
fn registered_snapshot(
    database: &Arc<EncryptedDatabase>,
    anchor: TrustAnchorV1,
    directory: Option<PathBuf>,
    configured: &Path,
    now: UnixMillis,
    baseline: Option<Arc<FsArchiveSource>>,
) -> Result<OperatorArchiveSnapshot, OperatorRuntimeError> {
    let Some(registered) =
        crate::native_archive::registered_component(database, anchor.trust_anchor_hash())?
    else {
        // Unverändert: ohne Registrierung weder Komponente noch Grundlinie.
        return OperatorArchiveSnapshot::open_with_anchor(
            &directory.ok_or(OperatorRuntimeError::Io)?,
            anchor,
            now,
            None,
            None,
        );
    };
    // Nur die committed Lesesicht; keine Sonde, kein Lock, kein Schreiben.
    let component = SqliteCommitStore::open_existing(
        Arc::clone(database),
        registered.namespace,
        registered.object_limit,
        registered.byte_limit,
    )
    .and_then(SqlcipherArchiveBackend::open)
    .map_err(|error| match error {
        ArchiveBackendError::Io => OperatorRuntimeError::Io,
        _ => OperatorRuntimeError::Archive,
    })?;
    let directory = match directory {
        Some(directory) => directory,
        None => unreadable_target_baseline(configured, baseline.as_deref())?,
    };
    let inherited = baseline.clone();
    let snapshot = OperatorArchiveSnapshot::open_with_anchor(
        &directory,
        anchor,
        now,
        Some(&component),
        baseline,
    )?;
    prune_published_rows(&component, &snapshot, inherited.as_deref());
    Ok(snapshot)
}

/// EA-CNA-SRC-4 für ein nicht kanonisierbares Netzziel: an seine Stelle tritt
/// höchstens die Grundlinie AUS DEMSELBEN kanonischen Verzeichnis, nie ein
/// anderer Pfad. Kanonisiert wird dazu der Elternordner, der Name bleibt
/// wörtlich; zeigt der Pfad als Symlink ins Leere oder woanders hin, passt
/// die Grundlinie nicht, und das Netzziel ist nicht lesbar.
fn unreadable_target_baseline(
    configured: &Path,
    baseline: Option<&FsArchiveSource>,
) -> Result<PathBuf, OperatorRuntimeError> {
    let baseline = baseline.ok_or(OperatorRuntimeError::NetworkArchiveUnavailable)?;
    let candidate = configured
        .parent()
        .map(|parent| {
            if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            }
        })
        .and_then(|parent| parent.canonicalize().ok())
        .zip(configured.file_name())
        .map(|(parent, name)| parent.join(name));
    match candidate {
        Some(candidate) if candidate == baseline.root() => Ok(candidate),
        _ => Err(OperatorRuntimeError::NetworkArchiveUnavailable),
    }
}

/// Diagnostic-only spans: fixed labels, public role/code location and times.
/// No payload, path, account, key, or context-authority value is emitted.
#[cfg(feature = "test-support")]
mod runtime_profile {
    use super::OperatorRoleV1;
    use std::{
        cell::Cell,
        sync::atomic::{AtomicU64, Ordering},
        time::Instant,
    };
    static NEXT: AtomicU64 = AtomicU64::new(1);
    thread_local! { static CURRENT: Cell<u64> = const { Cell::new(0) }; }
    pub(super) struct Span {
        id: u64,
        parent: u64,
        label: &'static str,
        role: &'static str,
        started: Instant,
    }
    impl Span {
        pub(super) fn start(
            label: &'static str,
            role: OperatorRoleV1,
            caller: Option<&'static std::panic::Location<'static>>,
        ) -> Option<Self> {
            if std::env::var_os("EA_TEST_NATIVE_RESUME_PHASES").as_deref()
                != Some(std::ffi::OsStr::new("1"))
            {
                return None;
            }
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let parent = CURRENT.replace(id);
            let role = match role {
                OperatorRoleV1::OrganizationAdmin => "admin",
                OperatorRoleV1::Writer => "writer",
                _ => "other",
            };
            let span = Self {
                id,
                parent,
                label,
                role,
                started: Instant::now(),
            };
            let (source, line) = caller.map_or(("none", 0), |caller| {
                let source = if caller.file().ends_with("destruction_runtime/exchange.rs") {
                    "exchange"
                } else if caller.file().ends_with("destruction_runtime.rs") {
                    "destruction"
                } else if caller.file().ends_with("operator_runtime.rs") {
                    "runtime"
                } else {
                    "other"
                };
                (source, caller.line())
            });
            eprintln!("runtime-profile {id} {parent} {role} {label} caller {source} {line}");
            span.mark("begin");
            Some(span)
        }
        pub(super) fn mark(&self, stage: &'static str) {
            eprintln!(
                "runtime-profile {} {} {} {} {stage} {}",
                self.id,
                self.parent,
                self.role,
                self.label,
                self.started.elapsed().as_micros()
            );
        }
    }
    impl Drop for Span {
        fn drop(&mut self) {
            self.mark("return");
            CURRENT.set(self.parent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn a_prompt_crossing_either_deadline_cannot_return_a_successful_presence_proof() {
        struct Prompt<'a>(&'a Cell<Duration>);
        impl OperatorPresence for Prompt<'_> {
            fn prove_presence_and_sign(&self, _: &[u8]) -> Result<[u8; 64], OperatorError> {
                self.0.set(self.0.get() + Duration::from_millis(1));
                Ok([0x5a; 64])
            }
        }
        let opened = UnixMillis::new(1_000);
        for (elapsed_ms, not_after) in [(299_999, 1_000_000), (499, 1_500)] {
            let elapsed = Cell::new(Duration::from_millis(elapsed_ms));
            let proof = prove_with_deadline(&Prompt(&elapsed), b"challenge", || {
                validate_freshness(elapsed.get(), opened, opened, UnixMillis::new(not_after))
            });
            assert!(matches!(proof, Err(OperatorError::ProofMismatch)));
        }
    }
    #[test]
    fn elapsed_prompt_time_and_forward_clock_jumps_expire_exclusively() {
        let opened = UnixMillis::new(1_000);
        let limit = UnixMillis::new(1_000_000);
        assert!(validate_freshness(Duration::from_millis(299_999), opened, opened, limit).is_ok());
        assert!(validate_freshness(Duration::from_millis(300_000), opened, opened, limit).is_err());
        assert!(
            validate_freshness(Duration::ZERO, UnixMillis::new(301_000), opened, limit).is_err()
        );
        assert!(
            validate_freshness(
                Duration::from_secs(2),
                UnixMillis::new(0),
                opened,
                UnixMillis::new(3_000)
            )
            .is_err()
        );
    }

    /// DRK-282, AK 53: nur der Ablauf wird gebucht, genau einmal je Aufruf,
    /// VOR der Abweisung — und der Fehlercode bleibt der des Ablaufs.
    #[test]
    fn only_an_expiry_is_booked_once_before_the_unchanged_refusal() {
        let booked = Cell::new(0_u32);
        let refused = refuse_expired_after_audit(Err(OperatorRuntimeError::Expired), || {
            booked.set(booked.get() + 1);
        });
        assert_eq!(booked.get(), 1);
        assert_eq!(
            refused.err().map(|error| error.code()),
            Some("EA-OPERATOR-RUNTIME-EXPIRED")
        );
        for other in [
            Ok(()),
            Err(OperatorRuntimeError::Posture),
            Err(OperatorRuntimeError::Config),
        ] {
            let before = booked.get();
            let expected = other.as_ref().err().map(|error| error.code());
            let result = refuse_expired_after_audit(other, || booked.set(booked.get() + 1));
            assert_eq!(booked.get(), before, "nur ein Ablauf ist ein Ablauf");
            assert_eq!(result.err().map(|error| error.code()), expected);
        }
    }
}
