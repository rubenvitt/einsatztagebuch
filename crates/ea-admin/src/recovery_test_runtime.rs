//! Native backup/recovery composition. Public source claims never replace the
//! independent anchor, current operator, measured machine or actual store.
use crate::native_archive::{NativeArchiveExistingComponent, NativeArchiveOpenError};
use crate::operator_runtime::{OperatorRuntime, OperatorRuntimeError};
use ea_archive::{
    ArchiveBackend, ArchiveBackendProfileV1, ArchiveSource, BoundArchiveProfilePolicyV1, WriterLock,
};
use ea_archive_fs::{CapabilityTestVectorV1, LocalPathBackend};
use ea_audit::{AuditActorProof, SqliteLocalAuditRepository, TypedLocalAuditEvent};
use ea_crypto::{SecretVec, object_hash};
use ea_format::{GenericAuditContextV1, LocalAuditActionV1, LocalAuditOutcomeV1, OperatorRoleV1};
use ea_local_store::{StoreError, StoreValue};
use ea_operator::ReauthPurpose;
use ea_recovery::{
    FsArchiveSource, KeyInventory, RecoveryBackupKdf, RecoveryProbeBinding, RecoverySourceCore,
    RecoverySourceFields, RecoveryTestError, VerifiedRecoverySource,
};
use ea_types::ObjectHash;
use std::path::{Path, PathBuf};

pub enum RecoveryRuntimeError {
    Runtime(OperatorRuntimeError),
    Test(RecoveryTestError),
    Store(StoreError),
    Backend(ea_archive::ArchiveBackendError),
    Aborted,
}
impl RecoveryRuntimeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Runtime(e) => e.code(),
            Self::Test(e) => e.code(),
            Self::Store(e) => e.code(),
            Self::Backend(e) => e.code(),
            Self::Aborted => "EA-RECOVERY-TEST-CANCELLED",
        }
    }
}
impl std::fmt::Display for RecoveryRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::fmt::Debug for RecoveryRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for RecoveryRuntimeError {}
impl From<RecoveryTestAbort> for RecoveryRuntimeError {
    fn from(_: RecoveryTestAbort) -> Self {
        Self::Aborted
    }
}
impl From<OperatorRuntimeError> for RecoveryRuntimeError {
    fn from(e: OperatorRuntimeError) -> Self {
        Self::Runtime(e)
    }
}
impl From<RecoveryTestError> for RecoveryRuntimeError {
    fn from(e: RecoveryTestError) -> Self {
        Self::Test(e)
    }
}
impl From<StoreError> for RecoveryRuntimeError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<ea_archive::ArchiveBackendError> for RecoveryRuntimeError {
    fn from(e: ea_archive::ArchiveBackendError) -> Self {
        Self::Backend(e)
    }
}
/// Autorität und Backend behalten ihren Code; jede andere Ablehnung der
/// Netzkomponente, auch eine nicht belegte Capability, ist für Recovery eine
/// nicht zugelassene Quelle (EA-CNA-REC-1).
impl From<NativeArchiveOpenError> for RecoveryRuntimeError {
    fn from(e: NativeArchiveOpenError) -> Self {
        match e {
            NativeArchiveOpenError::Runtime(e) => Self::Runtime(e),
            NativeArchiveOpenError::Backend(e) => Self::Backend(e),
            NativeArchiveOpenError::Role => Self::Test(RecoveryTestError::Operator),
            NativeArchiveOpenError::Config
            | NativeArchiveOpenError::RegistrationConflict
            | NativeArchiveOpenError::PointerConflict
            | NativeArchiveOpenError::ProfileMismatch
            | NativeArchiveOpenError::Audit
            | NativeArchiveOpenError::Capability => Self::Test(RecoveryTestError::Source),
        }
    }
}

pub struct RecoveryTestRuntime {
    runtime: OperatorRuntime,
    archive: RecoveryArchiveHandle,
}
/// Das Archiv, gegen das Recovery läuft. LocalPath bleibt das bisherige
/// Backend; ein Netzprofil trägt die registrierte SQLCipher-Komponente und das
/// vorhandene Netzziel getrennt (EA-CNA-REC-1). Die §19.3-Zielkopie trägt nur
/// den Lock über die Kopie des Netzziels und den Pfad des Exports, nie ein
/// Backend, eine Registrierung oder Publikationsfähigkeit (EA-CNA-REC-5).
enum RecoveryArchiveHandle {
    LocalPath(LocalPathBackend),
    Network {
        component: Box<NativeArchiveExistingComponent>,
        remote: LocalPathBackend,
    },
    ReadOnlyCopy {
        lock: LocalPathBackend,
        component_export: PathBuf,
    },
}
/// Beide Writer-Locks einer Recovery-Aktion. Die Felder fallen in
/// Deklarationsreihenfolge, der SQLCipher-Lock also vor dem des Netzziels.
struct RecoveryArchiveLocks {
    _local: WriterLock,
    _remote: Option<WriterLock>,
}
/// Only a completed report can be consumed by the readiness path. A failed
/// report is independently signed durable diagnosis.
pub enum RecoveryTestOutcome {
    Completed(ea_recovery::VerifiedCompletedRecoveryReport),
    Failed(ea_recovery::VerifiedFailedRecoveryReport),
}
pub struct RecoverySourceCapture<'a> {
    pub inventory: &'a KeyInventory,
    pub probes: Vec<RecoveryProbeBinding>,
    pub snapshot: &'a Path,
    pub passphrase: &'a SecretVec,
}
impl RecoveryTestRuntime {
    /// LocalPath verhält sich unverändert wie [`Self::new`], das sechs der
    /// sieben Capability-Zusagen verlangt (Verbindungsabbruch und
    /// Wiederanlauf nicht). Ein Netzprofil entsteht nur aus der registrierten
    /// Komponente (`open_current`), den drei SQLCipher-Zusagen und ALLEN
    /// sieben Zusagen des vorhandenen Netzziels
    /// ([`NativeArchiveExistingComponent::require_capabilities`],
    /// EA-CNA-REC-1).
    pub fn with_archive_config(
        runtime: OperatorRuntime,
        config: crate::native_archive::NativeArchiveConfig,
    ) -> Result<Self, RecoveryRuntimeError> {
        if !matches!(
            config.profile,
            ArchiveBackendProfileV1::ControlledNetworkPath(_)
        ) {
            return Self::new(runtime, config.profile);
        }
        runtime.ensure_current()?;
        if runtime.config().role != OperatorRoleV1::OrganizationAdmin {
            return Err(RecoveryTestError::Operator.into());
        }
        let profile = config.profile.clone();
        let component = NativeArchiveExistingComponent::open_current(&runtime, config)?;
        let policy = BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields());
        let directory = runtime.config().archive_directory.clone();
        component.require_capabilities(&directory, &policy)?;
        let remote = LocalPathBackend::open_existing(directory, profile, &policy)?;
        runtime.ensure_current()?;
        Ok(Self {
            runtime,
            archive: RecoveryArchiveHandle::Network {
                component: Box::new(component),
                remote,
            },
        })
    }
    pub fn archive_profile_hash(&self) -> Result<ea_types::Hash32, RecoveryRuntimeError> {
        match &self.archive {
            RecoveryArchiveHandle::LocalPath(backend) => Ok(backend.profile_hash()?),
            RecoveryArchiveHandle::Network { component, .. } => Ok(component.profile_hash()),
            RecoveryArchiveHandle::ReadOnlyCopy { lock, .. } => Ok(lock.profile_hash()?),
        }
    }
    /// EA-CNA-REC-2: zuerst der SQLCipher-Writer-Lock, dann der des
    /// Netzziels. Scheitert der zweite, gibt das Fallen des ersten ihn frei.
    fn archive_locks(&self) -> Result<RecoveryArchiveLocks, RecoveryRuntimeError> {
        match &self.archive {
            RecoveryArchiveHandle::LocalPath(backend) => Ok(RecoveryArchiveLocks {
                _local: backend.acquire_writer_lock()?,
                _remote: None,
            }),
            RecoveryArchiveHandle::Network { component, remote } => {
                let local = component.local_backend().acquire_writer_lock()?;
                let remote = remote.acquire_writer_lock()?;
                Ok(RecoveryArchiveLocks {
                    _local: local,
                    _remote: Some(remote),
                })
            }
            // Nur der Schutz-Lock der Kopie; eine Komponente gibt es hier nicht.
            RecoveryArchiveHandle::ReadOnlyCopy { lock, .. } => Ok(RecoveryArchiveLocks {
                _local: lock.acquire_writer_lock()?,
                _remote: None,
            }),
        }
    }
    /// Die Archivquelle der Aktion. Ein Netzprofil hat sie nur während einer
    /// Capture mit Export (EA-CNA-REC-3); ohne Export lehnt es ab, statt nur
    /// das Netzziel als vollständige Quelle zu lesen. Die Zielkopie liest
    /// die Kopie vereinigt mit dem Export (EA-CNA-REC-5).
    fn archive_source(&self) -> Result<FsArchiveSource, RecoveryRuntimeError> {
        let directory = &self.runtime.config().archive_directory;
        match &self.archive {
            RecoveryArchiveHandle::LocalPath(_) => {
                Ok(FsArchiveSource::open(directory).map_err(|_| RecoveryTestError::Source)?)
            }
            RecoveryArchiveHandle::Network { .. } => Err(RecoveryTestError::Source.into()),
            RecoveryArchiveHandle::ReadOnlyCopy {
                component_export, ..
            } => network_union(directory, component_export),
        }
    }
    /// A concrete backend rooted at the same verified native runtime path. A
    /// controlled-network profile is explicitly unsupported here, never cast to
    /// local or stripped of its local durable commit-component obligations.
    pub fn new(
        runtime: OperatorRuntime,
        profile: ArchiveBackendProfileV1,
    ) -> Result<Self, RecoveryRuntimeError> {
        runtime.ensure_current()?;
        if runtime.config().role != OperatorRoleV1::OrganizationAdmin {
            return Err(RecoveryTestError::Operator.into());
        }
        let vector = match &profile {
            ArchiveBackendProfileV1::LocalPath(p) => p.capability_test_vector_id.clone(),
            ArchiveBackendProfileV1::ControlledNetworkPath(_) => {
                return Err(RecoveryTestError::Source.into());
            }
        };
        let backend = LocalPathBackend::open(
            runtime.config().archive_directory.clone(),
            profile,
            &BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields()),
        )?;
        let measured = backend.run_capability_test(&CapabilityTestVectorV1::new(
            &vector,
            b"EINSATZARCHIV-RECOVERY-CAPABILITY-v1",
        )?)?;
        if !measured.exclusive_create_without_overwrite()
            || !measured.byte_conflict_detection()
            || !measured.same_filesystem_atomic_rename()
            || !measured.file_flush()
            || !measured.directory_flush()
            || !measured.exclusive_writer_lock()
        {
            return Err(RecoveryTestError::Source.into());
        }
        runtime.ensure_current()?;
        Ok(Self {
            runtime,
            archive: RecoveryArchiveHandle::LocalPath(backend),
        })
    }
    /// Die §19.3-Zielkopie eines Netzprofils: `archive_directory` ist die
    /// unveränderte Kopie des Netzziels, `component_export` der bei der
    /// Capture geschriebene Export der lokalen Komponente. Ohne Registrierung,
    /// ohne Komponente und ohne Capability-Test; Capture ist gesperrt, Restore
    /// und Test lesen nur (EA-CNA-REC-5, REC-6). Autorität und Rolle gelten
    /// unverändert.
    pub fn for_archive_copy(
        runtime: OperatorRuntime,
        profile: ArchiveBackendProfileV1,
        component_export: PathBuf,
    ) -> Result<Self, RecoveryRuntimeError> {
        runtime.ensure_current()?;
        if runtime.config().role != OperatorRoleV1::OrganizationAdmin {
            return Err(RecoveryTestError::Operator.into());
        }
        if !matches!(profile, ArchiveBackendProfileV1::ControlledNetworkPath(_)) {
            return Err(RecoveryTestError::Source.into());
        }
        let lock = LocalPathBackend::open_existing(
            runtime.config().archive_directory.clone(),
            profile,
            &BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields()),
        )?;
        runtime.ensure_current()?;
        Ok(Self {
            runtime,
            archive: RecoveryArchiveHandle::ReadOnlyCopy {
                lock,
                component_export,
            },
        })
    }
    /// Capture eines Netzprofils (EA-CNA-REC-3): exportiert unter beiden
    /// Locks alle verwalteten Objekte der lokalen Komponente exklusiv nach
    /// `component_export` und bindet die Vereinigung aus Netzziel und
    /// zurückgelesenem Export. LocalPath und Zielkopie lehnen ab.
    ///
    /// Die Sonden kommen unverändert aus `request.probes`; hier wird keine
    /// aus der Vereinigung gewählt. Das tut
    /// [`Self::capture_inventory_with_component_export`]. Scheitert der Export
    /// mittendrin, bleibt ein Teilverzeichnis liegen, das der Betreiber löschen
    /// muss; ein erneuter Versuch lehnt es als vorhanden ab.
    pub fn capture_source_with_component_export(
        &mut self,
        request: RecoverySourceCapture<'_>,
        component_export: &Path,
    ) -> Result<VerifiedRecoverySource, RecoveryRuntimeError> {
        self.capture_network(request, component_export, false)
    }
    /// `select_probes`: die Sonden werden aus der Vereinigung gewählt statt
    /// aus `request.probes` übernommen.
    fn capture_network(
        &mut self,
        request: RecoverySourceCapture<'_>,
        component_export: &Path,
        select_probes: bool,
    ) -> Result<VerifiedRecoverySource, RecoveryRuntimeError> {
        let _locks = self.archive_locks()?;
        if !matches!(self.archive, RecoveryArchiveHandle::Network { .. }) {
            return Err(RecoveryTestError::Source.into());
        }
        let remote = self.runtime.config().archive_directory.clone();
        let export = component_export.to_path_buf();
        self.capture_from(request, Some(component_export), select_probes, move || {
            network_union(&remote, &export)
        })
    }
    pub fn runtime(&self) -> &OperatorRuntime {
        &self.runtime
    }
    /// Capture einer LocalPath-Quelle. Ein Netzprofil braucht den Export
    /// ([`Self::capture_source_with_component_export`]); die Zielkopie
    /// erlaubt keine Capture.
    pub fn capture_source(
        &mut self,
        request: RecoverySourceCapture<'_>,
    ) -> Result<VerifiedRecoverySource, RecoveryRuntimeError> {
        let _locks = self.archive_locks()?;
        if !matches!(self.archive, RecoveryArchiveHandle::LocalPath(_)) {
            return Err(RecoveryTestError::Source.into());
        }
        let directory = self.runtime.config().archive_directory.clone();
        self.capture_from(request, None, false, move || {
            Ok(FsArchiveSource::open(&directory).map_err(|_| RecoveryTestError::Source)?)
        })
    }
    /// Gemeinsamer Körper beider Captures; der Aufrufer hält die Locks.
    /// `read_source` liest die Quelle bei jedem Aufruf neu, damit der Vergleich
    /// nach dem Schnappschuss echte Bytes sieht.
    fn capture_from(
        &mut self,
        request: RecoverySourceCapture<'_>,
        component_export: Option<&Path>,
        select_probes: bool,
        read_source: impl Fn() -> Result<FsArchiveSource, RecoveryRuntimeError>,
    ) -> Result<VerifiedRecoverySource, RecoveryRuntimeError> {
        let mut request = request;
        self.runtime.refresh_for_action()?;
        self.runtime.ensure_current()?;
        BoundArchiveProfilePolicyV1::from_policy(self.runtime.head().policy_fields())
            .require(self.archive_profile_hash()?)?;
        let before = self
            .runtime
            .reauthenticate_for(ReauthPurpose::RecoveryTest)?;
        if !before.proof().is_valid_for(
            ReauthPurpose::RecoveryTest,
            self.runtime.head().preexisting_effective_now(),
        ) {
            return Err(RecoveryTestError::Operator.into());
        }
        let machine = ea_key_provider::measure_native_machine_identity()
            .map_err(|_| RecoveryTestError::Machine)?;
        if let Some(export) = component_export {
            self.export_component(export)?;
        }
        let source = read_source()?;
        let inventory_hash = ea_recovery::recovery_archive_inventory_hash(&source)?;
        let probe = ea_recovery::RecoveryArchiveProbe::verify(
            &source,
            self.runtime.anchor(),
            self.runtime.head().preexisting_effective_now().value(),
        )?;
        if select_probes {
            request.probes = inputs::select_recovery_probes(request.inventory, &probe)?;
        }
        let tip = probe.verified_public_chain_head();
        if tip.sequence().get().checked_add(1) != Some(self.runtime.next_sequence().get()) {
            return Err(RecoveryTestError::Source.into());
        }
        let kdf = RecoveryBackupKdf::fresh()?;
        let key = kdf.derive(request.passphrase)?;
        self.runtime.ensure_current()?;
        let snapshot = self
            .runtime
            .database()
            .snapshot_with_backup_key(request.snapshot, &key)?;
        drop(key);
        self.runtime.ensure_current()?;
        let after = read_source()?;
        if ea_recovery::recovery_archive_inventory_hash(&after)? != inventory_hash
            || ea_key_provider::measure_native_machine_identity()
                .map_err(|_| RecoveryTestError::Machine)?
                != machine
        {
            return Err(RecoveryTestError::Source.into());
        }
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| RecoveryTestError::Entropy)?;
        let head = self.runtime.head();
        let core = RecoverySourceCore::new(RecoverySourceFields {
            source_id: id,
            organization_id: *self.runtime.anchor().organization_id().as_bytes(),
            chain_id: *self.runtime.anchor().chain_id().as_bytes(),
            anchor_hash: *self.runtime.anchor().trust_anchor_hash().as_bytes(),
            source_machine: *machine.fingerprint().as_bytes(),
            source_installation: *self.runtime.native().installation_id().as_bytes(),
            registry_version: head.registry_version().get(),
            registry_head: *head.registry_head_hash().as_bytes(),
            proposed_sequence: head.proposed_sequence().get(),
            effective_now: head.preexisting_effective_now().value().get(),
            inventory_hash: *request.inventory.exact_hash().as_bytes(),
            archive_inventory_hash: inventory_hash,
            tip_sequence: tip.sequence().get(),
            tip_entry_hash: *tip.entry_hash().as_bytes(),
            snapshot_hash: *snapshot.ciphertext_hash(),
            migrations_hash: *snapshot.migrations_hash(),
            kdf,
            probes: request.probes,
        })?;
        let session = self
            .runtime
            .reauthenticate_for_context(ReauthPurpose::RecoveryTest, core.context_hash())?;
        self.runtime.ensure_current()?;
        let audit = self
            .runtime
            .audit_service()
            .prepare_signed(
                AuditActorProof::OperatorSession(session.proof()),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(
                        ObjectHash::from(core.context_hash()),
                    ))),
                    outcome: LocalAuditOutcomeV1::Accepted,
                },
            )
            .map_err(|_| RecoveryTestError::Audit)?;
        let envelope = ea_recovery::recovery_source_envelope(&core, audit.exact_bytes())?;
        let verified = ea_recovery::verify_recovery_source(
            &envelope,
            &source,
            self.runtime.anchor(),
            request.inventory,
            head.preexisting_effective_now().value(),
        )?;
        self.runtime.ensure_current()?;
        self.runtime.database().transaction::<_,RecoveryRuntimeError>(|tx| {
            SqliteLocalAuditRepository::append_prepared_in(tx,&audit).map_err(|_|RecoveryTestError::Audit)?;
            tx.execute("INSERT INTO recovery_source_scope(source_hash,exact_envelope,capture_audit_event_id) VALUES(?1,?2,?3)",&[StoreValue::Blob(object_hash(&envelope).as_bytes().to_vec()),StoreValue::Blob(envelope.clone()),StoreValue::Blob(audit.id().as_bytes().to_vec())])?;
            Ok(())
        })?;
        self.runtime.ensure_current()?;
        Ok(verified)
    }
}

/// Ist das Profil ein kontrolliertes Netzprofil? Aufrufer ohne eigene
/// Archiv-Abhängigkeit entscheiden damit, ob ein Komponentenexport nötig ist.
#[must_use]
pub fn is_network_archive_profile(profile: &ArchiveBackendProfileV1) -> bool {
    matches!(profile, ArchiveBackendProfileV1::ControlledNetworkPath(_))
}

/// Netzziel vereinigt mit dem Export der lokalen Komponente, in dieser
/// Reihenfolge; ein Bytekonflikt oder ein unlesbarer Teil ist keine Quelle.
fn network_union(remote: &Path, export: &Path) -> Result<FsArchiveSource, RecoveryRuntimeError> {
    let remote = FsArchiveSource::open(remote).map_err(|_| RecoveryTestError::Source)?;
    let export = FsArchiveSource::open(export).map_err(|_| RecoveryTestError::Source)?;
    Ok(remote
        .with_exact_component(&export)
        .map_err(|_| RecoveryTestError::Source)?)
}

impl RecoveryTestRuntime {
    /// Schreibt alle verwalteten Objekte der Komponente (committed und
    /// Staging) exklusiv in ein neues Verzeichnis, flusht Dateien und
    /// Verzeichnisse und vergleicht den zurückgelesenen Export byte-genau mit
    /// der Komponente (EA-CNA-REC-3). Ein vorhandenes Ziel oder eines im
    /// Netzziel lehnt ab, bevor etwas angelegt wird. Der Aufrufer hält beide
    /// Locks.
    fn export_component(&self, component_export: &Path) -> Result<(), RecoveryRuntimeError> {
        let RecoveryArchiveHandle::Network { component, .. } = &self.archive else {
            return Err(RecoveryTestError::Source.into());
        };
        let refused = |_| RecoveryTestError::Source;
        if component_export.symlink_metadata().is_ok() {
            return Err(RecoveryTestError::Source.into());
        }
        let name = match component_export.components().next_back() {
            Some(std::path::Component::Normal(name)) => name.to_owned(),
            _ => return Err(RecoveryTestError::Source.into()),
        };
        let parent = match component_export.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let parent = std::fs::canonicalize(parent).map_err(refused)?;
        let archive =
            std::fs::canonicalize(&self.runtime.config().archive_directory).map_err(refused)?;
        if parent.starts_with(&archive) {
            return Err(RecoveryTestError::Source.into());
        }
        let mut managed = Vec::new();
        component
            .local_backend()
            .visit_managed_blobs(&mut |blob| {
                managed.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
                Ok(())
            })
            .map_err(|_| RecoveryTestError::Source)?;
        let root = parent.join(name);
        std::fs::create_dir(&root).map_err(refused)?;
        write_tree(&root, &managed)?;
        sync_directory(&parent)?;
        managed.sort();
        if read_tree(&root)? != managed {
            return Err(RecoveryTestError::Source.into());
        }
        Ok(())
    }
}

/// Legt jede Zeile exklusiv unter `root` an (Zwischenverzeichnisse per
/// `create_dir`, Dateien per `create_new`), flusht jede Datei und danach jedes
/// neu angelegte Verzeichnis von unten nach oben, zuletzt `root`.
fn write_tree(root: &Path, rows: &[(String, Vec<u8>)]) -> Result<(), RecoveryRuntimeError> {
    let mut created = vec![root.to_path_buf()];
    for (hint, bytes) in rows {
        let mut directory = root.to_path_buf();
        let mut parts = hint.split('/').peekable();
        while let Some(part) = parts.next() {
            if part.is_empty() || part == "." || part == ".." || part.contains('\\') {
                return Err(RecoveryTestError::Source.into());
            }
            if parts.peek().is_none() {
                write_exclusive(&directory.join(part), bytes)?;
                break;
            }
            directory.push(part);
            match std::fs::create_dir(&directory) {
                Ok(()) => created.push(directory.clone()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !std::fs::symlink_metadata(&directory)
                        .map_err(|_| RecoveryTestError::Source)?
                        .is_dir()
                    {
                        return Err(RecoveryTestError::Source.into());
                    }
                }
                Err(_) => return Err(RecoveryTestError::Source.into()),
            }
        }
    }
    for directory in created.iter().rev() {
        sync_directory(directory)?;
    }
    Ok(())
}

/// Liest einen Baum zurück, sortiert als Multiset von `(Adresse, Bytes)`.
fn read_tree(root: &Path) -> Result<Vec<(String, Vec<u8>)>, RecoveryRuntimeError> {
    let mut rows = Vec::new();
    FsArchiveSource::open(root)
        .map_err(|_| RecoveryTestError::Source)?
        .visit_blobs(&mut |blob| {
            rows.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .map_err(|_| RecoveryTestError::Source)?;
    rows.sort();
    Ok(rows)
}

/// Betreiberschritt für §19.3 (EA-CNA-REC-5): legt in `target` die
/// unveränderte Vereinigung aus der Kopie des Netzziels und dem Export der
/// lokalen Komponente an. Die Objekte sind unveränderlich und
/// inhaltsadressiert; bytegleiche Adressen fallen zusammen, abweichende lehnen
/// ab. `target` darf fehlen oder leer sein. Jede Datei entsteht exklusiv und
/// wird geflusht; der zurückgelesene Baum muss byte-genau der Vereinigung
/// entsprechen. Quelle und Export bleiben unberührt.
///
/// Ein Ziel innerhalb der Kopie oder des Exports lehnt ab. Scheitert das
/// Anlegen mittendrin, bleibt ein Teilverzeichnis liegen, das der Betreiber
/// löschen muss.
///
/// # Errors
///
/// `EA-RECOVERY-TEST-SOURCE` für einen nicht leeren, unlesbaren oder in einer
/// Quelle liegenden Zielordner, einen Bytekonflikt, einen Schreib- oder Flushfehler oder einen
/// abweichenden Rücklesebefund.
pub fn materialize_network_archive_copy(
    remote_copy: &Path,
    component_export: &Path,
    target: &Path,
) -> Result<(), RecoveryRuntimeError> {
    // Ein Ziel in einer der beiden Quellen würde diese Quelle verändern.
    let parent = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let parent = std::fs::canonicalize(parent).map_err(|_| RecoveryTestError::Source)?;
    for source in [remote_copy, component_export] {
        let source = std::fs::canonicalize(source).map_err(|_| RecoveryTestError::Source)?;
        if parent.starts_with(&source) {
            return Err(RecoveryTestError::Source.into());
        }
    }
    let union = network_union(remote_copy, component_export)?;
    let mut rows = Vec::new();
    union
        .visit_blobs(&mut |blob| {
            rows.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .map_err(|_| RecoveryTestError::Source)?;
    rows.sort();
    match std::fs::symlink_metadata(target) {
        Ok(meta) if meta.is_dir() => {
            if std::fs::read_dir(target)
                .map_err(|_| RecoveryTestError::Source)?
                .next()
                .is_some()
            {
                return Err(RecoveryTestError::Source.into());
            }
        }
        Ok(_) => return Err(RecoveryTestError::Source.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(target).map_err(|_| RecoveryTestError::Source)?;
            if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
                sync_directory(parent)?;
            }
        }
        Err(_) => return Err(RecoveryTestError::Source.into()),
    }
    write_tree(target, &rows)?;
    if read_tree(target)? != rows {
        return Err(RecoveryTestError::Source.into());
    }
    Ok(())
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<(), RecoveryRuntimeError> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| RecoveryTestError::Source)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| RecoveryTestError::Source)?;
    Ok(())
}

/// Auf Unix macht erst das `fsync` des Verzeichnisses einen neuen Namen
/// dauerhaft; andere Plattformen öffnen Verzeichnisse nicht als Datei.
fn sync_directory(directory: &Path) -> Result<(), RecoveryRuntimeError> {
    #[cfg(unix)]
    {
        std::fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| RecoveryTestError::Source)?;
    }
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

pub struct RecoverySourceRestore<'a> {
    pub inventory: &'a KeyInventory,
    pub exact_source: &'a [u8],
    pub snapshot: &'a Path,
    pub passphrase: &'a SecretVec,
    pub target: &'a Path,
}
/// Only the native service can obtain an actual restored database handle.
pub struct RestoredRecoverySource {
    database: ea_local_store::EncryptedDatabase,
    scope: VerifiedRecoverySource,
    content_hash: [u8; 32],
}
impl RecoveryTestRuntime {
    pub fn restore_source(
        &mut self,
        request: RecoverySourceRestore<'_>,
    ) -> Result<RestoredRecoverySource, RecoveryRuntimeError> {
        let _locks = self.archive_locks()?;
        // Die registrierte Netzquelle selbst ist nie Restore-Quelle; das Ziel
        // liest die Kopie (EA-CNA-REC-5).
        if matches!(self.archive, RecoveryArchiveHandle::Network { .. }) {
            return Err(RecoveryTestError::Source.into());
        }
        self.runtime.refresh_for_action()?;
        self.runtime.ensure_current()?;
        let source = self.archive_source()?;
        let scope = ea_recovery::verify_recovery_source(
            request.exact_source,
            &source,
            self.runtime.anchor(),
            request.inventory,
            self.runtime.head().preexisting_effective_now().value(),
        )?;
        let machine = ea_key_provider::measure_native_machine_identity()
            .map_err(|_| RecoveryTestError::Machine)?;
        if scope.core().fields().source_machine == *machine.fingerprint().as_bytes()
            || scope.core().fields().source_installation
                == *self.runtime.native().installation_id().as_bytes()
        {
            return Err(RecoveryTestError::Machine.into());
        }
        let before = self
            .runtime
            .reauthenticate_for(ReauthPurpose::RecoveryTest)?;
        if !before.proof().is_valid_for(
            ReauthPurpose::RecoveryTest,
            self.runtime.head().preexisting_effective_now(),
        ) {
            return Err(RecoveryTestError::Operator.into());
        }
        let source_hash = scope.envelope_hash();
        let f = scope.core().fields();
        let key = f.kdf.derive(request.passphrase)?;
        let provider = self.runtime.signing_provider();
        let restored = ea_local_store::EncryptedDatabase::restore_with_backup_key(
            request.snapshot,
            f.snapshot_hash,
            f.migrations_hash,
            &key,
            request.target,
            provider.as_ref(),
            &provider.handle(ea_key_provider::SecretPurpose::LocalDatabaseKey),
        )?;
        drop(key);
        let content_hash = restored.recovery_source_content_hash()?;
        self.runtime.ensure_current()?;
        let after_source = self.archive_source()?;
        if ea_recovery::recovery_archive_inventory_hash(&after_source)? != f.archive_inventory_hash
            || ea_key_provider::measure_native_machine_identity()
                .map_err(|_| RecoveryTestError::Machine)?
                != machine
        {
            return Err(RecoveryTestError::Source.into());
        }
        let binding = RestoreBinding {
            source_hash: *source_hash.as_bytes(),
            snapshot_hash: f.snapshot_hash,
            migrations_hash: f.migrations_hash,
            machine: *machine.fingerprint().as_bytes(),
            installation: *self.runtime.native().installation_id().as_bytes(),
            content_hash,
            registry_version: self.runtime.head().registry_version().get(),
            registry_head: *self.runtime.head().registry_head_hash().as_bytes(),
            sequence: self.runtime.next_sequence().get(),
        };
        let context = binding.context_hash()?;
        let session = self
            .runtime
            .reauthenticate_for_context(ReauthPurpose::RecoveryTest, context)?;
        self.runtime.ensure_current()?;
        if restored.recovery_source_content_hash()? != content_hash {
            return Err(RecoveryTestError::Source.into());
        }
        let audit = self
            .runtime
            .audit_service()
            .prepare_signed(
                AuditActorProof::OperatorSession(session.proof()),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(
                        ObjectHash::from(context),
                    ))),
                    outcome: LocalAuditOutcomeV1::Accepted,
                },
            )
            .map_err(|_| RecoveryTestError::Audit)?;
        let historical = ea_verify::historical_registry_head(
            self.runtime.inventory(),
            self.runtime.anchor(),
            self.runtime.head().registry_version(),
            self.runtime.head().registry_head_hash(),
            self.runtime.next_sequence(),
            self.runtime.head().preexisting_effective_now().value(),
        )
        .ok_or(RecoveryTestError::Source)?;
        ea_recovery::verify_recovery_audit_context(
            audit.exact_bytes(),
            &historical,
            context,
            self.runtime.head().preexisting_effective_now().value(),
            LocalAuditOutcomeV1::Accepted,
        )?;
        self.runtime.database().transaction::<_, RecoveryRuntimeError>(|tx| {
            SqliteLocalAuditRepository::append_prepared_in(tx, &audit)
                .map_err(|_| RecoveryTestError::Audit)?;
            tx.execute(
                "INSERT INTO recovery_restore_binding(singleton,source_hash,exact_envelope,snapshot_hash,migrations_hash,target_machine,target_installation,restored_content_hash,registry_version,registry_head,proposed_sequence,restore_audit_event_id) VALUES(0,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                &[
                    StoreValue::Blob(binding.source_hash.to_vec()),
                    StoreValue::Blob(scope.exact_envelope().to_vec()),
                    StoreValue::Blob(binding.snapshot_hash.to_vec()),
                    StoreValue::Blob(binding.migrations_hash.to_vec()),
                    StoreValue::Blob(binding.machine.to_vec()),
                    StoreValue::Blob(binding.installation.to_vec()),
                    StoreValue::Blob(binding.content_hash.to_vec()),
                    StoreValue::Integer(i64::try_from(binding.registry_version).map_err(|_| RecoveryTestError::Source)?),
                    StoreValue::Blob(binding.registry_head.to_vec()),
                    StoreValue::Integer(i64::try_from(binding.sequence).map_err(|_| RecoveryTestError::Source)?),
                    StoreValue::Blob(audit.id().as_bytes().to_vec()),
                ],
            )?;
            Ok(())
        })?;
        self.runtime.ensure_current()?;
        Ok(RestoredRecoverySource {
            database: restored,
            scope,
            content_hash,
        })
    }
}

impl RestoredRecoverySource {
    pub fn source_envelope_hash(&self) -> ObjectHash {
        self.scope.envelope_hash()
    }
    pub fn restored_content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }
    /// Re-read the actual complete source store. The database itself is not
    /// exposed as a mutable operational store by this recovery-test handle.
    pub fn verify_unchanged(&self) -> Result<(), RecoveryRuntimeError> {
        if self.database.recovery_source_content_hash()? != self.content_hash {
            return Err(RecoveryTestError::Source.into());
        }
        Ok(())
    }
}

// Kept in the target authorization database, never inserted into or used to
// rewrite the restored source. Every retained value is covered by the signed
// RecoveryTest/Accepted event; Accepted records restoration, not completion.
struct RestoreBinding {
    source_hash: [u8; 32],
    snapshot_hash: [u8; 32],
    migrations_hash: [u8; 32],
    machine: [u8; 32],
    installation: [u8; 32],
    content_hash: [u8; 32],
    registry_version: u64,
    registry_head: [u8; 32],
    sequence: u64,
}
impl RestoreBinding {
    fn context_hash(&self) -> Result<ea_types::Hash32, RecoveryTestError> {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(11)
            .and_then(|e| e.str("EINSATZARCHIV-RECOVERY-RESTORE-v1"))
            .and_then(|e| e.u8(1))
            .and_then(|e| e.bytes(&self.source_hash))
            .and_then(|e| e.bytes(&self.snapshot_hash))
            .and_then(|e| e.bytes(&self.migrations_hash))
            .and_then(|e| e.bytes(&self.machine))
            .and_then(|e| e.bytes(&self.installation))
            .and_then(|e| e.bytes(&self.content_hash))
            .and_then(|e| e.u64(self.registry_version))
            .and_then(|e| e.bytes(&self.registry_head))
            .and_then(|e| e.u64(self.sequence))
            .map_err(|_| RecoveryTestError::Source)?;
        ea_types::Hash32::try_from(object_hash(&e.into_writer()).as_bytes().as_slice())
            .map_err(|_| RecoveryTestError::Source)
    }
}

pub struct RecoveryTestMediumSource {
    pub medium_id_hash: ObjectHash,
    pub source: RecoveryMediumInput,
}
pub enum RecoveryMediumInput {
    Offline(ea_recovery::KeySourceSpec),
    NativeSigningSlot(RecoveryNativeSigningSlot),
}
impl RecoveryTestRuntime {
    pub fn reopen_restored_source(
        &mut self,
        inventory: &KeyInventory,
        path: &Path,
    ) -> Result<RestoredRecoverySource, RecoveryRuntimeError> {
        let _locks = self.archive_locks()?;
        self.runtime.refresh_for_action()?;
        self.runtime
            .reauthenticate_for(ReauthPurpose::RecoveryTest)?;
        let restored = self.open_bound_sources(inventory, path)?;
        self.runtime
            .reauthenticate_for(ReauthPurpose::RecoveryTest)?;
        restored.verify_unchanged()?;
        Ok(restored)
    }
}

mod execution;
mod guided;
pub use guided::{
    RecoveryMediumObservation, RecoveryMediumRequest, RecoveryMediumStatus,
    RecoverySessionObserver, RecoveryTestAbort, RecoveryTestGuide,
};

mod inputs;
pub use inputs::{parse_recovery_archive_profile, parse_recovery_media_sources};

mod import;
mod native_medium;
pub use native_medium::RecoveryNativeSigningSlot;
