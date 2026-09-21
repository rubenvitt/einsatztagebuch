use super::{
    CONFIG_ERROR, NativeDesktopRuntime, drafts::repository, now, writer_config::WriterSettings,
};
use crate::{
    commands::{CommandError, PREVIEW_MISMATCH, PREVIEW_NOT_ISSUED},
    state::{
        BoundWriter, StartupRecoveryPort, SyncStatePort, WriterFinalizePort, WriterPreviewPort,
    },
};
use ea_admin::{
    amendment::AmendmentDraftService,
    native_archive::{
        NativeArchiveConfig, NativeArchiveExistingComponent, NativeArchiveOpenError,
        refuse_local_path_on_registered_anchor,
    },
    native_provider::NativeSigningSlot,
    network_publication::{
        NetworkPublicationHost, ObservedPublicationPortV1, WriterCustodyObserverV1,
    },
    operator_runtime::writer::InteractiveOperatorRuntime as OperatorRuntime,
};
use ea_archive::{
    ArchiveBackend, ArchiveBackendError, ArchiveBackendProfileV1, ArchiveSource,
    BoundArchiveProfilePolicyV1,
};
use ea_archive_fs::{CapabilityTestVectorV1, LocalPathBackend};
use ea_destruction::{ObservedArchiveHoldingV1, SqliteManagedCustody};
use ea_draft::{IncidentNumberRegister, MasterDataRepository, OperatorProfileRepository};
use ea_key_provider::SecretPurpose;
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_ui_contracts::SyncStateView;
use ea_ui_contracts::{
    AmendmentInputView, CorrectionReferenceView, FinalizationPreviewView, FinalizeOutcomeView,
    IncidentInputView,
};
use ea_writer::{
    FinalizationPreview, RecoveryOutcome, StaleRegistryAcknowledgement, StaleRegistryStore,
    WriterBindingV1, WriterError, WriterService,
};
use std::{
    path::Path,
    sync::{
        Arc, Mutex, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

/// Die Ablage, in die der Writer committet: LocalPath wie bisher, für ein
/// Netzprofil ausschließlich die lokale SQLCipher-Komponente (EA-CNA-WRT-1).
/// Beide Varianten liegen auf dem Heap: sie sind groß und ungleich groß,
/// und die Umleitung entsteht einmal je Writer-Start.
enum WriterArchive {
    Local(Box<LocalPathBackend>),
    Network(Box<NativeArchiveExistingComponent>),
}
impl WriterArchive {
    fn holding(&self) -> &dyn ObservedArchiveHoldingV1 {
        match self {
            Self::Local(backend) => backend.as_ref(),
            Self::Network(component) => component.as_ref(),
        }
    }
    fn backend(&self) -> &dyn ArchiveBackend {
        match self {
            Self::Local(backend) => backend.as_ref(),
            Self::Network(component) => component.local_backend(),
        }
    }
}

/// Der Publikationshost eines Netz-Writers samt seinem Hostlauf
/// (EA-CNA-PUB-8 (c)).
///
/// Ein einziger `std::thread` führt [`NetworkPublicationHost::run_loop`] aus.
/// Jeder Lauf braucht die Beobachtung des Netzziels mit der aktuellen
/// Writer-Autorität (EA-CNA-WRT-7); die holt der Lauf über einen schwachen
/// Griff auf den Wirt und nur per `try_lock` — hält gerade eine Aktion oder
/// ein Präsenzdialog den Zustand, entfällt dieser Lauf (die Aktion
/// veröffentlicht in Schritt 12 selbst). Beim Abbau wird der Lauf beendet und
/// auf den Thread gewartet; ein hängender Mount hält den Abbau bis zum Ende
/// seines laufenden Aufrufs auf (bekannte Grenze aus Task 6).
pub(super) struct NetworkPublication {
    host: Arc<NetworkPublicationHost>,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Nur Fixture-Tests nehmen den Port aus Schritt 12 heraus.
    attached: AtomicBool,
}
impl NetworkPublication {
    fn new(host: Arc<NetworkPublicationHost>) -> Self {
        Self {
            host,
            worker: Mutex::new(None),
            attached: AtomicBool::new(true),
        }
    }
    /// Startet den Hostlauf; erst wenn der Wirt als `Arc` besteht.
    pub(super) fn start(&self, native: Weak<NativeDesktopRuntime>) {
        let host = self.host.clone();
        let worker = std::thread::spawn(move || {
            host.run_loop(&|host| {
                let Some(native) = native.upgrade() else {
                    host.shutdown();
                    return;
                };
                if let Ok(inner) = native.inner.try_lock() {
                    let runtime = &inner.runtime;
                    let observer = WriterCustodyObserverV1::new(
                        runtime.database().clone(),
                        runtime.head(),
                        runtime.config().device_certificate_hash,
                    );
                    let _ = host.run_once(&observer);
                }
            });
        });
        *self.worker.lock().unwrap_or_else(PoisonError::into_inner) = Some(worker);
    }
    pub(super) fn host(&self) -> &Arc<NetworkPublicationHost> {
        &self.host
    }
    pub(super) fn is_attached(&self) -> bool {
        self.attached.load(Ordering::SeqCst)
    }
    #[cfg(feature = "test-support")]
    pub(super) fn detach(&self) {
        self.attached.store(false, Ordering::SeqCst);
    }
    pub(super) fn stop(&self) {
        self.host.shutdown();
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(worker) = worker {
            // Endet der letzte starke Griff im Hostlauf selbst, darf er nicht
            // auf sich warten.
            if worker.thread().id() != std::thread::current().id() {
                let _ = worker.join();
            }
        }
    }
    /// Ein Lauf mit der Beobachtung der gegebenen Laufzeit.
    pub(super) fn run_once(
        &self,
        runtime: &OperatorRuntime,
    ) -> Result<ea_archive_fs::PublicationStateV1, ArchiveBackendError> {
        self.host.run_once(&WriterCustodyObserverV1::new(
            runtime.database().clone(),
            runtime.head(),
            runtime.config().device_certificate_hash,
        ))
    }
}
impl Drop for NetworkPublication {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Der Sync-Zustand eines Netz-Writers aus seinem Publikationshost
/// (EA-CNA-PUB-4).
pub(super) struct NetworkSyncState(pub(super) Arc<NetworkPublicationHost>);
impl SyncStatePort for NetworkSyncState {
    fn sync_state(&self) -> Result<SyncStateView, ArchiveBackendError> {
        let (status, detail_cause) = self.0.sync_state();
        Ok(SyncStateView {
            status,
            detail_cause,
        })
    }
}

pub(super) struct WriterResources {
    archive: WriterArchive,
    timezone: String,
    profile_hash: ea_types::Hash32,
    /// Nur für ein Netzprofil. Das Feld steht nach `archive`, der Host hält
    /// aber ohnehin eine eigene Lesesicht der Komponente.
    publication: Option<NetworkPublication>,
}
impl WriterResources {
    pub(super) fn publication(&self) -> Option<&NetworkPublication> {
        self.publication.as_ref()
    }
}
impl WriterResources {
    pub(super) fn open(path: &Path, runtime: &OperatorRuntime) -> Result<Self, CommandError> {
        if runtime.config().role != ea_format::OperatorRoleV1::Writer {
            return Err(CommandError::new(CONFIG_ERROR));
        }
        let config = WriterSettings::load(path)?;
        let profile = config.archive_profile;
        let profile_hash = profile
            .profile_hash()
            .map_err(|error| CommandError::new(error.code()))?;
        let policy = BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields());
        let mut network_host = None;
        let archive = match &profile {
            ArchiveBackendProfileV1::LocalPath(local) => {
                // EA-CNA-REG-10 vor jeder I/O: sonst schriebe der Writer vom
                // reinen Netzkettenkopf direkt ins registrierte Netzziel.
                refuse_local_path_on_registered_anchor(runtime)
                    .map_err(|error| CommandError::new(error.code()))?;
                let vector_id = local.capability_test_vector_id.clone();
                let backend = LocalPathBackend::open(
                    runtime.config().archive_directory.clone(),
                    profile,
                    &policy,
                )
                .map_err(|error| CommandError::new(error.code()))?;
                let vector =
                    CapabilityTestVectorV1::new(&vector_id, b"EINSATZARCHIV-NATIVE-CAPABILITY-v1")
                        .map_err(|error| CommandError::new(error.code()))?;
                if !backend
                    .run_capability_test(&vector)
                    .map_err(|error| CommandError::new(error.code()))?
                    .all_proven()
                {
                    return Err(CommandError::new("EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS"));
                }
                WriterArchive::Local(Box::new(backend))
            }
            ArchiveBackendProfileV1::ControlledNetworkPath(_) => {
                // Registrierung, Profilzeile, Policy und die eigene Datenbank
                // prüft die Komponente selbst (EA-CNA-WRT-2): ein Profil, das
                // nicht exakt der registrierten Zeile entspricht, lehnt `open`
                // mit `EA-ARCHIVE-BYTE-CONFLICT` ab.
                let component = NativeArchiveExistingComponent::open_writer(
                    runtime,
                    NativeArchiveConfig {
                        profile,
                        local_commit_database_path: config.local_commit_database_path,
                    },
                )
                .map_err(|error| CommandError::new(error.code()))?;
                // EA-CNA-WRT-3/4: SQLCipher- und Netzziel-Capability vor dem
                // ersten Writer-Dienst. Der Publikationshost führt genau diese
                // Zulassung selbst aus und entsteht nur, wenn sie besteht —
                // ein nie qualifiziertes Netzziel bekommt keinen Host. Ein
                // fremd gehaltener Writer-Lock oder ein nicht belegter Flush
                // ist eine fehlende Eigenschaft.
                let host = NetworkPublicationHost::new(
                    &component,
                    &runtime.config().archive_directory,
                    &policy,
                )
                .map_err(|error| match error {
                    NativeArchiveOpenError::Capability
                    | NativeArchiveOpenError::Backend(
                        ArchiveBackendError::AlreadyLocked | ArchiveBackendError::FlushFailed,
                    ) => CommandError::new("EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS"),
                    other => CommandError::new(other.code()),
                })?;
                network_host = Some(Arc::new(host));
                WriterArchive::Network(Box::new(component))
            }
        };
        SqliteManagedCustody::new(runtime.database().clone())
            .observe_writer_archive(
                runtime.head(),
                runtime.config().device_certificate_hash,
                archive.holding(),
            )
            .map_err(|error| CommandError::new(error.code()))?;
        // EA-CNA-PUB-8 (b): was ein früherer Prozess committed, aber nicht
        // veröffentlicht hat, wird beim Start aus den Bytes neu abgeleitet
        // und veröffentlicht; danach übernimmt der Hostlauf.
        let publication = network_host.map(|host: Arc<NetworkPublicationHost>| {
            let publication = NetworkPublication::new(host);
            // Ein Befund steht danach im Sync-Zustand; der Start scheitert
            // daran nicht.
            let _ = publication.run_once(runtime);
            publication
        });
        Ok(Self {
            archive,
            timezone: config.timezone,
            profile_hash,
            publication,
        })
    }
}

struct WriterCall<'a> {
    service: &'a WriterService<'a>,
    proof: &'a OperatorSessionProof,
    master: &'a MasterDataRepository,
    timezone: &'a str,
    amendments: &'a AmendmentDraftService<'a, 'a>,
    clock: &'a (dyn Fn() -> ea_types::UnixMillis + Send + Sync),
    issued: Option<FinalizationPreview>,
    receipt: Option<StaleRegistryAcknowledgement>,
    stale_proof: Option<OperatorSessionProof>,
    publication: Option<&'a dyn ea_writer::NetworkPublicationPortV1>,
}
impl WriterCall<'_> {
    fn bound(&self) -> BoundWriter<'_> {
        BoundWriter::new(
            self.service,
            self.proof,
            self.master,
            self.timezone,
            self.issued.as_ref(),
        )
        .with_amendments(self.amendments, self.clock)
    }
    fn confirmed(
        &self,
        confirmed: &FinalizationPreviewView,
    ) -> Result<&FinalizationPreview, CommandError> {
        let issued = self
            .issued
            .as_ref()
            .ok_or_else(|| CommandError::new(PREVIEW_NOT_ISSUED))?;
        if FinalizationPreviewView::from(issued) != *confirmed {
            return Err(CommandError::new(PREVIEW_MISMATCH));
        }
        Ok(issued)
    }
}
struct WriterResult<T> {
    value: T,
    preview: Option<FinalizationPreview>,
    receipt: Option<StaleRegistryAcknowledgement>,
}
impl<T> WriterResult<T> {
    fn finished(value: T) -> Self {
        Self {
            value,
            preview: None,
            receipt: None,
        }
    }
}
impl NativeDesktopRuntime {
    fn writer_action<T>(
        &self,
        action: impl FnOnce(WriterCall<'_>) -> Result<WriterResult<T>, CommandError>,
    ) -> Result<T, CommandError> {
        let resources = self
            .writer
            .as_ref()
            .ok_or_else(|| CommandError::new("EA-DESKTOP-WRITER-UNAVAILABLE"))?;
        let (mut inner, epoch) = self
            .current_writer()
            .map_err(|error| CommandError::new(error.code()))?;
        let issued = inner.preview.take();
        let receipt = inner.stale_receipt.take();
        let stale_proof = inner
            .sessions
            .remove(&ReauthPurpose::RegistryStaleFinalize)
            .map(|session| session.into_parts().1);
        let session = inner
            .sessions
            .get(&ReauthPurpose::Finalize)
            .ok_or_else(|| CommandError::new(WriterError::ReauthRequired.code()))?;
        inner.verify(ReauthPurpose::Finalize, session)?;
        let runtime = &inner.runtime;
        SqliteManagedCustody::new(runtime.database().clone())
            .observe_writer_archive(
                runtime.head(),
                runtime.config().device_certificate_hash,
                resources.archive.holding(),
            )
            .map_err(|error| CommandError::new(error.code()))?;
        let public = runtime
            .native()
            .public_key(NativeSigningSlot::Writer)
            .map_err(|error| CommandError::new(error.code()))?
            .ok_or_else(|| CommandError::new(WriterError::ReauthRequired.code()))?;
        // LocalPath liest wie bisher die eigene Wurzel; ein Netzprofil die
        // Vereinigung aus der Netzsicht der aktuellen Aktion und der live
        // gelesenen lokalen Komponente (EA-CNA-WRT-5).
        let local_source;
        let network_source;
        let source: &dyn ArchiveSource = match &resources.archive {
            WriterArchive::Local(backend) => {
                local_source = backend.as_archive_source();
                &local_source
            }
            WriterArchive::Network(component) => {
                network_source = component
                    .writer_source(runtime.archive_snapshot())
                    .map_err(|error| CommandError::new(error.code()))?;
                &network_source
            }
        };
        let service = WriterService::new_for_writer(
            repository(&inner),
            runtime.signing_provider().clone(),
            resources.archive.backend(),
            source,
            runtime.head(),
            &[],
            IncidentNumberRegister::new(runtime.database().clone()),
            OperatorProfileRepository::new(runtime.database().clone()),
            WriterBindingV1 {
                binding_object_hash: runtime.config().binding_object_hash,
                writer_certificate_hash: runtime.config().device_certificate_hash,
                writer_key_thumbprint: public.thumbprint(),
                writer_signing_handle: runtime
                    .signing_provider()
                    .handle(SecretPurpose::WriterSigningKey),
                chain_id: runtime.anchor().chain_id(),
                archive_profile_hash: resources.profile_hash,
            },
        )
        .with_stale_registry_store(
            StaleRegistryStore::new(runtime.database().clone())
                .map_err(|error| CommandError::new(error.code()))?,
        );
        // Schritt 12 eines Netzprofils: der Host veröffentlicht die eben
        // committed Bytes (EA-CNA-PUB-8 (a)).
        let observer = WriterCustodyObserverV1::new(
            runtime.database().clone(),
            runtime.head(),
            runtime.config().device_certificate_hash,
        );
        let port = resources
            .publication
            .as_ref()
            .filter(|publication| publication.is_attached())
            .map(|publication| ObservedPublicationPortV1 {
                host: publication.host.as_ref(),
                observer: &observer,
            });
        let service = match &port {
            Some(port) => service.with_network_publication(port),
            None => service,
        };
        let amendments = AmendmentDraftService::new(&service, runtime.anchor());
        let observed = now()?;
        let clock = || observed;
        let outcome = action(WriterCall {
            service: &service,
            proof: session.proof(),
            master: &self.master_data,
            timezone: &resources.timezone,
            amendments: &amendments,
            clock: &clock,
            issued,
            receipt,
            stale_proof,
            publication: port
                .as_ref()
                .map(|port| port as &dyn ea_writer::NetworkPublicationPortV1),
        })?;
        self.finish_draft_action(&mut inner, epoch)
            .map_err(|error| CommandError::new(error.code()))?;
        inner.preview = outcome.preview;
        inner.stale_receipt = outcome.receipt;
        Ok(outcome.value)
    }
}
impl WriterPreviewPort for NativeDesktopRuntime {
    fn preview(
        &self,
        incident: &IncidentInputView,
    ) -> Result<FinalizationPreviewView, CommandError> {
        self.writer_action(|call| {
            let preview = call
                .service
                .preview(call.proof, call.bound().input(incident)?, (call.clock)())
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult {
                value: FinalizationPreviewView::from(&preview),
                preview: Some(preview),
                receipt: None,
            })
        })
    }
    fn validate_amendment_reference(
        &self,
        reference: &CorrectionReferenceView,
    ) -> Result<(), CommandError> {
        self.writer_action(|call| {
            call.bound().validate_amendment_reference(reference)?;
            Ok(WriterResult::finished(()))
        })
    }
    fn preview_amendment(
        &self,
        input: &AmendmentInputView,
    ) -> Result<FinalizationPreviewView, CommandError> {
        self.writer_action(|call| {
            let preview = call
                .service
                .preview_amendment(
                    call.proof,
                    call.bound().prepare_amendment_input(input)?,
                    (call.clock)(),
                )
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult {
                value: FinalizationPreviewView::from(&preview),
                preview: Some(preview),
                receipt: None,
            })
        })
    }
}
impl WriterFinalizePort for NativeDesktopRuntime {
    fn finalize(
        &self,
        incident: &IncidentInputView,
        confirmed: &FinalizationPreviewView,
    ) -> Result<FinalizeOutcomeView, CommandError> {
        self.writer_action(|call| {
            let issued = call.confirmed(confirmed)?;
            let input = call.bound().input(incident)?;
            let outcome = match call.receipt.as_ref() {
                Some(receipt) => call.service.finalize_with_stale_registry(
                    call.proof,
                    input,
                    issued,
                    receipt,
                    (call.clock)(),
                ),
                None => call
                    .service
                    .finalize(call.proof, input, issued, (call.clock)()),
            }
            .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult::finished(FinalizeOutcomeView::new(
                &outcome, None,
            )))
        })
    }
    fn finalize_amendment(
        &self,
        input: &AmendmentInputView,
        confirmed: &FinalizationPreviewView,
    ) -> Result<FinalizeOutcomeView, CommandError> {
        self.writer_action(|call| {
            let issued = call.confirmed(confirmed)?;
            let input = call.bound().prepare_amendment_input(input)?;
            let outcome = match call.receipt.as_ref() {
                Some(receipt) => call.service.finalize_amendment_with_stale_registry(
                    call.proof,
                    input,
                    issued,
                    receipt,
                    (call.clock)(),
                ),
                None => call
                    .service
                    .finalize_amendment(call.proof, input, issued, (call.clock)()),
            }
            .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult::finished(FinalizeOutcomeView::new(
                &outcome, None,
            )))
        })
    }
    fn acknowledge_stale_registry(
        &self,
        incident: &IncidentInputView,
        confirmed: &FinalizationPreviewView,
        warning_confirmed: bool,
    ) -> Result<(), CommandError> {
        self.writer_action(|mut call| {
            let proof = call
                .stale_proof
                .take()
                .ok_or_else(|| CommandError::new(WriterError::ReauthRequired.code()))?;
            let receipt = call
                .service
                .acknowledge_stale_registry(
                    proof,
                    call.bound().input(incident)?,
                    call.confirmed(confirmed)?,
                    warning_confirmed,
                    (call.clock)(),
                )
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult {
                value: (),
                preview: call.issued,
                receipt: Some(receipt),
            })
        })
    }
    fn acknowledge_stale_amendment(
        &self,
        input: &AmendmentInputView,
        confirmed: &FinalizationPreviewView,
        warning_confirmed: bool,
    ) -> Result<(), CommandError> {
        self.writer_action(|mut call| {
            let proof = call
                .stale_proof
                .take()
                .ok_or_else(|| CommandError::new(WriterError::ReauthRequired.code()))?;
            let receipt = call
                .service
                .acknowledge_stale_amendment(
                    proof,
                    call.bound().prepare_amendment_input(input)?,
                    call.confirmed(confirmed)?,
                    warning_confirmed,
                    (call.clock)(),
                )
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult {
                value: (),
                preview: call.issued,
                receipt: Some(receipt),
            })
        })
    }
}
impl StartupRecoveryPort for NativeDesktopRuntime {
    fn resolve_pending_finalization(&self) -> Result<RecoveryOutcome, WriterError> {
        let mut operation = None;
        self.writer_action(|call| {
            operation = Some(call.service.recover_pending());
            // EA-CNA-PUB-8 (b): nach der Start-Wiederherstellung, mit der
            // Beobachtung derselben Aktion.
            if let Some(port) = call.publication {
                port.publish_committed();
            }
            Ok(WriterResult::finished(()))
        })
        .map_err(|_| WriterError::ReauthRequired)?;
        operation.expect("the guarded action completed")
    }
}
