//! Der Publikationshost eines kontrollierten Netzprofils (EA-CNA-PUB-*).
//!
//! Der Host hält KEINE Queue im Speicher, die etwas wüsste, was die Bytes
//! nicht wissen: jeder Lauf leitet den Plan neu aus den committed lokalen
//! Bytes und dem LIVE gelesenen Netzziel ab (EA-CNA-PUB-1) und reicht ihn an
//! die [`PublicationQueue`] weiter, die ihn grants-first/`.eip`-last und
//! byteidentisch veröffentlicht (EA-CNA-PUB-2/3). Nach einem Neustart
//! entsteht derselbe Plan aus denselben Bytes wieder.
//!
//! Ausgelöst wird (a) in Schritt 12 über [`ObservedPublicationPortV1`], (b)
//! nach der Start-Wiederherstellung und (c) durch den Hostlauf
//! [`NetworkPublicationHost::run_loop`] mit dem Backoff des Profils
//! (EA-CNA-PUB-8). Vor jeder Publikation wird das Netzziel mit seinem
//! kanonischen Wurzelpfad beobachtet (EA-CNA-WRT-7).

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, atomic::AtomicU64},
    time::{Duration, Instant},
};

use ea_archive::{
    ArchiveBackend, ArchiveBackendError, ArchiveBackendProfileV1, ArchiveBlob, ArchiveError,
    ArchiveSource, BoundArchiveProfilePolicyV1, ControlledNetworkProfileV1,
};
use ea_archive_fs::{
    DetailCause, LocalPathBackend, NetworkArchiveTargetV1, PlannedPublicationV1,
    PublicationOutcomeV1, PublicationQueue, PublicationStateV1, PublicationTargetV1,
    SqlcipherArchiveBackend, SyncLocalArchiveV1, SyncStatus,
};
use ea_destruction::{DestructionError, SqliteManagedCustody};
use ea_local_store::EncryptedDatabase;
use ea_recovery::FsArchiveSource;
use ea_trust::WriterRegistryHeadRef;
use ea_types::CertificateHash;
use ea_writer::NetworkPublicationPortV1;

use crate::native_archive::{
    NativeArchiveExistingComponent, NativeArchiveOpenError, NetworkWriterSourceV1,
};
use crate::operator_runtime::OperatorArchiveSnapshot;

/// Untergrenze jeder Wartezeit des Hostlaufs. Ein Profil mit Backoff 0 (das
/// Format prüft `> 0` nur für LocalPath) darf den Lauf nicht zur
/// Dauerschleife machen.
const MINIMUM_BACKOFF_MS: u64 = 1_000;

/// Beobachtet das Netzziel unmittelbar vor einer Publikation (EA-CNA-WRT-7).
pub trait NetworkTargetObserverV1 {
    /// # Errors
    ///
    /// Scheitert die Beobachtung, wird nicht veröffentlicht.
    fn observe_network_target(&self, target: &LocalPathBackend) -> Result<(), ArchiveBackendError>;
}

/// Die Verwahrungsbeobachtung des Writers (dieselbe wie beim Writer-Start,
/// `observe_writer_archive`), hier mit dem Netzziel als Bestand: Ort ist
/// dessen kanonischer Wurzelpfad in der unveränderten Domäne
/// `EINSATZARCHIV-MANAGED-ARCHIVE-LOCATION-v1`.
pub struct WriterCustodyObserverV1<'a> {
    custody: SqliteManagedCustody,
    head: WriterRegistryHeadRef<'a>,
    certificate: CertificateHash,
}
impl<'a> WriterCustodyObserverV1<'a> {
    #[must_use]
    pub fn new(
        database: std::sync::Arc<EncryptedDatabase>,
        head: WriterRegistryHeadRef<'a>,
        certificate: CertificateHash,
    ) -> Self {
        Self {
            custody: SqliteManagedCustody::new(database),
            head,
            certificate,
        }
    }
}
impl NetworkTargetObserverV1 for WriterCustodyObserverV1<'_> {
    fn observe_network_target(&self, target: &LocalPathBackend) -> Result<(), ArchiveBackendError> {
        self.custody
            .observe_writer_archive(self.head, self.certificate, target)
            .map(|_| ())
            .map_err(|error| match error {
                // `observe_writer_archive` meldet auch einen fremd gehaltenen
                // Writer-Lock des Netzziels als `Storage` (für die übrigen
                // Aufrufer unverändert). Hier wird die Konkurrenz eigens
                // geprüft: sie ist ein wartendes Netzziel (EA-CNA-REC-2),
                // kein Befund.
                DestructionError::Storage => {
                    match ea_archive::ArchiveBackend::acquire_writer_lock(target) {
                        Err(ArchiveBackendError::AlreadyLocked) => {
                            ArchiveBackendError::AlreadyLocked
                        }
                        // Lock, Wurzel oder Lesen des Netzziels: ob das die
                        // verlorene Erreichbarkeit ist, entscheidet der Host
                        // an der Wurzel.
                        _ => ArchiveBackendError::Io,
                    }
                }
                _ => ArchiveBackendError::VerificationFailed,
            })
    }
}

/// Der Schritt-12-Port: ein Lauf des Hosts mit der Beobachtung der
/// aktuellen Aktion. Nur hier wird der typisierte Ausgang auf
/// [`PublicationOutcomeV1`] verkürzt (ein Befund wird `Deferred`, weil der
/// Writer ihn ohnehin nur berichtet; den Befund trägt `sync_state`).
pub struct ObservedPublicationPortV1<'a> {
    pub host: &'a NetworkPublicationHost,
    pub observer: &'a (dyn NetworkTargetObserverV1 + Sync),
}
impl NetworkPublicationPortV1 for ObservedPublicationPortV1<'_> {
    fn publish_committed(&self) -> PublicationOutcomeV1 {
        self.host
            .run_once(self.observer)
            .map_or(PublicationOutcomeV1::Deferred, |state| state.outcome())
    }
}

/// Was der letzte Lauf über den Bestand wusste.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Observed {
    /// Noch kein Lauf: nichts ist bekannt.
    Unknown,
    /// Nichts steht aus: jedes committed lokale Objekt liegt am Netzziel.
    Clean,
    /// Es steht etwas aus; die Ursache tritt daneben.
    Waiting(DetailCause),
    /// Ein Datenbefund (Bytekonflikt, beschädigtes Objekt, lokaler
    /// Lesefehler), keine verlorene Erreichbarkeit.
    Failed,
}
impl Observed {
    const fn is_clean(self) -> bool {
        matches!(self, Self::Clean | Self::Unknown)
    }
}

struct HostState {
    observed: Observed,
    /// Hostläufe nach einem nicht sauberen Ausgang, je Prozess gezählt.
    attempts: u64,
    /// Die nächste Wartezeit nach einem nicht sauberen Ausgang.
    delay_ms: u64,
    /// `resume_max_attempts` ist verbraucht; gilt bis zum nächsten Start.
    exhausted: bool,
    /// Ein Lauf ist von sauber auf nicht sauber gekippt: der Hostlauf soll
    /// nicht bis zum Ende seiner Ruhe-Wartezeit schlafen.
    signaled: bool,
    stopped: bool,
    /// Hat der letzte `next_delay` einen Versuch gezählt?
    counted: bool,
}

/// Ergebnis der Ableitung eines Laufs.
enum Derived {
    /// Ohne Publikation erledigt (nichts ausstehend, wartend oder Befund).
    Done(Result<PublicationStateV1, ArchiveBackendError>),
    /// Es steht etwas aus: der Griff aufs Netzziel für die Beobachtung und
    /// der Plan.
    Pending(Box<LocalPathBackend>, PlannedPublicationV1),
}

/// Wie eine Wartezeit des Hostlaufs endete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Wake {
    Elapsed,
    Signaled,
    Stopped,
}

/// Der Publikationshost eines kontrollierten Netzprofils.
///
/// Er entsteht NUR über [`Self::new`], und `new` führt die Capability-
/// Zulassung von Komponente und Netzziel selbst aus
/// ([`NativeArchiveExistingComponent::require_capabilities`]). Ein Netzziel,
/// das die Zulassung nie bestand — etwa ein Share, der den vollen Flush
/// verweigert —, bekommt deshalb nie einen Host, statt ewig als
/// `Netzarchiv wartet` zu erscheinen.
pub struct NetworkPublicationHost {
    queue: PublicationQueue,
    local: Box<dyn ArchiveSource + Send + Sync>,
    remote_root: PathBuf,
    profile: ControlledNetworkProfileV1,
    policy: BoundArchiveProfilePolicyV1,
    state: Mutex<HostState>,
    wake: Condvar,
    /// Serialisiert ganze Läufe (Ableitung, Beobachtung UND Publikation):
    /// Schritt 12 und der Hostlauf dürfen sich nicht verschränken.
    run: Mutex<()>,
    runs: AtomicU64,
}

impl NetworkPublicationHost {
    /// Baut den Host über der lokalen Komponente eines Netzprofils.
    ///
    /// Führt zuerst die Capability-Zulassung aus (EA-CNA-WRT-3); erst danach
    /// entsteht das Produktionsziel [`NetworkArchiveTargetV1`] über
    /// `archive_directory` — nie angelegt, nie ein anderes Ziel.
    ///
    /// # Errors
    ///
    /// `Config` für eine LocalPath-Komponente; der Fehler der Zulassung
    /// (`Capability`, `Backend(AlreadyLocked | FlushFailed | Io | …)`)
    /// unverändert; sonst der Fehler beim Öffnen der Lesesicht oder der
    /// Policyprüfung des Ziels.
    pub fn new(
        component: &NativeArchiveExistingComponent,
        archive_directory: &Path,
        policy: &BoundArchiveProfilePolicyV1,
    ) -> Result<Self, NativeArchiveOpenError> {
        let profile = component
            .network_profile()
            .ok_or(NativeArchiveOpenError::Config)?
            .clone();
        component.require_capabilities(archive_directory, policy)?;
        let local = component.committed_reader()?;
        let target = NetworkArchiveTargetV1::new(
            archive_directory.to_owned(),
            ArchiveBackendProfileV1::ControlledNetworkPath(profile.clone()),
            policy.clone(),
        )?;
        Self::from_parts(
            Box::new(local),
            archive_directory,
            profile,
            policy,
            Box::new(target),
        )
    }

    /// Die Montage ohne Zulassung — nur für [`Self::new`] und die
    /// Unit-Tests, die das Ziel beobachten müssen.
    pub(crate) fn from_parts(
        local: Box<dyn ArchiveSource + Send + Sync>,
        remote_root: &Path,
        profile: ControlledNetworkProfileV1,
        policy: &BoundArchiveProfilePolicyV1,
        target: Box<dyn PublicationTargetV1>,
    ) -> Result<Self, NativeArchiveOpenError> {
        let queue = PublicationQueue::new(
            target,
            ArchiveBackendProfileV1::ControlledNetworkPath(profile.clone()),
            policy,
        )?;
        let host = Self {
            queue,
            local,
            remote_root: remote_root.to_owned(),
            state: Mutex::new(HostState {
                observed: Observed::Unknown,
                attempts: 0,
                delay_ms: 0,
                exhausted: false,
                signaled: false,
                stopped: false,
                counted: false,
            }),
            wake: Condvar::new(),
            profile,
            policy: policy.clone(),
            run: Mutex::new(()),
            runs: AtomicU64::new(0),
        };
        host.lock_state().delay_ms = host.initial_backoff_ms();
        Ok(host)
    }

    fn initial_backoff_ms(&self) -> u64 {
        self.profile
            .resume_backoff_initial_ms
            .max(MINIMUM_BACKOFF_MS)
    }

    fn maximum_backoff_ms(&self) -> u64 {
        self.profile
            .resume_backoff_max_ms
            .max(self.initial_backoff_ms())
    }

    fn open_remote(&self) -> Result<LocalPathBackend, ArchiveBackendError> {
        LocalPathBackend::open_existing(
            self.remote_root.clone(),
            ArchiveBackendProfileV1::ControlledNetworkPath(self.profile.clone()),
            &self.policy,
        )
    }

    /// Der abgeleitete Plan, ohne zu veröffentlichen (EA-CNA-PUB-1/2).
    ///
    /// # Errors
    ///
    /// Der Fehler beim Öffnen des Netzziels oder der Ableitung.
    pub fn pending(&self) -> Result<PlannedPublicationV1, ArchiveBackendError> {
        let remote = self.open_remote()?;
        PlannedPublicationV1::derive_pending(self.local.as_ref(), &remote)
    }

    /// Ein Lauf: ableiten, das Netzziel beobachten, veröffentlichen.
    ///
    /// `Ok` trägt veröffentlicht, nichts ausstehend oder aufgeschoben (ein
    /// nicht erreichbares Netzziel ist `Deferred` mit `Netzarchiv wartet`);
    /// `Err` ist ein Befund.
    ///
    /// # Errors
    ///
    /// Ein Datenbefund: Bytekonflikt, beschädigtes Objekt, lokaler
    /// Lesefehler der Komponente, gescheiterte Beobachtung eines erreichbaren
    /// Netzziels oder ein Hartfehler des Ziels. Ein aufgenommener Plan bleibt
    /// dabei in der Warteschlange; aus der Ableitung wurde nichts eingereiht.
    pub fn run_once(
        &self,
        observer: &dyn NetworkTargetObserverV1,
    ) -> Result<PublicationStateV1, ArchiveBackendError> {
        let _run = self.run.lock().unwrap_or_else(PoisonError::into_inner);
        self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let result = match self.derive() {
            Derived::Done(result) => result,
            Derived::Pending(remote, planned) => self.publish(observer, &remote, planned),
        };
        self.record(&result);
        result
    }

    /// Phase 1 des Hostlaufs, OHNE Autorität: ableiten und einen Ausgang,
    /// der keine Publikation braucht (nichts ausstehend, Netzziel weg,
    /// Befund), eintragen. `true` heißt: es steht etwas aus, und der
    /// Aufrufer muss mit Autorität [`Self::run_once`] rufen.
    ///
    /// So hält der Hostlauf die Autorität seines Wirts (und damit dessen
    /// Zustandssperre) nur, wenn wirklich veröffentlicht wird.
    pub fn settle_unless_pending(&self) -> bool {
        let _run = self.run.lock().unwrap_or_else(PoisonError::into_inner);
        self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match self.derive() {
            Derived::Done(result) => {
                self.record(&result);
                false
            }
            Derived::Pending(..) => true,
        }
    }

    fn record(&self, result: &Result<PublicationStateV1, ArchiveBackendError>) {
        let observed = match result {
            Ok(state) => match state.outcome() {
                PublicationOutcomeV1::NothingPending
                | PublicationOutcomeV1::PublishedCompletely => Observed::Clean,
                PublicationOutcomeV1::Deferred => Observed::Waiting(
                    state
                        .detail_cause()
                        .unwrap_or(DetailCause::NetworkArchiveWaiting),
                ),
                PublicationOutcomeV1::QueueLimitReached => {
                    Observed::Waiting(DetailCause::QueueLimitReached)
                }
            },
            Err(_) => Observed::Failed,
        };
        let mut state = self.lock_state();
        if state.observed.is_clean() && !observed.is_clean() {
            state.signaled = true;
            self.wake.notify_all();
        }
        state.observed = observed;
    }

    fn lost(&self, error: &ArchiveBackendError) -> bool {
        matches!(
            error,
            ArchiveBackendError::Io | ArchiveBackendError::FlushFailed
        ) && !self.remote_is_reachable()
    }

    /// Öffnen und Ableiten. Alles, was ohne Publikation endet, ist `Done`.
    fn derive(&self) -> Derived {
        let waiting = |cause| Derived::Done(Ok(PublicationStateV1::deferred(Some(cause))));
        // Die Ableitung öffnet ihren EIGENEN Griff auf das Netzziel und gibt
        // ihn zurück, bevor die Warteschlange ihren nimmt: beide nehmen
        // kurzzeitig den Writer-Lock des Netzziels, und sie dürfen sich nie
        // überlappen. Nicht als Feld zwischenspeichern.
        let remote = match self.open_remote() {
            Ok(remote) => remote,
            Err(error) if self.lost(&error) => return waiting(DetailCause::NetworkArchiveWaiting),
            Err(ArchiveBackendError::ProfileNotAllowed) => {
                return waiting(DetailCause::ProfileNotAllowed);
            }
            Err(error) => return Derived::Done(Err(error)),
        };
        // Ein Fehler der Ableitung ist ein Befund: Bytekonflikt, beschädigtes
        // Objekt oder ein LOKALER Lesefehler — `read_relative` des Netzziels
        // meldet selbst keinen Fehler.
        let planned = match PlannedPublicationV1::derive_pending(self.local.as_ref(), &remote) {
            Ok(planned) => planned,
            Err(error) => return Derived::Done(Err(error)),
        };
        if planned.is_empty() {
            drop(remote);
            // Nichts fehlt am Netzziel. Ein älterer, aufgeschobener Plan im
            // Platz wird trotzdem abgeräumt — über Create-if-absent ist das
            // idempotent und bringt keine neuen Bytes ans Netzziel.
            return Derived::Done(self.settle(self.queue.resume()));
        }
        Derived::Pending(Box::new(remote), planned)
    }

    fn publish(
        &self,
        observer: &dyn NetworkTargetObserverV1,
        remote: &LocalPathBackend,
        planned: PlannedPublicationV1,
    ) -> Result<PublicationStateV1, ArchiveBackendError> {
        let waiting = || {
            Ok(PublicationStateV1::deferred(Some(
                DetailCause::NetworkArchiveWaiting,
            )))
        };
        // EA-CNA-WRT-7: unmittelbar vor der Publikation. Ein fremd
        // gehaltener Netzziel-Lock wartet (EA-CNA-REC-2).
        match observer.observe_network_target(remote) {
            Ok(()) => {}
            Err(error) if self.lost(&error) => return waiting(),
            Err(ArchiveBackendError::AlreadyLocked) => return waiting(),
            Err(error) => return Err(error),
        }
        self.settle(self.queue.publish(planned))
    }

    /// Ein Fehler der Warteschlange: fremd gehaltener Netzziel-Lock (etwa
    /// eine Recovery-Capture, EA-CNA-REC-2) wartet, eine fehlende
    /// Policyzulassung trägt ihre Ursache, alles andere ist ein Befund.
    fn settle(
        &self,
        result: Result<PublicationStateV1, ArchiveBackendError>,
    ) -> Result<PublicationStateV1, ArchiveBackendError> {
        match result {
            Err(ArchiveBackendError::AlreadyLocked) => Ok(PublicationStateV1::deferred(Some(
                DetailCause::NetworkArchiveWaiting,
            ))),
            Err(ArchiveBackendError::Io | ArchiveBackendError::FlushFailed)
                if !self.remote_is_reachable() =>
            {
                Ok(PublicationStateV1::deferred(Some(
                    DetailCause::NetworkArchiveWaiting,
                )))
            }
            Err(ArchiveBackendError::ProfileNotAllowed) => Ok(PublicationStateV1::deferred(Some(
                DetailCause::ProfileNotAllowed,
            ))),
            other => other,
        }
    }

    fn remote_is_reachable(&self) -> bool {
        std::fs::metadata(&self.remote_root).is_ok_and(|metadata| metadata.is_dir())
    }

    fn lock_state(&self) -> MutexGuard<'_, HostState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Der Sync-Zustand nach EA-CNA-PUB-4: vier Zustände, die Ursache
    /// daneben.
    ///
    /// Ohne Server gilt: leere Queue → `lokal gesichert`; ausstehend →
    /// `Upload ausstehend` mit Ursache; ein Befund → `Fehler` (ein
    /// Bytekonflikt ist weder verlorene Eigenschaft noch leere Queue). Vor
    /// dem ersten Lauf ist nichts bekannt, und behauptet wird dann nur
    /// `Upload ausstehend` ohne Ursache — nie `lokal gesichert`.
    pub fn sync_state(&self) -> (SyncStatus, Option<DetailCause>) {
        let state = self.lock_state();
        match state.observed {
            Observed::Clean => (SyncStatus::LocallySaved, None),
            Observed::Unknown => (SyncStatus::UploadPending, None),
            Observed::Failed => (SyncStatus::Failed, None),
            Observed::Waiting(_) if state.exhausted => (
                SyncStatus::UploadPending,
                Some(DetailCause::ResumeAttemptsExhausted),
            ),
            Observed::Waiting(cause) => (SyncStatus::UploadPending, Some(cause)),
        }
    }

    /// Die Wartezeit bis zum nächsten Hostlauf (EA-CNA-PUB-8 (c)).
    ///
    /// Sauber: `resume_backoff_max_ms` als Ruhe-Wartezeit ohne Versuch; der
    /// Lauf wird vorher geweckt, sobald ein Lauf nicht sauber endet. Nicht
    /// sauber: jeder Aufruf zählt einen Versuch; die Wartezeit beginnt bei
    /// `resume_backoff_initial_ms` und verdoppelt sich bis
    /// `resume_backoff_max_ms`, jeweils mindestens eine Sekunde. Sind
    /// `resume_max_attempts` Versuche in diesem Prozess verbraucht, liefert
    /// sie `None` — bis zum nächsten Start mit `Wiederaufnahme erschöpft`.
    pub fn next_delay(&self) -> Option<Duration> {
        let initial = self.initial_backoff_ms();
        let maximum = self.maximum_backoff_ms();
        let mut state = self.lock_state();
        state.counted = false;
        if state.exhausted {
            return None;
        }
        if state.observed.is_clean() {
            state.delay_ms = initial;
            return Some(Duration::from_millis(maximum));
        }
        if state.attempts >= self.profile.resume_max_attempts {
            state.exhausted = true;
            return None;
        }
        state.attempts += 1;
        state.counted = true;
        let delay = state.delay_ms.max(initial);
        state.delay_ms = delay.saturating_mul(2).min(maximum);
        Some(Duration::from_millis(delay))
    }

    fn wait(&self, delay: Duration) -> Wake {
        let until = Instant::now() + delay;
        let mut state = self.lock_state();
        loop {
            if state.stopped {
                return Wake::Stopped;
            }
            if state.signaled {
                state.signaled = false;
                return Wake::Signaled;
            }
            let now = Instant::now();
            if now >= until {
                return Wake::Elapsed;
            }
            state = self
                .wake
                .wait_timeout(state, until - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Der Hostlauf: wartet [`Self::next_delay`] (oder bis ein Lauf von
    /// außen nicht sauber endet) und ruft dann `run`, bis `next_delay`
    /// `None` liefert oder [`Self::shutdown`] gerufen wurde.
    ///
    /// `run` liefert, ob tatsächlich ein Lauf stattfand. Ein übersprungener
    /// Lauf (etwa weil die Autorität gerade nicht verfügbar war) verbraucht
    /// keinen Versuch. Das Signal, das der eigene Lauf beim Kippen auslöst,
    /// wird verworfen: sonst zählte derselbe Lauf zwei Versuche.
    pub fn run_loop(&self, run: &dyn Fn(&Self) -> bool) {
        while let Some(delay) = self.next_delay() {
            match self.wait(delay) {
                Wake::Stopped => return,
                Wake::Signaled => {
                    // Ein Signal von außen kam, bevor der gezählte Lauf
                    // stattfand: der Versuch wird erst beim Lauf gezählt.
                    self.refund_attempt();
                }
                Wake::Elapsed => {
                    let ran = run(self);
                    if !ran {
                        self.refund_attempt();
                    }
                    self.lock_state().signaled = false;
                }
            }
        }
    }

    fn refund_attempt(&self) {
        let mut state = self.lock_state();
        if state.counted {
            state.attempts = state.attempts.saturating_sub(1);
            state.counted = false;
        }
    }

    /// Beendet [`Self::run_loop`] sofort, auch mitten in einer Wartezeit.
    pub fn shutdown(&self) {
        self.lock_state().stopped = true;
        self.wake.notify_all();
    }

    /// Die in diesem Prozess gezählten Wiederaufnahmeversuche.
    #[must_use]
    pub fn attempts(&self) -> u64 {
        self.lock_state().attempts
    }

    /// Wie viele Läufe dieser Host bisher begann.
    #[must_use]
    pub fn runs(&self) -> u64 {
        self.runs.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Der lokale Archivport des Sync-Klienten für ein kontrolliertes Netzprofil
/// (EA-CNA-PUB-5).
///
/// Die Quelle ist dieselbe Vereinigung wie beim Netz-Writer
/// ([`NetworkWriterSourceV1`]), aber mit einer Netzhälfte, die bei JEDEM
/// Aufruf von `committed_source` live aus dem Netzziel gelesen wird — ein
/// langlebiger Port sähe sonst nach einer Bereinigung (EA-CNA-SRC-5) eine
/// Lücke. Nur ein nicht lesbares Netzziel lässt die Grundlinie des Snapshots
/// an seine Stelle treten (EA-CNA-SRC-4); ist sie veraltet, scheitert die
/// Verifikation an der Lücke, statt still zu wenig zu sehen. Die lokale
/// Komponente wird bei jedem Besuch live gelesen. Das Backend ist die lokale SQLCipher-Komponente — nie
/// ein `LocalPathBackend` des Netzziels. Eine verifizierte Quittung landet
/// also lokal und erreicht das Netzziel erst über die Publikation.
pub struct NetworkSyncArchiveV1 {
    component: NativeArchiveExistingComponent,
    remote_root: PathBuf,
    baseline: Arc<FsArchiveSource>,
}

impl NetworkSyncArchiveV1 {
    /// Bindet die lokale Komponente an das Netzziel `archive_directory`
    /// (dasselbe Verzeichnis wie beim Start der Laufzeit) und behält die
    /// Netzsicht von `snapshot` als Grundlinie für ein unlesbares Netzziel.
    ///
    /// # Errors
    ///
    /// `Config` für eine LocalPath-Komponente oder einen Snapshot ohne
    /// Netzsicht — derselbe Befund wie bei
    /// [`NativeArchiveExistingComponent::writer_source`].
    pub fn new(
        component: NativeArchiveExistingComponent,
        archive_directory: &Path,
        snapshot: &OperatorArchiveSnapshot,
    ) -> Result<Self, NativeArchiveOpenError> {
        if component.sqlcipher_backend().is_none() {
            return Err(NativeArchiveOpenError::Config);
        }
        let baseline = Arc::clone(
            snapshot
                .remote_baseline()
                .ok_or(NativeArchiveOpenError::Config)?,
        );
        Ok(Self {
            component,
            remote_root: archive_directory.to_owned(),
            baseline,
        })
    }
}

impl SyncLocalArchiveV1 for NetworkSyncArchiveV1 {
    fn backend(&self) -> &dyn ArchiveBackend {
        self.component.local_backend()
    }

    fn committed_source(&self) -> Result<Box<dyn ArchiveSource + '_>, ArchiveBackendError> {
        // `new` lässt nur eine Netzkomponente zu; ohne SQLCipher-Backend gibt
        // es keine lokale Hälfte der Vereinigung.
        let local = self
            .component
            .sqlcipher_backend()
            .ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
        // Derselbe Lesepfad wie beim Start (`open_with_anchor`).
        let remote = match FsArchiveSource::open_committed(&self.remote_root) {
            Ok(live) => NetworkHalf::Live(live),
            Err(_) => NetworkHalf::Baseline(&self.baseline),
        };
        Ok(Box::new(NetworkSyncSourceV1 { remote, local }))
    }

    fn requires_network_publication(&self) -> bool {
        true
    }
}

/// Die Netzhälfte eines Aufrufs: live gelesen oder die Grundlinie.
enum NetworkHalf<'a> {
    Live(FsArchiveSource),
    Baseline(&'a FsArchiveSource),
}

/// Die Vereinigung eines Aufrufs; vereinigt wird wie beim Netz-Writer.
struct NetworkSyncSourceV1<'a> {
    remote: NetworkHalf<'a>,
    local: &'a SqlcipherArchiveBackend,
}

impl ArchiveSource for NetworkSyncSourceV1<'_> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        let remote = match &self.remote {
            NetworkHalf::Live(live) => live,
            NetworkHalf::Baseline(baseline) => baseline,
        };
        NetworkWriterSourceV1::over(remote, self.local).visit_blobs(visitor)
    }
}

#[cfg(test)]
#[path = "../../ea-format/tests/support/mod.rs"]
mod format_fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use ea_archive::{
        ArchiveBackendError, ArchiveBackendProfileV1, ArchiveBlob, ArchiveError, ArchivePath,
        ArchiveSource, BoundArchiveProfilePolicyV1, ControlledNetworkProfileV1,
    };
    use ea_archive_fs::{
        NetworkArchiveTargetV1, PublicationOutcomeV1, PublicationTargetV1, SyncStatus,
    };
    use ea_format::{FreeTextPolicyFieldsV1, PolicyFieldsV1, RetentionPolicyFieldsV1};
    use ea_types::{ChainSequence, OrganizationId};
    use std::sync::{Arc, Mutex};

    fn profile() -> ControlledNetworkProfileV1 {
        ControlledNetworkProfileV1 {
            filesystem_row_id: "unit-network-publication".into(),
            protocol_id: "SMB3".into(),
            server_product: "unit".into(),
            server_version: "1".into(),
            mount_options: vec![],
            failover_config_id: "none".into(),
            capability_test_vector_id: "unit-network-publication-v1".into(),
            queue_max_objects: 64,
            queue_max_bytes: 16 * 1024 * 1024,
            resume_backoff_initial_ms: 100,
            resume_backoff_max_ms: 300,
            resume_max_attempts: 2,
        }
    }
    fn policy(profile: &ArchiveBackendProfileV1) -> BoundArchiveProfilePolicyV1 {
        BoundArchiveProfilePolicyV1::from_policy(&PolicyFieldsV1 {
            organization_id: OrganizationId::try_from(&[0x21_u8; 16][..]).unwrap(),
            policy_version: 1,
            previous_policy_object_hash: None,
            operating_profile: 0,
            max_registry_age_ms: 86_400_000,
            max_future_clock_skew_ms: 300_000,
            registry_expiry_behavior: 0,
            evidence_max_delay_ms: 60_000,
            reader_inactivity_ms: 900_000,
            reader_trust_refresh_ms: 86_400_000,
            reader_history_access_allowed: true,
            allowed_archive_profile_hashes: vec![profile.profile_hash().unwrap()],
            backup_frequency_ms: 86_400_000,
            restore_test_interval_ms: 2_592_000_000,
            retention_policy: RetentionPolicyFieldsV1 {
                minimum_retention_ms: None,
                destruction_enabled: false,
                eds_privacy_decision_document_hash: None,
            },
            free_text_policy: FreeTextPolicyFieldsV1 {
                free_text_allowed: false,
                rule_set_version: "1".to_owned(),
                local_pattern_warning_enabled: true,
            },
            allowed_crypto_suite_ids: vec!["EINSATZARCHIV-SUITE-1".to_owned()],
            allowed_format_versions: vec![1],
            effective_from_sequence: ChainSequence::new(0),
        })
    }

    /// Keine Verwahrungsbeobachtung (die Desktop-Tests messen sie).
    struct Unobserved;
    impl NetworkTargetObserverV1 for Unobserved {
        fn observe_network_target(
            &self,
            _target: &ea_archive_fs::LocalPathBackend,
        ) -> Result<(), ArchiveBackendError> {
            Ok(())
        }
    }

    /// Die committed lokale Komponente als feste Liste.
    struct Committed(Vec<(String, Vec<u8>)>);
    impl ArchiveSource for Committed {
        fn visit_blobs(
            &self,
            visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
        ) -> Result<(), ArchiveError> {
            for (path, bytes) in &self.0 {
                visitor(ArchiveBlob::new(path, bytes))?;
            }
            Ok(())
        }
    }

    /// Das Produktionsziel, umhüllt: jede Adresse wird in der Reihenfolge
    /// protokolliert, in der sie das echte Netzziel ERREICHT.
    struct Spy {
        inner: NetworkArchiveTargetV1,
        order: Arc<Mutex<Vec<String>>>,
    }
    impl PublicationTargetV1 for Spy {
        fn is_connected(&self) -> bool {
            self.inner.is_connected()
        }
        fn reconnect(&self) {
            self.inner.reconnect();
        }
        fn publish_one(
            &self,
            relative: &ArchivePath,
            bytes: &[u8],
        ) -> Result<(), ArchiveBackendError> {
            self.inner.publish_one(relative, bytes)?;
            self.order
                .lock()
                .unwrap()
                .push(relative.as_str().to_owned());
            Ok(())
        }
    }

    #[test]
    fn publication_order_is_grants_first_entry_last() {
        let remote = std::env::temp_dir().join(format!(
            "ea-admin-network-publication-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&remote);
        std::fs::create_dir_all(&remote).unwrap();
        let network = profile();
        let wrapped = ArchiveBackendProfileV1::ControlledNetworkPath(network.clone());
        let policy = policy(&wrapped);
        let first_entry = format_fixture::valid_eip(vec![0x11; 48]);
        let second_entry = format_fixture::valid_eip(vec![0x22; 48]);
        // Absichtlich NICHT in Planordnung: das `.eip` der Sequenz 1 steht
        // vorn, die Grants der Sequenz 2 vor denen der Sequenz 1.
        let local = Committed(vec![
            ("entries/000000000001_e1.eip".into(), first_entry.clone()),
            (
                "grants/000000000002_a.eag".into(),
                format_fixture::valid_historical_eag(),
            ),
            ("entries/000000000002_e2.eip".into(), second_entry.clone()),
            (
                "grants/000000000001_b.eag".into(),
                format_fixture::valid_historical_eag(),
            ),
            (
                "grants/000000000001_a.eag".into(),
                format_fixture::valid_initial_eag(),
            ),
        ]);
        let order = Arc::new(Mutex::new(Vec::new()));
        let target = Spy {
            inner: NetworkArchiveTargetV1::new(remote.clone(), wrapped, policy.clone()).unwrap(),
            order: order.clone(),
        };
        let host = NetworkPublicationHost::from_parts(
            Box::new(local),
            &remote,
            network,
            &policy,
            Box::new(target),
        )
        .unwrap();

        let state = host.run_once(&Unobserved).unwrap();
        assert_eq!(state.outcome(), PublicationOutcomeV1::PublishedCompletely);
        assert_eq!(
            *order.lock().unwrap(),
            vec![
                "grants/000000000001_a.eag",
                "grants/000000000001_b.eag",
                "entries/000000000001_e1.eip",
                "grants/000000000002_a.eag",
                "entries/000000000002_e2.eip",
            ],
            "je Sequenz alle Grants vor ihrem `.eip`, die Sequenzen aufsteigend"
        );
        assert_eq!(
            std::fs::read(remote.join("entries/000000000001_e1.eip")).unwrap(),
            first_entry,
            "byteidentisch am Netzziel"
        );
        assert_eq!(host.sync_state(), (SyncStatus::LocallySaved, None));
        // Ein zweiter Lauf findet nichts mehr: die Queue ist abgeleitet.
        assert_eq!(
            host.run_once(&Unobserved).unwrap().outcome(),
            PublicationOutcomeV1::NothingPending
        );
        let _ = std::fs::remove_dir_all(&remote);
    }

    #[test]
    fn an_unreachable_remote_waits_with_profile_backoff_until_attempts_are_exhausted() {
        use ea_archive_fs::DetailCause;
        use std::time::Duration;
        let remote = std::env::temp_dir().join(format!(
            "ea-admin-network-publication-gone-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&remote);
        let network = profile();
        let wrapped = ArchiveBackendProfileV1::ControlledNetworkPath(network.clone());
        let policy = policy(&wrapped);
        let local = Committed(vec![(
            "entries/000000000001_e1.eip".into(),
            format_fixture::valid_eip(vec![0x33; 48]),
        )]);
        let target = NetworkArchiveTargetV1::new(remote.clone(), wrapped, policy.clone()).unwrap();
        let host = NetworkPublicationHost::from_parts(
            Box::new(local),
            &remote,
            network,
            &policy,
            Box::new(target),
        )
        .unwrap();
        assert_eq!(
            host.sync_state(),
            (SyncStatus::UploadPending, None),
            "vor dem ersten Lauf wird nichts behauptet"
        );
        // Sauber/unbekannt: die Ruhe-Wartezeit, mindestens eine Sekunde.
        assert_eq!(host.next_delay(), Some(Duration::from_millis(1_000)));
        let state = host.run_once(&Unobserved).unwrap();
        assert_eq!(state.outcome(), PublicationOutcomeV1::Deferred);
        assert!(!state.fell_back_to_another_target());
        assert!(!remote.exists(), "das Netzziel wird nie angelegt");
        assert_eq!(
            host.sync_state(),
            (
                SyncStatus::UploadPending,
                Some(DetailCause::NetworkArchiveWaiting)
            )
        );
        // Das Profil (100/300 ms) wird auf eine Sekunde angehoben; höchstens
        // `resume_max_attempts` (2) Versuche.
        assert_eq!(host.next_delay(), Some(Duration::from_millis(1_000)));
        let _ = host.run_once(&Unobserved);
        assert_eq!(host.next_delay(), Some(Duration::from_millis(1_000)));
        let _ = host.run_once(&Unobserved);
        assert_eq!(host.next_delay(), None);
        assert_eq!(
            host.sync_state(),
            (
                SyncStatus::UploadPending,
                Some(DetailCause::ResumeAttemptsExhausted)
            )
        );
        // Kehrt das Netzziel zurück, veröffentlicht ein Schritt-12-Lauf
        // trotzdem; der Hostlauf bleibt bis zum nächsten Start beendet.
        std::fs::create_dir_all(&remote).unwrap();
        assert_eq!(
            host.run_once(&Unobserved).unwrap().outcome(),
            PublicationOutcomeV1::PublishedCompletely
        );
        assert_eq!(host.sync_state(), (SyncStatus::LocallySaved, None));
        assert_eq!(host.next_delay(), None);
        let _ = std::fs::remove_dir_all(&remote);
    }

    /// Eine lokale Komponente, deren Lesen scheitert (SQLCipher-I/O).
    struct Unreadable;
    impl ArchiveSource for Unreadable {
        fn visit_blobs(
            &self,
            _visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
        ) -> Result<(), ArchiveError> {
            Err(ArchiveError::Unavailable)
        }
    }

    fn remote_dir(label: &str) -> std::path::PathBuf {
        let remote = std::env::temp_dir().join(format!(
            "ea-admin-network-publication-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&remote);
        std::fs::create_dir_all(&remote).unwrap();
        remote
    }

    fn host_over(
        local: Box<dyn ArchiveSource + Send + Sync>,
        remote: &std::path::Path,
        network: ControlledNetworkProfileV1,
    ) -> NetworkPublicationHost {
        let wrapped = ArchiveBackendProfileV1::ControlledNetworkPath(network.clone());
        let policy = policy(&wrapped);
        let target =
            NetworkArchiveTargetV1::new(remote.to_owned(), wrapped, policy.clone()).unwrap();
        NetworkPublicationHost::from_parts(local, remote, network, &policy, Box::new(target))
            .unwrap()
    }

    /// Fix-Runde 1: ein lokaler Lesefehler ist ein Befund, kein wartendes
    /// Netzziel.
    #[test]
    fn a_local_read_failure_is_a_finding_not_a_waiting_network_archive() {
        let remote = remote_dir("local-io");
        let host = host_over(Box::new(Unreadable), &remote, profile());
        assert!(
            host.run_once(&Unobserved).is_err(),
            "ein Befund, kein Ausgang"
        );
        assert_eq!(host.sync_state(), (SyncStatus::Failed, None));
        let _ = std::fs::remove_dir_all(&remote);
    }

    /// Fix-Runde 1: ein Profil mit Backoff 0 darf den Hostlauf nicht zur
    /// Dauerschleife machen.
    #[test]
    fn a_zero_backoff_profile_is_clamped_to_at_least_one_second() {
        let remote = std::env::temp_dir().join(format!(
            "ea-admin-network-publication-zero-gone-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&remote);
        let mut network = profile();
        network.resume_backoff_initial_ms = 0;
        network.resume_backoff_max_ms = 0;
        network.resume_max_attempts = 1_000;
        let host = host_over(Box::new(Committed(Vec::new())), &remote, network);
        let _ = host.run_once(&Unobserved);
        for _ in 0..3 {
            assert!(host.next_delay().unwrap() >= std::time::Duration::from_millis(1_000));
        }
    }

    /// Fix-Runde 1: der Hostlauf mit Backoff-0-Profil bleibt in einem
    /// Zeitfenster bei einer beschränkten Zahl von Läufen — nicht wartend
    /// (Netzziel weg) wie sauber (nichts ausstehend).
    #[test]
    fn the_host_loop_runs_a_bounded_number_of_times_with_a_zero_backoff_profile() {
        use std::sync::Arc;
        let mut network = profile();
        network.resume_backoff_initial_ms = 0;
        network.resume_backoff_max_ms = 0;
        network.resume_max_attempts = 1_000;
        for gone in [true, false] {
            let remote = remote_dir(if gone { "loop-gone" } else { "loop-clean" });
            if gone {
                std::fs::remove_dir_all(&remote).unwrap();
            }
            let local = if gone {
                vec![(
                    "entries/000000000001_e1.eip".into(),
                    format_fixture::valid_eip(vec![0x44; 48]),
                )]
            } else {
                Vec::new()
            };
            let host = Arc::new(host_over(
                Box::new(Committed(local)),
                &remote,
                network.clone(),
            ));
            let _ = host.run_once(&Unobserved);
            let before = host.runs();
            let looping = {
                let host = host.clone();
                std::thread::spawn(move || {
                    host.run_loop(&|host| {
                        let _ = host.run_once(&Unobserved);
                        true
                    });
                })
            };
            std::thread::sleep(std::time::Duration::from_millis(1_500));
            host.shutdown();
            looping.join().unwrap();
            let runs = host.runs() - before;
            assert!(runs <= 2, "gone={gone}: {runs} Läufe in 1,5 s");
            let _ = std::fs::remove_dir_all(&remote);
        }
    }

    /// Fix-Runde 2: das Selbstsignal des eigenen Kippens (sauber → nicht
    /// sauber) zählt keinen zweiten Versuch. Je Lauf nach dem Kippen genau
    /// ein Versuch.
    #[test]
    fn the_loops_own_flip_does_not_count_a_second_attempt() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        let remote = remote_dir("self-signal");
        let mut network = profile();
        network.resume_max_attempts = 1_000;
        let local = vec![(
            "entries/000000000001_e1.eip".into(),
            format_fixture::valid_eip(vec![0x55; 48]),
        )];
        // Das Netzziel fehlt schon; der Host glaubt aber noch „sauber“,
        // weil noch kein Lauf stattfand. Der erste Lauf des Hostlaufs kippt.
        std::fs::remove_dir_all(&remote).unwrap();
        let host = Arc::new(host_over(Box::new(Committed(local)), &remote, network));
        let loop_runs = Arc::new(AtomicU64::new(0));
        let looping = {
            let host = host.clone();
            let loop_runs = loop_runs.clone();
            std::thread::spawn(move || {
                host.run_loop(&|host| {
                    loop_runs.fetch_add(1, Ordering::SeqCst);
                    let _ = host.run_once(&Unobserved);
                    true
                });
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(3_500));
        host.shutdown();
        looping.join().unwrap();
        let runs = loop_runs.load(Ordering::SeqCst);
        assert!(runs >= 1);
        assert!(
            host.attempts() <= runs,
            "{} Versuche bei {runs} Läufen",
            host.attempts()
        );
    }

    /// Fix-Runde 2: ein übersprungener Lauf (Autorität nicht verfügbar)
    /// verbraucht keinen Versuch.
    #[test]
    fn a_skipped_loop_run_does_not_count_an_attempt() {
        use std::sync::Arc;
        let remote = std::env::temp_dir().join(format!(
            "ea-admin-network-publication-skip-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&remote);
        let local = vec![(
            "entries/000000000001_e1.eip".into(),
            format_fixture::valid_eip(vec![0x66; 48]),
        )];
        let host = Arc::new(host_over(Box::new(Committed(local)), &remote, profile()));
        let _ = host.run_once(&Unobserved);
        assert_eq!(host.attempts(), 0);
        let looping = {
            let host = host.clone();
            std::thread::spawn(move || host.run_loop(&|_| false))
        };
        std::thread::sleep(std::time::Duration::from_millis(2_500));
        host.shutdown();
        looping.join().unwrap();
        assert!(
            host.attempts() <= 1,
            "{} Versuche ohne einen einzigen Lauf",
            host.attempts()
        );
    }
}
