//! Der Publikationshost eines kontrollierten Netzprofils (EA-CNA-PUB-*).
//!
//! Der Host hält KEINE Queue im Speicher, die etwas wüsste, was die Bytes
//! nicht wissen: jeder Lauf leitet den Plan neu aus den committed lokalen
//! Bytes und dem LIVE gelesenen Netzziel ab (EA-CNA-PUB-1) und reicht ihn an
//! die [`PublicationQueue`] weiter, die ihn grants-first/`.eip`-last und
//! byteidentisch veröffentlicht (EA-CNA-PUB-2/3). Nach einem Neustart
//! entsteht derselbe Plan aus denselben Bytes wieder.
//!
//! Ausgelöst wird (a) in Schritt 12 über [`NetworkPublicationPortV1`], (b)
//! nach der Start-Wiederherstellung und (c) durch den Hostlauf des Wirts mit
//! dem Backoff des Profils ([`NetworkPublicationHost::next_delay`],
//! EA-CNA-PUB-8).

use std::{
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
    time::Duration,
};

use ea_archive::{
    ArchiveBackendError, ArchiveBackendProfileV1, ArchiveSource, BoundArchiveProfilePolicyV1,
    ControlledNetworkProfileV1,
};
use ea_archive_fs::{
    DetailCause, LocalPathBackend, NetworkArchiveTargetV1, PlannedPublicationV1,
    PublicationOutcomeV1, PublicationQueue, PublicationStateV1, PublicationTargetV1, SyncStatus,
};
use ea_writer::NetworkPublicationPortV1;

use crate::native_archive::{NativeArchiveExistingComponent, NativeArchiveOpenError};

/// Was der letzte Lauf über den Bestand wusste.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Observed {
    /// Noch kein Lauf: nichts ist bekannt.
    Unknown,
    /// Nichts steht aus: jedes committed lokale Objekt liegt am Netzziel.
    Clean,
    /// Es steht etwas aus; die Ursache tritt daneben.
    Waiting(DetailCause),
    /// Ein Datenbefund (etwa ein Bytekonflikt), keine verlorene
    /// Erreichbarkeit.
    Failed,
}

struct HostState {
    observed: Observed,
    /// Hostläufe nach einem nicht sauberen Ausgang, je Prozess gezählt.
    attempts: u64,
    /// Die nächste Wartezeit nach einem nicht sauberen Ausgang.
    delay_ms: u64,
    /// `resume_max_attempts` ist verbraucht; gilt bis zum nächsten Start.
    exhausted: bool,
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
    /// Serialisiert ganze Läufe (Ableitung UND Publikation): Schritt 12 und
    /// der Hostlauf dürfen sich nicht verschränken.
    run: Mutex<()>,
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
        Ok(Self {
            queue,
            local,
            remote_root: remote_root.to_owned(),
            state: Mutex::new(HostState {
                observed: Observed::Unknown,
                attempts: 0,
                delay_ms: profile.resume_backoff_initial_ms,
                exhausted: false,
            }),
            profile,
            policy: policy.clone(),
            run: Mutex::new(()),
        })
    }

    /// Der abgeleitete Plan, ohne zu veröffentlichen (EA-CNA-PUB-1/2).
    ///
    /// # Errors
    ///
    /// Der Fehler beim Öffnen oder Lesen des Netzziels oder der Ableitung.
    pub fn pending(&self) -> Result<PlannedPublicationV1, ArchiveBackendError> {
        // Die Ableitung öffnet ihren EIGENEN Griff auf das Netzziel und gibt
        // ihn zurück, bevor die Warteschlange ihren nimmt: beide nehmen
        // kurzzeitig den Writer-Lock des Netzziels, und sie dürfen sich nie
        // überlappen. Nicht als Feld zwischenspeichern.
        let remote = LocalPathBackend::open_existing(
            self.remote_root.clone(),
            ArchiveBackendProfileV1::ControlledNetworkPath(self.profile.clone()),
            &self.policy,
        )?;
        PlannedPublicationV1::derive_pending(self.local.as_ref(), &remote)
    }

    /// Ein Lauf: ableiten, dann veröffentlichen. Ein nicht erreichbares
    /// Netzziel ist `Deferred` mit `Netzarchiv wartet`, kein Fehler.
    pub fn run_once(&self) -> PublicationStateV1 {
        let _run = self.run.lock().unwrap_or_else(PoisonError::into_inner);
        let (observed, state) = self.publish_pending();
        self.lock_state().observed = observed;
        state
    }

    fn publish_pending(&self) -> (Observed, PublicationStateV1) {
        let waiting = |cause| {
            (
                Observed::Waiting(cause),
                PublicationStateV1::deferred(Some(cause)),
            )
        };
        let planned = match self.pending() {
            Ok(planned) => planned,
            // Wurzel verschwunden, Share weg, Mount unbrauchbar: dieselbe
            // verlorene Erreichbarkeit wie in der Warteschlange. Ein
            // Bytekonflikt oder ein beschädigtes Objekt bleibt ein Befund.
            Err(ArchiveBackendError::Io | ArchiveBackendError::FlushFailed)
                if !self.remote_is_reachable() =>
            {
                return waiting(DetailCause::NetworkArchiveWaiting);
            }
            Err(error) => return Self::refused(error),
        };
        let published = if planned.is_empty() {
            // Nichts fehlt am Netzziel. Ein älterer, aufgeschobener Plan im
            // Platz wird trotzdem abgeräumt — über Create-if-absent ist das
            // idempotent.
            self.queue.resume()
        } else {
            self.queue.publish(planned)
        };
        match published {
            Ok(state) => {
                let observed = match state.outcome() {
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
                };
                (observed, state)
            }
            Err(error) => Self::refused(error),
        }
    }

    /// Ein Fehler der Warteschlange oder der Ableitung.
    ///
    /// Kam der Fehler aus der Warteschlange, liegt der Plan dort
    /// aufgeschoben. Kam er aus der Ableitung (`pending`), wurde NICHTS
    /// eingereiht. Ein Datenbefund (Bytekonflikt, beschädigtes Objekt) wird
    /// trotzdem als [`PublicationOutcomeV1::Deferred`] ohne Ursache
    /// zurückgegeben, nur weil der Ausgang keinen Fehlerarm hat — er heißt
    /// hier ausdrücklich NICHT, dass ein `resume` ihn aufnähme. Maßgeblich
    /// ist [`NetworkPublicationHost::sync_state`], das dafür `Fehler` meldet.
    fn refused(error: ArchiveBackendError) -> (Observed, PublicationStateV1) {
        let cause = match error {
            // Ein anderer hält gerade den Writer-Lock des Netzziels (etwa
            // eine Recovery-Capture, EA-CNA-REC-2): das Ziel wartet.
            ArchiveBackendError::AlreadyLocked
            | ArchiveBackendError::Io
            | ArchiveBackendError::FlushFailed => DetailCause::NetworkArchiveWaiting,
            ArchiveBackendError::ProfileNotAllowed => DetailCause::ProfileNotAllowed,
            _ => return (Observed::Failed, PublicationStateV1::deferred(None)),
        };
        (
            Observed::Waiting(cause),
            PublicationStateV1::deferred(Some(cause)),
        )
    }

    fn remote_is_reachable(&self) -> bool {
        std::fs::metadata(&self.remote_root).is_ok_and(|metadata| metadata.is_dir())
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, HostState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Der Sync-Zustand nach EA-CNA-PUB-4: vier Zustände, die Ursache
    /// daneben.
    ///
    /// Ohne Server gilt: leere Queue → `lokal gesichert`; ausstehend →
    /// `Upload ausstehend` mit Ursache; ein Datenbefund → `Fehler`. Vor dem
    /// ersten Lauf ist nichts bekannt, und behauptet wird dann nur
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
    /// Nach einem sauberen Lauf: `resume_backoff_initial_ms`, ohne einen
    /// Versuch zu verbrauchen. Nach einem nicht sauberen Lauf zählt jeder
    /// Aufruf einen Versuch; die Wartezeit beginnt bei
    /// `resume_backoff_initial_ms` und verdoppelt sich bis
    /// `resume_backoff_max_ms`. Sind `resume_max_attempts` Versuche in
    /// diesem Prozess verbraucht, liefert sie `None` — bis zum nächsten Start
    /// mit der Ursache `Wiederaufnahme erschöpft`.
    pub fn next_delay(&self) -> Option<Duration> {
        let mut state = self.lock_state();
        if state.exhausted {
            return None;
        }
        if matches!(state.observed, Observed::Clean | Observed::Unknown) {
            state.delay_ms = self.profile.resume_backoff_initial_ms;
            return Some(Duration::from_millis(state.delay_ms));
        }
        if state.attempts >= self.profile.resume_max_attempts {
            state.exhausted = true;
            return None;
        }
        state.attempts += 1;
        let delay = state.delay_ms;
        state.delay_ms = delay
            .saturating_mul(2)
            .min(self.profile.resume_backoff_max_ms);
        Some(Duration::from_millis(delay))
    }
}

impl NetworkPublicationPortV1 for NetworkPublicationHost {
    fn publish_committed(&self) -> PublicationOutcomeV1 {
        self.run_once().outcome()
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

        let state = host.run_once();
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
            host.run_once().outcome(),
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
        assert_eq!(host.next_delay(), Some(Duration::from_millis(100)));
        let state = host.run_once();
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
        // Verdoppelnd bis zum Maximum, höchstens `resume_max_attempts` (2).
        assert_eq!(host.next_delay(), Some(Duration::from_millis(100)));
        host.run_once();
        assert_eq!(host.next_delay(), Some(Duration::from_millis(200)));
        host.run_once();
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
            host.run_once().outcome(),
            PublicationOutcomeV1::PublishedCompletely
        );
        assert_eq!(host.sync_state(), (SyncStatus::LocallySaved, None));
        assert_eq!(host.next_delay(), None);
        let _ = std::fs::remove_dir_all(&remote);
    }
}
