//! Der auditierte Profilwechsel nach `design.md` §11.5.
//!
//! Sechs Schritte, und die REIHENFOLGE ist die Zusage. Bei jedem Fehler bleibt
//! ausschliesslich das alte Profil aktiv: es gibt keinen Teilwechsel, keine
//! neue Finalisierung waehrend der Uebernahme und keinen Kettenkopf, der nur in
//! einem der beiden Profile existiert.

use std::sync::{Mutex, PoisonError};

use ea_archive::{ArchiveBackend, ArchiveBackendError, ArchivePath, BoundArchiveProfilePolicyV1};
use ea_audit::{AuditActorProof, LocalAuditService, TypedLocalAuditEvent};
use ea_crypto::{active_profile_pointer_digest, archive_inventory_digest};
use ea_format::{
    ActiveProfilePointerCoreV1, ArchiveProfileMigrationContextV1, LocalAuditActionV1,
    LocalAuditOutcomeV1, encode_active_profile_pointer_core, encode_archive_inventory_list,
};
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_trust::{PreexistingEffectiveNow, decode_trust_anchor};
use ea_types::{EventId, Hash32};
use ea_verify::{VerifyOptions, verify_archive};

use crate::{LocalPathBackend, PublicationQueue, SyncStatus};

/// Das QUELLPROFIL eines Wechsels: sein Bestand und seine offenen
/// Publikationen.
///
/// Die Warteschlangen sind KONSTRUKTORPARAMETER und kein Zusatz, weil
/// `design.md` §11.5 in Schritt 2 zuerst „alle ausstehenden Publikationen des
/// alten Profils beenden" verlangt und erst danach das Inventar. Ein Wechsel,
/// der eine aufgeschobene Publikation zuruecklaesst, verliert genau die
/// Objekte, die noch nicht im Quellinventar stehen — und zwar unbemerkt, weil
/// beide Inventare dann uebereinstimmen.
///
/// Ein Quellprofil ohne Netzziel uebergibt eine leere Liste; das ist eine
/// AUSSAGE des Aufrufers und keine uebersprungene Pruefung.
pub struct MigrationSourceV1<'a> {
    backend: &'a LocalPathBackend,
    pending: Vec<&'a PublicationQueue>,
}

impl<'a> MigrationSourceV1<'a> {
    /// Baut das Quellprofil aus seinem Bestand und seinen Warteschlangen.
    #[must_use]
    pub const fn new(backend: &'a LocalPathBackend, pending: Vec<&'a PublicationQueue>) -> Self {
        Self { backend, pending }
    }

    /// Der Bestand des Quellprofils.
    #[must_use]
    pub const fn backend(&self) -> &'a LocalPathBackend {
        self.backend
    }

    /// Beendet jede offene Publikation des Quellprofils.
    ///
    /// Sie laeuft ueber `resume`, weil genau das die byteidentische
    /// Fortsetzung ist. Was NICHT `synchronisiert` erreicht, bricht den
    /// Wechsel ab: eine noch wartende Publikation ist ein Objekt, das das
    /// Zielprofil nie sehen wuerde.
    ///
    /// Ein HARTFEHLER des Ziels ist dabei derselbe Befund wie eine wartende
    /// Publikation und nicht ein anderer: die Warteschlange bewahrt den Plan
    /// auch dann auf, es liegt also weiterhin etwas an. Der Fehler des Ziels
    /// wird deshalb ABSICHTLICH nicht durchgereicht — er beschreibt, WARUM
    /// nichts durchkam, aber der Befund des Wechsels ist, DASS noch etwas
    /// aussteht. Ein `?` an dieser Stelle liesse den Wechsel mit
    /// `EA-ARCHIVE-IO` abbrechen und den Bediener glauben, ein zweiter
    /// Versuch fange bei einer leeren Warteschlange an.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::PendingPublication`], wenn eine Warteschlange
    /// `synchronisiert` nicht erreicht — sei es als Zustand oder als
    /// Hartfehler ihres Ziels.
    fn finish_pending(&self) -> Result<(), ArchiveBackendError> {
        for queue in &self.pending {
            match queue.resume() {
                Ok(state) if state.sync_status() == SyncStatus::Synchronized => {}
                Ok(_) | Err(_) => return Err(ArchiveBackendError::PendingPublication),
            }
        }
        Ok(())
    }
}

/// Ein eingespielter Fehlerpunkt der Migration.
///
/// Vor UND nach jedem der sieben dauerhaften Schritte je eine benannte
/// Variante. Ein Fehlerpunkt, den es nur vor einem Schritt gibt, koennte nicht
/// belegen, dass die Ruecknahme auch NACH der Wirkung dieses Schrittes noch
/// vollstaendig ist.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MigrationFaultPoint {
    /// Vor dem exklusiven Sperren von Finalisierung, Profilaenderung und
    /// Objektbereinigung.
    BeforeFinalizationLock,
    /// Danach.
    AfterFinalizationLock,
    /// Vor dem Beenden ausstehender Publikationen und dem Inventar.
    BeforeInventory,
    /// Danach.
    AfterInventory,
    /// Vor der Create-if-absent-Uebernahme in den Staging-Bereich.
    BeforeStagingCopy,
    /// Danach.
    AfterStagingCopy,
    /// Vor der vollstaendigen Offlineverifikation des Ziels.
    BeforeTargetVerification,
    /// Danach.
    AfterTargetVerification,
    /// Vor dem dauerhaften Flush aller Verzeichnisse.
    BeforeDirectoryFlush,
    /// Danach.
    AfterDirectoryFlush,
    /// Vor dem atomaren Umschalten des lokalen Profilzeigers.
    BeforePointerSwap,
    /// Danach.
    AfterPointerSwap,
    /// Vor dem Buchen der signierten Auditzeile.
    BeforeAuditFlush,
    /// Danach — und damit hinter jeder dauerhaften Wirkung.
    AfterAuditFlush,
}

impl MigrationFaultPoint {
    /// Alle vierzehn Punkte, in Ablaufreihenfolge.
    pub const ALL: [Self; 14] = [
        Self::BeforeFinalizationLock,
        Self::AfterFinalizationLock,
        Self::BeforeInventory,
        Self::AfterInventory,
        Self::BeforeStagingCopy,
        Self::AfterStagingCopy,
        Self::BeforeTargetVerification,
        Self::AfterTargetVerification,
        Self::BeforeDirectoryFlush,
        Self::AfterDirectoryFlush,
        Self::BeforePointerSwap,
        Self::AfterPointerSwap,
        Self::BeforeAuditFlush,
        Self::AfterAuditFlush,
    ];

    /// Der stabile Name des Punktes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BeforeFinalizationLock => "before-finalization-lock",
            Self::AfterFinalizationLock => "after-finalization-lock",
            Self::BeforeInventory => "before-inventory",
            Self::AfterInventory => "after-inventory",
            Self::BeforeStagingCopy => "before-staging-copy",
            Self::AfterStagingCopy => "after-staging-copy",
            Self::BeforeTargetVerification => "before-target-verification",
            Self::AfterTargetVerification => "after-target-verification",
            Self::BeforeDirectoryFlush => "before-directory-flush",
            Self::AfterDirectoryFlush => "after-directory-flush",
            Self::BeforePointerSwap => "before-pointer-swap",
            Self::AfterPointerSwap => "after-pointer-swap",
            Self::BeforeAuditFlush => "before-audit-flush",
            Self::AfterAuditFlush => "after-audit-flush",
        }
    }
}

/// Der Zustand der Finalisierungssperre.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizationLockStateV1 {
    available: bool,
}

impl FinalizationLockStateV1 {
    /// Ist die Finalisierung wieder freigegeben?
    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.available
    }
}

/// Das Ergebnis eines erfolgreichen Profilwechsels.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MigrationResultV1 {
    audit_event_id: EventId,
    source_inventory_hash: Hash32,
    target_inventory_hash: Hash32,
    active_pointer_hash: Hash32,
    active_pointer_generation: u64,
    source_remains_readable: bool,
}

impl MigrationResultV1 {
    #[must_use]
    pub const fn audit_event_id(&self) -> EventId {
        self.audit_event_id
    }

    /// Der Inventarhash, den die Auditzeile traegt.
    ///
    /// GLEICH dem Quell- und dem Zielinventarhash: der Wechsel wird nur bei
    /// vollstaendiger Gleichheit vollzogen, also gibt es nur EINEN Wert.
    #[must_use]
    pub const fn inventory_hash(&self) -> Hash32 {
        self.target_inventory_hash
    }

    #[must_use]
    pub const fn source_inventory_hash(&self) -> Hash32 {
        self.source_inventory_hash
    }

    #[must_use]
    pub const fn target_inventory_hash(&self) -> Hash32 {
        self.target_inventory_hash
    }

    #[must_use]
    pub const fn active_pointer_hash(&self) -> Hash32 {
        self.active_pointer_hash
    }

    #[must_use]
    pub const fn active_pointer_generation(&self) -> u64 {
        self.active_pointer_generation
    }

    /// Blieb das alte Profil lesbar und UNVERAENDERT?
    ///
    /// GEMESSEN und nicht behauptet: nach dem Wechsel wird das Quellinventar
    /// ERNEUT gebildet und sein Hash gegen den vor der Uebernahme gebildeten
    /// gestellt. Ein Leser, der ein Literal zurueckgibt, koennte nicht
    /// fehlschlagen und waere damit kein Nachweis, dass die Anwendung das alte
    /// Profil nicht automatisch loescht (`design.md` §11.5).
    #[must_use]
    pub const fn source_remains_readable(&self) -> bool {
        self.source_remains_readable
    }
}

/// Der veraenderliche Zustand eines Migrators.
struct MigratorState {
    active_profile_hash: Hash32,
    generation: u64,
    finalization_locked: bool,
    staged_objects: usize,
    fault: Option<MigrationFaultPoint>,
}

/// Der Profilwechsler.
pub struct ProfileMigrator<'a> {
    source: MigrationSourceV1<'a>,
    target: &'a LocalPathBackend,
    policy: &'a BoundArchiveProfilePolicyV1,
    audit: &'a dyn LocalAuditService,
    anchor_bytes: &'a [u8],
    effective_now: &'a PreexistingEffectiveNow,
    carried_proof: OperatorSessionProof,
    state: Mutex<MigratorState>,
}

impl<'a> ProfileMigrator<'a> {
    /// Baut den Wechsler.
    ///
    /// Das aktive Profil ist beim Bauen das QUELLPROFIL — nicht das Ziel. Ein
    /// Migrator, der sein Ziel schon als aktiv fuehrte, koennte die Zusage
    /// „bei jedem Fehler bleibt nur das alte Profil aktiv" nicht mehr treffen.
    ///
    /// # Errors
    ///
    /// Der Kodierfehler des Quellprofils.
    pub fn new(
        source: MigrationSourceV1<'a>,
        target: &'a LocalPathBackend,
        policy: &'a BoundArchiveProfilePolicyV1,
        audit: &'a dyn LocalAuditService,
        anchor_bytes: &'a [u8],
        effective_now: &'a PreexistingEffectiveNow,
        proof: OperatorSessionProof,
    ) -> Result<Self, ArchiveBackendError> {
        let active_profile_hash = source.backend().profile_hash()?;
        Ok(Self {
            source,
            target,
            policy,
            audit,
            anchor_bytes,
            effective_now,
            carried_proof: proof,
            state: Mutex::new(MigratorState {
                active_profile_hash,
                generation: 0,
                finalization_locked: false,
                staged_objects: 0,
                fault: None,
            }),
        })
    }

    /// Spielt einen Fehlerpunkt ein.
    #[must_use]
    pub fn with_fault(&self, point: MigrationFaultPoint) -> &Self {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fault = Some(point);
        self
    }

    /// Der aktuell aktive Profilhash.
    #[must_use]
    pub fn active_profile_hash(&self) -> Hash32 {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .active_profile_hash
    }

    /// Der Zustand der Finalisierungssperre.
    #[must_use]
    pub fn finalization_lock(&self) -> FinalizationLockStateV1 {
        FinalizationLockStateV1 {
            available: !self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .finalization_locked,
        }
    }

    /// Die Zahl der bisher in den Staging-Bereich uebernommenen Objekte.
    #[must_use]
    pub fn staged_object_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .staged_objects
    }

    /// Die Generation VOR dem Wechsel.
    #[must_use]
    pub fn previous_generation(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .generation
    }

    /// Fuehrt den Wechsel mit dem mitgefuehrten Nachweis aus.
    ///
    /// # Errors
    ///
    /// Wie [`Self::run_with`].
    pub fn run(&self) -> Result<MigrationResultV1, ArchiveBackendError> {
        self.execute(&self.carried_proof)
    }

    /// Fuehrt den Wechsel mit `proof` aus.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ReauthMismatch`], wenn der Nachweis nicht genau
    /// [`ReauthPurpose::ArchiveProfileMigration`] traegt;
    /// [`ArchiveBackendError::ProfileNotAllowed`], wenn das Zielprofil nicht in
    /// der wirksamen Policy steht; [`ArchiveBackendError::MigrationFault`] am
    /// eingespielten Fehlerpunkt; sonst der Fehler des Schrittes, der nicht
    /// getragen hat.
    pub fn run_with(
        &self,
        proof: OperatorSessionProof,
    ) -> Result<MigrationResultV1, ArchiveBackendError> {
        self.execute(&proof)
    }

    fn fault_at(&self, point: MigrationFaultPoint) -> Result<(), ArchiveBackendError> {
        if self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fault
            == Some(point)
        {
            return Err(ArchiveBackendError::MigrationFault);
        }
        Ok(())
    }

    fn execute(
        &self,
        proof: &OperatorSessionProof,
    ) -> Result<MigrationResultV1, ArchiveBackendError> {
        let outcome = self.attempt(proof);
        // Die Finalisierungssperre wird IMMER freigegeben, auch auf jedem
        // Fehlerweg. Eine Sperre, die nach einem Abbruch haengt, machte den
        // Bestand unbenutzbar.
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .finalization_locked = false;
        outcome
    }

    #[allow(clippy::too_many_lines)]
    fn attempt(
        &self,
        proof: &OperatorSessionProof,
    ) -> Result<MigrationResultV1, ArchiveBackendError> {
        // Der EXAKTE frische Zweck, vor allem anderen. Ein Nachweis fuer den
        // Abschluss autorisiert keinen Profilwechsel.
        // Die Zeit kommt als `PreexistingEffectiveNow` des GEWAEHLTEN Kopfes
        // und nie als freier Wert — `OperatorSessionProof::is_valid_for`
        // verlangt genau das, damit die Aussage die Zeitstatusbewertung des
        // Kopfes traegt.
        if !proof.is_valid_for(ReauthPurpose::ArchiveProfileMigration, self.effective_now) {
            return Err(ArchiveBackendError::ReauthMismatch);
        }

        let source_profile_hash = self.source.backend().profile_hash()?;
        let target_profile_hash = self.target.profile_hash()?;
        // Fail-closed VOR jeder Kopie: Task 11 wiederholt genau diese Pruefung
        // gegen dieselbe gebundene Policyfassung in der Finalisierung.
        self.policy.require(target_profile_hash)?;

        self.fault_at(MigrationFaultPoint::BeforeFinalizationLock)?;
        // Schritt 1: Finalisierung, Profilaenderungen und Objektbereinigung
        // exklusiv sperren.
        let writer_lock = self.source.backend().acquire_writer_lock()?;
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .finalization_locked = true;
        self.fault_at(MigrationFaultPoint::AfterFinalizationLock)?;

        let result = self.migrate_under_lock(proof, source_profile_hash, target_profile_hash);
        // Der Waechter wird HIER verworfen, nicht am Blockende: die Sperre des
        // Quellbestands gehoert zur Uebernahme und nicht zur Auditbuchung.
        drop(writer_lock);
        result
    }

    fn migrate_under_lock(
        &self,
        proof: &OperatorSessionProof,
        source_profile_hash: Hash32,
        target_profile_hash: Hash32,
    ) -> Result<MigrationResultV1, ArchiveBackendError> {
        self.fault_at(MigrationFaultPoint::BeforeInventory)?;
        // Schritt 2a: ALLE ausstehenden Publikationen des alten Profils
        // beenden. Erst danach ist sein Inventar vollstaendig; eine
        // aufgeschobene Publikation waere ein Objekt, das im Quellinventar
        // fehlt und deshalb auch im Zielprofil nie erschiene.
        self.source.finish_pending()?;
        // Schritt 2b: aus den Bytes des alten Profils ein VOLLSTAENDIGES
        // Objektinventar bilden — Trust, Schemata, Objekte und Berichte.
        let source_inventory = self.source.backend().inventory()?;
        let source_bytes = encode_archive_inventory_list(&source_inventory)
            .map_err(ArchiveBackendError::Format)?;
        let source_inventory_hash = archive_inventory_digest(&source_bytes);
        self.fault_at(MigrationFaultPoint::AfterInventory)?;

        self.fault_at(MigrationFaultPoint::BeforeStagingCopy)?;
        // Schritt 3: saemtliche inventarisierten ORIGINALBYTES per
        // Create-if-absent uebernehmen; bestehende Zielobjekte muessen
        // bytegleich sein — genau das leistet `create_non_object_if_absent`,
        // und genau deshalb ist ein Bytekonflikt hier ein Abbruch.
        for entry in source_inventory.entries() {
            let bytes = self
                .source
                .backend()
                .read_relative(entry.relative_path())
                .ok_or(ArchiveBackendError::Io)?;
            let address = archive_path_of(entry.relative_path())?;
            self.target.create_non_object_if_absent(&address, &bytes)?;
            self.state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .staged_objects += 1;
        }
        self.fault_at(MigrationFaultPoint::AfterStagingCopy)?;

        self.fault_at(MigrationFaultPoint::BeforeTargetVerification)?;
        // Schritt 4: das neue Archiv VOLLSTAENDIG OFFLINE verifizieren und
        // Objektmenge, Kettenkopf und Trust-Head mit dem alten Profil
        // vergleichen.
        let anchor = decode_trust_anchor(self.anchor_bytes)
            .map_err(|_| ArchiveBackendError::VerificationFailed)?;
        let source_report = verify_archive(
            &self.source.backend().as_archive_source(),
            &anchor,
            VerifyOptions::new(self.effective_now.value()),
        )
        .map_err(|_| ArchiveBackendError::VerificationFailed)?;
        let target_report = verify_archive(
            &self.target.as_archive_source(),
            &anchor,
            VerifyOptions::new(self.effective_now.value()),
        )
        .map_err(|_| ArchiveBackendError::VerificationFailed)?;
        if source_report.report_hash().as_bytes() != target_report.report_hash().as_bytes() {
            // Der Berichtshash deckt Objektmenge, Kettenkopf,
            // Registrierungsfassungen, Grants, Quittungen, Evidence und
            // Stummel in EINEM Wert ab. Ein Feldvergleich daneben waere eine
            // zweite, schwaechere Formulierung derselben Aussage.
            return Err(ArchiveBackendError::InventoryMismatch);
        }
        let target_inventory = self.target.inventory()?;
        let target_bytes = encode_archive_inventory_list(&target_inventory)
            .map_err(ArchiveBackendError::Format)?;
        let target_inventory_hash = archive_inventory_digest(&target_bytes);
        if source_inventory_hash.as_bytes() != target_inventory_hash.as_bytes() {
            return Err(ArchiveBackendError::InventoryMismatch);
        }
        self.fault_at(MigrationFaultPoint::AfterTargetVerification)?;

        self.fault_at(MigrationFaultPoint::BeforeDirectoryFlush)?;
        // Schritt 5a: dauerhafte Synchronisierung ALLER Verzeichnisse.
        for entry in target_inventory.entries() {
            let address = archive_path_of(entry.relative_path())?;
            self.target.sync_file(&address)?;
            self.target.sync_directory(&address)?;
        }
        self.fault_at(MigrationFaultPoint::AfterDirectoryFlush)?;

        let generation = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .generation
            .checked_add(1)
            .ok_or(ArchiveBackendError::MigrationFault)?;
        let pointer = ActiveProfilePointerCoreV1::new(target_profile_hash, generation);
        let pointer_bytes =
            encode_active_profile_pointer_core(&pointer).map_err(ArchiveBackendError::Format)?;
        let active_pointer_hash = active_profile_pointer_digest(&pointer_bytes);

        self.fault_at(MigrationFaultPoint::BeforePointerSwap)?;
        // Schritt 5b: ERST JETZT den lokalen Profilzeiger atomar umschalten.
        //
        // Der Zeiger liegt in der Wurzel des ZIELPROFILS: genau diese Wurzel
        // muss im Augenblick des Umschaltens existieren und geflusht sein, und
        // genau eine Stelle traegt die Antwort. Auch die Ruecknahme schreibt
        // dorthin — dann steht dort, dass wieder das Quellprofil aktiv ist.
        //
        // Ab hier ist eine dauerhafte Wirkung eingetreten, und die Zusage
        // „bei jedem Fehler bleibt ausschliesslich das alte Profil aktiv"
        // (`design.md` §11.5) verlangt deshalb eine RUECKNAHME und nicht bloss
        // ein `?`. Sie ist kein Wiederherstellen des alten Zeigers, sondern ein
        // NEUER Zeiger auf das alte Profil mit der naechsthoeheren Generation —
        // genau so, wie das Addendum den Rueckfall beschreibt: eine wiederholte
        // Generation waere ein wiedereinspielbarer Zeiger.
        self.target.write_active_profile_pointer(&pointer)?;
        {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.active_profile_hash = target_profile_hash;
            state.generation = generation;
        }

        let context = ArchiveProfileMigrationContextV1::new(
            source_profile_hash,
            target_profile_hash,
            target_inventory_hash,
            active_pointer_hash,
        );
        match self.audit_after_swap(proof, context) {
            Ok(audit_event_id) => Ok(MigrationResultV1 {
                audit_event_id,
                source_inventory_hash,
                target_inventory_hash,
                active_pointer_hash,
                active_pointer_generation: generation,
                // Das alte Profil wird ERNEUT inventarisiert. Stimmt sein Hash
                // noch, ist es lesbar und unangetastet — und genau das ist die
                // Zusage „die Anwendung loescht es nicht automatisch".
                // Das alte Profil wird ERNEUT inventarisiert. Stimmt sein Hash
                // noch, ist es lesbar und unangetastet — und genau das ist die
                // Zusage „die Anwendung loescht es nicht automatisch".
                source_remains_readable: self.source.backend().inventory().is_ok_and(|inventory| {
                    encode_archive_inventory_list(&inventory).is_ok_and(|bytes| {
                        archive_inventory_digest(&bytes).as_bytes()
                            == source_inventory_hash.as_bytes()
                    })
                }),
            }),
            Err(error) => {
                self.roll_back_pointer(
                    proof,
                    source_profile_hash,
                    target_profile_hash,
                    target_inventory_hash,
                    generation,
                );
                Err(error)
            }
        }
    }

    /// Bucht die signierte Auditzeile des vollzogenen Wechsels.
    ///
    /// Sie traegt ausschliesslich Digests: kein Pfad, kein Hostname, kein
    /// fachlicher Name.
    fn audit_after_swap(
        &self,
        proof: &OperatorSessionProof,
        context: ArchiveProfileMigrationContextV1,
    ) -> Result<EventId, ArchiveBackendError> {
        self.fault_at(MigrationFaultPoint::AfterPointerSwap)?;
        self.fault_at(MigrationFaultPoint::BeforeAuditFlush)?;
        let event = self
            .audit
            .record_signed(
                // DER GEPRUEFTE Nachweis, nicht der mitgefuehrte: `run_with`
                // kann einen anderen uebergeben, und eine Auditzeile, die
                // jemand anderem zugerechnet wird als dem, dessen Zweck
                // geprueft wurde, waere falsch zugerechnet.
                AuditActorProof::OperatorSession(proof),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::ArchiveProfileMigration(context),
                    outcome: LocalAuditOutcomeV1::Completed,
                },
            )
            .map_err(|_| ArchiveBackendError::AuditFailed)?;
        self.fault_at(MigrationFaultPoint::AfterAuditFlush)?;
        Ok(event.id())
    }

    /// Nimmt einen bereits vollzogenen Zeigerwechsel zurueck.
    ///
    /// Der Rueckfallzeiger nennt das QUELLPROFIL bei der naechsthoeheren
    /// Generation, und die begleitende Auditzeile traegt den Ausgang `failed` —
    /// dann ist `active-profile-hash` gleich `source-profile-hash`, genau wie
    /// das Addendum es festlegt. Schlaegt auch die Ruecknahme fehl, bleibt der
    /// urspruengliche Fehler der gemeldete: ein zweiter Fehler darf den ersten
    /// nicht verdecken.
    fn roll_back_pointer(
        &self,
        proof: &OperatorSessionProof,
        source_profile_hash: Hash32,
        target_profile_hash: Hash32,
        inventory_hash: Hash32,
        swapped_generation: u64,
    ) {
        let Some(generation) = swapped_generation.checked_add(1) else {
            return;
        };
        let pointer = ActiveProfilePointerCoreV1::new(source_profile_hash, generation);
        if self.target.write_active_profile_pointer(&pointer).is_err() {
            return;
        }
        {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.active_profile_hash = source_profile_hash;
            state.generation = generation;
        }
        let Ok(bytes) = encode_active_profile_pointer_core(&pointer) else {
            return;
        };
        let _ = self.audit.record_signed(
            AuditActorProof::OperatorSession(proof),
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::ArchiveProfileMigration(
                    ArchiveProfileMigrationContextV1::new(
                        source_profile_hash,
                        target_profile_hash,
                        inventory_hash,
                        active_profile_pointer_digest(&bytes),
                    ),
                ),
                outcome: LocalAuditOutcomeV1::Failed,
            },
        );
    }
}

/// Die Transportadresse zu einem wurzelrelativen Inventarpfad.
///
/// Sie leitet das tragende Layoutverzeichnis aus dem Pfad ab, statt es zu
/// erraten: eine Wurzeldatei der Layoutliste wird als solche adressiert, alles
/// andere unterhalb seines Verzeichnisses.
fn archive_path_of(relative: &str) -> Result<ArchivePath, ArchiveBackendError> {
    if let Ok(path) = ArchivePath::at_layout_file(relative) {
        return Ok(path);
    }
    let mut best: Option<&str> = None;
    for candidate in ea_archive::LAYOUT_PATHS_V1 {
        if candidate.ends_with('/')
            && relative.starts_with(candidate)
            && best.is_none_or(|current| candidate.len() > current.len())
        {
            best = Some(candidate);
        }
    }
    let directory = best.ok_or(ArchiveBackendError::Path)?;
    ArchivePath::in_dir(directory, &relative[directory.len()..])
}

impl core::fmt::Debug for MigrationResultV1 {
    /// Nennt die Generation und ob Quell- und Zielinventar gleich sind — die
    /// beiden Groessen, die eine Fehlerzeile braucht. Die vier Digests bleiben
    /// draussen: `ea_types::Hash32` und `EventId` tragen in diesem Bauwerk
    /// bewusst keine Formatierung.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MigrationResultV1")
            .field("active_pointer_generation", &self.active_pointer_generation)
            .field(
                "inventory_hashes_equal",
                &(self.source_inventory_hash.as_bytes() == self.target_inventory_hash.as_bytes()),
            )
            .finish_non_exhaustive()
    }
}
