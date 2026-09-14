//! Der Zustand des Wirts — und die Naehte, an denen Task 16 andockt.

use std::sync::{Arc, Mutex, PoisonError};

use ea_admin::{GoLiveChecklist, TrustCeremonyKind};
use ea_archive::ArchiveBackendError;
use ea_archive_fs::{ArchiveHealthCheckV1, ArchiveHealthReport, BundleError};
use ea_draft::{DiscardService, DraftError, DraftRepository, MasterDataRepository, RestartState};
use ea_format::{ClockReleaseJustificationV1, OperatorRoleV1};
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_schema::{NativeSourceV1, PersonnelSnapshotV1, SchemaError, VehicleSnapshotV1};
use ea_types::{ObjectHash, UnixMillis};
use ea_ui_contracts::{
    BundleExportView, ClockReleaseOfferView, ClockReleaseOutcomeView, FinalizationPreviewView,
    FinalizeOutcomeView, IncidentInputView, PendingDeviceRequestView, PersonnelSelectionView,
    PolicyProfileView, RegistryHealthView, RevocationEffectView, SyncStateView, TrustCeremonyView,
    VehicleSelectionView, WriterTransitionView,
};
use ea_writer::{
    FinalizationInputV1, FinalizationPreview, RecoveryOutcome, WriterError, WriterService,
};

use crate::commands::{CommandError, MASTER_DATA_UNREADABLE, PREVIEW_MISMATCH, PREVIEW_NOT_ISSUED};

/// Die Quellkennung dieses Wirts und ihre Formatversion.
///
/// Sie beschreibt das ERFASSENDE Programm und nicht den Einsatz; sie gehoert
/// deshalb dem Wirt und kommt niemals aus einer Antwort der Oberflaeche. Eine
/// Oberflaeche, die ihre eigene Quellkennung waehlen kann, kann einen fremden
/// Erfasser in die signierte Nutzlast schreiben.
const NATIVE_SOURCE_ID: &str = "ea.desktop.writer";
const NATIVE_SOURCE_FORMAT_VERSION: u64 = 1;

/// Der synchrone Port des automatischen Startpfads.
///
/// Der Port existiert, weil [`WriterService`] eine Lebensdauer traegt
/// (`&'a dyn ArchiveBackend`) und damit nicht in den `'static`-Zustand einer
/// Tauri-Anwendung passt. Die Implementierung fuer [`WriterService`] darunter
/// ist die Naht: ein Implementierer, der die Ports haelt, baut je Aufruf einen
/// Dienst und ruft genau diese Methode.
///
/// `Send + Sync` steht NICHT als Supertrait daran, weil [`WriterService`] es
/// nicht ist; die Schranke sitzt an der Stelle, die sie braucht — am Feld von
/// [`DesktopState`].
pub trait StartupRecoveryPort {
    /// Loest eine liegende Abschlussmarke auf.
    ///
    /// # Errors
    ///
    /// Der Fehler des Schreibports, unveraendert.
    fn resolve_pending_finalization(&self) -> Result<RecoveryOutcome, WriterError>;
}

impl StartupRecoveryPort for WriterService<'_> {
    fn resolve_pending_finalization(&self) -> Result<RecoveryOutcome, WriterError> {
        self.recover_pending()
    }
}

/// Der synchrone Port des Archivgesundheitschecks.
///
/// Derselbe Grund wie bei [`StartupRecoveryPort`]: [`ArchiveHealthCheckV1`]
/// traegt fuenf Referenzen und damit eine Lebensdauer, passt also nicht in den
/// `'static`-Zustand einer Tauri-Anwendung. Die Implementierung darunter ist die
/// Naht — der Aufruf von [`ArchiveHealthCheckV1::run`] steht damit KOMPILIERT im
/// Code, und ein Implementierer, der Bestand, Inventar, Faehigkeitsbericht und
/// Verifikationsbericht besitzt, baut den Check je Aufruf.
/// Der SYNC-ZUSTAND dieses Geraets.
///
/// Ein PORT und kein `SyncClient`-Feld, und zwar aus demselben Grund wie bei
/// jedem anderen: solange dieses Geraet keinen aufgeloesten Sync-Aufbau hat,
/// ist kein Port verdrahtet, und die Abwesenheit sitzt am fehlenden Port statt
/// an einer fehlenden Zeile. Ein Vorgabewert waere hier eine Behauptung ueber
/// einen Bestand, ueber den nichts bekannt ist — und die freundlichste
/// Behauptung waere zufaellig `synchronisiert`.
///
/// SYNCHRON, wie jeder Port dieses Wirts: `crates/ea-sync-client` ist die
/// asynchrone Schale, und die Ableitung des Zustands dahinter ist es nicht.
pub trait SyncStatePort {
    /// Der Zustand aus committeten Archivbytes und dem dauerhaften
    /// Wiederaufnahmezustand.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError`], unveraendert — dieselbe Fehlerkante wie bei
    /// [`ArchiveHealthPort`], und aus demselben Grund: die Ableitung liest den
    /// BESTAND, und ihr Fehlschlag ist der des Bestands. Der Kommandorumpf
    /// uebersetzt ihn in einen stabilen Code und reicht keinen Text weiter;
    /// ein durchgereichter Fehlertext koennte einen Pfad oder eine Kennung
    /// nennen.
    fn sync_state(&self) -> Result<SyncStateView, ArchiveBackendError>;
}

pub trait ArchiveHealthPort {
    /// Fuehrt alle zehn Erkenner aus.
    ///
    /// # Errors
    ///
    /// Der Fehler des Bestands, unveraendert.
    fn health(&self) -> Result<ArchiveHealthReport, ArchiveBackendError>;
}

impl ArchiveHealthPort for ArchiveHealthCheckV1<'_> {
    fn health(&self) -> Result<ArchiveHealthReport, ArchiveBackendError> {
        self.run()
    }
}

/// Der synchrone Port der Entwurfsnutzlast.
///
/// Er ist die Naht zur Autospeicherung, und er ist ABSICHTLICH schmaler als
/// [`DraftRepository`]: die Grenze braucht genau zwei Wirkungen — die Nutzlast
/// des EINEN aktiven Entwurfs lesen und sie schreiben —, und beide werden hier
/// als Zeichenkette benannt. Der Rest des Entwurfsvertrages (Verwerfensabsicht,
/// Abschlussmarke, Schluesselgriff, Sperre) gehoert nicht an diese Grenze.
///
/// Der zweite Grund ist die MESSBARKEIT: [`ea_draft::Draft`] und
/// [`ea_draft::SavedDraft`] haben ausschliesslich `pub(crate)`-Konstruktoren, es
/// kann also ausserhalb von `ea-draft` gar kein Doppel eines
/// [`DraftRepository`] geben. Ein Port ueber Zeichenketten kann eines haben —
/// und ohne Doppel bliebe „das Speichern schreibt WIRKLICH die Eingabe" eine
/// Behauptung.
pub trait DraftPayloadPort {
    /// Die Nutzlast des EINEN aktiven Entwurfs, entsiegelt.
    ///
    /// # Errors
    ///
    /// Der Fehler der Ablage, unveraendert.
    fn load_payload(&self) -> Result<String, DraftError>;

    /// Schreibt die Nutzlast des EINEN aktiven Entwurfs.
    ///
    /// # Errors
    ///
    /// Der Fehler der Ablage, unveraendert — [`DraftError::RevisionConflict`]
    /// eingeschlossen: dann ist NICHTS geschrieben.
    fn save_payload(&self, payload: String) -> Result<(), DraftError>;
}

/// Jede echte Entwurfsablage IST dieser Port.
///
/// Die zwei Rumpfe sind die Naht: `load_or_create` liefert den einen aktiven
/// Entwurf, `Draft::with_notes` setzt die Nutzlast, und
/// `DraftRepository::save` siegelt sie als AEAD-Chiffrat unter dem `draftDEK`
/// (`ea-draft/src/autosave.rs`) und schreibt sie als Vergleich-und-Setze ueber
/// die Fassung. Diese Crate verschluesselt selbst nichts.
impl<T: DraftRepository + ?Sized> DraftPayloadPort for T {
    fn load_payload(&self) -> Result<String, DraftError> {
        Ok(self.load_or_create()?.notes().to_owned())
    }

    fn save_payload(&self, payload: String) -> Result<(), DraftError> {
        let draft = self.load_or_create()?;
        self.save(draft.with_notes(payload)).map(|_| ())
    }
}

/// Der synchrone Port des Ein-Datei-Buendelexports.
///
/// # Warum hier keine Naht wie [`BoundWriter`] steht
///
/// `ea_archive_fs::write_archive_bundle` verlangt einen aufgeloesten
/// `TrustAnchorV1`, und dieser Typ lebt in `ea-trust`. `ea-trust` steht nicht in
/// der Abhaengigkeitsmenge dieses Pakets, `ea-archive-fs` gibt ihn nicht weiter,
/// und kein erreichbares Paket liefert einen Wert dieses Typs — der Aufruf ist
/// hier also nicht einmal HINSCHREIBBAR. Diese Grenze erfindet ihn deshalb
/// nicht; sie zieht die Naht so eng an den Kern, wie es ohne diese Kante geht:
/// der Fehlerausgang IST [`BundleError`], und der Code einer Abweisung kommt
/// damit woertlich aus `crates/ea-archive/src/bundle_error.rs` und nicht aus einer
/// zweiten Liste. Ein Bestand, der nicht vollstaendig verifiziert, kommt als
/// [`BundleError::SourceNotFullyVerified`] an und wird abgewiesen.
///
/// Der Erfolgsausgang ist die ANSICHT und nicht `ea_archive_fs::BundleExportReport`:
/// dessen Feld ist privat und ohne oeffentlichen Konstruktor, und er nennt nur
/// die Objektzahl. Pfad und Byteumfang sind Tatsachen des Wirts ueber das Ziel,
/// das er selbst gewaehlt hat.
///
/// # Ohne Argument
///
/// Das Ziel gehoert dem WIRT und kommt nie aus einer Antwort der Oberflaeche;
/// der Implementierer haelt es, wie [`BoundWriter`] den Nachweis haelt. Die
/// Freies-Ziel-Regel samt `O_CREAT|O_EXCL` liegt im Kern und wird hier nicht
/// nachgebaut.
pub trait ArchiveBundleExportPort {
    /// Schreibt den Bestand als EINE Datei und meldet, was hinausging.
    ///
    /// # Errors
    ///
    /// Der Fehler des Buendelschreibers, unveraendert.
    fn export(&self) -> Result<BundleExportView, BundleError>;
}

/// Der synchrone Port des Verwerfens.
///
/// Derselbe Lebensdauergrund wie bei den Ports darueber: [`DiscardService`]
/// BORGT die Zeit des gewaehlten Registry-Head (`&'now PreexistingEffectiveNow`)
/// und haelt keine Momentaufnahme davon, traegt also eine Lebensdauer und passt
/// nicht in den `'static`-Zustand einer Tauri-Anwendung.
///
/// Der SITZUNGSNACHWEIS steht wie bei [`WriterPreviewPort`] nicht in der
/// Signatur: [`OperatorSessionProof`] ist ausdruecklich nicht `Clone`, und
/// ausserhalb von `ea-operator` kann ihn niemand bauen. Er gehoert dem
/// Implementierer, und [`BoundDiscard`] ist der eine, der ihn haelt.
///
/// Beide Rumpfe liefern [`RestartState`] und nicht `ea_draft::DiscardOutcome`.
/// Das ist eine Entscheidung mit zwei Gruenden: `DiscardOutcome` traegt die
/// Entwurfskennung und den leeren Entwurf — nichts davon gehoert an eine
/// Oberflaechengrenze —, und seine Konstruktoren sind `pub(crate)`, ein Doppel
/// kann es ausserhalb von `ea-draft` also gar nicht geben. [`RestartState`]
/// nennt dagegen GENAU das, was ein Bediener vorfindet, und ist messbar.
pub trait DraftDiscardPort {
    /// Bucht die Verwerfensabsicht dauerhaft und fuehrt das Verwerfen zu Ende.
    ///
    /// # Errors
    ///
    /// Der Fehler des Verwerfensdienstes, unveraendert.
    fn begin(&self) -> Result<RestartState, DraftError>;

    /// Setzt ein unterbrochenes Verwerfen fort.
    ///
    /// # Errors
    ///
    /// Der Fehler des Verwerfensdienstes, unveraendert.
    fn resume(&self) -> Result<RestartState, DraftError>;
}

/// Der Verwerfensdienst SAMT dem Nachweis, den nur der Wirt hat.
///
/// Der Nachweis liegt hinter einem Schloss und als `Option`, und das ist die
/// Zusage von `ea_draft::DiscardService::begin_discard` im Typ: die Methode
/// nimmt den Nachweis ALS WERT, weil ein Verwerfen unwiderruflich ist und ein
/// zweites Verwerfen eine zweite Wiederanmeldung verlangt. Ein gehaltener
/// Nachweis, der nach dem ersten Beginnen noch dalaege, waere genau die zweite
/// Autorisierung, die der Kern ausschliesst.
///
/// Sie traegt eine Lebensdauer und liegt deshalb NICHT im `'static`-Zustand der
/// Anwendung — wie [`BoundWriter`] wird sie je Aufruf gebaut. Die Aufloesung
/// von Bindung, Nachweis, Ablage und Schluesselport gehoert einem spaeteren
/// Task; was hier steht, ist die Naht, an der er andockt, und die drei Aufrufe
/// [`DiscardService::begin_discard`], [`DiscardService::resume_discard`] und
/// [`DiscardService::resume_after_restart`] stehen damit UEBERSETZT im Baum.
///
/// UEBERSETZT heisst nicht AUSGEFUEHRT: [`BoundDiscard::new`] hat heute keine
/// Aufrufstelle, weil kein Wirt einen Nachweis aufloest. Der heilende Arm des
/// Neustartpfads (`ea-draft/src/discard.rs`:220-224, VM-11) ist damit
/// STRUKTURELL VORBEREITET und nicht erreicht — er wird erreichbar, sobald ein
/// Wirt diese Naht baut, und keine Zeile dieses Pakets muss sich dafuer
/// aendern.
pub struct BoundDiscard<'a> {
    service: &'a DiscardService<'a>,
    proof: Mutex<Option<OperatorSessionProof>>,
}

impl<'a> BoundDiscard<'a> {
    #[must_use]
    pub fn new(service: &'a DiscardService<'a>, proof: OperatorSessionProof) -> Self {
        Self {
            service,
            proof: Mutex::new(Some(proof)),
        }
    }

    /// Der Nachweis unter seinem Schloss — vergiftet oder nicht.
    ///
    /// Ein vergiftetes Schloss darf hier kein `Err` werden: es waere ein
    /// Verwerfen, das nicht laeuft, weil ein anderer Thread abgestuerzt ist,
    /// und der Nachweis selbst bleibt davon unberuehrt.
    fn proof(&self) -> std::sync::MutexGuard<'_, Option<OperatorSessionProof>> {
        self.proof.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl DraftDiscardPort for BoundDiscard<'_> {
    /// Das Beginnen VERBRAUCHT den Nachweis.
    ///
    /// Ist er fort, ist das [`DraftError::ReauthRequired`] — derselbe Code, den
    /// der Kern fuer einen entwerteten Nachweis meldet, und keine erfundene
    /// zweite Aussage: ohne frische Wiederanmeldung verwirft dieses Geraet
    /// nichts.
    fn begin(&self) -> Result<RestartState, DraftError> {
        let proof = self.proof().take().ok_or(DraftError::ReauthRequired)?;
        self.service
            .begin_discard(proof)
            .map(|_| RestartState::NewBlankDraft)
    }

    /// Die Fortsetzung nimmt ZUERST die gebuchte Absicht und dann den
    /// Neustartpfad.
    ///
    /// Die Reihenfolge ist die Aussage. `resume_discard` setzt genau die
    /// gebuchte Absicht fort; kommt es dort nicht zum Fortsetzen, ist die Frage
    /// nicht beantwortet, sondern eine andere: was findet der Bediener vor? Das
    /// beantwortet `resume_after_restart` — samt der Vorrangregel der liegenden
    /// Abschlussmarke und samt dem heilenden Arm fuer einen Entwurf, dessen
    /// `draftDEK` nach einer zurueckgespielten Sicherung fort ist. Ein Entwurf,
    /// der nie mehr zu oeffnen ist, bliebe sonst als unladbare Zeile liegen.
    ///
    /// GENAU ZWEI Fehler fallen deshalb durch, und der zweite ist der wichtige:
    ///
    /// - [`DraftError::NoPendingDiscard`] — es ist keine Absicht gebucht.
    /// - [`DraftError::PreparedFinalizationPresent`] — eine Abschlussmarke
    ///   liegt. `DiscardService::resume_discard` prueft die Marke in `enter()`
    ///   und damit VOR `pending_discard()` (`ea-draft/src/discard.rs`:290-296),
    ///   meldet in diesem Fall also NIEMALS `NoPendingDiscard`. Ohne diesen
    ///   zweiten Arm waere `RestartState::PreparedFinalizationPending` von
    ///   dieser Naht aus UNERREICHBAR — der Ausgang, den die Oberflaeche als
    ///   Vorrangregel anzeigt, entstuende nie. Der Durchfall ist auch sachlich
    ///   richtig: `resume_after_restart` prueft die Marke als ERSTES und kehrt
    ///   mit genau diesem Ausgang zurueck, ohne ein Verwerfen fortzusetzen —
    ///   die Marke gewinnt an JEDEM Eingang.
    ///
    /// Jeder ANDERE Fehler bricht ab und wird nicht in den zweiten Weg
    /// umgedeutet: eine gehaltene Sperre oder ein Nachweis des falschen Zwecks
    /// ist keine Aussage darueber, was der Bediener vorfindet.
    fn resume(&self) -> Result<RestartState, DraftError> {
        let guard = self.proof();
        let proof = guard.as_ref().ok_or(DraftError::ReauthRequired)?;
        match self.service.resume_discard(proof) {
            Ok(_) => Ok(RestartState::NewBlankDraft),
            Err(DraftError::NoPendingDiscard | DraftError::PreparedFinalizationPresent) => {
                self.service.resume_after_restart(proof)
            }
            Err(other) => Err(other),
        }
    }
}

/// Der synchrone Port der Abschlussvorschau.
///
/// Derselbe Lebensdauergrund wie bei den zwei Ports darueber. Zusaetzlich ist
/// hier der SITZUNGSNACHWEIS nicht in der Signatur: er ist kein Wert, den eine
/// Grenze weiterreicht — [`OperatorSessionProof`] ist ausdruecklich nicht
/// `Clone`, und ausserhalb von `ea-operator` kann ihn niemand bauen. Er gehoert
/// dem Implementierer, und [`BoundWriter`] ist der eine, der ihn haelt.
///
/// Die Ansichtsmodelle stehen in der Signatur und nicht [`FinalizationPreview`]:
/// dessen Konstruktoren sind privat (`ea-writer/src/preview.rs`), eine Vorschau
/// kann also niemand ausserhalb des Kerns herstellen. Genau das ist gewollt —
/// und es heisst, dass die Grenze die ANSICHT weiterreicht und der Kern seine
/// eigene Vorschau behaelt.
pub trait WriterPreviewPort {
    fn validate_amendment_reference(
        &self,
        _reference: &ea_ui_contracts::CorrectionReferenceView,
    ) -> Result<(), CommandError> {
        Err(CommandError::new("EA-DESKTOP-AMENDMENT-UNAVAILABLE"))
    }
    fn preview_amendment(
        &self,
        _input: &ea_ui_contracts::AmendmentInputView,
    ) -> Result<FinalizationPreviewView, CommandError> {
        Err(CommandError::new("EA-DESKTOP-AMENDMENT-UNAVAILABLE"))
    }

    /// Die Vorschau zu genau diesem Einsatzrumpf.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns, oder eine benannte Voraussetzung des Wirts.
    fn preview(
        &self,
        incident: &IncidentInputView,
    ) -> Result<FinalizationPreviewView, CommandError>;
}

/// Der synchrone Port des unwiderruflichen Abschlusses.
///
/// Er hat [`WriterPreviewPort`] als Obertyp, weil ein Abschluss ohne die
/// Vorschau, gegen die er bestaetigt wurde, keiner ist: derselbe Wirt muss
/// beides koennen.
pub trait WriterFinalizePort: WriterPreviewPort {
    fn finalize_amendment(
        &self,
        _input: &ea_ui_contracts::AmendmentInputView,
        _confirmed: &FinalizationPreviewView,
    ) -> Result<FinalizeOutcomeView, CommandError> {
        Err(CommandError::new("EA-DESKTOP-AMENDMENT-UNAVAILABLE"))
    }
    fn acknowledge_stale_amendment(
        &self,
        _input: &ea_ui_contracts::AmendmentInputView,
        _confirmed: &FinalizationPreviewView,
        _warning_confirmed: bool,
    ) -> Result<(), CommandError> {
        Err(CommandError::new(WriterError::StaleAckRequired.code()))
    }

    /// Confirm the exact visible stale warning. The port must hold an opaque
    /// native proof whose signed context is this preview hash.
    fn acknowledge_stale_registry(
        &self,
        _incident: &IncidentInputView,
        _confirmed: &FinalizationPreviewView,
        _warning_confirmed: bool,
    ) -> Result<(), CommandError> {
        Err(CommandError::new(WriterError::StaleAckRequired.code()))
    }

    /// Schliesst den Eintrag ab — unwiderruflich.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns, oder eine benannte Voraussetzung des Wirts.
    fn finalize(
        &self,
        incident: &IncidentInputView,
        confirmed: &FinalizationPreviewView,
    ) -> Result<FinalizeOutcomeView, CommandError>;
}

/// Der Schreibdienst SAMT dem, was nur der Wirt hat.
///
/// Fuenf Teile, und keiner davon darf aus einer Antwort der Oberflaeche kommen:
/// der Dienst, der Sitzungsnachweis, die Stammdatenablage (aus ihr entstehen die
/// Momentaufnahmen mit Revision und Provenienz), die Geraetezeitzone und die
/// Vorschau, die dieser Wirt ausgestellt hat.
///
/// Sie traegt eine Lebensdauer und liegt deshalb NICHT im `'static`-Zustand der
/// Anwendung — wie [`ArchiveHealthCheckV1`] wird sie je Aufruf gebaut. Die
/// Aufloesung von Bindung, Nachweis, Datenbank, Bestand und Zeitzone gehoert
/// einem spaeteren Task; was hier steht, ist die Naht, an der er andockt, und
/// die zwei Aufrufe [`WriterService::preview`] und [`WriterService::finalize`]
/// stehen damit UEBERSETZT im Baum.
pub struct BoundWriter<'a> {
    amendments: Option<&'a ea_admin::amendment::AmendmentDraftService<'a, 'a>>,
    service: &'a WriterService<'a>,
    proof: &'a OperatorSessionProof,
    master_data: &'a MasterDataRepository,
    timezone: &'a str,
    issued: Option<&'a FinalizationPreview>,
    stale_proof: Option<&'a Mutex<Option<OperatorSessionProof>>>,
    stale_receipt: Option<&'a Mutex<Option<ea_writer::StaleRegistryAcknowledgement>>>,
    clock: &'a (dyn Fn() -> UnixMillis + Send + Sync),
}

impl<'a> BoundWriter<'a> {
    #[must_use]
    pub const fn new(
        service: &'a WriterService<'a>,
        proof: &'a OperatorSessionProof,
        master_data: &'a MasterDataRepository,
        timezone: &'a str,
        issued: Option<&'a FinalizationPreview>,
    ) -> Self {
        Self {
            service,
            proof,
            master_data,
            amendments: None,
            timezone,
            issued,
            stale_proof: None,
            stale_receipt: None,
            clock: &host_now,
        }
    }

    /// Bind the native reauthentication slot and retained opaque receipt of
    /// this host session. Startup owns these slots and clears them on lock.
    #[must_use]
    pub fn with_stale_registry(
        mut self,
        proof: &'a Mutex<Option<OperatorSessionProof>>,
        receipt: &'a Mutex<Option<ea_writer::StaleRegistryAcknowledgement>>,
        clock: &'a (dyn Fn() -> UnixMillis + Send + Sync),
    ) -> Self {
        self.stale_proof = Some(proof);
        self.stale_receipt = Some(receipt);
        self.clock = clock;
        self
    }

    #[must_use]
    pub fn with_amendments(
        mut self,
        service: &'a ea_admin::amendment::AmendmentDraftService<'a, 'a>,
        clock: &'a (dyn Fn() -> UnixMillis + Send + Sync),
    ) -> Self {
        self.amendments = Some(service);
        self.clock = clock;
        self
    }

    pub(crate) fn prepare_amendment_input(
        &self,
        input: &ea_ui_contracts::AmendmentInputView,
    ) -> Result<ea_writer::AmendmentInputV1, CommandError> {
        let reference = input
            .reference
            .to_reference()
            .ok_or_else(|| CommandError::new("EA-DESKTOP-AMENDMENT-REFERENCE-REJECTED"))?;
        let changes = input
            .changes
            .iter()
            .map(|change| {
                ea_schema::AmendmentChangeV1::new(
                    change.field_path.clone(),
                    change.change_text.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CommandError::new(e.code()))?;
        self.amendments
            .ok_or_else(|| CommandError::new("EA-DESKTOP-AMENDMENT-UNAVAILABLE"))?
            .create_from_reference(
                reference,
                ea_writer::AmendmentContentV1 {
                    timezone: self.timezone.to_owned(),
                    source: NativeSourceV1::new(NATIVE_SOURCE_ID, NATIVE_SOURCE_FORMAT_VERSION)
                        .map_err(|e| CommandError::new(e.code()))?,
                    reason: input.reason.clone(),
                    changes,
                },
                (self.clock)(),
            )
            .map_err(|e| CommandError::new(e.code()))
    }

    fn confirmed_preview(
        &self,
        confirmed: &FinalizationPreviewView,
    ) -> Result<&FinalizationPreview, CommandError> {
        let issued = self
            .issued
            .ok_or_else(|| CommandError::new(PREVIEW_NOT_ISSUED))?;
        if FinalizationPreviewView::from(issued) != *confirmed {
            return Err(CommandError::new(PREVIEW_MISMATCH));
        }
        Ok(issued)
    }

    /// Die Eingabe des Kerns aus der Ansicht der Oberflaeche.
    pub(crate) fn input(
        &self,
        incident: &IncidentInputView,
    ) -> Result<FinalizationInputV1, CommandError> {
        let personnel = incident
            .personnel
            .iter()
            .map(|person| self.personnel_snapshot(person))
            .collect::<Result<Vec<_>, _>>()?;
        let vehicles = incident
            .vehicles
            .iter()
            .map(|vehicle| self.vehicle_snapshot(vehicle))
            .collect::<Result<Vec<_>, _>>()?;
        finalization_input(incident, self.timezone, personnel, vehicles)
            .map_err(|error| CommandError::new(error.code()))
    }

    /// Die Momentaufnahme EINER Auswahl.
    ///
    /// Eine Stammdatenauswahl wird in der Ablage aufgeloest, damit Revision und
    /// Provenienz aus der Zeile kommen und nicht aus der Antwort einer
    /// Oberflaeche. Ein Ad-hoc-Eintrag traegt beides nicht — und zwar sichtbar.
    fn personnel_snapshot(
        &self,
        person: &PersonnelSelectionView,
    ) -> Result<PersonnelSnapshotV1, CommandError> {
        match person.master_personnel_id.as_deref() {
            None => {
                PersonnelSnapshotV1::ad_hoc(person.display_name.clone(), person.role_label.clone())
                    .map_err(|error| CommandError::new(error.code()))
            }
            Some(id) => self
                .master_data
                .snapshot_person(id)
                .map_err(|_| CommandError::new(MASTER_DATA_UNREADABLE)),
        }
    }

    fn vehicle_snapshot(
        &self,
        vehicle: &VehicleSelectionView,
    ) -> Result<VehicleSnapshotV1, CommandError> {
        match vehicle.master_vehicle_id.as_deref() {
            None => VehicleSnapshotV1::ad_hoc(
                vehicle.display_name.clone(),
                vehicle.radio_call_name.clone(),
                vehicle.license_plate.clone(),
            )
            .map_err(|error| CommandError::new(error.code())),
            Some(id) => self
                .master_data
                .snapshot_vehicle(id)
                .map_err(|_| CommandError::new(MASTER_DATA_UNREADABLE)),
        }
    }
}

impl WriterPreviewPort for BoundWriter<'_> {
    fn validate_amendment_reference(
        &self,
        reference: &ea_ui_contracts::CorrectionReferenceView,
    ) -> Result<(), CommandError> {
        self.prepare_amendment_input(&ea_ui_contracts::AmendmentInputView {
            reference: reference.clone(),
            reason: String::new(),
            changes: vec![],
        })
        .map(|_| ())
    }
    fn preview_amendment(
        &self,
        input: &ea_ui_contracts::AmendmentInputView,
    ) -> Result<FinalizationPreviewView, CommandError> {
        self.service
            .preview_amendment(
                self.proof,
                self.prepare_amendment_input(input)?,
                (self.clock)(),
            )
            .map(|preview| FinalizationPreviewView::from(&preview))
            .map_err(|e| CommandError::new(e.code()))
    }

    fn preview(
        &self,
        incident: &IncidentInputView,
    ) -> Result<FinalizationPreviewView, CommandError> {
        let input = self.input(incident)?;
        self.service
            .preview(self.proof, input, (self.clock)())
            .map(|preview| FinalizationPreviewView::from(&preview))
            .map_err(|error| CommandError::new(error.code()))
    }
}

impl WriterFinalizePort for BoundWriter<'_> {
    fn finalize_amendment(
        &self,
        input: &ea_ui_contracts::AmendmentInputView,
        confirmed: &FinalizationPreviewView,
    ) -> Result<FinalizeOutcomeView, CommandError> {
        let issued = self.confirmed_preview(confirmed)?;
        let input = self.prepare_amendment_input(input)?;
        let receipt = self
            .stale_receipt
            .map(|slot| {
                slot.lock()
                    .map(|mut slot| slot.take())
                    .map_err(|_| CommandError::new(WriterError::ReauthRequired.code()))
            })
            .transpose()?
            .flatten();
        let outcome = match receipt {
            Some(receipt) => self.service.finalize_amendment_with_stale_registry(
                self.proof,
                input,
                issued,
                &receipt,
                (self.clock)(),
            ),
            None => self
                .service
                .finalize_amendment(self.proof, input, issued, (self.clock)()),
        }
        .map_err(|e| CommandError::new(e.code()))?;
        Ok(FinalizeOutcomeView::new(&outcome, None))
    }

    fn acknowledge_stale_amendment(
        &self,
        input: &ea_ui_contracts::AmendmentInputView,
        confirmed: &FinalizationPreviewView,
        warning_confirmed: bool,
    ) -> Result<(), CommandError> {
        let issued = self.confirmed_preview(confirmed)?;
        let mut receipt = self
            .stale_receipt
            .ok_or_else(|| CommandError::new(WriterError::StaleAckRequired.code()))?
            .lock()
            .map_err(|_| CommandError::new(WriterError::ReauthRequired.code()))?;
        *receipt = None;
        let proof = self
            .stale_proof
            .and_then(|slot| slot.lock().ok()?.take())
            .ok_or_else(|| CommandError::new(WriterError::ReauthRequired.code()))?;
        *receipt = Some(
            self.service
                .acknowledge_stale_amendment(
                    proof,
                    self.prepare_amendment_input(input)?,
                    issued,
                    warning_confirmed,
                    (self.clock)(),
                )
                .map_err(|e| CommandError::new(e.code()))?,
        );
        Ok(())
    }

    fn acknowledge_stale_registry(
        &self,
        incident: &IncidentInputView,
        confirmed: &FinalizationPreviewView,
        warning_confirmed: bool,
    ) -> Result<(), CommandError> {
        let issued = self
            .issued
            .ok_or_else(|| CommandError::new(PREVIEW_NOT_ISSUED))?;
        if FinalizationPreviewView::from(issued) != *confirmed {
            return Err(CommandError::new(PREVIEW_MISMATCH));
        }
        let slot = self
            .stale_receipt
            .ok_or_else(|| CommandError::new(WriterError::StaleAckRequired.code()))?;
        let mut receipt = slot
            .lock()
            .map_err(|_| CommandError::new(WriterError::ReauthRequired.code()))?;
        *receipt = None;
        let proof = self
            .stale_proof
            .and_then(|slot| slot.lock().ok()?.take())
            .ok_or_else(|| CommandError::new(WriterError::ReauthRequired.code()))?;
        *receipt = Some(
            self.service
                .acknowledge_stale_registry(
                    proof,
                    self.input(incident)?,
                    issued,
                    warning_confirmed,
                    (self.clock)(),
                )
                .map_err(|error| CommandError::new(error.code()))?,
        );
        Ok(())
    }

    /// Der Abschluss gegen die Vorschau, die DIESER Wirt ausgestellt hat.
    ///
    /// Die Bestaetigung der Oberflaeche ist eine ANSICHT und keine Vorschau; sie
    /// wird deshalb gegen die gehaltene verglichen und nicht in eine
    /// zurueckgerechnet. Der Vergleich hier ist die Vorpruefung mit einem
    /// eigenen Code — die AUTORITATIVE Nachrechnung macht
    /// [`WriterService::finalize`] unter dem Writer-Lock und lehnt eine
    /// abweichende Vorschau mit dem Code des Kerns ab.
    fn finalize(
        &self,
        incident: &IncidentInputView,
        confirmed: &FinalizationPreviewView,
    ) -> Result<FinalizeOutcomeView, CommandError> {
        let issued = self
            .issued
            .ok_or_else(|| CommandError::new(PREVIEW_NOT_ISSUED))?;
        if FinalizationPreviewView::from(issued) != *confirmed {
            return Err(CommandError::new(PREVIEW_MISMATCH));
        }
        let input = self.input(incident)?;
        if let Some(slot) = self.stale_receipt
            && let Some(receipt) = slot
                .lock()
                .map_err(|_| CommandError::new(WriterError::ReauthRequired.code()))?
                .take()
        {
            return self
                .service
                .finalize_with_stale_registry(self.proof, input, issued, &receipt, (self.clock)())
                .map(|outcome| FinalizeOutcomeView::new(&outcome, None))
                .map_err(|error| CommandError::new(error.code()));
        }
        self.service
            .finalize(self.proof, input, issued, (self.clock)())
            .map(|outcome| FinalizeOutcomeView::new(&outcome, None))
            .map_err(|error| CommandError::new(error.code()))
    }
}

/// Die beobachtete Zeit des Wirts, JE AUFRUF gelesen.
///
/// Kein Feld: `WriterService::preview` bewertet Registry und Zeit bei jedem
/// Aufruf neu, und eine gespeicherte Messung waere keine erneute Bewertung. Vor
/// der Epoche liegt kein Zeitpunkt, den dieser Wirt melden koennte — der
/// Sattelpunkt ist deshalb null, und der Kern entscheidet dann ueber die
/// Zeitgrenzen des gebundenen Head.
fn host_now() -> UnixMillis {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    UnixMillis::new(millis)
}

/// Die Eingabe des Kerns aus Ansicht, Zeitzone und Momentaufnahmen — REIN.
///
/// Was diese Funktion NICHT tut: eine Momentaufnahme herstellen (die verlangt
/// die Stammdatenablage), einen Kopf fuellen (`recordId`,
/// `finalizedAtDevice`, der `operator`-Snapshot und die `registryVersion`
/// entstehen im Kern aus der geprueften Sitzung) und eine Zeitzone raten.
///
/// # Errors
///
/// Der [`SchemaError`] der Stufe 1, unveraendert — dieselben Konstruktoren, die
/// die eingefrorenen Bytes bauen.
pub fn finalization_input(
    incident: &IncidentInputView,
    timezone: &str,
    personnel: Vec<PersonnelSnapshotV1>,
    vehicles: Vec<VehicleSnapshotV1>,
) -> Result<FinalizationInputV1, SchemaError> {
    let scalars = incident.try_into_scalars()?;
    Ok(FinalizationInputV1 {
        timezone: timezone.to_owned(),
        source: NativeSourceV1::new(NATIVE_SOURCE_ID, NATIVE_SOURCE_FORMAT_VERSION)?,
        human_incident_number: incident.human_incident_number.clone(),
        occurred_at: scalars.occurred_at,
        keyword: scalars.keyword,
        location: scalars.location,
        personnel,
        personnel_empty_reason: incident.personnel_empty_reason.clone(),
        vehicles,
        vehicles_empty_reason: incident.vehicles_empty_reason.clone(),
        patient_count: scalars.patient_count,
        notes: incident.notes.clone(),
        external_organizations: scalars.external_organizations,
    })
}

/// Der synchrone Port der nativen Wiederanmeldung.
///
/// Der Port existiert aus demselben Grund wie die Ports darueber: eine
/// Wiederanmeldung verlangt einen `BoundOperator` aus einer aufgeloesten
/// Root-signierten Bindung am AKTUELLEN gewaehlten Head (`ea_operator::
/// OperatorAuthenticator::bound_operator`) und einen Anbieter nativer Praesenz
/// (Windows Hello, LocalAuthentication, PAM) — beides traegt Lebensdauern und
/// Plattformbezug und passt nicht in den `'static`-Zustand einer
/// Tauri-Anwendung. Bis zur Verdrahtung bleibt der Port `None`, und
/// `session_reauthenticate` antwortet mit der benannten Abwesenheit
/// [`crate::commands::REAUTH_UNAVAILABLE`].
///
/// # Warum der Rumpf KEINEN Nachweis herausgibt
///
/// [`OperatorSessionProof`] ist ausdruecklich nicht `Clone`, und ausserhalb
/// von `ea-operator` kann ihn niemand bauen. Ein Port, der ihn herausgaebe,
/// braeuchte einen Verbraucher, der ihn ueber die Kommandogrenze weiterreicht —
/// und keiner der Verbraucher (`DiscardService::begin_discard`,
/// `RootCeremonyService::publish_authorized_target`, `ClockReleaseService::
/// issue`) ist von hier aus mit einem Doppel messbar. Der Nachweis gehoert
/// deshalb dem IMPLEMENTIERER, wie bei [`BoundDiscard`] und [`BoundWriter`]:
/// derselbe Wirt, der die Praesenz verlangt, haelt das Ergebnis und reicht es
/// seinem Dienst selbst. Der Desktop merkt sich nur, DASS eine frische
/// Wiederanmeldung fuer genau diesen Zweck erbracht wurde
/// ([`SessionState::record_fresh_reauth`]) — die autoritative Pruefung des
/// Nachweises (`is_valid_for`, Bindung, Konto) bleibt im Kern.
///
/// `Send + Sync` steht wie bei den anderen Ports nicht als Supertrait daran;
/// die Schranke sitzt am Feld von [`DesktopState`].
pub trait ReauthPort {
    /// Verlangt frische Praesenz fuer GENAU `purpose`.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns (`EA-OPERATOR-*`), oder eine benannte
    /// Voraussetzung des Wirts.
    fn reauthenticate(&self, purpose: ReauthPurpose) -> Result<(), CommandError>;
}

/// Authority owned by the native host, checked again for each command. The UI
/// never receives or reconstructs its operator proofs.
pub trait RuntimeSessionPort: Send + Sync {
    fn verified_role(&self) -> Result<Option<OperatorRoleV1>, CommandError>;
    fn login(&self) -> Result<(), CommandError> {
        Err(CommandError::new(crate::commands::REAUTH_UNAVAILABLE))
    }
    /// Clear every proof, issued preview, and pending receipt before notifying UI.
    fn invalidate(&self);
}

/// Native destruction operations retain and verify their own proofs and exact
/// durable jobs. No caller-supplied boolean or view is an authority argument.
pub trait DestructionAdministrationPort: Send + Sync {
    /// Select existing public originals only. Legacy hosts must refuse;
    /// there is no fallback to unlock, prepare, start or archive bundle export.
    fn export_reader_delivery(
        &self,
        _id: ea_types::DestructionId,
        _expected_preflight_hash: ea_types::ObjectHash,
        _reader: ea_types::DeviceId,
    ) -> Result<ea_ui_contracts::DestructionReaderDeliveryView, CommandError> {
        Err(CommandError::new("EA-DESKTOP-READER-DELIVERY-UNAVAILABLE"))
    }

    /// Explicitly opens the same configured custodian and obtains its own
    /// Writer presence. This does not start, resume or finalize a destruction.
    fn authenticate_custodian(
        &self,
        id: ea_types::DestructionId,
        expected_preflight_hash: ea_types::ObjectHash,
    ) -> Result<ea_ui_contracts::DestructionAdministrationView, CommandError>;
    /// Authenticated server reads and verified local import only; no remote job or event POST.
    fn synchronize(
        &self,
        id: ea_types::DestructionId,
        expected_preflight_hash: ea_types::ObjectHash,
    ) -> Result<ea_ui_contracts::DestructionAdministrationView, CommandError>;
    fn read(
        &self,
        id: Option<ea_types::DestructionId>,
    ) -> Result<ea_ui_contracts::DestructionAdministrationView, CommandError>;
    fn prepare(
        &self,
        exact_authorization: &[u8],
    ) -> Result<ea_ui_contracts::DestructionAdministrationView, CommandError>;
    fn start(
        &self,
        id: ea_types::DestructionId,
        expected_preflight_hash: ea_types::ObjectHash,
    ) -> Result<ea_ui_contracts::DestructionAdministrationView, CommandError>;
    fn resume(
        &self,
        id: ea_types::DestructionId,
    ) -> Result<ea_ui_contracts::DestructionAdministrationView, CommandError>;
    /// The explicit, separately confirmed and final operator action that
    /// records missing confirmation (state 4). Resume never reaches it. Hosts
    /// without the native producer refuse; there is no fallback to Resume.
    fn mark_incomplete(
        &self,
        _id: ea_types::DestructionId,
        _expected_preflight_hash: ea_types::ObjectHash,
    ) -> Result<ea_ui_contracts::DestructionAdministrationView, CommandError> {
        Err(CommandError::new(
            "EA-DESKTOP-DESTRUCTION-MARK-INCOMPLETE-UNAVAILABLE",
        ))
    }
    fn import_progress(
        &self,
        id: ea_types::DestructionId,
        expected_preflight_hash: ea_types::ObjectHash,
        exact_etb_objects: &[Vec<u8>],
    ) -> Result<ea_ui_contracts::DestructionAdministrationView, CommandError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMediumChoice {
    UseConfiguredSource,
    Missing,
}

/// Admin orchestration with a separately authenticated native Writer.
/// No renderer evidence, session or unverified draft reference enters this port.
pub trait DestructionEvidencePort: Send + Sync {
    fn preview(
        &self,
        id: ea_types::DestructionId,
        expected_preflight_hash: ea_types::ObjectHash,
    ) -> Result<ea_ui_contracts::DestructionEvidenceReviewView, CommandError>;
    fn finalize(
        &self,
        id: ea_types::DestructionId,
        expected_preflight_hash: ea_types::ObjectHash,
        confirmed: &ea_ui_contracts::FinalizationPreviewView,
    ) -> Result<ea_ui_contracts::FinalizeOutcomeView, CommandError>;
    fn recover(
        &self,
        id: ea_types::DestructionId,
        expected_preflight_hash: ea_types::ObjectHash,
    ) -> Result<ea_ui_contracts::PendingResumeOutcomeView, CommandError>;
    fn discard(
        &self,
        id: ea_types::DestructionId,
        expected_preflight_hash: ea_types::ObjectHash,
    ) -> Result<ea_ui_contracts::DiscardStateView, CommandError>;
}

/// Inputs select only a configured medium route; the native kernel establishes
/// identity, protection and result independently.
pub trait RecoveryAdministrationPort: Send + Sync {
    fn read(&self) -> Result<ea_ui_contracts::RecoveryAdministrationView, CommandError>;
    fn start(&self) -> Result<ea_ui_contracts::RecoveryAdministrationView, CommandError>;
    fn submit(
        &self,
        operation: &str,
        run: &str,
        request: &str,
        choice: RecoveryMediumChoice,
    ) -> Result<ea_ui_contracts::RecoveryAdministrationView, CommandError>;
    fn cancel(
        &self,
        operation: &str,
    ) -> Result<ea_ui_contracts::RecoveryAdministrationView, CommandError>;
}

/// Der synchrone Port der Verwaltungsflaeche (Stufe 5, Task 6).
///
/// Der Port existiert, weil die vier Workflow-Dienste aus `ea-admin` allesamt
/// Lebensdauern tragen — `RootCeremonyService<'a>`, `ClockReleaseService<'a>`,
/// `WriterTransitionService<'a>`, `RegistryWorkflowService<'store>` — und
/// dazu einen gewaehlten Registry-Head, einen Trust-Speicher, den
/// Schluesselport und den Sitzungsnachweis, von denen die Anwendung beim
/// Hochkommen keines hat. Die Aufloesung geschieht bei der Verdrahtung; bis
/// dahin ist der Port `None`, und jedes `admin_*`-Kommando antwortet mit der
/// benannten Abwesenheit [`crate::commands::ADMINISTRATION_UNAVAILABLE`].
///
/// # Was der Port NICHT sieht
///
/// Keinen Freitext eines Bedieners: der Fingerprint kommt als geparster
/// [`ObjectHash`] (`ea_admin::fingerprint::parse_human_readable_fingerprint`
/// laeuft an der Kommandogrenze), die Zeremonieart und die Begruendung kommen
/// als geschlossene Aufzaehlungen. Keinen Sitzungsnachweis in der Signatur —
/// derselbe Grund wie bei [`ReauthPort`]: er gehoert dem Implementierer.
///
/// # Was der Port NICHT entscheidet
///
/// Die Schrittfolge. Jeder Zeremonierumpf liefert die ERREICHTE Ansicht, und
/// `commands::admin` prueft mit `ea_admin::ceremony_steps::next_step`, dass
/// genau ein Schritt weitergegangen wurde — ein Port, der springt oder
/// zurueckfaellt, wird mit
/// [`crate::commands::CEREMONY_STEP_OUT_OF_ORDER`] abgewiesen. Dafuer liest
/// die Grenze vor jedem Schritt [`Self::ceremony`].
///
/// # Was der Port liefert
///
/// Die Ansichtsmodelle aus `ea-ui-contracts`, fertig formatiert; einzig
/// [`Self::go_live_checklist`] liefert das Rust-Aggregat, weil die Grenze
/// daraus zwei Antworten macht (die Ansicht und die Evidenzliste
/// `unresolved_report_json`) und die Entscheidung `production_ready` im
/// Aggregat bleiben soll.
pub trait AdministrationPort {
    /// Read-only snapshot of the configured local archive's writer lock.
    /// Unconfigured adapters refuse rather than infer availability.
    fn diagnose_writer_lock(
        &self,
    ) -> Result<ea_ui_contracts::LocalWriterLockDiagnosis, CommandError> {
        Err(CommandError::new(
            crate::commands::ADMINISTRATION_UNAVAILABLE,
        ))
    }

    /// Reopens exact persisted unfinished rounds across all four workflows.
    /// Unconfigured/older adapters explicitly refuse this optional read seam.
    fn open_ceremonies(&self) -> Result<Vec<TrustCeremonyView>, CommandError> {
        Err(CommandError::new(
            crate::commands::ADMINISTRATION_UNAVAILABLE,
        ))
    }

    /// Die ausstehenden Geraeteanfragen.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns.
    fn pending_device_requests(&self) -> Result<Vec<PendingDeviceRequestView>, CommandError>;

    /// Der erreichte Stand EINER Zeremonie — vor jedem Schritt gelesen.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns; eine unbekannte Kennung ist ein Fehler und
    /// keine leere Zeremonie.
    fn ceremony(&self, ceremony_id: &str) -> Result<TrustCeremonyView, CommandError>;

    /// Beginnt eine Zeremonie fuer eine Anfrage; die Ansicht steht danach auf
    /// `PendingRequest`.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns.
    fn begin_ceremony(
        &self,
        request_id: &str,
        kind: TrustCeremonyKind,
    ) -> Result<TrustCeremonyView, CommandError>;

    /// Vergleicht den ueber den zweiten Kanal gemeldeten Fingerprint
    /// (`ea_admin::device::confirm_device_fingerprint`).
    ///
    /// # Errors
    ///
    /// `EA-WORKFLOW-FINGERPRINT-MISMATCH` oder ein anderer Code des Kerns.
    fn confirm_fingerprint(
        &self,
        ceremony_id: &str,
        reported: &ObjectHash,
    ) -> Result<TrustCeremonyView, CommandError>;

    /// Erteilt die Administrationsautorisierung — der Implementierer prueft
    /// seinen frischen Nachweis mit dem Zweck `AdminRootCeremony`.
    ///
    /// # Errors
    ///
    /// `EA-CEREMONY-*` oder ein anderer Code des Kerns.
    fn authorize(&self, ceremony_id: &str) -> Result<TrustCeremonyView, CommandError>;

    /// Schreibt die Root-Anfrage als Offline-Austauschdatei; die Ansicht
    /// traegt danach `exchange_file_name`.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns.
    fn export_request(&self, ceremony_id: &str) -> Result<TrustCeremonyView, CommandError>;

    /// Liest die Root-Antwort aus der Offline-Austauschdatei.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns.
    fn import_reply(&self, ceremony_id: &str) -> Result<TrustCeremonyView, CommandError>;

    /// Veroeffentlicht das Registry-Ereignis — der Implementierer prueft
    /// seinen frischen Nachweis mit dem Zweck `AdminRootCeremony`.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns.
    fn publish(&self, ceremony_id: &str) -> Result<TrustCeremonyView, CommandError>;

    /// Das Policy-Profil des gewaehlten Kopfes.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns.
    fn policy_profile(&self) -> Result<PolicyProfileView, CommandError>;

    /// Alter, Lease und Zeitstatus des gewaehlten Kopfes.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns.
    fn registry_health(&self) -> Result<RegistryHealthView, CommandError>;

    /// Die ausgewertete Go-live-Liste (`ea_admin::go_live::evaluate_go_live`).
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns.
    fn go_live_checklist(&self) -> Result<GoLiveChecklist, CommandError>;

    /// Was der Uhrenfreigabe-Assistent zeigen darf.
    ///
    /// # Errors
    ///
    /// `EA-SKEW-*` oder ein anderer Code des Kerns.
    fn clock_release_offer(&self) -> Result<ClockReleaseOfferView, CommandError>;

    /// Stellt eine Uhrenfreigabe aus — der Implementierer prueft seinen
    /// frischen Nachweis mit dem Zweck `ClockSkewRelease`.
    ///
    /// # Errors
    ///
    /// `EA-SKEW-*` oder ein anderer Code des Kerns.
    fn clock_release_issue(
        &self,
        justification: ClockReleaseJustificationV1,
    ) -> Result<ClockReleaseOutcomeView, CommandError>;

    /// Der Stand des Writer-Uebergangs.
    ///
    /// # Errors
    ///
    /// Der stabile Code des Kerns.
    fn writer_transition_state(&self) -> Result<WriterTransitionView, CommandError>;

    /// Bereitet den Uebergang aus dem JSON der Anfrage vor
    /// (`ea_admin::writer_transition::LoadedWriterTransitionRequest::from_json`).
    ///
    /// # Errors
    ///
    /// `EA-TRANSITION-*` oder ein anderer Code des Kerns.
    fn writer_transition_prepare(
        &self,
        request_json: &str,
    ) -> Result<WriterTransitionView, CommandError>;

    /// Aktiviert den vorbereiteten Uebergang — der Implementierer prueft
    /// seinen frischen Nachweis mit dem Zweck `AdminRootCeremony`.
    ///
    /// # Errors
    ///
    /// `EA-TRANSITION-*` oder ein anderer Code des Kerns.
    fn writer_transition_activate(&self) -> Result<WriterTransitionView, CommandError>;

    /// Was ein Widerruf dieses Ziels tut — und was nicht.
    ///
    /// # Errors
    ///
    /// `EA-WORKFLOW-TARGET-NOT-ACTIVE` oder ein anderer Code des Kerns.
    fn revocation_effect(&self, target: &ObjectHash) -> Result<RevocationEffectView, CommandError>;
}

/// Die geprueften Sitzungsangaben dieses Geraets.
///
/// Die Rolle ist eine `Option`, und `None` ist der Anfangszustand: sie kommt
/// aus einer Root-signierten Geraete-/OS-Kontobindung mit frischer Praesenz,
/// und diese Aufloesung gehoert Task 16. Solange sie fehlt, liefert
/// `verified_session` einen benannten Fehlschlag, und die Schale zeigt ihre
/// Flaeche ohne Sitzung — fail-closed und nicht ein erfundener Lesezustand.
///
/// Der Nachweis liegt daneben und nicht in der Rolle: [`OperatorSessionProof`]
/// ist absichtlich nicht `Clone`, damit [`Self::invalidate_on_lock`] keinen
/// gueltigen Stand daneben lassen kann. Er ist trotzdem keine Beigabe:
/// [`Self::role`] liefert `None`, solange er fehlt — die zwei Felder koennen
/// deshalb nicht auseinanderlaufen.
///
/// Die FRISCHEMARKE liegt als drittes Feld daneben: der Zweck der juengsten
/// nativen Wiederanmeldung, die ueber [`ReauthPort`] erbracht wurde. Sie ist
/// die Haelfte der Frischepflicht, die der Desktop erzwingen kann — der Nachweis
/// selbst liegt beim Implementierer (siehe [`ReauthPort`]), und
/// [`OperatorSessionProof`] traegt keinen Leser fuer seinen Zweck. Sie wird
/// VERBRAUCHT ([`Self::take_fresh_reauth`]) und nicht gelesen: eine
/// Wiederanmeldung traegt genau eine Root-Wirkung, wie
/// `DiscardService::begin_discard` den Nachweis als Wert nimmt.
///
/// Die Marke ist auf die ZWECKKLASSE bezogen ([`ReauthPurpose`]) und nicht
/// auf eine Zeremoniekennung oder ein Ziel — dieselbe Koernung wie der
/// [`OperatorSessionProof`] des Kerns, dessen Zweck ebenfalls klassenweit ist
/// und kein Ziel traegt. Eine Anwesenheit = eine privilegierte Handlung dieser
/// Klasse; WELCHE, entscheidet der Schritt, der sie verbraucht. Eine feinere
/// Bindung hier waere eine Zusage, die der Nachweis darunter nicht deckt.
pub struct SessionState {
    role: Option<OperatorRoleV1>,
    proof: Option<OperatorSessionProof>,
    fresh_reauth: Option<ReauthPurpose>,
}

impl SessionState {
    #[must_use]
    pub const fn new(role: Option<OperatorRoleV1>, proof: Option<OperatorSessionProof>) -> Self {
        Self {
            role,
            proof,
            fresh_reauth: None,
        }
    }

    /// Merkt sich, dass GENAU JETZT eine Wiederanmeldung fuer `purpose`
    /// erbracht wurde. Eine juengere ersetzt eine aeltere: es gibt eine
    /// frischeste Praesenz und keine Sammlung.
    pub fn record_fresh_reauth(&mut self, purpose: ReauthPurpose) {
        self.fresh_reauth = Some(purpose);
    }

    /// Der Zweck der frischesten Wiederanmeldung, solange sie unverbraucht ist.
    #[must_use]
    pub const fn fresh_reauth(&self) -> Option<ReauthPurpose> {
        self.fresh_reauth
    }

    /// Loescht die Frischemarke — unmittelbar VOR einer neuen Wiederanmeldung,
    /// damit eine fehlgeschlagene keine aeltere Marke stehen laesst.
    pub fn clear_fresh_reauth(&mut self) {
        self.fresh_reauth = None;
    }

    /// VERBRAUCHT die Frischemarke fuer `purpose` — `true`, wenn sie fuer genau
    /// diesen Zweck vorlag.
    ///
    /// Eine Marke fuer einen ANDEREN Zweck bleibt stehen: ein
    /// Zeremonieschritt, der versehentlich vor einer Uhrenfreigabe gerufen
    /// wird, darf dem Bediener die Freigabe nicht wegnehmen, die er gerade
    /// nachgewiesen hat. Verbraucht wird VOR dem Aufruf des Ports und nicht
    /// erst bei Erfolg: eine Praesenz, ein Versuch — ein Kern, der ablehnt,
    /// verlangt fuer den naechsten Versuch eine neue Praesenz, wie es der
    /// Verwerfensdienst mit seinem als Wert genommenen Nachweis auch tut.
    pub fn take_fresh_reauth(&mut self, purpose: ReauthPurpose) -> bool {
        if self.fresh_reauth == Some(purpose) {
            self.fresh_reauth = None;
            return true;
        }
        false
    }

    /// Die geprueften Rolle — und ausschliesslich MIT ihrem Nachweis.
    ///
    /// Der Nachweis ist die Bedingung und nicht die Beigabe: ohne
    /// [`OperatorSessionProof`] ist die Rolle hier nicht lesbar, auch wenn das
    /// Feld sie traegt. Ohne diese Klammer waeren Rolle und Nachweis zwei
    /// unabhaengige Felder, und ein Aufrufer, der die Rolle setzt und den
    /// Nachweis vergisst — Task 16 loest die Bindung auf —, bekaeme eine
    /// Sitzung, die niemand nachgewiesen hat. Die Frischepruefung des Nachweises
    /// (`OperatorSessionProof::is_valid_for` samt `MAX_INACTIVITY_MS`) verlangt
    /// eine `PreexistingEffectiveNow` aus `ea-trust` und gehoert damit Task 16;
    /// die ANWESENHEIT des Nachweises ist die Haelfte, die dieser Task
    /// erzwingen kann.
    #[must_use]
    pub const fn role(&self) -> Option<OperatorRoleV1> {
        if self.proof.is_none() {
            return None;
        }
        self.role
    }

    /// Entwertet die Sitzung wegen einer Sperre des Betriebssystems.
    ///
    /// Zwei Wirkungen, und beide sind notwendig: der Nachweis wird ueber
    /// [`OperatorSessionProof::invalidate_on_lock`] verbraucht, und die Rolle
    /// faellt weg. Ohne die zweite Haelfte blieben Rolle und Faehigkeiten
    /// lesbar, und die Oberflaeche haette nach der Sperre weiter eine Flaeche.
    pub fn invalidate_on_lock(&mut self) {
        self.role = None;
        self.proof = self
            .proof
            .take()
            .map(OperatorSessionProof::invalidate_on_lock);
        // Die Frischemarke geht mit: nach der Rueckkehr aus der Sperre ist jede
        // Wiederanmeldung neu zu erbringen.
        self.fresh_reauth = None;
    }
}

/// Der geteilte Zustand der Anwendung.
///
/// `Clone` ist billig — drei Zeiger — und ist die Voraussetzung dafuer, dass
/// jeder Kommandorumpf seine synchrone Kernoperation ueber
/// `tauri::async_runtime::spawn_blocking` schicken kann: der Abschluss dort
/// muss `Send + 'static` sein und darf deshalb keinen `tauri::State` fangen.
#[derive(Clone)]
pub struct DesktopState {
    session: Arc<Mutex<SessionState>>,
    runtime_session: Option<Arc<dyn RuntimeSessionPort>>,
    startup: Option<Arc<dyn StartupRecoveryPort + Send + Sync>>,
    master_data: Option<Arc<MasterDataRepository>>,
    drafts: Option<Arc<dyn DraftPayloadPort + Send + Sync>>,
    health: Option<Arc<dyn ArchiveHealthPort + Send + Sync>>,
    sync_state: Option<Arc<dyn SyncStatePort + Send + Sync>>,
    writer: Option<Arc<dyn WriterFinalizePort + Send + Sync>>,
    discard: Option<Arc<dyn DraftDiscardPort + Send + Sync>>,
    bundle_export: Option<Arc<dyn ArchiveBundleExportPort + Send + Sync>>,
    reauth: Option<Arc<dyn ReauthPort + Send + Sync>>,
    administration: Option<Arc<dyn AdministrationPort + Send + Sync>>,
    destruction: Option<Arc<dyn DestructionAdministrationPort>>,
    destruction_evidence: Option<Arc<dyn DestructionEvidencePort>>,
    recovery: Option<Arc<dyn RecoveryAdministrationPort>>,
}

impl DesktopState {
    #[must_use]
    pub fn new(
        session: SessionState,
        startup: Option<Arc<dyn StartupRecoveryPort + Send + Sync>>,
        master_data: Option<Arc<MasterDataRepository>>,
        drafts: Option<Arc<dyn DraftPayloadPort + Send + Sync>>,
        health: Option<Arc<dyn ArchiveHealthPort + Send + Sync>>,
        writer: Option<Arc<dyn WriterFinalizePort + Send + Sync>>,
    ) -> Self {
        Self {
            session: Arc::new(Mutex::new(session)),
            runtime_session: None,
            startup,
            master_data,
            drafts,
            health,
            sync_state: None,
            writer,
            discard: None,
            bundle_export: None,
            reauth: None,
            administration: None,
            destruction: None,
            destruction_evidence: None,
            recovery: None,
        }
    }

    /// Der Sync-Zustandsport dieses Wirts.
    ///
    /// Aus demselben Grund eine eigene Naht wie [`Self::with_discard`]: er
    /// verlangt einen aufgeloesten Bestand, eine geoeffnete lokale Ablage und
    /// ein konfiguriertes Sync-Ziel, und keines davon hat die Anwendung beim
    /// Hochkommen.
    #[must_use]
    pub fn with_sync_state(mut self, sync_state: Arc<dyn SyncStatePort + Send + Sync>) -> Self {
        self.sync_state = Some(sync_state);
        self
    }

    #[must_use]
    pub fn with_destruction(mut self, port: Arc<dyn DestructionAdministrationPort>) -> Self {
        self.destruction = Some(port);
        self
    }

    pub fn destruction_port(&self) -> Option<Arc<dyn DestructionAdministrationPort>> {
        self.destruction.clone()
    }

    #[must_use]
    pub fn with_destruction_evidence(mut self, port: Arc<dyn DestructionEvidencePort>) -> Self {
        self.destruction_evidence = Some(port);
        self
    }

    pub fn destruction_evidence_port(&self) -> Option<Arc<dyn DestructionEvidencePort>> {
        self.destruction_evidence.clone()
    }

    #[must_use]
    pub fn with_recovery(mut self, port: Arc<dyn RecoveryAdministrationPort>) -> Self {
        self.recovery = Some(port);
        self
    }

    pub fn recovery_port(&self) -> Option<Arc<dyn RecoveryAdministrationPort>> {
        self.recovery.clone()
    }

    /// Der Sync-Zustandsport, als GETEILTER Griff.
    ///
    /// Ein Griff und keine Referenz: der Kommandorumpf reicht ihn ueber
    /// `spawn_blocking` auf einen anderen Thread, und das verlangt einen
    /// besitzenden Wert.
    #[must_use]
    pub fn sync_state_port(&self) -> Option<Arc<dyn SyncStatePort + Send + Sync>> {
        self.sync_state.clone()
    }

    /// Der Verwerfensdienst dieses Wirts.
    ///
    /// Eine eigene Naht und keine siebte Stellung von [`Self::new`]: sechs
    /// Stellungen sind an der Aufrufstelle gerade noch lesbar, und
    /// `clippy::too_many_arguments` faellt ab der achten. Wichtiger ist die
    /// Aussage — der Verwerfensdienst kommt NICHT mit der Anwendung hoch: er
    /// verlangt einen Nachweis mit dem Zweck `ReauthPurpose::DiscardDraft`, und
    /// den gibt es erst, wenn ein Bediener sich fuer genau dieses Verwerfen neu
    /// angemeldet hat.
    #[must_use]
    pub fn with_discard(mut self, discard: Arc<dyn DraftDiscardPort + Send + Sync>) -> Self {
        self.discard = Some(discard);
        self
    }

    /// Der Buendelexport dieses Wirts.
    ///
    /// Aus demselben Grund eine eigene Naht wie [`Self::with_discard`]: er
    /// verlangt einen aufgeloesten Vertrauensanker und ein gewaehltes Ziel, und
    /// beides hat die Anwendung beim Hochkommen nicht.
    #[must_use]
    pub fn with_bundle_export(
        mut self,
        bundle_export: Arc<dyn ArchiveBundleExportPort + Send + Sync>,
    ) -> Self {
        self.bundle_export = Some(bundle_export);
        self
    }

    /// Die native Wiederanmeldung dieses Wirts.
    ///
    /// Aus demselben Grund eine eigene Naht wie [`Self::with_discard`]: sie
    /// verlangt einen `BoundOperator` aus einer aufgeloesten Root-signierten
    /// Bindung und einen Anbieter nativer Praesenz, und beides hat die
    /// Anwendung beim Hochkommen nicht.
    #[must_use]
    pub fn with_reauth(mut self, reauth: Arc<dyn ReauthPort + Send + Sync>) -> Self {
        self.reauth = Some(reauth);
        self
    }

    /// Die Wiederanmeldung, als GETEILTER Griff — aus demselben Grund wie
    /// [`Self::sync_state_port`]: der Kommandorumpf reicht ihn ueber
    /// `spawn_blocking` auf einen anderen Thread.
    #[must_use]
    pub fn reauth_port(&self) -> Option<Arc<dyn ReauthPort + Send + Sync>> {
        self.reauth.clone()
    }

    /// Die Verwaltungsflaeche dieses Wirts (Stufe 5, Task 6).
    ///
    /// Aus demselben Grund eine eigene Naht wie [`Self::with_discard`]: die
    /// vier Workflow-Dienste aus `ea-admin` verlangen einen gewaehlten Head,
    /// einen Trust-Speicher, den Schluesselport und einen Nachweis mit dem
    /// Zweck `AdminRootCeremony` — nichts davon hat die Anwendung beim
    /// Hochkommen, und keines davon kommt aus einer Antwort der Oberflaeche.
    #[must_use]
    pub fn with_administration(
        mut self,
        administration: Arc<dyn AdministrationPort + Send + Sync>,
    ) -> Self {
        self.administration = Some(administration);
        self
    }

    /// Die Verwaltungsflaeche, als GETEILTER Griff — aus demselben Grund wie
    /// [`Self::sync_state_port`].
    #[must_use]
    pub fn administration_port(&self) -> Option<Arc<dyn AdministrationPort + Send + Sync>> {
        self.administration.clone()
    }

    /// Die geprueften Sitzungsangaben, unter ihrem Schloss.
    #[must_use]
    pub fn session(&self) -> &Mutex<SessionState> {
        &self.session
    }

    #[must_use]
    pub fn with_runtime_session(mut self, runtime: Arc<dyn RuntimeSessionPort>) -> Self {
        self.runtime_session = Some(runtime);
        self
    }

    pub fn verified_role(&self) -> Result<Option<OperatorRoleV1>, CommandError> {
        if let Some(runtime) = &self.runtime_session {
            return runtime.verified_role();
        }
        self.session
            .lock()
            .map(|session| session.role())
            .map_err(|_| CommandError::new(crate::commands::SESSION_STATE_UNREADABLE))
    }

    pub fn login(&self) -> Result<(), CommandError> {
        self.runtime_session
            .as_ref()
            .ok_or_else(|| CommandError::new(crate::commands::REAUTH_UNAVAILABLE))?
            .login()
    }

    /// Entwertet die Sitzung, und zwar UNABHAENGIG von einem vergifteten
    /// Schloss.
    ///
    /// Ein `Err` waere hier die falsche Antwort: eine Sperre, die nicht
    /// wirkt, weil ein anderer Thread beim Halten des Schlosses abgestuerzt
    /// ist, liesse die Sitzung stehen. [`PoisonError::into_inner`] ist genau
    /// dafuer da.
    pub fn invalidate_session_on_lock(&self) {
        if let Some(runtime) = &self.runtime_session {
            runtime.invalidate();
        }
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .invalidate_on_lock();
    }

    /// Der Startpfad, wenn einer verdrahtet ist.
    #[must_use]
    pub fn startup(&self) -> Option<&(dyn StartupRecoveryPort + Send + Sync)> {
        self.startup.as_deref()
    }

    /// Die Stammdatenablage, wenn eine geoeffnete Datenbank vorliegt.
    #[must_use]
    pub fn master_data(&self) -> Option<&MasterDataRepository> {
        self.master_data.as_deref()
    }

    /// Die Entwurfsnutzlast, wenn eine geoeffnete Datenbank vorliegt.
    #[must_use]
    pub fn drafts(&self) -> Option<&(dyn DraftPayloadPort + Send + Sync)> {
        self.drafts.as_deref()
    }

    /// Der Gesundheitscheck, wenn ein Bestand geoeffnet ist.
    #[must_use]
    pub fn health(&self) -> Option<&(dyn ArchiveHealthPort + Send + Sync)> {
        self.health.as_deref()
    }

    /// Der Schreibdienst, wenn Bindung, Nachweis und Bestand aufgeloest sind.
    ///
    /// EIN Feld fuer Vorschau und Abschluss: ein Wirt, der die Vorschau
    /// ausstellen kann, ist derselbe, der abschliesst — und ein Wirt, der nur
    /// eines von beiden koennte, waere eine halbe Finalisierung.
    #[must_use]
    pub fn writer(&self) -> Option<&(dyn WriterFinalizePort + Send + Sync)> {
        self.writer.as_deref()
    }

    /// Der Verwerfensdienst, wenn Bindung, Nachweis und Ablage aufgeloest sind.
    #[must_use]
    pub fn discard(&self) -> Option<&(dyn DraftDiscardPort + Send + Sync)> {
        self.discard.as_deref()
    }

    /// Der Buendelexport, wenn Bestand, Vertrauensanker und Ziel aufgeloest
    /// sind.
    #[must_use]
    pub fn bundle_export(&self) -> Option<&(dyn ArchiveBundleExportPort + Send + Sync)> {
        self.bundle_export.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use ea_format::OperatorRoleV1;
    use ea_schema::PersonnelSnapshotV1;
    use ea_types::UnixMillis;
    use ea_ui_contracts::{
        IncidentInputView, KeywordView, LocationView, OccurredAtView, PatientCountView,
        PersonnelSelectionView,
    };

    use ea_operator::ReauthPurpose;

    use super::{
        CommandError, DesktopState, NATIVE_SOURCE_ID, ReauthPort, SessionState, finalization_input,
    };

    #[test]
    fn native_role_is_rechecked_and_lock_discards_host_authority_before_announcement() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct NativeSession(AtomicBool);
        impl super::RuntimeSessionPort for NativeSession {
            fn verified_role(&self) -> Result<Option<OperatorRoleV1>, CommandError> {
                Ok(self
                    .0
                    .load(Ordering::SeqCst)
                    .then_some(OperatorRoleV1::Writer))
            }
            fn invalidate(&self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let native = Arc::new(NativeSession(AtomicBool::new(true)));
        let state = DesktopState::new(SessionState::new(None, None), None, None, None, None, None)
            .with_runtime_session(native.clone());
        assert_eq!(state.verified_role().unwrap(), Some(OperatorRoleV1::Writer));
        crate::honor_session_lock(&state, || {
            assert!(!native.0.load(Ordering::SeqCst));
            assert_eq!(state.verified_role().unwrap(), None);
        });
        // Neither an old UI marker nor another role read revives native authority.
        state
            .session()
            .lock()
            .unwrap()
            .record_fresh_reauth(ReauthPurpose::Finalize);
        assert_eq!(state.verified_role().unwrap(), None);
    }

    fn view() -> IncidentInputView {
        IncidentInputView {
            human_incident_number: "2026-0001".to_owned(),
            occurred_at: OccurredAtView {
                start: UnixMillis::new(1_771_000_000_000),
                end: None,
            },
            keyword: KeywordView {
                reference_id: None,
                display_text: "Verkehrsunfall".to_owned(),
            },
            location: LocationView {
                free_text: Some("Bahnhofstrasse 1".to_owned()),
                address: None,
                coordinates: None,
            },
            personnel: vec![PersonnelSelectionView {
                master_personnel_id: None,
                display_name: "A. Beispiel".to_owned(),
                role_label: None,
            }],
            personnel_empty_reason: None,
            vehicles: Vec::new(),
            vehicles_empty_reason: Some("kein Fahrzeug alarmiert".to_owned()),
            patient_count: PatientCountView::Known(0),
            notes: Some("keine".to_owned()),
            external_organizations: Vec::new(),
        }
    }

    /// Die Eingabe des Kerns traegt JEDE Position der Ansicht — und die
    /// Quellkennung des WIRTS.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: eine Zusammenstellung, die eine
    /// Position fallen laesst (eine verlorene Begruendung verletzt die
    /// biconditionale Regel `EA-SCHEMA-LIST-REASON` erst tief im Schreibdienst)
    /// oder die Quellkennung aus der Antwort einer Oberflaeche nimmt. Die
    /// bekannte NULL ist dabei ausdruecklich mitgemessen: sie darf auf diesem
    /// Weg nicht zu `Unknown` werden.
    #[test]
    fn the_finalization_input_carries_every_position_of_the_view() {
        let personnel =
            vec![PersonnelSnapshotV1::ad_hoc("A. Beispiel", None).expect("ad hoc ist gueltig")];
        let input = finalization_input(&view(), "Europe/Berlin", personnel, Vec::new())
            .expect("die Stufe 1 nimmt an");
        assert_eq!(input.timezone, "Europe/Berlin");
        assert_eq!(input.source.source_id(), NATIVE_SOURCE_ID);
        assert_eq!(input.human_incident_number, "2026-0001");
        assert_eq!(input.personnel.len(), 1);
        assert!(!input.personnel[0].is_master());
        assert_eq!(input.personnel_empty_reason, None);
        assert!(input.vehicles.is_empty());
        assert_eq!(
            input.vehicles_empty_reason.as_deref(),
            Some("kein Fahrzeug alarmiert")
        );
        assert_eq!(input.patient_count.known(), Some(0));
        assert_eq!(input.notes.as_deref(), Some("keine"));
        assert!(input.external_organizations.is_empty());
    }

    /// Eine verletzte SKALARE Position kommt mit dem Code der Stufe 1 zurueck.
    #[test]
    fn a_violated_scalar_position_carries_the_stage_one_code() {
        let mut incident = view();
        incident.occurred_at.end = Some(UnixMillis::new(1_770_999_999_999));
        let Err(error) = finalization_input(&incident, "Europe/Berlin", Vec::new(), Vec::new())
        else {
            panic!("ein Ende vor dem Beginn ist kein Zeitraum")
        };
        assert_eq!(error.code(), "EA-SCHEMA-INTERVAL");
    }

    /// Der Zeuge der Klammer aus [`SessionState::role`].
    ///
    /// Er liest das FELD und den LESER getrennt — das ist der Grund, warum er
    /// hier steht und nicht in `commands/session.rs`: nur innerhalb dieses
    /// Moduls ist beides sichtbar. Faellt die Klammer weg, liefert `role()`
    /// wieder die Rolle ohne Nachweis, und `verified_session` gaebe eine
    /// Sitzung heraus, die niemand nachgewiesen hat.
    #[test]
    fn a_role_without_a_proof_is_not_a_readable_role() {
        let session = SessionState::new(Some(OperatorRoleV1::Writer), None);
        assert_eq!(session.role, Some(OperatorRoleV1::Writer));
        assert_eq!(session.role(), None);
    }

    /// Die Sperre nimmt AUCH das Feld mit und nicht bloss den Nachweis.
    #[test]
    fn the_lock_clears_the_declared_role_as_well() {
        let mut session = SessionState::new(Some(OperatorRoleV1::Writer), None);
        session.invalidate_on_lock();
        assert_eq!(session.role, None);
        assert!(session.proof.is_none());
    }

    /// Die Frischemarke ist EINMALIG und zweckgebunden: sie wird fuer genau
    /// den Zweck verbraucht, fuer den sie gesetzt wurde, und ein fremder Zweck
    /// verbraucht sie nicht.
    ///
    /// Der Fehlerfall: eine Marke, die nach dem Verbrauch stehen bliebe, liesse
    /// EINE Wiederanmeldung `AdminAuthorized` UND `RegistryPublished` tragen —
    /// zwei Root-Wirkungen fuer eine Praesenz. Und eine Marke, die ein
    /// Zeremonieschritt fuer den Zweck `ClockSkewRelease` verbrauchen koennte,
    /// naehme dem Bediener eine Freigabe weg, die er gerade nachgewiesen hat.
    #[test]
    fn a_fresh_reauth_is_consumed_once_and_only_for_its_purpose() {
        let mut session = SessionState::new(None, None);
        assert_eq!(session.fresh_reauth(), None);
        assert!(!session.take_fresh_reauth(ReauthPurpose::AdminRootCeremony));

        session.record_fresh_reauth(ReauthPurpose::ClockSkewRelease);
        assert!(!session.take_fresh_reauth(ReauthPurpose::AdminRootCeremony));
        assert_eq!(
            session.fresh_reauth(),
            Some(ReauthPurpose::ClockSkewRelease)
        );

        assert!(session.take_fresh_reauth(ReauthPurpose::ClockSkewRelease));
        assert_eq!(session.fresh_reauth(), None);
        assert!(!session.take_fresh_reauth(ReauthPurpose::ClockSkewRelease));

        session.record_fresh_reauth(ReauthPurpose::AdminRootCeremony);
        session.clear_fresh_reauth();
        assert_eq!(session.fresh_reauth(), None);
    }

    /// Eine zweite Wiederanmeldung ERSETZT die Marke: es gibt genau eine
    /// frischeste Praesenz, keine Sammlung.
    #[test]
    fn a_newer_reauth_replaces_the_older_marker() {
        let mut session = SessionState::new(None, None);
        session.record_fresh_reauth(ReauthPurpose::AdminRootCeremony);
        session.record_fresh_reauth(ReauthPurpose::ClockSkewRelease);
        assert!(!session.take_fresh_reauth(ReauthPurpose::AdminRootCeremony));
        assert!(session.take_fresh_reauth(ReauthPurpose::ClockSkewRelease));
    }

    /// Die Sperre nimmt die Frischemarke mit: nach der Rueckkehr aus der Sperre
    /// ist jede Wiederanmeldung neu zu erbringen.
    #[test]
    fn the_lock_clears_the_fresh_reauth_marker() {
        let mut session = SessionState::new(Some(OperatorRoleV1::OrganizationAdmin), None);
        session.record_fresh_reauth(ReauthPurpose::AdminRootCeremony);
        session.invalidate_on_lock();
        assert_eq!(session.fresh_reauth(), None);
    }

    /// Die zwei Verwaltungsnaehte sind beim Hochkommen LEER und werden ueber
    /// die Bauer gesetzt — nie ueber eine siebte Stellung von `new`.
    #[test]
    fn the_administration_seams_start_absent_and_are_set_by_their_builders() {
        struct NoReauth;
        impl ReauthPort for NoReauth {
            fn reauthenticate(&self, _purpose: ReauthPurpose) -> Result<(), CommandError> {
                Err(CommandError::new("EA-TEST-NEVER"))
            }
        }
        let bare = DesktopState::new(SessionState::new(None, None), None, None, None, None, None);
        assert!(bare.reauth_port().is_none());
        assert!(bare.administration_port().is_none());
        let wired = bare.with_reauth(std::sync::Arc::new(NoReauth));
        assert!(wired.reauth_port().is_some());
        assert!(wired.administration_port().is_none());
    }

    /// Die Reihenfolge von [`crate::honor_session_lock`], gemessen und nicht
    /// behauptet: zum Zeitpunkt der MELDUNG ist die Sitzung schon fort.
    ///
    /// Meldete der Wirt zuerst, gaebe es ein Fenster, in dem die Webview neu
    /// laedt und `verified_session` noch eine gueltige Sitzung liefert.
    #[test]
    fn the_lock_is_honored_before_the_shell_is_told() {
        let state = DesktopState::new(
            SessionState::new(Some(OperatorRoleV1::Writer), None),
            None,
            None,
            None,
            None,
            None,
        );
        let declared_at_announcement = Cell::new(Some(OperatorRoleV1::Writer));
        crate::honor_session_lock(&state, || {
            declared_at_announcement.set(state.session().lock().unwrap().role);
        });
        assert_eq!(declared_at_announcement.get(), None);
    }
}
