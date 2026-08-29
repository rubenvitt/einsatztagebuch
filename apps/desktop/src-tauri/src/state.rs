//! Der Zustand des Wirts — und die Naehte, an denen Task 16 andockt.

use std::sync::{Arc, Mutex, PoisonError};

use ea_archive::ArchiveBackendError;
use ea_archive_fs::{ArchiveHealthCheckV1, ArchiveHealthReport, BundleError};
use ea_draft::{DiscardService, DraftError, DraftRepository, MasterDataRepository, RestartState};
use ea_format::OperatorRoleV1;
use ea_operator::OperatorSessionProof;
use ea_schema::{NativeSourceV1, PersonnelSnapshotV1, SchemaError, VehicleSnapshotV1};
use ea_types::UnixMillis;
use ea_ui_contracts::{
    BundleExportView, FinalizationPreviewView, FinalizeOutcomeView, IncidentInputView,
    PersonnelSelectionView, SyncStateView, VehicleSelectionView,
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
/// damit woertlich aus `ea-archive-fs/src/bundle_error.rs` und nicht aus einer
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
    service: &'a WriterService<'a>,
    proof: &'a OperatorSessionProof,
    master_data: &'a MasterDataRepository,
    timezone: &'a str,
    issued: Option<&'a FinalizationPreview>,
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
            timezone,
            issued,
        }
    }

    /// Die Eingabe des Kerns aus der Ansicht der Oberflaeche.
    fn input(&self, incident: &IncidentInputView) -> Result<FinalizationInputV1, CommandError> {
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
    fn preview(
        &self,
        incident: &IncidentInputView,
    ) -> Result<FinalizationPreviewView, CommandError> {
        let input = self.input(incident)?;
        self.service
            .preview(self.proof, input, host_now())
            .map(|preview| FinalizationPreviewView::from(&preview))
            .map_err(|error| CommandError::new(error.code()))
    }
}

impl WriterFinalizePort for BoundWriter<'_> {
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
        self.service
            .finalize(self.proof, input, issued, host_now())
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
pub struct SessionState {
    role: Option<OperatorRoleV1>,
    proof: Option<OperatorSessionProof>,
}

impl SessionState {
    #[must_use]
    pub const fn new(role: Option<OperatorRoleV1>, proof: Option<OperatorSessionProof>) -> Self {
        Self { role, proof }
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
    startup: Option<Arc<dyn StartupRecoveryPort + Send + Sync>>,
    master_data: Option<Arc<MasterDataRepository>>,
    drafts: Option<Arc<dyn DraftPayloadPort + Send + Sync>>,
    health: Option<Arc<dyn ArchiveHealthPort + Send + Sync>>,
    sync_state: Option<Arc<dyn SyncStatePort + Send + Sync>>,
    writer: Option<Arc<dyn WriterFinalizePort + Send + Sync>>,
    discard: Option<Arc<dyn DraftDiscardPort + Send + Sync>>,
    bundle_export: Option<Arc<dyn ArchiveBundleExportPort + Send + Sync>>,
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
            startup,
            master_data,
            drafts,
            health,
            sync_state: None,
            writer,
            discard: None,
            bundle_export: None,
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

    /// Die geprueften Sitzungsangaben, unter ihrem Schloss.
    #[must_use]
    pub fn session(&self) -> &Mutex<SessionState> {
        &self.session
    }

    /// Entwertet die Sitzung, und zwar UNABHAENGIG von einem vergifteten
    /// Schloss.
    ///
    /// Ein `Err` waere hier die falsche Antwort: eine Sperre, die nicht
    /// wirkt, weil ein anderer Thread beim Halten des Schlosses abgestuerzt
    /// ist, liesse die Sitzung stehen. [`PoisonError::into_inner`] ist genau
    /// dafuer da.
    pub fn invalidate_session_on_lock(&self) {
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

    use super::{DesktopState, NATIVE_SOURCE_ID, SessionState, finalization_input};

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
