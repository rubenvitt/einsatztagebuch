//! Die Publikationswarteschlange: vier Zustaende, eine Detailursache DANEBEN.

use std::sync::{Mutex, PoisonError};

use ea_archive::{
    ArchiveBackendError, ArchiveBackendProfileV1, ArchivePath, ArchiveSource,
    BoundArchiveProfilePolicyV1,
};

use crate::LocalPathBackend;

/// Der Sync-Zustand — GESCHLOSSEN, vier Arme.
///
/// Die Beschriftungen sind die WOERTLICHE Oberflaechenkopie aus den globalen
/// Randbedingungen. `ea-writer` und `ea-ui-contracts` benutzen genau diese
/// Aufzaehlung weiter; ein zweiter Satz Zustandsnamen waere ein zweiter Satz
/// Wahrheiten.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SyncStatus {
    /// `lokal gesichert`
    LocallySaved,
    /// `Upload ausstehend`
    UploadPending,
    /// `synchronisiert`
    Synchronized,
    /// `Fehler`
    Failed,
}

impl SyncStatus {
    /// Alle vier Zustaende, in der Reihenfolge der Norm.
    pub const ALL: [Self; 4] = [
        Self::LocallySaved,
        Self::UploadPending,
        Self::Synchronized,
        Self::Failed,
    ];

    /// Die woertliche Oberflaechenkopie.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LocallySaved => "lokal gesichert",
            Self::UploadPending => "Upload ausstehend",
            Self::Synchronized => "synchronisiert",
            Self::Failed => "Fehler",
        }
    }
}

/// Die Detailursache — ein EIGENER Text, niemals ein fuenfter Zustand.
///
/// `design.md` §11.5 ist an dieser Stelle ausdruecklich: verliert ein
/// freigegebenes Netzbackend eine zugesicherte Faehigkeit, BLEIBT der Zustand
/// `Upload ausstehend` und die Ursache tritt DANEBEN. Ein fuenfter Zustand
/// waere genau die Vermischung, die die Norm verbietet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DetailCause {
    /// `Netzarchiv wartet`
    NetworkArchiveWaiting,
    /// Die Queuegrenze des Profils ist erreicht.
    QueueLimitReached,
    /// Das Profil steht nicht in der wirksamen Policy.
    ProfileNotAllowed,
    /// Die Wiederaufnahmeversuche des Profils sind erschoepft.
    ResumeAttemptsExhausted,
}

impl DetailCause {
    /// Alle Ursachen, in Deklarationsreihenfolge.
    pub const ALL: [Self; 4] = [
        Self::NetworkArchiveWaiting,
        Self::QueueLimitReached,
        Self::ProfileNotAllowed,
        Self::ResumeAttemptsExhausted,
    ];

    /// Der Oberflaechentext der Ursache.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NetworkArchiveWaiting => "Netzarchiv wartet",
            Self::QueueLimitReached => "Queuegrenze erreicht",
            Self::ProfileNotAllowed => "Profil nicht freigegeben",
            Self::ResumeAttemptsExhausted => "Wiederaufnahme erschoepft",
        }
    }
}

/// Ein Publikationsziel.
///
/// SYNCHRON, wie der ganze Rust-Kern: blockierendes Netz-I/O ist unter dem
/// `spawn_blocking`-Modell der Shell korrekt und kein Grund, `tokio` in die
/// Wurzeltabelle zu ziehen.
pub trait PublicationTargetV1: Send + Sync {
    /// Ist das Ziel gerade erreichbar?
    fn is_connected(&self) -> bool;

    /// Stellt die Verbindung wieder her.
    fn reconnect(&self);

    /// Veroeffentlicht EIN Objekt.
    ///
    /// # Errors
    ///
    /// Der Fehler des Ziels.
    fn publish_one(&self, relative: &ArchivePath, bytes: &[u8]) -> Result<(), ArchiveBackendError>;
}

/// Eine geplante Publikation. Die Reihenfolge IST Teil des Plans.
#[derive(Clone)]
pub struct PlannedPublicationV1 {
    objects: Vec<(ArchivePath, Vec<u8>)>,
}

impl PlannedPublicationV1 {
    #[must_use]
    pub const fn new(objects: Vec<(ArchivePath, Vec<u8>)>) -> Self {
        Self { objects }
    }

    /// Die exakten Bytes, in Planreihenfolge.
    #[must_use]
    pub fn exact_bytes(&self) -> Vec<Vec<u8>> {
        self.objects
            .iter()
            .map(|(_, bytes)| bytes.clone())
            .collect()
    }

    /// Die Adressen, in Planreihenfolge.
    #[must_use]
    pub fn order(&self) -> Vec<String> {
        self.objects
            .iter()
            .map(|(path, _)| path.as_str().to_owned())
            .collect()
    }

    /// Die Zahl der geplanten Objekte.
    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Ist der Plan leer?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Die Gesamtbytezahl des Plans.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.objects
            .iter()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum()
    }

    /// EA-CNA-PUB-1/2: der Plan aus committed lokalen Objekten, die am live
    /// gelesenen Netzziel FEHLEN — nie gespeichert, immer neu gebildet.
    ///
    /// Klassifiziert wird wie überall im Bestand ausschließlich am
    /// 9-Byte-Exact-Object-Präfix (`ea-archive/src/inventory.rs`): Beiwerk
    /// ohne dieses Präfix ist kein Publikationsgegenstand und wird
    /// übergangen. Trägt eine Adresse das Präfix, MUSS sie auch vollständig
    /// parsen — eine committete, aber beschädigte Adresse fiele sonst STILL
    /// aus der Publikation, statt als Befund zu erscheinen; ein Fehlschlag
    /// hier ist deshalb ein Fehler dieser Ableitung und kein übersprungenes
    /// Objekt. Liegt eine committed Adresse am Netzziel bereits mit
    /// DENSELBEN Bytes, ist sie schon veröffentlicht und fällt aus dem Plan.
    /// Liegt sie dort mit ANDEREN Bytes, ist das ein Bytekonflikt — keine
    /// Publikation, kein Überschreiben.
    ///
    /// Die Reihenfolge ist EA-CNA-PUB-2: aufsteigend nach der zwölfstelligen
    /// Sequenz vor dem ersten `_` des Dateinamens; Adressen ohne
    /// Sequenzpräfix stehen VOR allen sequenzierten, in binärer
    /// Adressordnung. Innerhalb einer Sequenz kommen alle Nicht-`.eip`-Objekte
    /// in binärer Adressordnung, das `.eip` zuletzt — Grants liegen damit
    /// immer vor ihrem Eintrag.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ByteConflict`] beim ersten gefundenen
    /// Bytekonflikt; [`ArchiveBackendError::Format`], wenn eine Adresse das
    /// Exact-Object-Präfix trägt, aber nicht vollständig parst; sonst der
    /// Fehler der Quelle oder des Netzziels.
    pub fn derive_pending(
        local: &dyn ArchiveSource,
        remote: &LocalPathBackend,
    ) -> Result<Self, ArchiveBackendError> {
        let mut pending: Vec<(ArchivePath, Vec<u8>)> = Vec::new();
        let mut failure: Option<ArchiveBackendError> = None;
        let visited = local.visit_blobs(&mut |blob| {
            if failure.is_some() {
                // Ein Befund liegt schon vor: nicht mehr weiterlesen, nur noch
                // sauber abbrechen.
                return Err(ea_archive::ArchiveError::Unavailable);
            }
            if !has_exact_object_prefix(blob.bytes()) {
                // Kein Archivobjekt (Formatbeiwerk & Co.) — kein
                // Publikationsgegenstand.
                return Ok(());
            }
            // Das Präfix ist da: die Bytes MÜSSEN auch vollständig parsen,
            // sonst fiele eine beschädigte, aber committete Adresse still aus
            // der Publikation statt als Befund zu erscheinen.
            if let Err(error) = ea_format::decode_exact_object(blob.bytes()) {
                failure = Some(ArchiveBackendError::from(error));
                return Err(ea_archive::ArchiveError::Unavailable);
            }
            let address = match crate::profile_migration::archive_path_of(blob.path_hint()) {
                Ok(address) => address,
                Err(error) => {
                    failure = Some(error);
                    return Err(ea_archive::ArchiveError::Unavailable);
                }
            };
            match remote.read_relative(address.as_str()) {
                Some(remote_bytes) if remote_bytes == blob.bytes() => {
                    // Bereits am Netzziel, byteidentisch: nichts zu tun.
                }
                Some(_) => {
                    failure = Some(ArchiveBackendError::ByteConflict);
                    return Err(ea_archive::ArchiveError::Unavailable);
                }
                None => pending.push((address, blob.bytes().to_vec())),
            }
            Ok(())
        });
        if let Some(error) = failure {
            return Err(error);
        }
        visited.map_err(|_| ArchiveBackendError::Io)?;
        pending.sort_by(|(left, _), (right, _)| compare_pending_addresses(left, right));
        Ok(Self::new(pending))
    }
}

/// Die sechs 9-Byte-Exact-Object-Präfixe — einzige Klassifikationsgrundlage,
/// wie überall im Bestand (`ea-archive/src/inventory.rs`).
const EXACT_OBJECT_PREFIXES_V1: [[u8; 9]; 6] = [
    ea_format::EIP_PREFIX_V1,
    ea_format::EAG_PREFIX_V1,
    ea_format::ESR_PREFIX_V1,
    ea_format::ECP_PREFIX_V1,
    ea_format::ETB_PREFIX_V1,
    ea_format::EDS_PREFIX_V1,
];

/// Trägt `bytes` eines der sechs Exact-Object-Präfixe?
fn has_exact_object_prefix(bytes: &[u8]) -> bool {
    EXACT_OBJECT_PREFIXES_V1
        .iter()
        .any(|prefix| bytes.starts_with(prefix))
}

/// Die zwölfstellige Sequenz vor dem ersten `_` des DATEINAMENS (nicht der
/// vollen Adresse) — `None`, wenn kein solches Präfix vorliegt.
fn sequence_prefix(path: &ArchivePath) -> Option<u64> {
    let filename = path.as_str().rsplit('/').next().unwrap_or(path.as_str());
    let (prefix, _rest) = filename.split_once('_')?;
    if prefix.len() == 12 && prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        prefix.parse::<u64>().ok()
    } else {
        None
    }
}

/// EA-CNA-PUB-2, als Vergleichsfunktion: Sequenz aufsteigend, sequenzlose
/// Adressen zuerst, `.eip` innerhalb einer Sequenz zuletzt, sonst binäre
/// Adressordnung.
fn compare_pending_addresses(left: &ArchivePath, right: &ArchivePath) -> std::cmp::Ordering {
    let is_eip = |path: &ArchivePath| path.as_str().ends_with(".eip");
    match (sequence_prefix(left), sequence_prefix(right)) {
        (None, None) => left.cmp(right),
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(left_sequence), Some(right_sequence)) => left_sequence
            .cmp(&right_sequence)
            .then_with(|| is_eip(left).cmp(&is_eip(right)))
            .then_with(|| left.cmp(right)),
    }
}

/// Was mit den geplanten Bytes GESCHAH — und ausdruecklich kein Zustand.
///
/// # Warum das hier steht und der Zustand nicht mehr
///
/// Bis Task 10 entschied diese Datei den oeffentlichen Sync-Zustand ein
/// ZWEITES Mal: einmal hier, einmal im Writer-Sync. `synchronisiert` ist aber
/// erst zulaessig, wenn der Server-Receipt in der lokalen Archivkomponente und
/// — sofern konfiguriert — im Netzarchiv liegt (`design.md`:1584), und davon
/// weiss die Warteschlange nichts. Seither sagt sie, was mit den Bytes
/// geschah, und `crates/ea-sync-client/src/queue.rs` bildet daraus den einen
/// oeffentlichen Zustand. Es gibt damit genau eine Wahrheit darueber.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PublicationOutcomeV1 {
    /// Es lag nichts an. KEINE Aussage darueber, ob je etwas veroeffentlicht
    /// wurde — nur darueber, dass gerade nichts aufgeschoben war.
    NothingPending,
    /// Jedes geplante Objekt ist beim Ziel angekommen.
    PublishedCompletely,
    /// Der Plan liegt VOLLSTAENDIG aufgeschoben in der Warteschlange; ein
    /// weiterer `resume` nimmt ihn byteidentisch wieder auf.
    Deferred,
    /// Die Queuegrenze des Profils ist ueberschritten. Der Plan wird
    /// ABGELEHNT und nicht aufbewahrt.
    QueueLimitReached,
}

impl PublicationOutcomeV1 {
    /// Alle Ausgaenge, in Deklarationsreihenfolge.
    pub const ALL: [Self; 4] = [
        Self::NothingPending,
        Self::PublishedCompletely,
        Self::Deferred,
        Self::QueueLimitReached,
    ];

    /// Ob der Plan die Warteschlange VOLLSTAENDIG verlassen hat.
    ///
    /// Die Frage, die ein Profilwechsel stellt: ein leerer Platz und kein
    /// Hartfehler. `NothingPending` traegt sie mit, weil ein nie belegter
    /// Platz derselbe Befund ist wie ein geleerter.
    #[must_use]
    pub const fn nothing_outstanding(self) -> bool {
        matches!(self, Self::NothingPending | Self::PublishedCompletely)
    }
}

/// Der beobachtbare Ausgang einer Publikation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationStateV1 {
    outcome: PublicationOutcomeV1,
    detail_cause: Option<DetailCause>,
    fell_back: bool,
    published_bytes: Vec<Vec<u8>>,
    published_order: Vec<String>,
}

impl PublicationStateV1 {
    /// Ein aufgeschobener Ausgang, der die Warteschlange gar nicht erst
    /// erreicht hat — etwa weil das Netzziel für die Ableitung
    /// (EA-CNA-PUB-1) nicht lesbar war. Nichts wurde veröffentlicht, und
    /// ausdrücklich nicht auf ein anderes Ziel ausgewichen.
    #[must_use]
    pub const fn deferred(detail_cause: Option<DetailCause>) -> Self {
        Self {
            outcome: PublicationOutcomeV1::Deferred,
            detail_cause,
            fell_back: false,
            published_bytes: Vec::new(),
            published_order: Vec::new(),
        }
    }

    /// Was mit den geplanten Bytes geschah.
    ///
    /// Es gab hier einmal ein `sync_status`. Es ist mit Task 10 gefallen, und
    /// zwar ersatzlos: die Abbildung auf die vier oeffentlichen Zustaende
    /// liegt seither ausschliesslich in `crates/ea-sync-client/src/queue.rs`,
    /// wo die verifizierte und abgelegte Quittung ueberhaupt bekannt ist.
    #[must_use]
    pub const fn outcome(&self) -> PublicationOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub const fn detail_cause(&self) -> Option<DetailCause> {
        self.detail_cause
    }

    /// Ob still auf ein anderes Ziel ausgewichen wurde.
    ///
    /// IMMER `false`, und das ist keine Vereinfachung: `design.md` §11.5 sagt,
    /// die Anwendung faellt niemals still auf ein anderes Ziel zurueck. Der
    /// Leser existiert, damit diese Zusage PRUEFBAR ist statt nur behauptet.
    #[must_use]
    pub const fn fell_back_to_another_target(&self) -> bool {
        self.fell_back
    }

    /// Die tatsaechlich veroeffentlichten Bytes, in Veroeffentlichungsreihenfolge.
    #[must_use]
    pub fn published_bytes(&self) -> Vec<Vec<u8>> {
        self.published_bytes.clone()
    }

    /// Die tatsaechlich veroeffentlichten Adressen, in derselben Reihenfolge.
    #[must_use]
    pub fn published_order(&self) -> Vec<String> {
        self.published_order.clone()
    }
}

/// Die Warteschlange vor einem Publikationsziel.
///
/// # Sperrreihenfolge: ERST `drain_lock`, DANN `pending`
///
/// Zwei getrennte Sperren, weil sie zwei verschiedene Dinge schützen:
/// `pending` ist nur der Platz selbst (kurz gehalten, auch für einen blinden
/// `take`/`store`), `drain_lock` ist die Zusage „höchstens EIN Drain läuft
/// gerade". `publish` und `resume` nehmen `drain_lock` deshalb ZUERST — vor
/// jedem Blick auf `pending` — und halten sie über den GESAMTEN Aufruf,
/// einschließlich eines etwaigen `drain`. Ohne das könnte ein gleichzeitiger
/// `resume` mitten in einem laufenden Drain einen GERADE GELEERTEN Platz
/// sehen und fälschlich [`PublicationOutcomeV1::NothingPending`] melden,
/// während der genommene Plan noch veröffentlicht wird — und
/// `ProfileMigrator::finish_pending` läse das als „nichts mehr offen" und
/// öffnete das Wechselgatter, obwohl der Plan noch unterwegs ist. Ebenso
/// könnte ein zweiter gleichzeitiger `publish` sonst PARALLEL zum ersten
/// drainen: beide Ziel-I/Os liefen verschachtelt, und EA-CNA-PUB-7s
/// „erst der ausstehende, dann neue Adressen" wäre nur noch eine Zusage über
/// die REIHENFOLGE INNERHALB eines Plans, nicht mehr über die tatsächliche
/// Ankunft am Ziel.
///
/// Eine Kehrseite, bewusst in Kauf genommen und nicht wegoptimiert: ein
/// hängender Mount (ein `is_connected`- oder `publish_one`-Aufruf, der nie
/// zurückkehrt) blockiert unter dieser Sperre JEDEN weiteren `publish`- und
/// `resume`-Aufruf auf derselben Warteschlange, nicht nur den eigenen. Die
/// Warteschlange erzwingt dafür keine Zeitschranke; das bleibt Aufgabe des
/// Ziels (siehe `PublicationTargetV1`-Implementierungen) und des Aufrufers.
pub struct PublicationQueue {
    target: Box<dyn PublicationTargetV1>,
    max_objects: u64,
    max_bytes: u64,
    pending: Mutex<Option<PlannedPublicationV1>>,
    /// Serialisiert JEDEN Drain gegen jeden anderen `publish`/`resume`-Aufruf.
    /// Siehe die Typdokumentation oben.
    drain_lock: Mutex<()>,
}

impl PublicationQueue {
    /// Baut die Warteschlange aus den Grenzen des gepinnten Profils.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::UnprofiledNetworkPath`], wenn das Profil kein
    /// kontrolliertes Netzprofil ist; [`ArchiveBackendError::ProfileNotAllowed`]
    /// fail-closed, wenn die Policy es nicht traegt.
    pub fn new(
        target: Box<dyn PublicationTargetV1>,
        profile: ArchiveBackendProfileV1,
        policy: &BoundArchiveProfilePolicyV1,
    ) -> Result<Self, ArchiveBackendError> {
        let ArchiveBackendProfileV1::ControlledNetworkPath(network) = &profile else {
            return Err(ArchiveBackendError::UnprofiledNetworkPath);
        };
        let (max_objects, max_bytes) = (network.queue_max_objects, network.queue_max_bytes);
        policy.require(profile.profile_hash()?)?;
        Ok(Self {
            target,
            max_objects,
            max_bytes,
            pending: Mutex::new(None),
            drain_lock: Mutex::new(()),
        })
    }

    /// Nimmt den Plan an und veröffentlicht, soweit das Ziel erreichbar ist.
    ///
    /// EA-CNA-PUB-7: ein neuer Plan VERDRÄNGT NIE einen ausstehenden. Liegt
    /// bereits ein Plan in der Warteschlange, wird er zuerst mit dem neuen
    /// VEREINIGT — dieselbe Adresse mit denselben Bytes zählt einmal,
    /// dieselbe Adresse mit ANDEREN Bytes ist ein Bytekonflikt und lässt den
    /// ausstehenden Plan UNVERÄNDERT zurück, sonst gilt: erst die
    /// ausstehenden, dann die neuen Adressen. Die Queuegrenze wird gegen die
    /// VEREINIGUNG geprüft; sprengt sie die Grenze, wird NUR die Vereinigung
    /// abgelehnt und der zuvor angenommene Plan bleibt bestehen.
    ///
    /// `drain_lock` wird ZUERST genommen (siehe Typdokumentation) und für den
    /// GESAMTEN Aufruf gehalten, einschließlich eines etwaigen `drain` — kein
    /// gleichzeitiger `publish` oder `resume` kann währenddessen laufen.
    ///
    /// Ein ANGENOMMENER Plan geht nicht mehr verloren: sowohl die verlorene
    /// Erreichbarkeit als auch ein Hartfehler des Ziels lassen ihn
    /// AUFGESCHOBEN in der Warteschlange zurück, `resume` setzt ihn dann
    /// byteidentisch fort. Nur die überschrittene Queuegrenze ist eine
    /// Ablehnung und wird deshalb nicht aufbewahrt.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ByteConflict`], wenn die Vereinigung mit dem
    /// ausstehenden Plan an derselben Adresse abweichende Bytes findet; sonst
    /// der Fehler des Ziels, wenn er NICHT die verlorene Erreichbarkeit ist —
    /// jene ist ein Zustand und kein Fehler. Der Plan bleibt in beiden Fällen
    /// aufgeschoben.
    pub fn publish(
        &self,
        planned: PlannedPublicationV1,
    ) -> Result<PublicationStateV1, ArchiveBackendError> {
        // Sperrreihenfolge: `drain_lock` VOR `pending` — siehe Typdokumentation.
        let _drain_guard = self
            .drain_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut guard = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let existing = guard.take();
        let merged = match &existing {
            None => planned,
            Some(existing_plan) => match Self::merge(existing_plan, &planned) {
                Ok(merged) => merged,
                Err(error) => {
                    // Bytekonflikt der Vereinigung: der ausstehende Plan
                    // bleibt UNVERÄNDERT, der neue wird verworfen.
                    *guard = existing;
                    return Err(error);
                }
            },
        };
        if merged.len() as u64 > self.max_objects || merged.total_bytes() > self.max_bytes {
            // Die Grenze ist überschritten: abgelehnt wird NUR die
            // Vereinigung, ausdrücklich KEIN Ausweichen auf ein anderes Ziel,
            // und der zuvor angenommene Plan bleibt bestehen.
            *guard = existing;
            return Ok(PublicationStateV1 {
                outcome: PublicationOutcomeV1::QueueLimitReached,
                detail_cause: Some(DetailCause::QueueLimitReached),
                fell_back: false,
                published_bytes: Vec::new(),
                published_order: Vec::new(),
            });
        }
        if !self.target.is_connected() {
            *guard = Some(merged);
            return Ok(PublicationStateV1 {
                outcome: PublicationOutcomeV1::Deferred,
                detail_cause: Some(DetailCause::NetworkArchiveWaiting),
                fell_back: false,
                published_bytes: Vec::new(),
                published_order: Vec::new(),
            });
        }
        // Ab hier läuft Netz-I/O: `pending` wird freigegeben (sie ist nur der
        // Platz, nicht die Serialisierung — die trägt weiterhin
        // `_drain_guard`, bis diese Funktion zurückkehrt).
        drop(guard);
        self.drain(merged)
    }

    /// Die Vereinigung aus `existing ⊎ new`: `existing`-Adressen zuerst, dann
    /// die neuen `new`-Adressen, die `existing` noch nicht trägt.
    ///
    /// Eine Adresse in BEIDEN Plänen mit denselben Bytes zählt EINMAL — genau
    /// die Idempotenz, die auch Create-if-absent trägt. Dieselbe Adresse mit
    /// ANDEREN Bytes ist ein Bytekonflikt.
    fn merge(
        existing: &PlannedPublicationV1,
        new: &PlannedPublicationV1,
    ) -> Result<PlannedPublicationV1, ArchiveBackendError> {
        let mut merged = existing.objects.clone();
        for (path, bytes) in &new.objects {
            match merged
                .iter()
                .find(|(existing_path, _)| existing_path == path)
            {
                Some((_, existing_bytes)) if existing_bytes == bytes => {
                    // Dieselbe Adresse, dieselben Bytes: schon vertreten.
                }
                Some(_) => return Err(ArchiveBackendError::ByteConflict),
                None => merged.push((path.clone(), bytes.clone())),
            }
        }
        Ok(PlannedPublicationV1::new(merged))
    }

    /// Legt den gerade gedrainten Plan zurück.
    ///
    /// # Warum der Platz hier IMMER leer sein muss
    ///
    /// `publish` und `resume` nehmen `drain_lock` VOR `pending` und halten
    /// sie für den GESAMTEN Aufruf einschließlich `drain` (siehe
    /// Typdokumentation von [`PublicationQueue`]). Der Aufrufer DIESER
    /// Methode hält `drain_lock` deshalb durchgehend seit dem `take`, das den
    /// hier übergebenen Plan aus `pending` herausgenommen hat — kein anderer
    /// `publish`- oder `resume`-Aufruf kann in der Zwischenzeit an `pending`
    /// herangekommen sein, ohne zuerst selbst an `drain_lock` zu hängen. Der
    /// Platz MUSS an dieser Stelle also leer sein.
    ///
    /// Ein belegter Platz wäre deshalb kein normaler Ausgang mehr, sondern
    /// ein Bruch genau dieser Sperrreihenfolge — ein Programmierfehler, nicht
    /// ein Wettlauf, den die Anwendung im Normalbetrieb je sieht. Er wird
    /// trotzdem NICHT blind überschrieben: bytegleiche Adressen werden
    /// vereinigt, eine abweichende Adresse liefert den Bytekonflikt an den
    /// Aufrufer zurück, statt eine Seite stillschweigend zu verwerfen — der
    /// gedrainte Plan bleibt dabei in jedem Fall erhalten.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ByteConflict`], wenn der Platz ENTGEGEN der
    /// Sperrreihenfolge doch belegt war und mit abweichenden Bytes.
    fn restore(&self, plan: PlannedPublicationV1) -> Result<(), ArchiveBackendError> {
        let mut guard = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        match guard.take() {
            None => {
                *guard = Some(plan);
                Ok(())
            }
            Some(unexpected) => match Self::merge(&plan, &unexpected) {
                Ok(merged) => {
                    *guard = Some(merged);
                    Ok(())
                }
                Err(error) => {
                    // Der gedrainte Plan bleibt WENIGSTENS erhalten; der
                    // Konflikt wird gemeldet statt verschluckt.
                    *guard = Some(plan);
                    Err(error)
                }
            },
        }
    }

    /// Stellt die Verbindung wieder her und gibt die Warteschlange zurueck.
    #[must_use]
    pub fn reconnect(&self) -> &Self {
        self.target.reconnect();
        self
    }

    /// Setzt die aufgeschobene Publikation fort — BYTEIDENTISCH und in
    /// derselben Reihenfolge.
    ///
    /// `drain_lock` wird ZUERST genommen (siehe Typdokumentation) und für den
    /// GESAMTEN Aufruf gehalten: läuft gerade ein anderer Drain, WARTET
    /// `resume`, statt einen mitten in der Veröffentlichung geleerten Platz
    /// zu sehen und fälschlich [`PublicationOutcomeV1::NothingPending`] zu
    /// melden — genau die Verwechslung, die `ProfileMigrator::finish_pending`
    /// als „Gatter offen" läse, während der Plan noch unterwegs ist.
    ///
    /// Ein Hartfehler des Ziels laesst den Plan aufgeschoben; ein weiterer
    /// `resume` nimmt ihn deshalb WIEDER auf.
    /// [`PublicationOutcomeV1::NothingPending`] heisst genau eines: es lag
    /// nichts an. Es heisst ausdruecklich NICHT `synchronisiert` — ob der
    /// Eintrag synchronisiert ist, entscheidet die verifizierte Quittung in
    /// `crates/ea-sync-client/src/queue.rs` und nicht ein leerer Platz.
    ///
    /// # Errors
    ///
    /// Der Fehler des Ziels. Der Plan bleibt in diesem Fall aufgeschoben.
    pub fn resume(&self) -> Result<PublicationStateV1, ArchiveBackendError> {
        // Sperrreihenfolge: `drain_lock` VOR `pending` — siehe Typdokumentation.
        let _drain_guard = self
            .drain_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let planned = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match planned {
            None => Ok(PublicationStateV1 {
                outcome: PublicationOutcomeV1::NothingPending,
                detail_cause: None,
                fell_back: false,
                published_bytes: Vec::new(),
                published_order: Vec::new(),
            }),
            Some(planned) => self.drain(planned),
        }
    }

    /// Veroeffentlicht den Plan in seiner Reihenfolge.
    ///
    /// Der Plan verlaesst die Warteschlange NUR vollstaendig veroeffentlicht:
    /// jeder andere Ausgang — verlorene Erreichbarkeit wie Hartfehler des
    /// Ziels — legt ihn GANZ zurueck. Ein fallengelassener Plan waere eine
    /// stille Herabstufung: der naechste `resume` faende einen leeren Slot,
    /// meldete [`PublicationOutcomeV1::NothingPending`] und ein Profilwechsel
    /// liefe durch, ohne dass die geplanten Objekte je beim Ziel angekommen
    /// sind.
    ///
    /// Nur `publish`/`resume` rufen diese Methode, und beide halten
    /// `drain_lock` bereits durchgehend (siehe dort und die Typdokumentation
    /// von [`PublicationQueue`]) — `drain` selbst nimmt keine Sperre.
    fn drain(
        &self,
        planned: PlannedPublicationV1,
    ) -> Result<PublicationStateV1, ArchiveBackendError> {
        let mut published_bytes = Vec::with_capacity(planned.len());
        let mut published_order = Vec::with_capacity(planned.len());
        for (path, bytes) in &planned.objects {
            if !self.target.is_connected() {
                // Mitten im Lauf verloren: der bereits veroeffentlichte Teil
                // bleibt, der Rest wird aufgeschoben. Die Bytes bleiben
                // dieselben — deshalb wird der GANZE Plan aufbewahrt und beim
                // Wiederanlauf von vorn durchlaufen; Create-if-absent macht das
                // idempotent.
                self.restore(planned)?;
                return Ok(PublicationStateV1 {
                    outcome: PublicationOutcomeV1::Deferred,
                    detail_cause: Some(DetailCause::NetworkArchiveWaiting),
                    fell_back: false,
                    published_bytes,
                    published_order,
                });
            }
            if let Err(error) = self.target.publish_one(path, bytes) {
                if indicates_lost_connectivity(&error) {
                    // Erreichbar laut `is_connected`, aber der Schreib- oder
                    // Lesevorgang selbst scheitert mit `Io`/`FlushFailed`
                    // (EA-CNA-PUB-4, Fund B): ein vorhandener, aber
                    // UNBENUTZBARER Mount (Mount-Stub, ein Share, der erst
                    // beim Schreiben scheitert) macht sich oft erst HIER
                    // bemerkbar, nicht schon an `is_connected`. Das ist
                    // dieselbe VERLORENE Erreichbarkeit wie oben und kein
                    // Hartfehler.
                    self.restore(planned)?;
                    return Ok(PublicationStateV1 {
                        outcome: PublicationOutcomeV1::Deferred,
                        detail_cause: Some(DetailCause::NetworkArchiveWaiting),
                        fell_back: false,
                        published_bytes,
                        published_order,
                    });
                }
                // HARTFEHLER, keine verlorene Erreichbarkeit: das Ziel ist
                // erreichbar und lehnt ab. Der GANZE Plan bleibt aufgeschoben
                // — dieselbe Aufbewahrung wie oben und aus demselben Grund,
                // denn ein Wiederanlauf ist ueber Create-if-absent idempotent.
                // Der Fehler des Ziels wird trotzdem gemeldet: aufbewahrt ist
                // nicht behoben.
                self.restore(planned)?;
                return Err(error);
            }
            published_bytes.push(bytes.clone());
            published_order.push(path.as_str().to_owned());
        }
        Ok(PublicationStateV1 {
            outcome: PublicationOutcomeV1::PublishedCompletely,
            detail_cause: None,
            fell_back: false,
            published_bytes,
            published_order,
        })
    }
}

/// Ob ein Zielfehler auf eine VERLORENE Verbindung hindeutet statt auf einen
/// reinen Datenbefund (EA-CNA-PUB-4, Fund B der Review).
///
/// `ByteConflict` (das Ziel ist erreichbar und lehnt eine ANDERE Bytefolge an
/// derselben Adresse ab), `Format` (kein gültiges Archivobjekt) und
/// `ProfileNotAllowed` bleiben AUSSERHALB — sie sind Datenbefunde, keine
/// Verbindungsstörung.
pub(crate) fn indicates_lost_connectivity(error: &ArchiveBackendError) -> bool {
    matches!(
        error,
        ArchiveBackendError::Io | ArchiveBackendError::FlushFailed
    )
}
