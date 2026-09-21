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
    /// Klassifiziert wird wie ueberall im Bestand ausschliesslich am
    /// 9-Byte-Exact-Object-Praefix (`ea-archive/src/inventory.rs`): Beiwerk
    /// ohne dieses Praefix ist kein Publikationsgegenstand und wird
    /// uebergangen. Liegt eine committed Adresse am Netzziel bereits mit
    /// DENSELBEN Bytes, ist sie schon veroeffentlicht und faellt aus dem Plan.
    /// Liegt sie dort mit ANDEREN Bytes, ist das ein Bytekonflikt — keine
    /// Publikation, kein Ueberschreiben.
    ///
    /// Die Reihenfolge ist EA-CNA-PUB-2: aufsteigend nach der zwoelfstelligen
    /// Sequenz vor dem ersten `_` des Dateinamens; Adressen ohne
    /// Sequenzpraefix stehen VOR allen sequenzierten, in binaerer
    /// Adressordnung. Innerhalb einer Sequenz kommen alle Nicht-`.eip`-Objekte
    /// in binaerer Adressordnung, das `.eip` zuletzt — Grants liegen damit
    /// immer vor ihrem Eintrag.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ByteConflict`] beim ersten gefundenen
    /// Bytekonflikt; sonst der Fehler der Quelle oder des Netzziels.
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
            if ea_format::decode_exact_object(blob.bytes()).is_err() {
                // Kein Archivobjekt (Formatbeiwerk & Co.) — kein
                // Publikationsgegenstand.
                return Ok(());
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

/// Die zwoelfstellige Sequenz vor dem ersten `_` des DATEINAMENS (nicht der
/// vollen Adresse) — `None`, wenn kein solches Praefix vorliegt.
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
/// Adressen zuerst, `.eip` innerhalb einer Sequenz zuletzt, sonst binaere
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
pub struct PublicationQueue {
    target: Box<dyn PublicationTargetV1>,
    max_objects: u64,
    max_bytes: u64,
    pending: Mutex<Option<PlannedPublicationV1>>,
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
        })
    }

    /// Nimmt den Plan an und veroeffentlicht, soweit das Ziel erreichbar ist.
    ///
    /// EA-CNA-PUB-7: ein neuer Plan VERDRAENGT NIE einen ausstehenden. Liegt
    /// bereits ein Plan in der Warteschlange, wird er zuerst mit dem neuen
    /// VEREINIGT — dieselbe Adresse mit denselben Bytes zaehlt einmal,
    /// dieselbe Adresse mit ANDEREN Bytes ist ein Bytekonflikt und laesst den
    /// ausstehenden Plan UNVERAENDERT zurueck, sonst gilt: erst die
    /// ausstehenden, dann die neuen Adressen. Die Queuegrenze wird gegen die
    /// VEREINIGUNG geprueft; sprengt sie die Grenze, wird NUR die Vereinigung
    /// abgelehnt und der zuvor angenommene Plan bleibt bestehen.
    ///
    /// Ein ANGENOMMENER Plan geht nicht mehr verloren: sowohl die verlorene
    /// Erreichbarkeit als auch ein Hartfehler des Ziels lassen ihn
    /// AUFGESCHOBEN in der Warteschlange zurueck, `resume` setzt ihn dann
    /// byteidentisch fort. Nur die ueberschrittene Queuegrenze ist eine
    /// Ablehnung und wird deshalb nicht aufbewahrt.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ByteConflict`], wenn die Vereinigung mit dem
    /// ausstehenden Plan an derselben Adresse abweichende Bytes findet; sonst
    /// der Fehler des Ziels, wenn er NICHT die verlorene Erreichbarkeit ist —
    /// jene ist ein Zustand und kein Fehler. Der Plan bleibt in beiden Faellen
    /// aufgeschoben.
    pub fn publish(
        &self,
        planned: PlannedPublicationV1,
    ) -> Result<PublicationStateV1, ArchiveBackendError> {
        let existing = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let merged = match &existing {
            None => planned,
            Some(existing_plan) => match Self::merge(existing_plan, &planned) {
                Ok(merged) => merged,
                Err(error) => {
                    // Bytekonflikt der Vereinigung: der ausstehende Plan
                    // bleibt UNVERAENDERT, der neue wird verworfen.
                    *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = existing;
                    return Err(error);
                }
            },
        };
        if merged.len() as u64 > self.max_objects || merged.total_bytes() > self.max_bytes {
            // Die Grenze ist ueberschritten: abgelehnt wird NUR die
            // Vereinigung, ausdruecklich KEIN Ausweichen auf ein anderes
            // Ziel, und der zuvor angenommene Plan bleibt bestehen.
            *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = existing;
            return Ok(PublicationStateV1 {
                outcome: PublicationOutcomeV1::QueueLimitReached,
                detail_cause: Some(DetailCause::QueueLimitReached),
                fell_back: false,
                published_bytes: Vec::new(),
                published_order: Vec::new(),
            });
        }
        if !self.target.is_connected() {
            *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(merged);
            return Ok(PublicationStateV1 {
                outcome: PublicationOutcomeV1::Deferred,
                detail_cause: Some(DetailCause::NetworkArchiveWaiting),
                fell_back: false,
                published_bytes: Vec::new(),
                published_order: Vec::new(),
            });
        }
        self.drain(merged)
    }

    /// Die Vereinigung aus `existing ⊎ new`: `existing`-Adressen zuerst, dann
    /// die neuen `new`-Adressen, die `existing` noch nicht traegt.
    ///
    /// Eine Adresse in BEIDEN Plaenen mit denselben Bytes zaehlt EINMAL —
    /// genau die Idempotenz, die auch Create-if-absent traegt. Dieselbe
    /// Adresse mit ANDEREN Bytes ist ein Bytekonflikt.
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

    /// Stellt die Verbindung wieder her und gibt die Warteschlange zurueck.
    #[must_use]
    pub fn reconnect(&self) -> &Self {
        self.target.reconnect();
        self
    }

    /// Setzt die aufgeschobene Publikation fort — BYTEIDENTISCH und in
    /// derselben Reihenfolge.
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
                *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(planned);
                return Ok(PublicationStateV1 {
                    outcome: PublicationOutcomeV1::Deferred,
                    detail_cause: Some(DetailCause::NetworkArchiveWaiting),
                    fell_back: false,
                    published_bytes,
                    published_order,
                });
            }
            if let Err(error) = self.target.publish_one(path, bytes) {
                // HARTFEHLER, keine verlorene Erreichbarkeit: das Ziel ist
                // erreichbar und lehnt ab. Der GANZE Plan bleibt aufgeschoben
                // — dieselbe Aufbewahrung wie oben und aus demselben Grund,
                // denn ein Wiederanlauf ist ueber Create-if-absent idempotent.
                // Der Fehler des Ziels wird trotzdem gemeldet: aufbewahrt ist
                // nicht behoben.
                *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(planned);
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
