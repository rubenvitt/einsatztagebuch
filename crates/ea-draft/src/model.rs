//! Die Werte, die zwischen Oberflaeche und Ablage reisen — und der Fehler.
//!
//! Task 7 legt seinen Verwerfensdienst NEBEN diese Typen; sie liegen deshalb
//! schon vollstaendig hier und nicht in der Ablage.

use core::fmt;

use ea_crypto::CryptoError;
use ea_key_provider::KeyError;
use ea_local_store::StoreError;
use ea_types::Id16;

/// Ein Fehlschlag an der Entwurfsgrenze.
///
/// Wie ueberall in diesem Bauwerk assertieren Tests gegen [`DraftError::code`]
/// und nie gegen eine Formatierung.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum DraftError {
    /// Die gelesene Fassung ist nicht mehr die gespeicherte.
    ///
    /// Es wurde NICHTS geschrieben. Der Aufrufer liest neu und speichert auf
    /// dem Gewinner weiter; alter Inhalt kehrt nicht zurueck.
    RevisionConflict,
    /// Diese Einsatznummer ist unter derselben Organisation und demselben
    /// oertlichen Kalenderjahr bereits verbraucht.
    IncidentNumberTaken,
    /// Es gibt keine Entwurfszeile, obwohl der Vorgang eine verlangt.
    NoDraft,
    /// Die ausschliessliche Entwurfssperre haelt bereits jemand.
    LockHeld,
    /// Der Uebergangszustand ist noch nicht anlegbar.
    ///
    /// `draft_transition` entsteht erst mit `0002_discard.sql`. Ein NAMENTLICHER
    /// Fehler statt eines rohen SQL-Fehlschlags: „die Tabelle gibt es noch
    /// nicht" ist eine andere Aussage als „die Datenbank ist beschaedigt", und
    /// nur die erste darf ein spaeterer Task auflloesen.
    TransitionUnavailable,
    /// Die entschluesselte Nutzlast hat nicht die Gestalt eines Entwurfs.
    Payload,
    /// Die lokale Zufallsquelle hat kein Material geliefert.
    LocalRng,
    /// Der Praesenznachweis ist veraltet oder durch eine Sperre entwertet.
    ///
    /// Verwerfen ist auf einem unbeaufsichtigt stehenden Geraet genauso
    /// unwiderruflich wie ein Abschluss (`design.md`:256, :432), also verlangt
    /// jeder Eingang eine FRISCHE Wiederanmeldung.
    ReauthRequired,
    /// Der Nachweis ist frisch, autorisiert aber einen ANDEREN Zweck.
    ///
    /// Eine Wiederanmeldung fuer den Abschluss eines Eintrags ist keine fuer
    /// das Verwerfen eines Entwurfs.
    ReauthPurposeMismatch,
    /// Eine vorbereitete Abschlussmarke liegt und hat Vorrang.
    ///
    /// Nach dem unwiderruflichen Schritt MUSS die Transaktion aus den
    /// vorbereiteten Bytes vollendet werden (`design.md`:456, :467); ein
    /// Verwerfen darf sie nicht ueberholen.
    PreparedFinalizationPresent,
    /// Es ist keine Verwerfensabsicht gebucht, die fortzusetzen waere.
    NoPendingDiscard,
    /// Der Schluesselspeicher meldet den `draftDEK` nach dem Loeschen weiterhin.
    ///
    /// Fail-closed: ein `Ok` von `delete` ist die Aussage des Providers ueber
    /// sich selbst, und die Zusage haengt an der ABWESENHEIT.
    KeyDeletionNotConfirmed,
    /// Ein Vorgang der Kryptografieschicht ist gescheitert.
    Crypto(CryptoError),
    /// Der Schluesselport hat abgelehnt.
    Key(KeyError),
    /// Die Ablage hat abgelehnt.
    Store(StoreError),
}

impl DraftError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RevisionConflict => "EA-DRAFT-REVISION-CONFLICT",
            Self::IncidentNumberTaken => "EA-DRAFT-INCIDENT-NUMBER-TAKEN",
            Self::NoDraft => "EA-DRAFT-NOT-FOUND",
            Self::LockHeld => "EA-DRAFT-LOCK-HELD",
            Self::TransitionUnavailable => "EA-DRAFT-TRANSITION-UNAVAILABLE",
            Self::Payload => "EA-DRAFT-PAYLOAD",
            Self::LocalRng => "EA-DRAFT-LOCAL-RNG",
            Self::ReauthRequired => "EA-DRAFT-REAUTH-REQUIRED",
            Self::ReauthPurposeMismatch => "EA-DRAFT-REAUTH-PURPOSE-MISMATCH",
            Self::PreparedFinalizationPresent => "EA-DRAFT-PREPARED-FINALIZATION-PRESENT",
            Self::NoPendingDiscard => "EA-DRAFT-NO-PENDING-DISCARD",
            Self::KeyDeletionNotConfirmed => "EA-DRAFT-KEY-DELETION-NOT-CONFIRMED",
            Self::Crypto(error) => error.code(),
            Self::Key(error) => error.code(),
            Self::Store(error) => error.code(),
        }
    }
}

impl fmt::Display for DraftError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for DraftError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for DraftError {}

impl From<CryptoError> for DraftError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<KeyError> for DraftError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<StoreError> for DraftError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Der gelesene Entwurf.
///
/// Er traegt die Fassung, gegen die er gelesen wurde. Genau daran entscheidet
/// [`crate::DraftRepository::save`], ob er noch der aktuelle ist.
#[derive(Clone, Eq, PartialEq)]
pub struct Draft {
    draft_id: Id16,
    revision: u64,
    notes: String,
}

impl Draft {
    pub(crate) const fn restored(draft_id: Id16, revision: u64, notes: String) -> Self {
        Self {
            draft_id,
            revision,
            notes,
        }
    }

    /// Die Kennung des Entwurfs — sechzehn CSPRNG-Bytes, kein neuer
    /// Bezeichnertyp.
    #[must_use]
    pub const fn draft_id(&self) -> Id16 {
        self.draft_id
    }

    /// Die Fassung, gegen die dieser Entwurf gelesen wurde.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn notes(&self) -> &str {
        &self.notes
    }

    /// Ersetzt den Text und laesst die gelesene Fassung unberuehrt.
    ///
    /// Die Fassung bleibt bewusst stehen: sie ist die Aussage „dieser Entwurf
    /// wurde gegen Fassung N gelesen", und ein Bearbeitungsschritt aendert
    /// daran nichts. Wuerde sie hier mitwandern, koennte eine zweite
    /// Autospeicherung den Vergleich-und-Setze-Schritt bestehen und den
    /// Gewinner ueberschreiben.
    #[must_use]
    pub fn with_notes(self, notes: impl Into<String>) -> Self {
        Self {
            notes: notes.into(),
            ..self
        }
    }
}

impl fmt::Debug for Draft {
    /// Undurchsichtig: ein Entwurfstext ist fachlicher Inhalt und gehoert nicht
    /// in eine Protokollzeile.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Draft(<sealed>)")
    }
}

/// Der Beleg einer durchgefuehrten Speicherung.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SavedDraft {
    draft_id: Id16,
    revision: u64,
}

impl SavedDraft {
    pub(crate) const fn new(draft_id: Id16, revision: u64) -> Self {
        Self { draft_id, revision }
    }

    #[must_use]
    pub const fn draft_id(&self) -> Id16 {
        self.draft_id
    }

    /// Die Fassung, die nach dieser Speicherung gilt.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

impl fmt::Debug for SavedDraft {
    /// Undurchsichtig wie [`Draft`]; der Rumpf existiert, damit
    /// `Result::unwrap_err` an diesem Typ ueberhaupt aufrufbar ist.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedDraft(<sealed>)")
    }
}

/// Die dauerhaft gebuchte Absicht, den Entwurf zu verwerfen.
///
/// Der Schritt, den Task 7 ueberschreitet: was danach passiert, ist eine
/// Fortsetzung und kein Neuanfang.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DiscardIntent {
    draft_id: Id16,
    revision: u64,
}

impl DiscardIntent {
    pub(crate) const fn new(draft_id: Id16, revision: u64) -> Self {
        Self { draft_id, revision }
    }

    #[must_use]
    pub const fn draft_id(&self) -> Id16 {
        self.draft_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Das Ergebnis eines abgeschlossenen Verwerfens.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DiscardOutcome {
    discarded: Id16,
    blank: SavedDraft,
}

impl DiscardOutcome {
    pub(crate) const fn new(discarded: Id16, blank: SavedDraft) -> Self {
        Self { discarded, blank }
    }

    /// Die Kennung des Entwurfs, dessen Chiffrat entfernt wurde.
    #[must_use]
    pub const fn discarded_draft_id(&self) -> Id16 {
        self.discarded
    }

    /// Der leere Entwurf, der an seine Stelle getreten ist.
    #[must_use]
    pub const fn blank(&self) -> SavedDraft {
        self.blank
    }
}

impl fmt::Debug for DiscardIntent {
    /// Undurchsichtig wie [`Draft`]: `Id16` traegt in diesem Bauwerk keine
    /// Formatierung, und ein Entwurfsbezeichner gehoert nicht in eine
    /// Protokollzeile.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiscardIntent(<committed>)")
    }
}

impl fmt::Debug for DiscardOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiscardOutcome(<done>)")
    }
}

/// Die vorbereitete Abschlussmarke — UNDURCHSICHTIG.
///
/// `ea-draft` erfaehrt nie, was ein vorbereiteter Abschluss enthaelt; damit
/// wird `ea-writer` niemals eine Abhaengigkeit der Speicherschicht.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedFinalizationMarker(Vec<u8>);

impl PreparedFinalizationMarker {
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PreparedFinalizationMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedFinalizationMarker(<opaque>)")
    }
}
