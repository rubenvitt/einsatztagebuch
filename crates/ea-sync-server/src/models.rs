//! Die TECHNISCHEN Modelle der Serverpersistenz.
//!
//! Jeder Typ dieses Moduls traegt ausschliesslich Hashes, Kennungen, Groessen
//! und Zeitpunkte. Es gibt hier keinen Einsatzwert — keine Einsatznummer, keine
//! Einsatzzeit, kein Stichwort, keinen Ort, keine Person, kein Fahrzeug, keinen
//! Patienten und keine Notiz —, weil der Server nach `design.md` §13.4 blind
//! bleibt und weil ein solcher Wert ueber Objektschluessel, Tags, Protokoll oder
//! Fehlertext sonst wieder herausliefe.

use core::fmt;

use ea_format::ObjectTypeV1;
use ea_types::{
    ChainId, ChainSequence, DeviceId, EntryHash, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};

/// Das Namensraumsegment einer Objektart im Object Store.
///
/// Es sind die Dateinamensendungen des Exact-Object-Praefixes aus `ea-format`
/// und damit KEINE zweite Aufzaehlung: die geschlossene Menge bleibt
/// [`ObjectTypeV1`], diese Funktion gibt ihr nur ihren Schluesselnamen.
#[must_use]
pub const fn object_type_segment(kind: ObjectTypeV1) -> &'static str {
    match kind {
        ObjectTypeV1::Entry => "eip",
        ObjectTypeV1::Grant => "eag",
        ObjectTypeV1::Receipt => "esr",
        ObjectTypeV1::Evidence => "ecp",
        ObjectTypeV1::Trust => "etb",
        ObjectTypeV1::Destroyed => "eds",
    }
}

/// Der EINZIGE Objektschluessel dieses Systems: `<type>/<hex objectHash>`.
///
/// `design.md` §13.4 laesst nichts anderes zu, und der Global Constraint ueber
/// Objektschluessel reserviert diesen Namensraum fuer Archivobjektarten. Der
/// Wrapped-Blob eines Readers liegt deshalb ausdruecklich NICHT hier, sondern
/// in einer eigenen Tabelle (`web-reader-design.md` §6.4).
#[must_use]
pub fn object_key(kind: ObjectTypeV1, hash: ObjectHash) -> String {
    format!(
        "{}/{}",
        object_type_segment(kind),
        hex::encode(hash.as_bytes())
    )
}

/// Ein gestromtes, gehashtes, noch NICHT dauerhaft abgelegtes Objekt.
///
/// Es liegt unter einem temporaeren Schluessel (`design.md` §13.3, Schritt 1)
/// und wird erst von [`crate::ObjectStore::put_if_absent`] content-addressed
/// uebernommen. Der Typ ist bewusst undurchsichtig: seinen Hash setzt
/// ausschliesslich der Object Store, der die Bytes selbst gerechnet hat.
#[derive(Clone, Eq, PartialEq)]
pub struct StagedObject {
    kind: ObjectTypeV1,
    object_hash: ObjectHash,
    size_bytes: u64,
    staging_key: String,
}

impl StagedObject {
    /// Nur der Object-Store-Adapter ruft das auf — er hat gerade gehasht.
    #[must_use]
    pub const fn new(
        kind: ObjectTypeV1,
        object_hash: ObjectHash,
        size_bytes: u64,
        staging_key: String,
    ) -> Self {
        Self {
            kind,
            object_hash,
            size_bytes,
            staging_key,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ObjectTypeV1 {
        self.kind
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub fn staging_key(&self) -> &str {
        &self.staging_key
    }

    /// Der endgueltige content-addressed Schluessel dieses Objekts.
    #[must_use]
    pub fn object_key(&self) -> String {
        object_key(self.kind, self.object_hash)
    }
}

/// Ein dauerhaft content-addressed abgelegtes Objekt.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredObject {
    kind: ObjectTypeV1,
    object_hash: ObjectHash,
    size_bytes: u64,
    newly_stored: bool,
}

impl StoredObject {
    #[must_use]
    pub const fn new(
        kind: ObjectTypeV1,
        object_hash: ObjectHash,
        size_bytes: u64,
        newly_stored: bool,
    ) -> Self {
        Self {
            kind,
            object_hash,
            size_bytes,
            newly_stored,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ObjectTypeV1 {
        self.kind
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// `false` heisst: die Bytes lagen schon byteweise identisch da. Das ist
    /// der zulaessige idempotente Wiederholungsfall, KEIN Konflikt.
    #[must_use]
    pub const fn newly_stored(&self) -> bool {
        self.newly_stored
    }
}

/// `Debug` von Hand, weil die Kennungen aus `ea-types` bewusst KEIN `Debug`
/// tragen. Gezeigt wird genau der Objektschluessel — er ist die technische
/// Adresse dieses Objekts und traegt nach `design.md` §13.4 ohnehin nichts
/// anderes.
impl fmt::Debug for StagedObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "StagedObject({}, {} bytes)",
            self.object_key(),
            self.size_bytes
        )
    }
}

impl fmt::Debug for StoredObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "StoredObject({}, {} bytes, newly_stored={})",
            object_key(self.kind, self.object_hash),
            self.size_bytes,
            self.newly_stored
        )
    }
}

/// Ein Eintrag des technischen Objektindex.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IndexedObjectV1 {
    pub kind: ObjectTypeV1,
    pub object_hash: ObjectHash,
    pub size_bytes: u64,
}

/// Die Commit-Identitaet nach `design.md` §13.3.
///
/// Nur DIESE vier Bestandteile machen aus einem zweiten Commit denselben
/// Commit; jede Abweichung ist ein Security Event und wird nicht repariert.
#[derive(Clone, Eq, PartialEq)]
pub struct CommitIdentityV1 {
    pub entry_hash: EntryHash,
    pub entry_object_hash: ObjectHash,
    pub initial_grant_plan_hash: Hash32,
    /// Aufsteigend sortiert — die Sortierung gehoert zur Identitaet.
    pub initial_grant_object_hashes: Vec<ObjectHash>,
}

/// Der Datenbankteil eines Entry-Commits (`design.md` §13.3, Schritte 4 bis 8).
///
/// Der Auftrag enthaelt bereits ALLES, was gemeinsam sichtbar geschaltet wird;
/// die Pruefung der Schritte 2 und 3 ist vorher passiert.
#[derive(Clone, Eq, PartialEq)]
pub struct CommitDbCommand {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub device_id: DeviceId,
    pub sequence: ChainSequence,
    /// `None` genau fuer die erste Sequenz einer Kette.
    pub previous_entry_hash: Option<EntryHash>,
    pub identity: CommitIdentityV1,
    pub receipt_object_hash: ObjectHash,
    pub accepted_at_server: UnixMillis,
    pub evidence_due_at: UnixMillis,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: ObjectHash,
    /// Der Objektindex des Commits: Entry, initiale Grants und Receipt.
    pub indexed_objects: Vec<IndexedObjectV1>,
}

/// Was nach dem Commit sichtbar ist.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommittedDbState {
    pub sequence: ChainSequence,
    pub entry_hash: EntryHash,
    pub receipt_object_hash: ObjectHash,
    pub accepted_at_server: UnixMillis,
    /// `false` heisst: derselbe Commit lag schon vor und wird unveraendert
    /// wieder ausgeliefert.
    pub newly_committed: bool,
}

impl fmt::Debug for CommittedDbState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CommittedDbState(sequence={}, newly_committed={})",
            self.sequence.get(),
            self.newly_committed
        )
    }
}

/// Die geschlossene Menge der Security Events dieser Stufe.
///
/// Sie folgt Wort fuer Wort `design.md` §13.3: der Schluessel mit anderen Bytes
/// aus Schritt 3 sowie die vier Faelle des Absatzes ueber die Commit-Identitaet.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SecurityEventKindV1 {
    /// Gleicher Objektschluessel, andere Bytes.
    ObjectHashConflict,
    /// Derselbe `entryHash` mit anderen Objektbytes oder Grants.
    EntryIdentityMismatch,
    /// Gleiche Sequenz mit anderem `entryHash`.
    SequenceFork,
    /// Falscher Vorgaenger.
    PredecessorMismatch,
    /// Unzulaessiger Writer.
    WriterUnauthorized,
}

impl SecurityEventKindV1 {
    /// Der stabile technische Code, wie er in der Tabelle steht.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ObjectHashConflict => "object-hash-conflict",
            Self::EntryIdentityMismatch => "entry-identity-mismatch",
            Self::SequenceFork => "sequence-fork",
            Self::PredecessorMismatch => "predecessor-mismatch",
            Self::WriterUnauthorized => "writer-unauthorized",
        }
    }
}

/// Ein aufgezeichnetes Security Event.
///
/// `subject` traegt AUSSCHLIESSLICH die technische Kennung, um die es geht —
/// einen Objektschluessel, einen Hash oder eine Sequenz. Eine freie
/// Beschreibung gibt es bewusst nicht: sie waere der Kanal, ueber den ein
/// fachlicher Wert doch noch in die Datenbank kaeme.
#[derive(Clone, Eq, PartialEq)]
pub struct SecurityEventV1 {
    pub organization_id: OrganizationId,
    pub kind: SecurityEventKindV1,
    pub subject: String,
    pub observed_at: UnixMillis,
}

/// Die Befunde des Object Stores.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// Gleicher content-addressed Schluessel, ANDERE Bytes. Ein Security Event
    /// nach `design.md` §13.3, Schritt 3, und niemals ein Replay.
    HashConflict,
    /// Der Koerper hat die uebergebene Grenze ueberschritten. Der Strom wird
    /// dabei NICHT bis zum Ende gelesen.
    LimitExceeded,
    /// Die ersten Bytes tragen nicht das Exact-Object-Praefix der angegebenen
    /// Art. Ohne diese Pruefung landete ein `.eip` im `etb/`-Namensraum.
    ObjectTypeMismatch,
    /// Unter diesem Hash liegt nichts.
    NotFound,
    /// Der Object Store antwortet nicht oder antwortet unbrauchbar.
    Unavailable,
}

impl StoreError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::HashConflict => "EA-STORE-HASH-CONFLICT",
            Self::LimitExceeded => "EA-STORE-LIMIT",
            Self::ObjectTypeMismatch => "EA-STORE-OBJECT-TYPE",
            Self::NotFound => "EA-STORE-NOT-FOUND",
            Self::Unavailable => "EA-STORE-UNAVAILABLE",
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for StoreError {}

/// Die Befunde der Datenbankseite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    /// Der Kettenkopf hat sich unter der Sperre bewegt; der Aufrufer liest neu.
    HeadConflict,
    /// Dieselbe Sequenz traegt bereits einen anderen `entryHash`, oder derselbe
    /// `entryHash` traegt eine andere Commit-Identitaet.
    CommitIdentityConflict,
    /// Die Request-ID war schon einmal da (`design.md` §13.1).
    RequestIdReplay,
    /// Die Datenbank antwortet nicht.
    Unavailable,
}

impl RepositoryError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::HeadConflict => "EA-DB-HEAD-CONFLICT",
            Self::CommitIdentityConflict => "EA-DB-COMMIT-IDENTITY-CONFLICT",
            Self::RequestIdReplay => "EA-DB-REQUEST-ID-REPLAY",
            Self::Unavailable => "EA-DB-UNAVAILABLE",
        }
    }
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for RepositoryError {}
