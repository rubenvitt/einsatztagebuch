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
    ChainId, ChainSequence, DeviceId, EntryHash, Hash32, KeyThumbprint, ObjectHash, OrganizationId,
    RegistryVersion, SubjectId, UnixMillis,
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
    /// `None` GENAU im Standardprofil.
    ///
    /// `design.md`:929 schreibt einem Standardprofil-Receipt
    /// `evidence-due-at = null` vor, und `design.md`:1699 haelt fest, dass ein
    /// solcher Receipt ohne getrennte Richtlinienaenderung KEINE
    /// Evidence-Grade-Konformitaet erzeugt. Eine hier hilfsweise gerechnete
    /// Zahl waere deshalb kein Ersatzwert, sondern ein Evidence-Auftrag, den
    /// es nicht geben darf — und eine zweite Quelle neben der EINEN, die
    /// `design.md`:1690 benennt: dem signierten `evidence-due-at` des
    /// Receipts.
    pub evidence_due_at: Option<UnixMillis>,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: ObjectHash,
    /// Der Objektindex des Commits: Entry, initiale Grants, Receipt UND
    /// Checkpoint. Die Fremdschluessel von `grants`, `receipts` und
    /// `checkpoints` zeigen alle darauf.
    pub indexed_objects: Vec<IndexedObjectV1>,
    /// Der Standard-Checkpoint, der GEMEINSAM mit dem Eintrag sichtbar wird.
    pub checkpoint: CheckpointCommitV1,
}

/// Der Datenbankteil eines Standard-Checkpoints.
///
/// Er reist IM Commit-Auftrag und nicht in einem eigenen, weil `design.md`
/// §15.2 den Checkpoint an die Annahme bindet: derselbe Kettenkopf, unter
/// derselben Sperre, in derselben Transaktion. Ein zweiter Auftrag danach
/// koennte ausfallen, und dann stuende ein angenommener Eintrag ohne seinen
/// Anker da.
///
/// `covered_sequence` ist der abgedeckte Sequenzbereich — von und bis fallen
/// im Standardprofil zusammen, weil ein Checkpoint GENAU EINEN Kopf-Eintrag
/// bindet und ueber keinen weiteren einen Nachweis fuehrt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CheckpointCommitV1 {
    pub object_hash: ObjectHash,
    pub covered_sequence: ChainSequence,
    pub issued_at_server: UnixMillis,
    /// Der Checkpoint, auf dem dieser aufsetzt — `None` genau fuer den ersten
    /// Checkpoint einer Kette. Die Transaktion stellt ihn gegen den
    /// tatsaechlichen Checkpoint-Kopf; weichen sie ab, gaebelte sich die
    /// Kette, und der Commit wird abgewiesen.
    pub previous_evidence_hash: Option<ObjectHash>,
}

impl fmt::Debug for CheckpointCommitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CheckpointCommitV1(covered={})",
            self.covered_sequence.get()
        )
    }
}

/// Ein Satz des Checkpoint-Index: Blaetterposition und Objekthash.
///
/// `technical_index` ist eine reine Zaehlgroesse — sie ist die Position, auf
/// die sich der `lastTechnicalIndex` eines technischen Cursors bezieht, und
/// traegt keine fachliche Bedeutung.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CheckpointIndexEntryV1 {
    pub technical_index: u64,
    pub object_hash: ObjectHash,
}

impl fmt::Debug for CheckpointIndexEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CheckpointIndexEntryV1(index={})",
            self.technical_index
        )
    }
}

/// Der aktuelle Kettenkopf, wie Schritt 5 ihn liest.
///
/// Er traegt die Annahmezeit MIT, weil `acceptedAtServer` das Maximum aus
/// Serverzeit und der Annahmezeit des direkten Vorgaengers ist. Ein Kopf ohne
/// diese Zahl beantwortete die Frage nicht, die Schritt 5 stellt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChainHeadStateV1 {
    pub sequence: ChainSequence,
    pub entry_hash: EntryHash,
    pub accepted_at_server: UnixMillis,
}

impl fmt::Debug for ChainHeadStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ChainHeadStateV1(sequence={})",
            self.sequence.get()
        )
    }
}

/// Was nach dem Commit sichtbar ist.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommittedDbState {
    pub sequence: ChainSequence,
    pub entry_hash: EntryHash,
    pub receipt_object_hash: ObjectHash,
    /// Der Checkpoint, der zu DIESEM Commit gehoert. Bei einem Replay ist es
    /// der GESPEICHERTE und nicht der eben gebildete — genau wie bei der
    /// Quittung.
    pub checkpoint_object_hash: ObjectHash,
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
    /// Der Standard-Checkpoint setzt auf einem ANDEREN Vorgaenger auf als dem
    /// Kopf der Checkpoint-Kette. Die Kette darf sich nicht gabeln: zwei
    /// Checkpoints ueber demselben Vorgaenger waeren zwei einander
    /// widersprechende Anker derselben Kette (`design.md` §15.2).
    CheckpointPredecessorConflict,
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
            Self::CheckpointPredecessorConflict => "checkpoint-predecessor-conflict",
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
    /// Der Standard-Checkpoint nennt einen anderen Vorgaenger als den Kopf der
    /// Checkpoint-Kette. Ein eigener Befund und KEIN Kopfkonflikt: der
    /// Kettenkopf kann unbewegt stehen, waehrend die Evidence-Kette sich
    /// gabelte.
    CheckpointPredecessorConflict,
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
            Self::CheckpointPredecessorConflict => "EA-DB-CHECKPOINT-PREDECESSOR",
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

/// Ein beantragtes, noch NICHT freigegebenes Geraet
/// (`design.md` §13.1, Proof of Possession).
///
/// Der Antrag traegt den beantragten Schluesselabdruck und den Hash der
/// exakten Antragsbytes — und sonst nichts. Er verleiht keine Autoritaet, und
/// es gibt in diesem Typ kein Feld, das eine verliehe.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingDeviceRequestV1 {
    pub organization_id: OrganizationId,
    pub device_id: DeviceId,
    pub requested_key_thumbprint: KeyThumbprint,
    /// SHA-256 ueber die exakten `device-registration-request-v1`-Bytes.
    pub request_object_hash: Hash32,
    pub received_at: UnixMillis,
}

impl fmt::Debug for PendingDeviceRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingDeviceRequestV1(<bound>)")
    }
}

/// Der EINZIGE Zustand, den ein Registrierungsantrag dieser Stufe annimmt.
///
/// Er steht als Konstante und nicht als Aufzaehlung, weil es genau einen gibt:
/// die Freigabe entsteht spaeter aus einem Root-signierten Trust-Objekt und
/// nicht aus einem Zustandswechsel in dieser Tabelle.
pub const PENDING_REGISTRATION_STATE_V1: &str = "pending";

/// Wie die Ablage auf einen Antrag antwortet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingRegistrationOutcome {
    /// Neu aufgenommen.
    Recorded,
    /// Byteweise DERSELBE Antrag lag schon vor — der zulaessige idempotente
    /// Wiederholungsfall.
    AlreadyPending,
    /// Fuer dieses Geraet liegt ein ANDERER Antrag vor. Kein Replay, sondern
    /// ein Widerspruch, und er wird nicht repariert.
    Conflict,
}

/// Ein registriertes WebAuthn-Credential (`web-reader-design.md` §6.4.1).
///
/// `subject_id` IST der `userHandle`. Es gibt hier keinen Anzeigenamen, keine
/// Kennung eines Menschen und keinen fachlichen Wert.
#[derive(Clone, Eq, PartialEq)]
pub struct WebauthnCredentialV1 {
    pub organization_id: OrganizationId,
    pub subject_id: SubjectId,
    pub credential_id: Vec<u8>,
    pub credential_public_cose_key: Vec<u8>,
    pub registered_at: UnixMillis,
}

impl fmt::Debug for WebauthnCredentialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebauthnCredentialV1(<bound>)")
    }
}

/// Wie die Credentialtabelle auf eine Registrierung antwortet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRegistrationOutcome {
    Registered,
    /// Genau dasselbe Credential fuer genau dieselbe `subjectId`.
    AlreadyRegistered,
    /// Diese `credentialId` gehoert in dieser Organisation bereits einer
    /// ANDEREN `subjectId`.
    Conflict,
}

/// Ein geprueftes `.etb`, wie es in den Index geht.
///
/// `registry_version` ist `Some` GENAU fuer ein `registryEvent`. Nur diese
/// Objektart traegt eine Registry-Version, und nur sie steht deshalb auf der
/// Registry-Linie von `GET /v1/trust/registry`: die Antwort verlangt streng
/// aufsteigende, duplikatfreie Versionen (`trust-registry-response-v1`), also
/// kann dort kein zweites Objekt unter derselben Version stehen.
#[derive(Clone, Eq, PartialEq)]
pub struct TrustEventCommandV1 {
    pub organization_id: OrganizationId,
    pub object_hash: ObjectHash,
    pub size_bytes: u64,
    pub subtype_code: String,
    pub registry_version: Option<RegistryVersion>,
    pub effective_from: UnixMillis,
    pub received_at: UnixMillis,
}

impl fmt::Debug for TrustEventCommandV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "TrustEventCommandV1({})",
            object_key(ObjectTypeV1::Trust, self.object_hash)
        )
    }
}

/// Wie der Index auf ein Trust-Ereignis antwortet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustIndexOutcome {
    Indexed,
    /// Byteweise dasselbe Objekt lag schon indiziert vor.
    AlreadyIndexed,
    /// Dieselbe Registry-Version traegt bereits ein ANDERES Objekt.
    Conflict,
}

/// Ein Satz der Registry-Linie.
///
/// Er traegt die Version und den Objekthash — NICHT die Bytes. Die exakten
/// Bytes kommen aus dem Object Store, damit die Leseantwort das archivierte
/// Objekt ausliefert und keine aus Zeilen zusammengesetzte Fassung davon.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RegistryLineEntryV1 {
    pub registry_version: RegistryVersion,
    pub object_hash: ObjectHash,
}

impl fmt::Debug for RegistryLineEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "RegistryLineEntryV1(version={})",
            self.registry_version.get()
        )
    }
}
