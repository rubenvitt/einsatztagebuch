//! `VerificationReportV1` — der Bericht als reiner Rust-Wert.
//!
//! Der Wert traegt genau die siebzehn Pflichtfelder von
//! `schemas/reports/v1/verification-report.schema.json` und die beiden
//! optionalen `reportSignature`/`runtimeMetadata`, die in Phase B IMMER
//! abwesend sind. Es gibt keinen oeffentlichen Rohkonstruktor: ein Bericht
//! entsteht ausschliesslich aus einem Lauf ueber einen Bestand.
//!
//! SORTIERUNG UND EINDEUTIGKEIT sind an die Behaeltertypen delegiert, nicht an
//! den Schreiber: jede Sammlung liegt in einer `BTreeMap`/`BTreeSet` ueber
//! genau dem `x-ea-unique-key` ihres Schemas, und die `Ord`-Ableitungen von
//! `ea-types` sind bytewise beziehungsweise numerisch aufsteigend — also
//! wortwoertlich die `x-ea-sort-key` des Schemas. In dieser Crate kommt
//! deshalb weder `HashMap` noch `HashSet` vor.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use ea_archive::QuarantineReason;
use ea_chain::RollbackAssessment;
use ea_crypto::verification_report_hash;
// `ObjectTypeV1` wird NICHT hier deklariert: die geschlossene Menge 1..6 steht
// neben den Exact-Object-Praefixen in `crates/ea-format/src/parser.rs`.
use ea_format::ObjectTypeV1;
use ea_types::{
    ChainId, ChainSequence, DestructionId, EntryHash, Hash32, KeyThumbprint, ObjectHash,
    RegistryVersion,
};

use crate::{
    VerifyError,
    json::{SCHEMA_ID_V1, TokenClass, array, hex_string, object, quoted, uint},
};

/// Schreibt 32 beziehungsweise 16 Hashbytes als Kleinbuchstaben-Hex.
///
/// `ea-types` leitet fuer Kennungs- und Hashtypen kein `Debug` ab; die
/// Debug-Ausgaben dieses Moduls sind deshalb von Hand geschrieben, genau wie in
/// `ea-chain` und `ea-archive`.
fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// Der Ausgang der Pruefung eines Objekts.
///
/// Geschlossen auf die beiden Schemaliterale `valid` und
/// `authorizedDestroyed`. Ein Objekt, das keines von beiden ist, erscheint
/// NICHT in `objectResults`, sondern in genau einem Fehler- oder
/// Quarantaenearray — nie in beidem.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObjectResultKindV1 {
    /// Vollstaendig geprueft.
    Valid,
    /// Autorisiert vernichtet; die Kettenidentitaet bleibt erhalten.
    AuthorizedDestroyed,
}

impl ObjectResultKindV1 {
    /// Das Schemaliteral.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::AuthorizedDestroyed => "authorizedDestroyed",
        }
    }
}

/// Ob eine Serverquittung fuer das Objekt vorliegt.
///
/// EIGENE DIMENSION neben [`ObjectResultKindV1`], nie hineingefaltet:
/// `design.md` §17.4 verbietet die Vermischung, und `notServerConfirmed` ist
/// KEIN Mangel (`design.md`:1608) — es senkt
/// [`VerificationReportV1::is_fully_verified`] nicht.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServerConfirmationV1 {
    /// Eine gueltige Serverquittung liegt vor.
    ServerConfirmed,
    /// Es liegt keine vor. Kein Mangel.
    NotServerConfirmed,
}

impl ServerConfirmationV1 {
    /// Das Schemaliteral.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerConfirmed => "serverConfirmed",
            Self::NotServerConfirmed => "notServerConfirmed",
        }
    }

    /// Die woertliche Oberflaechenkopie aus `design.md` §17.4.
    ///
    /// `nicht server-bestätigt` ist KEIN Mangel und DARF NICHT als `Lücke`
    /// oder `ungültig` dargestellt werden; im Datei-Modus des Web-Readers ist
    /// es der Regelfall.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ServerConfirmed => "server-bestätigt",
            Self::NotServerConfirmed => "nicht server-bestätigt",
        }
    }
}

/// Der Stand eines Vernichtungsvorgangs.
///
/// Die geschlossene Menge aus `authorizedDestruction.state`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DestructionStateV1 {
    /// Beantragt.
    Requested,
    /// In Ausfuehrung.
    InProgress,
    /// Wartet auf den Ablauf von Sicherungen.
    PendingBackupExpiry,
    /// Im verwalteten Bereich vollstaendig.
    CompleteManagedScope,
    /// Unvollstaendig, weil eine Replik nicht erreichbar war.
    IncompleteUnreachableReplica,
}

impl DestructionStateV1 {
    /// Das Schemaliteral.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::InProgress => "inProgress",
            Self::PendingBackupExpiry => "pendingBackupExpiry",
            Self::CompleteManagedScope => "completeManagedScope",
            Self::IncompleteUnreachableReplica => "incompleteUnreachableReplica",
        }
    }
}

/// Der Kopf der Kette, wie der Bericht ihn ausweist.
///
/// PFLICHTFELD UND NICHT NULLBAR. Zwei Saetze gelten normativ:
///
/// 1. `chain_id` ist IMMER `anchor.chain_id()` und kommt NIE aus dem Bestand.
///    Damit kann kein untergeschobenes Objekt die Kettenidentitaet des Berichts
///    bestimmen.
/// 2. Existiert kein verifizierter Kopf, gilt das Sentinel aus
///    [`ChainHeadV1::sentinel`]: `sequence = 0` und ein `entry_hash` aus
///    64 Nullen. `anchor.genesis_entry_hash()` wird dort ausdruecklich NICHT
///    eingesetzt, weil es einen verifizierten Genesis-Eintrag behaupten wuerde,
///    den es nicht gibt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChainHeadV1 {
    chain_id: ChainId,
    sequence: ChainSequence,
    entry_hash: EntryHash,
}

impl ChainHeadV1 {
    /// Ein verifizierter Kopf.
    #[must_use]
    pub const fn new(chain_id: ChainId, sequence: ChainSequence, entry_hash: EntryHash) -> Self {
        Self {
            chain_id,
            sequence,
            entry_hash,
        }
    }

    /// Der Kopf eines Bestands OHNE rekonstruierte Kette.
    ///
    /// Sequenz 0 und 64 Nullen — siehe die zweite Regel am Typ.
    #[must_use]
    pub fn sentinel(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            sequence: ChainSequence::new(0),
            entry_hash: EntryHash::from(Hash32::ZERO),
        }
    }

    /// Die Kettenkennung aus dem Trust Anchor.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Die Sequenz des verifizierten Kopfes, oder 0 als Sentinel.
    #[must_use]
    pub const fn sequence(&self) -> ChainSequence {
        self.sequence
    }

    /// Der Eintragshash des verifizierten Kopfes, oder 32 Nullbytes.
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    fn to_json(self, depth: usize) -> Result<String, VerifyError> {
        object(
            depth,
            &[
                ("chainId", hex_string(self.chain_id.as_bytes())?),
                ("sequence", uint(self.sequence.get())),
                ("entryHash", hex_string(self.entry_hash.as_bytes())?),
            ],
        )
    }
}

impl fmt::Debug for ChainHeadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChainHeadV1 { chain_id: ")?;
        write_hex(formatter, self.chain_id.as_bytes())?;
        write!(
            formatter,
            ", sequence: {}, entry_hash: ",
            self.sequence.get()
        )?;
        write_hex(formatter, self.entry_hash.as_bytes())?;
        formatter.write_str(" }")
    }
}

/// Das Ergebnis fuer ein einzelnes Objekt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ObjectResultV1 {
    object_hash: ObjectHash,
    object_type: ObjectTypeV1,
    result: ObjectResultKindV1,
    server_confirmation: ServerConfirmationV1,
}

impl ObjectResultV1 {
    #[must_use]
    pub const fn new(
        object_hash: ObjectHash,
        object_type: ObjectTypeV1,
        result: ObjectResultKindV1,
        server_confirmation: ServerConfirmationV1,
    ) -> Self {
        Self {
            object_hash,
            object_type,
            result,
            server_confirmation,
        }
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn object_type(&self) -> ObjectTypeV1 {
        self.object_type
    }

    #[must_use]
    pub const fn result(&self) -> ObjectResultKindV1 {
        self.result
    }

    #[must_use]
    pub const fn server_confirmation(&self) -> ServerConfirmationV1 {
        self.server_confirmation
    }

    fn to_json(self, depth: usize) -> Result<String, VerifyError> {
        object(
            depth,
            &[
                ("objectHash", hex_string(self.object_hash.as_bytes())?),
                ("objectType", uint(self.object_type.code())),
                (
                    "result",
                    quoted(self.result.as_str(), TokenClass::Identifier)?,
                ),
                (
                    "serverConfirmation",
                    quoted(self.server_confirmation.as_str(), TokenClass::Identifier)?,
                ),
            ],
        )
    }
}

impl fmt::Debug for ObjectResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectResultV1 { object_hash: ")?;
        write_hex(formatter, self.object_hash.as_bytes())?;
        write!(
            formatter,
            ", object_type: {}, result: {}, server_confirmation: {} }}",
            self.object_type.code(),
            self.result.as_str(),
            self.server_confirmation.as_str()
        )
    }
}

/// Ein Vernichtungsvorgang mitsamt seiner Autorisierung.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthorizedDestructionV1 {
    destruction_id: DestructionId,
    authorization_object_hash: ObjectHash,
    state: DestructionStateV1,
}

impl AuthorizedDestructionV1 {
    #[must_use]
    pub const fn new(
        destruction_id: DestructionId,
        authorization_object_hash: ObjectHash,
        state: DestructionStateV1,
    ) -> Self {
        Self {
            destruction_id,
            authorization_object_hash,
            state,
        }
    }

    #[must_use]
    pub const fn destruction_id(&self) -> DestructionId {
        self.destruction_id
    }

    #[must_use]
    pub const fn authorization_object_hash(&self) -> ObjectHash {
        self.authorization_object_hash
    }

    #[must_use]
    pub const fn state(&self) -> DestructionStateV1 {
        self.state
    }

    fn to_json(self, depth: usize) -> Result<String, VerifyError> {
        object(
            depth,
            &[
                ("destructionId", hex_string(self.destruction_id.as_bytes())?),
                (
                    "authorizationObjectHash",
                    hex_string(self.authorization_object_hash.as_bytes())?,
                ),
                (
                    "state",
                    quoted(self.state.as_str(), TokenClass::Identifier)?,
                ),
            ],
        )
    }
}

impl fmt::Debug for AuthorizedDestructionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedDestructionV1 { destruction_id: ")?;
        write_hex(formatter, self.destruction_id.as_bytes())?;
        formatter.write_str(", authorization_object_hash: ")?;
        write_hex(formatter, self.authorization_object_hash.as_bytes())?;
        write!(formatter, ", state: {} }}", self.state.as_str())
    }
}

/// Eine Luecke in der Kette, als geschlossenes Intervall.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChainGapV1 {
    chain_id: ChainId,
    from_sequence: ChainSequence,
    through_sequence: ChainSequence,
}

impl ChainGapV1 {
    #[must_use]
    pub const fn new(
        chain_id: ChainId,
        from_sequence: ChainSequence,
        through_sequence: ChainSequence,
    ) -> Self {
        Self {
            chain_id,
            from_sequence,
            through_sequence,
        }
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn from_sequence(&self) -> ChainSequence {
        self.from_sequence
    }

    #[must_use]
    pub const fn through_sequence(&self) -> ChainSequence {
        self.through_sequence
    }

    fn to_json(self, depth: usize) -> Result<String, VerifyError> {
        object(
            depth,
            &[
                ("chainId", hex_string(self.chain_id.as_bytes())?),
                ("fromSequence", uint(self.from_sequence.get())),
                ("throughSequence", uint(self.through_sequence.get())),
            ],
        )
    }
}

impl fmt::Debug for ChainGapV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChainGapV1 { chain_id: ")?;
        write_hex(formatter, self.chain_id.as_bytes())?;
        write!(
            formatter,
            ", from_sequence: {}, through_sequence: {} }}",
            self.from_sequence.get(),
            self.through_sequence.get()
        )
    }
}

/// Ein Objektbefund mit stabilem Fehlercode.
///
/// Traegt `formatErrors` ebenso wie `signatureErrors`, `evidenceErrors` und
/// `decryptionErrors`: alle vier haben im Schema dieselbe Gestalt. Die
/// Ableitungsreihenfolge von `Ord` ist `object_hash`, dann `code` — wortwoertlich
/// der `x-ea-sort-key` von `sortedErrors`, und da beide Felder zusammen der
/// `x-ea-unique-key` sind, dedupliziert eine `BTreeSet` genau richtig.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObjectErrorV1 {
    object_hash: ObjectHash,
    code: &'static str,
}

impl ObjectErrorV1 {
    /// `code` MUSS ein stabiler `EA-`-Code sein; der Schreiber weist alles
    /// andere mit [`VerifyError::NonCanonicalReport`] ab.
    #[must_use]
    pub const fn new(object_hash: ObjectHash, code: &'static str) -> Self {
        Self { object_hash, code }
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    fn to_json(self, depth: usize) -> Result<String, VerifyError> {
        object(
            depth,
            &[
                ("objectHash", hex_string(self.object_hash.as_bytes())?),
                ("code", quoted(self.code, TokenClass::ErrorCode)?),
            ],
        )
    }
}

impl fmt::Debug for ObjectErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectErrorV1 { object_hash: ")?;
        write_hex(formatter, self.object_hash.as_bytes())?;
        write!(formatter, ", code: {} }}", self.code)
    }
}

/// Ein isoliertes Objekt mitsamt seinem Grund.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct QuarantinedObjectV1 {
    object_hash: ObjectHash,
    reason: QuarantineReason,
}

impl QuarantinedObjectV1 {
    #[must_use]
    pub const fn new(object_hash: ObjectHash, reason: QuarantineReason) -> Self {
        Self {
            object_hash,
            reason,
        }
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn reason(&self) -> QuarantineReason {
        self.reason
    }

    fn to_json(self, depth: usize) -> Result<String, VerifyError> {
        object(
            depth,
            &[
                ("objectHash", hex_string(self.object_hash.as_bytes())?),
                (
                    "reason",
                    quoted(self.reason.as_str(), TokenClass::Identifier)?,
                ),
            ],
        )
    }
}

impl fmt::Debug for QuarantinedObjectV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QuarantinedObjectV1 { object_hash: ")?;
        write_hex(formatter, self.object_hash.as_bytes())?;
        write!(formatter, ", reason: {} }}", self.reason.as_str())
    }
}

/// Der Verifikationsbericht als reiner Rust-Wert.
///
/// Kein oeffentlicher Rohkonstruktor: der Wert entsteht ausschliesslich in
/// dieser Crate aus einem Lauf ueber einen Bestand
/// ([`crate::verify_archive`]).
pub struct VerificationReportV1 {
    pub(crate) archive_object_count: usize,
    pub(crate) entry_package_count: usize,
    pub(crate) destroyed_entry_count: usize,
    pub(crate) chain_head: ChainHeadV1,
    pub(crate) registry_versions: BTreeSet<RegistryVersion>,
    pub(crate) object_results: BTreeMap<ObjectHash, ObjectResultV1>,
    pub(crate) authorized_destructions: BTreeMap<DestructionId, AuthorizedDestructionV1>,
    pub(crate) gaps: BTreeMap<(ChainId, ChainSequence), ChainGapV1>,
    pub(crate) format_errors: BTreeMap<ObjectHash, ObjectErrorV1>,
    pub(crate) quarantined_objects: BTreeMap<ObjectHash, QuarantinedObjectV1>,
    pub(crate) non_object_file_count: usize,
    pub(crate) signature_errors: BTreeSet<ObjectErrorV1>,
    pub(crate) evidence_errors: BTreeSet<ObjectErrorV1>,
    pub(crate) decryption_errors: BTreeSet<ObjectErrorV1>,
    pub(crate) public_key_thumbprints: BTreeSet<KeyThumbprint>,
    /// Das Ergebnis der Rollback-Pruefung aus Gate `receipt`.
    ///
    /// KEIN Berichtsfeld: das Schema ist `additionalProperties: false` und
    /// durch Phase A geschlossen. Der Wert wirkt allein ueber
    /// [`VerificationReportV1::rollback_assessment`]; seine Befunde sind
    /// daneben bereits in `gaps` und `quarantinedObjects` abgebildet.
    pub(crate) rollback: RollbackAssessment,
    report_hash: Hash32,
    /// Lief die vollstaendige Pipeline?
    ///
    /// Gesetzt ausschliesslich am ENDE von [`crate::verify_archive`], nachdem
    /// alle neun Gates und die Entkapselung dahinter gelaufen sind. Ein Lauf,
    /// der an Gate `trust` fail-closed endet, laesst den Wert falsch.
    ///
    /// KEIN Berichtsfeld: das Schema ist `additionalProperties: false`. Der
    /// Wert wirkt allein ueber [`VerificationReportV1::is_fully_verified`].
    pub(crate) pipeline_completed: bool,
}

impl VerificationReportV1 {
    /// Ein leerer Bericht ueber `chain_head`, noch ohne `reportHash`.
    ///
    /// `pub(crate)`: der Bericht bleibt von aussen nur lesbar.
    pub(crate) fn empty(chain_head: ChainHeadV1) -> Self {
        Self {
            archive_object_count: 0,
            entry_package_count: 0,
            destroyed_entry_count: 0,
            chain_head,
            registry_versions: BTreeSet::new(),
            object_results: BTreeMap::new(),
            authorized_destructions: BTreeMap::new(),
            gaps: BTreeMap::new(),
            format_errors: BTreeMap::new(),
            quarantined_objects: BTreeMap::new(),
            non_object_file_count: 0,
            signature_errors: BTreeSet::new(),
            evidence_errors: BTreeSet::new(),
            decryption_errors: BTreeSet::new(),
            public_key_thumbprints: BTreeSet::new(),
            rollback: RollbackAssessment::NotAssessable,
            report_hash: Hash32::ZERO,
            pipeline_completed: false,
        }
    }

    /// Berechnet `reportHash` ueber das Urbild und schliesst den Bericht ab.
    ///
    /// Muss der LETZTE Schritt sein: jede spaetere Aenderung eines Feldes
    /// entwertete den Hash.
    pub(crate) fn seal(mut self) -> Result<Self, VerifyError> {
        let preimage = self.write_document(false)?;
        self.report_hash = verification_report_hash(preimage.as_bytes());
        Ok(self)
    }

    /// Bytesequenzen MIT Exact-Object-Praefix, jede einzeln.
    ///
    /// Unabhaengig von Parse-Erfolg und Duplikat. Invariante:
    /// `archive_object_count() + non_object_file_count()` ist die Zahl aller
    /// vom Bestand gelieferten Bytesequenzen.
    #[must_use]
    pub const fn archive_object_count(&self) -> usize {
        self.archive_object_count
    }

    /// Erfolgreich als Typ 1 geparste, nach `objectHash` eindeutige Objekte.
    ///
    /// Unabhaengig vom Gate-Ausgang.
    #[must_use]
    pub const fn entry_package_count(&self) -> usize {
        self.entry_package_count
    }

    /// Erfolgreich als Typ 6 geparste, nach `objectHash` eindeutige Objekte.
    #[must_use]
    pub const fn destroyed_entry_count(&self) -> usize {
        self.destroyed_entry_count
    }

    /// Bytesequenzen OHNE Exact-Object-Praefix.
    #[must_use]
    pub const fn non_object_file_count(&self) -> usize {
        self.non_object_file_count
    }

    /// Der Kettenkopf. Pflichtfeld, nie nullbar — siehe [`ChainHeadV1`].
    #[must_use]
    pub const fn chain_head(&self) -> ChainHeadV1 {
        self.chain_head
    }

    /// Die `registry_version`-Werte der Objekte, die Gate `manifest-signature`
    /// BESTANDEN haben, numerisch aufsteigend.
    ///
    /// Aus unauthentischen Bytes stammen nur Zaehler und Fehlereintraege,
    /// niemals Sachaussagen — deshalb speist sich dieses Feld ausschliesslich
    /// aus geprueften Manifesten.
    pub fn registry_versions(&self) -> impl ExactSizeIterator<Item = RegistryVersion> + '_ {
        self.registry_versions.iter().copied()
    }

    /// Die Objektergebnisse, aufsteigend nach `objectHash`.
    pub fn object_results(&self) -> impl ExactSizeIterator<Item = &ObjectResultV1> + '_ {
        self.object_results.values()
    }

    /// Die Vernichtungsvorgaenge, aufsteigend nach `destructionId`.
    pub fn authorized_destructions(
        &self,
    ) -> impl ExactSizeIterator<Item = &AuthorizedDestructionV1> + '_ {
        self.authorized_destructions.values()
    }

    /// Die Luecken, aufsteigend nach `chainId` und `fromSequence`.
    pub fn gaps(&self) -> impl ExactSizeIterator<Item = &ChainGapV1> + '_ {
        self.gaps.values()
    }

    /// Die Parse-Fehlschlaege, aufsteigend nach `objectHash`.
    ///
    /// Zu jedem Eintrag gehoert PAARWEISE ein [`QuarantinedObjectV1`] mit Grund
    /// [`QuarantineReason::Malformed`] ueber demselben Hash.
    pub fn format_errors(&self) -> impl ExactSizeIterator<Item = &ObjectErrorV1> + '_ {
        self.format_errors.values()
    }

    /// Die isolierten Objekte, aufsteigend nach `objectHash`.
    pub fn quarantined_objects(&self) -> impl ExactSizeIterator<Item = &QuarantinedObjectV1> + '_ {
        self.quarantined_objects.values()
    }

    /// Signaturfehler, aufsteigend nach `objectHash` und `code`.
    pub fn signature_errors(&self) -> impl ExactSizeIterator<Item = &ObjectErrorV1> + '_ {
        self.signature_errors.iter()
    }

    /// Evidence-Fehler, aufsteigend nach `objectHash` und `code`.
    pub fn evidence_errors(&self) -> impl ExactSizeIterator<Item = &ObjectErrorV1> + '_ {
        self.evidence_errors.iter()
    }

    /// Entschluesselungsfehler, aufsteigend nach `objectHash` und `code`.
    pub fn decryption_errors(&self) -> impl ExactSizeIterator<Item = &ObjectErrorV1> + '_ {
        self.decryption_errors.iter()
    }

    /// Jeder Schluesselabdruck, der an einer ERFOLGREICHEN Signaturpruefung
    /// dieses Laufs beteiligt war, bytewise aufsteigend.
    ///
    /// Nachweis des Geprueften, kein Katalogabzug: ein Zertifikat, das nur im
    /// Bestand liegt, aber nie eine Pruefung getragen hat, steht hier nicht.
    pub fn public_key_thumbprints(&self) -> impl ExactSizeIterator<Item = KeyThumbprint> + '_ {
        self.public_key_thumbprints.iter().copied()
    }

    /// Was Gate `receipt` ueber einen Rueckbau der Kette sagen konnte.
    ///
    /// ABGELEITETER Accessor, KEIN JSON-Feld. Er ist der einzige Ort, an dem
    /// [`RollbackAssessment::NotAssessable`] ueberhaupt sichtbar wird: ein
    /// Bestand ohne `.ecp` erzeugt keinen Reporteintrag und senkt
    /// [`Self::is_fully_verified`] NICHT. Nicht pruefbar ist kein Mangel des
    /// Bestands, sondern das Fehlen einer Referenz — und ausdruecklich NICHT
    /// dasselbe wie [`RollbackAssessment::Consistent`], das die affirmative
    /// Aussage „kein Rollback" traegt.
    #[must_use]
    pub const fn rollback_assessment(&self) -> &RollbackAssessment {
        &self.rollback
    }

    /// `reportHash`: SHA-256 ueber [`Self::canonical_hash_preimage`].
    #[must_use]
    pub const fn report_hash(&self) -> Hash32 {
        self.report_hash
    }

    /// Lief die Pruefung vollstaendig und ohne Befund?
    ///
    /// ABGELEITETER Accessor, KEIN JSON-Feld — das Schema ist
    /// `additionalProperties: false`. Wahr nur, wenn die vollstaendige Pipeline
    /// durchlief UND `formatErrors`, `quarantinedObjects`, `signatureErrors`,
    /// `evidenceErrors`, `decryptionErrors` und `gaps` saemtlich leer sind.
    ///
    /// ZWEI AUSNAHMEN, die den Wert NIE senken: `notServerConfirmed` ist kein
    /// Mangel (`design.md`:1608), und ein fehlender Empfaengerschluessel
    /// bedeutet keine versuchte Entschluesselung — beides erzeugt deshalb auch
    /// keinen Eintrag in einem der sechs Arrays.
    #[must_use]
    pub fn is_fully_verified(&self) -> bool {
        self.pipeline_completed
            && self.format_errors.is_empty()
            && self.quarantined_objects.is_empty()
            && self.signature_errors.is_empty()
            && self.evidence_errors.is_empty()
            && self.decryption_errors.is_empty()
            && self.gaps.is_empty()
    }

    /// Die kanonischen Berichtsbytes, `reportHash` eingeschlossen.
    ///
    /// # Errors
    ///
    /// [`VerifyError::NonCanonicalReport`], falls je eine Zeichenkette ausser
    /// der Reihe stuende.
    pub fn to_canonical_json(&self) -> Result<String, VerifyError> {
        self.write_document(true)
    }

    /// Das Urbild von `reportHash`.
    ///
    /// Ein VOLLSTAENDIGES JSON-Dokument mitsamt aeusseren Klammern, dem genau
    /// die drei Glieder `reportHash`, `reportSignature` und `runtimeMetadata`
    /// fehlen — die beiden letzten sind in Phase B ohnehin stets abwesend, und
    /// `reportHash` steht im `required`-Array an letzter Stelle, sodass das
    /// Urbild schlicht ein Glied frueher schliesst. Das ist die in
    /// `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`
    /// gepinnte Formel; Task 10 friert diese Bytes ein.
    ///
    /// # Errors
    ///
    /// Wie [`Self::to_canonical_json`].
    pub fn canonical_hash_preimage(&self) -> Result<String, VerifyError> {
        self.write_document(false)
    }

    /// Rendert das Dokument, wahlweise mit oder ohne `reportHash`.
    ///
    /// Die Gliederreihenfolge ist EXAKT das `required`-Array des Schemas.
    fn write_document(&self, include_report_hash: bool) -> Result<String, VerifyError> {
        let mut members: Vec<(&str, String)> = vec![
            ("schemaId", quoted(SCHEMA_ID_V1, TokenClass::SchemaId)?),
            ("archiveObjectCount", count(self.archive_object_count)),
            ("entryPackageCount", count(self.entry_package_count)),
            ("destroyedEntryCount", count(self.destroyed_entry_count)),
            ("chainHead", self.chain_head.to_json(1)?),
            (
                "registryVersions",
                array(
                    1,
                    &self
                        .registry_versions
                        .iter()
                        .map(|version| uint(version.get()))
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                "objectResults",
                array(
                    1,
                    &render(self.object_results.values(), |value| value.to_json(2))?,
                ),
            ),
            (
                "authorizedDestructions",
                array(
                    1,
                    &render(self.authorized_destructions.values(), |value| {
                        value.to_json(2)
                    })?,
                ),
            ),
            (
                "gaps",
                array(1, &render(self.gaps.values(), |value| value.to_json(2))?),
            ),
            (
                "formatErrors",
                array(
                    1,
                    &render(self.format_errors.values(), |value| value.to_json(2))?,
                ),
            ),
            (
                "quarantinedObjects",
                array(
                    1,
                    &render(self.quarantined_objects.values(), |value| value.to_json(2))?,
                ),
            ),
            ("nonObjectFileCount", count(self.non_object_file_count)),
            (
                "signatureErrors",
                array(
                    1,
                    &render(self.signature_errors.iter(), |value| value.to_json(2))?,
                ),
            ),
            (
                "evidenceErrors",
                array(
                    1,
                    &render(self.evidence_errors.iter(), |value| value.to_json(2))?,
                ),
            ),
            (
                "decryptionErrors",
                array(
                    1,
                    &render(self.decryption_errors.iter(), |value| value.to_json(2))?,
                ),
            ),
            (
                "publicKeyThumbprints",
                array(
                    1,
                    &self
                        .public_key_thumbprints
                        .iter()
                        .map(|thumbprint| hex_string(thumbprint.as_bytes()))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
        ];
        if include_report_hash {
            members.push(("reportHash", hex_string(self.report_hash.as_bytes())?));
        }
        object(0, &members)
    }
}

/// Zaehler als Dezimalzahl.
///
/// `usize` ist auf `wasm32-unknown-unknown` 32 Bit breit; die Umwandlung nach
/// `u64` ist deshalb auf jeder Zielarchitektur verlustfrei.
fn count(value: usize) -> String {
    uint(value as u64)
}

/// Rendert eine bereits geordnete Folge, ohne die Ordnung anzutasten.
fn render<T>(
    values: impl Iterator<Item = T>,
    render_one: impl Fn(T) -> Result<String, VerifyError>,
) -> Result<Vec<String>, VerifyError> {
    values.map(render_one).collect()
}

impl fmt::Debug for VerificationReportV1 {
    /// Gibt Zaehler und Kopf aus, nie die Berichtsbytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationReportV1")
            .field("archive_object_count", &self.archive_object_count)
            .field("non_object_file_count", &self.non_object_file_count)
            .field("entry_package_count", &self.entry_package_count)
            .field("destroyed_entry_count", &self.destroyed_entry_count)
            .field("chain_head", &self.chain_head)
            .field("format_error_count", &self.format_errors.len())
            .field("quarantined_count", &self.quarantined_objects.len())
            .field("is_fully_verified", &self.is_fully_verified())
            .finish_non_exhaustive()
    }
}
