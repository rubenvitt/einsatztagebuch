//! Die drei Inventarklassen eines Bestands nach `design.md` §11.4.
//!
//! Klassifiziert wird AUSSCHLIESSLICH am 9-Byte-Exact-Object-Praefix
//! (`crates/ea-format/src/parser.rs`), nie am Dateinamen und nie am
//! Verzeichnis:
//!
//! 1. Bytes MIT Praefix sind Archivobjekte. Sie werden geparst; ein
//!    Fehlschlag ist ein Befund (Quarantaene mit Grund), kein Abbruch.
//! 2. Bytes OHNE Praefix sind kein Archivobjekt. Sie werden weder geparst
//!    noch isoliert, sondern ausschliesslich gezaehlt.
//! 3. Der Trust Anchor ist NIE Teil dieser Klassifikation. Er kommt als
//!    Parameter der Verifikation, nicht aus dem Bestand.
//!
//! Ein gueltiges Objekt unter `README-FORMAT.txt` ist damit ein Archivobjekt;
//! eine Textdatei unter `entries/` ist keines. Die Klasse ist nicht durch
//! Umbenennen waehlbar.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use ea_crypto::object_hash;
use ea_format::{
    DestroyedEntryStubV1, EAG_PREFIX_V1, ECP_PREFIX_V1, EDS_PREFIX_V1, EIP_PREFIX_V1,
    ESR_PREFIX_V1, ETB_PREFIX_V1, EntryPackageV1, EvidenceObjectV1, GrantV1, Parsed,
    ParsedArchiveObject, ReceiptV1, TrustObjectV1, decode_exact_object,
};
use ea_types::{ChainId, ChainSequence, ObjectHash};

use crate::{
    ArchiveBlob, ArchiveError, ArchiveSource, MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1,
};

/// Die sechs 9-Byte-Exact-Object-Praefixe. Einzige Klassifikationsgrundlage.
const EXACT_OBJECT_PREFIXES_V1: [[u8; 9]; 6] = [
    EIP_PREFIX_V1,
    EAG_PREFIX_V1,
    ESR_PREFIX_V1,
    ECP_PREFIX_V1,
    ETB_PREFIX_V1,
    EDS_PREFIX_V1,
];

/// Traegt `bytes` eines der sechs Exact-Object-Praefixe?
#[must_use]
fn has_exact_object_prefix(bytes: &[u8]) -> bool {
    EXACT_OBJECT_PREFIXES_V1
        .iter()
        .any(|prefix| bytes.starts_with(prefix))
}

/// Schreibt 32 Hashbytes als Kleinbuchstaben-Hex.
///
/// `ea-types` leitet fuer Hashtypen kein `Debug` ab; die Debug-Ausgaben dieses
/// Moduls sind deshalb von Hand geschrieben, genau wie in `ea-chain`.
fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// Warum ein Objekt isoliert wurde.
///
/// Die geschlossene Menge aus `schemas/reports/v1/verification-report.schema.json`
/// (`quarantinedObject.reason`), vollstaendig hier definiert. `Unattributable`
/// entsteht erst bei der Zuordnung zu einem Schreiberzertifikat; die Menge ist
/// dennoch jetzt schon geschlossen, damit der Bericht keine Gruende nachtraegt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum QuarantineReason {
    /// Praefix vorhanden, Parser gescheitert. Traegt PAARWEISE einen
    /// [`FormatErrorEntry`] ueber demselben Objekthash.
    Malformed,
    /// Derselbe Objekthash mehrfach im Bestand.
    Duplicate,
    /// Widerspruch zu bereits Gepruefetem (Fork, Kettenbruch,
    /// Checkpoint-Kopfwiderspruch).
    Conflicting,
    /// Keinem gueltigen Schreiberzertifikat zuzuordnen.
    Unattributable,
}

impl QuarantineReason {
    /// Das Schemaliteral. Der Bericht kennt genau diese vier Zeichenketten.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Duplicate => "duplicate",
            Self::Conflicting => "conflicting",
            Self::Unattributable => "unattributable",
        }
    }

    /// Welcher Grund gewinnt, wenn auf denselben Objekthash mehrere zutreffen.
    ///
    /// `quarantinedObjects` ist im Berichtsschema nach `objectHash` eindeutig
    /// (`x-ea-unique-key`); ein Objekt traegt deshalb genau EINEN Grund. Der
    /// kleinere Rang gewinnt:
    ///
    /// 1. `Malformed` — muss gewinnen, sonst bricht die gepinnte eineindeutige
    ///    Kopplung an `formatErrors`: ein Parse-Fehlschlag erzeugt PAARWEISE
    ///    einen `formatError` und diesen Quarantaeneeintrag.
    /// 2. `Conflicting` — ein inhaltlicher Widerspruch wiegt schwerer als die
    ///    blosse Wiederholung derselben Bytes.
    /// 3. `Unattributable` — Zuordnungsmangel, aber keine Aussage ueber den
    ///    Bestand selbst.
    /// 4. `Duplicate` — der schwaechste Befund: dieselben Bytes noch einmal.
    ///
    /// BEWUSST nicht die abgeleitete `Ord`-Reihenfolge der Varianten: die
    /// Deklarationsreihenfolge folgt dem Schema, die Vorrangordnung folgt der
    /// Aussagekraft. Beides zu koppeln waere ein stiller Fallstrick.
    const fn precedence_rank(self) -> u8 {
        match self {
            Self::Malformed => 0,
            Self::Conflicting => 1,
            Self::Unattributable => 2,
            Self::Duplicate => 3,
        }
    }
}

/// Ein isoliertes Objekt mitsamt dem Grund.
///
/// Der Objekthash ist auch fuer NICHT parsbare Bytes berechenbar — das ist der
/// Grund, warum das Berichtsfeld ueberhaupt existiert.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct QuarantinedObject {
    object_hash: ObjectHash,
    reason: QuarantineReason,
}

impl QuarantinedObject {
    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn reason(&self) -> QuarantineReason {
        self.reason
    }
}

impl fmt::Debug for QuarantinedObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QuarantinedObject { object_hash: ")?;
        write_hex(formatter, self.object_hash.as_bytes())?;
        write!(formatter, ", reason: {} }}", self.reason.as_str())
    }
}

/// Ein Parse-Fehlschlag mitsamt dem stabilen Fehlercode.
///
/// `code` stammt unveraendert aus `ea_format::FormatError::code()` und passt
/// damit auf `^EA-[A-Z0-9-]+$`, wie es das Berichtsschema fordert.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FormatErrorEntry {
    object_hash: ObjectHash,
    code: &'static str,
}

impl FormatErrorEntry {
    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Debug for FormatErrorEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FormatErrorEntry { object_hash: ")?;
        write_hex(formatter, self.object_hash.as_bytes())?;
        write!(formatter, ", code: {} }}", self.code)
    }
}

/// Das Inventar ueber alle Bytes eines Bestands.
///
/// Die Objektfamilien sind nach `ObjectHash` eindeutig und aufsteigend
/// geordnet; die Zaehler zaehlen Bytesequenzen. Es gilt
/// `archive_object_count() + non_object_file_count() ==` Zahl der vom Port
/// gelieferten Bytesequenzen.
pub struct ArchiveInventory {
    archive_object_count: usize,
    non_object_file_count: usize,
    entries: Vec<Parsed<EntryPackageV1>>,
    grants: Vec<Parsed<GrantV1>>,
    receipts: Vec<Parsed<ReceiptV1>>,
    evidence: Vec<Parsed<EvidenceObjectV1>>,
    trust: Vec<Parsed<TrustObjectV1>>,
    destroyed: Vec<Parsed<DestroyedEntryStubV1>>,
    quarantined: Vec<QuarantinedObject>,
    format_errors: Vec<FormatErrorEntry>,
}

impl ArchiveInventory {
    /// Laeuft den Bestand EINMAL durch und klassifiziert jede Bytesequenz.
    ///
    /// [`MAX_ARCHIVE_BLOBS_V1`](crate::MAX_ARCHIVE_BLOBS_V1) und
    /// [`MAX_TOTAL_ARCHIVE_BYTES_V1`](crate::MAX_TOTAL_ARCHIVE_BYTES_V1) werden
    /// WAEHREND des Durchlaufs geprueft: ein Ueberschreiten liefert `Err` und
    /// haelt den Durchlauf an, ohne den Rest zu lesen. Unlesbare Objekte sind
    /// dagegen Befunde und nie ein `Err`.
    ///
    /// # Errors
    ///
    /// [`ArchiveError::BlobLimit`] oder [`ArchiveError::TotalByteLimit`] beim
    /// Ueberschreiten der Schranken, sonst der Fehler des Bestands selbst.
    pub fn build(source: &dyn ArchiveSource) -> Result<Self, ArchiveError> {
        let mut builder = InventoryBuilder::default();
        source.visit_blobs(&mut |blob| builder.accept(blob))?;
        Ok(builder.finish())
    }

    /// Bytesequenzen MIT Exact-Object-Praefix, jede einzeln.
    ///
    /// Unabhaengig von Parse-Erfolg und Duplikat: gezaehlt werden
    /// Bytesequenzen, nicht eindeutige Hashes.
    #[must_use]
    pub const fn archive_object_count(&self) -> usize {
        self.archive_object_count
    }

    /// Bytesequenzen OHNE Exact-Object-Praefix.
    #[must_use]
    pub const fn non_object_file_count(&self) -> usize {
        self.non_object_file_count
    }

    #[must_use]
    pub fn entries(&self) -> &[Parsed<EntryPackageV1>] {
        &self.entries
    }

    #[must_use]
    pub fn grants(&self) -> &[Parsed<GrantV1>] {
        &self.grants
    }

    #[must_use]
    pub fn receipts(&self) -> &[Parsed<ReceiptV1>] {
        &self.receipts
    }

    #[must_use]
    pub fn evidence(&self) -> &[Parsed<EvidenceObjectV1>] {
        &self.evidence
    }

    #[must_use]
    pub fn trust(&self) -> &[Parsed<TrustObjectV1>] {
        &self.trust
    }

    #[must_use]
    pub fn destroyed(&self) -> &[Parsed<DestroyedEntryStubV1>] {
        &self.destroyed
    }

    /// Die isolierten Objekte, aufsteigend nach `ObjectHash`.
    ///
    /// Je Objekthash genau EIN Eintrag — `quarantinedObjects` ist im Bericht
    /// nach `objectHash` eindeutig. Treffen mehrere Gruende zu, gewinnt der mit
    /// dem kleineren [`QuarantineReason::precedence_rank`]; `n` bytegleiche
    /// Kopien erzeugen deshalb einen einzigen `Duplicate`-Eintrag.
    ///
    /// Bei `Duplicate` bleibt die erste Kopie ausdruecklich das inventarisierte
    /// Objekt: sie erscheint weiterhin in ihrer Objektfamilie, damit die
    /// Zaehler und die Kette den Eintrag sehen. Ob der Bericht diesen Hash
    /// dann in `objectResults` fuehrt oder allein in `quarantinedObjects`, ist
    /// eine Entscheidung der Berichtsabbildung und faellt nicht hier.
    #[must_use]
    pub fn quarantined(&self) -> &[QuarantinedObject] {
        &self.quarantined
    }

    /// Die Parse-Fehlschlaege, aufsteigend nach `ObjectHash`.
    ///
    /// Zu jedem Eintrag gehoert genau ein [`QuarantinedObject`] mit Grund
    /// [`QuarantineReason::Malformed`] ueber demselben Hash; die uebrigen
    /// Gruende tragen keinen `formatError`.
    #[must_use]
    pub fn format_errors(&self) -> &[FormatErrorEntry] {
        &self.format_errors
    }
}

/// Der Zustand waehrend des einen Durchlaufs.
///
/// Durchgehend `BTreeMap` nach `ObjectHash`: die Reihenfolge der Familien und
/// der Befundlisten wird nach aussen sichtbar und darf deshalb nicht von einer
/// Hash-Streuung abhaengen.
#[derive(Default)]
struct InventoryBuilder {
    blob_count: usize,
    total_bytes: usize,
    archive_object_count: usize,
    non_object_file_count: usize,
    entries: BTreeMap<ObjectHash, Parsed<EntryPackageV1>>,
    grants: BTreeMap<ObjectHash, Parsed<GrantV1>>,
    receipts: BTreeMap<ObjectHash, Parsed<ReceiptV1>>,
    evidence: BTreeMap<ObjectHash, Parsed<EvidenceObjectV1>>,
    trust: BTreeMap<ObjectHash, Parsed<TrustObjectV1>>,
    destroyed: BTreeMap<ObjectHash, Parsed<DestroyedEntryStubV1>>,
    /// Objekthash -> Fehlercode. Dieselben unlesbaren Bytes mehrfach im
    /// Bestand sind EIN Befund: sonst traege ein Quarantaeneeintrag mehrere
    /// `formatError`s und die gepinnte Kopplung waere gebrochen.
    malformed: BTreeMap<ObjectHash, &'static str>,
    /// Jeder Objekthash, der schon einmal MIT Praefix geliefert wurde.
    ///
    /// Nur Bytes mit Praefix: Beiwerk traegt keine Objektidentitaet und kann
    /// deshalb nie ein Duplikat sein.
    seen: BTreeSet<ObjectHash>,
    /// Objekthash -> Grund, genau ein Grund je Hash
    /// (siehe [`QuarantineReason::precedence_rank`]).
    quarantine: BTreeMap<ObjectHash, QuarantineReason>,
}

/// Traegt `object_hash` den Grund `reason` ein, wenn dieser den bereits
/// vermerkten uebertrifft.
fn escalate(
    quarantine: &mut BTreeMap<ObjectHash, QuarantineReason>,
    object_hash: ObjectHash,
    reason: QuarantineReason,
) {
    quarantine
        .entry(object_hash)
        .and_modify(|existing| {
            if reason.precedence_rank() < existing.precedence_rank() {
                *existing = reason;
            }
        })
        .or_insert(reason);
}

/// Wer erhebt fuer eine Sequenz Verifikationsanspruch?
///
/// `identities` sind die BEANSPRUCHTEN urspruenglichen Eintraege, `members` die
/// Objekte, die den Anspruch tragen. Beide Mengen fallen fuer ein `.eip`
/// zusammen; fuer ein `.eds` ist die Identitaet der `original_eip_object_hash`,
/// das Mitglied aber der Objekthash des Stubs selbst.
#[derive(Default)]
struct SequenceClaims {
    identities: BTreeSet<ObjectHash>,
    members: BTreeSet<ObjectHash>,
}

impl InventoryBuilder {
    fn accept(&mut self, blob: ArchiveBlob<'_>) -> Result<(), ArchiveError> {
        self.blob_count += 1;
        if self.blob_count > MAX_ARCHIVE_BLOBS_V1 {
            return Err(ArchiveError::BlobLimit);
        }
        // `saturating_add`, weil `usize` auf wasm32 32 Bit breit ist: die
        // Schranke selbst liegt bei 2 GiB, eine einzelne Bytesequenz ist
        // hier aber noch unbeschraenkt.
        self.total_bytes = self.total_bytes.saturating_add(blob.bytes().len());
        if self.total_bytes > MAX_TOTAL_ARCHIVE_BYTES_V1 {
            return Err(ArchiveError::TotalByteLimit);
        }

        if !has_exact_object_prefix(blob.bytes()) {
            self.non_object_file_count += 1;
            return Ok(());
        }
        self.archive_object_count += 1;

        // Der Objekthash steht schon vor dem Parsen fest und ist die einzige
        // Identitaet, die diese Klasse kennt — der Pfadhinweis ist keine.
        let hash = object_hash(blob.bytes());
        if !self.seen.insert(hash) {
            escalate(&mut self.quarantine, hash, QuarantineReason::Duplicate);
        }

        match decode_exact_object(blob.bytes()) {
            Ok(parsed) => self.insert(parsed),
            Err(error) => {
                self.malformed.entry(hash).or_insert(error.code());
                escalate(&mut self.quarantine, hash, QuarantineReason::Malformed);
            }
        }
        Ok(())
    }

    /// Die Objekte, die fuer dieselbe Sequenz rivalisierenden Anspruch erheben.
    ///
    /// Der Bezugspunkt sind ausschliesslich geparste Feldwerte, nie Pfade:
    /// `ManifestCoreFieldsV1::chain_id`/`chain_sequence` fuer das Fach und
    /// `DestroyedEntryStubV1::original_eip_object_hash` fuer den Anspruch des
    /// Stubs.
    ///
    /// ABGRENZUNG: Ein `.eds` ist NICHT automatisch mit dem `.eip` in Konflikt,
    /// das es ersetzt — es traegt dessen `original_eip_object_hash` bewusst und
    /// beansprucht damit DIESELBE Identitaet. Liegt nur der Stub vor, ist das
    /// der Normalfall autorisiert vernichtet. Konflikt ist erst, wenn ein Fach
    /// mehr als eine urspruengliche Identitaet traegt.
    fn sequence_conflicts(&self) -> Vec<ObjectHash> {
        let mut slots: BTreeMap<(ChainId, ChainSequence), SequenceClaims> = BTreeMap::new();
        for entry in self.entries.values() {
            let fields = entry.value().manifest().fields();
            let slot = slots
                .entry((fields.chain_id, fields.chain_sequence))
                .or_default();
            slot.identities.insert(entry.object_hash());
            slot.members.insert(entry.object_hash());
        }
        for stub in self.destroyed.values() {
            let fields = stub.value().signed_manifest().manifest().fields();
            let slot = slots
                .entry((fields.chain_id, fields.chain_sequence))
                .or_default();
            slot.identities
                .insert(stub.value().original_eip_object_hash());
            slot.members.insert(stub.object_hash());
        }
        slots
            .into_values()
            .filter(|slot| slot.identities.len() > 1)
            .flat_map(|slot| slot.members)
            .collect()
    }

    /// Die Quittungen, die fuer denselben Eintrag verschiedene Bytes tragen.
    ///
    /// Gruppiert wird allein ueber `ReceiptCoreFieldsV1::entry_object_hash`;
    /// Quittungen gehoeren BEWUSST nicht in die Sequenzfaecher, denn sie
    /// erheben keinen Anspruch auf einen Kettenplatz, sondern bestaetigen einen
    /// bestimmten Eintrag.
    fn receipt_conflicts(&self) -> Vec<ObjectHash> {
        let mut claims: BTreeMap<ObjectHash, BTreeSet<ObjectHash>> = BTreeMap::new();
        for receipt in self.receipts.values() {
            claims
                .entry(receipt.value().core().fields().entry_object_hash)
                .or_default()
                .insert(receipt.object_hash());
        }
        claims
            .into_values()
            .filter(|members| members.len() > 1)
            .flatten()
            .collect()
    }

    fn insert(&mut self, parsed: ParsedArchiveObject) {
        match parsed {
            ParsedArchiveObject::Entry(value) => {
                self.entries.entry(value.object_hash()).or_insert(value);
            }
            ParsedArchiveObject::Grant(value) => {
                self.grants.entry(value.object_hash()).or_insert(value);
            }
            ParsedArchiveObject::Receipt(value) => {
                self.receipts.entry(value.object_hash()).or_insert(value);
            }
            ParsedArchiveObject::Evidence(value) => {
                self.evidence.entry(value.object_hash()).or_insert(value);
            }
            ParsedArchiveObject::Trust(value) => {
                self.trust.entry(value.object_hash()).or_insert(value);
            }
            ParsedArchiveObject::Destroyed(value) => {
                self.destroyed.entry(value.object_hash()).or_insert(value);
            }
        }
    }

    fn finish(mut self) -> ArchiveInventory {
        // Die Konflikte entstehen erst, wenn der ganze Bestand gelesen ist:
        // ein Anspruch ist nur im Vergleich mit den uebrigen einer.
        for object_hash in self.sequence_conflicts() {
            escalate(
                &mut self.quarantine,
                object_hash,
                QuarantineReason::Conflicting,
            );
        }
        for object_hash in self.receipt_conflicts() {
            escalate(
                &mut self.quarantine,
                object_hash,
                QuarantineReason::Conflicting,
            );
        }

        let quarantined = self
            .quarantine
            .iter()
            .map(|(object_hash, reason)| QuarantinedObject {
                object_hash: *object_hash,
                reason: *reason,
            })
            .collect();
        let format_errors = self
            .malformed
            .iter()
            .map(|(object_hash, code)| FormatErrorEntry {
                object_hash: *object_hash,
                code,
            })
            .collect();
        ArchiveInventory {
            archive_object_count: self.archive_object_count,
            non_object_file_count: self.non_object_file_count,
            entries: self.entries.into_values().collect(),
            grants: self.grants.into_values().collect(),
            receipts: self.receipts.into_values().collect(),
            evidence: self.evidence.into_values().collect(),
            trust: self.trust.into_values().collect(),
            destroyed: self.destroyed.into_values().collect(),
            quarantined,
            format_errors,
        }
    }
}
