use core::fmt;

use ea_types::{ChainId, ChainSequence, EntryHash, ObjectHash};

use crate::error::ChainError;
use crate::node::{ChainNode, hex};

/// Obergrenze der Knotenzahl je Aufruf von [`build_chain`].
///
/// Die Grenze schuetzt vor einem Bestand, der den Pruefer allein durch seine
/// Groesse blockiert. Ein Ueberschreiten ist ein Eingabefehler des Aufrufers,
/// kein Befund ueber den Bestand.
pub const MAX_CHAIN_NODES_V1: usize = 1_048_576;

/// Kopf einer Kette: Kette, Sequenz und Eintragshash.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChainHead {
    chain_id: ChainId,
    chain_sequence: ChainSequence,
    entry_hash: EntryHash,
}

impl ChainHead {
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn chain_sequence(&self) -> ChainSequence {
        self.chain_sequence
    }

    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }
}

impl fmt::Debug for ChainHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChainHead { chain_id: ")?;
        hex(self.chain_id.as_bytes(), formatter)?;
        write!(formatter, ", chain_sequence: {}", self.chain_sequence.get())?;
        formatter.write_str(", entry_hash: ")?;
        hex(self.entry_hash.as_bytes(), formatter)?;
        formatter.write_str(" }")
    }
}

/// Befund: Ein Knoten bindet seinen unmittelbaren Vorgaenger nicht.
///
/// Ein Bruch ist eine Aussage ueber den BESTAND, kein Eingabefehler. Er
/// erscheint deshalb im `Ok`-Zweig von [`build_chain`].
///
/// # Abbildung in den Pruefbericht
///
/// `schemas/reports/v1/verification-report.schema.json` kennt kein
/// `breaks`-Array und ist `additionalProperties: false`. Ein Bruch wird deshalb
/// zu einem Eintrag in `quarantinedObjects` mit `reason = "conflicting"` fuer
/// [`Self::object_hash`]. Ohne diese Abbildung waere der Bruch im JSON
/// unsichtbar — fail-open in genau der Dimension, fuer die dieser Befund
/// existiert. Die Abbildung gehoert nach `ea-verify` (Task 16) und wird dort
/// nicht neu erfunden, sondern von hier uebernommen.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChainBreak {
    sequence: ChainSequence,
    expected_previous_entry_hash: EntryHash,
    actual_previous_entry_hash: EntryHash,
    object_hash: ObjectHash,
}

impl ChainBreak {
    /// Sequenz des Knotens, dessen Vorgaengerbindung nicht aufgeht.
    #[must_use]
    pub const fn sequence(&self) -> ChainSequence {
        self.sequence
    }

    /// Eintragshash des Knotens mit `sequence - 1`.
    #[must_use]
    pub const fn expected_previous_entry_hash(&self) -> EntryHash {
        self.expected_previous_entry_hash
    }

    /// Vorgaengerhash, den der Knoten tatsaechlich traegt.
    #[must_use]
    pub const fn actual_previous_entry_hash(&self) -> EntryHash {
        self.actual_previous_entry_hash
    }

    /// Objekthash des Archivobjekts, aus dem der brechende Knoten stammt.
    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }
}

impl fmt::Debug for ChainBreak {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ChainBreak {{ sequence: {}", self.sequence.get())?;
        formatter.write_str(", expected_previous_entry_hash: ")?;
        hex(self.expected_previous_entry_hash.as_bytes(), formatter)?;
        formatter.write_str(", actual_previous_entry_hash: ")?;
        hex(self.actual_previous_entry_hash.as_bytes(), formatter)?;
        formatter.write_str(", object_hash: ")?;
        hex(self.object_hash.as_bytes(), formatter)?;
        formatter.write_str(" }")
    }
}

/// Form, in der zwei Knoten miteinander kollidieren.
///
/// Ein Knotenpaar kann BEIDE Formen zugleich erfuellen — zwei Kinder desselben
/// Vorgaengers auf derselben Sequenz sind der Regelfall eines Forks. Dafuer
/// entsteht GENAU EIN Befund, und zwar als [`Self::SequenceCollision`]: das ist
/// die spezifischere Aussage, weil sie die strittige Position in der Kette
/// benennt. Der zweite Befund wird nicht verschluckt, sondern waere derselbe
/// Befund ein zweites Mal — und wuerde in Task 16 dieselben Objekte doppelt
/// quarantaenieren.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ChainForkForm {
    /// Zwei Knoten auf derselben `chain_sequence` mit verschiedenem
    /// `entry_hash`.
    SequenceCollision,
    /// Zwei Knoten mit demselben `previous_entry_hash` und verschiedenem
    /// `entry_hash`, die NICHT bereits als [`Self::SequenceCollision`] erfasst
    /// sind. Die Erkennung haengt am Vorgaengerhash, nicht an der Sequenz:
    /// zwei Kinder desselben Vorgaengers auf verschiedenen Sequenzen sind
    /// ebenso eine gespaltene Kette.
    PredecessorCollision,
}

impl ChainForkForm {
    const fn label(self) -> &'static str {
        match self {
            Self::SequenceCollision => "SequenceCollision",
            Self::PredecessorCollision => "PredecessorCollision",
        }
    }
}

impl fmt::Debug for ChainForkForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Befund: Die Kette spaltet sich, zwei Knoten beanspruchen dieselbe Stelle.
///
/// Ein Fork ist eine Aussage ueber den BESTAND und deshalb kein `Err`: ein
/// `Err` koennte das unstrittige Praefix nicht mitfuehren, und ein Fork darf
/// weder stillschweigend zur Luecke degradieren noch die Verifikation der
/// Praefixsequenzen verhindern. [`VerifiedChain::verified_head`] haelt vor der
/// kleinsten Fork- oder Bruchsequenz an, [`VerifiedChain::head`] bleibt die
/// hoechste gesehene Sequenz.
///
/// Zwei bytegleiche Knoten sind KEIN Fork, sondern eine Dublette: beide Formen
/// verlangen verschiedene `entry_hash`-Werte, und [`build_chain`] dedupliziert
/// bytegleiche Knoten ohnehin vor der Analyse. Die Quarantaene fuer Dubletten
/// entsteht in `ea-archive`, nicht hier.
///
/// # Abbildung in den Pruefbericht
///
/// `schemas/reports/v1/verification-report.schema.json` kennt kein
/// `forks`-Array und ist `additionalProperties: false`. Ein Fork wird deshalb
/// zu Eintraegen in `quarantinedObjects` mit `reason = "conflicting"` fuer
/// BEIDE [`Self::competing_object_hashes`]. Ohne diese Abbildung waere ein Fork
/// im JSON unsichtbar — fail-open in genau der Dimension, fuer die
/// [`VerifiedChain::forks`] existiert. Die Abbildung gehoert nach `ea-verify`
/// (Task 16) und wird dort nicht neu erfunden, sondern von hier uebernommen.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChainFork {
    chain_id: ChainId,
    sequence: ChainSequence,
    competing_entry_hashes: [EntryHash; 2],
    competing_object_hashes: [ObjectHash; 2],
    form: ChainForkForm,
}

impl ChainFork {
    /// Kette, in der sich die Spaltung zeigt.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Kleinste der strittigen Sequenzen — die Stelle, an der die
    /// Kettenidentitaet zum ersten Mal mehrdeutig wird. Bei einer
    /// [`ChainForkForm::SequenceCollision`] ist das die gemeinsame Sequenz
    /// beider Knoten.
    #[must_use]
    pub const fn sequence(&self) -> ChainSequence {
        self.sequence
    }

    /// Die beiden konkurrierenden Eintragshashes, bytewise aufsteigend.
    ///
    /// Die Ordnung ist Teil des Vertrags: derselbe Bestand liefert in
    /// beliebiger Eingabereihenfolge denselben Befund.
    #[must_use]
    pub const fn competing_entry_hashes(&self) -> [EntryHash; 2] {
        self.competing_entry_hashes
    }

    /// Die Objekthashes der beiden konkurrierenden Knoten, bytewise
    /// aufsteigend.
    ///
    /// ACHTUNG: Index *i* dieses Feldes gehoert NICHT zu Index *i* von
    /// [`Self::competing_entry_hashes`]. Beide Felder sind unabhaengig
    /// voneinander aufsteigend sortiert, damit der Befund von der
    /// Eingabereihenfolge unabhaengig ist. Die Abbildung in den Bericht
    /// verbraucht sie als MENGE (beide Objekte in Quarantaene), nie als Paar.
    ///
    /// Traegt eine Seite mehrere Knoten mit demselben Eintragshash, steht hier
    /// deren kleinster Objekthash.
    #[must_use]
    pub const fn competing_object_hashes(&self) -> [ObjectHash; 2] {
        self.competing_object_hashes
    }

    /// Form der Kollision.
    #[must_use]
    pub const fn form(&self) -> ChainForkForm {
        self.form
    }
}

impl fmt::Debug for ChainFork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChainFork { chain_id: ")?;
        hex(self.chain_id.as_bytes(), formatter)?;
        write!(formatter, ", sequence: {}", self.sequence.get())?;
        formatter.write_str(", competing_entry_hashes: [")?;
        hex(self.competing_entry_hashes[0].as_bytes(), formatter)?;
        formatter.write_str(", ")?;
        hex(self.competing_entry_hashes[1].as_bytes(), formatter)?;
        formatter.write_str("], competing_object_hashes: [")?;
        hex(self.competing_object_hashes[0].as_bytes(), formatter)?;
        formatter.write_str(", ")?;
        hex(self.competing_object_hashes[1].as_bytes(), formatter)?;
        write!(formatter, "], form: {} }}", self.form.label())
    }
}

/// Befund: Ein zusammenhaengendes Intervall fehlender Sequenzen.
///
/// Das Intervall ist MAXIMAL: fehlen die Sequenzen 3, 4 und 5, ist das genau
/// ein `ChainGap` von 3 bis einschliesslich 5, nicht drei Befunde. Eine Luecke
/// existiert nur UNTERHALB der hoechsten gesehenen Sequenz; ueber nicht
/// existierende Fortsetzungen oberhalb von [`VerifiedChain::head`] ist keine
/// Aussage moeglich.
///
/// Ein Knoten mit [`ChainNodeKind::DestroyedStub`](crate::ChainNodeKind)
/// besetzt seine Sequenz vollstaendig und ist deshalb nie Teil einer Luecke:
/// der Stub veraendert die Kettenidentitaet nicht (design.md 11.4). Eine
/// ungeklaerte Luecke ist ein fehlender Eintrag OHNE gueltigen Stub.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChainGap {
    chain_id: ChainId,
    from_sequence: ChainSequence,
    through_sequence: ChainSequence,
}

impl ChainGap {
    /// Kette, in der das Intervall fehlt.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Erste fehlende Sequenz, einschliesslich.
    #[must_use]
    pub const fn from_sequence(&self) -> ChainSequence {
        self.from_sequence
    }

    /// Letzte fehlende Sequenz, einschliesslich.
    #[must_use]
    pub const fn through_sequence(&self) -> ChainSequence {
        self.through_sequence
    }
}

/// Sortierordnung nach `(chain_id bytewise, from_sequence numerisch)` — exakt
/// der `x-ea-sort-key`, den `schemas/reports/v1/verification-report.schema.json`
/// fuer `gaps` vorschreibt.
///
/// Die Ordnung laesst `through_sequence` bewusst aus, obwohl `Eq` alle drei
/// Felder vergleicht. Das ist widerspruchsfrei, weil Luecken maximal und damit
/// disjunkt sind: `(chain_id, from_sequence)` ist eindeutig — genau der
/// `x-ea-unique-key` desselben Schemas. Zwei Luecken mit gleichem Schluessel
/// und verschiedener Obergrenze kann es nicht geben.
impl Ord for ChainGap {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.chain_id, self.from_sequence).cmp(&(other.chain_id, other.from_sequence))
    }
}

impl PartialOrd for ChainGap {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for ChainGap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChainGap { chain_id: ")?;
        hex(self.chain_id.as_bytes(), formatter)?;
        write!(
            formatter,
            ", from_sequence: {}, through_sequence: {} }}",
            self.from_sequence.get(),
            self.through_sequence.get()
        )
    }
}

/// Ergebnis einer Verkettungspruefung samt Befunden.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedChain {
    chain_id: ChainId,
    nodes: Vec<ChainNode>,
    breaks: Vec<ChainBreak>,
    forks: Vec<ChainFork>,
    gaps: Vec<ChainGap>,
    head: Option<ChainHead>,
    verified_head: Option<ChainHead>,
}

impl VerifiedChain {
    /// Kette, gegen die geprueft wurde — der Parameter von [`build_chain`],
    /// nicht ein aus dem Bestand gelesener Wert.
    ///
    /// Bewusst `pub(crate)`: der einzige Verbraucher ist
    /// [`assess_rollback`](crate::assess_rollback), das Checkpoint-Aussagen
    /// fremder Ketten aussortieren muss, und zwar AUCH dann, wenn der Bestand
    /// leer ist und [`Self::head`] deshalb nichts hergibt — genau der Fall des
    /// vollstaendig geloeschten Archivs. Nach aussen bleibt der Wert
    /// verschlossen, weil der Pruefbericht seine `chainId` laut Schema immer
    /// vom Trust Anchor nimmt, nie aus dem Bestand.
    pub(crate) const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Alle Knoten in der deterministischen Reihenfolge `(chain_sequence,
    /// entry_hash, object_hash)`. Die Reihenfolge ist Teil des Vertrags; der
    /// dritte Bestandteil macht den Schluessel total, damit zwei Knoten mit
    /// gleicher Sequenz und gleichem Eintragshash nicht von der
    /// Eingabereihenfolge abhaengen.
    ///
    /// Bytegleiche Knoten erscheinen GENAU EINMAL: [`build_chain`] dedupliziert
    /// die Eingabe vor der Analyse. Eine Dublette ist kein Kettenbefund; ihre
    /// Quarantaene entsteht in `ea-archive`.
    #[must_use]
    pub fn nodes(&self) -> &[ChainNode] {
        &self.nodes
    }

    /// Alle Vorgaengerbrueche in Sequenzreihenfolge.
    #[must_use]
    pub fn breaks(&self) -> &[ChainBreak] {
        &self.breaks
    }

    /// Alle Kettenspaltungen, aufsteigend nach
    /// `(sequence, competing_entry_hashes[0])`.
    ///
    /// Ein nicht leeres Ergebnis senkt [`Self::is_fully_verified`] und haelt
    /// [`Self::verified_head`] vor der kleinsten Forksequenz an.
    #[must_use]
    pub fn forks(&self) -> &[ChainFork] {
        &self.forks
    }

    /// Hoechste gesehene Sequenz, unabhaengig von Befunden.
    #[must_use]
    pub const fn head(&self) -> Option<ChainHead> {
        self.head
    }

    /// Alle Lueckenintervalle, aufsteigend nach `(chain_id, from_sequence)`.
    ///
    /// Die Intervalle sind maximal und disjunkt; oberhalb von [`Self::head`]
    /// gibt es keine.
    #[must_use]
    pub fn gaps(&self) -> &[ChainGap] {
        &self.gaps
    }

    /// Letzte unstrittige Sequenz: der letzte Knoten, der vom niedrigsten
    /// vorhandenen Knoten aus in lueckenloser Folge mit passender
    /// Vorgaengerbindung erreicht wird, und zwar UNTERHALB der kleinsten Fork-
    /// oder Bruchsequenz.
    ///
    /// Liegt der erste Befund bereits auf der niedrigsten vorhandenen Sequenz,
    /// bleibt kein unstrittiges Praefix uebrig: das Ergebnis ist dann `None`
    /// und nicht etwa der strittige Knoten selbst.
    #[must_use]
    pub const fn verified_head(&self) -> Option<ChainHead> {
        self.verified_head
    }

    /// Kettenaussage: kein Bruch, keine Luecke und kein Fork.
    ///
    /// Das ist die Aussage ueber die KETTE, nicht ueber den Pruefbericht. Der
    /// Bericht leitet seine eigene, breitere Aussage ab (Formatfehler,
    /// Quarantaene, Signatur- und Nachweisfehler).
    #[must_use]
    pub fn is_fully_verified(&self) -> bool {
        self.breaks().is_empty() && self.gaps().is_empty() && self.forks().is_empty()
    }
}

impl fmt::Debug for VerifiedChain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedChain { chain_id: ")?;
        hex(self.chain_id.as_bytes(), formatter)?;
        formatter.write_str(", head: ")?;
        debug_optional_head(self.head, formatter)?;
        formatter.write_str(", verified_head: ")?;
        debug_optional_head(self.verified_head, formatter)?;
        formatter.write_str(", breaks: [")?;
        for (index, entry) in self.breaks.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            write!(formatter, "{entry:?}")?;
        }
        formatter.write_str("], forks: [")?;
        for (index, fork) in self.forks.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            write!(formatter, "{fork:?}")?;
        }
        formatter.write_str("], gaps: [")?;
        for (index, gap) in self.gaps.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            write!(formatter, "{gap:?}")?;
        }
        formatter.write_str("], nodes: [")?;
        for (index, node) in self.nodes.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            write!(formatter, "{node:?}")?;
        }
        formatter.write_str("] }")
    }
}

fn debug_optional_head(head: Option<ChainHead>, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match head {
        Some(head) => write!(formatter, "{head:?}"),
        None => formatter.write_str("none"),
    }
}

fn head_of(node: &ChainNode) -> ChainHead {
    ChainHead {
        chain_id: node.chain_id,
        chain_sequence: node.chain_sequence,
        entry_hash: node.entry_hash,
    }
}

/// Prueft die Vorgaengerbindung aller Knoten einer Kette.
///
/// Der Aufruf arbeitet ausschliesslich auf Kopien der Eingabe und sortiert sie
/// deterministisch nach `(chain_sequence, entry_hash, object_hash)` — bytewise, ohne
/// `HashMap` oder `HashSet`, damit die Iterationsreihenfolge reproduzierbar
/// bleibt.
///
/// Bytegleiche Knoten werden nach dem Sortieren dedupliziert. Eine Dublette
/// ist kein Kettenbefund — sie kann per Konstruktion keinen Fork ausloesen,
/// weil beide Kollisionsformen verschiedene Eintragshashes verlangen —, und
/// ihre Quarantaene entsteht in `ea-archive`.
///
/// Ein Bruch der Vorgaengerbindung bei zusammenhaengenden Sequenzen ist ein
/// BEFUND ueber den Bestand und erscheint in [`VerifiedChain::breaks`];
/// eine Kettenspaltung ebenso in [`VerifiedChain::forks`].
/// [`VerifiedChain::verified_head`] haelt dann vor der kleinsten gebrochenen
/// oder gespaltenen Sequenz an, waehrend [`VerifiedChain::head`] die hoechste
/// gesehene Sequenz bleibt. Enthaelt die Eingabe keinen Knoten mit Sequenz 0,
/// beginnt die
/// verifizierte Fortschreibung beim niedrigsten vorhandenen Knoten; das
/// Fehlen des Genesis-Knotens ist kein Fehler dieser Funktion, sondern
/// ebenfalls ein BEFUND: ein [`ChainGap`] `0..=0` in
/// [`VerifiedChain::gaps`]. Fehlende Sequenzen unterhalb der hoechsten
/// gesehenen werden dort zu maximalen zusammenhaengenden Intervallen
/// zusammengefasst; ein [`ChainNodeKind::DestroyedStub`](crate::ChainNodeKind)
/// besetzt seine Sequenz und ist nie Teil einer Luecke.
///
/// # Errors
///
/// - [`ChainError::NodeLimit`], wenn `nodes` mehr als [`MAX_CHAIN_NODES_V1`]
///   Eintraege hat.
/// - [`ChainError::ForeignChainId`], wenn ein Knoten eine andere `chain_id`
///   traegt als `chain_id`.
/// - [`ChainError::GenesisBinding`], wenn Sequenz 0 einen Vorgaengerhash
///   traegt oder eine Sequenz groesser 0 keinen.
pub fn build_chain(chain_id: ChainId, nodes: &[ChainNode]) -> Result<VerifiedChain, ChainError> {
    if nodes.len() > MAX_CHAIN_NODES_V1 {
        return Err(ChainError::NodeLimit);
    }

    for node in nodes {
        if node.chain_id != chain_id {
            return Err(ChainError::ForeignChainId);
        }
        let is_genesis = node.chain_sequence.get() == 0;
        if is_genesis != node.previous_entry_hash.is_none() {
            return Err(ChainError::GenesisBinding);
        }
    }

    let mut sorted = nodes.to_vec();
    sorted.sort_unstable_by_key(|node| (node.chain_sequence, node.entry_hash, node.object_hash));
    sorted.dedup();

    // Eine Sequenz traegt im Regelfall genau einen Knoten. Die Gruppierung
    // haelt den Ausnahmefall aus, ohne ihn zu bestrafen, und ist die einzige
    // Stelle, an der der Bestand nach Sequenzen zerlegt wird.
    let groups: Vec<&[ChainNode]> = sorted
        .chunk_by(|left, right| left.chain_sequence == right.chain_sequence)
        .collect();

    let forks = collect_forks(chain_id, &sorted, &groups);
    let breaks = collect_breaks(&groups);
    let stop = first_disputed_sequence(&forks, &breaks);
    let verified_head = walk_verified_prefix(&groups, stop);
    let head = sorted.last().map(head_of);
    let gaps = collect_gaps(chain_id, &sorted);

    Ok(VerifiedChain {
        chain_id,
        nodes: sorted,
        breaks,
        forks,
        gaps,
        head,
        verified_head,
    })
}

/// Eine Seite einer Kollision: ein Eintragshash mit seinen kleinsten Begleitern.
///
/// Traegt eine Seite mehrere Knoten mit demselben Eintragshash, zaehlt jeweils
/// der kleinste Objekthash und die kleinste Sequenz — beides bytewise bzw.
/// numerisch, damit der Befund nicht von der Eingabereihenfolge abhaengt.
#[derive(Clone, Copy)]
struct Competitor {
    entry_hash: EntryHash,
    object_hash: ObjectHash,
    sequence: ChainSequence,
}

/// Fasst nach `entry_hash` benachbarte Knoten zu je einer Kollisionsseite
/// zusammen. Die Eingabe MUSS nach `entry_hash` gruppiert sein.
fn competitors<'nodes>(nodes: impl Iterator<Item = &'nodes ChainNode>) -> Vec<Competitor> {
    let mut sides: Vec<Competitor> = Vec::new();
    for node in nodes {
        match sides.last_mut() {
            Some(last) if last.entry_hash == node.entry_hash => {
                last.object_hash = last.object_hash.min(node.object_hash);
                last.sequence = last.sequence.min(node.chain_sequence);
            }
            _ => sides.push(Competitor {
                entry_hash: node.entry_hash,
                object_hash: node.object_hash,
                sequence: node.chain_sequence,
            }),
        }
    }
    sides
}

fn fork_of(
    chain_id: ChainId,
    left: Competitor,
    right: Competitor,
    form: ChainForkForm,
) -> ChainFork {
    let mut competing_entry_hashes = [left.entry_hash, right.entry_hash];
    competing_entry_hashes.sort_unstable();
    let mut competing_object_hashes = [left.object_hash, right.object_hash];
    competing_object_hashes.sort_unstable();
    ChainFork {
        chain_id,
        // Die kleinere der beiden Sequenzen: dort wird die Kettenidentitaet
        // zum ersten Mal mehrdeutig.
        sequence: left.sequence.min(right.sequence),
        competing_entry_hashes,
        competing_object_hashes,
        form,
    }
}

/// Sammelt beide Kollisionsformen.
///
/// Kollidiert ein Paar in beiden Formen — der Regelfall zweier Kinder desselben
/// Vorgaengers auf derselben Sequenz —, entsteht GENAU EIN Befund als
/// [`ChainForkForm::SequenceCollision`]. Die Sequenzkollisionen werden deshalb
/// zuerst gesammelt und ihre Paare als Schluessel gemerkt; die
/// Vorgaengerkollisionen ueberspringen jedes bereits gemeldete Paar. Der
/// Vergleich laeuft ueber eine sortierte Liste mit `binary_search`, nicht ueber
/// eine `HashSet`, damit keine Iterationsreihenfolge ins Ergebnis sickert.
fn collect_forks(
    chain_id: ChainId,
    sorted: &[ChainNode],
    groups: &[&[ChainNode]],
) -> Vec<ChainFork> {
    let mut forks = Vec::new();
    let mut sequence_pairs: Vec<[EntryHash; 2]> = Vec::new();

    for group in groups {
        // Innerhalb der Gruppe ist nach `entry_hash` sortiert.
        for pair in competitors(group.iter()).windows(2) {
            let fork = fork_of(chain_id, pair[0], pair[1], ChainForkForm::SequenceCollision);
            sequence_pairs.push(fork.competing_entry_hashes);
            forks.push(fork);
        }
    }
    sequence_pairs.sort_unstable();

    // Genesis traegt keinen Vorgaenger; zwei Genesisknoten kollidieren bereits
    // ueber ihre Sequenz und brauchen keine zweite Meldung.
    let mut by_predecessor: Vec<&ChainNode> = sorted
        .iter()
        .filter(|node| node.previous_entry_hash.is_some())
        .collect();
    by_predecessor.sort_unstable_by_key(|node| {
        (
            node.previous_entry_hash,
            node.entry_hash,
            node.object_hash,
            node.chain_sequence,
        )
    });

    for group in
        by_predecessor.chunk_by(|left, right| left.previous_entry_hash == right.previous_entry_hash)
    {
        for pair in competitors(group.iter().copied()).windows(2) {
            let fork = fork_of(
                chain_id,
                pair[0],
                pair[1],
                ChainForkForm::PredecessorCollision,
            );
            if sequence_pairs
                .binary_search(&fork.competing_entry_hashes)
                .is_err()
            {
                forks.push(fork);
            }
        }
    }

    forks.sort_unstable_by_key(|fork| (fork.sequence, fork.competing_entry_hashes[0]));
    forks
}

/// Sammelt die Knoten, deren Vorgaengerbindung auf KEINEN Knoten der
/// unmittelbar vorangehenden Sequenz zeigt.
///
/// Geprueft wird gegen die gesamte Vorgaengersequenz, nicht gegen einen
/// einzelnen Knoten. Bei einer Sequenzkollision haette der Vergleich gegen
/// einen willkuerlich gewaehlten Knoten der Vorgaengersequenz einen
/// Phantombruch zur Folge — und der wuerde in Task 16 ein unschuldiges Objekt
/// in Quarantaene schicken.
///
/// Fehlt die Vorgaengersequenz ganz, entsteht KEIN Bruch: das ist eine Luecke,
/// und ueber die Bindung eines fehlenden Knotens ist nichts auszusagen.
///
/// `expected_previous_entry_hash` ist der kleinste Eintragshash der
/// Vorgaengersequenz; im Regelfall ist er der einzige.
fn collect_breaks(groups: &[&[ChainNode]]) -> Vec<ChainBreak> {
    let mut breaks = Vec::new();

    for pair in groups.windows(2) {
        let (preceding, group) = (pair[0], pair[1]);
        let sequence = group[0].chain_sequence;
        if preceding[0].chain_sequence.get().checked_add(1) != Some(sequence.get()) {
            continue;
        }
        for node in group {
            let Some(actual) = node.previous_entry_hash else {
                continue;
            };
            // Die Gruppe ist nach `entry_hash` sortiert.
            if preceding
                .binary_search_by(|candidate| candidate.entry_hash.cmp(&actual))
                .is_err()
            {
                breaks.push(ChainBreak {
                    sequence,
                    expected_previous_entry_hash: preceding[0].entry_hash,
                    actual_previous_entry_hash: actual,
                    object_hash: node.object_hash,
                });
            }
        }
    }

    breaks
}

/// Kleinste Sequenz, ab der die Kette strittig ist — Fork oder Bruch.
fn first_disputed_sequence(forks: &[ChainFork], breaks: &[ChainBreak]) -> Option<ChainSequence> {
    forks
        .iter()
        .map(|fork| fork.sequence)
        .chain(breaks.iter().map(|entry| entry.sequence))
        .min()
}

/// Laeuft vom niedrigsten vorhandenen Knoten aus, solange die Sequenzen
/// lueckenlos aufeinander folgen und jede ihren Vorgaenger bindet, und haelt
/// SPAETESTENS vor `stop` an.
///
/// Die Grenze wird im Lauf geprueft, nicht nachtraeglich abgeschnitten: liegt
/// der erste Befund auf der niedrigsten vorhandenen Sequenz, bleibt kein
/// unstrittiges Praefix uebrig, und das Ergebnis ist `None`.
///
/// Unterhalb von `stop` traegt jede Sequenz genau einen Eintragshash — sonst
/// waere sie eine Sequenzkollision und damit selbst `stop`. Der kleinste
/// Knoten der Gruppe steht deshalb stellvertretend fuer die Sequenz.
fn walk_verified_prefix(groups: &[&[ChainNode]], stop: Option<ChainSequence>) -> Option<ChainHead> {
    let mut verified: Option<ChainHead> = None;

    for group in groups {
        let node = &group[0];
        if stop.is_some_and(|stop| node.chain_sequence >= stop) {
            break;
        }
        // Der niedrigste vorhandene Knoten eroeffnet das Praefix; jeder weitere
        // muss lueckenlos folgen UND seinen Vorgaenger binden.
        let continues = verified.is_none_or(|preceding| {
            preceding.chain_sequence.get().checked_add(1) == Some(node.chain_sequence.get())
                && node.previous_entry_hash == Some(preceding.entry_hash)
        });
        if !continues {
            break;
        }
        verified = Some(head_of(node));
    }

    verified
}

/// Fasst die fehlenden Sequenzen aufsteigend sortierter Knoten zu maximalen
/// zusammenhaengenden Intervallen zusammen.
///
/// Ein Cursor laeuft ab Sequenz 0 mit; jede Sequenz oberhalb des Cursors
/// eroeffnet und schliesst genau ein Intervall. Es zaehlt nur die BESETZUNG
/// einer Sequenz, nicht die Art des Knotens: ein `DestroyedStub` fuellt seine
/// Sequenz genauso wie ein Eintragspaket, und zwei Knoten auf derselben
/// Sequenz lassen den Cursor unveraendert (Vergleich mit `>`, nicht mit `!=`).
///
/// `ChainSequence` ist `u64`. Ein Knoten bei `u64::MAX` darf weder ueberlaufen
/// noch panisch werden, deshalb wird ausschliesslich mit `checked_add` und
/// `checked_sub` gerechnet. Oberhalb des hoechsten Knotens entsteht nie ein
/// Intervall, weil ueber nicht existierende Fortsetzungen keine Aussage
/// moeglich ist.
fn collect_gaps(chain_id: ChainId, sorted: &[ChainNode]) -> Vec<ChainGap> {
    let mut gaps = Vec::new();
    let mut expected: u64 = 0;

    for node in sorted {
        let sequence = node.chain_sequence.get();
        if sequence > expected {
            let Some(through) = sequence.checked_sub(1) else {
                continue;
            };
            gaps.push(ChainGap {
                chain_id,
                from_sequence: ChainSequence::new(expected),
                through_sequence: ChainSequence::new(through),
            });
        }
        // Bei `u64::MAX` gibt es keine naechste erwartete Sequenz. Der Cursor
        // bleibt dann auf `u64::MAX` stehen, sodass ein weiterer Knoten auf
        // derselben Sequenz wegen `>` keine zweite Luecke erzeugt.
        expected = sequence.checked_add(1).unwrap_or(sequence);
    }

    gaps
}
