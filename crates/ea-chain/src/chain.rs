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
    nodes: Vec<ChainNode>,
    breaks: Vec<ChainBreak>,
    gaps: Vec<ChainGap>,
    head: Option<ChainHead>,
    verified_head: Option<ChainHead>,
}

impl VerifiedChain {
    /// Alle Knoten in der deterministischen Reihenfolge `(chain_sequence,
    /// entry_hash, object_hash)`. Die Reihenfolge ist Teil des Vertrags; der
    /// dritte Bestandteil macht den Schluessel total, damit zwei Knoten mit
    /// gleicher Sequenz und gleichem Eintragshash nicht von der
    /// Eingabereihenfolge abhaengen.
    #[must_use]
    pub fn nodes(&self) -> &[ChainNode] {
        &self.nodes
    }

    /// Alle Vorgaengerbrueche in Sequenzreihenfolge.
    #[must_use]
    pub fn breaks(&self) -> &[ChainBreak] {
        &self.breaks
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
    /// Vorgaengerbindung erreicht wird.
    #[must_use]
    pub const fn verified_head(&self) -> Option<ChainHead> {
        self.verified_head
    }

    /// Kettenaussage: kein Bruch und keine Luecke.
    ///
    /// Das ist die Aussage ueber die KETTE, nicht ueber den Pruefbericht. Der
    /// Bericht leitet seine eigene, breitere Aussage ab (Formatfehler,
    /// Quarantaene, Signatur- und Nachweisfehler).
    #[must_use]
    pub fn is_fully_verified(&self) -> bool {
        self.breaks().is_empty() && self.gaps().is_empty()
    }
}

impl fmt::Debug for VerifiedChain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedChain { head: ")?;
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
/// Ein Bruch der Vorgaengerbindung bei zusammenhaengenden Sequenzen ist ein
/// BEFUND ueber den Bestand und erscheint in [`VerifiedChain::breaks`];
/// [`VerifiedChain::verified_head`] haelt dann vor der ersten gebrochenen
/// Sequenz an, waehrend [`VerifiedChain::head`] die hoechste gesehene Sequenz
/// bleibt. Enthaelt die Eingabe keinen Knoten mit Sequenz 0, beginnt die
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

    let mut breaks = Vec::new();
    let mut verified_head = None;
    let mut still_verified = true;
    let mut previous: Option<&ChainNode> = None;

    for node in &sorted {
        match previous {
            None => {
                verified_head = Some(head_of(node));
            }
            Some(preceding) => {
                let consecutive = preceding.chain_sequence.get().checked_add(1)
                    == Some(node.chain_sequence.get());
                if !consecutive {
                    // Luecke oder Fork. Beides diagnostiziert Task 9; hier
                    // endet nur die verifizierte Fortschreibung.
                    still_verified = false;
                } else if let Some(actual) = node.previous_entry_hash {
                    if actual == preceding.entry_hash {
                        if still_verified {
                            verified_head = Some(head_of(node));
                        }
                    } else {
                        breaks.push(ChainBreak {
                            sequence: node.chain_sequence,
                            expected_previous_entry_hash: preceding.entry_hash,
                            actual_previous_entry_hash: actual,
                            object_hash: node.object_hash,
                        });
                        still_verified = false;
                    }
                }
            }
        }
        previous = Some(node);
    }

    let head = sorted.last().map(head_of);
    let gaps = collect_gaps(chain_id, &sorted);

    Ok(VerifiedChain {
        nodes: sorted,
        breaks,
        gaps,
        head,
        verified_head,
    })
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
