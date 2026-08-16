use core::fmt;

use ea_types::{ChainId, ChainSequence, EntryHash, ObjectHash};

use crate::chain::VerifiedChain;
use crate::node::hex;

/// Eine signierte Serveraussage ueber einen frueheren Kettenkopf, als reiner
/// Wert.
///
/// `ea-chain` parst keine `.ecp`-Datei und prueft keine Signatur. Der Aufrufer
/// legt hier ausschliesslich Aussagen ab, die er BEREITS als authentisch
/// nachgewiesen hat; ein unbestaetigter Checkpoint darf nie zu einem Claim
/// werden, sonst wuerde ein untergeschobenes Objekt einen Rollback behaupten.
///
/// [`Self::covered_from_sequence`] gehoert zur Aussage, weil ein Checkpoint ein
/// INTERVALL bezeugt. Die Rollback-Pruefung benutzt nur die Obergrenze: eine
/// Aussage ueber den Kopf ist eine Aussage darueber, wie weit die Kette
/// mindestens reichte.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CheckpointClaim {
    /// Kette, ueber die der Checkpoint spricht.
    pub chain_id: ChainId,
    /// Erste vom Checkpoint abgedeckte Sequenz, einschliesslich.
    pub covered_from_sequence: ChainSequence,
    /// Letzte vom Checkpoint abgedeckte Sequenz, einschliesslich. Sie ist die
    /// bezeugte Kopfsequenz.
    pub covered_through_sequence: ChainSequence,
    /// Eintragshash, den der Server fuer
    /// [`Self::covered_through_sequence`] bezeugt hat.
    pub head_entry_hash: EntryHash,
    /// Objekthash des Checkpoints selbst — die Herkunft der Aussage.
    pub checkpoint_object_hash: ObjectHash,
}

impl fmt::Debug for CheckpointClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointClaim { chain_id: ")?;
        hex(self.chain_id.as_bytes(), formatter)?;
        write!(
            formatter,
            ", covered_from_sequence: {}, covered_through_sequence: {}",
            self.covered_from_sequence.get(),
            self.covered_through_sequence.get()
        )?;
        formatter.write_str(", head_entry_hash: ")?;
        hex(self.head_entry_hash.as_bytes(), formatter)?;
        formatter.write_str(", checkpoint_object_hash: ")?;
        hex(self.checkpoint_object_hash.as_bytes(), formatter)?;
        formatter.write_str(" }")
    }
}

/// Ein einzelner Rollback-Befund.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RollbackFinding {
    /// Der Bestand reicht nicht bis zu der Sequenz, die der Checkpoint bezeugt.
    ///
    /// Zwei Ausloeser, beide mit derselben Aussage — der Bestand haelt die
    /// bezeugte Sequenz nicht verifiziert vor:
    ///
    /// 1. `verified_head_sequence < covered_through_sequence`, einschliesslich
    ///    `verified_head_sequence == None` (gar kein unstrittiges Praefix).
    /// 2. Die bezeugte Sequenz liegt UNTERHALB des niedrigsten vorhandenen
    ///    Knotens. Das verifizierte Praefix beginnt beim niedrigsten Knoten,
    ///    nicht zwingend bei Genesis; ohne diesen zweiten Ausloeser fiele ein
    ///    unten abgeschnittener Bestand durch die Zahlenpruefung und waere
    ///    faelschlich [`RollbackAssessment::Consistent`].
    TruncatedBelowCheckpoint {
        /// Bezeugte Kopfsequenz.
        covered_through_sequence: ChainSequence,
        /// Letzte unstrittige Sequenz des Bestands, `None` ohne unstrittiges
        /// Praefix. `None` und `Some(0)` sind verschiedene Aussagen und
        /// ergeben verschiedene bewiesene Intervalle, deshalb `Option` statt
        /// eines Sentinels.
        verified_head_sequence: Option<ChainSequence>,
        /// Objekthash des Checkpoints, der die Sequenz bezeugt.
        checkpoint_object_hash: ObjectHash,
    },
    /// Die bezeugte Sequenz existiert, traegt aber einen anderen Eintragshash.
    HeadEntryHashMismatch {
        /// Strittige Sequenz — die bezeugte Kopfsequenz.
        sequence: ChainSequence,
        /// Eintragshash laut Checkpoint.
        checkpoint_head_entry_hash: EntryHash,
        /// Eintragshash laut Bestand.
        chain_entry_hash: EntryHash,
        /// Objekthash des Checkpoints, der die Aussage traegt.
        checkpoint_object_hash: ObjectHash,
        /// Objekthash des Archivobjekts, das der Aussage widerspricht. Task 16
        /// quarantaeniert genau dieses Objekt mit `reason = "conflicting"`.
        conflicting_object_hash: ObjectHash,
    },
}

impl RollbackFinding {
    /// Das per Checkpoint BEWIESENE Intervall fehlender Sequenzen,
    /// `verified_head_sequence + 1 ..= covered_through_sequence`.
    ///
    /// Task 16 macht daraus die `gaps`-Eintraege des Pruefberichts. Der Befund
    /// gehoert dorthin und nicht in eine Quarantaene, weil es kein Objekt gibt,
    /// das man quarantaenieren koennte — es fehlt ja gerade.
    ///
    /// `None`, wenn kein Intervall folgt: bei einer Kopfabweichung (sie
    /// beweist keine Luecke), bei einer Truncation unterhalb des niedrigsten
    /// Knotens (dort ist die Untergrenze bereits groesser als die Obergrenze,
    /// und die Luecke steht ohnehin schon in
    /// [`VerifiedChain::gaps`](crate::VerifiedChain::gaps)) und bei einem
    /// verifizierten Kopf auf `u64::MAX`, wo es keine naechste Sequenz gibt.
    #[must_use]
    pub fn proven_missing_sequences(&self) -> Option<(ChainSequence, ChainSequence)> {
        let Self::TruncatedBelowCheckpoint {
            covered_through_sequence,
            verified_head_sequence,
            ..
        } = self
        else {
            return None;
        };
        let from = match verified_head_sequence {
            // `ChainSequence` ist `u64`. Bei `u64::MAX` gibt es keine naechste
            // Sequenz; dann entsteht kein Intervall statt eines Ueberlaufs.
            Some(verified) => verified.get().checked_add(1)?,
            None => 0,
        };
        if from > covered_through_sequence.get() {
            return None;
        }
        Some((ChainSequence::new(from), *covered_through_sequence))
    }

    /// Sortierschluessel: bezeugte Sequenz, dann Herkunft der Aussage.
    fn sort_key(&self) -> (ChainSequence, ObjectHash) {
        match self {
            Self::TruncatedBelowCheckpoint {
                covered_through_sequence,
                checkpoint_object_hash,
                ..
            } => (*covered_through_sequence, *checkpoint_object_hash),
            Self::HeadEntryHashMismatch {
                sequence,
                checkpoint_object_hash,
                ..
            } => (*sequence, *checkpoint_object_hash),
        }
    }
}

impl fmt::Debug for RollbackFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedBelowCheckpoint {
                covered_through_sequence,
                verified_head_sequence,
                checkpoint_object_hash,
            } => {
                write!(
                    formatter,
                    "TruncatedBelowCheckpoint {{ covered_through_sequence: {}, verified_head_sequence: ",
                    covered_through_sequence.get()
                )?;
                match verified_head_sequence {
                    Some(verified) => write!(formatter, "{}", verified.get())?,
                    None => formatter.write_str("none")?,
                }
                formatter.write_str(", checkpoint_object_hash: ")?;
                hex(checkpoint_object_hash.as_bytes(), formatter)?;
                formatter.write_str(" }")
            }
            Self::HeadEntryHashMismatch {
                sequence,
                checkpoint_head_entry_hash,
                chain_entry_hash,
                checkpoint_object_hash,
                conflicting_object_hash,
            } => {
                write!(
                    formatter,
                    "HeadEntryHashMismatch {{ sequence: {}, checkpoint_head_entry_hash: ",
                    sequence.get()
                )?;
                hex(checkpoint_head_entry_hash.as_bytes(), formatter)?;
                formatter.write_str(", chain_entry_hash: ")?;
                hex(chain_entry_hash.as_bytes(), formatter)?;
                formatter.write_str(", checkpoint_object_hash: ")?;
                hex(checkpoint_object_hash.as_bytes(), formatter)?;
                formatter.write_str(", conflicting_object_hash: ")?;
                hex(conflicting_object_hash.as_bytes(), formatter)?;
                formatter.write_str(" }")
            }
        }
    }
}

/// Ergebnis der Rollback-Pruefung.
///
/// # Abbildung in den Pruefbericht
///
/// `schemas/reports/v1/verification-report.schema.json` ist durch Phase A
/// geschlossen und kennt kein Rollback-Feld. Task 16 bildet deshalb ab:
///
/// - [`RollbackFinding::TruncatedBelowCheckpoint`] wird zu `gaps`-Eintraegen
///   ueber [`RollbackFinding::proven_missing_sequences`]. Eine per Checkpoint
///   BEWIESENE Luecke gehoert in `gaps` und nicht in eine Quarantaene, weil es
///   kein Objekt gibt, das man quarantaenieren koennte.
/// - [`RollbackFinding::HeadEntryHashMismatch`] wird zu einem
///   `quarantinedObjects`-Eintrag mit `reason = "conflicting"` fuer
///   `conflicting_object_hash`.
/// - [`Self::NotAssessable`] erzeugt KEINEN Reporteintrag und senkt
///   `is_fully_verified()` NICHT. Nicht pruefbar ist kein Mangel des Bestands,
///   sondern das Fehlen einer Referenz; ein Archiv ohne `.ecp` waere sonst
///   dauerhaft unvollstaendig. Sichtbar wird der Zustand ueber diesen Wert und
///   in Stage-1 Task 10 an der CLI.
#[derive(Clone, Eq, PartialEq)]
pub enum RollbackAssessment {
    /// Keine verwertbare Checkpoint-Aussage. Ueber Rollback ist NICHTS gesagt —
    /// insbesondere NICHT, dass keiner vorliegt.
    NotAssessable,
    /// Jede verwertbare Aussage wurde positiv gegen das verifizierte Praefix
    /// abgeglichen.
    Consistent,
    /// Mindestens ein Widerspruch. Die Liste ist nie leer und aufsteigend nach
    /// `(bezeugte Sequenz, checkpoint_object_hash)` sortiert.
    Rollback(Vec<RollbackFinding>),
}

impl fmt::Debug for RollbackAssessment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAssessable => formatter.write_str("NotAssessable"),
            Self::Consistent => formatter.write_str("Consistent"),
            Self::Rollback(findings) => {
                formatter.write_str("Rollback([")?;
                for (index, finding) in findings.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{finding:?}")?;
                }
                formatter.write_str("])")
            }
        }
    }
}

/// Prueft die Kette gegen bereits authentifizierte Checkpoint-Aussagen.
///
/// Ein Rueckbau ist NUR gegen Checkpoints definierbar: ohne eine signierte
/// Serveraussage ueber einen frueheren Kopf gibt es keine Referenz, gegen die
/// ein Rollback erkennbar waere. Deshalb ergeben eine leere `claims`-Liste und
/// eine Liste, die nach dem Aussortieren fremder Ketten leer ist, IMMER
/// [`RollbackAssessment::NotAssessable`] — auch bei makelloser Kette. Eine
/// Aussage ueber eine fremde Kette ist keine Aussage ueber diese und zaehlt
/// nicht als Referenz.
///
/// [`RollbackAssessment::Consistent`] entsteht ausschliesslich durch positiven
/// Abgleich: jede verbliebene Aussage muss auf einen Knoten des verifizierten
/// Praefixes mit dem bezeugten Eintragshash treffen. Kein Zweig faellt in
/// `Consistent` durch, weil er unbehandelt blieb — `Consistent` ist die
/// affirmative Aussage "kein Rollback" und darf nie durch Auslassung entstehen.
///
/// Geprueft wird gegen [`VerifiedChain::verified_head`], nicht gegen
/// [`VerifiedChain::head`]: ein Knoten jenseits eines Forks oder Bruchs ist
/// keine Grundlage, um eine Serveraussage zu bestaetigen.
#[must_use]
pub fn assess_rollback(chain: &VerifiedChain, claims: &[CheckpointClaim]) -> RollbackAssessment {
    let chain_id = chain.chain_id();

    // Deterministisch: gleiche Aussagenmenge, gleiche Befundfolge, unabhaengig
    // von der Eingabereihenfolge. Bytegleiche Aussagen zaehlen einmal.
    let mut relevant: Vec<CheckpointClaim> = claims
        .iter()
        .copied()
        .filter(|claim| claim.chain_id == chain_id)
        .collect();
    relevant.sort_unstable_by_key(|claim| {
        (
            claim.covered_through_sequence,
            claim.checkpoint_object_hash,
            claim.head_entry_hash,
            claim.covered_from_sequence,
        )
    });
    relevant.dedup();

    if relevant.is_empty() {
        return RollbackAssessment::NotAssessable;
    }

    let verified_head = chain.verified_head();
    let verified_head_sequence = verified_head.map(|head| head.chain_sequence());

    let mut findings = Vec::new();
    for claim in relevant {
        let truncated = RollbackFinding::TruncatedBelowCheckpoint {
            covered_through_sequence: claim.covered_through_sequence,
            verified_head_sequence,
            checkpoint_object_hash: claim.checkpoint_object_hash,
        };

        // Ausloeser 1: der unstrittige Teil reicht nicht bis zur bezeugten
        // Sequenz. Der Server hat sie nachweislich gesehen, der Bestand nicht.
        if verified_head_sequence.is_none_or(|verified| verified < claim.covered_through_sequence) {
            findings.push(truncated);
            continue;
        }

        // Ausloeser 2: die bezeugte Sequenz liegt unterhalb des niedrigsten
        // vorhandenen Knotens und fehlt damit ebenfalls.
        let Some(node) = verified_node_at(chain, claim.covered_through_sequence) else {
            findings.push(truncated);
            continue;
        };

        if node.entry_hash != claim.head_entry_hash {
            findings.push(RollbackFinding::HeadEntryHashMismatch {
                sequence: claim.covered_through_sequence,
                checkpoint_head_entry_hash: claim.head_entry_hash,
                chain_entry_hash: node.entry_hash,
                checkpoint_object_hash: claim.checkpoint_object_hash,
                conflicting_object_hash: node.object_hash,
            });
        }
    }

    if findings.is_empty() {
        return RollbackAssessment::Consistent;
    }

    findings.sort_unstable_by_key(RollbackFinding::sort_key);
    RollbackAssessment::Rollback(findings)
}

/// Der Knoten auf `sequence`, sofern vorhanden.
///
/// Der Aufrufer hat bereits sichergestellt, dass `sequence` nicht ueber dem
/// verifizierten Kopf liegt. Unterhalb davon traegt jede besetzte Sequenz genau
/// einen Eintragshash — andernfalls waere sie eine Sequenzkollision und damit
/// selbst die Grenze des verifizierten Praefixes. Bei mehreren Knoten mit
/// gleichem Eintragshash und verschiedenem Objekthash zaehlt der kleinste
/// Objekthash; `VerifiedChain::nodes` ist nach `(chain_sequence, entry_hash,
/// object_hash)` sortiert, weshalb der erste Treffer der Gruppe deterministisch
/// ist.
fn verified_node_at(chain: &VerifiedChain, sequence: ChainSequence) -> Option<&crate::ChainNode> {
    let nodes = chain.nodes();
    let index = nodes.partition_point(|node| node.chain_sequence < sequence);
    nodes
        .get(index)
        .filter(|node| node.chain_sequence == sequence)
}
