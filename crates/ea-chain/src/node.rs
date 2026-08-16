use core::fmt;

use ea_types::{CertificateHash, ChainId, ChainSequence, EntryHash, ObjectHash};

/// Schreibt `bytes` hexadezimal in Kleinbuchstaben.
///
/// `ea-types` leitet fuer seine Id- und Hash-Newtypes bewusst kein `Debug` ab
/// (`crates/ea-types/src/ids.rs`). `ea-chain` aendert `ea-types` nicht, sondern
/// implementiert `Debug` von Hand und gibt jede Id und jeden Hash ueber diesen
/// Helfer aus, damit ein fehlgeschlagener Test lesbar bleibt.
pub(crate) fn hex(bytes: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// Art eines Kettenknotens.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum ChainNodeKind {
    /// Ein Eintragspaket (Objekttyp 1).
    EntryPackage,
    /// Ein Stub eines autorisiert geloeschten Eintrags (Objekttyp 6).
    DestroyedStub,
}

impl ChainNodeKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::EntryPackage => "EntryPackage",
            Self::DestroyedStub => "DestroyedStub",
        }
    }
}

impl fmt::Debug for ChainNodeKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Ein Kettenknoten als reiner Wert.
///
/// Der Knoten traegt nur, was die Verkettungspruefung braucht. Er kennt weder
/// CBOR noch Signaturen; das Uebersetzen geparster Archivobjekte in Knoten ist
/// Sache von `ea-verify`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChainNode {
    /// Kette, zu der sich der Knoten bekennt.
    pub chain_id: ChainId,
    /// Position des Knotens in der Kette. Genesis ist 0.
    pub chain_sequence: ChainSequence,
    /// Vorgaengerbindung. Genau bei Genesis `None`, sonst `Some`.
    pub previous_entry_hash: Option<EntryHash>,
    /// Eintragshash dieses Knotens.
    pub entry_hash: EntryHash,
    /// Objekthash des Archivobjekts, aus dem der Knoten stammt.
    pub object_hash: ObjectHash,
    /// Zertifikat des schreibenden Geraets.
    pub writer_certificate_hash: CertificateHash,
    /// Uebergangsereignis, falls der Schreiber gewechselt hat.
    pub writer_transition_event_hash: Option<ObjectHash>,
    /// Art des Knotens.
    pub kind: ChainNodeKind,
}

impl fmt::Debug for ChainNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChainNode { chain_id: ")?;
        hex(self.chain_id.as_bytes(), formatter)?;
        write!(formatter, ", chain_sequence: {}", self.chain_sequence.get())?;
        formatter.write_str(", previous_entry_hash: ")?;
        match self.previous_entry_hash {
            Some(previous) => hex(previous.as_bytes(), formatter)?,
            None => formatter.write_str("none")?,
        }
        formatter.write_str(", entry_hash: ")?;
        hex(self.entry_hash.as_bytes(), formatter)?;
        formatter.write_str(", object_hash: ")?;
        hex(self.object_hash.as_bytes(), formatter)?;
        formatter.write_str(", writer_certificate_hash: ")?;
        hex(self.writer_certificate_hash.as_bytes(), formatter)?;
        formatter.write_str(", writer_transition_event_hash: ")?;
        match self.writer_transition_event_hash {
            Some(transition) => hex(transition.as_bytes(), formatter)?,
            None => formatter.write_str("none")?,
        }
        write!(formatter, ", kind: {} }}", self.kind.label())
    }
}
