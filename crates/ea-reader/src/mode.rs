//! Die zwei Betriebsarten des Readers.

/// Die zwei Wege, auf denen der Reader an Archivbytes kommt.
///
/// GESCHLOSSEN und ZWEIWERTIG, nach
/// `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §5.1
/// und §5.2. Es gibt keinen dritten Modus und insbesondere keinen gemischten:
/// der Cursor-Mechanismus entfaellt im Datei-Modus ersatzlos (§5.3), und ein
/// Wert, der beides zugleich behauptete, waere die Stelle, an der genau das
/// wieder zusammenliefe.
///
/// Ein Aufzaehlungstyp und kein `&str`: eine Zeichenkette liesse einen
/// unbekannten Modus bis in die Verifikation durchlaufen, wo er als „weder noch"
/// still das Falsche taete.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReaderMode {
    /// Der Reader spricht mit dem Sync-Server und laedt Objekte einzeln nach.
    Server,
    /// Der Reader liest EINE exportierte Buendeldatei aus dem Dateidialog.
    File,
}

impl ReaderMode {
    /// Beide Modi, in der Reihenfolge von §5.1 und §5.2.
    ///
    /// Die Liste ist die ausfuehrbare Fassung der Geschlossenheit: wer eine
    /// dritte Variante ergaenzt, muss sie hier eintragen, und der Zeuge in
    /// `crates/ea-reader-wasm/tests/bridge_boundary.rs` wird rot, bevor
    /// irgendein Aufrufer die neue Variante uebersieht.
    pub const ALL: [Self; 2] = [Self::Server, Self::File];

    /// Der stabile Code des Modus.
    ///
    /// Er verlaesst die Crate — die Bruecke reicht ihn nach JavaScript, und ein
    /// Protokolleintrag nennt ihn. Tests assertieren gegen ihn und nie gegen
    /// eine Formatierung, dieselbe Regel wie bei `BundleError::code`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::File => "file",
        }
    }
}
