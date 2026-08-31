use core::fmt;

use crate::ArchiveError;

/// Eine einzelne Bytesequenz des Bestands mitsamt ihrem Pfadhinweis.
///
/// Der Pfadhinweis ist ein HINWEIS: er benennt, wo die Bytes lagen, und wird
/// fuer Diagnose und Zuordnung mitgefuehrt. Er entscheidet nie darueber, ob
/// die Bytes ein Archivobjekt sind — das entscheidet ausschliesslich das
/// 9-Byte-Exact-Object-Praefix (`design.md` §11.4).
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ArchiveBlob<'a> {
    path_hint: &'a str,
    bytes: &'a [u8],
}

impl<'a> ArchiveBlob<'a> {
    #[must_use]
    pub const fn new(path_hint: &'a str, bytes: &'a [u8]) -> Self {
        Self { path_hint, bytes }
    }

    /// Wo die Bytes lagen. Diagnosewert, keine Klassifikationsgrundlage.
    #[must_use]
    pub const fn path_hint(&self) -> &'a str {
        self.path_hint
    }

    /// Die rohen Bytes, unveraendert wie geliefert.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

impl fmt::Debug for ArchiveBlob<'_> {
    /// Gibt Hinweis und Laenge aus, nie den Inhalt.
    ///
    /// Bestandsbytes koennen Ciphertext sein; ein Debug-Abzug davon gehoert in
    /// kein Protokoll.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArchiveBlob")
            .field("path_hint", &self.path_hint)
            .field("byte_length", &self.bytes.len())
            .finish()
    }
}

/// Der breite Port ueber ALLE Bytes eines Bestands.
///
/// Breiter als [`ea_trust::TrustObjectSource`]: dieser Port liefert auch
/// Beiwerk, das kein Exact-Object-Praefix traegt, denn nur so laesst sich
/// `nonObjectFileCount` ueberhaupt bilden. `TrustObjectSource` bleibt
/// unveraendert der schmale, archiv-agnostische Trust-Port; hier wird nichts
/// dupliziert und `ea-trust` erfaehrt nichts ueber Archivlayout.
///
/// Der Besucher wird beim Durchlaufen unmittelbar gerufen; es entsteht kein
/// zwischenzeitlicher unbeschraenkter Puffer. Liefert er einen Fehler, haelt
/// der Durchlauf VOR dem naechsten Element an und reicht den Fehler durch —
/// so setzt das Inventar [`MAX_ARCHIVE_BLOBS_V1`](crate::MAX_ARCHIVE_BLOBS_V1)
/// und [`MAX_TOTAL_ARCHIVE_BYTES_V1`](crate::MAX_TOTAL_ARCHIVE_BYTES_V1)
/// durch, ohne den Bestand vorher vollstaendig zu lesen.
///
/// Diese Crate enthaelt bewusst KEINE dateisystemgestuetzte Implementierung
/// und kein `std::fs`; eine solche entsteht ausserhalb.
/// [`ArchiveBundleSource`](crate::ArchiveBundleSource) ist keine Ausnahme
/// davon, sondern die zweite Lesart derselben Zusage: der Containerleser nimmt
/// Bytes entgegen und gibt Bytes heraus, und das Oeffnen einer Datei liegt
/// weiterhin ausserhalb, in `ea_archive_fs::open_archive_bundle`.
pub trait ArchiveSource {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError>;
}
