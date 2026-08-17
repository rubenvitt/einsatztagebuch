use core::fmt;
use std::io;

use ea_trust::TrustError;
use ea_verify::VerifyError;

/// Fehler eines Wiederherstellungslaufs.
///
/// Wie [`ea_archive::ArchiveError`] beschreibt diese Aufzaehlung
/// AUSSCHLIESSLICH, dass ein Lauf nicht durchgefuehrt werden kann — nie einen
/// Befund ueber den Bestand. Befunde stehen im Verifikationsbericht; ein
/// Bestand mit Mangel ist ein erfolgreicher Lauf mit einem Bericht, der den
/// Mangel benennt.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum RecoveryError {
    /// Das Dateisystem konnte einen Schritt nicht ausfuehren.
    ///
    /// Traegt AUSSCHLIESSLICH die [`io::ErrorKind`] und niemals den
    /// zugrunde liegenden [`io::Error`]. Dessen Anzeige nimmt je nach
    /// Aufrufpfad den Hostpfad auf, und ein Hostpfad darf nach der Global
    /// Constraint des Stage-1-Plans weder in eine Diagnose noch ueber sie in
    /// eine Ausgabe gelangen. Die Fehlerart genuegt fuer die Entscheidung und
    /// benennt nichts, was zum Bestand gehoert.
    Io(io::ErrorKind),
    /// Der Bestand uebersteigt
    /// [`ea_archive::MAX_TOTAL_ARCHIVE_BYTES_V1`].
    ///
    /// AUSDRUECKLICH NICHT dasselbe wie
    /// [`ea_archive::ArchiveError::TotalByteLimit`]: dort urteilt das Inventar
    /// ueber einen bereits durchlaufenen Bestand, hier bricht das Einlesen ab,
    /// BEVOR der Puffer entsteht. Es wird kein Urteil dupliziert, sondern ein
    /// Puffer begrenzt.
    ArchiveTooLarge,
    /// Die gelesenen Ankerbytes sind kein gueltiger Trust Anchor.
    ///
    /// AUSDRUECKLICH KEIN Aufruffehler. `design.md`:1765 laesst dazu keinen
    /// Spielraum: „Jede Abweichung endet mit Exitcode 12." Ein untergeschobener
    /// oder verstuemmelter Anker ist ein VERTRAUENSBEFUND, und ihn als
    /// Bedienfehler zu melden verwischte genau die Grenze, die der Anker zieht.
    ///
    /// Scharf getrennt von [`Self::Io`]: dort war die Datei nicht LESBAR, hier
    /// war sie lesbar und PASST NICHT. Der Betreiber unterscheidet daran ein
    /// vergessenes Recovery-Medium von einem manipulierten Anker.
    TrustAnchor(TrustError),
    /// Die Verifikationspipeline konnte kein Urteil bilden.
    Verify(VerifyError),
}

impl RecoveryError {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Io(_) => "EA-RECOVERY-IO",
            Self::ArchiveTooLarge => "EA-RECOVERY-ARCHIVE-TOO-LARGE",
            Self::TrustAnchor(error) => error.code(),
            Self::Verify(error) => error.code(),
        }
    }
}

impl From<VerifyError> for RecoveryError {
    fn from(error: VerifyError) -> Self {
        Self::Verify(error)
    }
}

impl From<io::Error> for RecoveryError {
    /// Behaelt die Fehlerart und verwirft den Rest.
    ///
    /// Das Verwerfen ist der Zweck: alles Uebrige an einem [`io::Error`] kann
    /// einen Hostpfad tragen.
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for RecoveryError {
    /// Wie [`fmt::Display`], bei [`Self::Io`] zusaetzlich mit der Fehlerart.
    ///
    /// Die Art ist ein geschlossener Aufzaehlungswert der Standardbibliothek
    /// und benennt daher nichts aus dem Bestand — anders als Pfad oder Bytes,
    /// die hier niemals erscheinen.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(formatter, "{}({kind:?})", self.code()),
            _ => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for RecoveryError {}
