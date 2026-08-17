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
    /// Das Ziel eines schreibenden Kommandos EXISTIERT BEREITS.
    ///
    /// Eine eigene Variante und ausdruecklich kein
    /// [`Self::Io`]`(ErrorKind::AlreadyExists)`: die beiden sagen Verschiedenes.
    /// Ein Dateisystemfehler heisst „ich konnte den Schritt nicht ausfuehren"
    /// und endet mit Exitcode 20; ein belegtes Ziel heisst „so wie du es
    /// aufgerufen hast, fuehre ich den Lauf nicht aus" und ist damit ein
    /// KONFIGURATIONSFEHLER, also Exitcode 2. Der Betreiber unterscheidet daran
    /// eine volle Platte von einem Zielpfad, den er noch waehlen muss.
    ///
    /// Der Bestand ist dabei voellig unberuehrt — es wurde nichts gefunden,
    /// sondern nichts geschrieben.
    OutputExists,
    /// Die Datei hinter `--key` traegt kein Schluesselmaterial dieser Form.
    ///
    /// Exitcode 2 und ausdruecklich NICHT 14: Code 14 heisst „Schluessel fehlt
    /// oder Entschluesselung fehlgeschlagen" und ist eine Aussage ueber den
    /// LAUF gegen einen Bestand. Hier ist noch gar kein Lauf zustande gekommen
    /// — der Aufrufer hat eine Datei benannt, die keine 32 Rohbytes und keine
    /// 64 Hexzeichen enthaelt, und derselbe Aufruf ist mit einer anderen Datei
    /// unveraendert wiederholbar. Das ist dieselbe Aussage wie bei
    /// [`Self::OutputExists`]: am Bestand liegt es nicht.
    ///
    /// Scharf getrennt von [`Self::Io`]: dort war die Datei nicht LESBAR, hier
    /// war sie lesbar und traegt das Falsche.
    KeySource,
    /// Es gibt keinen Grant dieses Bestands auf den vorgelegten Schluessel.
    ///
    /// `ea-verify` meldet das AUSDRUECKLICH NICHT als Befund: ein fehlender
    /// eigener Grant laesst den Eintrag `valid` und erzeugt keinen
    /// `decryptionErrors`-Eintrag (`crates/ea-verify/src/recipient.rs:13-15`).
    /// Fuer die Verifikation ist das richtig — fuer `decrypt` waere es fatal:
    /// der Bericht ist makellos, `exit_code_for` saehe `Success`, und das
    /// Werkzeug meldete Erfolg ueber ein LEERES Ziel. Genau diesen Fall
    /// kuendigt `crate::exit_code_for` in seiner Notiz an: ein Kommando mit
    /// eigenen Abbruchgruenden bildet sie in SEINEM Pfad.
    ///
    /// Exitcode 14, „Schluessel fehlt": der vorgelegte Schluessel oeffnet
    /// diesen Bestand nicht.
    NoOwnGrant,
    /// Ein Grant liess sich nicht oeffnen, obwohl der Bericht makellos ist.
    ///
    /// FAIL-CLOSED UND IM REGELFALL UNERREICHBAR: derselbe Grant wurde im
    /// Verifikationslauf bereits mit demselben Schluessel geoeffnet, sonst
    /// stuende ein `decryptionErrors`-Eintrag im Bericht und der Lauf waere
    /// vorher geendet. Der Fall bleibt trotzdem behandelt — eine
    /// Entschluesselung, die nicht gelingt, darf nie als gelungen gelten.
    ///
    /// Deckt auch den gefallenen Waechter der Kontextrekonstruktion ab.
    /// `crates/ea-verify/src/recipient.rs:202` trifft dieselbe Wahl und meldet
    /// ihn als [`ea_verify::DecryptionErrorV1::CekUnwrapFailed`], also
    /// ebenfalls auf Exitcode 14.
    Decryption,
    /// Diese Plattform kann die verlangten Rechte nicht setzen.
    ///
    /// `decrypt` schreibt KLARTEXT. Die Zusicherung, dass Zielverzeichnis und
    /// Zieldatei allein ihrem Eigentuemer gehoeren, ist deshalb keine Zugabe,
    /// sondern Bedingung des Kommandos. Wo sie sich nicht setzen laesst, wird
    /// nicht ersatzweise ohne sie geschrieben, sondern gar nicht: Exitcode 21,
    /// „nicht unterstuetzte Plattformfaehigkeit".
    RestrictivePermissionsUnsupported,
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
            Self::OutputExists => "EA-RECOVERY-OUTPUT-EXISTS",
            Self::KeySource => "EA-RECOVERY-KEY-SOURCE",
            Self::NoOwnGrant => "EA-RECOVERY-NO-OWN-GRANT",
            Self::Decryption => "EA-RECOVERY-DECRYPTION",
            Self::RestrictivePermissionsUnsupported => {
                "EA-RECOVERY-RESTRICTIVE-PERMISSIONS-UNSUPPORTED"
            }
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
