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
    /// AUSDRUECKLICH KEIN Aufruffehler. `design.md`:1782 laesst dazu keinen
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
    /// Der Container ist dekodiert, seine Art passt, der KDF ist gelaufen —
    /// und die AEAD oeffnet nicht.
    ///
    /// Exitcode 14 und ausdruecklich NICHT 2, in scharfer Abgrenzung zu
    /// [`Self::KeySource`]: dort traegt die benannte Datei kein
    /// Schluesselmaterial dieser Form — kein Container, eine fremde Art, eine
    /// fremde Parametrierung —, und das ist eine Aussage ueber den AUFRUF.
    /// Hier hat die Datei die Form vollstaendig erfuellt: sie ist als
    /// Container gelesen, ihre Art ist die verlangte, ihre Parameter sind die
    /// gepinnten. Gescheitert ist erst die ENTSCHLUESSELUNG, und
    /// „Schluessel fehlt oder Entschluesselung fehlgeschlagen" ist nach
    /// `design.md`:1808 die Zeile 14.
    ///
    /// Drei Wege fuehren hierher, und alle drei bekommen DIESELBE Antwort,
    /// damit ein Angreifer aus dem Fehler nichts lernt: die falsche
    /// Passphrase, ein verkipptes Byte in Chiffrat oder Tag, und ein
    /// verkipptes Kopfbyte, das noch dekodiert, aber die AAD veraendert —
    /// Salz, Nonce, Art. Welcher es war, sagt die Poly1305-Pruefung nicht,
    /// und dieses Bauwerk sagt es deshalb auch nicht.
    ///
    /// Scharf getrennt von [`Self::Decryption`]: dort scheiterte ein GRANT
    /// des Bestands, hier die Huelle um den Schluessel, mit dem der Bestand
    /// erst geoeffnet werden sollte. Beide stehen auf 14, weil die Norm nicht
    /// danach fragt, welche Huelle es war.
    ContainerOpen,
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
    ///
    /// `export` faellt unter dieselbe Zusicherung. Seine Bytes sind zwar
    /// verschluesselt, aber `design.md`:1796 nennt beide Kommandos in EINEM
    /// Satz, und die Dateinamen eines Exports geben die Kettensequenzen des
    /// Bestands preis.
    RestrictivePermissionsUnsupported,
    /// Die benannte Exportquelle ist kein Bestand im Dateisystem.
    ///
    /// Die Grammatik nennt `<archive-or-server>`; Stage 1 hat keine
    /// Serverquelle. Ein Argument, das kein existierendes Verzeichnis ist, ist
    /// deshalb eine NICHT UNTERSTUETZTE Quellart und ausdruecklich kein
    /// Dateisystemfehler: Exitcode 21 und nicht 20. Der Unterschied ist der
    /// ganze Zweck — 20 hiesse „ich konnte den Schritt nicht ausfuehren" und
    /// liesse einen Betreiber nach einer vollen Platte suchen, wo dieses
    /// Bauwerk schlicht keine Serverquelle kennt.
    ///
    /// Ein Verzeichnis, das EXISTIERT und sich nicht lesen laesst, bleibt
    /// dagegen [`Self::Io`] und damit 20. Die Grenze verlaeuft zwischen „diese
    /// Quellart trage ich nicht" und „an dieser Quelle ist etwas gescheitert".
    UnsupportedSource,
    /// Eine Container- oder Geheimnisdatei ist nicht als allein ihrem
    /// Eigentuemer gehoerend erwiesen.
    ///
    /// Zwei Wege fuehren hierher: ihre Rechte tragen ein Bit fuer Gruppe oder
    /// Welt (`mode & 0o077 != 0`), oder der genannte Pfad ist ein SYMLINK,
    /// dessen Rechte ueber die Datei dahinter nichts sagen. Beides wird
    /// festgestellt, BEVOR ein Byte gelesen wird — eine Passphrase, die jeder
    /// auf dem Rechner lesen kann, ist keine, und der Aufrufer soll das
    /// erfahren, bevor er sie irgendwo eingibt.
    ///
    /// Exitcode 2, „Aufruf- oder Konfigurationsfehler": derselbe Aufruf ist
    /// nach einem `chmod 600` unveraendert wiederholbar; am Bestand liegt es
    /// nicht. Scharf getrennt von [`Self::Io`] (die Datei liess sich nicht
    /// befragen) und von [`Self::KeySource`] (sie war lesbar und traegt das
    /// Falsche).
    KeySourceExposed,
    /// Eine Passphrasen- oder PIN-Datei ist — nach dem einen erlaubten
    /// Zeilenende — leer.
    ///
    /// Eine leere Passphrase ist keine, und ein KDF ueber null Bytes ist
    /// keine Sicherung, sondern ihre Attrappe. Exitcode 2: der Aufrufer hat
    /// eine Datei benannt, die kein Geheimnis traegt, und derselbe Aufruf ist
    /// mit einer gefuellten Datei unveraendert wiederholbar.
    SecretEmpty,
    /// A bounded, path-free failure of an explicitly selected token provider.
    Pkcs11Provider(crate::Pkcs11ProviderError),
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
            Self::ContainerOpen => "EA-RECOVERY-CONTAINER-OPEN",
            Self::NoOwnGrant => "EA-RECOVERY-NO-OWN-GRANT",
            Self::Decryption => "EA-RECOVERY-DECRYPTION",
            Self::RestrictivePermissionsUnsupported => {
                "EA-RECOVERY-RESTRICTIVE-PERMISSIONS-UNSUPPORTED"
            }
            Self::UnsupportedSource => "EA-RECOVERY-UNSUPPORTED-SOURCE",
            Self::KeySourceExposed => "EA-RECOVERY-KEY-SOURCE-EXPOSED",
            Self::SecretEmpty => "EA-RECOVERY-SECRET-EMPTY",
            Self::Pkcs11Provider(error) => error.code(),
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
