//! Kommando `export`: pruefen, dann den Bestand BYTEWEISE kopieren.
//!
//! # DER EXPORT IST EINE KOPIE, KEINE NEUAUSGABE
//!
//! Es wird nichts neu kodiert, nichts umsortiert und nichts ausgelassen. Jede
//! Bytesequenz des Bestands geht unveraendert unter DEMSELBEN relativen Pfad
//! hinaus — die Nicht-Objekt-Dateien eingeschlossen. `design.md`:1779 verlangt
//! ein zur Offlinepruefung ausreichendes Bundle, und `nonObjectFileCount`
//! gehoert zum Bestand: ein Export ohne `README-FORMAT.txt` und ohne alles
//! unter `format/` waere ein anderer Bestand, dessen Bericht schon in den
//! Zaehlern abwiche.
//!
//! Der Quellbestand wird dabei ausschliesslich GELESEN. Kopiert wird aus dem
//! Puffer, ueber den soeben geurteilt wurde ([`crate::verify::verify_source`]),
//! und nicht aus einem zweiten Lesevorgang — sonst hiesse „verify-before-use"
//! nur noch „verify, und dann irgendwas".
//!
//! # ES WIRD NICHT ENTSCHLUESSELT
//!
//! Der Export ist verschluesselt, WEIL die Objekte es sind. Es gibt hier kein
//! `--key`, keinen Empfaengerschluessel und keinen Klartext; genau deshalb ist
//! Akzeptanzkriterium 38 („ein vollstaendiger verschluesselter Export laesst
//! sich ohne Server, aber nur mit explizitem externem Trust Anchor authentisch
//! verifizieren") ueberhaupt erfuellbar.
//!
//! # DIE REIHENFOLGE
//!
//! 1. Diese Plattform kann restriktive Rechte setzen — sonst wird nicht
//!    gelesen und nicht geschrieben.
//! 2. Die Quelle ist ein existierendes VERZEICHNIS — sonst Exitcode 21.
//! 3. Bestand EINMAL einlesen, vollstaendig verifizieren.
//! 4. Traegt der Bericht einen Befund, endet der Lauf mit dessen Code, und es
//!    entsteht kein Ziel.
//! 5. Das Ziel ist neu oder leer — sonst Exitcode 2.
//! 6. Erst jetzt wird angelegt und geschrieben.
//!
//! Schritt 2 steht VOR Schritt 5 und liefert damit die 21 vor der 2. Das ist
//! dieselbe Wahl, die [`crate::decrypt::decrypt_directory`] fuer seine
//! Plattformpruefung bereits getroffen hat: eine Quellart oder eine Faehigkeit,
//! die dieses Bauwerk nicht traegt, ist keine Aussage ueber die Form des
//! Aufrufs, sondern ueber das Werkzeug. Der kleinste zutreffende spezifische
//! Code aus `design.md`:1795 ordnet die BEFUNDE eines Berichts; er macht aus
//! einer fehlenden Faehigkeit keinen Bedienfehler.
//!
//! # WAS EIN EXPORT NICHT TRAEGT
//!
//! Leere Verzeichnisse. [`crate::FsArchiveSource`] fuehrt AUSSCHLIESSLICH
//! Dateien — ein Verzeichnis ohne Datei traegt keine Bytesequenz, kommt in
//! keinem Blob vor und im Bericht ohnehin nicht. Der Export ist eine Kopie
//! jedes Bytes und nicht eine Nachbildung des Verzeichnisbaums; ebenso wenig
//! werden Symlinks oder Geraetedateien uebertragen, die schon der Leser
//! ueberspringt.

use std::{fs, io::Write as _, path::Path};

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveSource as _};
use ea_trust::TrustAnchorV1;
use ea_types::UnixMillis;
use ea_verify::{VerificationReportV1, VerifyError};

use crate::{
    ExitCode, FsArchiveSource, RecoveryError, exit_code_for,
    report::create_new_file,
    target::{
        create_output_subdirectory, output_directory_is_free, prepare_output_directory,
        restrictive_permissions_available,
    },
    verify::verify_source,
};

/// Das Ergebnis eines vollstaendigen `export`-Laufs.
///
/// Traegt den BERICHT und nicht bloss einen Code: der Aufrufer leitet den
/// Exitcode mit [`exit_code_for`] daraus ab — derselbe Weg wie bei `verify`,
/// `list`, `report` und `decrypt`, damit es fuer denselben Bericht nur EINE
/// Ableitung gibt.
#[derive(Debug)]
pub struct ExportV1 {
    /// Der vollstaendige Verifikationsbericht des Laufs.
    pub report: VerificationReportV1,
    /// Die Zahl der kopierten Dateien.
    ///
    /// Null genau dann, wenn der Bericht einen Befund traegt und deshalb gar
    /// nichts geschrieben wurde.
    pub copied_files: usize,
}

/// Prueft den Bestand unter `source` und kopiert ihn unveraendert nach
/// `output`.
///
/// # Errors
///
/// [`RecoveryError::RestrictivePermissionsUnsupported`], wenn diese Plattform
/// die Rechte nicht setzen kann; [`RecoveryError::UnsupportedSource`], wenn
/// `source` kein existierendes Verzeichnis ist; [`RecoveryError::Io`] und
/// [`RecoveryError::ArchiveTooLarge`] aus dem Einlesen;
/// [`RecoveryError::Verify`], wenn gar kein Bericht entsteht;
/// [`RecoveryError::OutputExists`], wenn das Ziel belegt ist.
///
/// Ein BEFUND ist kein Fehler: er kommt als `Ok` mit einem Bericht zurueck,
/// dessen [`exit_code_for`] ihn benennt, und mit
/// [`ExportV1::copied_files`] gleich null.
pub fn export_directory(
    source: &Path,
    anchor: &TrustAnchorV1,
    now: UnixMillis,
    output: &Path,
) -> Result<ExportV1, RecoveryError> {
    // 1 — VOR jedem gelesenen Byte. Wo die Zusicherung nicht zu halten ist,
    // wird nicht ersatzweise ohne sie gearbeitet.
    restrictive_permissions_available()?;

    // 2 — die Quellart, bevor gelesen wird.
    source_is_a_directory(source)?;

    // 3 — EINMAL einlesen. Der Puffer, ueber den geurteilt wird, ist derselbe,
    // aus dem danach kopiert wird.
    let read = FsArchiveSource::open(source)?;
    let report = verify_source(&read, anchor, now, None)?;

    // 4 — ein Befund beendet den Lauf, bevor irgendetwas entsteht. Nicht bloss
    // „das Ziel bleibt leer": es wird nicht ANGELEGT. Ein Werkzeug, das erst
    // ein Verzeichnis erzeugte und dann am Bestand scheiterte, hinterliesse
    // einen Zielpfad, der beim naechsten Versuch selbst als belegt gaelte.
    if exit_code_for(&report) != ExitCode::Success {
        return Ok(ExportV1 {
            report,
            copied_files: 0,
        });
    }

    // 5 — die Zielpruefung, OHNE anzulegen.
    output_directory_is_free(output)?;

    // 6 — erst jetzt.
    prepare_output_directory(output)?;
    let copied_files = copy_blobs(&read, output)?;

    Ok(ExportV1 {
        report,
        copied_files,
    })
}

/// Prueft, dass `source` ein EXISTIERENDES Verzeichnis ist.
///
/// # DREI AUSGAENGE, UND SIE SAGEN VERSCHIEDENES
///
/// - Es gibt den Pfad nicht, oder er ist kein Verzeichnis: die benannte Quelle
///   ist keine, die dieses Bauwerk kennt — [`RecoveryError::UnsupportedSource`]
///   und damit Exitcode 21. Hier landet auch jede Serveradresse, denn Stage 1
///   hat keine Serverquelle, und eine Zeichenkette wie `https://…` ist im
///   Dateisystem schlicht nicht vorhanden.
/// - Der Pfad laesst sich nicht befragen — ein Elternteil ohne Durchsuchrecht
///   etwa: [`RecoveryError::Io`] und damit 20. Es ist etwas GESCHEITERT, und
///   daraus „diese Quellart kenne ich nicht" zu machen waere eine Behauptung,
///   die dieser Lauf nicht belegen kann.
/// - Es ist ein Verzeichnis: der Lauf geht weiter. Ein Lesefehler DARIN faellt
///   danach in [`FsArchiveSource::open`] an und ist ebenfalls 20.
///
/// Gemessen wird mit [`fs::metadata`] und ausdruecklich nicht mit
/// [`fs::symlink_metadata`]: ein Symlink auf ein Bestandsverzeichnis IST ein
/// benutzbarer Quellpfad, und [`FsArchiveSource::open`] wuerde ihm mit seinem
/// `read_dir` ebenso folgen. Innerhalb des Bestands gilt das Gegenteil, und
/// zwar aus einem anderen Grund — dort waere ein Symlink ein Weg, den Bestand
/// aus sich heraus aufzublaehen (`crate::source`).
fn source_is_a_directory(source: &Path) -> Result<(), RecoveryError> {
    match fs::metadata(source) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(RecoveryError::UnsupportedSource),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(RecoveryError::UnsupportedSource)
        }
        Err(error) => Err(error.into()),
    }
}

/// Schreibt jeden eingelesenen Blob unter seinem Pfadhinweis nach `output`.
///
/// Liefert die Zahl der geschriebenen Dateien.
///
/// # DIE BYTES GEHEN UNVERAENDERT HINAUS
///
/// Kein Dekodieren, kein Neukodieren, keine Auswahl nach Objektart. Der
/// Besucher unterscheidet Eintrag, Grant, Trust-Objekt und Beiwerk gar nicht
/// erst — er kennt nur Pfad und Bytes. Was er nicht unterscheidet, kann er auch
/// nicht auslassen.
fn copy_blobs(read: &FsArchiveSource, output: &Path) -> Result<usize, RecoveryError> {
    let mut copied = 0usize;
    let mut failure: Option<RecoveryError> = None;
    read.visit_blobs(&mut |blob: ArchiveBlob<'_>| {
        match write_blob(blob.path_hint(), blob.bytes(), output) {
            Ok(()) => {
                copied += 1;
                Ok(())
            }
            Err(error) => {
                // Der Besucher darf nur `ArchiveError` melden. Der eigentliche
                // Grund wird deshalb hier festgehalten und unten
                // zurueckgegeben; `Unavailable` haelt lediglich den Durchlauf
                // an, damit nach einem gescheiterten Schreiben keine weitere
                // Datei mehr entsteht.
                failure = Some(error);
                Err(ArchiveError::Unavailable)
            }
        }
    })
    // Unerreichbar ausser ueber den Zweig oben: `FsArchiveSource::visit_blobs`
    // kann nach `crates/ea-recovery/src/source.rs:99-100` selbst nicht mehr
    // scheitern. Sollte der Port das je aendern, bekommt der Fehler denselben
    // Code wie in der Pipeline.
    .map_err(|error| failure.unwrap_or(RecoveryError::Verify(VerifyError::Archive(error))))?;
    Ok(copied)
}

/// Legt EINE Datei des Exports an und fuellt sie.
///
/// Der Pfadhinweis wird KOMPONENTENWEISE an das Ziel gehaengt und nie ueber
/// [`Path::join`] auf die ganze Zeichenkette: ein absoluter Hinweis ersetzte
/// damit stillschweigend die Wurzel, und `..` liefe aus dem Ziel heraus.
/// [`crate::FsArchiveSource`] bildet seine Hinweise zwar aus einzelnen
/// Verzeichniseintragsnamen — `fs::read_dir` liefert weder `.` noch `..`, und
/// kein Name enthaelt einen Trenner —, aber diese Zusicherung wird hier
/// GEPRUEFT und nicht geglaubt: das Ziel ist ein Ort, an dem dieses Werkzeug
/// schreibt, und was dort landet, entscheidet nicht der Bestand.
fn write_blob(path_hint: &str, bytes: &[u8], output: &Path) -> Result<(), RecoveryError> {
    let mut target = output.to_path_buf();
    let mut components = path_hint.split('/').peekable();
    while let Some(component) = components.next() {
        if component.is_empty() || component == "." || component == ".." {
            // Fail-closed und im Regelfall unerreichbar. `InvalidData` ist
            // dieselbe Fehlerart, mit der `crate::source` einen unbenennbaren
            // Eintrag meldet.
            return Err(RecoveryError::Io(std::io::ErrorKind::InvalidData));
        }
        target.push(component);
        if components.peek().is_some() {
            create_output_subdirectory(&target)?;
        }
    }

    let mut file = create_new_file(&target)?;
    file.write_all(bytes)?;
    // Ein Export, den ein Stromausfall zwischen `write` und dem Zurueckschreiben
    // des Puffers verschluckt, ist als Zweitbestand wertlos.
    file.sync_all()?;
    Ok(())
}
