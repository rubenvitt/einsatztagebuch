//! Die Zielpruefung der SCHREIBENDEN Kommandos.
//!
//! # Warum sie hier steht und nicht im Kommandopfad
//!
//! `decrypt` und `export` teilen sie sich Wort fuer Wort: ein Ziel ist neu oder
//! leer, es gehoert allein seinem Eigentuemer, und es entsteht ERST, wenn
//! feststeht, dass ueberhaupt geschrieben wird. Eine Regel, die zweimal
//! geschrieben wird, ist eine Regel, die zweimal falsch werden kann.
//!
//! # „LEER" HEISST WIRKLICH LEER
//!
//! Null Eintraege aus [`fs::read_dir`], Punktdateien eingeschlossen.
//! `read_dir` zaehlt `.` und `..` ohnehin nicht mit, wohl aber jede versteckte
//! Datei — und genau so soll es sein: ein `.DS_Store` oder ein `.gitkeep` im
//! Ziel bedeutet, dass dort schon jemand etwas ablegt. Klartext dazwischen zu
//! streuen waere das Gegenteil eines beherrschten Ablageorts.

use std::{fs, path::Path};

use crate::RecoveryError;

/// Die Rechte des Zielverzeichnisses unter unix: nur der Eigentuemer.
///
/// `0o700` und nicht `0o755`: das Verzeichnis nimmt Klartext auf, und ein
/// Leserecht fuer Gruppe und Welt hiesse, ihn auf einem geteilten Rechner
/// preiszugeben. Die Zieldatei traegt aus demselben Grund
/// [`crate::OUTPUT_FILE_MODE_V1`].
#[cfg(unix)]
pub const OUTPUT_DIRECTORY_MODE_V1: u32 = 0o700;

/// Ob diese Plattform restriktive Rechte setzen kann.
#[cfg(unix)]
pub(crate) const fn restrictive_permissions_available() -> Result<(), RecoveryError> {
    Ok(())
}

/// Auf dieser Plattform kann kein schreibendes Kommando seine Zusicherung
/// halten.
///
/// Windows ist nach der Global Constraint des Stage-1-Plans (Zeile 23) eine
/// ZIELPLATTFORM. Ein blosser `#[cfg(unix)]`-Rechteblock ohne diesen Gegenzweig
/// uebersetzte dort anstandslos und liesse die Zusicherung STILL fallen — die
/// Zieldateien laegen mit den Vorgaberechten des Elternverzeichnisses da.
/// Deshalb wird hier verweigert statt abgeschwaecht.
///
/// Der Zweig gilt fuer `decrypt` UND `export`. Beim Export sind die kopierten
/// Bytes zwar verschluesselt, aber `design.md`:1779 stellt beide Kommandos in
/// denselben Satz: sie schreiben „ausschliesslich in ein neu erzeugtes oder
/// leeres Ziel mit restriktiven Rechten". Ein Export mit weltweit lesbaren
/// Rechten legte ausserdem saemtliche Dateinamen und damit die Kettensequenzen
/// des Bestands offen.
#[cfg(not(unix))]
pub(crate) const fn restrictive_permissions_available() -> Result<(), RecoveryError> {
    Err(RecoveryError::RestrictivePermissionsUnsupported)
}

/// Prueft, ob `output` als Ziel taugt — OHNE etwas anzulegen.
///
/// # Warum die Pruefung von der Vorbereitung getrennt ist
///
/// Damit der AUFRUFCODE 2 vor jedem spezifischeren Code steht. `decrypt` kennt
/// zwischen der Verifikation und dem ersten geschriebenen Byte noch einen
/// eigenen Abbruchgrund (kein eigener Grant, Code 14); stuende das Anlegen
/// davor, hinterliesse dieser Ausgang ein Verzeichnis, das beim naechsten
/// Versuch selbst als belegt gaelte. Stuende die PRUEFUNG dahinter, gaebe ein
/// Aufruf mit belegtem Ziel UND falschem Schluessel die 14 statt der 2 —
/// `design.md`:1795 verlangt aber den kleinsten zutreffenden spezifischen Code.
///
/// Diese Funktion ersetzt [`prepare_output_directory`] NICHT: zwischen beiden
/// liegt ein Zeitfenster, und deshalb ist das Anlegen dort weiterhin selbst der
/// Test.
///
/// # Errors
///
/// [`RecoveryError::OutputExists`], wenn `output` existiert und kein leeres
/// Verzeichnis ist — eine Datei ebenso wie ein belegtes Verzeichnis und ebenso
/// wie ein SYMLINK, auch einer auf ein leeres Verzeichnis.
pub fn output_directory_is_free(output: &Path) -> Result<(), RecoveryError> {
    // ZUERST DIESELBE FRAGE WIE IN [`prepare_output_directory`]: ist das der
    // genannte Pfad selbst? `read_dir` folgt einem Symlink, und ein Link auf
    // ein leeres Verzeichnis gaelte hier sonst als freies Ziel — waehrend das
    // Anlegen ihn abweist. Diese Funktion steht aber genau deshalb VOR den
    // spezifischeren Abbruchgruenden, und ein Ziel, das nicht taugt, muss
    // seinen Code 2 vor ihnen tragen (`design.md`:1810). Gemessen wird mit
    // [`fs::symlink_metadata`], nie mit [`fs::metadata`], denn letzteres folgt.
    match fs::symlink_metadata(output) {
        Ok(metadata) if metadata.is_symlink() => return Err(RecoveryError::OutputExists),
        Ok(_) => {}
        // HIER heisst `NotFound` „frei" und nicht „im Rennfenster
        // verschwunden": dies ist der ERSTE Zugriff dieser Funktion, und genau
        // danach fragt ihr Vertrag. In [`prepare_output_directory`] steht
        // dieselbe Fehlerart hinter einem bewiesenen `AlreadyExists` und traegt
        // deshalb die umgekehrte Aussage — und dass sie DORT fail-closed
        // beantwortet wird, ist der zweite Grund: jene Funktion legt an, diese
        // raet nur.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        // Es gibt es, aber es laesst sich nicht befragen. Auch das heisst: so,
        // wie du es aufgerufen hast, schreibe ich dort nicht.
        Err(_) => return Err(RecoveryError::OutputExists),
    }

    match fs::read_dir(output) {
        // Es gibt es, es ist ein Verzeichnis — dann entscheidet sein Inhalt.
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(RecoveryError::OutputExists);
            }
            Ok(())
        }
        // Zwischen den beiden Fragen ist es verschwunden — der Regelfall
        // „gibt es nicht" hat die Frage oben schon beantwortet. Die Antwort
        // bleibt trotzdem „frei", und der umgekehrte Ausgang im
        // Rennzweig von [`prepare_output_directory`] ist kein Widerspruch: diese
        // Funktion RAET und legt nichts an. Die bindende Entscheidung faellt
        // dort, und dort ist derselbe Ausgang fail-closed. Ein Abbruch schon
        // hier verwuerfe einen Pfad, der in diesem Augenblick tatsaechlich
        // frei ist.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        // Es gibt es, aber es ist kein lesbares Verzeichnis — eine Datei etwa.
        // Auch das heisst: so, wie du es aufgerufen hast, schreibe ich dort
        // nicht.
        Err(_) => Err(RecoveryError::OutputExists),
    }
}

/// Stellt sicher, dass `output` ein NEUES oder LEERES Verzeichnis ist.
///
/// Existiert es nicht, wird es mit [`OUTPUT_DIRECTORY_MODE_V1`] angelegt.
///
/// # AUCH EIN VORGEFUNDENES LEERES ZIEL WIRD VERENGT
///
/// Und das ist ausdruecklich kein Uebergriff auf fremde Rechte. Der Stage-1-Plan
/// erlaubt als Ziel „ein neu erzeugtes ODER LEERES" Verzeichnis und verlangt im
/// selben Satz „mit restriktiven Rechten"; die Zusicherung haengt an beiden
/// Aesten. Ein Aufrufer, der sein Ziel mit einem gewoehnlichen `mkdir` unter der
/// ueblichen `umask` anlegt, bekommt 0755 — GEMESSEN, siehe
/// `apps/cli/tests/decrypt.rs::decrypt_tightens_a_pre_existing_empty_target`.
/// Die Klartextdateien darin blieben zwar 0600, aber ihre NAMEN und damit die
/// Kettensequenzen des Bestands laegen fuer jeden offen.
///
/// Verengt wird deshalb genau dann, wenn dieses Verzeichnis gleich Klartext
/// aufnimmt — und nicht als allgemeine Gewohnheit dieses Werkzeugs.
///
/// # NUR DAS ZIEL SELBST, NIE SEIN ELTERNTEIL
///
/// [`fs::create_dir`] und ausdruecklich nicht `create_dir_all`. Ein fehlendes
/// Elternverzeichnis ist ein Bedienfehler und liefert [`RecoveryError::Io`];
/// eine ganze Kette stillschweigend zu erzeugen hiesse, an einer Stelle
/// Verzeichnisse zu bauen, an der der Aufrufer sich vertan hat. Dieselbe
/// Entscheidung trifft [`crate::write_report_document`].
///
/// # Errors
///
/// [`RecoveryError::OutputExists`], wenn `output` existiert und keine leeres
/// Verzeichnis ist — eine Datei ebenso wie ein belegtes Verzeichnis und ebenso
/// wie ein SYMLINK, auch einer auf ein leeres Verzeichnis.
/// [`RecoveryError::Io`] fuer jeden Dateisystemfehler.
pub fn prepare_output_directory(output: &Path) -> Result<(), RecoveryError> {
    // ZUERST der Versuch, es anzulegen, und danach erst die Frage nach dem
    // Inhalt. Andersherum laege zwischen der Frage „gibt es dich?" und dem
    // Anlegen ein Zeitfenster, in dem sich die Antwort aendern kann — dieselbe
    // Ueberlegung, die `crate::report::create_new_file` zu `create_new(true)`
    // fuehrt.
    match create_directory(output) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }

    // ZUERST DIE FRAGE, OB ES DER GENANNTE PFAD SELBST IST. `read_dir` und
    // `set_permissions` folgen beide einem Symlink; zusammen hiessen sie sonst,
    // die Rechte eines FREMDEN Verzeichnisses auf 0700 zu setzen und den
    // Klartext ausserhalb des genannten Pfades abzulegen — beides allein
    // deshalb, weil dort ein Link steht. Gemessen wird mit
    // [`fs::symlink_metadata`], nie mit [`fs::metadata`], denn letzteres folgt;
    // dieselbe Regel wie beim Einlesen in `crate::source`. Ein Link ist damit
    // kein leeres Ziel, sondern ein belegtes.
    match fs::symlink_metadata(output) {
        Ok(metadata) if metadata.is_symlink() => return Err(RecoveryError::OutputExists),
        Ok(_) => {}
        // Zwischen dem `AlreadyExists` und dieser Frage kann das Ziel
        // verschwunden sein. Dann ist nicht erwiesen, dass dort ein leeres
        // Verzeichnis steht — und ohne diesen Nachweis wird nicht geschrieben.
        Err(_) => return Err(RecoveryError::OutputExists),
    }

    // Es existiert bereits und ist der genannte Pfad selbst. Dann traegt es
    // entweder nichts — und darf benutzt werden — oder es ist belegt
    // beziehungsweise gar kein Verzeichnis. `read_dir` beantwortet beides in
    // einem Schritt: auf einer Datei liefert es `NotADirectory` beziehungsweise
    // `Other`, und jeder Lesefehler zaehlt hier als „so, wie du es aufgerufen
    // hast, schreibe ich dort nicht".
    let Ok(mut entries) = fs::read_dir(output) else {
        return Err(RecoveryError::OutputExists);
    };
    if entries.next().is_some() {
        return Err(RecoveryError::OutputExists);
    }
    // Es ist leer und wird benutzt — also gelten fuer es dieselben Rechte wie
    // fuer ein selbst angelegtes.
    tighten_directory(output)?;
    Ok(())
}

/// Legt ein UNTERVERZEICHNIS des bereits vorbereiteten Ziels an.
///
/// # Warum es diese zweite Funktion gibt und nicht `create_dir_all`
///
/// `create_dir_all` legt jede fehlende Ebene mit den VORGABERECHTEN an — unter
/// der ueblichen `umask` also 0755. Ein Export, der seine Zwischenverzeichnisse
/// so erzeugte, liesse die Namen jedes Bestandsstuecks und damit dessen
/// Kettensequenzen weltweit lesbar zurueck, obwohl die Dateien darin 0600
/// tragen. Jede Ebene entsteht deshalb einzeln ueber dasselbe
/// [`create_directory`], das schon [`prepare_output_directory`] benutzt.
///
/// # EIN VORGEFUNDENES VERZEICHNIS IST HIER KEIN BELEGTES ZIEL
///
/// Der einzige Aufrufer legt seine Ebenen der Reihe nach an, und zwei Dateien
/// desselben Unterverzeichnisses treffen die zweite Ebene ein zweites Mal. Das
/// Ziel selbst wurde zuvor als NEU ODER LEER erwiesen; was hier bereits steht,
/// stammt deshalb aus DIESEM Lauf. Ein `AlreadyExists` ist damit kein Befund
/// ueber den Aufruf, sondern der Regelfall.
///
/// Der Fall „hier steht bereits eine DATEI dieses Namens" bleibt trotzdem
/// fail-closed: das anschliessende [`crate::report::create_new_file`] legt
/// keine Datei in einer Datei an und meldet [`RecoveryError::Io`].
///
/// # Errors
///
/// [`RecoveryError::Io`] fuer jeden Dateisystemfehler ausser `AlreadyExists`.
pub(crate) fn create_output_subdirectory(path: &Path) -> Result<(), RecoveryError> {
    match create_directory(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Setzt die Rechte eines VORGEFUNDENEN Zielverzeichnisses auf genau
/// [`OUTPUT_DIRECTORY_MODE_V1`].
///
/// Gesetzt wird auf dem PFAD und nicht auf einem Handle: ein
/// `File`-Handle auf ein Verzeichnis ist nicht portabel zu oeffnen. Das
/// Zeitfenster, das dadurch entsteht, ist dasselbe, das zwischen der
/// Leerheitspruefung und dem ersten Schreiben ohnehin besteht — und es endet
/// enger, als es begann.
///
/// DASS DER PFAD KEIN SYMLINK IST, ist deshalb Vorbedingung und nicht Zufall:
/// [`prepare_output_directory`] weist einen Link zuvor mit
/// [`RecoveryError::OutputExists`] ab. Ohne diesen Ausschluss verengte
/// [`fs::set_permissions`] das Ziel des Links statt des genannten Pfades.
#[cfg(unix)]
fn tighten_directory(output: &Path) -> Result<(), RecoveryError> {
    use std::{fs::Permissions, os::unix::fs::PermissionsExt as _};

    fs::set_permissions(output, Permissions::from_mode(OUTPUT_DIRECTORY_MODE_V1))?;
    Ok(())
}

/// Auf dieser Plattform gibt es nichts zu verengen.
///
/// Wird nie erreicht: jedes schreibende Kommando lehnt hier bereits mit
/// [`RecoveryError::RestrictivePermissionsUnsupported`] ab, bevor ein Ziel
/// entsteht.
#[cfg(not(unix))]
const fn tighten_directory(_output: &Path) -> Result<(), RecoveryError> {
    Ok(())
}

/// Legt `output` an und gibt ihm unter unix sofort restriktive Rechte.
///
/// Die Rechte stehen im `mkdir`-Aufruf selbst und nicht in einem zweiten
/// Schritt danach: zwischen einem `create_dir` mit Vorgaberechten und einem
/// nachtraeglichen `set_permissions` laege ein Fenster, in dem das Verzeichnis
/// fuer jeden lesbar waere. `mode` unterliegt der `umask` und kann Bits nur
/// wegnehmen — zu VIEL wird dadurch nie erlaubt.
///
/// Bleibt trotzdem ein zweites, EXAKTES Setzen: eine `umask`, die `0o700`
/// beschneidet, liesse das Verzeichnis sonst enger als verlangt zurueck, und
/// die Zusicherung lautet auf genau diese Zahl. Gesetzt wird auf dem Pfad, den
/// dieser Aufruf gerade selbst erzeugt hat.
#[cfg(unix)]
fn create_directory(output: &Path) -> Result<(), std::io::Error> {
    use std::{
        fs::Permissions,
        os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    };

    fs::DirBuilder::new()
        .mode(OUTPUT_DIRECTORY_MODE_V1)
        .create(output)?;
    fs::set_permissions(output, Permissions::from_mode(OUTPUT_DIRECTORY_MODE_V1))
}

/// Legt `output` an.
///
/// Wird auf dieser Plattform nie erreicht: jedes schreibende Kommando lehnt
/// nach [`crate::RecoveryError::RestrictivePermissionsUnsupported`] bereits ab,
/// bevor es hierher kaeme. Der Zweig steht, damit die Crate uebersetzt — und
/// nicht, damit ohne Rechte geschrieben wird.
#[cfg(not(unix))]
fn create_directory(output: &Path) -> Result<(), std::io::Error> {
    fs::create_dir(output)
}
