//! `decrypt` von Ende zu Ende, gemessen am echten Prozess.
//!
//! # Was hier gemessen wird
//!
//! Die vier Zusicherungen, die `decrypt` von einer blossen Entschluesselung
//! unterscheiden: VOLLSTAENDIGE Verifikation VOR jedem geschriebenen Byte, ein
//! NEUES oder LEERES Ziel, RESTRIKTIVE Rechte auf Verzeichnis und Datei, und
//! KEINE Klartext-Temporaerdatei. Jede einzelne ist eine Aussage ueber den
//! Prozess und nicht ueber eine Funktion — deshalb steht sie hier und nicht in
//! `crates/ea-recovery/tests`.
//!
//! # DIE UHR IST HIER KEIN PARAMETER
//!
//! Die CLI kennt genau eine, `SystemTime::now()`. Jeder Bestand stammt deshalb
//! aus der `live_clock_*`-Familie; die geerbten Bestaende sind unter der echten
//! Uhr stumm und liefern eine LEERE Aussage, die faelschlich wie Erfolg
//! aussieht. Die Begruendung steht in `apps/cli/tests/support/mod.rs`.
//!
//! # ZWEI WEGE AUF DIE 14, UND SIE SIND NICHT DERSELBE
//!
//! - FEHLENDER EIGENER GRANT: der vorgelegte Schluessel ist ein anderer, sein
//!   Abdruck steht in keinem Grant des Bestands. `ea-verify` meldet das
//!   ausdruecklich NICHT als Befund (`crates/ea-verify/src/recipient.rs:13-15`),
//!   der Bericht bleibt makellos, und `exit_code_for` saehe `Success`. Diesen
//!   Weg misst [`decrypt_with_the_wrong_key_fails_with_fourteen`]; der Code
//!   entsteht im Pfad von `decrypt` selbst, genau wie es
//!   `crates/ea-recovery/src/exit.rs:71-76` verlangt.
//! - FEHLGESCHLAGENE ENTKAPSELUNG: der Grant nennt den eigenen Abdruck, ist
//!   aber auf fremdes Material gekapselt. Das IST ein Befund, und der Lauf
//!   endet bereits an Schritt 2. Gemessen wird er in
//!   `crates/ea-recovery/tests/live_clock.rs`.

#[path = "support/mod.rs"]
mod support;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use ea_format::EIP_PREFIX_V1;

use support::{
    LiveArchive, TempDir, live_clock_archive, materialize, temp_dir,
    verify_support::{complete_recipient_secret_bytes, other_recipient_secret_bytes},
};

/// Der Name, den die einzige Klartextdatei eines Bestands mit genau einem
/// Eintrag auf Sequenz null traegt.
const GENESIS_PLAINTEXT_FILE_V1: &str = "000000000000.bin";

/// Ein abgelegter Bestand samt Anker, Schluesseldatei und Zielpfad.
///
/// Anker und Schluessel liegen in einem EIGENEN Verzeichnis und niemals im
/// Bestand: beide wuerden von `ea_recovery::FsArchiveSource::open` sonst
/// mitgelesen und als Beiwerk gezaehlt — der Bestand saehe je nach Testaufbau
/// anders aus. Das Ziel liegt aus demselben Grund daneben und nicht darin.
struct Laid {
    archive: TempDir,
    outside: TempDir,
}

impl Laid {
    fn archive_path(&self) -> String {
        path_argument(self.archive.path())
    }

    fn anchor_path(&self) -> String {
        path_argument(&self.outside.path().join("anchor.bin"))
    }

    fn key_path(&self) -> String {
        path_argument(&self.outside.path().join("key.bin"))
    }

    /// Der Zielpfad. Existiert AUSDRUECKLICH noch nicht.
    fn target(&self) -> PathBuf {
        self.outside.path().join("klartext")
    }

    fn target_path(&self) -> String {
        path_argument(&self.target())
    }
}

/// Ein vom Testrahmen selbst gebildeter Pfad als Argumentzeichenkette.
fn path_argument(path: &Path) -> String {
    path.to_str()
        .expect("der vom Testrahmen selbst gebildete Pfad ist UTF-8")
        .to_owned()
}

/// Legt Bestand, Anker und Schluesseldatei ab.
fn lay_out(tag: &str, built: &LiveArchive, key_bytes: &[u8]) -> Laid {
    let archive = temp_dir(&format!("{tag}-archive"));
    materialize(&built.fixture, archive.path());
    let outside = temp_dir(&format!("{tag}-outside"));
    fs::write(outside.path().join("anchor.bin"), &built.anchor_bytes)
        .expect("die Ankerdatei muss schreibbar sein");
    fs::write(outside.path().join("key.bin"), key_bytes)
        .expect("die Schluesseldatei muss schreibbar sein");
    Laid { archive, outside }
}

/// Startet das Werkzeug mit `tokens` und liefert seinen vollstaendigen Ausgang.
fn run(tokens: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(tokens)
        .output()
        .expect("das Testbinary muss startbar sein")
}

/// Startet das Werkzeug mit einem VORGEGEBENEN Temporaerverzeichnis.
///
/// Alle drei Namen werden gesetzt, weil `std::env::temp_dir` sie je nach
/// Plattform verschieden liest: `TMPDIR` auf unix, `TMP` und `TEMP` auf
/// Windows.
fn run_with_temporary_directory(tokens: &[&str], temporary: &Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"));
    command.args(tokens);
    for name in ["TMPDIR", "TMP", "TEMP"] {
        command.env(name, temporary);
    }
    command.output().expect("das Testbinary muss startbar sein")
}

/// Der Exitcode eines Laufs.
fn code_of(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("der Prozess muss regulaer enden")
}

/// Startet `decrypt` gegen `laid`.
fn run_decrypt(laid: &Laid) -> Output {
    let tokens = decrypt_argv(laid);
    run(&tokens.iter().map(String::as_str).collect::<Vec<_>>())
}

/// Die acht Glieder der Aufrufzeile.
fn decrypt_argv(laid: &Laid) -> Vec<String> {
    vec![
        "--trust-anchor".to_owned(),
        laid.anchor_path(),
        "decrypt".to_owned(),
        laid.archive_path(),
        "--key".to_owned(),
        laid.key_path(),
        "--output".to_owned(),
        laid.target_path(),
    ]
}

/// Die Namen der Eintraege eines Verzeichnisses, aufsteigend sortiert.
fn entry_names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("das Verzeichnis muss lesbar sein")
        .map(|entry| {
            entry
                .expect("der Verzeichniseintrag muss lesbar sein")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

// ===========================================================================
// Der Erfolgspfad
// ===========================================================================

/// DER KERN DES TASKS: erst vollstaendig pruefen, dann Klartext schreiben.
///
/// Der Bestand aus [`live_clock_archive`] traegt genau einen Eintrag auf
/// Sequenz null und genau einen Grant an [`complete_recipient_secret_bytes`].
/// Gemessen wird der Exitcode ZUERST — er ist die Aussage, an der alle
/// uebrigen haengen — und danach, dass genau eine Datei entstanden ist und ihr
/// Inhalt BYTEWEISE der Klartext der Fixture ist. Ein Vergleich der Laenge
/// allein liesse eine falsch entschluesselte Datei durchgehen.
#[test]
fn decrypt_writes_the_plaintext_only_after_full_verification() {
    let built = live_clock_archive();
    let laid = lay_out("decrypt-ok", &built, &complete_recipient_secret_bytes());

    let output = run_decrypt(&laid);

    assert_eq!(code_of(&output), 0, "exit code");
    assert_eq!(
        entry_names(&laid.target()),
        vec![GENESIS_PLAINTEXT_FILE_V1.to_owned()],
        "das Ziel muss genau die eine Klartextdatei des einen Eintrags tragen"
    );
    let written = fs::read(laid.target().join(GENESIS_PLAINTEXT_FILE_V1))
        .expect("die Klartextdatei muss lesbar sein");
    assert_eq!(
        written, built.plaintext,
        "die geschriebenen Bytes muessen der Klartext der Fixture sein"
    );
}

// ===========================================================================
// Die Zielpruefung
// ===========================================================================

/// Ein BELEGTES Ziel endet mit 2 und laesst den vorhandenen Inhalt in Ruhe.
///
/// Code 2 und nicht 20: geschrieben wurde nichts, gefunden wurde nichts, und
/// derselbe Lauf ist mit einem anderen `--output` unveraendert wiederholbar.
/// Die Begruendung steht an `ea_recovery::RecoveryError::OutputExists`.
#[test]
fn decrypt_refuses_a_non_empty_target() {
    let built = live_clock_archive();
    let laid = lay_out("decrypt-busy", &built, &complete_recipient_secret_bytes());
    fs::create_dir(laid.target()).expect("das Zielverzeichnis muss anlegbar sein");
    fs::write(laid.target().join("schon-da.txt"), b"fremder Inhalt\n")
        .expect("die fremde Datei muss schreibbar sein");

    let output = run_decrypt(&laid);

    assert_eq!(code_of(&output), 2, "exit code");
    assert_eq!(
        entry_names(&laid.target()),
        vec!["schon-da.txt".to_owned()],
        "im belegten Ziel darf nichts entstanden und nichts verschwunden sein"
    );
    let untouched =
        fs::read(laid.target().join("schon-da.txt")).expect("die fremde Datei muss lesbar sein");
    assert_eq!(
        untouched, b"fremder Inhalt\n",
        "die fremde Datei darf nicht gekuerzt oder ueberschrieben werden"
    );
}

// ===========================================================================
// Verify-before-use
// ===========================================================================

/// Ein Bestand mit FORMATBEFUND endet mit 10 — und das Ziel entsteht GAR NICHT.
///
/// Nicht bloss „leer": es wird nicht ANGELEGT. Ein Werkzeug, das erst ein
/// Verzeichnis erzeugte und dann am Bestand scheiterte, hinterliesse einen
/// Zielpfad, der beim naechsten Versuch als belegt gilt.
#[test]
fn decrypt_writes_nothing_when_verification_fails() {
    let mut built = live_clock_archive();
    let mut malformed = EIP_PREFIX_V1.to_vec();
    malformed.extend_from_slice(b"nicht dekodierbar");
    built
        .fixture
        .push_exact_bytes("entries/000000000099_broken.eip", malformed);
    let laid = lay_out("decrypt-broken", &built, &complete_recipient_secret_bytes());

    let output = run_decrypt(&laid);

    assert_eq!(code_of(&output), 10, "exit code");
    assert!(
        !laid.target().exists(),
        "ein gescheiterter Lauf darf das Ziel nicht einmal anlegen"
    );
}

/// Ein FREMDER Schluessel endet mit 14 — ohne Ziel und ohne Klartext.
///
/// Der Abdruck wird aus dem VORGELEGTEN Schluessel gerechnet, nie aus der
/// Datei gelesen. Er steht damit in keinem Grant dieses Bestands, der Zustand
/// ist FEHLENDER GRANT, und der Bericht bleibt makellos — der Code entsteht
/// ausschliesslich daraus, dass `decrypt` ohne einen einzigen eigenen Grant
/// nie Erfolg melden darf.
#[test]
fn decrypt_with_the_wrong_key_fails_with_fourteen() {
    let built = live_clock_archive();
    let laid = lay_out("decrypt-wrong-key", &built, &other_recipient_secret_bytes());

    let output = run_decrypt(&laid);

    assert_eq!(code_of(&output), 14, "exit code");
    assert!(
        !laid.target().exists(),
        "ohne eigenen Grant darf kein Ziel entstehen"
    );
}

// ===========================================================================
// Rechte und Temporaerdateien
// ===========================================================================

/// Verzeichnis 0700, Datei 0600 — gemessen, nicht zugesichert.
#[cfg(unix)]
#[test]
fn decrypt_target_has_restrictive_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let built = live_clock_archive();
    let laid = lay_out("decrypt-modes", &built, &complete_recipient_secret_bytes());

    let output = run_decrypt(&laid);
    assert_eq!(code_of(&output), 0, "exit code");

    let directory = fs::metadata(laid.target()).expect("das Ziel muss lesbar sein");
    assert_eq!(
        directory.permissions().mode() & 0o777,
        0o700,
        "das Zielverzeichnis gehoert allein seinem Eigentuemer"
    );
    let file = fs::metadata(laid.target().join(GENESIS_PLAINTEXT_FILE_V1))
        .expect("die Klartextdatei muss lesbar sein");
    assert_eq!(
        file.permissions().mode() & 0o777,
        0o600,
        "die Klartextdatei gehoert allein ihrem Eigentuemer"
    );
}

/// EIN VORGEFUNDENES LEERES ZIEL WIRD EBENFALLS VERENGT.
///
/// Die Norm erlaubt als Ziel „ein neu erzeugtes ODER LEERES" Verzeichnis, und
/// die Zusicherung „mit restriktiven Rechten" gilt fuer BEIDE Aeste. Ein
/// Aufrufer, der sein Ziel mit einem gewoehnlichen `mkdir` unter der ueblichen
/// `umask` anlegt, bekommt 0755 — und damit ein weltweit LESBARES Verzeichnis,
/// in das gleich Klartext faellt. Die Dateien darin blieben zwar 0600, aber
/// ihre Namen — und damit die Kettensequenzen des Bestands — laegen offen.
///
/// Gemessen wird deshalb genau dieser Fall, und zwar mit AUSDRUECKLICH
/// gesetzten 0755 statt mit dem, was die `umask` des Laufs gerade hergibt.
#[cfg(unix)]
#[test]
fn decrypt_tightens_a_pre_existing_empty_target() {
    use std::{fs::Permissions, os::unix::fs::PermissionsExt as _};

    let built = live_clock_archive();
    let laid = lay_out("decrypt-loose", &built, &complete_recipient_secret_bytes());
    fs::create_dir(laid.target()).expect("das Zielverzeichnis muss anlegbar sein");
    fs::set_permissions(laid.target(), Permissions::from_mode(0o755))
        .expect("die weiten Rechte muessen setzbar sein");

    let output = run_decrypt(&laid);
    assert_eq!(code_of(&output), 0, "exit code");

    let directory = fs::metadata(laid.target()).expect("das Ziel muss lesbar sein");
    assert_eq!(
        directory.permissions().mode() & 0o777,
        0o700,
        "auch ein vorgefundenes leeres Ziel gehoert danach allein seinem Eigentuemer"
    );
    assert_eq!(
        entry_names(&laid.target()),
        vec![GENESIS_PLAINTEXT_FILE_V1.to_owned()],
        "in das vorgefundene Ziel muss geschrieben worden sein"
    );
}

/// KEINE Klartext-Temporaerdatei — gemessen an einem eigenen Temporaerpfad.
///
/// Dem Kindprozess wird ein FRISCHES, leeres Verzeichnis als Temporaerpfad
/// vorgegeben; `std::env::temp_dir` liest genau diese Variablen. Bliebe darin
/// nach einem erfolgreichen Lauf auch nur ein Eintrag zurueck, haette das
/// Werkzeug Klartext zwischengelagert.
///
/// Der eigene Prozess wird dabei ausdruecklich NICHT umgestellt: `cargo test`
/// faehrt die Tests eines Targets parallel in Threads, und eine Momentaufnahme
/// von `env::temp_dir()` saehe die Temporaerverzeichnisse der Nachbartests.
#[test]
fn no_plaintext_temporary_file_is_created() {
    let built = live_clock_archive();
    let laid = lay_out("decrypt-notmp", &built, &complete_recipient_secret_bytes());
    let temporary = temp_dir("decrypt-notmp-tmpdir");
    assert!(
        entry_names(temporary.path()).is_empty(),
        "der vorgegebene Temporaerpfad muss leer beginnen"
    );

    let argv = decrypt_argv(&laid);
    let output = run_with_temporary_directory(
        &argv.iter().map(String::as_str).collect::<Vec<_>>(),
        temporary.path(),
    );

    assert_eq!(code_of(&output), 0, "exit code");
    assert!(
        entry_names(temporary.path()).is_empty(),
        "der Lauf darf im Temporaerpfad nichts hinterlassen, gefunden wurde {:?}",
        entry_names(temporary.path())
    );
}
