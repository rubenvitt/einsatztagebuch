//! `export` von Ende zu Ende, gemessen am echten Prozess.
//!
//! # Was hier gemessen wird
//!
//! Dass der Export eine KOPIE ist und keine Neuausgabe: jede Bytesequenz des
//! Bestands, unveraendert, unter demselben relativen Pfad — die
//! Nicht-Objekt-Dateien eingeschlossen. `design.md`:1779 verlangt ein zur
//! Offlinepruefung ausreichendes Bundle, und `nonObjectFileCount` gehoert zum
//! Bestand.
//!
//! # DIE UHR IST HIER KEIN PARAMETER
//!
//! Die CLI kennt genau eine, `SystemTime::now()`. Jeder Bestand stammt deshalb
//! aus der `live_clock_*`-Familie; die geerbten Bestaende sind unter der echten
//! Uhr stumm und liefern eine LEERE Aussage, die faelschlich wie Erfolg
//! aussieht. Die Begruendung steht in `apps/cli/tests/support/mod.rs`.

#[path = "support/mod.rs"]
mod support;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use ea_crypto::object_hash;
use ea_format::EIP_PREFIX_V1;

#[cfg(unix)]
use support::LIVE_FORMAT_SCHEMA_FILE_V1;
use support::{LiveArchive, TempDir, live_clock_archive, materialize, temp_dir};

/// Ein abgelegter Bestand samt Anker und Zielpfad.
///
/// Der Anker liegt in einem EIGENEN Verzeichnis und niemals im Bestand: er
/// wuerde von `ea_recovery::FsArchiveSource::open` sonst mitgelesen und als
/// Beiwerk gezaehlt — der Bestand saehe je nach Testaufbau anders aus und der
/// Export truege eine Datei, die gar nicht zu ihm gehoert. Das Ziel liegt aus
/// demselben Grund daneben und nicht darin.
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

    /// Der Zielpfad. Existiert AUSDRUECKLICH noch nicht.
    fn target(&self) -> PathBuf {
        self.outside.path().join("export")
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

/// Legt Bestand und Anker ab.
fn lay_out(tag: &str, built: &LiveArchive) -> Laid {
    let archive = temp_dir(&format!("{tag}-archive"));
    materialize(&built.fixture, archive.path());
    let outside = temp_dir(&format!("{tag}-outside"));
    fs::write(outside.path().join("anchor.bin"), &built.anchor_bytes)
        .expect("die Ankerdatei muss schreibbar sein");
    Laid { archive, outside }
}

/// Startet das Werkzeug mit `tokens` und liefert seinen vollstaendigen Ausgang.
fn run(tokens: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(tokens)
        .output()
        .expect("das Testbinary muss startbar sein")
}

/// Der Exitcode eines Laufs.
fn code_of(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("der Prozess muss regulaer enden")
}

/// Startet `export` gegen `laid`.
fn run_export(laid: &Laid) -> Output {
    run(&[
        "--trust-anchor",
        &laid.anchor_path(),
        "export",
        &laid.archive_path(),
        "--output",
        &laid.target_path(),
    ])
}

/// Startet `verify` gegen `archive` mit dem Anker aus `laid`.
///
/// Die TEXTFORM und nicht `json`: sie traegt `reportHash` als eigene Zeile und
/// ist damit unmittelbar vergleichbar.
fn run_verify(laid: &Laid, archive: &Path) -> Output {
    run(&[
        "--trust-anchor",
        &laid.anchor_path(),
        "verify",
        &path_argument(archive),
    ])
}

/// Die `reportHash`-Zeile aus einer Textausgabe.
fn report_hash_line(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .find(|line| line.starts_with("reportHash "))
        .expect("die Textausgabe traegt eine reportHash-Zeile")
        .to_owned()
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

/// Die Abbildung „relativer Pfad -> Rechte" eines Verzeichnisbaums.
///
/// Verzeichnisse tragen einen abschliessenden `/`, damit der Aufrufer beide
/// Arten in EINER Schleife unterscheiden kann, ohne ein zweites Mal auf die
/// Platte zu greifen.
#[cfg(unix)]
fn mode_map(root: &Path) -> BTreeMap<String, u32> {
    let mut map = BTreeMap::new();
    collect_modes(root, "", &mut map);
    map
}

/// Steigt in `directory` ab und traegt jeden Eintrag mit seinen Rechten ein.
#[cfg(unix)]
fn collect_modes(directory: &Path, prefix: &str, map: &mut BTreeMap<String, u32>) {
    use std::os::unix::fs::PermissionsExt as _;

    for entry in fs::read_dir(directory).expect("das Verzeichnis muss lesbar sein") {
        let entry = entry.expect("der Verzeichniseintrag muss lesbar sein");
        let name = entry
            .file_name()
            .to_str()
            .expect("der Fixture-Dateiname ist UTF-8")
            .to_owned();
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).expect("die Metadaten muessen lesbar sein");
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.is_dir() {
            map.insert(format!("{relative}/"), mode);
            collect_modes(&path, &relative, map);
        } else {
            map.insert(relative, mode);
        }
    }
}

/// Die Abbildung „relativer Pfad -> Abdruck der Bytes" eines Verzeichnisses.
///
/// # Warum ein Abdruck und nicht die Bytes selbst
///
/// [`object_hash`] ist SHA-256 ueber ein festes Domainpraefix und die EXAKTEN
/// Bytes. Die Abbildung ist damit eine deterministische Funktion des
/// Byteinhalts, und ihre Gleichheit ist der Gleichheit der Byteabbildung
/// gleichwertig — nur dass ein Fehlschlag zwei Hexzeilen zeigt statt zweier
/// Bytehalden.
///
/// Die Schluessel sind `/`-getrennt und relativ zu `root`, also genau die Form,
/// in der `ea_recovery::FsArchiveSource` ihre Pfadhinweise bildet.
fn digest_map(root: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    collect_digests(root, "", &mut map);
    map
}

/// Steigt in `directory` ab und traegt jede DATEI in `map` ein.
fn collect_digests(directory: &Path, prefix: &str, map: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(directory).expect("das Verzeichnis muss lesbar sein") {
        let entry = entry.expect("der Verzeichniseintrag muss lesbar sein");
        let name = entry
            .file_name()
            .to_str()
            .expect("der Fixture-Dateiname ist UTF-8")
            .to_owned();
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).expect("die Metadaten muessen lesbar sein");
        if metadata.is_dir() {
            collect_digests(&path, &relative, map);
        } else {
            let bytes = fs::read(&path).expect("die Datei muss lesbar sein");
            let previous = map.insert(relative, hex::encode(object_hash(&bytes).as_bytes()));
            assert!(previous.is_none(), "ein Pfad kann nur einmal vorkommen");
        }
    }
}

// ===========================================================================
// Der Kern des Tasks
// ===========================================================================

/// DER KERN DES TASKS: der Export traegt JEDE Bytesequenz des Bestands.
///
/// Der Nachweis ist ein MENGENGLEICHHEITSTEST und kein Stichprobenvergleich:
/// die vollstaendige Abbildung „relativer Pfad -> Abdruck" des Ziels muss der
/// des Quellbestands GLEICH sein. Eine Kopie, die eine Datei auslaesst, eine
/// hinzuerfindet oder ein Byte veraendert, faellt damit auf.
///
/// Der Bestand aus [`live_clock_archive`] ist der einzige der Familie mit
/// BEIWERK: `README-FORMAT.txt` und eine geschachtelte Datei unter `format/`.
/// Ohne sie waere die Aussage ueber die Nicht-Objekt-Dateien vakuum-wahr.
#[test]
fn export_preserves_every_original_byte() {
    let built = live_clock_archive();
    let laid = lay_out("export-bytes", &built);
    let before = digest_map(laid.archive.path());

    let output = run_export(&laid);

    assert_eq!(code_of(&output), 0, "exit code");
    assert_eq!(
        digest_map(&laid.target()),
        before,
        "der Export muss jede Bytesequenz unter demselben relativen Pfad tragen"
    );
    assert_eq!(
        digest_map(laid.archive.path()),
        before,
        "der Quellbestand wird ausschliesslich gelesen"
    );
}

/// AKZEPTANZKRITERIUM 38: der Export verifiziert zu DEMSELBEN `reportHash`.
///
/// Das ist die eigentliche Zusicherung — „ein vollstaendiger verschluesselter
/// Export laesst sich ohne Server, aber nur mit explizitem externem Trust
/// Anchor authentisch verifizieren". Eine byteweise Kopie, deren Bericht
/// abwiche, waere keine.
///
/// # BEIDE LAEUFE MUESSEN MIT NULL ENDEN
///
/// Ohne diese beiden Zusicherungen waere der Vergleich VAKUUM-WAHR: zwei
/// degenerierte Berichte ueber zwei stumme Bestaende stimmen ebenfalls
/// ueberein. Genau diesen Fall faengt Exitcode 15 ab, und genau ihn schliesst
/// die Uhrenregel dieses Testtargets aus. Gemessen wird deshalb zuerst der
/// Code jedes Laufs und erst danach die Gleichheit.
#[test]
fn the_exported_archive_verifies_to_the_same_report_hash() {
    let built = live_clock_archive();
    let laid = lay_out("export-hash", &built);

    assert_eq!(code_of(&run_export(&laid)), 0, "exit code des Exports");

    let original = run_verify(&laid, laid.archive.path());
    assert_eq!(code_of(&original), 0, "exit code der Quellpruefung");
    let exported = run_verify(&laid, &laid.target());
    assert_eq!(code_of(&exported), 0, "exit code der Exportpruefung");

    assert_eq!(
        report_hash_line(&exported.stdout),
        report_hash_line(&original.stdout),
        "der Export muss zu demselben reportHash verifizieren wie das Original"
    );
    // Der ganze Bericht und nicht nur seine letzte Zeile: die Zaehler —
    // `nonObjectFileCount` eingeschlossen — sind Teil derselben Aussage.
    assert_eq!(
        String::from_utf8_lossy(&exported.stdout),
        String::from_utf8_lossy(&original.stdout),
        "der Bericht ueber den Export muss der Bericht ueber das Original sein"
    );
}

// ===========================================================================
// Die Zielpruefung
// ===========================================================================

/// Ein BELEGTES Ziel endet mit 2 und laesst den vorhandenen Inhalt in Ruhe.
///
/// Code 2 und nicht 20: geschrieben wurde nichts, gefunden wurde nichts, und
/// derselbe Lauf ist mit einem anderen `--output` unveraendert wiederholbar.
/// Die Regel ist dieselbe, die `decrypt` traegt — sie steht in
/// `ea_recovery::target` genau EINMAL und wird hier nicht zum zweiten Mal
/// erfunden, sondern nur fuer diesen Kommandopfad gemessen.
#[test]
fn export_refuses_a_non_empty_target() {
    let built = live_clock_archive();
    let laid = lay_out("export-busy", &built);
    fs::create_dir(laid.target()).expect("das Zielverzeichnis muss anlegbar sein");
    fs::write(laid.target().join("schon-da.txt"), b"fremder Inhalt\n")
        .expect("die fremde Datei muss schreibbar sein");

    let output = run_export(&laid);

    assert_eq!(code_of(&output), 2, "exit code");
    assert_eq!(
        entry_names(&laid.target()),
        vec!["schon-da.txt".to_owned()],
        "im belegten Ziel darf nichts entstanden und nichts verschwunden sein"
    );
    assert_eq!(
        fs::read(laid.target().join("schon-da.txt")).expect("die fremde Datei muss lesbar sein"),
        b"fremder Inhalt\n",
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
fn export_writes_nothing_when_verification_fails() {
    let mut built = live_clock_archive();
    let mut malformed = EIP_PREFIX_V1.to_vec();
    malformed.extend_from_slice(b"nicht dekodierbar");
    built
        .fixture
        .push_exact_bytes("entries/000000000099_broken.eip", malformed);
    let laid = lay_out("export-broken", &built);

    let output = run_export(&laid);

    assert_eq!(code_of(&output), 10, "exit code");
    assert!(
        !laid.target().exists(),
        "ein gescheiterter Lauf darf das Ziel nicht einmal anlegen"
    );
}

// ===========================================================================
// Die Quellart
// ===========================================================================

/// Eine Quelle, die kein existierendes Verzeichnis ist, endet mit 21.
///
/// # ZWEI ZWEIGE, UND SIE SIND VERSCHIEDEN
///
/// Der Pfad EXISTIERT NICHT — hier landet auch jede Serveradresse, denn Stage 1
/// hat keine Serverquelle und `https://…` ist im Dateisystem schlicht nicht
/// vorhanden — oder er existiert und ist eine DATEI. Beide Wege muessen auf 21
/// fuehren und tun es aus verschiedenen Zweigen der Quellartpruefung.
///
/// Ausdruecklich NICHT 20: ein nicht unterstuetzter Quelltyp ist keine
/// Ein-/Ausgabestoerung. Der Unterschied zu `verify`, das fuer denselben Pfad
/// 20 liefert, ist gewollt — dort heisst das Argument `<archive-path>`, hier
/// `<archive-or-server>`.
#[test]
fn export_of_a_non_directory_source_is_unsupported() {
    let built = live_clock_archive();
    let laid = lay_out("export-source", &built);
    let anchor = laid.anchor_path();
    let target = laid.target_path();

    let absent = path_argument(&laid.outside.path().join("gibt-es-nicht"));
    let output = run(&[
        "--trust-anchor",
        &anchor,
        "export",
        &absent,
        "--output",
        &target,
    ]);
    assert_eq!(code_of(&output), 21, "exit code eines fehlenden Pfades");
    assert!(
        !laid.target().exists(),
        "eine abgelehnte Quelle darf kein Ziel hinterlassen"
    );

    let file = laid.outside.path().join("kein-verzeichnis.bin");
    fs::write(&file, b"kein Bestand").expect("die Datei muss schreibbar sein");
    let file = path_argument(&file);
    let output = run(&[
        "--trust-anchor",
        &anchor,
        "export",
        &file,
        "--output",
        &target,
    ]);
    assert_eq!(code_of(&output), 21, "exit code einer Datei als Quelle");
    assert!(
        !laid.target().exists(),
        "eine abgelehnte Quelle darf kein Ziel hinterlassen"
    );

    // Die Meldung NENNT die fehlende Faehigkeit, statt nur einen Code zu
    // zeigen. Ein Betreiber soll nicht raten, ob er sich vertippt hat.
    let message = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        message.contains("file system archive directory only")
            && message.contains("no server source"),
        "die Ablehnung muss sagen, dass diese Stufe nur ein Dateisystemverzeichnis \
         exportiert, war: {message}"
    );
    assert!(
        output.stdout.is_empty(),
        "eine Ablehnung gehoert nicht nach stdout, war: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

// ===========================================================================
// Rechte
// ===========================================================================

/// JEDES Verzeichnis 0700, JEDE Datei 0600 — gemessen, nicht zugesichert.
///
/// Gemessen wird der GANZE Baum und nicht nur seine Wurzel. Der Bestand aus
/// [`live_clock_archive`] traegt sein Schemabeiwerk unter `format/schemas/`,
/// also zwei angelegte Ebenen unterhalb des Ziels. Ein Schreiber, der seine
/// Zwischenverzeichnisse mit `create_dir_all` erzeugte, liesse genau diese
/// beiden mit 0755 zurueck — die Dateien darin blieben 0600, aber ihre Namen
/// und damit die Kettensequenzen des Bestands laegen offen. Eine Pruefung nur
/// der Wurzel saehe das nicht.
#[cfg(unix)]
#[test]
fn export_target_has_restrictive_permissions() {
    let built = live_clock_archive();
    let laid = lay_out("export-modes", &built);

    let output = run_export(&laid);
    assert_eq!(code_of(&output), 0, "exit code");

    let modes = mode_map(&laid.target());
    assert!(
        modes.contains_key(LIVE_FORMAT_SCHEMA_FILE_V1),
        "ohne die geschachtelte Beiwerkdatei prueft dieser Test die \
         Zwischenverzeichnisse gar nicht: {modes:?}"
    );
    for (path, mode) in &modes {
        let expected = if path.ends_with('/') { 0o700 } else { 0o600 };
        assert_eq!(
            *mode, expected,
            "{path} muss allein seinem Eigentuemer gehoeren"
        );
    }

    // Das Zielverzeichnis selbst steht in keiner seiner eigenen Eintragslisten.
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        fs::metadata(laid.target())
            .expect("das Ziel muss lesbar sein")
            .permissions()
            .mode()
            & 0o777,
        0o700,
        "das Zielverzeichnis gehoert allein seinem Eigentuemer"
    );
}
