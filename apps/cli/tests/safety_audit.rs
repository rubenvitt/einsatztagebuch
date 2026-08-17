//! DER SAFETY-AUDIT: die E6-Zusicherungen ueber ALLE schreibenden Kommandos.
//!
//! # Warum das EIN Test ist und nicht drei
//!
//! `decrypt`, `report` und `export` tragen dieselben vier Zusicherungen. Je
//! Kommando einzeln geprueft, sind sie drei Saetze, die auseinanderlaufen
//! koennen — und eine spaeter hinzukommende vierte Schreiboperation braechte
//! keinen einzigen Test, weil niemand ihren Test vergessen HAT: es gaebe ihn
//! einfach nicht. Deshalb steht die Kommandotabelle
//! [`WRITING_COMMANDS_V1`] hier an genau EINER Stelle, und die Schleife
//! darueber ist der Audit. Wer ein viertes schreibendes Kommando baut, traegt
//! es dort ein — oder faellt bei der naechsten Durchsicht dieser Datei auf.
//!
//! # Die vier Zusicherungen
//!
//! - (a) KEINE Klartext-Temporaerdatei: das dem Prozess vorgegebene
//!   Temporaerverzeichnis ist vor UND nach jedem Lauf leer.
//! - (b) EIN BELEGTES ZIEL wird nicht angefasst: Exitcode 2, und der
//!   vorgefundene Inhalt bleibt bytegleich.
//! - (c) RESTRIKTIVE RECHTE: unter unix traegt jedes erzeugte Verzeichnis
//!   `0o700` und jede erzeugte Datei `0o600`. Unter jeder anderen Plattform
//!   verweigert jedes schreibende Kommando mit 21, statt die Zusicherung still
//!   fallen zu lassen.
//! - (d) KEINE LAUFZEITSPUR: ohne `--include-runtime-metadata` traegt keine
//!   Ausgabe eines Kommandos den absoluten Quellpfad und keinen Zeitstempel
//!   aus der Laufzeit.
//!
//! # (b) UND (c) SCHLIESSEN EINANDER AUS — auf genau einer Plattform
//!
//! `ea_recovery` prueft die Plattformfaehigkeit VOR dem Ziel: unter
//! `cfg(not(unix))` endet jedes schreibende Kommando mit 21, bevor es ein
//! belegtes Ziel ueberhaupt ansieht. Eine unbedingt geschriebene Zusicherung
//! (b) waere dort selbstwidersprechend. Der Audit hat deshalb zwei Arme, und
//! der zweite ist auf dieser Maschine nicht ausfuehrbar — er ist als
//! Uebersetzungsaussage geschrieben und im `bericht` als solche benannt.
//!
//! # DIE UHR IST HIER KEIN PARAMETER
//!
//! Die CLI kennt genau eine, `SystemTime::now()`. Jeder Bestand stammt deshalb
//! aus der `live_clock_*`-Familie; die geerbten Bestaende sind unter der echten
//! Uhr stumm. Die Begruendung steht in `apps/cli/tests/support/mod.rs`.

#[path = "support/mod.rs"]
mod support;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use ea_crypto::object_hash;

use support::{
    LiveArchive, TempDir, live_clock_archive, materialize, temp_dir,
    verify_support::complete_recipient_secret_bytes,
};

// ===========================================================================
// Die Kommandotabelle
// ===========================================================================

/// Die Art des Ziels, das ein schreibendes Kommando vorgelegt bekommt.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    /// `decrypt` und `export` schreiben in ein VERZEICHNIS.
    Directory,
    /// `report` schreibt eine DATEI.
    File,
}

/// Ein schreibendes Kommando, so wie der Audit es ansieht.
struct WritingCommand {
    /// Das Verb der Grammatik.
    verb: &'static str,
    /// Die Art seines `--output`.
    target: TargetKind,
    /// Der Name, unter dem sein Ziel im Testaufbau liegt.
    target_name: &'static str,
}

/// ALLE Kommandos, die dieses Werkzeug schreiben laesst.
///
/// Waechst diese Tabelle, waechst der Audit mit — ohne dass eine einzige
/// Zusicherung ein zweites Mal geschrieben werden muss.
const WRITING_COMMANDS_V1: &[WritingCommand] = &[
    WritingCommand {
        verb: "decrypt",
        target: TargetKind::Directory,
        target_name: "klartext",
    },
    WritingCommand {
        verb: "report",
        target: TargetKind::File,
        target_name: "bericht.json",
    },
    WritingCommand {
        verb: "export",
        target: TargetKind::Directory,
        target_name: "export",
    },
];

/// Die LESENDEN Kommandos. Sie schreiben nichts und stehen nur in (d).
const READING_COMMANDS_V1: &[&str] = &["verify", "list"];

// ===========================================================================
// Aufbau
// ===========================================================================

/// Ein abgelegter Bestand samt Anker, Schluesseldatei und Zielraum.
///
/// Anker, Schluessel und jedes Ziel liegen in einem EIGENEN Verzeichnis und
/// niemals im Bestand: `ea_recovery::FsArchiveSource::open` liest ein
/// Bestandsverzeichnis vollstaendig und zaehlte sie sonst als Beiwerk mit.
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

    /// Ein Zielpfad unter `name`. Existiert AUSDRUECKLICH noch nicht.
    fn target(&self, name: &str) -> PathBuf {
        self.outside.path().join(name)
    }
}

/// Ein vom Testrahmen selbst gebildeter Pfad als Argumentzeichenkette.
fn path_argument(path: &Path) -> String {
    path.to_str()
        .expect("der vom Testrahmen selbst gebildete Pfad ist UTF-8")
        .to_owned()
}

/// Legt Bestand, Anker und Schluesseldatei ab.
fn lay_out(tag: &str, built: &LiveArchive) -> Laid {
    let archive = temp_dir(&format!("audit-{tag}-archive"));
    materialize(&built.fixture, archive.path());
    let outside = temp_dir(&format!("audit-{tag}-outside"));
    fs::write(outside.path().join("anchor.bin"), &built.anchor_bytes)
        .expect("die Ankerdatei muss schreibbar sein");
    fs::write(
        outside.path().join("key.bin"),
        complete_recipient_secret_bytes(),
    )
    .expect("die Schluesseldatei muss schreibbar sein");
    Laid { archive, outside }
}

/// Die Aufrufzeile eines schreibenden Kommandos mit `target` als `--output`.
fn writing_argv(command: &WritingCommand, laid: &Laid, target: &Path) -> Vec<String> {
    let mut argv = vec![
        "--trust-anchor".to_owned(),
        laid.anchor_path(),
        command.verb.to_owned(),
        laid.archive_path(),
    ];
    if command.verb == "decrypt" {
        argv.push("--key".to_owned());
        argv.push(laid.key_path());
    }
    argv.push("--output".to_owned());
    argv.push(path_argument(target));
    argv
}

/// Die Aufrufzeile eines lesenden Kommandos.
fn reading_argv(verb: &str, laid: &Laid) -> Vec<String> {
    vec![
        "--trust-anchor".to_owned(),
        laid.anchor_path(),
        verb.to_owned(),
        laid.archive_path(),
    ]
}

// ===========================================================================
// Der Prozessstart — mit Zusicherung (a) eingebaut
// ===========================================================================

/// Startet das Werkzeug mit einem VORGEGEBENEN Temporaerverzeichnis und
/// belegt dabei Zusicherung (a) fuer DIESEN Lauf.
///
/// Der eigene Prozess wird ausdruecklich NICHT umgestellt: `cargo test` faehrt
/// die Tests eines Targets parallel in Threads, und eine Momentaufnahme von
/// `env::temp_dir()` saehe die Temporaerverzeichnisse der Nachbartests. Das
/// Kind bekommt deshalb sein eigenes, und der Vergleich ist die EINTRAGSMENGE
/// dieses Verzeichnisses vor und nach dem Lauf.
///
/// Alle drei Namen werden gesetzt, weil `std::env::temp_dir` sie je nach
/// Plattform verschieden liest: `TMPDIR` auf unix, `TMP` und `TEMP` auf
/// Windows.
fn run_audited(argv: &[String], label: &str) -> Output {
    let temporary = temp_dir("audit-tmpdir");
    let before = entry_names(temporary.path());
    assert!(
        before.is_empty(),
        "{label}: der vorgegebene Temporaerpfad muss leer beginnen, war {before:?}"
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"));
    command.args(argv);
    for name in ["TMPDIR", "TMP", "TEMP"] {
        command.env(name, temporary.path());
    }
    let output = command.output().expect("das Testbinary muss startbar sein");

    let after = entry_names(temporary.path());
    assert_eq!(
        after, before,
        "(a) {label}: der Lauf darf im Temporaerpfad nichts hinterlassen"
    );
    output
}

/// Der Exitcode eines Laufs.
fn code_of(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("der Prozess muss regulaer enden")
}

// ===========================================================================
// Messwerkzeug
// ===========================================================================

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

/// Die Abbildung „relativer Pfad -> Abdruck der Bytes" eines Ziels.
///
/// Eine DATEI liefert einen einzigen Eintrag unter dem leeren Pfad; ein
/// VERZEICHNIS seinen ganzen Baum. Damit vergleicht (b) beide Zielarten mit
/// demselben Ausdruck.
///
/// [`object_hash`] ist SHA-256 ueber ein festes Domainpraefix und die EXAKTEN
/// Bytes; die Gleichheit dieser Abbildung ist der Gleichheit der Byteabbildung
/// gleichwertig — nur dass ein Fehlschlag zwei Hexzeilen zeigt statt zweier
/// Bytehalden.
fn digest_map(root: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let metadata = fs::symlink_metadata(root).expect("das Ziel muss lesbar sein");
    if metadata.is_dir() {
        collect_digests(root, "", &mut map);
    } else {
        let bytes = fs::read(root).expect("die Zieldatei muss lesbar sein");
        map.insert(String::new(), hex::encode(object_hash(&bytes).as_bytes()));
    }
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

/// Die Abbildung „relativer Pfad -> Rechte" eines Ziels.
///
/// Verzeichnisse tragen einen abschliessenden `/`, damit der Aufrufer beide
/// Arten in EINER Schleife unterscheiden kann. Die WURZEL steht mit darin —
/// sie ist selbst ein erzeugter Eintrag und faellt sonst durch jede Pruefung,
/// die nur ihre Eintragslisten liest.
#[cfg(unix)]
fn mode_map(root: &Path) -> BTreeMap<String, u32> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut map = BTreeMap::new();
    let metadata = fs::symlink_metadata(root).expect("das Ziel muss lesbar sein");
    let mode = metadata.permissions().mode() & 0o777;
    if metadata.is_dir() {
        map.insert("/".to_owned(), mode);
        collect_modes(root, "", &mut map);
    } else {
        map.insert(String::new(), mode);
    }
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

// ===========================================================================
// (d): der Laufzeitspuren-Scanner
// ===========================================================================

/// Das Fenster um die eigene Uhr, in dem eine Zahl als LAUFZEITSTEMPEL gilt.
///
/// Ein Tag. Die Zahl ist an den Fixture-Konstanten gemessen und nicht geraten:
/// die Zeitwerte, die dieser Bestand legitim in einen Bericht traegt, sind
/// `LIVE_CREATED_AT_DEVICE_V1` (1e9), `LIVE_POLICY_NOT_AFTER_V1` (1e12, also
/// 2001) und `LIVE_WRITER_NOT_AFTER_V1` (4_102_444_800_000, also 2100). Keiner
/// liegt naeher als Jahre an der echten Uhr, und keiner faellt deshalb je in
/// dieses Fenster. Umgekehrt liegt `runtimeMetadata.generatedAt` immer darin.
const RUNTIME_WINDOW_MS_V1: u64 = 86_400_000;

/// Die eigene Uhr in Millisekunden.
fn now_millis() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("die Uhr muss nach der Unix-Epoche stehen")
            .as_millis(),
    )
    .expect("die Uhr passt in u64-Millisekunden")
}

/// Ob `text` eine Dezimalzahl traegt, die innerhalb eines Tages um `now` liegt.
///
/// Gesucht wird ueber DEZIMALFOLGEN und nicht ueber eine Jahreszahl als
/// Zeichenkette: dieses Bauwerk drueckt Laufzeit ueberall in
/// Unix-Millisekunden aus — `runtimeMetadata.generatedAt` ebenso wie jeder
/// andere Zeitwert. Eine Suche nach „2026" faende genau die Form, die nirgends
/// vorkommt, und uebersaehe die, die vorkommt.
fn carries_a_runtime_timestamp(text: &str, now: u64) -> Option<u64> {
    let mut digits = String::new();
    let mut found = None;
    for character in text.chars().chain(std::iter::once(' ')) {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        if let Ok(value) = digits.parse::<u64>()
            && value.abs_diff(now) <= RUNTIME_WINDOW_MS_V1
        {
            found = Some(value);
        }
        digits.clear();
    }
    found
}

/// Eine gesammelte Ausgabe: woher sie stammt und was sie traegt.
struct Emission {
    label: String,
    text: String,
}

impl Emission {
    /// stdout UND stderr eines Laufs, als EIN Text.
    fn of(label: &str, output: &Output) -> Self {
        Self {
            label: label.to_owned(),
            text: format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }

    /// Ein geschriebenes Dokument.
    fn document(label: &str, path: &Path) -> Self {
        Self {
            label: label.to_owned(),
            text: String::from_utf8(fs::read(path).expect("das Dokument muss lesbar sein"))
                .expect("das Dokument ist UTF-8"),
        }
    }
}

// ===========================================================================
// DER AUDIT
// ===========================================================================

/// DER KERN DIESES TASKS: die vier E6-Zusicherungen ueber JEDES schreibende
/// Kommando, in EINER Schleife.
#[test]
fn no_writing_command_ever_leaves_plaintext_or_a_loose_target() {
    let now = now_millis();
    let mut emissions: Vec<Emission> = Vec::new();
    let mut source_paths: Vec<String> = Vec::new();

    // Die lesenden Kommandos stehen nur in (d) — sie schreiben nichts.
    {
        let built = live_clock_archive();
        let laid = lay_out("reading", &built);
        source_paths.push(laid.archive_path());
        for verb in READING_COMMANDS_V1 {
            for format in ["text", "json"] {
                let mut argv = reading_argv(verb, &laid);
                argv.splice(2..2, ["--format".to_owned(), format.to_owned()]);
                let label = format!("{verb} --format {format}");
                let output = run_audited(&argv, &label);
                assert_eq!(code_of(&output), 0, "exit code von {label}");
                emissions.push(Emission::of(&label, &output));
            }
        }
    }

    for command in WRITING_COMMANDS_V1 {
        let verb = command.verb;
        let built = live_clock_archive();
        let laid = lay_out(verb, &built);
        source_paths.push(laid.archive_path());

        // -------------------------------------------------------------------
        // Der ERFOLGSLAUF: (a) steckt in `run_audited`, (c) folgt darunter.
        // -------------------------------------------------------------------
        let target = laid.target(command.target_name);
        let argv = writing_argv(command, &laid, &target);
        let output = run_audited(&argv, verb);
        emissions.push(Emission::of(verb, &output));

        #[cfg(unix)]
        {
            assert_eq!(code_of(&output), 0, "exit code von {verb}");

            // (c) JEDES erzeugte Verzeichnis 0700, JEDE erzeugte Datei 0600.
            // Gemessen wird der GANZE Baum samt Wurzel: ein Schreiber, der
            // seine Zwischenebenen mit `create_dir_all` erzeugte, liesse
            // genau die mit 0755 zurueck, und die Dateinamen — also die
            // Kettensequenzen des Bestands — laegen offen.
            let modes = mode_map(&target);
            assert!(
                !modes.is_empty(),
                "(c) {verb}: das Ziel muss nach einem Erfolgslauf Eintraege tragen"
            );
            for (path, mode) in &modes {
                let expected = if path.is_empty() || !path.ends_with('/') {
                    0o600
                } else {
                    0o700
                };
                assert_eq!(
                    *mode, expected,
                    "(c) {verb}: {path} muss allein seinem Eigentuemer gehoeren"
                );
            }

            if command.target == TargetKind::File {
                emissions.push(Emission::document(&format!("{verb} document"), &target));
            }
        }
        #[cfg(not(unix))]
        {
            // Diese Plattform kann keine restriktiven Rechte setzen. Dann wird
            // VERWEIGERT und nicht abgeschwaecht — und dann gibt es auch kein
            // Ziel, dessen Inhalt (b) noch vergleichen koennte.
            assert_eq!(
                code_of(&output),
                21,
                "(c) {verb}: ohne restriktive Rechte muss verweigert werden"
            );
            assert!(
                !target.exists(),
                "(c) {verb}: eine Verweigerung darf kein Ziel hinterlassen"
            );
        }

        // -------------------------------------------------------------------
        // (b) EIN BELEGTES ZIEL: Code 2, und der Inhalt bleibt bytegleich.
        //
        // Unter `cfg(not(unix))` gibt es diese Aussage nicht: die
        // Plattformpruefung steht VOR der Zielpruefung, der Lauf endet dort
        // schon mit 21, und eine unbedingt geschriebene Zusicherung waere
        // selbstwidersprechend.
        // -------------------------------------------------------------------
        #[cfg(unix)]
        {
            let occupied = laid.target(&format!("{}-belegt", command.target_name));
            match command.target {
                TargetKind::Directory => {
                    fs::create_dir(&occupied).expect("das Zielverzeichnis muss anlegbar sein");
                    fs::write(occupied.join("schon-da.txt"), b"fremder Inhalt\n")
                        .expect("die fremde Datei muss schreibbar sein");
                }
                TargetKind::File => {
                    fs::write(&occupied, b"fremder Inhalt\n")
                        .expect("die fremde Datei muss schreibbar sein");
                }
            }
            let before = digest_map(&occupied);

            let argv = writing_argv(command, &laid, &occupied);
            let output = run_audited(&argv, &format!("{verb} (belegtes Ziel)"));
            emissions.push(Emission::of(&format!("{verb} (belegtes Ziel)"), &output));

            assert_eq!(
                code_of(&output),
                2,
                "(b) {verb}: ein belegtes Ziel ist ein Aufruffehler"
            );
            assert_eq!(
                digest_map(&occupied),
                before,
                "(b) {verb}: im belegten Ziel darf sich kein Byte aendern"
            );
        }
    }

    // -----------------------------------------------------------------------
    // (d) KEINE LAUFZEITSPUR in irgendeiner Ausgabe.
    // -----------------------------------------------------------------------
    assert!(
        emissions.len() >= READING_COMMANDS_V1.len() * 2 + WRITING_COMMANDS_V1.len(),
        "(d) prueft sonst weniger Ausgaben als es Kommandos gibt"
    );
    for emission in &emissions {
        for source in &source_paths {
            assert!(
                !emission.text.contains(source.as_str()),
                "(d) {}: die Ausgabe nennt den absoluten Quellpfad {source}:\n{}",
                emission.label,
                emission.text
            );
        }
        assert!(
            carries_a_runtime_timestamp(&emission.text, now).is_none(),
            "(d) {}: die Ausgabe traegt einen Zeitstempel aus der Laufzeit:\n{}",
            emission.label,
            emission.text
        );
    }

    // Der WAECHTER gegen eine vakuum-wahre (d): mit
    // `--include-runtime-metadata` muessen beide gesuchten Spuren WIRKLICH
    // auftauchen. Ohne diesen Lauf bestuende (d) auch dann, wenn der Scanner
    // gar nichts faende.
    #[cfg(unix)]
    {
        let built = live_clock_archive();
        let laid = lay_out("runtime", &built);
        let target = laid.target("mit-laufzeit.json");
        let mut argv = writing_argv(&WRITING_COMMANDS_V1[1], &laid, &target);
        argv.insert(0, "--include-runtime-metadata".to_owned());
        let output = run_audited(&argv, "report --include-runtime-metadata");
        assert_eq!(code_of(&output), 0, "exit code des Waechterlaufs");

        let document = Emission::document("runtimeMetadata", &target);
        assert!(
            document.text.contains(&laid.archive_path()),
            "der Waechterlauf muss den absoluten Quellpfad tragen, sonst misst \
             (d) den Pfadvergleich gar nicht:\n{}",
            document.text
        );
        assert!(
            carries_a_runtime_timestamp(&document.text, now).is_some(),
            "der Waechterlauf muss einen Laufzeitstempel tragen, sonst misst \
             (d) den Zeitvergleich gar nicht:\n{}",
            document.text
        );
    }
}
