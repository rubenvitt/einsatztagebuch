//! Die tragende Invariante von `organization init`: EINE Zeremonie, die den
//! Prozess ueberlebt — und ein Anker, den dieses Werkzeug niemals ueberschreibt.
//!
//! Zwei Saetze halten diese Datei zusammen, und beide sind hier Zeugen und
//! keine Prosa:
//!
//! 1. **Vorwaerts und wiederaufnehmbar.** Ein zweiter Lauf setzt die
//!    PERSISTIERTE Zeremonie fort und beginnt keine zweite daneben — dieselben
//!    Organisations- und Ketten-IDs, derselbe Schritt. `:1349` laesst neue
//!    Kennungen ausschliesslich nach einem Abbruch zu; ein Werkzeug, das bei
//!    jedem Aufruf neu wuerfelte, fuehrte zwei Wahrheiten ueber dieselbe
//!    Organisation.
//! 2. **Der Anker wird nicht erfunden und nicht ueberschrieben.** `:1782`
//!    verbietet Trust-on-first-use und jeden Anker aus dem geprueften Bestand.
//!    Eine belegte Ankerdatei ist deshalb ein Aufruffehler und kein Ziel.
//!
//! Gegen das GEBAUTE Binary, wie `apps/cli/tests/commands.rs`: der Exitcode ist
//! der Vertrag mit einem Prozessaufrufer, und er entsteht erst in `main`. Kein
//! `assert_cmd`, kein `predicates`.

#[path = "support/mod.rs"]
mod support;

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

/// Die Zeile, mit der die Grammatik das sechste Kommando nennt.
const ORGANIZATION_GRAMMAR_LINE: &str = "einsatzarchiv --trust-anchor <new-file> organization init";

/// Startet das Werkzeug mit `tokens` und liefert seinen vollstaendigen Ausgang.
fn run(tokens: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(tokens)
        .output()
        .expect("das Testbinary muss startbar sein")
}

/// Der Exitcode eines Laufs.
fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("der Prozess muss regulaer enden")
}

/// Ein Pfad als UTF-8-Argument.
fn argument(path: &Path) -> String {
    path.to_str()
        .expect("der vom Testrahmen selbst gebildete Pfad ist UTF-8")
        .to_owned()
}

/// Prueft, dass `tokens` mit Exitcode 2 endet und `name` WOERTLICH auf stderr
/// nennt, ohne stdout zu beruehren.
fn assert_usage_error(tokens: &[&str], name: &str) {
    let output = run(tokens);
    assert_eq!(code(&output), 2, "exit code");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(name),
        "die Meldung zu {tokens:?} muss {name} woertlich nennen, war: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "eine Fehlermeldung gehoert nicht nach stdout, war: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Die Zeilen einer erfolgreichen Statusausgabe.
fn status_lines(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Die Grammatik
// ---------------------------------------------------------------------------

/// Die gedruckte Grammatikzeile ist keine Prosa: sie LAEUFT.
///
/// Der Zeuge nimmt die Zeile, die das Werkzeug selbst gedruckt hat, ersetzt
/// ihren Platzhalter durch einen echten Pfad und fuehrt sie aus. Eine
/// Grammatik, die etwas anderes beschriebe als das, was der Parser annimmt,
/// faellt genau hier auf.
#[test]
fn the_printed_grammar_line_for_organization_init_actually_runs() {
    let printed = String::from_utf8_lossy(&run(&[]).stdout).into_owned();
    assert!(
        printed.contains(ORGANIZATION_GRAMMAR_LINE),
        "die Grammatik muss das sechste Kommando nennen, war: {printed}"
    );

    let directory = support::temp_dir("organization-grammar");
    let anchor = argument(&directory.path().join("anchor.etb"));
    let tokens: Vec<&str> = ORGANIZATION_GRAMMAR_LINE
        .split_whitespace()
        .skip(1)
        .map(|token| {
            if token == "<new-file>" {
                &anchor
            } else {
                token
            }
        })
        .collect();

    let output = run(&tokens);
    assert_eq!(code(&output), 0, "die gedruckte Zeile muss laufen");
}

/// Die Grammatik NENNT die Grenze dieser Scheibe.
///
/// Die Schritte, die eine Offline-Schluesselquelle brauchen, fuehrt dieses
/// Werkzeug nicht — `ea_key_provider::SecretPurpose` kennt keinen Wurzelzweck,
/// und ein CLI-Prozess kann die aeusseren Schluessel nicht herbeireden. Wer die
/// Grammatik liest, soll das erfahren, statt es an einem ausbleibenden Schritt
/// zu bemerken.
#[test]
fn the_grammar_says_that_this_tool_drives_no_step_that_needs_a_key_source() {
    let printed = String::from_utf8_lossy(&run(&[]).stdout).into_owned();
    assert!(
        printed.contains("offline key sources"),
        "die Grammatik muss die Grenze nennen, war: {printed}"
    );
}

// ---------------------------------------------------------------------------
// Die Aufrufform
// ---------------------------------------------------------------------------

/// Ohne `--trust-anchor` gibt es auch hier keinen Lauf.
///
/// Der Anker ist bei diesem Kommando keine gepruefte Eingabe, sondern der
/// PLATZ, den der Anker dieser Zeremonie einnehmen wird — die Pflicht bleibt
/// trotzdem, damit die Grammatik ueber alle sechs Kommandos dieselbe ist.
#[test]
fn organization_init_requires_the_trust_anchor_path() {
    assert_usage_error(&["organization", "init"], "--trust-anchor");
}

/// Die Gleichheitsform ist hier so wenig ein Schalter wie ueberall sonst.
#[test]
fn the_inline_trust_anchor_form_is_rejected_here_too() {
    assert_usage_error(
        &["--trust-anchor=anchor.etb", "organization", "init"],
        "--trust-anchor=anchor.etb",
    );
}

/// `organization` ohne Unterkommando nennt das Kommando.
#[test]
fn a_missing_subcommand_names_the_command() {
    assert_usage_error(
        &["--trust-anchor", "anchor.etb", "organization"],
        "organization",
    );
}

/// Ein unbekanntes Unterkommando wird WOERTLICH genannt.
#[test]
fn an_unknown_subcommand_is_named_verbatim() {
    assert_usage_error(
        &["--trust-anchor", "anchor.etb", "organization", "iniit"],
        "iniit",
    );
}

/// `--output` gehoert den schreibenden Kommandos; dieses schreibt keinen
/// Bestand.
#[test]
fn an_output_switch_outside_its_commands_names_the_switch() {
    assert_usage_error(
        &[
            "--trust-anchor",
            "anchor.etb",
            "organization",
            "init",
            "--output",
            "target",
        ],
        "--output",
    );
}

/// Die fuenf Wiederherstellungskommandos parsen unveraendert weiter.
///
/// Gemessen daran, dass sie NICHT auf 2 fallen: ein Aufruffehler entsteht vor
/// jedem Byte, jeder andere Ausgang beweist, dass der Parser sie
/// durchgelassen hat. Das sechste Kommando darf die fuenf nicht bewegen.
#[test]
fn the_five_recovery_commands_still_parse() {
    let directory = support::temp_dir("organization-five");
    let archive = argument(directory.path());
    let anchor = argument(&directory.path().join("absent-anchor.etb"));
    let target = argument(&directory.path().join("target"));
    let report = argument(&directory.path().join("report.json"));
    let key = argument(&directory.path().join("recipient.key"));

    for tokens in [
        vec!["--trust-anchor", &anchor, "verify", &archive],
        vec!["--trust-anchor", &anchor, "list", &archive],
        vec![
            "--trust-anchor",
            &anchor,
            "decrypt",
            &archive,
            "--key",
            &key,
            "--output",
            &target,
        ],
        vec![
            "--trust-anchor",
            &anchor,
            "report",
            &archive,
            "--output",
            &report,
        ],
        vec![
            "--trust-anchor",
            &anchor,
            "export",
            &archive,
            "--output",
            &target,
        ],
    ] {
        let output = run(&tokens);
        assert_ne!(
            code(&output),
            2,
            "{tokens:?} muss den Parser passieren, stderr war: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// ---------------------------------------------------------------------------
// Der Anker wird nicht ueberschrieben
// ---------------------------------------------------------------------------

/// Eine BELEGTE Ankerdatei beendet den Lauf, bevor irgendetwas entsteht.
///
/// Die Datei an diesem Pfad kann eine lebende Vertrauensquelle sein. `:1782`
/// laesst das Werkzeug keinen Vertrauensanker erfinden; sie ersatzweise zu
/// ueberschreiben waere genau das, nur schlimmer — es naehme einer bestehenden
/// Organisation ihre Wurzel.
#[test]
fn an_existing_anchor_file_is_never_overwritten_by_a_ceremony() {
    let directory = support::temp_dir("organization-occupied");
    let anchor_path = directory.path().join("anchor.etb");
    fs::write(&anchor_path, b"a living trust source").expect("die Datei muss schreibbar sein");
    let anchor = argument(&anchor_path);

    let output = run(&["--trust-anchor", &anchor, "organization", "init"]);
    assert_eq!(code(&output), 2, "eine belegte Ankerdatei ist Exitcode 2");
    assert!(
        output.stdout.is_empty(),
        "es ist keine Zeremonie entstanden, ueber die etwas zu sagen waere"
    );
    assert_eq!(
        fs::read(&anchor_path).expect("die Datei muss noch da sein"),
        b"a living trust source",
        "die vorhandene Ankerdatei bleibt BYTEGLEICH"
    );
    assert!(
        !directory.path().join("anchor.etb.bootstrap-state").exists(),
        "ein abgewiesener Lauf legt auch keinen Zeremoniezustand an"
    );
}

// ---------------------------------------------------------------------------
// Die Zeremonie
// ---------------------------------------------------------------------------

/// Ein frischer Lauf beginnt bei Schritt 1 von 12 — und nicht im
/// Produktivzustand.
#[test]
fn a_fresh_run_begins_the_ceremony_at_the_first_of_twelve_steps() {
    let directory = support::temp_dir("organization-fresh");
    let anchor = argument(&directory.path().join("anchor.etb"));

    let output = run(&["--trust-anchor", &anchor, "organization", "init"]);
    assert_eq!(code(&output), 0, "ein frischer Lauf gelingt");
    assert!(
        output.stderr.is_empty(),
        "ein gelungener Lauf schweigt auf stderr, war: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = status_lines(&output);
    assert_eq!(
        lines.len(),
        6,
        "die Statusausgabe ist eine GESCHLOSSENE Zeilenfolge, war: {lines:?}"
    );
    assert_eq!(lines[0], "bootstrapStep.number 1");
    assert_eq!(lines[1], "bootstrapStep.name GenerateIds");
    assert_eq!(lines[2], "bootstrapStep.count 12");
    assert!(
        lines[3].starts_with("organizationId ")
            && lines[3].trim_start_matches("organizationId ").len() == 32,
        "die Organisations-ID steht als 16 Byte Hex, war: {}",
        lines[3]
    );
    assert!(
        lines[4].starts_with("chainId ") && lines[4].trim_start_matches("chainId ").len() == 32,
        "die Ketten-ID steht als 16 Byte Hex, war: {}",
        lines[4]
    );
    assert_eq!(lines[5], "productionState BlockedRecoveryTest");
}

/// DER tragende Zeuge: der zweite Lauf SETZT FORT.
///
/// Verglichen wird die ganze Ausgabe und nicht nur der Schritt: gleiche
/// Organisations- und Ketten-ID heisst, dass es dieselbe Zeremonie ist. Ein
/// Werkzeug, das hier neu begaenne, warf die erste weg, ohne dass ein
/// Exitcode das saehe.
#[test]
fn a_second_run_resumes_the_same_ceremony_rather_than_starting_over() {
    let directory = support::temp_dir("organization-resume");
    let anchor = argument(&directory.path().join("anchor.etb"));

    let first = run(&["--trust-anchor", &anchor, "organization", "init"]);
    assert_eq!(code(&first), 0, "der erste Lauf gelingt");
    let second = run(&["--trust-anchor", &anchor, "organization", "init"]);
    assert_eq!(code(&second), 0, "der zweite Lauf gelingt ebenfalls");

    assert_eq!(
        status_lines(&second),
        status_lines(&first),
        "derselbe Schritt, dieselbe Organisation, dieselbe Kette"
    );
}

/// Der Zeremoniezustand liegt NEBEN dem kuenftigen Anker.
#[test]
fn the_ceremony_state_lives_next_to_the_anchor_path() {
    let directory = support::temp_dir("organization-state-file");
    let anchor = argument(&directory.path().join("anchor.etb"));

    assert_eq!(
        code(&run(&["--trust-anchor", &anchor, "organization", "init"])),
        0
    );
    assert!(
        directory
            .path()
            .join("anchor.etb.bootstrap-state")
            .is_file(),
        "der Zustand liegt als Datei neben dem Ankerpfad"
    );
    assert!(
        !directory.path().join("anchor.etb").exists(),
        "diese Scheibe erzeugt KEINEN Anker: dafuer fehlen die Schluesselports"
    );
}

/// Eine Ablage, die nicht antwortet, ist ein Speicherbefund: Exitcode 20.
#[test]
fn an_unwritable_state_path_ends_with_the_storage_exit_code() {
    let directory = support::temp_dir("organization-unwritable");
    let anchor = argument(&directory.path().join("anchor.etb"));
    fs::create_dir(directory.path().join("anchor.etb.bootstrap-state"))
        .expect("das Verzeichnis muss anlegbar sein");

    let output = run(&["--trust-anchor", &anchor, "organization", "init"]);
    assert_eq!(code(&output), 20, "ein Speicherbefund ist Exitcode 20");
    assert!(
        output.stdout.is_empty(),
        "ohne Zeremonie gibt es keine Statusausgabe"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("EA-CEREMONY-BOOTSTRAP-STORE-UNAVAILABLE"),
        "die Meldung nennt den stabilen Code, war: {stderr}"
    );
}

/// Fuer diese Statusausgabe gibt es kein Schema — also auch kein JSON.
///
/// `schemas/` ist geschlossen, und `crates/ea-verify` kennt genau ein
/// Berichtsdokument. Eine hier erfundene `ea.organization-bootstrap/v1` waere
/// eine Schemaaenderung durch die Hintertuer; das Werkzeug sagt stattdessen,
/// dass es diese Faehigkeit nicht hat (21) — es ist nichts misslungen.
#[test]
fn the_json_form_is_refused_because_no_schema_carries_this_status() {
    let directory = support::temp_dir("organization-json");
    let anchor = argument(&directory.path().join("anchor.etb"));

    let output = run(&[
        "--trust-anchor",
        &anchor,
        "--format",
        "json",
        "organization",
        "init",
    ]);
    assert_eq!(
        code(&output),
        21,
        "eine fehlende Faehigkeit ist Exitcode 21"
    );
    assert!(
        output.stdout.is_empty(),
        "es ist kein Dokument entstanden, ueber das etwas zu sagen waere"
    );
    assert!(
        !directory.path().join("anchor.etb.bootstrap-state").exists(),
        "die Verweigerung faellt VOR der Zeremonie"
    );
}
