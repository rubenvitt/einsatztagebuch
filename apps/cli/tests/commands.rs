//! Die Aufrufgrammatik, gemessen am echten Prozess.
//!
//! Gegen das GEBAUTE Binary und nicht gegen `parse`: der Exitcode ist der
//! Vertrag mit einem Prozessaufrufer, und er entsteht erst in `main`.
//! `env!("CARGO_BIN_EXE_einsatzarchiv")` liefert dessen Pfad, ohne dass
//! irgendwo ein Zielverzeichnis geraten werden muss. Kein `assert_cmd`, kein
//! `predicates` — dieser Task nimmt keine neue externe Dependency auf.
//!
//! # Arbeitsteilung mit den Unittests in `src/args.rs`
//!
//! Dort wird die ZUORDNUNG gemessen: welche Argumentfolge auf welche
//! `UsageError`-Auspraegung faellt, ohne Prozessstart und ohne Formatierung.
//! Hier wird gemessen, was den PROZESS verlaesst: Exitcode 2, der woertlich
//! benannte Name auf dem richtigen Strom. Beides ist noetig — eine Zuordnung
//! ohne Prozess sagt nichts ueber den Exitcode, und ein Exitcode ohne
//! Zuordnung nichts darueber, warum er kam.

#[path = "support/mod.rs"]
mod support;

use std::process::{Command, Output};

/// Die sechs Zeilen der Grammatik, wie sie das Werkzeug auf stdout druckt.
const GRAMMAR_V1: [&str; 6] = [
    "einsatzarchiv --trust-anchor <file> verify  <archive-path>",
    "einsatzarchiv --trust-anchor <file> list    <archive-path>",
    "einsatzarchiv --trust-anchor <file> decrypt <archive-path> --key <key-source> --output <target>",
    "einsatzarchiv --trust-anchor <file> report  <archive-path> --output <report-file>",
    "einsatzarchiv --trust-anchor <file> export  <archive-or-server> --output <new-target>",
    "einsatzarchiv --trust-anchor <new-file> organization init",
];

/// Startet das Werkzeug mit `tokens` und liefert seinen vollstaendigen Ausgang.
fn run(tokens: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(tokens)
        .output()
        .expect("das Testbinary muss startbar sein")
}

/// Prueft, dass `tokens` mit Exitcode 2 endet und `name` WOERTLICH auf stderr
/// nennt.
///
/// Zusaetzlich: stdout bleibt leer. Eine Fehlermeldung, die in einen
/// umgelenkten Berichtsstrom liefe, machte dessen Inhalt unbrauchbar.
fn assert_usage_error(tokens: &[&str], name: &str) {
    let output = run(tokens);

    let code = output
        .status
        .code()
        .expect("der Prozess muss regulaer enden");
    assert_eq!(code, 2, "exit code");

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

/// Ohne `--trust-anchor` gibt es keinen Lauf — bei ALLEN FUENF Kommandos.
///
/// `design.md`:1765 laesst dazu keinen Spielraum: der Anker kommt von aussen
/// und nie aus dem Bestand. Ein Werkzeug, das ihn weglassen liesse, verschoebe
/// die Entscheidung darueber, wem geglaubt wird, still in das zu pruefende
/// Archiv.
///
/// Das Ziel ist ein LEERES, existierendes Verzeichnis. Der Punkt ist genau,
/// dass es nicht darauf ankommt: die Grammatik entscheidet, bevor ein Byte
/// gelesen wird. Deshalb sind auch die uebrigen Schalter der schreibenden
/// Kommandos vollstaendig gesetzt — abgelehnt wird allein der fehlende Anker.
#[test]
fn trust_commands_require_external_anchor() {
    let archive = support::temp_dir("usage-archive");
    let archive_argument = archive
        .path()
        .to_str()
        .expect("der vom Testrahmen selbst gebildete Pfad ist UTF-8")
        .to_owned();
    let archive_path = archive_argument.as_str();

    for tokens in [
        vec!["verify", archive_path],
        vec!["list", archive_path],
        vec![
            "decrypt",
            archive_path,
            "--key",
            "recipient.key",
            "--output",
            "target",
        ],
        vec!["report", archive_path, "--output", "report.json"],
        vec!["export", archive_path, "--output", "target"],
    ] {
        assert_usage_error(&tokens, "--trust-anchor");
    }
}

#[test]
fn an_unknown_command_is_named_verbatim() {
    assert_usage_error(
        &["--trust-anchor", "anchor.etb", "veriify", "archive"],
        "veriify",
    );
}

#[test]
fn a_missing_positional_argument_names_the_command() {
    assert_usage_error(&["--trust-anchor", "anchor.etb", "verify"], "verify");
}

#[test]
fn a_surplus_positional_argument_names_the_command() {
    assert_usage_error(
        &[
            "--trust-anchor",
            "anchor.etb",
            "verify",
            "archive",
            "second",
        ],
        "verify",
    );
}

#[test]
fn a_missing_output_names_the_switch() {
    assert_usage_error(
        &["--trust-anchor", "anchor.etb", "report", "archive"],
        "--output",
    );
}

#[test]
fn a_missing_key_names_the_switch() {
    assert_usage_error(
        &[
            "--trust-anchor",
            "anchor.etb",
            "decrypt",
            "archive",
            "--output",
            "target",
        ],
        "--key",
    );
}

#[test]
fn an_unknown_format_value_names_the_switch() {
    assert_usage_error(
        &[
            "--trust-anchor",
            "anchor.etb",
            "--format",
            "yaml",
            "verify",
            "archive",
        ],
        "--format",
    );
}

#[test]
fn a_switch_without_a_value_names_the_switch() {
    assert_usage_error(&["--trust-anchor"], "--trust-anchor");
}

#[test]
fn a_duplicated_switch_names_the_switch() {
    assert_usage_error(
        &[
            "--trust-anchor",
            "one.etb",
            "--trust-anchor",
            "two.etb",
            "verify",
            "archive",
        ],
        "--trust-anchor",
    );
}

#[test]
fn runtime_metadata_outside_report_names_the_switch() {
    assert_usage_error(
        &[
            "--trust-anchor",
            "anchor.etb",
            "--include-runtime-metadata",
            "verify",
            "archive",
        ],
        "--include-runtime-metadata",
    );
}

/// Ohne Argumente ist die Grammatik eine NUTZAUSGABE.
///
/// Deshalb stdout und nicht stderr — und trotzdem Exitcode 2: es wurde kein
/// Lauf ausgefuehrt. Ein Werkzeug, das bei fehlendem Kommando 0 lieferte,
/// meldete einem Skript Erfolg, ohne etwas getan zu haben.
#[test]
fn an_empty_command_line_prints_the_grammar_to_stdout() {
    let output = run(&[]);

    let code = output
        .status
        .code()
        .expect("der Prozess muss regulaer enden");
    assert_eq!(code, 2, "exit code");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in GRAMMAR_V1 {
        assert!(
            stdout.contains(line),
            "die Grammatik muss {line} enthalten, war: {stdout}"
        );
    }
    assert!(
        output.stderr.is_empty(),
        "die Grammatik ist eine Nutzausgabe und gehoert nicht nach stderr, war: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
