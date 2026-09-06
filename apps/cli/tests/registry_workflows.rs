//! Die beiden Verwaltungskommandos `registry` und `clock-release`.
//!
//! # Zwei Messebenen, und sie messen Verschiedenes
//!
//! Gegen das GEBAUTE Binary wird gemessen, was den Prozess verlaesst:
//! Grammatikzeile, Exitcode, welcher Strom. Gegen die per `#[path]`
//! eingebundene [`output`]-Einheit wird gemessen, WELCHE ZEILEN entstehen —
//! dasselbe Muster, das `apps/cli/tests/operator.rs` bereits fuehrt.
//!
//! Die zweite Ebene ist hier nicht bequem, sondern noetig. Die Zeilen, um die
//! es geht, tragen die Zusagen des Plans an die Bedienfuehrung: dass ein
//! Widerruf nichts zurueckholt, und dass ohne unabhaengige Zeitreferenz GAR
//! KEINE Freigabe angeboten wird. Beide sind nur an der Ausgabe messbar, und
//! ein Bestand, der sie ueber den Prozess erreichbar machte, brauchte eine
//! vollstaendige, OS-gebundene Bedienerlaufzeit.
//!
//! # Die Nonce
//!
//! Gemessen wird sie nicht mit einem `contains`, sondern mit einem
//! GESCHLOSSENEN Zeilenvergleich: die Ausgabe der Freigabe wird Zeile fuer
//! Zeile gegen eine feste Folge geprueft, die von keinem Eingabebyte abhaengt.
//! Ein `contains` bewiese nur, dass eine bestimmte Zeichenkette fehlt; ein
//! geschlossener Vergleich schliesst jede zusaetzliche Zeile aus.
#![cfg(test)]

#[allow(dead_code)]
#[path = "../src/args.rs"]
mod args;
#[allow(dead_code)]
#[path = "../src/output.rs"]
mod output;

use std::process::{Command, Output};

use ea_admin::{clock_release::ClockReleaseAvailability, revocation::RevocationTargetClass};
use ea_types::{ChainSequence, RegistryVersion};

use output::RevocationPlanView;

/// Ein Plan, dessen Zahlen samtlich verschieden sind.
///
/// Verschieden, damit eine vertauschte Zuordnung auffaellt: gleiche Zahlen
/// liessen `stops_new_grants_from` und `valid_through_sequence` unbemerkt die
/// Plaetze tauschen.
fn view() -> RevocationPlanView {
    RevocationPlanView {
        target_class: RevocationTargetClass::OperatorBinding,
        registry_version: RegistryVersion::new(4),
        stops_new_grants_from: ChainSequence::new(10),
        valid_through_sequence: ChainSequence::new(20),
        recalls_issued_grants: false,
        recalls_decrypted_plaintext: false,
    }
}

/// Startet das Werkzeug mit `tokens` und liefert seinen vollstaendigen Ausgang.
fn run(tokens: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(tokens)
        .output()
        .expect("das Testbinary muss startbar sein")
}

/// Die Textform ist eine GESCHLOSSENE Zeilenfolge.
#[test]
fn the_revocation_plan_report_is_a_closed_line_sequence() {
    assert_eq!(
        output::revocation_plan_lines(&view()),
        vec![
            "target_class=operator-binding".to_owned(),
            "registry_version=4".to_owned(),
            "stops_new_grants_from=10".to_owned(),
            "valid_through_sequence=20".to_owned(),
            "recalls_issued_grants=false".to_owned(),
            "recalls_decrypted_plaintext=false".to_owned(),
            output::REVOCATION_SCOPE_NOTE_V1.to_owned(),
        ]
    );
}

/// Die drei Zielarten werden in der Ausgabe UNTERSCHIEDEN.
#[test]
fn every_revocation_target_class_has_its_own_word() {
    let words: Vec<String> = [
        RevocationTargetClass::NonAdminDevice,
        RevocationTargetClass::OperatorBinding,
        RevocationTargetClass::Component,
    ]
    .into_iter()
    .map(|class| {
        let mut view = view();
        view.target_class = class;
        output::revocation_plan_lines(&view)[0].clone()
    })
    .collect();
    assert_eq!(
        words,
        vec![
            "target_class=non-admin-device".to_owned(),
            "target_class=operator-binding".to_owned(),
            "target_class=component".to_owned(),
        ]
    );
}

/// Der Widerrufstext sagt die Nicht-Rueckholbarkeit AUSDRUECKLICH.
///
/// Das ist eine Zusage des Umsetzungsplans an die Bedienfuehrung und kein
/// Kommentar: vergangene Freigaben und bereits entschluesselter Klartext
/// kommen nicht zurueck, und ausbleiben tun allein NEUE Freigaben ab der
/// Wirksamkeitssequenz.
#[test]
fn the_revocation_scope_note_states_what_is_not_recalled() {
    let note = output::REVOCATION_SCOPE_NOTE_V1;
    for phrase in [
        "already issued grants",
        "already decrypted plaintext",
        "are not recalled",
        "only new grants",
        "effective sequence",
    ] {
        assert!(
            note.contains(phrase),
            "der Widerrufstext muss {phrase} nennen, war: {note}"
        );
    }
}

/// Die JSON-Form traegt DIESELBEN geschlossenen Felder.
#[test]
fn the_revocation_plan_json_carries_the_same_closed_fields() {
    assert_eq!(
        output::revocation_plan_json(&view()),
        format!(
            "{{\"target_class\":\"operator-binding\",\"registry_version\":4,\
             \"stops_new_grants_from\":10,\"valid_through_sequence\":20,\
             \"recalls_issued_grants\":false,\"recalls_decrypted_plaintext\":false,\
             \"scope_note\":\"{}\"}}",
            output::REVOCATION_SCOPE_NOTE_V1
        )
    );
}

/// Die DREI Verfuegbarkeiten sind in der Ausgabe unterscheidbar.
#[test]
fn the_three_clock_release_availabilities_are_distinguishable() {
    let notes = [
        ClockReleaseAvailability::Offered,
        ClockReleaseAvailability::IndependentTimeUnavailable,
        ClockReleaseAvailability::NotBlocked,
    ]
    .map(output::clock_release_availability_note);
    assert_ne!(notes[0], notes[1]);
    assert_ne!(notes[1], notes[2]);
    assert_ne!(notes[0], notes[2]);
}

/// Ohne unabhaengige Referenz wird GAR KEINE Freigabe angeboten.
///
/// Der Unterschied zu „angeboten und abgewiesen" ist der ganze Punkt: eine
/// Bedienfuehrung, die beides gleich beschriebe, liesse einen Betreiber nach
/// einer Freigabe suchen, die es nicht gibt.
#[test]
fn an_absent_independent_reference_offers_no_release_at_all() {
    let unavailable = output::clock_release_availability_note(
        ClockReleaseAvailability::IndependentTimeUnavailable,
    );
    assert!(
        unavailable.contains("no clock release is offered"),
        "war: {unavailable}"
    );
    let offered = output::clock_release_availability_note(ClockReleaseAvailability::Offered);
    assert!(
        offered.contains("was offered") && offered.contains("refused"),
        "war: {offered}"
    );
    let not_blocked = output::clock_release_availability_note(ClockReleaseAvailability::NotBlocked);
    assert!(not_blocked.contains("not blocked"), "war: {not_blocked}");
}

/// KEINE Ausgabe der Freigabe haengt an ihren Bytes — und damit an ihrer Nonce.
///
/// Alle vier Zeichenketten sind Konstanten ohne Platzhalter. Das ist die
/// strukturelle Zusicherung: was von keinem Eingabebyte abhaengt, kann keine
/// Nonce tragen.
#[test]
fn no_clock_release_output_depends_on_the_release_bytes() {
    let mut texts = vec![output::CLOCK_RELEASE_APPLIED_V1.to_owned()];
    texts.extend(
        [
            ClockReleaseAvailability::Offered,
            ClockReleaseAvailability::IndependentTimeUnavailable,
            ClockReleaseAvailability::NotBlocked,
        ]
        .into_iter()
        .map(|availability| output::clock_release_availability_note(availability).to_owned()),
    );
    for text in texts {
        assert!(
            text.is_ascii() && !text.contains('{') && !text.contains('%'),
            "eine Freigabezeile darf keinen Platzhalter tragen, war: {text}"
        );
    }
}

/// Die Grammatik fuehrt die beiden neuen Kommandos WOERTLICH.
#[test]
fn the_grammar_lists_both_new_commands() {
    let output = run(&[]);
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in [
        "einsatzarchiv --trust-anchor <file> registry revocation-plan --operator-config <file> \
         --effective-from <sequence> --valid-through <sequence> --not-after <unix-millis>",
        "einsatzarchiv --trust-anchor <file> clock-release apply --operator-config <file> \
         --release <file>",
    ] {
        assert!(
            stdout.contains(line),
            "die Grammatik muss {line} enthalten, war: {stdout}"
        );
    }
}

/// Die Grammatik verspricht NUR, was das Werkzeug kann.
///
/// `issue` und `availability` der Freigabe sind von `apps/cli` aus nicht
/// erreichbar — beide verlangen Typen aus `ea-trust` beziehungsweise
/// `ea-time` in ihrer Signatur. Sie duerfen deshalb in keiner Grammatikzeile
/// stehen.
#[test]
fn the_grammar_promises_no_unreachable_clock_release_step() {
    let stdout = String::from_utf8_lossy(&run(&[]).stdout).into_owned();
    for absent in ["clock-release issue", "clock-release availability"] {
        assert!(
            !stdout.contains(absent),
            "die Grammatik darf {absent} nicht versprechen, war: {stdout}"
        );
    }
}

/// Die angehaengte Wertform wird auch am Prozess abgewiesen.
#[test]
fn an_attached_switch_value_is_rejected_by_the_process() {
    for token in [
        "--effective-from=10",
        "--valid-through=20",
        "--not-after=1700000000000",
        "--release=release.local-audit",
    ] {
        let output = run(&["--trust-anchor", "anchor.etb", token, "registry"]);
        assert_eq!(output.status.code(), Some(2), "{token}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(token),
            "{token} muss woertlich genannt werden"
        );
        assert!(output.stdout.is_empty(), "{token}");
    }
}

/// Ein Schalter ohne Wert nennt SEINEN Namen und schreibt nichts nach stdout.
#[test]
fn a_new_switch_without_a_value_is_rejected_by_the_process() {
    for switch in [
        "--effective-from",
        "--valid-through",
        "--not-after",
        "--release",
    ] {
        let output = run(&["--trust-anchor", "anchor.etb", switch]);
        assert_eq!(output.status.code(), Some(2), "{switch}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(switch),
            "{switch} muss woertlich genannt werden"
        );
        assert!(output.stdout.is_empty(), "{switch}");
    }
}

/// Eine Bedienerdatei ohne Widerrufsziel endet mit einer BENANNTEN Ablehnung.
///
/// Exitcode 2 und nicht 12: am Bestand liegt es nicht, es wurde kein Byte
/// eines Archivs gelesen, und mit einer Bedienerdatei, die ein Ziel benennt,
/// ist der Lauf unveraendert wiederholbar.
#[test]
fn a_configuration_without_a_revocation_target_is_refused_before_any_archive() {
    let directory = tempdir("registry-plan-without-target");
    let config = directory.join("operator.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"archive_directory":"archive","database_path":"operator.sqlite","device_certificate_hash":"{}","binding_object_hash":"{}","role":"organization-admin","purpose":"admin-root-ceremony"}}"#,
            "11".repeat(32),
            "22".repeat(32)
        ),
    )
    .expect("die Bedienerdatei muss schreibbar sein");

    let output = run(&[
        "--trust-anchor",
        "anchor.etb",
        "registry",
        "revocation-plan",
        "--operator-config",
        config.to_str().expect("Testpfad ist UTF-8"),
        "--effective-from",
        "10",
        "--valid-through",
        "20",
        "--not-after",
        "1700000000000",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("target_certificate_hash"),
        "die Ablehnung muss das fehlende Feld benennen, war: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Eine Bedienerdatei MIT Widerrufsziel kommt an der Ablehnung VORBEI.
///
/// Der Gegenzeuge zum Test darueber, und er misst mehr als er scheint: dass
/// `target_certificate_hash` ohne `authority` ueberhaupt geparst wird. Das
/// Feld hat heute genau EINEN produktiven Verbraucher — den
/// Autoritaetsbetrieb —, und `OperatorRuntimeConfig::from_json` prueft es nur
/// in dessen Richtung. Waere es ohne `authority` unzulaessig, endete dieses
/// Kommando mit `EA-OPERATOR-CONFIG` und waere nie erreichbar.
///
/// Der Anker existiert absichtlich nicht: der Lauf soll SPAETER scheitern —
/// beim Oeffnen des Bestands — und nicht schon an der Bedienerdatei.
#[test]
fn a_configuration_with_a_revocation_target_reaches_the_archive() {
    let directory = tempdir("registry-plan-with-target");
    let config = directory.join("operator.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"archive_directory":"archive","database_path":"operator.sqlite","device_certificate_hash":"{}","binding_object_hash":"{}","role":"organization-admin","purpose":"admin-root-ceremony","target_certificate_hash":"{}"}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32)
        ),
    )
    .expect("die Bedienerdatei muss schreibbar sein");

    let output = run(&[
        "--trust-anchor",
        directory
            .join("absent-anchor.etb")
            .to_str()
            .expect("Testpfad ist UTF-8"),
        "registry",
        "revocation-plan",
        "--operator-config",
        config.to_str().expect("Testpfad ist UTF-8"),
        "--effective-from",
        "10",
        "--valid-through",
        "20",
        "--not-after",
        "1700000000000",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("target_certificate_hash"),
        "die Bedienerdatei benennt ein Ziel und darf nicht deswegen abgelehnt werden, war: {stderr}"
    );
    assert!(
        !stderr.contains("EA-OPERATOR-CONFIG"),
        "eine Bedienerdatei mit Ziel und ohne authority muss parsen, war: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

/// Eine fehlende Freigabedatei endet mit dem I/O-Code, bevor ein Archiv
/// geoeffnet wird.
#[test]
fn a_missing_release_file_ends_the_run_before_any_archive() {
    let directory = tempdir("clock-release-missing-file");
    let config = directory.join("operator.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"archive_directory":"archive","database_path":"operator.sqlite","device_certificate_hash":"{}","binding_object_hash":"{}","role":"organization-admin","purpose":"clock-skew-release"}}"#,
            "11".repeat(32),
            "22".repeat(32)
        ),
    )
    .expect("die Bedienerdatei muss schreibbar sein");

    let output = run(&[
        "--trust-anchor",
        "anchor.etb",
        "clock-release",
        "apply",
        "--operator-config",
        config.to_str().expect("Testpfad ist UTF-8"),
        "--release",
        directory
            .join("absent.local-audit")
            .to_str()
            .expect("Testpfad ist UTF-8"),
    ]);
    assert_eq!(output.status.code(), Some(20));
    assert!(output.stdout.is_empty());
}

/// Ein eigenes, leeres Arbeitsverzeichnis unter dem Temp-Pfad des Systems.
///
/// Der Testsupport der Wiederherstellungskette wird hier NICHT eingebunden: er
/// zieht die ganze Fixture-Kette mit, und dieses Ziel braucht nichts als ein
/// Verzeichnis.
fn tempdir(name: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "einsatzarchiv-{name}-{}-{}",
        std::process::id(),
        name.len()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("das Arbeitsverzeichnis muss anlegbar sein");
    directory
}
