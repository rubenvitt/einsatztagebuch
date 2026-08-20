//! Das eingecheckte Manifest der Stufe-2-Unterbrechungspunkte.
//!
//! Der `discard`-Abschnitt wird aus [`DiscardFaultPoint::ALL`] NEU ERZEUGT und
//! byteweise gegen die eingecheckte Datei verglichen. Ein neuer oder
//! umbenannter Unterbrechungspunkt, den niemand deklariert hat, bricht damit
//! `cargo test --workspace` — und nicht erst den Stufe-2-Gate von Task 17, der
//! diese Datei liest, ohne dass `tools/xtask` eine Kante auf eine Stufe-2-Crate
//! bekommt.
//!
//! Der `precedence`-Abschnitt ist AUSDRUECKLICH nicht erzeugt: sein einziger
//! Eintrag ist bewusst kein Mitglied von [`DiscardFaultPoint::ALL`], weil jeder
//! Punkt jenes Feldes in einen unveraenderten oder einen dauerhaft leeren
//! Entwurf neu startet, waehrend die Vorrangregel in
//! `RestartState::PreparedFinalizationPending` neu startet. Er wird von
//! `a_prepared_finalization_takes_precedence_over_resume_discard` getragen.

use std::{fs, path::PathBuf};

use ea_draft::{DiscardFaultPoint, PREPARED_FINALIZATION_BEATS_DISCARD_INTENT};

/// Der feste, repositoriumsrelative Pfad des Artefakts.
const MANIFEST_PATH: &str = "docs/traceability/stage-2-fault-points.json";

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates| crates.parent())
        .expect("crates/ea-draft liegt zwei Ebenen unter der Wurzel")
        .to_path_buf()
}

fn manifest() -> String {
    let path = repository_root().join(MANIFEST_PATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} ist nicht lesbar: {error}", path.display()))
}

/// Erzeugt den `discard`-Abschnitt in einen Puffer — dieselbe Gestalt, die die
/// eingecheckte Datei traegt.
fn generated_discard_section() -> String {
    let mut buffer = String::from("  \"discard\": [\n");
    for (index, point) in DiscardFaultPoint::ALL.iter().copied().enumerate() {
        buffer.push_str("    {\n");
        buffer.push_str(&format!("      \"name\": \"{}\",\n", point.name()));
        buffer.push_str(&format!("      \"brackets\": \"{}\"\n", point.brackets()));
        buffer.push_str("    }");
        if index + 1 < DiscardFaultPoint::ALL.len() {
            buffer.push(',');
        }
        buffer.push('\n');
    }
    buffer.push_str("  ],\n");
    buffer
}

#[test]
fn the_checked_in_manifest_declares_exactly_the_discard_fault_points() {
    let generated = generated_discard_section();
    assert!(
        manifest().contains(&generated),
        "der discard-Abschnitt von {MANIFEST_PATH} weicht ab. Erwartet:\n{generated}"
    );
}

#[test]
fn every_declared_name_and_bracket_is_distinct_and_non_empty() {
    let mut names: Vec<&str> = DiscardFaultPoint::ALL.iter().map(|p| p.name()).collect();
    let declared = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        declared,
        "zwei Unterbrechungspunkte tragen denselben Namen"
    );
    for point in DiscardFaultPoint::ALL.iter().copied() {
        assert!(!point.name().is_empty());
        assert!(
            !point.brackets().is_empty(),
            "{}: ein Punkt ohne benannten dauerhaften Schritt ist keine Deklaration",
            point.name()
        );
    }
}

#[test]
fn the_precedence_point_is_declared_by_hand_and_is_no_fault_point() {
    // Der Grund, warum der Erzeuger ihn NICHT erfassen darf: jeder Punkt von
    // `ALL` startet in einen unveraenderten oder einen leeren Entwurf neu,
    // dieser aber in `PreparedFinalizationPending`.
    assert!(
        !DiscardFaultPoint::ALL
            .iter()
            .any(|point| point.name() == PREPARED_FINALIZATION_BEATS_DISCARD_INTENT),
        "{PREPARED_FINALIZATION_BEATS_DISCARD_INTENT} darf kein Mitglied von ALL sein"
    );
    let manifest = manifest();
    assert!(
        manifest.contains("  \"precedence\": ["),
        "{MANIFEST_PATH} traegt keinen precedence-Abschnitt"
    );
    assert_eq!(
        manifest
            .matches(PREPARED_FINALIZATION_BEATS_DISCARD_INTENT)
            .count(),
        1,
        "{PREPARED_FINALIZATION_BEATS_DISCARD_INTENT} steht genau einmal im Manifest"
    );
}
