//! Das eingecheckte Manifest der Stufe-2-Unterbrechungspunkte, Abschnitt
//! `finalization`.
//!
//! Der Abschnitt wird aus [`FinalizationStep::ALL`] und
//! [`FinalizationFaultPoint::ALL`] NEU ERZEUGT und byteweise gegen die
//! eingecheckte Datei verglichen. Ein neuer oder umbenannter Punkt, den niemand
//! deklariert hat, bricht damit `cargo test --workspace` — und nicht erst der
//! Stufe-2-Gate von Task 17, der diese Datei liest, ohne dass `tools/xtask` eine
//! Kante auf eine Stufe-2-Crate bekommt.
//!
//! # Warum die Abdeckung gegen LITERALE Listen geprueft wird
//!
//! Ein Vergleich der Aufzaehlung mit sich selbst waere gruen, auch wenn die
//! Aufzaehlung eine einzige Variante haette. Die dreizehn Schrittnamen und die
//! sieben Punktklassen der Norm stehen deshalb als Zeichenkettenliteral IN
//! diesem Test — abgeschrieben aus `design.md` §9.3 und §20.4 — und nicht aus
//! dem Quelltext geholt.

mod support;

use std::{fs, path::PathBuf};

use ea_writer::{FinalizationFaultPoint, FinalizationPhase, FinalizationStep};

const MANIFEST_PATH: &str = "docs/traceability/stage-2-fault-points.json";

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates| crates.parent())
        .expect("crates/ea-writer liegt zwei Ebenen unter der Wurzel")
        .to_path_buf()
}

fn manifest() -> String {
    let path = repository_root().join(MANIFEST_PATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} ist nicht lesbar: {error}", path.display()))
}

/// Erzeugt den `finalization`-Abschnitt in einen Puffer.
fn generated_finalization_section() -> String {
    let mut buffer = String::from("  \"finalization\": {\n    \"steps\": [\n");
    for (index, step) in FinalizationStep::ALL.iter().copied().enumerate() {
        buffer.push_str("      {\n");
        buffer.push_str(&format!("        \"number\": {},\n", step.spec_number()));
        buffer.push_str(&format!("        \"name\": \"{}\"\n", step.name()));
        buffer.push_str("      }");
        if index + 1 < FinalizationStep::ALL.len() {
            buffer.push(',');
        }
        buffer.push('\n');
    }
    buffer.push_str("    ],\n    \"points\": [\n");
    for (index, point) in FinalizationFaultPoint::ALL.iter().copied().enumerate() {
        buffer.push_str("      {\n");
        buffer.push_str(&format!("        \"name\": \"{}\",\n", point.name()));
        buffer.push_str(&format!(
            "        \"brackets\": \"{}\",\n",
            point.brackets()
        ));
        buffer.push_str(&format!(
            "        \"phase\": \"{}\"\n",
            phase_name(point.phase())
        ));
        buffer.push_str("      }");
        if index + 1 < FinalizationFaultPoint::ALL.len() {
            buffer.push(',');
        }
        buffer.push('\n');
    }
    buffer.push_str("    ]\n  },\n");
    buffer
}

const fn phase_name(phase: FinalizationPhase) -> &'static str {
    match phase {
        FinalizationPhase::ReversibleDraft => "ReversibleDraft",
        FinalizationPhase::PreparedAndFlushed => "PreparedAndFlushed",
        FinalizationPhase::DraftKeyAbsent => "DraftKeyAbsent",
        FinalizationPhase::GrantsPublished => "GrantsPublished",
        FinalizationPhase::EntryCommitted => "EntryCommitted",
        FinalizationPhase::NetworkArchivePublished => "NetworkArchivePublished",
        FinalizationPhase::Reconciled => "Reconciled",
    }
}

#[test]
fn the_checked_in_manifest_declares_exactly_the_finalization_steps_and_points() {
    let generated = generated_finalization_section();
    assert!(
        manifest().contains(&generated),
        "der finalization-Abschnitt von {MANIFEST_PATH} weicht ab. Erwartet:\n{generated}"
    );
}

#[test]
fn the_declared_steps_cover_the_thirteen_of_design_section_9_3() {
    // LITERAL, aus `design.md` §9.3 abgeschrieben. Ein Vergleich der
    // Aufzaehlung mit sich selbst waere gruen, auch wenn sie nur eine Variante
    // haette.
    const NORMATIVE_STEPS: [&str; 13] = [
        "RebuildLocalHead",
        "CompareServerCheckpoint",
        "SelectRegistryHeadAndOperator",
        "ValidateAndSerialize",
        "BuildAndHashGrantPlan",
        "DrawSecretsAndBuildEntryHash",
        "ProduceGrantsAndEntryBytes",
        "StageAndFlush",
        "ZeroAndDeleteDraftKey",
        "PublishGrants",
        "PublishEntryLast",
        "PublishToNetworkArchive",
        "ReconcileAndOpenBlankDraft",
    ];
    let declared: Vec<&str> = FinalizationStep::ALL.iter().map(|s| s.name()).collect();
    assert_eq!(declared, NORMATIVE_STEPS.to_vec());
    for (index, step) in FinalizationStep::ALL.iter().copied().enumerate() {
        assert_eq!(
            usize::from(step.spec_number()),
            index + 1,
            "die Spec-Nummer folgt der Reihenfolge"
        );
    }
}

#[test]
fn every_point_class_of_design_section_20_4_has_at_least_one_declared_point() {
    // LITERAL: die sieben Klassen der normativen Injektionsliste
    // (`design.md` §20.4) mit einem Ausschnitt des Punktnamens, der sie traegt.
    const NORMATIVE_CLASSES: [(&str, &str); 7] = [
        ("Create-if-absent", "StagingCreate"),
        ("Datei-Flush", "FileFlush"),
        ("Verzeichnis-Flush", "DirectoryFlush"),
        ("Datenbankschritt", "MarkerCommit"),
        ("Keystore-Delete", "KeystoreDelete"),
        ("Rename", "EntryRename"),
        ("Object-Store-Schritt", "GrantPublish"),
    ];
    for (class, marker) in NORMATIVE_CLASSES {
        assert!(
            FinalizationFaultPoint::ALL
                .iter()
                .any(|point| point.name().contains(marker)),
            "keine Deklaration fuer die Klasse {class} (Marke {marker})"
        );
    }
    // Und die Rueckspielung als Ereignis von aussen.
    assert!(
        FinalizationFaultPoint::ALL
            .iter()
            .any(|point| point.name() == "BackupRestoreAfterKeyDeletion")
    );
}

#[test]
fn every_declared_name_and_bracket_is_distinct_and_non_empty() {
    let mut names: Vec<&str> = FinalizationFaultPoint::ALL
        .iter()
        .map(|point| point.name())
        .collect();
    let declared = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), declared, "zwei Punkte tragen denselben Namen");
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        assert!(!point.name().is_empty());
        assert!(
            !point.brackets().is_empty(),
            "{}: ein Punkt ohne benannten dauerhaften Schritt ist keine Deklaration",
            point.name()
        );
    }
}

/// Der Vorrangpunkt aus Task 7 bleibt UNBERUEHRT und steht genau einmal.
///
/// `crates/ea-draft/tests/fault_point_manifest.rs` pinnt genau das; ihn in den
/// Finalisierungsabschnitt zu duplizieren waere ein Bruch jenes Tests.
#[test]
fn the_precedence_point_of_task_seven_is_not_duplicated_here() {
    let manifest = manifest();
    assert_eq!(
        manifest
            .matches(ea_draft::PREPARED_FINALIZATION_BEATS_DISCARD_INTENT)
            .count(),
        1
    );
    assert!(manifest.contains("  \"discard\": ["));
    assert!(manifest.contains("  \"precedence\": ["));
}
