//! Die Driftschranke ueber der EINGECHECKTEN Emitterausgabe.
//!
//! Vier Zusagen, und jede deckt eine Luecke, die die andere offen laesst:
//!
//! 1. Die eingecheckte Datei IST das, was der Emitter schreibt. Ohne diese
//!    Zusicherung ist ein generiertes Artefakt eine Datei, die jeder von Hand
//!    aendern kann, ohne dass ein Lauf rot wird — genau das Loch, das die vier
//!    `verify-quick`-Kommandos fuer eingecheckte Generate offen lassen.
//! 2. Zwei Emitterlaeufe sind byteidentisch. Zeitstempel, Pfade,
//!    Umgebungsversionen und `HashMap`-Reihenfolge sind die vier ueblichen
//!    Quellen eines Byteunterschieds; ohne diese Zusicherung waere Zusage 1
//!    beim naechsten Lauf zufaellig rot.
//! 3. Jede Sicherheitsvereinigung traegt die Varianten ihrer Rustdefinition,
//!    in Deklarationsreihenfolge.
//! 4. Die Datei DEKLARIERT und RECHNET NICHT. TypeScript erzeugt keinen Grant,
//!    keinen Hash, keine Signatur, kein Chiffrat und kein Archivbyte; eine
//!    Kontraktdatei, die eine Funktion enthaelt, ist der erste Schritt in die
//!    andere Richtung.

use std::{fs, path::PathBuf};

fn generated_contracts_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/desktop/src/bridge/generated-contracts.ts")
}

/// Die Zeilen der Deklaration `export type NAME =`, den Kopf eingeschlossen.
///
/// Der Anker ist die VOLLSTAENDIGE Kopfzeile und nicht ein Praefix: sonst
/// gewinnt bei zwei Namen, von denen einer Praefix des anderen ist, der
/// falsche Block.
fn named_union_block(emitted: &str, name: &str) -> String {
    let header = format!("export type {name} =");
    let mut lines = emitted.lines();
    let found = lines
        .by_ref()
        .find(|line| *line == header)
        .unwrap_or_else(|| panic!("the generated contracts must declare a union named {name}"));
    let mut block = String::from(found);
    for line in lines {
        if !line.starts_with(' ') {
            break;
        }
        block.push('\n');
        block.push_str(line);
    }
    block
}

/// Die Mitglieder einer Vereinigung, in Deklarationsreihenfolge.
fn union_members(block: &str) -> Vec<&str> {
    block
        .lines()
        .filter_map(|line| line.trim().strip_prefix("| "))
        .map(|member| {
            member
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
                .unwrap_or_else(|| {
                    panic!("every union member must be a single-quoted literal, found {member}")
                })
        })
        .collect()
}

#[test]
fn the_checked_in_file_is_exactly_what_the_emitter_writes() {
    let generated = ea_ui_contracts::emit_typescript();
    let checked_in = fs::read_to_string(generated_contracts_path()).unwrap();
    assert_eq!(
        generated, checked_in,
        "run `cargo run --locked -p ea-ui-contracts --bin emit-ts` and commit the result"
    );
}

#[test]
fn two_emitter_runs_are_byte_identical() {
    assert_eq!(
        ea_ui_contracts::emit_typescript().into_bytes(),
        ea_ui_contracts::emit_typescript().into_bytes()
    );
}

#[test]
fn every_security_enum_is_derived_from_its_rust_definition() {
    let emitted = ea_ui_contracts::emit_typescript();
    assert!(
        !ea_ui_contracts::SECURITY_ENUMS_V1.is_empty(),
        "SECURITY_ENUMS_V1 must carry every security enum of the contract surface"
    );
    for (name, variants) in ea_ui_contracts::SECURITY_ENUMS_V1 {
        let block = named_union_block(&emitted, name);
        assert_eq!(
            union_members(&block),
            variants.to_vec(),
            "{name} must be emitted from its Rust definition, in declaration order"
        );
    }
    // Die uebrigen geschlossenen Mengen der Kontraktflaeche sind keine
    // Sicherheitsaufzaehlungen und stehen deshalb nicht in
    // `SECURITY_ENUMS_V1` — bewacht werden sie gleich streng.
    for (name, variants) in ea_ui_contracts::WRITER_ENUMS_V1 {
        let block = named_union_block(&emitted, name);
        assert_eq!(
            union_members(&block),
            variants.to_vec(),
            "{name} must be emitted from its Rust definition, in declaration order"
        );
    }
    // Die Variantenlisten in `lib.rs` sind der EINE Punkt, an dem eine
    // Variante still verloren gehen kann: eine HINZUGEKOMMENE Variante bricht
    // den `match` ohne Sammelarm und damit die Uebersetzung, eine
    // WEGGELASSENE bricht nichts — beide Seiten des Vergleichs oben leiten
    // sich aus derselben Liste ab. Diese Zaehlung ist der Zeuge dagegen. Wo
    // die definierende Crate ein `ALL` fuehrt, kommt die Zahl von DORT und
    // faengt damit auch das Wachstum; wo sie keines fuehrt, steht sie hier und
    // macht ein bewusstes Entfernen zu einer sichtbaren Aenderung.
    for (name, expected) in [
        ("SyncStatus", ea_ui_contracts::SyncStatus::ALL.len()),
        ("DetailCause", ea_ui_contracts::DetailCause::ALL.len()),
        (
            "FinalizationPhase",
            ea_ui_contracts::FinalizationPhase::ALL.len(),
        ),
        ("QuarantineReason", 4),
        ("LocalAuditOutcomeV1", 3),
        ("KeyProtectionProfileV1", 5),
        ("OperatorRoleV1", 3),
        ("SignerRole", 9),
    ] {
        assert_eq!(
            union_members(&named_union_block(&emitted, name)).len(),
            expected,
            "{name} must emit EVERY variant of its Rust definition"
        );
    }
    // Der EINE nicht zirkulaere Anker: die vier Zustandsnamen sind woertliche
    // Oberflaechenkopie aus den globalen Randbedingungen, hier als Text
    // gepinnt. Alles darueber vergleicht zwei Ableitungen derselben
    // Rustdefinition und faellt, wenn der Emitter umsortiert oder ein
    // Mitglied verliert; DIESE Zeile faellt auch, wenn die Kopie selbst
    // wandert.
    assert_eq!(
        union_members(&named_union_block(&emitted, "SyncStatus")),
        vec![
            "lokal gesichert",
            "Upload ausstehend",
            "synchronisiert",
            "Fehler"
        ]
    );
}

#[test]
fn the_emitted_file_declares_types_and_computes_nothing() {
    let emitted = ea_ui_contracts::emit_typescript();
    let lowercase = emitted.to_ascii_lowercase();
    for forbidden in [
        "function", "=>", "class", "import(", "require(", "crypto", "subtle", "sha",
    ] {
        assert!(
            !lowercase.contains(forbidden),
            "the generated contracts must contain no {forbidden}"
        );
    }
    // Die neunte verbotene Zeichenfolge des Briefs ist "sign", und die
    // Sicherheitsaufzaehlung `SignerRole` traegt sie im NAMEN. Statt die
    // Zusicherung fallen zu lassen, wird genau dieser eine Name maskiert:
    // `signature`, `sign(`, `signed`, `assign` und jedes andere Vorkommen
    // faellt weiterhin auf, und zwar zeilenweise mit der Fundstelle im Text.
    for line in emitted.lines() {
        let masked = line
            .to_ascii_lowercase()
            .replace("signerrole", "")
            .replace("signer_role", "");
        assert!(
            !masked.contains("sign"),
            "the generated contracts must contain no sign outside the SignerRole \
             declaration: {line}"
        );
    }
    for line in emitted.lines().filter(|line| !line.trim().is_empty()) {
        assert!(
            line.starts_with("//")
                || line.starts_with("export type")
                || line.starts_with("export const")
                || line.starts_with(' ')
                || line == "}"
                || line == "] as const",
            "unexpected construct in a generated declaration file: {line}"
        );
    }
}
