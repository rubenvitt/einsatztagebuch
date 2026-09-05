// crates/ea-reader-wasm/tests/session_dto.rs
//
// WIRTSZEUGE, und der cfg-Kopf sagt es — aus demselben Grund wie in
// `tests/bridge_boundary.rs`: ohne ihn uebergaebe der Browserlauf ein Ziel
// ohne einen einzigen `#[wasm_bindgen_test]` an den Laeufer.
#![cfg(not(target_arch = "wasm32"))]

//! Die ABBILDUNG der Sitzung und des Exportberichts auf ihre zwei
//! generierten DTOs, Feld fuer Feld — und die Zahl der Zielart.
//!
//! `session_view_json` und `export_report_json` sind die einzigen Strecken,
//! auf denen der Zustand der Sitzung und das Ergebnis eines Einzelexports die
//! Oberflaeche erreichen. Geparst und nicht als Text verglichen: „das DTO ist
//! gueltiges JSON" kann nur ein echter Parser belegen — die Lehre aus
//! `crates/ea-reader-wasm/src/bridge.rs`, wo eine mit `format!` gebaute
//! Kopfzeilenliste unparsbares JSON erzeugte und keine handgeschriebene
//! Zusicherung es sah.

use ea_reader::{EntryHash, ReaderExportTargetKindV1};
use ea_reader_wasm::export_bridge::{export_report_json, target_kind_from_number};
use ea_reader_wasm::visibility::session_view_json;

/// Die zwei Felder von `ReaderSessionView`, in der Reihenfolge des Generators.
const SESSION_VIEW_FIELDS_V1: [&str; 2] = ["locked", "openEntryHashes"];

/// Die zwei Felder von `SingleExportReportView`.
const EXPORT_REPORT_FIELDS_V1: [&str; 2] = ["entryHash", "targetKind"];

fn parsed(rendered: &str) -> serde_json::Map<String, serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_str(rendered).expect("das DTO MUSS gueltiges JSON sein");
    value.as_object().cloned().expect("das DTO ist ein Objekt")
}

/// Das Sitzungs-DTO traegt GENAU seine zwei Felder: die Sperre als `boolean`
/// und die offenen Datensaetze als Hexhashes — nie als Inhalt.
#[test]
fn the_session_view_carries_the_lock_and_the_open_hashes_as_hex() {
    let first = EntryHash::try_from(&[0x11_u8; 32][..]).expect("32 Byte");
    let second = EntryHash::try_from(&[0xab_u8; 32][..]).expect("32 Byte");
    let rendered = session_view_json(false, &[first, second]);
    let view = parsed(&rendered);
    let names: Vec<&str> = view.keys().map(String::as_str).collect();
    assert_eq!(
        names, SESSION_VIEW_FIELDS_V1,
        "das DTO traegt genau den Vertrag: {rendered}"
    );
    assert_eq!(view["locked"], serde_json::Value::Bool(false));
    assert_eq!(
        view["openEntryHashes"],
        serde_json::json!(["11".repeat(32), "ab".repeat(32)])
    );

    // Gesperrt: die Liste ist LEER, weil die Datensaetze mit dem Tresor
    // gefallen sind — und `locked` sagt es.
    let locked = parsed(&session_view_json(true, &[]));
    assert_eq!(locked["locked"], serde_json::Value::Bool(true));
    assert_eq!(locked["openEntryHashes"], serde_json::json!([]));
}

/// Der Exportbericht traegt Entry-Hash und die ZAHL der Zielart — die
/// eingefrorenen Werte der Position `target-kind`, und die Zahl geht ueber
/// `target_kind_from_number` wieder in die Zielart zurueck.
#[test]
fn the_export_report_carries_the_hash_and_the_frozen_target_kind_number() {
    let entry_hash = EntryHash::try_from(&[0x77_u8; 32][..]).expect("32 Byte");
    for (kind, number) in [
        (ReaderExportTargetKindV1::UserChosenFile, 1),
        (ReaderExportTargetKindV1::UserInitiatedDownload, 2),
    ] {
        let rendered = export_report_json(entry_hash, kind);
        let report = parsed(&rendered);
        let names: Vec<&str> = report.keys().map(String::as_str).collect();
        assert_eq!(
            names, EXPORT_REPORT_FIELDS_V1,
            "das DTO traegt genau den Vertrag: {rendered}"
        );
        assert_eq!(report["entryHash"], serde_json::json!("77".repeat(32)));
        assert_eq!(report["targetKind"], serde_json::json!(number));
        assert_eq!(target_kind_from_number(number), Some(kind));
    }
    assert_eq!(target_kind_from_number(0), None);
    assert_eq!(target_kind_from_number(3), None);
}
