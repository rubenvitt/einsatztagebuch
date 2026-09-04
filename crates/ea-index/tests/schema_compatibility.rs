//! Die Beschriftung beider Schemata und die Isolation des Unbekannten.

mod fixtures;

use ea_index::{IndexError, InvertedIndexV1, ReaderQueryV1, SchemaViewV1};
use ea_schema::{SCHEMA_VERSION_V1, SchemaError};

#[test]
fn every_view_labels_its_source_and_its_target_schema() {
    let view = SchemaViewV1::derive(&fixtures::indexable_incident_v1()).unwrap();
    assert_eq!(view.source_schema(), ("ea.incident", SCHEMA_VERSION_V1));
    assert_eq!(view.target_schema(), ("ea.incident", SCHEMA_VERSION_V1));
    // Die Ansicht traegt die BESCHRIFTUNG und die abgeleiteten Werte, nie die
    // exakten Nutzlastbytes: `IndexableRecordV1` bekommt sie gar nicht erst.
    assert_eq!(view.human_incident_number(), "2026-0001");
    let source = include_str!("../src/schema_view.rs");
    assert!(
        !source.contains("exact_source_bytes"),
        "the index never carries the exact payload bytes of a decrypted record"
    );
}

#[test]
fn an_unsupported_schema_is_isolated_and_never_becomes_a_row() {
    let mut index = InvertedIndexV1::empty();
    let refused = SchemaViewV1::derive(&fixtures::indexable_record_with_schema("ea.unknown", 1));
    assert!(matches!(
        refused,
        Err(IndexError::Schema(SchemaError::Unsupported { .. }))
    ));
    assert_eq!(
        index
            .upsert(&fixtures::indexable_record_with_schema("ea.incident", 99))
            .unwrap_err()
            .code(),
        "EA-SCHEMA-UNSUPPORTED"
    );
    assert_eq!(index.indexed_packages(), 0);
    assert!(
        index
            .search(&ReaderQueryV1::keyword("Brand"))
            .unwrap()
            .is_empty()
    );
}

/// Die Weigerung nennt das ABGEWIESENE Schema und keinen zweiten Code.
///
/// `EA-SCHEMA-UNSUPPORTED` gehoert `ea-schema` und wird DURCHGEREICHT; ein
/// eigener Code dieser Crate fuer dieselbe Tatsache waere die zweite Wahrheit,
/// die dieser Bestand sonst ueberall vermeidet.
#[test]
fn the_refusal_carries_the_rejected_schema_and_the_code_of_ea_schema() {
    let refused = SchemaViewV1::derive(&fixtures::indexable_record_with_schema("ea.amendment", 1))
        .unwrap_err();
    assert_eq!(refused.code(), "EA-SCHEMA-UNSUPPORTED");
    let IndexError::Schema(SchemaError::Unsupported {
        schema_id,
        schema_version,
    }) = &refused
    else {
        panic!("ein nicht projizierbares Zielschema ist genau diese Fehlerform: {refused}");
    };
    assert_eq!(schema_id, "ea.amendment");
    assert_eq!(*schema_version, SCHEMA_VERSION_V1);
}

/// Ein abgewiesener Datensatz hinterlaesst KEINE halbe Zeile.
///
/// Die Pruefung laeuft VOR jeder Veraenderung des Bestands; ein Index, der die
/// Trefferlisten schon fortgeschrieben und erst danach abgewiesen haette, truege
/// einen Term ohne Paket — und `search` faende eine Zeile, die es nicht gibt.
#[test]
fn a_refused_record_leaves_the_existing_index_untouched() {
    let records = fixtures::three_records();
    let mut index = fixtures::index_over(&records);
    let before = index.indexed_packages();

    index
        .upsert(&fixtures::indexable_record_with_schema("ea.genesis", 1))
        .unwrap_err();

    assert_eq!(index.indexed_packages(), before);
    assert_eq!(
        index
            .search(&ReaderQueryV1::vehicle("LF 10"))
            .unwrap()
            .len(),
        1
    );
}
