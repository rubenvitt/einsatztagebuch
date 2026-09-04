//! Die vier Filter, die Normalisierung und die EINTRITTSGRENZE der Crate.
//!
//! Die Eintrittsgrenze wird NICHT ueber einen Aufruf geprueft, den es gar nicht
//! geben darf, sondern ueber die Abwesenheit einer zweiten Aufnahmemethode und
//! ueber die Abwesenheit jeder Nennung eines Readertyps im Quelltext von
//! `src/inverted.rs` — dieselbe Form, mit der das Repositorium anderswo die
//! Abwesenheit eines Massenexports belegt.

mod fixtures;

use ea_index::{InvertedIndexV1, ReaderQueryV1};
use ea_schema::SCHEMA_VERSION_V1;
use ea_types::UnixMillis;

#[test]
fn the_four_filters_run_locally_over_decrypted_field_values() {
    let mut index = InvertedIndexV1::empty();
    index
        .upsert(&fixtures::indexable_incident(
            "2026-0001",
            "Brand",
            "LF 10",
            "Ada Lovelace",
            UnixMillis::new(1_771_000_000_000),
        ))
        .unwrap();
    index
        .upsert(&fixtures::indexable_incident(
            "2026-0002",
            "Verkehrsunfall",
            "RTW 1",
            "Grace Hopper",
            UnixMillis::new(1_772_000_000_000),
        ))
        .unwrap();

    for (query, expected) in [
        (ReaderQueryV1::vehicle("LF 10"), "2026-0001"),
        (ReaderQueryV1::person("Ada Lovelace"), "2026-0001"),
        (ReaderQueryV1::keyword("Verkehrsunfall"), "2026-0002"),
        (
            ReaderQueryV1::period(
                UnixMillis::new(1_771_500_000_000),
                UnixMillis::new(1_773_000_000_000),
            ),
            "2026-0002",
        ),
    ] {
        let hits = index.search(&query).unwrap();
        assert_eq!(
            hits.len(),
            1,
            "query {query:?} must match exactly one record"
        );
        assert_eq!(hits[0].human_incident_number(), expected);
        assert_eq!(hits[0].source_schema(), ("ea.incident", SCHEMA_VERSION_V1));
    }
    let combined = index
        .search(&ReaderQueryV1::keyword("Brand").and_vehicle("RTW 1"))
        .unwrap();
    assert!(
        combined.is_empty(),
        "filters combine conjunctively, not disjunctively"
    );
}

/// Der Debug-Text einer Anfrage nennt die GESETZTEN Achsen und keinen Wert.
///
/// Der Zeuge darueber formatiert `{query:?}` in seiner Fehlermeldung, und ein
/// Suchbegriff ist ein aus entschluesseltem Inhalt abgeleiteter Wert. Ein
/// abgeleitetes `Debug` truege ihn in jede Zusicherungsmeldung, jedes
/// Testprotokoll und jede spaetere Fehlerausgabe — genau der Weg, den die
/// Produktinvariante ueber Protokolle und Telemetrie ausschliesst. Dieselbe
/// Begruendung, aus der `VerifiedDecryptedRecord` sein `Debug` von Hand
/// schreibt.
#[test]
fn the_debug_form_of_a_query_names_its_axes_and_never_its_terms() {
    let query = ReaderQueryV1::keyword("Ölspur").and_vehicle("LF 10");
    let rendered = format!("{query:?}");

    assert!(
        rendered.contains("keyword") && rendered.contains("vehicle"),
        "the set axes must be visible: {rendered}"
    );
    assert!(
        !rendered.contains("person") && !rendered.contains("period"),
        "an unset axis must not be named: {rendered}"
    );
    for term in ["Ölspur", "ölspur", "LF 10", "lf 10"] {
        assert!(
            !rendered.contains(term),
            "{term} must not reach the debug form: {rendered}"
        );
    }
}

#[test]
fn exactly_one_ingestion_method_exists_and_it_never_names_a_reader_type() {
    let source = include_str!("../src/inverted.rs");
    assert_eq!(
        source.matches("pub fn upsert").count(),
        1,
        "exactly one ingestion method may exist"
    );
    assert_eq!(source.matches("pub fn rebuild_from").count(), 1);
    for forbidden in [
        "record_technical_state",
        "MissingGrant",
        "Quarantined",
        "pub fn upsert_raw",
    ] {
        assert!(
            !source.contains(forbidden),
            "{forbidden} must not exist: technical state lives in the reader, never in the index"
        );
    }
    // Die Kantenrichtung als Quelltextzusage: diese Crate kennt weder den
    // Zeugentyp noch den Geheimniswrapper. Waere hier ein
    // `VerifiedDecryptedRecord`, waere `ea-index` eine Abhaengigkeit von
    // `ea-reader` UND umgekehrt, und `cargo metadata` wiese den Arbeitsbereich
    // als Ganzes ab.
    for name in ["VerifiedDecryptedRecord", "SecretVec", "ea_reader"] {
        assert!(
            !source.contains(name),
            "{name} must not appear in ea-index: the edge runs ea-reader -> ea-index only"
        );
    }
}

#[test]
fn search_terms_are_nfc_normalized_and_case_folded_but_never_stemmed() {
    let mut index = InvertedIndexV1::empty();
    index
        .upsert(&fixtures::indexable_incident(
            "2026-0003",
            "Ölspur",
            "MTW",
            "Käthe Paulus",
            UnixMillis::new(1_771_000_000_000),
        ))
        .unwrap();
    assert_eq!(
        index
            .search(&ReaderQueryV1::keyword("o\u{0308}lspur"))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        index
            .search(&ReaderQueryV1::keyword("ÖLSPUR"))
            .unwrap()
            .len(),
        1
    );
    assert!(
        index
            .search(&ReaderQueryV1::keyword("Ölspuren"))
            .unwrap()
            .is_empty()
    );
}

/// Der Weg zurueck an einen Treffer laeuft ueber die HERKUNFTSKENNUNG.
#[test]
fn a_hit_is_reachable_through_its_source_entry_hash_and_never_through_a_row_number() {
    let records = fixtures::three_records();
    let index = fixtures::index_over(&records);

    let found = index
        .hit_for(records[1].source_entry_hash)
        .expect("ein aufgenommenes Paket ist ueber seinen Entry-Hash erreichbar");
    assert_eq!(found.human_incident_number(), "2026-0002");
    assert_eq!(found.chain_sequence(), records[1].chain_sequence);
    assert!(index.hit_for(fixtures::entry_hash(9_999)).is_none());
}

/// Dieselbe Herkunft zweimal aufgenommen ist EIN Paket und nicht zwei.
///
/// Ohne diese Zusage zaehlte ein wiederholter Lauf ueber denselben Bestand die
/// Schwelle hoch, ohne dass ein einziges Paket hinzugekommen waere — und die
/// GEMESSENE Schwelle waere eine Zaehlung von Aufrufen statt von Paketen.
#[test]
fn upserting_the_same_source_entry_hash_replaces_its_row_instead_of_adding_one() {
    let mut index = InvertedIndexV1::empty();
    index
        .upsert(&fixtures::indexable_incident(
            "2026-0001",
            "Brand",
            "LF 10",
            "Ada Lovelace",
            UnixMillis::new(1_771_000_000_000),
        ))
        .unwrap();
    // Dieselbe Einsatznummer und damit dieselbe Herkunft, aber andere Terme:
    // die Kulisse leitet den Entry-Hash aus der Nummer ab.
    let corrected = fixtures::indexable_incident(
        "2026-0001",
        "Verkehrsunfall",
        "RTW 1",
        "Grace Hopper",
        UnixMillis::new(1_771_000_000_000),
    );
    index.upsert(&corrected).unwrap();

    assert_eq!(index.indexed_packages(), 1);
    assert_eq!(
        index
            .search(&ReaderQueryV1::vehicle("RTW 1"))
            .unwrap()
            .len(),
        1
    );
    assert!(
        index
            .search(&ReaderQueryV1::vehicle("LF 10"))
            .unwrap()
            .is_empty(),
        "der ersetzte Bestand darf keine verwaiste Trefferliste hinterlassen"
    );
}
