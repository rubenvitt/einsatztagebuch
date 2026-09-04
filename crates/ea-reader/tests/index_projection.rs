//! Die Eintrittsgrenze des fachlichen Index, ueber den ECHTEN Zeugentyp.
//!
//! `fixtures::complete_archive_with_a_genesis_plaintext()` traegt den
//! eingefrorenen Genesis-VEKTOR als Klartext, und `decrypt_verified` liefert
//! darueber einen vollstaendigen `VerifiedDecryptedRecord` — derselbe Weg, den
//! `historical_expiry.rs` bereits faehrt. Der gewoehnliche
//! `fixtures::complete_archive()` taugt dafuer AUSDRUECKLICH nicht: sein
//! Klartext traegt keine Schemakennung, und `decrypt_verified` endet auf ihm
//! mit `EA-READER-SCHEMA-UNSUPPORTED`, bevor je ein Zeugentyp entsteht.
//!
//! Damit ist die ABLEHNUNG des fachlichen Index bezeugbar, ohne einen zweiten
//! Bestand zu bauen: ein Genesis-Paket ist kein Einsatz, also entsteht keine
//! Indexzeile.
//!
//! Der POSITIVE Weg — ein Einsatzpaket durch dieselbe Umwandlung — ist hier
//! NICHT bezeugbar: keine Kulisse dieses Arbeitsbaums verschluesselt eine
//! `ea.incident`-Nutzlast in einen Archivbestand, und eine zu bauen hiesse, die
//! von acht Zielen geteilte Kulissenkette umzustellen. Die Projektion selbst
//! haelt stattdessen `crates/ea-reader/src/search.rs` in seiner `mod tests`
//! fest, ueber von Hand gebaute `IncidentV1`-Werte. Was zwischen beiden offen
//! bleibt, ist genau eine Naht: dass `with_payload` einen Einsatz auch wirklich
//! als Einsatz herausgibt. Sie steht als Uebergabe im Task-Abschnitt des Plans.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{
    ReaderMode, ReaderVerifier, RecordingObserver, SchemaRegistry, decrypt_verified,
    indexable_record,
};

use verify_fixtures::fixtures;

/// Ein Genesis-Paket wird ISOLIERT und nie zu einer Einsatzzeile.
///
/// Der Code ist der bereits ausgelieferte `EA-READER-SCHEMA-UNSUPPORTED` und
/// kein neuer: „dieses Paket traegt keine fachliche Zeile" ist dieselbe
/// Tatsache, die der Reader schon kennt, und ein zweiter Code daneben waere die
/// zweite Wahrheit darueber.
#[test]
fn a_verified_genesis_record_never_becomes_an_index_row() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::complete_archive_with_a_genesis_plaintext();
    let mut observer = RecordingObserver::new();
    let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(source, &vault, &mut observer)
        .expect("der vollstaendige Bestand klassifiziert");
    let entry_hash = fixtures::entry_hash(source);
    let entry = classification
        .verified_entry(entry_hash)
        .expect("der Bestand traegt einen Zeugen");
    let grant = classification
        .verified_grant(entry_hash)
        .expect("und einen eigenen Grant");

    let mut decapsulation = RecordingObserver::new();
    let record = decrypt_verified(
        entry,
        grant,
        &vault,
        &SchemaRegistry::v1(),
        fixtures::EFFECTIVE_NOW,
        &mut decapsulation,
    )
    .expect("der Genesis-Klartext traegt die erste Schemabestimmung");

    // Die Positivkontrolle: der Zeuge IST ein vollwertiger, entschluesselter
    // Datensatz mit einer Schemabeschriftung. Ohne sie sagte die Weigerung
    // darunter nur, dass irgendetwas fehlgeschlagen ist.
    assert_eq!(record.source_schema().0, "ea.genesis");

    let refused = indexable_record(&record)
        .err()
        .expect("ein Genesis-Paket traegt keine fachliche Indexzeile");
    assert_eq!(refused.code(), "EA-READER-SCHEMA-UNSUPPORTED");
}
