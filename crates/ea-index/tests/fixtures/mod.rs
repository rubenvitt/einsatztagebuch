#![allow(dead_code)]

//! Die Kulisse der vier Zeugen dieser Crate.
//!
//! Sie baut `IndexableRecordV1`-Werte VON HAND und ohne jeden Umweg ueber eine
//! Readerflaeche — genau das ist die Zusage der Eintrittsgrenze: die Eingabe
//! des Index ist ein gewoehnlicher Wert, den diese Crate ohne Kenntnis des
//! Zeugentyps bauen und pruefen kann. Braeuchte die Kulisse einen entsiegelten
//! Datensatz, waere die Kante bereits umgedreht.
//!
//! Die Herkunftsspalten sind ABGELEITET und nicht ausgewuerfelt: der Entry-Hash
//! traegt die laufende Nummer in seinen ersten vier Bytes, die Sequenz ist
//! dieselbe Nummer. Damit ist jede Kulisse dieses Verzeichnisses reproduzierbar
//! und der bytegleiche Rebuild ueberhaupt pruefbar.

use ea_index::{IndexableRecordV1, InvertedIndexV1};
use ea_schema::SCHEMA_VERSION_V1;
use ea_types::{ChainSequence, EntryHash, RecordId, UnixMillis};

/// Die Kennung des EINEN Schemas, das diese Stufe projiziert.
pub const INCIDENT_SCHEMA_ID: &str = "ea.incident";

/// Der Entry-Hash der laufenden Nummer `ordinal`.
#[must_use]
pub fn entry_hash(ordinal: u32) -> EntryHash {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&ordinal.to_be_bytes());
    EntryHash::try_from(&bytes[..]).expect("32 Byte sind ein Entry-Hash")
}

/// Die Datensatzkennung der laufenden Nummer `ordinal`.
#[must_use]
pub fn record_id(ordinal: u32) -> RecordId {
    let mut bytes = [0_u8; 16];
    bytes[..4].copy_from_slice(&ordinal.to_be_bytes());
    RecordId::try_from(&bytes[..]).expect("16 Byte sind eine Datensatzkennung")
}

/// Ein Einsatz mit genau einem Stichwort, einem Fahrzeug und einer Person.
///
/// Die laufende Nummer entsteht aus der Einsatznummer, damit zwei Aufrufe mit
/// verschiedenen Nummern verschiedene Herkunftsspalten tragen.
#[must_use]
pub fn indexable_incident(
    human_incident_number: &str,
    keyword: &str,
    vehicle: &str,
    person: &str,
    occurred_at_start: UnixMillis,
) -> IndexableRecordV1 {
    let ordinal = ordinal_of(human_incident_number);
    IndexableRecordV1 {
        source_entry_hash: entry_hash(ordinal),
        chain_sequence: ChainSequence::new(u64::from(ordinal)),
        record_id: record_id(ordinal),
        source_schema_id: INCIDENT_SCHEMA_ID.to_owned(),
        source_schema_version: SCHEMA_VERSION_V1,
        target_schema_id: INCIDENT_SCHEMA_ID.to_owned(),
        target_schema_version: SCHEMA_VERSION_V1,
        human_incident_number: human_incident_number.to_owned(),
        occurred_at_start,
        occurred_at_end: None,
        keyword_terms: vec![keyword.to_owned()],
        vehicle_terms: vec![vehicle.to_owned()],
        person_terms: vec![person.to_owned()],
    }
}

/// Der Einsatz, den `schema_compatibility.rs` beschriftet.
#[must_use]
pub fn indexable_incident_v1() -> IndexableRecordV1 {
    indexable_incident(
        "2026-0001",
        "Brand",
        "LF 10",
        "Ada Lovelace",
        UnixMillis::new(1_771_000_000_000),
    )
}

/// Derselbe Einsatz unter einem ANDEREN Quell- und Zielschema.
///
/// Beide Beschriftungsspalten wandern mit: eine Ansicht, die nur die Quelle
/// umbenennt, waere gar keine Ansicht auf ein fremdes Ziel.
#[must_use]
pub fn indexable_record_with_schema(schema_id: &str, schema_version: u64) -> IndexableRecordV1 {
    IndexableRecordV1 {
        source_schema_id: schema_id.to_owned(),
        source_schema_version: schema_version,
        target_schema_id: schema_id.to_owned(),
        target_schema_version: schema_version,
        ..indexable_incident_v1()
    }
}

/// Drei Datensaetze, die zusammen jeden Kanarienvogel von `reindex.rs` tragen.
#[must_use]
pub fn three_records() -> Vec<IndexableRecordV1> {
    vec![
        indexable_incident(
            "2026-0001",
            "Brand",
            "LF 10",
            "CANARY-PERSON",
            UnixMillis::new(1_771_000_000_000),
        ),
        indexable_incident(
            "2026-0002",
            "Verkehrsunfall",
            "RTW 1",
            "Grace Hopper",
            UnixMillis::new(1_772_000_000_000),
        ),
        indexable_incident(
            "2026-0003",
            "Ölspur",
            "MTW",
            "Käthe Paulus",
            UnixMillis::new(1_773_000_000_000),
        ),
    ]
}

/// Der Index ueber eine gegebene Menge, in gelieferter Reihenfolge aufgenommen.
#[must_use]
pub fn index_over(records: &[IndexableRecordV1]) -> InvertedIndexV1 {
    let mut index = InvertedIndexV1::empty();
    for record in records {
        index
            .upsert(record)
            .expect("die Kulisse traegt ausschliesslich projizierbare Schemata");
    }
    index
}

/// Das `package`-te synthetische Paket der Schwellenmessung.
///
/// Jedes Paket traegt GENAU EINEN Term je Filterachse, und jeder dieser Terme
/// ist ueber die laufende Nummer eindeutig: damit misst
/// `scale_50000.rs` den Fall mit der GROESSTEN Zahl verschiedener
/// Termschluessel und nicht den bequemen Fall weniger, dafuer langer
/// Trefferlisten.
#[must_use]
pub fn synthetic_package(package: usize) -> IndexableRecordV1 {
    let ordinal = u32::try_from(package).expect("die Schwelle liegt weit unter u32::MAX");
    indexable_incident(
        &format!("2026-{package:06}"),
        &format!("Stichwort {package}"),
        &format!("LF {package}"),
        &format!("Person {package}"),
        UnixMillis::new(1_771_000_000_000 + i64::from(ordinal)),
    )
}

/// Ob `haystack` die Bytefolge `needle` an irgendeiner Stelle traegt.
///
/// Von Hand und nicht ueber eine Fremdcrate: der Kanarienzeuge ist die
/// Zusicherung selbst, und eine Suchbibliothek waere eine Kante, die
/// ausschliesslich er braeuchte.
#[must_use]
pub fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Die laufende Nummer hinter einer Einsatznummer der Form `JJJJ-NNNN`.
fn ordinal_of(human_incident_number: &str) -> u32 {
    human_incident_number
        .rsplit('-')
        .next()
        .and_then(|tail| tail.parse::<u32>().ok())
        .expect("jede Kulissen-Einsatznummer endet auf eine Zahl")
}
