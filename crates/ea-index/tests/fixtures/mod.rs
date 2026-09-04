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

use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes, SecretVec, aead_seal};
use ea_index::{INDEX_BLOB_MAGIC_V1, INDEX_FORMAT_VERSION_V1, IndexableRecordV1, InvertedIndexV1};
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

/// Der Stichworttext, den JEDES synthetische Paket traegt.
///
/// Er steht neben dem eindeutigen Term und ist die zweite Haelfte der Messung:
/// ohne ihn haette jede Trefferliste genau einen Eintrag, und die gemessene
/// Suchdauer beschriebe den billigstmoeglichen Pfad statt eines echten
/// Bestands, in dem ein Stichwort ueber viele Einsaetze laeuft.
pub const SHARED_KEYWORD_TERM_V1: &str = "Einsatz";

/// Das `package`-te synthetische Paket der Schwellenmessung.
///
/// Jedes Paket traegt einen EINDEUTIGEN Term je Filterachse — damit misst
/// `scale_50000.rs` den Fall mit der groessten Zahl verschiedener
/// Termschluessel, also die teuerste Aufnahme, den groessten Blob und den
/// hoechsten Speicher — UND zusaetzlich [`SHARED_KEYWORD_TERM_V1`], damit
/// derselbe Lauf auch die andere Seite messen kann: eine Trefferliste, die den
/// ganzen Bestand nennt.
#[must_use]
pub fn synthetic_package(package: usize) -> IndexableRecordV1 {
    let ordinal = u32::try_from(package).expect("die Schwelle liegt weit unter u32::MAX");
    let mut record = indexable_incident(
        &format!("2026-{package:06}"),
        &format!("Stichwort {package}"),
        &format!("LF {package}"),
        &format!("Person {package}"),
        UnixMillis::new(1_771_000_000_000 + i64::from(ordinal)),
    );
    record.keyword_terms.push(SHARED_KEYWORD_TERM_V1.to_owned());
    record
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

/// Eine Paketzeile des versiegelten Koerpers, VON HAND und mit Stellschrauben.
///
/// Sie existiert, damit die Zeugen Koerper bauen koennen, die
/// `crates/ea-index/src/blob.rs` selbst nie schriebe — wohlgeformtes,
/// kanonisches, grenzenkonformes CBOR, das trotzdem keine Indexzeile ist.
#[derive(Clone)]
pub struct HandBuiltRowV1 {
    /// Die Bytes an der Herkunftsposition. 32 ist die einzige gueltige Laenge.
    pub entry_hash: Vec<u8>,
    /// Die Bytes an der Datensatzposition. 16 ist die einzige gueltige Laenge.
    pub record_id: Vec<u8>,
    /// Die Stelligkeit der Zeile. 13 ist die einzige gueltige.
    pub positions: u64,
    /// Die Stelligkeit des Optionsbehaelters. 0 und 1 sind die gueltigen.
    pub option_positions: u64,
    /// Die Stichworttermliste, unveraendert uebernommen.
    pub keyword_terms: Vec<String>,
}

impl HandBuiltRowV1 {
    /// Die WOHLGEFORMTE Zeile der laufenden Nummer `ordinal`.
    #[must_use]
    pub fn valid(ordinal: u32) -> Self {
        let mut entry_hash = vec![0_u8; 32];
        entry_hash[..4].copy_from_slice(&ordinal.to_be_bytes());
        let mut record_id = vec![0_u8; 16];
        record_id[..4].copy_from_slice(&ordinal.to_be_bytes());
        Self {
            entry_hash,
            record_id,
            positions: 13,
            option_positions: 0,
            keyword_terms: vec!["brand".to_owned()],
        }
    }
}

/// Kodiert einen Koerper aus handgebauten Zeilen.
#[must_use]
pub fn hand_built_body(rows: &[HandBuiltRowV1]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(rows.len() as u64).unwrap();
    for row in rows {
        encoder.array(row.positions).unwrap();
        encoder.bytes(&row.entry_hash).unwrap();
        encoder.u64(0).unwrap();
        encoder.bytes(&row.record_id).unwrap();
        encoder.str(INCIDENT_SCHEMA_ID).unwrap();
        encoder.u64(SCHEMA_VERSION_V1).unwrap();
        encoder.str(INCIDENT_SCHEMA_ID).unwrap();
        encoder.u64(SCHEMA_VERSION_V1).unwrap();
        encoder.str("2026-0001").unwrap();
        encoder.i64(1_771_000_000_000).unwrap();
        encoder.array(row.option_positions).unwrap();
        for _ in 0..row.option_positions {
            encoder.i64(1_771_000_000_001).unwrap();
        }
        for terms in [&row.keyword_terms, &Vec::new(), &Vec::new()] {
            encoder.array(terms.len() as u64).unwrap();
            for term in terms {
                encoder.str(term).unwrap();
            }
        }
        // Eine ueberzaehlige Stelligkeit will auch ueberzaehlige Marken, sonst
        // waere der Koerper gar kein wohlgeformtes CBOR und faellt schon an
        // `ea_cbor::validate` statt an der Stelligkeitszusicherung.
        for _ in 13..row.positions {
            encoder.u64(0).unwrap();
        }
    }
    encoder.into_writer()
}

/// Versiegelt einen Koerper von Hand, wahlweise MIT oder OHNE den Kopf als AAD.
///
/// Die zweite Fassung ist die einzige Art, die AAD-Bindung ueberhaupt zu
/// bezeugen: Magic und Formatversion prueft `IndexBlobV1::open` ohnehin
/// ausdruecklich, und die Kopf-Nonce IST die AEAD-Nonce — kein Byte des
/// heutigen Kopfes faellt also allein am AAD auf. Ein Chiffrat, das ohne den
/// Kopf versiegelt wurde, faellt genau daran und an nichts sonst.
#[must_use]
pub fn hand_sealed_blob(
    body: &[u8],
    key: &SecretBytes<CEK_SIZE>,
    nonce: &SecretBytes<AEAD_NONCE_SIZE>,
    bind_header_as_aad: bool,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&INDEX_BLOB_MAGIC_V1);
    bytes.extend_from_slice(&INDEX_FORMAT_VERSION_V1.to_be_bytes());
    nonce.with_exposed(|exposed| bytes.extend_from_slice(exposed));
    let header = bytes.clone();
    let aad: &[u8] = if bind_header_as_aad { &header } else { &[] };
    let ciphertext = aead_seal(key, nonce, SecretVec::new(body.to_vec()), aad)
        .expect("die Kulisse versiegelt einen kurzen Koerper");
    bytes.extend_from_slice(&ciphertext);
    bytes
}
