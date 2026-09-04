#![cfg(target_arch = "wasm32")]

//! Der Weg des versiegelten Index durch OPFS, in headless Chromium.
//!
//! Die Kopfzeile `#![cfg(target_arch = "wasm32")]` steht in der ERSTEN Zeile:
//! ohne sie zoege `cargo test --workspace --all-targets --locked` dieses Ziel
//! auf dem Wirt mit und faende dort weder `FileSystemSyncAccessHandle` noch
//! einen Testlaeufer. `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg`
//! durchlaeuft nur `src/` und faengt das NICHT.
//!
//! IM DEDIZIERTEN WORKER: `OpfsBlobStore::open` verlangt ihn ausdruecklich, und
//! ein Zeuge auf dem Hauptthread bestuende jeden Wirtstest und fiele erst im
//! Browser.
//!
//! # Was dieser Zeuge belegt — und was nicht
//!
//! Er belegt den WEG: versiegeln, in OPFS schreiben, den Speicher SCHLIESSEN,
//! neu oeffnen, entsiegeln, suchen. Der Bestand ist klein (drei Pakete); die
//! GROESSENORDNUNG misst `crates/ea-index/tests/scale_50000.rs` auf dem Wirt,
//! wo eine halbe Minute Rechenzeit kein Browserfenster blockiert.
//!
//! Der Indexschluessel kommt aus `UnlockedVault::index_key()` und nicht aus
//! einer Konstanten dieses Zeugen: `HKDF-SHA-256(vault_key, info =
//! VAULT_INDEX_INFO_V1)` laeuft damit ebenfalls im Browser, und der Blob geht
//! unter dem ABGELEITETEN Schluessel wieder auf.
//!
//! Der Bestand wird VON HAND gebaut und nicht aus der Kulissenkette gewonnen.
//! Das ist eine Messung und keine Bequemlichkeit: der Fixture-Klartext traegt
//! keine Schemakennung, `decrypt_verified` endet auf ihm mit
//! `EA-READER-SCHEMA-UNSUPPORTED` — nachgewiesen von
//! `the_session_key_decapsulates_in_the_browser_only_behind_the_nine_gates` in
//! `tests/verify_browser.rs` —, und es entsteht dort gar kein Zeugentyp, aus
//! dem sich eine Indexzeile projizieren liesse.

#[path = "../../ea-reader/tests/verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_crypto::{AEAD_NONCE_SIZE, SecretBytes};
use ea_index::{IndexBlobV1, IndexableRecordV1, InvertedIndexV1, ReaderQueryV1};
use ea_reader::{ReaderBlobKey, ReaderBlobStore};
use ea_reader_wasm::opfs_worker::OpfsBlobStore;
use ea_schema::SCHEMA_VERSION_V1;
use ea_types::{ChainSequence, EntryHash, RecordId, UnixMillis};
use verify_fixtures::fixtures;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Der Namensraum dieses Zeugen — ein eigenes Verzeichnis, damit kein
/// nebenlaeufig gefahrener Fall Fremdes trifft.
const NAMESPACE: &str = "ea-reader-index-test";

/// Die Adresse des Indexblobs im Bytespeicher.
const INDEX_BLOB_KEY: &str = "index/blob-v1";

/// Die Nonce dieses Zeugen. Fest, weil er eine RUNDE belegt und keine
/// Entropiequelle; frisch gezogen wird sie im Betrieb von `ReaderSearch`.
const WITNESS_NONCE: [u8; AEAD_NONCE_SIZE] = [0x07; AEAD_NONCE_SIZE];

#[wasm_bindgen_test]
async fn the_sealed_index_survives_opfs_and_answers_after_a_fresh_open() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let index_key = vault.index_key();
    let index = InvertedIndexV1::rebuild_from(three_packages().iter())
        .expect("die drei Kulissenzeilen tragen ein projizierbares Zielschema");
    let blob = IndexBlobV1::seal(&index, &index_key, &SecretBytes::new(WITNESS_NONCE))
        .expect("der Bestand muss sich im Browser versiegeln lassen");

    let key = ReaderBlobKey::new(INDEX_BLOB_KEY).unwrap();
    let mut store = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("OPFS must be reachable");
    store.put(&key, blob.bytes()).unwrap();
    // GESCHLOSSEN und nicht bloss beiseitegelegt: `drop` gibt die
    // Zugriffshandles zurueck. Was der zweite Speicher liest, kann danach nur
    // von der Platte kommen — ein Index, der still im linearen Speicher
    // haengengeblieben waere, bestuende diesen Zeugen nicht.
    drop(store);

    let mut reopened_store = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("the namespace must reopen after the first store closed its handles");
    let persisted = reopened_store
        .get(&key)
        .unwrap()
        .expect("der Blob muss den Neustart des Speichers ueberleben");
    assert_eq!(persisted, blob.bytes());

    let reopened = IndexBlobV1::open(&persisted, &vault.index_key())
        .expect("derselbe abgeleitete Schluessel muss den Blob wieder oeffnen");
    assert_eq!(reopened.indexed_packages(), 3);
    let hits = reopened.search(&ReaderQueryV1::vehicle("LF 10")).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].human_incident_number(), "2026-0001");
    assert_eq!(
        reopened
            .search(&ReaderQueryV1::person("ada lovelace"))
            .unwrap()
            .len(),
        1,
        "die Faltung des Termschluessels laeuft im Browser wie auf dem Wirt"
    );

    // Und der FREMDE Schluessel faellt auch hier an der AEAD-Bindung: sonst
    // sagte der Zeuge nur, dass irgendein Weg durch OPFS geht.
    assert_eq!(
        IndexBlobV1::open(&persisted, &SecretBytes::new([0x34; 32]))
            .unwrap_err()
            .code(),
        "EA-CRYPTO-AEAD-OPEN"
    );

    // Aufgeraeumt wird ueber DENSELBEN Speicher und nicht ueber einen dritten:
    // `OpfsBlobStore::open` nimmt je Schluessel einen Warteschlangenplatz, und
    // ein zweiter Speicher auf einem Schluessel, den dieser Fall noch haelt,
    // wartete auf sich selbst. GEMESSEN gegen die erste Fassung dieses Zeugen:
    // `Failed to detect test as having been run. It might have timed out.`
    reopened_store.delete(&key).unwrap();
}

/// Drei Indexzeilen, von Hand und ohne Umweg ueber eine Readerflaeche.
fn three_packages() -> Vec<IndexableRecordV1> {
    [
        ("2026-0001", "Brand", "LF 10", "Ada Lovelace"),
        ("2026-0002", "Verkehrsunfall", "RTW 1", "Grace Hopper"),
        ("2026-0003", "Ölspur", "MTW", "Käthe Paulus"),
    ]
    .into_iter()
    .enumerate()
    .map(|(ordinal, (number, keyword, vehicle, person))| {
        let ordinal = u32::try_from(ordinal).expect("drei Zeilen");
        let mut hash = [0_u8; 32];
        hash[..4].copy_from_slice(&ordinal.to_be_bytes());
        let mut id = [0_u8; 16];
        id[..4].copy_from_slice(&ordinal.to_be_bytes());
        IndexableRecordV1 {
            source_entry_hash: EntryHash::try_from(&hash[..]).unwrap(),
            chain_sequence: ChainSequence::new(u64::from(ordinal)),
            record_id: RecordId::try_from(&id[..]).unwrap(),
            source_schema_id: "ea.incident".to_owned(),
            source_schema_version: SCHEMA_VERSION_V1,
            target_schema_id: "ea.incident".to_owned(),
            target_schema_version: SCHEMA_VERSION_V1,
            human_incident_number: number.to_owned(),
            occurred_at_start: UnixMillis::new(1_771_000_000_000 + i64::from(ordinal)),
            occurred_at_end: None,
            keyword_terms: vec![keyword.to_owned()],
            vehicle_terms: vec![vehicle.to_owned()],
            person_terms: vec![person.to_owned()],
        }
    })
    .collect()
}
