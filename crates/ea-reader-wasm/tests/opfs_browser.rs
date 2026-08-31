#![cfg(target_arch = "wasm32")]

//! Der zweite gegatete Zeuge und der erste `wasm-bindgen-test` des
//! Repositoriums.
//!
//! Die Kopfzeile `#![cfg(target_arch = "wasm32")]` steht in der ERSTEN Zeile:
//! ohne sie zoege `cargo test --workspace --all-targets --locked` dieses Ziel
//! auf dem Wirt mit und faende dort weder `FileSystemSyncAccessHandle` noch
//! einen Testlaeufer. `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg`
//! durchlaeuft nur `src/` und faengt das NICHT — eine fehlende Kopfzeile faellt
//! erst im `pnpm verify:quick`, an der spaetesten und teuersten Stelle.
//!
//! # Warum die Faelle ASYNCHRON sind
//!
//! `OpfsBlobStore::open` ist der asynchrone Vorlauf, der die Zugriffshandles
//! oeffnet; erst danach ist der Speicher synchron. Ein synchroner Testfall
//! koennte ihn nicht abwarten — genau die Naht, die
//! `crates/ea-reader-wasm/src/opfs_worker.rs` beschreibt. `put`, `get`,
//! `delete` und `keys` stehen in beiden Faellen bewusst OHNE `await` da: dass
//! sie es nicht brauchen, IST die Zusage dieses Zeugen.

use ea_reader::{InMemoryReaderBlobStore, ReaderBlobKey, ReaderBlobStore};
use ea_reader_wasm::opfs_worker::OpfsBlobStore;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

// IM DEDIZIERTEN WORKER und nirgends sonst: `FileSystemSyncAccessHandle`
// existiert auf dem Hauptthread nicht. Eine Implementierung dort bestuende jeden
// Wirtstest und fiele erst im Browser.
wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Der Namensraum der Zeugen — ein Verzeichnis unter der OPFS-Wurzel und nicht
/// die Wurzel selbst, damit kein Lauf Fremdes trifft.
const NAMESPACE: &str = "ea-reader-test";

/// Die Bytefolge traegt eine 0, ein 0xff und ASCII: sie faellt an jeder Stelle
/// auf, die Bytes fuer Text haelt oder am Nullbyte abschneidet.
const OPAQUE: &[u8] = b"\x00\xff\x00opaque";

#[wasm_bindgen_test]
async fn opfs_round_trips_the_same_bytes_the_in_memory_double_does() {
    let key = ReaderBlobKey::new("probe/opaque").unwrap();
    let mut opfs = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("OPFS must be reachable");
    // Das Doppel laeuft Schritt fuer Schritt MIT: der Zeuge vergleicht nicht
    // gegen erwartete Werte, die jemand aufgeschrieben hat, sondern gegen den
    // Port selbst, wie ihn `cargo test -p ea-reader` ohne Browser sieht.
    let mut double = InMemoryReaderBlobStore::new();

    assert_eq!(opfs.get(&key).unwrap(), double.get(&key).unwrap());

    opfs.put(&key, OPAQUE).unwrap();
    double.put(&key, OPAQUE).unwrap();
    assert_eq!(opfs.get(&key).unwrap().as_deref(), Some(OPAQUE));
    assert_eq!(opfs.get(&key).unwrap(), double.get(&key).unwrap());
    assert_eq!(opfs.keys().unwrap(), double.keys().unwrap());

    opfs.delete(&key).unwrap();
    double.delete(&key).unwrap();
    assert_eq!(opfs.get(&key).unwrap(), None);
    assert_eq!(opfs.get(&key).unwrap(), double.get(&key).unwrap());
    assert_eq!(opfs.keys().unwrap(), double.keys().unwrap());
}

/// Der Zeuge gegen den stillen Rueckfall in den Arbeitsspeicher.
///
/// Ein Speicher, der die Bytes in einer `BTreeMap` neben sich haelt, bestuende
/// den Rundlauf oben vollstaendig. Er faellt HIER: der erste Speicher wird
/// GESCHLOSSEN — `drop` gibt die Zugriffshandles zurueck —, und der zweite
/// oeffnet dieselbe Datei neu. Was der zweite liest, kann nur von der Platte
/// kommen.
#[wasm_bindgen_test]
async fn bytes_survive_a_store_that_is_dropped_and_opened_again() {
    let key = ReaderBlobKey::new("probe/persisted").unwrap();

    let mut first = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("OPFS must be reachable");
    first.put(&key, OPAQUE).unwrap();
    drop(first);

    let mut second = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("the namespace must reopen after the first store closed its handles");
    assert_eq!(second.get(&key).unwrap().as_deref(), Some(OPAQUE));

    // Und die Loeschung ueberlebt genauso: sonst kaeme der Blob nach einem
    // Neustart des Workers zurueck.
    second.delete(&key).unwrap();
    drop(second);

    let third = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("the namespace must reopen a third time");
    assert_eq!(third.get(&key).unwrap(), None);
}
