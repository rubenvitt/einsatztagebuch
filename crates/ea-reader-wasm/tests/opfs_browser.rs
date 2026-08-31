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

use ea_reader::{ReaderBlobKey, ReaderBlobStore};
use ea_reader_wasm::opfs_worker::OpfsBlobStore;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

// IM DEDIZIERTEN WORKER und nirgends sonst: `FileSystemSyncAccessHandle`
// existiert auf dem Hauptthread nicht. Eine Implementierung dort bestuende jeden
// Wirtstest und fiele erst im Browser.
wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
fn opfs_round_trips_the_same_bytes_the_in_memory_double_does() {
    let mut store = OpfsBlobStore::open("ea-reader-test").expect("OPFS must be reachable");
    let key = ReaderBlobKey::new("probe/opaque").unwrap();
    store.put(&key, b"\x00\xff\x00opaque").unwrap();
    assert_eq!(
        store.get(&key).unwrap().as_deref(),
        Some(&b"\x00\xff\x00opaque"[..])
    );
    store.delete(&key).unwrap();
    assert_eq!(store.get(&key).unwrap(), None);
}
