// crates/ea-reader-wasm/tests/bridge_boundary.rs
//
// WIRTSZEUGE, und der cfg-Kopf sagt es. Ohne ihn zoege der Browserlauf
// `cargo test --locked -p ea-reader-wasm --target wasm32-unknown-unknown`
// dieses Ziel mit, uebersetzte es fuer wasm32 und uebergaebe es dem
// `wasm-bindgen-test-runner` — der findet in einem Ziel ohne
// `#[wasm_bindgen_test]` keinen einzigen Fall. Das Spiegelbild steht ueber
// `crates/ea-reader-wasm/tests/opfs_browser.rs`, das aus dem umgekehrten Grund
// `#![cfg(target_arch = "wasm32")]` traegt.
#![cfg(not(target_arch = "wasm32"))]

use std::{
    fs,
    path::{Path, PathBuf},
};

use ea_reader::{GATE_ORDER_V1, ReaderMode};
use ea_reader_wasm::bridge_echo;

/// Der Rundlauf in BEIDE Richtungen: ein Argument geht hinein, ein anderer
/// Wert kommt heraus. Ein Export, der nur einen Rueckgabewert liefert, belegt
/// nicht, dass Argumente die Grenze ueberhaupt erreichen — genau die Luecke,
/// die `echo_from_js` im Spike `spikes/wasm-runtime-proof/src/lib.rs` schliesst.
#[test]
fn the_bridge_returns_what_its_caller_hands_it() {
    assert_eq!(bridge_echo("Datei-Modus"), "ea-reader-wasm: Datei-Modus");
    assert_ne!(bridge_echo("a"), bridge_echo("b"));
}

/// Das wasm-Ziel wird in diesem Task NICHT ausgefuehrt. Belegbar ist hier
/// deshalb nur die LAGE des Exports, und die wird als Text gelesen — dieselbe
/// Bauform, mit der `every_crates_member_is_classified_for_the_wasm32_gate`
/// den wasm32-Block aus `tools/xtask/src/main.rs` liest.
#[test]
fn every_wasm_bindgen_export_sits_behind_the_wasm32_cfg() {
    // Der Zeuge laeuft ueber JEDE Quelle der Bruecke und ueber BEIDE
    // Schreibweisen des Attributs. Acht spaetere Module — `bridge.rs`,
    // `opfs_worker.rs`, `vault_bridge.rs`, `webauthn.rs`, `fetch.rs`,
    // `file_access.rs`, `visibility.rs`, `view.rs` — legen Ausfuhren an, und
    // sie schreiben `#[wasm_bindgen(js_name = …)]` nach einem
    // `use wasm_bindgen::prelude::*;`. Ein Zeuge, der nur `src/lib.rs` liest
    // und nur die voll qualifizierte Form kennt, saehe keine davon.
    let mut sources: Vec<PathBuf> = fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
        .expect("the bridge crate must have a src directory")
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    sources.sort();
    assert!(
        !sources.is_empty(),
        "the bridge must carry at least one source file"
    );

    let mut exports = 0_usize;
    for path in &sources {
        // Die qualifizierte Form wird auf die kurze zurueckgefuehrt, damit
        // GENAU EIN Muster gesucht wird und keine Schreibweise durchrutscht.
        let source = fs::read_to_string(path)
            .expect("bridge sources must be readable")
            .replace("#[wasm_bindgen::prelude::wasm_bindgen", "#[wasm_bindgen");
        for (index, _) in source.match_indices("#[wasm_bindgen") {
            // `#[wasm_bindgen_test]` ist kein Export und wird nicht gezaehlt.
            if source[index..].starts_with("#[wasm_bindgen_test") {
                continue;
            }
            exports += 1;
            assert!(
                source[..index]
                    .trim_end()
                    .ends_with("#[cfg(target_arch = \"wasm32\")]"),
                "a wasm_bindgen export without the wasm32 cfg breaks the host build of \
                 `cargo test --workspace --all-targets --locked`: {}",
                path.display()
            );
        }
    }
    assert!(exports > 0, "the bridge must export at least once");
}

/// `ea-reader` traegt in diesem Task KEINE Rechnung. Die zwei Zusicherungen
/// sind: der Modus ist geschlossen und zweiwertig, und die Gate-Reihenfolge
/// kommt aus `ea-verify` und wird hier nicht ein zweites Mal geschrieben.
#[test]
fn the_reader_crate_reexports_the_gate_order_instead_of_redeclaring_it() {
    assert_eq!(GATE_ORDER_V1, ea_verify::GATE_ORDER_V1);
    assert_eq!(ReaderMode::ALL.len(), 2);
    assert_eq!(ReaderMode::Server.code(), "server");
    assert_eq!(ReaderMode::File.code(), "file");
}
