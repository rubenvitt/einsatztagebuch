// crates/ea-reader-wasm/tests/bridge_boundary.rs
//
// WIRTSZEUGE, und der cfg-Kopf sagt es. Ohne ihn zoege der Browserlauf
// `cargo test --locked -p ea-reader-wasm --target wasm32-unknown-unknown`
// dieses Ziel mit, uebersetzte es fuer wasm32 und uebergaebe es dem
// `wasm-bindgen-test-runner` — der findet in einem Ziel ohne
// `#[wasm_bindgen_test]` keinen einzigen Fall. Das Spiegelbild WIRD ueber
// `crates/ea-reader-wasm/tests/opfs_browser.rs` stehen und aus dem umgekehrten
// Grund `#![cfg(target_arch = "wasm32")]` tragen; die Datei gibt es heute noch
// nicht, sie entsteht mit der Aufgabe „`apps/web`, die wasm-bindgen-Bruecke,
// der OPFS-Bytespeicher und der Laufzeitnachweis im Gate".
#![cfg(not(target_arch = "wasm32"))]

use std::{
    fs,
    path::{Path, PathBuf},
};

use ea_reader::{GATE_ORDER_V1, ReaderMode};
use ea_reader_wasm::bridge_echo;

/// Sammelt JEDE `.rs`-Datei unter `directory`, REKURSIV.
///
/// Rekursiv und nicht flach, und das ist keine Vorsorge, sondern die
/// Voraussetzung dafuer, dass der Zeuge weiter misst, was sein Name sagt: ein
/// `fs::read_dir` ueber `src/` allein saehe `src/bridge/opfs.rs` NICHT, und
/// `assert!(exports > 0)` bliebe an `lib.rs` trotzdem gruen. Der Zeuge meldete
/// dann nichts und schwiege dabei laut. Nach der Messung im Doc-Kommentar
/// unten ist er die einzige Instanz, die ein fehlendes cfg faengt; er darf
/// keinen Winkel dieser Crate auslassen. Angelegt, solange die Crate EINE
/// Quelle hat und es nichts kostet.
fn collect_rust_sources(directory: &Path, into: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory).unwrap_or_else(|error| {
        panic!(
            "{} must be a readable directory: {error}",
            directory.display()
        )
    });
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, into);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            into.push(path);
        }
    }
}

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
///
/// # Die verlangte Bauform ist das cfg AM ITEM
///
/// Das `#[cfg(target_arch = "wasm32")]` steht unmittelbar ueber dem Attribut
/// jeder einzelnen Ausfuhr, nicht am umschliessenden `mod`. Ein Modultor waere
/// fuer die Uebersetzung gleichwertig, fuer diesen Zeugen aber unsichtbar: er
/// liest Text und folgt keinem `mod`. Die Regel ist deshalb die engere von
/// beiden — je Ausfuhr ein cfg —, und die Fehlermeldung unten sagt es.
///
/// # Dieser Zeuge ist die EINZIGE Instanz, und das ist GEMESSEN
///
/// Der Stufe-4-Plan nahm an, eine Ausfuhr ohne ihr cfg falle ohnehin am
/// Wirtsbau auf — „spaeter und unklarer", aber sie falle. Das ist falsch.
/// Gemessen in der Aufgabe „wasm32-Reichweite" mit entferntem
/// `#[cfg(target_arch = "wasm32")]` ueber `bridge_echo_js` und sonst
/// unveraendertem Baum: `cargo build --locked -p ea-reader-wasm --lib`,
/// `cargo test --locked -p ea-reader-wasm --all-targets --no-run` und
/// `cargo clippy --locked -p ea-reader-wasm --all-targets --all-features --
/// -D warnings` enden ALLE DREI mit 0 und ohne eine einzige Diagnose;
/// `wasm-bindgen 0.2.126` uebersetzt sein Attribut auf einem Nicht-wasm-Ziel
/// klaglos, sogar unter `#![forbid(unsafe_code)]`. Nur dieser Zeuge fiel
/// (Exitcode 101).
///
/// Es gibt also KEIN zweites Netz. Fuer die acht Bruecken-Module, die nach
/// diesem Task entstehen — `bridge.rs`, `opfs_worker.rs`, `vault_bridge.rs`,
/// `webauthn.rs`, `fetch.rs`, `file_access.rs`, `visibility.rs`, `view.rs` —,
/// heisst das: der Compiler warnt NICHT mit. Ein vergessenes cfg faellt hier
/// oder gar nicht, und die Ausfuhr wandert unbemerkt in die Wirtsbibliothek.
#[test]
fn every_wasm_bindgen_export_sits_behind_the_wasm32_cfg() {
    // Der Zeuge laeuft ueber JEDE Quelle der Bruecke — rekursiv, siehe
    // `collect_rust_sources` — und ueber BEIDE
    // Schreibweisen des Attributs. Acht spaetere Module — `bridge.rs`,
    // `opfs_worker.rs`, `vault_bridge.rs`, `webauthn.rs`, `fetch.rs`,
    // `file_access.rs`, `visibility.rs`, `view.rs` — legen Ausfuhren an, und
    // sie schreiben `#[wasm_bindgen(js_name = …)]` nach einem
    // `use wasm_bindgen::prelude::*;`. Ein Zeuge, der nur `src/lib.rs` liest
    // und nur die voll qualifizierte Form kennt, saehe keine davon.
    let mut sources: Vec<PathBuf> = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
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
                "every wasm_bindgen export must carry `#[cfg(target_arch = \"wasm32\")]` on \
                 the ITEM ITSELF, on the line directly above the attribute. A cfg on the \
                 enclosing `mod` instead does not satisfy this witness and is not the \
                 required shape: the witness reads text and cannot follow a module gate. \
                 Without a per-item cfg the export is compiled into the HOST library as well, \
                 and NOTHING ELSE reports it — on exactly that mutation `cargo build --lib`, \
                 `cargo test --all-targets --no-run` and \
                 `cargo clippy --all-targets -- -D warnings` were all measured to end with 0. \
                 This witness is the only instance that catches it: {}",
                path.display()
            );
        }
    }
    assert!(exports > 0, "the bridge must export at least once");
}

/// `ea-reader` traegt in diesem Task KEINE Rechnung. Was hier steht, sind
/// WERTPINS und keine Struktursicherungen, und das gehoert dazugesagt.
///
/// `assert_eq!(GATE_ORDER_V1, ea_verify::GATE_ORDER_V1)` vergleicht DURCH den
/// Re-Export hindurch und ist heute tautologisch: die zwei Namen bezeichnen
/// dasselbe Element. Eine handkopierte Liste gleichen Inhalts bliebe hier
/// gruen. Dass es keine zweite Liste GIBT, sagt das `pub use` in
/// `crates/ea-reader/src/lib.rs` und nicht dieser Test; die Zusicherung faengt
/// erst dann etwas, wenn `ea-reader` je eine eigene Konstante deklarierte —
/// dann misst sie deren Inhaltsgleichheit.
///
/// `ReaderMode::ALL.len()` pinnt ebenso einen WERT und keine Vollstaendigkeit.
/// Die Geschlossenheit erzwingt der erschoepfende `match` in
/// `ReaderMode::code`; aufgeschrieben und gemessen ist das an
/// `crates/ea-reader/src/mode.rs`.
#[test]
fn the_reader_crate_reexports_the_gate_order_instead_of_redeclaring_it() {
    assert_eq!(GATE_ORDER_V1, ea_verify::GATE_ORDER_V1);
    assert_eq!(ReaderMode::ALL.len(), 2);
    assert_eq!(ReaderMode::Server.code(), "server");
    assert_eq!(ReaderMode::File.code(), "file");
}
