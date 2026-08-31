#![forbid(unsafe_code)]
//! Die Bruecke zwischen dem geteilten Rust-Kern und der Browser-Umgebung.
//!
//! # In dieser Stufe ein Skelett
//!
//! Der echte Uebergang — OPFS-Bytespeicher, wasm-bindgen-Generatorlauf,
//! Vektorzeugen im Gate und headless-Chromium — gehoert der Aufgabe
//! „`apps/web`, die wasm-bindgen-Bruecke, der OPFS-Bytespeicher und der
//! Laufzeitnachweis im Gate". Hier steht genau so viel, wie die
//! wasm32-Reichweite belegen kann: EINE reine Funktion und EIN duenner Export
//! darueber. `xtask build-wasm` existiert seit dem Vorlauf-Task und hatte bis
//! jetzt nichts zu bauen; ab hier hat es das.
//!
//! # Die Bauform: reine Funktion, duenner Export
//!
//! [`bridge_echo`] traegt die Rechnung und ist auf JEDEM Ziel uebersetzbar;
//! darueber liegt ein Export, der nichts tut, als sie zu rufen, und der hinter
//! `cfg(target_arch = "wasm32")` steht. Das ist keine Formsache, sondern die
//! Voraussetzung von zwei Dingen zugleich: der Wirtsbau von
//! `cargo test --workspace --all-targets --locked` uebersetzt das
//! wasm-bindgen-Attribut nicht, und die Rechnung bleibt fuer einen gewoehnlichen
//! Wirtstest erreichbar. `crates/ea-reader-wasm/tests/bridge_boundary.rs` liest
//! diese Lage als Text und wird rot, sobald ein Export ohne sein cfg
//! danebensteht.

/// Der Rundlauf ueber die Bruecke, ohne eine einzige Zusage darueber hinaus.
///
/// Die Funktion gibt zurueck, was ihr Aufrufer ihr reicht, versehen mit dem
/// Namen der Crate. Sie belegt damit BEIDE Richtungen: dass ein Argument die
/// Grenze erreicht und dass ein Wert sie wieder verlaesst. Ein Export, der nur
/// einen Rueckgabewert liefert, belegte die erste Haelfte nicht — genau die
/// Luecke, die `echo_from_js` im Spike `spikes/wasm-runtime-proof/src/lib.rs`
/// geschlossen hat.
#[must_use]
pub fn bridge_echo(value: &str) -> String {
    format!("ea-reader-wasm: {value}")
}

/// [`bridge_echo`], ausgefuehrt nach JavaScript.
///
/// `js_name` in lowerCamelCase, weil der Name auf der JS-Seite gelesen wird.
/// Die volle Qualifizierung des Attributs statt eines `use` im Kopf: ein
/// `use wasm_bindgen::prelude::*;` waere auf einem Wirtsziel unbenutzt und
/// muesste selbst ein cfg tragen.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = bridgeEcho)]
#[must_use]
pub fn bridge_echo_js(value: &str) -> String {
    bridge_echo(value)
}
