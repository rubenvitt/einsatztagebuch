#![forbid(unsafe_code)]
//! Die Bruecke zwischen dem geteilten Rust-Kern und der Browser-Umgebung.
//!
//! # Kein Skelett mehr
//!
//! Bis zur Aufgabe „wasm32-Reichweite" stand hier genau so viel, wie diese
//! Reichweite belegen konnte: EINE reine Funktion und EIN duenner Export
//! darueber. Der echte Uebergang steht jetzt daneben — [`bridge`] traegt den
//! Laufzeitzeugen nach `web-reader-design.md` §14.1 und die zwei
//! Bytespeicher-Ausfuhren, [`opfs_worker`] den OPFS-Wirt dahinter, und
//! [`vault_bridge`] seit der Aufgabe „Browser-Vault: PRF-Envelopes,
//! Schlüsselprofil und die Verwahrung von Anchor und KEM-Schlüssel" die zwei
//! Tresorausfuhren. [`webauthn`] kommt mit der Aufgabe „Browser-Enrollment:
//! zwei Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate"
//! dazu und trägt die fünf Enrollment-Ausfuhren samt der Browserfassung des
//! Endpunktports.
//!
//! # Was hier NICHT liegt
//!
//! Die Rechnung selbst gehoert den geteilten Crates. `bridge.rs` ruft
//! `ea_crypto` und `ea_reader` und entscheidet nichts; `opfs_worker.rs` legt
//! OPAKE Bytes ab und weiss nicht, was in ihnen steht. Waere es anders, gaebe
//! es eine zweite Stelle, an der ueber Klartext entschieden wird — und
//! `web-reader-design.md` §9 laesst Kryptographie ausschliesslich in geteiltem
//! Rust zu.
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
//!
//! **Dieser Zeuge ist die EINZIGE Instanz, die das merkt, und das ist
//! GEMESSEN.** Mit entferntem cfg enden Uebersetzung, Testbau und Clippy-Gate
//! alle drei mit 0 und ohne eine einzige Diagnose; nur der Zeuge faellt. Der
//! Compiler ist hier also KEIN zweites Netz — wer ein weiteres Modul mit einer
//! Ausfuhr anlegt und ihr cfg vergisst, wird nirgends sonst gewarnt. Die
//! Messung samt ihren vier Kommandos steht im Doc-Kommentar von
//! `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg`.

/// Die Ausfuhren nach JavaScript und der Laufzeitzeuge.
///
/// Das Modul ist auf JEDEM Ziel uebersetzbar; nur seine Ausfuhren stehen
/// hinter `cfg(target_arch = "wasm32")`. Das ist dieselbe Bauform wie unten:
/// die Rechnung bleibt fuer einen gewoehnlichen Wirtstest erreichbar.
pub mod bridge;

/// Der OPFS-Bytespeicher — NUR auf `wasm32-unknown-unknown`.
///
/// Das Tor steht hier an der `mod`-Zeile und nicht an jedem Item, und das ist
/// zulaessig, weil das Modul KEINE `wasm_bindgen`-Ausfuhr traegt: die Regel
/// „cfg am Item" von `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg`
/// gilt genau den Ausfuhren, und die stehen in [`bridge`]. Auf einem Wirtsziel
/// gaebe es fuer `FileSystemSyncAccessHandle` ohnehin keinen Wirt.
///
/// Die Attributschreibweise steht hier bewusst OHNE ihre Klammern: der Zeuge
/// liest Text und unterscheidet eine Ausfuhr nicht von einer Erwaehnung. Ein
/// ausgeschriebenes Attribut in einem Fliesstext faerbte ihn rot — GEMESSEN
/// an genau dieser Zeile.
#[cfg(target_arch = "wasm32")]
pub mod opfs_worker;

/// Die Tresorbruecke: die zwei Ausfuhren des Browser-Tresors.
///
/// Das Modul steht OHNE cfg an der `mod`-Zeile, weil es Ausfuhren traegt und
/// die Regel „cfg am Item" dann fuer jede einzelne von ihnen gilt — dieselbe
/// Lage wie bei [`bridge`] und ausdruecklich nicht die von `opfs_worker`.
///
/// Hier ueberquert die PRF-Ausgabe die Grenze, und zwar NUR in dieser
/// Richtung: `web-reader-design.md` §9 laesst nach JavaScript Sitzungskennung,
/// Fingerabdruecke und Statuswerte, nie Schluesselmaterial.
pub mod vault_bridge;

/// Das Browser-Enrollment: die fuenf Ausfuhren und der Endpunktport dahinter.
///
/// Das Modul steht OHNE cfg an der `mod`-Zeile, weil es Ausfuhren traegt und
/// die Regel „cfg am Item" dann fuer jede einzelne von ihnen gilt — dieselbe
/// Lage wie bei [`bridge`] und [`vault_bridge`] und ausdruecklich nicht die
/// von `opfs_worker`. Ein `pub mod` und kein `mod`, weil der Zeuge
/// `crates/ea-reader-wasm/tests/bridge_boundary.rs` und die Aufgabe selbst die
/// Ausfuhren unter `ea_reader_wasm::webauthn` benennen.
///
/// Alle fuenf Ausfuhren laufen IM DEDIZIERTEN WORKER: der Zustand liegt in
/// einem `thread_local!`, OPFS und das synchrone `XMLHttpRequest` gibt es nur
/// dort. `navigator.credentials` gibt es umgekehrt nur auf dem Hauptthread —
/// die Naht dazwischen ist die Nachrichtenform von
/// `apps/web/src/bridge/opfs-worker.ts`.
pub mod webauthn;

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
