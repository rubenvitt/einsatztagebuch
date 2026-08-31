#![forbid(unsafe_code)]
//! Die Index-Crate des Web-Readers.
//!
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §12
//! macht `ea-reader` wasm32-faehig; die Crate steht deshalb auf der
//! wasm32-Positivliste von `verify_quick_commands()` und ausdruecklich NICHT
//! auf `WASM32_EXEMPT_CRATES` — dessen Kriterium ist der Griff ueber
//! `ea-verify` hinaus in das Wirtbetriebssystem, und geteilter Browsercode ist
//! genau das Gegenteil davon.
//!
//! # In dieser Stufe ein Skelett
//!
//! Sie traegt hier KEINE Rechnung: zwei Betriebsarten und den Re-Export der
//! Gate-Reihenfolge. Der Reader selbst — Verifikationsdurchlauf, Datei-Modus,
//! Tresor — entsteht in den folgenden Aufgaben der Stufe 4. Die Crate entsteht
//! VOR ihrem Inhalt, weil die wasm32-Reichweite in dem Task belegt sein muss,
//! der sie eroeffnet, und nicht in dem, der sie benutzt.
//!
//! # Die Gate-Reihenfolge wird RE-EXPORTIERT
//!
//! [`GATE_ORDER_V1`] kommt aus `ea-verify` und wird hier nicht ein zweites Mal
//! geschrieben. `crates/ea-verify/src/gates.rs` ist die EINZIGE Quelle dieser
//! neun Zeichenketten, und `tools/xtask/tests/spec_completeness.rs` haelt sie
//! gegen `design.md` §14.1; eine zweite Liste daneben waere die Stelle, an der
//! die Reihenfolge des Browsers von der des Wirts abweichen koennte.

mod mode;

pub use ea_verify::GATE_ORDER_V1;
pub use mode::ReaderMode;
