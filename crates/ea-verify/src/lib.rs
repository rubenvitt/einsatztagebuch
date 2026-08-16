#![forbid(unsafe_code)]
//! Gates, Pipeline und Verifikationsreport des Einsatzarchivs.
//!
//! Diese Crate haelt die einzige Quelle der neun Gate-Bezeichner aus
//! design.md 14.1 und schreibt den Report ueber einen handgeschriebenen
//! kanonischen JSON-Writer. Zeit und Trust Anchor kommen stets als
//! Parameter; weder `std::fs` noch eine Uhr noch eine JSON-Bibliothek
//! gehoeren in diese Crate.

mod gates;

pub use gates::{
    DECAPSULATION_EVENT_V1, Decapsulation, GATE_ORDER_V1, Gate, GateObserver, GateRunner,
    RecordingObserver, run_gates,
};
