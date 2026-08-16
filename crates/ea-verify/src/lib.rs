#![forbid(unsafe_code)]
//! Gates, Pipeline und Verifikationsreport des Einsatzarchivs.
//!
//! Diese Crate haelt die einzige Quelle der neun Gate-Bezeichner aus
//! design.md 14.1 und schreibt den Report ueber einen handgeschriebenen
//! kanonischen JSON-Writer. Zeit und Trust Anchor kommen stets als
//! Parameter; weder `std::fs` noch eine Uhr noch eine JSON-Bibliothek
//! gehoeren in diese Crate.
//!
//! `serde_json` und `jsonschema` sind hier AUSGESCHLOSSEN: `jsonschema` zoege
//! `getrandom 0.3.4` in den wasm-Graphen, und diese Crate steht auf der
//! wasm32-Positivliste von `tools/xtask/src/main.rs`. Der Schemanachweis des
//! Berichts liegt deshalb in `tests/ea-system-tests`.
//!
//! Ebenso ausgeschlossen sind `HashMap` und `HashSet`: die Reihenfolge jeder
//! Berichtssammlung ist Teil des Contracts, und eine Streuordnung waere in
//! Unit-Tests unauffaellig und kippte den Schematest nur sporadisch. Alle
//! Sammlungen liegen in `BTreeMap`/`BTreeSet` ueber genau dem
//! `x-ea-unique-key` ihres Schemas.

mod archive;
mod error;
mod gates;
mod json;
mod report;
mod state;

pub use archive::{VerifyOptions, verify_archive};
pub use error::VerifyError;
pub use gates::{
    DECAPSULATION_EVENT_V1, Decapsulation, GATE_ORDER_V1, Gate, GateObserver, GateRunner,
    RecordingObserver, run_gates,
};
pub use report::{
    AuthorizedDestructionV1, ChainGapV1, ChainHeadV1, DestructionStateV1, ObjectErrorV1,
    ObjectResultKindV1, ObjectResultV1, ObjectTypeV1, QuarantinedObjectV1, ServerConfirmationV1,
    VerificationReportV1,
};
pub use state::{EphemeralTrustStateStore, verification_state_key};
