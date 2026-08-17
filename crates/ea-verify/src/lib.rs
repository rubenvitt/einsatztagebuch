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
mod entry;
mod error;
mod evidence;
mod gates;
mod json;
mod recipient;
mod report;
mod state;

pub use archive::{
    EvidenceRequirementV1, RecipientKeyV1, VerifyOptions, verify_archive, verify_archive_observed,
};
pub use entry::GRANT_PLAN_MISMATCH_CODE_V1;
pub use error::{ManifestSignatureErrorV1, ReceiptGateErrorV1, VerifyError};
pub use evidence::EvidenceGateErrorV1;
pub use gates::{
    DECAPSULATION_EVENT_V1, Decapsulation, GATE_ORDER_V1, Gate, GateObserver, GateRunner,
    RecordingObserver, SilentObserver, run_gates,
};
pub use recipient::{DecryptionErrorV1, RecipientGrantErrorV1};
pub use report::{
    AuthorizedDestructionV1, ChainGapV1, ChainHeadV1, DestructionStateV1, ObjectErrorV1,
    ObjectResultKindV1, ObjectResultV1, ObjectTypeV1, QuarantinedObjectV1, ServerConfirmationV1,
    VerificationReportV1,
};
pub use state::{EphemeralTrustStateStore, verification_state_key};
