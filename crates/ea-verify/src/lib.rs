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
//!
//! # Die Pipeline
//!
//! [`verify_archive`] laeuft die neun Gates aus design.md 14.1 in genau der
//! Reihenfolge von [`GATE_ORDER_V1`] — `format`, `trust`, `registry`,
//! `manifest-signature`, `chain-position`, `grant-plan`, `receipt`, `evidence`,
//! `recipient-grant` — und danach, AUSDRUECKLICH ALS KEIN GATE, die
//! Entkapselung [`DECAPSULATION_EVENT_V1`]. Das Protokoll eines
//! [`GateObserver`] ist stets ein PRAEFIX von [`GATE_ORDER_V1`], gefolgt von
//! hoechstens einem Entkapselungsereignis; gemeldet wird der Eintritt in eine
//! STUFE, nicht der Eintritt je Objekt.
//!
//! `authorizedDestructions` entsteht ZULETZT und still: ein zehnter
//! Protokolleintrag waere eine erfundene Stufe. Zuletzt, weil die
//! Registrierungslinie sich nur VORWAERTS nachziehen laesst und die
//! `authorizationSequence` einer Vernichtung hinter den Eintragssequenzen
//! liegt.
//!
//! # Das Portverhaeltnis
//!
//! Diese Crate besitzt keinen eigenen Zugriff auf einen Bestand. Sie bekommt
//! `ea_archive::ArchiveSource` als Parameter, laesst `ea_archive::ArchiveInventory`
//! daraus klassifizieren und reicht dasselbe Inventar als
//! `ea_trust::TrustObjectSource` weiter. Kettenaussagen kommen aus `ea-chain`,
//! das seinerseits nur Werte sieht. Uhr, Trust Anchor und Empfaengerschluessel
//! sind Parameter in [`VerifyOptions`].
//!
//! # Der Reportvertrag
//!
//! [`VerificationReportV1`] ist ein reiner Rust-Wert; `to_canonical_json`
//! schreibt ihn ueber einen handgeschriebenen kanonischen Schreiber. Gepinnt
//! und nicht verhandelbar:
//!
//! - Ein Objekt erscheint ENTWEDER in `objectResults` ODER in genau einem
//!   Fehler-/Quarantaenearray, niemals in beidem.
//! - `registryVersions` und `publicKeyThumbprints` sind Nachweise des
//!   GEPRUEFTEN: die Version stammt nur aus Objekten, die Gate
//!   `manifest-signature` bestanden haben, der Abdruck nur aus einer
//!   ERFOLGREICHEN Signaturpruefung. Aus unauthentischen Bytes stammen
//!   ausschliesslich Zaehler und Fehlereintraege.
//! - `chainHead` ist Pflicht und nie null; `chainId` ist IMMER
//!   `anchor.chain_id()`. Ohne verifizierten Kopf gilt das Sentinel aus
//!   [`ChainHeadV1::sentinel`] — Sequenz null und ein Nullhash, und
//!   ausdruecklich NICHT `anchor.genesis_entry_hash()`, das einen verifizierten
//!   Genesis-Eintrag behaupten wuerde.
//! - [`VerificationReportV1::is_fully_verified`] ist ein ABGELEITETER Accessor
//!   und kein JSON-Feld; das Schema ist `additionalProperties: false`.
//!   `notServerConfirmed` und ein fehlender Empfaengerschluessel senken ihn NIE.
//! - `reportHash` ist SHA-256 ueber die kanonischen Bytes OHNE `reportHash`,
//!   `reportSignature` und `runtimeMetadata`.
//!
//! Ein Befund ueber ein einzelnes Objekt ist NIE ein `Err`. Auch ein
//! Fehlschlag von Gate `trust` liefert `Ok`, ist aber fail-closed fuer den
//! ganzen Bestand: es wird ueber keinen Eintrag etwas ausgesagt.

mod archive;
mod destruction;
mod entry;
mod error;
mod evidence;
mod gates;
mod json;
mod recipient;
mod report;
mod state;

/// Die geschlossene Menge der sechs Objektarten, DURCHGEREICHT.
///
/// Sie steht neben den Exact-Object-Praefixen in `ea-format` und nicht ein
/// zweites Mal hier; `objectResult.objectType` des Berichts ist genau ihr
/// Wertebereich.
pub use ea_format::ObjectTypeV1;

pub use archive::{
    EvidenceRequirementV1, RecipientKeyV1, VerifyOptions, verify_archive, verify_archive_observed,
};
pub use destruction::DestructionErrorV1;
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
    ObjectResultKindV1, ObjectResultV1, QuarantinedObjectV1, ServerConfirmationV1,
    VerificationReportV1,
};
pub use state::{EphemeralTrustStateStore, verification_state_key};
