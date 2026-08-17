#![forbid(unsafe_code)]
//! Rein wertbasierte Kettenlogik des Einsatzarchivs.
//!
//! Diese Crate kennt weder CBOR noch Signaturen noch geparste Archivobjekte,
//! sondern ausschliesslich Kettenknoten als Werte. Dadurch ist die gesamte
//! Verkettungspruefung ohne Fixtures testbar, analog zu `ea-time`. Einzige
//! Abhaengigkeit ist `ea-types`.
//!
//! `ea-types` leitet fuer seine Id- und Hash-Newtypes kein `Debug` ab. Alle
//! oeffentlichen Typen dieser Crate implementieren `Debug` deshalb von Hand
//! und geben Ids und Hashes hexadezimal in Kleinbuchstaben aus; `ea-types`
//! wird nicht angefasst. [`ChainError`] traegt zusaetzlich
//! `code() -> &'static str`, damit Tests gegen stabile Codes assertieren statt
//! gegen Formatierung.
//!
//! # Stellung in der Pipeline
//!
//! Diese Crate ist die UNTERSTE der drei: `ea-verify` haengt an ihr, sie an
//! nichts ausser `ea-types`. Sie beantwortet genau zwei Fragen, und beide
//! ausschliesslich ueber Werte:
//!
//! 1. [`build_chain`] — welche Gestalt hat die Kette? Genesis auf Sequenz null,
//!    danach exaktes Inkrement und Vorgaengerbindung. Ein Fork liefert
//!    ausdruecklich `Ok`: die abgeschnittene Kette muss mitgefuehrt werden, und
//!    ein Fork darf weder stillschweigend zur Luecke degradieren noch die
//!    Verifikation der unstrittigen Praefixsequenzen verhindern.
//!    [`VerifiedChain::verified_head`] haelt vor der kleinsten strittigen
//!    Sequenz an, [`VerifiedChain::head`] ist die hoechste gesehene.
//! 2. [`assess_rollback`] — widerspricht eine BEREITS AUTHENTIFIZIERTE
//!    Serveraussage der Kette? Ohne [`CheckpointClaim`] lautet die Antwort
//!    ausdruecklich [`RollbackAssessment::NotAssessable`] und nie
//!    „konsistent": ueber einen Rueckbau ist dann nichts gesagt.
//!
//! Die ABBILDUNG dieser Befunde in den Bericht gehoert nicht hierher, sondern
//! nach `ea-verify`: Fork und Bruch werden dort zu `quarantinedObjects` mit
//! Grund `conflicting`, eine bewiesen fehlende Sequenz zu `gaps`.

mod chain;
mod error;
mod node;
mod rollback;

pub use chain::{
    ChainBreak, ChainFork, ChainForkForm, ChainGap, ChainHead, MAX_CHAIN_NODES_V1, VerifiedChain,
    build_chain,
};
pub use error::ChainError;
pub use node::{ChainNode, ChainNodeKind};
pub use rollback::{CheckpointClaim, RollbackAssessment, RollbackFinding, assess_rollback};
