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
//! wird nicht angefasst.

mod chain;
mod error;
mod node;

pub use chain::{ChainBreak, ChainHead, MAX_CHAIN_NODES_V1, VerifiedChain, build_chain};
pub use error::ChainError;
pub use node::{ChainNode, ChainNodeKind};
