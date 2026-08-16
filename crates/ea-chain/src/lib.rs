#![forbid(unsafe_code)]
//! Rein wertbasierte Kettenlogik des Einsatzarchivs.
//!
//! Diese Crate kennt weder CBOR noch Signaturen noch geparste Archivobjekte,
//! sondern ausschliesslich Kettenknoten als Werte. Dadurch ist die gesamte
//! Verkettungspruefung ohne Fixtures testbar, analog zu `ea-time`. Einzige
//! Abhaengigkeit ist `ea-types`.
