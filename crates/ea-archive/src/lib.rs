#![forbid(unsafe_code)]
//! Ports und Inventar ueber die Bytes eines Archivbestands.
//!
//! Diese Crate traegt den breiten Port ueber ALLE Archivbytes, die
//! Layoutkonstanten aus design.md 11.4 und das Inventar, das am 9-Byte-
//! Exact-Object-Praefix klassifiziert, nie am Dateinamen. Das Inventar
//! bedient `ea_trust::TrustObjectSource` unmittelbar, sodass `ea-trust`
//! nichts ueber das Archivlayout erfaehrt.
