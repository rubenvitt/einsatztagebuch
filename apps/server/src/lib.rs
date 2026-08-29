//! Der Sync-Server der Stufe 3.
//!
//! Hier — und nur hier — lebt die Tokio-Laufzeit. Die Kernbibliotheken unter
//! `crates/` bleiben synchron, `crates/ea-sync-server` beschreibt die Ports,
//! und dieses Paket setzt sie gegen PostgreSQL, den S3-kompatiblen Object Store
//! und den Serverschluessel um.
//!
//! Die Module liegen in der BIBLIOTHEK und nicht im Binaerteil, weil die
//! Integrationstestziele unter `tests/` gegen ein Bibliotheksziel binden; ein
//! `bin`-Ziel koennen sie nicht erreichen. `src/main.rs` ist deshalb nur noch
//! der duenne Einstieg, der diese Bibliothek startet.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod config;
pub mod http;
pub mod router;
