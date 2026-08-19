//! Die vollstaendig verschluesselte lokale Datenbank eines Writers.
//!
//! Diese Crate besitzt das Schema, die Migrationsregistratur und die
//! Migrationskette. Sie besitzt KEINE Fachlogik: weder ein Entwurf noch eine
//! Auditzeile noch ein Bedienerprofil wird hier ausgelegt.
//!
//! Drei Zusagen tragen sie:
//!
//! 1. **Kein Weg um den Schluessel herum.** [`EncryptedDatabase::open`] nimmt
//!    den synchronen Schluesselport und einen Griff; einen Konstruktor, der
//!    einen Pfad allein nimmt, gibt es nicht. Die Zusage ist damit strukturell
//!    und nicht prozedural.
//! 2. **Vollverschluesselung heisst jede Datei.** Hauptdatei, Write-Ahead-Log
//!    und Indizes liegen unter SQLCipher, und `PRAGMA temp_store = MEMORY`
//!    haelt jede temporaere Ablage im Speicher (`design.md`:1961, :1965).
//! 3. **Der wirksame Unterbau ist beobachtbar.** ADR 0002 haelt fest, dass
//!    `LIBSQLITE3_SYS_USE_PKG_CONFIG` das gebundelte SQLCipher lautlos durch
//!    eine Hostbibliothek ersetzen kann — eine solche Datenbank naehme
//!    `PRAGMA key` als unbekanntes Pragma an und speicherte Klartext.
//!    [`EncryptedDatabase::open`] bricht deshalb ab, wenn
//!    `PRAGMA cipher_version` leer bleibt.
//!
//! Alle Methoden sind synchron, wie der ganze Rust-Kern.
#![forbid(unsafe_code)]

mod database;
pub mod migrations;

pub use database::{
    EncryptedDatabase, StoreError, StoreRow, StoreTransaction, StoreValue, unix_millis_now,
};
pub use migrations::Migration;
