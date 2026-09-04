//! Die Kulisse der Original/Nachtrag-Projektion.
//!
//! # Ein EIGENES Verzeichnis neben `tests/verify_fixtures`
//!
//! `crates/ea-reader/tests/verify_fixtures/fixtures.rs` wird ueber die
//! `#[path]`-Kette von mehreren Zielen dieser Crate UND von
//! `crates/ea-reader-wasm` uebersetzt. Diese Kulisse baut dagegen einen
//! ELFENTRAEGIGEN Bestand mit echter HPKE-Kapselung je Eintrag; sie gehoert
//! genau EINEM Ziel, und in `verify_fixtures` gelegt bezahlte jedes andere Ziel
//! ihre Uebersetzung mit.
//!
//! Der Tresor, die Uhr, `classify` und `entry_hash_at` werden trotzdem NICHT
//! nachgebaut: dieses Modul bindet `verify_fixtures` per `#[path]` ein und
//! benutzt genau dieselbe Registrierungslinie, denselben Anker und denselben
//! Entsperrweg. Ein zweiter Anker daneben liesse jeden Bestand hier an Gate
//! `trust` fallen.
//!
//! `#[path]`-Includes werden je Testziel uebersetzt; ein Ziel, das nur einen
//! Teil der Helfer nutzt, erzeugt sonst `dead_code`-Warnungen, die unter
//! `-D warnings` brechen. Daher `allow(dead_code)` auf Modulebene.
#![allow(dead_code)]

/// Die Reader-Kulisse aus `verify_fixtures`, unveraendert weiterverwendet.
///
/// Sie bindet ihrerseits das Fixture-Modul von `ea-verify` ein und liefert
/// damit `verify_support::complete_valid_archive_with_plaintexts`, auf dem
/// diese Kulisse aufsetzt.
#[path = "../verify_fixtures/mod.rs"]
pub mod verify_fixtures;

pub mod fixtures;
