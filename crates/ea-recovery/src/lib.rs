#![forbid(unsafe_code)]
//! Wiederherstellung des Einsatzarchivs: Dateisystem, Klartext, Exitcodes.
//!
//! Diese Crate ist die EINZIGE Stelle des Workspace, die einen Archivbestand
//! aus einem Verzeichnis liest, Klartext in Haenden haelt und Zieldateien mit
//! restriktiven Rechten anlegt. Sie darf `std::fs` tragen, weil sie kein
//! geteilter Browsercode ist: sie laeuft ausschliesslich als Bibliothek hinter
//! dem Wiederherstellungswerkzeug auf einem Betriebssystem.
//!
//! `ea-verify` darf das ausdruecklich NICHT. Nach
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §9
//! ist genau die Verifikationspipeline geteilter Rust-Code, der im Browser
//! laeuft; sie endet bei `ea-verify`, das deshalb auf der wasm32-Positivliste
//! von `tools/xtask/src/main.rs` steht und Zeit, Trust Anchor und Bestand nur
//! als Parameter entgegennimmt. Diese Crate steht dagegen als erster Eintrag
//! auf der begruendeten Ausnahmeliste desselben Gates.
//!
//! Die Richtung ist damit fest: `apps/cli` -> `ea-recovery` -> `ea-verify`.
//! Kein Kommandopfad ruft `verify_archive` direkt, damit verify-before-use,
//! Zielpruefung und Rechtevergabe an genau einer Stelle stehen und ohne
//! Prozessstart pruefbar bleiben.

mod error;
mod exit;
mod source;
mod verify;

pub use error::RecoveryError;
pub use exit::{ExitCode, exit_code_for, exit_code_for_error};
pub use source::FsArchiveSource;
pub use verify::{load_trust_anchor, verify_directory};
