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

mod decrypt;
mod error;
mod exit;
mod report;
mod source;
mod target;
mod verify;

pub use decrypt::{
    DecryptionV1, RECIPIENT_KEY_SIZE_V1, decrypt_directory, load_recipient_key,
    recipient_key_thumbprint,
};
pub use error::RecoveryError;
pub use exit::{ExitCode, exit_code_for, exit_code_for_error};
#[cfg(unix)]
pub use report::OUTPUT_FILE_MODE_V1;
pub use report::{RuntimeMetadataV1, emit_report_document, write_report_document};
pub use source::FsArchiveSource;
#[cfg(unix)]
pub use target::OUTPUT_DIRECTORY_MODE_V1;
pub use target::{output_directory_is_free, prepare_output_directory};
pub use verify::{load_trust_anchor, verify_directory};
