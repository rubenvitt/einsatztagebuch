//! Die fuenf Kommandopfade.
//!
//! # Was hier NICHT stehen darf
//!
//! Ein Aufruf von `ea_verify::verify_archive`. Verify-before-use, Zielpruefung
//! und Rechtevergabe stehen in `ea-recovery` an genau einer Stelle; ein
//! Handler, der sich seine `VerifyOptions` selbst zusammensetzte, koennte die
//! Empfaengerbindung vergessen, ohne dass ein Test das saehe.
//!
//! # Warum die Handler heute Ruempfe sind
//!
//! Dieser Task baut AUSSCHLIESSLICH die Aufrufgrammatik. Die Ruempfe liefern
//! [`ExitCode::Unsupported`] (21) und ausdruecklich nicht [`ExitCode::Usage`]
//! (2): der Code 2 gehoert der Grammatikpruefung, und ein Rumpf, der ihn schon
//! lieferte, machte deren Nachweis wertlos.

pub mod decrypt;
pub mod export;
pub mod list;
pub mod report;
pub mod verify;

use ea_recovery::ExitCode;

use crate::args::{Command, Invocation};

/// Fuehrt das geparste Kommando aus und liefert seinen Exitcode.
pub fn run(invocation: &Invocation) -> ExitCode {
    match invocation.command {
        Command::Verify { .. } => verify::run(invocation),
        Command::List { .. } => list::run(invocation),
        Command::Decrypt { .. } => decrypt::run(invocation),
        Command::Report { .. } => report::run(invocation),
        Command::Export { .. } => export::run(invocation),
    }
}
