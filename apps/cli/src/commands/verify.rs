//! Kommando `verify`.
//!
//! Prueft den Bestand und berichtet.
//!
//! Rumpf. Der Pfad entsteht in einem eigenen Task; bis dahin sagt dieser Lauf
//! ausdruecklich, dass er nichts getan hat.

use ea_recovery::ExitCode;

use crate::args::Invocation;

/// Fuehrt `verify` aus.
///
/// Noch nicht implementiert: liefert [`ExitCode::Unsupported`] und beruehrt
/// weder Bestand noch Ziel.
pub fn run(_invocation: &Invocation) -> ExitCode {
    ExitCode::Unsupported
}
