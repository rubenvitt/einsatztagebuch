//! Kommando `list`.
//!
//! Prueft den Bestand und listet seine Objektergebnisse auf.
//!
//! Rumpf. Der Pfad entsteht in einem eigenen Task; bis dahin sagt dieser Lauf
//! ausdruecklich, dass er nichts getan hat.

use ea_recovery::ExitCode;

use crate::args::Invocation;

/// Fuehrt `list` aus.
///
/// Noch nicht implementiert: liefert [`ExitCode::Unsupported`] und beruehrt
/// weder Bestand noch Ziel.
pub fn run(_invocation: &Invocation) -> ExitCode {
    ExitCode::Unsupported
}
