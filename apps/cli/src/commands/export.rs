//! Kommando `export`.
//!
//! Prueft vollstaendig und kopiert den Bestand VERSCHLUESSELT.
//!
//! Rumpf. Der Pfad entsteht in einem eigenen Task; bis dahin sagt dieser Lauf
//! ausdruecklich, dass er nichts getan hat.

use ea_recovery::ExitCode;

use crate::args::Invocation;

/// Fuehrt `export` aus.
///
/// Noch nicht implementiert: liefert [`ExitCode::Unsupported`] und beruehrt
/// weder Bestand noch Ziel.
pub fn run(_invocation: &Invocation) -> ExitCode {
    ExitCode::Unsupported
}
