//! Kommando `verify`.
//!
//! Prueft den Bestand und berichtet.
//!
//! # Der Bericht erscheint AUCH bei einem Befund
//!
//! Ein Werkzeug, das bei einem Mangel schwiege, zwaenge den Betreiber, den
//! Exitcode zu raten. Der Bericht IST die Diagnose; der Exitcode ist nur ihre
//! Zusammenfassung fuer einen Prozessaufrufer und beschneidet sie nicht.
//! Geschwiegen wird ausschliesslich dort, wo gar kein Urteil zustande kam —
//! siehe `super::verified`.

use std::path::Path;

use ea_recovery::{ExitCode, exit_code_for, exit_code_for_error};
use ea_types::UnixMillis;

use crate::{
    args::{Format, Invocation},
    output,
};

/// Fuehrt `verify` aus.
pub fn run(invocation: &Invocation, archive: &Path, now: UnixMillis) -> ExitCode {
    let report = match super::verified(invocation, archive, now) {
        Ok(report) => report,
        Err(code) => return code,
    };

    let written = match invocation.format {
        Format::Text => output::print_report_text(&report),
        Format::Json => output::print_report_json(&report),
    };
    // Ein gescheitertes SCHREIBEN ueberstimmt den Befund: wer die Ausgabe nicht
    // bekommen hat, darf nicht erfahren, dass alles in Ordnung sei.
    if let Err(error) = written {
        output::print_recovery_error(&error);
        return exit_code_for_error(&error);
    }

    exit_code_for(&report)
}
