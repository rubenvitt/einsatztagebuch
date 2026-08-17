//! Kommando `list`.
//!
//! Prueft den Bestand und listet seine Objektergebnisse auf.
//!
//! # DERSELBE LAUF WIE `verify`, nur eine andere Ansicht
//!
//! Die Auflistung entsteht AUS dem Verifikationsbericht und nicht aus einem
//! eigenen, leichteren Durchlauf. Eine Liste, die ohne vollstaendige Pruefung
//! entstuende, nennte Objekte, ueber die nichts feststeht — und genau das ist
//! die Verwechslung, die verify-before-use ausschliesst. `list --format json`
//! schreibt deshalb byteweise dasselbe Dokument wie `verify --format json`.

use std::path::Path;

use ea_recovery::{ExitCode, exit_code_for, exit_code_for_error};
use ea_types::UnixMillis;

use crate::{
    args::{Format, Invocation},
    output,
};

/// Fuehrt `list` aus.
pub fn run(invocation: &Invocation, archive: &Path, now: UnixMillis) -> ExitCode {
    let report = match super::verified(invocation, archive, now) {
        Ok(report) => report,
        Err(code) => return code,
    };

    let written = match invocation.format {
        Format::Text => output::print_listing_text(&report),
        Format::Json => output::print_report_json(&report),
    };
    if let Err(error) = written {
        output::print_recovery_error(&error);
        return exit_code_for_error(&error);
    }

    exit_code_for(&report)
}
