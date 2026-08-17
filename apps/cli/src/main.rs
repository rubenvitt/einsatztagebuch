//! Wiederherstellungswerkzeug des Einsatzarchivs.
//!
//! # Was dieses Paket traegt — und was ausdruecklich nicht
//!
//! AUSSCHLIESSLICH Argumentgrammatik, Ausgabeform und den Prozessabschluss.
//! Die gesamte Fachlogik wohnt in `ea-recovery`: dort stehen die
//! dateisystemgestuetzte `ArchiveSource`, die Verifikationsfassade, die
//! Exitcodeableitung, die Entschluesselung und der Export. Die Richtung ist
//! fest: `apps/cli` -> `ea-recovery` -> `ea-verify`.
//!
//! Der Grund ist pruefbarkeitshalber und nicht kosmetisch: Regeln, die in
//! einem Kommandopfad wohnen, lassen sich nur mit einem Prozessstart messen.
//! Regeln in `ea-recovery` lassen sich in `crates/ea-recovery/tests` direkt
//! messen — und sie stehen dort genau EINMAL, statt fuenfmal fast gleich.
//!
//! # Die Uhr
//!
//! `SystemTime::now()` gehoert in DIESE Datei und nirgendwo sonst im
//! Workspace. `ea-recovery` und `ea-verify` nehmen die Uhr als Parameter, weil
//! ein Verifikationsurteil an ihr haengt und eine Bibliothek, die sie sich
//! selbst holt, in keinem Test mehr steuerbar ist. Sie zieht hier ein, sobald
//! der erste Kommandopfad wirklich verifiziert; ein heute schon geholter
//! Zeitstempel haette keinen Abnehmer.

mod args;
mod commands;
mod output;

use std::{env, process::ExitCode as ProcessExitCode};

use ea_recovery::ExitCode;

use args::UsageError;

/// Der Zahlwert eines Exitcodes als Byte.
///
/// Die Tabelle reicht von 0 bis 21 und passt vollstaendig in ein Byte; die
/// Umwandlung kann nicht scheitern, und wenn sie es doch taete, waere die
/// Tabelle veraendert worden und muesste laut werden.
fn exit_byte(code: ExitCode) -> u8 {
    u8::try_from(code.as_i32()).expect("jeder Exitcode der Tabelle passt in ein Byte")
}

/// Parst, fuehrt aus, beendet.
///
/// Gibt [`ProcessExitCode`] zurueck, statt `std::process::exit` zu rufen.
/// Beobachtbar ist das dasselbe — derselbe Status verlaesst den Prozess —,
/// aber der Ruecksprung aus `main` leert stdout und laesst `Drop` laufen.
/// `std::process::exit` tut beides nicht, und eine Grammatikausgabe, die je
/// nach Pufferstand ankommt oder nicht, waere in keinem Test messbar.
fn main() -> ProcessExitCode {
    let invocation = match args::parse(env::args_os().skip(1)) {
        Ok(invocation) => invocation,
        // Der einzige Aufruffall mit einer NUTZAUSGABE: wer ohne Argument
        // ruft, fragt nach der Grammatik und bekommt sie auf stdout.
        Err(UsageError::NoArguments) => {
            output::print_grammar();
            return ProcessExitCode::from(exit_byte(ExitCode::Usage));
        }
        Err(error) => {
            output::print_usage_error(&error);
            return ProcessExitCode::from(exit_byte(ExitCode::Usage));
        }
    };

    ProcessExitCode::from(exit_byte(commands::run(&invocation)))
}
