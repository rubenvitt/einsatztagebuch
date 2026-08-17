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
//! `SystemTime::now()` steht in DIESER Datei und nirgendwo sonst im Workspace.
//! `ea-recovery` und `ea-verify` nehmen die Uhr als Parameter, weil ein
//! Verifikationsurteil an ihr haengt und eine Bibliothek, die sie sich selbst
//! holt, in keinem Test mehr steuerbar ist. Mit `verify` und `list` gibt es den
//! ersten Kommandopfad, der wirklich verifiziert; [`os_clock`] holt den
//! Zeitstempel genau EINMAL je Prozess und reicht ihn hinunter. Zweimal zu
//! lesen waere schon ein Fehler: zwei Kommandos desselben Laufs koennten dann
//! ueber verschiedene Registrierungsstaende urteilen.

mod args;
mod commands;
mod output;

use std::{
    env,
    process::ExitCode as ProcessExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use ea_recovery::ExitCode;
use ea_types::UnixMillis;

use args::UsageError;

/// Der Zahlwert eines Exitcodes als Byte.
///
/// Die Tabelle reicht von 0 bis 21 und passt vollstaendig in ein Byte; die
/// Umwandlung kann nicht scheitern, und wenn sie es doch taete, waere die
/// Tabelle veraendert worden und muesste laut werden.
fn exit_byte(code: ExitCode) -> u8 {
    u8::try_from(code.as_i32()).expect("jeder Exitcode der Tabelle passt in ein Byte")
}

/// Die Betriebssystemuhr als [`UnixMillis`], oder nichts.
///
/// # Warum das ein `Option` ist und kein `expect`
///
/// Eine Uhr vor der Unix-Epoche oder jenseits von `i64`-Millisekunden ist keine
/// Lage, die dieses Bauwerk kennt — und ein Panic waere die falsche Antwort
/// darauf: er verliesse den Prozess mit einem Status, der in der normativen
/// Tabelle gar nicht vorkommt. Der Aufrufer macht daraus
/// [`ExitCode::Unsupported`] (21), also „diese Plattformfaehigkeit trage ich
/// nicht". Auf keinen Fall darf hier ersatzweise irgendein Zeitpunkt entstehen:
/// jedes Verifikationsurteil haengt an dieser Zahl.
fn os_clock() -> Option<UnixMillis> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok().map(UnixMillis::new)
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

    let Some(now) = os_clock() else {
        eprintln!("einsatzarchiv: the system clock is not readable as unix milliseconds");
        return ProcessExitCode::from(exit_byte(ExitCode::Unsupported));
    };

    ProcessExitCode::from(exit_byte(commands::run(&invocation, now)))
}
