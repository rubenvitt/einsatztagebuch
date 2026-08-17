//! Kommando `report`.
//!
//! Prueft den Bestand und schreibt den Bericht kanonisch in eine DATEI.
//!
//! # `--format` AENDERT DIESE DATEI NICHT
//!
//! Die Zieldatei traegt immer das kanonische Dokument `ea.verification-report/v1`
//! — mit `--format text` genauso wie mit `--format json`. Der Schalter waehlt
//! die Form der Bildschirmausgabe von `verify` und `list`; der BERICHT ist die
//! Lieferung dieses Kommandos, und eine Datei, die je nach Schalter zwei
//! verschiedene Formen unter einem Namen truege, waere weder schemagueltig
//! noch byteweise vergleichbar. Deshalb steht hier kein `match` ueber
//! [`crate::args::Format`].
//!
//! # Der Bericht entsteht AUCH bei einem Befund
//!
//! Wie bei `verify`: der Bericht IST die Diagnose, der Exitcode nur ihre
//! Zusammenfassung. Geschwiegen wird ausschliesslich dort, wo gar kein Urteil
//! zustande kam.
//!
//! # Was dieser Handler NICHT tut
//!
//! Er kennt weder die Dokumentform noch die Zielregeln noch die Rechtevergabe.
//! Beides steht in `ea_recovery::report` an genau einer Stelle und ist dort
//! ohne Prozessstart pruefbar. Hier stehen nur die drei Schritte in ihrer
//! Reihenfolge und die Aufnahme der Laufzeitwerte, die es nur im Prozess gibt.

use std::{env, path::Path, time::Instant};

use ea_recovery::{
    ExitCode, RuntimeMetadataV1, emit_report_document, exit_code_for, exit_code_for_error,
    write_report_document,
};
use ea_types::UnixMillis;

use crate::{args::Invocation, output};

/// Der Rechnername, wenn die Umgebung keinen nennt.
///
/// Ein fester Platzhalter und ausdruecklich nichts Erfundenes: die
/// Standardbibliothek kennt keinen Rechnernamen, und ihn ueber einen
/// Unterprozess oder eine neue Kiste zu beschaffen waere fuer ein
/// Beiwerkfeld der falsche Preis. Was hier steht, ist entweder das, was die
/// Umgebung sagt, oder ehrlich „unbekannt".
const UNKNOWN_HOST_V1: &str = "unknown";

/// Fuehrt `report` aus.
///
/// `now` ist DIESELBE Zahl, gegen die verifiziert wurde. Ein zweiter
/// Zeitstempel fuer `generatedAt` waere eine zweite Uhr im selben Lauf — siehe
/// die Modulnotiz von `apps/cli/src/main.rs`.
pub fn run(
    invocation: &Invocation,
    archive: &Path,
    output_path: &Path,
    now: UnixMillis,
) -> ExitCode {
    // VOR der Verifikation, denn sie ist der Lauf, dessen Dauer gemessen wird.
    // `Instant` ist eine monotone Dauer und keine zweite Uhr: er nennt keinen
    // Zeitpunkt und kann keinen Bericht datieren.
    let started = Instant::now();

    let report = match super::verified(invocation, archive, now) {
        Ok(report) => report,
        Err(code) => return code,
    };

    let runtime = invocation
        .include_runtime_metadata
        .then(|| RuntimeMetadataV1 {
            generated_at: now.get(),
            host_name: host_name(),
            // `to_string_lossy`: ein Pfad ist auf darwin und Linux eine
            // Bytefolge, das Schema fuehrt `inputPath` als Zeichenkette. Der
            // Bestand wird davon nicht beruehrt — dies ist eine ANGABE ueber
            // den Aufruf und nichts, woraus gelesen wird.
            input_path: archive.to_string_lossy().into_owned(),
            runtime_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        });

    let document = match emit_report_document(&report, runtime.as_ref()) {
        Ok(document) => document,
        Err(error) => {
            output::print_recovery_error(&error);
            return exit_code_for_error(&error);
        }
    };

    // Ein gescheitertes SCHREIBEN ueberstimmt den Befund: wer den Bericht nicht
    // bekommen hat, darf nicht erfahren, dass alles in Ordnung sei.
    if let Err(error) = write_report_document(&document, output_path) {
        output::print_recovery_error(&error);
        return exit_code_for_error(&error);
    }

    exit_code_for(&report)
}

/// Der Rechnername aus der Umgebung, oder [`UNKNOWN_HOST_V1`].
///
/// Zwei Namen, weil zwei Plattformfamilien sie verschieden nennen. Gelesen wird
/// die Umgebung des Aufrufers — dieselbe Quelle wie die Eingabezeile und
/// ausdruecklich nicht der Bestand.
fn host_name() -> String {
    for key in ["HOSTNAME", "COMPUTERNAME"] {
        if let Some(value) = env::var_os(key) {
            let value = value.to_string_lossy().into_owned();
            if !value.is_empty() {
                return value;
            }
        }
    }
    UNKNOWN_HOST_V1.to_owned()
}
