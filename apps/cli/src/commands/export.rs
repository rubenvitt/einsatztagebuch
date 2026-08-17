//! Kommando `export`.
//!
//! Prueft vollstaendig und kopiert den Bestand VERSCHLUESSELT.
//!
//! # Was dieser Handler NICHT tut
//!
//! Er kennt weder die Reihenfolge der Schritte noch die Quellartpruefung noch
//! die Zielregeln noch die Rechtevergabe noch das Kopieren. Alles davon steht
//! in `ea_recovery::export` an genau einer Stelle und ist dort ohne
//! Prozessstart pruefbar. Hier stehen zwei Zeilen: Anker laden, exportieren —
//! und die Ableitung des Exitcodes aus dem Ergebnis.
//!
//! # ES WIRD NICHTS AUSGEGEBEN
//!
//! Kein Bericht auf stdout, keine Erfolgsmeldung, keine Liste kopierter
//! Dateien — dieselbe Wahl wie bei `decrypt` und aus demselben Grund: das
//! ERGEBNIS dieses Kommandos sind die Dateien im Ziel, und der Exitcode sagt,
//! ob man ihnen trauen darf. `--format` parst deshalb, entscheidet hier aber
//! nichts; wer den Bericht will, ruft `verify` oder `report`. Eine gedruckte
//! Zeile waere ein Vertrag, den kein gemessener Fall verlangt.
//!
//! # DIE ABGELEHNTE SERVERQUELLE BEKOMMT IHRE EIGENE MELDUNG
//!
//! Die Grammatik nennt `<archive-or-server>`, Stage 1 hat keine Serverquelle.
//! Ein Argument, das kein existierendes Verzeichnis ist, endet mit Exitcode 21
//! — und mit einem Satz, der das SAGT. Der blosse Fehlercode
//! `EA-RECOVERY-UNSUPPORTED-SOURCE` liesse einen Betreiber raten, ob er sich
//! vertippt hat; er soll erfahren, dass diese Stufe ausschliesslich einen
//! Dateisystembestand exportiert. Dieselbe Ueberlegung wie bei der
//! Verweigerung der Berichtssignatur in `super::report`.

use std::path::Path;

use ea_recovery::{
    ExitCode, RecoveryError, exit_code_for, exit_code_for_error, export_directory,
    load_trust_anchor,
};
use ea_types::UnixMillis;

use crate::{args::Invocation, output};

/// Fuehrt `export` aus.
///
/// `now` kommt als PARAMETER aus `main`; es gibt genau eine Uhr im Werkzeug.
pub fn run(
    invocation: &Invocation,
    source: &Path,
    output_path: &Path,
    now: UnixMillis,
) -> ExitCode {
    let anchor = match load_trust_anchor(&invocation.anchor) {
        Ok(anchor) => anchor,
        Err(error) => {
            output::print_recovery_error(&error);
            return exit_code_for_error(&error);
        }
    };

    match export_directory(source, &anchor, now, output_path) {
        // Ein BEFUND ueber den Bestand: derselbe Bericht, dieselbe Ableitung
        // wie bei `verify` und `list`. Kopiert wurde dann nichts — das stellt
        // `ea_recovery::export_directory` sicher, nicht dieser Handler.
        Ok(export) => exit_code_for(&export.report),
        // GAR KEIN Urteil, eine nicht unterstuetzte Quelle, ein belegtes Ziel:
        // der Code stammt aus `exit_code_for_error`, und stdout bleibt leer.
        Err(error) => {
            match error {
                RecoveryError::UnsupportedSource => output::print_export_source_refusal(),
                _ => output::print_recovery_error(&error),
            }
            exit_code_for_error(&error)
        }
    }
}
