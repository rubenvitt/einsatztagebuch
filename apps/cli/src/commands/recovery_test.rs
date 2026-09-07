//! Kommando `recovery-test`.
//!
//! Prueft vollstaendig, sichert das Ziel, liest das Inventar — und endet dann
//! an der benannten Grenze.
//!
//! # WAS DIESER HANDLER TUT
//!
//! Anker laden, die Fassade `ea_recovery::recovery_test_inputs` rufen, den
//! Exitcode ableiten. Die Reihenfolge — Verifikation ohne Schluessel, Befund
//! vor allem Weiteren, freies Ziel VOR dem Inventar — wohnt in der Fassade
//! und ist dort ohne Prozessstart messbar
//! (`crates/ea-recovery/tests/grant_inputs.rs`).
//!
//! # WARUM DER ERFOLGSPFAD MIT 21 ENDET, UND NICHT MIT 0 ODER 15
//!
//! Der `RecoveryTestService` und die Rust-Bindung von `ea.key-inventory/v1`
//! sind Stage-5 Task 9. Ein Lauf, der mit 0 endete, meldete einen bestandenen
//! Wiederherstellungstest, den niemand gefahren hat; einer, der mit 15
//! endete, behauptete eine vollstaendige Pruefung mit fachlichem Rest, wo gar
//! keine stattfand. 21 sagt, was ist: der Dienst ist nicht vorhanden. Das ist
//! dasselbe Muster wie `--report-signing-key` in `super::report` (ADR 0001,
//! „Blocked": angenommen, verweigert, benannt) und dieselbe Stellung wie in
//! `super::grant`: HINTER Verifikation und Eingaben, damit Befunde und
//! Eingabefehler ihre eigenen Codes tragen. Der Code ist
//! [`crate::output::RECOVERY_TEST_SERVICE_UNAVAILABLE_CODE`].
//!
//! # ES ENTSTEHT KEINE ZIELDATEI
//!
//! Die Fassade fragt nur, ob das Ziel frei ist; angelegt wird es erst vom
//! Dienst mit `create_new(true)`. Ein Ziel, das entstuende und leer bliebe,
//! gaelte beim naechsten Versuch als belegt — und truege den Namen eines
//! Berichts, den es nicht gibt. Gemessen in
//! `apps/cli/tests/full_grammar.rs`.
//!
//! # ES WIRD NICHTS AUSGEGEBEN
//!
//! Wie bei `grant`, `decrypt` und `export`: das Ergebnis dieses Kommandos
//! WIRD die Berichtsdatei sein, und `--format` entscheidet — wie bei
//! `report` — nicht ueber deren Form. Es parst und tut hier nichts; siehe
//! `crate::output` neben der JSON-Verweigerung von `organization init`.

use std::path::Path;

use ea_recovery::{
    ExitCode, exit_code_for, exit_code_for_error, load_trust_anchor, recovery_test_inputs,
};
use ea_types::UnixMillis;

use crate::{args::Invocation, output};

/// Fuehrt `recovery-test` aus.
///
/// `now` kommt als PARAMETER aus `main`; es gibt genau eine Uhr im Werkzeug.
pub fn run(
    invocation: &Invocation,
    archive: &Path,
    key_inventory: &Path,
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

    let inputs = match recovery_test_inputs(archive, &anchor, now, key_inventory, output_path) {
        Ok(inputs) => inputs,
        // GAR KEIN Urteil, ein belegtes Ziel, ein fehlendes Inventar: der
        // Code stammt aus `exit_code_for_error`, und stdout bleibt leer.
        Err(error) => {
            output::print_recovery_error(&error);
            return exit_code_for_error(&error);
        }
    };

    match exit_code_for(&inputs.report) {
        // Verifiziert, Ziel frei, Inventar gelesen — und hier endet die
        // Stufe. Die Inventarbytes werden nicht angefasst: es gibt keinen
        // Dienst, dem sie zu uebergeben waeren, und keine Bindung, die sie
        // parsen koennte.
        ExitCode::Success => {
            output::print_recovery_test_service_refusal();
            ExitCode::Unsupported
        }
        // Ein BEFUND ueber den Bestand: dieselbe Ableitung wie bei `verify`.
        finding => finding,
    }
}
