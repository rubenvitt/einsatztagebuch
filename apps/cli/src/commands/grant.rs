//! Kommando `grant`.
//!
//! Prueft vollstaendig, loest jede Eingabe eines historischen Re-Grants auf —
//! und endet dann an der benannten Grenze.
//!
//! # WAS DIESER HANDLER TUT
//!
//! Anker laden, die Fassade `ea_recovery::grant_inputs` rufen, den Exitcode
//! ableiten. Die Reihenfolge der Schritte — Recovery-Schluessel, Verifikation
//! mit seinem Abdruck, Befund vor allem Weiteren, Autoritaetsschluessel,
//! Dateien — wohnt in der Fassade und ist dort ohne Prozessstart messbar
//! (`crates/ea-recovery/tests/grant_inputs.rs`). Hier steht nur, was aus
//! ihrem Ergebnis wird.
//!
//! # WARUM DER ERFOLGSPFAD MIT 21 ENDET, UND NICHT MIT 0 ODER 15
//!
//! Nichts im Baum erzeugt oder prueft einen historischen Grant
//! (`crates/ea-verify/src/recipient.rs:236-238` weist
//! `GrantKindV1::Historical` als `AuthorizationUnverifiable` ab); der
//! `HistoricalGrantService` ist Stage-5 Task 8. Ein Lauf, der jede Eingabe
//! aufgeloest hat und dann mit 0 endete, meldete einem Skript einen Grant,
//! den es nicht gibt. 15 („vollstaendig geprueft, aber fachlich
//! unvollstaendig") waere ebenso eine Luege: es ist nichts unvollstaendig
//! GEPRUEFT, es ist ein Dienst nicht VORHANDEN — und genau das sagt 21,
//! „nicht unterstuetzte Providerfaehigkeit". Das ist dasselbe Muster wie
//! `--report-signing-key` in `super::report` und die PKCS#11-Grenze in
//! `ea_recovery::pkcs11`, beide in `docs/adr/0001` unter „Blocked":
//! angenommen, verweigert, benannt. Der Code ist
//! [`crate::output::GRANT_SERVICE_UNAVAILABLE_CODE`], damit ein Skript ihn
//! von jeder anderen 21 unterscheidet.
//!
//! Die Verweigerung steht HINTER der Verifikation und den Eingaben, nicht
//! davor wie bei `--report-signing-key`. Der Unterschied ist der Gegenstand
//! dieser Scheibe: Task 7 liefert verify-before-use, die Aufloesung der
//! Schluesselquellen und die Lesbarkeit der Dateien als messbares Verhalten,
//! und ein Aufrufer soll seine Eingaben JETZT gegen die Grammatik und den
//! Bestand halten koennen — mit denselben Codes, die der Dienst spaeter
//! traegt. Ein Befund (10, 11, 12, 13, 14) und ein Fehler an einer Eingabe
//! (2, 20, 21 der PKCS#11-Grenze) gewinnen deshalb gegen die Verweigerung.
//!
//! # ES WIRD NICHTS AUSGEGEBEN
//!
//! Kein Bericht auf stdout, keine Quittung, kein Teilerfolg: das Ergebnis
//! dieses Kommandos WIRD ein Grant-Objekt sein, und bis dahin gibt es nichts,
//! was eine Zeile versprechen duerfte. Dieselbe Wahl wie bei `decrypt` und
//! `export`, aus demselben Grund. `--format` parst deshalb, entscheidet hier
//! aber nichts — auch `--format json` verlangt kein Dokument, das dieses
//! Kommando schuldig bliebe; die Begruendung steht in `crate::output` neben
//! der JSON-Verweigerung von `organization init`.

use std::path::Path;

use ea_recovery::{ExitCode, exit_code_for, exit_code_for_error, grant_inputs, load_trust_anchor};
use ea_types::UnixMillis;

use crate::{
    args::{Invocation, KeySourceArgument},
    output,
};

/// Fuehrt `grant` aus.
///
/// `now` kommt als PARAMETER aus `main`; es gibt genau eine Uhr im Werkzeug.
pub fn run(
    invocation: &Invocation,
    archive: &Path,
    recovery_key: &KeySourceArgument,
    authority_key: &KeySourceArgument,
    authorization: &Path,
    recipient_certificate: &Path,
    now: UnixMillis,
) -> ExitCode {
    let anchor = match load_trust_anchor(&invocation.anchor) {
        Ok(anchor) => anchor,
        Err(error) => {
            output::print_recovery_error(&error);
            return exit_code_for_error(&error);
        }
    };

    let inputs = match grant_inputs(
        archive,
        &anchor,
        now,
        recovery_key.spec(),
        authority_key.spec(),
        authorization,
        recipient_certificate,
    ) {
        Ok(inputs) => inputs,
        // GAR KEIN Urteil, eine unbrauchbare Schluesselquelle, eine fehlende
        // Datei, die PKCS#11-Grenze: der Code stammt aus
        // `exit_code_for_error`, und stdout bleibt leer.
        Err(error) => {
            output::print_recovery_error(&error);
            return exit_code_for_error(&error);
        }
    };

    match exit_code_for(&inputs.report) {
        // Jede Eingabe ist aufgeloest — und hier endet die Stufe. Die
        // aufgeloesten Schluessel und Bytes werden ausdruecklich NICHT
        // angefasst: es gibt keinen Dienst, dem sie zu uebergeben waeren.
        ExitCode::Success => {
            output::print_grant_service_refusal();
            ExitCode::Unsupported
        }
        // Ein BEFUND ueber den Bestand: derselbe Bericht, dieselbe Ableitung
        // wie bei `verify` und `list`. Wer den Bericht will, ruft `verify`.
        finding => finding,
    }
}
