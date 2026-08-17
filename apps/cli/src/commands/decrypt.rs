//! Kommando `decrypt`.
//!
//! Prueft vollstaendig und schreibt danach Klartext in ein neues Ziel.
//!
//! # Was dieser Handler NICHT tut
//!
//! Er kennt weder die Reihenfolge der Schritte noch die Zielregeln noch die
//! Rechtevergabe noch die Entschluesselung. Alles davon steht in
//! `ea_recovery::decrypt` an genau einer Stelle und ist dort ohne Prozessstart
//! pruefbar. Hier stehen drei Zeilen: Anker laden, Schluessel laden,
//! entschluesseln — und die Ableitung des Exitcodes aus dem Ergebnis.
//!
//! # ES WIRD NICHTS AUSGEGEBEN
//!
//! Kein Bericht auf stdout, keine Erfolgsmeldung, keine Liste geschriebener
//! Dateien. Zwei Gruende: der Klartext und alles, was seine Herkunft benennt,
//! gehoert nach `design.md` §14 in keine beilaeufige Ausgabe — und jede
//! gedruckte Zeile waere ein Vertrag, den kein gemessener Fall verlangt. Das
//! ERGEBNIS dieses Kommandos sind die Dateien im Ziel; der Exitcode sagt, ob
//! man ihnen trauen darf. Wer den Bericht will, ruft `verify` oder `report`.
//!
//! # `--key` WIRD NICHT ZUM ANKER
//!
//! Der Schluessel oeffnet, der Anker entscheidet. Beide kommen von aussen und
//! beide getrennt: `ea_recovery::verify_directory` nimmt Abdruck und Material
//! ausdruecklich als eigene Angabe entgegen, damit ein falsch verdrahteter
//! Schluesselspeicher als ENTSCHLUESSELUNGSFEHLER sichtbar wird und nicht als
//! fehlender Grant.

use std::path::Path;

use ea_recovery::{
    ExitCode, decrypt_directory, exit_code_for, exit_code_for_error, load_recipient_key,
    load_trust_anchor,
};
use ea_types::UnixMillis;

use crate::{args::Invocation, output};

/// Fuehrt `decrypt` aus.
///
/// `now` kommt als PARAMETER aus `main`; es gibt genau eine Uhr im Werkzeug.
pub fn run(
    invocation: &Invocation,
    archive: &Path,
    key_source: &Path,
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
    let key = match load_recipient_key(key_source) {
        Ok(key) => key,
        Err(error) => {
            output::print_recovery_error(&error);
            return exit_code_for_error(&error);
        }
    };

    match decrypt_directory(archive, &anchor, now, &key, output_path) {
        // Ein BEFUND ueber den Bestand: derselbe Bericht, dieselbe Ableitung
        // wie bei `verify` und `list`. Geschrieben wurde dann nichts — das
        // stellt `ea_recovery::decrypt_directory` sicher, nicht dieser Handler.
        Ok(decryption) => exit_code_for(&decryption.report),
        // GAR KEIN Urteil, ein belegtes Ziel, ein fremder Schluessel: der Code
        // stammt aus `exit_code_for_error`, und stdout bleibt leer.
        Err(error) => {
            output::print_recovery_error(&error);
            exit_code_for_error(&error)
        }
    }
}
