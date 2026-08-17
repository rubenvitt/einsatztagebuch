//! Die fuenf Kommandopfade.
//!
//! # Was hier NICHT stehen darf
//!
//! Ein Aufruf von `ea_verify::verify_archive`. Verify-before-use, Zielpruefung
//! und Rechtevergabe stehen in `ea-recovery` an genau einer Stelle; ein
//! Handler, der sich seine `VerifyOptions` selbst zusammensetzte, koennte die
//! Empfaengerbindung vergessen, ohne dass ein Test das saehe. Jeder Pfad geht
//! deshalb durch [`verified`], und [`verified`] ruft ausschliesslich
//! [`ea_recovery::verify_directory`].
//!
//! # `decrypt` UND `export` gehen NICHT durch [`verified`]
//!
//! Kein Sonderweg, sondern derselbe Weg eine Ebene tiefer: beide brauchen den
//! Bericht UND die Bytes aus EINEM eingelesenen Bestand, und die Reihenfolge
//! ihrer Schritte ist der Gegenstand des jeweiligen Kommandos. Beides wohnt
//! deshalb geschlossen in `ea_recovery::decrypt_directory` beziehungsweise
//! `ea_recovery::export_directory`, die ihrerseits ausschliesslich durch
//! dieselbe Verifikationsfassade laufen. Auch hier ruft kein Kommandopfad
//! `verify_archive`.

pub mod decrypt;
pub mod export;
pub mod list;
pub mod report;
pub mod verify;

use std::path::Path;

use ea_recovery::{ExitCode, exit_code_for_error, load_trust_anchor, verify_directory};
use ea_types::UnixMillis;
use ea_verify::VerificationReportV1;

use crate::{
    args::{Command, Invocation},
    output,
};

/// Fuehrt das geparste Kommando aus und liefert seinen Exitcode.
///
/// `now` kommt als PARAMETER aus `main` und wird hier nirgends geholt. Die
/// Begruendung steht dort: es gibt genau eine Uhr im ganzen Werkzeug.
pub fn run(invocation: &Invocation, now: UnixMillis) -> ExitCode {
    match &invocation.command {
        Command::Verify { archive } => verify::run(invocation, archive, now),
        Command::List { archive } => list::run(invocation, archive, now),
        Command::Decrypt {
            archive,
            key,
            output,
        } => decrypt::run(invocation, archive, key, output, now),
        Command::Report { archive, output } => report::run(invocation, archive, output, now),
        Command::Export { source, output } => export::run(invocation, source, output, now),
    }
}

/// Laedt den Anker und verifiziert den Bestand VOLLSTAENDIG.
///
/// # Zwei Fehlerarten, EIN Rueckgabeweg
///
/// Scheitert schon das Laden des Ankers oder das Bilden eines Berichts, ist
/// ueber den Bestand GAR KEIN Urteil zustande gekommen. Dann gibt es auch
/// nichts auszugeben: die Meldung geht nach stderr, stdout bleibt LEER, und der
/// Code stammt aus [`exit_code_for_error`] statt aus `exit_code_for`. Ein
/// halber Bericht waere schlimmer als keiner — ein Skript, das ihn weiterreicht,
/// koennte ihn nicht von einem vollstaendigen unterscheiden.
///
/// # Kein Empfaengerschluessel
///
/// `verify` und `list` uebergeben ausdruecklich `None`. Ohne Schluessel wird
/// nichts entkapselt, was KEIN Mangel ist; `--key` gehoert nach
/// `crate::args` allein zu `decrypt`. Daraus folgt unmittelbar, dass
/// [`ExitCode::Key`] aus diesen beiden Pfaden nicht entstehen kann — gemessen
/// in `apps/cli/tests/exit_codes.rs`.
///
/// # Errors
///
/// Der bereits abgeleitete [`ExitCode`], damit der Aufrufer ihn nur noch
/// durchreicht.
fn verified(
    invocation: &Invocation,
    archive: &Path,
    now: UnixMillis,
) -> Result<VerificationReportV1, ExitCode> {
    let anchor = load_trust_anchor(&invocation.anchor).map_err(|error| {
        output::print_recovery_error(&error);
        exit_code_for_error(&error)
    })?;
    verify_directory(archive, &anchor, now, None).map_err(|error| {
        output::print_recovery_error(&error);
        exit_code_for_error(&error)
    })
}
