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
//! # Warum drei Handler noch Ruempfe sind
//!
//! `decrypt`, `report` und `export` entstehen in eigenen Tasks. Die Ruempfe
//! liefern [`ExitCode::Unsupported`] (21) und ausdruecklich nicht
//! [`ExitCode::Usage`] (2): der Code 2 gehoert der Grammatikpruefung, und ein
//! Rumpf, der ihn schon lieferte, machte deren Nachweis wertlos.

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
        Command::Decrypt { .. } => decrypt::run(invocation),
        Command::Report { .. } => report::run(invocation),
        Command::Export { .. } => export::run(invocation),
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
