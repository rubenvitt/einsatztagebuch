//! Die Kommandopfade und ihre jeweilige Host-Grenze.
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
//! # `decrypt`, `export`, `grant` UND `recovery-test` gehen NICHT durch [`verified`]
//!
//! Kein Sonderweg, sondern derselbe Weg eine Ebene tiefer: alle vier brauchen
//! den Bericht UND etwas aus demselben Lauf — `decrypt` und `export` die Bytes
//! des EINEN eingelesenen Bestands, `grant` die Verifikation mit dem Abdruck
//! seines Recovery-Schluessels und danach die uebrigen Eingaben,
//! `recovery-test` das freie Ziel und das Inventar HINTER dem Befund —, und
//! die Reihenfolge ihrer Schritte ist der Gegenstand des jeweiligen
//! Kommandos. Alles davon wohnt deshalb geschlossen in
//! `ea_recovery::decrypt_directory`, `ea_recovery::export_directory`,
//! `ea_recovery::grant_inputs` beziehungsweise
//! `ea_recovery::recovery_test_inputs`, die ihrerseits ausschliesslich durch
//! dieselbe Verifikationsfassade laufen. Auch hier ruft kein Kommandopfad
//! `verify_archive`.
//!
//! # `organization init` geht durch KEINE von beiden
//!
//! Und das ist kein Sonderweg, sondern die Folge seines Gegenstands: es prueft
//! keinen Bestand. Es gibt in diesem Lauf kein Archiv, ueber das ein Urteil zu
//! bilden waere — es gibt eine Zeremonie, die beginnt oder fortgesetzt wird.
//! Seine Fachlogik wohnt vollstaendig in `ea-admin`
//! (`ea_admin::BootstrapCoordinator`), genau wie die der fuenf anderen in
//! `ea-recovery`; `organization.rs` parst nicht, rechnet nicht und entscheidet
//! keinen Schritt, sondern ruft, druckt und ordnet einen Exitcode zu.

pub mod clock_release;
pub mod decrypt;
pub mod export;
pub mod grant;
pub mod list;
pub mod operator;
pub mod organization;
pub mod posture;
pub mod reader_key_escrow;
pub mod recovery_test;
pub mod registry;
pub mod report;
pub mod verify;
pub mod web_bundle;
pub mod writer_transition;

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
/// Operator-Dialoge pruefen zusaetzlich die frische Uhr und verstrichene Zeit
/// im Runtime-Kontext, bevor sie Erfolg auditieren oder ausgeben.
pub fn run(invocation: &Invocation, now: UnixMillis) -> ExitCode {
    match &invocation.command {
        Command::Verify { archive } => verify::run(invocation, archive, now),
        Command::List { archive } => list::run(invocation, archive, now),
        Command::Decrypt {
            archive,
            key,
            output,
        } => decrypt::run(invocation, archive, key, output, now),
        Command::Grant {
            archive,
            recovery_key,
            authority_key,
            authorization,
            recipient_certificate,
            operator_config,
            output,
        } => grant::run(
            invocation,
            archive,
            recovery_key,
            authority_key,
            authorization,
            recipient_certificate,
            operator_config.as_deref(),
            output.as_deref(),
            now,
        ),
        Command::Report { archive, output } => report::run(invocation, archive, output, now),
        Command::Export { source, output } => export::run(invocation, source, output, now),
        Command::RecoveryTest {
            runtime,
            archive,
            key_inventory,
            output,
        } => recovery_test::run(
            invocation,
            archive,
            key_inventory,
            output,
            runtime.as_ref(),
            now,
        ),
        // OHNE `now`: dieser Pfad verifiziert nichts und datiert nichts. Die
        // Begruendung steht an `organization::run`.
        Command::OrganizationInit => organization::run(invocation),
        Command::OrganizationCertifyRoot {
            initial_registry_version,
        } => organization::run_certify_root(invocation, *initial_registry_version),
        Command::OrganizationReaderKeyEscrowPublish { config, inbox } => {
            reader_key_escrow::run_publish(invocation, config, inbox, now)
        }
        // Die Root-Zeremonie der Bundle-Familie (U4); Fachlogik in
        // `ea_admin::web_bundle_release`.
        Command::OrganizationWebBundleRelease {
            config,
            bundle,
            bundle_version,
            effective_from,
        } => web_bundle::run_release(
            invocation,
            config,
            bundle,
            bundle_version,
            *effective_from,
            now,
        ),
        Command::OrganizationWebBundleRevoke {
            config,
            release,
            effective_from,
        } => web_bundle::run_revoke(invocation, config, release, *effective_from, now),
        // Zeremonie B: Fachlogik in `ea_admin::reader_key_escrow_opening`, der
        // Bestand eine Ebene tiefer in `OperatorRuntime::open` geprüft.
        Command::ReaderKeyEscrowOpen {
            config,
            recovery_key,
            authorization,
            inbox,
            outbox,
        } => reader_key_escrow::run_open(
            invocation,
            config,
            recovery_key,
            authorization,
            inbox,
            outbox,
            now,
        ),
        Command::ReaderKeyEscrowPickup {
            config,
            authorization,
            inbox,
            outbox,
        } => reader_key_escrow::run_pickup(invocation, config, authorization, inbox, outbox, now),
        Command::Posture { action, config } => posture::run(invocation, action, config, now),
        Command::Operator {
            action,
            config,
            archive_profile,
        } => operator::run(invocation, *action, config, archive_profile.as_deref(), now),
        // Beide neuen Pfade gehen weder durch [`verified`] noch durch die
        // Wiederherstellungsfassade, und aus demselben Grund wie
        // `organization init`: sie bilden ueber KEINEN Bestand ein Urteil. Ihre
        // Fachlogik wohnt vollstaendig in `ea-admin` — die Zielart, das
        // Registrierungsereignis und die Reichweite eines Widerrufs in
        // `ea_admin::revocation`, der Dreischritt der Uhrfreigabe in
        // `ea_admin::clock_release`. Der Bestand selbst wird dabei sehr wohl
        // geprueft, aber eine Ebene tiefer: `OperatorRuntime::open` verifiziert
        // ihn geschlossen, bevor es einen Kopf herausgibt.
        Command::RegistryRevocationPlan {
            config,
            effective_from_sequence,
            valid_through_sequence,
            not_after,
        } => registry::run(
            invocation,
            config,
            *effective_from_sequence,
            *valid_through_sequence,
            *not_after,
            now,
        ),
        Command::ClockReleaseApply { config, release } => {
            clock_release::run(invocation, config, release, now)
        }
        // Dieselbe Bauart wie die beiden Pfade darueber: kein Urteil ueber
        // einen Bestand, die Fachlogik in `ea_admin::writer_transition`, der
        // Bestand eine Ebene tiefer in `OperatorRuntime::open` geprueft.
        Command::WriterTransitionPrepare { config, request } => {
            writer_transition::prepare(invocation, config, request, now)
        }
        Command::WriterTransitionActivate {
            config,
            request,
            transition_object,
            valid_through_sequence,
            not_after,
        } => writer_transition::activate(
            invocation,
            config,
            request,
            transition_object,
            *valid_through_sequence,
            *not_after,
            now,
        ),
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
