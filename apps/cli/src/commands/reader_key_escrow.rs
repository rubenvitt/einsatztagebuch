//! Zeremonie B des Reader-Key-Escrows: `reader-key-escrow open|pickup`.
//!
//! Die gesamte Fachlogik wohnt in `ea_admin::reader_key_escrow_opening`; hier
//! wird geladen, aufgerufen, gedruckt und ein Exitcode zugeordnet. Der Bericht
//! trägt ausschließlich Hashes: kein PIN, kein Pfad, kein Schlüssellabel, keine
//! Subject-ID, kein Klartext. Eine JSON-Form gibt es nicht.
use crate::{
    args::{Format, Invocation, KeySourceArgument},
    output,
};
use ea_admin::{
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig, OperatorRuntimeError},
    reader_key_escrow_opening::{
        DeliveredReaderKeyEscrow, open_reader_key_escrow, pickup_reader_key_escrow,
    },
    reader_key_escrow_publication::{ActiveWebBundleRelease, publish_reader_key_escrow},
};
use ea_recovery::{ExitCode, ReaderKeyEscrowError, resolve_recipient_key};
use ea_types::UnixMillis;
use std::path::Path;

/// Wie eine Laufzeit geöffnet wird. Der ausgelieferte Einstieg wählt immer den
/// installierten Wirt; nur das getrennte Testbinär reicht einen Fixture-Öffner.
pub type RuntimeOpener<'a> = &'a dyn Fn(
    OperatorRuntimeConfig,
    &Path,
    UnixMillis,
) -> Result<OperatorRuntime, OperatorRuntimeError>;

fn installed(
    config: OperatorRuntimeConfig,
    anchor: &Path,
    now: UnixMillis,
) -> Result<OperatorRuntime, OperatorRuntimeError> {
    OperatorRuntime::open(config, anchor, now, false)
}

pub fn run_open(
    invocation: &Invocation,
    config: &Path,
    recovery_key: &KeySourceArgument,
    authorization: &Path,
    inbox: &Path,
    outbox: &Path,
    now: UnixMillis,
) -> ExitCode {
    run_open_with_runtime_opener(
        invocation,
        config,
        recovery_key,
        authorization,
        inbox,
        outbox,
        now,
        &installed,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_open_with_runtime_opener(
    invocation: &Invocation,
    config: &Path,
    recovery_key: &KeySourceArgument,
    authorization: &Path,
    inbox: &Path,
    outbox: &Path,
    now: UnixMillis,
    opener: RuntimeOpener<'_>,
) -> ExitCode {
    run_ceremony(
        invocation,
        config,
        authorization,
        now,
        opener,
        |runtime, exact| {
            // Token-Login und öffentlicher Schlüssel liegen VOR dem Verbrauch; die
            // private Operation erst danach (Entscheidung D2).
            let key = resolve_recipient_key(recovery_key.spec()).map_err(|error| {
                output::print_recovery_error(&error);
                ea_recovery::exit_code_for_error(&error)
            })?;
            open_reader_key_escrow(runtime, &key, exact, inbox, outbox).map_err(escrow_failure)
        },
    )
    .map_or_else(|code| code, |delivered| report("opened", &delivered))
}

pub fn run_pickup(
    invocation: &Invocation,
    config: &Path,
    authorization: &Path,
    inbox: &Path,
    outbox: &Path,
    now: UnixMillis,
) -> ExitCode {
    run_pickup_with_runtime_opener(
        invocation,
        config,
        authorization,
        inbox,
        outbox,
        now,
        &installed,
    )
}

pub fn run_pickup_with_runtime_opener(
    invocation: &Invocation,
    config: &Path,
    authorization: &Path,
    inbox: &Path,
    outbox: &Path,
    now: UnixMillis,
    opener: RuntimeOpener<'_>,
) -> ExitCode {
    run_ceremony(
        invocation,
        config,
        authorization,
        now,
        opener,
        |runtime, exact| {
            pickup_reader_key_escrow(runtime, exact, inbox, outbox).map_err(escrow_failure)
        },
    )
    .map_or_else(|code| code, |delivered| report("picked-up", &delivered))
}

/// Zeremonie A des Reader-Key-Escrows: `organization reader-key-escrow-publish`.
///
/// Der Cutover-Port ist fest der echte [`ActiveWebBundleRelease`]: ohne aktive,
/// wurzelsignierte `webBundleRelease` eines v1.1-fähigen Bundles im Bestand
/// endet die Zeremonie als erster Schritt mit `EA-ESCROW-CUTOVER-NOT-READY`
/// (Exit 21), ohne Inbox, Reauthentifizierung, Sperrzeile, Audit oder Datei.
/// Kein Argument, keine Konfiguration und keine Umgebung wählt einen anderen
/// Port.
///
/// Der Einstieg liegt hier und nicht in `organization.rs`: jene Datei wird von
/// einem zweiten Testziel per `#[path]` eingebunden, in dem dieses Modul nicht
/// existiert.
pub fn run_publish(
    invocation: &Invocation,
    config: &Path,
    inbox: &Path,
    now: UnixMillis,
) -> ExitCode {
    run_publish_with_runtime_opener(invocation, config, inbox, now, &installed)
}

/// Zeremonie A. Nur der Laufzeitöffner ist wählbar (das getrennte Testbinär
/// reicht einen Fixture-Öffner); der Cutover-Port ist fest der echte
/// [`ActiveWebBundleRelease`].
pub fn run_publish_with_runtime_opener(
    invocation: &Invocation,
    config: &Path,
    inbox: &Path,
    now: UnixMillis,
    opener: RuntimeOpener<'_>,
) -> ExitCode {
    if invocation.format == Format::Json {
        output::print_reader_key_escrow_json_refusal();
        return ExitCode::Unsupported;
    }
    let config = match OperatorRuntimeConfig::load(config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{}", error.code());
            return error.exit_code();
        }
    };
    let runtime = match opener(config, &invocation.anchor, now) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("{}", error.code());
            return error.exit_code();
        }
    };
    match publish_reader_key_escrow(&runtime, &ActiveWebBundleRelease, inbox) {
        Ok(published) => {
            output::print_reader_key_escrow_report(
                if published.replayed {
                    "republished"
                } else {
                    "published"
                },
                &[
                    ("package", published.package_hash.as_bytes()),
                    ("approval", published.approval_object_hash.as_bytes()),
                    ("escrow", published.escrow_object_hash.as_bytes()),
                ],
            );
            ExitCode::Success
        }
        Err(error) => escrow_failure(error),
    }
}

fn escrow_failure(error: ReaderKeyEscrowError) -> ExitCode {
    eprintln!("{}", error.code());
    error.exit_code()
}

fn report(action: &str, delivered: &DeliveredReaderKeyEscrow) -> ExitCode {
    output::print_reader_key_escrow_report(
        action,
        &[
            (
                "authorization",
                delivered.authorization_object_hash.as_bytes(),
            ),
            ("envelope", delivered.envelope_file_hash.as_bytes()),
        ],
    );
    ExitCode::Success
}

/// Textform, Bedienerdatei, Autorisierungsdatei, Laufzeit — dann die
/// Zeremonie.
fn run_ceremony(
    invocation: &Invocation,
    config: &Path,
    authorization: &Path,
    now: UnixMillis,
    opener: RuntimeOpener<'_>,
    ceremony: impl FnOnce(&OperatorRuntime, &[u8]) -> Result<DeliveredReaderKeyEscrow, ExitCode>,
) -> Result<DeliveredReaderKeyEscrow, ExitCode> {
    if invocation.format == Format::Json {
        output::print_reader_key_escrow_json_refusal();
        return Err(ExitCode::Unsupported);
    }
    let config = OperatorRuntimeConfig::load(config).map_err(|error| {
        eprintln!("{}", error.code());
        error.exit_code()
    })?;
    let exact = read_authorization(authorization)?;
    let runtime = opener(config, &invocation.anchor, now).map_err(|error| {
        eprintln!("{}", error.code());
        error.exit_code()
    })?;
    ceremony(&runtime, &exact)
}

/// Die Autorisierungsdatei, begrenzt; ein Lesefehler nennt keinen Pfad.
fn read_authorization(path: &Path) -> Result<Vec<u8>, ExitCode> {
    use std::io::Read as _;
    const LIMIT: u64 = 65_536;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(LIMIT + 1).read_to_end(&mut bytes))
        .map_err(|_| escrow_failure(ReaderKeyEscrowError::TransferFile))?;
    if bytes.is_empty() || bytes.len() as u64 > LIMIT {
        return Err(escrow_failure(ReaderKeyEscrowError::TransferFile));
    }
    Ok(bytes)
}
