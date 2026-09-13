//! Native recovery source capture, restore/test and verified report exchange.
//!
//! The explicit runtime configuration selects the independently provisioned
//! installation, current operator and exact archive profile. Every productive
//! operation uses RecoveryTestRuntime; caller paths or parsed inventory never
//! attest restoration, identity or readiness. Report targets are exclusive new
//! files, and failed tests retain their separate signed diagnostic status.
//!
//! Without runtime arguments the legacy verification-only facade keeps its
//! named Unsupported boundary. It cannot claim a successful recovery test or
//! create an empty report file merely because public archive checks passed.

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
    runtime: Option<&crate::args::RecoveryRuntimeArguments>,
    now: UnixMillis,
) -> ExitCode {
    if let Some(runtime) = runtime {
        return run_with_runtime_opener(
            invocation,
            archive,
            key_inventory,
            output_path,
            runtime,
            now,
            |config, anchor, now| {
                ea_admin::operator_runtime::OperatorRuntime::open(config, anchor, now, false)
            },
        );
    }
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

pub(crate) fn run_with_runtime_opener(
    invocation: &Invocation,
    archive: &Path,
    key_inventory: &Path,
    output: &Path,
    runtime: &crate::args::RecoveryRuntimeArguments,
    now: UnixMillis,
    open: impl FnOnce(
        ea_admin::operator_runtime::OperatorRuntimeConfig,
        &Path,
        UnixMillis,
    ) -> Result<
        ea_admin::operator_runtime::OperatorRuntime,
        ea_admin::operator_runtime::OperatorRuntimeError,
    >,
) -> ExitCode {
    use ea_admin::{
        operator_runtime::OperatorRuntimeConfig,
        recovery_test_runtime::{RecoveryTestRuntime, parse_recovery_archive_profile},
    };
    let result = (|| -> Result<(), CommandFailure> {
        let anchor = load_trust_anchor(&invocation.anchor)?;
        let source = ea_recovery::FsArchiveSource::open(archive)?;
        ea_recovery::RecoveryArchiveProbe::verify(&source, &anchor, now).map_err(test_failure)?;
        ea_recovery::output_file_is_free(output)?;
        let inventory = ea_recovery::KeyInventory::parse(&read(key_inventory, 1024 * 1024)?)
            .map_err(|_| test_failure(ea_recovery::RecoveryTestError::Inventory))?;
        let config = OperatorRuntimeConfig::load(&runtime.config)?;
        let observed = std::fs::canonicalize(archive).map_err(|_| io_failure())?;
        if observed != std::fs::canonicalize(&config.archive_directory).map_err(|_| io_failure())? {
            return Err(test_failure(ea_recovery::RecoveryTestError::Source));
        }
        let profile = parse_recovery_archive_profile(&read(&runtime.profile, 65536)?)?;
        let mut service =
            RecoveryTestRuntime::new(open(config, &invocation.anchor, now)?, profile)?;
        match &runtime.action {
            crate::args::recovery::RecoveryRuntimeAction::Capture {
                snapshot,
                passphrase,
            } => {
                let phrase = ea_recovery::read_secret_file(passphrase)?;
                let captured = service.capture_inventory(&inventory, snapshot, &phrase)?;
                write_new(output, captured.exact_envelope())?;
            }
            crate::args::recovery::RecoveryRuntimeAction::Import { source, report } => {
                let imported = service.import_completed_report(
                    &inventory,
                    &read(source, 512 * 1024)?,
                    &read(report, 4 * 1024 * 1024)?,
                )?;
                write_new(output, imported.exact_envelope())?;
            }
            crate::args::recovery::RecoveryRuntimeAction::Status => {
                let report = service
                    .read_imported_completed_report(&inventory)?
                    .ok_or_else(|| test_failure(ea_recovery::RecoveryTestError::Incomplete))?;
                write_new(output, report.exact_envelope())?;
            }
            crate::args::recovery::RecoveryRuntimeAction::FailureStatus { restore } => {
                let report = service
                    .read_failed_report(&inventory, restore)?
                    .ok_or_else(|| test_failure(ea_recovery::RecoveryTestError::Incomplete))?;
                write_new(output, report.exact_envelope())?;
                return Err(test_failure(ea_recovery::RecoveryTestError::Incomplete));
            }
            crate::args::recovery::RecoveryRuntimeAction::RestoreRun {
                source,
                snapshot,
                passphrase,
                restore,
                media,
            } => {
                let media = ea_admin::recovery_test_runtime::parse_recovery_media_sources(
                    &read(media, 1024 * 1024)?,
                    &inventory,
                )?;
                let exact_source = read(source, 512 * 1024)?;
                let phrase = ea_recovery::read_secret_file(passphrase)?;
                let restored = service.restore_source(
                    ea_admin::recovery_test_runtime::RecoverySourceRestore {
                        inventory: &inventory,
                        exact_source: &exact_source,
                        snapshot,
                        passphrase: &phrase,
                        target: restore,
                    },
                )?;
                drop(phrase);
                match service.run_restored_test_report(&restored, &inventory, &media)? {
                    ea_admin::recovery_test_runtime::RecoveryTestOutcome::Completed(report) => {
                        write_new(output, report.exact_envelope())?;
                    }
                    ea_admin::recovery_test_runtime::RecoveryTestOutcome::Failed(report) => {
                        write_new(output, report.exact_envelope())?;
                        return Err(test_failure(ea_recovery::RecoveryTestError::Incomplete));
                    }
                }
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::Success,
        Err(CommandFailure(code, exit)) => {
            eprintln!("{code}");
            exit
        }
    }
}
struct CommandFailure(&'static str, ExitCode);
fn io_failure() -> CommandFailure {
    CommandFailure("EA-RECOVERY-TEST-IO", ExitCode::Io)
}
fn test_failure(error: ea_recovery::RecoveryTestError) -> CommandFailure {
    use ea_recovery::RecoveryTestError::*;
    CommandFailure(
        error.code(),
        match error {
            Archive | Payload => ExitCode::Integrity,
            Key | Protection => ExitCode::Key,
            Role | Operator | Audit | Machine => ExitCode::Trust,
            Incomplete => ExitCode::Incomplete,
            Inventory | Source => ExitCode::Usage,
            Entropy | Store => ExitCode::Io,
        },
    )
}
impl From<ea_recovery::RecoveryError> for CommandFailure {
    fn from(error: ea_recovery::RecoveryError) -> Self {
        Self(error.code(), ea_recovery::exit_code_for_error(&error))
    }
}
impl From<ea_admin::operator_runtime::OperatorRuntimeError> for CommandFailure {
    fn from(error: ea_admin::operator_runtime::OperatorRuntimeError) -> Self {
        Self(error.code(), error.exit_code())
    }
}
impl From<ea_admin::recovery_test_runtime::RecoveryRuntimeError> for CommandFailure {
    fn from(error: ea_admin::recovery_test_runtime::RecoveryRuntimeError) -> Self {
        use ea_admin::recovery_test_runtime::RecoveryRuntimeError::*;
        match error {
            Runtime(e) => e.into(),
            Test(e) => test_failure(e),
            Aborted => Self("EA-RECOVERY-TEST-CANCELLED", ExitCode::Incomplete),
            Store(e) => Self(e.code(), ExitCode::Io),
            Backend(e) => Self(e.code(), ExitCode::Io),
        }
    }
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>, CommandFailure> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| io_failure())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| io_failure())?;
    if bytes.len() > limit {
        return Err(test_failure(ea_recovery::RecoveryTestError::Source));
    }
    Ok(bytes)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CommandFailure> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| io_failure())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| io_failure())?;
    #[cfg(unix)]
    std::fs::File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|d| d.sync_all())
    .map_err(|_| io_failure())?;
    Ok(())
}
