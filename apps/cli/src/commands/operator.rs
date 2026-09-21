//! Native operator commands share one verified runtime and its bounded clock.
use crate::{
    args::{Format, Invocation, OperatorAction},
    output,
};
use ea_admin::{
    native_archive::{NativeArchiveConfig, NativeArchiveOpenError, register_network_component},
    operator_authority, operator_ceremony,
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig, OperatorRuntimeError},
    recovery_test_runtime::parse_recovery_archive_profile,
};
use ea_recovery::ExitCode;
use ea_types::UnixMillis;
use std::path::Path;

pub fn run(
    invocation: &Invocation,
    action: OperatorAction,
    config_path: &Path,
    archive_profile: Option<&Path>,
    now: UnixMillis,
) -> ExitCode {
    run_with_runtime_opener(
        invocation,
        action,
        config_path,
        archive_profile,
        now,
        OperatorRuntime::open,
    )
}

// Shared by the ordinary command and the separate integration-test executable.
// The production entry point above always opens the validated installed helper,
// even when Cargo unifies a dependency's test-support feature in a test build.
pub(crate) fn run_with_runtime_opener(
    invocation: &Invocation,
    action: OperatorAction,
    config_path: &Path,
    archive_profile: Option<&Path>,
    now: UnixMillis,
    open: impl FnOnce(
        OperatorRuntimeConfig,
        &Path,
        UnixMillis,
        bool,
    ) -> Result<OperatorRuntime, OperatorRuntimeError>,
) -> ExitCode {
    let result = (|| {
        let config = OperatorRuntimeConfig::load(config_path)?;
        let authority = config.authority;
        let initialize = action == OperatorAction::Provision && !authority;
        let mut runtime = open(config, &invocation.anchor, now, initialize)?;
        if authority && action != OperatorAction::VerifySession {
            let count = match operator_authority::run_authority(&mut runtime) {
                Ok(count) => count,
                Err(error) => {
                    output::print_operator_authority_error(&error);
                    return Ok(error.exit_code());
                }
            };
            runtime.ensure_current()?;
            output::print_operator_authority_report(count, invocation.format)?;
        } else {
            match action {
                OperatorAction::VerifySession => {
                    let report = runtime.verify_session()?;
                    runtime.ensure_current()?;
                    output::print_operator_report(&report, invocation.format)?;
                }
                OperatorAction::Provision => {
                    let report = operator_ceremony::provision(&mut runtime)?;
                    runtime.ensure_current()?;
                    output::print_operator_report(&report, invocation.format)?;
                }
                OperatorAction::Revoke => {
                    let report = operator_ceremony::revoke(&mut runtime)?;
                    runtime.ensure_current()?;
                    output::print_operator_report(&report, invocation.format)?;
                }
                OperatorAction::RegisterNetworkArchive => {
                    // `args::parse` guarantees this switch for exactly this verb.
                    let profile_path = archive_profile
                        .expect("register-network-archive always carries --archive-profile");
                    return Ok(register_network_archive(
                        &runtime,
                        profile_path,
                        invocation.format,
                    ));
                }
            }
        }
        Ok::<_, OperatorRuntimeError>(ExitCode::Success)
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            output::print_operator_error(&error);
            error.exit_code()
        }
    }
}

/// Liest das Netzprofil und registriert die lokale Komponente (EA-CNA-REG-1).
///
/// Eigene Fehlerquittung statt `?`: [`NativeArchiveOpenError`] ist kein
/// `OperatorRuntimeError`, und `runtime.config().database_path` — nicht der
/// Aufrufpfad — ist die erklärte lokale SQLCipher-Datei (EA-CNA-REG-1).
fn register_network_archive(
    runtime: &OperatorRuntime,
    profile_path: &Path,
    format: Format,
) -> ExitCode {
    let profile = match std::fs::read(profile_path)
        .map_err(|_| OperatorRuntimeError::Io)
        .and_then(|bytes| {
            parse_recovery_archive_profile(&bytes).map_err(|_| OperatorRuntimeError::Config)
        }) {
        Ok(profile) => profile,
        Err(error) => {
            output::print_operator_error(&error);
            return error.exit_code();
        }
    };
    let config = NativeArchiveConfig {
        profile,
        local_commit_database_path: Some(runtime.config().database_path.clone()),
    };
    match register_network_component(runtime, config) {
        Ok((outcome, _component)) => {
            match output::print_operator_register_network_archive_report(outcome, format) {
                Ok(()) => ExitCode::Success,
                Err(error) => {
                    output::print_operator_error(&error);
                    error.exit_code()
                }
            }
        }
        Err(error) => {
            output::print_native_archive_error(&error);
            exit_code_for_native_archive_error(&error)
        }
    }
}

/// Ordnet einen Registrierungsfehler der normativen Exitcodetabelle zu.
///
/// Dieselbe Bauart wie `clock_release::exit_code_for`: `Runtime` delegiert an
/// die vorhandene Tabelle von [`OperatorRuntimeError`]; `Config` ist ein
/// Aufruffehler (2); `Audit` ist ein Schreib-/Speicherbefund (20); jeder
/// übrige Code — Rolle, Policy, ein `Backend`-Befund, Konflikt, Zeiger,
/// Profilmismatch, Kapazität — ist ein Vertrauens-/Richtlinienbefund (12),
/// wie bei `OperatorRuntimeError`s eigenem Auffangarm. `Backend` bleibt
/// ungeprüft: seine `ArchiveBackendError`-Nutzlast ist `ea-archive`, eine
/// Abhängigkeit, die dieses Paket bewusst nur als Dev-Dependency führt
/// (`apps/cli/Cargo.toml`) und die dieser Produktionscode deshalb nicht
/// benennt.
fn exit_code_for_native_archive_error(error: &NativeArchiveOpenError) -> ExitCode {
    match error {
        NativeArchiveOpenError::Config => ExitCode::Usage,
        NativeArchiveOpenError::Runtime(inner) => inner.exit_code(),
        NativeArchiveOpenError::Audit => ExitCode::Io,
        _ => ExitCode::Trust,
    }
}
