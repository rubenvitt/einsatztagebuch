//! Historical grant CLI: frozen input verification, native presence, signed audit, publication.
use crate::{
    args::{Invocation, KeySourceArgument},
    output,
};
use ea_admin::{
    historical_grant::issue_historical_grants,
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig, OperatorRuntimeError},
};
use ea_recovery::{ExitCode, exit_code_for, exit_code_for_error, grant_inputs, load_trust_anchor};
use ea_types::UnixMillis;
use std::path::Path;

#[allow(clippy::too_many_arguments)]
pub fn run(
    invocation: &Invocation,
    archive: &Path,
    recovery_key: &KeySourceArgument,
    authority_key: &KeySourceArgument,
    authorization: &Path,
    recipient_certificate: &Path,
    operator_config: Option<&Path>,
    output_directory: Option<&Path>,
    now: UnixMillis,
) -> ExitCode {
    run_with_runtime_opener(
        invocation,
        archive,
        recovery_key,
        authority_key,
        authorization,
        recipient_certificate,
        operator_config,
        output_directory,
        now,
        |config, anchor, now| OperatorRuntime::open(config, anchor, now, false),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_with_runtime_opener(
    invocation: &Invocation,
    archive: &Path,
    recovery_key: &KeySourceArgument,
    authority_key: &KeySourceArgument,
    authorization: &Path,
    recipient_certificate: &Path,
    operator_config: Option<&Path>,
    output_directory: Option<&Path>,
    now: UnixMillis,
    opener: impl FnOnce(
        OperatorRuntimeConfig,
        &Path,
        UnixMillis,
    ) -> Result<OperatorRuntime, OperatorRuntimeError>,
) -> ExitCode {
    let anchor = match load_trust_anchor(&invocation.anchor) {
        Ok(a) => a,
        Err(e) => {
            output::print_recovery_error(&e);
            return exit_code_for_error(&e);
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
        Ok(i) => i,
        Err(e) => {
            output::print_recovery_error(&e);
            return exit_code_for_error(&e);
        }
    };
    let finding = exit_code_for(&inputs.report);
    if finding != ExitCode::Success {
        return finding;
    }
    let Some(config_path) = operator_config else {
        eprintln!("EA-GRANT-NATIVE-CONFIGURATION-REQUIRED");
        return ExitCode::Usage;
    };
    let config = match OperatorRuntimeConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e.code());
            return e.exit_code();
        }
    };
    if std::fs::canonicalize(archive)
        .ok()
        .zip(std::fs::canonicalize(&config.archive_directory).ok())
        .is_none_or(|(a, b)| a != b)
    {
        eprintln!("EA-GRANT-ARCHIVE-MISMATCH");
        return ExitCode::Usage;
    }
    let runtime = match opener(config, &invocation.anchor, now) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e.code());
            return e.exit_code();
        }
    };
    let Some(inputs) = inputs.resolved else {
        return ExitCode::Integrity;
    };
    let grants = match issue_historical_grants(&runtime, &inputs) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{}", e.code());
            return ExitCode::Trust;
        }
    };
    if let Err(e) = runtime.ensure_current() {
        eprintln!("{}", e.code());
        return e.exit_code();
    }
    let default_output = archive.join("grants");
    match grants.publish(&runtime, output_directory.unwrap_or(&default_output)) {
        Ok(hashes) => {
            for hash in hashes {
                println!("{}", hex_hash(hash.as_bytes()));
            }
            ExitCode::Success
        }
        Err(e) => {
            eprintln!("{}", e.code());
            if matches!(e, ea_recovery::HistoricalGrantError::Output) {
                ExitCode::Io
            } else {
                ExitCode::Trust
            }
        }
    }
}
fn hex_hash(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
