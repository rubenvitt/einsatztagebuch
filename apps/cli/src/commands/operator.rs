//! Native operator commands share one verified runtime and its bounded clock.
use crate::{
    args::{Invocation, OperatorAction},
    output,
};
use ea_admin::{
    operator_authority, operator_ceremony,
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig, OperatorRuntimeError},
};
use ea_recovery::ExitCode;
use ea_types::UnixMillis;
use std::path::Path;

pub fn run(
    invocation: &Invocation,
    action: OperatorAction,
    config_path: &Path,
    now: UnixMillis,
) -> ExitCode {
    run_with_runtime_opener(invocation, action, config_path, now, OperatorRuntime::open)
}

// Shared by the ordinary command and the separate integration-test executable.
// The production entry point above always opens the validated installed helper,
// even when Cargo unifies a dependency's test-support feature in a test build.
pub(crate) fn run_with_runtime_opener(
    invocation: &Invocation,
    action: OperatorAction,
    config_path: &Path,
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
            let report = match action {
                OperatorAction::VerifySession => runtime.verify_session()?,
                OperatorAction::Provision => operator_ceremony::provision(&mut runtime)?,
                OperatorAction::Revoke => operator_ceremony::revoke(&mut runtime)?,
            };
            runtime.ensure_current()?;
            output::print_operator_report(&report, invocation.format)?;
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
