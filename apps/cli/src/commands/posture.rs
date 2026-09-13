//! Operational posture documentation; no caller-supplied identity or clock.
use crate::{
    args::{Invocation, PostureAction},
    output,
};
use ea_admin::operator_runtime::{
    OperatorRuntime, OperatorRuntimeConfig, OperatorRuntimeError, posture::PostureTargetContext,
};
use ea_recovery::ExitCode;
use ea_types::UnixMillis;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub fn run(
    invocation: &Invocation,
    action: &PostureAction,
    config: &Path,
    now: UnixMillis,
) -> ExitCode {
    run_with_runtime_opener(invocation, action, config, now, |config, anchor, now| {
        OperatorRuntime::open(config, anchor, now, false)
    })
}

pub(crate) fn run_with_runtime_opener(
    invocation: &Invocation,
    action: &PostureAction,
    config: &Path,
    now: UnixMillis,
    open: impl FnOnce(
        OperatorRuntimeConfig,
        &Path,
        UnixMillis,
    ) -> Result<OperatorRuntime, OperatorRuntimeError>,
) -> ExitCode {
    let result = (|| {
        let runtime = open(
            OperatorRuntimeConfig::load(config)?,
            &invocation.anchor,
            now,
        )?;
        match action {
            PostureAction::Target { output } => {
                write_new(output, &runtime.posture_target_context()?.to_json()?)?;
            }
            PostureAction::Issue {
                target,
                evidence_reference,
                lifetime_ms,
                output,
            } => {
                let target = PostureTargetContext::from_json(&read(target, 4096)?)?;
                let reference = read(evidence_reference, 1024 * 1024)?;
                if reference.is_empty() {
                    return Err(OperatorRuntimeError::Config);
                }
                let reference =
                    ea_admin::operator_runtime::posture::evidence_reference_hash(&reference)?;
                let exact = runtime.issue_posture_document(&target, reference, *lifetime_ms)?;
                write_new(output, &exact)?;
            }
            PostureAction::Import { document } => {
                runtime.import_posture_document(&read(document, 8192)?)?
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::Success,
        Err(error) => {
            output::print_operator_error(&error);
            error.exit_code()
        }
    }
}

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, OperatorRuntimeError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| OperatorRuntimeError::Io)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OperatorRuntimeError::Io)?;
    if bytes.len() > limit {
        return Err(OperatorRuntimeError::Config);
    }
    Ok(bytes)
}

fn write_new(path: &Path, exact: &[u8]) -> Result<(), OperatorRuntimeError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| OperatorRuntimeError::Io)?;
    file.write_all(exact)
        .and_then(|_| file.sync_all())
        .map_err(|_| OperatorRuntimeError::Io)?;
    #[cfg(unix)]
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|parent| parent.sync_all())
    .map_err(|_| OperatorRuntimeError::Io)?;
    Ok(())
}
