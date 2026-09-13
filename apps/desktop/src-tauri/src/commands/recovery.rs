//! Native recovery commands: no paths, private inputs or claimed test results
//! are accepted from the renderer.
use super::CommandError;
use crate::state::{DesktopState, RecoveryAdministrationPort, RecoveryMediumChoice};
use ea_ui_contracts::RecoveryAdministrationView;
use std::sync::Arc;
mod wire;
pub use wire::recovery_wire;

fn port(state: &DesktopState) -> Result<Arc<dyn RecoveryAdministrationPort>, CommandError> {
    super::admin::require_administrator(state.verified_role()?)?;
    state
        .recovery_port()
        .ok_or_else(|| CommandError::new("EA-DESKTOP-RECOVERY-UNAVAILABLE"))
}
fn identifier(value: &str, bytes: usize) -> Result<(), CommandError> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CommandError::new("EA-DESKTOP-RECOVERY-WIRE-VALUE"));
    }
    Ok(())
}
pub fn recovery_read_core(
    state: &DesktopState,
) -> Result<RecoveryAdministrationView, CommandError> {
    port(state)?.read()
}
pub fn recovery_start_core(
    state: &DesktopState,
) -> Result<RecoveryAdministrationView, CommandError> {
    port(state)?.start()
}
pub fn recovery_submit_core(
    state: &DesktopState,
    operation: &str,
    run: &str,
    request: &str,
    choice: u8,
) -> Result<RecoveryAdministrationView, CommandError> {
    let port = port(state)?;
    identifier(operation, 16)?;
    identifier(run, 16)?;
    identifier(request, 32)?;
    let choice = match choice {
        0 => RecoveryMediumChoice::UseConfiguredSource,
        1 => RecoveryMediumChoice::Missing,
        _ => return Err(CommandError::new("EA-DESKTOP-RECOVERY-WIRE-VALUE")),
    };
    port.submit(operation, run, request, choice)
}
pub fn recovery_cancel_core(
    state: &DesktopState,
    operation: &str,
) -> Result<RecoveryAdministrationView, CommandError> {
    let port = port(state)?;
    identifier(operation, 16)?;
    port.cancel(operation)
}

#[tauri::command]
pub async fn recovery_read(
    state: tauri::State<'_, DesktopState>,
) -> Result<serde_json::Value, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || recovery_wire(recovery_read_core(&state)?)).await
}
#[tauri::command]
pub async fn recovery_start(
    state: tauri::State<'_, DesktopState>,
) -> Result<serde_json::Value, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || recovery_wire(recovery_start_core(&state)?)).await
}
#[tauri::command]
pub async fn recovery_submit(
    state: tauri::State<'_, DesktopState>,
    operation_id: String,
    run_id: String,
    request_id: String,
    choice: u8,
) -> Result<serde_json::Value, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        recovery_wire(recovery_submit_core(
            &state,
            &operation_id,
            &run_id,
            &request_id,
            choice,
        )?)
    })
    .await
}
#[tauri::command]
pub async fn recovery_cancel(
    state: tauri::State<'_, DesktopState>,
    operation_id: String,
) -> Result<serde_json::Value, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || recovery_wire(recovery_cancel_core(&state, &operation_id)?)).await
}
