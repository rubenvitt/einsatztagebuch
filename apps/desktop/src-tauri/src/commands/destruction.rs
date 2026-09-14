//! Public views and exact public originals for the native destruction workflow.
//! No entry plaintext, private proof or key material crosses this boundary.

use ea_ui_contracts::{
    DestructionAdministrationView, DestructionPreflightView, DestructionProcessView,
    DestructionReplicaView, DestructionStateV1, DestructionTargetView,
};
use serde::Serialize;

use super::CommandError;

const WIRE_ERROR: &str = "EA-DESKTOP-DESTRUCTION-WIRE-VALUE";

fn port(
    state: &crate::state::DesktopState,
) -> Result<std::sync::Arc<dyn crate::state::DestructionAdministrationPort>, CommandError> {
    super::admin::require_administrator(state.verified_role()?)?;
    state
        .destruction_port()
        .ok_or_else(|| CommandError::new("EA-DESKTOP-DESTRUCTION-UNAVAILABLE"))
}

pub(crate) fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], CommandError> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CommandError::new(WIRE_ERROR));
    }
    let mut result = [0; N];
    for (output, pair) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *output = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| CommandError::new(WIRE_ERROR))?,
            16,
        )
        .map_err(|_| CommandError::new(WIRE_ERROR))?;
    }
    Ok(result)
}

pub(crate) fn parse_id(text: &str) -> Result<ea_types::DestructionId, CommandError> {
    ea_types::DestructionId::try_from(parse_hex::<16>(text)?.as_slice())
        .map_err(|_| CommandError::new(WIRE_ERROR))
}

pub fn destruction_read_core(
    state: &crate::state::DesktopState,
    id: Option<&str>,
) -> Result<DestructionAdministrationWire, CommandError> {
    let port = port(state)?;
    port.read(id.map(parse_id).transpose()?)?.try_into()
}
pub fn destruction_prepare_core(
    state: &crate::state::DesktopState,
    exact: &[u8],
) -> Result<DestructionAdministrationWire, CommandError> {
    let port = port(state)?;
    if exact.is_empty() || exact.len() > ea_format::ETB_MAX_RAW_BYTES_V1 {
        return Err(CommandError::new(WIRE_ERROR));
    }
    port.prepare(exact)?.try_into()
}
pub fn destruction_start_core(
    state: &crate::state::DesktopState,
    id: &str,
    hash: &str,
) -> Result<DestructionAdministrationWire, CommandError> {
    let port = port(state)?;
    let id = parse_id(id)?;
    let hash = ea_types::ObjectHash::try_from(parse_hex::<32>(hash)?.as_slice())
        .map_err(|_| CommandError::new(WIRE_ERROR))?;
    port.start(id, hash)?.try_into()
}
pub fn destruction_resume_core(
    state: &crate::state::DesktopState,
    id: &str,
) -> Result<DestructionAdministrationWire, CommandError> {
    let port = port(state)?;
    port.resume(parse_id(id)?)?.try_into()
}

pub fn destruction_synchronize_core(
    state: &crate::state::DesktopState,
    id: &str,
    expected_preflight_hash: &str,
) -> Result<DestructionAdministrationWire, CommandError> {
    let port = port(state)?;
    let id = parse_id(id)?;
    let hash = ea_types::ObjectHash::try_from(parse_hex::<32>(expected_preflight_hash)?.as_slice())
        .map_err(|_| CommandError::new(WIRE_ERROR))?;
    port.synchronize(id, hash)?.try_into()
}

/// The explicit final action only; Resume never records state 4.
pub fn destruction_mark_incomplete_core(
    state: &crate::state::DesktopState,
    id: &str,
    expected_preflight_hash: &str,
) -> Result<DestructionAdministrationWire, CommandError> {
    let port = port(state)?;
    let id = parse_id(id)?;
    let hash = ea_types::ObjectHash::try_from(parse_hex::<32>(expected_preflight_hash)?.as_slice())
        .map_err(|_| CommandError::new(WIRE_ERROR))?;
    port.mark_incomplete(id, hash)?.try_into()
}

pub fn destruction_authenticate_custodian_core(
    state: &crate::state::DesktopState,
    id: &str,
    expected_preflight_hash: &str,
) -> Result<DestructionAdministrationWire, CommandError> {
    let port = port(state)?;
    let id = parse_id(id)?;
    let hash = ea_types::ObjectHash::try_from(parse_hex::<32>(expected_preflight_hash)?.as_slice())
        .map_err(|_| CommandError::new(WIRE_ERROR))?;
    port.authenticate_custodian(id, hash)?.try_into()
}

pub fn destruction_import_progress_core(
    state: &crate::state::DesktopState,
    id: &str,
    expected_preflight_hash: &str,
    exact_etb_objects: &[Vec<u8>],
) -> Result<DestructionAdministrationWire, CommandError> {
    use ea_admin::destruction_runtime::{
        MAX_NATIVE_DESTRUCTION_IMPORT_OBJECTS, MAX_NATIVE_DESTRUCTION_IMPORT_TOTAL_BYTES,
    };
    let port = port(state)?;
    let id = parse_id(id)?;
    let hash = ea_types::ObjectHash::try_from(parse_hex::<32>(expected_preflight_hash)?.as_slice())
        .map_err(|_| CommandError::new(WIRE_ERROR))?;
    if exact_etb_objects.is_empty()
        || exact_etb_objects.len() > MAX_NATIVE_DESTRUCTION_IMPORT_OBJECTS
    {
        return Err(CommandError::new(WIRE_ERROR));
    }
    let mut total = 0usize;
    for exact in exact_etb_objects {
        total = total
            .checked_add(exact.len())
            .ok_or_else(|| CommandError::new(WIRE_ERROR))?;
        if exact.is_empty()
            || exact.len() > ea_format::ETB_MAX_RAW_BYTES_V1
            || total > MAX_NATIVE_DESTRUCTION_IMPORT_TOTAL_BYTES
        {
            return Err(CommandError::new(WIRE_ERROR));
        }
    }
    port.import_progress(id, hash, exact_etb_objects)?
        .try_into()
}

pub(crate) const fn destruction_state_literal(state: DestructionStateV1) -> &'static str {
    match state {
        DestructionStateV1::Requested
        | DestructionStateV1::InProgress
        | DestructionStateV1::PendingBackupExpiry
        | DestructionStateV1::CompleteManagedScope
        | DestructionStateV1::IncompleteUnreachableReplica => state.as_str(),
    }
}

fn safe_integer(value: u64) -> Result<u64, CommandError> {
    if value > 9_007_199_254_740_991 {
        Err(CommandError::new(WIRE_ERROR))
    } else {
        Ok(value)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestructionTargetWire {
    entry_hash: String,
    chain_sequence: u64,
    stub_object_hash: Option<String>,
}
impl TryFrom<DestructionTargetView> for DestructionTargetWire {
    type Error = CommandError;
    fn try_from(value: DestructionTargetView) -> Result<Self, Self::Error> {
        Ok(Self {
            entry_hash: value.entry_hash,
            chain_sequence: safe_integer(value.chain_sequence.get())?,
            stub_object_hash: value.stub_object_hash,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestructionPreflightWire {
    job_hash: String,
    exact_canonical_report_json: String,
    known_replica_count: u32,
}
impl From<DestructionPreflightView> for DestructionPreflightWire {
    fn from(value: DestructionPreflightView) -> Self {
        Self {
            job_hash: value.job_hash,
            exact_canonical_report_json: value.exact_canonical_report_json,
            known_replica_count: value.known_replica_count,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestructionReplicaWire {
    device_id: String,
    kind_code: u64,
    attestation_hash: Option<String>,
    result_code: Option<u64>,
    backup_expiry_at: Option<u64>,
}
impl TryFrom<DestructionReplicaView> for DestructionReplicaWire {
    type Error = CommandError;
    fn try_from(value: DestructionReplicaView) -> Result<Self, Self::Error> {
        if value.kind_code > 2
            || value.result_code.is_some_and(|code| code > 2)
            || value.attestation_hash.is_some() != value.result_code.is_some()
            || (value.result_code == Some(1) && value.backup_expiry_at.is_none())
        {
            return Err(CommandError::new(WIRE_ERROR));
        }
        Ok(Self {
            device_id: value.device_id,
            kind_code: value.kind_code,
            attestation_hash: value.attestation_hash,
            result_code: value.result_code,
            backup_expiry_at: value
                .backup_expiry_at
                .map(|time| {
                    safe_integer(
                        u64::try_from(time.get()).map_err(|_| CommandError::new(WIRE_ERROR))?,
                    )
                })
                .transpose()?,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestructionProcessWire {
    destruction_id: String,
    authorization_object_hash: String,
    state: &'static str,
    scope_code: u64,
    legal_reason_code: u64,
    controller_device_id: String,
    custodian_device_id: String,
    approver_certificate_hashes: Vec<String>,
    targets: Vec<DestructionTargetWire>,
    preflight: Option<DestructionPreflightWire>,
    replicas: Vec<DestructionReplicaWire>,
    evidence_entry_hash: Option<String>,
}
impl TryFrom<DestructionProcessView> for DestructionProcessWire {
    type Error = CommandError;
    fn try_from(value: DestructionProcessView) -> Result<Self, Self::Error> {
        Ok(Self {
            destruction_id: value.destruction_id,
            authorization_object_hash: value.authorization_object_hash,
            state: destruction_state_literal(value.state),
            scope_code: safe_integer(value.scope_code)?,
            legal_reason_code: safe_integer(value.legal_reason_code)?,
            controller_device_id: value.controller_device_id,
            custodian_device_id: value.custodian_device_id,
            approver_certificate_hashes: value.approver_certificate_hashes,
            targets: value
                .targets
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            preflight: value.preflight.map(Into::into),
            replicas: value
                .replicas
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            evidence_entry_hash: value.evidence_entry_hash,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestructionAdministrationWire {
    privacy_decision_enabled: bool,
    policy_hash: String,
    known_destruction_ids: Vec<String>,
    process: Option<DestructionProcessWire>,
}
impl TryFrom<DestructionAdministrationView> for DestructionAdministrationWire {
    type Error = CommandError;
    fn try_from(value: DestructionAdministrationView) -> Result<Self, Self::Error> {
        Ok(Self {
            privacy_decision_enabled: value.privacy_decision_enabled,
            policy_hash: value.policy_hash,
            known_destruction_ids: value.known_destruction_ids,
            process: value.process.map(TryInto::try_into).transpose()?,
        })
    }
}

#[tauri::command]
pub async fn destruction_read(
    state: tauri::State<'_, crate::state::DesktopState>,
    destruction_id: Option<String>,
) -> Result<DestructionAdministrationWire, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || destruction_read_core(&state, destruction_id.as_deref())).await
}

#[tauri::command]
pub async fn destruction_prepare(
    state: tauri::State<'_, crate::state::DesktopState>,
    exact_authorization: Vec<u8>,
) -> Result<DestructionAdministrationWire, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || destruction_prepare_core(&state, &exact_authorization)).await
}

#[tauri::command]
pub async fn destruction_start(
    state: tauri::State<'_, crate::state::DesktopState>,
    destruction_id: String,
    expected_preflight_hash: String,
) -> Result<DestructionAdministrationWire, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        destruction_start_core(&state, &destruction_id, &expected_preflight_hash)
    })
    .await
}

#[tauri::command]
pub async fn destruction_resume(
    state: tauri::State<'_, crate::state::DesktopState>,
    destruction_id: String,
) -> Result<DestructionAdministrationWire, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || destruction_resume_core(&state, &destruction_id)).await
}

#[tauri::command]
pub async fn destruction_import_progress(
    state: tauri::State<'_, crate::state::DesktopState>,
    destruction_id: String,
    expected_preflight_hash: String,
    exact_etb_objects: Vec<Vec<u8>>,
) -> Result<DestructionAdministrationWire, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        destruction_import_progress_core(
            &state,
            &destruction_id,
            &expected_preflight_hash,
            &exact_etb_objects,
        )
    })
    .await
}

#[tauri::command]
pub async fn destruction_synchronize(
    state: tauri::State<'_, crate::state::DesktopState>,
    destruction_id: String,
    expected_preflight_hash: String,
) -> Result<DestructionAdministrationWire, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        destruction_synchronize_core(&state, &destruction_id, &expected_preflight_hash)
    })
    .await
}

#[tauri::command]
pub async fn destruction_authenticate_custodian(
    state: tauri::State<'_, crate::state::DesktopState>,
    destruction_id: String,
    expected_preflight_hash: String,
) -> Result<DestructionAdministrationWire, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        destruction_authenticate_custodian_core(&state, &destruction_id, &expected_preflight_hash)
    })
    .await
}

#[tauri::command]
pub async fn destruction_mark_incomplete(
    state: tauri::State<'_, crate::state::DesktopState>,
    destruction_id: String,
    expected_preflight_hash: String,
) -> Result<DestructionAdministrationWire, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        destruction_mark_incomplete_core(&state, &destruction_id, &expected_preflight_hash)
    })
    .await
}

/// Three separate existing public originals; never a container or file path.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestructionReaderDeliveryWire {
    destruction_id: String,
    job_hash: String,
    reader_id: String,
    exact_authorization: Vec<u8>,
    exact_initiating_event: Vec<u8>,
    exact_job_upload: Vec<u8>,
}

pub fn destruction_export_reader_delivery_core(
    state: &crate::state::DesktopState,
    destruction_id: &str,
    expected_preflight_hash: &str,
    reader_id: &str,
) -> Result<DestructionReaderDeliveryWire, CommandError> {
    let port = port(state)?;
    let id = parse_id(destruction_id)?;
    let job = ea_types::ObjectHash::try_from(parse_hex::<32>(expected_preflight_hash)?.as_slice())
        .map_err(|_| CommandError::new(WIRE_ERROR))?;
    let reader = ea_types::DeviceId::try_from(parse_hex::<16>(reader_id)?.as_slice())
        .map_err(|_| CommandError::new(WIRE_ERROR))?;
    let value = port.export_reader_delivery(id, job, reader)?;
    // The port may be absent or substituted in other hosts. Its output is
    // still bounded and bound to the exact explicit selection before IPC.
    if value.destruction_id != destruction_id
        || value.job_hash != expected_preflight_hash
        || value.reader_id != reader_id
        || value.exact_authorization.is_empty()
        || value.exact_authorization.len() > ea_format::ETB_MAX_RAW_BYTES_V1
        || value.exact_initiating_event.is_empty()
        || value.exact_initiating_event.len() > ea_format::ETB_MAX_RAW_BYTES_V1
        || value.exact_job_upload.is_empty()
        || value.exact_job_upload.len() > ea_sync_protocol::MAX_READER_PAGE_BYTES_V1
    {
        return Err(CommandError::new(WIRE_ERROR));
    }
    Ok(DestructionReaderDeliveryWire {
        destruction_id: value.destruction_id,
        job_hash: value.job_hash,
        reader_id: value.reader_id,
        exact_authorization: value.exact_authorization,
        exact_initiating_event: value.exact_initiating_event,
        exact_job_upload: value.exact_job_upload,
    })
}

#[tauri::command]
pub async fn destruction_export_reader_delivery(
    state: tauri::State<'_, crate::state::DesktopState>,
    destruction_id: String,
    expected_preflight_hash: String,
    reader_id: String,
) -> Result<DestructionReaderDeliveryWire, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        destruction_export_reader_delivery_core(
            &state,
            &destruction_id,
            &expected_preflight_hash,
            &reader_id,
        )
    })
    .await
}
