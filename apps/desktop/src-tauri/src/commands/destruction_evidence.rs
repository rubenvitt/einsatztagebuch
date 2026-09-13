//! Separate native Writer actions for a job-bound evidence draft.
use super::{
    CommandError,
    destruction::{DestructionProcessWire, parse_hex, parse_id},
    writer::{
        DiscardStateDto, FinalizationPreviewDto, FinalizeOutcomeDto, PendingResumeOutcomeDto,
    },
};
use crate::state::{DesktopState, DestructionEvidencePort};
use ea_types::{DestructionId, ObjectHash};
use ea_ui_contracts::DestructionEvidenceReviewView;
use serde::Serialize;
use std::sync::Arc;

const WIRE_ERROR: &str = "EA-DESKTOP-DESTRUCTION-WIRE-VALUE";
fn error() -> CommandError {
    CommandError::new(WIRE_ERROR)
}
fn port(state: &DesktopState) -> Result<Arc<dyn DestructionEvidencePort>, CommandError> {
    super::admin::require_administrator(state.verified_role()?)?;
    state
        .destruction_evidence_port()
        .ok_or_else(|| CommandError::new("EA-DESKTOP-DESTRUCTION-EVIDENCE-UNAVAILABLE"))
}
fn identifiers(id: &str, hash: &str) -> Result<(DestructionId, ObjectHash), CommandError> {
    Ok((
        parse_id(id)?,
        ObjectHash::try_from(parse_hex::<32>(hash)?.as_slice()).map_err(|_| error())?,
    ))
}
fn checked_preview(value: &FinalizationPreviewDto) -> Result<(), CommandError> {
    const MAX: u64 = 9_007_199_254_740_991;
    if value.proposed_sequence > MAX
        || value.trust_age_ms > MAX
        || value.reader_trust_refresh_ms > MAX
        || value.effective_now < 0
        || value.effective_now > 8_640_000_000_000_000
    {
        return Err(error());
    }
    value.to_view()?;
    Ok(())
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestructionEvidenceReviewWire {
    writer_device_id: String,
    process: DestructionProcessWire,
    preview: FinalizationPreviewDto,
}
impl TryFrom<DestructionEvidenceReviewView> for DestructionEvidenceReviewWire {
    type Error = CommandError;
    fn try_from(value: DestructionEvidenceReviewView) -> Result<Self, Self::Error> {
        parse_hex::<16>(&value.writer_device_id)?;
        if value.writer_device_id != value.process.custodian_device_id
            || value.process.preflight.is_none()
        {
            return Err(error());
        }
        let preview = FinalizationPreviewDto::from(value.preview);
        checked_preview(&preview)?;
        Ok(Self {
            writer_device_id: value.writer_device_id,
            process: value.process.try_into()?,
            preview,
        })
    }
}
pub fn destruction_evidence_preview_core(
    state: &DesktopState,
    id: &str,
    hash: &str,
) -> Result<DestructionEvidenceReviewWire, CommandError> {
    let port = port(state)?;
    let (parsed, expected) = identifiers(id, hash)?;
    let view = port.preview(parsed, expected)?;
    if view.process.destruction_id != id
        || view
            .process
            .preflight
            .as_ref()
            .is_none_or(|p| p.job_hash != hash)
    {
        return Err(error());
    }
    view.try_into()
}
pub fn destruction_evidence_finalize_core(
    state: &DesktopState,
    id: &str,
    hash: &str,
    confirmed: &FinalizationPreviewDto,
) -> Result<FinalizeOutcomeDto, CommandError> {
    let port = port(state)?;
    let (id, hash) = identifiers(id, hash)?;
    checked_preview(confirmed)?;
    port.finalize(id, hash, &confirmed.to_view()?)
        .map(FinalizeOutcomeDto::from)
}
pub fn destruction_evidence_recover_core(
    state: &DesktopState,
    id: &str,
    hash: &str,
) -> Result<PendingResumeOutcomeDto, CommandError> {
    let port = port(state)?;
    let (id, hash) = identifiers(id, hash)?;
    Ok(PendingResumeOutcomeDto::from(&port.recover(id, hash)?))
}
pub fn destruction_evidence_discard_core(
    state: &DesktopState,
    id: &str,
    hash: &str,
) -> Result<DiscardStateDto, CommandError> {
    let port = port(state)?;
    let (id, hash) = identifiers(id, hash)?;
    let view = port.discard(id, hash)?;
    if ![
        ea_draft::RestartState::OriginalDraftUnchanged,
        ea_draft::RestartState::NewBlankDraft,
        ea_draft::RestartState::PreparedFinalizationPending,
    ]
    .into_iter()
    .any(|state| super::writer::discard_view(state) == view)
    {
        return Err(error());
    }
    Ok(DiscardStateDto::from(&view))
}

#[tauri::command]
pub async fn destruction_evidence_preview(
    state: tauri::State<'_, DesktopState>,
    destruction_id: String,
    expected_preflight_hash: String,
) -> Result<DestructionEvidenceReviewWire, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        destruction_evidence_preview_core(&state, &destruction_id, &expected_preflight_hash)
    })
    .await
}
#[tauri::command]
pub async fn destruction_evidence_finalize(
    state: tauri::State<'_, DesktopState>,
    destruction_id: String,
    expected_preflight_hash: String,
    confirmed: FinalizationPreviewDto,
) -> Result<FinalizeOutcomeDto, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        destruction_evidence_finalize_core(
            &state,
            &destruction_id,
            &expected_preflight_hash,
            &confirmed,
        )
    })
    .await
}
#[tauri::command]
pub async fn destruction_evidence_recover(
    state: tauri::State<'_, DesktopState>,
    destruction_id: String,
    expected_preflight_hash: String,
) -> Result<PendingResumeOutcomeDto, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        destruction_evidence_recover_core(&state, &destruction_id, &expected_preflight_hash)
    })
    .await
}
#[tauri::command]
pub async fn destruction_evidence_discard(
    state: tauri::State<'_, DesktopState>,
    destruction_id: String,
    expected_preflight_hash: String,
) -> Result<DiscardStateDto, CommandError> {
    let state = state.inner().clone();
    super::run_blocking(move || {
        destruction_evidence_discard_core(&state, &destruction_id, &expected_preflight_hash)
    })
    .await
}
