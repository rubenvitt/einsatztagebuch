//! Explicit job-bound Writer operations, behind the independently verified Admin host.
use super::*;
use crate::state::DestructionEvidencePort;
use ea_ui_contracts::{
    DestructionEvidenceReviewView, DiscardStateView, FinalizationPreviewView, FinalizeOutcomeView,
    PendingResumeOutcomeView,
};

const UNAVAILABLE: &str = "EA-DESKTOP-DESTRUCTION-EVIDENCE-UNAVAILABLE";
fn binding_error() -> CommandError {
    CommandError::new("EA-DRAFT-EVIDENCE-BINDING")
}
impl DestructionResources {
    fn evidence_writer(&mut self) -> Result<&mut NativeEvidenceWriter, CommandError> {
        let settings = self
            .evidence_settings
            .as_ref()
            .ok_or_else(|| CommandError::new(UNAVAILABLE))?;
        if let Some(source) = &self.reopen {
            let current = Config::load(&source.path)?;
            let base = source.path.parent().unwrap_or_else(|| Path::new("."));
            if current != source.config
                || current.evidence_settings(base)? != source.evidence_settings
            {
                return Err(config_error());
            }
        }
        if self.evidence_writer.is_none() {
            self.evidence_writer = Some(
                self.runtime
                    .evidence_writer(settings.timezone.clone(), settings.archive_profile.clone())
                    .map_err(|error| CommandError::new(error.code()))?,
            );
        }
        self.evidence_writer
            .as_mut()
            .ok_or_else(|| CommandError::new(UNAVAILABLE))
    }
    fn bound_evidence_writer(
        &mut self,
        id: DestructionId,
        hash: ObjectHash,
    ) -> Result<&mut NativeEvidenceWriter, CommandError> {
        let writer = self.evidence_writer()?;
        let bound = writer
            .pending()
            .map_err(|error| CommandError::new(error.code()))?
            .ok_or_else(binding_error)?;
        if bound.destruction_id() != id || bound.preflight_hash() != hash {
            return Err(binding_error());
        }
        Ok(writer)
    }
}
impl DestructionEvidencePort for NativeDesktopRuntime {
    fn preview(
        &self,
        id: DestructionId,
        hash: ObjectHash,
    ) -> Result<DestructionEvidenceReviewView, CommandError> {
        self.destruction_action(|resources| {
            // Establish explicit configured Writer resources before obtaining any projection.
            resources.evidence_writer()?;
            let evidence = if let Some(transport) = &mut resources.server_transport {
                transport.project_writer_evidence(&mut resources.runtime, id, hash)
                    .map_err(|error| CommandError::new(error.code()))?
            } else {
                resources.runtime.project_writer_evidence(id, ea_admin::destruction_runtime::NativeDestructionDelivery::NoRegisteredServer)
                    .map_err(|error| CommandError::new(error.code()))?
            };
            let source = evidence.draft_source().map_err(|error| CommandError::new(error.code()))?;
            if source.destruction_id() != id || source.preflight_hash() != hash { return Err(binding_error()); }
            // Read the durable public view before Writer preparation; failure after preparation
            // must never fabricate a preview or mark replicas as complete.
            let process = project(resources.runtime.status(id).map_err(|error| CommandError::new(error.code()))?)?;
            let preview = resources.evidence_writer()?.preview(evidence)
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(DestructionEvidenceReviewView {
                writer_device_id: process.custodian_device_id.clone(),
                process,
                preview: FinalizationPreviewView::from(&preview),
            })
        })
    }
    fn finalize(
        &self,
        id: DestructionId,
        hash: ObjectHash,
        confirmed: &FinalizationPreviewView,
    ) -> Result<FinalizeOutcomeView, CommandError> {
        self.destruction_action(|resources| {
            let writer = resources.bound_evidence_writer(id, hash)?;
            let issued = writer
                .issued_preview()
                .ok_or_else(|| CommandError::new(crate::commands::PREVIEW_NOT_ISSUED))?;
            if FinalizationPreviewView::from(issued) != *confirmed {
                return Err(CommandError::new(crate::commands::PREVIEW_MISMATCH));
            }
            let expected = issued.preview_hash();
            let outcome = writer
                .finalize(expected)
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(FinalizeOutcomeView::new(&outcome, None))
        })
    }
    fn recover(
        &self,
        id: DestructionId,
        hash: ObjectHash,
    ) -> Result<PendingResumeOutcomeView, CommandError> {
        self.destruction_action(|resources| {
            let outcome = resources
                .bound_evidence_writer(id, hash)?
                .recover(id, hash)
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(crate::commands::writer::resume_view(&outcome, None))
        })
    }
    fn discard(
        &self,
        id: DestructionId,
        hash: ObjectHash,
    ) -> Result<DiscardStateView, CommandError> {
        self.destruction_action(|resources| {
            let outcome = resources
                .bound_evidence_writer(id, hash)?
                .discard(id, hash)
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(crate::commands::writer::discard_view(outcome))
        })
    }
}
