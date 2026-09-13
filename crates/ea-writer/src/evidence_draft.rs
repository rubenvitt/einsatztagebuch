//! The durable draft route is checked independently of payload validation.
use crate::{WriterError, content::FinalizationContent, finalize::WriterService};

impl WriterService<'_> {
    pub(crate) fn require_draft_content(
        &self,
        content: &FinalizationContent,
    ) -> Result<(), WriterError> {
        let bound = self.repository.evidence_draft_source()?;
        match content {
            FinalizationContent::DestructionEvidence(input) => {
                let expected = input
                    .evidence
                    .draft_source()
                    .map_err(|_| WriterError::DestructionEvidenceInvalid)?;
                if bound != Some(expected) {
                    return Err(ea_draft::DraftError::EvidenceBinding.into());
                }
            }
            _ if bound.is_some() => return Err(ea_draft::DraftError::EvidenceBinding.into()),
            _ => {}
        }
        Ok(())
    }
}
