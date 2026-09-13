//! Independent native Writer composition for an opaque destruction projection.
use super::{DestructionHostGuard, DestructionRuntime, NativeDestructionError, NativeLocalHolder};
use crate::{VerifiedOperatorSession, operator_runtime::OperatorRuntime};
use ea_archive::ArchiveBackendProfileV1;
use ea_destruction::VerifiedDestructionEvidence;
use ea_draft::{
    AutosaveDraftRepository, DiscardService, DraftRepository, EvidenceDraftBinding,
    IncidentNumberRegister, OperatorProfileRepository, RestartState,
};
use ea_key_provider::SecretPurpose;
use ea_operator::ReauthPurpose;
use ea_types::{DestructionId, Hash32, ObjectHash};
use ea_writer::{
    DestructionEvidenceInputV1, FinalizationPreview, FinalizeOutcome, RecoveryOutcome,
    WriterBindingV1, WriterError, WriterService,
};
use std::sync::Arc;
mod ports;
use ports::{Boundary, Guarded};

#[derive(Debug)]
pub enum NativeEvidenceWriterError {
    Native(NativeDestructionError),
    Writer(WriterError),
    Draft(ea_draft::DraftError),
}
impl NativeEvidenceWriterError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Native(e) => e.code(),
            Self::Writer(e) => e.code(),
            Self::Draft(e) => e.code(),
        }
    }
}
impl std::fmt::Display for NativeEvidenceWriterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for NativeEvidenceWriterError {}
impl From<NativeDestructionError> for NativeEvidenceWriterError {
    fn from(e: NativeDestructionError) -> Self {
        Self::Native(e)
    }
}
impl From<WriterError> for NativeEvidenceWriterError {
    fn from(e: WriterError) -> Self {
        Self::Writer(e)
    }
}
impl From<ea_draft::DraftError> for NativeEvidenceWriterError {
    fn from(e: ea_draft::DraftError) -> Self {
        Self::Draft(e)
    }
}
type Error = NativeEvidenceWriterError;

pub struct NativeEvidenceWriter {
    runtime: OperatorRuntime,
    backend: ea_archive_fs::LocalPathBackend,
    timezone: String,
    boundary: Boundary,
    issued: Option<(FinalizationPreview, VerifiedDestructionEvidence)>,
}
impl DestructionRuntime {
    pub fn evidence_writer(
        &self,
        timezone: String,
        archive_profile: ArchiveBackendProfileV1,
    ) -> Result<NativeEvidenceWriter, Error> {
        self.check_host()?;
        ea_schema::validate_timezone(&timezone).map_err(WriterError::from)?;
        let runtime = self
            .custodian
            .reopened_for_action()
            .map_err(|_| NativeDestructionError::Session)?;
        self.check_host()?;
        let boundary = Boundary {
            native: runtime.native().clone(),
            host: self.host_guard.clone(),
            locked: false,
        };
        boundary.check()?;
        let holder = NativeLocalHolder::open(
            &runtime,
            runtime.config().archive_directory.clone(),
            archive_profile,
            runtime.config().device_certificate_hash,
        )?;
        boundary.check()?;
        Ok(NativeEvidenceWriter {
            runtime,
            backend: holder.backend,
            timezone,
            boundary,
            issued: None,
        })
    }
}
impl NativeEvidenceWriter {
    pub fn set_host_guard(&mut self, guard: Arc<dyn DestructionHostGuard>) {
        if self.boundary.check().is_err() {
            self.lock();
        }
        self.boundary.host = Some(guard);
    }
    pub fn lock(&mut self) {
        self.issued = None;
        self.boundary.locked = true;
    }
    pub fn issued_preview(&self) -> Option<&FinalizationPreview> {
        self.issued.as_ref().map(|(p, _)| p)
    }
    fn repository(&self) -> AutosaveDraftRepository {
        AutosaveDraftRepository::new(
            self.runtime.database().clone(),
            Arc::new(Guarded {
                inner: self.runtime.signing_provider().clone(),
                boundary: self.boundary.clone(),
            }),
        )
    }
    pub fn pending(&self) -> Result<Option<EvidenceDraftBinding>, Error> {
        self.boundary.check()?;
        let result = self.repository().evidence_binding()?;
        self.boundary.check()?;
        Ok(result)
    }
    fn authenticate(&self, purpose: ReauthPurpose) -> Result<VerifiedOperatorSession, Error> {
        self.boundary.check()?;
        let fresh = self
            .runtime
            .reopened_for_action()
            .map_err(|_| NativeDestructionError::Session)?;
        self.boundary.check()?;
        self.runtime
            .ensure_same_authority_as(&fresh)
            .map_err(|_| NativeDestructionError::Session)?;
        let proof = self
            .runtime
            .reauthenticate_for(purpose)
            .map_err(|_| NativeDestructionError::Session)?;
        self.boundary.check()?;
        let after = fresh
            .reopened_for_action()
            .map_err(|_| NativeDestructionError::Session)?;
        self.boundary.check()?;
        fresh
            .ensure_same_authority_as(&after)
            .map_err(|_| NativeDestructionError::Session)?;
        ea_operator::verify_current_session(
            after.head(),
            after.config().device_certificate_hash,
            ea_format::OperatorRoleV1::Writer,
            proof.proof(),
            purpose,
            after.native().as_ref(),
        )
        .map_err(|_| NativeDestructionError::Session)?;
        self.boundary.check()?;
        Ok(proof)
    }
    fn bound(&self, id: DestructionId, hash: ObjectHash) -> Result<EvidenceDraftBinding, Error> {
        let b = self
            .pending()?
            .ok_or(ea_draft::DraftError::EvidenceBinding)?;
        if b.destruction_id() != id || b.preflight_hash() != hash {
            return Err(ea_draft::DraftError::EvidenceBinding.into());
        }
        Ok(b)
    }
    fn with_writer<T>(
        &self,
        binding: EvidenceDraftBinding,
        action: impl FnOnce(&WriterService<'_>) -> Result<T, WriterError>,
    ) -> Result<T, Error> {
        self.boundary.check()?;
        let repository = Arc::new(Guarded {
            inner: self.repository().for_evidence_draft(binding)?,
            boundary: self.boundary.clone(),
        });
        let provider = Arc::new(Guarded {
            inner: self.runtime.signing_provider().clone(),
            boundary: self.boundary.clone(),
        });
        let backend = Guarded {
            inner: &self.backend,
            boundary: self.boundary.clone(),
        };
        let source = self.backend.as_archive_source();
        let source = Guarded {
            inner: source,
            boundary: self.boundary.clone(),
        };
        let public = self
            .runtime
            .head()
            .active_certificate_fields(self.runtime.config().device_certificate_hash)
            .and_then(|f| f.signing_key_thumbprint)
            .ok_or(NativeDestructionError::Configuration)?;
        let service = WriterService::new(
            repository,
            provider,
            &backend,
            &source,
            self.runtime.head(),
            &[],
            IncidentNumberRegister::new(self.runtime.database().clone()),
            OperatorProfileRepository::new(self.runtime.database().clone()),
            WriterBindingV1 {
                binding_object_hash: self.runtime.config().binding_object_hash,
                writer_certificate_hash: self.runtime.config().device_certificate_hash,
                writer_key_thumbprint: public,
                writer_signing_handle: self
                    .runtime
                    .signing_provider()
                    .handle(SecretPurpose::WriterSigningKey),
                chain_id: self.runtime.anchor().chain_id(),
                archive_profile_hash: self.backend.profile_hash().map_err(WriterError::from)?,
            },
        );
        let result = action(&service)?;
        self.boundary.check()?;
        Ok(result)
    }
    fn input(
        &self,
        evidence: VerifiedDestructionEvidence,
    ) -> Result<DestructionEvidenceInputV1, Error> {
        Ok(DestructionEvidenceInputV1 {
            timezone: self.timezone.clone(),
            source: ea_schema::NativeSourceV1::new("ea.native", 1).map_err(WriterError::from)?,
            evidence,
        })
    }
    pub fn preview(
        &mut self,
        evidence: VerifiedDestructionEvidence,
    ) -> Result<FinalizationPreview, Error> {
        self.issued = None;
        self.boundary.check()?;
        self.runtime
            .refresh_for_action()
            .map_err(|_| NativeDestructionError::Session)?;
        let proof = self.authenticate(ReauthPurpose::Finalize)?;
        evidence
            .validate_for_writer(
                self.runtime.anchor().organization_id(),
                self.runtime.anchor().chain_id(),
                self.runtime.next_sequence(),
                self.runtime.head().preexisting_effective_now().value(),
            )
            .map_err(|_| WriterError::DestructionEvidenceInvalid)?;
        self.boundary.check()?;
        let source = evidence
            .draft_source()
            .map_err(|_| WriterError::DestructionEvidenceInvalid)?;
        let repository = self.repository();
        self.boundary.check()?;
        let binding = repository.reserve_evidence_draft(source)?;
        self.boundary.check()?;
        let input = self.input(evidence.clone())?;
        let p = self.with_writer(binding, |s| {
            s.preview_destruction_evidence(
                proof.proof(),
                input,
                self.runtime.head().preexisting_effective_now().value(),
            )
        })?;
        self.issued = Some((p.clone(), evidence));
        Ok(p)
    }
    pub fn finalize(&mut self, expected_preview_hash: Hash32) -> Result<FinalizeOutcome, Error> {
        let (p, e) = self
            .issued
            .take()
            .ok_or(WriterError::StaleAckPreviewMismatch)?;
        if p.preview_hash() != expected_preview_hash {
            return Err(WriterError::StaleAckPreviewMismatch.into());
        }
        let proof = self.authenticate(ReauthPurpose::Finalize)?;
        let source = e
            .draft_source()
            .map_err(|_| WriterError::DestructionEvidenceInvalid)?;
        let binding = self.bound(source.destruction_id(), source.preflight_hash())?;
        if binding.source() != source {
            return Err(ea_draft::DraftError::EvidenceBinding.into());
        }
        let input = self.input(e)?;
        self.with_writer(binding, |s| {
            s.finalize_destruction_evidence(proof.proof(), input, &p, p.effective_now())
        })
    }
    pub fn recover(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<RecoveryOutcome, Error> {
        self.issued = None;
        let binding = self.bound(id, expected_preflight_hash)?;
        self.authenticate(ReauthPurpose::Finalize)?;
        self.with_writer(binding, |s| {
            s.recover_pending_for_evidence(binding.source())
        })
    }
    pub fn discard(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<RestartState, Error> {
        self.issued = None;
        let binding = self.bound(id, expected_preflight_hash)?;
        let proof = self.authenticate(ReauthPurpose::DiscardDraft)?;
        let repository = Arc::new(Guarded {
            inner: self.repository().for_evidence_draft(binding)?,
            boundary: self.boundary.clone(),
        });
        let provider = Arc::new(Guarded {
            inner: self.runtime.signing_provider().clone(),
            boundary: self.boundary.clone(),
        });
        let service = DiscardService::new(
            repository.clone(),
            provider,
            self.runtime.config().binding_object_hash,
            self.runtime.head().preexisting_effective_now(),
        );
        if repository.pending_discard()?.is_some() {
            service.resume_discard(proof.proof())?;
        } else {
            service.begin_discard(proof.into_parts().1)?;
        }
        self.boundary.check()?;
        Ok(RestartState::NewBlankDraft)
    }
}
