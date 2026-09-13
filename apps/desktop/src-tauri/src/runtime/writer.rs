use super::{
    CONFIG_ERROR, NativeDesktopRuntime, drafts::repository, now, writer_config::WriterSettings,
};
use crate::{
    commands::{CommandError, PREVIEW_MISMATCH, PREVIEW_NOT_ISSUED},
    state::{BoundWriter, StartupRecoveryPort, WriterFinalizePort, WriterPreviewPort},
};
use ea_admin::{
    amendment::AmendmentDraftService, native_provider::NativeSigningSlot,
    operator_runtime::writer::InteractiveOperatorRuntime as OperatorRuntime,
};
use ea_archive::{ArchiveBackendProfileV1, BoundArchiveProfilePolicyV1};
use ea_archive_fs::{CapabilityTestVectorV1, LocalPathBackend};
use ea_destruction::SqliteManagedCustody;
use ea_draft::{IncidentNumberRegister, MasterDataRepository, OperatorProfileRepository};
use ea_key_provider::SecretPurpose;
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_ui_contracts::{
    AmendmentInputView, CorrectionReferenceView, FinalizationPreviewView, FinalizeOutcomeView,
    IncidentInputView,
};
use ea_writer::{
    FinalizationPreview, RecoveryOutcome, StaleRegistryAcknowledgement, StaleRegistryStore,
    WriterBindingV1, WriterError, WriterService,
};
use std::path::Path;

pub(super) struct WriterResources {
    backend: LocalPathBackend,
    timezone: String,
    profile_hash: ea_types::Hash32,
}
impl WriterResources {
    pub(super) fn open(path: &Path, runtime: &OperatorRuntime) -> Result<Self, CommandError> {
        if runtime.config().role != ea_format::OperatorRoleV1::Writer {
            return Err(CommandError::new(CONFIG_ERROR));
        }
        let config = WriterSettings::load(path)?;
        let profile = config.archive_profile;
        let profile_hash = profile
            .profile_hash()
            .map_err(|error| CommandError::new(error.code()))?;
        let vector_id = match &profile {
            ArchiveBackendProfileV1::LocalPath(profile) => {
                profile.capability_test_vector_id.clone()
            }
            ArchiveBackendProfileV1::ControlledNetworkPath(_) => {
                return Err(CommandError::new("EA-DESKTOP-NETWORK-COMMIT-UNAVAILABLE"));
            }
        };
        let backend = LocalPathBackend::open(
            runtime.config().archive_directory.clone(),
            profile,
            &BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields()),
        )
        .map_err(|error| CommandError::new(error.code()))?;
        let vector = CapabilityTestVectorV1::new(&vector_id, b"EINSATZARCHIV-NATIVE-CAPABILITY-v1")
            .map_err(|error| CommandError::new(error.code()))?;
        if !backend
            .run_capability_test(&vector)
            .map_err(|error| CommandError::new(error.code()))?
            .all_proven()
        {
            return Err(CommandError::new("EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS"));
        }
        SqliteManagedCustody::new(runtime.database().clone())
            .observe_writer_archive(
                runtime.head(),
                runtime.config().device_certificate_hash,
                &backend,
            )
            .map_err(|error| CommandError::new(error.code()))?;
        Ok(Self {
            backend,
            timezone: config.timezone,
            profile_hash,
        })
    }
}

struct WriterCall<'a> {
    service: &'a WriterService<'a>,
    proof: &'a OperatorSessionProof,
    master: &'a MasterDataRepository,
    timezone: &'a str,
    amendments: &'a AmendmentDraftService<'a, 'a>,
    clock: &'a (dyn Fn() -> ea_types::UnixMillis + Send + Sync),
    issued: Option<FinalizationPreview>,
    receipt: Option<StaleRegistryAcknowledgement>,
    stale_proof: Option<OperatorSessionProof>,
}
impl WriterCall<'_> {
    fn bound(&self) -> BoundWriter<'_> {
        BoundWriter::new(
            self.service,
            self.proof,
            self.master,
            self.timezone,
            self.issued.as_ref(),
        )
        .with_amendments(self.amendments, self.clock)
    }
    fn confirmed(
        &self,
        confirmed: &FinalizationPreviewView,
    ) -> Result<&FinalizationPreview, CommandError> {
        let issued = self
            .issued
            .as_ref()
            .ok_or_else(|| CommandError::new(PREVIEW_NOT_ISSUED))?;
        if FinalizationPreviewView::from(issued) != *confirmed {
            return Err(CommandError::new(PREVIEW_MISMATCH));
        }
        Ok(issued)
    }
}
struct WriterResult<T> {
    value: T,
    preview: Option<FinalizationPreview>,
    receipt: Option<StaleRegistryAcknowledgement>,
}
impl<T> WriterResult<T> {
    fn finished(value: T) -> Self {
        Self {
            value,
            preview: None,
            receipt: None,
        }
    }
}
impl NativeDesktopRuntime {
    fn writer_action<T>(
        &self,
        action: impl FnOnce(WriterCall<'_>) -> Result<WriterResult<T>, CommandError>,
    ) -> Result<T, CommandError> {
        let resources = self
            .writer
            .as_ref()
            .ok_or_else(|| CommandError::new("EA-DESKTOP-WRITER-UNAVAILABLE"))?;
        let (mut inner, epoch) = self
            .current_writer()
            .map_err(|error| CommandError::new(error.code()))?;
        let issued = inner.preview.take();
        let receipt = inner.stale_receipt.take();
        let stale_proof = inner
            .sessions
            .remove(&ReauthPurpose::RegistryStaleFinalize)
            .map(|session| session.into_parts().1);
        let session = inner
            .sessions
            .get(&ReauthPurpose::Finalize)
            .ok_or_else(|| CommandError::new(WriterError::ReauthRequired.code()))?;
        inner.verify(ReauthPurpose::Finalize, session)?;
        let runtime = &inner.runtime;
        SqliteManagedCustody::new(runtime.database().clone())
            .observe_writer_archive(
                runtime.head(),
                runtime.config().device_certificate_hash,
                &resources.backend,
            )
            .map_err(|error| CommandError::new(error.code()))?;
        let public = runtime
            .native()
            .public_key(NativeSigningSlot::Writer)
            .map_err(|error| CommandError::new(error.code()))?
            .ok_or_else(|| CommandError::new(WriterError::ReauthRequired.code()))?;
        let source = resources.backend.as_archive_source();
        let service = WriterService::new_for_writer(
            repository(&inner),
            runtime.signing_provider().clone(),
            &resources.backend,
            &source,
            runtime.head(),
            &[],
            IncidentNumberRegister::new(runtime.database().clone()),
            OperatorProfileRepository::new(runtime.database().clone()),
            WriterBindingV1 {
                binding_object_hash: runtime.config().binding_object_hash,
                writer_certificate_hash: runtime.config().device_certificate_hash,
                writer_key_thumbprint: public.thumbprint(),
                writer_signing_handle: runtime
                    .signing_provider()
                    .handle(SecretPurpose::WriterSigningKey),
                chain_id: runtime.anchor().chain_id(),
                archive_profile_hash: resources.profile_hash,
            },
        )
        .with_stale_registry_store(
            StaleRegistryStore::new(runtime.database().clone())
                .map_err(|error| CommandError::new(error.code()))?,
        );
        let amendments = AmendmentDraftService::new(&service, runtime.anchor());
        let observed = now()?;
        let clock = || observed;
        let outcome = action(WriterCall {
            service: &service,
            proof: session.proof(),
            master: &self.master_data,
            timezone: &resources.timezone,
            amendments: &amendments,
            clock: &clock,
            issued,
            receipt,
            stale_proof,
        })?;
        self.finish_draft_action(&mut inner, epoch)
            .map_err(|error| CommandError::new(error.code()))?;
        inner.preview = outcome.preview;
        inner.stale_receipt = outcome.receipt;
        Ok(outcome.value)
    }
}
impl WriterPreviewPort for NativeDesktopRuntime {
    fn preview(
        &self,
        incident: &IncidentInputView,
    ) -> Result<FinalizationPreviewView, CommandError> {
        self.writer_action(|call| {
            let preview = call
                .service
                .preview(call.proof, call.bound().input(incident)?, (call.clock)())
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult {
                value: FinalizationPreviewView::from(&preview),
                preview: Some(preview),
                receipt: None,
            })
        })
    }
    fn validate_amendment_reference(
        &self,
        reference: &CorrectionReferenceView,
    ) -> Result<(), CommandError> {
        self.writer_action(|call| {
            call.bound().validate_amendment_reference(reference)?;
            Ok(WriterResult::finished(()))
        })
    }
    fn preview_amendment(
        &self,
        input: &AmendmentInputView,
    ) -> Result<FinalizationPreviewView, CommandError> {
        self.writer_action(|call| {
            let preview = call
                .service
                .preview_amendment(
                    call.proof,
                    call.bound().prepare_amendment_input(input)?,
                    (call.clock)(),
                )
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult {
                value: FinalizationPreviewView::from(&preview),
                preview: Some(preview),
                receipt: None,
            })
        })
    }
}
impl WriterFinalizePort for NativeDesktopRuntime {
    fn finalize(
        &self,
        incident: &IncidentInputView,
        confirmed: &FinalizationPreviewView,
    ) -> Result<FinalizeOutcomeView, CommandError> {
        self.writer_action(|call| {
            let issued = call.confirmed(confirmed)?;
            let input = call.bound().input(incident)?;
            let outcome = match call.receipt.as_ref() {
                Some(receipt) => call.service.finalize_with_stale_registry(
                    call.proof,
                    input,
                    issued,
                    receipt,
                    (call.clock)(),
                ),
                None => call
                    .service
                    .finalize(call.proof, input, issued, (call.clock)()),
            }
            .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult::finished(FinalizeOutcomeView::new(
                &outcome, None,
            )))
        })
    }
    fn finalize_amendment(
        &self,
        input: &AmendmentInputView,
        confirmed: &FinalizationPreviewView,
    ) -> Result<FinalizeOutcomeView, CommandError> {
        self.writer_action(|call| {
            let issued = call.confirmed(confirmed)?;
            let input = call.bound().prepare_amendment_input(input)?;
            let outcome = match call.receipt.as_ref() {
                Some(receipt) => call.service.finalize_amendment_with_stale_registry(
                    call.proof,
                    input,
                    issued,
                    receipt,
                    (call.clock)(),
                ),
                None => call
                    .service
                    .finalize_amendment(call.proof, input, issued, (call.clock)()),
            }
            .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult::finished(FinalizeOutcomeView::new(
                &outcome, None,
            )))
        })
    }
    fn acknowledge_stale_registry(
        &self,
        incident: &IncidentInputView,
        confirmed: &FinalizationPreviewView,
        warning_confirmed: bool,
    ) -> Result<(), CommandError> {
        self.writer_action(|mut call| {
            let proof = call
                .stale_proof
                .take()
                .ok_or_else(|| CommandError::new(WriterError::ReauthRequired.code()))?;
            let receipt = call
                .service
                .acknowledge_stale_registry(
                    proof,
                    call.bound().input(incident)?,
                    call.confirmed(confirmed)?,
                    warning_confirmed,
                    (call.clock)(),
                )
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult {
                value: (),
                preview: call.issued,
                receipt: Some(receipt),
            })
        })
    }
    fn acknowledge_stale_amendment(
        &self,
        input: &AmendmentInputView,
        confirmed: &FinalizationPreviewView,
        warning_confirmed: bool,
    ) -> Result<(), CommandError> {
        self.writer_action(|mut call| {
            let proof = call
                .stale_proof
                .take()
                .ok_or_else(|| CommandError::new(WriterError::ReauthRequired.code()))?;
            let receipt = call
                .service
                .acknowledge_stale_amendment(
                    proof,
                    call.bound().prepare_amendment_input(input)?,
                    call.confirmed(confirmed)?,
                    warning_confirmed,
                    (call.clock)(),
                )
                .map_err(|error| CommandError::new(error.code()))?;
            Ok(WriterResult {
                value: (),
                preview: call.issued,
                receipt: Some(receipt),
            })
        })
    }
}
impl StartupRecoveryPort for NativeDesktopRuntime {
    fn resolve_pending_finalization(&self) -> Result<RecoveryOutcome, WriterError> {
        let mut operation = None;
        self.writer_action(|call| {
            operation = Some(call.service.recover_pending());
            Ok(WriterResult::finished(()))
        })
        .map_err(|_| WriterError::ReauthRequired)?;
        operation.expect("the guarded action completed")
    }
}
