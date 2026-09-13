use super::{NativeDesktopRuntime, NativeState};
use crate::state::{DraftDiscardPort, DraftPayloadPort};
use ea_draft::{
    AutosaveDraftRepository, DiscardService, DraftError, DraftRepository, RestartState,
};
use ea_format::OperatorRoleV1;
use ea_operator::ReauthPurpose;
use std::sync::{Arc, MutexGuard, atomic::Ordering};
use zeroize::Zeroize;

impl NativeDesktopRuntime {
    pub(super) fn current_writer(&self) -> Result<(MutexGuard<'_, NativeState>, u64), DraftError> {
        let epoch = self.session_epoch.load(Ordering::SeqCst);
        if epoch & 1 != 0 || self.role != OperatorRoleV1::Writer {
            return Err(DraftError::ReauthRequired);
        }
        let mut inner = self.inner.lock().map_err(|_| DraftError::ReauthRequired)?;
        if self.session_epoch.load(Ordering::SeqCst) != epoch {
            return Err(DraftError::ReauthRequired);
        }
        inner.refresh().map_err(|_| DraftError::ReauthRequired)?;
        if inner.sessions.is_empty()
            || !inner
                .sessions
                .iter()
                .any(|(purpose, session)| inner.verify(*purpose, session).is_ok())
            || self.session_epoch.load(Ordering::SeqCst) != epoch
        {
            inner.invalidate();
            return Err(DraftError::ReauthRequired);
        }
        Ok((inner, epoch))
    }

    pub(super) fn finish_draft_action(
        &self,
        inner: &mut NativeState,
        epoch: u64,
    ) -> Result<(), DraftError> {
        if self.session_epoch.load(Ordering::SeqCst) != epoch
            || inner.runtime.native().ensure_session_active().is_err()
        {
            inner.invalidate();
            return Err(DraftError::ReauthRequired);
        }
        Ok(())
    }
}

pub(super) fn repository(inner: &NativeState) -> Arc<AutosaveDraftRepository> {
    Arc::new(AutosaveDraftRepository::new(
        inner.runtime.database().clone(),
        inner.runtime.signing_provider().clone(),
    ))
}

impl DraftPayloadPort for NativeDesktopRuntime {
    fn load_payload(&self) -> Result<String, DraftError> {
        let (mut inner, epoch) = self.current_writer()?;
        let draft = repository(&inner).load_or_create()?;
        self.finish_draft_action(&mut inner, epoch)?;
        // The Draft owns and zeroizes the plaintext if any final check fails.
        Ok(draft.notes().to_owned())
    }

    fn save_payload(&self, mut payload: String) -> Result<(), DraftError> {
        let (mut inner, epoch) = match self.current_writer() {
            Ok(value) => value,
            Err(error) => {
                payload.zeroize();
                return Err(error);
            }
        };
        inner.preview = None;
        inner.stale_receipt = None;
        inner.sessions.remove(&ReauthPurpose::RegistryStaleFinalize);
        let repository = repository(&inner);
        let draft = match repository.load_or_create() {
            Ok(draft) => draft,
            Err(error) => {
                payload.zeroize();
                return Err(error);
            }
        };
        repository.save(draft.with_notes(payload))?;
        self.finish_draft_action(&mut inner, epoch)
    }
}

impl DraftDiscardPort for NativeDesktopRuntime {
    fn begin(&self) -> Result<RestartState, DraftError> {
        let (mut inner, epoch) = self.current_writer()?;
        let session = inner
            .sessions
            .remove(&ReauthPurpose::DiscardDraft)
            .ok_or(DraftError::ReauthRequired)?;
        inner
            .verify(ReauthPurpose::DiscardDraft, &session)
            .map_err(|_| DraftError::ReauthRequired)?;
        inner.preview = None;
        inner.stale_receipt = None;
        inner.sessions.remove(&ReauthPurpose::RegistryStaleFinalize);
        let head = inner.runtime.head();
        let service = DiscardService::new(
            repository(&inner),
            inner.runtime.signing_provider().clone(),
            inner.runtime.config().binding_object_hash,
            head.preexisting_effective_now(),
        );
        service.begin_discard(session.into_parts().1)?;
        self.finish_draft_action(&mut inner, epoch)?;
        Ok(RestartState::NewBlankDraft)
    }

    fn resume(&self) -> Result<RestartState, DraftError> {
        let (mut inner, epoch) = self.current_writer()?;
        let session = inner
            .sessions
            .get(&ReauthPurpose::DiscardDraft)
            .ok_or(DraftError::ReauthRequired)?;
        inner
            .verify(ReauthPurpose::DiscardDraft, session)
            .map_err(|_| DraftError::ReauthRequired)?;
        let head = inner.runtime.head();
        let service = DiscardService::new(
            repository(&inner),
            inner.runtime.signing_provider().clone(),
            inner.runtime.config().binding_object_hash,
            head.preexisting_effective_now(),
        );
        let state = match service.resume_discard(session.proof()) {
            Ok(_) => RestartState::NewBlankDraft,
            Err(DraftError::NoPendingDiscard | DraftError::PreparedFinalizationPresent) => {
                service.resume_after_restart(session.proof())?
            }
            Err(error) => return Err(error),
        };
        inner.preview = None;
        inner.stale_receipt = None;
        inner.sessions.remove(&ReauthPurpose::RegistryStaleFinalize);
        self.finish_draft_action(&mut inner, epoch)?;
        Ok(state)
    }
}
