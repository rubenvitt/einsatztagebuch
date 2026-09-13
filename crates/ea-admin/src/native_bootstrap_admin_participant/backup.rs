//! Read-only interpretation of an existing complete participant journal.
use super::{
    store::{self, Journal, NativeBootstrapParticipantStore},
    *,
};
use crate::{BootstrapStateV1, native_provider::NativeSigningSlot};
use ea_key_provider::{KeyProvider, SecretPurpose};
use ea_operator::OsAccountProvider as _;
use zeroize::Zeroizing;

pub(crate) struct ParticipantBackupContext {
    store: NativeBootstrapParticipantStore,
    journal: Journal,
    exact: Zeroizing<Vec<u8>>,
    native: Arc<NativeOperatorProvider>,
    organization: OrganizationId,
}
impl ParticipantBackupContext {
    pub(crate) fn open(
        state: &BootstrapStateV1,
        path: &Path,
        native: &Arc<NativeOperatorProvider>,
    ) -> Result<Self, OperatorLifecycleError> {
        let store = NativeBootstrapParticipantStore::open(path, native)?;
        let journal = store
            .transaction(|tx| store::read(tx)?.ok_or(OperatorLifecycleError::JournalConflict))?;
        if journal.state != state.persisted_image()
            || journal.installation != native.installation_id()
            || journal.admin.is_none()
            || journal.operator.is_none()
            || journal.commitment
                != ea_crypto::operator_profile_commitment(
                    state.organization_id(),
                    journal.identity.subject,
                    journal.identity.name.as_str(),
                    journal.identity.function.as_str(),
                    &journal.identity.salt,
                )
        {
            return Err(OperatorLifecycleError::JournalConflict);
        }
        let exact = journal.encode()?;
        let context = Self {
            store,
            journal,
            exact,
            native: Arc::clone(native),
            organization: state.organization_id(),
        };
        context.current()?;
        Ok(context)
    }
    pub(crate) fn public(&self) -> &CanonicalPublicCoseKey {
        self.journal
            .admin
            .as_ref()
            .expect("admitted complete journal")
    }
    fn current(&self) -> Result<(), OperatorLifecycleError> {
        self.native
            .ensure_session_active()
            .map_err(|_| OperatorLifecycleError::Readiness)?;
        if self.native.installation_id() != self.journal.installation
            || self
                .native
                .os_account_binding_hash(self.organization, self.journal.identity.device)?
                != self.journal.account
            || self
                .journal
                .admin
                .as_ref()
                .zip(self.journal.operator.as_ref())
                .is_some_and(|(a, b)| a == b)
        {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        let provider = self.native.signing_provider(NativeSigningSlot::Admin);
        for (expected, slot, purpose) in [
            (
                &self.journal.admin,
                NativeSigningSlot::Admin,
                SecretPurpose::WriterSigningKey,
            ),
            (
                &self.journal.operator,
                NativeSigningSlot::Operator,
                SecretPurpose::OperatorInstanceKey,
            ),
        ] {
            let handle = provider.handle(purpose);
            if !provider
                .contains(&handle)
                .map_err(|_| OperatorLifecycleError::Readiness)?
                || provider
                    .reached_protection_profile(&handle)
                    .map_err(|_| OperatorLifecycleError::Readiness)?
                    != KeyProtectionProfileV1::OsWrapped
                || self
                    .native
                    .public_key(slot)
                    .map_err(|_| OperatorLifecycleError::Readiness)?
                    .as_ref()
                    != expected.as_ref()
            {
                return Err(OperatorLifecycleError::TargetMismatch);
            }
        }
        self.native
            .ensure_session_active()
            .map_err(|_| OperatorLifecycleError::Readiness)
    }
    pub(crate) fn confirm(&self) -> Result<(), OperatorLifecycleError> {
        self.current()?;
        self.store.confirm(&self.exact)?;
        self.current()?;
        self.store.ensure_path()?;
        self.native
            .ensure_session_active()
            .map_err(|_| OperatorLifecycleError::Readiness)
    }
}
