//! Local preparation of exactly one native participant. No certificate or Step 3 authority.

mod service;
mod store;

use crate::{FileBootstrapStore, OperatorLifecycleError, native_provider::NativeOperatorProvider};
use ea_crypto::CanonicalPublicCoseKey;
use ea_format::KeyProtectionProfileV1;
use ea_schema::{OperatorSnapshotV1, SecretText};
use ea_types::{ChainId, DeviceId, Hash32, OperatorSubjectId, OrganizationId};
use std::{path::Path, sync::Arc};

/// Explicit trusted-local participant attribution. Text is private and NFC-normalized;
/// attribution alone is not proof of an independently identified human or OS account.
pub struct BootstrapAdminParticipantIdentity {
    device: DeviceId,
    subject: OperatorSubjectId,
    name: SecretText,
    function: SecretText,
    salt: zeroize::Zeroizing<[u8; 32]>,
}

impl BootstrapAdminParticipantIdentity {
    #[must_use]
    pub fn new(
        device: DeviceId,
        subject: OperatorSubjectId,
        display_name: impl Into<String>,
        function_label: impl Into<String>,
        salt: [u8; 32],
    ) -> Self {
        let (name, function) =
            OperatorSnapshotV1::normalize_profile_texts(display_name, function_label);
        Self {
            device,
            subject,
            name,
            function,
            salt: zeroize::Zeroizing::new(salt),
        }
    }
}

/// Public local result only. This does not certify an Admin, confirm a backup,
/// establish two independent accounts, or advance the bootstrap ceremony.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedNativeBootstrapAdminParticipant {
    organization: OrganizationId,
    chain: ChainId,
    device: DeviceId,
    subject: OperatorSubjectId,
    admin: CanonicalPublicCoseKey,
    operator: CanonicalPublicCoseKey,
    account: Hash32,
    commitment: Hash32,
}

impl std::fmt::Debug for PreparedNativeBootstrapAdminParticipant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedNativeBootstrapAdminParticipant(<local public material>)")
    }
}

impl PreparedNativeBootstrapAdminParticipant {
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization
    }
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain
    }
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device
    }
    #[must_use]
    pub const fn operator_subject_id(&self) -> OperatorSubjectId {
        self.subject
    }
    #[must_use]
    pub fn admin_public_key(&self) -> &CanonicalPublicCoseKey {
        &self.admin
    }
    #[must_use]
    pub fn operator_public_key(&self) -> &CanonicalPublicCoseKey {
        &self.operator
    }
    #[must_use]
    pub const fn os_account_binding_hash(&self) -> Hash32 {
        self.account
    }
    #[must_use]
    pub const fn profile_commitment(&self) -> Hash32 {
        self.commitment
    }
    #[must_use]
    pub const fn protection_profile(&self) -> KeyProtectionProfileV1 {
        KeyProtectionProfileV1::OsWrapped
    }
}

/// Prepares or resumes one participant in an existing native SQLCipher database.
/// Requires the actual retained ceremony lease and an exact completed Root step.
/// Never creates a database, replaces a key, signs a Root certificate or commits Step 3.
///
/// # Errors
/// Refuses inconsistent predecessors, missing originals, native/DB mismatches,
/// occupied unassigned keys, ambiguous generation outcomes and invalid presence.
pub fn prepare_native_bootstrap_admin_participant(
    ceremony: &mut FileBootstrapStore,
    participant_database_path: &Path,
    native: &Arc<NativeOperatorProvider>,
    identity: BootstrapAdminParticipantIdentity,
) -> Result<PreparedNativeBootstrapAdminParticipant, OperatorLifecycleError> {
    service::prepare(ceremony, participant_database_path, native, identity)
}

mod backup;
pub(crate) use backup::ParticipantBackupContext;
