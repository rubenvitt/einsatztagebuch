use core::fmt;

use ea_time::TrustedTimeState;
use ea_types::{DeviceId, ObjectHash, OrganizationId, RegistryVersion};

use crate::TrustError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TrustStateKey {
    pub organization_id: OrganizationId,
    pub device_id: DeviceId,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RegistryHeadPin {
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
}

impl RegistryHeadPin {
    #[must_use]
    pub const fn new(registry_version: RegistryVersion, registry_head_hash: ObjectHash) -> Self {
        Self {
            registry_version,
            registry_head_hash,
        }
    }

    #[must_use]
    pub const fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }

    #[must_use]
    pub const fn registry_head_hash(&self) -> ObjectHash {
        self.registry_head_hash
    }
}

pub struct PersistedTrustRecord {
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
}

impl PersistedTrustRecord {
    #[must_use]
    pub const fn new(
        revision: u64,
        trusted_time: TrustedTimeState,
        pinned_head: Option<RegistryHeadPin>,
    ) -> Self {
        Self {
            revision,
            trusted_time,
            pinned_head,
        }
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn trusted_time(&self) -> &TrustedTimeState {
        &self.trusted_time
    }

    #[must_use]
    pub const fn pinned_head(&self) -> Option<&RegistryHeadPin> {
        self.pinned_head.as_ref()
    }
}

pub struct TrustStateSnapshot {
    key: TrustStateKey,
    record: PersistedTrustRecord,
}

impl TrustStateSnapshot {
    #[must_use]
    pub const fn key(&self) -> TrustStateKey {
        self.key
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.record.revision()
    }

    #[must_use]
    pub const fn trusted_time(&self) -> &TrustedTimeState {
        self.record.trusted_time()
    }

    #[must_use]
    pub const fn pinned_head(&self) -> Option<&RegistryHeadPin> {
        self.record.pinned_head()
    }
}

pub struct ClockReleaseReplayKey {
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    nonce: [u8; 32],
}

impl ClockReleaseReplayKey {
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
}

pub struct IndependentTimeCommit {
    next_trusted_time: TrustedTimeState,
}

impl IndependentTimeCommit {
    pub(crate) const fn new(next_trusted_time: TrustedTimeState) -> Self {
        Self { next_trusted_time }
    }

    #[must_use]
    pub const fn next_trusted_time(&self) -> &TrustedTimeState {
        &self.next_trusted_time
    }
}

pub struct RegistrySelectionCommit {
    next_trusted_time: TrustedTimeState,
    next_head: RegistryHeadPin,
    replay_key: Option<ClockReleaseReplayKey>,
}

impl RegistrySelectionCommit {
    #[must_use]
    pub const fn next_trusted_time(&self) -> &TrustedTimeState {
        &self.next_trusted_time
    }

    #[must_use]
    pub const fn next_head(&self) -> &RegistryHeadPin {
        &self.next_head
    }

    #[must_use]
    pub const fn replay_key(&self) -> Option<&ClockReleaseReplayKey> {
        self.replay_key.as_ref()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum StateStoreError {
    Conflict,
    ReplayAlreadyConsumed,
    MonotonicityViolation,
    Unavailable,
}

impl StateStoreError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Conflict => "EA-TRUST-STATE-CONFLICT",
            Self::ReplayAlreadyConsumed => "EA-TRUST-CLOCK-RELEASE-REPLAY",
            Self::MonotonicityViolation => "EA-TRUST-STATE-MONOTONICITY",
            Self::Unavailable => "EA-TRUST-STATE-UNAVAILABLE",
        }
    }
}

impl fmt::Display for StateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for StateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for StateStoreError {}

pub trait TrustStateStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError>;

    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError>;

    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError>;

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError>;
}

pub fn load_trust_state(
    store: &mut dyn TrustStateStore,
    key: TrustStateKey,
) -> Result<TrustStateSnapshot, TrustError> {
    let record = store.load(key).map_err(map_store_error)?;
    if record
        .trusted_time()
        .independent_reference()
        .is_some_and(|reference| reference.verified_time() > record.trusted_time().floor())
    {
        return Err(TrustError::StateMonotonicity);
    }
    Ok(TrustStateSnapshot { key, record })
}

pub(crate) const fn map_store_error(error: StateStoreError) -> TrustError {
    match error {
        StateStoreError::Conflict => TrustError::StateConflict,
        StateStoreError::ReplayAlreadyConsumed => TrustError::ClockReleaseReplay,
        StateStoreError::MonotonicityViolation => TrustError::StateMonotonicity,
        StateStoreError::Unavailable => TrustError::StateUnavailable,
    }
}
