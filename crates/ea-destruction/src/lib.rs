#![forbid(unsafe_code)]
//! Verified destruction authorization and signed history. This crate's request
//! service atomically stores the native-authorized request and its signed audit.
//! Execution and managed-replica completion evidence belong to the executor.
mod authorization;
mod imported_preflight;
mod original_authority;
pub use imported_preflight::{
    ImportedPreflightTarget, PreflightTargetContext, VerifiedImportedPreflight,
    preflight_target_contexts,
};
mod attestation;
mod barrier;
mod event;
mod execution;
mod inventory;
mod job;
mod local;
mod local_attestation;
mod preflight;
mod purge;
mod reconstruct;
mod service;
mod state;
mod stub;
pub use attestation::{
    ManagedReplicaKind, VerifiedDeletionAttestation, verify_attestation_historical,
};
pub use authorization::{
    VerifiedDestructionAuthorization, VerifiedDestructionTarget, verify_authorization,
    verify_authorization_historical,
};
pub use barrier::{
    ConfirmedDeliveryBarrier, DeliveryBarrierEvidence, ServerReservationPort,
    confirm_delivery_barrier, confirm_no_registered_server,
};
pub use ea_verify::DestructionStateV1 as DestructionState;
pub use event::{VerifiedDestructionEvent, verify_event, verify_event_historical};
pub use execution::{DestructionExecutionContext, DurableDestructionStart};
pub use inventory::{DurableManagedInventory, ManagedArchiveRegistration, SqliteManagedCustody};
pub use job::{DurableDestructionJob, SqliteDestructionJobs};
pub use local::{
    LocalActionAuthorityGuard, LocalDestructionCheckpoint, LocalDestructionExecution,
    MeasuredLocalRemoval,
};
pub use local_attestation::LocalAttestationCheckpoint;
pub use preflight::{SignedDestructionPreflight, prepare_preflight, verify_preflight};
pub use purge::{AcquisitionPurgeCheckpoint, MeasuredAcquisitionRemoval};
pub use reconstruct::{
    EvidenceReplicaStatus, ReconstructedDestruction, VerifiedDestructionEvidence,
    project_imported_evidence, reconstruct_imported_history,
};
pub use service::{
    DestructionRequestService, RequestedDestruction, ResumedDestruction,
    SqliteDestructionRepository,
};
pub use state::{ApplyOutcome, DestructionStateMachine, transition_allowed};
pub use stub::{build_stub, verify_stub_against_original};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestructionError {
    Format,
    PrivacyGate,
    Registry,
    Approvers,
    Signature,
    Target,
    Event,
    SecurityConflict,
    Operator,
    Audit,
    Storage,
}
impl DestructionError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Format => "EA-DESTRUCTION-FORMAT",
            Self::PrivacyGate => "EA-DESTRUCTION-PRIVACY-GATE",
            Self::Registry => "EA-DESTRUCTION-REGISTRY",
            Self::Approvers => "EA-DESTRUCTION-APPROVERS",
            Self::Signature => "EA-DESTRUCTION-SIGNATURE",
            Self::Target => "EA-DESTRUCTION-TARGET",
            Self::Event => "EA-DESTRUCTION-EVENT",
            Self::SecurityConflict => "EA-DESTRUCTION-SECURITY-CONFLICT",
            Self::Operator => "EA-DESTRUCTION-OPERATOR",
            Self::Audit => "EA-DESTRUCTION-AUDIT",
            Self::Storage => "EA-DESTRUCTION-STORAGE",
        }
    }
}
impl core::fmt::Display for DestructionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for DestructionError {}
impl From<ea_format::FormatError> for DestructionError {
    fn from(_: ea_format::FormatError) -> Self {
        Self::Format
    }
}
impl From<ea_crypto::CryptoError> for DestructionError {
    fn from(_: ea_crypto::CryptoError) -> Self {
        Self::Signature
    }
}
impl From<ea_local_store::StoreError> for DestructionError {
    fn from(_: ea_local_store::StoreError) -> Self {
        Self::Storage
    }
}
impl From<ea_audit::AuditError> for DestructionError {
    fn from(_: ea_audit::AuditError) -> Self {
        Self::Audit
    }
}
