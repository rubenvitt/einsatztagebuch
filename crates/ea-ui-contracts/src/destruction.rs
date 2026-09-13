//! Public observations and bounded original delivery of the native destruction process.
//! These views confer no authority: each native action reopens and verifies its
//! own persisted job, policy and current operator before acting.

use crate::DestructionStateV1;
use ea_types::{ChainSequence, UnixMillis};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructionTargetView {
    pub entry_hash: String,
    pub chain_sequence: ChainSequence,
    pub stub_object_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructionPreflightView {
    pub job_hash: String,
    pub exact_canonical_report_json: String,
    pub known_replica_count: u32,
}

/// `result_code` is the verified attestation's existing 0/1/2 protocol code.
/// None means no attestation, and never claims that a replica was contacted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructionReplicaView {
    pub device_id: String,
    pub kind_code: u64,
    pub attestation_hash: Option<String>,
    pub result_code: Option<u64>,
    pub backup_expiry_at: Option<UnixMillis>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructionProcessView {
    pub destruction_id: String,
    pub authorization_object_hash: String,
    pub state: DestructionStateV1,
    pub scope_code: u64,
    pub legal_reason_code: u64,
    pub controller_device_id: String,
    pub custodian_device_id: String,
    pub approver_certificate_hashes: Vec<String>,
    pub targets: Vec<DestructionTargetView>,
    pub preflight: Option<DestructionPreflightView>,
    pub replicas: Vec<DestructionReplicaView>,
    pub evidence_entry_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructionAdministrationView {
    pub privacy_decision_enabled: bool,
    pub policy_hash: String,
    pub known_destruction_ids: Vec<String>,
    pub process: Option<DestructionProcessView>,
}

/// A public review of the separate normal Writer's prepared evidence draft.
/// The actual evidence, draft binding, presence and preview remain native.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructionEvidenceReviewView {
    pub writer_device_id: String,
    pub process: DestructionProcessView,
    pub preview: crate::FinalizationPreviewView,
}

/// Exact public originals selected by the native runtime for one Reader.
/// These are untrusted delivery inputs, not transferable native authority.
/// The IPC boundary bounds each ETB to 4 MiB and the existing upload to 64 MiB.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructionReaderDeliveryView {
    pub destruction_id: String,
    pub job_hash: String,
    pub reader_id: String,
    pub exact_authorization: Vec<u8>,
    pub exact_initiating_event: Vec<u8>,
    pub exact_job_upload: Vec<u8>,
}
