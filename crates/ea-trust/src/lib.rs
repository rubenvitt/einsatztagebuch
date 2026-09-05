//! Opaque trust proofs are produced only by their verified state transitions.
//! The following compile contracts close the remaining raw-construction and
//! authority-substitution boundaries.
//!
//! `VerifiedSignedTime` cannot be assembled from caller-controlled fields:
//!
//! ```compile_fail
//! use ea_trust::VerifiedSignedTime;
//! let _ = VerifiedSignedTime { input: panic!(), authority_head: panic!() };
//! ```
//!
//! `VerifiedAdminAuthorization` cannot be assembled from raw authorization
//! metadata:
//!
//! ```compile_fail
//! use ea_trust::VerifiedAdminAuthorization;
//! let _ = VerifiedAdminAuthorization { inner: panic!() };
//! ```
//!
//! `VerifiedAdminAuthorizationIntent` — the proof state for the time before
//! the Root signature — is no more constructible than the published one:
//!
//! ```compile_fail
//! use ea_trust::VerifiedAdminAuthorizationIntent;
//! let _ = VerifiedAdminAuthorizationIntent { inner: panic!() };
//! ```
//!
//! `AdminAuthorizationReplayKey` cannot be assembled from raw identifiers, so
//! no caller can mark a foreign authorization as consumed:
//!
//! ```compile_fail
//! use ea_trust::AdminAuthorizationReplayKey;
//! let _ = AdminAuthorizationReplayKey {
//!     organization_id: panic!(),
//!     dimension: panic!(),
//! };
//! ```
//!
//! `PreexistingRegistryAuthority` cannot be assembled from a caller-selected
//! resolver state:
//!
//! ```compile_fail
//! use ea_trust::PreexistingRegistryAuthority;
//! let _ = PreexistingRegistryAuthority { inner: panic!() };
//! ```
//!
//! `RegistryCandidate` cannot be assembled from raw hashes and times:
//!
//! ```compile_fail
//! use ea_trust::RegistryCandidate;
//! let _ = RegistryCandidate {
//!     registry_version: panic!(),
//!     registry_head_hash: panic!(),
//!     preexisting_authority: panic!(),
//!     candidate_state: panic!(),
//!     target_policy: panic!(),
//!     guard_policy: panic!(),
//!     head_event: panic!(),
//!     state_key: panic!(),
//!     state_revision: panic!(),
//!     trusted_time: panic!(),
//!     original_pin: panic!(),
//!     proposed_sequence: panic!(),
//!     pre_transition_sequence: panic!(),
//!     fallback_barrier: panic!(),
//! };
//! ```
//!
//! `PreexistingEffectiveNow` cannot be assembled from a raw time:
//!
//! ```compile_fail
//! use ea_trust::PreexistingEffectiveNow;
//! let _ = PreexistingEffectiveNow { value: panic!() };
//! ```
//!
//! `VerifiedTrust` cannot be assembled from a caller-selected catalog:
//!
//! ```compile_fail
//! use ea_trust::VerifiedTrust;
//! let _ = VerifiedTrust { inner: panic!() };
//! ```
//!
//! `LocalTimeBlock` cannot be assembled around a caller-selected store and
//! evaluation:
//!
//! ```compile_fail
//! use ea_trust::LocalTimeBlock;
//! let _: LocalTimeBlock<'static> = LocalTimeBlock {
//!     store: panic!(),
//!     candidate_state: panic!(),
//!     state_key: panic!(),
//!     expected_revision: panic!(),
//!     trusted_time: panic!(),
//!     pinned_head: panic!(),
//!     observed_os_wall_clock: panic!(),
//!     candidate_registry_version: panic!(),
//!     candidate_registry_head_hash: panic!(),
//!     guard_policy_object_hash: panic!(),
//!     proposed_sequence: panic!(),
//!     pre_transition_sequence: panic!(),
//!     evaluation: panic!(),
//! };
//! ```
//!
//! Raw hashes, times, roles, and capability strings cannot substitute for any
//! verified proof:
//!
//! ```compile_fail
//! use ea_trust::VerifiedTrust;
//! use ea_types::{Hash32, ObjectHash};
//! let _: VerifiedTrust = ObjectHash::from(Hash32::ZERO).into();
//! ```
//!
//! ```compile_fail
//! use ea_trust::PreexistingEffectiveNow;
//! use ea_types::UnixMillis;
//! let _: PreexistingEffectiveNow = UnixMillis::new(0).into();
//! ```
//!
//! ```compile_fail
//! use ea_format::OperatorRoleV1;
//! use ea_trust::VerifiedAdminAuthorization;
//! let _: VerifiedAdminAuthorization = OperatorRoleV1::Reader.into();
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdminAuthorizationReplayKey;
//! use ea_types::{AuthorizationId, Id16};
//! let _: AdminAuthorizationReplayKey = AuthorizationId::from(Id16::ZERO).into();
//! ```
//!
//! An intent is not a published target: the two proof states do not convert
//! into one another.
//!
//! ```compile_fail
//! use ea_trust::{VerifiedAdminAuthorization, VerifiedAdminAuthorizationIntent};
//! fn reject(intent: VerifiedAdminAuthorizationIntent) -> VerifiedAdminAuthorization {
//!     intent.into()
//! }
//! ```
//!
//! ```compile_fail
//! use ea_trust::RegistryCandidate;
//! let _: RegistryCandidate = vec![String::from("initialGrant")].into();
//! ```
//!
//! A candidate is not a certificate resolver:
//!
//! ```compile_fail
//! use ea_crypto::SignerCertificateResolver;
//! use ea_trust::RegistryCandidate;
//! fn require_resolver(_: &dyn SignerCertificateResolver) {}
//! fn reject(candidate: &RegistryCandidate) { require_resolver(candidate); }
//! ```
//!
//! Preexisting authority remains private to verification and is not itself a
//! public certificate resolver:
//!
//! ```compile_fail
//! use ea_crypto::SignerCertificateResolver;
//! use ea_trust::PreexistingRegistryAuthority;
//! fn require_resolver(_: &dyn SignerCertificateResolver) {}
//! fn reject(authority: &PreexistingRegistryAuthority) { require_resolver(authority); }
//! ```
//!
//! A pending successor is not operation authority:
//!
//! ```compile_fail
//! use ea_crypto::SignerCertificateResolver;
//! use ea_trust::PendingFutureSuccessor;
//! fn require_resolver(_: &dyn SignerCertificateResolver) {}
//! fn reject(pending: &PendingFutureSuccessor) { require_resolver(pending); }
//! ```
//!
//! An advanced catch-up result is not operation authority:
//!
//! ```compile_fail
//! use ea_crypto::SignerCertificateResolver;
//! use ea_trust::AdvancedRegistryHead;
//! fn require_resolver(_: &dyn SignerCertificateResolver) {}
//! fn reject(advanced: &AdvancedRegistryHead) { require_resolver(advanced); }
//! ```
//!
//! The non-selected states expose none of the active authority views. Each
//! method boundary is compiled independently so one absent method cannot mask
//! another accidentally exposed method:
//!
//! ```compile_fail
//! use ea_trust::RegistryCandidate;
//! fn reject(value: &RegistryCandidate) { let _ = value.active_certificate_fields(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::RegistryCandidate;
//! fn reject(value: &RegistryCandidate) { let _ = value.active_capabilities(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::RegistryCandidate;
//! fn reject(value: &RegistryCandidate) { let _ = value.active_operator_binding_fields(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PreexistingRegistryAuthority;
//! fn reject(value: &PreexistingRegistryAuthority) { let _ = value.active_certificate_fields(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PreexistingRegistryAuthority;
//! fn reject(value: &PreexistingRegistryAuthority) { let _ = value.active_capabilities(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PreexistingRegistryAuthority;
//! fn reject(value: &PreexistingRegistryAuthority) { let _ = value.active_operator_binding_fields(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.active_certificate_fields(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.active_capabilities(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.active_operator_binding_fields(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! fn reject(value: &AdvancedRegistryHead) { let _ = value.active_certificate_fields(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! fn reject(value: &AdvancedRegistryHead) { let _ = value.active_capabilities(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! fn reject(value: &AdvancedRegistryHead) { let _ = value.active_operator_binding_fields(panic!()); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! fn reject(value: &AdvancedRegistryHead) { let _ = value.policy_fields(); }
//! ```
//!
//! Pending outcomes expose no diagnostic or authority getters:
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.registry_version(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.registry_head_hash(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.policy_object_hash(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.policy_fields(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.effective_from_sequence(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.valid_through_sequence(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.proposed_sequence(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.preexisting_effective_now(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.warnings(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! fn reject(value: &PendingFutureSuccessor) { let _ = value.committed_revision(); }
//! ```
//!
//! Advanced outcomes expose exactly version, Head hash, and committed
//! revision, but no selected-Head details:
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! fn reject(value: &AdvancedRegistryHead) { let _ = value.policy_object_hash(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! fn reject(value: &AdvancedRegistryHead) { let _ = value.effective_from_sequence(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! fn reject(value: &AdvancedRegistryHead) { let _ = value.valid_through_sequence(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! fn reject(value: &AdvancedRegistryHead) { let _ = value.proposed_sequence(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! fn reject(value: &AdvancedRegistryHead) { let _ = value.preexisting_effective_now(); }
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! fn reject(value: &AdvancedRegistryHead) { let _ = value.warnings(); }
//! ```
//!
//! `RegistryCandidate` remains single-use:
//!
//! ```compile_fail
//! use ea_trust::RegistryCandidate;
//! fn require_clone<T: Clone>() {}
//! require_clone::<RegistryCandidate>();
//! ```
//!
//! None of the public proof-state types has a default value:
//!
//! ```compile_fail
//! use ea_trust::VerifiedSignedTime;
//! let _: VerifiedSignedTime = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::VerifiedAdminAuthorization;
//! let _: VerifiedAdminAuthorization = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::PreexistingRegistryAuthority;
//! let _: PreexistingRegistryAuthority = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdminAuthorizationReplayKey;
//! let _: AdminAuthorizationReplayKey = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::VerifiedAdminAuthorizationIntent;
//! let _: VerifiedAdminAuthorizationIntent = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! let _: PendingFutureSuccessor = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! let _: AdvancedRegistryHead = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::RegistryCandidate;
//! let _: RegistryCandidate = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::VerifiedClockRelease;
//! let _: VerifiedClockRelease = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::PreexistingEffectiveNow;
//! let _: PreexistingEffectiveNow = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::SelectedRegistryHead;
//! let _: SelectedRegistryHead = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::VerifiedTrust;
//! let _: VerifiedTrust = Default::default();
//! ```
//!
//! ```compile_fail
//! use ea_trust::LocalTimeBlock;
//! let _: LocalTimeBlock<'static> = Default::default();
//! ```
//!
//! Nor can any proof state be deserialized directly from caller-controlled
//! CBOR:
//!
//! ```compile_fail
//! use ea_trust::VerifiedSignedTime;
//! let _: VerifiedSignedTime = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::VerifiedAdminAuthorization;
//! let _: VerifiedAdminAuthorization = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::PreexistingRegistryAuthority;
//! let _: PreexistingRegistryAuthority = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdminAuthorizationReplayKey;
//! let _: AdminAuthorizationReplayKey = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::VerifiedAdminAuthorizationIntent;
//! let _: VerifiedAdminAuthorizationIntent = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::PendingFutureSuccessor;
//! let _: PendingFutureSuccessor = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::AdvancedRegistryHead;
//! let _: AdvancedRegistryHead = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::RegistryCandidate;
//! let _: RegistryCandidate = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::VerifiedClockRelease;
//! let _: VerifiedClockRelease = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::PreexistingEffectiveNow;
//! let _: PreexistingEffectiveNow = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::SelectedRegistryHead;
//! let _: SelectedRegistryHead = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::VerifiedTrust;
//! let _: VerifiedTrust = minicbor::decode(&[]).unwrap();
//! ```
//!
//! ```compile_fail
//! use ea_trust::LocalTimeBlock;
//! let _: LocalTimeBlock<'static> = minicbor::decode(&[]).unwrap();
//! ```
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as ea_trust;

#[cfg_attr(not(test), allow(dead_code))]
mod admin_authorization;
mod admission;
mod anchor;
#[cfg_attr(not(test), allow(dead_code))]
mod certificate;
// Task 5 is the first production consumer of the private, validated index.
#[cfg_attr(not(test), allow(dead_code))]
mod catalog;
mod clock_release;
mod error;
#[cfg_attr(not(test), allow(dead_code))]
mod operator_binding;
mod policy;
mod registry;
#[cfg_attr(not(test), allow(dead_code))]
mod resolver;
mod source;
mod state;
mod time;

pub use admin_authorization::{
    VerifiedAdminAuthorization, VerifiedAdminAuthorizationIntent, consume_admin_authorization,
    consume_admin_authorization_intent, verify_authorized_trust_target,
    verify_intended_trust_target,
};
pub use admission::{bootstrap_active_certificates, verify_catalogue_admission};
pub use anchor::{
    PreAnchorV1, TrustAnchorV1, VerifiedTrust, decode_pre_anchor, decode_trust_anchor,
    encode_pre_anchor_v1, verify_trust,
};
pub use clock_release::{VerifiedClockRelease, verify_clock_release};
pub use error::{ClockReleaseError, RegistryError, TrustError, TrustSourceError};
pub use registry::{
    AdvancedRegistryHead, PendingFutureSuccessor, PreexistingEffectiveNow,
    PreexistingRegistryAuthority, RegistryCandidate, RegistrySelectionOutcome,
    SelectedRegistryHead, select_registry_head, verify_current_head_fallback,
    verify_registry_candidate,
};
pub use source::{MAX_TOTAL_TRUST_OBJECT_BYTES_V1, MAX_TRUST_OBJECTS_V1, TrustObjectSource};
pub use state::{
    AdminAuthorizationReplayDimension, AdminAuthorizationReplayKey, ClockReleaseReplayKey,
    IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin, RegistrySelectionCommit,
    StateStoreError, TrustStateKey, TrustStateSnapshot, TrustStateStore, load_trust_state,
};
pub use time::{
    LocalTimeBlock, VerifiedSignedTime, prepare_local_time, verify_checkpoint_time,
    verify_receipt_time,
};
