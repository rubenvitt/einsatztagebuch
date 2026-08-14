#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as ea_trust;

#[cfg_attr(not(test), allow(dead_code))]
mod admin_authorization;
mod anchor;
#[cfg_attr(not(test), allow(dead_code))]
mod certificate;
// Task 5 is the first production consumer of the private, validated index.
#[cfg_attr(not(test), allow(dead_code))]
mod catalog;
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

pub use admin_authorization::VerifiedAdminAuthorization;
pub use anchor::{TrustAnchorV1, VerifiedTrust, decode_trust_anchor, verify_trust};
pub use error::{RegistryError, TrustError, TrustSourceError};
pub use registry::{PreexistingRegistryAuthority, RegistryCandidate, verify_registry_candidate};
pub use source::{MAX_TOTAL_TRUST_OBJECT_BYTES_V1, MAX_TRUST_OBJECTS_V1, TrustObjectSource};
pub use state::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, StateStoreError, TrustStateKey, TrustStateSnapshot, TrustStateStore,
    load_trust_state,
};
pub use time::{VerifiedSignedTime, verify_checkpoint_time, verify_receipt_time};
