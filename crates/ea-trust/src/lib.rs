#![forbid(unsafe_code)]

mod anchor;
#[cfg_attr(not(test), allow(dead_code))]
mod certificate;
// Task 5 is the first production consumer of the private, validated index.
#[cfg_attr(not(test), allow(dead_code))]
mod catalog;
mod error;
#[cfg_attr(not(test), allow(dead_code))]
mod operator_binding;
#[cfg_attr(not(test), allow(dead_code))]
mod resolver;
mod source;
mod state;

pub use anchor::{TrustAnchorV1, VerifiedTrust, decode_trust_anchor, verify_trust};
pub use error::{TrustError, TrustSourceError};
pub use source::{MAX_TOTAL_TRUST_OBJECT_BYTES_V1, MAX_TRUST_OBJECTS_V1, TrustObjectSource};
pub use state::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, StateStoreError, TrustStateKey, TrustStateSnapshot, TrustStateStore,
    load_trust_state,
};
