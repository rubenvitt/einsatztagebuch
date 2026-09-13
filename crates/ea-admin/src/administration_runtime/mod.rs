//! Native administration over the existing current operator authority.
mod activation;
pub mod authorization;
pub mod ceremony;
pub mod exchange;
pub mod inbox;
pub mod publication;
mod registration;
pub mod target;
pub(crate) mod root_exchange;
pub mod views;

/// Exact object whose bytes were compared through the second channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FingerprintSubjectV1 {
    RegistrationRequest,
    IssuedCertificate,
}
/// Dependent signed objects have distinct authorization and replay identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustCeremonyRoundV1 {
    IssueTarget,
    ActivateRegistry,
}

mod inbox_directory;

mod direct_intent;

pub mod transition;
