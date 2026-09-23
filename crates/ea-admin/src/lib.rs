//! Die administrative Wurzelzeremonie.
//!
//! Diese Crate liegt OBERHALB von `ea-trust`, `ea-crypto`, `ea-format`,
//! `ea-key-provider`, `ea-audit` und `ea-operator`, und der Grund ist eine
//! Schichtungsentscheidung und keine Ablage: der Zeremoniendienst schreibt eine
//! lokale Auditzeile, `ea-audit` traegt aber bewusst KEINE `ea-trust`-Kante
//! (`crates/ea-audit/src/repository.rs`). Eine Audit-Anbindung innerhalb von
//! `ea-trust` kehrte die Schichtung um. `ea-trust` waechst durch diese Crate um
//! keine einzige Abhaengigkeit.
//!
//! Sie fuegt der Vertrauensschicht KEINE Regel hinzu. Geprueft wird weiterhin
//! ausschliesslich in `ea-trust` — [`ea_trust::verify_authorized_trust_target`]
//! gibt den Beweiszustand heraus, [`ea_trust::consume_admin_authorization`]
//! verbraucht ihn. Diese Crate ordnet die Schritte an und haelt fest, dass sie
//! stattgefunden haben.
//!
//! # Der Beweiszustand ist die einzige Eintrittskarte
//!
//! [`RootCeremonyService::publish_authorized_target`] nimmt einen
//! [`ea_trust::VerifiedAdminAuthorization`] entgegen und nichts, was ihn
//! ersetzen koennte. Der Typ ist ausserhalb von `ea-trust` nicht frei baubar;
//! ein Aufrufer kann sich die Erlaubnis also nicht selbst ausstellen:
//!
//! ```compile_fail
//! use ea_trust::VerifiedAdminAuthorization;
//!
//! fn forge() -> VerifiedAdminAuthorization {
//!     VerifiedAdminAuthorization::default()
//! }
//! ```
//!
//! Und die herausgegebenen Zielbytes sind ausschliesslich das, was
//! `ea_format::encode_trust` gebaut hat — `ExactObjectBytes::new` ist
//! `pub(crate)` in `ea-format`:
//!
//! ```compile_fail
//! use ea_format::ExactObjectBytes;
//!
//! fn forge(bytes: Vec<u8>) -> ExactObjectBytes {
//!     ExactObjectBytes::new(bytes)
//! }
//! ```
//!
//! Der positive Gegenzeuge, damit die beiden obigen an ihrem Gegenstand
//! scheitern und nicht an ihren Importen:
//!
//! ```
//! use ea_admin::AdminError;
//!
//! assert_eq!(AdminError::AuditFailed.code(), "EA-CEREMONY-AUDIT-FAILED");
//! // Der Wiedereinspielbefund behaelt den Code seiner Herkunft.
//! assert_eq!(
//!     AdminError::Trust(ea_trust::TrustError::AuthReplay).code(),
//!     "EA-TRUST-AUTH-REPLAY"
//! );
//! let _ = ea_format::encode_trust;
//! ```
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as ea_admin;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

mod native_bootstrap_admin_participant;
mod native_bootstrap_root;
pub use native_bootstrap_admin_participant::{
    BootstrapAdminParticipantIdentity, PreparedNativeBootstrapAdminParticipant,
    prepare_native_bootstrap_admin_participant,
};
mod native_identity;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use native_bootstrap_root::complete_native_root_step_with_test_opener;
pub use native_bootstrap_root::{
    NativeInitialRootV1, complete_installed_native_root_step, complete_native_root_step,
    prepare_native_root_for_ceremony, sign_native_initial_root,
};
mod native_process;
mod native_watch;

pub mod administration_runtime;
pub mod amendment;
pub mod anchor_media;
pub mod bootstrap;
pub mod bootstrap_store;
pub mod genesis;
pub mod native_archive;
pub mod native_provider;
pub mod network_publication;
pub mod operator_authority;
pub mod operator_ceremony;
pub mod operator_exchange;
mod operator_remote;
pub mod operator_runtime;
pub mod recovery_test_runtime;
pub use operator_runtime::posture;
pub mod destruction_runtime;
pub mod historical_grant;
pub mod production_state;
pub mod reader_key_escrow_inbox;
pub mod reader_key_escrow_opening;
pub mod reader_key_escrow_publication;

pub mod ceremony_steps;
pub mod clock_release;
pub mod device;
mod error;
pub mod fingerprint;
pub mod go_live;
pub mod operator;
pub mod operator_profile;
pub mod operator_trust_store;
pub mod policy;
pub mod registry;
pub mod revocation;
mod root_ceremony;
pub mod writer_transition;
pub use operator::*;
pub use operator_profile::verify_operator_snapshot;

pub use anchor_media::{
    AnchorMedia, AnchorMediumId, MediaConfirmation, SecondChannelConfirmation,
    confirm_final_anchor_fingerprint, confirm_on_media, confirm_pre_anchor_fingerprint,
    verify_anchor_transition,
};
pub use bootstrap::{
    AdminBootstrapPairV1, BackedUpKeyClass, BootstrapCoordinator, BootstrapStateV1, BootstrapStep,
    BootstrapStore, BootstrapTranscriptV1, CeremonyRandomSource, ComponentBindingV1,
    KeyBackupRecordV1, OuterKeyRecordV1, RootKeyMaterialV1, SystemRandomSource,
};
pub use bootstrap_store::FileBootstrapStore;
pub use ceremony_steps::{
    TrustCeremonyKind, TrustCeremonyStep, next_step, reauth_purpose, requires_fresh_reauth,
};
pub use error::AdminError;
pub use fingerprint::{
    FINGERPRINT_PARSE_ERROR, FingerprintParseError, human_readable_fingerprint,
    parse_human_readable_fingerprint,
};
pub use genesis::{GenesisBinding, GenesisEnvelopeV1, bind_genesis};
pub use go_live::{
    EdsPrivacyDecision, GO_LIVE_REQUIREMENT_CODES, GoLiveChecklist, GoLiveEvidence,
    GoLiveRequirement, GoLiveRequirementStatus, RecoveryTestFreshness, RegistryFreshness,
    evaluate_go_live, evaluate_go_live_with_posture_admission,
};
pub use production_state::{FreshMachineRecoveryProof, ProductionState, machine_fingerprint};
#[cfg(feature = "test-support")]
pub use production_state::{RecoveryTestObservation, verify_fresh_machine_recovery_test};
pub use root_ceremony::RootCeremonyService;
pub use writer_transition::{
    ActivatedWriterTransition, PreparedWriterTransition, TrustedChainHead, WriterTransitionError,
    WriterTransitionPhase, WriterTransitionRequest, WriterTransitionService,
};

mod native_signing_backup;
pub use native_signing_backup::{
    NativeSigningBackupError, seal_native_bootstrap_admin_backup, seal_native_bootstrap_root_backup,
};
