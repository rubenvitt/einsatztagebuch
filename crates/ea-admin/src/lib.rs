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

mod error;
mod root_ceremony;

pub use error::AdminError;
pub use root_ceremony::RootCeremonyService;
