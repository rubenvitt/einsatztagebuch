//! Die Aktivierungsregel des Web-Bundles nach `web-reader-design.md` §4.2.
//!
//! Die Regel selbst liegt seit dem v1.1-Profil (Reader-Key-Escrow, §5) in
//! `ea-trust` (`crates/ea-trust/src/bundle_release.rs`): dieselbe Pinnung
//! entscheidet dort die Cutover-Vorbedingung für Server und native Zeremonie.
//! Diese Datei bleibt als Wiederausfuhr stehen, damit jeder bestehende Pfad
//! und jede Doku-Stelle, die sie nennt, weiter trägt; Verhalten und
//! Oberfläche des Readers sind unverändert.

pub use ea_trust::{
    BundleActivationDecisionV1, BundleRejectionCodeV1, ReaderBundleError, ReaderBundlePin,
};
