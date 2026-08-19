//! Die Bedieneridentitaet einer Stufe-2-Sitzung.
//!
//! Diese Crate KONSUMIERT Bedieneridentitaet; sie stellt keine aus. Die
//! Root-signierte Geraete- und OS-Kontobindung, das gesalzene Bedienerprofil und
//! die Profilzusage entstehen in Stufe 5. Hier existiert deshalb keine API, die
//! eine Bindung oder ein Profil schreibt, anlegt oder aendert — nur eine, die
//! gegen eine bereits bestehende Bindung PRUEFT.
//!
//! Drei Zusagen tragen die Crate:
//!
//! 1. **Kein zweiter Bindungshash.** Die drei OS-Konto-Bindungshashes gehoeren
//!    Stufe 1 (`crates/ea-crypto/src/os_account.rs`). Diese Crate erntet
//!    ausschliesslich Rohangaben und gibt sie unveraendert weiter; sie kennt
//!    weder die Domainkonstante noch die kanonische Kodierung.
//! 2. **Keine freie Zeit.** Jede Gueltigkeitsaussage laeuft ueber
//!    [`ea_trust::PreexistingEffectiveNow`] eines gewaehlten Registry-Head. Ein
//!    selbst gebauter Zeitwert waere in Stufe 1 ohnehin nicht konstruierbar und
//!    wuerde die Zeitstatusbewertung umgehen.
//! 3. **Keine Archivbytes.** Der Praesenznachweis verlaesst das Geraet nie und
//!    wird nie serialisiert. Er hat deshalb kein eingefrorenes Format, keinen
//!    neuen `ContentType` und keine Stufe-1-Domainkonstante — nur eine lokale,
//!    domaingetrennte Challenge innerhalb dieser Crate.
//!
//! Der Praesenznachweis ist undurchsichtig: aus einem
//! [`OperatorSessionProof`] fuehrt kein Weg zu einem Kontobezeichner, einem
//! Schluessel oder einer Signatur.
//!
//! ```compile_fail
//! use ea_operator::OperatorSessionProof;
//!
//! fn account_of(proof: &OperatorSessionProof) -> &[u8] {
//!     proof.os_account_binding_hash()
//! }
//! ```
//!
//! Ein Nachweis laesst sich nicht vervielfaeltigen — sonst ueberlebte der
//! gueltige Stand die OS-Sperre neben dem entwerteten:
//!
//! ```compile_fail
//! use ea_operator::OperatorSessionProof;
//!
//! fn require_clone<T: Clone>() {}
//! require_clone::<OperatorSessionProof>();
//! ```
//!
//! Rohangaben eines Kontos werden nicht selbst zu einem Bindungshash gerechnet;
//! der Weg fuehrt nur ueber die Stufe-1-Funktionen:
//!
//! ```compile_fail
//! use ea_operator::linux;
//!
//! let inputs = linux::account_inputs(b"0123456789abcdef0123456789abcdef\n".to_vec(), 1000);
//! let raw = inputs.canonical_cbor();
//! ```
//!
//! Und die Rohangaben tragen keine Formatierung, ueber die sie in eine
//! Protokollzeile geraten koennten:
//!
//! ```compile_fail
//! use ea_operator::linux;
//!
//! let inputs = linux::account_inputs(b"0123456789abcdef0123456789abcdef\n".to_vec(), 1000);
//! println!("{inputs:?}");
//! ```
//!
//! Dieser Doctest uebersetzt und belegt damit zugleich, dass die drei
//! `compile_fail`-Doctests oben an ihrem jeweiligen GEGENSTAND scheitern und
//! nicht an einem unaufloesbaren Import: er nennt beide Pfade, die sie brauchen.
//!
//! ```
//! use ea_operator::{OperatorSessionProof, ReauthPurpose, linux};
//!
//! let inputs = linux::account_inputs(b"0123456789abcdef0123456789abcdef\n".to_vec(), 1000);
//! let _hash_needs_an_organization_and_a_device = &inputs;
//! // `OperatorSessionProof` ist erreichbar und traegt Formatierung, weil in ihm
//! // kein Geheimnis liegt — anders als in `OsAccountInputs`.
//! fn takes_a_proof(proof: &OperatorSessionProof, purpose: ReauthPurpose) -> String {
//!     format!("{proof:?} {}", purpose.label())
//! }
//! let _ = takes_a_proof;
//! ```
//!
//! Alle Methoden sind synchron.
#![forbid(unsafe_code)]

mod account;
// Die drei Plattformraender sind BEDINGUNGSLOS deklariert und nicht per
// `#[cfg(target_os = …)]` gegated: so belegt der gepinnte Compiler auf dem
// Pruefhost die Typkorrektheit aller drei Ernten, und nicht nur die des Hosts.
pub mod linux;
pub mod macos;
mod session;
pub mod windows;

pub use account::{BoundOperator, OperatorError, OsAccountInputs, OsAccountProvider};
pub use session::{
    MAX_INACTIVITY_MS, OperatorAuthenticator, OperatorSessionProof, REAUTH_CHALLENGE_DOMAIN,
    ReauthPurpose,
};
