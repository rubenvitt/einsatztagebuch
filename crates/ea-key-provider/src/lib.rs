//! Die Grenze, hinter der natives Schluesselmaterial eines Writers liegt.
//!
//! Diese Crate exportiert einen synchronen Port, einen undurchsichtigen Griff,
//! zwei disjunkte Zweck-Aufzaehlungen und die Rollentrennung des Writers. Sie
//! exportiert KEIN privates Schluesselmaterial, und die folgenden
//! `compile_fail`-Doctests sind der Beleg dafuer.
//!
//! Sie sind der EINZIGE Beleg: `verify-quick` fuehrt Clippy mit
//! `--all-features` aus, `--no-default-features` allein traegt die Zusage also
//! nicht, und das Testkommando des Workspace laeuft mit `--all-targets`, was
//! Doctests gerade ausschliesst.
//!
//! Ein Griff gibt keine Bytes heraus:
//!
//! ```compile_fail
//! use ea_key_provider::KeyHandle;
//!
//! fn key_bytes(handle: &KeyHandle) -> &[u8] {
//!     handle.expose_secret()
//! }
//! ```
//!
//! Aus fertigen COSE_Sign1-Bytes fuehrt kein Weg zurueck zu einem
//! Signaturschluessel:
//!
//! ```compile_fail
//! use ea_crypto::SecretBytes;
//! use ea_key_provider::CoseSign1Bytes;
//!
//! fn signing_key_from(signed: CoseSign1Bytes) -> SecretBytes<32> {
//!     signed.into()
//! }
//! ```
//!
//! Und die vierte Produktinvariante — kein privater Reader-, Recovery-,
//! Historical-Grant-Authority- oder Key-Approver-Schluessel auf einem Writer —
//! haengt am TYP und nicht an einer Laufzeitpruefung: [`KeyPurpose`] und
//! [`SecretPurpose`] sind disjunkt, und aus einem fremden Zweck entsteht kein
//! lokaler. Es gibt keine Umwandlung:
//!
//! ```compile_fail
//! use ea_key_provider::{KeyPurpose, SecretPurpose};
//!
//! fn local_from_foreign(purpose: KeyPurpose) -> SecretPurpose {
//!     SecretPurpose::from(purpose)
//! }
//! ```
//!
//! Und es gibt keinen Weg an der positiven Haelfte vorbei: ein fremder Zweck
//! ist kein Argument von `validate_local`, und das entscheidet der Uebersetzer
//! und keine Zeile, die jemand vergessen kann.
//!
//! ```compile_fail
//! use ea_key_provider::{KeyPurpose, WriterKeyProfile};
//!
//! WriterKeyProfile::validate_local(&[KeyPurpose::ReaderKem]).unwrap();
//! ```
//!
//! Was der Griff dagegen sehr wohl herausgibt, ist seine Bindung — Speicher,
//! Anwendung, Kontoinstanz, Zweck und Verbreitungspolitik. Dieser Doctest
//! uebersetzt und belegt damit zugleich, dass die vier obigen an ihrem
//! jeweiligen Gegenstand scheitern und nicht an ihren Importen:
//!
//! ```
//! use ea_crypto::SecretBytes;
//! use ea_key_provider::{KeyPurpose, SecretPurpose, WriterKeyProfile};
//!
//! WriterKeyProfile::validate_local(&[SecretPurpose::DraftDek]).unwrap();
//! // Benennt JEDEN Pfad, den die `compile_fail`-Doctests oben brauchen. Ohne
//! // diese Zeilen bestuenden sie auch dann, wenn `ea_crypto::SecretBytes` oder
//! // `ea_key_provider::KeyPurpose` in einem Doctest gar nicht aufloest — sie
//! // waeren dann kein Beleg fuer die fehlende Umwandlung, sondern nur fuer
//! // einen kaputten Import.
//! let _secret = SecretBytes::<32>::new([0; 32]);
//! WriterKeyProfile::validate(&[KeyPurpose::ReaderKem]).unwrap_err();
//! ```
#![forbid(unsafe_code)]

mod contract;
#[cfg(feature = "test-support")]
mod in_memory;
// Die drei Plattformraender sind BEDINGUNGSLOS deklariert und nicht per
// `#[cfg(target_os = …)]` gegated. Ein gegateter Rand wuerde auf dem Host, auf
// dem Stufe 2 geprueft wird, nicht einmal geparst — der gepinnte Compiler
// (`rust-toolchain.toml`) belegt so fuer alle drei Raender Typkorrektheit,
// waehrend nur die Aufloesung des Hosts (`SupportMatrixRow::current_host`)
// zielabhaengig ist.
pub mod linux;
pub mod macos;
mod posture;
mod profile;
pub mod windows;

pub use contract::{
    APPLICATION_NAMESPACE, CoseSign1Bytes, KeyEntryPolicy, KeyError, KeyHandle, KeyProvider,
    KeyPurpose, KeystoreProvider, SecretPurpose,
};
#[cfg(feature = "test-support")]
pub use in_memory::InMemoryKeyProvider;
#[cfg(feature = "test-support")]
pub use posture::DevicePostureProviderFake;
pub use posture::{
    DevicePostureProvider, DevicePostureReport, PostureCheck, PostureRequirement, SupportMatrixRow,
};
pub use profile::{WriterKeyProfile, require_claimed_protection_profile};
