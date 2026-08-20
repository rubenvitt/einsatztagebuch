//! Der EINE aktive Entwurf eines Writers.
//!
//! `design.md`:426 — es existiert genau ein aktiver Entwurf. Diese Crate haelt
//! ihn verschluesselt, speichert ihn als Vergleich-und-Setze und gibt ihn nach
//! einem Neustart unveraendert zurueck.
//!
//! Fuenf Zusagen tragen sie:
//!
//! 1. **Zwei Verschluesselungen uebereinander.** Die Nutzlast liegt als
//!    AEAD-Chiffrat unter einem eigenen `draftDEK`, BEVOR die Zeile SQLCipher
//!    erreicht. Ist der `draftDEK` fort, sind alte Datenbankseiten unlesbar,
//!    auch wenn der Datenbankschluessel noch existiert.
//! 2. **Keine Wiederauferstehung.** [`DraftRepository::save`] nimmt nur einen
//!    Entwurf an, dessen gelesene Fassung noch der gespeicherten entspricht.
//!    Zwei ueberlappende Autospeicherungen koennen alten Inhalt deshalb nicht
//!    zurueckholen.
//! 3. **Stufe 2 konsumiert Bedieneridentitaet und stellt sie nicht aus.**
//!    [`OperatorProfileRepository`] hat GENAU einen Arm, und der liest.
//! 4. **Verwerfen ist unwiderruflich UND fortsetzbar.** [`DiscardService`]
//!    bucht die Absicht dauerhaft, BEVOR irgendetwas Unwiderrufliches
//!    geschieht; danach ist jeder Neustart eine Fortsetzung. Jeder Punkt von
//!    [`DiscardFaultPoint::ALL`] fuehrt auf genau zwei Zustaende — der alte
//!    Entwurf steht, oder ein DAUERHAFT leerer Entwurf steht. Ein durabler
//!    `PreparedFinalization` gewinnt an jedem Eingang
//!    ([`PREPARED_FINALIZATION_BEATS_DISCARD_INTENT`]).
//! 5. **Stammdaten werden importiert, nie erfunden.** [`CsvImporter`] nimmt
//!    GENAU zwei eingefrorene Kopfzeilen an, hasht die exakten Eingabebytes und
//!    trennt Trockenlauf von Buchung. Die exakten `import-report-v1`-Bytes
//!    bleiben aufbewahrt, damit der in einer Momentaufnahme versiegelte
//!    `importProtocolHash` ein nachpruefbares Urbild hat.
//!
//! Alle Methoden sind synchron, wie der ganze Rust-Kern; `Arc<dyn
//! DraftRepository>` ist damit trivial konstruierbar.
#![forbid(unsafe_code)]

mod autosave;
mod csv_import;
mod discard;
mod fault;
mod incident_number;
mod lock;
mod master_data;
mod model;
mod operator_profile;
mod repository;

pub use autosave::AutosaveDraftRepository;
pub use csv_import::{CsvImporter, ImportError};
pub use discard::{DiscardPhase, DiscardService};
pub use fault::{DiscardFaultPoint, PREPARED_FINALIZATION_BEATS_DISCARD_INTENT, RestartState};
pub use incident_number::IncidentNumberRegister;
pub use lock::DraftLock;
pub use master_data::{MasterDataError, MasterDataRepository};
pub use model::{
    DiscardIntent, DiscardOutcome, Draft, DraftError, PreparedFinalizationMarker, SavedDraft,
};
pub use operator_profile::{OperatorProfile, OperatorProfileRepository};
pub use repository::DraftRepository;
