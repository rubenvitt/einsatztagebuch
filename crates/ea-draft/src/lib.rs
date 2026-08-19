//! Der EINE aktive Entwurf eines Writers.
//!
//! `design.md`:426 — es existiert genau ein aktiver Entwurf. Diese Crate haelt
//! ihn verschluesselt, speichert ihn als Vergleich-und-Setze und gibt ihn nach
//! einem Neustart unveraendert zurueck.
//!
//! Drei Zusagen tragen sie:
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
//!
//! Alle Methoden sind synchron, wie der ganze Rust-Kern; `Arc<dyn
//! DraftRepository>` ist damit trivial konstruierbar.
#![forbid(unsafe_code)]

mod autosave;
mod incident_number;
mod lock;
mod model;
mod operator_profile;
mod repository;

pub use autosave::AutosaveDraftRepository;
pub use incident_number::IncidentNumberRegister;
pub use lock::DraftLock;
pub use model::{
    DiscardIntent, DiscardOutcome, Draft, DraftError, PreparedFinalizationMarker, SavedDraft,
};
pub use operator_profile::{OperatorProfile, OperatorProfileRepository};
pub use repository::DraftRepository;
