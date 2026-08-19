//! Die getypte, klartextfreie lokale Auditzeile.
//!
//! Drei Zusagen tragen diese Crate:
//!
//! 1. **Kein zweiter Typsatz.** Die zwoelf Aktionen und ihre Kontexte kommen
//!    unveraendert aus `ea_format`; diese Crate deklariert weder eine zweite
//!    Aktionsaufzaehlung noch einen zweiten Kontexttyp. Ein zweiter Typsatz ist
//!    genau der Weg, auf dem falsche Bytes entstehen.
//! 2. **Kein Freitext.** [`TypedLocalAuditEvent`] traegt eine Aktion und einen
//!    Ausgang, sonst nichts. Es gibt keine Metadaten-API, keinen Aenderungs-
//!    und keinen Loeschpfad.
//! 3. **Kein Ereignisinhalt in einer Fehlermeldung.** [`AuditError`] formatiert
//!    ausschliesslich seinen stabilen Code.
//!
//! Alle Methoden sind synchron, wie der ganze Rust-Kern.
#![forbid(unsafe_code)]

mod event;
mod repository;

pub use event::{
    AuditActorProof, AuditError, AuthenticatedDevice, LocalAuditService, SignedLocalAuditEvent,
    TypedLocalAuditEvent,
};
pub use repository::{LocalAuditRepository, SignedLocalAuditService, SqliteLocalAuditRepository};
