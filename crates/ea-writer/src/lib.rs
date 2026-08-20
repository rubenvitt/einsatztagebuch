//! Die Offline-Finalisierung des Writers.
//!
//! `design.md` §9.3 — die Finalisierung laeuft unter EINEM exklusiven
//! Writer-Lock und in dreizehn Schritten. Diese Crate ist genau dieser
//! Zustandsautomat, sein Gegenstueck [`WriterService::recover_pending`] und die
//! benannten Unterbrechungspunkte, an denen beide gemessen werden.
//!
//! # Vier Zusagen tragen sie
//!
//! 1. **Die Reihenfolge ist ERZWUNGEN.** `entryHash` entsteht als Nebenprodukt
//!    von `EntryPackageV1::new`, und der `.eag`-Rumpf verlangt ihn als
//!    Pflichtfeld; ein `.eag` vor dem Eintragspaket ist nicht baubar. Es gibt
//!    keine zweite konstruierbare Ordnung.
//! 2. **Ein committed `.eip` und ein nutzbarer `draftDEK` existieren NIE
//!    gleichzeitig.** Der Schluessel geht in Schritt 9, seine Abwesenheit wird
//!    ZURUECKGEFRAGT, und erst danach wird veroeffentlicht.
//! 3. **Nach der Grenze wird nichts neu serialisiert.**
//!    [`WriterService::recover_pending`] vollendet aus den gespeicherten exakten
//!    Bytes; es gibt genau EINEN Veroeffentlichungspfad, und beide Seiten gehen
//!    ihn.
//! 4. **Kein zweiter Hashpfad.** `initialGrantPlanHash` rechnet
//!    `GrantPlanV1::new`, `entryHash` rechnet `EntryPackageV1::new`,
//!    `previewHash` rechnet `ea_crypto::finalization_preview_digest` ueber
//!    `ea_format::encode_finalization_preview_core`. Diese Crate rechnet keinen
//!    davon nach.
//!
//! Alles hier ist SYNCHRON, wie der ganze Rust-Kern.
//!
//! # Was diese Crate NICHT liefert
//!
//! `CommittedFinalization` mit `exact_bytes()` ist NICHT gebaut. Der Brief
//! nennt ihn neben [`PreparedFinalization`], aber es gibt keinen Verbraucher,
//! den [`FinalizeOutcome`] plus die committed Archivbytes nicht schon
//! bedienen — und ein Typ ohne Erzeuger ist eine Attrappe. Er entsteht mit
//! seinem ersten Leser.
//!
//! Der Bestaetigungspfad eines VERALTETEN Registry-Head
//! (`acknowledge_stale_registry`, `StaleRegistryAcknowledgement`) ist nicht
//! gebaut. Die ERKENNUNG ist es: [`WriterService::preview`] und
//! [`WriterService::finalize`] nehmen die beobachtete Zeit des Wirts als
//! Argument, und gegen sie sind [`StaleDecision::StaleAcknowledgeable`] und
//! [`StaleDecision::HardBlock`] erreichbar — gemessen in
//! `tests/stale_registry_warning.rs`. Ohne den Bestaetigungspfad ist der
//! Ausgang fail-closed: [`WriterError::StaleAckRequired`] fuer das
//! Standardprofil mit signiertem `warn`, [`WriterError::RegistryStaleBlocked`]
//! fuer Evidence Grade und signiertes `block`. Ein Typ ohne Erzeuger waere eine
//! Attrappe und schlimmer als eine benannte Auslassung.
//!
//! Was die beobachtete Zeit NICHT ist: eine Zeit, die dieser Kern selbst
//! feststellt. Sie kommt vom Wirt, wie jede Zeit in diesem Workspace
//! (`apps/cli/src/main.rs`), und ein Aufrufer, der eine Zeit vor `notAfter`
//! einreicht, laesst einen veralteten Head frisch erscheinen. Der Boden am
//! Auswahlzeitpunkt macht nur das gemeldete VERTRAUENSALTER monoton.
#![forbid(unsafe_code)]

mod entropy;
mod error;
mod fault;
mod finalize;
mod grant_plan;
mod incident;
mod marker;
mod operator_commitment;
mod preview;
mod recover;

pub use entropy::EntropyDraws;
#[cfg(any(test, feature = "test-support"))]
pub use entropy::{entropy_draws, reset_entropy_draws};
pub use error::WriterError;
pub use fault::{FinalizationFaultPoint, FinalizationPhase, FinalizationStep};
pub use finalize::{
    FinalizeOutcome, PreparedFinalization, ReachedState, WriterBindingV1, WriterService,
};
pub use grant_plan::build_grant_plan;
pub use incident::FinalizationInputV1;
pub use preview::{FinalizationPreview, StaleDecision};
pub use recover::RecoveryOutcome;
