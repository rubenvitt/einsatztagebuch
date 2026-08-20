#![forbid(unsafe_code)]
//! Die WIRTIMPLEMENTIERUNGEN der Archivports.
//!
//! `crates/ea-archive` traegt ausschliesslich zielunabhaengige Ports und
//! beruehrt kein `std::fs`; es bleibt damit auf der wasm32-Positivliste, deren
//! Text der geschlossene Stufe-1-Gate einfriert. Alles, was dahinter das
//! Wirtbetriebssystem braucht — Create-if-absent, Datei- und
//! Verzeichnis-Flush, dateisysteminterner Rename, exklusive Sperre,
//! Publikationswarteschlange, Gesundheitscheck und der auditierte
//! Profilwechsel —, lebt hier.
//!
//! Die Abhaengigkeitsrichtung ist erzwungen und nicht gewaehlt:
//! `crates/ea-verify/Cargo.toml` haengt schon an `ea-archive`, eine Kante von
//! `ea-archive` auf `ea-verify` waere ein Cargo-Zyklus. Diese Crate ist die
//! einzige, die `ea-verify` fuer die vollstaendige Offlineverifikation des
//! Migrationsziels benutzt.
//!
//! Alles hier ist SYNCHRON, wie der ganze Rust-Kern. Blockierendes Datei- und
//! Netz-I/O ist unter dem `spawn_blocking`-Modell der Shell korrekt.

mod controlled_network;
mod health;
mod local_path;
mod profile_migration;
mod publication_queue;

pub use controlled_network::{ControlledNetworkBackend, LocalCommitComponentV1};
pub use health::{ArchiveHealthCheckV1, ArchiveHealthReport, FreeSpaceV1, HealthFinding};
pub use local_path::{
    CONTROL_FILES_V1, CapabilityReportV1, CapabilityTestVectorV1, LocalPathArchiveSource,
    LocalPathBackend,
};
pub use profile_migration::{
    FinalizationLockStateV1, MigrationFaultPoint, MigrationResultV1, ProfileMigrator,
};
pub use publication_queue::{
    DetailCause, PlannedPublicationV1, PublicationQueue, PublicationStateV1, PublicationTargetV1,
    SyncStatus,
};
