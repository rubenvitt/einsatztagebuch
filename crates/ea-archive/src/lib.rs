#![forbid(unsafe_code)]
//! Ports und Inventar ueber die Bytes eines Archivbestands.
//!
//! Diese Crate traegt den breiten Port ueber ALLE Archivbytes, die
//! Layoutkonstanten aus design.md 11.4 und das Inventar, das am 9-Byte-
//! Exact-Object-Praefix klassifiziert, nie am Dateinamen. Das Inventar
//! bedient `ea_trust::TrustObjectSource` unmittelbar, sodass `ea-trust`
//! nichts ueber das Archivlayout erfaehrt.
//!
//! # Das Portverhaeltnis
//!
//! [`ArchiveSource`] ist der NEUE, BREITE Port ueber alle Archivbytes;
//! `ea_trust::TrustObjectSource` bleibt unveraendert der schmale,
//! archiv-agnostische Trust-Port. [`ArchiveInventory`] IMPLEMENTIERT den
//! schmalen Port ueber seinem beschraenkten Trust-Index — es wird nichts
//! dupliziert und keine Zwischenliste gebaut: der Visitor wird beim Durchlaufen
//! unmittelbar gerufen, und der Durchlauf haelt VOR dem naechsten Element an,
//! sobald der Visitor einen Fehler liefert. Die Schranken
//! `ea_trust::MAX_TRUST_OBJECTS_V1` und `MAX_TOTAL_TRUST_OBJECT_BYTES_V1`
//! gelten unveraendert und werden hier nicht neu definiert.
//!
//! # Drei Inventarklassen (design.md 11.4)
//!
//! Das 9-Byte-Praefix entscheidet, nie der Dateiname:
//!
//! 1. Bytes MIT Exact-Object-Praefix sind Archivobjekte. Sie zaehlen in
//!    `archiveObjectCount`, jede Sequenz einzeln und unabhaengig von
//!    Parse-Erfolg und Duplikat. Ein Parse-Fehlschlag erzeugt PAARWEISE einen
//!    [`FormatErrorEntry`] und einen [`QuarantinedObject`] mit Grund
//!    [`QuarantineReason::Malformed`].
//! 2. Bytes OHNE dieses Praefix sind KEIN Archivobjekt. Sie werden nie
//!    isoliert und zaehlen ausschliesslich in `nonObjectFileCount` — ohne diese
//!    Trennung isolierte jedes normkonforme Archiv sein eigenes
//!    [`README_FORMAT_FILE_V1`] und waere nie vollstaendig verifiziert.
//! 3. Der Trust Anchor kommt als Parameter und nie aus dem Bestand; er faellt
//!    in keine der beiden Zaehlklassen.
//!
//! Invariante: `archiveObjectCount + nonObjectFileCount` ist die Gesamtzahl der
//! von [`ArchiveSource`] gelieferten Bytesequenzen.
//!
//! # Der Ein-Datei-Container
//!
//! [`ArchiveBundleSource`] implementiert [`ArchiveSource`] ueber die Bytes
//! EINER exportierten Datei und liegt hier, weil er geteilter Browsercode ist:
//! der Datei-Modus des Web-Readers liest ihn im wasm32-Ziel. Er beruehrt kein
//! `std::fs` — das Format steht in `bundle.rs`, das Oeffnen einer Datei in
//! `ea_archive_fs::open_archive_bundle`.

mod backend;
mod backend_error;
mod bundle;
mod bundle_error;
mod error;
mod inventory;
mod layout;
mod lock;
mod path;
mod profile;
mod source;
mod transaction;

pub use backend::ArchiveBackend;
pub use backend_error::ArchiveBackendError;
pub use bundle::{
    ArchiveBundleSource, BUNDLE_FILE_EXTENSION_V1, BUNDLE_HEADER_BYTES_V1, BUNDLE_MAGIC_V1,
    INDEX_RECORD_FIXED_BYTES,
};
pub use bundle_error::BundleError;
pub use error::ArchiveError;
pub use inventory::{ArchiveInventory, FormatErrorEntry, QuarantineReason, QuarantinedObject};
pub use layout::{
    AUTHORIZATIONS_DIR_V1, CHECKPOINTS_DIR_V1, COMPATIBILITY_MATRIX_FILE_V1,
    DESTROYED_ENTRIES_DIR_V1, DESTRUCTION_ATTESTATIONS_SUBDIR_V1, DESTRUCTION_EVENTS_SUBDIR_V1,
    DESTRUCTIONS_DIR_V1, ENTRIES_DIR_V1, FORMAT_DIR_V1, FORMAT_SCHEMAS_DIR_V1,
    FORMAT_TRANSFORMATIONS_DIR_V1, GRANTS_DIR_V1, LAYOUT_PATHS_V1, MAX_ARCHIVE_BLOBS_V1,
    MAX_TOTAL_ARCHIVE_BYTES_V1, OPERATOR_BINDINGS_DIR_V1, ORGANIZATION_TRUST_FILE_V1,
    README_FORMAT_FILE_V1, RECEIPTS_DIR_V1, RECOVERY_REPORTS_DIR_V1, REGISTRY_EVENTS_DIR_V1,
    TRUST_DIR_V1,
};
pub use lock::{WriterLock, WriterLockRelease};
pub use path::ArchivePath;
pub use profile::{
    ArchiveBackendProfileV1, BoundArchiveProfilePolicyV1, ControlledNetworkProfileV1,
    LocalPathProfileV1,
};
pub use source::{ArchiveBlob, ArchiveSource};
pub use transaction::{
    ArchiveTransaction, STAGING_SUFFIX_V1, StagedBytesV1, StagedObjectV1, is_staging_path,
};
