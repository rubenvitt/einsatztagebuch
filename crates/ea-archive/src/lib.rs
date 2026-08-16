#![forbid(unsafe_code)]
//! Ports und Inventar ueber die Bytes eines Archivbestands.
//!
//! Diese Crate traegt den breiten Port ueber ALLE Archivbytes, die
//! Layoutkonstanten aus design.md 11.4 und das Inventar, das am 9-Byte-
//! Exact-Object-Praefix klassifiziert, nie am Dateinamen. Das Inventar
//! bedient `ea_trust::TrustObjectSource` unmittelbar, sodass `ea-trust`
//! nichts ueber das Archivlayout erfaehrt.

mod error;
mod inventory;
mod layout;
mod source;

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
pub use source::{ArchiveBlob, ArchiveSource};
