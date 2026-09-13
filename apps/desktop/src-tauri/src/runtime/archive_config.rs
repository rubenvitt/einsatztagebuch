//! Shared explicit profile grammar. It never grants filesystem capability or
//! policy admission; each actual backend proves those independently.
use ea_archive::{ArchiveBackendProfileV1, ControlledNetworkProfileV1, LocalPathProfileV1};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum ProfileConfig {
    LocalPath {
        filesystem_row_id: String,
        capability_test_vector_id: String,
    },
    ControlledNetworkPath {
        filesystem_row_id: String,
        protocol_id: String,
        server_product: String,
        server_version: String,
        mount_options: Vec<String>,
        failover_config_id: String,
        capability_test_vector_id: String,
        queue_max_objects: u64,
        queue_max_bytes: u64,
        resume_backoff_initial_ms: u64,
        resume_backoff_max_ms: u64,
        resume_max_attempts: u64,
    },
}
impl ProfileConfig {
    pub(super) fn into_profile(self) -> ArchiveBackendProfileV1 {
        match self {
            Self::LocalPath {
                filesystem_row_id,
                capability_test_vector_id,
            } => ArchiveBackendProfileV1::LocalPath(LocalPathProfileV1 {
                filesystem_row_id,
                capability_test_vector_id,
            }),
            Self::ControlledNetworkPath {
                filesystem_row_id,
                protocol_id,
                server_product,
                server_version,
                mount_options,
                failover_config_id,
                capability_test_vector_id,
                queue_max_objects,
                queue_max_bytes,
                resume_backoff_initial_ms,
                resume_backoff_max_ms,
                resume_max_attempts,
            } => ArchiveBackendProfileV1::ControlledNetworkPath(ControlledNetworkProfileV1 {
                filesystem_row_id,
                protocol_id,
                server_product,
                server_version,
                mount_options,
                failover_config_id,
                capability_test_vector_id,
                queue_max_objects,
                queue_max_bytes,
                resume_backoff_initial_ms,
                resume_backoff_max_ms,
                resume_max_attempts,
            }),
        }
    }
}
