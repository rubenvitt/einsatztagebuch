use crate::{PayloadV1, SchemaError};

pub const PAYLOAD_PLAINTEXT_MAX_BYTES_V1: usize = 1_048_576;
pub const SCHEMA_VERSION_V1: u64 = 1;
pub const SUITE_ID_V1: &str = ea_types::SUITE_ID_V1;
pub const IANA_TZDB_VERSION_V1: &str = "2026c";

pub fn encode_payload(payload: &PayloadV1) -> Result<Vec<u8>, SchemaError> {
    crate::encode::encode_payload(payload)
}
