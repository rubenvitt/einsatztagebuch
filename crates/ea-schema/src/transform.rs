use crate::{PayloadV1, ValidatedPayload};

pub struct DerivedView {
    source_schema_id: &'static str,
    source_schema_version: u64,
    target_schema_id: &'static str,
    target_schema_version: u64,
    validated_payload: ValidatedPayload,
}

impl DerivedView {
    pub(crate) fn identity(
        schema_id: &'static str,
        schema_version: u64,
        validated_payload: ValidatedPayload,
    ) -> Self {
        Self {
            source_schema_id: schema_id,
            source_schema_version: schema_version,
            target_schema_id: schema_id,
            target_schema_version: schema_version,
            validated_payload,
        }
    }

    #[must_use]
    pub const fn source_schema_id(&self) -> &'static str {
        self.source_schema_id
    }

    #[must_use]
    pub const fn source_schema_version(&self) -> u64 {
        self.source_schema_version
    }

    #[must_use]
    pub const fn target_schema_id(&self) -> &'static str {
        self.target_schema_id
    }

    #[must_use]
    pub const fn target_schema_version(&self) -> u64 {
        self.target_schema_version
    }

    #[must_use]
    pub fn exact_source_bytes(&self) -> &[u8] {
        self.validated_payload.exact_bytes()
    }

    #[must_use]
    pub const fn validated_payload(&self) -> &ValidatedPayload {
        &self.validated_payload
    }

    #[must_use]
    pub const fn payload(&self) -> &PayloadV1 {
        self.validated_payload.payload()
    }
}
