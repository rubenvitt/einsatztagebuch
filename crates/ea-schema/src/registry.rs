use core::fmt::Write;

use crate::{
    DerivedView, IANA_TZDB_VERSION_V1, PAYLOAD_PLAINTEXT_MAX_BYTES_V1, SCHEMA_VERSION_V1,
    SUITE_ID_V1, SchemaError, ValidatedPayload,
};

pub struct SchemaRegistry;

#[derive(Clone, Copy)]
pub struct SchemaDescriptor {
    schema_id: &'static str,
    record_type: &'static str,
}

const V1_SCHEMAS: [SchemaDescriptor; 5] = [
    SchemaDescriptor {
        schema_id: "ea.genesis",
        record_type: "genesis",
    },
    SchemaDescriptor {
        schema_id: "ea.incident",
        record_type: "incident",
    },
    SchemaDescriptor {
        schema_id: "ea.amendment",
        record_type: "amendment",
    },
    SchemaDescriptor {
        schema_id: "ea.key-transition",
        record_type: "keyTransition",
    },
    SchemaDescriptor {
        schema_id: "ea.destruction-evidence",
        record_type: "destructionEvidence",
    },
];
const UNKNOWN_SCHEMA_COMPATIBILITY: &str = "unsupported";
const UNKNOWN_VERSION_COMPATIBILITY: &str = "unsupported";
const UNSUPPORTED_SUITE_COMPATIBILITY: &str = "unsupported-suite";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreflightDecision {
    Proceed,
    Unsupported,
    PlaintextLimit,
}

impl SchemaDescriptor {
    #[must_use]
    pub const fn schema_id(self) -> &'static str {
        self.schema_id
    }

    #[must_use]
    pub const fn record_type(self) -> &'static str {
        self.record_type
    }

    #[must_use]
    pub const fn schema_version(self) -> u64 {
        SCHEMA_VERSION_V1
    }

    #[must_use]
    pub const fn suite_id(self) -> &'static str {
        SUITE_ID_V1
    }

    #[must_use]
    pub const fn tzdb_version(self) -> &'static str {
        IANA_TZDB_VERSION_V1
    }

    #[must_use]
    pub const fn identity_view_only(self) -> bool {
        true
    }
}

impl SchemaRegistry {
    #[must_use]
    pub const fn v1() -> Self {
        Self
    }

    #[must_use]
    pub const fn schemas(&self) -> &'static [SchemaDescriptor] {
        &V1_SCHEMAS
    }

    pub fn validate(
        &self,
        schema_id: &str,
        schema_version: u64,
        exact_bytes: &[u8],
    ) -> Result<ValidatedPayload, SchemaError> {
        match preflight(schema_id, schema_version, exact_bytes.len()) {
            PreflightDecision::Proceed => {}
            PreflightDecision::Unsupported => {
                return Err(SchemaError::Unsupported {
                    schema_id: schema_id.to_owned(),
                    schema_version,
                });
            }
            PreflightDecision::PlaintextLimit => {
                return Err(SchemaError::invalid("EA-SCHEMA-PLAINTEXT-LIMIT", None));
            }
        }
        ea_cbor::validate(exact_bytes, ea_cbor::ParserLimits::V1)?;
        let payload = crate::decode::decode_payload(schema_id, exact_bytes)?;
        payload.validate()?;
        let reencoded = crate::encode::encode_payload_unchecked(&payload)?;
        if reencoded != exact_bytes {
            return Err(SchemaError::invalid("EA-SCHEMA-REENCODE", None));
        }
        Ok(ValidatedPayload {
            payload,
            exact_bytes: exact_bytes.to_vec(),
        })
    }

    pub fn derive_view(
        &self,
        schema_id: &str,
        schema_version: u64,
        exact_bytes: &[u8],
    ) -> Result<DerivedView, SchemaError> {
        self.require_schema(schema_id, schema_version)?;
        let validated = self.validate(schema_id, schema_version, exact_bytes)?;
        Ok(DerivedView::identity(
            schema_id_for(schema_id),
            schema_version,
            validated,
        ))
    }

    pub fn require_suite(&self, suite_id: &str) -> Result<(), SchemaError> {
        if suite_id != SUITE_ID_V1 {
            return Err(SchemaError::invalid("EA-SCHEMA-UNSUPPORTED-SUITE", None));
        }
        Ok(())
    }

    #[must_use]
    pub fn compatibility_matrix_json(&self) -> String {
        let mut output = format!(
            "{{\n  \"formatVersion\": {SCHEMA_VERSION_V1},\n  \"release\": \"0.1\",\n  \"suiteIds\": [\n    \"{SUITE_ID_V1}\"\n  ],\n  \"tzdbVersion\": \"{IANA_TZDB_VERSION_V1}\",\n  \"schemas\": [\n",
        );
        for (index, schema) in V1_SCHEMAS.iter().enumerate() {
            write!(
                output,
                "    {{\n      \"recordType\": \"{}\",\n      \"schemaId\": \"{}\",\n      \"schemaVersion\": {},\n      \"readable\": true,\n      \"view\": {{\n        \"kind\": \"identity\",\n        \"preservesSourceBytes\": true,\n        \"targetSchemaId\": \"{}\",\n        \"targetSchemaVersion\": {}\n      }}\n    }}{}\n",
                schema.record_type,
                schema.schema_id,
                schema.schema_version(),
                schema.schema_id,
                schema.schema_version(),
                if index + 1 == V1_SCHEMAS.len() { "" } else { "," },
            )
            .expect("writing to String cannot fail");
        }
        write!(
            output,
            "  ],\n  \"safeFailure\": {{\n    \"unknownSchema\": \"{UNKNOWN_SCHEMA_COMPATIBILITY}\",\n    \"unknownVersion\": \"{UNKNOWN_VERSION_COMPATIBILITY}\",\n    \"unsupportedSuite\": \"{UNSUPPORTED_SUITE_COMPATIBILITY}\"\n  }}\n}}\n",
        )
        .expect("writing to String cannot fail");
        output
    }

    fn require_schema(&self, schema_id: &str, schema_version: u64) -> Result<(), SchemaError> {
        if preflight(schema_id, schema_version, 0) == PreflightDecision::Unsupported {
            return Err(SchemaError::Unsupported {
                schema_id: schema_id.to_owned(),
                schema_version,
            });
        }
        Ok(())
    }
}

fn preflight(schema_id: &str, schema_version: u64, exact_bytes_len: usize) -> PreflightDecision {
    if schema_version != SCHEMA_VERSION_V1
        || !V1_SCHEMAS
            .iter()
            .any(|schema| schema.schema_id == schema_id)
    {
        PreflightDecision::Unsupported
    } else if exact_bytes_len > PAYLOAD_PLAINTEXT_MAX_BYTES_V1 {
        PreflightDecision::PlaintextLimit
    } else {
        PreflightDecision::Proceed
    }
}

fn schema_id_for(schema_id: &str) -> &'static str {
    V1_SCHEMAS
        .iter()
        .find(|schema| schema.schema_id == schema_id)
        .map(|schema| schema.schema_id)
        .expect("supported schema was checked before lookup")
}

#[cfg(test)]
mod tests {
    use super::{PreflightDecision, preflight};
    use crate::PAYLOAD_PLAINTEXT_MAX_BYTES_V1;

    #[test]
    fn borrowed_preflight_decides_before_any_payload_proportional_work() {
        assert!(core::mem::size_of::<PreflightDecision>() <= core::mem::size_of::<usize>());
        assert!(!core::mem::needs_drop::<PreflightDecision>());

        let oversized = PAYLOAD_PLAINTEXT_MAX_BYTES_V1 + 1;
        assert_eq!(
            preflight("ea.unknown", 99, oversized),
            PreflightDecision::Unsupported
        );
        assert_eq!(
            preflight("ea.incident", 1, oversized),
            PreflightDecision::PlaintextLimit
        );
        assert_eq!(
            preflight("ea.incident", 1, PAYLOAD_PLAINTEXT_MAX_BYTES_V1),
            PreflightDecision::Proceed
        );
    }
}
