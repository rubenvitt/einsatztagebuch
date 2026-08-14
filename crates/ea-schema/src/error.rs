pub struct UnsupportedSchema {
    pub schema_id: String,
    pub schema_version: u64,
}

pub enum SchemaError {
    Unsupported {
        schema_id: String,
        schema_version: u64,
    },
    Invalid {
        code: &'static str,
        field: Option<&'static str>,
    },
    Cbor(ea_cbor::CborError),
}

impl SchemaError {
    pub(crate) const fn invalid(code: &'static str, field: Option<&'static str>) -> Self {
        Self::Invalid { code, field }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "EA-SCHEMA-UNSUPPORTED",
            Self::Invalid { code, .. } => code,
            Self::Cbor(error) => error.code(),
        }
    }

    #[must_use]
    pub const fn field(&self) -> Option<&'static str> {
        match self {
            Self::Unsupported { .. } => None,
            Self::Invalid { field, .. } => *field,
            Self::Cbor(_) => None,
        }
    }
}

impl From<ea_cbor::CborError> for SchemaError {
    fn from(value: ea_cbor::CborError) -> Self {
        Self::Cbor(value)
    }
}

impl From<UnsupportedSchema> for SchemaError {
    fn from(value: UnsupportedSchema) -> Self {
        Self::Unsupported {
            schema_id: value.schema_id,
            schema_version: value.schema_version,
        }
    }
}

impl core::fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())?;
        if let Some(field) = self.field() {
            write!(formatter, " field={field}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for SchemaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for SchemaError {}
