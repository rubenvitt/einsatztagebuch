#![forbid(unsafe_code)]

mod decode;
mod encode;
mod limits;

use ea_types::TechnicalErrorCode;

pub use decode::{BoundedDecoder, validate};
pub use encode::{canonical_reencode, to_deterministic_vec};
pub use limits::ParserLimits;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CborError {
    Indefinite,
    ItemLimit,
    DepthLimit,
    ContainerLimit,
    TokenLimit,
    TrailingBytes,
    NonMinimal,
    Float,
    InvalidUtf8,
    NonNfc,
    MapOrder,
    DuplicateKey,
    Invalid,
    Encode,
}

impl CborError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Indefinite => "EA-CBOR-INDEFINITE",
            Self::ItemLimit => "EA-CBOR-ITEM-LIMIT",
            Self::DepthLimit => "EA-CBOR-DEPTH-LIMIT",
            Self::ContainerLimit => "EA-CBOR-CONTAINER-LIMIT",
            Self::TokenLimit => "EA-CBOR-TOKEN-LIMIT",
            Self::TrailingBytes => "EA-CBOR-TRAILING",
            Self::NonMinimal => "EA-CBOR-NONMINIMAL",
            Self::Float => "EA-CBOR-FLOAT",
            Self::InvalidUtf8 => "EA-CBOR-UTF8",
            Self::NonNfc => "EA-CBOR-NON-NFC",
            Self::MapOrder => "EA-CBOR-MAP-ORDER",
            Self::DuplicateKey => "EA-CBOR-DUPLICATE-KEY",
            Self::Invalid => "EA-CBOR-INVALID",
            Self::Encode => "EA-CBOR-ENCODE",
        }
    }

    #[must_use]
    pub const fn technical_code(self) -> TechnicalErrorCode {
        TechnicalErrorCode::InvalidObject
    }
}

impl core::fmt::Display for CborError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl core::fmt::Debug for CborError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for CborError {}
