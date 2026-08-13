use core::fmt;

use ea_types::TechnicalErrorCode;

#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum CryptoError {
    InvalidCose,
    UnsupportedSuite,
    InvalidPublicKey,
    SignerMismatch,
    SignerUnresolved,
    SignerUnauthorized,
    SignatureInvalid,
    AeadOpen,
    HpkeKey,
    HpkeOpen,
    LocalRng,
    SizeLimit,
    InvalidOsAccount,
    InvalidProtocolCore,
}

impl CryptoError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCose => "EA-CRYPTO-INVALID-COSE",
            Self::UnsupportedSuite => "EA-CRYPTO-UNSUPPORTED-SUITE",
            Self::InvalidPublicKey => "EA-CRYPTO-INVALID-PUBLIC-KEY",
            Self::SignerMismatch => "EA-TRUST-SIGNER-MISMATCH",
            Self::SignerUnresolved => "EA-TRUST-SIGNER-UNRESOLVED",
            Self::SignerUnauthorized => "EA-TRUST-SIGNER-UNAUTHORIZED",
            Self::SignatureInvalid => "EA-TRUST-SIGNATURE-INVALID",
            Self::AeadOpen => "EA-CRYPTO-AEAD-OPEN",
            Self::HpkeKey => "EA-CRYPTO-HPKE-KEY",
            Self::HpkeOpen => "EA-CRYPTO-HPKE-OPEN",
            Self::LocalRng => "EA-LOCAL-CRYPTO-RNG",
            Self::SizeLimit => "EA-CRYPTO-SIZE-LIMIT",
            Self::InvalidOsAccount => "EA-IDENTITY-INVALID-OS-ACCOUNT",
            Self::InvalidProtocolCore => "EA-CRYPTO-INVALID-PROTOCOL-CORE",
        }
    }

    #[must_use]
    pub const fn technical_code(self) -> TechnicalErrorCode {
        match self {
            Self::InvalidCose
            | Self::UnsupportedSuite
            | Self::InvalidPublicKey
            | Self::InvalidProtocolCore => TechnicalErrorCode::InvalidObject,
            Self::SignerMismatch
            | Self::SignerUnresolved
            | Self::SignerUnauthorized
            | Self::SignatureInvalid
            | Self::AeadOpen
            | Self::HpkeOpen => TechnicalErrorCode::TrustViolation,
            Self::HpkeKey | Self::SizeLimit | Self::InvalidOsAccount => {
                TechnicalErrorCode::InvalidInput
            }
            Self::LocalRng => TechnicalErrorCode::LocalResourceUnavailable,
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for CryptoError {}
