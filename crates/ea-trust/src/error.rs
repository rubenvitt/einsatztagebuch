use core::fmt;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TrustError {
    Source,
    SourceCountLimit,
    SourceByteLimit,
    AnchorShape,
    AnchorHash,
    AnchorPin,
    BootstrapPair,
    Signature,
    SignerInactive,
    SubjectMismatch,
    ClockReleaseReplay,
    StateConflict,
    StateMonotonicity,
    StateUnavailable,
}

impl TrustError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Source => "EA-TRUST-SOURCE",
            Self::SourceCountLimit => "EA-TRUST-SOURCE-COUNT-LIMIT",
            Self::SourceByteLimit => "EA-TRUST-SOURCE-BYTE-LIMIT",
            Self::AnchorShape => "EA-TRUST-ANCHOR-SHAPE",
            Self::AnchorHash => "EA-TRUST-ANCHOR-HASH",
            Self::AnchorPin => "EA-TRUST-ANCHOR-PIN",
            Self::BootstrapPair => "EA-TRUST-BOOTSTRAP-PAIR",
            Self::Signature => "EA-TRUST-SIGNATURE",
            Self::SignerInactive => "EA-TRUST-SIGNER-INACTIVE",
            Self::SubjectMismatch => "EA-TRUST-SUBJECT-MISMATCH",
            Self::ClockReleaseReplay => "EA-TRUST-CLOCK-RELEASE-REPLAY",
            Self::StateConflict => "EA-TRUST-STATE-CONFLICT",
            Self::StateMonotonicity => "EA-TRUST-STATE-MONOTONICITY",
            Self::StateUnavailable => "EA-TRUST-STATE-UNAVAILABLE",
        }
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for TrustError {}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TrustSourceError {
    Unavailable,
    CountLimit,
    ByteLimit,
}

impl TrustSourceError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "EA-TRUST-SOURCE",
            Self::CountLimit => "EA-TRUST-SOURCE-COUNT-LIMIT",
            Self::ByteLimit => "EA-TRUST-SOURCE-BYTE-LIMIT",
        }
    }
}

impl fmt::Display for TrustSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for TrustSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for TrustSourceError {}

impl From<TrustSourceError> for TrustError {
    fn from(error: TrustSourceError) -> Self {
        match error {
            TrustSourceError::Unavailable => Self::Source,
            TrustSourceError::CountLimit => Self::SourceCountLimit,
            TrustSourceError::ByteLimit => Self::SourceByteLimit,
        }
    }
}
