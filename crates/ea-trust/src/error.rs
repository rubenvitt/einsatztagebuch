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
    SelfAuthorization,
    AuthReplay,
    AuthNotYetValid,
    AuthExpired,
    ActionMismatch,
    TimeSourceUnsupported,
    TimeOverflow,
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
            Self::SelfAuthorization => "EA-TRUST-SELF-AUTHORIZATION",
            Self::AuthReplay => "EA-TRUST-AUTH-REPLAY",
            Self::AuthNotYetValid => "EA-TRUST-AUTH-NOT-YET-VALID",
            Self::AuthExpired => "EA-TRUST-AUTH-EXPIRED",
            Self::ActionMismatch => "EA-TRUST-ACTION-MISMATCH",
            Self::TimeSourceUnsupported => "EA-TRUST-TIME-SOURCE-UNSUPPORTED",
            Self::TimeOverflow => "EA-TIME-OVERFLOW",
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
pub enum RegistryError {
    Trust(TrustError),
    Gap,
    Fork,
    Rollback,
    Overflow,
    Previous,
    ActivationHead,
    ActivationMissing,
    PolicyMismatch,
    SequenceLease,
}

impl RegistryError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Trust(error) => error.code(),
            Self::Gap => "EA-TRUST-REGISTRY-GAP",
            Self::Fork => "EA-TRUST-REGISTRY-FORK",
            Self::Rollback => "EA-TRUST-REGISTRY-ROLLBACK",
            Self::Overflow => "EA-TRUST-REGISTRY-OVERFLOW",
            Self::Previous => "EA-TRUST-REGISTRY-PREVIOUS",
            Self::ActivationHead => "EA-TRUST-ACTIVATION-HEAD",
            Self::ActivationMissing => "EA-TRUST-ACTIVATION-MISSING",
            Self::PolicyMismatch => "EA-TRUST-POLICY-MISMATCH",
            Self::SequenceLease => "EA-TRUST-SEQUENCE-LEASE",
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for RegistryError {}

impl From<TrustError> for RegistryError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

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
