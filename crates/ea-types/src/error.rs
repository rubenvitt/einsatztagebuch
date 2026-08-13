use crate::Redacted;
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorClass {
    Domain,
    LocalResource,
    TemporaryTransport,
    TrustSecurity,
    Format,
    Evidence,
    RecoveryDestruction,
}

impl ErrorClass {
    #[must_use]
    pub const fn disposition(self) -> RetryDisposition {
        match self {
            Self::Domain => RetryDisposition::CorrectInput,
            Self::LocalResource => RetryDisposition::RetainDraftAndBlock,
            Self::TemporaryTransport => RetryDisposition::BoundedRetry,
            Self::TrustSecurity => RetryDisposition::FailClosed,
            Self::Format => RetryDisposition::IsolateObject,
            Self::Evidence => RetryDisposition::PreserveEntryAndReport,
            Self::RecoveryDestruction => RetryDisposition::ReportExactPartialState,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDisposition {
    CorrectInput,
    RetainDraftAndBlock,
    BoundedRetry,
    FailClosed,
    IsolateObject,
    PreserveEntryAndReport,
    ReportExactPartialState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TechnicalErrorCode {
    InvalidInput,
    LocalResourceUnavailable,
    TemporaryTransport,
    TrustViolation,
    InvalidObject,
    EvidenceUnavailable,
    RecoveryPartialState,
}

impl TechnicalErrorCode {
    #[must_use]
    pub const fn class(self) -> ErrorClass {
        match self {
            Self::InvalidInput => ErrorClass::Domain,
            Self::LocalResourceUnavailable => ErrorClass::LocalResource,
            Self::TemporaryTransport => ErrorClass::TemporaryTransport,
            Self::TrustViolation => ErrorClass::TrustSecurity,
            Self::InvalidObject => ErrorClass::Format,
            Self::EvidenceUnavailable => ErrorClass::Evidence,
            Self::RecoveryPartialState => ErrorClass::RecoveryDestruction,
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "EA-DOMAIN-INVALID-INPUT",
            Self::LocalResourceUnavailable => "EA-LOCAL-RESOURCE-UNAVAILABLE",
            Self::TemporaryTransport => "EA-TRANSPORT-TEMPORARY",
            Self::TrustViolation => "EA-TRUST-VIOLATION",
            Self::InvalidObject => "EA-FORMAT-INVALID-OBJECT",
            Self::EvidenceUnavailable => "EA-EVIDENCE-UNAVAILABLE",
            Self::RecoveryPartialState => "EA-RECOVERY-PARTIAL-STATE",
        }
    }
}

pub struct TechnicalError {
    code: TechnicalErrorCode,
    attempt: Option<u64>,
    secret: Option<Redacted<String>>,
}

impl TechnicalError {
    #[must_use]
    pub const fn new(code: TechnicalErrorCode) -> Self {
        Self {
            code,
            attempt: None,
            secret: None,
        }
    }

    #[must_use]
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(Redacted::new(secret.into()));
        self
    }

    #[must_use]
    pub const fn with_attempt(mut self, attempt: u64) -> Self {
        self.attempt = Some(attempt);
        self
    }

    #[must_use]
    pub const fn code(&self) -> TechnicalErrorCode {
        self.code
    }

    #[must_use]
    pub const fn class(&self) -> ErrorClass {
        self.code.class()
    }

    #[must_use]
    pub fn secret_matches(&self, candidate: &str) -> bool {
        self.secret
            .as_ref()
            .is_some_and(|secret| secret.matches(candidate))
    }

    pub fn into_retry_policy(self, config: RetryConfig) -> Result<RetryPolicy, Self> {
        if self.class() != ErrorClass::TemporaryTransport {
            return Err(self);
        }

        Ok(RetryPolicy {
            config,
            state: RetryState::Active { failed_attempts: 0 },
        })
    }
}

impl fmt::Display for TechnicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.code())?;
        if let Some(attempt) = self.attempt {
            write!(formatter, " attempt={attempt}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for TechnicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for TechnicalError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryConfig {
    max_retries: u8,
    base_delay_ms: u64,
    cap_delay_ms: u64,
}

impl RetryConfig {
    #[must_use]
    pub const fn new(max_retries: u8, base_delay_ms: u64, cap_delay_ms: u64) -> Option<Self> {
        if max_retries == 0 || base_delay_ms == 0 || cap_delay_ms == 0 {
            return None;
        }
        Some(Self {
            max_retries,
            base_delay_ms,
            cap_delay_ms,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    config: RetryConfig,
    state: RetryState,
}

impl RetryPolicy {
    #[must_use]
    pub fn next(&mut self, jitter: &mut impl JitterSource) -> RetryDecision {
        let failed_attempts = match self.state {
            RetryState::Active { failed_attempts } => failed_attempts
                .checked_add(1)
                .expect("retry state cannot exceed the u8 retry limit"),
            RetryState::Exhausted { failed_attempts } => {
                return RetryDecision::Exhausted { failed_attempts };
            }
        };

        if failed_attempts > u16::from(self.config.max_retries) {
            self.state = RetryState::Exhausted { failed_attempts };
            return RetryDecision::Exhausted { failed_attempts };
        }

        self.state = RetryState::Active { failed_attempts };

        let exponent = u32::from(failed_attempts - 1);
        let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let ceiling_ms = self
            .config
            .base_delay_ms
            .saturating_mul(multiplier)
            .min(self.config.cap_delay_ms);
        let delay_ms = jitter.jitter_ms(ceiling_ms).min(ceiling_ms);
        RetryDecision::RetryAfter { delay_ms }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum RetryState {
    Active { failed_attempts: u16 },
    Exhausted { failed_attempts: u16 },
}

pub trait JitterSource {
    fn jitter_ms(&mut self, ceiling_ms: u64) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDecision {
    RetryAfter { delay_ms: u64 },
    Exhausted { failed_attempts: u16 },
}
