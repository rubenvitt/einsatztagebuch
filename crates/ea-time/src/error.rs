use core::fmt;

#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum TimeError {
    Overflow,
    StateMonotonicity,
}

impl TimeError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Overflow => "EA-TIME-OVERFLOW",
            Self::StateMonotonicity => "EA-TIME-STATE-MONOTONICITY",
        }
    }
}

impl fmt::Display for TimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for TimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for TimeError {}
