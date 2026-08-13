#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStatus {
    LocallySecured,
    UploadPending,
    Synchronized,
    Error,
}

impl SyncStatus {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LocallySecured => "locallySecured",
            Self::UploadPending => "uploadPending",
            Self::Synchronized => "synchronized",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
    Verified,
    Gap,
    MissingGrant,
    UnknownKey,
    UnsupportedSchema,
    Invalid,
}

impl VerificationStatus {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Gap => "gap",
            Self::MissingGrant => "missingGrant",
            Self::UnknownKey => "unknownKey",
            Self::UnsupportedSchema => "unsupportedSchema",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStatus {
    Complete,
    Pending,
    Overdue,
    Invalid,
}

impl EvidenceStatus {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Pending => "pending",
            Self::Overdue => "overdue",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryStatus {
    Present,
    AuthorizedDestroyed,
    UnexplainedGap,
}

impl EntryStatus {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::AuthorizedDestroyed => "authorizedDestroyed",
            Self::UnexplainedGap => "unexplainedGap",
        }
    }
}
