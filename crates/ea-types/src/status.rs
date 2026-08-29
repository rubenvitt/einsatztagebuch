//! Die maschinenstabilen Codes der Statusvereinigungen.
//!
//! EINE Aufzaehlung fehlt hier, und ihre Abwesenheit ist die Aussage: der
//! Sync-Zustand. Er lebt in `crates/ea-archive-fs/src/publication_queue.rs`,
//! traegt dort die WOERTLICHE Oberflaechenkopie („lokal gesichert", „Upload
//! ausstehend", „synchronisiert", „Fehler") und wird von `ea-ui-contracts` und
//! `ea-sync-client` von dort re-exportiert. Diese Datei fuehrte bis Stufe 3
//! eine zweite, namensverschiedene Kopie (`LocallySecured`/`Error`) ohne einen
//! einzigen Produktionsaufrufer; mit dem Writer-Sync waere sie die dritte
//! Wahrheit ueber denselben Zustand geworden und ist deshalb gefallen.

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
