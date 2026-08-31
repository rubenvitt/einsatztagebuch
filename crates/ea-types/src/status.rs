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

    /// Die woertliche Oberflaechenkopie aus `design.md` §17.4.
    ///
    /// NEBEN [`Self::code`] und nie an dessen Stelle: der Code traegt die
    /// JSON-Schemata unter `schemas/reports/v1/`, der Text traegt die
    /// Oberflaeche. Ein Feld fuer beides waere die Vermischung, die §17.4
    /// verbietet.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Verified => "verifiziert",
            Self::Gap => "Lücke",
            Self::MissingGrant => "fehlender Grant",
            Self::UnknownKey => "unbekannter Schlüssel",
            Self::UnsupportedSchema => "nicht darstellbares Schema",
            Self::Invalid => "ungültig",
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

    /// Die woertliche Oberflaechenkopie aus `design.md` §17.4.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "vollständig",
            Self::Pending => "ausstehend",
            Self::Overdue => "überfällig",
            Self::Invalid => "ungültig",
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

    /// Die woertliche Oberflaechenkopie aus `design.md` §17.4.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Present => "vorhanden",
            Self::AuthorizedDestroyed => "autorisiert vernichtet",
            Self::UnexplainedGap => "ungeklärte Lücke",
        }
    }
}
