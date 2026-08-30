#![forbid(unsafe_code)]
//! Der Writer-Sync-Klient: Warteschlange, Reihenfolge, Quittung.
//!
//! # Die EINE Wahrheit ueber den Zustand
//!
//! Die vier oeffentlichen Zustaende kommen aus
//! `crates/ea-archive-fs/src/publication_queue.rs` und werden hier
//! RE-EXPORTIERT, nie neu erklaert. Die Abbildung auf sie liegt seit diesem
//! Task vollstaendig in [`queue`]: `PublicationQueue` liefert nur noch das
//! Publikationsergebnis, und `synchronisiert` haengt an einer Quittung, die
//! verifiziert und abgelegt ist. Vorher entschieden zwei Stellen dasselbe.
//!
//! # Die Reihenfolge, die diese Crate durchsetzt
//!
//! `design.md` §9.3 Schritt 12 ist woertlich: bei einem kontrollierten
//! Netzlaufwerkprofil werden exakt dieselben committeten Bytes in gleicher
//! Reihenfolge veroeffentlicht — Grants zuerst, `.eip` zuletzt —, und „vor
//! erfolgreicher Netzarchiv-Publikation findet kein Sync-Server-Upload dieses
//! Eintrags statt". [`SyncClient::push_pending`] kehrt deshalb um, BEVOR sie
//! den Transport auch nur anfasst, wenn das Netzarchiv noch wartet.
//!
//! # Woraus die Warteschlange entsteht
//!
//! Ausschliesslich aus committeten Archivbytes (`design.md` §9.4: „Nach dem
//! `.eip`-Rename ist das Archivpaket die Wahrheit. Ein Neustart rekonstruiert
//! Kettenkopf, Queue und UI daraus"). Kein Feld dieser Crate ueberlebt einen
//! Neustart ausser dem Wiederaufnahmezaehler, und der liegt in der
//! verschluesselten lokalen Ablage.
//!
//! # Asynchron aussen, synchron innen
//!
//! Der Rust-Kern ist synchron. Diese Crate ist die Schale davor: jeder
//! blockierende Aufruf nach `ea-archive-fs` oder `ea-local-store` laeuft ueber
//! [`tokio::task::spawn_blocking`], und kein Kern erfaehrt von einer Laufzeit.

mod client;
mod queue;
mod receipt;
mod retry;

/// Die Attributmakro-Kante der objekt-sicheren Transportnaht.
///
/// RE-EXPORTIERT, damit ein Testdoppel in `tests/` [`SyncTransportV1`]
/// implementieren kann, ohne `async-trait` selbst als Dev-Kante zu fuehren —
/// zwei Kanten auf dasselbe Makro waeren zwei Fassungen desselben Vertrags.
pub use async_trait::async_trait;

/// Die VIER oeffentlichen Zustaende und ihre Detailursache DANEBEN.
///
/// Sie werden durchgereicht und nicht wiederholt: ein zweiter Satz
/// Zustandsnamen waere ein zweiter Satz Wahrheiten, und
/// `crates/ea-ui-contracts` emittiert die Oberflaechenliteralen aus derselben
/// Quelle.
pub use ea_archive_fs::{DetailCause, SyncStatus};

pub use client::{
    CONNECT_TIMEOUT_MS_V1, HyperTlsTransport, PushSummary, REQUEST_TIMEOUT_MS_V1, SyncClient,
    SyncClientConfigV1, SyncTransportV1, TransportErrorV1, TransportRequestV1, TransportResponseV1,
};
pub use queue::{PendingEntryV1, PendingStepV1, SyncQueueV1, step_of, sync_state_of};
pub use receipt::{VerifiedReceiptV1, entry_is_server_confirmed, verify_receipt_against_archive};
pub use retry::{OsJitter, RetryScheduleV1, RetryStore, SYNC_RETRY_TABLE_V1};

/// Der Fehlschlag eines Sync-Laufs — ein stabiler CODE und kein Fliesstext.
///
/// # Warum kein Klartext danebensteht
///
/// `design.md` §11.3 verbietet fachlichen Klartext in Protokollen und
/// Fehlermeldungen. Diese Aufzaehlung traegt deshalb keinen Nutzdatenanteil,
/// keinen Pfad und keine Kennung — auch nicht in [`core::fmt::Debug`], das
/// hier von Hand auf den Code zeigt.
///
/// # Warum die Codes NEU sind und nicht die des Protokolls
///
/// `ea_sync_protocol::SyncProtocolError` traegt seine eigene `EA-SYNC-`-
/// Familie fuer RAHMEN und LEITUNG. Diese hier benennt die Entscheidungen des
/// KLIENTEN — verworfene Quittung, erschoepfte Wiederaufnahme, nicht
/// wiederholbare Ablehnung —, und keiner ihrer Codes kollidiert mit jenen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncClientError {
    /// Der lokale Bestand liess sich nicht lesen oder nicht beschreiben.
    Archive,
    /// Die committeten Bytes ergeben keine Warteschlange: ein `.eip` ohne
    /// vollstaendige initiale Grants, oder ein Grant-Plan, dessen Hash nicht
    /// der des Manifests ist.
    QueueDerivation,
    /// Der Transport hat nach der begrenzten Wiederaufnahme aufgegeben.
    ResumeAttemptsExhausted,
    /// Der Dienst hat abgelehnt, und die Ablehnung wird NICHT automatisch
    /// wiederholt: Format, Signatur, Fork, Registry oder Autorisierung.
    NotAutomaticallyRetried,
    /// Die Quittung hat die vollstaendige Verifikation nicht bestanden.
    ReceiptInvalid,
    /// Die verifizierte Quittung liess sich nicht dauerhaft ablegen.
    ReceiptNotPersisted,
    /// Der Wiederaufnahmezustand der lokalen Ablage ist nicht lesbar.
    RetryStateUnreadable,
    /// Ein Rahmen liess sich nicht bilden oder nicht lesen.
    Protocol,
}

impl SyncClientError {
    /// Der STABILE Code. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Archive => "EA-SYNC-CLIENT-ARCHIVE",
            Self::QueueDerivation => "EA-SYNC-CLIENT-QUEUE-DERIVATION",
            Self::ResumeAttemptsExhausted => "EA-SYNC-CLIENT-RESUME-EXHAUSTED",
            Self::NotAutomaticallyRetried => "EA-SYNC-CLIENT-NOT-RETRIED",
            Self::ReceiptInvalid => "EA-SYNC-RECEIPT-INVALID",
            Self::ReceiptNotPersisted => "EA-SYNC-RECEIPT-NOT-PERSISTED",
            Self::RetryStateUnreadable => "EA-SYNC-CLIENT-RETRY-STATE",
            Self::Protocol => "EA-SYNC-CLIENT-PROTOCOL",
        }
    }

    /// Alle Codes, in Deklarationsreihenfolge.
    pub const ALL: [Self; 8] = [
        Self::Archive,
        Self::QueueDerivation,
        Self::ResumeAttemptsExhausted,
        Self::NotAutomaticallyRetried,
        Self::ReceiptInvalid,
        Self::ReceiptNotPersisted,
        Self::RetryStateUnreadable,
        Self::Protocol,
    ];
}

impl core::fmt::Display for SyncClientError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SyncClientError {}

impl From<ea_archive::ArchiveBackendError> for SyncClientError {
    fn from(_: ea_archive::ArchiveBackendError) -> Self {
        Self::Archive
    }
}

impl From<ea_archive::ArchiveError> for SyncClientError {
    fn from(_: ea_archive::ArchiveError) -> Self {
        Self::Archive
    }
}

impl From<ea_format::FormatError> for SyncClientError {
    fn from(_: ea_format::FormatError) -> Self {
        Self::QueueDerivation
    }
}

impl From<ea_sync_protocol::SyncProtocolError> for SyncClientError {
    fn from(_: ea_sync_protocol::SyncProtocolError) -> Self {
        Self::Protocol
    }
}

#[cfg(test)]
mod tests {
    use super::SyncClientError;

    /// Jeder Code ist eindeutig, traegt das Praefix der Familie und kollidiert
    /// mit KEINEM Code des Protokollrahmens.
    ///
    /// Die dritte Haelfte ist der eigentliche Punkt: `ea-sync-protocol` fuehrt
    /// eine eigene `EA-SYNC-`-Familie, und zwei gleiche Codes mit zwei
    /// Bedeutungen waeren genau die zweite Wahrheit, die dieser Task
    /// abschafft.
    #[test]
    fn every_client_code_is_unique_and_free_of_the_protocol_family() {
        let mut seen = std::collections::BTreeSet::new();
        for error in SyncClientError::ALL {
            assert!(error.code().starts_with("EA-SYNC-"));
            assert!(seen.insert(error.code()), "{} steht zweimal", error.code());
        }
        for protocol in ea_sync_protocol::SyncProtocolError::ALL {
            assert!(
                !seen.contains(protocol.code()),
                "{} kollidiert mit dem Protokollrahmen",
                protocol.code()
            );
        }
    }
}
