//! Zeremonie A des Reader-Key-Escrows im Browser (Profil §5, Scheibe e).

use ea_crypto::CryptoError;
use ea_sync_protocol::SyncProtocolError;

/// Der Fehlschlag einer Escrow-Zeremonie im Browser.
///
/// Die eigenen Varianten tragen ihren Code ausgeschrieben, die
/// durchreichenden geben den Code IHRER QUELLE weiter — dieselbe Regel wie
/// bei [`crate::EnrollmentError`].
#[derive(Debug)]
pub enum ReaderKeyEscrowError {
    /// `ea-crypto` hat abgewiesen.
    Crypto(CryptoError),
    /// Ein Protokollrahmen hat abgewiesen.
    Protocol(SyncProtocolError),
}

impl ReaderKeyEscrowError {
    /// Der stabile Code des Fehlschlags.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Crypto(error) => error.code(),
            Self::Protocol(error) => error.code(),
        }
    }
}

impl From<CryptoError> for ReaderKeyEscrowError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<SyncProtocolError> for ReaderKeyEscrowError {
    fn from(error: SyncProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl core::fmt::Display for ReaderKeyEscrowError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ReaderKeyEscrowError {}
