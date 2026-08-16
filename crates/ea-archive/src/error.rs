use core::fmt;

/// Fehler beim Durchlaufen eines Bestands.
///
/// Diese Variante beschreibt AUSSCHLIESSLICH, dass der Bestand nicht weiter
/// durchlaufen werden kann, nie einen Befund ueber ein einzelnes Objekt.
/// Unlesbare, doppelte oder widerspruechliche Objekte sind Befunde und
/// erscheinen als Quarantaene im Bericht, nicht als `ArchiveError`.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArchiveError {
    /// Der zugrunde liegende Bestand kann Bytes nicht liefern.
    Unavailable,
    /// Die Zahl der Bytesequenzen uebersteigt
    /// [`MAX_ARCHIVE_BLOBS_V1`](crate::MAX_ARCHIVE_BLOBS_V1).
    BlobLimit,
    /// Die Gesamtbytezahl uebersteigt
    /// [`MAX_TOTAL_ARCHIVE_BYTES_V1`](crate::MAX_TOTAL_ARCHIVE_BYTES_V1).
    TotalByteLimit,
}

impl ArchiveError {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "EA-ARCHIVE-UNAVAILABLE",
            Self::BlobLimit => "EA-ARCHIVE-BLOB-LIMIT",
            Self::TotalByteLimit => "EA-ARCHIVE-TOTAL-BYTE-LIMIT",
        }
    }
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ArchiveError {}
