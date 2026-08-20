use core::fmt;

use ea_format::FormatError;

/// Fehler beim SCHREIBEN in einen Bestand.
///
/// Bewusst NICHT [`ArchiveError`](crate::ArchiveError): jener beschreibt
/// ausschliesslich, dass ein Bestand nicht weiter DURCHLAUFEN werden kann
/// (`crates/ea-archive/src/error.rs`), und ein Bytekonflikt ist ein Befund
/// ueber ein EINZELNES Objekt. Diese beiden Fehlerklassen zusammenzulegen
/// bricht den Vertrag des Lesefehlers.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArchiveBackendError {
    /// Der Zielpfad existiert schon und traegt ANDERE Bytes.
    ///
    /// Create-if-absent ist idempotent fuer bytegleiche Wiederholungen und
    /// fail-closed fuer alles andere. Ohne diesen Arm liesse sich ein Objekt
    /// still ueberschreiben.
    ByteConflict,
    /// Ein zweiter exklusiver Schreibersperrversuch.
    AlreadyLocked,
    /// Quelle und Ziel eines Rename liegen auf verschiedenen Dateisystemen.
    ///
    /// Wird ABGELEHNT und nicht durch Kopieren ersetzt: ein Kopieren waere
    /// nicht atomar, und genau die Atomarheit ist die Zusage.
    NotSameFilesystem,
    /// Eine Datei- oder Verzeichnis-Flush-Operation ist nicht durchgekommen.
    FlushFailed,
    /// Das Wirtdateisystem hat die Operation abgelehnt.
    Io,
    /// Der Pfad ist keine gueltige Transportadresse innerhalb eines Bestands.
    Path,
    /// Der `archiveProfileHash` steht nicht in `allowed-archive-profile-hashes`
    /// der gebundenen Policy.
    ProfileNotAllowed,
    /// Ein generischer UNC-, SMB-, NFS- oder WebDAV-Pfad ohne freigegebenes
    /// Profil.
    UnprofiledNetworkPath,
    /// Ein kontrolliertes Netzprofil ohne verschluesselte lokale
    /// Commit-Komponente.
    MissingLocalCommitComponent,
    /// Der Bedienernachweis traegt nicht genau den verlangten Zweck.
    ReauthMismatch,
    /// Ein eingespielter Fehlerpunkt der Migration hat gegriffen.
    MigrationFault,
    /// Quell- und Zielinventar stimmen nicht ueberein.
    InventoryMismatch,
    /// Die vollstaendige Offlineverifikation des Ziels hat nicht getragen.
    VerificationFailed,
    /// Die signierte Auditzeile liess sich nicht schreiben.
    AuditFailed,
    /// Ein Kodier- oder Formfehler eines Urbilds.
    Format(FormatError),
}

impl ArchiveBackendError {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ByteConflict => "EA-ARCHIVE-BYTE-CONFLICT",
            Self::AlreadyLocked => "EA-ARCHIVE-ALREADY-LOCKED",
            Self::NotSameFilesystem => "EA-ARCHIVE-NOT-SAME-FILESYSTEM",
            Self::FlushFailed => "EA-ARCHIVE-FLUSH-FAILED",
            Self::Io => "EA-ARCHIVE-IO",
            Self::Path => "EA-ARCHIVE-PATH",
            Self::ProfileNotAllowed => "EA-ARCHIVE-PROFILE-NOT-ALLOWED",
            Self::UnprofiledNetworkPath => "EA-ARCHIVE-UNPROFILED-NETWORK-PATH",
            Self::MissingLocalCommitComponent => "EA-ARCHIVE-MISSING-LOCAL-COMMIT",
            Self::ReauthMismatch => "EA-ARCHIVE-REAUTH-MISMATCH",
            Self::MigrationFault => "EA-ARCHIVE-MIGRATION-FAULT",
            Self::InventoryMismatch => "EA-ARCHIVE-INVENTORY-MISMATCH",
            Self::VerificationFailed => "EA-ARCHIVE-VERIFICATION-FAILED",
            Self::AuditFailed => "EA-ARCHIVE-AUDIT-FAILED",
            Self::Format(error) => error.code(),
        }
    }
}

impl From<FormatError> for ArchiveBackendError {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}

impl fmt::Display for ArchiveBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ArchiveBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ArchiveBackendError {}
