//! Der Fehler des Ein-Datei-Buendels.

use core::fmt;

/// Fehler beim SCHREIBEN oder LESEN eines Archivbuendels.
///
/// # Er erreicht die Traitgrenze NICHT
///
/// [`ArchiveSource::visit_blobs`](crate::ArchiveSource::visit_blobs) bleibt auf
/// `Result<(), ArchiveError>` festgelegt (`crates/ea-archive/src/source.rs`);
/// jeder Fall dieses Typs entsteht in
/// [`ArchiveBundleSource::from_bytes`](crate::ArchiveBundleSource::from_bytes)
/// oder in den Wirtswegen `ea_archive_fs::open_archive_bundle` und
/// `ea_archive_fs::write_archive_bundle` und endet dort. Der Container ist eine
/// Transportschale und veraendert keinen bestehenden Port.
///
/// # Die Liste bleibt GESCHLOSSEN, auch ueber die Crategrenze
///
/// `Io` steht hier, obwohl diese Crate kein `std::fs` beruehrt: die Variante
/// wird ausschliesslich in `crates/ea-archive-fs` konstruiert, und eine zweite
/// Fehleraufzaehlung dort waere der Weg, auf dem zwei Codes fuer denselben
/// Befund entstehen. Der Fehler des Containers gehoert zum Container, und der
/// Wirtsteil borgt ihn sich, statt ihn zu spiegeln.
///
/// # Kein Byte und kein Wirtpfad in der Ausgabe
///
/// Die Liste ist GESCHLOSSEN und jede Variante ist datenlos — genau die
/// Begruendung, die `crates/ea-recovery/src/source.rs:42-48` fuer
/// `FsArchiveSource` schon aufgeschrieben hat: ein abgeleitetes `Debug` gaebe
/// den Hostpfad und die Bestandsbytes heraus. `Debug` ist deshalb der
/// Fehlercode und nichts sonst.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum BundleError {
    /// Der Quellbestand ist nicht vollstaendig verifiziert.
    ///
    /// Auch der Fall, in dem die Verifikation gar nicht DURCHLAEUFT: ein
    /// Bestand, ueber den kein Bericht entsteht, ist nicht vollstaendig
    /// verifiziert, und ein zweiter Fehlerarm daneben waere dieselbe Aussage
    /// mit zwei Namen.
    SourceNotFullyVerified,
    /// Die Zieladresse ist belegt.
    ///
    /// Es wird NICHTS ueberschrieben und nichts angehaengt — dieselbe
    /// Freies-Ziel-Regel, die `crates/ea-recovery/src/target.rs` einmal
    /// aufschreibt.
    TargetOccupied,
    /// Der Container verletzt eine Strukturregel.
    ///
    /// Falsche Magie, ein Index, der nicht genau aufgeht, eine unsortierte
    /// oder doppelte Adresse, eine Luecke, eine Ueberlappung oder eine
    /// abgeschnittene Nutzlast.
    Malformed,
    /// Der Container fuehrt mehr Bytesequenzen als
    /// [`MAX_ARCHIVE_BLOBS_V1`](crate::MAX_ARCHIVE_BLOBS_V1).
    BlobLimit,
    /// Die Nutzlast ueberschreitet
    /// [`MAX_TOTAL_ARCHIVE_BYTES_V1`](crate::MAX_TOTAL_ARCHIVE_BYTES_V1).
    TotalByteLimit,
    /// Das Wirtdateisystem hat die Operation abgelehnt.
    Io,
}

impl BundleError {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SourceNotFullyVerified => "EA-BUNDLE-SOURCE-NOT-FULLY-VERIFIED",
            Self::TargetOccupied => "EA-BUNDLE-TARGET-OCCUPIED",
            Self::Malformed => "EA-BUNDLE-MALFORMED",
            Self::BlobLimit => "EA-BUNDLE-BLOB-LIMIT",
            Self::TotalByteLimit => "EA-BUNDLE-TOTAL-BYTE-LIMIT",
            Self::Io => "EA-BUNDLE-IO",
        }
    }
}

impl fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for BundleError {}
