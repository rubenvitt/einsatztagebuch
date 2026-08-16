use core::fmt;

use ea_archive::ArchiveError;

/// Fehler, die den Verifikationslauf ALS GANZES abbrechen.
///
/// Scharfe Abgrenzung, wie schon bei [`ArchiveError`]: ein Befund ueber ein
/// einzelnes Objekt — unlesbar, doppelt, widerspruechlich, unzuordenbar — ist
/// NIE ein `VerifyError`. Solche Befunde erscheinen als `formatErrors` und
/// `quarantinedObjects` im Bericht, und der Lauf liefert `Ok`. Ein `Err` sagt
/// ausschliesslich: ueber diesen Bestand laesst sich gar kein Bericht bilden.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerifyError {
    /// Der Bestand liess sich nicht vollstaendig durchlaufen.
    Archive(ArchiveError),
    /// Der Berichtsschreiber sollte ein Zeichen ausgeben, das ausserhalb der
    /// zugelassenen Zeichenmengen liegt.
    ///
    /// Kann nur eintreten, wenn irgendwo unkontrollierter Text in den Bericht
    /// gelangt waere. Genau deshalb bricht der Schreiber hier ab, statt zu
    /// maskieren: der Bericht kennt keine freien Zeichenketten, und was keine
    /// ist, darf auch nicht als solche hinausgehen.
    NonCanonicalReport,
}

impl VerifyError {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Archive(error) => error.code(),
            Self::NonCanonicalReport => "EA-VERIFY-NON-CANONICAL-REPORT",
        }
    }
}

impl From<ArchiveError> for VerifyError {
    fn from(error: ArchiveError) -> Self {
        Self::Archive(error)
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for VerifyError {}
