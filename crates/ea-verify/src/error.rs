use core::fmt;

use ea_archive::ArchiveError;
use ea_crypto::CryptoError;

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

/// Der Befund von Gate `manifest-signature` ueber GENAU EIN Objekt.
///
/// Ausdruecklich KEIN [`VerifyError`]: ein Objekt, dessen Signatur nicht
/// traegt, bricht den Lauf nicht ab, sondern erscheint als
/// `signatureErrors`-Eintrag im Bericht. Der Lauf liefert `Ok`.
///
/// Die Codes bilden eine EIGENE Familie `EA-VERIFY-MANIFEST-*` und werden nicht
/// aus [`CryptoError::code`] durchgereicht: dessen Codes (`EA-TRUST-*`,
/// `EA-CRYPTO-*`) benennen die kryptografische Ursache, hier steht aber das
/// GATE im Bericht. Ein Leser des Berichts muss dem Code ansehen, welche der
/// neun Stufen aus `design.md` §14.1 gefallen ist.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ManifestSignatureErrorV1 {
    /// Der Signaturwert traegt nicht.
    ///
    /// Der geschuetzte Header und die Bindung an das Schreiberzertifikat sind
    /// unversehrt; allein die Ed25519-Pruefung schlaegt fehl.
    SignatureInvalid,
    /// Signierer und Manifest passen nicht zueinander.
    ///
    /// Deckt jede Bindung ab, die `verify_cose_sign1` VOR der eigentlichen
    /// Signaturpruefung verlangt — insbesondere den Schluesselabdruck im
    /// geschuetzten Header gegen den oeffentlichen Schluessel des aufgeloesten
    /// Zertifikats (`crates/ea-crypto/src/cose.rs:1435-1437`).
    SignerMismatch,
    /// Das Zertifikat des Signierers traegt hier keine Schreiberautoritaet.
    SignerUnauthorized,
    /// Die Signatur liess sich nicht pruefen.
    ///
    /// AUFFANGFALL, und deshalb notwendig: [`CryptoError`] ist
    /// `#[non_exhaustive]`, eine neue Variante darf diese Abbildung nicht
    /// brechen. Ein Befund bleibt ein Befund, auch wenn seine Ursache neu ist.
    Unverifiable,
}

impl ManifestSignatureErrorV1 {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SignatureInvalid => "EA-VERIFY-MANIFEST-SIGNATURE-INVALID",
            Self::SignerMismatch => "EA-VERIFY-MANIFEST-SIGNER-MISMATCH",
            Self::SignerUnauthorized => "EA-VERIFY-MANIFEST-SIGNER-UNAUTHORIZED",
            Self::Unverifiable => "EA-VERIFY-MANIFEST-UNVERIFIABLE",
        }
    }
}

impl From<CryptoError> for ManifestSignatureErrorV1 {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::SignatureInvalid => Self::SignatureInvalid,
            CryptoError::SignerMismatch => Self::SignerMismatch,
            CryptoError::SignerUnauthorized | CryptoError::SignerUnresolved => {
                Self::SignerUnauthorized
            }
            _ => Self::Unverifiable,
        }
    }
}

impl fmt::Display for ManifestSignatureErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}
