//! Der Fehlerbegriff der Zeremonie.

use core::fmt;

use ea_crypto::CryptoError;
use ea_format::FormatError;
use ea_key_provider::KeyError;
use ea_trust::TrustError;

/// Ein Fehlschlag an der Grenze des Zeremoniendienstes.
///
/// # Warum das Praefix `EA-CEREMONY-` heisst und nicht `EA-ADMIN-`
///
/// `EA-ADMIN-` ist bereits vergeben, und zwar als AKTIONSCODE-Namensraum der
/// acht Serverzeilen des technischen Verwaltungsaudits
/// (`apps/server/src/admin_audit.rs`, in `docs/traceability/stage-3-gate.md`
/// als „acht `EA-ADMIN-`-Codes" gefuehrt). Jene Codes stehen IN ausgelieferten
/// Auditzeilen und benennen eine Handlung; ein Fehlercode desselben Praefixes
/// benennte einen Abbruch. Beides in einer Familie zu fuehren hiesse, dass ein
/// Leser einer Zeile nicht mehr entscheiden kann, ob `EA-ADMIN-…` eine
/// vollzogene Handlung oder ihr Scheitern meldet.
///
/// `EA-CEREMONY-` benennt stattdessen den Gegenstand dieser Crate — die
/// Zeremonie — und ist im ganzen Baum frei
/// (`grep -o '"EA-[A-Z0-9]*-' crates apps` kennt 45 Familien, diese nicht).
///
/// Die durchgereichten Arme behalten den Code ihrer Herkunft. Insbesondere ist
/// die Wiedereinspielung einer Administrationsautorisierung weiterhin
/// [`TrustError::AuthReplay`] mit `EA-TRUST-AUTH-REPLAY`: die Zusage gehoert
/// `ea-trust`, und ein zweiter Code fuer denselben Befund waere eine zweite
/// Wahrheit.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum AdminError {
    /// Der Bedienernachweis dient einem anderen Zweck, ist abgelaufen oder
    /// durch die Bildschirmsperre entwertet.
    ReauthMismatch,
    /// Der Nachweis gehoert zu einer ANDEREN Bedienerbindung.
    ///
    /// `OperatorSessionProof::is_valid_for` prueft die Bindung ausdruecklich
    /// nicht; dieser Arm ist die Stelle, an der dieser Dienst sie prueft.
    BindingMismatch,
    /// Die Bedienerbindung ist am gewaehlten Kopf nicht aktiv.
    BindingInactive,
    /// Der Beweiszustand wurde gegen einen ANDEREN Registrierungsstand
    /// gefuehrt als den, gegen den dieser Dienst handelt.
    ///
    /// Zeit, Bedienerbindung, Wurzelzertifikat und Auditdienst kommen aus dem
    /// gewaehlten Kopf; ein Beweis aus einem veralteten Bestand duerfte unter
    /// einem aktuellen Kopf nicht wirken.
    HeadMismatch,
    /// Die vorgelegten Autorisierungsbytes sind nicht die, ueber die der
    /// Beweiszustand spricht.
    AuthorizationMismatch,
    /// Die vorgelegte Nutzlast traegt einen anderen Subtyp als den, den der
    /// Beweiszustand deckt.
    TargetMismatch,
    /// Die Auditzeile konnte nicht gebucht werden — die Zielbytes bleiben
    /// zurueck.
    AuditFailed,
    /// Ein Befund der Vertrauensschicht, unveraendert durchgereicht.
    Trust(TrustError),
    /// Ein Befund der Kryptografieschicht, unveraendert durchgereicht.
    Crypto(CryptoError),
    /// Ein Befund des Schluesselports, unveraendert durchgereicht.
    Key(KeyError),
    /// Ein Befund der Formatschicht, unveraendert durchgereicht.
    Format(FormatError),
}

impl AdminError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReauthMismatch => "EA-CEREMONY-REAUTH-MISMATCH",
            Self::BindingMismatch => "EA-CEREMONY-BINDING-MISMATCH",
            Self::BindingInactive => "EA-CEREMONY-BINDING-INACTIVE",
            Self::HeadMismatch => "EA-CEREMONY-HEAD-MISMATCH",
            Self::AuthorizationMismatch => "EA-CEREMONY-AUTHORIZATION-MISMATCH",
            Self::TargetMismatch => "EA-CEREMONY-TARGET-MISMATCH",
            Self::AuditFailed => "EA-CEREMONY-AUDIT-FAILED",
            Self::Trust(error) => error.code(),
            Self::Crypto(error) => error.code(),
            Self::Key(error) => error.code(),
            Self::Format(error) => error.code(),
        }
    }
}

impl From<TrustError> for AdminError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

impl From<CryptoError> for AdminError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<KeyError> for AdminError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<FormatError> for AdminError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

impl fmt::Display for AdminError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for AdminError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for AdminError {}
