//! Der menschenlesbare Fingerprint: 32 Paare Gross-Hex, durch Doppelpunkte
//! getrennt — und der Rueckweg zum [`ObjectHash`].
//!
//! # Was ein Fingerprint hier IST
//!
//! Der Objekthash der exakten Zertifikatsbytes, und nichts Zweites
//! ([`crate::device::PendingDeviceRegistration::fingerprint`]). Dieses Modul
//! rechnet ihn nicht — es SCHREIBT ihn, so dass zwei Menschen ihn ueber einen
//! zweiten Kanal Paar fuer Paar vergleichen koennen, und LIEST ihn zurueck,
//! damit die Rueckmeldung als [`ObjectHash`] gegen
//! [`crate::device::confirm_device_fingerprint`] laufen kann.
//!
//! # Warum das hier liegt und nicht in `ea-types` oder in TypeScript
//!
//! `ea-types` fuehrt bewusst keinen Zeichenkettenzugriff auf seine Hashes; die
//! Byteform gehoert dem Archiv. TypeScript darf keinen Hash rechnen und soll
//! auch keinen formatieren, weil `apps/desktop/src/bridge/generated-contracts.ts`
//! nur fertige Zeichenketten traegt. Uebrig bleibt der administrative Kern:
//! hier entsteht die Schreibweise EINMAL, und die Schale zeigt sie an.
//!
//! # Die Schreibweise
//!
//! `AA:BB:…` — genau `^([0-9A-F]{2}:){31}[0-9A-F]{2}$`. Grossbuchstaben, weil
//! `B` und `8`, `D` und `0` in Kleinschreibung auf einem Telefon schwerer zu
//! unterscheiden sind; Doppelpunkte, damit der Vergleich in Paaren laeuft und
//! eine ausgelassene Stelle auffaellt. Der Rueckweg ist grosszuegiger als der
//! Hinweg: Klein- und Grossschreibung, mit oder ohne Doppelpunkte, Leerraum an
//! den Enden. Alles andere — ein Paar zu wenig oder zu viel, ein Zeichen, das
//! kein Hex ist, Leerraum in der Mitte — ist mit EINEM Code unlesbar.

use core::fmt;

use ea_types::ObjectHash;

/// Der stabile Code eines unlesbaren Fingerprints.
///
/// `EA-WORKFLOW-`, weil der Fingerprint-Vergleich ein Schritt des
/// Registrierungs-Workflows ist (`EA-WORKFLOW-FINGERPRINT-MISMATCH` in
/// [`crate::registry::RegistryWorkflowError`] ist sein Nachbar): dort ist er
/// gelesen und passt nicht, hier ist er gar nicht erst lesbar.
pub const FINGERPRINT_PARSE_ERROR: &str = "EA-WORKFLOW-FINGERPRINT-UNREADABLE";

/// Die Zahl der Bytes eines Fingerprints — und damit der Paare.
const PAIR_COUNT: usize = 32;

/// Die Rueckmeldung eines Fingerprints ist nicht lesbar.
///
/// EIN Arm fuer jede Form der Unlesbarkeit: zu kurz, zu lang, kein Hex,
/// Leerraum in der Mitte. Die Abhilfe ist in allen Faellen dieselbe — noch
/// einmal vergleichen und noch einmal eingeben —, und ein Code je Ursache
/// verriete einem Angreifer, der eine Rueckmeldung erraten will, an welcher
/// Stelle er nachbessern muss.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum FingerprintParseError {
    /// Die Zeichenkette ist keine der angenommenen Schreibweisen.
    Unreadable,
}

impl FingerprintParseError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unreadable => FINGERPRINT_PARSE_ERROR,
        }
    }
}

impl fmt::Display for FingerprintParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for FingerprintParseError {
    /// AUSSCHLIESSLICH der Code: die abgewiesene Eingabe koennte ein halb
    /// getippter Fingerprint sein, und der gehoert in kein Protokoll.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for FingerprintParseError {}

/// Der Fingerprint als `AA:BB:…` — 32 Paare Gross-Hex, durch Doppelpunkte
/// getrennt.
#[must_use]
pub fn human_readable_fingerprint(hash: &ObjectHash) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(PAIR_COUNT * 3 - 1);
    for (index, byte) in hash.as_bytes().iter().enumerate() {
        if index > 0 {
            out.push(':');
        }
        // Ein `write!` in einen `String` schlaegt nicht fehl.
        let _ = write!(out, "{byte:02X}");
    }
    out
}

/// Der Rueckweg: eine Rueckmeldung als [`ObjectHash`].
///
/// Angenommen werden Gross- und Kleinschreibung, die Form mit 31 Doppelpunkten
/// und die Form ganz ohne, jeweils mit Leerraum an den Enden.
///
/// # Errors
///
/// [`FingerprintParseError::Unreadable`] fuer jede andere Zeichenkette.
pub fn parse_human_readable_fingerprint(text: &str) -> Result<ObjectHash, FingerprintParseError> {
    let trimmed = text.trim();
    let mut bytes = [0_u8; PAIR_COUNT];
    let pairs: Vec<&str> = trimmed.split(':').collect();
    match pairs.as_slice() {
        [compact] if compact.len() == PAIR_COUNT * 2 => {
            hex::decode_to_slice(compact, &mut bytes)
                .map_err(|_| FingerprintParseError::Unreadable)?;
        }
        separated if separated.len() == PAIR_COUNT => {
            for (slot, pair) in bytes.iter_mut().zip(separated) {
                if pair.len() != 2 {
                    return Err(FingerprintParseError::Unreadable);
                }
                let mut one = [0_u8; 1];
                hex::decode_to_slice(pair, &mut one)
                    .map_err(|_| FingerprintParseError::Unreadable)?;
                *slot = one[0];
            }
        }
        _ => return Err(FingerprintParseError::Unreadable),
    }
    ObjectHash::try_from(bytes.as_slice()).map_err(|_| FingerprintParseError::Unreadable)
}
