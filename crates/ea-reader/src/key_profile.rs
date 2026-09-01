//! Das Schluesselprofil des Readers: vier fail-closed-Klauseln, und die vierte
//! ist die einzige, die ohne sie durchginge.
//!
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §6.1
//! gibt dem Reader ZWEI getrennte Schluessel: X25519 fuer die HPKE-Entkapselung,
//! Ed25519 fuer Geraet und Audit. [`ReaderKeyProfile::validate`] entscheidet
//! gegen die GEPARSTEN Felder eines `DeviceCertificateFieldsV1` und nie gegen
//! rohe Zeichenketten — dieselbe Regel, die
//! `WriterKeyProfile::validate_capabilities` in
//! `crates/ea-key-provider/src/profile.rs` aufschreibt.
//!
//! # Die Reihenfolge der Klauseln ist selbst begruendet
//!
//! 1. **Rolle.** Ein Writer-Zertifikat faellt an der ERSTEN Klausel und nicht
//!    an einem fehlenden Schluessel: die Rolle entscheidet, nicht die
//!    Ausstattung. Sonst laese sich ein falsch ausgestelltes Zertifikat nicht
//!    von einem unvollstaendig ausgestatteten unterscheiden.
//! 2. **Anwesenheit und Kurve.** Beide oeffentlichen COSE-Schluessel muessen
//!    vorliegen und ueber `CanonicalPublicCoseKey::from_deterministic_cbor` als
//!    X25519 beziehungsweise Ed25519 aufgehen.
//! 3. **Abdruck passt zum Schluessel.** Die beiden `KeyThumbprint`-Felder
//!    muessen `CanonicalPublicCoseKey::thumbprint()` der jeweiligen Schluessel
//!    sein.
//! 4. **Rollenkollision.** Die 32 ROHEN Schluesselbytes der beiden Rollen
//!    muessen verschieden sein.
//!
//! # Warum Klausel 4 ueber die ROHBYTES entscheidet und nicht ueber Abdruecke
//!
//! `CanonicalPublicCoseKey::to_deterministic_cbor` schreibt die Kurve mit —
//! `crv 6` fuer Ed25519, `crv 4` fuer X25519. DIESELBEN 32 Bytes tragen in
//! beiden Rollen also zwei VERSCHIEDENE Abdruecke und passierten jede
//! Prueferei, die nur Abdruecke vergleicht. Genau deshalb ist
//! `EA-KEY-ROLE-COLLISION` ein eigener Code, und
//! `reader_requires_distinct_kem_and_authentication_keys` ist seine einzige
//! Messung. `CanonicalPublicCoseKey` hat keinen Zugriff auf seine Rohbytes
//! ausser ueber die beiden oeffentlichen Tupelvarianten; der Vergleich laeuft
//! deshalb ueber ein Muster und nicht ueber einen Akzessor.
//!
//! # Warum der Code das Praefix `EA-KEY-` traegt
//!
//! Es gehoert bisher `ea_key_provider::KeyError`. Der neue Code entsteht
//! trotzdem HIER, weil `crates/ea-key-provider` auf `WASM32_EXEMPT_CRATES`
//! steht — es greift in den Betriebssystem-Keystore — und ein Reader gar keinen
//! Writer-Schluessel haelt. Das Praefix benennt die SACHE (eine
//! Schluesselrollenkollision) und nicht die Crate; ohne diesen Absatz laese es
//! sich als versehentlicher Praefixdiebstahl lesen.
//!
//! # Reader-Zertifikate tragen KEINE Capabilities
//!
//! `crates/ea-trust/tests/support/mod.rs` gibt `CertificateKindV1::Reader` eine
//! LEERE Capability-Liste. Eine Capability-Forderung hier wiese also jedes
//! echte Reader-Zertifikat ab; geprueft werden die Rolle, die zwei Schluessel,
//! die zwei Abdruecke und die Byte-Ungleichheit — nichts sonst.

use core::fmt;

use ea_crypto::{CanonicalPublicCoseKey, CryptoError};
use ea_format::{CertificateKindV1, DeviceCertificateFieldsV1};
use ea_types::KeyThumbprint;

/// Der Fehlschlag der Profilpruefung.
///
/// Ein eigener Typ neben `ReaderVaultError`, weil ein Zertifikat kein Tresor
/// ist: die Pruefung laeuft, bevor je ein Tresor existiert, und ein gemeinsamer
/// Typ zwaenge jeden Aufrufer, Faelle zu behandeln, die an seiner Stelle gar
/// nicht auftreten koennen.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ReaderKeyProfileError {
    /// Das Zertifikat ist keines der Rolle `Reader`.
    CertificateKind,
    /// Ein oeffentlicher Schluessel oder sein Abdruck fehlt.
    MissingPublicKey,
    /// Ein Schluessel liegt auf der falschen Kurve fuer seine Rolle.
    UnexpectedKeyRole,
    /// Ein hinterlegter Abdruck gehoert nicht zu seinem Schluessel.
    ThumbprintMismatch,
    /// Beide Rollen tragen DIESELBEN 32 Rohbytes.
    RoleCollision,
    /// `ea-crypto` konnte einen der beiden COSE-Schluessel nicht lesen.
    Crypto(CryptoError),
}

impl ReaderKeyProfileError {
    /// Der stabile Code des Fehlschlags.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CertificateKind => "EA-READER-KEY-CERTIFICATE-KIND",
            Self::MissingPublicKey => "EA-READER-KEY-MISSING-PUBLIC-KEY",
            Self::UnexpectedKeyRole => "EA-READER-KEY-UNEXPECTED-ROLE",
            Self::ThumbprintMismatch => "EA-READER-KEY-THUMBPRINT-MISMATCH",
            Self::RoleCollision => "EA-KEY-ROLE-COLLISION",
            Self::Crypto(error) => error.code(),
        }
    }
}

impl From<CryptoError> for ReaderKeyProfileError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl fmt::Display for ReaderKeyProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReaderKeyProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReaderKeyProfileError {}

/// Das gepruefte Schluesselpaar eines Reader-Zertifikats.
///
/// Der Typ ist der BELEG der Pruefung und nicht ihre Eingabe: er entsteht
/// ausschliesslich in [`ReaderKeyProfile::validate`], und wer ihn haelt, weiss
/// damit, dass alle vier Klauseln gehalten haben.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderKeyProfile {
    kem_public_key: CanonicalPublicCoseKey,
    signing_public_key: CanonicalPublicCoseKey,
    kem_key_thumbprint: KeyThumbprint,
    signing_key_thumbprint: KeyThumbprint,
}

impl ReaderKeyProfile {
    /// Prueft ein Geraetezertifikat fail-closed gegen die vier Klauseln.
    ///
    /// # Errors
    /// `EA-READER-KEY-CERTIFICATE-KIND`, `EA-READER-KEY-MISSING-PUBLIC-KEY`,
    /// `EA-READER-KEY-UNEXPECTED-ROLE`, `EA-READER-KEY-THUMBPRINT-MISMATCH`,
    /// `EA-KEY-ROLE-COLLISION` sowie die durchgereichten Codes von
    /// `ea-crypto`, wenn ein COSE-Schluessel nicht lesbar ist.
    pub fn validate(fields: &DeviceCertificateFieldsV1) -> Result<Self, ReaderKeyProfileError> {
        if fields.certificate_kind != CertificateKindV1::Reader {
            return Err(ReaderKeyProfileError::CertificateKind);
        }

        let kem_public_key = decode_key(fields.kem_public_cose_key.as_deref())?;
        let signing_public_key = decode_key(fields.signing_public_cose_key.as_deref())?;
        let kem_key_thumbprint = fields
            .kem_key_thumbprint
            .ok_or(ReaderKeyProfileError::MissingPublicKey)?;
        let signing_key_thumbprint = fields
            .signing_key_thumbprint
            .ok_or(ReaderKeyProfileError::MissingPublicKey)?;

        // Die Kurve traegt die Rolle. Erschoepfend und ohne `_`-Auffangfall,
        // damit eine neue Variante von `CanonicalPublicCoseKey` die
        // Uebersetzung bricht, statt still durchzugehen.
        let kem_bytes = match &kem_public_key {
            CanonicalPublicCoseKey::X25519(bytes) => bytes,
            CanonicalPublicCoseKey::Ed25519(_) => {
                return Err(ReaderKeyProfileError::UnexpectedKeyRole);
            }
        };
        let signing_bytes = match &signing_public_key {
            CanonicalPublicCoseKey::Ed25519(bytes) => bytes,
            CanonicalPublicCoseKey::X25519(_) => {
                return Err(ReaderKeyProfileError::UnexpectedKeyRole);
            }
        };

        if kem_public_key.thumbprint() != kem_key_thumbprint
            || signing_public_key.thumbprint() != signing_key_thumbprint
        {
            return Err(ReaderKeyProfileError::ThumbprintMismatch);
        }

        // Klausel 4: die ROHEN Bytes, nicht die Abdruecke. Ein Abdruckvergleich
        // an dieser Stelle ginge nachweislich durch — die Kurve geht in den
        // Abdruck ein.
        if kem_bytes == signing_bytes {
            return Err(ReaderKeyProfileError::RoleCollision);
        }

        Ok(Self {
            kem_public_key,
            signing_public_key,
            kem_key_thumbprint,
            signing_key_thumbprint,
        })
    }

    /// Der oeffentliche X25519-Schluessel der Entkapselung.
    #[must_use]
    pub const fn kem_public_key(&self) -> &CanonicalPublicCoseKey {
        &self.kem_public_key
    }

    /// Der oeffentliche Ed25519-Schluessel von Geraet und Audit.
    #[must_use]
    pub const fn signing_public_key(&self) -> &CanonicalPublicCoseKey {
        &self.signing_public_key
    }

    /// Der Abdruck des KEM-Schluessels.
    #[must_use]
    pub const fn kem_key_thumbprint(&self) -> KeyThumbprint {
        self.kem_key_thumbprint
    }

    /// Der Abdruck des Signaturschluessels.
    #[must_use]
    pub const fn signing_key_thumbprint(&self) -> KeyThumbprint {
        self.signing_key_thumbprint
    }
}

impl fmt::Debug for ReaderKeyProfile {
    /// Nennt AUSSCHLIESSLICH die beiden Abdruecke, hex geschrieben.
    ///
    /// Ein abgeleitetes `Debug` uebersetzt nicht — `KeyThumbprint` und
    /// `CanonicalPublicCoseKey` tragen keins — und es waere hier auch nicht
    /// gewollt: der Abdruck sagt alles, was ein Fehlschlag braucht.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderKeyProfile { kem_key_thumbprint: ")?;
        write_hex(formatter, self.kem_key_thumbprint.as_bytes())?;
        formatter.write_str(", signing_key_thumbprint: ")?;
        write_hex(formatter, self.signing_key_thumbprint.as_bytes())?;
        formatter.write_str(" }")
    }
}

/// Liest einen oeffentlichen COSE-Schluessel oder weist ihn ab.
fn decode_key(bytes: Option<&[u8]>) -> Result<CanonicalPublicCoseKey, ReaderKeyProfileError> {
    let bytes = bytes.ok_or(ReaderKeyProfileError::MissingPublicKey)?;
    Ok(CanonicalPublicCoseKey::from_deterministic_cbor(bytes)?)
}

/// Schreibt Bytes als Kleinbuchstaben-Hex.
fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
