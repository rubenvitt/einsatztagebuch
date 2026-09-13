//! Frozen, fully verified inputs for historical grant issuance.
use std::{fs, path::Path};

use crate::{ResolvedRecipientKey, ResolvedSigningKey};
use ea_trust::TrustAnchorV1;
use ea_types::UnixMillis;
use ea_verify::VerificationReportV1;

use crate::{
    ExitCode, FsArchiveSource, KeySourceSpec, RecoveryError,
    decrypt::recipient_key_thumbprint,
    exit_code_for,
    key_source::{resolve_recipient_key, resolve_signing_key},
    verify::verify_source,
};

/// Das Ergebnis eines vollstaendigen `grant`-Eingabelaufs.
///
/// Traegt den BERICHT und nicht bloss einen Code — derselbe Weg wie bei
/// [`crate::DecryptionV1`], damit es fuer denselben Bericht nur EINE
/// Ableitung gibt: der Aufrufer leitet den Exitcode mit [`exit_code_for`]
/// daraus ab.
///
/// # Kein `Debug`
///
/// [`ResolvedGrantInputsV1`] haelt zwei private Schluessel. Ein `Debug` auf
/// dem Traeger waere der bequemste Weg, sie in eine Protokollzeile zu
/// bringen.
pub struct GrantInputsV1 {
    /// Der vollstaendige Verifikationsbericht des Laufs.
    pub report: VerificationReportV1,
    /// Die aufgeloesten Eingaben — `None` GENAU DANN, wenn der Bericht einen
    /// Befund traegt.
    ///
    /// Die Aequivalenz ist die Zusicherung von Schritt 3 der Modulnotiz: bei
    /// einem Befund wird kein weiterer Schluessel aufgeloest und keine Datei
    /// gelesen, also gibt es auch nichts, was hier stehen koennte.
    pub resolved: Option<ResolvedGrantInputsV1>,
}

/// Die vier Eingaben von `grant`, aufgeloest und gelesen.
///
/// # Die Schluessel sind PRIVAT, die Bytes oeffentlich
///
/// Die beiden Dateien tragen oeffentliche Objekte — eine signierte
/// Autorisierung und ein Zertifikat —, und der HistoricalGrantService prueft sie
/// vor der Erzeugung; sie duerfen als Felder herausgegeben werden. Die beiden Schluessel
/// sind Geheimnisse und gehen nur ueber Zugriffe heraus, damit ein Aufrufer
/// bewusst entscheidet, was er damit tut. Kein `Debug` — siehe
/// [`GrantInputsV1`].
pub struct ResolvedGrantInputsV1 {
    /// Die EXAKTEN Bytes der Autorisierungsdatei, ungeparst.
    pub authorization_bytes: Vec<u8>,
    /// Die EXAKTEN Bytes des Empfaengerzertifikats, ungeparst.
    pub recipient_certificate_bytes: Vec<u8>,
    source: FsArchiveSource,
    recovery_key: ResolvedRecipientKey,
    authority: ResolvedSigningKey,
}

impl ResolvedGrantInputsV1 {
    /// Immutable archive snapshot verified before resolving the HGA key.
    pub fn source(&self) -> &FsArchiveSource {
        &self.source
    }
    /// Der private Recovery-KEM-Schluessel, mit dessen Abdruck verifiziert
    /// wurde.
    #[must_use]
    pub const fn recovery_key(&self) -> &ResolvedRecipientKey {
        &self.recovery_key
    }

    /// Der GETRENNTE Signierschluessel der historischen Grant-Autoritaet.
    #[must_use]
    pub const fn authority(&self) -> &ResolvedSigningKey {
        &self.authority
    }
}

/// Loest die Eingaben von `grant` gegen den Bestand unter `root` auf.
///
/// Die Schritte und ihre Reihenfolge stehen in der Modulnotiz.
///
/// # Errors
///
/// Aus Schritt 1 die Fehler von [`crate::resolve_recipient_key`]; aus
/// Schritt 2 [`RecoveryError::Io`], [`RecoveryError::ArchiveTooLarge`] und
/// [`RecoveryError::Verify`]; aus Schritt 4 die Fehler von
/// [`crate::resolve_signing_key`]; aus Schritt 5 [`RecoveryError::Io`].
///
/// Ein BEFUND ist kein Fehler: er kommt als `Ok` mit einem Bericht zurueck,
/// dessen [`exit_code_for`] ihn benennt, und mit
/// [`GrantInputsV1::resolved`] gleich `None`.
pub fn grant_inputs(
    root: &Path,
    anchor: &TrustAnchorV1,
    now: UnixMillis,
    recovery_key: &KeySourceSpec,
    authority_key: &KeySourceSpec,
    authorization: &Path,
    recipient_certificate: &Path,
) -> Result<GrantInputsV1, RecoveryError> {
    // 1 — der Recovery-Schluessel, weil der Bericht seinen Abdruck braucht.
    let recovery_key = resolve_recipient_key(recovery_key)?;
    let key_thumbprint = recipient_key_thumbprint(&recovery_key)?;

    // 2 — EINMAL einlesen, mit dem Abdruck verifizieren.
    let source = FsArchiveSource::open(root)?;
    let report = verify_source(&source, anchor, now, Some((key_thumbprint, &recovery_key)))?;

    // 3 — ein Befund beendet den Lauf, bevor ein weiterer Schluessel oder
    // eine Datei angefasst wird.
    if exit_code_for(&report) != ExitCode::Success {
        return Ok(GrantInputsV1 {
            report,
            resolved: None,
        });
    }

    // 4 — der getrennte Autoritaetsschluessel.
    let authority = resolve_signing_key(authority_key)?;

    // 5 — die beiden Dateien, ungeparst.
    let authorization_bytes = fs::read(authorization)?;
    let recipient_certificate_bytes = fs::read(recipient_certificate)?;

    Ok(GrantInputsV1 {
        report,
        resolved: Some(ResolvedGrantInputsV1 {
            authorization_bytes,
            recipient_certificate_bytes,
            source,
            recovery_key,
            authority,
        }),
    })
}
