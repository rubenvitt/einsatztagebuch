//! Kommando `grant`: pruefen, dann JEDE Eingabe eines historischen Re-Grants
//! aufloesen — und dort enden.
//!
//! # WAS DIESE FASSADE IST, UND WAS NICHT
//!
//! Sie ist die EINGABESEITE von `design.md` §16.2: der Recovery-Schluessel,
//! der getrennte HGA-Signierschluessel, die Autorisierung und das
//! Empfaengerzertifikat werden benannt, aufgeloest beziehungsweise gelesen
//! und in der dokumentierten Reihenfolge angefasst. Sie ist NICHT der
//! Dienst: nichts im Baum erzeugt oder prueft einen historischen Grant
//! (`crates/ea-verify/src/recipient.rs:236-238` weist
//! `GrantKindV1::Historical` als `AuthorizationUnverifiable` ab), und der
//! `HistoricalGrantService` ist Stage-5 Task 8. Die beiden Dateien werden
//! deshalb als BYTES herausgegeben und nicht geparst — der Parser gehoert zum
//! Dienst, und ein Parser ohne Dienst waere ein Vertrag ohne Gegenseite.
//!
//! # DIE REIHENFOLGE IST DER GEGENSTAND
//!
//! 1. Der Recovery-Schluessel wird aufgeloest — VOR der Verifikation, und
//!    das ist kein Widerspruch zu verify-before-use, sondern dessen
//!    Voraussetzung: der Bericht braucht den ABDRUCK des Schluessels, damit
//!    ein Grant auf fremdes Material als Entschluesselungsbefund sichtbar
//!    wird und nicht als fehlender Grant (`crates/ea-verify/src/archive.rs:97-105`).
//!    Dieselbe Ordnung waehlt [`crate::decrypt_directory`]. Ein Aufruffehler
//!    an dieser Quelle (offene Passphrasendatei, falsche Art, 2) und die
//!    benannte PKCS#11-Grenze (21) enden deshalb, bevor ein Byte des Bestands
//!    gelesen ist.
//! 2. Bestand EINMAL einlesen, vollstaendig verifizieren — mit dem Abdruck.
//! 3. Traegt der Bericht einen Befund, endet der Lauf mit dessen Code. Es
//!    wird KEIN weiterer Schluessel aufgeloest und KEINE Datei gelesen: ein
//!    Befund ueber den Bestand gewinnt gegen jeden Fehler, der danach noch
//!    kaeme — auch gegen einen fehlenden Autoritaetsschluessel. Das ist die
//!    Regel des kleinsten spezifischen Codes (`design.md`:1815) in ihrer
//!    Reihenfolgeform: 10, 11, 12, 13 und 14 sind Aussagen ueber den Bestand
//!    und stehen vor 2, 20 und 21 ueber die Aufrufmittel.
//! 4. Der Autoritaetsschluessel wird aufgeloest. Ein Container der Art
//!    `RecipientKem` an dieser Stelle ist [`RecoveryError::KeySource`] (2):
//!    der Kopf traegt die Art, und ein Recovery-Schluessel wird nie als
//!    Signierschluessel gelesen.
//! 5. Autorisierung und Empfaengerzertifikat werden gelesen — in dieser
//!    Reihenfolge, jede fehlende Datei ist [`RecoveryError::Io`] (20).
//!
//! # ES WIRD NICHTS GESCHRIEBEN
//!
//! Deshalb steht hier — anders als in [`crate::decrypt_directory`] — KEIN
//! `restrictive_permissions_available`: die Zusicherung „nur der
//! Eigentuemer" gilt fuer Zieldateien, und diese Fassade legt keine an. Die
//! Geheimnisquellen pruefen ihre eigenen Rechte selbst
//! ([`crate::read_secret_file`], [`crate::EncryptedKeyContainer::read_from`]).

use std::{fs, path::Path};

use ea_crypto::{CoseSigner, HpkeRecipientPrivateKey};
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
/// Autorisierung und ein Zertifikat —, und der Dienst (Task 8) wird sie
/// parsen; sie duerfen als Felder herausgegeben werden. Die beiden Schluessel
/// sind Geheimnisse und gehen nur ueber Zugriffe heraus, damit ein Aufrufer
/// bewusst entscheidet, was er damit tut. Kein `Debug` — siehe
/// [`GrantInputsV1`].
pub struct ResolvedGrantInputsV1 {
    /// Die EXAKTEN Bytes der Autorisierungsdatei, ungeparst.
    pub authorization_bytes: Vec<u8>,
    /// Die EXAKTEN Bytes des Empfaengerzertifikats, ungeparst.
    pub recipient_certificate_bytes: Vec<u8>,
    recovery_key: HpkeRecipientPrivateKey,
    authority: CoseSigner,
}

impl ResolvedGrantInputsV1 {
    /// Der private Recovery-KEM-Schluessel, mit dessen Abdruck verifiziert
    /// wurde.
    #[must_use]
    pub const fn recovery_key(&self) -> &HpkeRecipientPrivateKey {
        &self.recovery_key
    }

    /// Der GETRENNTE Signierschluessel der historischen Grant-Autoritaet.
    #[must_use]
    pub const fn authority(&self) -> &CoseSigner {
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
            recovery_key,
            authority,
        }),
    })
}
