//! Die Fassade, durch die JEDER Kommandopfad verifiziert.
//!
//! # Die Uhr ist ein PARAMETER
//!
//! Nirgends in dieser Crate steht `SystemTime::now()`. Die Begruendung ist
//! dieselbe, die `crates/ea-verify/src/archive.rs:60-70` fuer `VerifyOptions`
//! gibt: eine Uhr, die sich die Bibliothek selbst holt, ist in keinem Test mehr
//! steuerbar, und ein Verifikationsurteil haengt an ihr. Sie kommt genau EINMAL
//! im ganzen Workspace aus dem Betriebssystem, in `apps/cli/src/main.rs`.
//!
//! # Warum es diese Fassade ueberhaupt gibt
//!
//! Damit kein Kommandohandler `verify_archive` direkt ruft. Verify-before-use,
//! Zielpruefung und Rechtevergabe stehen dadurch an genau einer Stelle und
//! bleiben ohne Prozessstart pruefbar. Ein Handler, der sich seine
//! `VerifyOptions` selbst zusammensetzte, koennte die Empfaengerbindung
//! vergessen, ohne dass ein Test das saehe.

use std::{fs, path::Path};

use ea_crypto::HpkeRecipientPrivateKey;
use ea_trust::{TrustAnchorV1, decode_trust_anchor};
use ea_types::{KeyThumbprint, UnixMillis};
use ea_verify::{VerificationReportV1, VerifyOptions, verify_archive};

use crate::{FsArchiveSource, RecoveryError};

/// Verifiziert den Bestand unter `root` gegen `anchor` zur Uhr `now`.
///
/// `recipient` ist BEIDES ODER NICHTS: der Abdruck benennt, WER der Aufrufer
/// laut Registrierung ist, der private Schluessel ist das Material, mit dem die
/// Entkapselung rechnet. `ea_verify::VerifyOptions::with_recipient` nimmt sie
/// ausdruecklich getrennt entgegen, damit ein falsch verdrahteter
/// Schluesselspeicher als ENTSCHLUESSELUNGSFEHLER sichtbar wird und nicht als
/// fehlender Grant. Ohne Schluessel wird nichts entkapselt — was ausdruecklich
/// KEIN Mangel ist.
///
/// # Ein Befund ist kein Fehler
///
/// Ein Bestand mit Mangel liefert `Ok` mit einem Bericht, der den Mangel
/// benennt. `Err` sagt ausschliesslich: ueber diesen Bestand laesst sich gar
/// kein Bericht bilden.
///
/// # Errors
///
/// [`RecoveryError::Io`] und [`RecoveryError::ArchiveTooLarge`] aus
/// [`FsArchiveSource::open`], [`RecoveryError::Verify`] aus der Pipeline.
pub fn verify_directory(
    root: &Path,
    anchor: &TrustAnchorV1,
    now: UnixMillis,
    recipient: Option<(KeyThumbprint, &HpkeRecipientPrivateKey)>,
) -> Result<VerificationReportV1, RecoveryError> {
    let source = FsArchiveSource::open(root)?;
    verify_source(&source, anchor, now, recipient)
}

/// Verifiziert einen BEREITS EINGELESENEN Bestand.
///
/// # Warum es diesen zweiten Einstieg gibt
///
/// Nicht, um ein zweites Lesen zu sparen — sondern damit `decrypt` und
/// `export` genau die Bytes weiterverarbeiten, ueber die geurteilt wurde.
/// Laese ein schreibendes Kommando das Verzeichnis nach der Verifikation
/// erneut, koennte sich zwischen Urteil und Verwendung jedes Byte geaendert
/// haben, und „verify-before-use" hiesse nur noch „verify, und dann irgendwas".
/// Der Puffer aus [`FsArchiveSource::open`] ist der Gegenstand beider
/// Schritte.
pub(crate) fn verify_source(
    source: &FsArchiveSource,
    anchor: &TrustAnchorV1,
    now: UnixMillis,
    recipient: Option<(KeyThumbprint, &HpkeRecipientPrivateKey)>,
) -> Result<VerificationReportV1, RecoveryError> {
    let options = VerifyOptions::new(now);
    let options = match recipient {
        Some((key_thumbprint, private_key)) => options.with_recipient(key_thumbprint, private_key),
        None => options,
    };
    Ok(verify_archive(source, anchor, options)?)
}

/// Liest den Trust Anchor aus einer Datei.
///
/// # ZWEI FEHLERARTEN, UND SIE WERDEN NICHT VERSCHMOLZEN
///
/// Ein Lesefehler ist [`RecoveryError::Io`] (Exitcode 20), eine gescheiterte
/// Dekodierung [`RecoveryError::TrustAnchor`] (Exitcode 12). Der erste sagt
/// „ich konnte nicht nachsehen", der zweite „ich habe nachgesehen und es passt
/// nicht". Ein gemeinsamer Code naehme dem Betreiber die Unterscheidung
/// zwischen einem vergessenen Recovery-Medium und einem untergeschobenen Anker.
///
/// # Der Anker kommt NIE aus dem Bestand
///
/// Diese Funktion nimmt einen Pfad und keine [`ea_archive::ArchiveSource`].
/// `design.md`:1782 schliesst Trust-on-first-use ebenso aus wie einen Anker aus
/// dem zu pruefenden Archiv; die Signatur macht den zweiten Fall unmoeglich,
/// statt ihn zu verbieten.
///
/// # Errors
///
/// [`RecoveryError::Io`], wenn die Datei nicht lesbar ist,
/// [`RecoveryError::TrustAnchor`], wenn ihre Bytes kein gueltiger Anker sind.
pub fn load_trust_anchor(path: &Path) -> Result<TrustAnchorV1, RecoveryError> {
    let exact_bytes = fs::read(path)?;
    decode_trust_anchor(&exact_bytes).map_err(RecoveryError::TrustAnchor)
}
