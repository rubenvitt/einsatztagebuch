//! Kommando `recovery-test`: pruefen, das Ziel sichern, das Inventar lesen —
//! und dort enden.
//!
//! # WAS DIESE FASSADE IST, UND WAS NICHT
//!
//! Sie ist die EINGABESEITE von `recovery-test`: der Bestand wird
//! verifiziert, die Zieldatei des Berichts als frei erwiesen und das
//! Schluesselinventar gelesen. Sie ist NICHT der Dienst: den gefuehrten Lauf
//! traegt `RecoveryTestRun` (`test_run.rs`) mit der nativen
//! `RecoveryTestRuntime` in `ea-admin`, die Rust-Bindung von
//! `ea.key-inventory/v1` (`schemas/reports/v1/key-inventory.schema.json`) ist
//! `KeyInventory` (`key_inventory.rs`). Diese Fassade gibt das Inventar
//! weiterhin als exakte BYTES heraus und parst es nicht; das Parsen gehoert
//! dem Aufrufer, der den Lauf fuehrt.
//!
//! # DIE REIHENFOLGE IST DER GEGENSTAND
//!
//! 1. Bestand einlesen, vollstaendig verifizieren — OHNE Empfaengerschluessel:
//!    `recovery-test` nimmt nach `design.md` §16.1 keinen, und ohne
//!    Schluessel wird nichts entkapselt, was ausdruecklich KEIN Mangel ist
//!    (dieselbe Aussage wie bei `verify` und `list`).
//! 2. Traegt der Bericht einen Befund, endet der Lauf mit dessen Code —
//!    bevor das Ziel befragt und das Inventar gelesen wird. Dieselbe
//!    Ordnung wie in [`crate::decrypt_directory`]: ein Befund ueber den
//!    Bestand gewinnt gegen jeden Fehler ueber die Aufrufmittel.
//! 3. Das Ziel muss FREI sein — [`RecoveryError::OutputExists`] (2) —, und
//!    zwar VOR dem Inventar, damit der kleinere Aufrufcode 2 den
//!    Dateisystemcode 20 eines fehlenden Inventars ueberstimmt
//!    (`design.md`:1815). Gefragt wird nur; angelegt wird nichts. Die
//!    bindende Entscheidung mit `create_new(true)` trifft der Dienst, wenn er
//!    den Bericht schreibt.
//! 4. Das Inventar wird gelesen; eine fehlende Datei ist
//!    [`RecoveryError::Io`] (20).
//!
//! # ES WIRD NICHTS GESCHRIEBEN
//!
//! Und deshalb — wie in [`crate::grant`] — kein
//! `restrictive_permissions_available`: die Zusicherung gilt fuer
//! Zieldateien, und diese Fassade legt keine an.

use std::{fs, path::Path};

use ea_trust::TrustAnchorV1;
use ea_types::UnixMillis;
use ea_verify::VerificationReportV1;

use crate::{
    ExitCode, RecoveryError, exit_code_for, target::output_file_is_free, verify_directory,
};

/// Das Ergebnis eines vollstaendigen `recovery-test`-Eingabelaufs.
///
/// Traegt den BERICHT und nicht bloss einen Code — derselbe Weg wie bei
/// [`crate::DecryptionV1`] und [`crate::GrantInputsV1`]; der Aufrufer leitet
/// den Exitcode mit [`exit_code_for`] daraus ab.
///
/// Kein `Debug`: das Inventar benennt nach seinem Schema Schluesselabdrucke
/// und Medien, und eine beilaeufige Anzeige gehoert in keine Protokollzeile.
pub struct RecoveryTestInputsV1 {
    /// Der vollstaendige Verifikationsbericht des Laufs.
    pub report: VerificationReportV1,
    /// Die EXAKTEN Bytes des Inventars, ungeparst — `None` GENAU DANN, wenn
    /// der Bericht einen Befund traegt.
    ///
    /// Die Aequivalenz ist die Zusicherung von Schritt 2 der Modulnotiz: bei
    /// einem Befund wird das Ziel nicht befragt und das Inventar nicht
    /// gelesen.
    pub key_inventory_bytes: Option<Vec<u8>>,
}

/// Loest die Eingaben von `recovery-test` gegen den Bestand unter `root` auf.
///
/// Die Schritte und ihre Reihenfolge stehen in der Modulnotiz.
///
/// # Errors
///
/// Aus Schritt 1 [`RecoveryError::Io`], [`RecoveryError::ArchiveTooLarge`]
/// und [`RecoveryError::Verify`]; aus Schritt 3
/// [`RecoveryError::OutputExists`]; aus Schritt 4 [`RecoveryError::Io`].
///
/// Ein BEFUND ist kein Fehler: er kommt als `Ok` mit einem Bericht zurueck,
/// dessen [`exit_code_for`] ihn benennt, und mit
/// [`RecoveryTestInputsV1::key_inventory_bytes`] gleich `None`.
pub fn recovery_test_inputs(
    root: &Path,
    anchor: &TrustAnchorV1,
    now: UnixMillis,
    key_inventory: &Path,
    output: &Path,
) -> Result<RecoveryTestInputsV1, RecoveryError> {
    // 1 — ohne Empfaengerschluessel: dieses Kommando nimmt keinen.
    let report = verify_directory(root, anchor, now, None)?;

    // 2 — ein Befund beendet den Lauf, bevor Ziel oder Inventar angefasst
    // werden.
    if exit_code_for(&report) != ExitCode::Success {
        return Ok(RecoveryTestInputsV1 {
            report,
            key_inventory_bytes: None,
        });
    }

    // 3 — das Ziel, VOR dem Inventar und OHNE anzulegen.
    output_file_is_free(output)?;

    // 4 — das Inventar, ungeparst.
    let key_inventory_bytes = fs::read(key_inventory)?;

    Ok(RecoveryTestInputsV1 {
        report,
        key_inventory_bytes: Some(key_inventory_bytes),
    })
}
