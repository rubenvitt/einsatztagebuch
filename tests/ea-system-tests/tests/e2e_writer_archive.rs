//! Ein Einsatz von der leeren Maske bis zum committed Bestand — OHNE Netz.
//!
//! Erfassen, pruefen, abschliessen, verifizieren, und danach steht wieder eine
//! leere Maske. Der einzige Bestand des Laufs ist ein
//! [`ea_archive_fs::LocalPathBackend`]; keine Publikationsschlange, kein
//! kontrolliertes Netzprofil, kein erreichbarer Server.
//!
//! # Was dieser Lauf NICHT behauptet
//!
//! Der Bestand verifiziert nicht VOLLSTAENDIG, und das ist GEMESSEN und nicht
//! uebersehen: die Fixture legt ihre Registrierungslinie im Vertrauensspeicher
//! ab und nicht im Bestand — der Writer liest sie von dort und veroeffentlicht
//! sie nicht. Ein Bestand ohne archivresidente Vertrauenslinie hat keinen
//! auswaehlbaren Registrierungskopf, sein Eintrag ist damit nicht zuordenbar,
//! und `is_fully_verified` ist `false`. Genau deshalb steht hier die
//! fail-closed-Zusicherung des Buendelexports statt einer Berichtsgleichheit:
//! die Gleichheit von Verzeichnis- und Buendelbericht traegt
//! `crates/ea-archive-fs/tests/bundle_export.rs::bundle_verifies_to_the_same_report_as_the_directory`
//! ueber einen vollstaendig verifizierenden Bestand, und ein zweites Mal
//! behauptet sie hier nichts.

mod support;

use ea_archive_fs::{ArchiveBundleSource, BundleError, write_archive_bundle};
use ea_operator::ReauthPurpose;

use support::{WriterMatrixHarness, writer_support};

/// `SyncStatus` des reinen Offlinelaufs: lokal gespeichert und nichts
/// hochgeladen.
const OFFLINE_SYNC_STATUS: ea_archive_fs::SyncStatus = ea_archive_fs::SyncStatus::LocallySaved;

#[test]
fn one_incident_goes_from_the_blank_mask_to_a_committed_archive_without_a_network() {
    let harness = WriterMatrixHarness::with_incident();
    let writer = harness.inner();

    // Die Maske ist GEFUELLT — die Autospeicherung der Erfassung.
    assert!(
        !writer.draft_is_blank(),
        "die Erfassung MUSS Inhalt hinterlassen haben, sonst messen die naechsten Zeilen nichts"
    );
    assert!(
        writer.published_entry_paths().is_empty(),
        "der Bestand beginnt LEER"
    );

    let source = writer.source();
    let service = writer.service(&source);
    let proof = writer.proof_for(ReauthPurpose::Finalize);

    // Pruefen: die Vorschau der Schritte 1 bis 5. Sie zieht kein Geheimnis.
    let preview = service
        .preview(
            &proof,
            writer_support::valid_incident(),
            writer.observed_now(),
        )
        .expect("die Vorschau muss tragen");

    // Abschliessen: die Vorschau wird unter der Sperre NACHGERECHNET.
    let outcome = service
        .finalize(
            &proof,
            writer_support::valid_incident(),
            &preview,
            writer.observed_now(),
        )
        .expect("der Abschluss muss tragen");
    assert_eq!(
        outcome.sync_status, OFFLINE_SYNC_STATUS,
        "ein Offlinelauf ist LOKAL gespeichert und nichts weiter"
    );

    // Der Bestand traegt GENAU einen Eintrag und jeden geplanten Grant.
    assert_eq!(writer.published_entry_paths().len(), 1);
    assert_eq!(
        writer.published_grant_paths().len(),
        writer.expected_grant_count(),
        "jeder geplante Grant MUSS veroeffentlicht sein"
    );
    harness
        .every_published_object_is_complete()
        .unwrap_or_else(|defect| panic!("{defect}"));
    assert_eq!(
        writer.staged_object_count(),
        0,
        "Schritt 13 raeumt das Staging auf"
    );

    // Und die Maske ist wieder LEER, ohne Schluessel auf den Inhalt.
    assert!(
        writer.draft_is_blank(),
        "Schritt 13 oeffnet einen leeren Entwurf"
    );
    assert!(
        writer.writer_keys_cannot_decrypt(outcome.entry_hash),
        "kein Geheimnis dieses Writers oeffnet den committed Eintrag"
    );

    // Verifizieren: der Lauf ueber das Verzeichnis liest jedes Objekt und
    // meldet KEINEN Formatfehler. Ein abgeschnittenes oder halb geschriebenes
    // Objekt behielte sein Exact-Object-Praefix und erschiene hier.
    let report = ea_verify::verify_archive(
        &writer.backend().as_archive_source(),
        &writer.anchor(),
        ea_verify::VerifyOptions::new(writer.observed_now()),
    )
    .expect("der Verifikationslauf muss ein Ergebnis liefern");
    assert_eq!(
        report.format_errors().len(),
        0,
        "kein veroeffentlichtes Objekt darf am Parser scheitern"
    );
    assert_eq!(
        report.entry_package_count(),
        1,
        "der Lauf MUSS genau den einen Eintrag dieses Einsatzes gefunden haben"
    );

    // Der Bericht ist DETERMINISTISCH: zwei Laeufe ueber denselben Bestand
    // ergeben denselben Berichtshash. Eine GLEICHHEIT und keine Beschreibung.
    let repeated = ea_verify::verify_archive(
        &writer.backend().as_archive_source(),
        &writer.anchor(),
        ea_verify::VerifyOptions::new(writer.observed_now()),
    )
    .expect("der zweite Verifikationslauf muss ein Ergebnis liefern");
    assert_eq!(
        repeated.report_hash().as_bytes(),
        report.report_hash().as_bytes()
    );
    assert_eq!(
        repeated
            .to_canonical_json()
            .expect("der Bericht muss kodieren"),
        report
            .to_canonical_json()
            .expect("der Bericht muss kodieren")
    );
}

/// Der ERSATZ fuer die briefvorgeschriebene Berichtsgleichheit von Verzeichnis
/// und Buendel — und ein Test, der INVERTIERT.
///
/// # INVERTIERT, wenn die Vertrauenslinie archivresident wird
///
/// Dieser Test ist gruen, WEIL der Writer nichts unter
/// `trust/registry-events/` veroeffentlicht: der von ihm erzeugte Bestand
/// verifiziert damit nie vollstaendig, und `write_archive_bundle` ist
/// fail-closed auf genau diese Bedingung. Wer die Luecke schliesst — Stufe 3
/// (Sync) oder Stufe 5 (Registry-Verwaltung), oder eine Fixture, die die
/// Registrierungsobjekte in den Bestand legt —, faerbt diesen Test ROT, und er
/// liest sich dann als Regress, obwohl er ein Fortschritt ist.
///
/// DIESELBE Aenderung MUSS ihn deshalb ersetzen durch die Zusicherung, die der
/// Brief hier urspruenglich verlangt hat: ein Verifikationslauf ueber das
/// Verzeichnis UND ueber das Ein-Datei-Buendel mit GLEICHEM Berichtshash. Ihr
/// Nachfolger steht schon und muss nur ueber diesen Bestand gefahren werden:
/// `crates/ea-archive-fs/tests/bundle_export.rs::bundle_verifies_to_the_same_report_as_the_directory`.
#[test]
fn the_single_file_bundle_refuses_a_committed_archive_that_does_not_fully_verify() {
    let harness = WriterMatrixHarness::with_incident();
    let writer = harness.inner();
    harness.finalize().expect("der Abschluss muss tragen");
    assert_eq!(writer.published_entry_paths().len(), 1);

    let target = writer.root().join("einsatzarchiv.eab");
    let refused = write_archive_bundle(
        writer.backend(),
        &writer.anchor(),
        writer.observed_now(),
        &target,
    );
    // FAIL-CLOSED, und das ist die Zusage: ein Bestand, dessen
    // Vertrauenslinie nicht im Bestand liegt, verifiziert nicht vollstaendig,
    // und der Export verlaesst damit nicht das Haus.
    assert_eq!(
        refused.unwrap_err(),
        BundleError::SourceNotFullyVerified,
        "der Export MUSS einen nicht vollstaendig verifizierenden Bestand abweisen"
    );
    assert!(
        !target.exists(),
        "ein abgewiesener Export legt keine Zieldatei an"
    );
    assert!(
        ArchiveBundleSource::open(&target).is_err(),
        "es gibt kein Buendel zu oeffnen"
    );
}
