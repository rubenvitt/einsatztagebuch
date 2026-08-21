//! Die Fehlermatrix der Stufe 2 — jeder deklarierte Abbruchpunkt, ein Ausgang.
//!
//! # Was diese Datei messen kann, was keine einzelne Crate messen kann
//!
//! `crates/ea-writer/tests/prepared_recovery.rs`,
//! `crates/ea-draft/tests/discard_faults.rs` und
//! `crates/ea-archive-fs/tests/profile_migration.rs` messen JE IHRE Invariante.
//! Diese Datei setzt Writer, Entwurfsablage, Wirtsbestand, Gesundheitscheck und
//! Verifikation in EINEN Prozess und fuegt genau das hinzu, was dort nirgends
//! stehen kann:
//!
//! * nach JEDEM Abbruchpunkt ist JEDES veroeffentlichte Archivobjekt
//!   vollstaendig — dieselbe Aussage, die der Buendelexport fail-closed
//!   verlangt, hier ueber einen Bestand, den der Writer selbst geschrieben hat;
//! * unter zwei Medienverweigerungen an jedem dieser Punkte entsteht kein
//!   halbes Archivobjekt, gemessen gegen das Inventar VOR der Verweigerung;
//! * die Vorrangregel des vorbereiteten Abschlusses gegen ein liegendes
//!   Verwerfen, gemessen am Neustartpfad der Entwurfsablage.
//!
//! Die Doppelung mit den crateweisen Tests ist ABSICHT und keine Nachlaessigkeit:
//! die Stufenabnahme braucht eine eigene, benannte Belegzeile, die den ganzen
//! Stapel in einem Lauf traegt.

mod support;

use ea_archive_fs::{HealthFinding, MigrationFaultPoint};
use ea_draft::{DiscardFaultPoint, RestartState};
use ea_writer::FinalizationFaultPoint;

use support::{
    MatrixOutcome, MediumFailure, WriterMatrixHarness, archive_support, draft_support,
    published_objects_are_complete,
};

/// Die Befunde, die einen HALB geschriebenen Bestand bezeugen wuerden.
///
/// Die drei und nicht alle zehn, und das ist gemessen und nicht abgesprochen:
/// die Fixture des Writers legt ihre Vertrauenslinie NICHT im Bestand ab (der
/// Writer liest sie aus dem Vertrauensspeicher), also meldet jeder Lauf ueber
/// einen von ihr erzeugten Bestand
/// [`HealthFinding::IncompleteTrustData`] — strukturell und unabhaengig von
/// jeder Injektion. Und eine liegengebliebene Staging-Adresse ist
/// [`HealthFinding::OrphanGrantOrTemporaryFile`], aber ausdruecklich KEIN halbes
/// Archivobjekt: sie traegt den Suffix `.staging`, ist nicht veroeffentlicht und
/// gehoert dem Bestand nicht. Die drei hier sind die, die genau die Zusage
/// dieses Tests brechen wuerden.
const HALF_WRITTEN_ARCHIVE_FINDINGS: [HealthFinding; 3] = [
    HealthFinding::MissingFile,
    HealthFinding::ModifiedFile,
    HealthFinding::HashSignatureOrChainError,
];

#[test]
fn every_declared_stage_two_fault_point_has_exactly_one_survivable_outcome() {
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        let mut harness = WriterMatrixHarness::with_incident();
        let prepared = harness.interrupt_at(point);
        let resumed = harness.restart_from_disk();
        match resumed {
            MatrixOutcome::DraftUnchanged => {
                assert_eq!(
                    harness.draft_notes().as_deref(),
                    Some(harness.notes_before()),
                    "{point:?} liegt vor der Grenze: der Entwurf MUSS unveraendert lesbar sein"
                );
                assert!(
                    harness.archive_has_no_entry(),
                    "{point:?} liegt vor der Grenze und hat dennoch veroeffentlicht"
                );
            }
            MatrixOutcome::Committed => {
                let prepared = prepared.expect("hinter der Grenze liegt eine Abschlussmarke");
                let committed = harness
                    .committed_entry_bytes()
                    .expect("eine Vollendung veroeffentlicht genau einen Eintrag");
                // Byteidentisch: die veroeffentlichten Bytes stehen
                // UNVERAENDERT in der Abschlussmarke. `CommittedFinalization`
                // mit `exact_bytes` ist nicht gebaut (`crates/ea-writer/src/lib.rs`
                // nennt den Grund), also wird gegen die Marke selbst gemessen —
                // dieselbe Zusicherung wie in
                // `crates/ea-writer/tests/prepared_recovery.rs:170-176`.
                assert!(
                    prepared.windows(committed.len()).any(|w| w == committed),
                    "{point:?}: die veroeffentlichten Bytes stehen nicht in der Abschlussmarke"
                );
                assert!(
                    harness.draft_key_is_gone(),
                    "{point:?}: ein committed Eintrag und der ihn erzeugende Entwurf zugleich"
                );
            }
            MatrixOutcome::BackupTookThePreparedBytes => {
                // Der EINE benannte Sonderfall. Er ist an genau diesen Punkt
                // gebunden; jeder andere Punkt, der hier landete, waere ein
                // Defekt und kein dritter Ausgang.
                assert_eq!(
                    point,
                    FinalizationFaultPoint::BackupRestoreAfterKeyDeletion,
                    "nur die Rueckspielung darf die vorbereiteten Bytes mitnehmen"
                );
                assert!(
                    harness.archive_has_no_entry(),
                    "die Rueckspielung veroeffentlicht nichts"
                );
                assert!(
                    harness.draft_key_is_gone(),
                    "der geraetegebundene Schluesselspeichereintrag kehrt NICHT mit den Dateien \
                     zurueck"
                );
            }
        }
        // Die Zusage, die keine crateweise Datei traegt: was veroeffentlicht
        // ist, ist VOLLSTAENDIG. Abgeschnittene Bytes behalten ihr
        // Exact-Object-Praefix und scheitern am Parser dahinter.
        harness
            .every_published_object_is_complete()
            .unwrap_or_else(|defect| panic!("{point:?}: {defect}"));
    }
}

#[test]
fn every_declared_discard_fault_point_restarts_into_one_of_two_states() {
    for point in DiscardFaultPoint::ALL.iter().copied() {
        let mut harness = draft_support::DraftHarness::with_nonempty_draft();
        let _ = harness.discard_with_fault(point);
        let state = harness
            .restart_and_resume()
            .unwrap_or_else(|error| panic!("{point:?}: der Neustart muss tragen: {error:?}"));
        assert!(
            state == RestartState::OriginalDraftUnchanged || state == RestartState::NewBlankDraft,
            "{point:?} restarted into {state:?}"
        );
        // Ein halb verworfener Entwurf ist keiner der beiden Zustaende, und
        // genau das wird hier zusaetzlich gemessen: nach dem Neustart steht
        // KEINE Verwerfensabsicht mehr offen.
        assert!(
            harness.pending_discard_is_absent(),
            "{point:?}: nach dem Neustart steht noch eine Verwerfensabsicht offen"
        );
    }
}

#[test]
fn a_media_failure_at_any_durable_step_never_produces_a_half_written_archive() {
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        for failure in [MediumFailure::NoSpaceLeft, MediumFailure::ReadOnlyMount] {
            let mut harness = WriterMatrixHarness::with_incident();
            let _ = harness.interrupt_at(point);
            // Das ERWARTETE Inventar entsteht VOR der Verweigerung. Aus den
            // tatsaechlichen Bytes gebildet koennten `MissingFile` und
            // `ModifiedFile` nie feuern, und die Zusicherung waere leer.
            let expected = harness.inventory();
            let before = harness.archive_digest_map();
            harness.fail_the_medium(failure);
            let refused = harness.finalize();
            assert!(
                refused.is_err(),
                "{point:?}/{failure:?}: das Medium verweigert, und der Abschluss meldet Erfolg"
            );
            // Der TRAGENDE Zeuge: der fehlgeschlagene Schreibvorgang hat den
            // Bestand nicht angetastet. Er wird VOR dem Heilen und vor dem
            // Gesundheitscheck genommen, weil der Capability-Test des Checks
            // selbst in die Kratzwurzel schreibt.
            assert_eq!(
                harness.archive_digest_map(),
                before,
                "{point:?}/{failure:?}: der abgewiesene Abschluss hat Bytes im Bestand veraendert"
            );
            harness.heal_the_medium();
            let report = harness.health_against(&expected);
            for finding in HALF_WRITTEN_ARCHIVE_FINDINGS {
                assert!(
                    !report.contains(finding),
                    "{point:?}/{failure:?} hinterliess {finding:?}; gemeldet wurde {:?}",
                    report.findings()
                );
            }
            harness
                .every_published_object_is_complete()
                .unwrap_or_else(|defect| panic!("{point:?}/{failure:?}: {defect}"));
        }
    }
}

#[test]
fn an_interrupted_profile_migration_leaves_exactly_one_active_pointer() {
    for point in MigrationFaultPoint::ALL.iter().copied() {
        let harness = archive_support::migration_harness();
        let migrator = harness.migrator();
        let outcome = migrator.with_fault(point).run();
        assert!(outcome.is_err(), "{point:?} MUSS die Migration abbrechen");
        // GENAU EIN aktiver Zeiger, und es ist der ALTE: `active_profile_hash`
        // liefert einen einzigen Wert, und dass er der des Quellprofils ist,
        // ist die Aussage „das Zielprofil ist nicht aktiv geworden".
        assert_eq!(
            migrator.active_profile_hash().as_bytes(),
            archive_support::source_profile_hash().as_bytes(),
            "{point:?} liess mehr als das alte Profil aktiv"
        );
        assert!(
            migrator.finalization_lock().is_available(),
            "{point:?} gab die Finalisierungssperre nicht frei"
        );
        // Und der Bestand ist danach GANZ lesbar: jedes Archivobjekt des
        // Quellprofils traegt weiterhin alle seine Bytes.
        published_objects_are_complete(harness.source())
            .unwrap_or_else(|defect| panic!("{point:?}: {defect}"));
    }
}

#[test]
fn a_prepared_finalization_survives_a_crash_and_beats_a_pending_discard() {
    let mut harness = draft_support::DraftHarness::with_nonempty_draft();
    // Erst die Absicht buchen, dann die Marke legen: die Vorrangregel gilt an
    // JEDEM Eingang, also auch an dem, an dem das Verwerfen schon dauerhaft
    // gebucht ist.
    harness
        .discard_with_fault(DiscardFaultPoint::AfterIntentCommit)
        .expect("die gebuchte Absicht muss erreichbar sein");
    harness.set_prepared_finalization_marker();
    let state = harness
        .restart_and_resume()
        .expect("die Wiederaufnahme muss gelingen");
    assert_eq!(
        state,
        RestartState::PreparedFinalizationPending,
        "eine liegende Abschlussmarke hat Vorrang vor einer gebuchten Verwerfensabsicht"
    );
    // Sie hat Vorrang, und sie VERBRAUCHT die Absicht nicht: ein zweiter
    // Neustart meldet denselben Zustand. Eine GLEICHHEIT und keine
    // Beschreibung.
    assert_eq!(
        harness
            .restart_and_resume()
            .expect("der zweite Neustart muss tragen"),
        RestartState::PreparedFinalizationPending
    );
    assert!(
        harness.draft_dek_is_present(),
        "solange die Marke liegt, wird kein Verwerfen fortgesetzt"
    );
}
