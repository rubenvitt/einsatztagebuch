//! Jeder Unterbrechungspunkt fuehrt auf GENAU zwei Zustaende.
//!
//! Entweder der Entwurf ist wiederherstellbar und die Sequenz unverbraucht,
//! oder dieselbe vorbereitete Transaktion ist vollendet. Ein dritter Zustand —
//! ein halb veroeffentlichter Bestand, ein committed `.eip` neben einem
//! nutzbaren `draftDEK`, eine zweimal benutzte Sequenz — existiert nicht, und
//! diese Datei ist der Beleg dafuer.

mod support;

use ea_writer::{FinalizationFaultPoint, RecoveryOutcome};
use support::{WriterHarness, valid_incident};

#[test]
fn every_fault_recovers_the_draft_or_completes_the_same_prepared_transaction() {
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        let harness = WriterHarness::with_incident();
        let source = harness.source();
        let service = harness.service(&source);
        let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

        let interrupted = service
            .finalize_interrupted_at(&proof, valid_incident(), point)
            .unwrap_or_else(|error| panic!("{point:?} muss erreichbar sein: {error:?}"));

        // Der Abbruch hat WIRKLICH etwas getan. Ohne diese Zusicherung waere
        // die ganze Schleife auch gruen, wenn die Fehlerinjektion nichts tut —
        // gemessen mit Mutation 2.
        assert!(
            interrupted.reached_step().is_some(),
            "{point:?}: der Lauf hat keinen einzigen Schritt ausgefuehrt"
        );
        // Ab der Datenbanktransaktion liegt eine Abschlussmarke, also darf die
        // Wiederherstellung NICHT „nichts zu tun" melden.
        let marker_expected = !matches!(
            point,
            FinalizationFaultPoint::BeforeStagingCreate
                | FinalizationFaultPoint::AfterStagingCreateBeforeFileFlush
                | FinalizationFaultPoint::AfterStagingFileFlushBeforeDirectoryFlush
                | FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker
        );
        if marker_expected {
            assert!(
                interrupted.prepared().is_some(),
                "{point:?}: ab der Datenbanktransaktion MUSS eine Marke liegen"
            );
        }

        let first = service
            .recover_pending()
            .unwrap_or_else(|error| panic!("{point:?}: recover muss tragen: {error:?}"));

        // Die Klassifikation des Punktes ENTSCHEIDET den Ausgang, und das ist
        // die eigentliche Zusage: vor der Grenze ist der Entwurf
        // wiederherstellbar und die Sequenz unverbraucht, hinter ihr MUSS
        // dieselbe vorbereitete Transaktion vollendet werden. Ein
        // `matches!` ueber alle drei Arme waere hier gruen, ohne etwas zu
        // sagen.
        if marker_expected {
            assert_ne!(
                first,
                RecoveryOutcome::NothingPending,
                "{point:?}: eine liegende Marke MUSS aufgeloest werden"
            );
        }
        if point.phase().is_irreversible() {
            assert!(
                matches!(first, RecoveryOutcome::CommittedFromPreparedBytes { .. }),
                "{point:?} liegt hinter der Grenze, wurde aber als {first:?} aufgeloest"
            );
        } else {
            assert!(
                first.is_original_draft(),
                "{point:?} liegt vor der Grenze, wurde aber als {first:?} aufgeloest"
            );
        }

        // Ein ZWEITES recover ist ein no-op — eine GLEICHHEIT und keine
        // Beschreibung.
        let second = service
            .recover_pending()
            .unwrap_or_else(|error| panic!("{point:?}: das zweite recover muss tragen: {error:?}"));
        assert_eq!(
            second,
            RecoveryOutcome::NothingPending,
            "ein zweites recover ist ein no-op: {point:?}"
        );

        // Die TRAGENDE Zusage: nie beides zugleich.
        //
        // Gemessen wird der ENTWURF und nicht die blosse Anwesenheit EINES
        // `draftDEK`: Schritt 13 oeffnet einen leeren Entwurf mit FRISCHEM
        // Schluessel, und der ist die Nachbedingung und nicht der Verstoss. Die
        // Zusage lautet „kein nutzbarer `draftDEK` DIESES Eintrags", und der
        // Zeuge dafuer ist, dass sein Inhalt fort ist.
        let committed = harness
            .backend()
            .relative_paths_below_for_test("entries/")
            .into_iter()
            .filter(|path| path.ends_with(".eip"))
            .count();
        assert!(
            committed == 0 || harness.draft_is_blank(),
            "{point:?}: ein committed .eip und der ihn erzeugende Entwurf zugleich lesbar"
        );
        assert!(committed <= 1, "{point:?}: kein Duplikat");
    }
}

#[test]
fn after_the_key_boundary_recovery_completes_the_exact_prepared_bytes() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    let interrupted = service
        .finalize_interrupted_at(
            &proof,
            valid_incident(),
            FinalizationFaultPoint::AfterAbsenceConfirmation,
        )
        .expect("der Abbruch an der Grenze muss erreichbar sein");
    let prepared = interrupted
        .prepared()
        .expect("hinter der Grenze liegt eine Abschlussmarke");
    let prepared_bytes = prepared.exact_bytes().to_vec();
    let sequence = prepared.sequence();
    let draws_before = ea_writer::entropy_draws();

    let recovered = service
        .recover_pending()
        .expect("die Wiederherstellung hinter der Grenze muss tragen");
    assert_eq!(
        recovered,
        RecoveryOutcome::CommittedFromPreparedBytes { sequence }
    );

    // KEINE neue Zufallsziehung — die tragende Zusage von `design.md` §9.4.
    assert_eq!(
        ea_writer::entropy_draws(),
        draws_before,
        "die Wiederherstellung zieht keine Zufallswerte"
    );

    // Und dieselben Bytes: das committed `.eip` ist genau das der Marke.
    let entries = harness
        .backend()
        .relative_paths_below_for_test("entries/")
        .into_iter()
        .filter(|path| path.ends_with(".eip"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    let committed = harness
        .backend()
        .read_for_test(&entries[0])
        .expect("das committed .eip muss lesbar sein");
    assert!(
        prepared_bytes
            .windows(committed.len())
            .any(|w| w == committed),
        "die veroeffentlichten Bytes stehen unveraendert in der Abschlussmarke"
    );
}

#[test]
fn before_the_key_boundary_the_sequence_stays_unused() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    let interrupted = service
        .finalize_interrupted_at(
            &proof,
            valid_incident(),
            FinalizationFaultPoint::AfterPreparedMarkerCommit,
        )
        .expect("der Abbruch vor der Grenze muss erreichbar sein");
    let sequence = interrupted.prepared().expect("die Marke liegt").sequence();

    assert_eq!(
        service.recover_pending().expect("recover muss tragen"),
        RecoveryOutcome::DraftRestored {
            unused_sequence: sequence
        }
    );
    assert!(
        harness.draft_dek_is_present(),
        "vor der Grenze bleibt der Entwurf lesbar"
    );
    assert_eq!(
        harness
            .backend()
            .relative_paths_below_for_test("entries/")
            .into_iter()
            .filter(|path| path.ends_with(".eip"))
            .count(),
        0,
        "vor der Grenze ist nichts veroeffentlicht"
    );
}

#[test]
fn a_prepared_finalization_beats_a_second_finalization_attempt() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    service
        .finalize_interrupted_at(
            &proof,
            valid_incident(),
            FinalizationFaultPoint::AfterPreparedMarkerCommit,
        )
        .expect("der Abbruch muss erreichbar sein");

    let preview = service.preview(&proof, valid_incident());
    assert_eq!(
        preview.err().map(|error| error.code()),
        Some("EA-WRITER-PREPARED-FINALIZATION-PRESENT"),
        "solange eine Marke liegt, beginnt keine zweite Finalisierung"
    );
}
