//! Jeder Unterbrechungspunkt fuehrt auf GENAU zwei Zustaende.
//!
//! Entweder der Entwurf ist wiederherstellbar und die Sequenz unverbraucht,
//! oder dieselbe vorbereitete Transaktion ist vollendet. Ein dritter Zustand —
//! ein halb veroeffentlichter Bestand, ein committed `.eip` neben einem
//! nutzbaren `draftDEK`, eine zweimal benutzte Sequenz — existiert nicht, und
//! diese Datei ist der Beleg dafuer.
//!
//! Die EINE Ausnahme ist benannt und gemessen:
//! [`FinalizationFaultPoint::BackupRestoreAfterKeyDeletion`] ist kein Punkt der
//! Reihenfolge, sondern ein Ereignis von aussen, und es nimmt die vorbereiteten
//! Bytes MIT. Der Entwurf ist dann verloren und der Bestand unberuehrt — kein
//! halber Zustand, aber auch keine Vollendung.

mod support;

use ea_writer::{FinalizationFaultPoint, FinalizationStep, RecoveryOutcome};
use support::{WriterHarness, valid_incident};

#[test]
fn every_fault_recovers_the_draft_or_completes_the_same_prepared_transaction() {
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        let mut harness = WriterHarness::with_incident();
        let interrupted = harness
            .finalize_with_fault(point)
            .unwrap_or_else(|error| panic!("{point:?} muss erreichbar sein: {error:?}"));

        // Der Abbruch hat WIRKLICH etwas getan. Ohne diese Zusicherung waere
        // die ganze Schleife auch gruen, wenn die Fehlerinjektion nichts tut —
        // gemessen mit Mutation 2.
        assert!(
            interrupted.reached_step().is_some(),
            "{point:?}: der Lauf hat keinen einzigen Schritt ausgefuehrt"
        );

        // Die Rueckspielung nimmt die Datenbankdateien des Zustands VOR der
        // Finalisierung zurueck; die Abschlussmarke ist damit fort, obwohl der
        // `draftDEK` geloescht bleibt. Das ist der Grund, warum dieser Punkt
        // ueberhaupt ein eigener ist.
        let restored_backup = point == FinalizationFaultPoint::BackupRestoreAfterKeyDeletion;
        // Ab der Datenbanktransaktion liegt eine Abschlussmarke, also darf die
        // Wiederherstellung NICHT „nichts zu tun" melden.
        let marker_expected = !restored_backup
            && !matches!(
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

        let source = harness.source();
        let service = harness.service(&source);
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
        if restored_backup {
            // Die eigene, ANDERE Messung dieses Punktes: die Marke ist mit der
            // Sicherung verschwunden, also findet die Wiederherstellung nichts
            // vor — an [`FinalizationFaultPoint::AfterAbsenceConfirmation`],
            // demselben Programmpunkt ohne Rueckspielung, vollendet sie
            // dagegen. Der Bestand bleibt unberuehrt, und der `draftDEK` ist
            // fort: die vorbereitete Transaktion ist verloren, nicht halb
            // vollzogen.
            assert_eq!(
                first,
                RecoveryOutcome::NothingPending,
                "die Rueckspielung hat die vorbereiteten Bytes mitgenommen"
            );
            assert!(
                harness.published_entry_paths().is_empty(),
                "die Rueckspielung veroeffentlicht nichts"
            );
            assert!(
                !harness.draft_dek_is_present(),
                "der geraetegebundene Schluesselspeichereintrag kehrt NICHT mit den Dateien zurueck"
            );
        } else if point.phase().is_irreversible() {
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
        let committed = harness.published_entry_paths().len();
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
            harness.observed_now(),
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
    let entries = harness.published_entry_paths();
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
            harness.observed_now(),
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
    assert!(
        harness.published_entry_paths().is_empty(),
        "vor der Grenze ist nichts veroeffentlicht"
    );
}

/// „Die Sequenz gilt dann als NICHT verbraucht" ist eine Zusage ueber den
/// NAECHSTEN Lauf.
///
/// Eine liegengebliebene `entries/<seq>_<hash>.eip.staging` traegt dieselben
/// Bytes wie das Archivobjekt und damit dasselbe Exact-Object-Praefix. Zaehlte
/// sie als Kettenknoten, stuende `verified_head` auf einem Objekt, das NIE
/// veroeffentlicht wurde: Schritt 3 verlangte `EA-WRITER-HEAD-RECONCILIATION-\
/// REQUIRED` auf einem Bestand, in dem nichts liegt — dauerhaft —, und ein
/// spaeterer Eintrag bindet einen Vorgaenger, den es nicht gibt.
///
/// Der Zeuge laeuft ueber BEIDE Punkte, an denen Staging liegen bleibt: den mit
/// Abschlussmarke und den ohne.
#[test]
fn leftover_staging_objects_do_not_consume_the_sequence() {
    for point in [
        FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker,
        FinalizationFaultPoint::AfterPreparedMarkerCommit,
    ] {
        let mut harness = WriterHarness::with_incident();
        harness
            .finalize_with_fault(point)
            .unwrap_or_else(|error| panic!("{point:?} muss erreichbar sein: {error:?}"));

        let source = harness.source();
        let service = harness.service(&source);
        service
            .recover_pending()
            .unwrap_or_else(|error| panic!("{point:?}: recover muss tragen: {error:?}"));

        // Die Staging-Datei liegt WEITERHIN da. Der Port hat keine
        // Loeschprimitive, und der Zeuge misst deshalb den Filter und nicht
        // eine Bereinigung.
        assert!(
            harness.staged_object_count() > 0,
            "{point:?}: ohne liegengebliebenes Staging messe dieser Test nichts"
        );
        assert!(harness.published_entry_paths().is_empty());

        // Und der naechste Lauf gelingt — auf DERSELBEN Sequenz und ohne
        // Vorgaenger.
        let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
        let preview = service
            .preview(&proof, valid_incident(), harness.observed_now())
            .unwrap_or_else(|error| {
                panic!("{point:?}: die Sequenz MUSS unverbraucht sein: {error:?}")
            });
        assert_eq!(preview.proposed_sequence().get(), 0);
        assert!(
            preview.previous_entry_hash().is_none(),
            "{point:?}: ein Bestand ohne veroeffentlichten Eintrag hat keinen Vorgaenger"
        );
        let out = service
            .finalize(&proof, valid_incident(), &preview, harness.observed_now())
            .unwrap_or_else(|error| panic!("{point:?}: der zweite Anlauf muss tragen: {error:?}"));
        assert_eq!(out.sequence.get(), 0);
        assert_eq!(harness.published_entry_paths().len(), 1);
    }
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
            harness.observed_now(),
            FinalizationFaultPoint::AfterPreparedMarkerCommit,
        )
        .expect("der Abbruch muss erreichbar sein");

    let preview = service.preview(&proof, valid_incident(), harness.observed_now());
    assert_eq!(
        preview.err().map(|error| error.code()),
        Some("EA-WRITER-PREPARED-FINALIZATION-PRESENT"),
        "solange eine Marke liegt, beginnt keine zweite Finalisierung"
    );
}

/// Eine liegende Abschlussmarke verhindert ein Verwerfen des Entwurfs.
///
/// Der Vorrangpunkt aus Task 7, von dieser Seite gemessen: nach Schritt 8 liegt
/// die Marke, und `begin_discard` MUSS fail-closed abweisen.
#[test]
fn a_prepared_finalization_beats_a_pending_discard_intent() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    service
        .finalize_up_to(
            &proof,
            valid_incident(),
            harness.observed_now(),
            FinalizationStep::StageAndFlush,
        )
        .expect("Schritt 8 muss erreichbar sein");
    assert!(harness.prepared_marker_is_present());

    let discard = ea_draft::DiscardService::new(
        harness.repository(),
        harness.provider() as std::sync::Arc<dyn ea_key_provider::KeyProvider>,
        harness.binding().binding_object_hash,
        harness.head().preexisting_effective_now(),
    );
    assert_eq!(
        discard
            .begin_discard(harness.proof_for(ea_operator::ReauthPurpose::DiscardDraft))
            .err()
            .map(|error| error.code()),
        Some("EA-DRAFT-PREPARED-FINALIZATION-PRESENT")
    );
}
