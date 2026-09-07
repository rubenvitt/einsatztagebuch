//! Der Writer-Uebergang durch den NORMALEN Finalisierungspfad und die
//! Blockade des zurueckgespielten alten Writers.
//!
//! Stufe 5, Task 5, Luecken 2 und 3: der Writer erzeugt einen `keyTransition`
//! ueber dieselben dreizehn Schritte wie einen Einsatz, liest den wirksamen
//! Uebergang AUSSCHLIESSLICH aus dem gewaehlten Kopf und stellt LOKAL fest,
//! ob sein Bindungszertifikat der laufende Writer ist — bevor ein Nachweis
//! geprueft, eine Nummer beansprucht oder ein Geheimnis gezogen wird.
//!
//! Jede Zusicherung ist falsifizierbar: fuer jeden neuen Waechter in
//! `finalize.rs` steht hier ein Zeuge, der rot wird, sobald der Waechter
//! fehlt.

#[path = "support/mod.rs"]
mod support;

use ea_schema::{PayloadV1, SCHEMA_VERSION_V1, SchemaRegistry};
use ea_testkit::contains_canary;
use ea_types::{ChainSequence, EntryHash};

use support::{
    CANARY_TRANSITION_REASON, TransitionHarness, key_transition_input, other_incident,
    valid_incident,
};

/// Der Code, mit dem ein Lauf NICHT stattgefunden hat.
///
/// `expect_err` verlangt `Debug` auf dem `Ok`-Typ, und eine Vorschau hat
/// bewusst keines — ihr Inhalt gehoert in keine Protokollzeile.
fn blocked_with<T>(result: Result<T, ea_writer::WriterError>, why: &str) -> &'static str {
    match result {
        Ok(_) => panic!("{why}"),
        Err(error) => error.code(),
    }
}

/// Ein `previous_entry_hash`, den KEIN Eintrag dieses Bestands traegt.
fn foreign_previous_entry_hash() -> EntryHash {
    EntryHash::from(support::trust_support::hash32(0x35))
}

#[test]
fn the_new_writer_finalizes_the_key_transition_bound_to_the_exact_transition_hash() {
    let mut harness = TransitionHarness::new();
    let first = harness.old_writer_finalizes_first_entry();
    assert_eq!(first.sequence, ChainSequence::new(0));
    let transition_hash = harness.activate_transition(1, first.entry_hash);

    let head = harness.post_transition_head(1);
    let transition = *head
        .effective_writer_transition()
        .expect("der Uebergangskopf traegt seinen Uebergang");
    assert!(transition.object_hash() == transition_hash);
    assert!(transition.previous_entry_hash() == first.entry_hash);

    let claims = harness.checkpoint_claims_through(&first);
    let source = harness.old().source();
    let service = harness.new_writer_service(&source, &head, &claims);
    let proof = harness.new_writer_proof(&head);
    let now = harness.old().observed_now();

    let preview = service
        .preview_key_transition(&proof, key_transition_input(CANARY_TRANSITION_REASON), now)
        .expect("die Vorschau des Uebergangs muss entstehen");
    assert_eq!(preview.proposed_sequence(), ChainSequence::new(1));
    let outcome = service
        .finalize_key_transition(
            &proof,
            key_transition_input(CANARY_TRANSITION_REASON),
            &preview,
            now,
        )
        .expect("der keyTransition muss abschliessen");
    assert_eq!(outcome.sequence, ChainSequence::new(1));

    // Das Manifest traegt GENAU den Objekthash des wirksamen Uebergangs.
    let entry = harness.old().published_entry(outcome.entry_hash);
    let fields = entry.value().manifest().fields();
    assert!(fields.writer_transition_event_hash == Some(transition_hash));
    assert!(fields.writer_certificate_hash == harness.new_writer_certificate_hash());
    assert!(fields.previous_entry_hash == Some(first.entry_hash));

    // Die Nutzlast ist ein `keyTransition` mit demselben Hash und der
    // eingegebenen Begruendung — gelesen wie ein Recovery-Empfaenger liest.
    let plaintext = harness.decrypt_entry_as_recovery_recipient(outcome.entry_hash);
    let validated = SchemaRegistry::v1()
        .validate("ea.key-transition", SCHEMA_VERSION_V1, &plaintext)
        .expect("die entschluesselte Nutzlast ist ein gueltiger keyTransition");
    let PayloadV1::KeyTransition(key_transition) = validated.payload() else {
        panic!("die Nutzlast ist kein keyTransition");
    };
    assert!(key_transition.writer_transition_event_object_hash() == transition_hash);
    assert_eq!(
        key_transition.organizational_reason(),
        CANARY_TRANSITION_REASON
    );

    // Die Begruendung ist VERSIEGELT: kein veroeffentlichter Bytestrom
    // traegt sie (`design.md`:397).
    let published = harness.old().published_archive_bytes();
    assert!(
        !published.is_empty(),
        "die Zusicherung waere leer: es liegt kein veroeffentlichtes Objekt"
    );
    for (path, bytes) in &published {
        assert!(
            !contains_canary(bytes, CANARY_TRANSITION_REASON.as_bytes()),
            "die organisatorische Begruendung steht im Klartext in {path}"
        );
    }
    assert!(harness.old().staged_object_count() == 0);
}

#[test]
fn the_transition_sequence_takes_only_a_key_transition_and_the_next_takes_only_an_incident() {
    let mut harness = TransitionHarness::new();
    let first = harness.old_writer_finalizes_first_entry();
    let transition_hash = harness.activate_transition(1, first.entry_hash);
    let claims = harness.checkpoint_claims_through(&first);
    let now = harness.old().observed_now();

    // An der Uebergangssequenz ist ein Einsatz NICHT zulaessig — und der
    // Waechter faellt vor jedem Anspruch und jedem Geheimnis.
    {
        let head = harness.post_transition_head(1);
        let source = harness.old().source();
        let service = harness.new_writer_service(&source, &head, &claims);
        let proof = harness.new_writer_proof(&head);
        assert_eq!(
            blocked_with(
                service.preview(&proof, other_incident(), now),
                "ein Einsatz an der Uebergangssequenz ist kein Uebergang",
            ),
            "EA-WRITER-TRANSITION-REQUIRED"
        );
        let transition_preview = service
            .preview_key_transition(&proof, key_transition_input(CANARY_TRANSITION_REASON), now)
            .expect("die Vorschau des Uebergangs traegt");
        assert_eq!(
            blocked_with(
                service.finalize(&proof, other_incident(), &transition_preview, now),
                "eine Uebergangsvorschau bestaetigt keinen Einsatz",
            ),
            "EA-WRITER-TRANSITION-REQUIRED"
        );
        assert!(!harness.new_writer_incident_number_is_taken("2026-000043"));
        assert_eq!(harness.old().staged_object_count(), 0);
        assert!(harness.new_writer_draft_dek_is_present());

        service
            .finalize_key_transition(
                &proof,
                key_transition_input(CANARY_TRANSITION_REASON),
                &transition_preview,
                now,
            )
            .expect("der keyTransition muss abschliessen");
    }

    // Die naechste Sequenz nimmt einen Einsatz, und sein Manifest traegt
    // KEINEN Uebergangshash: der Writer hat sich nicht geaendert.
    let head = harness.post_transition_head(2);
    let source = harness.old().source();
    let service = harness.new_writer_service(&source, &head, &claims);
    let proof = harness.new_writer_proof(&head);
    let preview = service
        .preview(&proof, other_incident(), now)
        .expect("die Vorschau des ersten Einsatzes des neuen Writers traegt");
    let outcome = service
        .finalize(&proof, other_incident(), &preview, now)
        .expect("der erste Einsatz des neuen Writers muss abschliessen");
    assert_eq!(outcome.sequence, ChainSequence::new(2));
    let entry = harness.old().published_entry(outcome.entry_hash);
    let fields = entry.value().manifest().fields();
    assert!(fields.writer_transition_event_hash.is_none());
    assert!(fields.writer_certificate_hash == harness.new_writer_certificate_hash());
    assert!(harness.new_writer_incident_number_is_taken("2026-000043"));

    // Ein ZWEITER keyTransition ist an keiner weiteren Sequenz zulaessig:
    // der wirksame Uebergang gilt fuer GENAU seine Sequenz.
    let head = harness.post_transition_head(3);
    let source = harness.old().source();
    let service = harness.new_writer_service(&source, &head, &claims);
    let proof = harness.new_writer_proof(&head);
    assert_eq!(
        blocked_with(
            service.preview_key_transition(
                &proof,
                key_transition_input(CANARY_TRANSITION_REASON),
                now
            ),
            "ein zweiter keyTransition hat keinen wirksamen Uebergang",
        ),
        "EA-WRITER-TRANSITION-MISMATCH"
    );
    assert!(head.effective_writer_transition().is_some_and(|t| {
        t.object_hash() == transition_hash && t.effective_from_sequence() == ChainSequence::new(1)
    }));
}

#[test]
fn a_writer_without_an_effective_transition_cannot_finalize_a_key_transition() {
    let harness = TransitionHarness::new();
    let first = harness.old_writer_finalizes_first_entry();
    let claims = harness.checkpoint_claims_through(&first);

    // Der laufende Writer auf einer Linie OHNE Change 3.
    let head = harness.pre_transition_head(1);
    assert!(head.effective_writer_transition().is_none());
    let source = harness.old().source();
    let service = harness.old_writer_service(&source, &head, &claims);
    let proof = harness.old_writer_proof(&head);
    assert_eq!(
        blocked_with(
            service.preview_key_transition(
                &proof,
                key_transition_input(CANARY_TRANSITION_REASON),
                harness.old().observed_now(),
            ),
            "ohne wirksamen Uebergang gibt es keinen keyTransition",
        ),
        "EA-WRITER-TRANSITION-MISMATCH"
    );
    assert_eq!(harness.old().staged_object_count(), 0);
}

#[test]
fn the_old_writer_is_revoked_locally_on_the_post_transition_head_before_any_secret() {
    let mut harness = TransitionHarness::new();
    let first = harness.old_writer_finalizes_first_entry();
    harness.activate_transition(1, first.entry_hash);
    let claims = harness.checkpoint_claims_through(&first);
    let now = harness.old().observed_now();

    let head = harness.post_transition_head(1);
    assert!(head.current_writer_certificate_hash() == Some(harness.new_writer_certificate_hash()));
    let source = harness.old().source();
    let service = harness.old_writer_service(&source, &head, &claims);
    // Der Nachweis stammt vom STALEN Kopf des alten Writers: auf dem neuen
    // Kopf ist sein Zertifikat nicht mehr aktiv, und ein Nachweis dagegen ist
    // gar nicht ausstellbar. Der Waechter faellt VOR der Nachweispruefung.
    let proof = harness.old_writer_proof(&harness.pre_transition_head(1));

    assert_eq!(
        blocked_with(
            service.preview(&proof, other_incident(), now),
            "der alte Writer ist auf dem Uebergangskopf widerrufen",
        ),
        "EA-WRITER-REVOKED"
    );
    assert_eq!(
        blocked_with(
            service.preview_key_transition(
                &proof,
                key_transition_input(CANARY_TRANSITION_REASON),
                now
            ),
            "der alte Writer darf auch keinen keyTransition schreiben",
        ),
        "EA-WRITER-REVOKED"
    );
    // `finalize` mit einer Vorschau, die auf dem stalen Kopf entstanden ist:
    // die Neubewertung unter der Sperre faellt am selben Waechter.
    let stale_preview = {
        let stale_head = harness.pre_transition_head(1);
        let stale_service = harness.old_writer_service(&source, &stale_head, &claims);
        stale_service
            .preview(&proof, other_incident(), now)
            .expect("auf dem stalen Kopf entsteht eine Vorschau")
    };
    assert_eq!(
        blocked_with(
            service.finalize(&proof, other_incident(), &stale_preview, now),
            "die Neubewertung unter der Sperre weist den alten Writer ab",
        ),
        "EA-WRITER-REVOKED"
    );

    // Nichts gestagt, keine Nummer beansprucht, der draftDEK unberuehrt.
    assert_eq!(harness.old().staged_object_count(), 0);
    assert!(!harness.old().incident_number_is_taken("2026-000043"));
    assert!(harness.old().draft_dek_is_present());
    assert_eq!(harness.old().published_entry_paths().len(), 1);
}

/// Die Rueckspielung: der alte Writer kommt aus einer Sicherung VOR dem
/// Uebergang zurueck.
///
/// Waehlt er den NEUEN Kopf, ist er lokal widerrufen. Waehlt er nur seinen
/// STALEN alten Kopf, kennt dieser den Uebergang nicht — und der lokale
/// Writer-Waechter greift NICHT: er stellt fest, was der gewaehlte Kopf sagt,
/// und haengt damit an der Kopfauswahl. Das wird hier GEMESSEN und nicht
/// beschoenigt — an der Vorschau, denn Schritt 3 ist der Ort des Waechters.
/// Die beiden anderen Tore sind die Sequenz-Lease des Kopfes (in dieser
/// Fixture bis 120 offen) und der Server (`EA-COMMIT-WRITER-REVOKED`).
///
/// Was die Rueckspielung dieser Fixture AUSSERDEM zeigt, gehoert nicht zum
/// Writer-Waechter: der `draftDEK` kehrt nicht zurueck (er ist
/// geraetegebunden, siehe `WriterHarness::restore_captured_backup`), also
/// scheiterte ein voller Abschluss auf dem stalen Kopf ohnehin an Schritt 9 —
/// an der Grenze, nicht am Uebergang.
#[test]
fn a_restored_old_writer_is_revoked_on_the_new_head_but_a_stale_head_cannot_see_the_transition() {
    let mut harness = TransitionHarness::new();
    let first = harness.old_writer_finalizes_first_entry();
    harness.activate_transition(1, first.entry_hash);
    let claims = harness.checkpoint_claims_through(&first);
    let now = harness.old().observed_now();

    // Die Sicherung wurde VOR dem ersten Abschluss genommen: die Nummer ist
    // wieder frei, der `draftDEK` der gesicherten Entwurfszeile ist FORT, und
    // der Bestand traegt weiterhin Eintrag 0.
    harness.old_mut().restore_captured_backup();
    assert!(!harness.old().draft_dek_is_present());
    assert!(
        !harness
            .old()
            .incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER)
    );
    assert_eq!(harness.old().published_entry_paths().len(), 1);

    // Der neue Kopf: widerrufen, lokal, vor jedem Geheimnis.
    {
        let head = harness.post_transition_head(1);
        let source = harness.old().source();
        let service = harness.old_writer_service(&source, &head, &claims);
        let proof = harness.old_writer_proof(&harness.pre_transition_head(1));
        assert_eq!(
            blocked_with(
                service.preview(&proof, valid_incident(), now),
                "der zurueckgespielte alte Writer ist auf dem neuen Kopf widerrufen",
            ),
            "EA-WRITER-REVOKED"
        );
        assert_eq!(
            blocked_with(
                service.preview_key_transition(
                    &proof,
                    key_transition_input(CANARY_TRANSITION_REASON),
                    now
                ),
                "der zurueckgespielte alte Writer schreibt auch keinen keyTransition",
            ),
            "EA-WRITER-REVOKED"
        );
        assert_eq!(harness.old().staged_object_count(), 0);
        assert!(
            !harness
                .old()
                .incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER)
        );
    }

    // Der STALE Kopf: er kennt keinen Uebergang, sein laufender Writer ist der
    // alte, und die Lease reicht bis 120. Der Writer-Waechter in Schritt 3
    // KANN hier nicht ansprechen, und die Vorschau (Schritte 1 bis 5) entsteht.
    let stale_head = harness.pre_transition_head(1);
    assert!(stale_head.effective_writer_transition().is_none());
    assert!(
        stale_head.current_writer_certificate_hash() == Some(harness.old_writer_certificate_hash())
    );
    let source = harness.old().source();
    let service = harness.old_writer_service(&source, &stale_head, &claims);
    let proof = harness.old_writer_proof(&stale_head);
    let preview = service
        .preview(&proof, valid_incident(), now)
        .expect("die lokale Blockade haengt an der Kopfauswahl — gemessen, nicht beschoenigt");
    assert_eq!(preview.proposed_sequence(), ChainSequence::new(1));
    assert_eq!(harness.old().staged_object_count(), 0);
}

#[test]
fn a_key_transition_whose_previous_entry_is_not_the_local_head_requires_reconciliation() {
    let mut harness = TransitionHarness::new();
    let first = harness.old_writer_finalizes_first_entry();
    // Der Uebergang nennt als letzten Eintrag des alten Writers einen, den
    // dieser Bestand NICHT traegt: Root hat gegen einen anderen Kopf
    // signiert als den, der hier committet liegt. Der neue Writer muss sich
    // vor der Aktivierung gegen Server, Reader oder einen externen signierten
    // Checkpoint abgleichen — und schreibt vorher nichts.
    let transition_hash = harness.activate_transition(1, foreign_previous_entry_hash());
    let claims = harness.checkpoint_claims_through(&first);

    let head = harness.post_transition_head(1);
    let transition = head
        .effective_writer_transition()
        .expect("der Uebergangskopf traegt seinen Uebergang");
    assert!(transition.object_hash() == transition_hash);
    assert!(transition.previous_entry_hash() != first.entry_hash);
    let source = harness.old().source();
    let service = harness.new_writer_service(&source, &head, &claims);
    let proof = harness.new_writer_proof(&head);
    assert_eq!(
        blocked_with(
            service.preview_key_transition(
                &proof,
                key_transition_input(CANARY_TRANSITION_REASON),
                harness.old().observed_now(),
            ),
            "ein Uebergang, der einen fremden Vorgaenger nennt, verlangt den Abgleich",
        ),
        "EA-WRITER-HEAD-RECONCILIATION-REQUIRED"
    );
    assert_eq!(harness.old().staged_object_count(), 0);
    assert_eq!(harness.old().published_entry_paths().len(), 1);
}

#[test]
fn the_new_writer_before_its_change_3_is_not_the_current_writer() {
    let harness = TransitionHarness::new();
    let first = harness.old_writer_finalizes_first_entry();
    let claims = harness.checkpoint_claims_through(&first);

    // Vor dem Change 3 ist das neue Zertifikat freigegeben und bereichsaktiv,
    // aber NICHT der laufende Writer. Ein Nachweis gegen diesen Kopf ist fuer
    // die neue Bindung nicht ausstellbar; der Dienst faellt trotzdem lokal —
    // und zwar am Writer-Waechter, nicht erst am Nachweis.
    let head = harness.pre_transition_head(1);
    assert!(head.current_writer_certificate_hash() == Some(harness.old_writer_certificate_hash()));
    let source = harness.old().source();
    let service = harness.new_writer_service(&source, &head, &claims);
    let proof = harness.old_writer_proof(&head);
    assert_eq!(
        blocked_with(
            service.preview(&proof, other_incident(), harness.old().observed_now()),
            "der neue Writer ist vor seinem Change 3 nicht der laufende Writer",
        ),
        "EA-WRITER-REVOKED"
    );
}
