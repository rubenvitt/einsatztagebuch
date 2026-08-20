//! Sequenz, Kennung und Geheimnisse — EINMAL, und nie zweimal.

mod support;

use support::{WriterHarness, valid_incident};

#[test]
fn uuid_cek_and_nonce_are_drawn_exactly_once() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    let preview = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau muss entstehen");
    // Nach der Vorschau ist GENAU der UUIDv7 gezogen — und kein Geheimnis. Das
    // ist die tragende Zusage: keine lebende CEK ueberdauert den
    // Bestaetigungsdialog.
    assert_eq!(
        ea_writer::entropy_draws(),
        ea_writer::EntropyDraws {
            uuid: 1,
            cek: 0,
            nonce: 0
        },
        "die Vorschau zieht die Kennung und KEIN Geheimnis"
    );

    service
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect("der Abschluss muss tragen");
    assert_eq!(
        ea_writer::entropy_draws(),
        ea_writer::EntropyDraws {
            uuid: 1,
            cek: 1,
            nonce: 1
        },
        "der Abschluss uebernimmt die Kennung und zieht CEK und Nonce genau einmal"
    );
}

#[test]
fn the_entry_uuid_is_version_seven_and_variant_two() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    let reached = service
        .finalize_up_to(
            &proof,
            valid_incident(),
            harness.observed_now(),
            ea_writer::FinalizationStep::ValidateAndSerialize,
        )
        .expect("Schritt 4 muss erreichbar sein");

    // Der `recordId` steht im serialisierten Nutzlastkopf. Gelesen wird er
    // ueber den Dekoder von `ea-schema` und nicht ueber eine geratene
    // Byteposition.
    // Ueber `validate` und nicht ueber einen Rohdekoder: der Aufruf dekodiert,
    // validiert UND rekodiert gegen die Eingabebytes. Er belegt damit
    // nebenbei, dass Schritt 4 wirklich DETERMINISTISCH serialisiert hat.
    let payload = ea_schema::SchemaRegistry::v1()
        .validate("ea.incident", 1, reached.draft_record_bytes())
        .expect("die serialisierte Nutzlast muss validieren und bytegleich rekodieren");
    let ea_schema::PayloadV1::Incident(incident) = payload.payload() else {
        panic!("die Fixture serialisiert einen Einsatz");
    };
    let uuid = incident.header().record_id();
    let bytes = uuid.as_bytes();
    assert_eq!(bytes[6] >> 4, 0x7, "RFC 9562 §5.7: Version sieben");
    assert_eq!(bytes[8] >> 6, 0b10, "RFC 9562: Variante zwei");
}

#[test]
fn the_first_entry_binds_no_predecessor_and_claims_sequence_zero() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    let preview = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau muss entstehen");
    assert_eq!(preview.proposed_sequence().get(), 0);
    assert!(
        preview.previous_entry_hash().is_none(),
        "ein leerer Bestand hat keinen Vorgaenger"
    );

    let out = service
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect("der Abschluss muss tragen");
    assert_eq!(out.sequence.get(), 0);
}

/// Eine schon verbrauchte Einsatznummer wird abgewiesen, BEVOR etwas gestagt
/// ist.
///
/// Vorab beansprucht und nicht durch einen zweiten Abschluss erzeugt: ein
/// zweiter Abschluss im selben Bestand faellt schon an Schritt 3, weil der
/// gebundene Head fuer die inzwischen verbrauchte Sequenz gewaehlt ist. Der
/// Vorabanspruch isoliert genau die Anspruchspruefung.
#[test]
fn a_taken_incident_number_is_refused_before_anything_is_staged() {
    let harness = WriterHarness::with_incident();
    harness.preclaim_incident_number();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    // `expect_err` verlangt `Debug` am Ok-Typ, und `FinalizationPreview` traegt
    // keines — er haelt Hashes, und Stufe 1 leitet fuer die kein `Debug` ab.
    let error = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .err()
        .expect("dieselbe Nummer im selben Jahr ist verbraucht");
    assert_eq!(error.code(), "EA-WRITER-INCIDENT-NUMBER-TAKEN");
    assert_eq!(
        harness.staged_object_count(),
        0,
        "die Ablehnung stagt nichts"
    );
}

/// Ein zweiter Abschluss gegen denselben Head ist ein Kopfabgleichfall.
///
/// Der gebundene Head ist fuer die vorgeschlagene Sequenz gewaehlt. Ist sie
/// verbraucht, MUSS die Finalisierung blockieren statt eine Sequenz zweimal zu
/// benutzen — das ist die Produktinvariante „jede committed Sequenz ist
/// eindeutig".
#[test]
fn a_second_finalization_against_a_consumed_sequence_blocks() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    let preview = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau muss entstehen");
    service
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect("der erste Abschluss muss tragen");

    let error = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .err()
        .expect("die verbrauchte Sequenz MUSS blockieren");
    assert_eq!(error.code(), "EA-WRITER-HEAD-RECONCILIATION-REQUIRED");
    assert_eq!(
        harness
            .backend()
            .relative_paths_below_for_test("entries/")
            .into_iter()
            .filter(|path| path.ends_with(".eip"))
            .count(),
        1,
        "kein zweiter Eintrag"
    );
}

/// Eine ABGEWIESENE Finalisierung verbrennt die Einsatznummer NICHT.
///
/// `IncidentNumberRegister` hat `claim` und `contains` und KEINE Freigabe. Stand
/// der dauerhafte Anspruch vor dem Vorschauvergleich, dann machte jede
/// fail-closed Ablehnung — ein geaenderter Head, eine geaenderte Policy, ein
/// fortgeschrittenes `effectiveNow` — die Nummer fuer immer unbenutzbar, und
/// der Bediener muesste sich fuer denselben realen Einsatz eine andere
/// ausdenken. Das Addendum verlangt an genau dieser Stelle „eine neue Vorschau
/// und eine neue Bestaetigung" und ausdruecklich keine Umgehung — eine
/// verbrannte Nummer waere weder das eine noch das andere.
#[test]
fn a_refused_finalization_does_not_burn_the_incident_number() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    // Eine Vorschau ueber einen ANDEREN Inhalt, gegen den Abschluss des
    // ersten gestellt: der Inhalt geht ueber den `recordDigest` in den
    // `previewHash` ein, also weicht die unter der Sperre nachgerechnete
    // Vorschau ab.
    let foreign = service
        .preview(&proof, support::other_incident(), harness.observed_now())
        .expect("die zweite Vorschau muss entstehen");
    let error = service
        .finalize(&proof, valid_incident(), &foreign, harness.observed_now())
        .expect_err("eine fremde Vorschau MUSS fail-closed abgewiesen werden");
    assert_eq!(error.code(), "EA-REGISTRY-STALE-ACK-PREVIEW-MISMATCH");

    // Und die Nummer ist FREI — der dauerhafte Anspruch liegt hinter dem Tor.
    assert!(
        !harness.incident_number_is_taken("2026-000042"),
        "die abgewiesene Finalisierung darf die Nummer nicht verbrauchen"
    );
    assert!(!harness.incident_number_is_taken("2026-000043"));

    // Der Beleg, dass die Nummer wirklich noch benutzbar ist.
    let preview = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau muss erneut entstehen");
    service
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect("derselbe Einsatz MUSS danach abschliessbar sein");
    assert!(harness.incident_number_is_taken("2026-000042"));
}
