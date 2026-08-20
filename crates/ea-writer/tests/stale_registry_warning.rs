//! Der VERALTETE Registry-Head — erreichbar, unterschieden und fail-closed.
//!
//! `select_registry_head` gibt einen aktuellen Head nur heraus, solange
//! `rawNow <= notAfter` gilt: bei der AUSWAHL ist er also immer frisch. Veraltet
//! wird er erst, waehrend er gebunden ist, und genau dafuer existiert
//! `registryExpiryBehavior` (`design.md`:1447, :1455 — das Feld steuert
//! ausschliesslich die Finalisierung).
//!
//! Die Feststellung braucht deshalb eine ZWEITE, spaetere Zeit. Sie kommt vom
//! Wirt und ist ein Argument je Aufruf; gegen
//! `SelectedRegistryHead::preexisting_effective_now` — die Zeit ZUM
//! Auswahlzeitpunkt — waere jeder Head strukturell immer frisch, und der harte
//! Block fuer Evidence Grade eine Attrappe.
//!
//! Der BESTAETIGUNGSpfad (`acknowledge_stale_registry`,
//! `StaleRegistryAcknowledgement`) ist eine offengelegte Auslassung dieses
//! Tasks. Ohne ihn ist der Ausgang fail-closed: ein veralteter Head blockiert,
//! und diese Datei belegt, dass er die drei Faelle UNTERSCHEIDET.

mod support;

use ea_writer::StaleDecision;
use support::{LineVariantV1, WriterHarness, valid_incident};

#[test]
fn a_head_that_expires_while_bound_is_acknowledgeable_and_blocks_fail_closed() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    // Dieselbe Bindung, dieselbe Auswahl — nur eine spaetere beobachtete Zeit.
    let preview = service
        .preview(
            &proof,
            valid_incident(),
            harness.observed_now_after_expiry(),
        )
        .expect("die Vorschau MELDET die Veralterung und blockiert nicht");
    assert_eq!(
        preview.decision(),
        StaleDecision::StaleAcknowledgeable,
        "Standardprofil mit signiertem warn ist bestaetigungsfaehig"
    );
    assert!(!preview.decision().is_hard_block());

    // Und ohne Bestaetigungspfad ist der Abschluss fail-closed.
    let error = service
        .finalize(
            &proof,
            valid_incident(),
            &preview,
            harness.observed_now_after_expiry(),
        )
        .expect_err("ein veralteter Head darf nicht stillschweigend finalisieren");
    assert_eq!(error.code(), "EA-REGISTRY-STALE-ACK-REQUIRED");
    assert_eq!(
        harness.staged_object_count(),
        0,
        "die Ablehnung stagt nichts"
    );
    assert!(!harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
}

#[test]
fn evidence_grade_and_a_signed_block_never_reach_an_acknowledgement() {
    for variant in [
        LineVariantV1 {
            evidence_grade: true,
            ..LineVariantV1::default()
        },
        LineVariantV1 {
            signed_block_expiry: true,
            ..LineVariantV1::default()
        },
    ] {
        let harness = WriterHarness::with_variant(variant);
        let source = harness.source();
        let service = harness.service(&source);
        let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

        let preview = service
            .preview(
                &proof,
                valid_incident(),
                harness.observed_now_after_expiry(),
            )
            .expect("die Vorschau meldet auch den harten Block");
        assert_eq!(preview.decision(), StaleDecision::HardBlock);
        assert!(preview.decision().is_hard_block());

        let error = service
            .finalize(
                &proof,
                valid_incident(),
                &preview,
                harness.observed_now_after_expiry(),
            )
            .expect_err("ein harter Block ist IMMER ein Fehler");
        assert_eq!(error.code(), "EA-REGISTRY-STALE-BLOCKED");
        assert_eq!(harness.staged_object_count(), 0);

        // Und derselbe Bestand mit derselben Bindung schliesst zur FRISCHEN
        // Zeit ab: der Block haengt an der Zeit und nicht an der Fixture.
        let preview = service
            .preview(&proof, valid_incident(), harness.observed_now())
            .expect("zur frischen Zeit entsteht eine Vorschau");
        assert_eq!(preview.decision(), StaleDecision::Fresh);
        service
            .finalize(&proof, valid_incident(), &preview, harness.observed_now())
            .expect("zur frischen Zeit MUSS derselbe Lauf abschliessen");
    }
}

/// Die Vorschau traegt das Alter des GEBUNDENEN Vertrauensbestands und die
/// Policyfrist.
///
/// Der Bezugspunkt ist `SelectedRegistryHead::issued_at` und kein Feld, das der
/// Aufrufer neben der Bindung mitfuehrt — sonst waere die Auffrischungswarnung
/// eine, die der Aufrufer abschalten kann.
#[test]
fn the_preview_shows_the_trust_age_and_the_policy_refresh_deadline() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    let preview = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau muss entstehen");

    assert_eq!(
        preview.trust_age_ms(),
        harness.expected_trust_age_ms(harness.observed_now())
    );
    assert!(
        preview.trust_age_ms() > 0,
        "ein Alter von null bezeugte nichts"
    );
    assert_eq!(
        preview.reader_trust_refresh_ms(),
        harness.head().policy_fields().reader_trust_refresh_ms
    );
    assert!(
        !preview.trust_refresh_overdue(),
        "eine Stunde ist unter der Vorgabefrist von vierundzwanzig"
    );

    // Eine zurueckgedrehte Uhr macht den gebundenen Head nicht JUENGER: der
    // Auswahlzeitpunkt ist der Boden.
    let rewound = service
        .preview(
            &proof,
            valid_incident(),
            ea_types::UnixMillis::new(harness.head().issued_at().get()),
        )
        .expect("die Vorschau entsteht auch gegen eine zurueckgedrehte Uhr");
    assert_eq!(
        rewound.trust_age_ms(),
        preview.trust_age_ms(),
        "der Boden am Auswahlzeitpunkt haelt das gemeldete Alter monoton"
    );
}

/// Eine ueberschrittene Auffrischungsfrist ist eine WARNUNG und keine Blockade.
///
/// Sie muss deshalb bei einem FRISCHEN Head auftreten koennen. Mit der
/// Vorgabefrist von vierundzwanzig Stunden ist das arithmetisch unmoeglich —
/// `notAfter` liegt eine Sekunde davor —, also traegt die Policy dieser Fixture
/// eine kurze Frist.
#[test]
fn an_overdue_refresh_deadline_warns_without_blocking() {
    let harness = WriterHarness::with_variant(LineVariantV1 {
        short_reader_trust_refresh: true,
        ..LineVariantV1::default()
    });
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    let preview = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau muss entstehen");

    assert_eq!(preview.decision(), StaleDecision::Fresh);
    assert!(
        preview.trust_age_ms() > preview.reader_trust_refresh_ms(),
        "das Alter liegt UEBER der Frist"
    );
    assert!(preview.trust_refresh_overdue());

    // Und der Abschluss laeuft trotzdem: der blockierende Zeitbegriff ist
    // `notAfter` und nicht `readerTrustRefreshMs`.
    service
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect("eine ueberfaellige Auffrischung blockiert NICHT");
}
