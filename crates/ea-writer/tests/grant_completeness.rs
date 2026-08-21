//! Der initiale Grant-Plan ist VOLLSTAENDIG oder er entsteht nicht.
//!
//! „Jeder aktive Reader wird initial freigegeben" ist eine Produktinvariante.
//! Ein stillschweigend uebersprungener Reader waere ein Eintrag, den ein
//! berechtigter Leser nie oeffnen kann — und niemand haette es gemerkt.

mod support;

use ea_format::GrantPurposeV1;
use support::{LineVariantV1, WriterHarness, valid_incident};

#[test]
fn the_plan_holds_exactly_one_recovery_and_every_active_reader() {
    let harness = WriterHarness::with_incident();
    let plan = ea_writer::build_grant_plan(harness.head()).expect("der Plan muss entstehen");
    assert_eq!(
        plan.items()
            .iter()
            .filter(|item| item.purpose() == GrantPurposeV1::Recovery)
            .count(),
        1
    );
    assert_eq!(plan.items().len(), harness.expected_grant_count());
    assert_eq!(
        plan.items()
            .iter()
            .filter(|item| item.purpose() == GrantPurposeV1::Reader)
            .count(),
        harness.expected_grant_count() - 1,
        "der Rest sind ausnahmslos Reader"
    );
}

/// Ein Reader ohne KEM-Abdruck erreicht den Writer GAR NICHT.
///
/// Der Vertrag von `SelectedRegistryHead::active_certificates` warnt, dass
/// nichts die Empfaengerentscheidung erzwinge und ein Zertifikat mit
/// `kem_key_thumbprint: None` denkbar sei. Am ACCESSOR stimmt das; am
/// VERTRAUENSPFAD nicht: die Kandidatenpruefung der Stufe 1 weist eine Linie
/// mit einem solchen Readerzertifikat ab, bevor ein Head daraus entsteht.
///
/// Der Waechter in `build_grant_plan` bleibt deshalb stehen und ist
/// Tiefenverteidigung — sein Fehlercode `EA-WRITER-READER-WITHOUT-KEM-KEY` ist
/// ueber eine GUELTIGE Registry nicht erreichbar. Dieser Test belegt genau das,
/// statt eine Zusicherung zu behaupten, die kein Aufbau herstellen kann.
#[test]
fn a_reader_without_a_kem_key_never_reaches_the_writer() {
    assert_eq!(
        WriterHarness::candidate_rejection(LineVariantV1 {
            reader_without_kem_key: true,
            ..LineVariantV1::default()
        }),
        Some("EA-TRUST-ACTION-MISMATCH"),
        "die Kandidatenpruefung der Stufe 1 weist einen Reader ohne KEM-Schluessel ab"
    );
    // Und die glatte Linie wird NICHT abgewiesen — sonst bezeugte der Vergleich
    // oben nur, dass jede Linie faellt.
    assert_eq!(
        WriterHarness::candidate_rejection(LineVariantV1::default()),
        None
    );
}

#[test]
fn a_second_recovery_recipient_is_refused_by_the_stage_one_constructor() {
    let harness = WriterHarness::with_variant(LineVariantV1 {
        second_recovery_recipient: true,
        ..LineVariantV1::default()
    });
    // Der Code kommt aus `GrantPlanV1::new` und NICHT aus dieser Crate: die
    // Negativregel ist in Stufe 1 eingefroren, und eine nachgebaute waere eine
    // zweite Quelle derselben Wahrheit.
    let error = ea_writer::build_grant_plan(harness.head())
        .expect_err("zwei Recovery-Empfaenger sind kein baubarer Plan");
    assert_eq!(error.code(), "EA-GRANT-DUPLICATE-RECOVERY");
}

#[test]
fn every_planned_grant_exists_as_an_eag_before_the_entry_is_published() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    let reached = service
        .finalize_up_to(
            &proof,
            valid_incident(),
            harness.observed_now(),
            ea_writer::FinalizationStep::ProduceGrantsAndEntryBytes,
        )
        .expect("Schritt 7 muss erreichbar sein");
    let plan = reached.grant_plan().expect("der Plan liegt");
    for item in plan.items() {
        assert!(
            reached.grant_for(item.recipient_key_thumbprint()).is_some(),
            "jedes Planitem hat sein .eag"
        );
    }
    assert_eq!(
        reached
            .manifest_core()
            .expect("das Manifest liegt")
            .fields()
            .initial_grant_plan_hash,
        *plan.hash().as_bytes(),
        "das Manifest bindet den Plan und nicht die erzeugten Objekthashes"
    );
}

/// Das NULL-Bein der dritten Invariante: kein aktiver Recovery-Empfaenger.
///
/// Die beiden anderen Beine sind bezeugt — der VOLLSTAENDIGE Plan oben und der
/// ZWEITE Empfaenger, den der eingefrorene Konstruktor abweist. Fuer das Null-Bein
/// gab es keinen Aufbau: `WriterError::NoActiveRecoveryRecipient` (Schritt 3) hatte
/// in allen Testverzeichnissen null Treffer. Der sechste Knopf der Fixture stellt
/// den Zustand her, und er ist ERREICHBAR und keine Attrappe: die Kandidatenpruefung
/// der Stufe 1 weist eine Linie ohne Recovery-Empfaenger NICHT ab.
#[test]
fn a_registry_without_an_active_recovery_recipient_is_refused_before_any_secret_is_drawn() {
    let variant = LineVariantV1 {
        without_recovery_recipient: true,
        ..LineVariantV1::default()
    };
    // Erstens: Stufe 1 laesst diese Linie durch. Ohne diese Zeile koennte die
    // Zusicherung unten auch von einem Aufbau kommen, den der Vertrauenspfad
    // schon verworfen hat — dann bezeugte sie nichts ueber Schritt 3.
    assert_eq!(
        WriterHarness::candidate_rejection(variant),
        None,
        "die Linie ohne Recovery-Empfaenger MUSS verifizieren, sonst ist der Waechter \
         unerreichbar und dieser Test leer"
    );
    let harness = WriterHarness::with_variant(variant);
    // Zweitens: der Head weicht in GENAU diesem Punkt ab. Kein
    // Recovery-Empfaenger, aber weiterhin seine zwei Reader — sonst faellt die
    // Finalisierung an einem leeren Head statt am fehlenden Empfaenger.
    assert_eq!(
        harness
            .head()
            .active_certificates()
            .filter(|(_, fields)| fields.certificate_kind
                == ea_format::CertificateKindV1::RecoveryRecipient)
            .count(),
        0
    );
    assert_eq!(
        harness.expected_grant_count(),
        2,
        "die zwei Reader stehen weiter aktiv"
    );

    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    // Die VORSCHAU ist der Produktionseinstieg, der Schritt 3 zuerst erreicht,
    // und sie zieht KEIN Geheimnis: der Abschluss ist damit abgewiesen, bevor
    // CEK und AEAD-Nonce ueberhaupt entstehen.
    // `let Err(...) else` statt `expect_err`: `FinalizationPreview` leitet kein
    // `Debug` ab — eine Vorschau gehoert in keine Protokollzeile.
    let Err(refused) = service.preview(&proof, valid_incident(), harness.observed_now()) else {
        panic!("ohne Recovery-Empfaenger entsteht keine Vorschau");
    };
    // Gemessen wird der CODE und nicht blosses `is_err`, und das trennt die zwei
    // Waechter des Null-Beins: nimmt man den aus Schritt 3 heraus, weist der
    // eingefrorene Konstruktor der Stufe 1 denselben Aufbau mit
    // `EA-GRANT-MISSING-RECOVERY` ab — nachgeprueft per Mutation. Diese
    // Zusicherung bezeugt also GENAU den frueheren der beiden: die Pruefung am
    // HEAD, vor jeder Serialisierung.
    assert_eq!(refused.code(), "EA-WRITER-NO-ACTIVE-RECOVERY-RECIPIENT");

    // Und die Abweisung verklemmt nichts und hinterlaesst nichts: kein
    // gestagtes Objekt, keine Abschlussmarke, die Nummer unverbraucht, der
    // Entwurf unveraendert lesbar.
    assert_eq!(harness.staged_object_count(), 0);
    assert!(!harness.prepared_marker_is_present());
    assert!(!harness.incident_number_is_taken(&valid_incident().human_incident_number));
    assert!(!harness.draft_is_blank());

    // Die Gegenkontrolle steht in diesem Ziel und wird nicht wiederholt:
    // `every_planned_grant_exists_as_an_eag_before_the_entry_is_published`
    // faehrt DIESELBE Fixture mit der glatten Linie bis Schritt 7. Eine zweite
    // Fixture hier waere ausserdem eine zweite prozessweite Sperre im selben
    // Test und damit ein Selbstblock.
}
