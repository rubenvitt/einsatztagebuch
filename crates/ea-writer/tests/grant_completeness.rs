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
