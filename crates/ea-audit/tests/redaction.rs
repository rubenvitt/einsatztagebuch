//! Die getypte Auditzeile traegt keine fachlichen Bytes und leckt nicht in
//! Fehlermeldungen.

mod support;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod trust_support;

use ea_audit::{AuditActorProof, TypedLocalAuditEvent};
use ea_format::{GenericAuditContextV1, LocalAuditActionV1, LocalAuditOutcomeV1};
use ea_types::ObjectHash;
use support::AuditHarness;

#[test]
fn typed_audit_never_carries_fachliche_bytes_and_never_leaks_in_errors() {
    let harness = AuditHarness::new();
    let audit = harness.audit_service();
    let session = harness.operator_session();
    let canary_hash = ObjectHash::try_from([0xCA; 32].as_slice()).unwrap();
    let event = audit
        .record_signed(
            AuditActorProof::OperatorSession(&session),
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::Login(GenericAuditContextV1::new(Some(canary_hash))),
                outcome: LocalAuditOutcomeV1::Accepted,
            },
        )
        .unwrap();
    assert!(ea_testkit::contains_canary(
        event.exact_bytes(),
        canary_hash.as_bytes()
    ));
    // ABWEICHUNG VOM BRIEF, gemessen und nicht angenommen. Die Briefform
    //
    //     cddl_cat::validate_cbor_bytes("local-audit-event-v1", CDDL,
    //                                   event.exact_bytes())
    //
    // scheitert bereits beim PARSEN der Grammatik:
    //
    //     ParseError { kind: Unparseable,
    //       ctx: "local-audit-event-v1 = [local-audit-event-core-v1,
    //             #6.18(COSE-Sign1)]" }
    //
    // `cddl_cat` kennt den CBOR-Tag-Ausdruck `#6.18(...)` nicht — derselbe
    // Befund, den `tools/xtask/tests/spec_completeness.rs`:2260-2266 bereits
    // protokolliert und mit derselben Normalisierung umgeht.
    //
    // Die Zusicherung ist deshalb ZWEIGETEILT, und die STAERKERE steht zuerst:
    // der exakte Kern — die unveraenderten Bytes, die die Signatur deckt — wird
    // gegen `local-audit-event-core-v1` gemessen. Danach wird die Gestalt des
    // Paares gegen `local-audit-event-v1` gemessen, mit der Normalisierung des
    // Workspace und einem `null` an der Signaturstelle, weil `any` ein `null`
    // annimmt und einen Tag nicht.
    //
    // Der Kern kommt aus `decode_local_audit_event` und nicht aus einem
    // Nachbau: der Dekodierer prueft in derselben Bewegung erneut, dass die
    // gespeicherte COSE genau diesen Kern deckt.
    let decoded = ea_format::decode_local_audit_event(event.exact_bytes()).unwrap();
    // Die Normalisierung gilt fuer BEIDE Aufrufe: `cddl_cat` parst die GANZE
    // Grammatik, auch wenn nur eine Regel als Wurzel dient — der Tagausdruck
    // laesst deshalb sogar die Kernpruefung scheitern. Beruehrt ist
    // ausschliesslich die Paarregel; `local-audit-event-core-v1` und alles,
    // woraus sie besteht, steht Zeichen fuer Zeichen unveraendert da.
    let cddl = include_str!("../../../schemas/reports/v1/local-audit.cddl")
        .replace("#6.18(COSE-Sign1)", "COSE-Sign1");
    cddl_cat::validate_cbor_bytes("local-audit-event-core-v1", &cddl, decoded.exact_core())
        .unwrap();

    let mut pair = Vec::with_capacity(decoded.exact_core().len() + 2);
    pair.push(0x82); // CBOR: definites Array aus zwei Gliedern
    pair.extend_from_slice(decoded.exact_core());
    pair.push(0xf6); // CBOR: null an der Signaturstelle
    cddl_cat::validate_cbor_bytes("local-audit-event-v1", &cddl, &pair).unwrap();
    let error = audit
        .record_signed(
            AuditActorProof::Expired,
            TypedLocalAuditEvent::login_failed(),
        )
        .unwrap_err();
    assert!(!ea_testkit::contains_canary(
        error.to_string().as_bytes(),
        canary_hash.as_bytes()
    ));
    assert_eq!(
        harness
            .reopen_audit()
            .event(event.id())
            .unwrap()
            .exact_bytes(),
        event.exact_bytes()
    );
}
