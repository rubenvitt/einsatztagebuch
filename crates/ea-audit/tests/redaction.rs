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

/// DRK-282, AK 53: die Abweisung einer abgelaufenen Sitzung ist eine eigene,
/// klartextfreie Aktion (`sessionExpired`, Code 12) mit dem Ausgang `failed`.
/// Der generische Kontext nennt höchstens einen Bindungshash — kein Konto,
/// keinen Namen, keinen Freitext.
#[test]
fn a_session_expiry_is_booked_as_its_own_failed_action_under_the_frozen_grammar() {
    let harness = AuditHarness::new();
    let audit = harness.audit_service();
    let session = harness.operator_session();
    let binding = session.binding_object_hash();
    let event = audit
        .record_signed(
            AuditActorProof::OperatorSession(&session),
            TypedLocalAuditEvent::session_expired(Some(binding)),
        )
        .unwrap();
    let decoded = ea_format::decode_local_audit_event(event.exact_bytes()).unwrap();
    assert_eq!(decoded.action().code(), 12);
    assert_eq!(decoded.action().context_tag(), 0);
    assert_eq!(decoded.outcome(), LocalAuditOutcomeV1::Failed);
    let LocalAuditActionV1::SessionExpired(context) = decoded.action() else {
        panic!("sessionExpired expected");
    };
    assert!(context.subject_object_hash() == Some(binding));
    assert!(decoded.operator_binding_object_hash() == Some(binding));
    let cddl = include_str!("../../../schemas/reports/v1/local-audit.cddl")
        .replace("#6.18(COSE-Sign1)", "COSE-Sign1");
    cddl_cat::validate_cbor_bytes("local-audit-event-core-v1", &cddl, decoded.exact_core())
        .unwrap();
    assert_eq!(
        harness
            .reopen_audit()
            .event(event.id())
            .unwrap()
            .exact_bytes(),
        event.exact_bytes()
    );
}

/// DRK-458, Profil §8: Publikation (13) und Öffnung (14) eines
/// Reader-Key-Escrows sind klartextfreie Zeilen mit Kontextarm 9 — nur
/// Hashes, und je Aktion genau die Nullbelegung, die das Profil verlangt.
#[test]
fn reader_key_escrow_rows_carry_only_hashes_under_the_frozen_grammar() {
    let harness = AuditHarness::new();
    let audit = harness.audit_service();
    let session = harness.operator_session();
    let hash = |fill: u8| ObjectHash::try_from([fill; 32].as_slice()).unwrap();
    let transport = ea_types::KeyThumbprint::try_from([0x7a; 32].as_slice()).unwrap();
    let cddl = include_str!("../../../schemas/reports/v1/local-audit.cddl")
        .replace("#6.18(COSE-Sign1)", "COSE-Sign1");
    for (event, code, outcome) in [
        (
            TypedLocalAuditEvent::reader_key_escrow_published(hash(0x71), hash(0x72), hash(0x73)),
            13,
            LocalAuditOutcomeV1::Completed,
        ),
        (
            TypedLocalAuditEvent::reader_key_escrow_consumed(hash(0x74), hash(0x75), transport),
            14,
            LocalAuditOutcomeV1::Accepted,
        ),
        (
            TypedLocalAuditEvent::reader_key_escrow_delivered(hash(0x74), hash(0x75), transport),
            14,
            LocalAuditOutcomeV1::Completed,
        ),
        (
            TypedLocalAuditEvent::reader_key_escrow_failed(hash(0x74), hash(0x75), transport),
            14,
            LocalAuditOutcomeV1::Failed,
        ),
    ] {
        let signed = audit
            .record_signed(AuditActorProof::OperatorSession(&session), event)
            .unwrap();
        let decoded = ea_format::decode_local_audit_event(signed.exact_bytes()).unwrap();
        assert_eq!(decoded.action().code(), code);
        assert_eq!(decoded.action().context_tag(), 9);
        assert_eq!(decoded.outcome(), outcome);
        let (LocalAuditActionV1::ReaderKeyEscrowPublication(context)
        | LocalAuditActionV1::ReaderKeyEscrowOpening(context)) = decoded.action()
        else {
            panic!("a reader key escrow row expected");
        };
        if code == 13 {
            assert!(context.escrow_object_hash() == hash(0x71));
            assert!(context.authorization_object_hash() == hash(0x72));
            assert!(context.target_transport_key_thumbprint().is_none());
            assert!(context.bundle_release_object_hash() == Some(hash(0x73)));
        } else {
            assert!(context.escrow_object_hash() == hash(0x74));
            assert!(context.authorization_object_hash() == hash(0x75));
            assert!(context.target_transport_key_thumbprint() == Some(transport));
            assert!(context.bundle_release_object_hash().is_none());
        }
        cddl_cat::validate_cbor_bytes("local-audit-event-core-v1", &cddl, decoded.exact_core())
            .unwrap();
        assert_eq!(
            harness
                .reopen_audit()
                .event(signed.id())
                .unwrap()
                .exact_bytes(),
            signed.exact_bytes()
        );
    }
}
