//! Persisted lifecycle audits must verify under the certificate they actually name.
#[path = "support/operator_lifecycle.rs"]
mod lifecycle;
mod support;

use ea_admin::OperatorBindingService;
use ea_crypto::{SignerRole, VerificationContext, verify_cose_sign1};
use ea_format::{LocalAuditActionV1, LocalAuditOutcomeV1, decode_local_audit_event};
use ea_trust::SelectedRegistryHead;
use ea_types::{CertificateHash, ObjectHash};
use lifecycle::*;

fn certificate_hash(certificate: CertificateHash) -> ObjectHash {
    ObjectHash::try_from(certificate.as_bytes().as_slice()).unwrap()
}

fn signature_verifies(bytes: &[u8], head: &SelectedRegistryHead, role: SignerRole) -> bool {
    let row = ea_format::decode_local_audit_event(bytes).unwrap();
    let mut decoder = minicbor::Decoder::new(bytes);
    assert_eq!(decoder.array().unwrap(), Some(2));
    decoder.skip().unwrap();
    let signature_start = decoder.position();
    decoder.skip().unwrap();
    let signature = &bytes[signature_start..decoder.position()];
    let context = VerificationContext::local_audit(
        row.exact_core(),
        head.proposed_sequence(),
        role,
        head.registry_version(),
    )
    .unwrap();
    verify_cose_sign1(signature, head, &context).is_ok()
}

#[test]
fn persisted_login_signature_matches_its_named_writer_certificate() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let authenticator = h.authenticator(&head);
    OperatorBindingService::new(&head, audit.service())
        .verify_session(h.login(&authenticator))
        .unwrap();
    let rows = audit.booked();
    assert_eq!(rows.len(), 1);
    assert!(signature_verifies(&rows[0], &head, SignerRole::Writer));
    let row = decode_local_audit_event(&rows[0]).unwrap();
    assert!(row.signer_certificate_object_hash() == certificate_hash(h.certificate));
    assert!(row.operator_binding_object_hash() == Some(h.binding));
    assert_eq!(row.outcome(), LocalAuditOutcomeV1::Completed);
    let LocalAuditActionV1::Login(context) = row.action() else {
        panic!("login expected")
    };
    assert!(context.subject_object_hash() == Some(h.binding));
}

#[test]
fn failed_login_and_reauth_have_valid_device_signatures_and_the_known_binding() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let mut authenticator = h.authenticator(&head);
    authenticator.fail = true;
    assert!(
        OperatorBindingService::new(&head, audit.service())
            .verify_session(h.login(&authenticator))
            .is_err()
    );
    let rows = audit.booked();
    assert_eq!(rows.len(), 2);
    for (index, bytes) in rows.iter().enumerate() {
        assert!(signature_verifies(bytes, &head, SignerRole::Writer));
        let row = decode_local_audit_event(bytes).unwrap();
        assert_eq!(row.outcome(), LocalAuditOutcomeV1::Failed);
        assert!(row.operator_binding_object_hash() == Some(h.binding));
        assert!(row.signer_certificate_object_hash() == certificate_hash(h.certificate));
        let context = match (index, row.action()) {
            (0, LocalAuditActionV1::Login(context))
            | (1, LocalAuditActionV1::ReauthFailure(context)) => context,
            _ => panic!("exact failure action order expected"),
        };
        assert!(context.subject_object_hash() == Some(h.binding));
    }
}

#[test]
fn unknown_requested_binding_is_audited_without_attributing_it_to_an_operator() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let authenticator = h.authenticator(&head);
    let mut request = h.login(&authenticator);
    request.binding_object_hash = ObjectHash::try_from(&[0xab; 32][..]).unwrap();
    assert!(
        head.active_operator_binding_fields(request.binding_object_hash)
            .is_none()
    );
    assert!(
        OperatorBindingService::new(&head, audit.service())
            .verify_session(request)
            .is_err()
    );
    let rows = audit.booked();
    assert_eq!(rows.len(), 2);
    for bytes in rows {
        assert!(signature_verifies(&bytes, &head, SignerRole::Writer));
        let row = decode_local_audit_event(&bytes).unwrap();
        assert!(row.operator_binding_object_hash().is_none());
        assert_eq!(row.outcome(), LocalAuditOutcomeV1::Failed);
        match row.action() {
            LocalAuditActionV1::Login(context) | LocalAuditActionV1::ReauthFailure(context) => {
                assert!(context.subject_object_hash().is_none());
            }
            _ => panic!("expected failed login or reauth"),
        }
    }
}

#[test]
fn binding_and_revocation_audits_verify_exact_actor_targets_and_effective_sequence() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("audit-target");
    let native = Native::new();
    let mut authorization = h.authorization();
    let prepared = h
        .provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut authorization,
        )
        .unwrap();
    let expected_sequence = registry_fields(prepared.activation_bytes()).effective_from_sequence;
    let rows = audit.booked();
    for bytes in &rows {
        assert!(signature_verifies(bytes, &head, SignerRole::Writer));
    }
    let binding_changes: Vec<_> = rows
        .iter()
        .map(|bytes| decode_local_audit_event(bytes).unwrap())
        .filter(|row| matches!(row.action(), LocalAuditActionV1::BindingChange(_)))
        .collect();
    assert_eq!(binding_changes.len(), 1);
    let row = &binding_changes[0];
    assert!(row.operator_binding_object_hash() == Some(h.binding));
    assert_eq!(row.outcome(), LocalAuditOutcomeV1::Accepted);
    let LocalAuditActionV1::BindingChange(context) = row.action() else {
        unreachable!()
    };
    assert!(context.old_binding_object_hash().is_none());
    assert!(context.new_binding_object_hash() == Some(prepared.binding_object_hash()));
    assert_eq!(context.effective_from_sequence(), expected_sequence);

    let active = authorization.activate(&prepared);
    let audit = h.audit(&active, 0);
    let revoked = h
        .revoke(
            &active,
            audit.service(),
            prepared.binding_object_hash(),
            &mut authorization,
        )
        .unwrap();
    let expected_sequence = registry_fields(revoked.registry_bytes()).effective_from_sequence;
    let rows = audit.booked();
    for bytes in &rows {
        assert!(signature_verifies(bytes, &active, SignerRole::Writer));
    }
    let revocations: Vec<_> = rows
        .iter()
        .map(|bytes| decode_local_audit_event(bytes).unwrap())
        .filter(|row| matches!(row.action(), LocalAuditActionV1::Revocation(_)))
        .collect();
    assert_eq!(revocations.len(), 1);
    let row = &revocations[0];
    assert!(row.operator_binding_object_hash() == Some(h.binding));
    assert_eq!(row.outcome(), LocalAuditOutcomeV1::Accepted);
    let LocalAuditActionV1::Revocation(context) = row.action() else {
        unreachable!()
    };
    assert!(context.old_binding_object_hash() == Some(prepared.binding_object_hash()));
    assert!(context.new_binding_object_hash().is_none());
    assert_eq!(context.effective_from_sequence(), expected_sequence);
}

#[test]
fn signature_verification_rejects_tampering_and_the_original_root_device_mismatch() {
    let h = Harness::new();
    let head = h.head();
    let authenticator = h.authenticator(&head);
    let audit = h.audit(&head, 0);
    OperatorBindingService::new(&head, audit.service())
        .verify_session(h.login(&authenticator))
        .unwrap();
    let mut bytes = audit.booked().remove(0);
    assert!(signature_verifies(&bytes, &head, SignerRole::Writer));
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(!signature_verifies(&bytes, &head, SignerRole::Writer));

    let mismatched = support::AuditHarness::with_provider(
        &head,
        certificate_hash(h.certificate),
        0,
        support::FixtureKeyProvider::root(),
    );
    OperatorBindingService::new(&head, mismatched.service())
        .verify_session(h.login(&authenticator))
        .unwrap();
    assert!(!signature_verifies(
        &mismatched.booked()[0],
        &head,
        SignerRole::Writer
    ));
}

#[test]
fn sqlcipher_persisted_login_bytes_verify_after_reopening_the_database() {
    let h = Harness::new();
    let head = h.head();
    let authenticator = h.authenticator(&head);
    let audit = sql_audit(&head, &h.database, h.certificate);
    OperatorBindingService::new(&head, &audit)
        .verify_session(h.login(&authenticator))
        .unwrap();
    drop(audit);
    let directory = h.directory;
    drop(h.database);
    let reopened = reopen_database(directory.path());
    let row = reopened
        .query_row("SELECT exact_bytes FROM local_audit_event", &[])
        .unwrap()
        .unwrap();
    let bytes = row.blob(0).unwrap();
    assert!(signature_verifies(bytes, &head, SignerRole::Writer));
    assert_eq!(
        decode_local_audit_event(bytes).unwrap().outcome(),
        LocalAuditOutcomeV1::Completed
    );
}

#[test]
fn recovery_admin_login_is_signed_by_its_own_admin_certificate() {
    let mut h = Harness::new();
    let admin = RecoveryAdmin::enroll(&mut h.line);
    let head = support::selected_head_at(&h.line, 3, 50);
    let audit = admin.audit(&head);
    let authenticator = admin.authenticator(&head);
    OperatorBindingService::new(&head, audit.service())
        .verify_session(admin.login(&authenticator))
        .unwrap();
    let rows = audit.booked();
    assert_eq!(rows.len(), 1);
    assert!(signature_verifies(
        &rows[0],
        &head,
        SignerRole::OrganizationAdmin
    ));
    assert!(
        decode_local_audit_event(&rows[0])
            .unwrap()
            .signer_certificate_object_hash()
            == certificate_hash(admin.certificate)
    );
}
