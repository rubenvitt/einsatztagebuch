#[path = "support/operator_lifecycle.rs"]
mod lifecycle;
mod support;

use ea_admin::RevokedOperatorBinding;
use ea_admin::{OperatorBindingService, OperatorLifecycleError};
use ea_draft::OperatorProfileRepository;
use ea_format::{
    DecodedTrustPayloadV1, OperatorRoleV1, ParsedArchiveObject, RegistryChangeV1,
    decode_exact_object,
};
use ea_local_store::StoreValue;
use lifecycle::*;
use std::sync::Arc;

#[test]
fn each_login_rechecks_account_instance_device_role_and_native_presence() {
    let h = Harness::new();
    let head = h.head();
    for (case, code) in [
        (0, "EA-OPERATOR-ACCOUNT-MISMATCH"),
        (1, "EA-OPERATOR-INSTANCE-KEY-MISSING"),
        (2, "EA-OPERATOR-INSTANCE-KEY-MISMATCH"),
        (3, "EA-OPERATOR-ROLE-MISMATCH"),
        (4, "EA-OPERATOR-DEVICE-MISMATCH"),
        (5, "EA-OPERATOR-PRESENCE-PROOF-INVALID"),
    ] {
        let audit = h.audit(&head, 0);
        let mut authenticator = h.authenticator(&head);
        authenticator.fail = case == 5;
        let mut login = h.login(&authenticator);
        let mut account = h.account.clone();
        match case {
            0 => account.hash = support::trust_support::hash32(0x99),
            1 => account.secret = None,
            2 => account.secret = Some([0x99; 32]),
            3 => login.role = OperatorRoleV1::Reader,
            4 => {
                login.device_certificate_hash =
                    ea_types::CertificateHash::from(h.line.bootstrap_admin_hash())
            }
            _ => {}
        }
        login.account = Arc::new(account);
        assert_eq!(
            OperatorBindingService::new(&head, audit.service())
                .verify_session(login)
                .err()
                .unwrap()
                .code(),
            code
        );
        assert_eq!(audit.booked().len(), 2);
    }
}

#[test]
fn external_identity_failure_and_forged_or_root_only_authorization_cannot_write_a_profile() {
    let h = Harness::new();
    let head = h.head();
    for case in 0..4 {
        let target = database("negative");
        let native = Native::new();
        let audit = h.audit(&head, 0);
        let mut identity = Identity::valid();
        identity.fail = case == 0;
        identity.wrong_challenge = case == 1;
        let mut auth = h.authorization();
        auth.wrong_core = case == 2;
        auth.root_only = case == 3;
        assert!(
            h.provision(
                &head,
                &audit,
                &target.database,
                &native,
                &identity,
                &mut auth
            )
            .is_err()
        );
        assert!(
            OperatorProfileRepository::new(target.database.clone())
                .load()
                .unwrap()
                .is_none()
        );
        let booked = audit.booked();
        let last = ea_format::decode_local_audit_event(booked.last().unwrap()).unwrap();
        assert!(matches!(
            last.action(),
            ea_format::LocalAuditActionV1::BindingChange(_)
        ));
        assert_eq!(last.outcome(), ea_format::LocalAuditOutcomeV1::Failed);
    }
}

#[test]
fn binding_and_activation_cannot_share_a_nonce_even_before_registry_commit() {
    let h = Harness::new();
    let head = h.head();
    let target = database("nonce");
    let native = Native::new();
    let audit = h.audit(&head, 0);
    let mut auth = h.authorization();
    auth.reused_nonce = true;
    assert!(
        h.provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth
        )
        .is_err()
    );
    assert!(
        OperatorProfileRepository::new(target.database.clone())
            .load()
            .unwrap()
            .is_none()
    );
}

#[test]
fn lifecycle_audit_failure_withholds_provisioned_bytes_and_encrypted_profile() {
    let h = Harness::new();
    let head = h.head();
    let target = database("audit-fail");
    let native = Native::new();
    let mut auth = h.authorization();
    h.database.execute("CREATE TRIGGER fail_lifecycle_audit BEFORE INSERT ON local_audit_event WHEN (SELECT count(*) FROM local_audit_event)>=3 BEGIN SELECT RAISE(ABORT,'injected'); END",&[]).unwrap();
    let audit = sql_audit(&head, &h.database, h.certificate);
    assert_eq!(
        h.provision_at(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            None
        )
        .err()
        .unwrap()
        .code(),
        "EA-OPERATOR-AUDIT-FAILED"
    );
    assert!(
        OperatorProfileRepository::new(target.database.clone())
            .load()
            .unwrap()
            .is_none()
    );
}

#[test]
fn revocation_signs_the_exact_binding_registry_change_and_only_activates_at_its_sequence() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("revoke");
    let native = Native::new();
    let mut auth = h.authorization();
    let prepared = h
        .provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
        )
        .unwrap();
    let active = auth.activate(&prepared);
    let audit = h.audit(&active, 0);
    let revocation = h
        .revoke(
            &active,
            audit.service(),
            prepared.binding_object_hash(),
            &mut auth,
        )
        .unwrap();
    assert!(
        active
            .active_operator_binding_fields(prepared.binding_object_hash())
            .is_some()
    );
    let ParsedArchiveObject::Trust(parsed) =
        decode_exact_object(revocation.registry_bytes()).unwrap()
    else {
        panic!()
    };
    let DecodedTrustPayloadV1::RegistryEvent(event) = parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    assert!(
        matches!(event.fields().change,RegistryChangeV1::Target{target_kind:1,object_hash} if object_hash==prepared.binding_object_hash())
    );
    assert_eq!(event.fields().effective_from_sequence.get(), 201);
    assert!(
        RevokedOperatorBinding::verify(
            &active,
            &active,
            revocation.registry_bytes(),
            prepared.binding_object_hash()
        )
        .is_err()
    );
    auth.line.add_object(revocation.registry_bytes().to_vec());
    let revoked = selected(&auth.line, revocation.registry_bytes(), 201);
    assert!(
        revoked
            .active_operator_binding_fields(prepared.binding_object_hash())
            .is_none()
    );
    assert!(
        RevokedOperatorBinding::verify(
            &active,
            &revoked,
            revocation.registry_bytes(),
            prepared.binding_object_hash()
        )
        .is_ok()
    );
}

#[test]
fn replacement_requires_activated_revocation_preserves_person_and_rotates_salt_and_key() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("replace");
    let native = Native::new();
    let mut auth = h.authorization();
    let first = h
        .provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
        )
        .unwrap();
    let original = OperatorProfileRepository::new(target.database.clone())
        .load()
        .unwrap()
        .unwrap();
    let active = auth.activate(&first);
    let audit = h.audit(&active, 0);
    let original_account = native.account.borrow().clone();
    let original_authenticator = native.authenticator(&active, first.binding_object_hash());
    assert!(
        h.provision_at(
            &active,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            None
        )
        .is_err()
    );
    let revocation = h
        .revoke(
            &active,
            audit.service(),
            first.binding_object_hash(),
            &mut auth,
        )
        .unwrap();
    auth.line.add_object(revocation.registry_bytes().to_vec());
    let revoked = selected(&auth.line, revocation.registry_bytes(), 201);
    let evidence = RevokedOperatorBinding::verify(
        &active,
        &revoked,
        revocation.registry_bytes(),
        first.binding_object_hash(),
    )
    .unwrap();
    let audit = h.audit(&revoked, 0);
    let mut identity = Identity::valid();
    identity.wrong_subject = true;
    assert!(
        h.provision_at(
            &revoked,
            audit.service(),
            &target.database,
            &native,
            &identity,
            &mut auth,
            Some(&evidence)
        )
        .is_err()
    );
    native.reuse.set(true);
    assert!(
        h.provision_at(
            &revoked,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            Some(&evidence)
        )
        .is_err()
    );
    native.reuse.set(false);
    let second = h
        .provision_at(
            &revoked,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            Some(&evidence),
        )
        .unwrap();
    let replacement = OperatorProfileRepository::new(target.database.clone())
        .load()
        .unwrap()
        .unwrap();
    assert!(original.operator_subject_id() == replacement.operator_subject_id());
    assert_ne!(
        original.profile_commitment_salt(),
        replacement.profile_commitment_salt()
    );
    assert!(first.binding_object_hash() != second.binding_object_hash());
    let selected = auth.activate(&second);
    assert!(
        selected
            .active_operator_binding_fields(first.binding_object_hash())
            .is_none()
    );
    assert!(
        selected
            .active_operator_binding_fields(second.binding_object_hash())
            .is_some()
    );
    let audit = h.audit(&selected, 0);
    let new_authenticator = native.authenticator(&selected, second.binding_object_hash());
    let mut login = native.login(
        &target.database,
        &new_authenticator,
        second.binding_object_hash(),
        h.certificate,
    );
    login.account = Arc::new(original_account);
    assert_eq!(
        OperatorBindingService::new(&selected, audit.service())
            .verify_session(login)
            .err()
            .unwrap()
            .code(),
        "EA-OPERATOR-INSTANCE-KEY-MISMATCH"
    );
    let old_login = native.login(
        &target.database,
        &original_authenticator,
        first.binding_object_hash(),
        h.certificate,
    );
    assert_eq!(
        OperatorBindingService::new(&selected, audit.service())
            .verify_session(old_login)
            .err()
            .unwrap()
            .code(),
        "EA-OPERATOR-BINDING-NOT-ACTIVE"
    );
}

#[test]
fn restart_after_profile_commit_before_return_recovers_the_exact_staged_activation() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("restart");
    let native = Native::new();
    let mut auth = h.authorization();
    let prepared = h
        .provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
        )
        .unwrap();
    drop(prepared);
    drop(target.database);
    let Authorization {
        stage_directory, ..
    } = auth;
    let reopened = reopen_database(target.directory.path());
    let pending = OperatorProfileRepository::new(reopened.clone())
        .load()
        .unwrap()
        .unwrap();
    assert!(
        head.active_operator_binding_fields(pending.operator_binding_object_hash())
            .is_none()
    );
    let mut restored_catalog = h.line.clone();
    let mut activation = None;
    for entry in std::fs::read_dir(stage_directory.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes.windows(12).any(|w| w == b"Grace Hopper"));
        let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&bytes).unwrap() else {
            panic!()
        };
        if matches!(
            parsed.value().decoded_payload().unwrap(),
            DecodedTrustPayloadV1::RegistryEvent(_)
        ) {
            activation = Some(bytes.clone());
        }
        restored_catalog.add_object(bytes);
    }
    let active = selected(&restored_catalog, &activation.unwrap(), 101);
    let authenticator = native.authenticator(&active, pending.operator_binding_object_hash());
    let audit = h.audit(&active, 0);
    let login = native.login(
        &reopened,
        &authenticator,
        pending.operator_binding_object_hash(),
        h.certificate,
    );
    assert_eq!(
        OperatorBindingService::new(&active, audit.service())
            .verify_session(login)
            .unwrap()
            .profile()
            .display_name(),
        "Grace Hopper"
    );
}

#[test]
fn revocation_audit_failure_withholds_event_and_does_not_change_the_selected_head() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("revoke-audit");
    let native = Native::new();
    let mut auth = h.authorization();
    let prepared = h
        .provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
        )
        .unwrap();
    let active = auth.activate(&prepared);
    h.database.execute("CREATE TRIGGER fail_revocation_audit BEFORE INSERT ON local_audit_event WHEN (SELECT count(*) FROM local_audit_event)>=2 BEGIN SELECT RAISE(ABORT,'injected'); END",&[]).unwrap();
    let audit = sql_audit(&active, &h.database, h.certificate);
    assert_eq!(
        h.revoke(&active, &audit, prepared.binding_object_hash(), &mut auth)
            .err()
            .unwrap()
            .code(),
        "EA-OPERATOR-AUDIT-FAILED"
    );
    assert_eq!(auth.staged.len(), 4);
    assert!(
        active
            .active_operator_binding_fields(prepared.binding_object_hash())
            .is_some()
    );
}

#[test]
fn login_checks_the_decrypted_commitment_before_releasing_profile_and_proof() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let service = OperatorBindingService::new(&head, audit.service());
    let authenticator = h.authenticator(&head);
    let session = service.verify_session(h.login(&authenticator)).unwrap();
    assert_eq!(session.profile().display_name(), "Ada Lovelace");
    assert_eq!(audit.booked().len(), 1);
    h.database
        .execute(
            "UPDATE operator_profile SET display_name = ?1",
            &[StoreValue::Text("Renamed".into())],
        )
        .unwrap();
    let error = service
        .verify_session(h.login(&authenticator))
        .err()
        .unwrap();
    assert_eq!(error.code(), "EA-OPERATOR-PROFILE-COMMITMENT");
    assert_eq!(audit.booked().len(), 3);
}

#[test]
fn failed_login_audit_withholds_the_profile_and_session() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 1);
    let service = OperatorBindingService::new(&head, audit.service());
    let authenticator = h.authenticator(&head);
    assert!(matches!(
        service.verify_session(h.login(&authenticator)),
        Err(OperatorLifecycleError::AuditFailed)
    ));
}

#[test]
fn provision_persists_encrypted_pending_profile_and_two_separate_authorized_objects() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("provision");
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
    let stored = OperatorProfileRepository::new(target.database.clone())
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(stored.display_name(), "Grace Hopper");
    assert!(
        head.active_operator_binding_fields(stored.operator_binding_object_hash())
            .is_none()
    );
    assert!(stored.operator_binding_object_hash() == prepared.binding_object_hash());
    assert_eq!(authorization.authorizations.len(), 2);
    assert_ne!(
        authorization.authorizations[0],
        authorization.authorizations[1]
    );
    assert_eq!(authorization.staged.len(), 4);
    let bytes = std::fs::read(target.database.path()).unwrap();
    assert!(!bytes.windows(12).any(|w| w == b"Grace Hopper"));
    assert!(!bytes.starts_with(b"SQLite format 3"));
    let active = authorization.activate(&prepared);
    let authenticator = native.authenticator(&active, prepared.binding_object_hash());
    let active_audit = h.audit(&active, 0);
    let login = native.login(
        &target.database,
        &authenticator,
        prepared.binding_object_hash(),
        h.certificate,
    );
    let verified = OperatorBindingService::new(&active, active_audit.service())
        .verify_session(login)
        .unwrap();
    assert_eq!(verified.profile().display_name(), "Grace Hopper");
}

#[test]
fn failed_durable_staging_cannot_leave_an_unrecoverable_profile_row() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("stage-fail");
    let native = Native::new();
    let mut auth = h.authorization();
    auth.fail_stage = true;
    assert!(
        h.provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth
        )
        .is_err()
    );
    assert!(
        OperatorProfileRepository::new(target.database.clone())
            .load()
            .unwrap()
            .is_none()
    );
}

#[test]
fn failed_revocation_staging_records_failed_outcome() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("revoke-stage");
    let native = Native::new();
    let mut auth = h.authorization();
    let prepared = h
        .provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
        )
        .unwrap();
    let active = auth.activate(&prepared);
    let audit = h.audit(&active, 0);
    auth.fail_stage = true;
    assert!(
        h.revoke(
            &active,
            audit.service(),
            prepared.binding_object_hash(),
            &mut auth
        )
        .is_err()
    );
    let booked = audit.booked();
    let last = ea_format::decode_local_audit_event(booked.last().unwrap()).unwrap();
    assert_eq!(last.outcome(), ea_format::LocalAuditOutcomeV1::Failed);
}

#[test]
fn loss_of_the_local_profile_cannot_skip_a_known_previous_binding() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("lost-profile");
    let native = Native::new();
    let mut auth = h.authorization();
    let mut identity = Identity::valid();
    identity.previous_binding = Some(h.binding);
    assert!(
        h.provision(
            &head,
            &audit,
            &target.database,
            &native,
            &identity,
            &mut auth
        )
        .is_err()
    );
    assert!(native.account.borrow().secret.is_none());
}

#[test]
fn encrypted_profile_constraint_failure_preserves_the_old_row_and_withholds_success() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("profile-write-fail");
    let native = Native::new();
    let mut auth = h.authorization();
    target.database.execute("CREATE TRIGGER fail_profile_write BEFORE INSERT ON operator_profile BEGIN SELECT RAISE(ABORT,'injected'); END",&[]).unwrap();
    assert!(
        h.provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth
        )
        .is_err()
    );
    assert!(
        OperatorProfileRepository::new(target.database.clone())
            .load()
            .unwrap()
            .is_none()
    );
    let booked = audit.booked();
    let last = ea_format::decode_local_audit_event(booked.last().unwrap()).unwrap();
    assert_eq!(last.outcome(), ea_format::LocalAuditOutcomeV1::Failed);
}

#[test]
fn provision_normalizes_decomposed_identity_before_committing_the_writer_snapshot() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("unicode");
    let native = Native::new();
    let mut auth = h.authorization();
    let mut identity = Identity::valid();
    identity.decomposed = true;
    let prepared = h
        .provision(
            &head,
            &audit,
            &target.database,
            &native,
            &identity,
            &mut auth,
        )
        .unwrap();
    let profile = OperatorProfileRepository::new(target.database.clone())
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(profile.display_name(), "Amélie");
    assert_eq!(profile.function_label(), "Führung\r\nStab");
    let snapshot = ea_schema::OperatorSnapshotV1::new(
        profile.organization_id(),
        profile.operator_subject_id(),
        "Ame\u{301}lie",
        "Fu\u{308}hrung\r\nStab",
        *profile.profile_commitment_salt(),
        prepared.binding_object_hash(),
    )
    .unwrap();
    assert_eq!(profile.display_name(), snapshot.display_name());
    assert_eq!(profile.function_label(), snapshot.function_label());
    let mut bytes = Vec::new();
    minicbor::Encoder::new(&mut bytes)
        .array(5)
        .unwrap()
        .bytes(snapshot.organization_id().as_bytes())
        .unwrap()
        .bytes(snapshot.operator_subject_id().as_bytes())
        .unwrap()
        .str(snapshot.display_name())
        .unwrap()
        .str(snapshot.function_label())
        .unwrap()
        .bytes(snapshot.salt())
        .unwrap();
    let active = auth.activate(&prepared);
    assert!(
        active
            .active_operator_binding_fields(prepared.binding_object_hash())
            .unwrap()
            .operator_profile_commitment
            == ea_crypto::operator_profile_digest(&bytes)
    );
}
