#[path = "support/operator_lifecycle.rs"]
mod lifecycle;
mod support;

use ea_admin::RevokedOperatorBinding;
use ea_admin::{
    OperatorLifecycleError, OperatorMutationPorts, ProvisionOperatorRequest, RevokeOperatorRequest,
    RootCeremonyService,
};
use ea_draft::OperatorProfileRepository;
use ea_format::{
    DecodedTrustPayloadV1, OperatorRoleV1, ParsedArchiveObject, RegistryChangeV1,
    decode_exact_object,
};
use ea_local_store::StoreValue;
use lifecycle::*;
use std::sync::{Arc, Mutex};

#[test]
fn lost_writer_key_is_revoked_and_replaced_at_next_entry_50_inside_lease_100() {
    let mut h = Harness::new();
    let admin = RecoveryAdmin::enroll(&mut h.line);
    let head = support::selected_head_at(&h.line, 3, 50);
    assert_eq!(head.proposed_sequence().get(), 50);
    assert_eq!(head.valid_through_sequence().get(), 100);
    let old = h.binding;
    let original = OperatorProfileRepository::new(h.database.clone())
        .load()
        .unwrap()
        .unwrap();
    h.account.secret = None;
    let lost_authenticator = h.authenticator(&head);
    assert_eq!(
        h.service(&head, h.audit(&head, 0).service())
            .verify_session(h.login(&lost_authenticator))
            .err()
            .unwrap()
            .code(),
        "EA-OPERATOR-INSTANCE-KEY-MISSING"
    );

    let mut authorization = h.authorization();
    let provider = support::FixtureKeyProvider::root();
    let table = Arc::new(Mutex::new(support::ReplayTable::default()));
    let mut store = support::PersistentStore::open(&table);
    let audit = admin.audit(&head);
    let ceremony = RootCeremonyService::new(
        &head,
        &provider,
        provider.handle(),
        ea_types::CertificateHash::from(head.root_certificate_object_hash()),
        audit.service(),
        admin.binding,
    );
    let admin_authenticator = admin.authenticator(&head);
    let revocation = admin
        .service(&head, audit.service())
        .revoke(
            RevokeOperatorRequest {
                database: &h.database,
                binding_object_hash: old,
                window: window(50, 100),
            },
            &mut OperatorMutationPorts {
                authorization: &mut authorization,
                ceremony: &ceremony,
                store: &mut store,
            },
            admin.login(&admin_authenticator),
        )
        .unwrap();
    let revoke_event = registry_fields(revocation.registry_bytes());
    assert_eq!(revoke_event.effective_from_sequence.get(), 50);
    assert!(
        matches!(revoke_event.change,RegistryChangeV1::Target{target_kind:1,object_hash} if object_hash==old)
    );
    let revoked = selected(&authorization.line, revocation.registry_bytes(), 50);
    let evidence =
        RevokedOperatorBinding::verify(&head, &revoked, revocation.registry_bytes(), old).unwrap();
    let booked = audit.booked();
    let row = ea_format::decode_local_audit_event(booked.last().unwrap()).unwrap();
    let ea_format::LocalAuditActionV1::Revocation(context) = row.action() else {
        panic!()
    };
    assert_eq!(context.effective_from_sequence().get(), 50);
    assert!(context.old_binding_object_hash() == Some(old));
    assert!(context.new_binding_object_hash().is_none());

    let native = Native::new();
    *native.account.borrow_mut() = h.account.clone();
    let audit = admin.audit(&revoked);
    let ceremony = RootCeremonyService::new(
        &revoked,
        &provider,
        provider.handle(),
        ea_types::CertificateHash::from(revoked.root_certificate_object_hash()),
        audit.service(),
        admin.binding,
    );
    let admin_authenticator = admin.authenticator(&revoked);
    let request = ProvisionOperatorRequest {
        database: &h.database,
        device_certificate_hash: h.certificate,
        role: OperatorRoleV1::Writer,
        window: window(50, 100),
        replacement: Some(&evidence),
    };
    let mut identity = Identity::valid();
    identity.fail = true;
    assert_eq!(
        admin
            .service(&revoked, audit.service())
            .provision(
                request,
                &native,
                &identity,
                &mut OperatorMutationPorts {
                    authorization: &mut authorization,
                    ceremony: &ceremony,
                    store: &mut store
                },
                admin.login(&admin_authenticator)
            )
            .err()
            .unwrap()
            .code(),
        "EA-OPERATOR-IDENTITY-VERIFICATION"
    );
    assert!(native.account.borrow().secret.is_none());
    let replacement = admin
        .service(&revoked, audit.service())
        .provision(
            ProvisionOperatorRequest {
                database: &h.database,
                device_certificate_hash: h.certificate,
                role: OperatorRoleV1::Writer,
                window: window(50, 100),
                replacement: Some(&evidence),
            },
            &native,
            &Identity::valid(),
            &mut OperatorMutationPorts {
                authorization: &mut authorization,
                ceremony: &ceremony,
                store: &mut store,
            },
            admin.login(&admin_authenticator),
        )
        .unwrap();
    admin
        .service(&revoked, audit.service())
        .authorize_prepared(
            &h.database,
            &replacement,
            &native,
            &mut OperatorMutationPorts {
                authorization: &mut authorization,
                ceremony: &ceremony,
                store: &mut store,
            },
            admin.login(&admin_authenticator),
        )
        .unwrap();
    let replacement = publish(
        admin.service(&revoked, audit.service()),
        &h.database,
        &replacement,
        &native,
        &mut authorization,
    )
    .unwrap();
    assert_eq!(
        registry_fields(replacement.activation_bytes())
            .effective_from_sequence
            .get(),
        50
    );
    let active = selected(&authorization.line, replacement.activation_bytes(), 50);
    assert_eq!(active.proposed_sequence().get(), 50);
    assert!(active.active_operator_binding_fields(old).is_none());
    let fields = active
        .active_operator_binding_fields(replacement.binding_object_hash())
        .unwrap();
    assert_eq!(fields.effective_from_sequence.get(), 50);
    assert!(
        fields.operator_instance_key_thumbprint
            != head
                .active_operator_binding_fields(old)
                .unwrap()
                .operator_instance_key_thumbprint
    );
    let booked = audit.booked();
    let row = ea_format::decode_local_audit_event(booked.last().unwrap()).unwrap();
    let ea_format::LocalAuditActionV1::BindingChange(context) = row.action() else {
        panic!()
    };
    assert_eq!(context.effective_from_sequence().get(), 50);
    assert!(context.old_binding_object_hash() == Some(old));
    assert!(context.new_binding_object_hash() == Some(replacement.binding_object_hash()));
    let authenticator = native.authenticator(&active, replacement.binding_object_hash());
    let audit = h.audit(&active, 0);
    let mut login = native.login(
        &h.database,
        &authenticator,
        replacement.binding_object_hash(),
        h.certificate,
    );
    login.purpose = ea_operator::ReauthPurpose::Finalize;
    let usable = h
        .service(&active, audit.service())
        .verify_session(login)
        .unwrap();
    assert!(usable.proof().binding_object_hash() == replacement.binding_object_hash());
    assert!(usable.profile().operator_binding_object_hash() == replacement.binding_object_hash());
    assert!(usable.profile().operator_subject_id() == original.operator_subject_id());
    assert_ne!(
        usable.profile().profile_commitment_salt(),
        original.profile_commitment_salt()
    );
    assert!(usable.proof().is_valid_for(
        ea_operator::ReauthPurpose::Finalize,
        active.preexisting_effective_now()
    ));
}

#[test]
fn lifecycle_windows_reject_past_proposals_reversed_windows_and_registry_gaps() {
    let h = Harness::new();
    let head = h.head();
    let provider = support::FixtureKeyProvider::root();
    for (effective, through, not_after) in [
        (49, 100, 10_000_000),
        (20, 100, 10_000_000),
        (50, 49, 10_000_000),
        (102, 200, 10_000_000),
        (50, 100, 1000),
    ] {
        let audit = h.audit(&head, 0);
        let ceremony = RootCeremonyService::new(
            &head,
            &provider,
            provider.handle(),
            ea_types::CertificateHash::from(head.root_certificate_object_hash()),
            audit.service(),
            h.binding,
        );
        let authenticator = h.authenticator(&head);
        let mut authorization = h.authorization();
        let table = Arc::new(Mutex::new(support::ReplayTable::default()));
        let mut store = support::PersistentStore::open(&table);
        let mut ports = OperatorMutationPorts {
            authorization: &mut authorization,
            ceremony: &ceremony,
            store: &mut store,
        };
        let mut requested = window(effective, through);
        requested.not_after = ea_types::UnixMillis::new(not_after);
        let service = h.service(&head, audit.service());
        assert_eq!(
            service
                .revoke(
                    RevokeOperatorRequest {
                        database: &h.database,
                        binding_object_hash: h.binding,
                        window: requested
                    },
                    &mut ports,
                    h.login(&authenticator)
                )
                .err()
                .unwrap()
                .code(),
            "EA-OPERATOR-REGISTRY-WINDOW"
        );
        let target = database("invalid-window");
        let native = Native::new();
        assert_eq!(
            service
                .provision(
                    ProvisionOperatorRequest {
                        database: &target.database,
                        device_certificate_hash: h.certificate,
                        role: OperatorRoleV1::Writer,
                        window: requested,
                        replacement: None
                    },
                    &native,
                    &Identity::valid(),
                    &mut ports,
                    h.login(&authenticator)
                )
                .err()
                .unwrap()
                .code(),
            "EA-OPERATOR-REGISTRY-WINDOW"
        );
        assert!(native.account.borrow().secret.is_none());
        assert!(
            OperatorProfileRepository::new(target.database.clone())
                .load()
                .unwrap()
                .is_none()
        );
        assert!(authorization.authorizations.is_empty());
        assert!(authorization.staged.is_empty());
    }
}

#[test]
fn deliberate_future_revocation_is_preserved_inside_the_lease_and_at_its_next_boundary() {
    let h = Harness::new();
    let head = h.head();
    let provider = support::FixtureKeyProvider::root();
    for effective in [75, 101] {
        // Independent future-window examples need independent durable intents.
        let target = database("future-revocation-window");
        let audit = h.audit(&head, 0);
        let authenticator = h.authenticator(&head);
        let mut authorization = h.authorization();
        let ceremony = RootCeremonyService::new(
            &head,
            &provider,
            provider.handle(),
            ea_types::CertificateHash::from(head.root_certificate_object_hash()),
            audit.service(),
            h.binding,
        );
        let table = Arc::new(Mutex::new(support::ReplayTable::default()));
        let mut store = support::PersistentStore::open(&table);
        let prepared = h
            .service(&head, audit.service())
            .revoke(
                RevokeOperatorRequest {
                    database: &target.database,
                    binding_object_hash: h.binding,
                    window: window(effective, 150),
                },
                &mut OperatorMutationPorts {
                    authorization: &mut authorization,
                    ceremony: &ceremony,
                    store: &mut store,
                },
                h.login(&authenticator),
            )
            .unwrap();
        assert_eq!(
            registry_fields(prepared.registry_bytes())
                .effective_from_sequence
                .get(),
            effective
        );
        let before = support::selected_head_at(&h.line, 2, effective - 1);
        assert!(before.active_operator_binding_fields(h.binding).is_some());
        let after = selected(&authorization.line, prepared.registry_bytes(), effective);
        assert!(after.active_operator_binding_fields(h.binding).is_none());
        assert!(
            RevokedOperatorBinding::verify(&head, &after, prepared.registry_bytes(), h.binding)
                .is_ok()
        );
    }
}

#[test]
fn replacement_survives_an_intervening_authenticated_head() {
    for reconstruct_evidence in [false, true] {
        let mut fixture = RevokedEnrollment::new();
        let later = fixture.advance();
        assert_eq!(
            later.registry_version().get(),
            fixture.revoked.registry_version().get() + 1
        );
        assert!(later.registry_head_hash() != fixture.revoked.registry_head_hash());
        let original = OperatorProfileRepository::new(fixture.target.database.clone())
            .load()
            .unwrap()
            .unwrap();
        fixture.native.account.borrow_mut().secret = None;
        let reconstructed = reconstruct_evidence
            .then(|| RevokedOperatorBinding::resolve(&later, fixture.binding).unwrap());
        let evidence = reconstructed.as_ref().unwrap_or(&fixture.evidence);
        let prepared = fixture
            .harness
            .provision_at(
                &later,
                fixture.harness.audit(&later, 0).service(),
                &fixture.target.database,
                &fixture.native,
                &Identity::valid(),
                &mut fixture.authorization,
                Some(evidence),
            )
            .unwrap();
        let active = fixture.authorization.activate(&prepared);
        assert!(
            active
                .active_operator_binding_fields(fixture.binding)
                .is_none()
        );
        let authenticator = fixture
            .native
            .authenticator(&active, prepared.binding_object_hash());
        let audit = fixture.harness.audit(&active, 0);
        let verified = fixture
            .harness
            .service(&active, audit.service())
            .verify_session(fixture.native.login(
                &fixture.target.database,
                &authenticator,
                prepared.binding_object_hash(),
                fixture.harness.certificate,
            ))
            .unwrap();
        assert!(verified.profile().operator_subject_id() == original.operator_subject_id());
        assert_ne!(
            verified.profile().profile_commitment_salt(),
            original.profile_commitment_salt()
        );
    }
}

#[test]
fn replacement_evidence_rejects_stale_absent_pending_and_unrelated_chain_heads() {
    let mut fixture = RevokedEnrollment::new();
    let initial = fixture.harness.head();
    let pending = selected(
        &fixture.authorization.line,
        fixture
            .harness
            .line
            .exact_object_bytes(initial.registry_head_hash()),
        50,
    );
    let other_chain = selected_on_chain(
        &fixture.authorization.line,
        fixture.revocation.registry_bytes(),
        201,
        ea_types::ChainId::try_from(&[0x99; 16][..]).unwrap(),
    );
    assert!(other_chain.chain_id() != fixture.revoked.chain_id());
    assert!(other_chain.registry_head_hash() == fixture.revoked.registry_head_hash());
    assert!(
        other_chain
            .revoked_operator_binding_fields(fixture.binding)
            .is_some()
    );
    assert!(
        RevokedOperatorBinding::verify(
            &fixture.active,
            &other_chain,
            fixture.revocation.registry_bytes(),
            fixture.binding
        )
        .is_err()
    );
    for head in [&initial, &pending, &fixture.active] {
        assert_eq!(
            RevokedOperatorBinding::resolve(head, fixture.binding)
                .err()
                .unwrap()
                .code(),
            "EA-OPERATOR-REPLACEMENT-REQUIRES-REVOCATION"
        );
    }
    assert!(
        RevokedOperatorBinding::resolve(
            &fixture.revoked,
            ea_types::ObjectHash::from(ea_types::Hash32::ZERO)
        )
        .is_err()
    );
    let counts = (
        fixture.authorization.authorizations.len(),
        fixture.authorization.staged.len(),
    );
    let secret = fixture.native.account.borrow().secret;
    for head in [&initial, &pending, &fixture.active, &other_chain] {
        assert_eq!(
            fixture
                .harness
                .provision_at(
                    head,
                    fixture.harness.audit(head, 0).service(),
                    &fixture.target.database,
                    &fixture.native,
                    &Identity::valid(),
                    &mut fixture.authorization,
                    Some(&fixture.evidence)
                )
                .err()
                .unwrap()
                .code(),
            "EA-OPERATOR-REPLACEMENT-REQUIRES-REVOCATION"
        );
        assert!(
            OperatorProfileRepository::new(fixture.target.database.clone())
                .load()
                .unwrap()
                .unwrap()
                .operator_binding_object_hash()
                == fixture.binding
        );
        assert_eq!(fixture.native.account.borrow().secret, secret);
        assert_eq!(
            (
                fixture.authorization.authorizations.len(),
                fixture.authorization.staged.len()
            ),
            counts
        );
    }
}

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
            h.service(&head, audit.service())
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
            .is_some()
    );
}

#[test]
fn lifecycle_audit_failure_withholds_provisioned_bytes_and_encrypted_profile() {
    let h = Harness::new();
    let head = h.head();
    let target = database("audit-fail");
    let native = Native::new();
    let mut auth = h.authorization();
    h.database.execute("CREATE TRIGGER fail_lifecycle_audit BEFORE INSERT ON local_audit_event WHEN (SELECT count(*) FROM local_audit_event)>=2 BEGIN SELECT RAISE(ABORT,'injected'); END",&[]).unwrap();
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
    assert!(auth.staged.is_empty());
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
        h.service(&selected, audit.service())
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
        h.service(&selected, audit.service())
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
        h.service(&active, audit.service())
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
    let service = h.service(&head, audit.service());
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
    let service = h.service(&head, audit.service());
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
    let verified = h
        .service(&active, active_audit.service())
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
            .is_some()
    );
    let prepared = h
        .service(&head, audit.service())
        .resume_prepared(&target.database)
        .unwrap()
        .unwrap();
    assert_eq!(
        prepared.state(),
        ea_admin::PreparedBindingState::PublicationUncertain
    );
    auth.fail_stage = false;
    publish(
        h.service(&head, audit.service()),
        &target.database,
        &prepared,
        &native,
        &mut auth,
    )
    .unwrap();
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
