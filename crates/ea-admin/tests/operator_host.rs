#[path = "support/operator_lifecycle.rs"]
mod lifecycle;
mod support;

use ea_admin::{OperatorMutationPorts, PreparedBindingState, RootCeremonyService};
use ea_draft::OperatorProfileRepository;
use lifecycle::*;

fn authorize(
    h: &Harness,
    head: &ea_trust::SelectedRegistryHead,
    audit: &support::AuditHarness,
    database: &std::sync::Arc<ea_local_store::EncryptedDatabase>,
    native: &Native,
    authorization: &mut Authorization,
    prepared: &ea_admin::PreparedOperatorBinding,
) -> Result<ea_admin::PreparedOperatorBinding, ea_admin::OperatorLifecycleError> {
    let provider = support::FixtureKeyProvider::root();
    let ceremony = RootCeremonyService::new(
        head,
        &provider,
        provider.handle(),
        ea_types::CertificateHash::from(head.root_certificate_object_hash()),
        audit.service(),
        h.binding,
    );
    let table = authorization.replay_table.clone();
    let mut store = support::PersistentStore::open(&table);
    h.service(head, audit.service()).authorize_prepared(
        database,
        prepared,
        native,
        &mut OperatorMutationPorts {
            authorization,
            ceremony: &ceremony,
            store: &mut store,
        },
        h.login(&h.authenticator(head)),
    )
}

#[test]
fn binding_only_commit_resumes_after_reopen_before_activation_is_authorized() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("host-restart");
    let native = Native::new();
    let mut authorization = h.authorization();
    let prepared = h
        .prepare_at(
            &head,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut authorization,
            None,
        )
        .unwrap();
    assert_eq!(prepared.state(), PreparedBindingState::BindingPrepared);
    assert_eq!(authorization.authorizations.len(), 1);
    assert!(authorization.staged.is_empty());
    let hash = prepared.binding_object_hash();
    let original_key = native.account.borrow().secret;
    drop(target.database);
    let database = reopen_database(target.directory.path());
    let resumed = h
        .service(&head, audit.service())
        .resume_prepared(&database)
        .unwrap()
        .unwrap();
    assert!(resumed.binding_object_hash() == hash);
    let ready = authorize(
        &h,
        &head,
        &audit,
        &database,
        &native,
        &mut authorization,
        &resumed,
    )
    .unwrap();
    assert_eq!(ready.state(), PreparedBindingState::Ready);
    assert_eq!(authorization.authorizations.len(), 2);
    assert!(authorization.staged.is_empty());
    assert_eq!(native.account.borrow().secret, original_key);
    let published = publish(
        h.service(&head, audit.service()),
        &database,
        &ready,
        &native,
        &mut authorization,
    )
    .unwrap();
    let active = authorization.activate(&published);
    let login = native.authenticator(&active, hash);
    let audit = h.audit(&active, 0);
    let verified = h
        .service(&active, audit.service())
        .complete_prepared(&ready, native.login(&database, &login, hash, h.certificate))
        .unwrap();
    assert!(verified.profile().operator_binding_object_hash() == hash);
    assert_eq!(
        h.service(&active, audit.service())
            .resume_prepared(&database)
            .unwrap()
            .unwrap()
            .state(),
        PreparedBindingState::Active
    );
}

#[test]
fn later_binding_authorization_keeps_verified_time_through_restart_and_activation() {
    use ea_types::UnixMillis;
    for activation_now in [1000_i64, 1060] {
        let expected_activation = activation_now.max(1050);
        let h = Harness::new();
        let head = h.head();
        let target = database("later-binding-authorization");
        let native = Native::new();
        let mut authorization = h.authorization();
        authorization.binding_authorization_timing =
            Some((UnixMillis::new(1020), UnixMillis::new(1050)));
        let prepared = h
            .prepare_at(
                &head,
                h.audit(&head, 0).service(),
                &target.database,
                &native,
                &Identity::valid(),
                &mut authorization,
                None,
            )
            .unwrap();
        let row = target
            .database
            .query_row(
                "SELECT prepared_at,binding_authorization FROM operator_binding_journal",
                &[],
            )
            .unwrap()
            .unwrap();
        assert_eq!(row.integer(0).unwrap(), 1050);
        assert_eq!(row.blob(1).unwrap(), authorization.authorizations[0]);
        assert_eq!(
            head.preexisting_effective_now().value(),
            UnixMillis::new(1000)
        );
        let instance = native.account.borrow().secret;
        drop(target.database);
        let database = reopen_database(target.directory.path());
        let later = selected_at(
            &authorization.line,
            authorization
                .line
                .exact_object_bytes(head.registry_head_hash()),
            head.proposed_sequence().get(),
            UnixMillis::new(activation_now),
        );
        let audit = h.audit(&later, 0);
        let resumed = h
            .service(&later, audit.service())
            .resume_prepared(&database)
            .unwrap()
            .unwrap();
        authorization.lose_activation_reply = true;
        assert!(
            authorize(
                &h,
                &later,
                &audit,
                &database,
                &native,
                &mut authorization,
                &resumed
            )
            .is_err()
        );
        assert_eq!(authorization.authorizations.len(), 2);
        let row = database
            .query_row(
                "SELECT prepared_at,activation_issued_at FROM operator_binding_journal",
                &[],
            )
            .unwrap()
            .unwrap();
        assert_eq!(row.integer(0).unwrap(), 1050);
        assert_eq!(row.integer(1).unwrap(), expected_activation);
        drop(database);
        let database = reopen_database(target.directory.path());
        let later = selected_at(
            &authorization.line,
            authorization
                .line
                .exact_object_bytes(head.registry_head_hash()),
            head.proposed_sequence().get(),
            UnixMillis::new(1070),
        );
        let audit = h.audit(&later, 0);
        let ready = authorize(
            &h,
            &later,
            &audit,
            &database,
            &native,
            &mut authorization,
            &prepared,
        )
        .unwrap();
        assert_eq!(ready.state(), PreparedBindingState::Ready);
        assert_eq!(authorization.authorizations.len(), 2);
        assert_eq!(native.account.borrow().secret, instance);
        let row = database
            .query_row(
                "SELECT activation_issued_at FROM operator_binding_journal",
                &[],
            )
            .unwrap()
            .unwrap();
        assert_eq!(row.integer(0).unwrap(), expected_activation);
        let published = publish(
            h.service(&later, audit.service()),
            &database,
            &ready,
            &native,
            &mut authorization,
        )
        .unwrap();
        let active = authorization.activate(&published);
        assert_eq!(active.issued_at(), UnixMillis::new(expected_activation));
        let login = native.authenticator(&active, prepared.binding_object_hash());
        h.service(&active, h.audit(&active, 0).service())
            .complete_prepared(
                &ready,
                native.login(
                    &database,
                    &login,
                    prepared.binding_object_hash(),
                    h.certificate,
                ),
            )
            .unwrap();
    }
}

#[test]
fn verified_preparation_time_does_not_allow_a_new_activation_after_binding_auth_expiry() {
    use ea_types::UnixMillis;
    let h = Harness::new();
    let head = h.head();
    let target = database("expired-binding-authorization");
    let native = Native::new();
    let mut authorization = h.authorization();
    authorization.binding_authorization_timing =
        Some((UnixMillis::new(1020), UnixMillis::new(1050)));
    let prepared = h
        .prepare_at(
            &head,
            h.audit(&head, 0).service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut authorization,
            None,
        )
        .unwrap();
    let later = selected_at(
        &authorization.line,
        authorization
            .line
            .exact_object_bytes(head.registry_head_hash()),
        head.proposed_sequence().get(),
        UnixMillis::new(1200),
    );
    let audit = h.audit(&later, 0);
    let error = authorize(
        &h,
        &later,
        &audit,
        &target.database,
        &native,
        &mut authorization,
        &prepared,
    )
    .err()
    .unwrap();
    assert_eq!(error.code(), "EA-OPERATOR-NOT-READY");
    assert_eq!(authorization.authorizations.len(), 1);
    assert!(authorization.staged.is_empty());
    assert_eq!(
        h.service(&later, audit.service())
            .resume_prepared(&target.database)
            .unwrap()
            .unwrap()
            .state(),
        PreparedBindingState::BindingPrepared
    );
}

#[test]
fn lost_native_key_after_profile_commit_prevents_activation_authorization() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("host-lost-key");
    let native = Native::new();
    let mut authorization = h.authorization();
    let prepared = h
        .prepare_at(
            &head,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut authorization,
            None,
        )
        .unwrap();
    native.account.borrow_mut().secret = None;
    let error = authorize(
        &h,
        &head,
        &audit,
        &target.database,
        &native,
        &mut authorization,
        &prepared,
    )
    .err()
    .unwrap();
    assert_eq!(error.code(), "EA-OPERATOR-INSTANCE-KEY-MISSING");
    assert_eq!(authorization.authorizations.len(), 1);
    assert!(authorization.staged.is_empty());
}

#[test]
fn profile_commit_failure_never_releases_viable_activation_objects() {
    let h = Harness::new();
    let head = h.head();
    let target = database("host-profile-failure");
    target.database.execute("CREATE TRIGGER fail_profile BEFORE INSERT ON operator_profile BEGIN SELECT RAISE(ABORT,'injected'); END", &[]).unwrap();
    let mut authorization = h.authorization();
    let result = h.provision(
        &head,
        &h.audit(&head, 0),
        &target.database,
        &Native::new(),
        &Identity::valid(),
        &mut authorization,
    );
    assert!(result.is_err());
    assert!(
        OperatorProfileRepository::new(target.database.clone())
            .load()
            .unwrap()
            .is_none()
    );
    assert!(
        authorization.staged.is_empty(),
        "activation bytes escaped before the profile committed"
    );
    assert_eq!(authorization.authorizations.len(), 1);
    assert!(authorization.included.is_empty());
}

#[test]
fn unknown_requested_certificate_still_records_signed_failed_login() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let authenticator = h.authenticator(&head);
    let mut request = h.login(&authenticator);
    request.device_certificate_hash = ea_types::CertificateHash::try_from(&[0xee; 32][..]).unwrap();
    request.binding_object_hash = ea_types::ObjectHash::try_from(&[0xef; 32][..]).unwrap();
    assert!(
        h.service(&head, audit.service())
            .verify_session(request)
            .is_err()
    );
    let rows = audit.booked();
    assert_eq!(
        rows.len(),
        2,
        "unknown request must not suppress device audit"
    );
    for bytes in rows {
        let row = ea_format::decode_local_audit_event(&bytes).unwrap();
        assert!(
            row.signer_certificate_object_hash()
                == ea_types::ObjectHash::try_from(h.certificate.as_bytes().as_slice()).unwrap()
        );
        assert!(row.operator_binding_object_hash().is_none());
    }
}

#[test]
fn journal_insert_failure_rolls_back_profile_and_never_requests_activation() {
    let h = Harness::new();
    let head = h.head();
    let target = database("journal-atomic");
    target.database.execute("CREATE TRIGGER fail_journal BEFORE INSERT ON operator_binding_journal BEGIN SELECT RAISE(ABORT,'injected'); END", &[]).unwrap();
    let mut auth = h.authorization();
    let audit = h.audit(&head, 0);
    assert!(
        h.prepare_at(
            &head,
            audit.service(),
            &target.database,
            &Native::new(),
            &Identity::valid(),
            &mut auth,
            None
        )
        .is_err()
    );
    assert_eq!(auth.authorizations.len(), 1);
    assert!(auth.included.is_empty());
    assert!(auth.staged.is_empty());
    assert!(
        OperatorProfileRepository::new(target.database.clone())
            .load()
            .unwrap()
            .is_none()
    );
    assert!(
        h.service(&head, audit.service())
            .resume_prepared(&target.database)
            .unwrap()
            .is_none()
    );
}

#[test]
fn readiness_rechecks_profile_account_instance_and_exact_signed_objects() {
    for case in 0..5 {
        let h = Harness::new();
        let head = h.head();
        let target = database("readiness-negative");
        let audit = h.audit(&head, 0);
        let native = Native::new();
        let mut auth = h.authorization();
        let prepared = h
            .prepare_at(
                &head,
                audit.service(),
                &target.database,
                &native,
                &Identity::valid(),
                &mut auth,
                None,
            )
            .unwrap();
        match case {
            0 => {
                target
                    .database
                    .execute("UPDATE operator_profile SET display_name='altered'", &[])
                    .unwrap();
            }
            1 => native.account.borrow_mut().hash = ea_types::Hash32::ZERO,
            2 => native.account.borrow_mut().secret = Some([0xf1; 32]),
            3 => {
                target
                    .database
                    .execute("UPDATE operator_binding_journal SET binding=X'80'", &[])
                    .unwrap();
            }
            4 => {
                target
                    .database
                    .execute(
                        "UPDATE operator_binding_journal SET binding_authorization=X'80'",
                        &[],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let result = authorize(
            &h,
            &head,
            &audit,
            &target.database,
            &native,
            &mut auth,
            &prepared,
        );
        assert!(result.is_err(), "case {case}");
        assert_eq!(
            auth.authorizations.len(),
            1,
            "case {case} authorized activation despite failed readiness"
        );
        assert!(auth.included.is_empty());
        assert!(auth.staged.is_empty());
    }
}

#[test]
fn activation_request_is_durable_before_root_signing_and_recovers_exact_response() {
    let h = Harness::new();
    let head = h.head();
    let target = database("activation-uncertain");
    let audit = h.audit(&head, 0);
    let native = Native::new();
    let mut auth = h.authorization();
    let prepared = h
        .prepare_at(
            &head,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            None,
        )
        .unwrap();
    authorize(
        &h,
        &head,
        &audit,
        &target.database,
        &native,
        &mut auth,
        &prepared,
    )
    .unwrap();
    let row = target
        .database
        .query_row(
            "SELECT activation,activation_authorization FROM operator_binding_journal",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(auth.replay_table.lock().unwrap().len(), 2);
    // Model the authority's retained response after target-side interruption.
    let response = row.blob(0).unwrap().to_vec();
    let exact_auth = row.blob(1).unwrap().to_vec();
    target
        .database
        .execute(
            "UPDATE operator_binding_journal SET activation=NULL,state=1",
            &[],
        )
        .unwrap();
    drop(target.database);
    let database = reopen_database(target.directory.path());
    let prepared = h
        .service(&head, audit.service())
        .resume_prepared(&database)
        .unwrap()
        .unwrap();
    assert_eq!(prepared.state(), PreparedBindingState::ActivationRequested);
    assert!(authorize(&h, &head, &audit, &database, &native, &mut auth, &prepared).is_err());
    assert_eq!(auth.authorizations.len(), 2);
    let mut forged = response.clone();
    *forged.last_mut().unwrap() ^= 1;
    auth.recovered = Some(forged);
    assert!(authorize(&h, &head, &audit, &database, &native, &mut auth, &prepared).is_err());
    auth.recovered = Some(response.clone());
    let ready = authorize(&h, &head, &audit, &database, &native, &mut auth, &prepared).unwrap();
    assert_eq!(ready.state(), PreparedBindingState::Ready);
    assert_eq!(auth.authorizations.len(), 2);
    let row = database
        .query_row(
            "SELECT activation,activation_authorization FROM operator_binding_journal",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(row.blob(0).unwrap(), response);
    assert_eq!(row.blob(1).unwrap(), exact_auth);
    assert!(auth.staged.is_empty());
}

#[derive(Default)]
struct Publisher {
    calls: usize,
    bytes: Vec<Vec<u8>>,
    fail: bool,
}
impl ea_admin::OperatorBindingPublisher for Publisher {
    fn publish(
        &mut self,
        ready: &ea_admin::ReadyOperatorBinding,
    ) -> Result<(), ea_admin::OperatorLifecycleError> {
        self.calls += 1;
        self.bytes = [
            ready.binding_authorization_bytes(),
            ready.binding_bytes(),
            ready.activation_authorization_bytes(),
            ready.activation_bytes(),
        ]
        .iter()
        .map(|b| b.to_vec())
        .collect();
        if self.fail {
            Err(ea_admin::OperatorLifecycleError::Unsupported)
        } else {
            Ok(())
        }
    }
}

#[test]
fn publication_failure_retries_exact_bytes_and_withholds_on_missing_key_or_audit_failure() {
    let h = Harness::new();
    let head = h.head();
    let target = database("publication-uncertain");
    let audit = h.audit(&head, 0);
    let native = Native::new();
    let mut auth = h.authorization();
    let service = h.service(&head, audit.service());
    let prepared = h
        .prepare_at(
            &head,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            None,
        )
        .unwrap();
    let mut publisher = Publisher::default();
    assert!(
        service
            .publish_prepared(&target.database, &prepared, &native, &mut publisher)
            .is_err()
    );
    assert_eq!(publisher.calls, 0);
    authorize(
        &h,
        &head,
        &audit,
        &target.database,
        &native,
        &mut auth,
        &prepared,
    )
    .unwrap();
    target.database.execute("CREATE TRIGGER fail_publication_state BEFORE UPDATE ON operator_binding_journal WHEN NEW.state=3 BEGIN SELECT RAISE(ABORT,'injected'); END", &[]).unwrap();
    assert!(
        service
            .publish_prepared(&target.database, &prepared, &native, &mut publisher)
            .is_err()
    );
    assert_eq!(publisher.calls, 0);
    target
        .database
        .execute("DROP TRIGGER fail_publication_state", &[])
        .unwrap();
    publisher.fail = true;
    assert!(
        service
            .publish_prepared(&target.database, &prepared, &native, &mut publisher)
            .is_err()
    );
    let original = publisher.bytes.clone();
    assert_eq!(
        service
            .resume_prepared(&target.database)
            .unwrap()
            .unwrap()
            .state(),
        PreparedBindingState::PublicationUncertain
    );
    let key = native.account.borrow_mut().secret.take();
    assert!(
        service
            .publish_prepared(&target.database, &prepared, &native, &mut publisher)
            .is_err()
    );
    assert_eq!(publisher.calls, 1);
    native.account.borrow_mut().secret = key;
    let failing_audit = h.audit(&head, 1);
    assert_eq!(
        h.service(&head, failing_audit.service())
            .publish_prepared(&target.database, &prepared, &native, &mut publisher)
            .err()
            .unwrap()
            .code(),
        "EA-OPERATOR-AUDIT-FAILED"
    );
    assert_eq!(publisher.calls, 1);
    publisher.fail = false;
    service
        .publish_prepared(&target.database, &prepared, &native, &mut publisher)
        .unwrap();
    assert_eq!(publisher.calls, 2);
    assert_eq!(publisher.bytes, original);
    assert_eq!(
        service
            .resume_prepared(&target.database)
            .unwrap()
            .unwrap()
            .state(),
        PreparedBindingState::Published
    );
}

#[test]
fn unactivated_binding_can_be_abandoned_only_after_fresh_external_identification() {
    let h = Harness::new();
    let head = h.head();
    let target = database("abandon");
    let audit = h.audit(&head, 0);
    let native = Native::new();
    let mut auth = h.authorization();
    let service = h.service(&head, audit.service());
    let prepared = h
        .prepare_at(
            &head,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            None,
        )
        .unwrap();
    let first_key = native.account.borrow().secret;
    assert!(
        h.prepare_at(
            &head,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            None
        )
        .is_err()
    );
    let mut identity = Identity::valid();
    identity.wrong_subject = true;
    assert!(
        service
            .abandon_prepared(&target.database, &prepared, &identity)
            .is_err()
    );
    assert!(
        OperatorProfileRepository::new(target.database.clone())
            .load()
            .unwrap()
            .is_some()
    );
    service
        .abandon_prepared(&target.database, &prepared, &Identity::valid())
        .unwrap();
    assert!(
        OperatorProfileRepository::new(target.database.clone())
            .load()
            .unwrap()
            .is_none()
    );
    assert!(service.resume_prepared(&target.database).unwrap().is_none());
    let replacement = h
        .prepare_at(
            &head,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            None,
        )
        .unwrap();
    assert_ne!(native.account.borrow().secret, first_key);
    assert!(replacement.binding_object_hash() != prepared.binding_object_hash());
    authorize(
        &h,
        &head,
        &audit,
        &target.database,
        &native,
        &mut auth,
        &replacement,
    )
    .unwrap();
    assert!(
        service
            .abandon_prepared(&target.database, &replacement, &Identity::valid())
            .is_err()
    );
}

#[test]
fn profile_uses_external_attestation_salt_and_replacement_rejects_reusing_it() {
    let fixture = RevokedEnrollment::new();
    let h = &fixture.harness;
    let audit = h.audit(&fixture.revoked, 0);
    let old = OperatorProfileRepository::new(fixture.target.database.clone())
        .load()
        .unwrap()
        .unwrap();
    let mut identity = Identity::valid();
    identity.salt = Some(*old.profile_commitment_salt());
    let before = fixture.native.account.borrow().secret;
    let mut authorization = fixture.authorization;
    assert_eq!(
        h.prepare_at(
            &fixture.revoked,
            audit.service(),
            &fixture.target.database,
            &fixture.native,
            &identity,
            &mut authorization,
            Some(&fixture.evidence)
        )
        .err()
        .unwrap()
        .code(),
        "EA-OPERATOR-PROFILE-COMMITMENT"
    );
    assert_eq!(fixture.native.account.borrow().secret, before);
    identity.salt = Some([0xe9; 32]);
    h.prepare_at(
        &fixture.revoked,
        audit.service(),
        &fixture.target.database,
        &fixture.native,
        &identity,
        &mut authorization,
        Some(&fixture.evidence),
    )
    .unwrap();
    let profile = OperatorProfileRepository::new(fixture.target.database.clone())
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(profile.profile_commitment_salt(), &[0xe9; 32]);
    assert!(profile.operator_subject_id() == old.operator_subject_id());
}

#[test]
fn pending_replacement_abandonment_after_later_head_retains_the_revoked_predecessor() {
    let mut fixture = RevokedEnrollment::new();
    let h = &fixture.harness;
    let audit = h.audit(&fixture.revoked, 0);
    let prepared = h
        .prepare_at(
            &fixture.revoked,
            audit.service(),
            &fixture.target.database,
            &fixture.native,
            &Identity::valid(),
            &mut fixture.authorization,
            Some(&fixture.evidence),
        )
        .unwrap();
    let later = fixture.advance();
    let h = &fixture.harness;
    let audit = h.audit(&later, 0);
    let service = h.service(&later, audit.service());
    service
        .abandon_prepared(&fixture.target.database, &prepared, &Identity::valid())
        .unwrap();
    assert_eq!(
        h.prepare_at(
            &later,
            audit.service(),
            &fixture.target.database,
            &fixture.native,
            &Identity::valid(),
            &mut fixture.authorization,
            None
        )
        .err()
        .unwrap()
        .code(),
        "EA-OPERATOR-REPLACEMENT-REQUIRES-REVOCATION"
    );
    let fresh = h
        .prepare_at(
            &later,
            audit.service(),
            &fixture.target.database,
            &fixture.native,
            &Identity::valid(),
            &mut fixture.authorization,
            Some(&fixture.evidence),
        )
        .unwrap();
    assert!(fresh.previous_binding_object_hash() == Some(fixture.binding));
}

#[test]
fn failed_root_signing_keeps_exact_activation_request_and_withholds_publication() {
    let h = Harness::new();
    let head = h.head();
    let target = database("failed-root");
    let audit = h.audit(&head, 0);
    let native = Native::new();
    let mut auth = h.authorization();
    let prepared = h
        .prepare_at(
            &head,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            None,
        )
        .unwrap();
    let provider = support::FixtureKeyProvider::foreign();
    let ceremony = RootCeremonyService::new(
        &head,
        &provider,
        provider.handle(),
        ea_types::CertificateHash::from(head.root_certificate_object_hash()),
        audit.service(),
        h.binding,
    );
    let table = std::sync::Arc::new(std::sync::Mutex::new(support::ReplayTable::default()));
    let mut store = support::PersistentStore::open(&table);
    assert!(
        h.service(&head, audit.service())
            .authorize_prepared(
                &target.database,
                &prepared,
                &native,
                &mut OperatorMutationPorts {
                    authorization: &mut auth,
                    ceremony: &ceremony,
                    store: &mut store
                },
                h.login(&h.authenticator(&head))
            )
            .is_err()
    );
    assert_eq!(provider.signatures_produced(), 1);
    assert!(table.lock().unwrap().is_empty());
    assert_eq!(auth.authorizations.len(), 2);
    let row = target
        .database
        .query_row(
            "SELECT activation_authorization,activation,state FROM operator_binding_journal",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(row.blob(0).unwrap(), &auth.authorizations[1]);
    assert_eq!(row.integer(2).unwrap(), 1);
    assert!(row.blob(1).is_err());
    assert!(auth.staged.is_empty());
    assert!(
        h.service(&head, audit.service())
            .abandon_prepared(&target.database, &prepared, &Identity::valid())
            .is_err()
    );
}

#[test]
fn unknown_request_needs_no_pre_resolved_binding_and_failed_audit_withholds_result() {
    struct Presence(std::cell::Cell<usize>);
    impl ea_admin::OperatorPresence for Presence {
        fn prove_presence_and_sign(
            &self,
            _: &[u8],
        ) -> Result<[u8; 64], ea_operator::OperatorError> {
            self.0.set(self.0.get() + 1);
            Err(ea_operator::OperatorError::PresenceProofInvalid)
        }
    }
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 1);
    let presence = Presence(std::cell::Cell::new(0));
    let request = ea_admin::VerifySessionRequest {
        database: &h.database,
        binding_object_hash: ea_types::ObjectHash::from(ea_types::Hash32::ZERO),
        device_certificate_hash: ea_types::CertificateHash::from(ea_types::ObjectHash::from(
            ea_types::Hash32::ZERO,
        )),
        role: ea_format::OperatorRoleV1::Writer,
        purpose: ea_operator::ReauthPurpose::Finalize,
        account: std::sync::Arc::new(h.account.clone()),
        authenticator: &presence,
    };
    assert_eq!(
        h.service(&head, audit.service())
            .verify_session(request)
            .err()
            .unwrap()
            .code(),
        "EA-OPERATOR-AUDIT-FAILED"
    );
    assert_eq!(presence.0.get(), 0);
    assert!(audit.booked().is_empty());
}

#[test]
fn completion_before_verified_activation_is_audited_and_releases_no_profile() {
    let h = Harness::new();
    let head = h.head();
    let target = database("complete-pending");
    let audit = h.audit(&head, 0);
    let native = Native::new();
    let mut auth = h.authorization();
    let prepared = h
        .prepare_at(
            &head,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            None,
        )
        .unwrap();
    let authenticator = h.authenticator(&head);
    let mut request = h.login(&authenticator);
    request.database = &target.database;
    request.binding_object_hash = prepared.binding_object_hash();
    let before = audit.booked().len();
    assert!(
        h.service(&head, audit.service())
            .complete_prepared(&prepared, request)
            .is_err()
    );
    assert_eq!(audit.booked().len(), before + 2);
    assert!(auth.staged.is_empty());
}

#[test]
fn lost_remote_authorization_reply_is_journaled_and_never_reauthorized_with_a_new_nonce() {
    let h = Harness::new();
    let head = h.head();
    let target = database("remote-auth-loss");
    let audit = h.audit(&head, 0);
    let native = Native::new();
    let mut auth = h.authorization();
    let prepared = h
        .prepare_at(
            &head,
            audit.service(),
            &target.database,
            &native,
            &Identity::valid(),
            &mut auth,
            None,
        )
        .unwrap();
    auth.lose_activation_reply = true;
    assert!(
        authorize(
            &h,
            &head,
            &audit,
            &target.database,
            &native,
            &mut auth,
            &prepared
        )
        .is_err()
    );
    assert_eq!(auth.authorizations.len(), 2);
    let service = h.service(&head, audit.service());
    assert_eq!(
        service
            .resume_prepared(&target.database)
            .unwrap()
            .unwrap()
            .state(),
        PreparedBindingState::ActivationRequested
    );
    assert!(
        service
            .abandon_prepared(&target.database, &prepared, &Identity::valid())
            .is_err()
    );
    let row = target
        .database
        .query_row(
            "SELECT activation_issued_at,activation_authorization FROM operator_binding_journal",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        row.integer(0).unwrap(),
        head.preexisting_effective_now().value().get()
    );
    assert!(row.blob(1).is_err());
    drop(target.database);
    let database = reopen_database(target.directory.path());
    let ready = authorize(&h, &head, &audit, &database, &native, &mut auth, &prepared).unwrap();
    assert_eq!(ready.state(), PreparedBindingState::Ready);
    assert_eq!(auth.authorizations.len(), 2);
    assert_eq!(auth.replay_table.lock().unwrap().len(), 2);
}
