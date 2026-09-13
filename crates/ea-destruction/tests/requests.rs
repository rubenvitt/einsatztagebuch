mod support;
use ea_destruction::*;
use ea_format::OperatorRoleV1;
use ea_local_store::StoreValue;
use ea_operator::ReauthPurpose;
use support::*;
fn count(f: &RequestFixture, table: &str) -> i64 {
    f.database
        .query_row(&format!("SELECT count(*) FROM {table}"), &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}

#[test]
fn historical_resume_reconstructs_expired_original_context_without_current_authority_escape() {
    let mut f = RequestFixture::new();
    let old = f.f.head();
    let (exact, target) = f.authorization();
    let request = event(&f.f, &exact, event_fields(&f.f, &exact, 1, None, 0, None));
    let proof = f.proof(&old, ReauthPurpose::Destruction);
    let audit = f.audit(&old, false, false);
    let repo = SqliteDestructionRepository::new(f.database.clone());
    let service = DestructionRequestService {
        head: &old,
        certificate: f.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &audit,
        repository: &repo,
    };
    let saved = service
        .request(&exact, &request, &[target], &proof)
        .unwrap();
    f.f.line.push(
        trust::ActionSpec::Device {
            kind: ea_format::CertificateKindV1::Reader,
            marker: 0x7c,
            effective_from: None,
        },
        trust::HeadOptions {
            not_after: ea_types::UnixMillis::new(30_000_000),
            ..options()
        },
    );
    let current = selected(&f.f.line, 20_000_000);
    assert!(current.preexisting_effective_now().value() > old.not_after());
    let trust =
        f.f.line
            .verified(trust::Pin::Head(f.f.line.heads().len() - 1));
    let historical = ea_trust::verify_historical_registry_authority(
        &trust,
        old.registry_version(),
        old.registry_head_hash(),
        old.proposed_sequence(),
    )
    .unwrap();
    let auth = verify_authorization_historical(&exact, &historical).unwrap();
    let fresh = f.proof(&current, ReauthPurpose::Destruction);
    let audit = f.audit(&current, false, false);
    let reopened = SqliteDestructionRepository::new(f.reopen());
    let service = DestructionRequestService {
        head: &current,
        certificate: f.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &audit,
        repository: &reopened,
    };
    assert!(
        service
            .resume_historical(&auth, &historical, &proof)
            .is_err()
    );
    let resumed = service
        .resume_historical(&auth, &historical, &fresh)
        .unwrap();
    assert_eq!(
        resumed.request().audit_exact_bytes(),
        saved.audit_exact_bytes()
    );
    assert_eq!(resumed.request().authorization().exact_bytes(), exact);
    let mut next = event_fields(
        &f.f,
        &exact,
        2,
        Some(0),
        1,
        Some(saved.event().object_hash()),
    );
    next.executed_at = current.preexisting_effective_now().value();
    assert!(resumed.verify_event(&event(&f.f, &exact, next)).is_ok());
}

#[test]
fn restart_continues_same_authorization_after_unrelated_registry_progress() {
    let mut f = RequestFixture::new();
    let original = f.f.head();
    let (auth, target) = f.authorization();
    let first = event(&f.f, &auth, event_fields(&f.f, &auth, 1, None, 0, None));
    let proof = f.proof(&original, ReauthPurpose::Destruction);
    let audit = f.audit(&original, false, false);
    let repository = SqliteDestructionRepository::new(f.database.clone());
    let service = DestructionRequestService {
        head: &original,
        certificate: f.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &audit,
        repository: &repository,
    };
    let requested = service.request(&auth, &first, &[target], &proof).unwrap();
    f.f.line.push(
        trust::ActionSpec::Device {
            kind: ea_format::CertificateKindV1::Reader,
            marker: 0x79,
            effective_from: None,
        },
        options(),
    );
    let current = selected(&f.f.line, NOW + 301000);
    let reopened = SqliteDestructionRepository::new(f.reopen());
    // Historical evidence is reconstructed at H; a separate fresh H+1 native
    // session governs continuation. The old five-minute proof is unusable.
    let loaded = reopened
        .reconstruct(requested.authorization(), &original)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.authorization().exact_bytes(), auth);
    assert_eq!(loaded.event().exact_bytes(), first);
    assert_eq!(loaded.audit_exact_bytes(), requested.audit_exact_bytes());
    let current_audit = f.audit(&current, false, false);
    let resumed_service = DestructionRequestService {
        head: &current,
        certificate: f.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &current_audit,
        repository: &reopened,
    };
    assert_eq!(
        resumed_service
            .resume(loaded.authorization(), &original, &proof)
            .err()
            .map(|e| e.code()),
        Some("EA-DESTRUCTION-OPERATOR")
    );
    let fresh = f.proof(&current, ReauthPurpose::Destruction);
    let resumed = resumed_service
        .resume(loaded.authorization(), &original, &fresh)
        .unwrap();
    let mut fields = event_fields(
        &f.f,
        &auth,
        2,
        Some(0),
        1,
        Some(loaded.event().object_hash()),
    );
    fields.executed_at = current.preexisting_effective_now().value();
    let exact = event(&f.f, &auth, fields);
    assert!(
        verify_event(&exact, loaded.authorization(), &original).is_err(),
        "frozen historical time cannot authorize current execution"
    );
    let next = resumed.verify_event(&exact).unwrap();
    let mut machine = DestructionStateMachine::new(loaded.authorization());
    machine.apply(loaded.event()).unwrap();
    machine.apply(&next).unwrap();
    assert_eq!(machine.state(), Some(DestructionState::InProgress));
    assert_eq!(resumed.request().authorization().exact_bytes(), auth);
    assert!(next.fields().destruction_id == loaded.authorization().fields().destruction_id);
    // This is verified claim admission only: resume creates no durable state.
    assert_eq!(count(&f, "local_audit_event"), 1);
    assert_eq!(count(&f, "destruction_request"), 1);
}

#[test]
fn continuation_rejects_current_revocation_and_later_only_component_certificate() {
    for later_component in [false, true] {
        let mut f = RequestFixture::new();
        let original = f.f.head();
        let (auth, target) = f.authorization();
        let first = event(&f.f, &auth, event_fields(&f.f, &auth, 1, None, 0, None));
        let proof = f.proof(&original, ReauthPurpose::Destruction);
        let audit = f.audit(&original, false, false);
        let repository = SqliteDestructionRepository::new(f.database.clone());
        let service = DestructionRequestService {
            head: &original,
            certificate: f.certificate,
            role: OperatorRoleV1::Writer,
            account: &Account { matching: true },
            audit: &audit,
            repository: &repository,
        };
        let requested = service.request(&auth, &first, &[target], &proof).unwrap();
        if later_component {
            let added = f.f.line.push(
                trust::ActionSpec::Device {
                    kind: ea_format::CertificateKindV1::DeletionAttest,
                    marker: 0x79,
                    effective_from: None,
                },
                options(),
            );
            f.f.deletion = ea_types::CertificateHash::from(added.direct_object_hash.unwrap());
        } else {
            f.f.line.push(
                trust::ActionSpec::Revoke {
                    target_kind: 2,
                    object_hash: ea_types::ObjectHash::try_from(f.f.deletion.as_bytes().as_slice())
                        .unwrap(),
                },
                options(),
            );
        }
        let current = selected(&f.f.line, NOW + 301000);
        assert_eq!(
            current.active_certificate_fields(f.f.deletion).is_some(),
            later_component
        );
        let fresh = f.proof(&current, ReauthPurpose::Destruction);
        let current_audit = f.audit(&current, false, false);
        let service = DestructionRequestService {
            head: &current,
            certificate: f.certificate,
            role: OperatorRoleV1::Writer,
            account: &Account { matching: true },
            audit: &current_audit,
            repository: &repository,
        };
        let resumed = service
            .resume(requested.authorization(), &original, &fresh)
            .unwrap();
        let mut fields = event_fields(
            &f.f,
            &auth,
            2,
            Some(0),
            1,
            Some(requested.event().object_hash()),
        );
        fields.executed_at = current.preexisting_effective_now().value();
        let exact = event(&f.f, &auth, fields);
        assert_eq!(
            resumed.verify_event(&exact).err().map(|e| e.code()),
            Some("EA-DESTRUCTION-SIGNATURE")
        );
        assert!(
            repository
                .reconstruct(requested.authorization(), &original)
                .unwrap()
                .is_some()
        );
        assert_eq!(count(&f, "local_audit_event"), 1);
    }
}

#[test]
fn resume_rechecks_current_policy_and_exact_native_purpose_without_rewriting_history() {
    for fault in 0..3 {
        let mut f = RequestFixture::new();
        let original = f.f.head();
        let (auth, target) = f.authorization();
        let first = event(&f.f, &auth, event_fields(&f.f, &auth, 1, None, 0, None));
        let proof = f.proof(&original, ReauthPurpose::Destruction);
        let audit = f.audit(&original, false, false);
        let repository = SqliteDestructionRepository::new(f.database.clone());
        let service = DestructionRequestService {
            head: &original,
            certificate: f.certificate,
            role: OperatorRoleV1::Writer,
            account: &Account { matching: true },
            audit: &audit,
            repository: &repository,
        };
        let requested = service.request(&auth, &first, &[target], &proof).unwrap();
        f.f.line.push(
            trust::ActionSpec::Policy {
                policy_version: None,
                previous_policy_hash: None,
                effective_from: None,
            },
            trust::HeadOptions {
                policy_destruction_enabled_override: Some(fault != 0),
                policy_eds_privacy_decision_document_hash_override: Some(
                    (fault != 1).then(|| trust::hash32(0x91)),
                ),
                ..options()
            },
        );
        let current = selected(&f.f.line, NOW + 301000);
        let fresh = f.proof(
            &current,
            if fault == 2 {
                ReauthPurpose::Finalize
            } else {
                ReauthPurpose::Destruction
            },
        );
        let current_audit = f.audit(&current, false, false);
        let service = DestructionRequestService {
            head: &current,
            certificate: f.certificate,
            role: OperatorRoleV1::Writer,
            account: &Account { matching: true },
            audit: &current_audit,
            repository: &repository,
        };
        assert_eq!(
            service
                .resume(requested.authorization(), &original, &fresh)
                .err()
                .map(|e| e.code()),
            Some(if fault == 2 {
                "EA-DESTRUCTION-OPERATOR"
            } else {
                "EA-DESTRUCTION-PRIVACY-GATE"
            })
        );
        assert!(
            repository
                .reconstruct(requested.authorization(), &original)
                .unwrap()
                .is_some()
        );
        assert_eq!(count(&f, "local_audit_event"), 1);
    }
}

#[test]
fn request_is_signed_audited_durable_and_exact_replay_survives_reopen() {
    let f = RequestFixture::new();
    let head = f.f.head();
    let (auth, target) = f.authorization();
    let event = event(&f.f, &auth, event_fields(&f.f, &auth, 1, None, 0, None));
    let proof = f.proof(&head, ReauthPurpose::Destruction);
    let audit = f.audit(&head, false, false);
    let repository = SqliteDestructionRepository::new(f.database.clone());
    let service = DestructionRequestService {
        head: &head,
        certificate: f.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &audit,
        repository: &repository,
    };
    let requested = service.request(&auth, &event, &[target], &proof).unwrap();
    assert_eq!(requested.state(), DestructionState::Requested);
    assert_eq!(count(&f, "local_audit_event"), 1);
    // Plan T11 Step 3: the flushed audit binds only the authorization hash,
    // the state-event hash and the outcome, each checked on its own value.
    let stored = f
        .database
        .query_row("SELECT exact_bytes FROM local_audit_event", &[])
        .unwrap()
        .unwrap();
    let stored = stored.blob(0).unwrap();
    assert_eq!(stored, requested.audit_exact_bytes());
    let recorded = ea_format::decode_local_audit_event(stored).unwrap();
    let ea_format::LocalAuditActionV1::Destruction(context) = recorded.action() else {
        panic!("destruction audit action")
    };
    assert!(
        context.destruction_authorization_object_hash() == ea_crypto::object_hash(&auth),
        "audit must bind the authorization hash"
    );
    assert!(
        context.state_event_object_hash() == ea_crypto::object_hash(&event),
        "audit must bind the requested state-event hash"
    );
    assert!(recorded.outcome() == ea_format::LocalAuditOutcomeV1::Completed);
    let verified = verify_authorization(&auth, &head).unwrap();
    let restarted = SqliteDestructionRepository::new(f.reopen());
    let loaded = restarted.reconstruct(&verified, &head).unwrap().unwrap();
    assert!(loaded.audit_event_id() == requested.audit_event_id());
    let (_, target) = f.authorization();
    let replay = service.request(&auth, &event, &[target], &proof).unwrap();
    assert!(replay.audit_event_id() == requested.audit_event_id());
    assert_eq!(count(&f, "local_audit_event"), 1);
    let conflict = event_fields(&f.f, &auth, 2, None, 0, None);
    let different = support::event(&f.f, &auth, conflict);
    let (_, target) = f.authorization();
    assert_eq!(
        service
            .request(&auth, &different, &[target], &proof)
            .err()
            .unwrap()
            .code(),
        "EA-DESTRUCTION-SECURITY-CONFLICT"
    );
}
#[test]
fn wrong_purpose_stale_account_and_audit_failure_never_publish_requested() {
    for fault in 0..5 {
        let f = RequestFixture::new();
        let head = f.f.head();
        let (auth, target) = f.authorization();
        let event = event(&f.f, &auth, event_fields(&f.f, &auth, 1, None, 0, None));
        let proof = f.proof(
            &head,
            if fault == 0 {
                ReauthPurpose::Finalize
            } else {
                ReauthPurpose::Destruction
            },
        );
        let proof = if fault == 1 {
            proof.invalidate_on_lock()
        } else {
            proof
        };
        let audit = f.audit(&head, fault == 3, fault == 4);
        let repository = SqliteDestructionRepository::new(f.database.clone());
        let account = Account {
            matching: fault != 2,
        };
        let service = DestructionRequestService {
            head: &head,
            certificate: f.certificate,
            role: OperatorRoleV1::Writer,
            account: &account,
            audit: &audit,
            repository: &repository,
        };
        assert!(service.request(&auth, &event, &[target], &proof).is_err());
        assert_eq!(count(&f, "local_audit_event"), 0);
        assert!(
            repository
                .reconstruct(&verify_authorization(&auth, &head).unwrap(), &head)
                .unwrap()
                .is_none()
        );
    }
}
#[test]
fn request_insert_failure_rolls_back_the_prepared_audit() {
    for failed_table in ["local_audit_event", "destruction_request"] {
        let f = RequestFixture::new();
        let head = f.f.head();
        let (auth, target) = f.authorization();
        let event = event(&f.f, &auth, event_fields(&f.f, &auth, 1, None, 0, None));
        let proof = f.proof(&head, ReauthPurpose::Destruction);
        let audit = f.audit(&head, false, false);
        let repository = SqliteDestructionRepository::new(f.database.clone());
        f.database.execute(&format!("CREATE TRIGGER fail_request BEFORE INSERT ON {failed_table} BEGIN SELECT RAISE(ABORT, 'fixture fault'); END"),&[]).unwrap();
        let service = DestructionRequestService {
            head: &head,
            certificate: f.certificate,
            role: OperatorRoleV1::Writer,
            account: &Account { matching: true },
            audit: &audit,
            repository: &repository,
        };
        assert!(service.request(&auth, &event, &[target], &proof).is_err());
        assert_eq!(count(&f, "local_audit_event"), 0);
        assert_eq!(count(&f, "destruction_request"), 0);
        f.database
            .execute("DROP TRIGGER fail_request", &[])
            .unwrap();
        let (_, target) = f.authorization();
        service.request(&auth, &event, &[target], &proof).unwrap();
        assert_eq!(count(&f, "local_audit_event"), 1);
        assert!(
            f.database
                .execute("DELETE FROM destruction_request", &[])
                .is_err()
        );
        assert!(
            f.database
                .execute(
                    "UPDATE destruction_request SET exact_event=?1",
                    &[StoreValue::Blob(vec![0])]
                )
                .is_err()
        );
    }
}

#[test]
fn exact_five_minute_expiry_and_wrong_actor_certificate_or_incomplete_targets_fail_closed() {
    for fault in 0..3 {
        let f = RequestFixture::new();
        let original = f.f.head();
        let head = if fault == 0 {
            support::selected(&f.f.line, 301000)
        } else {
            f.f.head()
        };
        let (auth, target) = f.authorization();
        let mut fields = event_fields(&f.f, &auth, 1, None, 0, None);
        fields.executed_at = head.preexisting_effective_now().value();
        let event = event(&f.f, &auth, fields);
        let proof = f.proof(&original, ReauthPurpose::Destruction);
        let audit = f.audit(&head, false, false);
        let repository = SqliteDestructionRepository::new(f.database.clone());
        let certificate = if fault == 1 {
            f.f.approvers[0]
        } else {
            f.certificate
        };
        let service = DestructionRequestService {
            head: &head,
            certificate,
            role: OperatorRoleV1::Writer,
            account: &Account { matching: true },
            audit: &audit,
            repository: &repository,
        };
        let targets = if fault == 2 { vec![] } else { vec![target] };
        assert!(service.request(&auth, &event, &targets, &proof).is_err());
        assert_eq!(count(&f, "local_audit_event"), 0);
        assert_eq!(count(&f, "destruction_request"), 0);
    }
}

#[test]
fn request_refuses_a_database_without_durable_commit_sync() {
    for mode in ["OFF", "NORMAL"] {
        let f = RequestFixture::new();
        let head = f.f.head();
        let (auth, target) = f.authorization();
        let event = event(&f.f, &auth, event_fields(&f.f, &auth, 1, None, 0, None));
        let proof = f.proof(&head, ReauthPurpose::Destruction);
        let audit = f.audit(&head, false, false);
        let repository = SqliteDestructionRepository::new(f.database.clone());
        f.database
            .execute(&format!("PRAGMA synchronous = {mode}"), &[])
            .unwrap();
        let service = DestructionRequestService {
            head: &head,
            certificate: f.certificate,
            role: OperatorRoleV1::Writer,
            account: &Account { matching: true },
            audit: &audit,
            repository: &repository,
        };
        assert_eq!(
            service
                .request(&auth, &event, &[target], &proof)
                .err()
                .map(|e| e.code()),
            Some("EA-DESTRUCTION-STORAGE")
        );
        assert_eq!(count(&f, "local_audit_event"), 0);
        assert_eq!(count(&f, "destruction_request"), 0);
        f.database
            .execute("PRAGMA synchronous = FULL", &[])
            .unwrap();
        let (_, target) = f.authorization();
        service.request(&auth, &event, &[target], &proof).unwrap();
    }
}
