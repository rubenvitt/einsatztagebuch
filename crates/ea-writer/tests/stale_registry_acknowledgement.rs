mod support;

use ea_operator::ReauthPurpose;
use ea_writer::{StaleRegistryStore, WriterError};
use support::{WriterHarness, valid_incident};

// Removing the signed receipt gate must break these real service/store tests.
#[test]
fn standard_warn_persists_a_signed_receipt_before_finalizing_once() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let store = StaleRegistryStore::new(harness.database()).unwrap();
    let service = harness.service(&source).with_stale_registry_store(store);
    let initial = harness.proof_for(ReauthPurpose::Finalize);
    let now = harness.observed_now_after_expiry();
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
    let ack = service
        .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
        .unwrap();
    let exact = harness.audit_bytes(ack.event_id());
    let decoded = ea_format::decode_local_audit_event(&exact).unwrap();
    assert!(matches!(
        decoded.action(),
        ea_format::LocalAuditActionV1::RegistryStaleWarnAcceptance(_)
    ));
    assert_eq!(decoded.outcome(), ea_format::LocalAuditOutcomeV1::Accepted);
    assert!(decoded.effective_now() == now);
    let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
    let outcome = service
        .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, now)
        .unwrap();
    assert_eq!(outcome.sequence.get(), 0);
    assert_eq!(harness.audit_bytes(ack.event_id()), exact);
    assert_eq!(
        service
            .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, now)
            .unwrap_err(),
        WriterError::StaleAckReplay
    );
}

#[test]
fn no_confirmation_wrong_purpose_unbound_context_or_expired_presence_release_no_receipt() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness
        .service(&source)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    let now = harness.observed_now_after_expiry();
    let initial = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
    assert_eq!(
        service
            .acknowledge_stale_registry(proof, valid_incident(), &preview, false, now)
            .unwrap_err(),
        WriterError::StaleAckRequired
    );
    let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
    assert_eq!(
        service
            .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
            .unwrap_err(),
        WriterError::ReauthPurposeMismatch
    );
    let proof = harness.proof_for(ReauthPurpose::RegistryStaleFinalize);
    assert_eq!(
        service
            .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
            .unwrap_err(),
        WriterError::ReauthRequired
    );
    let other_preview = service.preview(&initial, valid_incident(), now).unwrap();
    let proof = harness.context_proof(&other_preview, ReauthPurpose::RegistryStaleFinalize, now);
    assert_eq!(
        service
            .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
            .unwrap_err(),
        WriterError::StaleAckPreviewMismatch
    );
    let proof = harness
        .context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now)
        .invalidate_on_lock();
    assert_eq!(
        service
            .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
            .unwrap_err(),
        WriterError::ReauthRequired
    );
    assert_eq!(count(&harness, "local_audit_event"), 0);
    assert_eq!(count(&harness, "writer_stale_receipt"), 0);
}

#[test]
fn changed_input_operator_device_and_time_cannot_use_an_acknowledgement() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness
        .service(&source)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    let now = harness.observed_now_after_expiry();
    let initial = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    let foreign = harness.proof_of_another_operator_binding(ReauthPurpose::RegistryStaleFinalize);
    assert_eq!(
        service
            .acknowledge_stale_registry(foreign, valid_incident(), &preview, true, now)
            .unwrap_err(),
        WriterError::ReauthBindingMismatch
    );
    let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
    let ack = service
        .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
        .unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
    let mut input = valid_incident();
    input.notes = Some("changed".to_owned());
    assert_eq!(
        service
            .finalize_with_stale_registry(&proof, input, &preview, &ack, now)
            .unwrap_err(),
        WriterError::StaleAckPreviewMismatch
    );
    let later = ea_types::UnixMillis::new(now.get() + 300_000);
    assert_eq!(
        service
            .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, later)
            .unwrap_err(),
        WriterError::ReauthRequired
    );
    let mut binding = harness.binding();
    binding.writer_certificate_hash =
        ea_types::CertificateHash::try_from([0xa2; 32].as_slice()).unwrap();
    let wrong = harness
        .service_with_binding(&source, binding)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    assert_eq!(
        wrong
            .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, now)
            .unwrap_err(),
        WriterError::WriterRevoked
    );
    assert_eq!(count(&harness, "writer_stale_consumption"), 0);
    assert_eq!(harness.staged_object_count(), 0);
    service
        .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, now)
        .unwrap();
}

#[test]
fn evidence_and_signed_block_never_issue_receipts() {
    for variant in [
        support::LineVariantV1 {
            evidence_grade: true,
            ..Default::default()
        },
        support::LineVariantV1 {
            signed_block_expiry: true,
            ..Default::default()
        },
    ] {
        let harness = WriterHarness::with_variant(variant);
        let source = harness.source();
        let service = harness
            .service(&source)
            .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
        let now = harness.observed_now_after_expiry();
        let initial = harness.proof_for(ReauthPurpose::Finalize);
        let preview = service.preview(&initial, valid_incident(), now).unwrap();
        let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
        assert_eq!(
            service
                .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
                .unwrap_err(),
            WriterError::RegistryStaleBlocked
        );
        assert_eq!(count(&harness, "local_audit_event"), 0);
    }
}

#[test]
fn signature_or_atomic_audit_write_failure_never_releases_authority() {
    use ea_key_provider::KeyProvider;
    for signing_failure in [false, true] {
        let harness = WriterHarness::with_incident();
        let source = harness.source();
        let service = harness
            .service(&source)
            .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
        let now = harness.observed_now_after_expiry();
        let initial = harness.proof_for(ReauthPurpose::Finalize);
        let preview = service.preview(&initial, valid_incident(), now).unwrap();
        if signing_failure {
            harness
                .provider()
                .delete(&harness.binding().writer_signing_handle)
                .unwrap();
        } else {
            harness.database().execute("CREATE TRIGGER refuse_stale_receipt BEFORE INSERT ON writer_stale_receipt BEGIN SELECT RAISE(ABORT, 'injected'); END", &[]).unwrap();
        }
        let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
        assert!(
            service
                .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
                .is_err()
        );
        assert_eq!(count(&harness, "local_audit_event"), 0);
        assert_eq!(count(&harness, "writer_stale_receipt"), 0);
        assert_eq!(harness.staged_object_count(), 0);
    }
}

#[test]
fn consumed_receipt_stays_consumed_after_real_store_reopen_and_exact_byte_recovery() {
    let mut harness = WriterHarness::with_incident();
    let now = harness.observed_now_after_expiry();
    let (ack, preview, prepared_bytes, entry_hash, audit_bytes) = {
        let source = harness.source();
        let service = harness
            .service(&source)
            .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
        let initial = harness.proof_for(ReauthPurpose::Finalize);
        let preview = service.preview(&initial, valid_incident(), now).unwrap();
        let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
        let ack = service
            .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
            .unwrap();
        let audit_bytes = harness.audit_bytes(ack.event_id());
        let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
        let reached = service
            .finalize_stale_interrupted_at(
                &proof,
                valid_incident(),
                &preview,
                &ack,
                now,
                ea_writer::FinalizationFaultPoint::AfterAbsenceConfirmation,
            )
            .unwrap();
        (
            ack,
            preview,
            reached.entry_bytes().to_vec(),
            reached.prepared().unwrap().entry_hash(),
            audit_bytes,
        )
    };
    harness.reopen_store();
    let source = harness.source();
    let service = harness
        .service(&source)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
    assert_eq!(
        service
            .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, now)
            .unwrap_err(),
        WriterError::StaleAckReplay
    );
    assert!(matches!(
        service.recover_pending().unwrap(),
        ea_writer::RecoveryOutcome::CommittedFromPreparedBytes { .. }
    ));
    assert_eq!(
        harness.published_entry(entry_hash).exact_bytes().as_bytes(),
        prepared_bytes
    );
    assert_eq!(harness.audit_bytes(ack.event_id()), audit_bytes);
    assert!(harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
    assert_eq!(
        service.recover_pending().unwrap(),
        ea_writer::RecoveryOutcome::NothingPending
    );
    service.reconcile_to_completion().unwrap();
    assert!(harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
}

#[test]
fn reversible_prepared_recovery_restores_draft_and_number_but_never_receipt_authority() {
    let mut harness = WriterHarness::with_incident();
    let now = harness.observed_now_after_expiry();
    let (ack, preview) = {
        let source = harness.source();
        let service = harness
            .service(&source)
            .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
        let initial = harness.proof_for(ReauthPurpose::Finalize);
        let preview = service.preview(&initial, valid_incident(), now).unwrap();
        let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
        let ack = service
            .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
            .unwrap();
        let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
        service
            .finalize_stale_interrupted_at(
                &proof,
                valid_incident(),
                &preview,
                &ack,
                now,
                ea_writer::FinalizationFaultPoint::AfterPreparedMarkerCommit,
            )
            .unwrap();
        assert!(harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
        (ack, preview)
    };
    harness.reopen_store();
    let source = harness.source();
    let service = harness
        .service(&source)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    assert!(matches!(
        service.recover_pending().unwrap(),
        ea_writer::RecoveryOutcome::DraftRestored { .. }
    ));
    assert!(!harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
    let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
    assert_eq!(
        service
            .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, now)
            .unwrap_err(),
        WriterError::StaleAckReplay
    );
    service.reconcile_to_completion().unwrap();
    let fresh = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
    let ack = service
        .acknowledge_stale_registry(fresh, valid_incident(), &preview, true, now)
        .unwrap();
    service
        .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, now)
        .unwrap();
}

fn count(harness: &WriterHarness, table: &str) -> i64 {
    harness
        .database()
        .query_row(&format!("SELECT count(*) FROM {table}"), &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}

#[test]
fn concurrent_receipt_reuse_commits_at_most_one_entry() {
    use std::sync::{Arc, Barrier};
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness
        .service(&source)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    let now = harness.observed_now_after_expiry();
    let initial = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
    let ack = service
        .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
        .unwrap();
    let proofs = [
        harness.context_proof(&preview, ReauthPurpose::Finalize, now),
        harness.context_proof(&preview, ReauthPurpose::Finalize, now),
    ];
    let head = harness.head();
    let binding = harness.binding();
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let threads: Vec<_> = proofs
            .iter()
            .map(|proof| {
                let backend = harness.backend_handle();
                let repository = harness.repository();
                let database = harness.database();
                let provider = harness.provider();
                let barrier = Arc::clone(&barrier);
                let preview = &preview;
                let ack = &ack;
                scope.spawn(move || {
                    let source = backend.as_archive_source();
                    let service = ea_writer::WriterService::new(
                        repository,
                        provider,
                        backend.as_ref(),
                        &source,
                        head,
                        &[],
                        ea_draft::IncidentNumberRegister::new(Arc::clone(&database)),
                        ea_draft::OperatorProfileRepository::new(Arc::clone(&database)),
                        binding,
                    )
                    .with_stale_registry_store(StaleRegistryStore::new(database).unwrap());
                    barrier.wait();
                    service.finalize_with_stale_registry(proof, valid_incident(), preview, ack, now)
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(count(&harness, "writer_stale_consumption"), 1);
    assert_eq!(
        service
            .finalize_with_stale_registry(&proofs[0], valid_incident(), &preview, &ack, now)
            .unwrap_err(),
        WriterError::StaleAckReplay
    );
}

#[test]
fn consumption_write_failure_stops_before_secrets_or_prepared_bytes() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness
        .service(&source)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    let now = harness.observed_now_after_expiry();
    let initial = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
    let ack = service
        .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
        .unwrap();
    harness.database().execute("CREATE TRIGGER refuse_consumption BEFORE INSERT ON writer_stale_consumption BEGIN SELECT RAISE(ABORT, 'injected'); END", &[]).unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
    assert!(
        service
            .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, now)
            .is_err()
    );
    assert_eq!(count(&harness, "writer_stale_consumption"), 0);
    assert!(!harness.prepared_marker_is_present());
    assert_eq!(harness.staged_object_count(), 0);
    assert!(!harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
}

#[test]
fn changed_selected_time_requires_a_new_preview_and_native_context() {
    use std::sync::Arc;
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness
        .service(&source)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    let now = harness.observed_now_after_expiry();
    let initial = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
    let ack = service
        .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
        .unwrap();
    let selected =
        harness.reselected_head(ea_types::UnixMillis::new(harness.observed_now().get() + 1));
    let database = harness.database();
    let newer = ea_writer::WriterService::new(
        harness.repository(),
        harness.provider(),
        harness.backend(),
        &source,
        &selected,
        &[],
        ea_draft::IncidentNumberRegister::new(Arc::clone(&database)),
        ea_draft::OperatorProfileRepository::new(Arc::clone(&database)),
        harness.binding(),
    )
    .with_stale_registry_store(StaleRegistryStore::new(database).unwrap());
    let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
    assert_eq!(
        newer
            .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, now)
            .unwrap_err(),
        WriterError::StaleAckPreviewMismatch
    );
    assert_eq!(count(&harness, "writer_stale_consumption"), 0);
}

#[test]
fn stale_presence_time_preserves_the_floor_and_refuses_independent_future_skew() {
    let harness = WriterHarness::with_incident();
    let rewound = ea_types::UnixMillis::new(harness.observed_now().get() - 1);
    assert!(
        harness
            .reauthentication_time_at(rewound, false)
            .unwrap()
            .value()
            == harness.observed_now()
    );
    assert!(
        harness
            .reauthentication_time_at(harness.observed_now(), true)
            .is_ok()
    );
    assert!(matches!(
        harness.reauthentication_time_at(harness.observed_now_after_expiry(), true),
        Err(ea_trust::RegistryError::FutureSkew)
    ));
}

#[test]
fn native_context_proof_cannot_outlive_the_independent_clock_limit() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let now = ea_types::UnixMillis::new(harness.observed_now().get() + 299_999);
    let initial = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    let time = harness.reauthentication_time_at(now, true).unwrap();
    let proof =
        harness.context_proof_with_time(&preview, ReauthPurpose::RegistryStaleFinalize, &time);
    assert!(proof.is_valid_at(
        ReauthPurpose::RegistryStaleFinalize,
        ea_types::UnixMillis::new(now.get() + 1)
    ));
    assert!(!proof.is_valid_at(
        ReauthPurpose::RegistryStaleFinalize,
        ea_types::UnixMillis::new(now.get() + 2)
    ));
}

#[test]
fn a_different_signing_key_cannot_issue_a_receipt_under_the_writer_certificate() {
    use ea_key_provider::KeyProvider;
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let mut binding = harness.binding();
    binding.writer_signing_handle = harness
        .provider()
        .generate(
            ea_key_provider::SecretPurpose::OperatorInstanceKey,
            ea_format::KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let service = harness
        .service_with_binding(&source, binding)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    let now = harness.observed_now_after_expiry();
    let initial = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
    assert!(
        service
            .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
            .is_err()
    );
    assert_eq!(count(&harness, "local_audit_event"), 0);
    assert_eq!(count(&harness, "writer_stale_receipt"), 0);
}

#[test]
fn exhausted_lease_cannot_produce_the_selected_authority_required_by_a_writer() {
    let harness = WriterHarness::with_incident();
    assert!(matches!(
        harness.candidate_beyond_lease(),
        Err(ea_trust::RegistryError::SequenceLease)
    ));
    assert_eq!(count(&harness, "local_audit_event"), 0);
}

#[test]
fn review_crash_before_marker_must_release_incident_number() {
    for fault in [
        ea_writer::FinalizationFaultPoint::BeforeStagingCreate,
        ea_writer::FinalizationFaultPoint::AfterStagingCreateBeforeFileFlush,
        ea_writer::FinalizationFaultPoint::AfterStagingFileFlushBeforeDirectoryFlush,
        ea_writer::FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker,
    ] {
        let mut harness = WriterHarness::with_incident();
        let now = harness.observed_now_after_expiry();
        let original = harness.repository().load_or_create().unwrap();
        {
            let source = harness.source();
            let service = harness
                .service(&source)
                .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
            let initial = harness.proof_for(ReauthPurpose::Finalize);
            let preview = service.preview(&initial, valid_incident(), now).unwrap();
            let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
            let ack = service
                .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
                .unwrap();
            let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
            service
                .finalize_stale_interrupted_at(&proof, valid_incident(), &preview, &ack, now, fault)
                .unwrap();
            assert!(!harness.prepared_marker_is_present());
            assert!(harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
        }
        harness.reopen_store();
        let source = harness.source();
        let service = harness
            .service(&source)
            .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
        assert_eq!(
            service.recover_pending().unwrap(),
            ea_writer::RecoveryOutcome::NothingPending
        );
        service.reconcile_to_completion().unwrap();
        assert_eq!(count(&harness, "writer_stale_consumption"), 1);
        assert!(
            !harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER),
            "reversible crash leaves draft permanently blocked by its own number claim"
        );
        assert_eq!(harness.repository().load_or_create().unwrap(), original);
        // A repeated startup must never re-release an old journaled attempt's
        // number after a different finalization has claimed it again.
        ea_draft::IncidentNumberRegister::new(harness.database())
            .claim(
                harness.proof_for(ReauthPurpose::Finalize).organization_id(),
                2026,
                support::FIXTURE_INCIDENT_NUMBER,
            )
            .unwrap();
        service.recover_pending().unwrap();
        service.reconcile_to_completion().unwrap();
        assert!(harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
    }
}

#[test]
fn claim_journal_failure_rolls_back_the_number_but_keeps_receipt_consumed() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness
        .service(&source)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    let now = harness.observed_now_after_expiry();
    let initial = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
    let ack = service
        .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
        .unwrap();
    harness.database().execute("CREATE TRIGGER refuse_claim_journal BEFORE INSERT ON writer_stale_claim BEGIN SELECT RAISE(ABORT, 'injected'); END", &[]).unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
    assert!(
        service
            .finalize_with_stale_registry(&proof, valid_incident(), &preview, &ack, now)
            .is_err()
    );
    assert_eq!(count(&harness, "writer_stale_consumption"), 1);
    assert_eq!(count(&harness, "writer_stale_claim"), 0);
    assert!(!harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
    assert!(!harness.prepared_marker_is_present());
    assert_eq!(harness.staged_object_count(), 0);
}

#[test]
fn unmarked_claim_requires_the_original_decryptable_draft_and_atomic_release() {
    use ea_key_provider::KeyProvider;
    for mode in ["missing-key", "replacement-draft", "release-write-failure"] {
        let mut harness = WriterHarness::with_incident();
        let now = harness.observed_now_after_expiry();
        {
            let source = harness.source();
            let service = harness
                .service(&source)
                .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
            let initial = harness.proof_for(ReauthPurpose::Finalize);
            let preview = service.preview(&initial, valid_incident(), now).unwrap();
            let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
            let ack = service
                .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
                .unwrap();
            let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
            service
                .finalize_stale_interrupted_at(
                    &proof,
                    valid_incident(),
                    &preview,
                    &ack,
                    now,
                    ea_writer::FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker,
                )
                .unwrap();
        }
        match mode {
            "missing-key" => {
                let repository = harness.repository();
                let saved = repository
                    .save(repository.load_or_create().unwrap())
                    .unwrap();
                harness
                    .provider()
                    .delete(&repository.draft_dek_handle(&saved).unwrap())
                    .unwrap();
            }
            "replacement-draft" => {
                harness.repository().replace_with_blank().unwrap();
            }
            _ => {
                harness.database().execute("CREATE TRIGGER refuse_release_journal BEFORE INSERT ON writer_stale_claim_released BEGIN SELECT RAISE(ABORT, 'injected'); END", &[]).unwrap();
            }
        }
        harness.reopen_store();
        let source = harness.source();
        let service = harness
            .service(&source)
            .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
        if mode == "replacement-draft" {
            service.recover_pending().unwrap();
        } else {
            assert!(service.recover_pending().is_err());
            assert!(service.reconcile_to_completion().is_err());
            assert!(harness.staged_object_count() > 0);
        }
        assert!(harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
        assert_eq!(count(&harness, "writer_stale_consumption"), 1);
        assert_eq!(count(&harness, "writer_stale_claim_released"), 0);
        if mode == "release-write-failure" {
            harness
                .database()
                .execute("DROP TRIGGER refuse_release_journal", &[])
                .unwrap();
            service.recover_pending().unwrap();
            assert!(!harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
            assert_eq!(count(&harness, "writer_stale_claim_released"), 1);
        }
    }
}

#[test]
fn known_successor_stops_receipt_issuance_and_consumption_at_readiness() {
    let mut harness = WriterHarness::with_incident();
    let now = harness.observed_now_after_expiry();
    let ready = ea_types::UnixMillis::new(now.get() + 1);
    let finalize_time = harness.reauthentication_time_at(now, false).unwrap();
    harness.add_known_successor(ready);
    let source = harness.source();
    let service = harness
        .service(&source)
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    let initial = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    let time = harness.fallback_reauthentication_time(now).unwrap();
    let delayed =
        harness.context_proof_with_time(&preview, ReauthPurpose::RegistryStaleFinalize, &time);
    let proof =
        harness.context_proof_with_time(&preview, ReauthPurpose::RegistryStaleFinalize, &time);
    let ack = service
        .acknowledge_stale_registry(proof, valid_incident(), &preview, true, now)
        .unwrap();
    // Keep the Finalize proof unexpired to isolate the receipt's own presence
    // boundary in the actual consumer.
    let finalize_proof =
        harness.context_proof_with_time(&preview, ReauthPurpose::Finalize, &finalize_time);
    assert_eq!(
        service
            .acknowledge_stale_registry(delayed, valid_incident(), &preview, true, ready)
            .unwrap_err(),
        WriterError::ReauthRequired
    );
    assert_eq!(
        service
            .finalize_with_stale_registry(&finalize_proof, valid_incident(), &preview, &ack, ready)
            .unwrap_err(),
        WriterError::ReauthRequired
    );
    assert_eq!(count(&harness, "writer_stale_consumption"), 0);
    assert!(!harness.prepared_marker_is_present());
    assert!(matches!(
        harness.fallback_reauthentication_time(ready),
        Err(ea_trust::RegistryError::SuccessorReady)
    ));
}

#[test]
fn an_already_expired_writer_context_requires_and_consumes_the_exact_signed_ack() {
    let harness = WriterHarness::with_incident();
    let now = harness.observed_now_after_expiry();
    let head = harness.stale_writer_head(now);
    let source = harness.source();
    let service = harness
        .service_for_writer(&source, head.as_writer())
        .with_stale_registry_store(StaleRegistryStore::new(harness.database()).unwrap());
    let initial = harness.writer_context_proof(head.as_writer(), ReauthPurpose::Finalize, None);
    let preview = service.preview(&initial, valid_incident(), now).unwrap();
    assert!(
        service
            .finalize(&initial, valid_incident(), &preview, now)
            .is_err()
    );
    let accept = harness.writer_context_proof(
        head.as_writer(),
        ReauthPurpose::RegistryStaleFinalize,
        Some(&preview),
    );
    let receipt = service
        .acknowledge_stale_registry(accept, valid_incident(), &preview, true, now)
        .unwrap();
    let finalize =
        harness.writer_context_proof(head.as_writer(), ReauthPurpose::Finalize, Some(&preview));
    let outcome = service
        .finalize_with_stale_registry(&finalize, valid_incident(), &preview, &receipt, now)
        .unwrap();
    assert_eq!(outcome.sequence.get(), 0);
    assert_eq!(
        service
            .finalize_with_stale_registry(&finalize, valid_incident(), &preview, &receipt, now)
            .unwrap_err(),
        WriterError::StaleAckReplay
    );
}
