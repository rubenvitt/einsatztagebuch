mod support;

use ea_operator::ReauthPurpose;
use ea_schema::{AmendmentChangeV1, PayloadV1};
use ea_writer::{AmendmentContentV1, OriginalReferenceV1, WriterError};
use support::{LineVariantV1, WriterHarness};

fn content() -> AmendmentContentV1 {
    AmendmentContentV1 {
        timezone: "Europe/Berlin".into(),
        source: support::valid_incident().source,
        reason: "Anzahl berichtigen".into(),
        changes: vec![AmendmentChangeV1::new("patientCount", "Zwei statt einer Person").unwrap()],
    }
}

fn original(harness: &WriterHarness) -> OriginalReferenceV1 {
    harness.materialize_trust_objects();
    let outcome = harness.finalize_once();
    // A separate fixture Recovery actor opens the original. Its private key
    // is never passed to the Writer service or stored in its provider.
    let bytes = harness.decrypt_entry_as_recovery_recipient(outcome.entry_hash);
    let validated = ea_schema::SchemaRegistry::v1()
        .validate("ea.incident", 1, &bytes)
        .unwrap();
    let PayloadV1::Incident(incident) = validated.payload() else {
        panic!("original must be an incident");
    };
    OriginalReferenceV1 {
        original_record_id: incident.header().record_id(),
        original_entry_hash: outcome.entry_hash,
        original_sequence: outcome.sequence,
    }
}

// Removing the normal Amendment variant or trusting caller record identity
// must break this actual archive/source/finalization witness.
#[test]
fn amendment_preserves_original_bytes_and_uses_the_exact_writer_origin_identity() {
    let mut harness = WriterHarness::with_variant(LineVariantV1 {
        recovery_recipient_openable: true,
        ..LineVariantV1::default()
    });
    let reference = original(&harness);
    let before = harness
        .published_entry(reference.original_entry_hash)
        .exact_bytes()
        .as_bytes()
        .to_vec();
    harness.select_sequence(1);
    let source = harness.source();
    let service = harness.service(&source);
    let anchor = harness.anchor();
    let now = harness.observed_now();
    let public_report =
        ea_verify::verify_archive(&source, &anchor, ea_verify::VerifyOptions::new(now)).unwrap();
    assert!(
        public_report.is_fully_verified(),
        "{}",
        public_report.to_canonical_json().unwrap()
    );
    let input = service
        .prepare_amendment(reference, content(), &anchor, now)
        .unwrap();
    let proof = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview_amendment(&proof, input, now).unwrap();
    let input = service
        .prepare_amendment(reference, content(), &anchor, now)
        .unwrap();
    let amended = service
        .finalize_amendment(&proof, input, &preview, now)
        .unwrap();
    assert_eq!(
        harness
            .published_entry(reference.original_entry_hash)
            .exact_bytes()
            .as_bytes(),
        before
    );
    let bytes = harness.decrypt_entry_as_recovery_recipient(amended.entry_hash);
    let validated = ea_schema::SchemaRegistry::v1()
        .validate("ea.amendment", 1, &bytes)
        .unwrap();
    let PayloadV1::Amendment(amendment) = validated.payload() else {
        panic!("normal Writer must produce Amendment");
    };
    assert!(amendment.original_record_id() == reference.original_record_id);
    assert!(amendment.original_entry_hash() == reference.original_entry_hash);
    assert_eq!(amendment.original_sequence(), reference.original_sequence);
    assert_eq!(
        amendment.original_incident_number(),
        support::FIXTURE_INCIDENT_NUMBER
    );
    assert_eq!(amendment.reason(), "Anzahl berichtigen");
    assert!(harness.writer_keys_cannot_decrypt(amended.entry_hash));
}

#[test]
fn caller_record_id_cannot_forge_an_original_link() {
    let mut harness = WriterHarness::with_variant(LineVariantV1 {
        recovery_recipient_openable: true,
        ..LineVariantV1::default()
    });
    let mut reference = original(&harness);
    let mut wrong = *reference.original_record_id.as_bytes();
    wrong[15] ^= 1;
    reference.original_record_id = ea_types::RecordId::try_from(wrong.as_slice()).unwrap();
    harness.select_sequence(1);
    let source = harness.source();
    assert!(matches!(
        harness.service(&source).prepare_amendment(
            reference,
            content(),
            &harness.anchor(),
            harness.observed_now()
        ),
        Err(WriterError::OriginalIdentityMismatch)
    ));
}

#[test]
fn pending_identity_cannot_authorize_an_unpublished_original_and_reopen_releases_only_its_claim() {
    let mut harness = WriterHarness::with_incident();
    harness.materialize_trust_objects();
    let reached = harness
        .finalize_with_fault(
            ea_writer::FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker,
        )
        .unwrap();
    let entry = ea_format::decode_exact_object(reached.entry_bytes()).unwrap();
    let ea_format::ParsedArchiveObject::Entry(entry) = entry else {
        panic!("entry");
    };
    let row = harness
        .database()
        .query_row("SELECT record_id FROM writer_original_identity", &[])
        .unwrap()
        .unwrap();
    let reference = OriginalReferenceV1 {
        original_record_id: ea_types::RecordId::try_from(row.blob(0).unwrap()).unwrap(),
        original_entry_hash: entry.value().entry_hash(),
        original_sequence: ea_types::ChainSequence::new(0),
    };
    assert!(harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
    harness.reopen_store();
    let source = harness.source();
    let service = harness.service(&source);
    assert!(matches!(
        service.prepare_amendment(
            reference,
            content(),
            &harness.anchor(),
            harness.observed_now()
        ),
        Err(WriterError::OriginalIdentityMissing)
    ));
    assert_eq!(
        service.recover_pending().unwrap(),
        ea_writer::RecoveryOutcome::NothingPending
    );
    service.reconcile_to_completion().unwrap();
    assert!(!harness.incident_number_is_taken(support::FIXTURE_INCIDENT_NUMBER));
    assert!(harness.published_entry_paths().is_empty());
}

#[test]
fn irreversible_reopen_publishes_exact_original_and_its_identity_together() {
    let mut harness = WriterHarness::with_incident();
    harness.materialize_trust_objects();
    let reached = harness
        .finalize_with_fault(ea_writer::FinalizationFaultPoint::AfterAbsenceConfirmation)
        .unwrap();
    let exact = reached.entry_bytes().to_vec();
    let row = harness
        .database()
        .query_row(
            "SELECT record_id,entry_hash FROM writer_original_identity",
            &[],
        )
        .unwrap()
        .unwrap();
    let reference = OriginalReferenceV1 {
        original_record_id: ea_types::RecordId::try_from(row.blob(0).unwrap()).unwrap(),
        original_entry_hash: ea_types::EntryHash::try_from(row.blob(1).unwrap()).unwrap(),
        original_sequence: ea_types::ChainSequence::new(0),
    };
    assert!(
        harness
            .database()
            .query_row("SELECT 1 FROM writer_original_published", &[])
            .unwrap()
            .is_none()
    );
    harness.reopen_store();
    {
        let source = harness.source();
        assert!(matches!(
            harness.service(&source).recover_pending().unwrap(),
            ea_writer::RecoveryOutcome::CommittedFromPreparedBytes { .. }
        ));
    }
    assert_eq!(
        harness
            .published_entry(reference.original_entry_hash)
            .exact_bytes()
            .as_bytes(),
        exact
    );
    harness.select_sequence(1);
    let source = harness.source();
    assert!(
        harness
            .service(&source)
            .prepare_amendment(
                reference,
                content(),
                &harness.anchor(),
                harness.observed_now()
            )
            .is_ok()
    );
}

#[test]
fn missing_restored_identity_source_never_falls_back_to_caller_assertion() {
    let mut harness = WriterHarness::with_variant(LineVariantV1 {
        recovery_recipient_openable: true,
        ..LineVariantV1::default()
    });
    let reference = original(&harness);
    let exact = harness
        .published_entry(reference.original_entry_hash)
        .exact_bytes()
        .as_bytes()
        .to_vec();
    harness.restore_captured_backup();
    harness.select_sequence(1);
    let source = harness.source();
    let result = harness.service(&source).prepare_amendment(
        reference,
        content(),
        &harness.anchor(),
        harness.observed_now(),
    );
    assert!(matches!(result, Err(WriterError::OriginalIdentityMissing)));
    assert_eq!(
        harness
            .published_entry(reference.original_entry_hash)
            .exact_bytes()
            .as_bytes(),
        exact
    );
}

#[test]
fn source_rejects_mutation_and_reference_sequence_or_unknown_hash() {
    let mut harness = WriterHarness::with_variant(LineVariantV1 {
        recovery_recipient_openable: true,
        ..LineVariantV1::default()
    });
    let reference = original(&harness);
    for sql in [
        "UPDATE writer_original_identity SET incident_number='forged'",
        "DELETE FROM writer_original_identity",
        "DELETE FROM writer_original_published",
    ] {
        assert!(harness.database().execute(sql, &[]).is_err());
    }
    harness.select_sequence(1);
    let source = harness.source();
    let service = harness.service(&source);
    assert!(matches!(
        service.prepare_amendment(
            OriginalReferenceV1 {
                original_sequence: ea_types::ChainSequence::new(1),
                ..reference
            },
            content(),
            &harness.anchor(),
            harness.observed_now()
        ),
        Err(WriterError::OriginalIdentityMismatch)
    ));
    let mut wrong = *reference.original_entry_hash.as_bytes();
    wrong[0] ^= 1;
    assert!(matches!(
        service.prepare_amendment(
            OriginalReferenceV1 {
                original_entry_hash: ea_types::EntryHash::try_from(wrong.as_slice()).unwrap(),
                ..reference
            },
            content(),
            &harness.anchor(),
            harness.observed_now()
        ),
        Err(WriterError::OriginalIdentityMissing)
    ));
}

#[test]
fn amendment_stale_warning_consumes_the_native_signed_receipt_without_claiming_a_new_incident_number()
 {
    let mut harness = WriterHarness::with_variant(LineVariantV1 {
        recovery_recipient_openable: true,
        ..LineVariantV1::default()
    });
    let reference = original(&harness);
    harness.select_sequence(1);
    let source = harness.source();
    let service = harness
        .service(&source)
        .with_stale_registry_store(ea_writer::StaleRegistryStore::new(harness.database()).unwrap());
    let now = harness.observed_now_after_expiry();
    let input = || {
        service
            .prepare_amendment(reference, content(), &harness.anchor(), now)
            .unwrap()
    };
    let proof = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service.preview_amendment(&proof, input(), now).unwrap();
    assert!(matches!(
        service.finalize_amendment(&proof, input(), &preview, now),
        Err(WriterError::StaleAckRequired)
    ));
    let native = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
    let receipt = service
        .acknowledge_stale_amendment(native, input(), &preview, true, now)
        .unwrap();
    let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
    let outcome = service
        .finalize_amendment_with_stale_registry(&proof, input(), &preview, &receipt, now)
        .unwrap();
    assert_eq!(outcome.sequence.get(), 1);
    assert_eq!(
        harness
            .database()
            .query_row("SELECT COUNT(*) FROM incident_number_register", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
    assert!(matches!(
        service.finalize_amendment_with_stale_registry(&proof, input(), &preview, &receipt, now),
        Err(WriterError::StaleAckReplay)
    ));
}

#[test]
fn failed_identity_publication_keeps_irreversible_marker_and_reopen_finishes_same_bytes() {
    let mut harness = WriterHarness::with_incident();
    harness.materialize_trust_objects();
    harness
        .finalize_with_fault(ea_writer::FinalizationFaultPoint::BeforeStagingCreate)
        .unwrap();
    {
        let source = harness.source();
        let service = harness.service(&source);
        service.recover_pending().unwrap();
        service.reconcile_to_completion().unwrap();
    }
    harness.database().execute("CREATE TRIGGER fail_original_publication BEFORE INSERT ON writer_original_published BEGIN SELECT RAISE(ABORT,'test write failure'); END", &[]).unwrap();
    {
        let source = harness.source();
        let service = harness.service(&source);
        let proof = harness.proof_for(ReauthPurpose::Finalize);
        let preview = service
            .preview(&proof, support::valid_incident(), harness.observed_now())
            .unwrap();
        assert!(
            service
                .finalize(
                    &proof,
                    support::valid_incident(),
                    &preview,
                    harness.observed_now()
                )
                .is_err()
        );
    }
    assert!(harness.prepared_marker_is_present());
    assert!(harness.draft_dek_entry_is_absent());
    let before = harness.published_archive_bytes();
    assert_eq!(harness.published_entry_paths().len(), 1);
    harness.reopen_store();
    harness
        .database()
        .execute("DROP TRIGGER fail_original_publication", &[])
        .unwrap();
    let source = harness.source();
    assert!(matches!(
        harness.service(&source).recover_pending().unwrap(),
        ea_writer::RecoveryOutcome::CommittedFromPreparedBytes { .. }
    ));
    assert_eq!(harness.published_archive_bytes(), before);
    assert_eq!(
        harness
            .database()
            .query_row("SELECT COUNT(*) FROM writer_original_published", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
}

#[test]
fn original_identity_requires_its_retained_number_source() {
    let mut harness = WriterHarness::with_variant(LineVariantV1 {
        recovery_recipient_openable: true,
        ..LineVariantV1::default()
    });
    let reference = original(&harness);
    harness
        .database()
        .execute("DELETE FROM incident_number_register", &[])
        .unwrap();
    harness.select_sequence(1);
    let source = harness.source();
    assert!(matches!(
        harness.service(&source).prepare_amendment(
            reference,
            content(),
            &harness.anchor(),
            harness.observed_now()
        ),
        Err(WriterError::OriginalIdentityMismatch)
    ));
}

#[test]
fn amendment_reopen_after_irreversible_boundary_finishes_the_same_prepared_entry() {
    let mut harness = WriterHarness::with_variant(LineVariantV1 {
        recovery_recipient_openable: true,
        ..LineVariantV1::default()
    });
    let reference = original(&harness);
    let original_before = harness
        .published_entry(reference.original_entry_hash)
        .exact_bytes()
        .as_bytes()
        .to_vec();
    harness.select_sequence(1);
    let (exact, hash) = {
        let source = harness.source();
        let service = harness.service(&source);
        let input = service
            .prepare_amendment(
                reference,
                content(),
                &harness.anchor(),
                harness.observed_now(),
            )
            .unwrap();
        let proof = harness.proof_for(ReauthPurpose::Finalize);
        let reached = service
            .finalize_amendment_interrupted_at(
                &proof,
                input,
                harness.observed_now(),
                ea_writer::FinalizationFaultPoint::AfterAbsenceConfirmation,
            )
            .unwrap();
        (
            reached.entry_bytes().to_vec(),
            reached.prepared().unwrap().entry_hash(),
        )
    };
    harness.reopen_store();
    let source = harness.source();
    assert!(matches!(
        harness.service(&source).recover_pending().unwrap(),
        ea_writer::RecoveryOutcome::CommittedFromPreparedBytes { .. }
    ));
    assert_eq!(
        harness.published_entry(hash).exact_bytes().as_bytes(),
        exact
    );
    assert_eq!(
        harness
            .published_entry(reference.original_entry_hash)
            .exact_bytes()
            .as_bytes(),
        original_before
    );
    assert_eq!(
        harness
            .database()
            .query_row("SELECT COUNT(*) FROM writer_original_published", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
}

#[test]
fn original_source_never_substitutes_for_signed_archive_verification() {
    let mut harness = WriterHarness::with_variant(LineVariantV1 {
        recovery_recipient_openable: true,
        ..LineVariantV1::default()
    });
    let reference = original(&harness);
    let original_before = harness
        .published_entry(reference.original_entry_hash)
        .exact_bytes()
        .as_bytes()
        .to_vec();
    let path = harness
        .backend()
        .relative_paths_below_for_test(ea_archive::REGISTRY_EVENTS_DIR_V1)
        .into_iter()
        .next()
        .unwrap();
    let mut altered = harness.backend().read_for_test(&path).unwrap();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    harness.backend().overwrite_for_test(&path, &altered);
    harness.select_sequence(1);
    let source = harness.source();
    assert!(matches!(
        harness.service(&source).prepare_amendment(
            reference,
            content(),
            &harness.anchor(),
            harness.observed_now()
        ),
        Err(WriterError::OriginalArchiveUnverified)
    ));
    assert_eq!(
        harness
            .published_entry(reference.original_entry_hash)
            .exact_bytes()
            .as_bytes(),
        original_before
    );
}

#[test]
fn changed_amendment_content_cannot_use_the_previous_confirmation() {
    let mut harness = WriterHarness::with_variant(LineVariantV1 {
        recovery_recipient_openable: true,
        ..LineVariantV1::default()
    });
    let reference = original(&harness);
    harness.select_sequence(1);
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ReauthPurpose::Finalize);
    let now = harness.observed_now();
    let preview = service
        .preview_amendment(
            &proof,
            service
                .prepare_amendment(reference, content(), &harness.anchor(), now)
                .unwrap(),
            now,
        )
        .unwrap();
    let mut changed = content();
    changed.reason = "Andere Begründung".into();
    let input = service
        .prepare_amendment(reference, changed, &harness.anchor(), now)
        .unwrap();
    assert!(matches!(
        service.finalize_amendment(&proof, input, &preview, now),
        Err(WriterError::StaleAckPreviewMismatch)
    ));
    assert_eq!(harness.published_entry_paths().len(), 1);
}
