use super::*;
#[test]
fn missing_publication_binding_cannot_publish_reserved_evidence() {
    let fixture = local_fixture::local_evidence_fixture();
    let provider = Arc::new(FixtureProvider {
        inner: InMemoryKeyProvider::new_for_test([0x32; 32]),
        deleted_draft: std::sync::atomic::AtomicBool::new(false),
    });
    let signing = provider
        .generate(
            SecretPurpose::WriterSigningKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let repository = Arc::new(AutosaveDraftRepository::new(
        fixture.native.database.clone(),
        provider.clone(),
    ));
    let draft = repository.load_or_create().unwrap();
    let saved = repository.save(draft).unwrap();
    let draft_key = repository.draft_dek_handle(&saved).unwrap();
    let binding = repository
        .reserve_evidence_draft(fixture.evidence.draft_source().unwrap())
        .unwrap();
    let repository = Arc::new(repository.for_evidence_draft(binding).unwrap());
    use ea_local_store::StoreValue as V;
    fixture.native.database.execute("INSERT INTO operator_profile(singleton,organization_id,operator_subject_id,display_name,function_label,profile_commitment_salt,operator_binding_object_hash) VALUES(0,?1,?2,?3,?4,?5,?6)",&[V::Blob(fixture.head.active_certificate_fields(fixture.native.certificate).unwrap().organization_id.as_bytes().to_vec()),V::Blob(vec![0x73;16]),V::Text("Destruction Writer".into()),V::Text("Operator".into()),V::Blob(vec![0x74;32]),V::Blob(fixture.native.binding.as_bytes().to_vec())]).unwrap();
    let source = fixture.backend.as_archive_source();
    let service = ea_writer::WriterService::new(
        repository.clone(),
        provider.clone(),
        &fixture.backend,
        &source,
        &fixture.head,
        &[],
        IncidentNumberRegister::new(fixture.native.database.clone()),
        OperatorProfileRepository::new(fixture.native.database.clone()),
        ea_writer::WriterBindingV1 {
            binding_object_hash: fixture.native.binding,
            writer_certificate_hash: fixture.native.certificate,
            writer_key_thumbprint: fixture
                .head
                .active_certificate_fields(fixture.native.certificate)
                .unwrap()
                .signing_key_thumbprint
                .unwrap(),
            writer_signing_handle: signing,
            chain_id: fixture.head.chain_id(),
            archive_profile_hash: fixture.backend.profile_hash().unwrap(),
        },
    );
    let input = || ea_writer::DestructionEvidenceInputV1 {
        timezone: "Europe/Berlin".into(),
        source: ea_schema::NativeSourceV1::new("ea.native", 1).unwrap(),
        evidence: fixture.evidence.clone(),
    };
    let proof = fixture
        .native
        .proof(&fixture.head, ea_operator::ReauthPurpose::Finalize);

    service
        .finalize_destruction_evidence_interrupted_at(
            &proof,
            input(),
            UnixMillis::new(1001),
            ea_writer::FinalizationFaultPoint::AfterAbsenceConfirmation,
        )
        .unwrap();
    assert!(!provider.contains(&draft_key).unwrap());
    fixture
        .native
        .database
        .execute("DROP TRIGGER writer_destruction_evidence_no_delete", &[])
        .unwrap();
    fixture
        .native
        .database
        .execute("DELETE FROM writer_destruction_evidence", &[])
        .unwrap();
    assert!(
        service.recover_pending().is_err(),
        "missing exact0021 binding must never publish bound Evidence"
    );
    assert!(repository.prepared_finalization_marker().unwrap().is_some());
}

#[test]
fn wrong_job_auth_or_preflight_cannot_consume_prepared_evidence() {
    let fixture = local_fixture::local_evidence_fixture();
    let provider = Arc::new(FixtureProvider {
        inner: InMemoryKeyProvider::new_for_test([0x32; 32]),
        deleted_draft: std::sync::atomic::AtomicBool::new(false),
    });
    let signing = provider
        .generate(
            SecretPurpose::WriterSigningKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let repository = Arc::new(AutosaveDraftRepository::new(
        fixture.native.database.clone(),
        provider.clone(),
    ));
    let draft = repository.load_or_create().unwrap();
    let saved = repository.save(draft).unwrap();
    let draft_key = repository.draft_dek_handle(&saved).unwrap();
    let binding = repository
        .reserve_evidence_draft(fixture.evidence.draft_source().unwrap())
        .unwrap();
    let repository = Arc::new(repository.for_evidence_draft(binding).unwrap());
    use ea_local_store::StoreValue as V;
    fixture.native.database.execute("INSERT INTO operator_profile(singleton,organization_id,operator_subject_id,display_name,function_label,profile_commitment_salt,operator_binding_object_hash) VALUES(0,?1,?2,?3,?4,?5,?6)",&[V::Blob(fixture.head.active_certificate_fields(fixture.native.certificate).unwrap().organization_id.as_bytes().to_vec()),V::Blob(vec![0x73;16]),V::Text("Destruction Writer".into()),V::Text("Operator".into()),V::Blob(vec![0x74;32]),V::Blob(fixture.native.binding.as_bytes().to_vec())]).unwrap();
    let source = fixture.backend.as_archive_source();
    let service = ea_writer::WriterService::new(
        repository.clone(),
        provider.clone(),
        &fixture.backend,
        &source,
        &fixture.head,
        &[],
        IncidentNumberRegister::new(fixture.native.database.clone()),
        OperatorProfileRepository::new(fixture.native.database.clone()),
        ea_writer::WriterBindingV1 {
            binding_object_hash: fixture.native.binding,
            writer_certificate_hash: fixture.native.certificate,
            writer_key_thumbprint: fixture
                .head
                .active_certificate_fields(fixture.native.certificate)
                .unwrap()
                .signing_key_thumbprint
                .unwrap(),
            writer_signing_handle: signing,
            chain_id: fixture.head.chain_id(),
            archive_profile_hash: fixture.backend.profile_hash().unwrap(),
        },
    );
    let input = || ea_writer::DestructionEvidenceInputV1 {
        timezone: "Europe/Berlin".into(),
        source: ea_schema::NativeSourceV1::new("ea.native", 1).unwrap(),
        evidence: fixture.evidence.clone(),
    };
    let proof = fixture
        .native
        .proof(&fixture.head, ea_operator::ReauthPurpose::Finalize);

    service
        .finalize_destruction_evidence_interrupted_at(
            &proof,
            input(),
            UnixMillis::new(1001),
            ea_writer::FinalizationFaultPoint::AfterAbsenceConfirmation,
        )
        .unwrap();
    assert!(!provider.contains(&draft_key).unwrap());

    let source = binding.source();
    for wrong in [
        ea_draft::EvidenceDraftSource::new(
            source.organization_id(),
            DestructionId::try_from(&[0xee; 16][..]).unwrap(),
            source.authorization_hash(),
            source.preflight_hash(),
        ),
        ea_draft::EvidenceDraftSource::new(
            source.organization_id(),
            source.destruction_id(),
            ObjectHash::try_from(&[0xee; 32][..]).unwrap(),
            source.preflight_hash(),
        ),
        ea_draft::EvidenceDraftSource::new(
            source.organization_id(),
            source.destruction_id(),
            source.authorization_hash(),
            ObjectHash::try_from(&[0xee; 32][..]).unwrap(),
        ),
    ] {
        assert!(service.recover_pending_for_evidence(wrong).is_err());
        assert!(repository.prepared_finalization_marker().unwrap().is_some());
    }
    assert!(matches!(
        service.recover_pending_for_evidence(source).unwrap(),
        ea_writer::RecoveryOutcome::CommittedFromPreparedBytes { .. }
    ));
}
