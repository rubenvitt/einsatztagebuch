use super::*;

#[test]
fn evidence_preview_refuses_an_existing_incident_draft_without_consuming_it() {
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
    let before = repository.load_or_create().unwrap();
    let id = before.draft_id();
    let saved = repository
        .save(before.with_notes("existing incident MUST survive"))
        .unwrap();
    let handle = repository.draft_dek_handle(&saved).unwrap();
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
    let proof = fixture
        .native
        .proof(&fixture.head, ea_operator::ReauthPurpose::Finalize);
    let result = service.preview_destruction_evidence(
        &proof,
        ea_writer::DestructionEvidenceInputV1 {
            timezone: "Europe/Berlin".into(),
            source: ea_schema::NativeSourceV1::new("ea.native", 1).unwrap(),
            evidence: fixture.evidence.clone(),
        },
        UnixMillis::new(1001),
    );
    assert!(
        result.is_err(),
        "evidence must not use the active incident draft"
    );
    let after = repository.load_or_create().unwrap();
    assert!(after.draft_id() == id);
    assert_eq!(after.notes(), "existing incident MUST survive");
    assert_eq!(after.revision(), saved.revision());
    assert!(provider.contains(&handle).unwrap());
    assert!(repository.prepared_finalization_marker().unwrap().is_none());
}

#[test]
fn evidence_reservation_survives_reopen_and_blocks_all_ordinary_draft_access() {
    let fixture = local_fixture::local_evidence_fixture();
    let provider = Arc::new(FixtureProvider {
        inner: InMemoryKeyProvider::new_for_test([0x32; 32]),
        deleted_draft: std::sync::atomic::AtomicBool::new(false),
    });
    let repository =
        AutosaveDraftRepository::new(fixture.native.database.clone(), provider.clone());
    let old = repository.load_or_create().unwrap();
    let id = old.draft_id();
    let row = fixture.native.database.query_row(
        "SELECT organization_id,destruction_id,authorization_hash,exact_core FROM destruction_job", &[]
    ).unwrap().unwrap();
    let source = ea_draft::EvidenceDraftSource::new(
        OrganizationId::try_from(row.blob(0).unwrap()).unwrap(),
        DestructionId::try_from(row.blob(1).unwrap()).unwrap(),
        ObjectHash::try_from(row.blob(2).unwrap()).unwrap(),
        ea_crypto::object_hash(row.blob(3).unwrap()),
    );
    let binding = repository
        .reserve_evidence_draft(source)
        .expect("a real started immutable job can reserve the empty draft");
    assert!(binding.draft_id() == id);
    drop(repository);
    let reopened = AutosaveDraftRepository::new(fixture.native.reopen(), provider);
    assert!(reopened.evidence_binding().unwrap() == Some(binding));
    assert!(
        reopened.load_or_create().is_err(),
        "WriterPage must not see an apparently blank Incident"
    );
    assert!(reopened.save(old.with_notes("late autosave")).is_err());
    assert!(reopened.prepared_finalization_marker().is_err());
    assert!(reopened.replace_with_blank().is_err());
    let exact = reopened.for_evidence_draft(binding).unwrap();
    assert!(exact.load_or_create().unwrap().notes().is_empty());
    let saved = exact.save(exact.load_or_create().unwrap()).unwrap();
    assert!(
        reopened.commit_discard_intent(&saved).is_err(),
        "ordinary discard cannot resolve a referenced Evidence"
    );
}

#[path = "../support/incident_input.rs"]
mod incident_input;
fn source_of(fixture: &local_fixture::LocalEvidenceFixture) -> ea_draft::EvidenceDraftSource {
    let row = fixture.native.database.query_row(
        "SELECT organization_id,destruction_id,authorization_hash,exact_core FROM destruction_job", &[]
    ).unwrap().unwrap();
    ea_draft::EvidenceDraftSource::new(
        OrganizationId::try_from(row.blob(0).unwrap()).unwrap(),
        DestructionId::try_from(row.blob(1).unwrap()).unwrap(),
        ObjectHash::try_from(row.blob(2).unwrap()).unwrap(),
        ea_crypto::object_hash(row.blob(3).unwrap()),
    )
}
#[test]
fn bound_evidence_draft_cannot_be_finalized_as_an_incident() {
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
    let before = repository.load_or_create().unwrap();
    let id = before.draft_id();
    let saved = repository.save(before).unwrap();
    let handle = repository.draft_dek_handle(&saved).unwrap();
    use ea_local_store::StoreValue as V;
    fixture.native.database.execute("INSERT INTO operator_profile(singleton,organization_id,operator_subject_id,display_name,function_label,profile_commitment_salt,operator_binding_object_hash) VALUES(0,?1,?2,?3,?4,?5,?6)",&[V::Blob(fixture.head.active_certificate_fields(fixture.native.certificate).unwrap().organization_id.as_bytes().to_vec()),V::Blob(vec![0x73;16]),V::Text("Destruction Writer".into()),V::Text("Operator".into()),V::Blob(vec![0x74;32]),V::Blob(fixture.native.binding.as_bytes().to_vec())]).unwrap();
    let binding = repository
        .reserve_evidence_draft(source_of(&fixture))
        .unwrap();
    let repository = Arc::new(repository.for_evidence_draft(binding).unwrap());
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
    let proof = fixture
        .native
        .proof(&fixture.head, ea_operator::ReauthPurpose::Finalize);
    let incident = incident_input::incident_numbered_at(
        incident_input::FIXTURE_INCIDENT_NUMBER,
        UnixMillis::new(1000),
    );
    let result = service.preview(&proof, incident, UnixMillis::new(1001));
    assert!(
        matches!(
            &result,
            Err(ea_writer::WriterError::Draft(
                ea_draft::DraftError::EvidenceBinding
            ))
        ),
        "a scoped repository must not turn an Evidence draft into an ordinary Incident; actual refusal: {:?}",
        result.as_ref().err().map(|error| error.code())
    );
    let after = repository.load_or_create().unwrap();
    assert!(after.draft_id() == id);
    assert!(after.notes().is_empty());
    assert_eq!(after.revision(), saved.revision());
    assert!(provider.contains(&handle).unwrap());
    assert!(repository.prepared_finalization_marker().unwrap().is_none());
}

#[test]
fn evidence_discard_uses_the_existing_irreversible_path_and_keeps_the_job() {
    let fixture = local_fixture::local_evidence_fixture();
    let provider = Arc::new(FixtureProvider {
        inner: InMemoryKeyProvider::new_for_test([0x32; 32]),
        deleted_draft: std::sync::atomic::AtomicBool::new(false),
    });
    let ordinary = Arc::new(AutosaveDraftRepository::new(
        fixture.native.database.clone(),
        provider.clone(),
    ));
    let binding = ordinary
        .reserve_evidence_draft(source_of(&fixture))
        .unwrap();
    let exact = Arc::new(ordinary.for_evidence_draft(binding).unwrap());
    let proof = || {
        fixture
            .native
            .proof(&fixture.head, ea_operator::ReauthPurpose::DiscardDraft)
    };
    let unbound = ea_draft::DiscardService::new(
        ordinary.clone(),
        provider.clone(),
        fixture.native.binding,
        fixture.head.preexisting_effective_now(),
    );
    assert!(matches!(
        unbound.begin_discard(proof()),
        Err(ea_draft::DraftError::EvidenceReserved)
    ));
    assert!(
        !provider
            .deleted_draft
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    let service = ea_draft::DiscardService::new(
        exact,
        provider.clone(),
        fixture.native.binding,
        fixture.head.preexisting_effective_now(),
    );
    service.begin_discard(proof()).unwrap();
    assert!(
        provider
            .deleted_draft
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    assert!(ordinary.evidence_binding().unwrap().is_none());
    assert!(ordinary.load_or_create().unwrap().draft_id() != binding.draft_id());
    assert_eq!(
        fixture
            .native
            .database
            .query_row("SELECT count(*) FROM destruction_job", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
}

#[test]
fn evidence_reservation_refuses_a_foreign_job_hash_and_existing_transition() {
    let fixture = local_fixture::local_evidence_fixture();
    let provider = Arc::new(FixtureProvider {
        inner: InMemoryKeyProvider::new_for_test([0x32; 32]),
        deleted_draft: std::sync::atomic::AtomicBool::new(false),
    });
    let repository =
        AutosaveDraftRepository::new(fixture.native.database.clone(), provider.clone());
    let draft = repository.load_or_create().unwrap();
    let id = draft.draft_id();
    let source = source_of(&fixture);
    let foreign = ea_draft::EvidenceDraftSource::new(
        source.organization_id(),
        source.destruction_id(),
        source.authorization_hash(),
        ea_crypto::object_hash(b"other preflight"),
    );
    assert!(matches!(
        repository.reserve_evidence_draft(foreign),
        Err(ea_draft::DraftError::EvidenceBinding)
    ));
    assert!(repository.evidence_binding().unwrap().is_none());
    assert!(repository.load_or_create().unwrap().draft_id() == id);
    let saved = repository.save(draft).unwrap();
    let intent = repository.commit_discard_intent(&saved).unwrap();
    assert!(matches!(
        repository.reserve_evidence_draft(source),
        Err(ea_draft::DraftError::EvidenceOccupied)
    ));
    assert!(repository.pending_discard().unwrap().unwrap().draft_id() == intent.draft_id());
    assert!(repository.evidence_binding().unwrap().is_none());
}

#[test]
fn missing_registered_evidence_table_cannot_reopen_a_reserved_slot_as_blank() {
    let fixture = local_fixture::local_evidence_fixture();
    let provider = Arc::new(FixtureProvider {
        inner: InMemoryKeyProvider::new_for_test([0x32; 32]),
        deleted_draft: std::sync::atomic::AtomicBool::new(false),
    });
    let ordinary = AutosaveDraftRepository::new(fixture.native.database.clone(), provider);
    ordinary
        .reserve_evidence_draft(source_of(&fixture))
        .unwrap();
    fixture
        .native
        .database
        .execute("DROP TABLE writer_evidence_draft", &[])
        .unwrap();
    assert!(
        ordinary.load_or_create().is_err(),
        "registered Evidence schema missing is corruption, not an unreserved empty draft"
    );
}
