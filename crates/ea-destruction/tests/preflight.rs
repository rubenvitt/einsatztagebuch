#[path = "preflight/pending_deadline.rs"]
mod pending_deadline;
#[path = "preflight/remaining_states.rs"]
mod remaining_states;
pub mod support;
use archive_support::archive_support::trust_support as trust;
use ea_destruction::*;
use ea_format::*;
use ea_operator::ReauthPurpose;
use ea_types::*;
pub use support::verify_support as archive_support;
use support::{Account, RequestFixture, select_verified};

pub struct LocalEvidenceFixture {
    pub native: RequestFixture,
    pub original: archive_support::destruction_v12::OriginalFixture,
    pub backend: ea_archive_fs::LocalPathBackend,
    pub head: ea_trust::SelectedRegistryHead,
    pub evidence: VerifiedDestructionEvidence,
}
pub fn local_evidence_fixture() -> LocalEvidenceFixture {
    run_local_scenario(None, false, None).unwrap()
}

#[test]
fn signed_preflight_comes_from_complete_exact_original_archive_and_native_request() {
    run_local_scenario(None, false, None);
}

#[test]
fn local_removal_resumes_after_every_durable_boundary_with_same_job() {
    use LocalDestructionCheckpoint::*;
    for point in [
        BeforeStubCreate,
        StubCreated,
        StubFileFlushed,
        StubDirectoryFlushed,
        StubVerified,
        BeforeRemove,
        Removed,
        FinalScan,
        MeasurementCommitted,
    ] {
        run_local_scenario(Some(point), false, None);
    }
}

#[test]
fn local_cleanup_refuses_changed_registered_original_bytes_before_removing_anything() {
    run_local_scenario(None, true, None);
}

#[test]
fn acquisition_purge_rolls_back_permits_sources_and_tokens_at_every_transaction_boundary() {
    use AcquisitionPurgeCheckpoint::*;
    for point in [
        TokenRetained,
        PermitsInserted,
        SourceDeleted,
        PermitsRemoved,
        Committed,
        Compacted,
    ] {
        run_local_scenario(None, false, Some(point));
    }
}

#[test]
fn historical_pending_requires_all_immediately_removable_replica_duties() {
    run_local_scenario_with_probe(
        None,
        false,
        None,
        Some(remaining_states::Probe::PendingMissingDuty),
    );
}

#[test]
fn historical_late_exact_reader_claim_preserves_failure_and_allows_recovery() {
    run_local_scenario_with_probe(
        None,
        false,
        None,
        Some(remaining_states::Probe::LateOriginal),
    );
}

fn run_local_scenario(
    crash: Option<LocalDestructionCheckpoint>,
    corrupt: bool,
    purge_crash: Option<AcquisitionPurgeCheckpoint>,
) -> Option<LocalEvidenceFixture> {
    run_local_scenario_with_probe(crash, corrupt, purge_crash, None)
}

fn run_local_scenario_with_probe(
    crash: Option<LocalDestructionCheckpoint>,
    corrupt: bool,
    purge_crash: Option<AcquisitionPurgeCheckpoint>,
    remaining_probe: Option<remaining_states::Probe>,
) -> Option<LocalEvidenceFixture> {
    run_local_scenario_with_probes(crash, corrupt, purge_crash, remaining_probe, None)
}

fn run_local_scenario_with_probes(
    crash: Option<LocalDestructionCheckpoint>,
    corrupt: bool,
    purge_crash: Option<AcquisitionPurgeCheckpoint>,
    remaining_probe: Option<remaining_states::Probe>,
    pending_deadline_probe: Option<pending_deadline::Probe>,
) -> Option<LocalEvidenceFixture> {
    let mut writer_evidence = None;
    let mut original = archive_support::destruction_v12::OriginalFixture::new(
        archive_support::COMPLETE_PLAINTEXT_V1,
    );
    let mut native = RequestFixture::new();
    let original_device = original.source();
    let original_device = ea_archive::ArchiveInventory::build(&original_device).unwrap();
    let original_writer = original_device.entries()[0]
        .value()
        .manifest()
        .fields()
        .writer_certificate_hash;
    let original_certificate = original_device
        .trust()
        .iter()
        .find(|value| value.object_hash().as_bytes() == original_writer.as_bytes())
        .unwrap();
    let DecodedTrustPayloadV1::AuthorizedDevice(original_certificate) =
        original_certificate.value().decoded_payload().unwrap()
    else {
        panic!("original Writer certificate");
    };
    let original_device = original_certificate.fields().device_id;
    let reader_device = original_device_from_kind(&original, CertificateKindV1::Reader);
    let reader_deletion = CertificateHash::from(
        original
            .line
            .push(
                trust::ActionSpec::Device {
                    kind: CertificateKindV1::DeletionAttest,
                    marker: 0x78,
                    effective_from: Some(1),
                },
                trust::HeadOptions {
                    effective_from: Some(1),
                    valid_through: Some(100),
                    device_id_override: Some(reader_device),
                    ..Default::default()
                },
            )
            .direct_object_hash
            .unwrap(),
    );
    let server_device = original_device_from_kind(&original, CertificateKindV1::ServerReceipt);
    let server_deletion = CertificateHash::from(
        original
            .line
            .push(
                trust::ActionSpec::Device {
                    kind: CertificateKindV1::DeletionAttest,
                    marker: 0x79,
                    effective_from: Some(1),
                },
                trust::HeadOptions {
                    effective_from: Some(1),
                    valid_through: Some(100),
                    device_id_override: Some(server_device),
                    ..Default::default()
                },
            )
            .direct_object_hash
            .unwrap(),
    );
    let replacement = CertificateHash::from(
        original
            .line
            .push(
                trust::ActionSpec::Device {
                    kind: CertificateKindV1::DeletionAttest,
                    marker: 0x75,
                    effective_from: Some(1),
                },
                trust::HeadOptions {
                    effective_from: Some(1),
                    valid_through: Some(100),
                    device_id_override: Some(original_device),
                    ..Default::default()
                },
            )
            .direct_object_hash
            .unwrap(),
    );
    let foreign_component = CertificateHash::from(
        original
            .line
            .push(
                trust::ActionSpec::Device {
                    kind: CertificateKindV1::DeletionAttest,
                    marker: 0x77,
                    effective_from: Some(1),
                },
                trust::HeadOptions {
                    effective_from: Some(1),
                    valid_through: Some(100),
                    ..Default::default()
                },
            )
            .direct_object_hash
            .unwrap(),
    );
    let local_profile =
        ea_archive::ArchiveBackendProfileV1::LocalPath(ea_archive::LocalPathProfileV1 {
            filesystem_row_id: "fixture-destruction-fs".into(),
            capability_test_vector_id: "cap-v1-destruction".into(),
        });
    original.line.push(
        trust::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: Some(1),
        },
        trust::HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            policy_allowed_archive_profile_hashes_override: Some(vec![
                local_profile.profile_hash().unwrap(),
            ]),
            ..Default::default()
        },
    );
    let inventory = ea_archive::ArchiveInventory::build(&original.source()).unwrap();
    let parsed = &inventory.entries()[0];
    native.certificate = parsed.value().manifest().fields().writer_certificate_hash;
    native.binding = original
        .line
        .push(
            trust::ActionSpec::OperatorBinding {
                certificate_hash: ObjectHash::try_from(native.certificate.as_bytes().as_slice())
                    .unwrap(),
                role: OperatorRoleV1::Writer,
                marker: 0x73,
                effective_from: Some(1),
            },
            trust::HeadOptions {
                effective_from: Some(1),
                valid_through: Some(100),
                binding_operator_profile_commitment_override: Some(writer_profile_commitment()),
                binding_instance_key_thumbprint_override: Some(
                    support::instance_key().thumbprint(),
                ),
                ..Default::default()
            },
        )
        .direct_object_hash
        .unwrap();
    let current = original.head();
    let select = |version, hash, seq, now| {
        let trust = original.line.verified_with_record(
            trust::Pin::Exact(version, hash),
            17,
            ea_time::TrustedTimeState::initial(UnixMillis::new(now)),
            trust::state_key(),
        );
        select_verified(&trust, version, hash, ChainSequence::new(seq), now).unwrap()
    };
    let head = select(current.version, current.object_hash, 1, 1000);
    let manifest = parsed.value().manifest().fields();
    let historical = select(
        manifest.registry_version,
        ObjectHash::try_from(manifest.registry_head_hash.as_slice()).unwrap(),
        0,
        200,
    );
    let authorization = original.authorization();
    let auth = verify_authorization(&authorization, &head).unwrap();
    let target = auth.verify_target(parsed.value(), &historical).unwrap();
    let payload = TrustPayloadV1::destruction_transition(DestructionTransitionFieldsV1 {
        destruction_id: auth.fields().destruction_id,
        destruction_authorization_object_hash: auth.object_hash(),
        event_id: EventId::try_from(&[0x67; 16][..]).unwrap(),
        previous_event_object_hash: None,
        from_state: None,
        to_state: 0,
        trigger_code: 0,
        executed_at: UnixMillis::new(1000),
    })
    .unwrap();
    let signature = trust::authorized_device_signer()
        .sign_destruction_transition_digest(
            original.deletion,
            payload.exact_digest_input(),
            &authorization,
        )
        .unwrap();
    let event = encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap()).unwrap();
    let proof = native.proof(&head, ReauthPurpose::Destruction);
    let audit = native.audit(&head, false, false);
    let repository = SqliteDestructionRepository::new(native.database.clone());
    let service = DestructionRequestService {
        head: &head,
        certificate: native.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &audit,
        repository: &repository,
    };
    let requested = service
        .request(&authorization, event.as_bytes(), &[target], &proof)
        .unwrap();
    let resumed = service
        .resume(requested.authorization(), &head, &proof)
        .unwrap();
    let custody = SqliteManagedCustody::new(native.database.clone());
    let backend = ea_archive_fs::LocalPathBackend::open(
        native.directory.join("archive"),
        local_profile.clone(),
        &ea_archive::BoundArchiveProfilePolicyV1::from_policy(head.policy_fields()),
    )
    .unwrap();
    for (path, bytes) in original.source().blobs() {
        let absolute = backend.root().join(path);
        std::fs::create_dir_all(absolute.parent().unwrap()).unwrap();
        std::fs::write(absolute, bytes).unwrap();
    }
    let staged_grant = backend.root().join(format!(
        "grants/nested/duplicate.eag{}",
        ea_archive::STAGING_SUFFIX_V1
    ));
    std::fs::create_dir_all(staged_grant.parent().unwrap()).unwrap();
    std::fs::write(&staged_grant, &original.initial_grant_bytes).unwrap();
    let registered = custody
        .observe_local_archive(&head, native.certificate, &backend)
        .unwrap();
    let reregistered = SqliteManagedCustody::new(native.reopen())
        .observe_local_archive(&head, native.certificate, &backend)
        .unwrap();
    assert!(registered.location_id() == reregistered.location_id());
    assert!(
        custody
            .observe_writer_archive(
                ea_trust::WriterRegistryHeadRef::from(&head),
                native.certificate,
                &backend
            )
            .unwrap()
            .location_id()
            == registered.location_id()
    );
    assert!(registered.profile_hash() == backend.profile_hash().unwrap());
    let second_backend = ea_archive_fs::LocalPathBackend::open(
        native.directory.join("archive-two"),
        local_profile.clone(),
        &ea_archive::BoundArchiveProfilePolicyV1::from_policy(head.policy_fields()),
    )
    .unwrap();
    for (path, bytes) in [
        ("entries/original.eip", &original.original_bytes),
        ("grants/original.eag", &original.initial_grant_bytes),
    ] {
        let absolute = second_backend.root().join(path);
        std::fs::create_dir_all(absolute.parent().unwrap()).unwrap();
        std::fs::write(absolute, bytes).unwrap();
    }
    custody
        .observe_local_archive(&head, native.certificate, &second_backend)
        .unwrap();
    let empty_backend = ea_archive_fs::LocalPathBackend::open(
        native.directory.join("archive-empty"),
        local_profile,
        &ea_archive::BoundArchiveProfilePolicyV1::from_policy(head.policy_fields()),
    )
    .unwrap();
    custody
        .observe_local_archive(&head, native.certificate, &empty_backend)
        .unwrap();
    let inventory = custody.freeze(&resumed).unwrap();
    let mut wire = minicbor::Decoder::new(inventory.exact_bytes());
    wire.array().unwrap();
    for _ in 0..5 {
        wire.skip().unwrap();
    }
    let mut holding_codes = std::collections::BTreeSet::new();
    for _ in 0..wire.array().unwrap().unwrap() {
        let mut record = minicbor::Decoder::new(wire.bytes().unwrap());
        record.array().unwrap();
        if record.u8().unwrap() == 2 {
            for _ in 0..7 {
                record.skip().unwrap();
            }
            holding_codes.insert(record.u8().unwrap());
        }
    }
    assert_eq!(
        holding_codes,
        std::collections::BTreeSet::from([1, 2]),
        "custody uses normative ObjectTypeV1 codes, not Rust discriminants"
    );
    let preflight = prepare_preflight(
        &resumed,
        &inventory,
        &original.source(),
        &original.anchor,
        original.deletion,
        &trust::authorized_device_signer(),
    )
    .unwrap();
    assert_eq!(preflight.target_count(), 1);
    assert_eq!(preflight.removal_object_hashes().len(), 2);
    assert!(preflight.report_json().contains("\"entryPackageCount\": 1"));
    assert!(!preflight.report_json().contains("runtimeMetadata"));
    verify_preflight(&preflight, &resumed, &inventory).unwrap();
    let verified_line = original.line.verified_with_record(
        trust::Pin::Exact(current.version, current.object_hash),
        17,
        ea_time::TrustedTimeState::initial(UnixMillis::new(1000)),
        trust::state_key(),
    );
    let jobs = SqliteDestructionJobs::new(native.database.clone());
    let durable = jobs
        .persist(&preflight, &resumed, &inventory, &verified_line)
        .unwrap();
    assert_eq!(
        durable.preflight().exact_core_bytes(),
        preflight.exact_core_bytes()
    );
    let replay = jobs
        .persist(&preflight, &resumed, &inventory, &verified_line)
        .unwrap();
    assert_eq!(
        replay.preflight().exact_signature_bytes(),
        preflight.exact_signature_bytes()
    );
    drop(jobs);
    let reopened = SqliteDestructionJobs::new(native.reopen());
    let loaded = reopened
        .load(&resumed, &inventory, &verified_line)
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.preflight().exact_inventory_bytes(),
        preflight.exact_inventory_bytes()
    );
    assert!(
        native
            .database
            .execute("UPDATE destruction_job SET exact_core=X'00'", &[])
            .is_err()
    );
    struct ServerStatus(Vec<u8>);
    impl ServerReservationPort for ServerStatus {
        fn read_current_status(
            &mut self,
            _: OrganizationId,
            _: DestructionId,
        ) -> Result<Vec<u8>, DestructionError> {
            Ok(self.0.clone())
        }
    }
    let mut status = ServerStatus(
        ea_sync_protocol::DestructionStatusResponseV1::new(
            auth.fields().destruction_id,
            0,
            auth.object_hash(),
            vec![],
            vec![],
        )
        .unwrap()
        .exact_bytes()
        .to_vec(),
    );
    let barrier = confirm_delivery_barrier(&auth, &mut status).unwrap();
    original.line.push(
        trust::ActionSpec::Revoke {
            target_kind: 2,
            object_hash: ObjectHash::try_from(original.deletion.as_bytes().as_slice()).unwrap(),
        },
        trust::HeadOptions {
            effective_from: Some(2),
            valid_through: Some(100),
            ..Default::default()
        },
    );
    let late_replacement = CertificateHash::from(
        original
            .line
            .push(
                trust::ActionSpec::Device {
                    kind: CertificateKindV1::DeletionAttest,
                    marker: 0x76,
                    effective_from: Some(2),
                },
                trust::HeadOptions {
                    effective_from: Some(2),
                    valid_through: Some(100),
                    ..Default::default()
                },
            )
            .direct_object_hash
            .unwrap(),
    );
    let advanced = original.head();
    let current_trust = original.line.verified_with_record(
        trust::Pin::Exact(advanced.version, advanced.object_hash),
        17,
        ea_time::TrustedTimeState::initial(UnixMillis::new(1001)),
        trust::state_key(),
    );
    let advanced_head = select_verified(
        &current_trust,
        advanced.version,
        advanced.object_hash,
        ChainSequence::new(2),
        1001,
    )
    .unwrap();
    let fresh_proof = native.proof(&advanced_head, ReauthPurpose::Destruction);
    let fresh_audit = native.audit(&advanced_head, false, false);
    let fresh_service = DestructionRequestService {
        head: &advanced_head,
        certificate: native.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &fresh_audit,
        repository: &repository,
    };
    let fresh_resumed = fresh_service.resume(&auth, &head, &fresh_proof).unwrap();
    let loaded = reopened
        .load(&fresh_resumed, &inventory, &current_trust)
        .expect("old authentic report survives its signer's later revocation")
        .unwrap();
    let payload = TrustPayloadV1::destruction_transition(DestructionTransitionFieldsV1 {
        destruction_id: auth.fields().destruction_id,
        destruction_authorization_object_hash: auth.object_hash(),
        event_id: EventId::try_from(&[0x68; 16][..]).unwrap(),
        previous_event_object_hash: Some(requested.event().object_hash()),
        from_state: Some(0),
        to_state: 1,
        trigger_code: 1,
        executed_at: UnixMillis::new(1001),
    })
    .unwrap();
    let late_signature = trust::authorized_device_signer()
        .sign_destruction_transition_digest(
            late_replacement,
            payload.exact_digest_input(),
            &authorization,
        )
        .unwrap();
    let late_event =
        encode_trust(&TrustObjectV1::new(payload.clone(), vec![late_signature]).unwrap()).unwrap();
    let signature = trust::authorized_device_signer()
        .sign_destruction_transition_digest(
            replacement,
            payload.exact_digest_input(),
            &authorization,
        )
        .unwrap();
    let start_event = encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap()).unwrap();
    let context = DestructionExecutionContext {
        resumed: &fresh_resumed,
        job: &loaded,
        custody: &inventory,
        barrier: &barrier,
        trust: &current_trust,
    };
    assert!(
        reopened
            .start_execution(
                &context,
                late_event.as_bytes(),
                &fresh_service,
                &fresh_proof
            )
            .is_err(),
        "later-first-active cert cannot extend the immutable v1 operation"
    );
    let failed_audit = native.audit(&advanced_head, false, true);
    let failing_service = DestructionRequestService {
        head: &advanced_head,
        certificate: native.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &failed_audit,
        repository: &repository,
    };
    let audit_count_before = native
        .database
        .query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    assert!(
        reopened
            .start_execution(
                &context,
                start_event.as_bytes(),
                &failing_service,
                &fresh_proof
            )
            .is_err()
    );
    let wrong_purpose = native.proof(&advanced_head, ReauthPurpose::RecoveryTest);
    assert!(
        reopened
            .start_execution(
                &context,
                start_event.as_bytes(),
                &fresh_service,
                &wrong_purpose
            )
            .is_err()
    );
    assert_eq!(
        native
            .database
            .query_row("SELECT count(*) FROM destruction_job_event", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    assert_eq!(
        native
            .database
            .query_row("SELECT count(*) FROM local_audit_event", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        audit_count_before
    );
    let started = reopened
        .start_execution(
            &context,
            start_event.as_bytes(),
            &fresh_service,
            &fresh_proof,
        )
        .unwrap();
    assert_eq!(started.event().fields().to_state, 1);
    assert!(started.job_hash() == ea_crypto::object_hash(preflight.exact_core_bytes()));
    let replay = reopened
        .start_execution(
            &context,
            start_event.as_bytes(),
            &fresh_service,
            &fresh_proof,
        )
        .unwrap();
    assert_eq!(started.exact_audit_bytes(), replay.exact_audit_bytes());
    let count = native
        .database
        .query_row("SELECT count(*) FROM destruction_job_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    assert_eq!(count, 1);
    let component_signer = trust::authorized_device_signer();
    assert_eq!(
        advanced_head
            .active_certificate_fields(replacement)
            .unwrap()
            .device_id
            .as_bytes(),
        advanced_head
            .active_certificate_fields(native.certificate)
            .unwrap()
            .device_id
            .as_bytes(),
        "local component must be certified for the actual registered Writer device"
    );
    let local = LocalDestructionExecution {
        backend: &backend,
        custody_certificate: native.certificate,
        component_certificate: replacement,
        signer: &component_signer,
    };
    let mut checkpoints = Vec::new();
    let wrong_signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([0x16; 32]));
    for (certificate, signer) in [
        (original.deletion, &component_signer),
        (foreign_component, &component_signer),
        (replacement, &wrong_signer),
    ] {
        let refused = LocalDestructionExecution {
            backend: &backend,
            custody_certificate: native.certificate,
            component_certificate: certificate,
            signer,
        };
        assert!(
            reopened
                .execute_local(
                    &context,
                    &started,
                    &fresh_service,
                    &fresh_proof,
                    &refused,
                    &mut |_| Ok(())
                )
                .is_err()
        );
    }
    assert!(
        reopened
            .execute_local(
                &context,
                &started,
                &fresh_service,
                &wrong_purpose,
                &local,
                &mut |_| Ok(())
            )
            .is_err()
    );
    assert!(backend.root().join("entries/original.eip").exists());
    assert!(backend.root().join("grants/original.eag").exists());
    if corrupt {
        std::fs::write(
            backend.root().join("entries/original.eip"),
            b"corrupted managed original",
        )
        .unwrap();
        assert!(
            reopened
                .execute_local(
                    &context,
                    &started,
                    &fresh_service,
                    &fresh_proof,
                    &local,
                    &mut |_| Ok(())
                )
                .is_err(),
            "changed registered original must not disappear from the remaining-data measurement"
        );
        assert!(
            backend.root().join("grants/original.eag").exists(),
            "failed preflight removes no grant"
        );
        assert_eq!(
            native
                .database
                .query_row("SELECT count(*) FROM destruction_local_measurement", &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap(),
            0
        );
        return None;
    }
    if let Some(crash) = crash {
        let mut interrupted = false;
        assert!(
            reopened
                .execute_local(
                    &context,
                    &started,
                    &fresh_service,
                    &fresh_proof,
                    &local,
                    &mut |point| {
                        if point == crash && !interrupted {
                            interrupted = true;
                            return Err(DestructionError::Storage);
                        }
                        Ok(())
                    }
                )
                .is_err()
        );
        assert!(interrupted, "checkpoint {crash:?} was reached");
        if matches!(
            crash,
            LocalDestructionCheckpoint::BeforeStubCreate
                | LocalDestructionCheckpoint::StubCreated
                | LocalDestructionCheckpoint::StubFileFlushed
                | LocalDestructionCheckpoint::StubDirectoryFlushed
                | LocalDestructionCheckpoint::StubVerified
                | LocalDestructionCheckpoint::BeforeRemove
        ) {
            assert!(backend.root().join("entries/original.eip").exists());
            assert!(backend.root().join("grants/original.eag").exists());
        }
        let receipts = native
            .database
            .query_row("SELECT count(*) FROM destruction_local_measurement", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap();
        assert_eq!(
            receipts,
            i64::from(crash == LocalDestructionCheckpoint::MeasurementCommitted)
        );
        // A new SQLCipher connection reconstructs the durable old pre-state
        // after a partial physical removal, without requesting original EIP.
        let restarted = SqliteDestructionJobs::new(native.reopen());
        let restored = restarted
            .load(&fresh_resumed, &inventory, &current_trust)
            .unwrap()
            .unwrap();
        assert_eq!(
            restored.preflight().exact_core_bytes(),
            loaded.preflight().exact_core_bytes()
        );
    }
    let measured = reopened
        .execute_local(
            &context,
            &started,
            &fresh_service,
            &fresh_proof,
            &local,
            &mut |point| {
                checkpoints.push(point);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(measured.removed_object_hashes().len(), 2);
    assert!(checkpoints.contains(&LocalDestructionCheckpoint::StubVerified));
    assert!(!backend.root().join("entries/original.eip").exists());
    assert!(!backend.root().join("grants/original.eag").exists());
    assert!(
        !staged_grant.exists(),
        "a staging duplicate remains inside managed scope"
    );
    let stored_stub = backend.root().join(format!(
        "destroyed-entries/{}.eds",
        hex::encode(original.entry_hash.as_bytes())
    ));
    assert!(stored_stub.exists());
    for exact in [
        auth.exact_bytes(),
        requested.event().exact_bytes(),
        started.event().exact_bytes(),
    ] {
        let path = backend.root().join(format!(
            "destructions/{}.etb",
            hex::encode(ea_crypto::object_hash(exact).as_bytes())
        ));
        assert_eq!(
            std::fs::read(path)
                .expect("local .eds has durable exact authorization and event history"),
            exact
        );
    }
    let replay_measurement = reopened
        .execute_local(
            &context,
            &started,
            &fresh_service,
            &fresh_proof,
            &local,
            &mut |_| Ok(()),
        )
        .unwrap();
    assert_eq!(measured.exact_bytes(), replay_measurement.exact_bytes());
    if crash.is_none() {
        seed_acquisition_sources(&native, &original, auth.fields().organization_id);
        // A permit is a complete OLD-tuple match, never a table-wide flag.
        native.database.execute("INSERT INTO destruction_identity_purge_permit SELECT entry_hash,object_hash,record_id,sequence+1,organization_id,civil_year,incident_number FROM writer_original_identity WHERE entry_hash=?1",&[ea_local_store::StoreValue::Blob(original.entry_hash.as_bytes().to_vec())]).unwrap();
        assert!(
            native
                .database
                .execute(
                    "DELETE FROM writer_original_identity WHERE entry_hash=?1",
                    &[ea_local_store::StoreValue::Blob(
                        original.entry_hash.as_bytes().to_vec()
                    )]
                )
                .is_err()
        );
        assert!(
            reopened
                .purge_local_acquisition(&context, &started, &fresh_service, &fresh_proof, &local)
                .is_err(),
            "preexisting permits cannot authorize a new invocation"
        );
        native
            .database
            .execute("DELETE FROM destruction_identity_purge_permit", &[])
            .unwrap();
        if let Some(crash) = purge_crash {
            let mut interrupted = false;
            assert!(
                reopened
                    .purge_local_acquisition_with_progress(
                        &context,
                        &started,
                        &fresh_service,
                        &fresh_proof,
                        &local,
                        &mut |point| {
                            if point == crash {
                                interrupted = true;
                                return Err(DestructionError::Storage);
                            }
                            Ok(())
                        }
                    )
                    .is_err()
            );
            assert!(interrupted, "purge checkpoint {crash:?} reached");
            let committed = matches!(
                crash,
                AcquisitionPurgeCheckpoint::Committed | AcquisitionPurgeCheckpoint::Compacted
            );
            assert_eq!(
                native
                    .database
                    .query_row("SELECT count(*) FROM writer_original_identity", &[])
                    .unwrap()
                    .unwrap()
                    .integer(0)
                    .unwrap(),
                if committed { 1 } else { 2 }
            );
            assert_eq!(
                native
                    .database
                    .query_row("SELECT count(*) FROM incident_number_retained_token", &[])
                    .unwrap()
                    .unwrap()
                    .integer(0)
                    .unwrap(),
                i64::from(committed)
            );
            assert_eq!(native.database.query_row("SELECT (SELECT count(*) FROM destruction_identity_purge_permit)+(SELECT count(*) FROM destruction_claim_purge_permit)",&[]).unwrap().unwrap().integer(0).unwrap(),0);
        }
        let purged = reopened
            .purge_local_acquisition(&context, &started, &fresh_service, &fresh_proof, &local)
            .unwrap();
        let replay = reopened
            .purge_local_acquisition(&context, &started, &fresh_service, &fresh_proof, &local)
            .unwrap();
        assert_eq!(purged.exact_bytes(), replay.exact_bytes());
        assert_eq!(
            native
                .database
                .query_row("SELECT count(*) FROM writer_original_identity", &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap(),
            1,
            "unrelated identity remains"
        );
        assert_eq!(
            native
                .database
                .query_row("SELECT count(*) FROM writer_original_published", &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap(),
            1
        );
        assert_eq!(
            native
                .database
                .query_row("SELECT count(*) FROM writer_incident_claim", &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap(),
            0
        );
        assert_eq!(
            native
                .database
                .query_row("SELECT count(*) FROM incident_number_retained_token", &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap(),
            1
        );
        let register = ea_draft::IncidentNumberRegister::new(native.database.clone());
        assert!(
            register
                .contains(auth.fields().organization_id, 2026, "target-Cafe\u{301}")
                .unwrap()
        );
        assert!(
            native
                .database
                .execute("DELETE FROM writer_original_identity", &[])
                .is_err(),
            "ordinary guards remain active"
        );
        assert!(
            reopened
                .attest_local_replica(
                    &context,
                    &started,
                    &fresh_service,
                    &fresh_proof,
                    std::slice::from_ref(&local)
                )
                .is_err(),
            "one cleaned directory does not attest the device"
        );
        assert!(second_backend.root().join("entries/original.eip").exists());
        let all_locations = [
            local,
            LocalDestructionExecution {
                backend: &second_backend,
                custody_certificate: native.certificate,
                component_certificate: replacement,
                signer: &component_signer,
            },
            LocalDestructionExecution {
                backend: &empty_backend,
                custody_certificate: native.certificate,
                component_certificate: replacement,
                signer: &component_signer,
            },
        ];
        if purge_crash.is_none() {
            use LocalAttestationCheckpoint::*;
            for fault in [
                LocationsMeasured,
                AcquisitionCompacted,
                Signed,
                BeforeStore,
                Stored,
            ] {
                let mut hit = false;
                assert!(
                    reopened
                        .attest_local_replica_with_progress(
                            &context,
                            &started,
                            &fresh_service,
                            &fresh_proof,
                            &all_locations,
                            &mut |point| {
                                if point == fault {
                                    hit = true;
                                    return Err(DestructionError::Storage);
                                }
                                Ok(())
                            }
                        )
                        .is_err()
                );
                assert!(hit, "attestation checkpoint {fault:?} reached");
                assert_eq!(
                    native
                        .database
                        .query_row("SELECT count(*) FROM destruction_local_attestation", &[])
                        .unwrap()
                        .unwrap()
                        .integer(0)
                        .unwrap(),
                    i64::from(fault == Stored)
                );
            }
        }
        let attested = reopened
            .attest_local_replica(
                &context,
                &started,
                &fresh_service,
                &fresh_proof,
                &all_locations,
            )
            .unwrap();
        assert_eq!(
            attested.fields().replica_kind,
            ManagedReplicaKind::Writer.code()
        );
        assert_eq!(attested.fields().replica_id, *original_device.as_bytes());
        assert_eq!(attested.fields().result, 0);
        assert_eq!(attested.fields().removed_object_hashes.len(), 2);
        assert!(!second_backend.root().join("entries/original.eip").exists());
        assert!(!second_backend.root().join("grants/original.eag").exists());
        let replay = SqliteDestructionJobs::new(native.reopen())
            .attest_local_replica(
                &context,
                &started,
                &fresh_service,
                &fresh_proof,
                &all_locations,
            )
            .unwrap();
        assert_eq!(attested.exact_bytes(), replay.exact_bytes());
        for local in &all_locations {
            let path = local.backend.root().join(format!(
                "destructions/{}.etb",
                hex::encode(attested.object_hash().as_bytes())
            ));
            assert_eq!(
                std::fs::read(path)
                    .expect("exact component attestation is durable in every local archive"),
                attested.exact_bytes()
            );
        }
        let evidence = reopened
            .project_evidence(&context, &started, std::slice::from_ref(&attested))
            .unwrap();
        assert_eq!(evidence.replicas().len(), inventory.known_replica_count());
        assert!(evidence.confirmed_entries() == [original.entry_hash]);
        assert_eq!(
            evidence
                .replicas()
                .iter()
                .filter(|(_, s)| matches!(s, EvidenceReplicaStatus::Successful(_)))
                .count(),
            1,
            "three locations are one attested device"
        );
        assert!(
            !evidence.all_managed_replicas_confirmed(),
            "known Reader remains in denominator"
        );
        let empty = reopened.project_evidence(&context, &started, &[]).unwrap();
        assert!(empty.confirmed_entries().is_empty());
        assert!(!empty.all_managed_replicas_confirmed());
        let auth_historical = ea_trust::verify_historical_registry_authority(
            &current_trust,
            head.registry_version(),
            head.registry_head_hash(),
            head.proposed_sequence(),
        )
        .unwrap();
        for change in [0, 1] {
            let mut fields = attested.fields().clone();
            if change == 0 {
                fields.removed_object_hashes.clear();
            } else {
                fields.replica_kind = ManagedReplicaKind::Reader.code();
            }
            let p = TrustPayloadV1::deletion_attestation(fields).unwrap();
            let signature = component_signer
                .sign_deletion_attestation_digest(
                    replacement,
                    p.exact_digest_input(),
                    auth.exact_bytes(),
                )
                .unwrap();
            let exact = encode_trust(&TrustObjectV1::new(p, vec![signature]).unwrap()).unwrap();
            let claim = verify_attestation_historical(
                exact.as_bytes(),
                &auth,
                &auth_historical,
                UnixMillis::new(1001),
            )
            .unwrap();
            assert!(
                reopened
                    .project_evidence(&context, &started, &[claim])
                    .is_err(),
                "partial hash coverage or wrong registered replica kind cannot unlock success"
            );
        }
        let upload = ea_sync_protocol::DestructionJobUploadV1::new(
            loaded.preflight().exact_core_bytes(),
            loaded.preflight().exact_signature_bytes(),
            loaded.preflight().exact_inventory_bytes(),
            loaded.preflight().certificate_hash(),
        )
        .unwrap();
        let target_authority = ea_trust::verify_historical_registry_authority(
            &current_trust,
            historical.registry_version(),
            historical.registry_head_hash(),
            historical.proposed_sequence(),
        )
        .unwrap();
        let imported = VerifiedImportedPreflight::verify(
            &upload,
            &auth,
            &auth_historical,
            &auth_historical,
            &[target_authority],
        )
        .unwrap();
        let pending_fields = DeletionAttestationFieldsV1 {
            destruction_id: auth.fields().destruction_id,
            destruction_authorization_object_hash: auth.object_hash(),
            replica_id: *reader_device.as_bytes(),
            replica_kind: ManagedReplicaKind::Reader.code(),
            removed_object_hashes: vec![],
            result: 1,
            backup_expiry_at: Some(UnixMillis::new(2000)),
            executed_at: UnixMillis::new(1001),
        };
        // Later historical verification is only for the explicit deadline
        // probes; all existing scenarios retain their original horizon.
        let historical_verification_now = UnixMillis::new(if pending_deadline_probe.is_some() {
            3000
        } else {
            2000
        });
        let signed_claim = |fields: DeletionAttestationFieldsV1, certificate| {
            let p = TrustPayloadV1::deletion_attestation(fields).unwrap();
            let sig = component_signer
                .sign_deletion_attestation_digest(
                    certificate,
                    p.exact_digest_input(),
                    auth.exact_bytes(),
                )
                .unwrap();
            let exact = encode_trust(&TrustObjectV1::new(p, vec![sig]).unwrap()).unwrap();
            verify_attestation_historical(
                exact.as_bytes(),
                &auth,
                &auth_historical,
                historical_verification_now,
            )
            .unwrap()
        };
        let claim = |fields| signed_claim(fields, reader_deletion);
        let pending = claim(pending_fields.clone());
        let mut removed_fields = pending_fields;
        removed_fields.result = 0;
        removed_fields.executed_at = UnixMillis::new(2000);
        let removed = claim(removed_fields);
        let transition = |from: u8, to: u8, prev: ObjectHash, time: i64, id: u8| {
            let p = TrustPayloadV1::destruction_transition(DestructionTransitionFieldsV1 {
                destruction_id: auth.fields().destruction_id,
                destruction_authorization_object_hash: auth.object_hash(),
                event_id: EventId::try_from(&[id; 16][..]).unwrap(),
                previous_event_object_hash: Some(prev),
                from_state: Some(from),
                to_state: to,
                trigger_code: if from == 4 && to == 1 {
                    5
                } else {
                    u64::from(to)
                },
                executed_at: UnixMillis::new(time),
            })
            .unwrap();
            let sig = component_signer
                .sign_destruction_transition_digest(
                    replacement,
                    p.exact_digest_input(),
                    auth.exact_bytes(),
                )
                .unwrap();
            let exact = encode_trust(&TrustObjectV1::new(p, vec![sig]).unwrap()).unwrap();
            verify_event_historical(
                exact.as_bytes(),
                &auth,
                &auth_historical,
                historical_verification_now,
            )
            .unwrap()
        };
        let backup = transition(1, 2, started.event().object_hash(), 1001, 0x81);
        let complete = transition(2, 3, backup.object_hash(), 2000, 0x82);
        let events = [
            requested.event().clone(),
            started.event().clone(),
            backup.clone(),
            complete,
        ];
        // These certified Reader/Server claims test historical reduction only;
        // this fixture does not pretend to execute the remote providers.
        let mut server_fields = attested.fields().clone();
        server_fields.replica_id = *server_device.as_bytes();
        server_fields.replica_kind = ManagedReplicaKind::SyncServer.code();
        server_fields.removed_object_hashes.clear();
        let p = TrustPayloadV1::deletion_attestation(server_fields).unwrap();
        let sig = component_signer
            .sign_deletion_attestation_digest(
                server_deletion,
                p.exact_digest_input(),
                auth.exact_bytes(),
            )
            .unwrap();
        let exact = encode_trust(&TrustObjectV1::new(p, vec![sig]).unwrap()).unwrap();
        let server = verify_attestation_historical(
            exact.as_bytes(),
            &auth,
            &auth_historical,
            UnixMillis::new(1001),
        )
        .unwrap();
        let claims = [
            attested.clone(),
            pending.clone(),
            removed.clone(),
            server.clone(),
        ];
        if let Some(probe) = remaining_probe {
            remaining_states::run(
                probe,
                remaining_states::Inputs {
                    job: &imported,
                    requested: requested.event(),
                    started: started.event(),
                    writer: &attested,
                    reader_pending: &pending,
                    server: &server,
                },
                &claim,
                &transition,
            );
        }
        if let Some(probe) = pending_deadline_probe {
            pending_deadline::run(
                probe,
                remaining_states::Inputs {
                    job: &imported,
                    requested: requested.event(),
                    started: started.event(),
                    writer: &attested,
                    reader_pending: &pending,
                    server: &server,
                },
                &transition,
                &|fields| signed_claim(fields, server_deletion),
                &claim,
            );
        }
        let mut premature_fields = removed.fields().clone();
        premature_fields.executed_at = UnixMillis::new(1999);
        premature_fields.backup_expiry_at = None;
        // A later success may not erase the earlier known retention deadline,
        // even when the proposed Complete event itself is at the deadline.
        let premature = claim(premature_fields);
        assert!(
            reconstruct_imported_history(
                &imported,
                &events,
                &[attested.clone(), pending.clone(), premature, server.clone()],
            )
            .is_err(),
            "removal before the known backup deadline cannot justify Complete"
        );
        let mut shortened_fields = pending.fields().clone();
        shortened_fields.executed_at = UnixMillis::new(1100);
        shortened_fields.backup_expiry_at = Some(UnixMillis::new(1500));
        let shortened = claim(shortened_fields);
        let mut premature_fields = removed.fields().clone();
        premature_fields.executed_at = UnixMillis::new(1600);
        premature_fields.backup_expiry_at = None;
        let premature = claim(premature_fields);
        let mut conflicting_deadlines = vec![
            attested.clone(),
            pending.clone(),
            shortened,
            premature,
            server.clone(),
        ];
        for _ in 0..2 {
            assert!(
                reconstruct_imported_history(&imported, &events, &conflicting_deadlines).is_err(),
                "later shorter backup bound cannot erase the known maximum"
            );
            conflicting_deadlines.reverse();
        }
        let mut simultaneous_fields = pending.fields().clone();
        // Both conflicts occur after Started, so only the later Complete sees
        // the newer success together with the older conflicting pair.
        simultaneous_fields.executed_at = UnixMillis::new(1100);
        let simultaneous_first = claim(simultaneous_fields.clone());
        simultaneous_fields.backup_expiry_at = Some(UnixMillis::new(1500));
        let simultaneous = claim(simultaneous_fields);
        let direct_complete = transition(1, 3, started.event().object_hash(), 2000, 0x91);
        let direct_events = [
            requested.event().clone(),
            started.event().clone(),
            direct_complete,
        ];
        let mut same_time_conflict = vec![
            attested.clone(),
            simultaneous_first,
            simultaneous,
            removed.clone(),
            server.clone(),
        ];
        for _ in 0..2 {
            assert!(
                reconstruct_imported_history(&imported, &direct_events, &same_time_conflict)
                    .is_err(),
                "different same-time claims must conflict even behind a newer first claim"
            );
            same_time_conflict.reverse();
        }
        let exact_replay = [
            attested.clone(),
            removed.clone(),
            pending.clone(),
            pending.clone(),
            server.clone(),
        ];
        assert!(
            reconstruct_imported_history(&imported, &direct_events, &exact_replay).is_ok(),
            "byte-identical old claim replay remains idempotent"
        );
        let rebuilt = reconstruct_imported_history(&imported, &events, &claims).unwrap();
        assert_eq!(rebuilt.state(), DestructionState::CompleteManagedScope);
        assert!(rebuilt.evidence().all_managed_replicas_confirmed());
        let early = transition(2, 3, backup.object_hash(), 1999, 0x83);
        assert!(
            reconstruct_imported_history(
                &imported,
                &[
                    requested.event().clone(),
                    started.event().clone(),
                    backup.clone(),
                    early
                ],
                &claims
            )
            .is_err(),
            "later signed actual removal cannot justify earlier Complete"
        );
        assert!(
            reconstruct_imported_history(
                &imported,
                &events,
                &[attested.clone(), pending.clone(), server.clone()]
            )
            .is_err(),
            "elapsed deadline alone is never actual deletion"
        );
        let mut shuffled = events.to_vec();
        shuffled.reverse();
        shuffled.push(events[0].clone());
        assert_eq!(
            reconstruct_imported_history(&imported, &shuffled, &claims)
                .unwrap()
                .state(),
            DestructionState::CompleteManagedScope
        );
        let direct = transition(1, 3, started.event().object_hash(), 2000, 0x84);
        assert_eq!(
            reconstruct_imported_history(
                &imported,
                &[requested.event().clone(), started.event().clone(), direct],
                &claims
            )
            .unwrap()
            .state(),
            DestructionState::CompleteManagedScope
        );
        let unreachable = transition(1, 4, started.event().object_hash(), 1001, 0x85);
        let available = [attested.clone(), server.clone()];
        assert_eq!(
            reconstruct_imported_history(
                &imported,
                &[
                    requested.event().clone(),
                    started.event().clone(),
                    unreachable.clone()
                ],
                &available
            )
            .unwrap()
            .state(),
            DestructionState::IncompleteUnreachableReplica
        );
        let retry = transition(4, 1, unreachable.object_hash(), 1002, 0x86);
        let retry_history = [
            requested.event().clone(),
            started.event().clone(),
            unreachable.clone(),
            retry.clone(),
        ];
        let historical_retry =
            reconstruct_imported_history(&imported, &retry_history, &available).unwrap();
        assert_eq!(historical_retry.state(), DestructionState::InProgress);
        // The signed historical assertion supplies no missing removal claim.
        assert_eq!(historical_retry.evidence().replicas().len(), 3);
        assert!(
            historical_retry
                .evidence()
                .replicas()
                .iter()
                .any(|(device, status)| {
                    device.as_bytes() == &pending.fields().replica_id
                        && *status == EvidenceReplicaStatus::Unreachable
                })
        );
        assert!(!historical_retry.evidence().all_managed_replicas_confirmed());
        remaining_states::assert_original_targets(historical_retry.evidence(), &imported);
        let premature_complete = transition(1, 3, retry.object_hash(), 2000, 0xa4);
        let mut completion_attempt = retry_history.to_vec();
        completion_attempt.push(premature_complete);
        assert!(reconstruct_imported_history(&imported, &completion_attempt, &available).is_err());

        let mut replay = retry_history.to_vec();
        replay.push(retry.clone());
        replay.reverse();
        let replayed = reconstruct_imported_history(&imported, &replay, &available).unwrap();
        assert_eq!(replayed.state(), historical_retry.state());
        assert!(replayed.last_event_hash() == historical_retry.last_event_hash());
        assert!(replayed.evidence().replicas() == historical_retry.evidence().replicas());
        // Distinct valid signatures still cannot fork the original operation.
        let mut fork = retry_history.to_vec();
        fork.push(transition(4, 1, unreachable.object_hash(), 1003, 0xa5));
        assert!(matches!(
            reconstruct_imported_history(&imported, &fork, &available),
            Err(DestructionError::SecurityConflict)
        ));
        // Reusing retry's ID on an otherwise correctly linked next event is
        // a different exact object, not idempotent replay.
        let mut reused_id = retry_history.to_vec();
        reused_id.push(transition(1, 4, retry.object_hash(), 1003, 0x86));
        assert!(matches!(
            reconstruct_imported_history(&imported, &reused_id, &available),
            Err(DestructionError::SecurityConflict)
        ));
        let mut wrong_previous = retry_history.to_vec();
        wrong_previous.push(transition(
            1,
            4,
            ObjectHash::try_from(&[0xee; 32][..]).unwrap(),
            1003,
            0xa6,
        ));
        assert!(matches!(
            reconstruct_imported_history(&imported, &wrong_previous, &available),
            Err(DestructionError::SecurityConflict)
        ));
        let mut reached_fields = pending.fields().clone();
        reached_fields.executed_at = UnixMillis::new(1002);
        let reached = claim(reached_fields);
        assert_eq!(
            reconstruct_imported_history(
                &imported,
                &[
                    requested.event().clone(),
                    started.event().clone(),
                    unreachable,
                    retry
                ],
                &[attested.clone(), server.clone(), reached]
            )
            .unwrap()
            .state(),
            DestructionState::InProgress
        );
        let mut failed_fields = pending.fields().clone();
        failed_fields.result = 2;
        failed_fields.executed_at = UnixMillis::new(1002);
        let failed = claim(failed_fields);
        let lost = transition(2, 4, backup.object_hash(), 1002, 0x87);
        assert_eq!(
            reconstruct_imported_history(
                &imported,
                &[
                    requested.event().clone(),
                    started.event().clone(),
                    backup,
                    lost
                ],
                &[attested.clone(), server, pending, failed]
            )
            .unwrap()
            .state(),
            DestructionState::IncompleteUnreachableReplica
        );
        writer_evidence = Some(evidence);
    }
    assert!(
        native
            .database
            .execute("DELETE FROM destruction_job", &[])
            .is_err()
    );
    let mut incomplete = archive_support::archive_support::ArchiveFixture::new();
    for (path, bytes) in original.source().blobs() {
        if path != "grants/original.eag" {
            incomplete.push_exact_bytes(path, bytes.clone());
        }
    }
    assert!(
        prepare_preflight(
            &resumed,
            &inventory,
            &incomplete,
            &original.anchor,
            original.deletion,
            &trust::authorized_device_signer()
        )
        .is_err()
    );
    writer_evidence.map(|evidence| {
        // The archive's actual next sequence is still1. The signed successor
        // effective2 is known but cannot grant Writer authority early. This
        // independently selected Writer fixture has not pinned that future head.
        let writer_trust = original.line.verified_with_record(
            trust::Pin::Exact(head.registry_version(), head.registry_head_hash()),
            17,
            ea_time::TrustedTimeState::initial(UnixMillis::new(1001)),
            trust::state_key(),
        );
        let writer_head = select_verified(
            &writer_trust,
            head.registry_version(),
            head.registry_head_hash(),
            ChainSequence::new(1),
            1001,
        )
        .unwrap();
        LocalEvidenceFixture {
            native,
            original,
            backend,
            head: writer_head,
            evidence,
        }
    })
}

fn writer_profile_commitment() -> Hash32 {
    let mut exact = Vec::new();
    minicbor::Encoder::new(&mut exact)
        .array(5)
        .unwrap()
        .bytes(trust::organization().as_bytes())
        .unwrap()
        .bytes(&[0x73; 16])
        .unwrap()
        .str("Destruction Writer")
        .unwrap()
        .str("Operator")
        .unwrap()
        .bytes(&[0x74; 32])
        .unwrap();
    ea_crypto::operator_profile_digest(&exact)
}

fn seed_acquisition_sources(
    native: &RequestFixture,
    original: &archive_support::destruction_v12::OriginalFixture,
    organization: OrganizationId,
) {
    use ea_local_store::StoreValue as V;
    // Same encrypted acquisition schema as the independently tested normal
    // Writer. These rows exercise target selection and guards, not issuance.
    for sql in [
        "CREATE TABLE IF NOT EXISTS writer_incident_claim (claim_id INTEGER PRIMARY KEY AUTOINCREMENT,draft_id BLOB NOT NULL,draft_revision INTEGER NOT NULL,organization_id BLOB NOT NULL,civil_year INTEGER NOT NULL,incident_number TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS writer_incident_claim_released (claim_id INTEGER PRIMARY KEY REFERENCES writer_incident_claim(claim_id))",
        "CREATE TABLE IF NOT EXISTS writer_original_identity (entry_hash BLOB PRIMARY KEY NOT NULL,object_hash BLOB NOT NULL,record_id BLOB NOT NULL,sequence INTEGER NOT NULL,organization_id BLOB NOT NULL,civil_year INTEGER NOT NULL,incident_number TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS writer_original_published (entry_hash BLOB PRIMARY KEY NOT NULL REFERENCES writer_original_identity(entry_hash))",
    ] {
        native.database.execute(sql, &[]).unwrap();
    }
    for table in [
        "writer_incident_claim",
        "writer_incident_claim_released",
        "writer_original_identity",
        "writer_original_published",
    ] {
        for operation in ["UPDATE", "DELETE"] {
            native.database.execute(&format!("CREATE TRIGGER IF NOT EXISTS {table}_no_{operation} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'append-only'); END"),&[]).unwrap();
        }
    }
    native
        .database
        .execute(
            "INSERT INTO writer_original_identity VALUES(?1,?2,?3,0,?4,2026,'target-Café')",
            &[
                V::Blob(original.entry_hash.as_bytes().to_vec()),
                V::Blob(
                    ea_crypto::object_hash(&original.original_bytes)
                        .as_bytes()
                        .to_vec(),
                ),
                V::Blob(vec![0x18; 16]),
                V::Blob(organization.as_bytes().to_vec()),
            ],
        )
        .unwrap();
    native
        .database
        .execute(
            "INSERT INTO writer_original_identity VALUES(?1,?2,?3,7,?4,2026,'unrelated')",
            &[
                V::Blob(vec![0x19; 32]),
                V::Blob(vec![0x20; 32]),
                V::Blob(vec![0x21; 16]),
                V::Blob(organization.as_bytes().to_vec()),
            ],
        )
        .unwrap();
    native
        .database
        .execute(
            "INSERT INTO writer_original_published SELECT entry_hash FROM writer_original_identity",
            &[],
        )
        .unwrap();
    native.database.execute("INSERT INTO writer_incident_claim(draft_id,draft_revision,organization_id,civil_year,incident_number) VALUES(?1,1,?2,2026,?3)",&[V::Blob(vec![0x22;16]),V::Blob(organization.as_bytes().to_vec()),V::Text("target-Cafe\u{301}".into())]).unwrap();
    native
        .database
        .execute(
            "INSERT INTO writer_incident_claim_released SELECT claim_id FROM writer_incident_claim",
            &[],
        )
        .unwrap();
    let register = ea_draft::IncidentNumberRegister::new(native.database.clone());
    register.claim(organization, 2026, "target-Café").unwrap();
    register.claim(organization, 2026, "unrelated").unwrap();
    assert!(
        native
            .database
            .execute("DELETE FROM writer_original_identity", &[])
            .is_err()
    );
}

fn original_device_from_kind(
    original: &archive_support::destruction_v12::OriginalFixture,
    kind: CertificateKindV1,
) -> DeviceId {
    ea_archive::ArchiveInventory::build(&original.source())
        .unwrap()
        .trust()
        .iter()
        .find_map(|object| match object.value().decoded_payload().unwrap() {
            DecodedTrustPayloadV1::AuthorizedDevice(cert)
                if cert.fields().certificate_kind == kind =>
            {
                Some(cert.fields().device_id)
            }
            _ => None,
        })
        .expect("fixture contains the requested real certificate")
}
