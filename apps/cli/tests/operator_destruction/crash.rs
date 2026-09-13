use super::*;
use ea_destruction::*;
use ea_operator::ReauthPurpose;
use ea_types::{ChainSequence, RegistryVersion};
fn open_role(f: &NativeDestructionFixture, admin: bool) -> OperatorRuntime {
    let (directory, config) = if admin {
        (&f.admin_directory, &f.admin_config)
    } else {
        (&f.writer_directory, &f.writer_config)
    };
    let native =
        NativeOperatorProvider::open_test_fixture(directory.join("ea-native-operator"), false)
            .unwrap();
    OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap()
}
#[test]
fn native_destruction_real_stub_flush_crash_reopens_normal_runtime_and_resumes() {
    let f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    runtime
        .start(
            requested.destruction_id,
            requested.preflight_hash.unwrap(),
            ea_admin::destruction_runtime::NativeDestructionDelivery::NoRegisteredServer,
        )
        .unwrap();
    drop(runtime);
    {
        let controller = open_role(&f, true);
        let custodian = open_role(&f, false);
        let session = controller
            .reauthenticate_for(ReauthPurpose::Destruction)
            .unwrap();
        let original = ea_trust::verify_historical_registry_authority(
            controller.trust(),
            controller.head().registry_version(),
            controller.head().registry_head_hash(),
            ChainSequence::new(1),
        )
        .unwrap();
        let auth = verify_authorization_historical(&f.authorization, &original).unwrap();
        let db = custodian.database().clone();
        let repository = SqliteDestructionRepository::new(db.clone());
        let audit = controller.audit_service();
        let native = DestructionRequestService {
            head: controller.head(),
            certificate: controller.config().device_certificate_hash,
            role: OperatorRoleV1::OrganizationAdmin,
            account: controller.native().as_ref(),
            audit: &audit,
            repository: &repository,
        };
        let resumed = native
            .resume_historical(&auth, &original, session.proof())
            .unwrap();
        let backend = ea_archive_fs::LocalPathBackend::open(
            f.archive.clone(),
            f.profile.clone(),
            &ea_archive::BoundArchiveProfilePolicyV1::from_policy(
                controller.head().policy_fields(),
            ),
        )
        .unwrap();
        let custody = SqliteManagedCustody::new(db.clone());
        let frozen = custody.freeze(&resumed).unwrap();
        let jobs = SqliteDestructionJobs::new(db.clone());
        let job = jobs
            .load(&resumed, &frozen, controller.trust())
            .unwrap()
            .unwrap();
        let row=db.query_row("SELECT exact_core,exact_signature,exact_inventory,signer_certificate_hash FROM destruction_job",&[]).unwrap().unwrap();
        let upload = ea_sync_protocol::DestructionJobUploadV1::new(
            row.blob(0).unwrap(),
            row.blob(1).unwrap(),
            row.blob(2).unwrap(),
            CertificateHash::try_from(row.blob(3).unwrap()).unwrap(),
        )
        .unwrap();
        let core = ea_crypto::decode_destruction_preflight_core(upload.core_bytes()).unwrap();
        let execution = ea_trust::verify_historical_registry_authority(
            controller.trust(),
            RegistryVersion::new(core.execution_registry),
            ObjectHash::try_from(core.execution_head.as_slice()).unwrap(),
            ChainSequence::new(core.execution_sequence),
        )
        .unwrap();
        let targets = preflight_target_contexts(&upload)
            .unwrap()
            .into_iter()
            .map(|route| {
                ea_trust::verify_historical_registry_authority(
                    controller.trust(),
                    route.registry,
                    route.head,
                    route.sequence,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let imported =
            VerifiedImportedPreflight::verify(&upload, &auth, &original, &execution, &targets)
                .unwrap();
        let catalog = ea_trust::verify_catalog_custody_authority(controller.trust()).unwrap();
        let barrier = confirm_no_registered_server(
            &auth,
            &original,
            controller.head(),
            &catalog,
            &imported,
            &frozen,
        )
        .unwrap();
        let context = DestructionExecutionContext {
            resumed: &resumed,
            job: &job,
            custody: &frozen,
            barrier: &barrier,
            trust: controller.trust(),
        };
        let event = db
            .query_row(
                "SELECT exact_event FROM destruction_job_event ORDER BY insertion_sequence LIMIT 1",
                &[],
            )
            .unwrap()
            .unwrap();
        let started = jobs
            .start_execution(&context, event.blob(0).unwrap(), &native, session.proof())
            .unwrap();
        let ea_recovery::ResolvedSigningKey::Software(signer) =
            ea_recovery::resolve_signing_key(&f.key_source).unwrap()
        else {
            panic!("protected fixture container")
        };
        let local = LocalDestructionExecution {
            backend: &backend,
            custody_certificate: f.writer_certificate,
            component_certificate: f.component,
            signer: &signer,
        };
        let result = jobs.execute_local(
            &context,
            &started,
            &native,
            session.proof(),
            &local,
            &mut |point| {
                if point == LocalDestructionCheckpoint::StubDirectoryFlushed {
                    Err(DestructionError::Storage)
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err(), "actual durable stub interruption");
        let inventory = ea_archive::ArchiveInventory::build(&backend.as_archive_source()).unwrap();
        assert_eq!(inventory.entries().len(), 1);
        assert_eq!(inventory.destroyed().len(), 1);
        assert_eq!(
            db.query_row("SELECT count(*) FROM destruction_local_measurement", &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap(),
            0
        );
    }
    // Ordinary production opening reconstructs the real dual-artifact state.
    // No alternate snapshot, projected source or special bootstrap is used.
    let mut reopened = f.runtime();
    reopened.unlock().unwrap();
    assert_eq!(
        reopened
            .status(requested.destruction_id)
            .unwrap()
            .state
            .code(),
        1
    );
    let completed = reopened
        .resume_local(
            requested.destruction_id,
            ea_admin::destruction_runtime::NativeDestructionDelivery::NoRegisteredServer,
        )
        .unwrap();
    assert!(
        completed
            .replicas
            .iter()
            .any(|replica| replica.attestation_hash.is_some())
    );
    drop(reopened);
    let mut reopened = f.runtime();
    reopened.unlock().unwrap();
    let status = reopened.status(requested.destruction_id).unwrap();
    assert!(
        status
            .replicas
            .iter()
            .any(|replica| replica.attestation_hash.is_some())
    );
}
