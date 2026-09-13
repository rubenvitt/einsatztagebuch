use super::*;

#[test]
#[ignore = "requires authentic portable source and native Ubuntu completion artifact"]
fn native_recovery_readiness_observes_durable_signed_floor_after_issuance() {
    let export=PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let completed_path=PathBuf::from(std::env::var_os("EA_T9_COMPLETED_REPORT").unwrap());
    let target:Value=serde_json::from_slice(&fs::read(export.join("target-context.json")).unwrap()).unwrap();
    let installed=RecoveryInstallation::with_target(Some(&target));
    let inventory=KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let exact_source=fs::read(export.join("source-envelope.cbor")).unwrap();
    let exact_report=fs::read(completed_path).unwrap();
    // The independent Source fixture anchor predates the imported scope.
    let anchor=ea_recovery::load_trust_anchor(&installed.anchor).unwrap();
    let source=ea_recovery::FsArchiveSource::open(&export.join("archive")).unwrap();
    let scope=ea_recovery::verify_recovery_source(&exact_source,&source,&anchor,&inventory,support::live_clock()).unwrap();
    assert_eq!(&scope.core().fields().source_machine,ea_key_provider::measure_native_machine_identity().unwrap().fingerprint().as_bytes());
    let native=NativeOperatorProvider::open_test_fixture(installed.directory.path().join("ea-native-operator"),false).unwrap();
    assert_eq!(&scope.core().fields().source_installation,native.installation_id().as_bytes());
    let provider=native.signing_provider(ea_admin::native_provider::NativeSigningSlot::Admin);
    let phrase=ea_recovery::read_secret_file(&export.join("backup.passphrase")).unwrap();
    let key=scope.core().fields().kdf.derive(&phrase).unwrap();
    let restored=installed.directory.path().join("snapshot-restored-source.sqlite");
    let db=EncryptedDatabase::restore_with_backup_key(
        &export.join("snapshot.db"),scope.core().fields().snapshot_hash,scope.core().fields().migrations_hash,&key,&restored,
        &provider,&provider.handle(SecretPurpose::LocalDatabaseKey),
    ).unwrap();
    assert_eq!(db.query_row("SELECT operator_subject_id FROM operator_profile",&[]).unwrap().unwrap().blob(0).unwrap(),&[0x42;16]);
    assert_eq!(db.query_row("SELECT count(*) FROM recovery_test_report",&[]).unwrap().unwrap().integer(0).unwrap(),0);
    drop(db); drop(key);drop(provider);drop(native);
    let config_path=installed.directory.path().join("source-import-operator.json");
    let original_archive=installed.directory.path().join("snapshot-restored-original-archive");
    copy_public_tree(&export.join("archive"),&original_archive);
    let mut config:Value=serde_json::from_slice(&fs::read(&installed.config).unwrap()).unwrap();
    config["database_path"]=json!("snapshot-restored-source.sqlite");
    config["archive_directory"]=json!("snapshot-restored-original-archive");
    write_private(&config_path,&serde_json::to_vec(&config).unwrap());
    let open=|| {
        let native=NativeOperatorProvider::open_test_fixture(installed.directory.path().join("ea-native-operator"),false).unwrap();
        let host=Arc::from(ea_key_provider::SupportMatrixRow::current_host().unwrap().posture_provider());
        let runtime=OperatorRuntime::open_with_test_native_and_posture(OperatorRuntimeConfig::load(&config_path).unwrap(),&installed.anchor,support::live_clock(),false,native,host).unwrap();
        if runtime.posture_admission().is_err() {
            let target=runtime.posture_target_context().unwrap();
            let document=runtime.issue_posture_document(&target,ea_crypto::object_hash(b"T9 isolated Source import prerequisites"),300_000).unwrap();
            runtime.import_posture_document(&document).unwrap();
        }
        RecoveryTestRuntime::new(runtime,installed.profile.clone()).unwrap()
    };
    assert_eq!(ea_recovery::recovery_archive_inventory_hash(&ea_recovery::FsArchiveSource::open(&original_archive).unwrap()).unwrap(),scope.core().fields().archive_inventory_hash, "the import witness must use the actual signed original archive bytes");
    let mut runtime=open();
    assert!(runtime.fresh_machine_recovery_proof(&inventory).is_err());
    let mut tampered=exact_report.clone();let last=tampered.len()-1;tampered[last]^=1;
    assert!(runtime.import_completed_report(&inventory,&exact_source,&tampered).is_err());
    assert_eq!(runtime.runtime().database().query_row("SELECT count(*) FROM recovery_test_report",&[]).unwrap().unwrap().integer(0).unwrap(),0);
    let imported=runtime.import_completed_report(&inventory,&exact_source,&exact_report).unwrap();
    let hash=imported.envelope_hash();
    drop(runtime);
    let mut reopened=open();
    let report=reopened.read_imported_completed_report(&inventory).unwrap().unwrap();
    assert!(report.envelope_hash()==hash);
    assert_eq!(report.exact_envelope(),exact_report);

    use ea_trust::*;
    let cert = reopened.runtime().head().active_certificates()
        .find(|(_,c)|c.certificate_kind==CertificateKindV1::ServerReceipt).unwrap().0;
    let policy = reopened.runtime().head().policy_object_hash();
    let device = reopened.runtime().head().active_certificate_fields(reopened.runtime().config().device_certificate_hash).unwrap().device_id;
    let key = TrustStateKey { organization_id:anchor.organization_id(),device_id:device };
    let mut store = reopened.runtime().trust_store().clone();
    let archive=ea_archive::ArchiveInventory::build(&ea_recovery::FsArchiveSource::open(&original_archive).unwrap()).unwrap();
    let due=report.next_due_at();
    let proof=reopened.fresh_machine_recovery_proof(&inventory).unwrap();
    assert!(proof.is_current(), "authentic imported native report must first mint a current proof");
    let trust=verify_trust(&anchor,&archive,load_trust_state(&mut store,key).unwrap()).unwrap();
    let candidate=verify_registry_candidate(&trust,ChainSequence::new(1)).unwrap();
    let old_pin=*trust.pinned_head().unwrap();
    let floor=UnixMillis::new(due.get()+1);
    let signer=ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(trust_support::device_signing_secret()));
    let core=ea_format::ReceiptCoreV1::new(ea_format::ReceiptCoreFieldsV1{
        organization_id:anchor.organization_id(),chain_id:anchor.chain_id(),chain_sequence:ChainSequence::new(1),
        entry_hash:anchor.genesis_entry_hash(),entry_object_hash:ObjectHash::try_from(&[0x11;32][..]).unwrap(),
        previous_entry_hash:Some(anchor.genesis_entry_hash()),registry_version:old_pin.registry_version(),
        registry_head_hash:Hash32::try_from(old_pin.registry_head_hash().as_bytes().as_slice()).unwrap(),
        policy_object_hash:policy,initial_grant_plan_hash:Hash32::try_from(&[0x12;32][..]).unwrap(),
        initial_grant_object_hashes:vec![ObjectHash::try_from(&[0x13;32][..]).unwrap()],accepted_at_server:floor,
        evidence_due_at:None,server_key_thumbprint:signer.public_key().unwrap().thumbprint(),server_certificate_hash:cert,
    }).unwrap();
    let signature=signer.sign_receipt(core.exact_bytes()).unwrap();
    let exact=ea_format::encode_receipt(&ea_format::ReceiptV1::new(core,signature).unwrap()).unwrap();
    let ea_format::ParsedArchiveObject::Receipt(receipt)=ea_format::decode_exact_object(exact.as_bytes()).unwrap() else{panic!("receipt")};
    let verified=verify_receipt_time(candidate.preexisting_authority().unwrap(),&receipt).unwrap();
    drop(prepare_local_time(&mut store,&candidate,support::live_clock(),&[verified]).unwrap());
    let durable=load_trust_state(&mut store,key).unwrap();
    assert_eq!(durable.trusted_time().floor().get(),floor.get());
    assert!(durable.pinned_head().unwrap().registry_head_hash()==old_pin.registry_head_hash());
    assert!(!proof.is_current(),"a retained live FreshMachineRecoveryProof must observe the newer signed durable floor beyond report.nextDueAt");
}
