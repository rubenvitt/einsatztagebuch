mod native_archive_existing_component;
mod native_archive_registration;
mod native_archive_startup;
mod guided;
use super::*;
#[cfg(feature = "desktop-fixture")]
mod desktop;
#[cfg(feature = "desktop-fixture")]
mod desktop_portable;
#[cfg(all(feature = "pkcs11-fixture", unix))]
mod pkcs11;
use ea_admin::{
    native_provider::NativeOperatorProvider,
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig},
    recovery_test_runtime::{RecoverySourceCapture, RecoveryTestRuntime},
};
use ea_crypto::SecretVec;
use ea_recovery::{KeyInventory, RecoveryKeyRole, RecoveryProbeBinding};
use ea_trust::TrustObjectSource;
#[path = "../../../../crates/ea-recovery/tests/source_manifest/epochs.rs"]
mod epochs;

pub(super) fn pause_test_signature(directory:&Path,data:&[u8]) {
    let barrier=directory.join("hold-recovery-test-signature");
    if !barrier.exists() {return;}
    // Parse the actual Sig_structure and protected headers. A marker alone
    // never pauses another native signature purpose.
    let mut d=minicbor::Decoder::new(data);
    if d.array().ok()!=Some(Some(4))||d.str().ok()!=Some("Signature1") {return;}
    let Ok(protected)=d.bytes() else {return;};
    let mut p=minicbor::Decoder::new(protected);
    let Some(Some(count))=p.map().ok() else {return;};
    let mut matches=false;
    for _ in 0..count {
        if p.datatype().ok()==Some(minicbor::data::Type::String) {
            if p.str().is_err()||p.skip().is_err(){return;}
            continue;
        }
        let Ok(label)=p.i64() else {return;};
        if label==3 {matches=p.str().ok()==Some("application/vnd.einsatzarchiv.recovery-test-digest");}
        else if p.skip().is_err() {return;}
    }
    if !matches||p.position()!=protected.len()||d.bytes().ok()!=Some(&[][..])||d.bytes().is_err()||d.position()!=data.len() {return;}
    fs::write(directory.join("recovery-test-signature-paused"),b"").unwrap();
    let deadline=std::time::Instant::now()+std::time::Duration::from_secs(5);
    while barrier.exists() {
        assert!(std::time::Instant::now()<deadline,"bounded recovery provider fixture");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn native_recovery_pause_fixture_matches_actual_typed_signature_domain() {
    let directory=support::temp_dir("recovery-pause-domain");
    let signer=ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([0x37;32]));
    let request=ea_crypto::ExternalCoseSigningRequest::recovery_test(
        signer.public_key().unwrap(),CertificateHash::try_from([0x38;32].as_slice()).unwrap(),ea_crypto::SecretBytes::new([0x39;32]),
    ).unwrap();
    let exact=request.sig_structure_bytes();
    let barrier=directory.path().join("hold-recovery-test-signature");
    let marker=directory.path().join("recovery-test-signature-paused");
    fs::write(&barrier,b"").unwrap();
    let mut other=exact.clone();
    let domain=b"application/vnd.einsatzarchiv.recovery-test-digest";
    let index=other.windows(domain.len()).position(|part|part==domain).unwrap();other[index]=b'x';
    pause_test_signature(directory.path(),&other);
    assert!(!marker.exists(),"marker alone cannot pause another domain");
    let path=directory.path().to_owned();
    let worker=std::thread::spawn(move||pause_test_signature(&path,&exact));
    let until=std::time::Instant::now()+std::time::Duration::from_secs(2);
    while !marker.exists()&&std::time::Instant::now()<until {std::thread::sleep(std::time::Duration::from_millis(10));}
    let observed=marker.exists();
    fs::remove_file(&barrier).unwrap();worker.join().unwrap();
    assert!(observed,"actual typed RecoveryTest signature reaches bounded pause");
}

struct RecoveryInstallation {
    directory: support::TempDir,
    config: PathBuf,
    anchor: PathBuf,
    archive: PathBuf,
    profile: ea_archive::ArchiveBackendProfileV1,
    entry_hash: ea_types::EntryHash,
    grant_hash: ObjectHash,
    target_config: Option<Value>,
    historical_epoch: Option<epochs::KemEpoch>,
}
impl RecoveryInstallation {
    fn new() -> Self {
        Self::with_target(None)
    }
    fn with_target(target: Option<&Value>) -> Self {
        Self::with_target_and_epochs(target, false)
    }
    fn with_target_and_epochs(target: Option<&Value>, historical:bool) -> Self {
        Self::with_profile(target, historical, None)
    }
    fn with_profile(target: Option<&Value>, historical:bool, configured_profile:Option<ea_archive::ArchiveBackendProfileV1>) -> Self {
        use support::verify_support as fixture;
        let directory = support::temp_dir("recovery-native-source");
        install_fixture_helper(directory.path());
        fs::write(directory.path().join("authority-fixture"), b"").unwrap();
        let subject = OperatorSubjectId::try_from([0x42; 16].as_slice()).unwrap();
        let mut writer_binding=None;
        let mut material = fixture::historical::fixture_with_host_options(
            |version,binding| {writer_binding=Some(binding);payload::recovery_payload(version,binding)},
            Some(fixture::historical::HostOptions {
                not_after: support::LIVE_WRITER_NOT_AFTER_V1,
                max_age: support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
                instance: ADMIN_INSTANCE_SECRET,
                account_hash: native_account_hash_for(
                    true,
                    DeviceId::try_from([0x52; 16].as_slice()).unwrap(),
                ),
                commitment: ea_crypto::operator_profile_commitment(
                    trust_support::organization(),
                    subject,
                    TEST_NAME,
                    TEST_FUNCTION,
                    &PROFILE_SALT,
                ),
            }),
        );
        let profile = configured_profile.unwrap_or_else(||
            ea_archive::ArchiveBackendProfileV1::LocalPath(ea_archive::LocalPathProfileV1 {
                filesystem_row_id: "fixture-recovery-fs".into(),
                capability_test_vector_id: "native-recovery-cap-v1".into(),
            }));
        let options = || HeadOptions {
            effective_from: Some(1),
            valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
            ..Default::default()
        };
        material.line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::DeletionAttest,
                marker: 0x73,
                effective_from: Some(1),
            },
            options(),
        );
        let historical_epoch=if historical {
            material.head=material.line.push(ActionSpec::RootRotate{previous_root_hash:None,effective_version:None},options());
            Some(epochs::append_kem_epoch(&mut material,writer_binding.unwrap(),true,Some((support::LIVE_WRITER_NOT_AFTER_V1,support::LIVE_WRITER_LEASE_THROUGH_V1))))
        } else {None};
        // The second immutable Entry already used its exact Writer-transition
        // Head at sequence1. Later setup/binding/policy events first apply at
        // the NEXT sequence, preserving that historical authority window.
        let source_sequence=if historical {2}else{1};
        let after_entries=||HeadOptions{effective_from:Some(source_sequence),..options()};
        let target_config=target.map(|target| {
            assert_eq!(target["schemaId"],"ea.recovery-target-fixture/v1");
            assert_eq!(target["deviceId"],hex::encode(target_device().as_bytes()));
            let certificate=material.line.push(ActionSpec::AdminIssue{marker:0x34,effective_from:Some(source_sequence)},after_entries()).direct_object_hash.unwrap();
            let binding=material.line.push(ActionSpec::OperatorBinding{certificate_hash:certificate,role:OperatorRoleV1::OrganizationAdmin,marker:0x34,effective_from:Some(source_sequence)},HeadOptions{
                binding_os_account_hash_override:Some(Hash32::try_from(hex::decode(target["accountHash"].as_str().unwrap()).unwrap().as_slice()).unwrap()),
                binding_instance_key_thumbprint_override:Some(ea_types::KeyThumbprint::try_from(hex::decode(target["instanceThumbprint"].as_str().unwrap()).unwrap().as_slice()).unwrap()),
                binding_operator_profile_commitment_override:Some(ea_crypto::operator_profile_commitment(trust_support::organization(),OperatorSubjectId::try_from(&[0x34;16][..]).unwrap(),TEST_NAME,TEST_FUNCTION,&PROFILE_SALT)),
                ..after_entries()
            }).direct_object_hash.unwrap();
            json!({"archive_directory":"archive","database_path":"active-authorization.sqlite","device_certificate_hash":hex::encode(certificate.as_bytes()),"binding_object_hash":hex::encode(binding.as_bytes()),"role":"organization-admin","purpose":"recovery-test"})
        });
        material.line.push(
            ActionSpec::Policy {
                policy_version: Some(2),
                previous_policy_hash: Some(material.line.current_policy_hash()),
                effective_from: Some(source_sequence),
            },
            HeadOptions {
                policy_max_registry_age_ms_override: Some(
                    support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
                ),
                policy_allowed_archive_profile_hashes_override: Some(vec![
                    profile.profile_hash().unwrap(),
                ]),
                ..after_entries()
            },
        );
        let archive = directory.path().join("archive");
        support::materialize(&material.fixture, &archive);
        if let Some(epoch)=&historical_epoch {
            fs::write(archive.join("entries/000000000001_epoch.eip"),&epoch.entry_bytes).unwrap();
            fs::write(archive.join("grants/000000000001_epoch.eag"),&epoch.grant_bytes).unwrap();
        }
        let source = material.line.source();
        source
            .visit_trust_object_hashes(&mut |hash| {
                if material
                    .fixture
                    .blobs()
                    .iter()
                    .any(|(_, bytes)| ea_crypto::object_hash(bytes) == hash)
                {
                    return Ok(());
                }
                let path = archive
                    .join("registry/events")
                    .join(format!("{}.etb", hex::encode(hash.as_bytes())));
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, source.read_exact_trust_object(hash)?.unwrap()).unwrap();
                Ok(())
            })
            .unwrap();
        let anchor = directory.path().join("independent-anchor.etb");
        fs::write(&anchor, material.line.exact_anchor_bytes()).unwrap();
        let (provider, key) = database_provider_for(true);
        let db =
            EncryptedDatabase::open(&directory.path().join("operator.sqlite"), &provider, &key)
                .unwrap();
        db.execute(
            "INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",
            &[
                StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                StoreValue::Blob(subject.as_bytes().to_vec()),
                StoreValue::Text(TEST_NAME.into()),
                StoreValue::Text(TEST_FUNCTION.into()),
                StoreValue::Blob(PROFILE_SALT.to_vec()),
                StoreValue::Blob(material.operator_binding.as_bytes().to_vec()),
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO incident_number_retained_key VALUES(0,?1)",
            &[StoreValue::Blob(vec![81; 32])],
        )
        .unwrap();
        db.execute(
            "INSERT INTO incident_number_retained_token VALUES(?1)",
            &[StoreValue::Blob(vec![82; 32])],
        )
        .unwrap();
        drop(db);
        let config = directory.path().join("operator.json");
        fs::write(&config,serde_json::to_vec(&json!({"archive_directory":"archive","database_path":"operator.sqlite","device_certificate_hash":hex::encode(material.line.second_bootstrap_admin_hash().as_bytes()),"binding_object_hash":hex::encode(material.operator_binding.as_bytes()),"role":"organization-admin","purpose":"recovery-test"})).unwrap()).unwrap();
        Self {
            directory,
            config,
            anchor,
            archive,
            profile,
            entry_hash: material.entry_hash,
            grant_hash: ea_crypto::object_hash(&material.original_bytes),
            target_config,
            historical_epoch,
        }
    }
    fn open(&self) -> OperatorRuntime {
        let native = NativeOperatorProvider::open_test_fixture(
            self.directory.path().join("ea-native-operator"),
            false,
        )
        .unwrap();
        // A documentable measurement independent of the runner's disk: the
        // unencrypted root of GitHub's ubuntu-24.04 runner is a measured Fail
        // that no posture document may cover (see operator_posture_document).
        let host: Arc<dyn ea_key_provider::DevicePostureProvider> =
            Arc::new(ea_key_provider::DevicePostureProviderFake::unknown(
                ea_key_provider::PostureRequirement::FullDiskEncryption,
            ));
        let runtime = OperatorRuntime::open_with_test_native_and_posture(
            OperatorRuntimeConfig::load(&self.config).unwrap(),
            &self.anchor,
            support::live_clock(),
            false,
            native,
            host,
        )
        .unwrap();
        if runtime.posture_admission().is_err() {
            let target = runtime.posture_target_context().unwrap();
            let document = runtime
                .issue_posture_document(
                    &target,
                    ea_crypto::object_hash(b"T9 fixture documented prerequisites"),
                    60_000,
                )
                .unwrap();
            runtime.import_posture_document(&document).unwrap();
        }
        runtime
    }
    fn inventory(&self, runtime: &OperatorRuntime) -> KeyInventory {
        KeyInventory::parse(&self.inventory_exact(runtime)).unwrap()
    }
    fn inventory_exact(&self, runtime: &OperatorRuntime) -> Vec<u8> {
        let mut rows = Vec::new();
        for (hash, c) in runtime.head().active_certificates() {
            let role = match c.certificate_kind {
                CertificateKindV1::Writer => "writer",
                CertificateKindV1::Reader => "reader",
                CertificateKindV1::OrganizationAdmin => "organizationAdmin",
                CertificateKindV1::KeyApprover => "keyApprover",
                CertificateKindV1::RecoveryRecipient => "recoveryRecipient",
                CertificateKindV1::HistoricalGrantAuthority => "historicalGrantAuthority",
                CertificateKindV1::ServerReceipt => "serverReceipt",
                CertificateKindV1::DeletionAttest => "deletionAttest",
            };
            let recovery = c.certificate_kind == CertificateKindV1::RecoveryRecipient;
            rows.push(json!({"mediumId":hex::encode(hash.as_bytes()),"keyRole":role,"expectedKeyThumbprint":hex::encode(if recovery{c.kem_key_thumbprint.unwrap()}else{c.signing_key_thumbprint.unwrap()}.as_bytes()),"certificateObjectHash":hex::encode(hash.as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":if recovery{"recoveryDecrypt"}else{"signatureChallenge"}}));
        }
        rows.push(json!({"mediumId":"root","keyRole":"root","expectedKeyThumbprint":hex::encode(runtime.anchor().root_key_thumbprint().as_bytes()),"certificateObjectHash":hex::encode(runtime.anchor().root_certificate_object_hash().as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"signatureChallenge"}));
        if let Some(epoch)=&self.historical_epoch {
            let ea_format::ParsedArchiveObject::Entry(original)=ea_format::decode_exact_object(
                &fs::read(self.archive.join("entries/000000000000_entry.eip")).unwrap(),
            ).unwrap() else {panic!("original immutable Entry")};
            let old_writer=hex::encode(original.value().manifest().fields().writer_certificate_hash.as_bytes());
            if !rows.iter().any(|row|row["certificateObjectHash"]==old_writer) {
                rows.push(json!({"mediumId":"old-writer-epoch","keyRole":"writer","expectedKeyThumbprint":hex::encode(trust_support::authorized_device_signing_key_thumbprint().as_bytes()),"certificateObjectHash":old_writer,"protectionProfile":"offlineEncryptedContainer","testKind":"signatureChallenge"}));
            }
            rows.push(json!({"mediumId":"old-recovery-epoch","keyRole":"recoveryRecipient","expectedKeyThumbprint":hex::encode(support::verify_support::complete_recipient_key_thumbprint().as_bytes()),"certificateObjectHash":hex::encode(epoch.old_certificate.as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"recoveryDecrypt"}));
            rows.push(json!({"mediumId":"root-current","keyRole":"root","expectedKeyThumbprint":hex::encode(runtime.head().root_certificate_fields().root_key_thumbprint.as_bytes()),"certificateObjectHash":hex::encode(runtime.head().root_certificate_object_hash().as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"signatureChallenge"}));
        }
        rows.sort_by(|a, b| a["mediumId"].as_str().cmp(&b["mediumId"].as_str()));
        serde_json::to_vec(
            &json!({"schemaId":"ea.key-inventory/v1","inventoryId":"aa".repeat(16),"media":rows}),
        )
        .unwrap()
    }
    fn probes(&self, keys: &KeyInventory) -> Vec<RecoveryProbeBinding> {
        let mut rows = keys
            .media()
            .iter()
            .filter(|m| m.role() == RecoveryKeyRole::RecoveryRecipient)
            .map(|m| RecoveryProbeBinding {
                medium_hash: *m.pseudonymous_id_hash().as_bytes(),
                certificate_hash: *m.certificate().as_bytes(),
                key_thumbprint: *m.expected_thumbprint().as_bytes(),
                setup_entry_hash: *self.historical_epoch.as_ref().filter(|epoch|epoch.new_certificate==m.certificate()).map_or(self.entry_hash,|epoch|epoch.entry_hash).as_bytes(),
                initial_grant_hash: *self.historical_epoch.as_ref().filter(|epoch|epoch.new_certificate==m.certificate()).map_or(self.grant_hash,|epoch|ea_crypto::object_hash(&epoch.grant_bytes)).as_bytes(),
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|p| p.medium_hash);
        rows
    }
}

#[test]
fn native_source_capture_binds_real_snapshot_machine_inventory_and_signed_audit_without_readiness()
{
    let installed = RecoveryInstallation::new();
    let runtime = installed.open();
    let inventory = installed.inventory(&runtime);
    let probes = installed.probes(&inventory);
    let mut recovery = RecoveryTestRuntime::new(runtime, installed.profile.clone()).unwrap();
    let snapshot = installed.directory.path().join("backup.db");
    let phrase = SecretVec::new(b"T9 native backup fixture phrase".to_vec());
    let captured = recovery
        .capture_source(RecoverySourceCapture {
            inventory: &inventory,
            probes,
            snapshot: &snapshot,
            passphrase: &phrase,
        })
        .unwrap();
    let machine = ea_key_provider::measure_native_machine_identity().unwrap();
    assert_eq!(
        captured.core().fields().source_machine,
        *machine.fingerprint().as_bytes()
    );
    assert_eq!(
        captured.core().fields().snapshot_hash,
        *ea_crypto::object_hash(&fs::read(&snapshot).unwrap()).as_bytes()
    );
    assert_eq!(
        recovery
            .runtime()
            .database()
            .query_row("SELECT count(*) FROM recovery_test_report", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    let exact = captured.exact_envelope().to_vec();
    drop(recovery);
    let reopened = installed.open();
    let row = reopened
        .database()
        .query_row("SELECT exact_envelope FROM recovery_source_scope", &[])
        .unwrap()
        .unwrap();
    assert_eq!(row.blob(0).unwrap(), exact);
    let source = ea_recovery::FsArchiveSource::open_committed(&installed.archive).unwrap();
    assert!(
        ea_recovery::verify_recovery_source(
            &exact,
            &source,
            reopened.anchor(),
            &inventory,
            support::live_clock()
        )
        .is_ok()
    );
    let key = captured.core().fields().kdf.derive(&phrase).unwrap();
    let (target_provider, target_key) = database_provider_for(false);
    let restored = EncryptedDatabase::restore_with_backup_key(
        &snapshot,
        captured.core().fields().snapshot_hash,
        captured.core().fields().migrations_hash,
        &key,
        &installed.directory.path().join("inspected.db"),
        &target_provider,
        &target_key,
    )
    .unwrap();
    assert_eq!(
        restored
            .query_row("SELECT token FROM incident_number_retained_token", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        &[82; 32]
    );
}

#[test]
fn native_target_database_key_is_fresh_and_survives_actual_provider_reopen() {
    use ea_admin::native_provider::NativeSigningSlot;
    let directory = support::temp_dir("recovery-fresh-native-key");
    install_fixture_helper(directory.path());
    fs::write(directory.path().join("authority-fixture"), b"").unwrap();
    fs::write(directory.path().join("target-recovery-fixture"), b"").unwrap();
    let native = NativeOperatorProvider::open_test_fixture(
        directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    let provider = native.signing_provider(NativeSigningSlot::Admin);
    let key = provider.handle(SecretPurpose::LocalDatabaseKey);
    assert!(
        !provider.contains(&key).unwrap(),
        "fresh installation has no inherited database key"
    );
    let created = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let database = directory.path().join("fresh.sqlite");
    let db = EncryptedDatabase::open(&database, &provider, &created).unwrap();
    db.execute("CREATE TABLE target_witness(value INTEGER NOT NULL)", &[])
        .unwrap();
    db.execute("INSERT INTO target_witness VALUES(91)", &[])
        .unwrap();
    let (old_provider, old_key) = database_provider_for(true);
    assert!(
        EncryptedDatabase::open_existing(&database, &old_provider, &old_key).is_err(),
        "source fixture key must not open the new target"
    );
    drop(db);
    drop(provider);
    drop(native);
    let native = NativeOperatorProvider::open_test_fixture(
        directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    let provider = native.signing_provider(NativeSigningSlot::Admin);
    let key = provider.handle(SecretPurpose::LocalDatabaseKey);
    let db = EncryptedDatabase::open_existing(&database, &provider, &key).unwrap();
    assert_eq!(
        db.query_row("SELECT value FROM target_witness", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        91
    );
    assert!(
        provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped
            )
            .is_err(),
        "fresh key generation must never replace an existing key"
    );
}

// Test process storage only. The target secret is generated in this isolated
// helper process, encrypted at rest, and never copied from the source fixture.
pub(super) fn target_key_response(directory: &Path, request: &Value) -> Option<Value> {
    if !directory.join("target-recovery-fixture").exists() || request["slot"] != "database-key" {
        return None;
    }
    let path = directory.join("target-database-key.sealed");
    Some(match request["op"].as_str().unwrap() {
        "contains" => json!({"contains":path.exists()}),
        "generate"
            if !path.exists()
                && request["replace"] == false
                && request["presence"] == true
                && request["kind"] == "secret32" =>
        {
            let mut secret = [0; 32];
            getrandom::fill(&mut secret).unwrap();
            let mut nonce = [0; 12];
            getrandom::fill(&mut nonce).unwrap();
            let mut ciphertext = nonce.to_vec();
            ciphertext.extend(
                ea_crypto::aead_seal(
                    &ea_crypto::SecretBytes::new([0x9a; 32]),
                    &ea_crypto::SecretBytes::new(nonce),
                    SecretVec::new(secret.to_vec()),
                    b"native-target-recovery-fixture-v1",
                )
                .unwrap(),
            );
            use zeroize::Zeroize as _;
            secret.zeroize();
            let mut options = fs::OpenOptions::new();
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = options
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(&ciphertext).unwrap();
            file.sync_all().unwrap();
            json!({})
        }
        "unwrap-secret" if path.exists() => {
            let ciphertext = fs::read(path).unwrap();
            ea_crypto::aead_open(
                &ea_crypto::SecretBytes::new([0x9a; 32]),
                &ea_crypto::SecretBytes::new(ciphertext[..12].try_into().unwrap()),
                &ciphertext[12..],
                b"native-target-recovery-fixture-v1",
            )
            .unwrap()
            .with_exposed(|bytes| json!({"secret":hex::encode(bytes)}))
        }
        _ => json!({"ok":false}),
    })
}

pub(super) const TARGET_INSTANCE_SECRET: [u8; 32] = [0x6b; 32];
fn target_device() -> DeviceId {
    DeviceId::try_from(&[0x74; 16][..]).unwrap()
}
pub(super) fn target_installation_id(directory: &Path) -> Option<String> {
    if !directory.join("target-recovery-fixture").exists() {
        return None;
    }
    let path = directory.join("target-installation-id");
    if !path.exists() {
        let mut value = [0; 32];
        getrandom::fill(&mut value).unwrap();
        let mut options = fs::OpenOptions::new();
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(hex::encode(value).as_bytes()).unwrap();
        file.sync_all().unwrap();
    }
    Some(fs::read_to_string(path).unwrap())
}
pub(super) fn target_account_response(directory: &Path) -> Option<Value> {
    if !directory.join("target-recovery-fixture").exists() {
        return None;
    }
    if cfg!(target_os = "linux") {
        let output = std::process::Command::new("/usr/bin/id")
            .arg("-u")
            .output()
            .unwrap();
        assert!(output.status.success());
        let uid = std::str::from_utf8(&output.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        Some(
            json!({"platform":"linux","machine_id_bytes":hex::encode(fs::read("/etc/machine-id").unwrap()),"uid":uid,"locked":false}),
        )
    } else {
        Some(account_response_for(true))
    }
}

#[test]
#[ignore = "explicit portable test artifact export, requires EA_T9_TARGET_DIRECTORY"]
fn export_target_native_context() {
    use ea_admin::native_provider::NativeSigningSlot;
    use ea_operator::OsAccountProvider;
    let directory = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    install_fixture_helper(&directory);
    fs::write(directory.join("authority-fixture"), b"").unwrap();
    fs::write(directory.join("target-recovery-fixture"), b"").unwrap();
    let native =
        NativeOperatorProvider::open_test_fixture(directory.join("ea-native-operator"), false)
            .unwrap();
    let provider = native.signing_provider(NativeSigningSlot::Admin);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let db =
        EncryptedDatabase::open(&directory.join("authorization.sqlite"), &provider, &key).unwrap();
    let measured = ea_key_provider::measure_native_machine_identity().unwrap();
    let context = json!({
        "schemaId":"ea.recovery-target-fixture/v1",
        "machineHash":hex::encode(measured.fingerprint().as_bytes()),
        "installationId":hex::encode(native.installation_id().as_bytes()),
        "deviceId":hex::encode(target_device().as_bytes()),
        "accountHash":hex::encode(native.os_account_binding_hash(trust_support::organization(),target_device()).unwrap().as_bytes()),
        "instanceThumbprint":hex::encode(native.public_key(NativeSigningSlot::Operator).unwrap().unwrap().thumbprint().as_bytes()),
    });
    fs::write(
        directory.join("public-context.json"),
        serde_json::to_vec(&context).unwrap(),
    )
    .unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM operator_profile", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
}

#[test]
fn native_restore_rejects_source_machine_before_touching_backup_or_creating_target() {
    let installed = RecoveryInstallation::new();
    let runtime = installed.open();
    let inventory = installed.inventory(&runtime);
    let probes = installed.probes(&inventory);
    let mut recovery = RecoveryTestRuntime::new(runtime, installed.profile.clone()).unwrap();
    let snapshot = installed.directory.path().join("backup.db");
    let phrase = SecretVec::new(b"T9 fixture phrase".to_vec());
    let source = recovery
        .capture_source(RecoverySourceCapture {
            inventory: &inventory,
            probes,
            snapshot: &snapshot,
            passphrase: &phrase,
        })
        .unwrap();
    let target = installed.directory.path().join("forbidden-restore.db");
    let error = recovery
        .restore_source(ea_admin::recovery_test_runtime::RecoverySourceRestore {
            inventory: &inventory,
            exact_source: source.exact_envelope(),
            snapshot: &installed.directory.path().join("absent-backup"),
            passphrase: &phrase,
            target: &target,
        })
        .err()
        .expect("same native source machine must be rejected before file/key access");
    assert_eq!(error.code(), "EA-RECOVERY-TEST-MACHINE");
    assert!(!target.exists());
    assert_eq!(
        recovery
            .runtime()
            .database()
            .query_row("SELECT count(*) FROM recovery_restore_binding", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
}

mod payload {
    include!("../../../../crates/ea-recovery/tests/recovery_fixture/mod.rs");
}

fn write_private(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn copy_public_tree(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_public_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
fn fixture_signing_secrets() -> Vec<[u8; 32]> {
    vec![
        trust_support::root_signing_secret(),
        trust_support::device_signing_secret(),
        trust_support::second_admin_signing_secret(),
        hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
            .unwrap()
            .try_into()
            .unwrap(),
        [0x88;32],
        hex::decode("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5").unwrap().try_into().unwrap(),
    ]
}

#[test]
fn native_historical_source_capture_requires_old_and_current_key_epochs() {
    let installed=RecoveryInstallation::with_target_and_epochs(None,true);
    let source=ea_recovery::FsArchiveSource::open_committed(&installed.archive).unwrap();
    let anchor=ea_recovery::load_trust_anchor(&installed.anchor).unwrap();
    let public=ea_verify::verify_archive(&source,&anchor,ea_verify::VerifyOptions::new(support::live_clock())).unwrap();
    assert!(public.verified_public_chain_head().is_some(),"{}",public.to_canonical_json().unwrap());
    let runtime=installed.open();
    let context=runtime.posture_target_context().unwrap();
    let document=runtime.issue_posture_document(&context,ea_crypto::object_hash(b"T9 historical source capture prerequisites"),300_000).unwrap();
    runtime.import_posture_document(&document).unwrap();
    let exact=installed.inventory_exact(&runtime);
    let inventory=KeyInventory::parse(&exact).unwrap();
    for role in [RecoveryKeyRole::Root,RecoveryKeyRole::Writer,RecoveryKeyRole::RecoveryRecipient] {
        assert_eq!(inventory.media().iter().filter(|medium|medium.role()==role).count(),2,"{role:?}");
    }
    let mut service=RecoveryTestRuntime::new(runtime,installed.profile.clone()).unwrap();
    let passphrase=SecretVec::new(b"T9 historical source fixture backup".to_vec());
    for missing in ["root","old-recovery-epoch"] {
        let mut reduced:Value=serde_json::from_slice(&exact).unwrap();
        reduced["media"].as_array_mut().unwrap().retain(|row|row["mediumId"]!=missing);
        let reduced=KeyInventory::parse(&serde_json::to_vec(&reduced).unwrap()).unwrap();
        let error=service.capture_inventory(&reduced,&installed.directory.path().join(format!("missing-{missing}.sqlite")),&passphrase).err().unwrap_or_else(||panic!("missing historical medium {missing} must not capture complete source"));
        assert_eq!(error.code(),ea_recovery::RecoveryTestError::Incomplete.code(),"required historical epoch {missing}");
        assert_eq!(service.runtime().database().query_row("SELECT count(*) FROM recovery_source_scope",&[]).unwrap().unwrap().integer(0).unwrap(),0);
    }
    // Retirement does not create a new obligation to retain an old signing
    // private key. Its signed Entry remains present and publicly verified;
    // when declared in the final inventory below its medium is mandatory.
    let mut without_old_writer:Value=serde_json::from_slice(&exact).unwrap();
    without_old_writer["media"].as_array_mut().unwrap().retain(|row|row["mediumId"]!="old-writer-epoch");
    let without_old_writer=KeyInventory::parse(&serde_json::to_vec(&without_old_writer).unwrap()).unwrap();
    let retired=service.capture_inventory(&without_old_writer,&installed.directory.path().join("retired-writer-source.sqlite"),&passphrase).unwrap();
    assert_eq!(retired.core().fields().tip_sequence,1);
    assert_eq!(retired.core().fields().probes.len(),2);
    let source=service.capture_inventory(&inventory,&installed.directory.path().join("complete-historical.sqlite"),&passphrase).unwrap();
    assert_eq!(source.core().fields().probes.len(),2);
    assert_ne!(source.core().fields().probes[0].certificate_hash,source.core().fields().probes[1].certificate_hash);
    assert_ne!(source.core().fields().probes[0].key_thumbprint,source.core().fields().probes[1].key_thumbprint);
    assert_eq!(source.core().fields().tip_sequence,1);
    assert_eq!(service.runtime().database().query_row("SELECT count(*) FROM recovery_test_report",&[]).unwrap().unwrap().integer(0).unwrap(),0);
}

#[test]
#[ignore = "explicit Mac pre-loss capture; EA_T9_TARGET_CONTEXT and EA_T9_SOURCE_EXPORT required"]
fn export_native_source_capture_for_portable_restore() {
    use ea_recovery::{ContainedKeyKind, EncryptedKeyContainer};
    let target: Value = serde_json::from_slice(
        &fs::read(std::env::var_os("EA_T9_TARGET_CONTEXT").unwrap()).unwrap(),
    )
    .unwrap();
    assert_ne!(
        target["machineHash"],
        hex::encode(
            ea_key_provider::measure_native_machine_identity()
                .unwrap()
                .fingerprint()
                .as_bytes()
        )
    );
    let historical=std::env::var_os("EA_T9_INCLUDE_HISTORICAL_EPOCHS").is_some();
    let installed = RecoveryInstallation::with_target_and_epochs(Some(&target),historical);
    let runtime = installed.open();
    let mut inventory_exact = installed.inventory_exact(&runtime);
    if let Some(token)=target.get("pkcs11") {
        assert!(!historical,"separate baseline token fixture; no implicit historical token keys");
        let mut document:Value=serde_json::from_slice(&inventory_exact).unwrap();
        let mut signing=0;
        let mut recovery=0;
        for row in document["media"].as_array_mut().unwrap() {
            let kem=row["keyRole"]=="recoveryRecipient";
            let expected=if kem {&token["recoveryThumbprint"]}else{&token["signingThumbprint"]};
            if &row["expectedKeyThumbprint"]==expected {
                row["protectionProfile"]=json!("pkcs11");
                if kem {recovery+=1;} else {signing+=1;row["testKind"]=json!("providerPresence");}
            }
        }
        assert!(signing>0&&recovery>0,"both measured token keys must match the signed source inventory");
        inventory_exact=serde_json::to_vec(&document).unwrap();
    }
    if std::env::var_os("EA_T9_INCLUDE_NATIVE_MEDIUM").is_some() {
        let certificate=installed.target_config.as_ref().unwrap()["device_certificate_hash"].as_str().unwrap();
        let mut document:Value=serde_json::from_slice(&inventory_exact).unwrap();
        let rows=document["media"].as_array_mut().unwrap();
        let mut native=rows.iter().find(|row|row["certificateObjectHash"]==certificate).unwrap().clone();
        native["mediumId"]=json!("native-target-admin");
        native["protectionProfile"]=json!("osWrapped");
        native["testKind"]=json!("providerPresence");
        rows.push(native);
        rows.sort_by(|a,b|a["mediumId"].as_str().cmp(&b["mediumId"].as_str()));
        inventory_exact=serde_json::to_vec(&document).unwrap();
    }
    let inventory = KeyInventory::parse(&inventory_exact).unwrap();
    let probes = installed.probes(&inventory);
    let mut recovery = RecoveryTestRuntime::new(runtime, installed.profile.clone()).unwrap();
    let export = PathBuf::from(std::env::var_os("EA_T9_SOURCE_EXPORT").unwrap());
    fs::create_dir(&export).unwrap();
    fs::set_permissions(&export, fs::Permissions::from_mode(0o700)).unwrap();
    let snapshot = export.join("snapshot.db");
    let phrase = SecretVec::new(b"T9 portable fixture passphrase".to_vec());
    let source = recovery
        .capture_source(RecoverySourceCapture {
            inventory: &inventory,
            probes,
            snapshot: &snapshot,
            passphrase: &phrase,
        })
        .unwrap();
    write_private(
        &export.join("source-envelope.cbor"),
        source.exact_envelope(),
    );
    write_private(&export.join("inventory.json"), &inventory_exact);
    write_private(
        &export.join("backup.passphrase"),
        b"T9 portable fixture passphrase",
    );
    write_private(
        &export.join("target-operator.json"),
        &serde_json::to_vec(installed.target_config.as_ref().unwrap()).unwrap(),
    );
    write_private(
        &export.join("target-context.json"),
        &serde_json::to_vec(&target).unwrap(),
    );
    fs::copy(&installed.anchor, export.join("independent-anchor.etb")).unwrap();
    copy_public_tree(&installed.archive, &export.join("archive"));
    let media = export.join("media");
    fs::create_dir(&media).unwrap();
    let signers = fixture_signing_secrets();
    let mut mapping = Vec::new();
    for medium in inventory.media() {
        if medium.protection()==ea_format::KeyProtectionProfileV1::Pkcs11 {
            let id=if medium.role()==RecoveryKeyRole::RecoveryRecipient {"c1"}else{"d1"};
            mapping.push(json!({"mediumId":medium.id(),"pkcs11Id":id}));
            continue;
        }
        if medium.test_kind()==ea_recovery::RecoveryTestKind::ProviderPresence {
            assert_eq!(medium.id(),"native-target-admin");
            mapping.push(json!({"mediumId":medium.id(),"nativeSlot":"admin-signing"}));
            continue;
        }
        let recovery = medium.role() == RecoveryKeyRole::RecoveryRecipient;
        let secret = if recovery {
            if medium.expected_thumbprint()==support::verify_support::complete_recipient_key_thumbprint() {
                support::verify_support::complete_recipient_secret_bytes()
            } else {
                assert!(historical);
                support::verify_support::other_recipient_secret_bytes()
            }
        } else {
            *signers
                .iter()
                .find(|secret| public(**secret).thumbprint() == medium.expected_thumbprint())
                .unwrap()
        };
        let name = format!(
            "{}.container",
            hex::encode(medium.pseudonymous_id_hash().as_bytes())
        );
        EncryptedKeyContainer::seal(
            if recovery {
                ContainedKeyKind::RecipientKem
            } else {
                ContainedKeyKind::Signing
            },
            ea_crypto::SecretBytes::new(secret),
            &phrase,
        )
        .unwrap()
        .write_new(&media.join(&name))
        .unwrap();
        mapping.push(json!({"mediumId":medium.id(),"container":format!("media/{name}"),"passphraseFile":"backup.passphrase"}));
    }
    write_private(
        &export.join("media.json"),
        &serde_json::to_vec(&mapping).unwrap(),
    );
    assert_eq!(
        recovery
            .runtime()
            .database()
            .query_row("SELECT count(*) FROM recovery_test_report", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
}

fn open_portable_target(export: &Path, target: &Path) -> RecoveryTestRuntime {
    use ea_admin::native_provider::NativeSigningSlot;
    install_fixture_helper(target);
    let expected: Value =
        serde_json::from_slice(&fs::read(export.join("target-context.json")).unwrap()).unwrap();
    let native =
        NativeOperatorProvider::open_test_fixture(target.join("ea-native-operator"), false)
            .unwrap();
    assert_eq!(
        expected["machineHash"],
        hex::encode(
            ea_key_provider::measure_native_machine_identity()
                .unwrap()
                .fingerprint()
                .as_bytes()
        )
    );
    assert_eq!(
        expected["installationId"],
        hex::encode(native.installation_id().as_bytes())
    );
    let config: Value =
        serde_json::from_slice(&fs::read(export.join("target-operator.json")).unwrap()).unwrap();
    if !target.join("archive").exists() {
        copy_public_tree(&export.join("archive"), &target.join("archive"));
    }
    if !target.join("independent-anchor.etb").exists() {
        fs::copy(
            export.join("independent-anchor.etb"),
            target.join("independent-anchor.etb"),
        )
        .unwrap();
    }
    fs::write(
        target.join("operator.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let provider = native.signing_provider(NativeSigningSlot::Admin);
    let key = provider.handle(SecretPurpose::LocalDatabaseKey);
    let path = target.join("active-authorization.sqlite");
    let database = if path.exists() {
        EncryptedDatabase::open_existing(&path, &provider, &key).unwrap()
    } else {
        EncryptedDatabase::open(&path, &provider, &key).unwrap()
    };
    if database
        .query_row("SELECT count(*) FROM operator_profile", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
        == 0
    {
        database
            .execute(
                "INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",
                &[
                    StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                    StoreValue::Blob(vec![0x34; 16]),
                    StoreValue::Text(TEST_NAME.into()),
                    StoreValue::Text(TEST_FUNCTION.into()),
                    StoreValue::Blob(PROFILE_SALT.to_vec()),
                    StoreValue::Blob(
                        hex::decode(config["binding_object_hash"].as_str().unwrap()).unwrap(),
                    ),
                ],
            )
            .unwrap();
    }
    drop(database);
    let host = Arc::from(
        ea_key_provider::SupportMatrixRow::current_host()
            .unwrap()
            .posture_provider(),
    );
    let runtime = OperatorRuntime::open_with_test_native_and_posture(
        OperatorRuntimeConfig::load(&target.join("operator.json")).unwrap(),
        &target.join("independent-anchor.etb"),
        support::live_clock(),
        false,
        native,
        host,
    )
    .unwrap();
    if runtime.posture_admission().is_err() {
        let target = runtime.posture_target_context().unwrap();
        let document = runtime
            .issue_posture_document(
                &target,
                ea_crypto::object_hash(b"T9 Linux isolated software lifecycle prerequisites"),
                300_000,
            )
            .unwrap();
        runtime.import_posture_document(&document).unwrap();
    }
    RecoveryTestRuntime::new(
        runtime,
        ea_archive::ArchiveBackendProfileV1::LocalPath(ea_archive::LocalPathProfileV1 {
            filesystem_row_id: "fixture-recovery-fs".into(),
            capability_test_vector_id: "native-recovery-cap-v1".into(),
        }),
    )
    .unwrap()
}

fn renew_portable_fixture_posture(runtime: &RecoveryTestRuntime) {
    // Each independent test action starts with a newly signed native document,
    // never a longer old proof or a changed productive admission limit.
    let fresh = runtime.runtime().reopened_for_action().unwrap();
    let context = fresh.posture_target_context().unwrap();
    let exact = fresh.issue_posture_document(
        &context,
        ea_crypto::object_hash(b"T9 Linux isolated software lifecycle prerequisites"),
        300_000,
    ).unwrap();
    fresh.import_posture_document(&exact).unwrap();
}

struct BoundedPortableWatcher(PathBuf);
impl BoundedPortableWatcher {
    fn open(target: &Path) -> Self {
        let path = target.join("long-recovery-run");
        write_private(&path, b"bounded interactive V4 fixture watcher");
        Self(path)
    }
}
impl Drop for BoundedPortableWatcher {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}

struct PortableMediaGuide<'a> {
    target: &'a Path,
    media: &'a [ea_admin::recovery_test_runtime::RecoveryTestMediumSource],
}
impl ea_admin::recovery_test_runtime::RecoveryTestGuide for PortableMediaGuide<'_> {
    fn request_medium(
        &mut self,
        request: &ea_admin::recovery_test_runtime::RecoveryMediumRequest,
    ) -> Result<Option<ea_admin::recovery_test_runtime::RecoveryMediumInput>, ea_admin::recovery_test_runtime::RecoveryTestAbort> {
        // Real independent native documentation between inputs. This does not
        // lengthen the kernel's current provider action or renew its Watch.
        let native=NativeOperatorProvider::open_test_fixture(self.target.join("ea-native-operator"),false).unwrap();
        let fresh=OperatorRuntime::open_with_test_native_and_posture(
            OperatorRuntimeConfig::load(&self.target.join("operator.json")).unwrap(),
            &self.target.join("independent-anchor.etb"),support::live_clock(),false,native,
            Arc::from(ea_key_provider::SupportMatrixRow::current_host().unwrap().posture_provider()),
        ).unwrap();
        let context=fresh.posture_target_context().unwrap();
        let exact=fresh.issue_posture_document(&context,
            ea_crypto::object_hash(b"T9 Linux isolated software lifecycle prerequisites"),300_000,
        ).unwrap();
        fresh.import_posture_document(&exact).unwrap();
        Ok(self.media.iter().find(|m|m.medium_id_hash==request.medium_id_hash()).map(|m|match &m.source {
            ea_admin::recovery_test_runtime::RecoveryMediumInput::Offline(source)=>ea_admin::recovery_test_runtime::RecoveryMediumInput::Offline(source.clone()),
            ea_admin::recovery_test_runtime::RecoveryMediumInput::NativeSigningSlot(slot)=>ea_admin::recovery_test_runtime::RecoveryMediumInput::NativeSigningSlot(*slot),
        }))
    }
    fn medium_result(&mut self,_:&ea_admin::recovery_test_runtime::RecoveryMediumObservation)->Result<(),ea_admin::recovery_test_runtime::RecoveryTestAbort>{Ok(())}
    fn ensure_active(&self)->Result<(),ea_admin::recovery_test_runtime::RecoveryTestAbort>{Ok(())}
}

#[test]
#[ignore = "actual foreign-machine fixture; EA_T9_TARGET_DIRECTORY and EA_T9_PORTABLE_SOURCE required"]
fn portable_native_restore_preserves_original_sources_and_separate_target_authority() {
    use ea_admin::native_provider::NativeSigningSlot;
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let mut runtime = open_portable_target(&export, &target);
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let envelope = fs::read(export.join("source-envelope.cbor")).unwrap();
    let phrase = ea_recovery::read_secret_file(&export.join("backup.passphrase")).unwrap();
    let restored = runtime
        .restore_source(ea_admin::recovery_test_runtime::RecoverySourceRestore {
            inventory: &inventory,
            exact_source: &envelope,
            snapshot: &export.join("snapshot.db"),
            passphrase: &phrase,
            target: &target.join("restored-sources.sqlite"),
        })
        .unwrap();
    drop(restored);
    assert_eq!(
        runtime
            .runtime()
            .database()
            .query_row("SELECT operator_subject_id FROM operator_profile", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        &[0x34; 16]
    );
    assert_eq!(
        runtime
            .runtime()
            .database()
            .query_row("SELECT count(*) FROM recovery_test_report", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    let provider = runtime
        .runtime()
        .native()
        .signing_provider(NativeSigningSlot::Admin);
    let db = EncryptedDatabase::open_existing(
        &target.join("restored-sources.sqlite"),
        &provider,
        &provider.handle(SecretPurpose::LocalDatabaseKey),
    )
    .unwrap();
    assert_eq!(
        db.query_row("SELECT operator_subject_id FROM operator_profile", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        &[0x42; 16]
    );
    assert_eq!(
        db.query_row("SELECT key_bytes FROM incident_number_retained_key", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        &[81; 32]
    );
    assert_eq!(
        db.query_row("SELECT token FROM incident_number_retained_token", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        &[82; 32]
    );
}


#[test]
#[ignore = "explicit fresh-machine portable lifecycle; requires captured source and retained native target"]
fn portable_native_full_recovery_reopens_sources_tests_every_medium_and_commits_signed_status() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let _watch = BoundedPortableWatcher::open(&target);
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let mapping: Vec<Value> = serde_json::from_slice(&fs::read(export.join("media.json")).unwrap()).unwrap();
    let media: Vec<_> = inventory.media().iter().map(|medium| {
        let row = mapping.iter().find(|row| row["mediumId"] == medium.id()).unwrap();
        ea_admin::recovery_test_runtime::RecoveryTestMediumSource {
            medium_id_hash: medium.pseudonymous_id_hash(),
            source: if row.get("nativeSlot").is_some() {
                assert_eq!(row["nativeSlot"],"admin-signing");
                ea_admin::recovery_test_runtime::RecoveryMediumInput::NativeSigningSlot(ea_admin::recovery_test_runtime::RecoveryNativeSigningSlot::Admin)
            } else {ea_admin::recovery_test_runtime::RecoveryMediumInput::Offline(ea_recovery::KeySourceSpec::Container {
                path: export.join(row["container"].as_str().unwrap()),
                passphrase_file: export.join(row["passphraseFile"].as_str().unwrap()),
            })},
        }
    }).collect();
    let mut runtime = open_portable_target(&export, &target);
    let reports_before=runtime.runtime().database().query_row("SELECT count(*) FROM recovery_test_report",&[]).unwrap().unwrap().integer(0).unwrap();
    let restored = runtime.reopen_restored_source(&inventory, &target.join("restored-sources.sqlite")).unwrap();
    renew_portable_fixture_posture(&runtime);
    let incomplete = runtime.run_restored_test_guided(&restored, &inventory,
        &mut PortableMediaGuide{target:&target,media:&media[..media.len()-1]},
    ).unwrap();
    let ea_admin::recovery_test_runtime::RecoveryTestOutcome::Failed(incomplete)=incomplete else {panic!("one missing medium is incomplete")};
    let partial:Value=serde_json::from_slice(incomplete.public_report()).unwrap();
    assert_eq!(partial["errorCode"], "EA-RECOVERY-TEST-INCOMPLETE");
    assert_eq!(partial["media"].as_array().unwrap().iter().filter(|m|m["result"]=="missing").count(),1);
    assert_eq!(runtime.runtime().database().query_row("SELECT count(*) FROM recovery_test_report",&[]).unwrap().unwrap().integer(0).unwrap(),reports_before);
    renew_portable_fixture_posture(&runtime);
    let complete = runtime.run_restored_test_guided(&restored, &inventory,
        &mut PortableMediaGuide{target:&target,media:&media},
    ).unwrap();
    let ea_admin::recovery_test_runtime::RecoveryTestOutcome::Completed(report)=complete else {panic!("all actual media and epochs passed")};
    let public_times:Value=serde_json::from_slice(report.public_report()).unwrap();
    assert!(report.completed_at().get()>public_times["effectiveNow"].as_i64().unwrap(),"completion uses the actual fresh end-time selection");
    assert_eq!(report.tested_media_count(), inventory.media().len());
    assert_eq!(report.restored_content_hash(), restored.restored_content_hash());
    let report_hash = report.envelope_hash();
    let exact = report.exact_envelope().to_vec();
    restored.verify_unchanged().unwrap();
    drop(restored); drop(runtime);
    let mut reopened = open_portable_target(&export, &target);
    let durable = reopened.read_completed_report(&inventory, &target.join("restored-sources.sqlite")).unwrap().unwrap();
    assert!(durable.envelope_hash() == report_hash);
    assert_eq!(durable.exact_envelope(), exact);
    let public: Value = serde_json::from_slice(durable.public_report()).unwrap();
    assert_eq!(public["result"],"complete");
    assert_eq!(public["media"].as_array().unwrap().len(),inventory.media().len());
    assert!(!String::from_utf8(exact.clone()).unwrap_or_default().contains("Erika Beispiel"));
    let destination=std::env::var_os("EA_T9_COMPLETION_EXPORT").map(PathBuf::from).unwrap_or_else(||target.join("completed-recovery.cbor"));
    write_private(&destination,&exact);
}


#[test]
fn native_cli_capture_dispatches_exact_arguments_to_durable_signed_source() {
    let installed = RecoveryInstallation::new();
    let existing = installed.open();
    let inventory_path = installed.directory.path().join("cli-inventory.json");
    write_private(&inventory_path,&installed.inventory_exact(&existing));
    drop(existing);
    let profile = installed.directory.path().join("cli-profile.json");
    write_private(&profile,br#"{"kind":"localPath","filesystemRowId":"fixture-recovery-fs","capabilityTestVectorId":"native-recovery-cap-v1"}"#);
    let phrase = installed.directory.path().join("cli-passphrase");
    write_private(&phrase,b"T9 CLI capture fixture");
    let snapshot = installed.directory.path().join("cli-snapshot.db");
    let output = installed.directory.path().join("cli-source.cbor");
    let arguments = [
        "--trust-anchor".into(), installed.anchor.as_os_str().to_owned(),
        "recovery-test".into(), installed.archive.as_os_str().to_owned(),
        "--key-inventory".into(), inventory_path.as_os_str().to_owned(),
        "--output".into(),output.as_os_str().to_owned(),
        "--recovery-mode".into(),"capture".into(),
        "--operator-config".into(),installed.config.as_os_str().to_owned(),
        "--archive-profile".into(),profile.as_os_str().to_owned(),
        "--snapshot".into(),snapshot.as_os_str().to_owned(),
        "--backup-passphrase-file".into(),phrase.as_os_str().to_owned(),
    ];
    let invocation=crate::args::parse(arguments.into_iter()).unwrap();
    let crate::args::Command::RecoveryTest { ref runtime,ref archive,ref key_inventory,ref output }=invocation.command else {panic!("parsed recovery mode")};
    let code=crate::recovery_command::run_with_runtime_opener(
        &invocation,archive,key_inventory,output,runtime.as_ref().unwrap(),support::live_clock(),
        |config,anchor,now| {
            let native=NativeOperatorProvider::open_test_fixture(installed.directory.path().join("ea-native-operator"),false)?;
            // Same documentable measurement as `RecoveryInstallation::open`.
            let host:Arc<dyn ea_key_provider::DevicePostureProvider>=Arc::new(ea_key_provider::DevicePostureProviderFake::unknown(ea_key_provider::PostureRequirement::FullDiskEncryption));
            OperatorRuntime::open_with_test_native_and_posture(config,anchor,now,false,native,host)
        },
    );
    assert_eq!(code,ea_recovery::ExitCode::Success);
    let after=installed.open();
    let exact=fs::read(output).unwrap();
    let stored=after.database().query_row("SELECT exact_envelope FROM recovery_source_scope",&[]).unwrap().unwrap();
    assert_eq!(stored.blob(0).unwrap(),exact);
    assert_eq!(after.database().query_row("SELECT count(*) FROM recovery_test_report",&[]).unwrap().unwrap().integer(0).unwrap(),0);
    assert!(snapshot.exists());
}


#[test]
#[ignore = "authentic Ubuntu completion imported into an explicitly snapshot-restored isolated Mac Source context"]
fn native_source_import_accepts_authentic_foreign_completion_and_mints_only_durable_fresh_proof() {
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
    let proof=reopened.fresh_machine_recovery_proof(&inventory).unwrap();
    assert!(proof.machine_fingerprint()!=ea_key_provider::measure_native_machine_identity().unwrap().fingerprint());
    assert_eq!(proof.expected_trust_anchor_hash().as_bytes(),anchor.trust_anchor_hash().as_bytes());
    assert_eq!(proof.media_expected(),inventory.media().len());
    let profile_path=installed.directory.path().join("source-profile.json");
    write_private(&profile_path,br#"{"kind":"localPath","filesystemRowId":"fixture-recovery-fs","capabilityTestVectorId":"native-recovery-cap-v1"}"#);
    for mode in ["import","status"] {
        let result_path=installed.directory.path().join(format!("cli-{mode}-report.cbor"));
        let mut words=vec!["recovery-test".to_string(),original_archive.to_string_lossy().into(),"--key-inventory".into(),export.join("inventory.json").to_string_lossy().into(),"--trust-anchor".into(),installed.anchor.to_string_lossy().into(),"--output".into(),result_path.to_string_lossy().into(),"--operator-config".into(),config_path.to_string_lossy().into(),"--archive-profile".into(),profile_path.to_string_lossy().into(),"--recovery-mode".into(),mode.into()];
        if mode=="import" { words.extend(["--source-envelope".into(),export.join("source-envelope.cbor").to_string_lossy().into(),"--completed-report".into(),PathBuf::from(std::env::var_os("EA_T9_COMPLETED_REPORT").unwrap()).to_string_lossy().into()]); }
        let invocation=args::parse(words.into_iter().map(std::ffi::OsString::from)).unwrap();
        let args::Command::RecoveryTest{archive,key_inventory,output,runtime:Some(command)}=&invocation.command else{panic!("native recovery command")};
        let code=recovery_command::run_with_runtime_opener(&invocation,archive,key_inventory,output,command,support::live_clock(),|config,anchor,now|{
            let native=NativeOperatorProvider::open_test_fixture(installed.directory.path().join("ea-native-operator"),false).unwrap();
            OperatorRuntime::open_with_test_native_and_posture(config,anchor,now,false,native,Arc::from(ea_key_provider::SupportMatrixRow::current_host().unwrap().posture_provider()))
        });
        assert_eq!(code,ea_recovery::ExitCode::Success,"native CLI {mode}");
        assert_eq!(fs::read(result_path).unwrap(),exact_report);
    }
    let checklist=reopened.evaluate_current_go_live(Some(&inventory),|current,freshness|{
        assert_eq!(current.head().registry_version().get(),scope.core().fields().registry_version);
        let evidence=ea_admin::GoLiveEvidence{active_admin_count:None,key_backups:None,registry:None,policy_present:None,evidence_policy_present:None,last_recovery_test:freshness,writer_transition:None,device_posture:None,eds_privacy_decision:None};
        ea_admin::evaluate_go_live(&evidence)
    }).unwrap();
    assert_eq!(checklist.requirements()[9].status(),ea_admin::GoLiveRequirementStatus::Confirmed);
    let freshness=reopened.recovery_test_freshness(&inventory).unwrap();
    let evidence=ea_admin::GoLiveEvidence{active_admin_count:None,key_backups:None,registry:None,policy_present:None,evidence_policy_present:None,last_recovery_test:Some(freshness),writer_transition:None,device_posture:None,eds_privacy_decision:None};
    assert_eq!(ea_admin::evaluate_go_live(&evidence).requirements()[9].status(),ea_admin::GoLiveRequirementStatus::Confirmed);
    let changed=original_archive.join("entries/000000000000_entry.eip");
    let original=fs::read(&changed).unwrap();
    let mut different=original.clone();let last=different.len()-1;different[last]^=1;
    fs::write(&changed,different).unwrap();
    assert_eq!(ea_admin::evaluate_go_live(&evidence).requirements()[9].status(),ea_admin::GoLiveRequirementStatus::NotMet);
    fs::write(changed,original).unwrap();
}


#[test]
#[ignore = "checks exact immutable evidence of the measured 198-second portable run"]
fn completed_time_of_portable_native_run_is_later_than_its_start() {
    let export=PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let exact_report=fs::read(PathBuf::from(std::env::var_os("EA_T9_COMPLETED_REPORT").unwrap())).unwrap();
    let source=ea_recovery::FsArchiveSource::open(&export.join("archive")).unwrap();
    let anchor=ea_recovery::load_trust_anchor(&export.join("independent-anchor.etb")).unwrap();
    let inventory=KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let scope=ea_recovery::verify_recovery_source(&fs::read(export.join("source-envelope.cbor")).unwrap(),&source,&anchor,&inventory,support::live_clock()).unwrap();
    let report=ea_recovery::verify_completed_recovery_report(&exact_report,&scope,&source,&anchor,&inventory,support::live_clock()).unwrap();
    let public:Value=serde_json::from_slice(report.public_report()).unwrap();
    assert!(report.completed_at().get()>public["effectiveNow"].as_i64().unwrap(),"a measured multi-minute native run must have a completion time after its opening selection");
}

#[test]
#[ignore = "actual fresh Ubuntu CLI restore-run using separate native authorization and immutable originals"]
fn portable_native_cli_restore_run_uses_every_explicit_source_and_commits_exact_report() {
    use ea_key_provider::SecretPurpose;
    let write_exact=|path:&Path,bytes:&[u8]| {
        if path.exists() {assert_eq!(fs::read(path).unwrap(),bytes,"retained CLI fixture bytes must match exactly");}
        else {write_private(path,bytes);}
    };
    let export=PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target=PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let existing=open_portable_target(&export,&target);
    let provider=Arc::clone(existing.runtime().signing_provider());
    let database=target.join("cli-restore-authorization.sqlite");
    let db=if database.exists() {
        EncryptedDatabase::open_existing(&database,provider.as_ref(),&provider.handle(SecretPurpose::LocalDatabaseKey)).unwrap()
    } else {
        let db=EncryptedDatabase::open(&database,provider.as_ref(),&provider.handle(SecretPurpose::LocalDatabaseKey)).unwrap();
        let profile=existing.runtime().database().query_row("SELECT organization_id,operator_subject_id,display_name,function_label,profile_commitment_salt,operator_binding_object_hash FROM operator_profile",&[]).unwrap().unwrap();
        db.execute("INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",&[StoreValue::Blob(profile.blob(0).unwrap().to_vec()),StoreValue::Blob(profile.blob(1).unwrap().to_vec()),StoreValue::Text(profile.text(2).unwrap().into()),StoreValue::Text(profile.text(3).unwrap().into()),StoreValue::Blob(profile.blob(4).unwrap().to_vec()),StoreValue::Blob(profile.blob(5).unwrap().to_vec())]).unwrap();
        db
    };
    drop(db);drop(existing);
    let config_path=target.join("cli-restore-operator.json");
    let mut config:Value=serde_json::from_slice(&fs::read(target.join("operator.json")).unwrap()).unwrap();
    config["database_path"]=json!("cli-restore-authorization.sqlite");
    write_exact(&config_path,&serde_json::to_vec(&config).unwrap());
    let profile_path=target.join("cli-restore-profile.json");
    write_exact(&profile_path,br#"{"kind":"localPath","filesystemRowId":"fixture-recovery-fs","capabilityTestVectorId":"native-recovery-cap-v1"}"#);
    let mapping:Vec<Value>=serde_json::from_slice(&fs::read(export.join("media.json")).unwrap()).unwrap();
    let rows:Vec<Value>=mapping.iter().map(|row| {
        let source=if row.get("pkcs11Id").is_some() {
            #[cfg(all(feature="pkcs11-fixture",unix))]
            {pkcs11::explicit_source(row,&target)}
            #[cfg(not(all(feature="pkcs11-fixture",unix)))]
            {panic!("the actual token fixture requires explicit pkcs11-fixture feature")}
        } else if let Some(slot)=row.get("nativeSlot") {format!("native:{}",slot.as_str().unwrap())}
        else {format!("container:{};passphrase-file={}",export.join(row["container"].as_str().unwrap()).display(),export.join(row["passphraseFile"].as_str().unwrap()).display())};
        json!({"mediumId":row["mediumId"],"source":source})
    }).collect();
    let media_path=target.join("cli-media-sources.json");
    write_exact(&media_path,&serde_json::to_vec(&json!({"schemaId":"ea.recovery-media-sources/v1","media":rows})).unwrap());
    let result_path=target.join("completed-cli-recovery.cbor");
    let words=vec!["--trust-anchor".into(),target.join("independent-anchor.etb").into_os_string(),"recovery-test".into(),target.join("archive").into_os_string(),"--key-inventory".into(),export.join("inventory.json").into_os_string(),"--output".into(),result_path.clone().into_os_string(),"--operator-config".into(),config_path.into_os_string(),"--archive-profile".into(),profile_path.into_os_string(),"--recovery-mode".into(),"restore-run".into(),"--source-envelope".into(),export.join("source-envelope.cbor").into_os_string(),"--snapshot".into(),export.join("snapshot.db").into_os_string(),"--backup-passphrase-file".into(),export.join("backup.passphrase").into_os_string(),"--restore-database".into(),target.join("cli-restored-sources.sqlite").into_os_string(),"--media-sources".into(),media_path.into_os_string()];
    let invocation=args::parse(words.into_iter()).unwrap();
    let args::Command::RecoveryTest{archive,key_inventory,output,runtime:Some(command)}=&invocation.command else{panic!("native recovery command")};
    let code=recovery_command::run_with_runtime_opener(&invocation,archive,key_inventory,output,command,support::live_clock(),|config,anchor,now|{
        let native=NativeOperatorProvider::open_test_fixture(target.join("ea-native-operator"),false).unwrap();
        let runtime=OperatorRuntime::open_with_test_native_and_posture(config,anchor,now,false,native,Arc::from(ea_key_provider::SupportMatrixRow::current_host().unwrap().posture_provider()))?;
        if runtime.posture_admission().is_err() {
            let context=runtime.posture_target_context()?;
            let exact=runtime.issue_posture_document(&context,ea_crypto::object_hash(b"T9 isolated CLI prerequisites"),300_000)?;
            runtime.import_posture_document(&exact)?;
        }
        Ok(runtime)
    });
    assert_eq!(code,ea_recovery::ExitCode::Success);
    let exact=fs::read(&result_path).unwrap();
    let database=EncryptedDatabase::open_existing(&database,provider.as_ref(),&provider.handle(SecretPurpose::LocalDatabaseKey)).unwrap();
    assert_eq!(database.query_row("SELECT exact_report FROM recovery_test_report ORDER BY completed_at DESC LIMIT 1",&[]).unwrap().unwrap().blob(0).unwrap(),exact);
    assert_eq!(database.query_row("SELECT operator_subject_id FROM operator_profile",&[]).unwrap().unwrap().blob(0).unwrap(),&[0x34;16]);
}

#[test]
fn native_recovery_medium_tests_installed_slots_with_presence_and_never_counts_an_offline_backup() {
    use ea_admin::recovery_test_runtime::RecoveryNativeSigningSlot;
    let installed=RecoveryInstallation::new();
    let runtime=installed.open();
    let mut inventory:Value=serde_json::from_slice(&installed.inventory_exact(&runtime)).unwrap();
    let admin=hex::encode(runtime.config().device_certificate_hash.as_bytes());
    for medium in inventory["media"].as_array_mut().unwrap() {
        if medium["certificateObjectHash"]==admin || medium["keyRole"]=="root" {
            medium["protectionProfile"]=json!("osWrapped");
            medium["testKind"]=json!("providerPresence");
        }
    }
    let inventory=KeyInventory::parse(&serde_json::to_vec(&inventory).unwrap()).unwrap();
    let admin=inventory.media().iter().find(|m|hex::encode(m.certificate().as_bytes())==admin).unwrap();
    let root=inventory.media().iter().find(|m|m.role()==RecoveryKeyRole::Root).unwrap();
    let offline=inventory.media().iter().find(|m|m.protection()==ea_format::KeyProtectionProfileV1::OfflineEncryptedContainer).unwrap();
    let sources=serde_json::to_vec(&json!({"schemaId":"ea.recovery-media-sources/v1","media":[{"mediumId":admin.id(),"source":"native:admin-signing"}]})).unwrap();
    let parsed=ea_admin::recovery_test_runtime::parse_recovery_media_sources(&sources,&inventory).unwrap();
    assert_eq!(parsed.len(),1);
    assert!(matches!(parsed[0].source,ea_admin::recovery_test_runtime::RecoveryMediumInput::NativeSigningSlot(RecoveryNativeSigningSlot::Admin)));
    for invalid in ["native:operator-instance","native:arbitrary-purpose"] {
        let sources=serde_json::to_vec(&json!({"schemaId":"ea.recovery-media-sources/v1","media":[{"mediumId":admin.id(),"source":invalid}]})).unwrap();
        assert!(ea_admin::recovery_test_runtime::parse_recovery_media_sources(&sources,&inventory).is_err());
    }
    let mut service=RecoveryTestRuntime::new(runtime,installed.profile.clone()).unwrap();
    let admin_proof=service.test_native_medium(admin,RecoveryNativeSigningSlot::Admin).unwrap();
    assert!(admin_proof.key_thumbprint()==admin.expected_thumbprint());
    service.test_native_medium(root,RecoveryNativeSigningSlot::Root).unwrap();
    assert!(service.test_native_medium(admin,RecoveryNativeSigningSlot::Writer).is_err());
    assert!(service.test_native_medium(offline,RecoveryNativeSigningSlot::Admin).is_err());
    assert_eq!(service.runtime().database().query_row("SELECT count(*) FROM recovery_test_report",&[]).unwrap().unwrap().integer(0).unwrap(),0);
    fs::write(installed.directory.path().join("helper-mode"),b"instance-missing").unwrap();
    assert!(service.test_native_medium(admin,RecoveryNativeSigningSlot::Admin).is_err());
}

mod current_floor;

mod failure;
mod diagnostics;
mod session_observer;

mod native_archive;
