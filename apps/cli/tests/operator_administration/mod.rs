use super::*;
use ea_admin::{
    administration_runtime::views::current_view,
    native_provider::NativeOperatorProvider,
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig},
};

struct AdministrationInstallation {
    directory: support::TempDir,
    config: PathBuf,
    anchor: PathBuf,
    writer: ObjectHash,
    admin: ObjectHash,
    reader: ObjectHash,
    line: RegistryLineBuilder,
}
impl AdministrationInstallation {
    fn new() -> Self {
        let directory = support::temp_dir("administration-native");
        install_fixture_helper(directory.path());
        fs::write(directory.path().join("authority-fixture"), b"").unwrap();
        let subject = OperatorSubjectId::try_from(&[0x42; 16][..]).unwrap();
        let material = support::verify_support::historical::fixture_with_host_options(
            |_, _| b"administration fixture does not open incident plaintext".to_vec(),
            Some(support::verify_support::historical::HostOptions {
                not_after: support::LIVE_WRITER_NOT_AFTER_V1,
                max_age: support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
                instance: ADMIN_INSTANCE_SECRET,
                account_hash: native_account_hash_for(
                    true,
                    DeviceId::try_from(&[0x52; 16][..]).unwrap(),
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
        let archive = directory.path().join("archive");
        support::materialize(&material.fixture, &archive);
        let anchor = directory.path().join("anchor.etb");
        fs::write(&anchor, material.line.exact_anchor_bytes()).unwrap();
        let admin = material.line.second_bootstrap_admin_hash();
        let writer = material.line.heads()[5].direct_object_hash.unwrap();
        let reader =
            ObjectHash::try_from(material.recipient_certificate_hash.as_bytes().as_slice())
                .unwrap();
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
        drop(db);
        let config = directory.path().join("operator.json");
        fs::write(
            &config,
            serde_json::to_vec(&json!({
                "archive_directory":"archive","database_path":"operator.sqlite",
                "device_certificate_hash":hex::encode(admin.as_bytes()),
                "binding_object_hash":hex::encode(material.operator_binding.as_bytes()),
                "role":"organization-admin","purpose":"admin-root-ceremony"
            }))
            .unwrap(),
        )
        .unwrap();
        Self {
            directory,
            config,
            anchor,
            writer,
            admin,
            reader,
            line: material.line,
        }
    }
    fn open(&self) -> OperatorRuntime {
        let native = NativeOperatorProvider::open_test_fixture(
            self.directory.path().join("ea-native-operator"),
            false,
        )
        .unwrap();
        OperatorRuntime::open_with_test_native(
            OperatorRuntimeConfig::load(&self.config).unwrap(),
            &self.anchor,
            support::live_clock(),
            false,
            native,
        )
        .unwrap()
    }
}

#[test]
fn current_native_admin_views_classify_real_targets_and_do_not_claim_revocation_recall() {
    let installation = AdministrationInstallation::new();
    let mut runtime = installation.open();
    let view = current_view(&mut runtime).unwrap();
    assert_eq!(view.policy().operating_profile, 0);
    assert_eq!(view.policy().registry_expiry_behavior, 0);
    assert_eq!(
        view.current_writer().unwrap().as_bytes(),
        installation.writer.as_bytes()
    );
    assert!(view.transition().is_none());
    let effect = view.revocation_effect(installation.writer).unwrap();
    assert_eq!(effect.stops_new_grants_from().get(), 1);
    assert!(!effect.recalls_issued_grants());
    assert!(!effect.recalls_decrypted_plaintext());
    assert_eq!(
        view.revocation_effect(installation.admin)
            .unwrap_err()
            .code(),
        "EA-WORKFLOW-ADMIN-CERTIFICATE-LIFECYCLE"
    );
    assert_eq!(
        view.revocation_effect(ea_crypto::object_hash(b"unknown target"))
            .unwrap_err()
            .code(),
        "EA-WORKFLOW-TARGET-NOT-ACTIVE"
    );
}

#[test]
fn native_writer_authority_cannot_open_an_administration_view() {
    let installation = Installation::new();
    let native = NativeOperatorProvider::open_test_fixture(
        installation.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    let mut runtime = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&installation.config).unwrap(),
        &installation.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap();
    assert!(current_view(&mut runtime).is_err());
}

#[test]
fn native_revoke_intent_is_durable_without_fabricating_an_authorized_or_published_step() {
    use ea_admin::administration_runtime::{TrustCeremonyRoundV1, ceremony};
    use ea_admin::{TrustCeremonyKind, TrustCeremonyStep};
    let installed = AdministrationInstallation::new();
    let mut runtime = installed.open();
    let before = runtime.head().registry_head_hash();
    let created = ceremony::begin_revoke(&mut runtime, installed.reader).unwrap();
    assert_eq!(created.kind(), TrustCeremonyKind::DeviceRevoke);
    assert_eq!(created.round(), TrustCeremonyRoundV1::ActivateRegistry);
    assert_eq!(created.step(), TrustCeremonyStep::PendingRequest);
    assert!(created.fingerprint_subject().is_none());
    let id = created.id();
    let exact = created.exact_target_payload().to_vec();
    drop(runtime);
    let mut runtime = installed.open();
    let resumed = ceremony::load(&mut runtime, id).unwrap();
    assert_eq!(resumed.step(), TrustCeremonyStep::PendingRequest);
    assert_eq!(resumed.exact_target_payload(), exact);
    assert!(runtime.head().registry_head_hash() == before);
    assert!(
        runtime
            .head()
            .active_certificate_fields(CertificateHash::from(installed.reader))
            .is_some()
    );
}

const SOURCE_ADMIN_INSTANCE_SECRET: [u8; 32] = [0x6a; 32];
/// Only the explicit test marker changes this synthetic provider. Production
/// never consults a directory marker and this source does not hold a Root slot.
pub(super) fn native_key_response(directory: &Path, request: &Value) -> Option<Value> {
    if !directory.join("administration-source-fixture").exists() {
        return None;
    }
    let slot = request["slot"].as_str().unwrap_or("");
    let op = request["op"].as_str().unwrap_or("");
    if slot == "root-signing" {
        return Some(json!({"ok":false}));
    }
    let secret = match slot {
        "admin-signing" => trust_support::device_signing_secret(),
        "operator-instance" => SOURCE_ADMIN_INSTANCE_SECRET,
        _ => return None,
    };
    match op {
        "public-key" => Some(
            json!({"public_key":hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())}),
        ),
        "sign" => Some(
            json!({"signature":hex::encode(SigningKey::from_bytes(&secret).sign(&hex::decode(request["data"].as_str().unwrap()).unwrap()).to_bytes())}),
        ),
        "contains" => Some(json!({"contains":true})),
        _ => None,
    }
}

#[test]
fn native_revoke_admin_authorization_requires_its_purpose_and_durable_signed_audit() {
    use ea_admin::TrustCeremonyStep;
    use ea_admin::administration_runtime::{authorization, ceremony};
    let installed = AdministrationInstallation::new();
    let mut runtime = installed.open();
    let intent = ceremony::begin_revoke(&mut runtime, installed.reader).unwrap();
    let wrong = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::RecoveryTest)
        .unwrap();
    assert!(authorization::authorize(&mut runtime, intent.id(), &wrong).is_err());
    assert_eq!(
        ceremony::load(&mut runtime, intent.id()).unwrap().step(),
        TrustCeremonyStep::PendingRequest
    );
    let correct = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    let authorized = authorization::authorize(&mut runtime, intent.id(), &correct).unwrap();
    assert_eq!(authorized.step(), TrustCeremonyStep::AdminAuthorized);
    assert!(
        runtime
            .head()
            .active_certificate_fields(CertificateHash::from(installed.reader))
            .is_some()
    );
    let row=runtime.database().query_row("SELECT r.exact_record,a.exact_bytes FROM administration_ceremony_record r JOIN local_audit_event a ON a.event_id=r.audit_event_id WHERE r.intent_hash=?1 AND r.stage=1",&[StoreValue::Blob(intent.id().as_bytes().to_vec())]).unwrap().unwrap();
    let exact_record = row.blob(0).unwrap().to_vec();
    let exact_target = authorized.exact_target_payload().to_vec();
    let parsed = ea_format::decode_local_audit_event(row.blob(1).unwrap()).unwrap();
    assert_eq!(parsed.outcome(), ea_format::LocalAuditOutcomeV1::Accepted);
    assert!(matches!(
        parsed.action(),
        ea_format::LocalAuditActionV1::Login(_)
    ));
    drop(runtime);
    let mut runtime = installed.open();
    assert_eq!(
        ceremony::load(&mut runtime, intent.id()).unwrap().step(),
        TrustCeremonyStep::AdminAuthorized
    );
    let renewed_presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    let repeated = authorization::authorize(&mut runtime, intent.id(), &renewed_presence).unwrap();
    assert_eq!(repeated.exact_target_payload(), exact_target);
    let reread = runtime.database().query_row("SELECT exact_record FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=1", &[StoreValue::Blob(intent.id().as_bytes().to_vec())]).unwrap().unwrap();
    assert_eq!(reread.blob(0).unwrap(), exact_record);
    assert!(
        !fs::read_to_string(installed.directory.path().join("helper-calls"))
            .unwrap()
            .contains("root-signing")
    );
}

#[test]
fn native_authorization_audit_flush_failure_preserves_only_the_unsigned_intent() {
    use ea_admin::administration_runtime::{authorization, ceremony};
    let installed = AdministrationInstallation::new();
    let mut runtime = installed.open();
    let intent = ceremony::begin_revoke(&mut runtime, installed.reader).unwrap();
    let proof = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    runtime.database().execute("CREATE TRIGGER administration_test_fail_audit BEFORE INSERT ON local_audit_event BEGIN SELECT RAISE(ABORT,'injected durable audit failure'); END", &[]).unwrap();
    assert!(authorization::authorize(&mut runtime, intent.id(), &proof).is_err());
    assert!(
        runtime
            .database()
            .query_row(
                "SELECT stage FROM administration_ceremony_record WHERE intent_hash=?1",
                &[StoreValue::Blob(intent.id().as_bytes().to_vec())]
            )
            .unwrap()
            .is_none()
    );
    drop(runtime);
    let mut reopened = installed.open();
    assert_eq!(
        ceremony::load(&mut reopened, intent.id()).unwrap().step(),
        ea_admin::TrustCeremonyStep::PendingRequest
    );
    assert!(
        reopened
            .head()
            .active_certificate_fields(CertificateHash::from(installed.reader))
            .is_some()
    );
}

struct SeparateAdministrationStations {
    source: AdministrationInstallation,
    root: AdministrationInstallation,
    exchange: support::TempDir,
    profile: ea_archive::ArchiveBackendProfileV1,
}
impl SeparateAdministrationStations {
    fn new() -> Self {
        use ea_trust::TrustObjectSource as _;
        let mut root = AdministrationInstallation::new();
        let mut source = AdministrationInstallation::new();
        let mut prior = std::collections::BTreeSet::new();
        root.line
            .source()
            .visit_trust_object_hashes(&mut |hash| {
                prior.insert(hash);
                Ok(())
            })
            .unwrap();
        let options = || HeadOptions {
            effective_from: Some(1),
            valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
            ..HeadOptions::default()
        };
        let certificate = root
            .line
            .push(
                ActionSpec::AdminIssue {
                    marker: 0x34,
                    effective_from: Some(1),
                },
                options(),
            )
            .direct_object_hash
            .unwrap();
        let subject = OperatorSubjectId::try_from(&[0x34; 16][..]).unwrap();
        let instance = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
            SOURCE_ADMIN_INSTANCE_SECRET,
        ))
        .public_key()
        .unwrap();
        let binding = root
            .line
            .push(
                ActionSpec::OperatorBinding {
                    certificate_hash: certificate,
                    role: OperatorRoleV1::OrganizationAdmin,
                    marker: 0x34,
                    effective_from: Some(1),
                },
                HeadOptions {
                    binding_instance_key_thumbprint_override: Some(instance.thumbprint()),
                    binding_operator_profile_commitment_override: Some(
                        ea_crypto::operator_profile_commitment(
                            trust_support::organization(),
                            subject,
                            TEST_NAME,
                            TEST_FUNCTION,
                            &PROFILE_SALT,
                        ),
                    ),
                    binding_os_account_hash_override: Some(native_account_hash_for(
                        true,
                        DeviceId::try_from(&[0x74; 16][..]).unwrap(),
                    )),
                    ..options()
                },
            )
            .direct_object_hash
            .unwrap();
        let profile =
            ea_archive::ArchiveBackendProfileV1::LocalPath(ea_archive::LocalPathProfileV1 {
                filesystem_row_id: "fixture-native-administration-fs".into(),
                capability_test_vector_id: "native-administration-v1".into(),
            });
        root.line.push(
            ActionSpec::Policy {
                policy_version: Some(2),
                previous_policy_hash: Some(root.line.current_policy_hash()),
                effective_from: Some(1),
            },
            HeadOptions {
                policy_max_registry_age_ms_override: Some(
                    support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
                ),
                policy_allowed_archive_profile_hashes_override: Some(vec![
                    profile.profile_hash().unwrap(),
                ]),
                ..options()
            },
        );
        let archive = root.directory.path().join("archive");
        let catalog = root.line.source();
        catalog
            .visit_trust_object_hashes(&mut |hash| {
                let exact = catalog.read_exact_trust_object(hash)?.unwrap();
                if !prior.contains(&hash) {
                    fs::write(
                        archive.join(format!("{}.etb", hex::encode(hash.as_bytes()))),
                        exact.as_ref(),
                    )
                    .unwrap();
                }
                Ok(())
            })
            .unwrap();
        drop(catalog);
        fs::write(
            source
                .directory
                .path()
                .join("administration-source-fixture"),
            b"",
        )
        .unwrap();
        let (provider, key) = database_provider_for(true);
        let db = EncryptedDatabase::open(
            &source.directory.path().join("operator.sqlite"),
            &provider,
            &key,
        )
        .unwrap();
        db.execute("UPDATE operator_profile SET operator_subject_id=?1,operator_binding_object_hash=?2 WHERE singleton=0",&[StoreValue::Blob(subject.as_bytes().to_vec()),StoreValue::Blob(binding.as_bytes().to_vec())]).unwrap();
        drop(db);
        let exchange = support::temp_dir("admin-root-exchange");
        let mut source_config: Value =
            serde_json::from_slice(&fs::read(&source.config).unwrap()).unwrap();
        let mut root_config: Value =
            serde_json::from_slice(&fs::read(&root.config).unwrap()).unwrap();
        source_config["archive_directory"] = json!(archive);
        source_config["device_certificate_hash"] = json!(hex::encode(certificate.as_bytes()));
        source_config["binding_object_hash"] = json!(hex::encode(binding.as_bytes()));
        source_config["admin_certificate_hash"] = root_config["device_certificate_hash"].clone();
        source_config["admin_binding_object_hash"] = root_config["binding_object_hash"].clone();
        source_config["ceremony_exchange_directory"] = json!(exchange.path());
        root_config["ceremony_exchange_directory"] = json!(exchange.path());
        root_config["authority"] = json!(true);
        root_config["target_certificate_hash"] = json!(hex::encode(certificate.as_bytes()));
        fs::write(&source.config, serde_json::to_vec(&source_config).unwrap()).unwrap();
        fs::write(&root.config, serde_json::to_vec(&root_config).unwrap()).unwrap();
        source.admin = certificate;
        source.reader = root.reader;
        Self {
            source,
            root,
            exchange,
            profile,
        }
    }
    fn service(&self) -> RootService {
        use std::process::{Command, Stdio};
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "process_native::fixture_cli",
                "--nocapture",
            ])
            .env("EA_OPERATOR_FIXTURE_DIRECTORY", self.root.directory.path())
            .env(
                "EA_OPERATOR_FIXTURE_ARGS",
                serde_json::to_string(&vec![
                    "--trust-anchor",
                    self.root.anchor.to_str().unwrap(),
                    "operator",
                    "provision",
                    "--operator-config",
                    self.root.config.to_str().unwrap(),
                    "--format",
                    "json",
                ])
                .unwrap(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        RootService(child)
    }
}
struct RootService(std::process::Child);
impl Drop for RootService {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn native_ceremony_exports_and_imports_exact_root_reply_across_restarts() {
    use ea_admin::administration_runtime::{authorization, ceremony, exchange};
    let stations = SeparateAdministrationStations::new();
    let mut runtime = stations.source.open();
    let intent = ceremony::begin_revoke(&mut runtime, stations.source.reader).unwrap();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    authorization::authorize(&mut runtime, intent.id(), &presence).unwrap();
    let exported = exchange::export_request(&mut runtime, intent.id()).unwrap();
    assert_eq!(
        exported.step(),
        ea_admin::TrustCeremonyStep::RootRequestExported
    );
    let request = fs::read_dir(stations.exchange.path())
        .unwrap()
        .map(Result::unwrap)
        .find(|e| e.file_name().to_string_lossy().starts_with("request-"))
        .unwrap()
        .path();
    let exact_request = fs::read(&request).unwrap();
    drop(runtime);
    let mut runtime = stations.source.open();
    assert_eq!(
        ceremony::load(&mut runtime, intent.id()).unwrap().step(),
        ea_admin::TrustCeremonyStep::RootRequestExported
    );
    exchange::export_request(&mut runtime, intent.id()).unwrap();
    assert_eq!(fs::read(&request).unwrap(), exact_request);
    assert!(exchange::import_reply(&mut runtime, intent.id()).is_err());
    let mut service = stations.service();
    let reply = request.with_file_name(
        request
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .replacen("request-", "reply-", 1),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    while !reply.exists() {
        assert!(service.0.try_wait().unwrap().is_none());
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let imported = exchange::import_reply(&mut runtime, intent.id()).unwrap();
    assert_eq!(
        imported.step(),
        ea_admin::TrustCeremonyStep::RootReplyImported
    );
    assert!(
        runtime
            .head()
            .active_certificate_fields(CertificateHash::from(stations.source.reader))
            .is_some()
    );
    drop(runtime);
    let mut runtime = stations.source.open();
    assert_eq!(
        ceremony::load(&mut runtime, intent.id()).unwrap().step(),
        ea_admin::TrustCeremonyStep::RootReplyImported
    );
}
#[test]
fn native_exchange_file_failure_cannot_claim_request_exported() {
    use ea_admin::administration_runtime::{authorization, ceremony, exchange};
    let stations = SeparateAdministrationStations::new();
    let mut runtime = stations.source.open();
    let intent = ceremony::begin_revoke(&mut runtime, stations.source.reader).unwrap();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    authorization::authorize(&mut runtime, intent.id(), &presence).unwrap();
    fs::create_dir(stations.exchange.path().join(".ea-exchange-write.lock")).unwrap();
    assert!(exchange::export_request(&mut runtime, intent.id()).is_err());
    assert_eq!(
        ceremony::load(&mut runtime, intent.id()).unwrap().step(),
        ea_admin::TrustCeremonyStep::AdminAuthorized
    );
}

fn prepare_registry_publication(
    stations: &SeparateAdministrationStations,
) -> (ea_admin::operator_runtime::OperatorRuntime, ObjectHash) {
    use ea_admin::administration_runtime::{authorization, ceremony, exchange};
    let mut runtime = stations.source.open();
    let intent = ceremony::begin_revoke(&mut runtime, stations.source.reader).unwrap();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    authorization::authorize(&mut runtime, intent.id(), &presence).unwrap();
    let exported = exchange::export_request(&mut runtime, intent.id()).unwrap();
    let reply = stations.exchange.path().join(
        exported
            .exchange_file_name()
            .unwrap()
            .replacen("request-", "reply-", 1),
    );
    let mut service = stations.service();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    while !reply.exists() {
        assert!(service.0.try_wait().unwrap().is_none());
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    exchange::import_reply(&mut runtime, intent.id()).unwrap();
    (runtime, intent.id())
}
#[test]
fn a_published_registry_resumes_after_completion_commit_failure_with_the_same_signed_audit() {
    use ea_admin::administration_runtime::{ceremony, publication};
    let stations = SeparateAdministrationStations::new();
    let (mut runtime, id) = prepare_registry_publication(&stations);
    runtime.database().execute("CREATE TRIGGER fail_admin_publication_completion BEFORE INSERT ON administration_ceremony_record WHEN NEW.stage=5 BEGIN SELECT RAISE(ABORT,'fixture-completion-flush'); END",&[]).unwrap();
    let before = runtime.head().registry_head_hash();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    assert!(publication::publish(&mut runtime, id, &stations.profile, &presence).is_err());
    assert!(runtime.head().registry_head_hash() != before);
    assert!(
        runtime
            .head()
            .active_certificate_fields(CertificateHash::from(stations.source.reader))
            .is_none()
    );
    let signed=runtime.database().query_row("SELECT r.exact_record,a.exact_bytes FROM administration_ceremony_record r JOIN local_audit_event a ON a.event_id=r.audit_event_id WHERE r.intent_hash=?1 AND r.stage=4",&[StoreValue::Blob(id.as_bytes().to_vec())]).unwrap().unwrap();
    let exact_job = signed.blob(0).unwrap().to_vec();
    let exact_audit = signed.blob(1).unwrap().to_vec();
    runtime
        .database()
        .execute("DROP TRIGGER fail_admin_publication_completion", &[])
        .unwrap();
    drop(runtime);
    let mut reopened = stations.source.open();
    assert_eq!(
        ceremony::load(&mut reopened, id).unwrap().step(),
        ea_admin::TrustCeremonyStep::RootReplyImported
    );
    let presence = reopened
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    assert_eq!(
        publication::publish(&mut reopened, id, &stations.profile, &presence)
            .unwrap()
            .step(),
        ea_admin::TrustCeremonyStep::RegistryPublished
    );
    let same=reopened.database().query_row("SELECT r.exact_record,a.exact_bytes FROM administration_ceremony_record r JOIN local_audit_event a ON a.event_id=r.audit_event_id WHERE r.intent_hash=?1 AND r.stage=4",&[StoreValue::Blob(id.as_bytes().to_vec())]).unwrap().unwrap();
    assert_eq!(same.blob(0).unwrap(), exact_job);
    assert_eq!(same.blob(1).unwrap(), exact_audit);
}
#[test]
fn a_failed_publication_audit_releases_no_registry_or_authorization_bytes() {
    use ea_admin::administration_runtime::{ceremony, publication};
    let stations = SeparateAdministrationStations::new();
    let (mut runtime, id) = prepare_registry_publication(&stations);
    let before = runtime.head().registry_head_hash();
    let count = std::fs::read_dir(runtime.config().archive_directory.join("trust"))
        .unwrap()
        .count();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    runtime.database().execute("CREATE TRIGGER fail_admin_publication_audit BEFORE INSERT ON local_audit_event BEGIN SELECT RAISE(ABORT,'fixture-audit-flush'); END",&[]).unwrap();
    assert!(publication::publish(&mut runtime, id, &stations.profile, &presence).is_err());
    assert!(runtime.head().registry_head_hash() == before);
    assert_eq!(
        std::fs::read_dir(runtime.config().archive_directory.join("trust"))
            .unwrap()
            .count(),
        count
    );
    assert!(runtime.database().query_row("SELECT stage FROM administration_ceremony_record WHERE intent_hash=?1 AND stage>=4",&[StoreValue::Blob(id.as_bytes().to_vec())]).unwrap().is_none());
    runtime
        .database()
        .execute("DROP TRIGGER fail_admin_publication_audit", &[])
        .unwrap();
    drop(runtime);
    let mut reopened = stations.source.open();
    assert_eq!(
        ceremony::load(&mut reopened, id).unwrap().step(),
        ea_admin::TrustCeremonyStep::RootReplyImported
    );
    assert!(
        reopened
            .head()
            .active_certificate_fields(CertificateHash::from(stations.source.reader))
            .is_some()
    );
}
#[test]
fn native_registry_publication_is_effective_and_reopens_from_its_original_exact_job() {
    use ea_admin::administration_runtime::{authorization, ceremony, exchange, publication};
    let stations = SeparateAdministrationStations::new();
    let mut runtime = stations.source.open();
    let before = runtime.head().registry_head_hash();
    let intent = ceremony::begin_revoke(&mut runtime, stations.source.reader).unwrap();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    authorization::authorize(&mut runtime, intent.id(), &presence).unwrap();
    let exported = exchange::export_request(&mut runtime, intent.id()).unwrap();
    let reply = stations.exchange.path().join(
        exported
            .exchange_file_name()
            .unwrap()
            .replacen("request-", "reply-", 1),
    );
    let mut service = stations.service();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    while !reply.exists() {
        assert!(service.0.try_wait().unwrap().is_none());
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    exchange::import_reply(&mut runtime, intent.id()).unwrap();
    let wrong = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::RecoveryTest)
        .unwrap();
    assert!(publication::publish(&mut runtime, intent.id(), &stations.profile, &wrong).is_err());
    assert!(runtime.head().registry_head_hash() == before);
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    let published = publication::publish(&mut runtime, intent.id(), &stations.profile, &presence);
    assert!(runtime.head().registry_head_hash() != before);
    assert!(
        runtime
            .head()
            .active_certificate_fields(CertificateHash::from(stations.source.reader))
            .is_none()
    );
    assert_eq!(runtime.next_sequence().get(), 1);
    let published = published.unwrap();
    assert_eq!(
        published.step(),
        ea_admin::TrustCeremonyStep::RegistryPublished
    );
    drop(runtime);
    let mut reopened = stations.source.open();
    assert_eq!(
        ceremony::load(&mut reopened, intent.id()).unwrap().step(),
        ea_admin::TrustCeremonyStep::RegistryPublished
    );
    assert!(
        reopened
            .head()
            .active_certificate_fields(CertificateHash::from(stations.source.reader))
            .is_none()
    );
}
#[test]
fn separate_native_root_signs_the_exact_existing_admin_authorization_target() {
    use ea_admin::administration_runtime::{authorization, ceremony};
    use ea_admin::operator_exchange::{NativeExchangeSigner, PendingExchange, write_exchange_file};
    let stations = SeparateAdministrationStations::new();
    let mut runtime = stations.source.open();
    let intent = ceremony::begin_revoke(&mut runtime, stations.source.reader).unwrap();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    let authorized = authorization::authorize(&mut runtime, intent.id(), &presence).unwrap();
    let row=runtime.database().query_row("SELECT exact_record FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=1",&[StoreValue::Blob(intent.id().as_bytes().to_vec())]).unwrap().unwrap();
    let mut decoder = minicbor::Decoder::new(row.blob(0).unwrap());
    assert_eq!(decoder.array().unwrap(), Some(2));
    let exact_authorization = decoder.bytes().unwrap().to_vec();
    let config = runtime.config();
    let authority = config.admin_certificate_hash.unwrap();
    let public = |certificate| {
        CanonicalPublicCoseKey::from_deterministic_cbor(
            runtime
                .head()
                .active_certificate_fields(certificate)
                .unwrap()
                .signing_public_cose_key
                .as_deref()
                .unwrap(),
        )
        .unwrap()
    };
    let pending=PendingExchange::load_or_create(runtime.database(),json!({
      "context":{"organization_id":hex::encode(runtime.anchor().organization_id().as_bytes()),"chain_id":hex::encode(runtime.head().chain_id().as_bytes()),
      "registry_head_hash":hex::encode(runtime.head().registry_head_hash().as_bytes()),"registry_version":runtime.head().registry_version().get(),
      "sequence":runtime.next_sequence().get(),"device_certificate_hash":hex::encode(config.device_certificate_hash.as_bytes()),
      "admin_certificate_hash":hex::encode(authority.as_bytes()),"admin_binding_object_hash":hex::encode(config.admin_binding_object_hash.unwrap().as_bytes())},
      "op":"admin-trust-target","args":{"target_payload":hex::encode(authorized.exact_target_payload()),"authorization":hex::encode(&exact_authorization),"relevant_objects":[]}
    }),&NativeExchangeSigner::administrator(runtime.native()),&public(config.device_certificate_hash)).unwrap();
    write_exchange_file(
        &stations
            .exchange
            .path()
            .join(format!("request-{}.json", pending.request_id())),
        pending.request_bytes(),
    )
    .unwrap();
    let mut service = stations.service();
    let reply_path = stations
        .exchange
        .path()
        .join(format!("reply-{}.json", pending.request_id()));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    while !reply_path.exists() {
        assert!(
            service.0.try_wait().unwrap().is_none(),
            "authority exited before signed reply"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "bounded root reply timeout"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let exact_reply = fs::read(&reply_path).unwrap();
    let response = pending
        .open_reply(&exact_reply, &public(authority))
        .unwrap();
    assert!(
        response.get("error").is_none(),
        "actual Root dispatch refused: {response}"
    );
    assert_eq!(response.as_object().unwrap().len(), 1);
    let target = hex::decode(response["target"].as_str().unwrap()).unwrap();
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&target).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        parsed.value().exact_digest_input(),
        authorized.exact_target_payload()
    );
    let context = ea_crypto::VerificationContext::root_trust_digest(
        parsed.value().exact_digest_input(),
        CertificateHash::from(runtime.head().root_certificate_object_hash()),
        Some(&exact_authorization),
    )
    .unwrap();
    for signature in parsed.value().signatures() {
        ea_crypto::verify_cose_sign1(signature, runtime.head(), &context).unwrap();
    }
    let (provider, key) = database_provider_for(true);
    let db = EncryptedDatabase::open(
        &stations.root.directory.path().join("operator.sqlite"),
        &provider,
        &key,
    )
    .unwrap();
    let row = db
        .query_row(
            "SELECT exact_bytes FROM local_audit_event ORDER BY insertion_sequence DESC LIMIT 1",
            &[],
        )
        .unwrap()
        .unwrap();
    let audit = ea_format::decode_local_audit_event(row.blob(0).unwrap()).unwrap();
    let ea_format::LocalAuditActionV1::AdminRootCeremony(a) = audit.action() else {
        panic!()
    };
    assert!(a.target_object_hash() == ea_crypto::object_hash(&target));
    assert!(a.authorization_object_hash() == ea_crypto::object_hash(&exact_authorization));
    assert!(
        !fs::read_to_string(stations.source.directory.path().join("helper-calls"))
            .unwrap()
            .contains("root-signing")
    );
    assert!(
        fs::read_to_string(stations.root.directory.path().join("helper-calls"))
            .unwrap()
            .contains("sign root-signing")
    );
    let signatures = fs::read_to_string(stations.root.directory.path().join("helper-calls"))
        .unwrap()
        .lines()
        .filter(|s| *s == "sign root-signing")
        .count();
    let audit_count = db
        .query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    drop(service);
    fs::remove_file(&reply_path).unwrap();
    let mut restarted = stations.service();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    while !reply_path.exists() {
        assert!(restarted.0.try_wait().unwrap().is_none());
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(fs::read(&reply_path).unwrap(), exact_reply);
    assert_eq!(
        fs::read_to_string(stations.root.directory.path().join("helper-calls"))
            .unwrap()
            .lines()
            .filter(|s| *s == "sign root-signing")
            .count(),
        signatures
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM local_audit_event", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        audit_count
    );
}

fn actual_registration_intent(
    runtime: &ea_admin::operator_runtime::OperatorRuntime,
) -> (Vec<u8>, Vec<u8>) {
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([0x68; 32]));
    let core = ea_crypto::DeviceRegistrationRequestCoreV1 {
        organization_id: runtime.anchor().organization_id(),
        device_id: ea_types::DeviceId::try_from([0x69; 16].as_slice()).unwrap(),
        requested_role: 1,
        signing_public_cose_key: signer.public_key().unwrap(),
        kem_public_cose_key: Some(
            ea_crypto::CanonicalPublicCoseKey::x25519(
                *ea_crypto::HpkeRecipientPrivateKey::from_bytes(ea_crypto::SecretBytes::new(
                    [0x67; 32],
                ))
                .unwrap()
                .public_key()
                .as_bytes(),
            )
            .unwrap(),
        ),
        supported_format_versions: vec![1],
        supported_suite_ids: vec![ea_crypto::SUITE_ID.into()],
    };
    let exact_core = ea_crypto::encode_device_registration_request_core(&core).unwrap();
    let request = ea_sync_protocol::DeviceRegistrationRequestV1::new(
        core.clone(),
        &signer.sign_enrollment(&exact_core).unwrap(),
    )
    .unwrap();
    let target = ea_format::TrustPayloadV1::authorized_device_certificate(
        ea_format::DeviceCertificateFieldsV1 {
            organization_id: core.organization_id,
            device_id: core.device_id,
            certificate_kind: CertificateKindV1::Reader,
            signing_public_cose_key: Some(core.signing_public_cose_key.to_deterministic_cbor()),
            signing_key_thumbprint: Some(core.signing_public_cose_key.thumbprint()),
            kem_public_cose_key: Some(
                core.kem_public_cose_key
                    .as_ref()
                    .unwrap()
                    .to_deterministic_cbor(),
            ),
            kem_key_thumbprint: Some(core.kem_public_cose_key.as_ref().unwrap().thumbprint()),
            capabilities: vec![],
            key_protection_profile: ea_format::KeyProtectionProfileV1::OsWrapped,
            effective_from_sequence: runtime.next_sequence(),
            revoked_from_sequence: None,
            authority_subject_id: None,
        },
        ObjectHash::from(ea_types::Hash32::ZERO),
    )
    .unwrap();
    (
        request.exact_bytes().to_vec(),
        target.exact_digest_input().to_vec(),
    )
}
#[test]
fn native_registration_fingerprint_is_request_bound_and_cannot_skip_confirmation() {
    use ea_admin::administration_runtime::{
        FingerprintSubjectV1, TrustCeremonyRoundV1, authorization, ceremony,
    };
    let installed = AdministrationInstallation::new();
    let mut runtime = installed.open();
    let (request, target) = actual_registration_intent(&runtime);
    let pending = ceremony::begin_registration(&mut runtime, &request, &target).unwrap();
    assert_eq!(pending.round(), TrustCeremonyRoundV1::IssueTarget);
    assert_eq!(pending.kind(), ea_admin::TrustCeremonyKind::DeviceApprove);
    assert_eq!(
        pending.fingerprint_subject(),
        Some(FingerprintSubjectV1::RegistrationRequest)
    );
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    assert!(authorization::authorize(&mut runtime, pending.id(), &presence).is_err());
    assert!(
        ceremony::confirm_registration_fingerprint(
            &mut runtime,
            pending.id(),
            ObjectHash::from(ea_types::Hash32::ZERO)
        )
        .is_err()
    );
    assert_eq!(
        ceremony::confirm_registration_fingerprint(
            &mut runtime,
            pending.id(),
            ea_crypto::object_hash(&request)
        )
        .unwrap()
        .step(),
        ea_admin::TrustCeremonyStep::FingerprintConfirmed
    );
    drop(runtime);
    let mut reopened = installed.open();
    assert_eq!(
        ceremony::load(&mut reopened, pending.id()).unwrap().step(),
        ea_admin::TrustCeremonyStep::FingerprintConfirmed
    );
    let presence = reopened
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    assert_eq!(
        authorization::authorize(&mut reopened, pending.id(), &presence)
            .unwrap()
            .step(),
        ea_admin::TrustCeremonyStep::AdminAuthorized
    );
    assert!(
        reopened
            .head()
            .active_certificates()
            .all(|(_, c)| c.device_id.as_bytes() != &[0x69; 16])
    );
}

#[test]
fn native_registration_publishes_exact_certificate_without_claiming_activation() {
    use ea_admin::administration_runtime::{authorization, ceremony, exchange, publication};
    let stations = SeparateAdministrationStations::new();
    let mut runtime = stations.source.open();
    let before = runtime.head().registry_head_hash();
    let (request, target) = actual_registration_intent(&runtime);
    let pending = ceremony::begin_registration(&mut runtime, &request, &target).unwrap();
    ceremony::confirm_registration_fingerprint(
        &mut runtime,
        pending.id(),
        ea_crypto::object_hash(&request),
    )
    .unwrap();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    authorization::authorize(&mut runtime, pending.id(), &presence).unwrap();
    let exported = exchange::export_request(&mut runtime, pending.id()).unwrap();
    let reply = stations.exchange.path().join(
        exported
            .exchange_file_name()
            .unwrap()
            .replacen("request-", "reply-", 1),
    );
    let mut service = stations.service();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    while !reply.exists() {
        assert!(service.0.try_wait().unwrap().is_none());
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    exchange::import_reply(&mut runtime, pending.id()).unwrap();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    let published =
        publication::publish(&mut runtime, pending.id(), &stations.profile, &presence).unwrap();
    assert_eq!(
        published.step(),
        ea_admin::TrustCeremonyStep::TargetPublished
    );
    assert!(runtime.head().registry_head_hash() == before);
    assert!(
        runtime
            .head()
            .active_certificates()
            .all(|(_, c)| c.device_id.as_bytes() != &[0x69; 16])
    );
    let row = runtime.database().query_row("SELECT a.exact_bytes FROM administration_ceremony_record r JOIN local_audit_event a ON r.audit_event_id=a.event_id WHERE r.intent_hash=?1 AND r.stage=4",&[StoreValue::Blob(pending.id().as_bytes().to_vec())]).unwrap();
    let row = row.unwrap();
    let audit = ea_format::decode_local_audit_event(row.blob(0).unwrap()).unwrap();
    let ea_format::LocalAuditActionV1::AdminRootCeremony(context) = audit.action() else {
        panic!()
    };
    let certificate = fs::read(
        runtime
            .config()
            .archive_directory
            .join("trust")
            .join(format!(
                "{}.etb",
                hex::encode(context.target_object_hash().as_bytes())
            )),
    )
    .unwrap();
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&certificate).unwrap()
    else {
        panic!()
    };
    assert!(
        matches!(parsed.value().decoded_payload().unwrap(),ea_format::DecodedTrustPayloadV1::AuthorizedDevice(c) if c.fields().device_id.as_bytes()==&[0x69;16])
    );
    drop(runtime);
    let mut runtime = stations.source.open();
    assert_eq!(
        ceremony::load(&mut runtime, pending.id()).unwrap().step(),
        ea_admin::TrustCeremonyStep::TargetPublished
    );
    assert!(runtime.head().registry_head_hash() == before);
    // Later signed Registry publication at the same entry sequence must not
    // erase this exact historical certificate-publication receipt.
    let revoke = ceremony::begin_revoke(&mut runtime, stations.source.reader).unwrap();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    authorization::authorize(&mut runtime, revoke.id(), &presence).unwrap();
    let exported = exchange::export_request(&mut runtime, revoke.id()).unwrap();
    let next_reply = stations.exchange.path().join(
        exported
            .exchange_file_name()
            .unwrap()
            .replacen("request-", "reply-", 1),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    while !next_reply.exists() {
        assert!(service.0.try_wait().unwrap().is_none());
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    exchange::import_reply(&mut runtime, revoke.id()).unwrap();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    assert_eq!(
        publication::publish(&mut runtime, revoke.id(), &stations.profile, &presence)
            .unwrap()
            .step(),
        ea_admin::TrustCeremonyStep::RegistryPublished
    );
    assert!(runtime.head().registry_head_hash() != before);
    assert_eq!(runtime.next_sequence().get(), 1);
    drop(runtime);
    let mut runtime = stations.source.open();
    assert_eq!(
        ceremony::load(&mut runtime, pending.id()).unwrap().step(),
        ea_admin::TrustCeremonyStep::TargetPublished
    );
}

#[test]
fn native_registration_rejects_foreign_or_escalated_certificate_intents_before_journaling() {
    use ea_admin::administration_runtime::ceremony;
    let installed = AdministrationInstallation::new();
    let mut runtime = installed.open();
    let (request, target) = actual_registration_intent(&runtime);
    let original = ea_format::TrustPayloadV1::from_exact_digest_input(&target).unwrap();
    let ea_format::DecodedTrustPayloadV1::AuthorizedDevice(core) =
        original.decoded_payload().unwrap()
    else {
        panic!()
    };
    for mutation in 0..7 {
        let mut fields = core.fields().clone();
        match mutation {
            0 => {
                fields.organization_id =
                    ea_types::OrganizationId::try_from(&[0x77; 16][..]).unwrap()
            }
            1 => fields.device_id = DeviceId::try_from(&[0x77; 16][..]).unwrap(),
            2 => {
                fields.certificate_kind = CertificateKindV1::Writer;
                fields.capabilities = vec!["initialGrant".into()];
            }
            3 => {
                let key =
                    ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([0x72; 32]))
                        .public_key()
                        .unwrap();
                fields.signing_key_thumbprint = Some(key.thumbprint());
                fields.signing_public_cose_key = Some(key.to_deterministic_cbor());
            }
            4 => {
                fields.effective_from_sequence =
                    ea_types::ChainSequence::new(runtime.next_sequence().get() + 1)
            }
            5 => {
                fields.key_protection_profile =
                    ea_format::KeyProtectionProfileV1::HardwareNonExportable
            }
            6 => fields.key_protection_profile = ea_format::KeyProtectionProfileV1::Pkcs11,
            _ => unreachable!(),
        }
        let altered = ea_format::TrustPayloadV1::authorized_device_certificate(
            fields,
            ObjectHash::from(ea_types::Hash32::ZERO),
        )
        .unwrap();
        assert!(
            ceremony::begin_registration(&mut runtime, &request, altered.exact_digest_input())
                .is_err(),
            "mutation {mutation}"
        );
    }
    let mut damaged = request.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(ceremony::begin_registration(&mut runtime, &damaged, &target).is_err());
    assert_eq!(
        runtime
            .database()
            .query_row("SELECT count(*) FROM administration_ceremony_intent", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    assert_eq!(
        ceremony::begin_registration(&mut runtime, &request, &target)
            .unwrap()
            .step(),
        ea_admin::TrustCeremonyStep::PendingRequest
    );
}

fn complete_administration_exchange(
    stations: &SeparateAdministrationStations,
    runtime: &mut OperatorRuntime,
    id: ObjectHash,
) {
    use ea_admin::administration_runtime::exchange;
    let exported = exchange::export_request(runtime, id).unwrap();
    let reply = stations.exchange.path().join(
        exported
            .exchange_file_name()
            .unwrap()
            .replacen("request-", "reply-", 1),
    );
    let mut service = stations.service();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    while !reply.exists() {
        assert!(service.0.try_wait().unwrap().is_none());
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    exchange::import_reply(runtime, id).unwrap();
}
#[test]
fn native_registration_requires_a_linked_separate_root_activation_round() {
    use ea_admin::administration_runtime::{
        FingerprintSubjectV1, TrustCeremonyRoundV1, authorization, ceremony, publication,
    };
    let stations = SeparateAdministrationStations::new();
    // The Root station has its own immutable starting public snapshot. New
    // certificate bytes must cross the authenticated exact exchange, not a
    // shared catalog path.
    fn copy_snapshot(from: &Path, to: &Path) {
        fs::create_dir(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.file_type().unwrap();
            assert!(!metadata.is_symlink());
            if metadata.is_dir() {
                copy_snapshot(&entry.path(), &to.join(entry.file_name()));
            } else {
                assert!(metadata.is_file());
                fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }
    let mut root_config: Value =
        serde_json::from_slice(&fs::read(&stations.root.config).unwrap()).unwrap();
    let root_snapshot = stations
        .root
        .directory
        .path()
        .join("independent-root-snapshot");
    copy_snapshot(
        &stations.root.directory.path().join(root_config["archive_directory"].as_str().unwrap()),
        &root_snapshot,
    );
    root_config["archive_directory"] = json!(root_snapshot);
    fs::write(
        &stations.root.config,
        serde_json::to_vec(&root_config).unwrap(),
    )
    .unwrap();
    let mut runtime = stations.source.open();
    let before = runtime.head().registry_head_hash();
    let (request, target) = actual_registration_intent(&runtime);
    let first = ceremony::begin_registration(&mut runtime, &request, &target).unwrap();
    ceremony::confirm_registration_fingerprint(
        &mut runtime,
        first.id(),
        ea_crypto::object_hash(&request),
    )
    .unwrap();
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    authorization::authorize(&mut runtime, first.id(), &presence).unwrap();
    complete_administration_exchange(&stations, &mut runtime, first.id());
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    let issued =
        publication::publish(&mut runtime, first.id(), &stations.profile, &presence).unwrap();
    assert_eq!(issued.step(), ea_admin::TrustCeremonyStep::TargetPublished);
    assert!(runtime.head().registry_head_hash() == before);
    let next_id = issued.linked_ceremony_id().expect(
        "actual dependent Registry round is journalled only after exact issued target exists",
    );
    let next = ceremony::load(&mut runtime, next_id).unwrap();
    assert_eq!(next.round(), TrustCeremonyRoundV1::ActivateRegistry);
    assert_eq!(next.step(), ea_admin::TrustCeremonyStep::PendingRequest);
    assert_eq!(
        next.fingerprint_subject(),
        Some(FingerprintSubjectV1::IssuedCertificate)
    );
    assert!(next.linked_ceremony_id() == Some(first.id()));
    let certificate = next.target_fingerprint().unwrap();
    assert!(certificate != ea_crypto::object_hash(&request));
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    assert!(authorization::authorize(&mut runtime, next_id, &presence).is_err());
    ceremony::confirm_registration_fingerprint(&mut runtime, next_id, certificate).unwrap();
    authorization::authorize(&mut runtime, next_id, &presence).unwrap();
    complete_administration_exchange(&stations, &mut runtime, next_id);
    let presence = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    let activated =
        publication::publish(&mut runtime, next_id, &stations.profile, &presence).unwrap();
    assert_eq!(
        activated.step(),
        ea_admin::TrustCeremonyStep::RegistryPublished
    );
    assert!(runtime.head().registry_head_hash() != before);
    assert!(
        runtime
            .head()
            .active_certificate_fields(CertificateHash::from(certificate))
            .is_some()
    );
    drop(runtime);
    let mut runtime = stations.source.open();
    let parent = ceremony::load(&mut runtime, first.id()).unwrap();
    let child = ceremony::load(&mut runtime, next_id).unwrap();
    assert_eq!(parent.step(), ea_admin::TrustCeremonyStep::TargetPublished);
    assert_eq!(child.step(), ea_admin::TrustCeremonyStep::RegistryPublished);
    assert!(parent.linked_ceremony_id() == Some(next_id));
    assert!(child.linked_ceremony_id() == Some(first.id()));
    let first_auth=runtime.database().query_row("SELECT exact_record FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=1",&[StoreValue::Blob(first.id().as_bytes().to_vec())]).unwrap().unwrap();
    let next_auth=runtime.database().query_row("SELECT exact_record FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=1",&[StoreValue::Blob(next_id.as_bytes().to_vec())]).unwrap().unwrap();
    assert_ne!(first_auth.blob(0).unwrap(), next_auth.blob(0).unwrap());
}

#[test]
fn native_registration_inbox_is_exact_durable_and_preserves_the_observed_time() {
    use ea_admin::administration_runtime::inbox::pending_registrations;
    let installation = AdministrationInstallation::new();
    let inbox = installation.directory.path().join("registration-inbox");
    fs::create_dir(&inbox).unwrap();
    let mut runtime = installation.open();
    let (request, target) = actual_registration_intent(&runtime);
    let request_hash = ea_crypto::object_hash(&request);
    let stem = hex::encode(request_hash.as_bytes());
    let request_path = inbox.join(format!("{stem}.registration.cbor"));
    let target_path = inbox.join(format!("{stem}.certificate-intent.cbor"));
    fs::write(&request_path, &request).unwrap();
    fs::write(&target_path, &target).unwrap();
    let pending = pending_registrations(&mut runtime, &inbox).unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].request_hash() == request_hash);
    assert!(pending[0].ceremony_id() == ea_crypto::object_hash(&target));
    assert_eq!(pending[0].certificate_kind(), ea_format::CertificateKindV1::Reader);
    let first_observed = pending[0].received_at();
    assert!(first_observed <= runtime.head().preexisting_effective_now().value());
    let id = pending[0].ceremony_id();
    fs::remove_file(&request_path).unwrap();
    fs::remove_file(&target_path).unwrap();
    drop(runtime);
    let mut reopened = installation.open();
    let pending = pending_registrations(&mut reopened, &inbox).unwrap();
    assert_eq!(pending.len(), 1, "accepted requests survive removal of transport copies");
    assert_eq!(pending[0].received_at(), first_observed);
    assert!(pending[0].ceremony_id() == id);
    assert_eq!(
        ea_admin::administration_runtime::ceremony::load(&mut reopened, id).unwrap().step(),
        ea_admin::TrustCeremonyStep::PendingRequest
    );
    assert!(pending_registrations(&mut reopened, &inbox.join("missing")).is_err());
}

#[test]
fn native_registration_inbox_rejects_bad_complete_batches_without_partial_intake() {
    use ea_admin::administration_runtime::inbox::pending_registrations;
    let installation = AdministrationInstallation::new();
    let inbox = installation.directory.path().join("registration-inbox");
    fs::create_dir(&inbox).unwrap();
    let mut runtime = installation.open();
    assert!(pending_registrations(&mut runtime, &inbox).unwrap().is_empty());
    let (request, target) = actual_registration_intent(&runtime);
    let stem = hex::encode(ea_crypto::object_hash(&request).as_bytes());
    let request_path = inbox.join(format!("{stem}.registration.cbor"));
    let target_path = inbox.join(format!("{stem}.certificate-intent.cbor"));
    let count = |runtime: &OperatorRuntime| runtime.database().query_row(
        "SELECT COUNT(*) FROM administration_ceremony_intent", &[]
    ).unwrap().unwrap().integer(0).unwrap();
    fs::write(&request_path, &request).unwrap();
    assert!(pending_registrations(&mut runtime, &inbox).is_err(), "unpaired request");
    assert_eq!(count(&runtime), 0);
    fs::write(&target_path, &target).unwrap();
    let bad = inbox.join("unexpected.json");
    fs::write(&bad, b"{}").unwrap();
    assert!(pending_registrations(&mut runtime, &inbox).is_err());
    assert_eq!(count(&runtime), 0, "valid first pair must not commit before bad entry");
    fs::remove_file(&bad).unwrap();
    let mut corrupt = request.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&request_path, &corrupt).unwrap();
    assert!(pending_registrations(&mut runtime, &inbox).is_err());
    assert_eq!(count(&runtime), 0);
    fs::write(&request_path, &request).unwrap();
    #[cfg(unix)] {
        fs::remove_file(&target_path).unwrap();
        let outside = installation.directory.path().join("outside.cbor");
        fs::write(&outside, &target).unwrap();
        std::os::unix::fs::symlink(&outside, &target_path).unwrap();
        assert!(pending_registrations(&mut runtime, &inbox).is_err());
        assert_eq!(count(&runtime), 0);
        fs::remove_file(&target_path).unwrap();
        fs::write(&target_path, &target).unwrap();
    }
    assert_eq!(pending_registrations(&mut runtime, &inbox).unwrap().len(), 1);
    let mut changed = target.clone();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(&target_path, changed).unwrap();
    assert!(pending_registrations(&mut runtime, &inbox).is_err(), "stored request cannot acquire a different target");
    assert_eq!(count(&runtime), 1);
}

#[test]
fn native_policy_requires_two_exact_rounds_and_retains_the_real_profile_until_activation() {
    use ea_admin::administration_runtime::{authorization, ceremony, publication};
    use ea_format::TrustPayloadV1;
    use ea_types::Hash32;
    let stations = SeparateAdministrationStations::new();
    let mut runtime = stations.source.open();
    let old_policy = runtime.head().policy_fields().clone();
    let old_hash = runtime.head().policy_object_hash();
    let mut fields = old_policy.clone();
    fields.policy_version += 1;
    fields.previous_policy_object_hash = Some(old_hash);
    fields.effective_from_sequence = runtime.next_sequence();
    fields.evidence_max_delay_ms += 1;
    let exact = TrustPayloadV1::policy(fields.clone(), ObjectHash::from(Hash32::ZERO)).unwrap();
    for choice in 0..4 {
        let mut invalid=fields.clone();
        match choice {
            0 => invalid.organization_id = ea_types::OrganizationId::try_from(&[0x11;16][..]).unwrap(),
            1 => invalid.policy_version += 1,
            2 => invalid.previous_policy_object_hash=Some(ea_crypto::object_hash(b"foreign policy")),
            3 => invalid.effective_from_sequence=ea_types::ChainSequence::new(runtime.next_sequence().get()+1),
            _ => unreachable!(),
        }
        let invalid=TrustPayloadV1::policy(invalid,ObjectHash::from(Hash32::ZERO)).unwrap();
        assert!(ceremony::begin_policy(&mut runtime,invalid.exact_digest_input()).is_err());
    }
    let first=ceremony::begin_policy(&mut runtime,exact.exact_digest_input()).unwrap();
    assert_eq!(first.kind(), ea_admin::TrustCeremonyKind::PolicyChange);
    assert!(first.fingerprint_subject().is_none());
    let presence=runtime.reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony).unwrap();
    authorization::authorize(&mut runtime,first.id(),&presence).unwrap();
    complete_administration_exchange(&stations,&mut runtime,first.id());
    let presence=runtime.reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony).unwrap();
    let issued=publication::publish(&mut runtime,first.id(),&stations.profile,&presence).unwrap();
    assert_eq!(issued.step(),ea_admin::TrustCeremonyStep::TargetPublished);
    assert!(runtime.head().policy_object_hash()==old_hash);
    assert_eq!(runtime.head().policy_fields().evidence_max_delay_ms,old_policy.evidence_max_delay_ms);
    let second=issued.linked_ceremony_id().unwrap();
    let presence=runtime.reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony).unwrap();
    authorization::authorize(&mut runtime,second,&presence).unwrap();
    complete_administration_exchange(&stations,&mut runtime,second);
    let presence=runtime.reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony).unwrap();
    let active=publication::publish(&mut runtime,second,&stations.profile,&presence).unwrap();
    assert_eq!(active.step(),ea_admin::TrustCeremonyStep::RegistryPublished);
    assert_eq!(runtime.head().policy_fields().evidence_max_delay_ms,fields.evidence_max_delay_ms);
    drop(runtime);
    let mut reopened=stations.source.open();
    assert_eq!(ceremony::load(&mut reopened,first.id()).unwrap().step(),ea_admin::TrustCeremonyStep::TargetPublished);
    assert_eq!(ceremony::load(&mut reopened,second).unwrap().step(),ea_admin::TrustCeremonyStep::RegistryPublished);
}

#[test]
fn native_writer_transition_rejects_caller_tip_and_activates_only_the_exact_two_round_history() {
    use ea_admin::administration_runtime::{authorization, ceremony, publication};
    use ea_trust::TrustObjectSource;
    let mut stations=SeparateAdministrationStations::new();
    let mut before_catalog=std::collections::BTreeSet::new();
    stations.root.line.source().visit_trust_object_hashes(&mut |hash| {
        before_catalog.insert(hash);Ok(())
    }).unwrap();
    let new_writer=stations.root.line.push(ActionSpec::Device {
        kind:ea_format::CertificateKindV1::Writer,marker:0x6c,effective_from:Some(1),
    },HeadOptions {
        effective_from:Some(1),valid_through:Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
        not_after:UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
        ..HeadOptions::default()
    }).direct_object_hash.unwrap();
    let catalog=stations.root.line.source();
    catalog.visit_trust_object_hashes(&mut |hash|{
        if !before_catalog.contains(&hash) {
            fs::write(stations.root.directory.path().join("archive").join(format!("{}.etb",hex::encode(hash.as_bytes()))),
                catalog.read_exact_trust_object(hash)?.unwrap()).unwrap();
        }
        Ok(())
    }).unwrap();
    drop(catalog);
    let mut runtime=stations.source.open();
    let old_writer=runtime.head().current_writer_certificate_hash().unwrap();
    assert!(runtime.head().approved_writer_certificate_fields(CertificateHash::from(new_writer),runtime.next_sequence()).is_some());
    let source=ea_recovery::FsArchiveSource::open_committed(&runtime.config().archive_directory).unwrap();
    let report=ea_verify::verify_archive(&source,runtime.anchor(),ea_verify::VerifyOptions::new(support::live_clock())).unwrap();
    let tip=report.verified_public_chain_head().unwrap();
    let request=json!({
        "old_writer_certificate_hash":hex::encode(old_writer.as_bytes()),
        "new_writer_certificate_hash":hex::encode(new_writer.as_bytes()),
        "trusted_head":{"chain_sequence":tip.sequence().get(),"entry_hash":hex::encode(tip.entry_hash().as_bytes())},
        "reason_code":1
    });
    let mut bad=request.clone();
    bad["trusted_head"]["entry_hash"]=json!(hex::encode(ea_crypto::object_hash(b"forged tip").as_bytes()));
    assert!(ceremony::begin_writer_transition(&mut runtime,&serde_json::to_vec(&bad).unwrap()).is_err());
    bad=request.clone();
    bad["new_writer_certificate_hash"]=json!(hex::encode(stations.source.reader.as_bytes()));
    assert!(ceremony::begin_writer_transition(&mut runtime,&serde_json::to_vec(&bad).unwrap()).is_err());
    let first=ceremony::begin_writer_transition(&mut runtime,&serde_json::to_vec(&request).unwrap()).unwrap();
    assert_eq!(first.kind(),ea_admin::TrustCeremonyKind::WriterTransition);
    let state=ea_admin::administration_runtime::transition::current_transition(&mut runtime).unwrap();
    assert_eq!(state.phase(),ea_admin::writer_transition::WriterTransitionPhase::Prepared);
    assert!(state.ceremony_id()==Some(first.id()));
    assert!(state.current_writer()==old_writer);
    assert!(state.new_writer()==Some(CertificateHash::from(new_writer)));
    drop(runtime);
    let mut runtime=stations.source.open();
    assert!(ea_admin::administration_runtime::transition::current_transition(&mut runtime).unwrap().ceremony_id()==Some(first.id()));
    let presence=runtime.reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony).unwrap();
    authorization::authorize(&mut runtime,first.id(),&presence).unwrap();
    complete_administration_exchange(&stations,&mut runtime,first.id());
    let presence=runtime.reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony).unwrap();
    let issued=publication::publish(&mut runtime,first.id(),&stations.profile,&presence).unwrap();
    assert_eq!(issued.step(),ea_admin::TrustCeremonyStep::TargetPublished);
    assert!(runtime.head().current_writer_certificate_hash()==Some(old_writer));
    let second=issued.linked_ceremony_id().unwrap();
    let state=ea_admin::administration_runtime::transition::current_transition(&mut runtime).unwrap();
    assert_eq!(state.phase(),ea_admin::writer_transition::WriterTransitionPhase::Prepared);
    assert!(state.ceremony_id()==Some(second));
    let presence=runtime.reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony).unwrap();
    authorization::authorize(&mut runtime,second,&presence).unwrap();
    complete_administration_exchange(&stations,&mut runtime,second);
    let presence=runtime.reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony).unwrap();
    let active=publication::publish(&mut runtime,second,&stations.profile,&presence).unwrap();
    assert_eq!(active.step(),ea_admin::TrustCeremonyStep::RegistryPublished);
    assert!(runtime.head().current_writer_certificate_hash()==Some(CertificateHash::from(new_writer)));
    drop(runtime);
    let mut reopened=stations.source.open();
    assert!(reopened.head().current_writer_certificate_hash()==Some(CertificateHash::from(new_writer)));
    let state=ea_admin::administration_runtime::transition::current_transition(&mut reopened).unwrap();
    assert_eq!(state.phase(),ea_admin::writer_transition::WriterTransitionPhase::Activated);
    assert!(state.ceremony_id().is_none());
    assert_eq!(ceremony::load(&mut reopened,first.id()).unwrap().step(),ea_admin::TrustCeremonyStep::TargetPublished);
    assert_eq!(ceremony::load(&mut reopened,second).unwrap().step(),ea_admin::TrustCeremonyStep::RegistryPublished);
}

/// Gap witness: the normal current-authority constructor must remain closed.
/// The eventual repair constructor must expose only this bounded diagnostic,
/// never an ordinary SelectedRegistryHead/admin action.
#[test]
#[ignore = "DRK-282: contradicts the FutureSkew boundary (expects the ordinary reopen after restart to succeed); superseded by clock_repair.rs"]
fn native_clock_repair_after_actual_restart_gap() {
    use ea_trust::{prepare_local_time,verify_receipt_time,verify_registry_candidate};
    let installation=AdministrationInstallation::new();
    let runtime=installation.open();
    let now=support::live_clock();
    let server=runtime.head().active_certificates().find(
        |(_,fields)| fields.certificate_kind==ea_format::CertificateKindV1::ServerReceipt
    ).unwrap().0;
    let accepted=UnixMillis::new(now.get()-i64::try_from(runtime.head().policy_fields().max_future_clock_skew_ms).unwrap()-30_000);
    let signer=ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(trust_support::device_signing_secret()));
    let core=ea_format::ReceiptCoreV1::new(ea_format::ReceiptCoreFieldsV1 {
        organization_id:runtime.anchor().organization_id(),chain_id:runtime.anchor().chain_id(),
        chain_sequence:runtime.next_sequence(),entry_hash:runtime.anchor().genesis_entry_hash(),
        entry_object_hash:ea_crypto::object_hash(b"actual signed clock gap entry identity"),
        previous_entry_hash:Some(runtime.anchor().genesis_entry_hash()),
        registry_version:runtime.head().registry_version(),
        registry_head_hash:Hash32::try_from(runtime.head().registry_head_hash().as_bytes().as_slice()).unwrap(),
        policy_object_hash:runtime.head().policy_object_hash(),
        initial_grant_plan_hash:Hash32::try_from(&[0x21;32][..]).unwrap(),
        initial_grant_object_hashes:vec![ea_crypto::object_hash(b"clock gap grant")],
        accepted_at_server:accepted,evidence_due_at:None,
        server_key_thumbprint:signer.public_key().unwrap().thumbprint(),
        server_certificate_hash:server,
    }).unwrap();
    let signature=signer.sign_receipt(core.exact_bytes()).unwrap();
    let exact=ea_format::encode_receipt(&ea_format::ReceiptV1::new(core,signature).unwrap()).unwrap();
    let ea_format::ParsedArchiveObject::Receipt(receipt)=ea_format::decode_exact_object(exact.as_bytes()).unwrap()
        else {panic!()};
    let candidate=verify_registry_candidate(runtime.trust(),runtime.next_sequence()).unwrap();
    let verified=verify_receipt_time(candidate.preexisting_authority().unwrap(),&receipt).unwrap();
    let mut store=runtime.trust_store().clone();
    drop(prepare_local_time(&mut store,&candidate,now,&[verified]).unwrap());
    assert_eq!(runtime.clock_release_availability(now).unwrap(),ea_admin::clock_release::ClockReleaseAvailability::Offered);
    let config=runtime.config().clone();
    drop(runtime);
    let native=NativeOperatorProvider::open_test_fixture(installation.directory.path().join("ea-native-operator"),false).unwrap();
    let reopened=OperatorRuntime::open_with_test_native(config,&installation.anchor,support::live_clock(),false,native);
    let observed=reopened.and_then(|runtime|runtime.clock_release_availability(support::live_clock()).map_err(|_|ea_admin::operator_runtime::OperatorRuntimeError::Config));
    assert!(matches!(observed,Ok(ea_admin::clock_release::ClockReleaseAvailability::Offered)),
        "a clock-only diagnostic must survive restart while current authority remains refused: {observed:?}");
}

#[cfg(feature = "desktop-fixture")]
mod host;

mod open_ceremonies;

mod clock_repair;
