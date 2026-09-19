use super::*;
use ea_admin::{
    native_provider::NativeOperatorProvider,
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig},
};
use ea_key_provider::{DevicePostureProvider, SupportMatrixRow};
use std::sync::Arc;

#[test]
fn posture_cli_accepts_only_closed_documentation_operations() {
    for tail in [
        vec!["target", "--output", "target.json"],
        vec![
            "issue",
            "--posture-target",
            "target.json",
            "--evidence-reference",
            "public.txt",
            "--valid-for-ms",
            "60000",
            "--output",
            "document.cbor",
        ],
        vec!["import", "--posture-document", "document.cbor"],
    ] {
        let mut arguments = vec!["--trust-anchor", "anchor", "posture"];
        arguments.extend(tail);
        arguments.extend(["--operator-config", "operator.json"]);
        assert!(args::parse(arguments.into_iter().map(Into::into)).is_ok());
    }
    for tail in [
        vec!["target", "--posture-document", "doc", "--output", "out"],
        vec!["import", "--posture-document", "doc", "--output", "out"],
        vec![
            "issue",
            "--posture-target",
            "target",
            "--evidence-reference",
            "ref",
            "--valid-for-ms",
            "86400001",
            "--output",
            "out",
        ],
        vec![
            "issue",
            "--posture-target",
            "target",
            "--evidence-reference",
            "ref",
            "--valid-for-ms",
            "0",
            "--output",
            "out",
        ],
        vec!["target", "--output", "out", "--key", "private-key"],
        vec!["target", "--output", "out", "--not-after", "123"],
        vec!["target", "--output", "out", "--posture-pass", "true"],
    ] {
        let mut arguments = vec!["--trust-anchor", "anchor", "posture"];
        arguments.extend(tail);
        arguments.extend(["--operator-config", "operator.json"]);
        assert!(args::parse(arguments.into_iter().map(Into::into)).is_err());
    }
}

/// A documentable measurement that does not depend on the runner's disk.
///
/// The real Ubuntu adapter measures full-disk encryption, and the root of
/// GitHub's `ubuntu-24.04` runner is an unencrypted `part`/`disk` chain: a
/// measured Fail that no posture document may cover (`unknown_mask`). Only
/// `actual_cli_target_issue_import_uses_native_admin_and_real_host_measurements`
/// keeps measuring the actual host.
fn documentable_measurement() -> Arc<dyn DevicePostureProvider> {
    Arc::new(ea_key_provider::DevicePostureProviderFake::unknown(
        ea_key_provider::PostureRequirement::FullDiskEncryption,
    ))
}

struct NativePostureFixture {
    directory: support::TempDir,
    config: PathBuf,
    anchor: PathBuf,
}
impl NativePostureFixture {
    fn new() -> Self {
        use support::verify_support as fixture;
        let directory = support::temp_dir("go-live-posture-native");
        install_fixture_helper(directory.path());
        fs::write(directory.path().join("authority-fixture"), b"").unwrap();
        let subject = OperatorSubjectId::try_from(&[0x42; 16][..]).unwrap();
        let material = fixture::historical::fixture_with_host_options(
            |_, _| fixture::COMPLETE_PLAINTEXT_V1.to_vec(),
            Some(fixture::historical::HostOptions {
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
        let config = directory.path().join("operator.json");
        fs::write(&config,serde_json::to_vec(&json!({
            "archive_directory":"archive","database_path":"operator.sqlite",
            "device_certificate_hash":hex::encode(material.line.second_bootstrap_admin_hash().as_bytes()),
            "binding_object_hash":hex::encode(material.operator_binding.as_bytes()),
            "role":"organization-admin","purpose":"admin-root-ceremony"
        })).unwrap()).unwrap();
        Self {
            directory,
            config,
            anchor,
        }
    }
    fn open(&self, posture: Arc<dyn DevicePostureProvider>) -> OperatorRuntime {
        let native = NativeOperatorProvider::open_test_fixture(
            self.directory.path().join("ea-native-operator"),
            false,
        )
        .unwrap();
        OperatorRuntime::open_with_test_native_and_posture(
            OperatorRuntimeConfig::load(&self.config).unwrap(),
            &self.anchor,
            support::live_clock(),
            false,
            native,
            posture,
        )
        .unwrap()
    }
}
#[test]
fn signed_native_posture_document_allows_admission_after_real_reopen_without_relabeling_unknown() {
    let fixture = NativePostureFixture::new();
    let host = documentable_measurement();
    let runtime = fixture.open(host.clone());
    assert!(
        !runtime
            .device_posture_report()
            .unwrap()
            .is_production_ready()
    );
    assert!(runtime.reauthenticate().is_err());
    let target = runtime.posture_target_context().unwrap();
    let document = runtime
        .issue_posture_document(
            &target,
            ea_crypto::object_hash(b"public organizational prerequisites verified"),
            60_000,
        )
        .unwrap();
    assert!(
        runtime.reauthenticate().is_err(),
        "issuance alone is not durable target import"
    );
    runtime.import_posture_document(&document).unwrap();
    drop(runtime);
    let reopened = fixture.open(host);
    let admission = reopened.posture_admission().unwrap();
    assert!(admission.documented_unknown_mask() > 0);
    reopened.reauthenticate().unwrap();
    assert!(
        !reopened
            .device_posture_report()
            .unwrap()
            .is_production_ready(),
        "raw native Unknown remains visible"
    );
    let report = reopened.go_live_report().unwrap();
    // Ein dokumentiertes Unknown öffnet die Sitzung, ist aber keine
    // Go-live-Produktionsreife: Der JSON-Bericht nennt nur die Zulassung und
    // führt keinen Schlüssel `production_ready`, der sie als Reife ausgäbe.
    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(json["session_admitted"], serde_json::Value::Bool(true));
    assert!(
        json.get("production_ready").is_none(),
        "the operator report must not label a documented Unknown as production ready"
    );
    let documented = report.documented_posture.unwrap();
    assert_eq!(
        documented.document_hash,
        hex::encode(ea_crypto::object_hash(&document).as_bytes())
    );
    assert!(documented.documented_unknown_mask > 0);
}

#[test]
fn issuance_returns_nothing_without_exact_durable_document_bytes() {
    let fixture = NativePostureFixture::new();
    let runtime = fixture.open(documentable_measurement());
    runtime.database().execute("CREATE TRIGGER corrupt_issued_document AFTER INSERT ON go_live_posture_issued BEGIN UPDATE go_live_posture_issued SET exact_envelope=x'80' WHERE object_hash=NEW.object_hash; END",&[]).unwrap();
    let result = runtime.issue_posture_document(
        &runtime.posture_target_context().unwrap(),
        ea_crypto::object_hash(b"evidence"),
        60_000,
    );
    assert!(
        result.is_err(),
        "successful publication requires the exact durable source bytes"
    );
}

#[test]
fn documented_admission_marks_only_live_unknown_rows_and_never_confirms_them() {
    use ea_admin::go_live::{
        GoLiveEvidence, GoLiveRequirementStatus, evaluate_go_live_with_posture_admission,
    };
    use ea_key_provider::{DevicePostureReport, HostOsBuild, KeyError, PostureRequirement};
    struct Measurement(std::sync::Mutex<DevicePostureReport>);
    impl DevicePostureProvider for Measurement {
        fn report(&self) -> Result<DevicePostureReport, KeyError> {
            Ok(*self.0.lock().unwrap())
        }
        fn os_build_identity(&self) -> Result<HostOsBuild, KeyError> {
            Ok(HostOsBuild::test_fixture(1, 1))
        }
    }
    let fixture = NativePostureFixture::new();
    let posture = Arc::new(Measurement(std::sync::Mutex::new(
        DevicePostureReport::unresolved(),
    )));
    let runtime = fixture.open(posture.clone());
    let document = runtime
        .issue_posture_document(
            &runtime.posture_target_context().unwrap(),
            ea_crypto::object_hash(b"evidence"),
            60_000,
        )
        .unwrap();
    runtime.import_posture_document(&document).unwrap();
    let admission = runtime.posture_admission().unwrap();
    let raw = runtime.device_posture_report().unwrap();
    let evidence = GoLiveEvidence {
        active_admin_count: None,
        key_backups: None,
        registry: None,
        policy_present: None,
        evidence_policy_present: None,
        last_recovery_test: None,
        writer_transition: None,
        device_posture: Some(&raw),
        eds_privacy_decision: None,
    };
    let report = evaluate_go_live_with_posture_admission(&evidence, Some(&admission));
    // Ruling 2026-09-13 ("Plan wörtlich"): a valid document stays visible as
    // evidence, but a documented Unknown is never green in Go-live.
    for row in &report.requirements()[11..15] {
        assert_eq!(
            row.status(),
            GoLiveRequirementStatus::NotAutomaticallyVerifiable
        );
        assert_eq!(row.evidence_code(), "EA-GOLIVE-POSTURE-DOCUMENTED");
    }
    assert!(
        !report.production_ready(),
        "documented Unknown posture rows remain unresolved"
    );
    posture.0.lock().unwrap().automatic_screen_lock =
        PostureRequirement::AutomaticScreenLock.fail();
    let changed = evaluate_go_live_with_posture_admission(&evidence, Some(&admission));
    assert!(
        changed.requirements()[11..15].iter().all(|row| {
            row.status() != GoLiveRequirementStatus::Confirmed
                && row.evidence_code() != "EA-GOLIVE-POSTURE-DOCUMENTED"
        }),
        "old opaque admission cannot mark rows documented after a new measured failure"
    );
    assert!(runtime.reauthenticate().is_err());
}

#[test]
fn actual_cli_target_issue_import_uses_native_admin_and_real_host_measurements() {
    let fixture = NativePostureFixture::new();
    let dir = fixture.directory.path();
    fs::write(
        dir.join("public-evidence.txt"),
        b"Public organizational prerequisite record",
    )
    .unwrap();
    let run = |tail: &[&str]| {
        let mut args = vec![
            "--trust-anchor",
            fixture.anchor.to_str().unwrap(),
            "posture",
        ];
        args.extend_from_slice(tail);
        args.extend(["--operator-config", fixture.config.to_str().unwrap()]);
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "process_native::fixture_cli",
                "--nocapture",
            ])
            .env(
                "EA_OPERATOR_FIXTURE_ARGS",
                serde_json::to_string(&args).unwrap(),
            )
            .env("EA_OPERATOR_FIXTURE_DIRECTORY", dir)
            .output()
            .unwrap()
    };
    let target = dir.join("target.json");
    let doc = dir.join("document.cbor");
    let evidence = dir.join("public-evidence.txt");
    // The CLI measures the actual host. A measured Fail is never documentable:
    // on such a host (GitHub's unencrypted ubuntu-24.04 root) the target step
    // itself refuses and publishes nothing.
    let measured = SupportMatrixRow::current_host()
        .unwrap()
        .posture_provider()
        .report()
        .unwrap();
    if ea_key_provider::PostureRequirement::ALL
        .into_iter()
        .any(|requirement| {
            matches!(
                measured.check(requirement),
                ea_key_provider::PostureCheck::Fail { .. }
            )
        })
    {
        let output = run(&["target", "--output", target.to_str().unwrap()]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(12), "{stderr}");
        assert!(stderr.contains("EA-OPERATOR-POSTURE"), "{stderr}");
        assert!(
            !target.exists(),
            "a refused target step writes no public output"
        );
        return;
    }
    for args in [
        vec!["target", "--output", target.to_str().unwrap()],
        vec![
            "issue",
            "--posture-target",
            target.to_str().unwrap(),
            "--evidence-reference",
            evidence.to_str().unwrap(),
            "--valid-for-ms",
            "60000",
            "--output",
            doc.to_str().unwrap(),
        ],
        vec!["import", "--posture-document", doc.to_str().unwrap()],
    ] {
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let host = Arc::from(SupportMatrixRow::current_host().unwrap().posture_provider());
    let runtime = fixture.open(host);
    assert!(
        runtime
            .posture_admission()
            .unwrap()
            .document_hash()
            .is_some()
    );
    runtime.reauthenticate().unwrap();
    let before = fs::read(&doc).unwrap();
    assert_ne!(
        run(&["target", "--output", doc.to_str().unwrap()])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        fs::read(doc).unwrap(),
        before,
        "CLI never overwrites an existing public output"
    );
}

#[test]
fn forged_target_signature_and_durable_document_tampering_fail_after_reopen() {
    let fixture = NativePostureFixture::new();
    let host = documentable_measurement();
    let runtime = fixture.open(host.clone());
    let target = runtime.posture_target_context().unwrap();
    let document = runtime
        .issue_posture_document(&target, ea_crypto::object_hash(b"evidence"), 60_000)
        .unwrap();
    let mut wrong: serde_json::Value = serde_json::from_slice(&target.to_json().unwrap()).unwrap();
    wrong["installation_id"] = json!("ab".repeat(32));
    let wrong = ea_admin::operator_runtime::posture::PostureTargetContext::from_json(
        &serde_json::to_vec(&wrong).unwrap(),
    )
    .unwrap();
    let foreign = runtime
        .issue_posture_document(&wrong, ea_crypto::object_hash(b"evidence"), 60_000)
        .unwrap();
    assert!(
        runtime.import_posture_document(&foreign).is_err(),
        "signed public target claims cannot replace local installation facts"
    );
    let mut tampered = document.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(runtime.import_posture_document(&tampered).is_err());
    runtime.import_posture_document(&document).unwrap();
    runtime
        .database()
        .execute(
            "UPDATE go_live_posture_evidence SET exact_envelope=?1,object_hash=?2",
            &[
                StoreValue::Blob(tampered.clone()),
                StoreValue::Blob(ea_crypto::object_hash(&tampered).as_bytes().to_vec()),
            ],
        )
        .unwrap();
    drop(runtime);
    let reopened = fixture.open(host);
    assert!(
        reopened.posture_admission().is_err(),
        "matching local digest does not replace the signature"
    );
    assert!(reopened.reauthenticate().is_err());
}

#[test]
fn document_expiry_and_durable_clock_watermark_are_checked_after_reopen() {
    let fixture = NativePostureFixture::new();
    let host = documentable_measurement();
    let runtime = fixture.open(host.clone());
    let doc = runtime
        .issue_posture_document(
            &runtime.posture_target_context().unwrap(),
            ea_crypto::object_hash(b"evidence"),
            3_000,
        )
        .unwrap();
    runtime.import_posture_document(&doc).unwrap();
    let until = runtime.posture_admission().unwrap().valid_until().unwrap();
    while support::live_clock() < until {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(
        runtime.posture_admission().is_err(),
        "validUntil is exclusive"
    );
    drop(runtime);
    let runtime = fixture.open(host.clone());
    assert!(runtime.import_posture_document(&doc).is_err());
    let fresh = runtime
        .issue_posture_document(
            &runtime.posture_target_context().unwrap(),
            ea_crypto::object_hash(b"evidence"),
            60_000,
        )
        .unwrap();
    runtime.import_posture_document(&fresh).unwrap();
    runtime
        .database()
        .execute(
            "UPDATE go_live_posture_clock SET last_observed_wall=?1",
            &[StoreValue::Integer(support::live_clock().get() + 30_000)],
        )
        .unwrap();
    drop(runtime);
    assert!(
        fixture.open(host).posture_admission().is_err(),
        "a real reopen cannot ignore the durable wall watermark"
    );
}

#[test]
fn native_context_proof_uses_exact_retained_context_and_documentation_cannot_be_generic_reauth() {
    let installation = Installation::new();
    let native = NativeOperatorProvider::open_test_fixture(
        installation.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    let runtime = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&installation.config).unwrap(),
        &installation.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap();
    let hash = Hash32::try_from(&[0x81; 32][..]).unwrap();
    let session = runtime
        .reauthenticate_for_context(ea_operator::ReauthPurpose::RegistryStaleFinalize, hash)
        .unwrap();
    assert!(session.proof().context_hash() == Some(hash));
    assert!(!session.proof().is_valid_for(
        ea_operator::ReauthPurpose::GoLivePostureDocumentation,
        runtime.head().preexisting_effective_now()
    ));
    assert!(
        runtime
            .reauthenticate_for(ea_operator::ReauthPurpose::GoLivePostureDocumentation)
            .is_err()
    );
    assert!(
        runtime
            .issue_posture_document(
                &NativePostureFixture::new()
                    .open(documentable_measurement())
                    .posture_target_context()
                    .unwrap(),
                ea_crypto::object_hash(b"evidence"),
                60_000
            )
            .is_err(),
        "a Writer cannot issue an Admin document"
    );
}

struct ControlledMeasurement {
    report: std::sync::Mutex<ea_key_provider::DevicePostureReport>,
    build: std::sync::atomic::AtomicU8,
    unavailable: std::sync::atomic::AtomicBool,
}
#[test]
fn target_claims_cannot_document_requirements_the_actual_target_measures_as_pass() {
    let fixture = NativePostureFixture::new();
    let runtime = fixture.open(Arc::new(ControlledMeasurement::new()));
    let mut target: serde_json::Value =
        serde_json::from_slice(&runtime.posture_target_context().unwrap().to_json().unwrap())
            .unwrap();
    target["unknown_mask"] = json!(3);
    let target = ea_admin::operator_runtime::posture::PostureTargetContext::from_json(
        &serde_json::to_vec(&target).unwrap(),
    )
    .unwrap();
    let doc = runtime
        .issue_posture_document(&target, ea_crypto::object_hash(b"evidence"), 60_000)
        .unwrap();
    assert!(
        runtime.import_posture_document(&doc).is_err(),
        "first import must compare the documented Unknown mask with the actual measurement"
    );
}
impl ControlledMeasurement {
    fn new() -> Self {
        Self {
            report: std::sync::Mutex::new(
                ea_key_provider::DevicePostureProviderFake::unknown(
                    ea_key_provider::PostureRequirement::LockedNonSharedAccount,
                )
                .report()
                .unwrap(),
            ),
            build: std::sync::atomic::AtomicU8::new(1),
            unavailable: std::sync::atomic::AtomicBool::new(false),
        }
    }
}
impl DevicePostureProvider for ControlledMeasurement {
    fn report(&self) -> Result<ea_key_provider::DevicePostureReport, ea_key_provider::KeyError> {
        if self.unavailable.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ea_key_provider::KeyError::NotFound);
        }
        Ok(*self.report.lock().unwrap())
    }
    fn os_build_identity(&self) -> Result<ea_key_provider::HostOsBuild, ea_key_provider::KeyError> {
        Ok(ea_key_provider::HostOsBuild::test_fixture(
            1,
            self.build.load(std::sync::atomic::Ordering::SeqCst),
        ))
    }
}
#[test]
fn native_build_changes_new_unknown_and_provider_failure_cannot_reuse_documentation() {
    use ea_key_provider::PostureRequirement;
    use std::sync::atomic::Ordering::SeqCst;
    let fixture = NativePostureFixture::new();
    let posture = Arc::new(ControlledMeasurement::new());
    let runtime = fixture.open(posture.clone());
    let exact = runtime
        .issue_posture_document(
            &runtime.posture_target_context().unwrap(),
            ea_crypto::object_hash(b"evidence"),
            60_000,
        )
        .unwrap();
    runtime.import_posture_document(&exact).unwrap();
    posture.build.store(2, SeqCst);
    assert!(runtime.posture_admission().is_err());
    posture.build.store(1, SeqCst);
    posture.report.lock().unwrap().full_disk_encryption =
        PostureRequirement::FullDiskEncryption.unknown();
    assert!(
        runtime.posture_admission().is_err(),
        "new uncovered Unknown cannot reuse a different mask"
    );
    posture.report.lock().unwrap().full_disk_encryption =
        PostureRequirement::FullDiskEncryption.pass();
    posture.unavailable.store(true, SeqCst);
    assert!(runtime.posture_admission().is_err());
    assert!(
        runtime
            .issue_posture_document(
                &ea_admin::operator_runtime::posture::PostureTargetContext::from_json(&{
                    posture.unavailable.store(false, SeqCst);
                    let target = runtime.posture_target_context().unwrap().to_json().unwrap();
                    posture.unavailable.store(true, SeqCst);
                    target
                })
                .unwrap(),
                ea_crypto::object_hash(b"evidence"),
                60_000
            )
            .is_err()
    );
}

#[test]
fn native_documentation_prompt_rechecks_measurement_and_audits_failure_before_any_document_is_returned()
 {
    let fixture = NativePostureFixture::new();
    let posture = Arc::new(ControlledMeasurement::new());
    let runtime = fixture.open(posture.clone());
    let target = runtime.posture_target_context().unwrap();
    let barrier = fixture.directory.path().join("hold-operator-signature");
    let paused = fixture.directory.path().join("operator-signature-paused");
    fs::write(&barrier, b"").unwrap();
    std::thread::scope(|scope| {
        let work = scope.spawn(|| {
            runtime.issue_posture_document(&target, ea_crypto::object_hash(b"evidence"), 60_000)
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !paused.exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        posture.report.lock().unwrap().automatic_screen_lock =
            ea_key_provider::PostureRequirement::AutomaticScreenLock.fail();
        fs::remove_file(barrier).unwrap();
        assert!(work.join().unwrap().is_err());
    });
    let row = runtime
        .database()
        .query_row("SELECT count(*) FROM go_live_posture_issued", &[])
        .unwrap()
        .unwrap();
    assert_eq!(row.integer(0).unwrap(), 0);
    let row = runtime
        .database()
        .query_row(
            "SELECT exact_bytes FROM local_audit_event ORDER BY insertion_sequence DESC LIMIT 1",
            &[],
        )
        .unwrap()
        .unwrap();
    let event = ea_format::decode_local_audit_event(row.blob(0).unwrap()).unwrap();
    assert_eq!(event.outcome(), LocalAuditOutcomeV1::Failed);
}

#[test]
fn valid_admin_signatures_still_require_exact_current_registry_target_and_time() {
    use ea_crypto::{CoseSigner, GoLivePostureCore, SecretBytes};
    let fixture = NativePostureFixture::new();
    let runtime = fixture.open(documentable_measurement());
    let exact = runtime
        .issue_posture_document(
            &runtime.posture_target_context().unwrap(),
            ea_crypto::object_hash(b"evidence"),
            60_000,
        )
        .unwrap();
    let mut decoder = minicbor::Decoder::new(&exact);
    decoder.array().unwrap();
    let original = GoLivePostureCore::from_exact(decoder.bytes().unwrap()).unwrap();
    let signer = CoseSigner::from_secret(SecretBytes::new(
        trust_support::second_admin_signing_secret(),
    ));
    for index in 0..14 {
        let mut fields = original.fields().clone();
        match index {
            0 => {
                fields.organization_id =
                    ea_types::OrganizationId::try_from(&[0xab; 16][..]).unwrap()
            }
            1 => fields.chain_id = ea_types::ChainId::try_from(&[0xab; 16][..]).unwrap(),
            2 => fields.target_installation_id = Hash32::try_from(&[0xab; 32][..]).unwrap(),
            3 => fields.target_account_hash = Hash32::try_from(&[0xab; 32][..]).unwrap(),
            4 => fields.target_device_id = DeviceId::try_from(&[0xab; 16][..]).unwrap(),
            5 => {
                fields.target_certificate_hash = CertificateHash::try_from(&[0xab; 32][..]).unwrap()
            }
            6 => fields.target_binding_hash = ea_crypto::object_hash(b"foreign binding"),
            7 => fields.os_family = 3,
            8 => fields.os_build_hash = ea_crypto::object_hash(b"other native build"),
            9 => {
                fields.registry_version =
                    ea_types::RegistryVersion::new(fields.registry_version.get() + 1)
            }
            10 => fields.registry_head_hash = ea_crypto::object_hash(b"foreign head"),
            11 => {
                fields.issued_sequence =
                    ea_types::ChainSequence::new(fields.issued_sequence.get() + 1)
            }
            12 => fields.issuer_binding_hash = ea_crypto::object_hash(b"foreign issuer binding"),
            13 => fields.issued_at = UnixMillis::new(fields.issued_at.get() + 30_000),
            _ => unreachable!(),
        }
        let core = GoLivePostureCore::new(fields).unwrap();
        let signed = signer
            .sign_go_live_posture_document(core.exact_bytes())
            .unwrap();
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(core.exact_bytes())
            .unwrap()
            .bytes(&signed)
            .unwrap();
        assert!(
            runtime.import_posture_document(&e.into_writer()).is_err(),
            "valid Admin signature must not waive context field {index}"
        );
    }
    let forged = CoseSigner::from_secret(SecretBytes::new(trust_support::device_signing_secret()))
        .sign_go_live_posture_document(original.exact_bytes())
        .unwrap();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .bytes(original.exact_bytes())
        .unwrap()
        .bytes(&forged)
        .unwrap();
    assert!(
        runtime.import_posture_document(&e.into_writer()).is_err(),
        "Writer key cannot substitute for the selected Admin signer"
    );
}

#[test]
fn separate_native_admin_documents_writer_target_and_new_selected_head_invalidates_it() {
    use ea_trust::TrustObjectSource as _;
    let mut writer = Installation::new();
    let admin = NativePostureFixture::new();
    let subject = OperatorSubjectId::try_from(&[0x42; 16][..]).unwrap();
    let admin_certificate = writer.line.second_bootstrap_admin_hash();
    let binding = writer
        .line
        .push(
            ActionSpec::OperatorBinding {
                certificate_hash: admin_certificate,
                role: OperatorRoleV1::OrganizationAdmin,
                marker: 0x42,
                effective_from: Some(1),
            },
            HeadOptions {
                effective_from: Some(1),
                valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
                not_after: UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
                binding_operator_profile_commitment_override: Some(
                    ea_crypto::operator_profile_commitment(
                        trust_support::organization(),
                        subject,
                        TEST_NAME,
                        TEST_FUNCTION,
                        &PROFILE_SALT,
                    ),
                ),
                binding_instance_key_thumbprint_override: Some(
                    public(ADMIN_INSTANCE_SECRET).thumbprint(),
                ),
                binding_os_account_hash_override: Some(native_account_hash_for(
                    true,
                    DeviceId::try_from(&[0x52; 16][..]).unwrap(),
                )),
                ..HeadOptions::default()
            },
        )
        .direct_object_hash
        .unwrap();
    fn publish(line: &RegistryLineBuilder, archive: &std::path::Path) {
        fn existing(path: &std::path::Path, out: &mut Vec<Vec<u8>>) {
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    existing(&path, out);
                } else {
                    out.push(fs::read(path).unwrap());
                }
            }
        }
        let mut seen = Vec::new();
        existing(archive, &mut seen);
        let source = line.source();
        let mut hashes = Vec::new();
        source
            .visit_trust_object_hashes(&mut |hash| {
                hashes.push(hash);
                Ok(())
            })
            .unwrap();
        for hash in hashes {
            let exact = source.read_exact_trust_object(hash).unwrap().unwrap();
            if !seen.iter().any(|old| old.as_slice() == exact.as_ref()) {
                fs::write(
                    archive.join(format!("{}.etb", hex::encode(hash.as_bytes()))),
                    exact,
                )
                .unwrap();
            }
        }
    }
    publish(&writer.line, &writer.archive);
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&admin.config).unwrap()).unwrap();
    config["archive_directory"] = json!(writer.archive);
    config["binding_object_hash"] = json!(hex::encode(binding.as_bytes()));
    fs::write(&admin.config, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::write(&admin.anchor, fs::read(&writer.anchor).unwrap()).unwrap();
    let (provider, key) = database_provider_for(true);
    let db = EncryptedDatabase::open(
        &admin.directory.path().join("operator.sqlite"),
        &provider,
        &key,
    )
    .unwrap();
    db.execute(
        "UPDATE operator_profile SET operator_binding_object_hash=?1",
        &[StoreValue::Blob(binding.as_bytes().to_vec())],
    )
    .unwrap();
    drop(db);
    let host = documentable_measurement();
    let native = NativeOperatorProvider::open_test_fixture(
        writer.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    let mut target = OperatorRuntime::open_with_test_native_and_posture(
        OperatorRuntimeConfig::load(&writer.config).unwrap(),
        &writer.anchor,
        support::live_clock(),
        false,
        native,
        host.clone(),
    )
    .unwrap();
    let authority = admin.open(host);
    assert!(target.native().installation_id() != authority.native().installation_id());
    assert!(target.reauthenticate().is_err());
    let exact = authority
        .issue_posture_document(
            &target.posture_target_context().unwrap(),
            ea_crypto::object_hash(b"Writer operational prerequisites documented by Admin"),
            60_000,
        )
        .unwrap();
    target.import_posture_document(&exact).unwrap();
    target.reauthenticate().unwrap();
    assert!(
        authority.import_posture_document(&exact).is_err(),
        "Writer document does not authorize Admin target"
    );
    writer.line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: Some(1),
        },
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
            policy_max_registry_age_ms_override: Some(support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1),
            ..HeadOptions::default()
        },
    );
    publish(&writer.line, &writer.archive);
    target.refresh_for_action().unwrap();
    assert!(
        target.posture_admission().is_err(),
        "exact newly selected HEAD invalidates documentation before nominal expiry"
    );
    assert!(target.import_posture_document(&exact).is_err());
}

#[test]
fn concurrent_duplicate_imports_are_idempotent_older_document_cannot_replace_newer_and_diagnosis_is_read_only()
 {
    let fixture = NativePostureFixture::new();
    let runtime = fixture.open(Arc::new(ControlledMeasurement::new()));
    let target = runtime.posture_target_context().unwrap();
    let old = runtime
        .issue_posture_document(&target, ea_crypto::object_hash(b"first evidence"), 60_000)
        .unwrap();
    runtime.import_posture_document(&old).unwrap();
    std::thread::scope(|scope| {
        let a = scope.spawn(|| runtime.import_posture_document(&old));
        let b = scope.spawn(|| runtime.import_posture_document(&old));
        a.join().unwrap().unwrap();
        b.join().unwrap().unwrap();
    });
    let new = runtime
        .issue_posture_document(&target, ea_crypto::object_hash(b"new evidence"), 60_000)
        .unwrap();
    runtime.import_posture_document(&new).unwrap();
    assert!(runtime.import_posture_document(&old).is_err());
    let before = runtime
        .database()
        .query_row("SELECT last_observed_wall FROM go_live_posture_clock", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    let report = runtime.go_live_report().unwrap();
    assert!(report.session_admitted);
    let after = runtime
        .database()
        .query_row("SELECT last_observed_wall FROM go_live_posture_clock", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    assert_eq!(
        before, after,
        "diagnostic report never mutates the rollback guard"
    );
    assert_eq!(
        runtime
            .database()
            .query_row("SELECT count(*) FROM go_live_posture_evidence", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
    assert!(
        runtime.posture_admission().unwrap().document_hash() == Some(ea_crypto::object_hash(&new))
    );
}
