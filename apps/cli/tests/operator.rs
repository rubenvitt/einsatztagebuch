//! Die Operator-Kommandos akzeptieren keine Ersatzidentität oder Schlüsseldatei.
#![cfg(test)]

// A separate test executable shares the production parser, output, and command
// dispatcher. The shipped main never selects its explicit fixture opener.
#[allow(dead_code)]
#[path = "../src/args.rs"]
mod args;
#[allow(dead_code)]
#[path = "../src/commands/operator.rs"]
mod operator_command;
#[allow(dead_code)]
#[path = "../src/output.rs"]
mod output;

mod support;

use std::{fs, process::Command};

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_einsatzarchiv"))
        .args(arguments)
        .output()
        .expect("CLI starts")
}

fn public_config() -> String {
    format!(
        r#"{{"archive_directory":"archive","database_path":"operator.sqlite","device_certificate_hash":"{}","binding_object_hash":"{}","role":"writer","purpose":"finalize"}}"#,
        "11".repeat(32),
        "22".repeat(32)
    )
}

#[test]
fn each_operator_action_requires_public_configuration() {
    for action in ["provision", "verify-session", "revoke"] {
        let output = run(&["--trust-anchor", "anchor", "operator", action]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--operator-config"));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn operator_configuration_is_rejected_on_other_commands() {
    for command in [
        "verify",
        "list",
        "report",
        "export",
        "decrypt",
        "organization",
    ] {
        let output = run(&[
            "--trust-anchor",
            "anchor",
            "--operator-config",
            "config.json",
            command,
            "archive",
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--operator-config"));
    }
}

#[test]
fn public_config_reaches_real_anchor_validation_without_mutating_inputs() {
    let directory = support::temp_dir("operator-runtime-anchor");
    let anchor = directory.path().join("external-anchor.etb");
    let config = directory.path().join("public-config.json");
    let original = b"existing private-path independent anchor";
    fs::write(&anchor, original).unwrap();
    fs::write(&config, public_config()).unwrap();
    let output = run(&[
        "--trust-anchor",
        anchor.to_str().unwrap(),
        "operator",
        "verify-session",
        "--operator-config",
        config.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(12));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(anchor.to_str().unwrap()));
    assert!(!stderr.contains("private-path"));
    assert_eq!(fs::read(&anchor).unwrap(), original);
    assert_eq!(fs::read_to_string(&config).unwrap(), public_config());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn private_identity_fields_in_config_are_rejected_before_archive_or_native_access() {
    let directory = support::temp_dir("operator-runtime-config");
    let path = directory.path().join("config.json");
    let mut config: serde_json::Value = serde_json::from_str(&public_config()).unwrap();
    config["display_name"] = serde_json::json!("never print this private name");
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let output = run(&[
        "--trust-anchor",
        "absent-anchor",
        "--operator-config",
        path.to_str().unwrap(),
        "operator",
        "verify-session",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("EA-OPERATOR-CONFIG"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private name"));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn duplicate_or_missing_operator_config_values_are_usage_errors() {
    for args in [
        vec!["--operator-config"],
        vec!["--operator-config", "one", "--operator-config", "two"],
    ] {
        let mut arguments = vec!["--trust-anchor", "anchor", "operator", "verify-session"];
        arguments.extend(args);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2));
    }
}

#[test]
fn each_operator_action_requires_an_external_anchor_argument() {
    for action in ["provision", "verify-session", "revoke"] {
        let output = run(&["operator", action]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--trust-anchor"));
    }
}

#[test]
fn operator_actions_reject_free_identity_text_and_key_or_output_paths() {
    for extra in [
        vec!["freely-entered-person"],
        vec!["--key", "instance-key-file"],
        vec!["--output", "plaintext-profile"],
        vec!["--include-runtime-metadata"],
        vec!["--report-signing-key", "signer"],
    ] {
        for action in ["provision", "verify-session", "revoke"] {
            let mut arguments = vec!["--trust-anchor", "anchor", "operator", action];
            arguments.extend(extra.iter().copied());
            let output = run(&arguments);
            assert_eq!(output.status.code(), Some(2), "{arguments:?}");
            assert!(output.stdout.is_empty());
        }
    }
}

#[test]
fn operator_subcommands_are_closed() {
    for arguments in [
        vec!["--trust-anchor", "anchor", "operator"],
        vec!["--trust-anchor", "anchor", "operator", "restore"],
        vec!["--trust-anchor", "anchor", "operator", "login-as"],
    ] {
        assert_eq!(run(&arguments).status.code(), Some(2));
    }
}

#[test]
fn invalid_subcommands_report_command_specific_choices() {
    for (command, action, expected_diagnostic) in [
        (
            "organization",
            "iniit",
            "einsatzarchiv: unknown organization subcommand iniit; expected init",
        ),
        (
            "operator",
            "restore",
            "einsatzarchiv: unknown operator subcommand restore; expected provision, verify-session or revoke",
        ),
    ] {
        let output = run(&["--trust-anchor", "anchor", command, action]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.lines().next(), Some(expected_diagnostic));
    }
}

#[test]
fn json_format_cannot_bypass_required_operator_configuration() {
    let output = run(&[
        "--trust-anchor",
        "anchor",
        "--format",
        "json",
        "operator",
        "verify-session",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

// The helper below exists only in a temporary test installation and the test
// executable uses an explicit library fixture port. Production rejects it.
#[cfg(unix)]
mod process_native {
    use super::*;
    use ea_crypto::{CanonicalPublicCoseKey, SignerRole, VerificationContext};
    use ea_format::{
        CertificateKindV1, KeyProtectionProfileV1, LocalAuditActionV1, LocalAuditOutcomeV1,
        OperatorRoleV1,
    };
    use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
    use ea_local_store::{EncryptedDatabase, StoreValue};
    use ea_types::{
        CertificateHash, ChainSequence, DeviceId, Hash32, ObjectHash, OperatorSubjectId, UnixMillis,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::{Value, json};
    use std::{
        io::{BufRead, Read, Write},
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::Arc,
    };
    use support::verify_support::archive_support::trust_support::{
        self, ActionSpec, HeadOptions, RegistryLineBuilder,
    };

    const INSTANCE_SECRET: [u8; 32] = [0x47; 32];
    const PROFILE_SALT: [u8; 32] = [0x53; 32];
    const TEST_NAME: &str = "Private Fixture Operator";
    const TEST_FUNCTION: &str = "Private Fixture Function";
    const TEST_GUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const ADMIN_INSTANCE_SECRET: [u8; 32] = [0x68; 32];

    fn account_response() -> Value {
        account_response_for(false)
    }
    fn account_response_for(authority: bool) -> Value {
        let guid = if authority {
            "ffeeddcc-bbaa-9988-7766-554433221100"
        } else {
            TEST_GUID
        };
        let uid = if authority { 502 } else { 501 };
        if cfg!(target_os = "macos") {
            json!({"platform":"macos","guid_values":[guid],"unique_id_values":[uid.to_string()],"uid":uid,"locked":false})
        } else {
            json!({"platform":"linux","machine_id_bytes":hex::encode(format!("{}\n", guid.replace('-', ""))),"uid":uid,"locked":false})
        }
    }
    fn native_account_hash() -> Hash32 {
        native_account_hash_for(false, device())
    }
    fn native_account_hash_for(authority: bool, device: DeviceId) -> Hash32 {
        let response = account_response_for(authority);
        let uid = response["uid"].as_u64().unwrap() as u32;
        let inputs = if cfg!(target_os = "macos") {
            ea_operator::macos::account_inputs(
                vec![response["guid_values"][0].as_str().unwrap().into()],
                vec![uid.to_string()],
                uid,
            )
        } else {
            ea_operator::linux::account_inputs(
                hex::decode(response["machine_id_bytes"].as_str().unwrap()).unwrap(),
                uid,
            )
        };
        inputs
            .binding_hash(trust_support::organization(), device)
            .unwrap()
    }
    fn device() -> DeviceId {
        DeviceId::try_from([0x51; 16].as_slice()).unwrap()
    }
    fn public(secret: [u8; 32]) -> CanonicalPublicCoseKey {
        CanonicalPublicCoseKey::ed25519(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
            .unwrap()
    }
    fn database_provider() -> (InMemoryKeyProvider, ea_key_provider::KeyHandle) {
        database_provider_for(false)
    }
    fn database_provider_for(authority: bool) -> (InMemoryKeyProvider, ea_key_provider::KeyHandle) {
        let provider = InMemoryKeyProvider::new_for_test([if authority { 0x95 } else { 0x94 }; 32]);
        let key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        (provider, key)
    }
    fn open_database(path: &Path) -> Arc<EncryptedDatabase> {
        let (provider, key) = database_provider();
        Arc::new(EncryptedDatabase::open(path, &provider, &key).unwrap())
    }
    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
    }
    fn install_fixture_helper(directory: &Path) {
        let helper = directory.join("ea-native-operator");
        let test_binary = std::env::current_exe().unwrap();
        // Keep the native response pipe on fd 3 before discarding libtest's
        // stdout. exec avoids a shell/awk pipeline for every native operation;
        // stderr remains connected to the production subprocess reader.
        fs::write(
            &helper,
            format!(
                "#!/bin/sh\nexport EA_CLI_TEST_DIRECTORY={}\nexec 3>&1\nexec {} --ignored --exact process_native::native_cli_helper --nocapture >/dev/null\n",
                shell_quote(directory),
                shell_quote(&test_binary)
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    }

    struct Installation {
        directory: support::TempDir,
        binary: PathBuf,
        config: PathBuf,
        anchor: PathBuf,
        archive: PathBuf,
        database: PathBuf,
        binding: ObjectHash,
        certificate: CertificateHash,
        line: RegistryLineBuilder,
    }
    impl Installation {
        fn new() -> Self {
            let directory = support::temp_dir("operator-native-process");
            let binary = directory.path().join("einsatzarchiv");
            fs::copy(env!("CARGO_BIN_EXE_einsatzarchiv"), &binary).unwrap();
            install_fixture_helper(directory.path());
            let archive = directory.path().join("archive");
            let mut fixture = support::live_clock_archive();
            // Rebuild exactly the shared fixture's deterministic trust prefix,
            // then add one newly signed native-account binding at the next seq.
            let mut line = RegistryLineBuilder::new();
            line.push(
                ActionSpec::Policy {
                    policy_version: None,
                    previous_policy_hash: None,
                    effective_from: None,
                },
                HeadOptions {
                    effective_from: Some(0),
                    valid_through: Some(0),
                    not_after: UnixMillis::new(support::LIVE_POLICY_NOT_AFTER_V1),
                    policy_max_registry_age_ms_override: Some(
                        support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
                    ),
                    ..HeadOptions::default()
                },
            );
            let writer = line.push(
                ActionSpec::Device {
                    kind: CertificateKindV1::Writer,
                    marker: 0x11,
                    effective_from: Some(0),
                },
                HeadOptions {
                    effective_from: Some(0),
                    valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
                    not_after: UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
                    ..HeadOptions::default()
                },
            );
            let certificate_object = writer.direct_object_hash.unwrap();
            assert!(
                fixture
                    .fixture
                    .blobs()
                    .iter()
                    .any(|(_, bytes)| ea_crypto::object_hash(bytes) == writer.object_hash)
            );
            let subject = OperatorSubjectId::try_from([0x71; 16].as_slice()).unwrap();
            let binding = line
                .push(
                    ActionSpec::OperatorBinding {
                        certificate_hash: certificate_object,
                        role: OperatorRoleV1::Writer,
                        marker: 0x71,
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
                            public(INSTANCE_SECRET).thumbprint(),
                        ),
                        binding_os_account_hash_override: Some(native_account_hash()),
                        ..HeadOptions::default()
                    },
                )
                .direct_object_hash
                .unwrap();
            use ea_trust::TrustObjectSource as _;
            let source = line.source();
            let mut hashes = Vec::new();
            source
                .visit_trust_object_hashes(&mut |hash| {
                    hashes.push(hash);
                    Ok(())
                })
                .unwrap();
            for hash in hashes {
                let bytes = source
                    .read_exact_trust_object(hash)
                    .unwrap()
                    .unwrap()
                    .to_vec();
                if !fixture
                    .fixture
                    .blobs()
                    .iter()
                    .any(|(_, existing)| existing == &bytes)
                {
                    fixture.fixture.push_exact_bytes(
                        &format!(
                            "{}.etb",
                            hex::encode(ea_crypto::object_hash(&bytes).as_bytes())
                        ),
                        bytes,
                    );
                }
            }
            drop(source);
            support::materialize(&fixture.fixture, &archive);
            let anchor = directory.path().join("independent-anchor.etb");
            fs::write(&anchor, &fixture.anchor_bytes).unwrap();
            let database = directory.path().join("operator.sqlite");
            let db = open_database(&database);
            db.execute(
                "INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",
                &[
                    StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                    StoreValue::Blob(subject.as_bytes().to_vec()),
                    StoreValue::Text(TEST_NAME.into()),
                    StoreValue::Text(TEST_FUNCTION.into()),
                    StoreValue::Blob(PROFILE_SALT.to_vec()),
                    StoreValue::Blob(binding.as_bytes().to_vec()),
                ],
            )
            .unwrap();
            drop(db);
            let config = directory.path().join("public.json");
            fs::write(&config,serde_json::to_vec(&json!({
                "archive_directory":"archive","database_path":"operator.sqlite","device_certificate_hash":hex::encode(certificate_object.as_bytes()),
                "binding_object_hash":hex::encode(binding.as_bytes()),"role":"writer","purpose":"finalize"
            })).unwrap()).unwrap();
            Self {
                directory,
                binary,
                config,
                anchor,
                archive,
                database,
                binding,
                certificate: CertificateHash::from(certificate_object),
                line,
            }
        }
        fn arguments(&self) -> Vec<String> {
            [
                "--trust-anchor",
                self.anchor.to_str().unwrap(),
                "operator",
                "verify-session",
                "--operator-config",
                self.config.to_str().unwrap(),
                "--format",
                "json",
            ]
            .map(str::to_owned)
            .to_vec()
        }
        fn production_login(&self) -> std::process::Output {
            Command::new(&self.binary)
                .args(self.arguments())
                .output()
                .unwrap()
        }
        fn login(&self) -> std::process::Output {
            let mut output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "process_native::fixture_cli",
                    "--nocapture",
                ])
                .env(
                    "EA_OPERATOR_FIXTURE_ARGS",
                    serde_json::to_string(&self.arguments()).unwrap(),
                )
                .env("EA_OPERATOR_FIXTURE_DIRECTORY", self.directory.path())
                .output()
                .unwrap();
            // Strip only libtest's framing, emitted before the real dispatcher.
            // No report or error byte is replaced by the fixture controller.
            let marker = b"EA_CLI_FIXTURE_OUTPUT\n";
            let start = output
                .stdout
                .windows(marker.len())
                .position(|bytes| bytes == marker)
                .unwrap_or_else(|| {
                    panic!(
                        "fixture executable did not start: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )
                });
            output.stdout.drain(..start + marker.len());
            output
        }
        fn mode(&self, mode: &str) {
            fs::write(self.directory.path().join("helper-mode"), mode).unwrap();
        }
        fn publish_fixture_revocation(&mut self) {
            use ea_trust::TrustObjectSource as _;
            let mut previous = Vec::new();
            self.line
                .source()
                .visit_trust_object_hashes(&mut |hash| {
                    previous.push(hash);
                    Ok(())
                })
                .unwrap();
            self.line.push(
                ActionSpec::Revoke {
                    target_kind: 1,
                    object_hash: self.binding,
                },
                HeadOptions {
                    effective_from: Some(1),
                    valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
                    not_after: UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
                    ..HeadOptions::default()
                },
            );
            let source = self.line.source();
            source
                .visit_trust_object_hashes(&mut |hash| {
                    if !previous.contains(&hash) {
                        let exact = source.read_exact_trust_object(hash)?.unwrap();
                        fs::write(
                            self.archive
                                .join(format!("{}.etb", hex::encode(hash.as_bytes()))),
                            exact,
                        )
                        .unwrap();
                    }
                    Ok(())
                })
                .unwrap();
        }
        fn latest_audit(&self, outcome: LocalAuditOutcomeV1) -> (Vec<u8>, i64) {
            let db = open_database(&self.database);
            let count = db
                .query_row("SELECT count(*) FROM local_audit_event", &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap();
            let row = db.query_row("SELECT exact_bytes FROM local_audit_event ORDER BY insertion_sequence DESC LIMIT 1 OFFSET ?1", &[StoreValue::Integer(if outcome == LocalAuditOutcomeV1::Failed {1} else {0})]).unwrap().expect("native login must audit");
            let reauth = if outcome == LocalAuditOutcomeV1::Failed {
                let latest = db.query_row("SELECT exact_bytes FROM local_audit_event ORDER BY insertion_sequence DESC LIMIT 1", &[]).unwrap().unwrap().blob(0).unwrap().to_vec();
                let event = ea_format::decode_local_audit_event(&latest).unwrap();
                assert!(matches!(
                    event.action(),
                    LocalAuditActionV1::ReauthFailure(_)
                ));
                assert_eq!(event.outcome(), LocalAuditOutcomeV1::Failed);
                Some(latest)
            } else {
                None
            };
            let bytes = row.blob(0).unwrap().to_vec();
            let event = ea_format::decode_local_audit_event(&bytes).unwrap();
            assert_eq!(event.outcome(), outcome);
            assert!(matches!(event.action(), LocalAuditActionV1::Login(_)));
            assert!(event.device_id() == device());
            assert!(
                event.signer_certificate_object_hash().as_bytes() == self.certificate.as_bytes()
            );
            // Verify the persisted COSE under the actual active certificate.
            let snapshot = ea_admin::operator_runtime::OperatorArchiveSnapshot::open(
                &self.archive,
                &self.anchor,
                support::live_clock(),
            )
            .unwrap();
            let key = ea_trust::TrustStateKey {
                organization_id: trust_support::organization(),
                device_id: device(),
            };
            let mut store = ea_admin::operator_trust_store::OperatorTrustStateStore::open(
                db,
                key,
                snapshot.anchor().chain_id(),
                snapshot.anchor().trust_anchor_hash(),
                UnixMillis::new(0),
            )
            .unwrap();
            let trust = ea_trust::verify_trust(
                snapshot.anchor(),
                snapshot.inventory(),
                ea_trust::load_trust_state(&mut store, key).unwrap(),
            )
            .unwrap();
            let candidate =
                ea_trust::verify_registry_candidate(&trust, ChainSequence::new(1)).unwrap();
            let time =
                ea_trust::prepare_local_time(&mut store, &candidate, support::live_clock(), &[])
                    .unwrap();
            let ea_trust::RegistrySelectionOutcome::Selected(head) =
                ea_trust::select_registry_head(candidate, time, None).unwrap()
            else {
                panic!("current persistent head");
            };
            for exact in std::iter::once(bytes.as_slice()).chain(reauth.as_deref()) {
                let event = ea_format::decode_local_audit_event(exact).unwrap();
                assert!(event.device_id() == device());
                assert!(
                    event.signer_certificate_object_hash().as_bytes()
                        == self.certificate.as_bytes()
                );
                let mut decoder = minicbor::Decoder::new(exact);
                assert_eq!(decoder.array().unwrap(), Some(2));
                decoder.skip().unwrap();
                let start = decoder.position();
                decoder.skip().unwrap();
                let context = VerificationContext::local_audit(
                    event.exact_core(),
                    head.proposed_sequence(),
                    SignerRole::Writer,
                    head.registry_version(),
                )
                .unwrap();
                ea_crypto::verify_cose_sign1(&exact[start..decoder.position()], &head, &context)
                    .unwrap();
            }
            (bytes, count)
        }
    }

    #[test]
    fn production_cli_rejects_an_unsigned_fixed_sibling_helper() {
        let installed = Installation::new();
        let output = installed.production_login();
        assert_eq!(output.status.code(), Some(12));
        assert!(output.stdout.is_empty());
        assert!(!installed.directory.path().join("helper-calls").exists());
        assert_eq!(
            open_database(&installed.database)
                .query_row("SELECT count(*) FROM local_audit_event", &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap(),
            0
        );
    }

    #[test]
    fn fixture_cli_native_login_succeeds_and_persists_a_real_signed_login_across_restart() {
        let installed = Installation::new();
        for expected_count in [1, 2] {
            let output = installed.login();
            assert_eq!(
                output.status.code(),
                Some(0),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["binding_state"], "active");
            assert_eq!(
                report["productive_binding_hashes"],
                json!([hex::encode(installed.binding.as_bytes())])
            );
            assert_eq!(report["current_native_account_match"], true);
            assert_eq!(report["next_sequence"], 1);
            for private in [
                TEST_NAME,
                TEST_FUNCTION,
                TEST_GUID,
                installed.directory.path().to_str().unwrap(),
            ] {
                assert!(!String::from_utf8_lossy(&output.stdout).contains(private));
                assert!(!String::from_utf8_lossy(&output.stderr).contains(private));
            }
            let (_, count) = installed.latest_audit(LocalAuditOutcomeV1::Completed);
            assert_eq!(count, expected_count);
        }
        let calls = fs::read_to_string(installed.directory.path().join("helper-calls")).unwrap();
        for forbidden in ["initialize", "generate", "root-signing", "admin-signing"] {
            assert!(!calls.contains(forbidden));
        }
        assert!(calls.contains("sign operator-instance"));
        assert!(calls.contains("sign writer-signing"));
    }

    #[test]
    fn fixture_cli_unknown_binding_is_rejected_with_an_authentic_failed_login_audit() {
        let installed = Installation::new();
        let mut config: Value =
            serde_json::from_slice(&fs::read(&installed.config).unwrap()).unwrap();
        config["binding_object_hash"] = json!("00".repeat(32));
        fs::write(&installed.config, serde_json::to_vec(&config).unwrap()).unwrap();
        let output = installed.login();
        assert_eq!(
            output.status.code(),
            Some(12),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        let (bytes, count) = installed.latest_audit(LocalAuditOutcomeV1::Failed);
        assert_eq!(count, 2);
        assert!(
            ea_format::decode_local_audit_event(&bytes)
                .unwrap()
                .operator_binding_object_hash()
                .is_none()
        );
        let calls = fs::read_to_string(installed.directory.path().join("helper-calls")).unwrap();
        assert!(!calls.contains("sign operator-instance"));
        assert!(calls.contains("sign writer-signing"));
    }

    #[test]
    fn fixture_cli_applies_a_new_signed_revocation_after_a_previously_successful_login() {
        let mut installed = Installation::new();
        assert_eq!(installed.login().status.code(), Some(0));
        installed.publish_fixture_revocation();
        let output = installed.login();
        assert_eq!(output.status.code(), Some(12));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("EA-OPERATOR-BINDING-NOT-ACTIVE"));
        let (_, count) = installed.latest_audit(LocalAuditOutcomeV1::Failed);
        assert_eq!(count, 3);
    }

    #[test]
    fn fixture_cli_does_not_create_database_or_keys_and_rejects_a_foreign_native_signer() {
        let installed = Installation::new();
        installed.mode("foreign-writer");
        let output = installed.login();
        assert_eq!(output.status.code(), Some(12));
        assert!(String::from_utf8_lossy(&output.stderr).contains("EA-OPERATOR-SIGNER-MISMATCH"));
        let db = open_database(&installed.database);
        assert_eq!(
            db.query_row("SELECT count(*) FROM local_audit_event", &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap(),
            0
        );
        drop(db);
        installed.mode("database-key-missing");
        assert_eq!(installed.login().status.code(), Some(14));
        installed.mode("");
        fs::remove_file(&installed.database).unwrap();
        let output = installed.login();
        assert_eq!(output.status.code(), Some(14));
        assert!(!installed.database.exists());
        let calls = fs::read_to_string(installed.directory.path().join("helper-calls")).unwrap();
        assert!(!calls.contains("generate"));
        assert!(!calls.contains("initialize"));
    }

    #[test]
    fn fixture_cli_missing_or_replaced_instance_is_audited_without_regeneration() {
        let installed = Installation::new();
        for (mode, expected_count) in [("instance-missing", 2), ("foreign-instance", 4)] {
            installed.mode(mode);
            let output = installed.login();
            assert_eq!(output.status.code(), Some(12));
            assert!(output.stdout.is_empty());
            let (_, count) = installed.latest_audit(LocalAuditOutcomeV1::Failed);
            assert_eq!(count, expected_count);
        }
        let calls = fs::read_to_string(installed.directory.path().join("helper-calls")).unwrap();
        assert!(!calls.contains("generate"));
        assert!(!calls.contains("sign operator-instance"));
    }

    #[test]
    fn fixture_cli_watch_invalidation_eof_or_stall_survives_unlock_and_runtime_refresh() {
        for mode in ["watch-event", "watch-eof", "watch-stall"] {
            let installed = Installation::new();
            installed.mode(mode);
            let output = installed.login();
            assert_eq!(
                output.status.code(),
                Some(12),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stdout.is_empty());
            assert!(
                installed
                    .directory
                    .path()
                    .join("watch-healthy-before-fault")
                    .exists(),
                "the real runtime must validate a live watcher before the injected fault"
            );
            let calls =
                fs::read_to_string(installed.directory.path().join("helper-calls")).unwrap();
            assert_eq!(
                calls
                    .lines()
                    .filter(|line| line.starts_with("watch-session "))
                    .count(),
                1
            );
            assert!(!calls.contains("sign operator-instance"));
            assert_eq!(
                open_database(&installed.database)
                    .query_row("SELECT count(*) FROM local_audit_event", &[])
                    .unwrap()
                    .unwrap()
                    .integer(0)
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn fixture_watch_terminal_frame_survives_first_byte_reader_close() {
        use std::{
            process::{Child, Stdio},
            sync::mpsc,
            thread,
            time::{Duration, Instant},
        };

        struct ReapedChild(Child);
        impl Drop for ReapedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let directory = support::temp_dir("watch-terminal-frame");
        install_fixture_helper(directory.path());
        for trial in 0..12 {
            let action = directory.path().join("watch-action");
            let delivered = directory.path().join("watch-delivered");
            if action.exists() {
                fs::remove_file(&action).unwrap();
            }
            if delivered.exists() {
                fs::remove_file(&delivered).unwrap();
            }
            let mut child = ReapedChild(
                Command::new(directory.path().join("ea-native-operator"))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let mut input = child.0.stdin.take().unwrap();
            let output = child.0.stdout.take().unwrap();
            let (ready_tx, ready_rx) = mpsc::channel();
            let (terminal_tx, terminal_rx) = mpsc::channel();
            let reader = thread::spawn(move || {
                let mut output = std::io::BufReader::new(output);
                let mut ready = String::new();
                let valid = output.read_line(&mut ready).is_ok()
                    && serde_json::from_str::<Value>(&ready)
                        .is_ok_and(|value| value["ready"] == true);
                let _ = ready_tx.send(valid);
                let mut first = [0];
                let terminal = output.read_exact(&mut first).is_ok() && first == [b'{'];
                // Match SessionWatch: unsolicited first byte invalidates and
                // drops the reader immediately, without waiting for the line.
                drop(output);
                let _ = terminal_tx.send(terminal);
            });
            input.write_all(b"{\"op\":\"watch-session\"}\n").unwrap();
            assert!(ready_rx.recv_timeout(Duration::from_secs(2)).unwrap());
            fs::write(&action, "watch-event").unwrap();
            assert!(terminal_rx.recv_timeout(Duration::from_secs(2)).unwrap());
            drop(input);
            reader.join().unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(Instant::now() < deadline, "terminal helper must exit");
                thread::sleep(Duration::from_millis(5));
            };
            let mut stderr = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            assert!(
                status.success() && delivered.exists(),
                "terminal delivery marker must survive reader closure (trial {trial}, broken_pipe={})",
                stderr.contains("Broken pipe")
            );
        }
    }

    #[test]
    #[ignore = "separate cfg(test) CLI fixture executable; never selected by production main"]
    fn fixture_cli() {
        use ea_admin::{
            native_provider::NativeOperatorProvider, operator_runtime::OperatorRuntime,
        };
        let directory = PathBuf::from(std::env::var_os("EA_OPERATOR_FIXTURE_DIRECTORY").unwrap());
        let arguments: Vec<String> =
            serde_json::from_str(&std::env::var("EA_OPERATOR_FIXTURE_ARGS").unwrap()).unwrap();
        println!("EA_CLI_FIXTURE_OUTPUT");
        std::io::stdout().flush().unwrap();
        let invocation = args::parse(arguments.into_iter().map(std::ffi::OsString::from)).unwrap();
        let args::Command::Operator { action, ref config } = invocation.command else {
            panic!("fixture executable only dispatches operator commands");
        };
        let code = operator_command::run_with_runtime_opener(
            &invocation,
            action,
            config,
            support::live_clock(),
            |config, anchor, now, initialize| {
                let native = NativeOperatorProvider::open_test_fixture(
                    directory.join("ea-native-operator"),
                    initialize,
                )?;
                let mut runtime = OperatorRuntime::open_with_test_native(
                    config,
                    anchor,
                    now,
                    initialize,
                    Arc::clone(&native),
                )?;
                let mode = fs::read_to_string(directory.join("helper-mode")).unwrap_or_default();
                if matches!(mode.as_str(), "watch-event" | "watch-eof" | "watch-stall") {
                    // A legitimate snapshot refresh retains the same watcher.
                    let binding = runtime.config().binding_object_hash;
                    runtime.refresh_with_binding(binding)?;
                    assert!(Arc::ptr_eq(&native, runtime.native()));
                    fs::write(directory.join("watch-healthy-before-fault"), b"").unwrap();
                    fs::write(directory.join("watch-action"), &mode).unwrap();
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                    while runtime.ensure_current().is_ok() {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "watcher must latch its event/EOF/stall"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    fs::remove_file(directory.join("watch-action")).unwrap();
                    fs::write(directory.join("helper-mode"), "").unwrap();
                    // The helper's one-shot account now reports unlocked. This
                    // cannot reset the lifetime latch or mint another session.
                    assert!(runtime.ensure_current().is_err());
                    assert!(runtime.refresh_with_binding(binding).is_err());
                }
                Ok(runtime)
            },
        );
        std::io::stdout().flush().unwrap();
        std::io::stderr().flush().unwrap();
        std::process::exit(code.as_i32());
    }

    fn emit_native_response(response: &Value) {
        let mut frame = serde_json::to_vec(response).unwrap();
        frame.push(b'\n');
        if response.get("invalidated") == Some(&Value::Bool(true)) {
            // An unsolicited first byte closes the native reader immediately.
            // Keep this terminal frame within POSIX's minimum atomic pipe size.
            assert!(frame.len() <= 512);
        }
        let mut pipe = fs::OpenOptions::new()
            .write(true)
            .open("/dev/fd/3")
            .expect("fixture helper requires its inherited native response pipe");
        pipe.write_all(&frame).unwrap();
        pipe.flush().unwrap();
    }

    #[test]
    #[ignore = "entry point of the temporary fixed sibling helper, invoked by process fixtures"]
    fn native_cli_helper() {
        let directory = PathBuf::from(
            std::env::var_os("EA_CLI_TEST_DIRECTORY")
                .expect("test helper requires isolated directory"),
        );
        let mut reader = std::io::BufReader::new(std::io::stdin());
        let mut input = String::new();
        reader.read_line(&mut input).unwrap();
        let request: Value = serde_json::from_str(&input).unwrap();
        let op = request["op"].as_str().unwrap();
        let slot = request["slot"].as_str().unwrap_or("");
        let authority = directory.join("authority-fixture").exists();
        let installation = if authority { "c2" } else { "c1" }.repeat(32);
        writeln!(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(directory.join("helper-calls"))
                .unwrap(),
            "{op} {slot}"
        )
        .unwrap();
        if op == "watch-session" {
            emit_native_response(&json!({"ok":true,"installation_id":installation,"ready":true}));
            let (sender, incoming) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                loop {
                    let mut bytes = Vec::new();
                    if reader
                        .by_ref()
                        .take(1025)
                        .read_until(b'\n', &mut bytes)
                        .is_err()
                        || bytes.len() > 1024
                        || bytes.last() != Some(&b'\n')
                    {
                        return;
                    }
                    let Some(challenge) = std::str::from_utf8(&bytes)
                        .ok()
                        .and_then(|line| line.strip_prefix("{\"challenge\":\""))
                        .and_then(|line| line.strip_suffix("\"}\n"))
                    else {
                        return;
                    };
                    if challenge.len() != 64
                        || !challenge
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        || sender.send(challenge.to_owned()).is_err()
                    {
                        return;
                    }
                }
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
            while std::time::Instant::now() < deadline {
                let challenge = match incoming.recv_timeout(std::time::Duration::from_millis(20)) {
                    Ok(challenge) => Some(challenge),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                };
                if !directory.exists() {
                    return;
                }
                // Consume the fixture's native event before acknowledging the
                // actual fresh challenge. No nonce or private context is logged.
                match fs::read_to_string(directory.join("watch-action"))
                    .unwrap_or_default()
                    .as_str()
                {
                    "watch-event" => {
                        emit_native_response(
                            &json!({"ok":true,"installation_id":installation,"invalidated":true}),
                        );
                        fs::write(directory.join("watch-delivered"), b"").unwrap();
                        return;
                    }
                    "watch-eof" => return,
                    "watch-stall" => continue,
                    _ => {}
                }
                if let Some(challenge) = challenge {
                    emit_native_response(
                        &json!({"ok":true,"installation_id":installation,"challenge":challenge}),
                    );
                }
            }
            return;
        }
        let mode = fs::read_to_string(directory.join("helper-mode")).unwrap_or_default();
        let generation = fs::read_to_string(directory.join("instance-generation"))
            .ok()
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);
        let offline_target = directory.join("offline-target").exists();
        let instance = if authority {
            ADMIN_INSTANCE_SECRET
        } else if offline_target {
            [0x47 + generation; 32]
        } else {
            INSTANCE_SECRET
        };
        let allowed = matches!(slot, "operator-instance")
            || if authority {
                matches!(slot, "admin-signing" | "root-signing")
            } else {
                slot == "writer-signing"
            };
        let secret = match slot {
            "operator-instance" if mode == "foreign-instance" => [0x78; 32],
            "operator-instance" => instance,
            "writer-signing" if mode == "foreign-writer" => [0x79; 32],
            "writer-signing" => trust_support::device_signing_secret(),
            "admin-signing" if authority => trust_support::second_admin_signing_secret(),
            "root-signing" if authority => trust_support::root_signing_secret(),
            _ => [0; 32],
        };
        let mut response = match op {
            "account" => account_response_for(authority),
            "initialize" if !authority => account_response(),
            "generate" if slot == "operator-instance" && !authority && offline_target => {
                assert_eq!(request["replace"], true);
                fs::write(
                    directory.join("instance-generation"),
                    (generation + 1).to_string(),
                )
                .unwrap();
                json!({})
            }
            "public-key"
                if slot == "operator-instance"
                    && (mode == "instance-missing" || offline_target && generation == 0) =>
            {
                json!({"public_key":null})
            }
            "public-key" if allowed => {
                json!({"public_key":hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())})
            }
            "unwrap-secret" if slot == "database-key" && mode != "database-key-missing" => {
                let (provider, key) = database_provider_for(authority);
                provider
                    .unwrap_database_key(&key)
                    .unwrap()
                    .with_exposed(|bytes| json!({"secret":hex::encode(bytes)}))
            }
            "contains" => json!({"contains":mode!="database-key-missing"}),
            "sign" if allowed => {
                if authority && slot == "root-signing" {
                    let barrier = directory.join("hold-root-signature");
                    if barrier.exists() {
                        fs::write(directory.join("root-signature-paused"), b"").unwrap();
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(5);
                        while barrier.exists() {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "bounded Root fixture barrier"
                            );
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    }
                }
                let data = hex::decode(request["data"].as_str().unwrap()).unwrap();
                json!({"signature":hex::encode(SigningKey::from_bytes(&secret).sign(&data).to_bytes())})
            }
            _ => json!({"ok":false}),
        };
        if response.get("ok").is_none() {
            response["ok"] = json!(true);
        }
        response["installation_id"] = json!(installation);
        emit_native_response(&response);
    }

    mod offline {
        include!("operator_offline/mod.rs");
    }
}
