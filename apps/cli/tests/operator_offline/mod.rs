// Included only below the cfg(test), Unix process fixture module.
use super::*;
use ea_admin::{
    native_provider::NativeOperatorProvider,
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig},
};
use ea_trust::TrustObjectSource as _;
use std::{
    process::{Child, ChildStdin, Output, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const ADMIN_NAME: &str = "Private Offline Fixture Admin";
const ADMIN_FUNCTION: &str = "Private Offline Fixture Authority";
const PHASE_LIMIT: Duration = Duration::from_secs(60);

struct Device {
    directory: support::TempDir,
    authority: bool,
    certificate: CertificateHash,
}
impl Device {
    fn new(authority: bool, certificate: CertificateHash) -> Self {
        let directory = support::temp_dir(if authority {
            "offline-authority"
        } else {
            "offline-target"
        });
        install_fixture_helper(directory.path());
        fs::write(
            directory.path().join(if authority {
                "authority-fixture"
            } else {
                "offline-target"
            }),
            b"",
        )
        .unwrap();
        let device = Self {
            directory,
            authority,
            certificate,
        };
        drop(device.database());
        device
    }
    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }
    fn database(&self) -> Arc<EncryptedDatabase> {
        let (provider, key) = database_provider_for(self.authority);
        Arc::new(EncryptedDatabase::open(&self.path("operator.sqlite"), &provider, &key).unwrap())
    }
    fn configure(
        &self,
        binding: ObjectHash,
        authority: &Device,
        admin_binding: ObjectHash,
        target: CertificateHash,
        exchange: &Path,
    ) {
        fs::write(self.path("public.json"), serde_json::to_vec(&json!({
            "archive_directory":"archive", "database_path":"operator.sqlite",
            "device_certificate_hash":hex::encode(self.certificate.as_bytes()),
            "binding_object_hash":hex::encode(binding.as_bytes()),
            "role":if self.authority {"organization-admin"} else {"writer"},
            "purpose":if self.authority {"admin-root-ceremony"} else {"finalize"},
            "admin_certificate_hash":hex::encode(authority.certificate.as_bytes()),
            "admin_binding_object_hash":hex::encode(admin_binding.as_bytes()),
            "ceremony_exchange_directory":exchange,
            "authority":self.authority,
            "target_certificate_hash":if self.authority {Some(hex::encode(target.as_bytes()))} else {None}
        })).unwrap()).unwrap();
    }
    fn set_binding(&self, binding: &str) {
        let mut config: Value =
            serde_json::from_slice(&fs::read(self.path("public.json")).unwrap()).unwrap();
        config["binding_object_hash"] = json!(binding);
        fs::write(
            self.path("public.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
    }
    fn arguments(&self, action: &str) -> Vec<String> {
        vec![
            "--trust-anchor".into(),
            self.path("independent-anchor.etb").to_str().unwrap().into(),
            "operator".into(),
            action.into(),
            "--operator-config".into(),
            self.path("public.json").to_str().unwrap().into(),
            "--format".into(),
            "json".into(),
        ]
    }
    fn command(&self, action: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "process_native::fixture_cli",
                "--nocapture",
            ])
            .env("EA_OPERATOR_FIXTURE_DIRECTORY", self.directory.path())
            .env(
                "EA_OPERATOR_FIXTURE_ARGS",
                serde_json::to_string(&self.arguments(action)).unwrap(),
            );
        command
    }
    fn runtime(&self) -> OperatorRuntime {
        let native =
            NativeOperatorProvider::open_test_fixture(self.path("ea-native-operator"), false)
                .unwrap();
        OperatorRuntime::open_with_test_native(
            OperatorRuntimeConfig::load(&self.path("public.json")).unwrap(),
            &self.path("independent-anchor.etb"),
            support::live_clock(),
            false,
            native,
        )
        .unwrap()
    }
    fn calls(&self) -> String {
        fs::read_to_string(self.path("helper-calls")).unwrap_or_default()
    }
    fn login(&self) -> Output {
        self.run_alone("verify-session")
    }
    fn run_alone(&self, action: &str) -> Output {
        let mut child = Target::spawn(self.command(action));
        let deadline = Instant::now() + PHASE_LIMIT;
        loop {
            if let Some(output) = child.poll() {
                return output;
            }
            assert!(
                Instant::now() < deadline,
                "bounded target {action} timed out"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

struct Ceremony {
    target: Device,
    authority: Device,
    exchange: support::TempDir,
}
impl Ceremony {
    fn new() -> Self {
        let mut fixture = support::live_clock_archive();
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
        assert!(
            fixture
                .fixture
                .blobs()
                .iter()
                .any(|(_, b)| ea_crypto::object_hash(b) == writer.object_hash)
        );
        let certificate = CertificateHash::from(writer.direct_object_hash.unwrap());
        let admin_certificate = line.second_bootstrap_admin_hash();
        let admin_subject = OperatorSubjectId::try_from([0x42; 16].as_slice()).unwrap();
        let admin_binding = line
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
                            admin_subject,
                            ADMIN_NAME,
                            ADMIN_FUNCTION,
                            &PROFILE_SALT,
                        ),
                    ),
                    binding_instance_key_thumbprint_override: Some(
                        public(ADMIN_INSTANCE_SECRET).thumbprint(),
                    ),
                    binding_os_account_hash_override: Some(native_account_hash_for(
                        true,
                        DeviceId::try_from([0x52; 16].as_slice()).unwrap(),
                    )),
                    ..HeadOptions::default()
                },
            )
            .direct_object_hash
            .unwrap();
        let source = line.source();
        source
            .visit_trust_object_hashes(&mut |hash| {
                let bytes = source.read_exact_trust_object(hash)?.unwrap().to_vec();
                if !fixture.fixture.blobs().iter().any(|(_, b)| b == &bytes) {
                    fixture
                        .fixture
                        .push_exact_bytes(&format!("{}.etb", hex::encode(hash.as_bytes())), bytes);
                }
                Ok(())
            })
            .unwrap();
        let target = Device::new(false, certificate);
        let authority = Device::new(true, CertificateHash::from(admin_certificate));
        for device in [&target, &authority] {
            support::materialize(&fixture.fixture, &device.path("archive"));
            fs::write(device.path("independent-anchor.etb"), &fixture.anchor_bytes).unwrap();
        }
        authority
            .database()
            .execute(
                "INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",
                &[
                    StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                    StoreValue::Blob(admin_subject.as_bytes().to_vec()),
                    StoreValue::Text(ADMIN_NAME.into()),
                    StoreValue::Text(ADMIN_FUNCTION.into()),
                    StoreValue::Blob(PROFILE_SALT.to_vec()),
                    StoreValue::Blob(admin_binding.as_bytes().to_vec()),
                ],
            )
            .unwrap();
        let exchange = support::temp_dir("offline-ciphertext-exchange");
        target.configure(
            ObjectHash::from(Hash32::ZERO),
            &authority,
            admin_binding,
            certificate,
            exchange.path(),
        );
        authority.configure(
            admin_binding,
            &authority,
            admin_binding,
            certificate,
            exchange.path(),
        );
        Self {
            target,
            authority,
            exchange,
        }
    }
    fn phase(&self, action: &str) -> (Output, Vec<Value>) {
        let mut authority = Authority::spawn(&self.authority);
        let mut target = Target::spawn(self.target.command(action));
        let deadline = Instant::now() + PHASE_LIMIT;
        let mut authority_exit = None;
        loop {
            authority.pump(true);
            if let Some(output) = target.poll() {
                return (output, authority.events.clone());
            }
            if authority.exited() {
                let exited = authority_exit.get_or_insert_with(Instant::now);
                assert!(
                    exited.elapsed() < Duration::from_secs(2),
                    "authority exited before target consumed its reply: {:?}",
                    authority.events
                );
            }
            assert!(
                Instant::now() < deadline,
                "bounded {action} timed out; public authority events: {:?}",
                authority.events
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn adopt_activation(&self, binding: &str) {
        self.target.set_binding(binding);
        for entry in fs::read_dir(self.target.path("archive")).unwrap() {
            let entry = entry.unwrap();
            let destination = self.authority.path("archive").join(entry.file_name());
            if !destination.exists() {
                fs::copy(entry.path(), destination).unwrap();
            }
        }
        // Retain completed requests/replies across head changes. The actual
        // authority must distinguish durable replies from new stale requests.
    }
    fn replay_committed_reply_after_authority_restart(&self) {
        let replies: Vec<_> = fs::read_dir(self.exchange.path())
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| entry.file_name().to_str().unwrap().starts_with("reply-"))
            .map(|entry| (entry.path(), fs::read(entry.path()).unwrap()))
            .collect();
        assert!(!replies.is_empty());
        let audit_before = audit_bytes(&self.authority);
        let root_before = self
            .authority
            .calls()
            .lines()
            .filter(|line| *line == "sign root-signing")
            .count();
        for (path, _) in &replies {
            fs::remove_file(path).unwrap();
        }
        {
            let mut authority = Authority::spawn(&self.authority);
            let deadline = Instant::now() + PHASE_LIMIT;
            loop {
                authority.pump(false);
                assert!(
                    !authority
                        .events
                        .iter()
                        .any(|event| event.get("prompt").is_some())
                );
                if replies.iter().all(|(path, _)| path.exists()) {
                    break;
                }
                assert!(
                    !authority.exited(),
                    "cached reply restart failed: {:?}",
                    authority.events
                );
                assert!(
                    Instant::now() < deadline,
                    "cached reply publication timeout"
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
        for (path, bytes) in replies {
            assert!(
                fs::read(path).unwrap() == bytes,
                "replayed encrypted reply must be byte-identical"
            );
        }
        assert!(
            audit_bytes(&self.authority) == audit_before,
            "reply replay must not repeat a ceremony audit"
        );
        assert_eq!(
            self.authority
                .calls()
                .lines()
                .filter(|line| *line == "sign root-signing")
                .count(),
            root_before
        );
    }
    fn assert_private_files(&self, output: &Output) {
        let target_salt = self
            .target
            .database()
            .query_row("SELECT profile_commitment_salt FROM operator_profile", &[])
            .unwrap()
            .map(|row| row.blob(0).unwrap().to_vec());
        let mut secrets: Vec<Vec<u8>> = [
            TEST_NAME,
            TEST_FUNCTION,
            ADMIN_NAME,
            ADMIN_FUNCTION,
            TEST_GUID,
            "ffeeddcc-bbaa-9988-7766-554433221100",
        ]
        .map(|s| s.as_bytes().to_vec())
        .to_vec();
        secrets.push(PROFILE_SALT.to_vec());
        secrets.extend(target_salt);
        secrets.extend(
            [
                trust_support::device_signing_secret(),
                trust_support::second_admin_signing_secret(),
                trust_support::root_signing_secret(),
                ADMIN_INSTANCE_SECRET,
            ]
            .map(|key| key.to_vec()),
        );
        let generation = fs::read_to_string(self.target.path("instance-generation"))
            .ok()
            .and_then(|value| value.parse::<u8>().ok())
            .unwrap_or(0);
        for instance in 0..=generation {
            secrets.push(vec![0x47 + instance; 32]);
        }
        let database = self.target.database();
        let pending = database
            .query_row("SELECT count(*) FROM operator_pending_exchange", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap();
        assert!((0..128).contains(&pending), "bounded pending exchange keys");
        for offset in 0..pending {
            let row = database
                .query_row(
                    "SELECT reply_private_key FROM operator_pending_exchange ORDER BY rowid LIMIT 1 OFFSET ?1",
                    &[StoreValue::Integer(offset)],
                )
                .unwrap()
                .unwrap();
            secrets.push(row.blob(0).unwrap().to_vec());
        }
        let needles: Vec<_> = secrets
            .iter()
            .flat_map(|value| [value.clone(), hex::encode(value).into_bytes()])
            .collect();
        let check = |bytes: &[u8]| {
            for needle in &needles {
                assert!(
                    !bytes.windows(needle.len()).any(|window| window == needle),
                    "private data appeared outside SQLCipher/HPKE"
                );
            }
        };
        check(&output.stdout);
        check(&output.stderr);
        let mut paths = vec![
            self.target.directory.path().to_path_buf(),
            self.authority.directory.path().to_path_buf(),
            self.exchange.path().to_path_buf(),
        ];
        let mut files = 0;
        while let Some(path) = paths.pop() {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    paths.push(entry.path());
                } else {
                    files += 1;
                    assert!(files < 1024, "bounded fixture inventory");
                    check(&fs::read(entry.path()).unwrap());
                }
            }
        }
        // Separate stores must actually require different native database keys.
        let (wrong_provider, wrong_key) = database_provider_for(false);
        assert!(
            EncryptedDatabase::open_existing(
                &self.authority.path("operator.sqlite"),
                &wrong_provider,
                &wrong_key
            )
            .is_err()
        );
    }
    fn reject_changed_request_after_restart(&self) {
        let entry = fs::read_dir(self.exchange.path())
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| entry.file_name().to_str().unwrap().starts_with("request-"))
            .unwrap();
        let mut envelope: Value = serde_json::from_slice(&fs::read(entry.path()).unwrap()).unwrap();
        let mut signature = hex::decode(envelope["signature"].as_str().unwrap()).unwrap();
        signature[0] ^= 1;
        envelope["signature"] = json!(hex::encode(signature));
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let id = hex::encode(ea_crypto::object_hash(&bytes).as_bytes());
        let path = self.exchange.path().join(format!("request-{id}.json"));
        fs::write(&path, bytes).unwrap();
        let audits = audit_bytes(&self.authority);
        let root_count = self
            .authority
            .calls()
            .lines()
            .filter(|line| *line == "sign root-signing")
            .count();
        {
            let mut authority = Authority::spawn(&self.authority);
            let deadline = Instant::now() + PHASE_LIMIT;
            loop {
                authority.pump(false);
                assert!(
                    !authority
                        .events
                        .iter()
                        .any(|event| event.get("prompt").is_some())
                );
                if authority.exited() {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "invalid replay must terminate without authorization"
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
        assert!(
            !self
                .exchange
                .path()
                .join(format!("reply-{id}.json"))
                .exists()
        );
        assert!(
            audit_bytes(&self.authority) == audits,
            "unauthenticated replay cannot produce successful audits"
        );
        assert_eq!(
            self.authority
                .calls()
                .lines()
                .filter(|line| *line == "sign root-signing")
                .count(),
            root_count
        );
        fs::remove_file(path).unwrap();
    }
}

fn audit_bytes(device: &Device) -> Vec<Vec<u8>> {
    let database = device.database();
    let count = database
        .query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    assert!((0..1024).contains(&count));
    (0..count).map(|offset|database.query_row("SELECT exact_bytes FROM local_audit_event ORDER BY insertion_sequence LIMIT 1 OFFSET ?1",&[StoreValue::Integer(offset)]).unwrap().unwrap().blob(0).unwrap().to_vec()).collect()
}

fn verify_audits(device: &Device) -> usize {
    let runtime = device.runtime();
    let mut writer_logins = 0;
    let mut admin_signed = 0;
    for exact in audit_bytes(device) {
        let event = ea_format::decode_local_audit_event(&exact).unwrap();
        let certificate = CertificateHash::from(event.signer_certificate_object_hash());
        let fields = runtime
            .head()
            .active_certificate_fields(certificate)
            .unwrap();
        let role = match fields.certificate_kind {
            CertificateKindV1::Writer => SignerRole::Writer,
            CertificateKindV1::OrganizationAdmin => {
                admin_signed += 1;
                SignerRole::OrganizationAdmin
            }
            _ => panic!("unexpected ceremony audit signer role"),
        };
        assert!(event.device_id() == fields.device_id);
        let mut decoder = minicbor::Decoder::new(&exact);
        assert_eq!(decoder.array().unwrap(), Some(2));
        decoder.skip().unwrap();
        let start = decoder.position();
        decoder.skip().unwrap();
        let context = VerificationContext::local_audit(
            event.exact_core(),
            runtime.next_sequence(),
            role,
            runtime.head().registry_version(),
        )
        .unwrap();
        ea_crypto::verify_cose_sign1(&exact[start..decoder.position()], runtime.head(), &context)
            .unwrap();
        if certificate == device.certificate
            && !device.authority
            && matches!(event.action(), LocalAuditActionV1::Login(_))
            && event.outcome() == LocalAuditOutcomeV1::Completed
        {
            writer_logins += 1;
        }
    }
    assert!(
        admin_signed > 0,
        "actual authority-signed audits must be present"
    );
    writer_logins
}

fn profile_secret_state(device: &Device) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let row=device.database().query_row("SELECT operator_subject_id,profile_commitment_salt,operator_binding_object_hash FROM operator_profile",&[]).unwrap().unwrap();
    (
        row.blob(0).unwrap().to_vec(),
        row.blob(1).unwrap().to_vec(),
        row.blob(2).unwrap().to_vec(),
    )
}

struct Target {
    child: Child,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
}
impl Target {
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        fn read(pipe: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
            thread::spawn(move || {
                let mut bytes = Vec::new();
                pipe.take(1_048_576).read_to_end(&mut bytes).unwrap();
                bytes
            })
        }
        let stdout = read(child.stdout.take().unwrap());
        let stderr = read(child.stderr.take().unwrap());
        Self {
            child,
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }
    fn poll(&mut self) -> Option<Output> {
        let status = self.child.try_wait().unwrap()?;
        let mut stdout = self.stdout.take().unwrap().join().unwrap();
        let stderr = self.stderr.take().unwrap().join().unwrap();
        let marker = b"EA_CLI_FIXTURE_OUTPUT\n";
        if let Some(start) = stdout.windows(marker.len()).position(|b| b == marker) {
            stdout.drain(..start + marker.len());
        }
        Some(Output {
            status,
            stdout,
            stderr,
        })
    }
    fn suspend(&mut self) {
        let pid = self.child.id().to_string();
        assert!(
            Command::new("/bin/kill")
                .args(["-STOP", &pid])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = Command::new("/bin/ps")
                .args(["-o", "state=", "-p", &pid])
                .output()
                .unwrap();
            assert!(
                status.status.success(),
                "owned target must remain alive before reply delivery"
            );
            if status.stdout.contains(&b'T') {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "owned target must stop before Root is released"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Authority {
    child: Child,
    input: Option<ChildStdin>,
    receiver: mpsc::Receiver<Value>,
    events: Vec<Value>,
}
impl Authority {
    fn spawn(device: &Device) -> Self {
        let mut command = Command::new("/usr/bin/python3");
        command
            .args([
                "-u",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/operator_offline/pty_driver.py"
                ),
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "process_native::fixture_cli",
                "--nocapture",
            ])
            .env("EA_OPERATOR_FIXTURE_DIRECTORY", device.directory.path())
            .env(
                "EA_OPERATOR_FIXTURE_ARGS",
                serde_json::to_string(&device.arguments("provision")).unwrap(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let event = serde_json::from_str(&line)
                    .unwrap_or_else(|_| json!({"driver_error":"invalid-frame"}));
                if sender.send(event).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            receiver,
            events: Vec::new(),
        }
    }
    fn send(&mut self, value: Value) {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, &value).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }
    fn pump(&mut self, answer: bool) {
        self.pump_until(if answer { 4 } else { 0 });
    }
    fn pump_until(&mut self, answers: u64) {
        while let Ok(event) = self.receiver.try_recv() {
            assert!(
                event.get("private_echo").is_none(),
                "private PTY input was echoed"
            );
            assert!(
                event.get("driver_error").is_none() && event.get("driver_timeout").is_none(),
                "PTY driver failed without logging private terminal bytes"
            );
            if let Some(index) = event["prompt"].as_u64() {
                assert_eq!(event["echo_disabled"], true);
                if index < answers {
                    let subject = hex::encode([0x71; 16]);
                    let answers = [
                        "extern-geprueft",
                        subject.as_str(),
                        TEST_NAME,
                        TEST_FUNCTION,
                    ];
                    self.send(json!({"line":answers[index as usize],"private":index>=2}));
                }
            }
            self.events.push(event);
        }
    }
    fn exited(&mut self) -> bool {
        self.child.try_wait().unwrap().is_some()
    }
}

#[test]
fn published_binding_recovers_in_a_new_process_with_authority_offline() {
    let ceremony = Ceremony::new();
    let database = ceremony.target.database();
    database.execute("CREATE TRIGGER stop_before_active BEFORE UPDATE ON operator_binding_journal WHEN NEW.state=5 BEGIN SELECT RAISE(ABORT,'fixture completion write failure'); END", &[]).unwrap();
    let (interrupted, _) = ceremony.phase("provision");
    assert!(!interrupted.status.success());
    assert!(interrupted.stdout.is_empty());
    let journal = database
        .query_row(
            "SELECT state,binding_hash FROM operator_binding_journal",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        journal.integer(0).unwrap(),
        4,
        "production publication reached Published before the failed completion write"
    );
    let hash = ObjectHash::try_from(journal.blob(1).unwrap()).unwrap();
    let runtime = ceremony.target.runtime();
    assert!(
        runtime
            .head()
            .active_operator_binding_fields(hash)
            .is_some(),
        "independent full archive verification must establish actual activation"
    );
    let before_head = runtime.head().registry_head_hash();
    drop(runtime);
    let generation = fs::read(ceremony.target.path("instance-generation")).unwrap();
    let root_calls = ceremony.authority.calls();
    let target_calls = ceremony
        .target
        .calls()
        .lines()
        .filter(|line| *line == "sign operator-instance")
        .count();
    let requests = fs::read_dir(ceremony.exchange.path()).unwrap().count();
    database
        .execute("DROP TRIGGER stop_before_active", &[])
        .unwrap();
    drop(database);
    // No authority process is running and the public config still has zero binding.
    let resumed = ceremony.target.run_alone("provision");
    let report = success(&resumed);
    assert_eq!(
        report["productive_binding_hashes"],
        json!([hex::encode(hash.as_bytes())])
    );
    assert_eq!(
        ceremony
            .target
            .database()
            .query_row("SELECT state FROM operator_binding_journal", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        5
    );
    assert!(fs::read(ceremony.target.path("instance-generation")).unwrap() == generation);
    assert!(
        ceremony.authority.calls() == root_calls,
        "offline completion must not contact authority"
    );
    assert_eq!(
        fs::read_dir(ceremony.exchange.path()).unwrap().count(),
        requests
    );
    assert!(
        ceremony
            .target
            .calls()
            .lines()
            .filter(|line| *line == "sign operator-instance")
            .count()
            > target_calls,
        "completion obtains a fresh native session"
    );
    let runtime = ceremony.target.runtime();
    assert!(runtime.head().registry_head_hash() == before_head);
    drop(runtime);
    ceremony.assert_private_files(&resumed);
    verify_audits(&ceremony.target);
}

#[test]
fn pending_exchange_survives_target_process_crash_before_authority_delivery() {
    let ceremony = Ceremony::new();
    let mut target = Target::spawn(ceremony.target.command("provision"));
    let deadline = Instant::now() + PHASE_LIMIT;
    let request = loop {
        let entries: Vec<_> = fs::read_dir(ceremony.exchange.path())
            .unwrap()
            .map(Result::unwrap)
            .collect();
        if let Some(entry) = entries
            .into_iter()
            .find(|entry| entry.file_name().to_str().unwrap().starts_with("request-"))
        {
            break (entry.path(), fs::read(entry.path()).unwrap());
        }
        assert!(
            target.poll().is_none(),
            "target exited before persisting its request"
        );
        assert!(Instant::now() < deadline, "request publication timed out");
        thread::sleep(Duration::from_millis(20));
    };
    let row = ceremony
        .target
        .database()
        .query_row(
            "SELECT request_bytes,reply_private_key FROM operator_pending_exchange",
            &[],
        )
        .unwrap()
        .unwrap();
    let private = row.blob(1).unwrap().to_vec();
    assert!(row.blob(0).unwrap() == request.1);
    drop(target); // Actual process termination; no synthetic journal assignment.
    let reopened = ceremony
        .target
        .database()
        .query_row(
            "SELECT request_bytes,reply_private_key FROM operator_pending_exchange",
            &[],
        )
        .unwrap()
        .unwrap();
    assert!(reopened.blob(0).unwrap() == request.1);
    assert!(reopened.blob(1).unwrap() == private);
    let (resumed, _) = ceremony.phase("provision");
    success(&resumed);
    assert!(
        fs::read(request.0).unwrap() == request.1,
        "resume retains exact signed request/nonce"
    );
    assert_eq!(
        ceremony
            .target
            .calls()
            .lines()
            .filter(|line| *line == "generate operator-instance")
            .count(),
        1
    );
    ceremony.assert_private_files(&resumed);
    verify_audits(&ceremony.target);
}

#[test]
fn target_watch_abort_during_real_private_identity_prompt_prevents_publication() {
    let ceremony = Ceremony::new();
    let initial_objects = fs::read_dir(ceremony.target.path("archive"))
        .unwrap()
        .count();
    let mut authority = Authority::spawn(&ceremony.authority);
    let mut target = Target::spawn(ceremony.target.command("provision"));
    let deadline = Instant::now() + PHASE_LIMIT;
    loop {
        authority.pump_until(2);
        if authority.events.iter().any(|event| event["prompt"] == 2) {
            break;
        }
        assert!(
            !authority.exited(),
            "authority did not reach private name prompt: {:?}",
            authority.events
        );
        assert!(
            target.poll().is_none(),
            "target failed before watch-abort point"
        );
        assert!(Instant::now() < deadline, "private prompt deadline");
        thread::sleep(Duration::from_millis(20));
    }
    fs::write(ceremony.target.path("watch-action"), "watch-event").unwrap();
    while !ceremony.target.path("watch-delivered").exists() {
        assert!(Instant::now() < deadline, "watch event delivery deadline");
        thread::sleep(Duration::from_millis(10));
    }
    authority.send(json!({"line":TEST_NAME,"private":true}));
    let failed = loop {
        authority.pump(true);
        if let Some(output) = target.poll() {
            break output;
        }
        assert!(
            Instant::now() < deadline,
            "watch abort must finish without success"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert_eq!(
        fs::read_dir(ceremony.target.path("archive"))
            .unwrap()
            .count(),
        initial_objects
    );
    assert!(!ceremony.authority.calls().contains("sign root-signing"));
    assert_eq!(
        ceremony
            .target
            .database()
            .query_row("SELECT count(*) FROM operator_binding_journal", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    for bytes in audit_bytes(&ceremony.target) {
        let event = ea_format::decode_local_audit_event(&bytes).unwrap();
        assert!(
            !(event.signer_certificate_object_hash().as_bytes()
                == ceremony.target.certificate.as_bytes()
                && matches!(event.action(), LocalAuditActionV1::Login(_))
                && event.outcome() == LocalAuditOutcomeV1::Completed)
        );
    }
    ceremony.assert_private_files(&failed);
}

#[derive(PartialEq)]
struct PendingRevocation {
    operation_hash: Vec<u8>,
    request_bytes: Vec<u8>,
    reply_private_key: Vec<u8>,
    issued_at: UnixMillis,
}
impl PendingRevocation {
    fn request_hash(&self) -> ObjectHash {
        ea_crypto::object_hash(&self.request_bytes)
    }
}

fn pending_revocations(device: &Device, binding: ObjectHash) -> Vec<PendingRevocation> {
    let database = device.database();
    let count = database
        .query_row("SELECT count(*) FROM operator_pending_exchange", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    assert!(
        (0..128).contains(&count),
        "bounded revocation outbox inventory"
    );
    let mut pending = Vec::new();
    for offset in 0..count {
        let row = database.query_row(
            "SELECT operation_hash,request_bytes,reply_private_key FROM operator_pending_exchange ORDER BY rowid LIMIT 1 OFFSET ?1",
            &[StoreValue::Integer(offset)],
        ).unwrap().unwrap();
        let request = ea_admin::operator_exchange::VerifiedExchangeRequest::verify(
            row.blob(1).unwrap(),
            &public(trust_support::device_signing_secret()),
        )
        .unwrap();
        if request.payload()["op"] != "authorize-target" {
            continue;
        }
        let bytes = hex::decode(
            request.payload()["args"]["target_payload"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let payload = ea_format::TrustPayloadV1::from_exact_digest_input(&bytes).unwrap();
        let ea_format::DecodedTrustPayloadV1::RegistryEvent(event) =
            payload.decoded_payload().unwrap()
        else {
            continue;
        };
        if event.fields().change
            != (ea_format::RegistryChangeV1::Target {
                target_kind: 1,
                object_hash: binding,
            })
        {
            continue;
        }
        pending.push(PendingRevocation {
            operation_hash: row.blob(0).unwrap().to_vec(),
            request_bytes: row.blob(1).unwrap().to_vec(),
            reply_private_key: row.blob(2).unwrap().to_vec(),
            issued_at: event.fields().issued_at,
        });
    }
    pending
}

fn root_signatures(device: &Device) -> usize {
    device
        .calls()
        .lines()
        .filter(|line| *line == "sign root-signing")
        .count()
}

fn replay_state(device: &Device) -> Vec<(i64, Vec<u8>)> {
    let database = device.database();
    let count = database
        .query_row("SELECT count(*) FROM operator_admin_replay", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    assert!((0..128).contains(&count), "bounded replay snapshot");
    (0..count).map(|offset| {
        let row = database.query_row(
            "SELECT dimension,replay_value FROM operator_admin_replay ORDER BY organization_id,dimension,replay_value LIMIT 1 OFFSET ?1",
            &[StoreValue::Integer(offset)],
        ).unwrap().unwrap();
        (row.integer(0).unwrap(), row.blob(1).unwrap().to_vec())
    }).collect()
}

fn root_and_revocation_audits(device: &Device) -> Vec<Vec<u8>> {
    audit_bytes(device)
        .into_iter()
        .filter(|bytes| {
            matches!(
                ea_format::decode_local_audit_event(bytes).unwrap().action(),
                LocalAuditActionV1::AdminRootCeremony(_) | LocalAuditActionV1::Revocation(_)
            )
        })
        .collect()
}

#[test]
fn revocation_committed_reply_loss_resumes_original_intent_at_later_time_on_same_media() {
    revocation_reply_recovery(false);
}

#[test]
fn revocation_target_journal_abort_rolls_back_replays_and_audits_then_resumes_exact_bytes() {
    revocation_reply_recovery(true);
}

fn revocation_reply_recovery(abort_final_journal: bool) {
    let ceremony = Ceremony::new();
    let (provision, _) = ceremony.phase("provision");
    let report = success(&provision);
    let binding_text = report["productive_binding_hashes"][0].as_str().unwrap();
    let binding = ObjectHash::try_from(hex::decode(binding_text).unwrap().as_slice()).unwrap();
    let retained_media: Vec<_> = fs::read_dir(ceremony.exchange.path())
        .unwrap()
        .map(Result::unwrap)
        .map(|entry| (entry.path(), fs::read(entry.path()).unwrap()))
        .collect();
    assert!(!retained_media.is_empty());
    ceremony.adopt_activation(binding_text);
    let original_context = ceremony.target.runtime();
    let head = original_context.head().registry_head_hash();
    let sequence = original_context.next_sequence();
    drop(original_context);
    let roots_before = root_signatures(&ceremony.authority);

    fs::write(ceremony.authority.path("hold-root-signature"), b"").unwrap();
    let mut authority = Authority::spawn(&ceremony.authority);
    let mut target = Target::spawn(ceremony.target.command("revoke"));
    let deadline = Instant::now() + PHASE_LIMIT;
    while !ceremony.authority.path("root-signature-paused").exists() {
        authority.pump(false);
        assert!(
            !authority.exited(),
            "authority must reach the Root fixture barrier on retained media"
        );
        assert!(
            target.poll().is_none(),
            "target must await its first revocation reply"
        );
        assert!(Instant::now() < deadline, "bounded revocation Root barrier");
        thread::sleep(Duration::from_millis(10));
    }
    target.suspend();
    let mut requests = pending_revocations(&ceremony.target, binding);
    assert!(
        requests.len() == 1,
        "one original typed revocation request before response delivery"
    );
    let original = requests.pop().unwrap();
    let request_hash = original.request_hash();
    let reply_path = ceremony.exchange.path().join(format!(
        "reply-{}.json",
        hex::encode(request_hash.as_bytes())
    ));
    assert!(
        !reply_path.exists(),
        "target was stopped before its completed reply existed"
    );
    fs::remove_file(ceremony.authority.path("hold-root-signature")).unwrap();

    let (reply, authorization, registry) = loop {
        authority.pump(false);
        let database = ceremony.authority.database();
        let completed = database.query_row(
            "SELECT request_bytes,reply_bytes FROM operator_authority_request WHERE request_hash=?1 AND state=1",
            &[StoreValue::Blob(request_hash.as_bytes().to_vec())],
        ).unwrap();
        if let Some(row) = completed
            && reply_path.exists()
        {
            assert!(
                row.blob(0).unwrap() == original.request_bytes,
                "authority committed the exact original request"
            );
            let reply = row.blob(1).unwrap().to_vec();
            assert!(
                fs::read(&reply_path).unwrap() == reply,
                "published reply equals the committed ciphertext"
            );
            let signed = database.query_row(
                "SELECT authorization,target FROM operator_authority_target WHERE request_hash=?1 AND action_code=1",
                &[StoreValue::Blob(request_hash.as_bytes().to_vec())],
            ).unwrap().expect("committed typed revocation objects");
            break (
                reply,
                signed.blob(0).unwrap().to_vec(),
                signed.blob(1).unwrap().to_vec(),
            );
        }
        assert!(
            !authority.exited(),
            "authority must commit its original Root-signed reply"
        );
        assert!(
            Instant::now() < deadline,
            "bounded committed revocation reply"
        );
        thread::sleep(Duration::from_millis(10));
    };
    drop(authority);
    fs::rename(
        &reply_path,
        ceremony
            .exchange
            .path()
            .join("withheld-committed-reply.json"),
    )
    .unwrap();
    drop(target); // Kill the stopped target after the real authority commit, before any read.
    assert!(
        root_signatures(&ceremony.authority) == roots_before + 1,
        "exactly one authority Root signing before restart"
    );
    assert!(
        pending_revocations(&ceremony.target, binding) == [original],
        "original request/hash/reply key survived the actual target kill"
    );
    let original = pending_revocations(&ceremony.target, binding)
        .pop()
        .unwrap();
    let reopened = ceremony.target.runtime();
    assert!(
        reopened.head().registry_head_hash() == head,
        "restart retains the same verified head"
    );
    assert!(
        reopened.next_sequence() == sequence,
        "restart retains the same verified sequence"
    );
    assert!(
        reopened.head().preexisting_effective_now().value() > original.issued_at,
        "restart must use a later actual wall clock"
    );
    assert!(
        reopened
            .head()
            .active_operator_binding_fields(binding)
            .is_some(),
        "no revocation publication before consuming the reply"
    );
    drop(reopened);

    let replays_before = replay_state(&ceremony.target);
    let audits_before = root_and_revocation_audits(&ceremony.target);
    if abort_final_journal {
        let database = ceremony.target.database();
        database.execute("CREATE TRIGGER stop_revocation_commit BEFORE INSERT ON operator_revocation_journal BEGIN SELECT RAISE(ABORT,'fixture final revocation write failure'); END", &[]).unwrap();
        let (failed, _) = ceremony.phase("revoke");
        assert!(
            !failed.status.success() && failed.stdout.is_empty(),
            "injected final-pair write failure must prevent success"
        );
        assert!(
            replay_state(&ceremony.target) == replays_before,
            "failed target commit must not consume either replay dimension"
        );
        assert!(
            root_and_revocation_audits(&ceremony.target) == audits_before,
            "failed target commit must not append Root or Revocation audit rows"
        );
        assert!(
            database
                .query_row(
                    "SELECT binding_hash FROM operator_revocation_journal WHERE binding_hash=?1",
                    &[StoreValue::Blob(binding.as_bytes().to_vec())]
                )
                .unwrap()
                .is_none(),
            "failed target commit must not persist its final pair"
        );
        let staged = database.query_row("SELECT authorization,root_signature FROM operator_revocation_intent WHERE binding_hash=?1", &[StoreValue::Blob(binding.as_bytes().to_vec())]).unwrap().unwrap();
        let ea_format::ParsedArchiveObject::Trust(object) =
            ea_format::decode_exact_object(&registry).unwrap()
        else {
            panic!("actual signed registry");
        };
        assert!(
            staged.blob(0).unwrap() == authorization,
            "original authorization remains staged through failed commit"
        );
        assert!(
            object.value().signatures().len() == 1
                && staged.blob(1).unwrap() == object.value().signatures()[0],
            "original Root signature remains staged through failed commit"
        );
        assert!(
            pending_revocations(&ceremony.target, binding).as_slice()
                == std::slice::from_ref(&original),
            "failed commit preserves original outbox bytes and reply key"
        );
        let unchanged = ceremony.target.runtime();
        assert!(
            unchanged.head().registry_head_hash() == head
                && unchanged
                    .head()
                    .active_operator_binding_fields(binding)
                    .is_some(),
            "full archive verification stays on the active head after failed commit"
        );
        drop(unchanged);
        ceremony.assert_private_files(&failed);
        database
            .execute("DROP TRIGGER stop_revocation_commit", &[])
            .unwrap();
    }

    let (resumed, events) = ceremony.phase("revoke");
    let revoked = success(&resumed);
    assert!(!events.iter().any(|event| event.get("prompt").is_some()));
    assert_eq!(revoked["binding_state"], "revoked");
    let new_replays: Vec<_> = replay_state(&ceremony.target)
        .into_iter()
        .filter(|key| !replays_before.contains(key))
        .collect();
    assert!(
        new_replays.len() == 2
            && new_replays.iter().any(|key| key.0 == 0)
            && new_replays.iter().any(|key| key.0 == 1),
        "successful target commit consumes exactly both original replay dimensions"
    );
    assert!(
        root_and_revocation_audits(&ceremony.target).len() == audits_before.len() + 2,
        "successful target commit appends exactly the Root and Revocation audit pair"
    );
    assert!(
        pending_revocations(&ceremony.target, binding) == [original],
        "later-time restart must reuse the original request/hash/reply key"
    );
    assert!(
        root_signatures(&ceremony.authority) == roots_before + 1,
        "reply loss must not request another authority Root signature"
    );
    assert!(
        fs::read(reply_path).unwrap() == reply,
        "authority restart replays the original encrypted reply"
    );
    let journal = ceremony
        .target
        .database()
        .query_row(
            "SELECT authorization,registry FROM operator_revocation_journal WHERE binding_hash=?1",
            &[StoreValue::Blob(binding.as_bytes().to_vec())],
        )
        .unwrap()
        .unwrap();
    assert!(
        journal.blob(0).unwrap() == authorization && journal.blob(1).unwrap() == registry,
        "target commits the original authority-signed revocation bytes"
    );
    let current = ceremony.target.runtime();
    assert!(
        current.head().registry_head_hash().as_bytes()
            == ea_crypto::object_hash(&registry).as_bytes(),
        "full archive verification selects the original signed revocation"
    );
    assert!(
        current
            .head()
            .revoked_operator_binding_fields(binding)
            .is_some()
    );
    drop(current);
    assert!(
        ceremony.target.login().status.code() == Some(12),
        "revoked login must fail after another process restart"
    );
    for (path, bytes) in retained_media {
        assert!(
            fs::read(path).unwrap() == bytes,
            "completed earlier-head exchange media is retained unchanged"
        );
    }
    verify_audits(&ceremony.target);
    verify_audits(&ceremony.authority);
    ceremony.assert_private_files(&resumed);
}

impl Drop for Authority {
    fn drop(&mut self) {
        if let Some(mut input) = self.input.take() {
            let _ = input.write_all(b"{\"stop\":true}\n");
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[track_caller]
fn success(output: &Output) -> Value {
    let codes: Vec<_> = String::from_utf8_lossy(&output.stderr)
        .split_whitespace()
        .filter(|word| word.starts_with("EA-"))
        .map(str::to_owned)
        .collect();
    assert_eq!(
        output.status.code(),
        Some(0),
        "public target error codes: {codes:?}"
    );
    serde_json::from_slice(&output.stdout).expect("public JSON report")
}

#[test]
fn actual_two_device_pty_provision_verify_replay_revoke_and_replacement() {
    let ceremony = Ceremony::new();
    let (provision, events) = ceremony.phase("provision");
    let report = success(&provision);
    assert_eq!(
        events.iter().filter(|e| e.get("prompt").is_some()).count(),
        4
    );
    assert_eq!(report["binding_state"], "active");
    assert_eq!(report["current_native_account_match"], true);
    let binding = report["productive_binding_hashes"][0].as_str().unwrap();
    ceremony.target.set_binding(binding);
    let logins = verify_audits(&ceremony.target);
    assert!(logins > 0);
    verify_audits(&ceremony.authority);
    ceremony.assert_private_files(&provision);
    ceremony.replay_committed_reply_after_authority_restart();
    ceremony.reject_changed_request_after_restart();
    assert_eq!(
        success(&ceremony.target.login())["productive_binding_hashes"],
        report["productive_binding_hashes"]
    );
    assert_eq!(verify_audits(&ceremony.target), logins + 1);
    let (subject, salt, old_binding) = profile_secret_state(&ceremony.target);
    let old_instance = fs::read(ceremony.target.path("instance-generation")).unwrap();
    ceremony.adopt_activation(binding);
    let (revoke, events) = ceremony.phase("revoke");
    assert!(!events.iter().any(|event| event.get("prompt").is_some()));
    let report = success(&revoke);
    assert_eq!(report["binding_state"], "revoked");
    assert_eq!(report["productive_binding_hashes"], json!([]));
    assert_eq!(report["revoked_binding_hashes"], json!([binding]));
    assert_eq!(ceremony.target.login().status.code(), Some(12));
    ceremony.assert_private_files(&revoke);
    ceremony.adopt_activation(binding);
    let (replacement, events) = ceremony.phase("provision");
    let replacement_report = success(&replacement);
    assert_eq!(
        events.iter().filter(|e| e.get("prompt").is_some()).count(),
        4
    );
    let next_binding = replacement_report["productive_binding_hashes"][0]
        .as_str()
        .unwrap();
    assert_ne!(next_binding, binding);
    ceremony.target.set_binding(next_binding);
    assert_eq!(success(&ceremony.target.login())["binding_state"], "active");
    let (new_subject, new_salt, new_binding) = profile_secret_state(&ceremony.target);
    assert!(
        subject == new_subject,
        "replacement retains the externally verified subject"
    );
    assert!(salt != new_salt, "replacement needs a fresh profile salt");
    assert!(old_binding != new_binding);
    assert!(
        fs::read(ceremony.target.path("instance-generation")).unwrap() != old_instance,
        "replacement needs a fresh native instance key"
    );
    let runtime = ceremony.target.runtime();
    let revoked = ObjectHash::try_from(old_binding.as_slice()).unwrap();
    assert!(
        runtime
            .head()
            .revoked_operator_binding_fields(revoked)
            .is_some()
    );
    assert!(
        runtime
            .head()
            .active_operator_binding_fields(revoked)
            .is_none()
    );
    assert!(
        runtime
            .head()
            .active_operator_binding_fields(ObjectHash::try_from(new_binding.as_slice()).unwrap())
            .is_some()
    );
    drop(runtime);
    verify_audits(&ceremony.target);
    verify_audits(&ceremony.authority);
    ceremony.assert_private_files(&replacement);
    assert!(!ceremony.target.calls().contains("admin-signing"));
    assert!(!ceremony.target.calls().contains("root-signing"));
    assert!(ceremony.authority.calls().contains("sign root-signing"));
    assert!(!ceremony.authority.calls().contains("writer-signing"));
}
