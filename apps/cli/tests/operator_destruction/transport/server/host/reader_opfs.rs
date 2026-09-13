//! One native job, actual populated product Worker OPFS, exact ETB return,
//! native verification and authenticated TLS completion. No test-created claim.
use super::*;
use ea_desktop::commands::destruction::{
    destruction_authenticate_custodian_core, destruction_export_reader_delivery_core,
    destruction_import_progress_core,
};
use ea_reader::{
    AuthenticatorPrfV1, InMemoryReaderBlobStore, ReaderBlobStore, ReaderObjectCache, ReaderVault,
    VaultContentsV1,
};
use std::io::{BufRead, Write};
use std::process::{Child, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

struct BrowserHarness {
    child: Child,
    lines: Receiver<String>,
}
impl BrowserHarness {
    fn start(private: &Path) -> Self {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(private, fs::Permissions::from_mode(0o700)).unwrap();
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let script =
            manifest.join("tests/operator_destruction/transport/server/host/reader_opfs.mjs");
        let mut child = Command::new("node")
            .arg(script)
            .arg(manifest.join("../web"))
            .arg(private)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("installed Node/browser runtime");
        let stdout = child.stdout.take().unwrap();
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if send.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let harness = Self { child, lines };
        assert_eq!(
            harness.lines.recv_timeout(Duration::from_secs(90)).unwrap(),
            "READY",
            "actual product Worker and browser are ready before native actions"
        );
        harness
    }
    fn execute(&mut self, input: &Path) {
        writeln!(self.child.stdin.take().unwrap(), "{}", input.display()).unwrap();
        assert_eq!(
            self.lines.recv_timeout(Duration::from_secs(180)).unwrap(),
            "COMPLETE",
            "bounded actual OPFS lifecycle including browser/Vault reopen"
        );
        assert!(self.child.wait().unwrap().success());
    }
}
impl Drop for BrowserHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn denominator(view: &serde_json::Value) -> Vec<serde_json::Value> {
    view["process"]["replicas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| serde_json::json!([r["deviceId"], r["kindCode"]]))
        .collect()
}

#[test]
fn reader_same_host_expired_writer_recovers_through_explicit_custodian_login() {
    let began = std::time::Instant::now();
    let f = NativeDestructionFixture::without_server();
    let short = f.writer_directory.join("reader-opfs-short-watch");
    let events = f.writer_directory.join("reader-opfs-watch-events");
    fs::write(&short, b"").unwrap();
    fs::write(
        f.writer_directory.join("reader-opfs-watch-diagnostics"),
        b"",
    )
    .unwrap();
    let ea_archive::ArchiveBackendProfileV1::LocalPath(profile) = &f.profile else {
        panic!("explicit local fixture");
    };
    let KeySourceSpec::Container {
        path,
        passphrase_file,
    } = &f.key_source
    else {
        panic!("explicit protected component container");
    };
    let config = f._directory.path().join("reader-custodian-reopen.json");
    let exact_config = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "writer_operator_config": f.writer_config,
        "component_certificate_hash": hex(f.component.as_bytes()),
        "component_key_source": format!("container:{};passphrase-file={}", path.display(), passphrase_file.display()),
        "delivery": "no-registered-server",
        "holders": [{"archive_directory": f.archive,
            "filesystem_row_id": profile.filesystem_row_id,
            "capability_test_vector_id": profile.capability_test_vector_id,
            "custody_certificate_hash": hex(f.writer_certificate.as_bytes())}]
    })).unwrap();
    fs::write(&config, &exact_config).unwrap();
    let controller_provider = NativeOperatorProvider::open_test_fixture(
        f.admin_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    let controller = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.admin_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        controller_provider,
    )
    .unwrap();
    let host = NativeDesktopRuntime::open_with_test_destruction_reopen_configuration(
        DesktopLaunchConfig {
            operator_config: f.admin_config.clone(),
            trust_anchor: f.anchor.clone(),
            writer_config: None,
            destruction_config: Some(config.clone()),
            recovery_config: None,
            administration_config: None,
        },
        controller,
        &f.writer_directory.join("ea-native-operator"),
    )
    .unwrap();
    host.login().unwrap();
    let state = host.desktop_state();
    let prepared =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let id = prepared["process"]["destructionId"].as_str().unwrap();
    let hash = prepared["process"]["preflight"]["jobHash"]
        .as_str()
        .unwrap();
    let archive_bytes = || {
        let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
        let mut bytes = Vec::new();
        source
            .visit_blobs(&mut |blob| {
                bytes.push(blob.bytes().to_vec());
                Ok(())
            })
            .unwrap();
        bytes.sort();
        bytes
    };
    let before_archive = archive_bytes();
    eprintln!(
        "custodian reauth diagnosis: actual durable Prepared at {:?}",
        began.elapsed()
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(75);
    while !fs::read_to_string(&events)
        .unwrap()
        .contains("writer ttl-exit\n")
    {
        assert!(
            std::time::Instant::now() < deadline,
            "bounded actual Writer expiry"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        destruction_read_core(&state, Some(id)).err().unwrap().code,
        "EA-DESTRUCTION-NATIVE-SESSION"
    );
    fs::remove_file(&short).unwrap();
    assert_eq!(
        destruction_read_core(&state, Some(id)).err().unwrap().code,
        "EA-DESTRUCTION-NATIVE-SESSION",
        "old provider remains invalidated"
    );
    let presence_count = |directory: &Path| {
        fs::read_to_string(directory.join("helper-calls"))
            .unwrap()
            .lines()
            .filter(|line| *line == "sign operator-instance")
            .count()
    };
    let writer_before = presence_count(&f.writer_directory);
    let admin_before = presence_count(&f.admin_directory);
    eprintln!(
        "custodian reauth diagnosis: actual TTL-exit and exact refusal at {:?}",
        began.elapsed()
    );
    // Same host and same DesktopState: only the explicit product command may
    // acquire a new Writer provider and its own typed presence.
    let reauthenticated =
        serde_json::to_value(destruction_authenticate_custodian_core(&state, id, hash).unwrap())
            .unwrap();
    assert_eq!(
        presence_count(&f.writer_directory),
        writer_before + 1,
        "one independent Writer presence through the existing native command"
    );
    assert!(
        presence_count(&f.admin_directory) >= admin_before + 2,
        "separate Admin unlocks before and after Writer login"
    );
    assert_eq!(
        fs::read_to_string(&events).unwrap(),
        "writer start\nwriter ttl-exit\nwriter start\n"
    );
    assert_eq!(reauthenticated["process"], prepared["process"]);
    assert_eq!(denominator(&reauthenticated), denominator(&prepared));
    assert!(fs::read(&config).unwrap() == exact_config);
    assert!(
        archive_bytes() == before_archive,
        "login does not modify archive objects"
    );
    let current = serde_json::to_value(destruction_read_core(&state, Some(id)).unwrap()).unwrap();
    assert_eq!(current["process"], prepared["process"]);
    assert_eq!(current["process"]["state"], "requested");
    assert!(current["process"]["evidenceEntryHash"].is_null());
    assert!(
        current["process"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|target| target["stubObjectHash"].is_null())
    );
    eprintln!(
        "custodian reauth diagnosis: same-host explicit Writer/Admin presence and unchanged durable job at {:?}; fresh provider uses standard300s",
        began.elapsed()
    );
}

#[test]
#[ignore = "explicit native Resume diagnostic with fixed phase/elapsed tracing"]
fn reader_native_resume_phase_diagnosis_with_actual_reservation() {
    assert_eq!(std::env::var("EA_TEST_NATIVE_RESUME_PHASES").unwrap(), "1");
    let began = std::time::Instant::now();
    let f = NativeDestructionFixture::with_reader_opfs();
    fs::write(f.admin_directory.join("long-recovery-run"), b"").unwrap();
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let mut native = f.runtime();
    let prepared = native.prepare(&f.authorization).unwrap();
    let mut reservation = ActualReservation {
        services: &services,
        server: &server.server,
    };
    native
        .start(
            prepared.destruction_id,
            prepared.preflight_hash.unwrap(),
            ea_admin::destruction_runtime::NativeDestructionDelivery::AuthenticatedServer(
                &mut reservation,
            ),
        )
        .unwrap();
    drop(native);
    assert_eq!(job_count(&services, &server), 0);
    eprintln!(
        "resume diagnosis: actual native Started/reservation at {:?}",
        began.elapsed()
    );
    let origin = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();
    for directory in [&f.admin_directory, &f.writer_directory] {
        fs::write(directory.join("reader-resume-trace-origin"), &origin).unwrap();
    }
    let host = configured_host(&f, &server);
    eprintln!(
        "resume diagnosis: actual fresh Desktop host at {:?}",
        began.elapsed()
    );
    let result = destruction_resume_core(
        &host.desktop_state(),
        &hex(prepared.destruction_id.as_bytes()),
    );
    eprintln!(
        "resume diagnosis: Desktop Resume returned {} at {:?}",
        result.as_ref().err().map_or("success", |error| error.code),
        began.elapsed()
    );
    for directory in [&f.admin_directory, &f.writer_directory] {
        // The helper owns this file and emits only fixed labels/ordinals/time.
        eprint!(
            "{}",
            fs::read_to_string(directory.join("reader-resume-helper-trace")).unwrap()
        );
    }
    let view = serde_json::to_value(result.unwrap()).unwrap();
    assert_eq!(job_count(&services, &server), 1);
    assert!(
        view["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|replica| replica["kindCode"] == 1 && replica["resultCode"].is_null())
    );
    assert_ne!(
        view["process"]["state"], "completeManagedScope",
        "diagnostic supplies no Reader claim and cannot establish full completion"
    );
}

#[test]
fn reader_fixture_writer_watch_expiry_refuses_current_host_and_fresh_host_recovers() {
    let began = std::time::Instant::now();
    let f = NativeDestructionFixture::with_server_state(true, 4);
    let short = f.writer_directory.join("reader-opfs-short-watch");
    let diagnostics = f.writer_directory.join("reader-opfs-watch-diagnostics");
    let events = f.writer_directory.join("reader-opfs-watch-events");
    fs::write(&short, b"").unwrap();
    fs::write(&diagnostics, b"").unwrap();
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    destruction_read_core(&state, None).unwrap();
    assert_eq!(fs::read_to_string(&events).unwrap(), "writer start\n");
    eprintln!(
        "writer-watch diagnosis: actual current host read succeeds at {:?}",
        began.elapsed()
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(75);
    while !fs::read_to_string(&events)
        .unwrap()
        .contains("writer ttl-exit\n")
    {
        assert!(
            std::time::Instant::now() < deadline,
            "bounded actual fixture Writer TTL expiry"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let error = destruction_read_core(&state, None).err().unwrap();
    assert_eq!(error.code, "EA-DESTRUCTION-NATIVE-SESSION");
    eprintln!(
        "writer-watch diagnosis: actual writer TTL-exit then current host {} at {:?}",
        error.code,
        began.elapsed()
    );
    fs::remove_file(&short).unwrap();
    assert_eq!(
        destruction_read_core(&state, None).err().unwrap().code,
        "EA-DESTRUCTION-NATIVE-SESSION",
        "removing the test knob cannot revive an expired current watch"
    );
    host.login().unwrap();
    assert_eq!(
        destruction_read_core(&state, None).err().unwrap().code,
        "EA-DESTRUCTION-NATIVE-SESSION",
        "explicit general host login does not replace the expired independent Writer provider"
    );
    eprintln!(
        "writer-watch diagnosis: same-host explicit login succeeds but read still refuses the expired Writer watch"
    );
    drop(state);
    drop(host);
    let fresh = configured_host(&f, &server);
    destruction_read_core(&fresh.desktop_state(), None).unwrap();
    assert_eq!(
        fs::read_to_string(&events).unwrap(),
        "writer start\nwriter ttl-exit\nwriter start\n"
    );
    assert_eq!(
        job_count(&services, &server),
        0,
        "diagnosis performs no destruction job or TLS reservation"
    );
    eprintln!(
        "writer-watch diagnosis: actual host restart/login/read succeeds at {:?}; normal 300s Writer TTL restored",
        began.elapsed()
    );
}

#[test]
fn native_reader_actual_opfs_exact_etb_tls_completion_survives_reopen() {
    let began = std::time::Instant::now();
    let private = support::temp_dir("native-reader-browser");
    let mut browser = BrowserHarness::start(private.path());
    eprintln!(
        "reader witness: actual Worker ready at {:?}",
        began.elapsed()
    );
    let f = NativeDestructionFixture::with_reader_opfs();
    fs::write(f.admin_directory.join("long-recovery-run"), b"").unwrap();
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    eprintln!(
        "reader witness: native fixture and original Server receipt ready at {:?}",
        began.elapsed()
    );
    // Seed has added the real original receipt; retain complete exact source
    // before the first local deletion. This source is not the cache being erased.
    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    let inventory = ArchiveInventory::build(&source).unwrap();
    assert!(
        !inventory.receipts().is_empty(),
        "source includes actual signed receipt added by ServerFixture::seed"
    );
    let (reader, kem) = inventory
        .trust()
        .iter()
        .find_map(|object| match object.value().decoded_payload().ok()? {
            DecodedTrustPayloadV1::AuthorizedDevice(c)
                if c.fields().certificate_kind == CertificateKindV1::Reader =>
            {
                Some((c.fields().device_id, c.fields().kem_key_thumbprint.unwrap()))
            }
            _ => None,
        })
        .unwrap();
    let mut archive = Vec::new();
    source
        .visit_blobs(&mut |blob| {
            archive.push(serde_json::json!({
                "name": format!("{}.etb", hex(object_hash(blob.bytes()).as_bytes())),
                "bytes": blob.bytes(),
            }));
            Ok(())
        })
        .unwrap();
    let credential = vec![0xd6; 32];
    let prf = [0xd7; 32];
    let authenticator =
        || AuthenticatorPrfV1::new(credential.clone(), ea_crypto::SecretBytes::new(prf));
    let sealed = ReaderVault::seal(
        VaultContentsV1::new(
            ea_crypto::SecretBytes::new(fixture::other_recipient_secret_bytes()),
            ea_crypto::SecretBytes::new(READER_OPFS_COMPONENT_SECRET),
            fs::read(&f.anchor).unwrap(),
            None,
        ),
        &[authenticator()],
    )
    .unwrap();
    let vault = ReaderVault::unlock(&sealed, &authenticator()).unwrap();
    let wrong_sealed = ReaderVault::seal(
        VaultContentsV1::new(
            ea_crypto::SecretBytes::new([0xd8; 32]),
            ea_crypto::SecretBytes::new([0xd9; 32]),
            fs::read(&f.anchor).unwrap(),
            None,
        ),
        &[authenticator()],
    )
    .unwrap();
    assert!(
        vault.kem_key_thumbprint() == kem,
        "actual registered Reader KEM"
    );
    let cache = ReaderObjectCache::open(&vault);
    let mut blobs = InMemoryReaderBlobStore::new();
    let mut target_hashes = Vec::new();
    let mut server_held = Vec::new();
    for entry in inventory.entries() {
        target_hashes.push(
            cache
                .put_exact_object(&mut blobs, entry.exact_bytes().as_bytes())
                .unwrap(),
        );
        server_held.push((ObjectTypeV1::Entry, entry.object_hash()));
    }
    for grant in inventory.grants() {
        target_hashes.push(
            cache
                .put_exact_object(&mut blobs, grant.exact_bytes().as_bytes())
                .unwrap(),
        );
        server_held.push((ObjectTypeV1::Grant, grant.object_hash()));
    }
    assert!(!target_hashes.is_empty());
    let cache_input = blobs
        .keys()
        .unwrap()
        .into_iter()
        .map(|key| {
            serde_json::json!({
                "key": key.as_str(), "bytes": blobs.get(&key).unwrap().unwrap(),
            })
        })
        .collect::<Vec<_>>();
    drop(vault);
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let prepared =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let id = prepared["process"]["destructionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let hash = prepared["process"]["preflight"]["jobHash"]
        .as_str()
        .unwrap()
        .to_owned();
    let original_denominator = denominator(&prepared);
    assert!(
        original_denominator.iter().any(|r| r[1] == 1),
        "Reader stays in original denominator"
    );
    assert_eq!(
        destruction_export_reader_delivery_core(&state, &id, &hash, &hex(reader.as_bytes()))
            .err()
            .unwrap()
            .code,
        "EA-DESTRUCTION-EVENT",
        "no export before actual Started event"
    );
    drop(state);
    drop(host);
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let started =
        serde_json::to_value(destruction_start_core(&state, &id, &hash).unwrap()).unwrap();
    assert_eq!(started["process"]["state"], "inProgress");
    assert!(
        started["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kindCode"] == 1 && r["resultCode"].is_null())
    );
    assert_eq!(job_count(&services, &server), 1);
    eprintln!(
        "reader witness: native Started and actual Server effect at {:?}",
        began.elapsed()
    );
    drop(state);
    drop(host);
    // A native refusal locks resources by design. Each next user operation
    // must reopen and authenticate rather than reuse that failed action.
    let export = |expected: &str, replica: &str| {
        let host = configured_host(&f, &server);
        let state = host.desktop_state();
        // Host login is not a Destruction unlock. The existing explicit read
        // obtains the purpose-bound native session that export must retain.
        destruction_read_core(&state, Some(&id)).unwrap();
        destruction_export_reader_delivery_core(&state, &id, expected, replica)
    };
    assert_eq!(
        export(&hash, &"ff".repeat(16)).err().unwrap().code,
        "EA-DESTRUCTION-TARGET"
    );
    assert_eq!(
        export(&"ff".repeat(32), &hex(reader.as_bytes()))
            .err()
            .unwrap()
            .code,
        "EA-DESTRUCTION-SECURITY-CONFLICT"
    );
    let delivery = serde_json::to_value(export(&hash, &hex(reader.as_bytes())).unwrap()).unwrap();
    assert_eq!(delivery["destructionId"], id);
    assert_eq!(delivery["jobHash"], hash);
    assert_eq!(delivery["readerId"], hex(reader.as_bytes()));
    let original_authorization: Vec<u8> =
        serde_json::from_value(delivery["exactAuthorization"].clone()).unwrap();
    let original_upload: Vec<u8> =
        serde_json::from_value(delivery["exactJobUpload"].clone()).unwrap();
    assert_eq!(original_authorization, f.authorization);
    let input = serde_json::json!({
        "archive": archive, "sealed": sealed.to_deterministic_cbor(), "wrongSealed": wrong_sealed.to_deterministic_cbor(),
        "credential": credential, "prf": prf, "cache": cache_input,
        "authorization": original_authorization, "initiatingEvent": delivery["exactInitiatingEvent"],
        "jobUpload": original_upload, "readerId": hex(reader.as_bytes()), "jobHash": hash,
        "component": hex(f.reader_opfs_component.unwrap().as_bytes()),
        "wrongComponent": hex(f.component.as_bytes()),
        "targetHashes": target_hashes.iter().map(|h| hex(h.as_bytes())).collect::<Vec<_>>(),
    });
    let input_path = private.path().join("private-input.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&input_path)
        .unwrap();
    file.write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    drop(file);
    drop(input);
    eprintln!(
        "reader witness: exact native originals exported at {:?}",
        began.elapsed()
    );
    browser.execute(&input_path);
    eprintln!(
        "reader witness: actual OPFS removal, product ETB and Vault/profile reopen at {:?}",
        began.elapsed()
    );
    let etb = fs::read(private.path().join("reader-attestation.etb")).unwrap();
    let browser_result: serde_json::Value =
        serde_json::from_slice(&fs::read(private.path().join("reader-result.json")).unwrap())
            .unwrap();
    assert_eq!(browser_result["reopenedIdentical"], true);
    // Independent native historical authority and COSE verification before
    // calling the import API, using the same archive's admitted component.
    {
        let operator = OperatorRuntime::open_with_test_native(
            OperatorRuntimeConfig::load(&f.admin_config).unwrap(),
            &f.anchor,
            support::live_clock(),
            false,
            NativeOperatorProvider::open_test_fixture(
                f.admin_directory.join("ea-native-operator"),
                false,
            )
            .unwrap(),
        )
        .unwrap();
        let ParsedArchiveObject::Trust(auth_object) =
            decode_exact_object(&f.authorization).unwrap()
        else {
            panic!("authorization ETB")
        };
        let DecodedTrustPayloadV1::DestructionAuthorization(fields) =
            auth_object.value().decoded_payload().unwrap()
        else {
            panic!("authorization payload")
        };
        let historical = ea_trust::verify_historical_registry_authority(
            operator.trust(),
            fields.registry_version,
            ObjectHash::try_from(fields.registry_head_hash.as_bytes().as_slice()).unwrap(),
            ChainSequence::new(fields.authorization_sequence),
        )
        .unwrap();
        let auth =
            ea_destruction::verify_authorization_historical(&f.authorization, &historical).unwrap();
        let observed = UnixMillis::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
        );
        let verified =
            ea_destruction::verify_attestation_historical(&etb, &auth, &historical, observed)
                .unwrap();
        assert!(verified.certificate_hash() == f.reader_opfs_component.unwrap());
        assert_eq!(verified.fields().replica_kind, 1);
        assert_eq!(verified.fields().replica_id, *reader.as_bytes());
        assert_eq!(verified.fields().result, 0);
        let mut actual = verified.fields().removed_object_hashes.clone();
        actual.sort();
        target_hashes.sort();
        assert!(actual == target_hashes);
    }
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let mut corrupt = etb.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(destruction_import_progress_core(&state, &id, &hash, &[corrupt]).is_err());
    drop(state);
    drop(host);
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let imported = serde_json::to_value(
        destruction_import_progress_core(&state, &id, &hash, std::slice::from_ref(&etb)).unwrap(),
    )
    .unwrap();
    let replayed = serde_json::to_value(
        destruction_import_progress_core(&state, &id, &hash, std::slice::from_ref(&etb)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        imported, replayed,
        "exact ETB replay creates no duplicate local claim"
    );
    assert_eq!(denominator(&replayed), original_denominator);
    eprintln!(
        "reader witness: exact native Reader import and replay at {:?}",
        began.elapsed()
    );
    drop(state);
    drop(host);
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let resumed = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(denominator(&resumed), original_denominator);
    eprintln!(
        "reader witness: actual TLS Resume returned at {:?}; state {}",
        began.elapsed(),
        resumed["process"]["state"]
    );
    // Actual host restart between long operations. The isolated TTL witness
    // separately proves that general login cannot renew the cached Writer watch.
    drop(state);
    drop(host);
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let synchronized =
        serde_json::to_value(destruction_synchronize_core(&state, &id, &hash).unwrap()).unwrap();
    assert_eq!(denominator(&synchronized), original_denominator);
    eprintln!(
        "reader witness: actual TLS Synchronize returned after host restart at {:?}; state {}",
        began.elapsed(),
        synchronized["process"]["state"]
    );
    drop(state);
    drop(host);
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let completed = if synchronized["process"]["state"] == "completeManagedScope" {
        synchronized
    } else {
        serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap()
    };
    assert_eq!(
        completed["process"]["state"], "completeManagedScope",
        "real reconstructed completion after every duty"
    );
    assert_eq!(
        completed["process"]["preflight"],
        prepared["process"]["preflight"]
    );
    assert_eq!(denominator(&completed), original_denominator);
    assert!(
        completed["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["resultCode"] == 0)
    );
    assert!(
        completed["process"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["stubObjectHash"].is_string())
    );
    assert_eq!(job_count(&services, &server), 1);
    services.block_on(async {
        let returned: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT object_hash FROM destruction_attestations WHERE object_hash = $1",
        )
        .bind(object_hash(&etb).as_bytes().as_slice())
        .fetch_all(server.database.pool())
        .await
        .unwrap();
        assert_eq!(
            returned,
            vec![object_hash(&etb).as_bytes().to_vec()],
            "actual TLS Server indexes original browser ETB exactly once"
        );
        let client = common::object_store_client().await;
        let exact = client
            .get_object()
            .bucket(&server.bucket)
            .key(ea_sync_server::object_key(
                ObjectTypeV1::Trust,
                object_hash(&etb),
            ))
            .send()
            .await
            .unwrap()
            .body
            .collect()
            .await
            .unwrap()
            .into_bytes();
        assert_eq!(
            exact.as_ref(),
            etb.as_slice(),
            "actual stored Server ETB is byte-identical to browser return"
        );
        let upload: Vec<u8> = sqlx::query_scalar("SELECT exact_upload FROM destruction_jobs")
            .fetch_one(server.database.pool())
            .await
            .unwrap();
        assert_eq!(
            upload, original_upload,
            "immutable original native upload survives all relays"
        );
        for (kind, hash) in server_held {
            let versions = client
                .list_object_versions()
                .bucket(&server.bucket)
                .prefix(ea_sync_server::object_key(kind, hash))
                .send()
                .await
                .unwrap();
            assert!(
                versions.versions().is_empty() && versions.delete_markers().is_empty(),
                "all actual S3 original versions absent"
            );
        }
    });
    let after =
        ArchiveInventory::build(&ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap())
            .unwrap();
    assert!(
        after.entries().is_empty() && after.grants().is_empty(),
        "actual Writer originals removed before Evidence"
    );
    eprintln!(
        "reader witness: complete reconstructed scope, exact Server ETB/upload and all original versions absent at {:?}",
        began.elapsed()
    );
    drop(state);
    drop(host);
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let review =
        serde_json::to_value(destruction_evidence_preview_core(&state, &id, &hash).unwrap())
            .unwrap();
    let confirmed: FinalizationPreviewDto =
        serde_json::from_value(review["preview"].clone()).unwrap();
    let finalized = serde_json::to_value(
        destruction_evidence_finalize_core(&state, &id, &hash, &confirmed).unwrap(),
    )
    .unwrap();
    drop(state);
    drop(host);
    let reopened = configured_host(&f, &server);
    let persisted =
        serde_json::to_value(destruction_read_core(&reopened.desktop_state(), Some(&id)).unwrap())
            .unwrap();
    assert_eq!(persisted["process"]["state"], "completeManagedScope");
    assert_eq!(
        persisted["process"]["evidenceEntryHash"],
        finalized["entryHash"]
    );
    assert_eq!(denominator(&persisted), original_denominator);
    eprintln!(
        "native Reader OPFS witness: verified exact Reader ETB {}; complete managed scope; durable Evidence {}",
        hex(object_hash(&etb).as_bytes()),
        finalized["entryHash"]
    );
}
