//! Recovery-Quelle eines kontrollierten Netzprofils (EA-CNA-REC-2 … REC-6):
//! die Capture exportiert die lokale Komponente exklusiv und bindet Netzziel
//! vereinigt mit dem Export; die §19.3-Zielkopie ist eine Nur-Lese-Ressource.
//! Das Temp-Verzeichnis ist kein Beleg für ein gemountetes Netzdateisystem.
use super::native_archive_existing_component::{config, profile};
use super::native_archive_startup::{MOVED, register_and_move_head};
use super::*;
use ea_admin::native_archive::NativeArchiveExistingComponent;
use ea_admin::recovery_test_runtime::{
    RecoveryRuntimeError, RecoverySourceRestore, materialize_network_archive_copy,
};
use ea_recovery::FsArchiveSource;

const PHRASE: &[u8] = b"DRK-320 network source fixture phrase";

fn code<T>(result: Result<T, RecoveryRuntimeError>) -> &'static str {
    match result {
        Ok(_) => panic!("the recovery action must refuse"),
        Err(error) => error.code(),
    }
}

fn sorted_blobs(source: &dyn ea_archive::ArchiveSource) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    source
        .visit_blobs(&mut |blob| {
            rows.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .unwrap();
    rows.sort();
    rows
}

/// Alle verwalteten Objekte der Komponente, gelesen unter ihrem Writer-Lock.
fn component_blobs(runtime: &OperatorRuntime) -> Vec<(String, Vec<u8>)> {
    let component =
        NativeArchiveExistingComponent::open_current(runtime, config(runtime, profile())).unwrap();
    let _lock = component.local_backend().acquire_writer_lock().unwrap();
    let mut rows = Vec::new();
    component
        .local_backend()
        .visit_managed_blobs(&mut |blob| {
            rows.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .unwrap();
    rows.sort();
    rows
}

fn union(remote: &Path, export: &Path) -> FsArchiveSource {
    FsArchiveSource::open(remote)
        .unwrap()
        .with_exact_component(&FsArchiveSource::open(export).unwrap())
        .unwrap()
}

fn network_recovery(installed: &RecoveryInstallation) -> RecoveryTestRuntime {
    let runtime = installed.open();
    let archive_config = config(&runtime, profile());
    RecoveryTestRuntime::with_archive_config(runtime, archive_config).unwrap()
}

/// Registriertes Netzprofil mit einem lokal committeten, nicht publizierten
/// Grant samt `.eip` (Sequenz 1); das Netzziel trägt nur Sequenz 0.
fn network_installation() -> RecoveryInstallation {
    let installed = RecoveryInstallation::with_profile(None, true, Some(profile()));
    register_and_move_head(&installed);
    installed
}

fn network_installation_with_target(target: &Value) -> RecoveryInstallation {
    let installed = RecoveryInstallation::with_profile(Some(target), true, Some(profile()));
    register_and_move_head(&installed);
    installed
}

fn capture(
    installed: &RecoveryInstallation,
    recovery: &mut RecoveryTestRuntime,
    export: &Path,
) -> Result<ea_recovery::VerifiedRecoverySource, RecoveryRuntimeError> {
    let inventory = installed.inventory(recovery.runtime());
    let probes = installed.probes(&inventory);
    let phrase = SecretVec::new(PHRASE.to_vec());
    recovery.capture_source_with_component_export(
        RecoverySourceCapture {
            inventory: &inventory,
            probes,
            snapshot: &installed.directory.path().join("backup.db"),
            passphrase: &phrase,
        },
        export,
    )
}

fn scope_rows(runtime: &OperatorRuntime) -> i64 {
    runtime
        .database()
        .query_row("SELECT count(*) FROM recovery_source_scope", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}

#[test]
fn network_capture_binds_unpublished_local_entry_and_exports_it_exactly() {
    let installed = network_installation();
    let mut recovery = network_recovery(&installed);
    let export = installed.directory.path().join("component-export");
    let captured = capture(&installed, &mut recovery, &export).unwrap();
    let managed = component_blobs(recovery.runtime());
    for (directory, name) in MOVED {
        let path = format!("{directory}{name}");
        assert!(managed.iter().any(|(hint, _)| *hint == path));
        assert!(!installed.archive.join(&path).exists(), "nothing published");
    }
    assert_eq!(
        sorted_blobs(&FsArchiveSource::open(&export).unwrap()),
        managed,
        "the export holds exactly the component's managed blobs"
    );
    let fields = captured.core().fields();
    assert_eq!(
        ea_recovery::recovery_archive_inventory_hash(&union(&installed.archive, &export)).unwrap(),
        fields.archive_inventory_hash
    );
    let epoch = installed.historical_epoch.as_ref().unwrap();
    assert_eq!(fields.tip_sequence, 1);
    assert_eq!(fields.tip_entry_hash, *epoch.entry_hash.as_bytes());
    assert_eq!(scope_rows(recovery.runtime()), 1);
}

#[test]
fn network_capture_without_the_local_set_fails() {
    let installed = network_installation();
    let mut recovery = network_recovery(&installed);
    let export = installed.directory.path().join("component-export");
    let captured = capture(&installed, &mut recovery, &export).unwrap();
    let inventory = installed.inventory(recovery.runtime());
    let remote_only = ea_recovery::verify_recovery_source(
        captured.exact_envelope(),
        &FsArchiveSource::open(&installed.archive).unwrap(),
        recovery.runtime().anchor(),
        &inventory,
        support::live_clock(),
    );
    assert_eq!(
        remote_only.err().map(|error| error.code()),
        Some("EA-RECOVERY-TEST-SOURCE")
    );
    assert!(
        ea_recovery::verify_recovery_source(
            captured.exact_envelope(),
            &union(&installed.archive, &export),
            recovery.runtime().anchor(),
            &inventory,
            support::live_clock(),
        )
        .is_ok()
    );
}

#[test]
fn network_capture_refuses_existing_or_nested_export_directory() {
    let installed = network_installation();
    let mut recovery = network_recovery(&installed);
    // Ohne Exportziel ist die Netzquelle nie vollständig.
    let inventory = installed.inventory(recovery.runtime());
    let phrase = SecretVec::new(PHRASE.to_vec());
    assert_eq!(
        code(recovery.capture_source(RecoverySourceCapture {
            inventory: &inventory,
            probes: installed.probes(&inventory),
            snapshot: &installed.directory.path().join("plain.db"),
            passphrase: &phrase,
        })),
        "EA-RECOVERY-TEST-SOURCE"
    );
    let existing = installed.directory.path().join("existing-export");
    fs::create_dir(&existing).unwrap();
    assert_eq!(
        code(capture(&installed, &mut recovery, &existing)),
        "EA-RECOVERY-TEST-SOURCE"
    );
    assert_eq!(fs::read_dir(&existing).unwrap().count(), 0);
    for nested in [
        installed.archive.join("component-export"),
        installed.archive.join("entries").join("component-export"),
    ] {
        assert_eq!(
            code(capture(&installed, &mut recovery, &nested)),
            "EA-RECOVERY-TEST-SOURCE"
        );
        assert!(!nested.exists());
    }
    assert!(!installed.directory.path().join("backup.db").exists());
    assert_eq!(scope_rows(recovery.runtime()), 0);
    drop(recovery);
    // LocalPath kennt keinen Komponentenexport.
    let local = RecoveryInstallation::new();
    let runtime = local.open();
    let mut local_recovery = RecoveryTestRuntime::new(runtime, local.profile.clone()).unwrap();
    let export = local.directory.path().join("component-export");
    assert_eq!(
        code(capture(&local, &mut local_recovery, &export)),
        "EA-RECOVERY-TEST-SOURCE"
    );
    assert!(!export.exists());
}

/// Ein Zielkontext auf DIESEM Rechner, erzeugt wie
/// `export_target_native_context`, aber im Temp-Verzeichnis des Tests.
fn same_host_target(directory: &Path) -> Value {
    use ea_admin::native_provider::NativeSigningSlot;
    use ea_operator::OsAccountProvider as _;
    install_fixture_helper(directory);
    fs::write(directory.join("authority-fixture"), b"").unwrap();
    fs::write(directory.join("target-recovery-fixture"), b"").unwrap();
    let native =
        NativeOperatorProvider::open_test_fixture(directory.join("ea-native-operator"), false)
            .unwrap();
    let provider = native.signing_provider(NativeSigningSlot::Admin);
    provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    json!({
        "schemaId":"ea.recovery-target-fixture/v1",
        "machineHash":hex::encode(ea_key_provider::measure_native_machine_identity().unwrap().fingerprint().as_bytes()),
        "installationId":hex::encode(native.installation_id().as_bytes()),
        "deviceId":hex::encode(target_device().as_bytes()),
        "accountHash":hex::encode(native.os_account_binding_hash(trust_support::organization(),target_device()).unwrap().as_bytes()),
        "instanceThumbprint":hex::encode(native.public_key(NativeSigningSlot::Operator).unwrap().unwrap().thumbprint().as_bytes()),
    })
}

/// Öffnet die Zielinstallation über die Kopie des Netzziels, ohne
/// Registrierung, Komponente oder Capability-Test.
fn open_copy_target(
    installed: &RecoveryInstallation,
    target: &Path,
    export: &Path,
) -> RecoveryTestRuntime {
    use ea_admin::native_provider::NativeSigningSlot;
    let config = installed.target_config.as_ref().unwrap();
    fs::write(
        target.join("operator.json"),
        serde_json::to_vec(config).unwrap(),
    )
    .unwrap();
    if !target.join("independent-anchor.etb").exists() {
        fs::copy(&installed.anchor, target.join("independent-anchor.etb")).unwrap();
    }
    let native =
        NativeOperatorProvider::open_test_fixture(target.join("ea-native-operator"), false)
            .unwrap();
    let provider = native.signing_provider(NativeSigningSlot::Admin);
    let key = provider.handle(SecretPurpose::LocalDatabaseKey);
    let path = target.join("active-authorization.sqlite");
    let database = if path.exists() {
        EncryptedDatabase::open_existing(&path, &provider, &key).unwrap()
    } else {
        let database = EncryptedDatabase::open(&path, &provider, &key).unwrap();
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
        database
    };
    drop(database);
    drop(provider);
    let host: Arc<dyn ea_key_provider::DevicePostureProvider> =
        Arc::new(ea_key_provider::DevicePostureProviderFake::unknown(
            ea_key_provider::PostureRequirement::FullDiskEncryption,
        ));
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
        let context = runtime.posture_target_context().unwrap();
        let document = runtime
            .issue_posture_document(
                &context,
                ea_crypto::object_hash(b"DRK-320 archive copy target prerequisites"),
                60_000,
            )
            .unwrap();
        runtime.import_posture_document(&document).unwrap();
    }
    RecoveryTestRuntime::for_archive_copy(runtime, profile(), export.to_path_buf()).unwrap()
}

/// Alle Dateien eines Baums außer den Steuerdateien des Writer-Locks.
fn object_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(root: &Path, directory: &Path, rows: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &entry.path(), rows);
            } else if !ea_archive_fs::CONTROL_FILES_V1
                .iter()
                .any(|name| entry.file_name() == *name)
            {
                rows.push((
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                ));
            }
        }
    }
    let mut rows = Vec::new();
    walk(root, root, &mut rows);
    rows.sort();
    rows
}

/// §19.3 (EA-CNA-REC-5): Das Ziel erhält die unveränderte committete
/// Vereinigung als Archivverzeichnis, gebaut mit
/// `materialize_network_archive_copy` aus der Kopie des Netzziels und dem
/// Export. Wie bei den LocalPath-Tests auf einem Rechner gilt der gemessene
/// andere Rechner unverändert: `restore_source` prüft ihn HINTER der
/// Quellverifikation, `EA-RECOVERY-TEST-MACHINE` belegt also, dass Kopie und
/// Export die signierte Quelle tragen. Der erfolgreiche Restore auf einem
/// fremden Rechner bleibt dem portablen Ablauf vorbehalten.
#[test]
fn archive_copy_restores_on_other_machine_without_backend_or_publication() {
    let target = support::temp_dir("recovery-network-copy-target");
    let context = same_host_target(target.path());
    let installed = network_installation_with_target(&context);
    let mut recovery = network_recovery(&installed);
    let export = installed.directory.path().join("component-export");
    let captured = capture(&installed, &mut recovery, &export).unwrap();
    let inventory = installed.inventory(recovery.runtime());
    let envelope = captured.exact_envelope().to_vec();
    drop(recovery);
    let remote_copy = target.path().join("remote-copy");
    copy_public_tree(&installed.archive, &remote_copy);
    let copied_export = target.path().join("component-export");
    copy_public_tree(&export, &copied_export);
    let archive = target.path().join("archive");
    materialize_network_archive_copy(&remote_copy, &copied_export, &archive).unwrap();
    assert_eq!(
        code(materialize_network_archive_copy(&remote_copy, &copied_export, &archive)),
        "EA-RECOVERY-TEST-SOURCE",
        "a non-empty target is never merged into"
    );
    for (directory, name) in MOVED {
        assert!(archive.join(directory).join(name).exists());
        assert!(!remote_copy.join(directory).join(name).exists());
    }
    let before = object_files(&archive);
    let phrase = SecretVec::new(PHRASE.to_vec());
    let restore = |copy: &mut RecoveryTestRuntime, name: &str| {
        copy.restore_source(RecoverySourceRestore {
            inventory: &inventory,
            exact_source: &envelope,
            snapshot: &installed.directory.path().join("backup.db"),
            passphrase: &phrase,
            target: &target.path().join(name),
        })
        .map(|_| ())
    };

    let mut copy = open_copy_target(&installed, target.path(), &copied_export);
    assert_eq!(
        code(restore(&mut copy, "restored-sources.sqlite")),
        "EA-RECOVERY-TEST-MACHINE",
        "the union copy carries the signed source; only the same host remains"
    );
    let inventory_again = installed.inventory(copy.runtime());
    assert_eq!(
        code(copy.capture_source(RecoverySourceCapture {
            inventory: &inventory_again,
            probes: installed.probes(&inventory_again),
            snapshot: &target.path().join("copy-capture.db"),
            passphrase: &phrase,
        })),
        "EA-RECOVERY-TEST-SOURCE"
    );
    assert_eq!(
        code(capture(&installed, &mut copy, &target.path().join("copy-export"))),
        "EA-RECOVERY-TEST-SOURCE"
    );
    assert!(!target.path().join("copy-export").exists());
    assert!(!target.path().join("restored-sources.sqlite").exists());
    assert_eq!(
        copy.runtime()
            .database()
            .query_row("SELECT count(*) FROM native_archive_component", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    drop(copy);
    assert_eq!(object_files(&archive), before, "the copy stays unchanged");

    // Kontrolle: eine Zielkopie ohne die exportierten lokalen Objekte
    // scheitert vor dem Restore. Als Quelle geprüft passt sie weder im
    // Inventarhash noch im Kettenkopf zur signierten Quelle …
    assert_eq!(
        ea_recovery::verify_recovery_source(
            &envelope,
            &FsArchiveSource::open(&remote_copy).unwrap(),
            &ea_recovery::load_trust_anchor(&installed.anchor).unwrap(),
            &inventory,
            support::live_clock(),
        )
        .err()
        .map(|error| error.code()),
        Some("EA-RECOVERY-TEST-SOURCE")
    );
    // … und eine Zielinstallation darüber sieht schon beim Auffrischen der
    // Autorität die kürzere Kette.
    let empty_export = target.path().join("empty-export");
    fs::create_dir(&empty_export).unwrap();
    let mut without_local = open_copy_target(&installed, target.path(), &empty_export);
    for (directory, name) in MOVED {
        fs::remove_file(archive.join(directory).join(name)).unwrap();
    }
    let refused = code(restore(&mut without_local, "restored-without-local.sqlite"));
    assert_eq!(refused, "EA-TRUST-SEQUENCE-LEASE");
    assert!(!target.path().join("restored-without-local.sqlite").exists());
}

/// CLI-Capture eines Netzprofils: `--component-export` ist Pflicht, für
/// LocalPath abgelehnt, und die gespeicherte Quelle bindet die Vereinigung.
#[test]
fn cli_network_capture_requires_component_export_and_binds_the_union() {
    let installed = network_installation();
    let existing = installed.open();
    let inventory_path = installed.directory.path().join("cli-inventory.json");
    write_private(&inventory_path, &installed.inventory_exact(&existing));
    drop(existing);
    let network_profile = installed.directory.path().join("network-profile.json");
    fs::write(
        &network_profile,
        serde_json::to_vec(&json!({
            "kind": "controlledNetworkPath",
            "filesystemRowId": "existing-component-only-no-mount",
            "protocolId": "SMB3",
            "serverProduct": "native-component-fixture",
            "serverVersion": "1",
            "mountOptions": ["component-only"],
            "failoverConfigId": "none",
            "capabilityTestVectorId": "native-existing-component-v1",
            "queueMaxObjects": 10000,
            "queueMaxBytes": 64 * 1024 * 1024,
            "resumeBackoffInitialMs": 1000,
            "resumeBackoffMaxMs": 5000,
            "resumeMaxAttempts": 3,
        }))
        .unwrap(),
    )
    .unwrap();
    let local_profile = installed.directory.path().join("local-profile.json");
    fs::write(
        &local_profile,
        br#"{"kind":"localPath","filesystemRowId":"fixture-recovery-fs","capabilityTestVectorId":"native-recovery-cap-v1"}"#,
    )
    .unwrap();
    let phrase = installed.directory.path().join("cli-passphrase");
    write_private(&phrase, PHRASE);
    let export = installed.directory.path().join("cli-component-export");
    let run = |profile: &Path, export: Option<&Path>, name: &str| {
        let written = installed.directory.path().join(format!("{name}.cbor"));
        let mut arguments: Vec<std::ffi::OsString> = vec![
            "--trust-anchor".into(), installed.anchor.as_os_str().to_owned(),
            "recovery-test".into(), installed.archive.as_os_str().to_owned(),
            "--key-inventory".into(), inventory_path.as_os_str().to_owned(),
            "--output".into(), written.as_os_str().to_owned(),
            "--recovery-mode".into(), "capture".into(),
            "--operator-config".into(), installed.config.as_os_str().to_owned(),
            "--archive-profile".into(), profile.as_os_str().to_owned(),
            "--snapshot".into(), installed.directory.path().join(format!("{name}.db")).into_os_string(),
            "--backup-passphrase-file".into(), phrase.as_os_str().to_owned(),
        ];
        if let Some(export) = export {
            arguments.push("--component-export".into());
            arguments.push(export.as_os_str().to_owned());
        }
        let invocation = crate::args::parse(arguments.into_iter()).unwrap();
        let crate::args::Command::RecoveryTest { ref runtime, ref archive, ref key_inventory, ref output } =
            invocation.command
        else {
            panic!("parsed recovery mode")
        };
        let code = crate::recovery_command::run_with_runtime_opener(
            &invocation, archive, key_inventory, output, runtime.as_ref().unwrap(), support::live_clock(),
            |config, anchor, now| {
                let native = NativeOperatorProvider::open_test_fixture(
                    installed.directory.path().join("ea-native-operator"), false,
                )?;
                let host: Arc<dyn ea_key_provider::DevicePostureProvider> =
                    Arc::new(ea_key_provider::DevicePostureProviderFake::unknown(
                        ea_key_provider::PostureRequirement::FullDiskEncryption,
                    ));
                OperatorRuntime::open_with_test_native_and_posture(config, anchor, now, false, native, host)
            },
        );
        (code, written)
    };
    let (code, output) = run(&network_profile, None, "without-export");
    assert_ne!(code, ea_recovery::ExitCode::Success);
    assert!(!output.exists());
    let (code, output) = run(&local_profile, Some(&export), "local-with-export");
    assert_ne!(code, ea_recovery::ExitCode::Success);
    assert!(!output.exists());
    assert!(!export.exists());
    let (code, output) = run(&network_profile, Some(&export), "with-export");
    assert_eq!(code, ea_recovery::ExitCode::Success);
    let after = installed.open();
    let exact = fs::read(&output).unwrap();
    let stored = after
        .database()
        .query_row("SELECT exact_envelope FROM recovery_source_scope", &[])
        .unwrap()
        .unwrap();
    assert_eq!(stored.blob(0).unwrap(), exact);
    let inventory = installed.inventory(&after);
    assert!(
        ea_recovery::verify_recovery_source(
            &exact,
            &union(&installed.archive, &export),
            after.anchor(),
            &inventory,
            support::live_clock(),
        )
        .is_ok()
    );
}
