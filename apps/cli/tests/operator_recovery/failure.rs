use super::*;
#[test]
#[ignore = "actual foreign-machine restored v3 fixture with retained successful completion"]
fn portable_native_failure_report_survives_reopen_without_replacing_success() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let mut runtime = open_portable_target(&export, &target);
    let restored_path = target.join("restored-sources.sqlite");
    let successful = runtime
        .read_completed_report(&inventory, &restored_path)
        .unwrap()
        .unwrap();
    let successful_exact = successful.exact_envelope().to_vec();
    let restored = runtime
        .reopen_restored_source(&inventory, &restored_path)
        .unwrap();
    let failed_before = runtime
        .runtime()
        .database()
        .query_row("SELECT count(*) FROM recovery_test_failure", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    let result = runtime
        .run_restored_test_report(&restored, &inventory, &[])
        .unwrap();
    let ea_admin::recovery_test_runtime::RecoveryTestOutcome::Failed(report) = result else {
        panic!("missing media must produce a diagnostic failure");
    };
    let public: Value = serde_json::from_slice(report.public_report()).unwrap();
    assert_eq!(public["result"], "failed");
    assert_eq!(
        public["media"].as_array().unwrap().len(),
        inventory.media().len()
    );
    assert!(
        public["media"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["result"] == "missing")
    );
    let exact = report.exact_envelope().to_vec();
    let failure_hash = report.envelope_hash();
    assert_eq!(
        runtime
            .runtime()
            .database()
            .query_row("SELECT count(*) FROM recovery_test_failure", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        failed_before + 1
    );
    assert_eq!(
        runtime
            .read_completed_report(&inventory, &restored_path)
            .unwrap()
            .unwrap()
            .exact_envelope(),
        successful_exact
    );
    drop(restored);
    drop(runtime);
    let mut reopened = open_portable_target(&export, &target);
    let report = reopened
        .read_failed_report(&inventory, &restored_path)
        .unwrap()
        .unwrap();
    assert_eq!(report.exact_envelope(), exact);
    assert!(report.envelope_hash() == failure_hash);
    assert_eq!(
        reopened
            .read_completed_report(&inventory, &restored_path)
            .unwrap()
            .unwrap()
            .exact_envelope(),
        successful_exact
    );
    assert!(
        !String::from_utf8(report.public_report().to_vec())
            .unwrap()
            .contains("Erika Beispiel")
    );
}

#[test]
#[ignore = "actual foreign-machine durable failure status with no private input or reimport"]
fn portable_native_cli_failure_status_reads_signed_last_failure_after_reopen() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let restored = target.join("restored-sources.sqlite");
    let mut current = open_portable_target(&export, &target);
    let expected = current
        .read_failed_report(&inventory, &restored)
        .unwrap()
        .unwrap()
        .exact_envelope()
        .to_vec();
    let success = current
        .read_completed_report(&inventory, &restored)
        .unwrap()
        .unwrap()
        .exact_envelope()
        .to_vec();
    drop(current);
    let scratch = support::temp_dir("native-cli-failure-status");
    let config_path = scratch.path().join("operator.json");
    let mut config: Value =
        serde_json::from_slice(&fs::read(target.join("operator.json")).unwrap()).unwrap();
    config["archive_directory"] = json!(target.join("archive"));
    config["database_path"] = json!(target.join("active-authorization.sqlite"));
    write_private(&config_path, &serde_json::to_vec(&config).unwrap());
    let profile = scratch.path().join("profile.json");
    write_private(&profile,br#"{"kind":"localPath","filesystemRowId":"fixture-recovery-fs","capabilityTestVectorId":"native-recovery-cap-v1"}"#);
    let destination = scratch.path().join("failed.cbor");
    let words = vec![
        "--trust-anchor".into(),
        target.join("independent-anchor.etb").into_os_string(),
        "recovery-test".into(),
        target.join("archive").into_os_string(),
        "--key-inventory".into(),
        export.join("inventory.json").into_os_string(),
        "--output".into(),
        destination.clone().into_os_string(),
        "--operator-config".into(),
        config_path.into_os_string(),
        "--archive-profile".into(),
        profile.into_os_string(),
        "--recovery-mode".into(),
        "failure-status".into(),
        "--restore-database".into(),
        restored.clone().into_os_string(),
    ];
    let invocation = args::parse(words.into_iter()).unwrap();
    let args::Command::RecoveryTest {
        archive,
        key_inventory,
        output,
        runtime: Some(command),
    } = &invocation.command
    else {
        panic!("native failure status")
    };
    let code = recovery_command::run_with_runtime_opener(
        &invocation,
        archive,
        key_inventory,
        output,
        command,
        support::live_clock(),
        |config, anchor, now| {
            let native =
                NativeOperatorProvider::open_test_fixture(target.join("ea-native-operator"), false)
                    .unwrap();
            OperatorRuntime::open_with_test_native_and_posture(
                config,
                anchor,
                now,
                false,
                native,
                Arc::from(
                    ea_key_provider::SupportMatrixRow::current_host()
                        .unwrap()
                        .posture_provider(),
                ),
            )
        },
    );
    assert_eq!(code, ea_recovery::ExitCode::Incomplete);
    assert!(
        destination.exists(),
        "verified durable failure is available without private inputs or reimport"
    );
    assert_eq!(fs::read(destination).unwrap(), expected);
    let mut reopened = open_portable_target(&export, &target);
    assert_eq!(
        reopened
            .read_completed_report(&inventory, &restored)
            .unwrap()
            .unwrap()
            .exact_envelope(),
        success
    );
}

#[test]
#[ignore = "actual foreign-machine CLI failure after exclusive full source restore"]
fn portable_native_cli_restore_run_exports_failed_report_without_claiming_success() {
    use ea_key_provider::SecretPurpose;
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let scratch = support::temp_dir("native-cli-failed-restore");
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let existing = open_portable_target(&export, &target);
    let provider = Arc::clone(existing.runtime().signing_provider());
    let db_path = scratch.path().join("authorization.sqlite");
    let db = EncryptedDatabase::open(
        &db_path,
        provider.as_ref(),
        &provider.handle(SecretPurpose::LocalDatabaseKey),
    )
    .unwrap();
    let profile=existing.runtime().database().query_row("SELECT organization_id,operator_subject_id,display_name,function_label,profile_commitment_salt,operator_binding_object_hash FROM operator_profile",&[]).unwrap().unwrap();
    db.execute(
        "INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",
        &[
            StoreValue::Blob(profile.blob(0).unwrap().to_vec()),
            StoreValue::Blob(profile.blob(1).unwrap().to_vec()),
            StoreValue::Text(profile.text(2).unwrap().into()),
            StoreValue::Text(profile.text(3).unwrap().into()),
            StoreValue::Blob(profile.blob(4).unwrap().to_vec()),
            StoreValue::Blob(profile.blob(5).unwrap().to_vec()),
        ],
    )
    .unwrap();
    drop(db);
    drop(existing);
    let config_path = scratch.path().join("operator.json");
    let mut config: Value =
        serde_json::from_slice(&fs::read(target.join("operator.json")).unwrap()).unwrap();
    config["archive_directory"] = json!(target.join("archive"));
    config["database_path"] = json!(db_path);
    write_private(&config_path, &serde_json::to_vec(&config).unwrap());
    let profile_path = scratch.path().join("profile.json");
    write_private(&profile_path,br#"{"kind":"localPath","filesystemRowId":"fixture-recovery-fs","capabilityTestVectorId":"native-recovery-cap-v1"}"#);
    let media_path = scratch.path().join("missing-media.json");
    write_private(
        &media_path,
        br#"{"schemaId":"ea.recovery-media-sources/v1","media":[]}"#,
    );
    let restored = scratch.path().join("restored.sqlite");
    let destination = scratch.path().join("failed.cbor");
    let words = vec![
        "--trust-anchor".into(),
        target.join("independent-anchor.etb").into_os_string(),
        "recovery-test".into(),
        target.join("archive").into_os_string(),
        "--key-inventory".into(),
        export.join("inventory.json").into_os_string(),
        "--output".into(),
        destination.clone().into_os_string(),
        "--operator-config".into(),
        config_path.clone().into_os_string(),
        "--archive-profile".into(),
        profile_path.clone().into_os_string(),
        "--recovery-mode".into(),
        "restore-run".into(),
        "--source-envelope".into(),
        export.join("source-envelope.cbor").into_os_string(),
        "--snapshot".into(),
        export.join("snapshot.db").into_os_string(),
        "--backup-passphrase-file".into(),
        export.join("backup.passphrase").into_os_string(),
        "--restore-database".into(),
        restored.clone().into_os_string(),
        "--media-sources".into(),
        media_path.into_os_string(),
    ];
    let invocation = args::parse(words.into_iter()).unwrap();
    let args::Command::RecoveryTest {
        archive,
        key_inventory,
        output,
        runtime: Some(command),
    } = &invocation.command
    else {
        panic!("native failed restore command")
    };
    let open = |config, anchor: &Path, now| {
        let native =
            NativeOperatorProvider::open_test_fixture(target.join("ea-native-operator"), false)
                .unwrap();
        let runtime = OperatorRuntime::open_with_test_native_and_posture(
            config,
            anchor,
            now,
            false,
            native,
            Arc::from(
                ea_key_provider::SupportMatrixRow::current_host()
                    .unwrap()
                    .posture_provider(),
            ),
        )?;
        if runtime.posture_admission().is_err() {
            let context = runtime.posture_target_context()?;
            let exact = runtime.issue_posture_document(
                &context,
                ea_crypto::object_hash(b"T9 CLI failure diagnostic prerequisites"),
                300_000,
            )?;
            runtime.import_posture_document(&exact)?;
        }
        Ok(runtime)
    };
    let code = recovery_command::run_with_runtime_opener(
        &invocation,
        archive,
        key_inventory,
        output,
        command,
        support::live_clock(),
        open,
    );
    assert_eq!(code, ea_recovery::ExitCode::Incomplete);
    assert!(
        destination.exists(),
        "actual failed test exports its signed diagnostic envelope"
    );
    let exact = fs::read(destination).unwrap();
    let mut reopened = RecoveryTestRuntime::new(
        open(
            OperatorRuntimeConfig::load(&config_path).unwrap(),
            &target.join("independent-anchor.etb"),
            support::live_clock(),
        )
        .unwrap(),
        ea_admin::recovery_test_runtime::parse_recovery_archive_profile(
            &fs::read(profile_path).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let failed = reopened
        .read_failed_report(&inventory, &restored)
        .unwrap()
        .unwrap();
    assert_eq!(failed.exact_envelope(), exact);
    assert!(
        reopened
            .read_completed_report(&inventory, &restored)
            .unwrap()
            .is_none()
    );
    let public: Value = serde_json::from_slice(failed.public_report()).unwrap();
    assert!(
        public["media"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["result"] == "missing")
    );
}
