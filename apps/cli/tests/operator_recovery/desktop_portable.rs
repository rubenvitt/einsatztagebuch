//! Actual portable Desktop command/worker witnesses; no renderer or medium mocks.
use super::*;
use ea_desktop::{
    commands::recovery::{
        recovery_cancel_core, recovery_read_core, recovery_start_core, recovery_submit_core,
    },
    runtime::{DesktopLaunchConfig, NativeDesktopRuntime},
    state::RuntimeSessionPort,
};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    time::{Duration, Instant},
};

fn write_exact(path: &Path, exact: &[u8]) {
    if path.exists() {
        assert_eq!(
            fs::read(path).unwrap(),
            exact,
            "retained fixture configuration is exact"
        );
    } else {
        write_private(path, exact);
    }
}

fn host(export: &Path, target: &Path) -> Arc<NativeDesktopRuntime> {
    let current = open_portable_target(export, target);
    // An independent Host action starts with a new genuine signed document.
    // open_portable_target only renews an already expired one.
    renew_portable_fixture_posture(&current);
    let config = target.join("desktop-portable-recovery.json");
    let profile = target.join("desktop-portable-profile.json");
    let sources = target.join("desktop-portable-media.json");
    write_exact(&profile, br#"{"kind":"localPath","filesystemRowId":"fixture-recovery-fs","capabilityTestVectorId":"native-recovery-cap-v1"}"#);
    let mapping: Vec<Value> =
        serde_json::from_slice(&fs::read(export.join("media.json")).unwrap()).unwrap();
    let media: Vec<Value> = mapping
        .iter()
        .map(|row| {
            let source = if let Some(slot) = row.get("nativeSlot") {
                format!("native:{}", slot.as_str().unwrap())
            } else {
                assert!(
                    row.get("pkcs11Id").is_none(),
                    "this is the distinct portable V4 fixture"
                );
                format!(
                    "container:{};passphrase-file={}",
                    export.join(row["container"].as_str().unwrap()).display(),
                    export
                        .join(row["passphraseFile"].as_str().unwrap())
                        .display()
                )
            };
            json!({"mediumId":row["mediumId"],"source":source})
        })
        .collect();
    write_exact(
        &sources,
        &serde_json::to_vec(&json!({"schemaId":"ea.recovery-media-sources/v1","media":media}))
            .unwrap(),
    );
    write_exact(&config, &serde_json::to_vec(&json!({"version":1,
        "key_inventory_path":export.join("inventory.json"), "archive_profile_path":profile,
        "media_sources_path":sources,"restored_source_database_path":target.join("restored-sources.sqlite")
    })).unwrap());
    let launch = DesktopLaunchConfig::parse([
        OsString::from("--operator-config"),
        target.join("operator.json").into_os_string(),
        OsString::from("--trust-anchor"),
        target.join("independent-anchor.etb").into_os_string(),
        OsString::from("--recovery-config"),
        config.into_os_string(),
    ])
    .unwrap()
    .unwrap();
    let runtime = current.runtime().reopened_for_action().unwrap();
    drop(current);
    let host = NativeDesktopRuntime::open_with_test_runtime(launch, runtime).unwrap();
    host.login().expect("portable Desktop native login");
    assert_eq!(
        host.verified_role()
            .expect("portable Desktop post-login role"),
        Some(ea_format::OperatorRoleV1::OrganizationAdmin),
        "portable Desktop post-login role is current",
    );
    host
}

fn retain_current_fixture_posture(target: &Path) {
    // Genuine independent native documentation; the short fixture evidence is
    // refreshed between inputs without extending an in-flight action proof.
    let native =
        NativeOperatorProvider::open_test_fixture(target.join("ea-native-operator"), false)
            .unwrap();
    let runtime = OperatorRuntime::open_with_test_native_and_posture(
        OperatorRuntimeConfig::load(&target.join("operator.json")).unwrap(),
        &target.join("independent-anchor.etb"),
        support::live_clock(),
        false,
        native,
        Arc::from(
            ea_key_provider::SupportMatrixRow::current_host()
                .unwrap()
                .posture_provider(),
        ),
    )
    .unwrap();
    let context = runtime.posture_target_context().unwrap();
    let exact = runtime
        .issue_posture_document(
            &context,
            ea_crypto::object_hash(b"T9 actual portable Desktop fixture prerequisites"),
            300_000,
        )
        .unwrap();
    runtime.import_posture_document(&exact).unwrap();
}

fn export_public(view: &ea_ui_contracts::RecoveryAdministrationView) {
    let wire = ea_desktop::commands::recovery::recovery_wire(view.clone()).unwrap();
    let exact = serde_json::to_vec_pretty(&wire).unwrap();
    let text = std::str::from_utf8(&exact).unwrap();
    for private in [
        "/tmp/",
        "/Users/",
        "Erika Beispiel",
        "Private Fixture",
        "passphrase-file",
        "pin-file",
    ] {
        assert!(
            !text.contains(private),
            "only public recovery progress crosses IPC"
        );
    }
    if let Some(path) = std::env::var_os("EA_T13_NATIVE_RECOVERY_VIEW_OUTPUT") {
        write_private(&PathBuf::from(path), &exact);
    }
}

#[test]
#[ignore = "actual V4 foreign-machine restore, every configured medium through Desktop IPC"]
fn portable_native_desktop_recovery_completes_each_medium_and_reopens_signed_status() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let _watch = BoundedPortableWatcher::open(&target);
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let runtime = host(&export, &target);
    let state = runtime.desktop_state();
    let before = recovery_read_core(&state).unwrap();
    assert!(
        before.last_success.is_some(),
        "the genuine preceding portable run is retained"
    );
    let started = recovery_start_core(&state).unwrap();
    let operation = started.run.unwrap().operation_id;
    let deadline = Instant::now() + Duration::from_secs(1_200);
    let mut requests = BTreeSet::new();
    let mut run_id = None;
    let terminal = loop {
        let view = recovery_read_core(&state).unwrap();
        let run = view.run.as_ref().unwrap();
        assert_eq!(run.operation_id, operation);
        if matches!(run.phase_code, 3..=6) {
            break view;
        }
        if run.phase_code == 1 {
            let request = run.request.as_ref().unwrap();
            assert!(
                requests.insert(request.request_id.clone()),
                "one submission per current request"
            );
            assert_eq!(request.index as usize, requests.len());
            assert_eq!(request.total as usize, inventory.media().len());
            assert_eq!(run.observations.len() + 1, requests.len());
            if let Some(previous) = &run_id {
                assert_eq!(previous, &request.run_id);
            } else {
                run_id = Some(request.run_id.clone());
            }
            retain_current_fixture_posture(&target);
            let next =
                recovery_submit_core(&state, &operation, &request.run_id, &request.request_id, 0)
                    .unwrap();
            assert_eq!(next.run.unwrap().operation_id, operation);
        }
        assert!(
            Instant::now() < deadline,
            "bounded actual native Desktop worker"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let run = terminal.run.as_ref().unwrap();
    assert_eq!(
        run.phase_code, 3,
        "every real configured medium should complete: {:?}",
        run.error_code
    );
    assert_eq!(requests.len(), inventory.media().len());
    assert_eq!(run.observations.len(), inventory.media().len());
    assert!(run.observations.iter().all(|row| row.result_code == 0
        && row.observed_thumbprint.as_ref() == Some(&row.request.expected_thumbprint)
        && row.error_code.is_none()));
    let report = run.report.clone().unwrap();
    assert!(report.completed && report.next_due_at_ms.unwrap() > report.finished_at_ms);
    let public: Value = serde_json::from_str(&report.exact_public_report_json).unwrap();
    assert_eq!(public["testId"], run_id.unwrap());
    assert_eq!(
        public["samples"].as_array().unwrap().len(),
        2,
        "both historical Writer samples are verified"
    );
    assert_eq!(terminal.last_success.as_ref(), Some(&report));
    assert_eq!(terminal.last_failure, before.last_failure);
    export_public(&terminal);
    drop(state);
    drop(runtime);
    let reopened = host(&export, &target);
    let durable = recovery_read_core(&reopened.desktop_state()).unwrap();
    assert_eq!(durable.last_success, Some(report));
    assert_eq!(durable.last_failure, before.last_failure);
    assert!(durable.run.is_none());
}

#[test]
#[ignore = "actual V4 Desktop cancellation at the first native medium wait"]
fn portable_native_desktop_first_wait_cancel_preserves_previous_signed_status() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let runtime = host(&export, &target);
    let state = runtime.desktop_state();
    let before = recovery_read_core(&state).unwrap();
    assert!(before.last_success.is_some());
    let operation = recovery_start_core(&state)
        .unwrap()
        .run
        .unwrap()
        .operation_id;
    let deadline = Instant::now() + Duration::from_secs(90);
    let request = loop {
        let view = recovery_read_core(&state).unwrap();
        let run = view.run.unwrap();
        assert_eq!(run.operation_id, operation);
        if run.phase_code == 1 {
            break run.request.unwrap();
        }
        assert!(
            run.phase_code < 3,
            "native worker reached an unexpected terminal state"
        );
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(request.index, 1);
    assert!(
        recovery_start_core(&state).is_err(),
        "the still-waiting worker retains the only run slot"
    );
    let mut cancelled = recovery_cancel_core(&state, &operation).unwrap();
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let run = cancelled.run.as_ref().unwrap();
        assert_eq!(run.operation_id, operation);
        assert!(run.report.is_none() && run.observations.is_empty());
        assert!(run.request.is_none());
        assert_eq!(cancelled.last_success, before.last_success);
        assert_eq!(cancelled.last_failure, before.last_failure);
        // The worker may already have returned before the command snapshot.
        // Phase7 only requests cancellation; phase5 is its actual final result.
        match run.phase_code {
            5 => break,
            7 => {}
            other => panic!("unexpected native cancellation phase: {other}"),
        }
        assert!(
            Instant::now() < deadline,
            "native worker completes cancellation"
        );
        std::thread::sleep(Duration::from_millis(100));
        cancelled = recovery_read_core(&state).unwrap();
    }
    assert!(
        recovery_submit_core(&state, &operation, &request.run_id, &request.request_id, 0).is_err()
    );
    export_public(&cancelled);
    drop(state);
    drop(runtime);
    let reopened = host(&export, &target);
    let durable = recovery_read_core(&reopened.desktop_state()).unwrap();
    assert_eq!(durable.last_success, before.last_success);
    assert_eq!(durable.last_failure, before.last_failure);
    assert!(durable.run.is_none());
}
