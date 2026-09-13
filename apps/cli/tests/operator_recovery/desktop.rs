//! Actual native Desktop composition must preserve the foreign-machine rule.
use super::*;
use ea_desktop::{
    commands::recovery::{recovery_read_core, recovery_start_core},
    runtime::{DesktopLaunchConfig, NativeDesktopRuntime},
    state::RuntimeSessionPort,
};
use std::ffi::OsString;

#[test]
fn native_desktop_recovery_worker_refuses_its_actual_source_machine_without_success() {
    let installed = RecoveryInstallation::new();
    let runtime = installed.open();
    let inventory_exact = installed.inventory_exact(&runtime);
    let inventory = KeyInventory::parse(&inventory_exact).unwrap();
    let mut service = RecoveryTestRuntime::new(runtime, installed.profile.clone()).unwrap();
    let directory = installed.directory.path();
    let snapshot = directory.join("desktop-snapshot.db");
    let phrase = SecretVec::new(b"actual desktop recovery fixture phrase".to_vec());
    let captured = service
        .capture_source(RecoverySourceCapture {
            inventory: &inventory,
            probes: installed.probes(&inventory),
            snapshot: &snapshot,
            passphrase: &phrase,
        })
        .unwrap();
    fs::write(
        directory.join("desktop-source.cbor"),
        captured.exact_envelope(),
    )
    .unwrap();
    fs::write(directory.join("desktop-inventory.json"), inventory_exact).unwrap();
    fs::write(
        directory.join("desktop-media.json"),
        br#"{"schemaId":"ea.recovery-media-sources/v1","media":[]}"#,
    )
    .unwrap();
    let ea_archive::ArchiveBackendProfileV1::LocalPath(profile) = &installed.profile else {
        panic!("fixture profile");
    };
    fs::write(directory.join("desktop-profile.json"),serde_json::to_vec(&json!({"kind":"localPath",
        "filesystemRowId":profile.filesystem_row_id,"capabilityTestVectorId":profile.capability_test_vector_id})).unwrap()).unwrap();
    write_private(
        &directory.join("desktop-passphrase"),
        b"actual desktop recovery fixture phrase",
    );
    let config = directory.join("desktop-recovery.json");
    fs::write(&config,serde_json::to_vec(&json!({"version":1,
        "key_inventory_path":"desktop-inventory.json","archive_profile_path":"desktop-profile.json",
        "media_sources_path":"desktop-media.json","restored_source_database_path":"desktop-restored.db",
        "initial_restore":{"exact_source_path":"desktop-source.cbor","snapshot_path":"desktop-snapshot.db",
            "passphrase_file":"desktop-passphrase"}})).unwrap()).unwrap();
    let launch = DesktopLaunchConfig::parse([
        OsString::from("--operator-config"),
        installed.config.clone().into_os_string(),
        OsString::from("--trust-anchor"),
        installed.anchor.clone().into_os_string(),
        OsString::from("--recovery-config"),
        config.into_os_string(),
    ])
    .unwrap()
    .unwrap();
    let host = NativeDesktopRuntime::open_with_test_runtime(launch, installed.open()).unwrap();
    host.login().unwrap();
    let state = host.desktop_state();
    let started = recovery_start_core(&state).unwrap();
    assert!(started.last_success.is_none());
    let id = started.run.unwrap().operation_id;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let final_view = loop {
        let view = recovery_read_core(&state).unwrap();
        let run = view.run.as_ref().unwrap();
        assert_eq!(run.operation_id, id);
        if run.phase_code >= 3 {
            break view;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bounded native worker"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let wire = ea_desktop::commands::recovery::recovery_wire(final_view.clone()).unwrap();
    if let Some(output) = std::env::var_os("EA_T13_NATIVE_RECOVERY_VIEW_OUTPUT") {
        fs::write(output, serde_json::to_vec_pretty(&wire).unwrap()).unwrap();
    }
    let run = final_view.run.unwrap();
    assert_eq!(run.phase_code, 6);
    assert_eq!(run.error_code.as_deref(), Some("EA-RECOVERY-TEST-MACHINE"));
    assert!(run.report.is_none());
    assert!(run.observations.is_empty());
    assert!(final_view.last_success.is_none());
    assert!(final_view.last_failure.is_none());
    assert!(!directory.join("desktop-restored.db").exists());
}
