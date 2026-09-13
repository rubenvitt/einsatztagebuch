//! Actual configured Host, separate native Writer presence, and durable job.
use super::*;
use ea_desktop::commands::destruction::destruction_authenticate_custodian_core;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn configuration(f: &NativeDestructionFixture) -> (PathBuf, Vec<u8>) {
    let ArchiveBackendProfileV1::LocalPath(profile) = &f.profile else {
        panic!("local native fixture");
    };
    let KeySourceSpec::Container {
        path,
        passphrase_file,
    } = &f.key_source
    else {
        panic!("protected component container");
    };
    let exact = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "writer_operator_config": f.writer_config,
        "component_certificate_hash": hex(f.component.as_bytes()),
        "component_key_source": format!("container:{};passphrase-file={}", path.display(), passphrase_file.display()),
        "delivery": "no-registered-server",
        "holders": [{
            "archive_directory": f.archive,
            "filesystem_row_id": profile.filesystem_row_id,
            "capability_test_vector_id": profile.capability_test_vector_id,
            "custody_certificate_hash": hex(f.writer_certificate.as_bytes())
        }]
    })).unwrap();
    let path = f._directory.path().join("desktop-custodian.json");
    fs::write(&path, &exact).unwrap();
    (path, exact)
}
pub(super) fn configured(f: &NativeDestructionFixture, config: &Path) -> Arc<NativeDesktopRuntime> {
    let native = NativeOperatorProvider::open_test_fixture(
        f.admin_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    let controller = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.admin_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap();
    NativeDesktopRuntime::open_with_test_destruction_reopen_configuration(
        DesktopLaunchConfig {
            operator_config: f.admin_config.clone(),
            trust_anchor: f.anchor.clone(),
            writer_config: None,
            destruction_config: Some(config.to_owned()),
            recovery_config: None,
            administration_config: None,
        },
        controller,
        &f.writer_directory.join("ea-native-operator"),
    )
    .unwrap()
}

#[test]
fn native_configured_custodian_login_preserves_job_and_refuses_changed_configuration() {
    let f = NativeDestructionFixture::without_server();
    let (config, exact_config) = configuration(&f);
    let host = configured(&f, &config);
    let state = host.desktop_state();
    assert_eq!(
        destruction_authenticate_custodian_core(&state, &"11".repeat(16), &"22".repeat(32))
            .err()
            .unwrap()
            .code,
        "EA-DESKTOP-ADMINISTRATION-FORBIDDEN"
    );
    host.login().unwrap();
    let prepared =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let id = prepared["process"]["destructionId"].as_str().unwrap();
    let job = prepared["process"]["preflight"]["jobHash"]
        .as_str()
        .unwrap();
    assert_eq!(
        destruction_authenticate_custodian_core(&state, id, &"ff".repeat(32))
            .err()
            .unwrap()
            .code,
        "EA-DESTRUCTION-SECURITY-CONFLICT"
    );
    let authenticated =
        serde_json::to_value(destruction_authenticate_custodian_core(&state, id, job).unwrap())
            .unwrap();
    assert_eq!(
        authenticated, prepared,
        "login cannot start, resume or finalize the prepared job"
    );
    let inventory = ea_archive::ArchiveInventory::build(
        &ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap(),
    )
    .unwrap();
    assert!(!inventory.entries().is_empty());
    assert!(
        inventory.destroyed().is_empty(),
        "no local removal during login"
    );

    let mut changed: serde_json::Value = serde_json::from_slice(&exact_config).unwrap();
    changed["writer_operator_config"] = serde_json::to_value(&f.admin_config).unwrap();
    fs::write(&config, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert_eq!(
        destruction_authenticate_custodian_core(&state, id, job)
            .err()
            .unwrap()
            .code,
        "EA-DESKTOP-LAUNCH-CONFIG",
        "login cannot switch configured operator resources"
    );
    fs::write(&config, &exact_config).unwrap();
    let restored = serde_json::to_value(destruction_read_core(&state, Some(id)).unwrap()).unwrap();
    assert_eq!(restored, prepared);
    host.invalidate();
    assert_eq!(
        destruction_authenticate_custodian_core(&state, id, job)
            .err()
            .unwrap()
            .code,
        "EA-DESKTOP-ADMINISTRATION-FORBIDDEN"
    );
    drop(state);
    drop(host);
    let reopened = configured(&f, &config);
    reopened.login().unwrap();
    assert_eq!(
        serde_json::to_value(destruction_read_core(&reopened.desktop_state(), Some(id)).unwrap())
            .unwrap(),
        prepared
    );
}
