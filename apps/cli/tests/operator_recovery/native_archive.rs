//! Actual native authority/SQLCipher constructor component test. The temp
//! directory is deliberately NOT evidence of a supported mounted filesystem.
use super::*;
use ea_admin::native_archive::NativeArchiveConfig;

fn component_profile() -> ea_archive::ArchiveBackendProfileV1 {
    ea_archive::ArchiveBackendProfileV1::ControlledNetworkPath(ea_archive::ControlledNetworkProfileV1 {
        filesystem_row_id: "component-only-not-a-mounted-network-row".into(),
        protocol_id: "SMB3".into(), server_product: "component-fixture".into(), server_version: "1".into(),
        mount_options: vec!["component-only".into()], failover_config_id: "component-no-failover".into(),
        capability_test_vector_id: "native-recovery-cap-v1".into(), queue_max_objects: 10000,
        queue_max_bytes: 64 * 1024 * 1024, resume_backoff_initial_ms: 1000,
        resume_backoff_max_ms: 5000, resume_max_attempts: 3,
    })
}

#[test]
fn native_recovery_opens_exact_policy_bound_sqlcipher_component_without_profile_relabeling() {
    let installed=RecoveryInstallation::with_profile(None,false,Some(component_profile()));
    let runtime=installed.open();
    let database_path=runtime.database().path().to_owned();
    assert!(runtime.head().policy_fields().allowed_archive_profile_hashes.contains(&installed.profile.profile_hash().unwrap()));
    let archive_config=NativeArchiveConfig {profile:installed.profile.clone(),local_commit_database_path:Some(database_path)};
    let recovery=RecoveryTestRuntime::with_archive_config(runtime,archive_config)
        .expect("actual native current authority plus exact existing SQLCipher component must open the explicitly configured profile");
    assert!(recovery.archive_profile_hash().unwrap()==installed.profile.profile_hash().unwrap());
}
