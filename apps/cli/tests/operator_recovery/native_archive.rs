//! Actual native authority/SQLCipher constructor component test. The temp
//! directory is deliberately NOT evidence of a supported mounted filesystem.
use super::*;
use ea_admin::native_archive::NativeArchiveConfig;
use ea_archive::{ArchiveBackend, BoundArchiveProfilePolicyV1};
use ea_archive_fs::LocalPathBackend;

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
    ea_admin::native_archive::register_network_component(&runtime, NativeArchiveConfig{profile:installed.profile.clone(),local_commit_database_path:Some(runtime.database().path().to_owned())}).unwrap();
    let database_path=runtime.database().path().to_owned();
    assert!(runtime.head().policy_fields().allowed_archive_profile_hashes.contains(&installed.profile.profile_hash().unwrap()));
    let archive_config=NativeArchiveConfig {profile:installed.profile.clone(),local_commit_database_path:Some(database_path)};
    let recovery=RecoveryTestRuntime::with_archive_config(runtime,archive_config)
        .expect("actual native current authority plus exact existing SQLCipher component must open the explicitly configured profile");
    assert!(recovery.archive_profile_hash().unwrap()==installed.profile.profile_hash().unwrap());
}

/// EA-CNA-REC-1/REC-2: Die Netzprofil-Laufzeit entsteht nur über die
/// registrierte Komponente, und jede Recovery-Aktion nimmt vor allem anderen
/// den SQLCipher-Writer-Lock und den Writer-Lock des Netzziels. Die
/// Reihenfolge beider Locks ist über die öffentliche API nicht unterscheidbar;
/// beobachtbar ist, dass jeder der beiden Locks die Aktion sperrt und ein
/// gescheiterter Versuch den SQLCipher-Lock wieder freigibt.
#[test]
fn native_recovery_network_handle_holds_sqlcipher_then_remote_lock() {
    let installed=RecoveryInstallation::with_profile(None,false,Some(component_profile()));
    let runtime=installed.open();
    let config=NativeArchiveConfig{profile:installed.profile.clone(),local_commit_database_path:Some(runtime.database().path().to_owned())};
    let (_, component)=ea_admin::native_archive::register_network_component(&runtime,config.clone()).unwrap();
    let inventory=installed.inventory(&runtime);
    let policy=BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields());
    let mut recovery=RecoveryTestRuntime::with_archive_config(runtime,config).unwrap();
    let missing=installed.directory.path().join("never-restored.sqlite");
    let code=|recovery:&mut RecoveryTestRuntime| match recovery.reopen_restored_source(&inventory,&missing) {
        Ok(_) => panic!("a held Writer lock must refuse the recovery action"),
        Err(error) => error.code(),
    };

    let local=component.local_backend().acquire_writer_lock().unwrap();
    assert_eq!(code(&mut recovery),"EA-ARCHIVE-ALREADY-LOCKED","the SQLCipher Writer lock gates the action");
    drop(local);

    let remote_backend=LocalPathBackend::open_existing(installed.archive.clone(),installed.profile.clone(),&policy).unwrap();
    let remote=remote_backend.acquire_writer_lock().unwrap();
    assert_eq!(code(&mut recovery),"EA-ARCHIVE-ALREADY-LOCKED","the remote Writer lock gates the action");
    let released=component.local_backend().acquire_writer_lock()
        .expect("a refused attempt releases the SQLCipher lock it took first");
    drop(released);
    drop(remote);
    assert!(!missing.exists(),"a refused action touches no restore path");

    let refused=RecoveryTestRuntime::new(installed.open(),installed.profile.clone());
    assert_eq!(refused.err().map(|error|error.code()),Some("EA-RECOVERY-TEST-SOURCE"),"`new` never opens a network profile");
}
