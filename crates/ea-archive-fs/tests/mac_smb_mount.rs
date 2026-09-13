//! Explicit opt-in test of an already mounted, isolated Mac Samba fixture.
//! This does not create/stop/remount servers or assert native Writer readiness.
#![cfg(target_os = "macos")]
mod support;

use ea_archive::{
    ArchiveBackendProfileV1, ArchivePath, BoundArchiveProfilePolicyV1, ControlledNetworkProfileV1,
    GRANTS_DIR_V1,
};
use ea_archive_fs::{
    AtRestEncryptedStoreV1, ControlledNetworkBackend, LocalCommitComponentV1, SqliteCommitStore,
};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::EncryptedDatabase;
use ea_types::Hash32;
use std::{fs, os::unix::fs::MetadataExt, path::PathBuf, process::Command, sync::Arc};

fn measured_profile() -> ArchiveBackendProfileV1 {
    let mut options = [
        "automounted",
        "nobrowse",
        "nodev",
        "noexec",
        "nodatacache",
        "nomdatacache",
        "noowners",
        "nosuid",
        "soft",
    ]
    .map(str::to_owned)
    .to_vec();
    options.sort();
    ArchiveBackendProfileV1::ControlledNetworkPath(ControlledNetworkProfileV1 {
        filesystem_row_id: "macos-27-smb3.1.1-samba4.19.5-btrfs-fixture".into(),
        protocol_id: "smb-3.1.1".into(),
        server_product: "samba".into(),
        server_version: "4.19.5-Ubuntu".into(),
        mount_options: options,
        failover_config_id: "single-test-container-persistent-volume".into(),
        capability_test_vector_id: "drk250-mac-smb-20260913".into(),
        queue_max_objects: 64,
        queue_max_bytes: 1_048_576,
        resume_backoff_initial_ms: 10,
        resume_backoff_max_ms: 100,
        resume_max_attempts: 3,
    })
}

fn require_mount(root: &std::path::Path) {
    let output = Command::new("/sbin/mount").output().unwrap();
    assert!(output.status.success());
    let needle = format!(" on {} ", root.display());
    let entries: Vec<_> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .filter(|line| line.contains(&needle))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "refuse fallback into an unmounted local directory"
    );
    assert!(entries[0].starts_with("//guest:@127.0.0.1:59445/archive on "));
    assert!(entries[0].contains("(smbfs,"));
    assert!(root.starts_with("/private/tmp"));
    assert!(
        root.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("drk250-smb-mount-")
    );
    assert!(fs::symlink_metadata(root).unwrap().is_dir());
}

#[test]
#[ignore = "requires explicitly prepared isolated Mac SMB3.1.1 fixture and EA_TEST_MAC_SMB_MOUNT"]
fn actual_unqualified_smb_backend_refuses_flush_and_preserves_local_originals() {
    let mount = PathBuf::from(
        std::env::var_os("EA_TEST_MAC_SMB_MOUNT").expect("explicit isolated test mount required"),
    );
    require_mount(&mount);
    let (_guard, local) = support::temp_root("actual-mac-smb-sqlcipher");
    assert_ne!(
        fs::metadata(&mount).unwrap().dev(),
        fs::metadata(&local).unwrap().dev()
    );
    let remote = mount.join(format!("rust-backend-{}", std::process::id()));
    fs::create_dir(&remote).expect("fresh own remote subdirectory");
    let provider = InMemoryKeyProvider::new_for_test([0x73; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let path = local.join("operator.sqlite");
    let database = Arc::new(EncryptedDatabase::open(&path, &provider, &key).unwrap());
    let namespace = Hash32::try_from([0x74; 32].as_slice()).unwrap();
    let store = SqliteCommitStore::new(database.clone(), namespace, 64, 1_048_576).unwrap();
    let grant = support::signed_grant_a();
    let relative = ArchivePath::in_dir(GRANTS_DIR_V1, "exact.eag").unwrap();
    store.put(relative.as_str(), grant.as_bytes()).unwrap();
    assert!(
        !remote
            .join(relative.as_str())
            .try_exists()
            .expect("initial remote absence must be observable"),
        "committed original starts only in local SQLCipher"
    );
    let profile = measured_profile();
    let policy = BoundArchiveProfilePolicyV1::from_policy(&support::policy_with(vec![
        support::profile_hash(&profile),
    ]));
    let carrier = ControlledNetworkBackend::open_local_component(
        remote.clone(),
        Some(LocalCommitComponentV1::new(path.clone(), Box::new(store))),
        profile,
        &policy,
    )
    .unwrap();
    // The measured Samba/Mac combination refuses full sync.
    // Rust 1.95 File::sync_all uses F_FULLFSYNC on this host.
    // Do not turn the earlier successful POSIX fsync observation into admission.
    assert_eq!(
        carrier.connect_existing(&policy).unwrap_err().code(),
        "EA-ARCHIVE-FLUSH-FAILED"
    );
    assert!(
        !remote
            .join(relative.as_str())
            .try_exists()
            .expect("remote absence after refused flush must be observable")
    );
    assert_eq!(
        carrier.local_commit().read(relative.as_str()).unwrap(),
        grant.as_bytes()
    );
    drop(carrier);
    drop(database);
    require_mount(&mount);
    let reopened = Arc::new(EncryptedDatabase::open_existing(&path, &provider, &key).unwrap());
    let store = SqliteCommitStore::open_existing(reopened, namespace, 64, 1_048_576).unwrap();
    assert_eq!(store.get(relative.as_str()).unwrap(), grant.as_bytes());
    assert!(
        !remote
            .join(relative.as_str())
            .try_exists()
            .expect("remote absence after local reopen must be observable")
    );
    assert_eq!(
        store.at_rest_contains(relative.as_str(), grant.as_bytes()),
        Some(false)
    );
    println!(
        "unsupported SMB backend refused; reopened SQLCipher retains {} exact grant bytes; no positive capability or native activation claim",
        grant.as_bytes().len()
    );
}
