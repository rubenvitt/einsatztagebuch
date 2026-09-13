//! Local temporary-directory fixtures only: no network mount or race guarantee.
mod support;

use ea_archive::{ArchiveBackend, ArchivePath};
use ea_archive_fs::{
    AtRestEncryptedStoreV1, CapabilityTestVectorV1, ControlledNetworkBackend,
    LocalCommitComponentV1, LocalPathBackend, SqliteCommitStore,
};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::EncryptedDatabase;
use ea_types::Hash32;
use std::{fs, sync::Arc};

#[test]
fn temp_fixture_sqlcipher_local_open_and_failed_connect_preserve_exact_bytes_on_reopen() {
    let (_guard, root) = support::temp_root("local-only-sqlcipher");
    let provider = InMemoryKeyProvider::new_for_test([0x71; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let path = root.join("operator.sqlite");
    let database = Arc::new(EncryptedDatabase::open(&path, &provider, &key).unwrap());
    let namespace = Hash32::try_from([0x72; 32].as_slice()).unwrap();
    let store = SqliteCommitStore::new(database.clone(), namespace, 4, 1024).unwrap();
    store
        .put("entries/private.eip", b"private exact original")
        .unwrap();
    let network = root.join("missing-parent/network");
    let policy = support::policy_allowing_controlled_network();
    let carrier = ControlledNetworkBackend::open_local_component(
        network.clone(),
        Some(LocalCommitComponentV1::new(path.clone(), Box::new(store))),
        support::controlled_network_profile(),
        &policy,
    )
    .unwrap();
    assert!(!network.parent().unwrap().exists());
    assert!(carrier.connect_existing(&policy).is_err());
    assert!(!network.parent().unwrap().exists());
    assert_eq!(
        carrier.local_commit().read("entries/private.eip").unwrap(),
        b"private exact original"
    );
    fs::create_dir_all(&network).unwrap();
    assert!(
        carrier
            .connect_existing(&support::policy_allowing_nothing())
            .is_err()
    );
    assert_eq!(fs::read_dir(&network).unwrap().count(), 0);
    let connected = carrier.connect_existing(&policy).unwrap();
    assert_eq!(connected.root(), network);
    assert!(network.join("README-FORMAT.txt").is_file());
    drop(connected);
    drop(carrier);
    drop(database);
    let reopened = Arc::new(EncryptedDatabase::open_existing(&path, &provider, &key).unwrap());
    let store = SqliteCommitStore::new(reopened, namespace, 4, 1024).unwrap();
    assert_eq!(
        store.get("entries/private.eip").unwrap(),
        b"private exact original"
    );
    assert_eq!(
        store.at_rest_contains("entries/private.eip", b"private exact original"),
        Some(false)
    );
}

#[test]
fn temp_fixture_local_policy_refusal_precedes_probe_and_remote_access() {
    let (_guard, root) = support::temp_root("local-only-policy");
    let local = root.join("local");
    let remote = root.join("remote");
    assert!(
        ControlledNetworkBackend::open_local_component(
            remote.clone(),
            Some(support::encrypted_local_commit(local.clone())),
            support::controlled_network_profile(),
            &support::policy_allowing_nothing()
        )
        .is_err()
    );
    assert!(!local.exists());
    assert!(!remote.exists());
    fs::write(&remote, b"not a directory").unwrap();
    let carrier = ControlledNetworkBackend::open_local_component(
        remote.clone(),
        Some(support::encrypted_local_commit(local)),
        support::controlled_network_profile(),
        &support::policy_allowing_controlled_network(),
    )
    .unwrap();
    assert!(
        carrier
            .connect_existing(&support::policy_allowing_controlled_network())
            .is_err()
    );
    assert_eq!(fs::read(remote).unwrap(), b"not a directory");
}

#[test]
fn temp_fixture_existing_mode_never_recreates_removed_root_or_missing_parents() {
    let (_guard, root) = support::temp_root("existing-root");
    let remote = root.join("remote");
    let policy = support::policy_allowing_controlled_network();
    assert!(
        LocalPathBackend::open_existing(
            remote.clone(),
            support::controlled_network_profile(),
            &policy
        )
        .is_err()
    );
    assert!(!remote.exists());
    fs::create_dir(&remote).unwrap();
    let backend = LocalPathBackend::open_existing(
        remote.clone(),
        support::controlled_network_profile(),
        &policy,
    )
    .unwrap();
    let from = ArchivePath::in_dir("recovery-reports/", "from").unwrap();
    let to = ArchivePath::in_dir("recovery-reports/", "to").unwrap();
    let deep = ArchivePath::in_dir("entries/", "missing/parent/object").unwrap();
    assert!(
        backend
            .create_non_object_if_absent(&deep, b"bytes")
            .is_err()
    );
    assert!(!remote.join("entries").exists());
    assert!(
        backend
            .create_directory_if_absent("trust/registry-events/")
            .is_err()
    );
    assert!(!remote.join("trust").exists());
    assert!(
        backend
            .atomic_rename_same_fs(
                &from,
                &ArchivePath::in_dir("trust/registry-events/", "target").unwrap()
            )
            .is_err()
    );
    assert!(!remote.join("trust").exists());
    fs::remove_dir_all(&remote).unwrap();
    assert!(
        backend
            .create_non_object_if_absent(
                &ArchivePath::at_layout_file("README-FORMAT.txt").unwrap(),
                b"bytes"
            )
            .is_err()
    );
    assert!(
        backend
            .create_non_object_if_absent(&from, b"bytes")
            .is_err()
    );
    assert!(backend.atomic_rename_same_fs(&from, &to).is_err());
    assert!(
        backend
            .create_directory_if_absent("recovery-reports/")
            .is_err()
    );
    assert!(ea_archive_fs::materialize_format_package(&backend).is_err());
    assert!(
        backend
            .run_capability_test(&CapabilityTestVectorV1::new("probe", b"bytes").unwrap())
            .is_err()
    );
    assert!(!remote.exists());
}

#[test]
fn temp_fixture_existing_open_propagates_lock_io_but_defers_real_contention() {
    let (_guard, root) = support::temp_root("existing-lock-errors");
    let remote = root.join("remote");
    fs::create_dir(&remote).unwrap();
    fs::create_dir(remote.join(".ea-writer.lock")).unwrap();
    let profile = support::controlled_network_profile();
    let policy = support::policy_allowing_controlled_network();
    assert_eq!(
        LocalPathBackend::open_existing(remote.clone(), profile.clone(), &policy).unwrap_err(),
        ea_archive::ArchiveBackendError::Io
    );
    fs::remove_dir(remote.join(".ea-writer.lock")).unwrap();
    let backend =
        LocalPathBackend::open_existing(remote.clone(), profile.clone(), &policy).unwrap();
    let _lock = backend.acquire_writer_lock().unwrap();
    let contender = LocalPathBackend::open_existing(remote, profile, &policy).unwrap();
    assert_eq!(
        contender.format_package_outcome(),
        ea_archive_fs::FormatPackageOutcomeV1::Deferred
    );
}
