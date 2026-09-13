//! Component fixtures: real SQLCipher and OS file locks, no mounted network claim.
mod support;

use ea_archive::{ArchiveBackend, ArchiveBackendError, ArchivePath, ArchiveSource};
use ea_archive_fs::{SqlcipherArchiveBackend, SqliteCommitStore};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::EncryptedDatabase;
use ea_types::Hash32;
use std::{path::Path, sync::Arc};

fn database(path: &Path) -> Arc<EncryptedDatabase> {
    let provider = InMemoryKeyProvider::new_for_test([0x91; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    Arc::new(EncryptedDatabase::open(path, &provider, &key).unwrap())
}
fn backend(database: Arc<EncryptedDatabase>, marker: u8, limit: u64) -> SqlcipherArchiveBackend {
    SqlcipherArchiveBackend::open(
        SqliteCommitStore::new(
            database,
            Hash32::try_from([marker; 32].as_slice()).unwrap(),
            limit,
            1_048_576,
        )
        .unwrap(),
    )
    .unwrap()
}
fn address(name: &str) -> ArchivePath {
    ArchivePath::in_dir("entries/", name).unwrap()
}
fn contents(source: &dyn ArchiveSource) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    source
        .visit_blobs(&mut |blob| {
            rows.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .unwrap();
    rows
}

#[test]
fn exact_sqlcipher_rename_preserves_source_on_conflict_and_survives_reopen() {
    let (_guard, root) = support::temp_root("sqlcipher-backend-rename");
    let path = root.join("operator.sqlite");
    let db = database(&path);
    let archive = backend(db.clone(), 1, 2);
    let staging = address("one.eip.staging");
    let target = address("one.eip");
    archive
        .create_non_object_if_absent(&staging, b"exact-original")
        .unwrap();
    archive.sync_file(&staging).unwrap();
    archive.sync_directory(&staging).unwrap();
    assert_eq!(archive.staged_paths().unwrap(), vec![staging.as_str()]);
    assert!(
        contents(&archive).is_empty(),
        "staging never becomes chain progress"
    );
    archive.atomic_rename_same_fs(&staging, &target).unwrap();
    archive.atomic_rename_same_fs(&target, &target).unwrap();
    assert_eq!(
        contents(&archive),
        vec![(target.as_str().into(), b"exact-original".to_vec())],
        "same-path rename must not delete bytes"
    );
    archive
        .create_non_object_if_absent(&staging, b"different-original")
        .unwrap();
    assert_eq!(
        archive.atomic_rename_same_fs(&staging, &target),
        Err(ArchiveBackendError::ByteConflict)
    );
    assert_eq!(archive.staged_paths().unwrap(), vec![staging.as_str()]);
    let mut managed = Vec::new();
    archive
        .visit_managed_blobs(&mut |blob| {
            managed.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        managed.len(),
        2,
        "custody enumeration includes remaining staging"
    );
    drop(archive);
    drop(db);
    let reopened = backend(database(&path), 1, 2);
    assert_eq!(
        contents(&reopened),
        vec![(target.as_str().into(), b"exact-original".to_vec())]
    );
    reopened.remove_if_present(&staging).unwrap();
    reopened
        .create_non_object_if_absent(&staging, b"exact-original")
        .unwrap();
    reopened.atomic_rename_same_fs(&staging, &target).unwrap();
    assert!(reopened.staged_paths().unwrap().is_empty());
    assert!(
        reopened
            .atomic_rename_same_fs(&address("absent.eip"), &address("absent.eip"))
            .is_err()
    );
}

#[test]
fn namespace_limits_and_measured_durability_guards_cannot_be_bypassed() {
    let (_guard, root) = support::temp_root("sqlcipher-backend-guards");
    let path = root.join("operator.sqlite");
    let db = database(&path);
    let archive = backend(db.clone(), 2, 1);
    let staging = address("one.eip.staging");
    let target = address("one.eip");
    archive
        .create_directory_if_absent("recovery-reports/")
        .unwrap();
    assert_eq!(
        database(&path)
            .query_row(
                "SELECT count(*) FROM local_commit_directory WHERE directory='recovery-reports/'",
                &[]
            )
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1,
        "empty layout directory is durable state after independent reopen"
    );
    assert_eq!(
        archive.create_directory_if_absent("arbitrary/"),
        Err(ArchiveBackendError::Path)
    );
    archive
        .create_non_object_if_absent(&staging, b"one")
        .unwrap();
    assert_eq!(
        archive.create_non_object_if_absent(&address("two.eip"), b"two"),
        Err(ArchiveBackendError::PendingPublication)
    );
    archive.atomic_rename_same_fs(&staging, &target).unwrap();
    assert!(contents(&backend(database(&path), 3, 1)).is_empty());
    assert_eq!(
        archive.sync_file(&address("missing.eip")),
        Err(ArchiveBackendError::FlushFailed)
    );
    db.execute("PRAGMA synchronous = OFF", &[]).unwrap();
    assert_eq!(
        archive.sync_file(&target),
        Err(ArchiveBackendError::FlushFailed)
    );
    assert_eq!(
        archive.sync_directory(&target),
        Err(ArchiveBackendError::FlushFailed)
    );
    assert_eq!(
        archive.remove_if_present(&target),
        Err(ArchiveBackendError::FlushFailed)
    );
    assert_eq!(
        archive.atomic_rename_same_fs(&target, &staging),
        Err(ArchiveBackendError::FlushFailed)
    );
    db.execute("PRAGMA synchronous = FULL", &[]).unwrap();
    assert_eq!(
        contents(&archive),
        vec![(target.as_str().into(), b"one".to_vec())]
    );
}

#[test]
fn failed_sql_rename_rolls_back_both_names_without_exposing_partial_commit() {
    let (_guard, root) = support::temp_root("sqlcipher-backend-rollback");
    let db = database(&root.join("operator.sqlite"));
    let archive = backend(db.clone(), 6, 1);
    let staging = address("one.eip.staging");
    let target = address("one.eip");
    archive
        .create_non_object_if_absent(&staging, b"exact-before-fault")
        .unwrap();
    db.execute("CREATE TEMP TRIGGER fixture_block_rename BEFORE DELETE ON local_commit_object BEGIN SELECT RAISE(ABORT,'fixture rename interruption'); END",&[]).unwrap();
    assert!(archive.atomic_rename_same_fs(&staging, &target).is_err());
    assert!(contents(&archive).is_empty());
    assert_eq!(archive.staged_paths().unwrap(), vec![staging.as_str()]);
    db.execute("DROP TRIGGER fixture_block_rename", &[])
        .unwrap();
    archive.atomic_rename_same_fs(&staging, &target).unwrap();
    assert_eq!(
        contents(&archive),
        vec![(target.as_str().into(), b"exact-before-fault".to_vec())]
    );
}

#[test]
fn writer_lock_spans_independent_connections_and_process_crash() {
    let (_guard, root) = support::temp_root("sqlcipher-backend-process");
    let path = root.join("operator.sqlite");
    let archive = backend(database(&path), 4, 2);
    let second = backend(database(&path), 5, 2);
    let held = archive.acquire_writer_lock().unwrap();
    assert!(
        matches!(
            second.acquire_writer_lock(),
            Err(ArchiveBackendError::AlreadyLocked)
        ),
        "one database cannot admit a second Writer through another namespace"
    );
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "independent_process_fixture",
            "--nocapture",
        ])
        .env("EA_SQLCIPHER_COMPONENT_PATH", &path)
        .env("EA_SQLCIPHER_COMPONENT_MODE", "contended")
        .status()
        .unwrap();
    assert!(result.success());
    drop(held);
    let marker = root.join("child-committed");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "independent_process_fixture",
            "--nocapture",
        ])
        .env("EA_SQLCIPHER_COMPONENT_PATH", &path)
        .env("EA_SQLCIPHER_COMPONENT_MODE", "crash")
        .env("EA_SQLCIPHER_COMPONENT_MARKER", &marker)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let observed = marker.exists();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        observed,
        "child must acknowledge actual durable write before termination"
    );
    drop(archive);
    drop(second);
    let reopened = backend(database(&path), 4, 2);
    let _lock = reopened.acquire_writer_lock().unwrap();
    assert_eq!(
        contents(&reopened),
        vec![("entries/committed.eip".into(), b"crash-survivor".to_vec())]
    );
}

#[test]
#[ignore = "child of the SQLCipher component process test"]
fn independent_process_fixture() {
    let Some(path) = std::env::var_os("EA_SQLCIPHER_COMPONENT_PATH") else {
        return;
    };
    let archive = backend(database(Path::new(&path)), 4, 2);
    if std::env::var("EA_SQLCIPHER_COMPONENT_MODE").unwrap() == "contended" {
        assert!(matches!(
            archive.acquire_writer_lock(),
            Err(ArchiveBackendError::AlreadyLocked)
        ));
        return;
    }
    let _lock = archive.acquire_writer_lock().unwrap();
    let staging = address("committed.eip.staging");
    let target = address("committed.eip");
    archive
        .create_non_object_if_absent(&staging, b"crash-survivor")
        .unwrap();
    archive.sync_file(&staging).unwrap();
    archive.sync_directory(&staging).unwrap();
    archive.atomic_rename_same_fs(&staging, &target).unwrap();
    archive.sync_directory(&target).unwrap();
    std::fs::write(
        std::env::var_os("EA_SQLCIPHER_COMPONENT_MARKER").unwrap(),
        b"committed",
    )
    .unwrap();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
