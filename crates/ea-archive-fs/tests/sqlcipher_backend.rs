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

fn component_rows(db: &ea_local_store::EncryptedDatabase) -> Vec<i64> {
    [
        "SELECT count(*) FROM local_commit_object",
        "SELECT count(*) FROM local_commit_directory",
        "SELECT count(*) FROM local_commit_probe",
    ]
    .iter()
    .map(|sql| db.query_row(sql, &[]).unwrap().unwrap().integer(0).unwrap())
    .collect()
}

#[test]
fn sqlcipher_capability_measures_durability_flush_and_exclusive_lock_without_writes() {
    let (_guard, root) = support::temp_root("sqlcipher-backend-capability");
    let path = root.join("operator.sqlite");
    let db = database(&path);
    let archive = backend(db.clone(), 7, 2);
    archive
        .create_non_object_if_absent(&address("seen.eip"), b"before")
        .unwrap();
    let before = component_rows(&db);
    let report = archive.run_capability_test().unwrap();
    assert!(report.durable_wal_full());
    assert!(report.physical_flush());
    assert!(report.exclusive_writer_lock());
    assert!(report.all_proven());
    assert_eq!(
        component_rows(&db),
        before,
        "measurement writes no object, directory or probe row"
    );
    // Nach der Messung ist der Writer-Lock wieder frei.
    let _lock = archive.acquire_writer_lock().unwrap();
}

#[test]
fn sqlcipher_capability_reports_lock_contention_when_already_held() {
    let (_guard, root) = support::temp_root("sqlcipher-backend-capability-held");
    let path = root.join("operator.sqlite");
    let archive = backend(database(&path), 8, 2);
    let other = backend(database(&path), 9, 2);
    let held = other.acquire_writer_lock().unwrap();
    assert_eq!(
        archive.run_capability_test(),
        Err(ArchiveBackendError::AlreadyLocked)
    );
    drop(held);
    assert!(archive.run_capability_test().unwrap().all_proven());
}

/// Eine live gelesene Netzsicht, nur für die Bereinigung: Adresse → Bytes.
struct RemoteView(Vec<(String, Vec<u8>)>);
impl ArchiveSource for RemoteView {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(
            ea_archive::ArchiveBlob<'_>,
        ) -> Result<(), ea_archive::ArchiveError>,
    ) -> Result<(), ea_archive::ArchiveError> {
        for (path, bytes) in &self.0 {
            visitor(ea_archive::ArchiveBlob::new(path, bytes))?;
        }
        Ok(())
    }
}

fn staged_rows(archive: &SqlcipherArchiveBackend) -> Vec<String> {
    archive.staged_paths().unwrap()
}

/// EA-CNA-SRC-5: entfernt wird genau eine committed Zeile, deren Adresse am
/// Netzziel mit DENSELBEN Bytes liegt. Abweichende Bytes, fehlende Adressen,
/// Staging (auch bytegleich am Netzziel), Verzeichniszeilen und die Sonde
/// bleiben.
#[test]
fn prune_removes_only_committed_rows_identical_at_the_remote() {
    use ea_archive_fs::AtRestEncryptedStoreV1;
    let (_guard, root) = support::temp_root("sqlcipher-backend-prune");
    let path = root.join("operator.sqlite");
    let db = database(&path);
    let namespace = Hash32::try_from([0x31; 32].as_slice()).unwrap();
    let archive = SqlcipherArchiveBackend::open(
        SqliteCommitStore::new(db.clone(), namespace, 16, 1_048_576).unwrap(),
    )
    .unwrap();
    let published = address("000000000001_published.eip");
    let grant = ArchivePath::in_dir("grants/", "000000000001_published.eag").unwrap();
    let diverging = address("000000000002_diverging.eip");
    let unpublished = address("000000000003_unpublished.eip");
    let staging = address("000000000004_staged.eip.staging");
    for (address, bytes) in [
        (&published, &b"published-entry"[..]),
        (&grant, b"published-grant"),
        (&diverging, b"local-bytes"),
        (&unpublished, b"not-yet-at-remote"),
        (&staging, b"staged-bytes"),
    ] {
        archive.create_non_object_if_absent(address, bytes).unwrap();
    }
    SqliteCommitStore::open_existing(db.clone(), namespace, 16, 1_048_576)
        .unwrap()
        .put(".ea-at-rest-probe", b"probe")
        .unwrap();
    let before = component_rows(&db);
    let remote = RemoteView(vec![
        (published.as_str().to_owned(), b"published-entry".to_vec()),
        (grant.as_str().to_owned(), b"published-grant".to_vec()),
        (diverging.as_str().to_owned(), b"remote-bytes".to_vec()),
        (staging.as_str().to_owned(), b"staged-bytes".to_vec()),
        (
            "entries/000000000009_remote-only.eip".to_owned(),
            b"remote-only".to_vec(),
        ),
    ]);

    let lock = archive
        .try_writer_lock()
        .unwrap()
        .expect("der Lock ist frei");
    assert_eq!(archive.prune_published(&remote, &lock).unwrap(), 2);
    drop(lock);

    assert_eq!(
        contents(&archive),
        vec![
            (diverging.as_str().to_owned(), b"local-bytes".to_vec()),
            (
                unpublished.as_str().to_owned(),
                b"not-yet-at-remote".to_vec()
            ),
        ],
        "nur die zwei bytegleich veröffentlichten committed Zeilen fallen weg"
    );
    assert_eq!(staged_rows(&archive), vec![staging.as_str().to_owned()]);
    let after = component_rows(&db);
    assert_eq!(after[0], before[0] - 2, "genau zwei Objektzeilen weniger");
    assert_eq!(after[1], before[1], "Verzeichniszeilen bleiben");
    assert_eq!(after[2], before[2], "die Sonde bleibt");
    // Die bereinigte Komponente ist wieder beschreibbar und bleibt
    // idempotent: eine zweite Bereinigung findet nichts mehr.
    let lock = archive.try_writer_lock().unwrap().unwrap();
    assert_eq!(archive.prune_published(&remote, &lock).unwrap(), 0);
}

/// EA-CNA-SRC-5: ist der Writer-Lock belegt, liefert `try_writer_lock`
/// `None` ohne Fehler, und ohne Lock gibt es keine Bereinigung.
#[test]
fn prune_is_skipped_when_the_writer_lock_is_held() {
    let (_guard, root) = support::temp_root("sqlcipher-backend-prune-held");
    let path = root.join("operator.sqlite");
    let archive = backend(database(&path), 0x32, 4);
    let other = backend(database(&path), 0x33, 4);
    let published = address("000000000001_published.eip");
    archive
        .create_non_object_if_absent(&published, b"published-entry")
        .unwrap();
    let remote = RemoteView(vec![(
        published.as_str().to_owned(),
        b"published-entry".to_vec(),
    )]);
    let held = other.acquire_writer_lock().unwrap();
    assert!(
        archive.try_writer_lock().unwrap().is_none(),
        "ein fremd gehaltener Lock ist kein Fehler, sondern kein Lock"
    );
    assert_eq!(contents(&archive).len(), 1, "nichts wurde bereinigt");
    drop(held);
    let lock = archive.try_writer_lock().unwrap().expect("wieder frei");
    assert_eq!(archive.prune_published(&remote, &lock).unwrap(), 1);
    assert!(contents(&archive).is_empty());
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
