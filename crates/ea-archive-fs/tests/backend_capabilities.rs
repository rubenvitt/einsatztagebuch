//! Die Dauerhaftigkeitsprimitive des lokalen Wirtbackends.
//!
//! Jeder Test nimmt die prozessweite Sperre und arbeitet auf einer eigenen
//! Temporaerwurzel; die Serialisierung liegt in `support::temp_root`, nicht in
//! einem `--test-threads=1` an der Kommandozeile.

mod support;

use ea_archive::{ArchiveBackend, ArchivePath, GRANTS_DIR_V1};
use ea_archive_fs::LocalPathBackend;

/// Ein Bestand auf einer frischen Temporaerwurzel.
fn backend(label: &str) -> (std::sync::MutexGuard<'static, ()>, LocalPathBackend) {
    let (guard, root) = support::temp_root(label);
    let backend = LocalPathBackend::open(
        root,
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .expect("der Bestand muss sich oeffnen lassen");
    (guard, backend)
}

#[test]
fn create_if_absent_is_idempotent_for_equal_bytes_and_rejects_a_byte_conflict() {
    let (_guard, backend) = backend("create-if-absent");
    let path = ArchivePath::in_dir(GRANTS_DIR_V1, "x.eag").expect("die Adresse ist gueltig");
    let first = support::signed_grant_a();
    let second = support::signed_grant_b();
    assert_ne!(
        first.as_bytes(),
        second.as_bytes(),
        "die beiden Grants MUESSEN sich unterscheiden, sonst belegt der Konflikt nichts"
    );
    backend.create_if_absent(&path, &first).unwrap();
    backend.create_if_absent(&path, &first).unwrap();
    assert_eq!(
        backend.create_if_absent(&path, &second).unwrap_err().code(),
        "EA-ARCHIVE-BYTE-CONFLICT"
    );
    assert_eq!(
        backend.read_for_test(path.as_str()).as_deref(),
        Some(first.as_bytes()),
        "der abgewiesene Schreibvorgang darf die Bytes nicht angetastet haben"
    );
}

#[test]
fn every_declared_capability_is_proven_on_the_host_filesystem() {
    let (_guard, backend) = backend("capabilities");
    let report = backend
        .run_capability_test(&support::capability_test_vector())
        .unwrap();
    assert!(report.exclusive_create_without_overwrite());
    assert!(report.byte_conflict_detection());
    assert!(report.same_filesystem_atomic_rename());
    assert!(report.file_flush() && report.directory_flush());
    assert!(report.exclusive_writer_lock());
    assert!(report.disconnect_and_resume_keeps_exact_bytes());
    assert!(report.all_proven());
}

#[test]
fn a_second_writer_lock_is_refused_and_released_on_drop() {
    let (_guard, backend) = backend("writer-lock");
    let held = backend.acquire_writer_lock().unwrap();
    assert_eq!(
        backend.acquire_writer_lock().unwrap_err().code(),
        "EA-ARCHIVE-ALREADY-LOCKED"
    );
    drop(held);
    assert!(backend.acquire_writer_lock().is_ok());
}

#[test]
fn a_rename_across_filesystems_is_refused_instead_of_copied() {
    let (_guard, backend) = backend("cross-filesystem");
    let staged = support::staged_path();
    let foreign = support::foreign_filesystem_path();
    backend
        .create_if_absent(&staged, &support::signed_grant_a())
        .unwrap();

    // Erst der Gegenbeweis: derselbe Aufruf innerhalb desselben Dateisystems
    // TRAEGT. Ohne ihn koennte die Ablehnung unten auch ein Backend sein, das
    // jeden Rename abweist.
    let inside = ArchivePath::in_dir(GRANTS_DIR_V1, "published.eag").expect("gueltige Adresse");
    backend.atomic_rename_same_fs(&staged, &inside).unwrap();
    assert!(backend.exists_for_test(inside.as_str()));

    backend.mark_foreign_filesystem_for_test(foreign.as_str());
    assert_eq!(
        backend
            .atomic_rename_same_fs(&inside, &foreign)
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-NOT-SAME-FILESYSTEM"
    );
    assert!(
        !backend.exists_for_test(foreign.as_str()),
        "ein abgewiesener Rename darf NICHTS kopiert haben"
    );
    assert!(
        backend.exists_for_test(inside.as_str()),
        "die Quelle MUSS unangetastet bleiben"
    );
}

#[test]
fn a_directory_flush_addresses_the_carrying_directory_and_not_the_file() {
    let (_guard, backend) = backend("directory-flush");
    let path = ArchivePath::in_dir(GRANTS_DIR_V1, "flushed.eag").expect("gueltige Adresse");
    backend
        .create_if_absent(&path, &support::signed_grant_a())
        .unwrap();
    backend.sync_file(&path).unwrap();
    backend.sync_directory(&path).unwrap();
    assert!(backend.directory_exists_for_test(GRANTS_DIR_V1));
    assert_eq!(
        backend.relative_paths_below_for_test(GRANTS_DIR_V1),
        vec!["grants/flushed.eag".to_owned()]
    );
}
