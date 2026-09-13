//! Read-only probes must preserve names and exact contents, even with a real owner.
#![cfg(any(
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod support;

use ea_archive::ArchiveBackend;
use ea_archive_fs::{
    CONTROL_FILES_V1, LocalPathBackend, LocalWriterLockDiagnosis as State,
    diagnose_local_writer_lock,
};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
};

fn snapshot(root: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    fn visit(root: &Path, at: &Path, out: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(at).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                out.push((path.strip_prefix(root).unwrap().to_owned(), Vec::new()));
                visit(root, &path, out);
            } else if kind.is_symlink() {
                out.push((
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read_link(&path)
                        .unwrap()
                        .as_os_str()
                        .as_encoded_bytes()
                        .to_vec(),
                ));
            } else {
                out.push((
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(&path).unwrap(),
                ));
            }
        }
    }
    let mut result = Vec::new();
    visit(root, root, &mut result);
    result.sort();
    result
}

#[cfg(unix)]
#[test]
fn missing_and_inert_diagnoses_preserve_all_names_and_bytes_and_release_probe() {
    let (_guard, root) = support::temp_root("lock-diagnosis");
    fs::create_dir(root.join("staging")).unwrap();
    fs::write(root.join("staging/opaque"), b"untouched archive bytes").unwrap();
    let before = snapshot(&root);
    assert_eq!(diagnose_local_writer_lock(&root), State::Missing);
    assert_eq!(snapshot(&root), before);
    let lock = root.join(CONTROL_FILES_V1[0]);
    fs::write(&lock, b"PID and age are not evidence").unwrap();
    let before = snapshot(&root);
    assert_eq!(diagnose_local_writer_lock(&root), State::AbandonedInert);
    assert_eq!(snapshot(&root), before);
    let backend = LocalPathBackend::open(
        root.clone(),
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .unwrap();
    let held = backend.acquire_writer_lock().unwrap();
    assert_eq!(diagnose_local_writer_lock(&root), State::LiveOwner);
    drop(held);
    let second = LocalPathBackend::open(
        root.clone(),
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .unwrap();
    assert!(second.acquire_writer_lock().is_ok());
    assert_eq!(fs::read(lock).unwrap(), b"PID and age are not evidence");
}

#[cfg(unix)]
#[test]
fn live_other_process_is_observed_without_releasing_its_lock() {
    let (_guard, root) = support::temp_root("lock-diagnosis-process");
    fs::write(root.join(CONTROL_FILES_V1[0]), b"persistent lock bytes").unwrap();
    let before = snapshot(&root);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "other_process_lock_holder",
            "--ignored",
            "--nocapture",
        ])
        .env("EA_LOCK_DIAGNOSIS_CHILD_ROOT", &root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut observed = Vec::new();
    let mut byte = [0];
    while !observed.ends_with(b"LOCK_READY\n") {
        assert_eq!(
            stdout.read(&mut byte).unwrap(),
            1,
            "child exited before lock acquisition"
        );
        observed.push(byte[0]);
    }
    for _ in 0..2 {
        assert_eq!(diagnose_local_writer_lock(&root), State::LiveOwner);
        assert_eq!(snapshot(&root), before);
    }
    child.stdin.take().unwrap().write_all(b"release").unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(diagnose_local_writer_lock(&root), State::AbandonedInert);
    assert_eq!(snapshot(&root), before);
}

#[test]
#[ignore = "only invoked as the lock-holder subprocess"]
fn other_process_lock_holder() {
    let root = std::env::var_os("EA_LOCK_DIAGNOSIS_CHILD_ROOT").unwrap();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(Path::new(&root).join(CONTROL_FILES_V1[0]))
        .unwrap();
    file.try_lock().unwrap();
    println!("LOCK_READY");
    std::io::stdout().flush().unwrap();
    let mut signal = Vec::new();
    std::io::stdin().read_to_end(&mut signal).unwrap();
    drop(file);
}

#[test]
fn absent_root_and_non_regular_lock_are_unreadable_without_creation() {
    let (_guard, root) = support::temp_root("lock-diagnosis-invalid");
    let missing = root.join("missing");
    assert_eq!(diagnose_local_writer_lock(&missing), State::Unreadable);
    assert!(!missing.exists());
    fs::create_dir(root.join(CONTROL_FILES_V1[0])).unwrap();
    let before = snapshot(&root);
    assert_eq!(diagnose_local_writer_lock(&root), State::Unreadable);
    assert_eq!(snapshot(&root), before);
}

#[cfg(unix)]
#[test]
fn symlink_root_or_lock_and_denied_permissions_are_conservatively_unreadable() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (_guard, root) = support::temp_root("lock-diagnosis-unreadable");
    let target = root.join("outside");
    fs::write(&target, b"outside bytes").unwrap();
    let lock = root.join(CONTROL_FILES_V1[0]);
    symlink(&target, &lock).unwrap();
    let before = snapshot(&root);
    assert_eq!(diagnose_local_writer_lock(&root), State::Unreadable);
    assert_eq!(snapshot(&root), before);
    fs::remove_file(&lock).unwrap();
    fs::write(&lock, b"private bytes").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o0)).unwrap();
    assert_eq!(diagnose_local_writer_lock(&root), State::Unreadable);
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = root.join("alias");
    symlink(&root, &alias).unwrap();
    assert_eq!(diagnose_local_writer_lock(&alias), State::Unreadable);
    assert_eq!(fs::read(target).unwrap(), b"outside bytes");
}

#[test]
fn existing_fifo_is_unreadable_without_waiting_for_a_writer() {
    let (_guard, root) = support::temp_root("lock-diagnosis-fifo");
    let lock = root.join(CONTROL_FILES_V1[0]);
    assert!(
        Command::new("mkfifo")
            .arg(&lock)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(diagnose_local_writer_lock(&root), State::Unreadable);
    use std::os::unix::fs::FileTypeExt as _;
    assert!(fs::symlink_metadata(lock).unwrap().file_type().is_fifo());
}
