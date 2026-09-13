//! Actual filesystem reads; no activation authority is inferred from a pointer.
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

use ea_archive_fs::{CONTROL_FILES_V1, LocalPathBackend};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn open(root: &Path) -> LocalPathBackend {
    LocalPathBackend::open_existing(
        root.to_owned(),
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .unwrap()
}
fn exact() -> Vec<u8> {
    let mut bytes = vec![0x83, 1, 0x58, 32];
    bytes.extend_from_slice(&[0x5a; 32]);
    bytes.extend_from_slice(&[0x1b, 255, 255, 255, 255, 255, 255, 255, 255]);
    bytes
}
fn names(root: &Path) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    paths
}

#[test]
fn only_a_missing_pointer_under_an_existing_root_is_absent() {
    let (_guard, root) = support::temp_root("pointer-absent");
    let backend = open(&root);
    let before = names(&root);
    assert!(backend.read_active_profile_pointer().unwrap().is_none());
    assert_eq!(names(&root), before);
    let detached = root.with_extension("detached");
    fs::rename(&root, &detached).unwrap();
    assert!(backend.read_active_profile_pointer().is_err());
    assert!(!root.exists());
    fs::rename(&detached, &root).unwrap();
}

#[test]
fn reads_the_maximum_canonical_pointer_without_changing_original_bytes() {
    let (_guard, root) = support::temp_root("pointer-exact");
    let backend = open(&root);
    let path = root.join(CONTROL_FILES_V1[1]);
    fs::write(&path, exact()).unwrap();
    let before = names(&root);
    let pointer = backend.read_active_profile_pointer().unwrap().unwrap();
    assert_eq!(pointer.generation(), u64::MAX);
    assert_eq!(pointer.active_profile_hash().as_bytes(), &[0x5a; 32]);
    assert_eq!(fs::read(&path).unwrap(), exact());
    assert_eq!(backend.active_profile_pointer_bytes().unwrap(), exact());
    assert_eq!(names(&root), before);
}

#[test]
fn corrupt_empty_oversized_and_noncanonical_pointers_are_errors_not_absence() {
    let (_guard, root) = support::temp_root("pointer-corrupt");
    let backend = open(&root);
    let path = root.join(CONTROL_FILES_V1[1]);
    let mut noncanonical = vec![0x83, 0x18, 1];
    noncanonical.extend_from_slice(&exact()[2..36]);
    noncanonical.push(0);
    for bytes in [vec![], vec![0x83, 1], vec![0; 46], noncanonical] {
        fs::write(&path, &bytes).unwrap();
        assert!(backend.read_active_profile_pointer().is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn symlinks_directories_and_unreadable_files_never_become_valid_or_absent() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (_guard, root) = support::temp_root("pointer-unreadable");
    let backend = open(&root);
    let path = root.join(CONTROL_FILES_V1[1]);
    let target = root.join("outside");
    fs::write(&target, exact()).unwrap();
    symlink(&target, &path).unwrap();
    assert!(backend.read_active_profile_pointer().is_err());
    fs::remove_file(&path).unwrap();
    symlink(root.join("does-not-exist"), &path).unwrap();
    assert!(backend.read_active_profile_pointer().is_err());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(backend.read_active_profile_pointer().is_err());
    fs::remove_dir(&path).unwrap();
    fs::write(&path, exact()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
    assert!(backend.read_active_profile_pointer().is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&target).unwrap(), exact());
    let root_permissions = fs::metadata(&root).unwrap().permissions();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o0)).unwrap();
    assert!(backend.read_active_profile_pointer().is_err());
    fs::set_permissions(&root, root_permissions).unwrap();
    let detached = root.with_extension("detached");
    fs::rename(&root, &detached).unwrap();
    symlink(&detached, &root).unwrap();
    assert!(backend.read_active_profile_pointer().is_err());
    fs::remove_file(&root).unwrap();
    fs::rename(&detached, &root).unwrap();
}

#[test]
fn fifo_pointer_returns_without_waiting_for_a_writer() {
    let (_guard, root) = support::temp_root("pointer-fifo");
    let _backend = open(&root);
    let path = root.join(CONTROL_FILES_V1[1]);
    assert!(
        Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "fifo_read_child"])
        .env("EA_POINTER_TEST_ROOT", &root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("pointer read blocked on a FIFO");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    use std::os::unix::fs::FileTypeExt as _;
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_fifo());
}

#[test]
#[ignore = "invoked by the bounded FIFO parent"]
fn fifo_read_child() {
    let root = std::env::var_os("EA_POINTER_TEST_ROOT").unwrap();
    assert!(
        open(Path::new(&root))
            .read_active_profile_pointer()
            .is_err()
    );
}
