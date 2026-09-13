//! A macOS ACL can deny directory listing without changing POSIX mode bits.
#![cfg(target_os = "macos")]
mod support;

use ea_archive_fs::{CONTROL_FILES_V1, LocalPathBackend};
use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf, process::Command};

struct DeniedDirectoryListing(PathBuf);

impl DeniedDirectoryListing {
    fn install(root: PathBuf) -> Self {
        assert!(
            Command::new("/bin/chmod")
                .args(["+a", "everyone deny list"])
                .arg(&root)
                .output()
                .unwrap()
                .status
                .success()
        );
        Self(root)
    }
}

impl Drop for DeniedDirectoryListing {
    fn drop(&mut self) {
        // Also removes our one ACL entry during assertion unwinding. This is
        // a fresh test TempDir; no inherited or unrelated ACL is removed.
        let _ = Command::new("/bin/chmod")
            .args(["-a", "everyone deny list"])
            .arg(&self.0)
            .output();
    }
}

#[test]
fn acl_denied_root_is_unavailable_even_when_missing_pointer_metadata_says_not_found() {
    let (_guard, root) = support::temp_root("pointer-root-acl");
    let backend = LocalPathBackend::open_existing(
        root.clone(),
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .unwrap();
    let original_mode = fs::metadata(&root).unwrap().permissions().mode();
    assert!(fs::read_dir(&root).is_ok());
    let acl = DeniedDirectoryListing::install(root.clone());
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode(),
        original_mode
    );
    assert_eq!(
        fs::read_dir(&root).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        fs::symlink_metadata(root.join(CONTROL_FILES_V1[1]))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound,
    );
    let result = backend.read_active_profile_pointer();
    drop(acl);
    assert!(
        fs::read_dir(&root).is_ok(),
        "the test ACL must be removed before cleanup"
    );
    assert!(
        result.is_err(),
        "an ACL-unreadable root must not yield an absent pointer"
    );
}
