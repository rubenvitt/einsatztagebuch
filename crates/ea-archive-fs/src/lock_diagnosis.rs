//! Technical observation of an existing local writer lock; never repair authority.

use std::{fs, path::Path};

use crate::local_path::CONTROL_FILES_V1;

/// A momentary, path-free observation. None of these states authorizes mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalWriterLockDiagnosis {
    /// The existing root has no writer lock file. Nothing was created.
    Missing,
    /// The existing file admitted the kernel lock; the probe has released it.
    /// This says nothing about a later writer and requires no file repair.
    AbandonedInert,
    /// The kernel reported contention. The owner is not inferred from file bytes.
    LiveOwner,
    /// Root/file validation, opening, identity checks, or locking was inconclusive.
    Unreadable,
}

/// Observes a local lock without opening an archive backend or creating any file.
///
/// The probe never reads lock contents, writes, truncates, unlinks, or recovers.
/// Its temporary kernel lock is released by closing its independently opened
/// file before return. The result is only a snapshot, never authority to mutate;
/// a later authorized writer must acquire its own exclusive lock.
///
/// macOS (x86_64/aarch64) and GNU Linux (64-bit x86_64/aarch64) use a
/// read-only, nonblocking, no-follow open and compare file identities. Other platforms conservatively return `Unreadable` for existing
/// files. Symlink roots and symlink/nonregular lock files are rejected. The
/// caller must provide a stable root namespace: these std-only path operations
/// do not defend against concurrent ancestor replacement/rename. Identity checks
/// detect ordinary replacement but do not promise race-free path containment.
/// No-follow protects the final path component; nonblocking open prevents a
/// concurrently substituted FIFO from waiting for a writer.
#[must_use]
pub fn diagnose_local_writer_lock(existing_root: &Path) -> LocalWriterLockDiagnosis {
    use LocalWriterLockDiagnosis::{Missing, Unreadable};
    let Ok(root_metadata) = fs::symlink_metadata(existing_root) else {
        return Unreadable;
    };
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Unreadable;
    }
    let path = existing_root.join(CONTROL_FILES_V1[0]);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Missing,
        Err(_) => return Unreadable,
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Unreadable;
    }
    probe(existing_root, &root_metadata, &path, &metadata)
}

#[cfg(any(
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
fn probe(
    root: &Path,
    root_before: &fs::Metadata,
    path: &Path,
    before: &fs::Metadata,
) -> LocalWriterLockDiagnosis {
    use LocalWriterLockDiagnosis::{AbandonedInert, LiveOwner, Unreadable};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    // Verified against the pinned libc 0.2.189 source (no new dependency):
    // src/unix/bsd/mod.rs:245-246; linux_like/linux/gnu/b64/
    // x86_64/mod.rs:335,527 and aarch64/mod.rs:262,453.
    // O_NOFOLLOW differs between Linux x86_64 and aarch64!
    #[cfg(target_os = "macos")]
    const NOFOLLOW_NONBLOCK: i32 = 0x100 | 0x4;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const NOFOLLOW_NONBLOCK: i32 = 0x20000 | 2048;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const NOFOLLOW_NONBLOCK: i32 = 0x8000 | 2048;

    // Even a privileged process reports a file without read permission bits
    // conservatively. ACL/open errors below are equally inconclusive.
    if before.mode() & 0o444 == 0 {
        return Unreadable;
    }
    let Ok(file) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW_NONBLOCK)
        .open(path)
    else {
        return Unreadable;
    };
    let same = |left: &fs::Metadata, right: &fs::Metadata| {
        left.dev() == right.dev() && left.ino() == right.ino()
    };
    let identities_match = || {
        let (Ok(opened), Ok(named), Ok(root_now)) = (
            file.metadata(),
            fs::symlink_metadata(path),
            fs::symlink_metadata(root),
        ) else {
            return false;
        };
        opened.is_file()
            && named.is_file()
            && root_now.is_dir()
            && same(before, &opened)
            && same(&opened, &named)
            && same(root_before, &root_now)
    };
    if !identities_match() {
        return Unreadable;
    }
    let state = match file.try_lock() {
        Ok(()) => AbandonedInert,
        Err(fs::TryLockError::WouldBlock) => LiveOwner,
        Err(fs::TryLockError::Error(_)) => Unreadable,
    };
    let result = if identities_match() {
        state
    } else {
        Unreadable
    };
    drop(file); // RAII also covers every early return after open.
    result
}

#[cfg(not(any(
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
)))]
fn probe(_: &Path, _: &fs::Metadata, _: &Path, _: &fs::Metadata) -> LocalWriterLockDiagnosis {
    LocalWriterLockDiagnosis::Unreadable
}
