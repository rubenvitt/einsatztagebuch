//! The bootstrap lease belongs to the kernel, not to the existence of a file.

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

use ea_admin::{
    AdminError, BootstrapCoordinator, BootstrapStore as _, FileBootstrapStore, SystemRandomSource,
};
use std::{
    fs,
    io::{BufRead as _, Write as _},
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, MutexGuard, mpsc},
    time::Duration,
};

const UNAVAILABLE: &str = "EA-CEREMONY-BOOTSTRAP-STORE-UNAVAILABLE";

// Isolate process resources between cases. Concurrency is exercised by the
// explicit holder/contender children inside each case, without retries/sleeps.
static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
struct Fixture {
    root: PathBuf,
    _serial: MutexGuard<'static, ()>,
}
impl Fixture {
    fn new() -> Self {
        let serial = FIXTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("ea-bootstrap-lock-{}", hex::encode(random)));
        fs::create_dir(&path).unwrap();
        Self {
            root: path,
            _serial: serial,
        }
    }
    fn state(&self) -> PathBuf {
        self.root.join("anchor.etb.bootstrap-state")
    }
    fn lock(&self) -> PathBuf {
        self.root.join("anchor.etb.bootstrap-state.lock")
    }
    fn writing(&self) -> PathBuf {
        self.root.join("anchor.etb.bootstrap-state.writing")
    }
}

fn refused<T>(result: Result<T, AdminError>) {
    match result {
        Err(error) => {
            assert_eq!(error.code(), UNAVAILABLE);
            assert_eq!(error.to_string(), UNAVAILABLE);
            assert_eq!(format!("{error:?}"), UNAVAILABLE);
        }
        Ok(_) => panic!("bootstrap lease must refuse this operation"),
    }
}

struct ChildLease {
    child: Child,
    response: mpsc::Receiver<String>,
}
impl ChildLease {
    fn start(path: &Path, mode: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "bootstrap_lease_child",
                "--nocapture",
            ])
            .env("EA_BOOTSTRAP_LOCK_TEST_PATH", path)
            .env("EA_BOOTSTRAP_LOCK_TEST_MODE", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, response) = mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some((_, message)) = line.split_once("bootstrap-lease:") {
                    let _ = sender.send(message.to_owned());
                }
                // Drain libtest output until EOF: closing the parent's read
                // end at readiness would make a healthy child hit BrokenPipe.
            }
        });
        Self { child, response }
    }
    fn expect(&mut self, message: &str) {
        // A deadline bounds a broken child; readiness itself comes only from
        // the child AFTER successful kernel acquisition, never from a sleep.
        assert_eq!(
            self.response.recv_timeout(Duration::from_secs(5)).unwrap(),
            message
        );
    }
    fn release(mut self) {
        drop(self.child.stdin.take());
        assert!(self.child.wait().unwrap().success());
    }
    fn crash(mut self) {
        self.child.kill().unwrap();
        assert!(!self.child.wait().unwrap().success());
    }
}
impl Drop for ChildLease {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "child entry point of the bounded bootstrap lease tests"]
fn bootstrap_lease_child() {
    let path = PathBuf::from(std::env::var_os("EA_BOOTSTRAP_LOCK_TEST_PATH").unwrap());
    let mode = std::env::var("EA_BOOTSTRAP_LOCK_TEST_MODE").unwrap();
    match FileBootstrapStore::new(path).acquire_lease() {
        Ok(_lease) => {
            println!("bootstrap-lease:held");
            std::io::stdout().flush().unwrap();
            if mode == "hold" {
                let mut release = String::new();
                std::io::stdin().read_line(&mut release).unwrap();
            }
        }
        Err(error) => {
            assert_eq!(error.code(), UNAVAILABLE);
            println!("bootstrap-lease:refused");
            std::io::stdout().flush().unwrap();
        }
    }
}

#[test]
fn a_live_child_lease_excludes_other_leases_and_unleased_writes() {
    let fixture = Fixture::new();
    let mut legacy = FileBootstrapStore::new(fixture.state());
    BootstrapCoordinator::begin(&mut legacy, &mut SystemRandomSource, None).unwrap();
    let state = legacy.load().unwrap().unwrap();
    let before = fs::read(fixture.state()).unwrap();
    let mut holder = ChildLease::start(&fixture.state(), "hold");
    holder.expect("held");
    let mut contender = ChildLease::start(&fixture.state(), "probe");
    contender.expect("refused");
    contender.release();
    let original_inode = fs::metadata(fixture.lock()).unwrap().ino();
    refused(FileBootstrapStore::new(fixture.state()).acquire_lease());

    fs::write(fixture.writing(), b"active writer bytes").unwrap();
    refused(legacy.store(&state));
    assert_eq!(fs::read(fixture.writing()).unwrap(), b"active writer bytes");
    assert_eq!(fs::read(fixture.state()).unwrap(), before);
    holder.release();

    let leased = FileBootstrapStore::new(fixture.state())
        .acquire_lease()
        .unwrap();
    assert_eq!(fs::metadata(fixture.lock()).unwrap().ino(), original_inode);
    refused(legacy.store(&state));
    drop(leased);
    legacy.store(&state).unwrap();
    assert!(!fixture.writing().try_exists().unwrap());
    assert_eq!(fs::read(fixture.state()).unwrap(), before);
}

#[test]
fn process_death_releases_the_kernel_lease_without_deleting_its_inode() {
    let fixture = Fixture::new();
    let mut holder = ChildLease::start(&fixture.state(), "hold");
    holder.expect("held");
    let before = fs::metadata(fixture.lock()).unwrap();
    assert_eq!(before.len(), 0);
    assert_eq!(before.mode() & 0o7777, 0o600);
    holder.crash();

    let mut next = ChildLease::start(&fixture.state(), "hold");
    next.expect("held");
    assert_eq!(fs::metadata(fixture.lock()).unwrap().ino(), before.ino());
    next.release();
    assert_eq!(fs::metadata(fixture.lock()).unwrap().ino(), before.ino());
    assert!(!fixture.state().try_exists().unwrap());
}

#[test]
fn a_replaced_lock_inode_invalidates_an_already_held_lease() {
    let fixture = Fixture::new();
    let mut legacy = FileBootstrapStore::new(fixture.state());
    BootstrapCoordinator::begin(&mut legacy, &mut SystemRandomSource, None).unwrap();
    let before = fs::read(fixture.state()).unwrap();
    let leased = FileBootstrapStore::new(fixture.state())
        .acquire_lease()
        .unwrap();
    let original_inode = fs::metadata(fixture.lock()).unwrap().ino();
    // Deliberate hostile namespace change in this fixture only. Production
    // never renames or removes its lock file, even after an owner crashes.
    fs::rename(fixture.lock(), fixture.root.join("displaced.lock")).unwrap();
    let mut replacement = ChildLease::start(&fixture.state(), "hold");
    replacement.expect("held");
    assert_ne!(fs::metadata(fixture.lock()).unwrap().ino(), original_inode);
    refused(leased.load());
    refused(leased.acquire_lease());
    assert_eq!(fs::read(fixture.state()).unwrap(), before);
    replacement.release();
}

#[test]
fn lock_file_shape_and_permissions_fail_closed_without_following_or_blocking() {
    let fixture = Fixture::new();
    let target = fixture.root.join("unrelated");
    fs::write(&target, b"unrelated original bytes").unwrap();
    symlink(&target, fixture.lock()).unwrap();
    let mut probe = ChildLease::start(&fixture.state(), "probe");
    probe.expect("refused");
    probe.release();
    assert_eq!(fs::read(&target).unwrap(), b"unrelated original bytes");
    fs::remove_file(fixture.lock()).unwrap();

    assert!(
        Command::new("mkfifo")
            .arg(fixture.lock())
            .status()
            .unwrap()
            .success()
    );
    let mut probe = ChildLease::start(&fixture.state(), "probe");
    probe.expect("refused");
    probe.release();
    assert!(
        fs::symlink_metadata(fixture.lock())
            .unwrap()
            .file_type()
            .is_fifo()
    );
    fs::remove_file(fixture.lock()).unwrap();

    fs::write(fixture.lock(), b"oversized for an empty lock").unwrap();
    fs::set_permissions(fixture.lock(), fs::Permissions::from_mode(0o600)).unwrap();
    refused(FileBootstrapStore::new(fixture.state()).acquire_lease());
    assert_eq!(
        fs::read(fixture.lock()).unwrap(),
        b"oversized for an empty lock"
    );
    fs::write(fixture.lock(), b"").unwrap();
    fs::set_permissions(fixture.lock(), fs::Permissions::from_mode(0o644)).unwrap();
    refused(FileBootstrapStore::new(fixture.state()).acquire_lease());
    fs::set_permissions(fixture.lock(), fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(fixture.lock(), fixture.root.join("alias")).unwrap();
    refused(FileBootstrapStore::new(fixture.state()).acquire_lease());
    assert_eq!(fs::metadata(fixture.lock()).unwrap().nlink(), 2);
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn construction_is_inert_and_lease_precedes_loading_state() {
    let fixture = Fixture::new();
    let store = FileBootstrapStore::new(fixture.state());
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);
    fs::write(fixture.state(), b"malformed persisted state").unwrap();
    let leased = store.acquire_lease().unwrap();
    match leased.load() {
        Err(error) => assert_eq!(error.code(), "EA-CEREMONY-BOOTSTRAP-STATE-SHAPE"),
        Ok(_) => panic!("malformed state must stay unreadable"),
    }
    assert!(fixture.lock().is_file());
}
