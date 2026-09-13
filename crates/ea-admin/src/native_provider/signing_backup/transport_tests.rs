use super::*;
use std::io::Cursor;

fn binding() -> FrameBinding {
    FrameBinding {
        role: 2,
        installation: [0x31; 32],
        public: [0x41; 32],
    }
}

fn exact_frame() -> Vec<u8> {
    let mut frame = b"EABKSEED".to_vec();
    frame.extend([1, 2]);
    frame.extend([0x31; 32]);
    frame.extend([0x41; 32]);
    frame.extend([0x51; 32]);
    assert_eq!(frame.len(), 106);
    frame
}

#[test]
fn exact_frame_requires_all_header_bindings_and_exact_eof() {
    let exact = read_frame(Cursor::new(exact_frame())).unwrap();
    let seed = exact
        .take_seed(&binding())
        .expect("exact bound binary frame");
    assert!(seed.with_exposed(|bytes| bytes.iter().all(|byte| *byte == 0x51)));
    for offset in [0, 8, 9, 10, 42] {
        let mut bytes = exact_frame();
        bytes[offset] ^= 1;
        assert!(
            read_frame(Cursor::new(bytes))
                .unwrap()
                .take_seed(&binding())
                .is_err()
        );
    }
    for length in 0..106 {
        let frame = read_frame(Cursor::new(exact_frame()[..length].to_vec())).unwrap();
        assert!(frame.take_seed(&binding()).is_err());
    }
    let mut trailing = exact_frame();
    trailing.push(b'\n');
    assert!(read_frame(Cursor::new(trailing)).is_err());
}

#[test]
fn fixed_frame_reader_never_reads_beyond_107_bytes() {
    struct Oversize {
        read: usize,
    }
    impl std::io::Read for Oversize {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            assert!(self.read + output.len() <= 107);
            output.fill(0x51);
            self.read += output.len();
            Ok(output.len())
        }
    }
    assert!(read_frame(Oversize { read: 0 }).is_err());
}

#[cfg(unix)]
#[test]
fn actual_pipe_frame_requires_exit_eof_and_unchanged_deadline() {
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let fixture =
        Fixture(std::env::temp_dir().join(format!("ea-backup-frame-{}", hex::encode(random))));
    std::fs::create_dir(&fixture.0).unwrap();
    let executable = fixture.0.join("frame-fixture");
    assert!(
        std::process::Command::new("cc")
            .args([
                "-std=c11",
                "-D_POSIX_C_SOURCE=200809L",
                "-Wall",
                "-Wextra",
                "-Werror"
            ])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/native_backup_frame_fixture.c"
            ))
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let invoke = |mode: &str| {
        let mut command = std::process::Command::new(&executable);
        command.arg(mode);
        if mode == "no-eof" {
            command
                .arg(fixture.0.join("descendant-state"))
                .arg(fixture.0.join("release-descendant"));
        }
        run(
            command,
            b"{}".to_vec(),
            std::time::Duration::from_millis(if matches!(mode, "no-exit" | "no-eof") {
                100
            } else {
                2000
            }),
            |_| Ok(()),
            || Ok(()),
        )
    };
    assert!(invoke("exact").unwrap().take_seed(&binding()).is_ok());
    assert!(invoke("extra").is_err());
    assert!(invoke("short").unwrap().take_seed(&binding()).is_err());
    assert!(matches!(
        invoke("exit-error"),
        Err(NativeProviderError::Denied)
    ));
    use std::sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    for mode in ["no-exit", "no-eof"] {
        let probe = Arc::new(CleanupProbe::default());
        PROBE.with(|slot| *slot.borrow_mut() = Some(Arc::clone(&probe)));
        assert!(matches!(invoke(mode), Err(NativeProviderError::Timeout)));
        assert!(probe.dropped.load(Ordering::SeqCst));
        assert!(probe.wiped_nonempty.load(Ordering::SeqCst));
        if mode == "no-eof" {
            assert_eq!(
                std::fs::read_to_string(fixture.0.join("descendant-state")).unwrap(),
                "held"
            );
            assert!(!fixture.0.join("release-descendant").exists());
            // The descendant is still in the observed held state. Only this
            // release authorizes it to close stdout, after Return AND FrameDrop.
            std::fs::write(fixture.0.join("release-descendant"), b"").unwrap();
            let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                if std::fs::read_to_string(fixture.0.join("descendant-state")).unwrap()
                    == "released"
                {
                    break;
                }
                assert!(std::time::Instant::now() < until);
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }
    let probe = Arc::new(CleanupProbe::default());
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let entered = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = std::sync::mpsc::channel();
    let action_probe = Arc::clone(&probe);
    let action_gate = Arc::clone(&gate);
    let action_entered = Arc::clone(&entered);
    let action = std::thread::spawn(move || {
        PROBE.with(|slot| *slot.borrow_mut() = Some(Arc::clone(&action_probe)));
        let mut command = std::process::Command::new(executable);
        command.arg("exact");
        let result = run(
            command,
            b"{}".to_vec(),
            std::time::Duration::from_millis(150),
            |_| Ok(()),
            move || {
                if action_probe.read.load(Ordering::SeqCst) {
                    action_entered.store(true, Ordering::SeqCst);
                    let (lock, ready) = &*action_gate;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        released = ready.wait(released).unwrap();
                    }
                }
                Ok(())
            },
        );
        let _ = sender.send(result);
    });
    let timely = receiver.recv_timeout(std::time::Duration::from_secs(2));
    let blocked = entered.load(Ordering::SeqCst) && !*gate.0.lock().unwrap();
    let wiped = probe.dropped.load(Ordering::SeqCst) && probe.wiped_nonempty.load(Ordering::SeqCst);
    // Release the synthetic public-only worker even if a future regression
    // makes the operation miss its deadline. Assertions use the earlier facts.
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    action.join().unwrap();
    assert!(matches!(timely, Ok(Err(NativeProviderError::Timeout))));
    assert!(
        blocked,
        "the actual watch worker was held when the operation returned"
    );
    assert!(wiped, "the nonempty frame was zeroed before worker release");
    PROBE.with(|slot| *slot.borrow_mut() = None);
}
