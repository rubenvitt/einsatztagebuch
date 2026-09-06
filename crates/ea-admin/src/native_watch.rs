//! A provider-lifetime subscription; unlock never revives the old session.
use crate::{
    native_identity::NativeExecutableIdentity,
    native_process::terminate,
    native_provider::{NativeProviderError, helper_command},
};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::Child,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

const LINE_LIMIT: u64 = 1024;
const COVERAGE_DEADLINE: Duration = Duration::from_secs(1);
pub(crate) struct SessionWatch {
    child: Mutex<Child>,
    invalidated: Arc<AtomicBool>,
    started: Instant,
    coverage: Mutex<mpsc::Receiver<()>>,
    pending: Arc<Mutex<Option<String>>>,
}
impl SessionWatch {
    pub fn start(
        path: &Path,
        installation: &[u8; 32],
        identity: &NativeExecutableIdentity,
    ) -> Result<Self, NativeProviderError> {
        let started = Instant::now();
        let mut child = helper_command(path, std::env::vars_os())
            .spawn()
            .map_err(|_| NativeProviderError::Unavailable)?;
        let invalidated = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(Mutex::new(None::<String>));
        let (acknowledged, coverage) = mpsc::channel();
        let result = (|| {
            identity.verify_child(path, child.id())?;
            let id = hex::encode(installation);
            let mut request =
                serde_json::to_vec(&serde_json::json!({"op":"watch-session","installation_id":id}))
                    .map_err(|_| NativeProviderError::Protocol)?;
            request.push(b'\n');
            let handshake_started = Instant::now();
            // This bounded public request fits an empty anonymous pipe. Keep the
            // handle open until Drop: EOF tells the native subscriber to stop.
            child
                .stdin
                .as_mut()
                .ok_or(NativeProviderError::Protocol)?
                .write_all(&request)
                .map_err(|_| NativeProviderError::Protocol)?;
            let stdout = child.stdout.take().ok_or(NativeProviderError::Protocol)?;
            let latch = invalidated.clone();
            let pending = pending.clone();
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stdout);
                let first = read_line(&mut reader).and_then(|value| {
                    if value != serde_json::json!({"ok":true,"installation_id":id,"ready":true}) {
                        return Err(NativeProviderError::Protocol);
                    }
                    Ok(())
                });
                if first.is_err() {
                    latch.store(true, Ordering::SeqCst);
                }
                if sender.send(first).is_err() {
                    return;
                }
                while watch_acknowledgement(&mut reader, &id, &pending).is_ok() {
                    if acknowledged.send(()).is_err() {
                        break;
                    }
                }
                latch.store(true, Ordering::SeqCst);
            });
            receiver
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| NativeProviderError::Timeout)??;
            if handshake_started.elapsed() >= Duration::from_secs(10) {
                return Err(NativeProviderError::Timeout);
            }
            if invalidated.load(Ordering::SeqCst) {
                return Err(NativeProviderError::Locked);
            }
            Ok(())
        })();
        if let Err(error) = result {
            terminate(&mut child);
            return Err(error);
        }
        Ok(Self {
            child: Mutex::new(child),
            invalidated,
            started,
            coverage: Mutex::new(coverage),
            pending,
        })
    }
    pub fn ensure_valid(&self) -> Result<(), NativeProviderError> {
        // Serialize coverage requests. A nonce is consumed exactly once, so
        // queued old output cannot refresh a stopped native event loop.
        let receiver = self
            .coverage
            .lock()
            .map_err(|_| NativeProviderError::Locked)?;
        self.check_lifetime()?;
        let mut random = [0; 32];
        getrandom::fill(&mut random).map_err(|_| NativeProviderError::Unavailable)?;
        let challenge = hex::encode(random);
        let mut request = serde_json::to_vec(&serde_json::json!({"challenge":challenge}))
            .map_err(|_| NativeProviderError::Protocol)?;
        request.push(b'\n');
        let requested = Instant::now();
        let result = (|| {
            *self
                .pending
                .lock()
                .map_err(|_| NativeProviderError::Locked)? = Some(challenge);
            self.child
                .lock()
                .map_err(|_| NativeProviderError::Locked)?
                .stdin
                .as_mut()
                .ok_or(NativeProviderError::Locked)?
                .write_all(&request)
                .map_err(|_| NativeProviderError::Locked)?;
            receiver
                .recv_timeout(COVERAGE_DEADLINE)
                .map_err(|_| NativeProviderError::Locked)?;
            if requested.elapsed() >= COVERAGE_DEADLINE {
                return Err(NativeProviderError::Locked);
            }
            self.check_lifetime()
        })();
        if result.is_err() {
            self.invalidated.store(true, Ordering::SeqCst);
        }
        result
    }
    fn check_lifetime(&self) -> Result<(), NativeProviderError> {
        if self.started.elapsed() >= Duration::from_secs(300) {
            self.invalidated.store(true, Ordering::SeqCst);
        }
        let exited = self
            .child
            .lock()
            .map_err(|_| NativeProviderError::Locked)?
            .try_wait()
            .map_err(|_| NativeProviderError::Locked)?
            .is_some();
        if exited {
            self.invalidated.store(true, Ordering::SeqCst);
        }
        if self.invalidated.load(Ordering::SeqCst) {
            Err(NativeProviderError::Locked)
        } else {
            Ok(())
        }
    }
}

fn watch_acknowledgement(
    reader: &mut impl BufRead,
    installation: &str,
    pending: &Mutex<Option<String>>,
) -> Result<(), NativeProviderError> {
    let mut first = [0; 1];
    if reader
        .read(&mut first)
        .map_err(|_| NativeProviderError::Locked)?
        != 1
    {
        return Err(NativeProviderError::Locked);
    }
    // Unsolicited output invalidates on its first byte, including a truncated
    // terminal frame. During a request, the caller's one-second deadline also
    // bounds incomplete acknowledgements without granting an old valid proof.
    let challenge = pending
        .lock()
        .map_err(|_| NativeProviderError::Locked)?
        .clone()
        .ok_or(NativeProviderError::Locked)?;
    let mut bytes = first.to_vec();
    reader
        .take(LINE_LIMIT)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| NativeProviderError::Locked)?;
    if bytes.len() > LINE_LIMIT as usize || bytes.last() != Some(&b'\n') {
        return Err(NativeProviderError::Locked);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| NativeProviderError::Locked)?;
    if value != serde_json::json!({"ok":true,"installation_id":installation,"challenge":challenge})
    {
        return Err(NativeProviderError::Locked);
    }
    if pending
        .lock()
        .map_err(|_| NativeProviderError::Locked)?
        .take()
        .as_ref()
        != Some(&challenge)
    {
        return Err(NativeProviderError::Locked);
    }
    Ok(())
}
impl Drop for SessionWatch {
    fn drop(&mut self) {
        self.invalidated.store(true, Ordering::SeqCst);
        if let Ok(child) = self.child.get_mut() {
            child.stdin.take();
            terminate(child);
        }
    }
}
fn read_line(reader: &mut impl BufRead) -> Result<serde_json::Value, NativeProviderError> {
    let mut bytes = Vec::new();
    reader
        .take(LINE_LIMIT + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| NativeProviderError::Protocol)?;
    if bytes.len() > LINE_LIMIT as usize || bytes.last() != Some(&b'\n') {
        return Err(NativeProviderError::Protocol);
    }
    serde_json::from_slice(&bytes).map_err(|_| NativeProviderError::Protocol)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

    struct Fixture {
        directory: PathBuf,
        path: PathBuf,
    }
    impl Fixture {
        fn new(mode: &str) -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let directory = std::env::temp_dir().join(format!("ea-watch-{}", hex::encode(random)));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("helper");
            let script = r#"#!/usr/bin/python3
import json, sys, time
mode = MODE
installation = "01" * 32
json.loads(sys.stdin.buffer.readline())
def emit(value):
    sys.stdout.write(json.dumps(value) + "\n")
    sys.stdout.flush()
emit(dict(ok=True, installation_id=installation, ready=True))
if mode in ("unsolicited-byte", "terminal-no-newline"):
    time.sleep(.02)
    sys.stdout.write("x" if mode == "unsolicited-byte" else json.dumps(dict(ok=True, installation_id=installation, invalidated=True)))
    sys.stdout.flush()
    sys.stdin.read()
    sys.exit(0)
previous = None
for line in sys.stdin:
    request = json.loads(line)
    nonce = request["challenge"]
    if mode == "invalidate":
        emit(dict(ok=True, installation_id=installation, invalidated=True))
        break
    if mode == "partial-ack":
        sys.stdout.write('{"ok":true')
        sys.stdout.flush()
        sys.stdin.read()
        break
    if mode == "slow": time.sleep(1.1)
    answer = previous if mode == "replay" and previous else nonce
    emit(dict(ok=True, installation_id=installation, challenge=answer))
    previous = nonce
"#.replace("MODE", &serde_json::to_string(mode).unwrap());
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self { directory, path }
        }
        fn watch(&self) -> SessionWatch {
            SessionWatch::start(&self.path, &[1; 32], &NativeExecutableIdentity::fixture()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn fresh_coverage_is_required_each_time_and_old_acknowledgements_cannot_replay() {
        let fixture = Fixture::new("ack");
        let watch = fixture.watch();
        for _ in 0..4 {
            watch.ensure_valid().unwrap();
        }
        drop(watch);
        let fixture = Fixture::new("replay");
        let watch = fixture.watch();
        watch.ensure_valid().unwrap();
        assert!(matches!(
            watch.ensure_valid(),
            Err(NativeProviderError::Locked)
        ));
        assert!(matches!(
            watch.ensure_valid(),
            Err(NativeProviderError::Locked)
        ));
    }

    #[test]
    fn stopped_native_event_loop_cannot_confirm_old_coverage() {
        let fixture = Fixture::new("ack");
        let watch = fixture.watch();
        watch.ensure_valid().unwrap();
        let pid = watch.child.lock().unwrap().id();
        assert!(
            Command::new("/bin/kill")
                .args(["-STOP", &pid.to_string()])
                .status()
                .unwrap()
                .success()
        );
        assert!(matches!(
            watch.ensure_valid(),
            Err(NativeProviderError::Locked)
        ));
        assert!(matches!(
            watch.ensure_valid(),
            Err(NativeProviderError::Locked)
        ));
        // Drop kills and reaps only this test's stopped child.
    }

    #[test]
    fn incomplete_terminal_output_invalidates_without_waiting_for_a_newline() {
        for mode in ["unsolicited-byte", "terminal-no-newline"] {
            let fixture = Fixture::new(mode);
            let watch = fixture.watch();
            std::thread::sleep(Duration::from_millis(100));
            assert!(watch.invalidated.load(Ordering::SeqCst));
            assert!(matches!(
                watch.ensure_valid(),
                Err(NativeProviderError::Locked)
            ));
        }
    }

    #[test]
    fn an_incomplete_or_late_acknowledgement_never_grants_a_valid_session() {
        for mode in ["partial-ack", "slow"] {
            let fixture = Fixture::new(mode);
            let watch = fixture.watch();
            assert!(matches!(
                watch.ensure_valid(),
                Err(NativeProviderError::Locked)
            ));
            assert!(matches!(
                watch.ensure_valid(),
                Err(NativeProviderError::Locked)
            ));
        }
    }

    #[test]
    fn a_terminal_lock_latches_until_an_explicitly_new_watch() {
        let fixture = Fixture::new("invalidate");
        let watch = fixture.watch();
        assert!(matches!(
            watch.ensure_valid(),
            Err(NativeProviderError::Locked)
        ));
        assert!(matches!(
            watch.ensure_valid(),
            Err(NativeProviderError::Locked)
        ));
        drop(watch);
        let fixture = Fixture::new("ack");
        fixture.watch().ensure_valid().unwrap();
    }
}
