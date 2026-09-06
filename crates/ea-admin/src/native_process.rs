//! Bounded subprocess I/O for installed native code and trusted OS validators.
use crate::native_provider::NativeProviderError;
use std::{
    io::{Read, Write},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const LIMIT: usize = 65_536;
pub(crate) struct Output {
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: Zeroizing<Vec<u8>>,
    pub success: bool,
}
enum Message {
    Written(Result<(), NativeProviderError>),
    Read(bool, Result<Zeroizing<Vec<u8>>, NativeProviderError>),
}

pub(crate) fn run(
    command: Command,
    input: Zeroizing<Vec<u8>>,
    timeout: Duration,
    check: impl FnOnce(u32) -> Result<(), NativeProviderError>,
) -> Result<Output, NativeProviderError> {
    run_started(Instant::now(), command, input, timeout, check)
}

fn run_started(
    started: Instant,
    mut command: Command,
    input: Zeroizing<Vec<u8>>,
    timeout: Duration,
    check: impl FnOnce(u32) -> Result<(), NativeProviderError>,
) -> Result<Output, NativeProviderError> {
    if input.len() > LIMIT {
        return Err(NativeProviderError::Protocol);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| NativeProviderError::Unavailable)?;
    let result = (|| {
        // Validate the actual running image before sending any request/secret.
        check(child.id())?;
        if started.elapsed() >= timeout {
            return Err(NativeProviderError::Timeout);
        }
        let mut stdin = child.stdin.take().ok_or(NativeProviderError::Protocol)?;
        let stdout = child.stdout.take().ok_or(NativeProviderError::Protocol)?;
        let stderr = child.stderr.take().ok_or(NativeProviderError::Protocol)?;
        let (sender, receiver) = mpsc::channel();
        let writer = sender.clone();
        std::thread::spawn(move || {
            let result = stdin
                .write_all(&input)
                .map_err(|_| NativeProviderError::Protocol);
            drop(stdin);
            let _ = writer.send(Message::Written(result));
        });
        read_pipe(stdout, true, sender.clone());
        read_pipe(stderr, false, sender);
        let mut wrote = false;
        let mut stdout = None;
        let mut stderr = None;
        let mut status = None;
        loop {
            while let Ok(message) = receiver.try_recv() {
                match message {
                    Message::Written(result) => {
                        result?;
                        wrote = true;
                    }
                    Message::Read(true, result) => stdout = Some(result?),
                    Message::Read(false, result) => stderr = Some(result?),
                }
            }
            if status.is_none() {
                status = child
                    .try_wait()
                    .map_err(|_| NativeProviderError::Unavailable)?;
            }
            // Expiry wins even when all pipe and exit notifications arrived
            // during the last polling sleep or a scheduler delay.
            if started.elapsed() >= timeout {
                return Err(NativeProviderError::Timeout);
            }
            if wrote
                && let Some(status) = status
                && stdout.is_some()
                && stderr.is_some()
            {
                return Ok(Output {
                    stdout: stdout.take().expect("received stdout"),
                    stderr: stderr.take().expect("received stderr"),
                    success: status.success(),
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        terminate(&mut child);
    }
    result
}

fn read_pipe(pipe: impl Read + Send + 'static, stdout: bool, sender: mpsc::Sender<Message>) {
    std::thread::spawn(move || {
        let mut output = Zeroizing::new(Vec::new());
        let result = pipe
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut output)
            .map_err(|_| NativeProviderError::Protocol)
            .and_then(|_| {
                if output.len() > LIMIT {
                    Err(NativeProviderError::Protocol)
                } else {
                    Ok(output)
                }
            });
        let _ = sender.send(Message::Read(stdout, result));
    });
}
pub(crate) fn terminate(child: &mut Child) {
    let _ = child.kill();
    let started = Instant::now();
    while child.try_wait().ok().flatten().is_none() && started.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Fixture {
        directory: PathBuf,
        executable: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let directory =
                std::env::temp_dir().join(format!("ea-process-fixture-{}", hex::encode(random)));
            fs::create_dir(&directory).unwrap();
            let executable = directory.join("pipe-fixture");
            let status = Command::new("cc")
                .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/support/native_process_fixture.c"
                ))
                .arg("-o")
                .arg(&executable)
                .status()
                .unwrap();
            assert!(status.success());
            Self {
                directory,
                executable,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn completion_after_the_deadline_is_never_accepted() {
        let fixture = Fixture::new();
        for _ in 0..12 {
            let started = Instant::now();
            let before = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros();
            let mut command = Command::new(&fixture.executable);
            command.arg("late").arg((before + 41_000).to_string());
            let result = run_started(
                started,
                command,
                Zeroizing::new(vec![]),
                Duration::from_millis(40),
                |_| {
                    std::thread::sleep(Duration::from_millis(30));
                    Ok(())
                },
            );
            assert!(matches!(result, Err(NativeProviderError::Timeout)));
        }
    }

    #[test]
    fn successful_output_still_requires_all_pipes_and_child_exit() {
        let fixture = Fixture::new();
        for mode in ["no-read", "no-eof", "no-exit"] {
            let mut command = Command::new(&fixture.executable);
            command.arg(mode);
            assert!(matches!(
                run(
                    command,
                    Zeroizing::new(vec![0; LIMIT]),
                    Duration::from_millis(60),
                    |_| Ok(())
                ),
                Err(NativeProviderError::Timeout)
            ));
        }
        let mut command = Command::new(&fixture.executable);
        command.arg("good");
        let output = run(
            command,
            Zeroizing::new(vec![]),
            Duration::from_secs(2),
            |_| Ok(()),
        )
        .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout.as_slice(), b"{}\n");
    }
}
