//! Fixed owning binary response, successful exit and EOF under the native deadline.
use super::super::NativeProviderError;
use ea_crypto::SecretBytes;
#[cfg(test)]
use std::io::Read;
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
#[derive(Default)]
struct CleanupProbe {
    read: std::sync::atomic::AtomicBool,
    dropped: std::sync::atomic::AtomicBool,
    wiped_nonempty: std::sync::atomic::AtomicBool,
}
#[cfg(test)]
thread_local! {static PROBE:std::cell::RefCell<Option<std::sync::Arc<CleanupProbe>>>=const{std::cell::RefCell::new(None)};}

pub(super) struct FrameBinding {
    pub role: u8,
    pub installation: [u8; 32],
    pub public: [u8; 32],
}
pub(super) struct SecretFrame {
    bytes: Zeroizing<Box<[u8]>>,
    length: usize,
    #[cfg(test)]
    probe: Option<std::sync::Arc<CleanupProbe>>,
}
impl SecretFrame {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; 107].into_boxed_slice()),
            length: 0,
            #[cfg(test)]
            probe: PROBE.with(|probe| probe.borrow().clone()),
        }
    }
    fn read_count(&mut self, count: usize) {
        self.length += count;
        #[cfg(test)]
        if count > 0
            && let Some(probe) = &self.probe
        {
            probe.read.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    pub(super) fn take_seed(
        self,
        expected: &FrameBinding,
    ) -> Result<SecretBytes<32>, NativeProviderError> {
        if self.length != 106
            || &self.bytes[..8] != b"EABKSEED"
            || self.bytes[8] != 1
            || !matches!(expected.role, 1 | 2)
            || self.bytes[9] != expected.role
            || self.bytes[10..42] != expected.installation
            || self.bytes[42..74] != expected.public
        {
            return Err(NativeProviderError::Protocol);
        }
        // Deliberate bounded stack-to-SecretBytes copy; wipe this owner immediately.
        // Earlier compiler moves are outside the complete-physical-wipe claim.
        let mut temporary = [0; 32];
        temporary.copy_from_slice(&self.bytes[74..106]);
        let seed = SecretBytes::new(temporary);
        temporary.zeroize();
        Ok(seed)
    }
}
impl Drop for SecretFrame {
    fn drop(&mut self) {
        #[cfg(test)]
        let had_bytes = self.bytes.iter().any(|byte| *byte != 0);
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(probe) = &self.probe {
            probe.wiped_nonempty.store(
                had_bytes && self.bytes.iter().all(|byte| *byte == 0),
                std::sync::atomic::Ordering::SeqCst,
            );
            probe
                .dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}
#[cfg(test)]
fn read_frame(mut pipe: impl Read) -> Result<SecretFrame, NativeProviderError> {
    // Allocation occurs before any secret read and never changes size. Moving this
    // Box across the channel moves its owner, not its secret-containing allocation.
    let mut frame = SecretFrame::new();
    loop {
        if frame.length == 107 {
            return Err(NativeProviderError::Protocol);
        }
        match pipe.read(&mut frame.bytes[frame.length..]) {
            Ok(0) => return Ok(frame),
            Ok(count) => frame.read_count(count),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(NativeProviderError::Protocol),
        }
    }
}
pub(super) fn run(
    command: Command,
    input: Vec<u8>,
    timeout: Duration,
    check: impl FnOnce(u32) -> Result<(), NativeProviderError> + Send + 'static,
    watch: impl Fn() -> Result<(), NativeProviderError> + Send + Sync + 'static,
) -> Result<SecretFrame, NativeProviderError> {
    if input.len() > 512 {
        return Err(NativeProviderError::Protocol);
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let started = Instant::now();
        #[cfg(test)]
        let probe = PROBE.with(|probe| probe.borrow().clone());
        // A dedicated runtime thread also works when the synchronous native host
        // is called from an existing Tokio runtime. Public check workers are NOT
        // joined by this scope and never borrow or own the response allocation.
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    #[cfg(test)]
                    PROBE.with(|slot| *slot.borrow_mut() = probe);
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .enable_time()
                        .build()
                        .map_err(|_| NativeProviderError::Unavailable)?;
                    runtime.block_on(run_async(
                        command,
                        input,
                        started,
                        timeout,
                        check,
                        std::sync::Arc::new(watch),
                    ))
                })
                .join()
                .map_err(|_| NativeProviderError::Unavailable)?
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // Tokio Windows ChildStdio uses Blocking<ArcFile> with an extra Vec.
        // That is outside this controlled-buffer contract. Refuse before spawn.
        let _ = (command, input, timeout, check, watch);
        Err(NativeProviderError::Unavailable)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn public_check(
    deadline: tokio::time::Instant,
    work: impl FnOnce() -> Result<(), NativeProviderError> + Send + 'static,
) -> Result<(), NativeProviderError> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let worker = std::thread::Builder::new()
        .spawn(move || {
            let _ = sender.send(work());
        })
        .map_err(|_| NativeProviderError::Unavailable)?;
    // ensure_valid may block on its existing mutex/write before its own receive
    // timeout. Only its public result is awaited here; never join that worker.
    drop(worker);
    tokio::time::timeout_at(deadline, receiver)
        .await
        .map_err(|_| NativeProviderError::Timeout)?
        .map_err(|_| NativeProviderError::Unavailable)?
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn run_async(
    command: Command,
    input: Vec<u8>,
    started: Instant,
    timeout: Duration,
    check: impl FnOnce(u32) -> Result<(), NativeProviderError> + Send + 'static,
    watch: std::sync::Arc<impl Fn() -> Result<(), NativeProviderError> + Send + Sync + 'static>,
) -> Result<SecretFrame, NativeProviderError> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let deadline = tokio::time::Instant::from_std(
        started
            .checked_add(timeout)
            .ok_or(NativeProviderError::Protocol)?,
    );
    let before = std::sync::Arc::clone(&watch);
    public_check(deadline, move || before()).await?;
    let mut child = tokio::process::Command::from(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| NativeProviderError::Unavailable)?;
    let result=async {
        let pid=child.id().ok_or(NativeProviderError::Unavailable)?;
        public_check(deadline,move||check(pid)).await?;
        // No request bytes can reach the helper before successful identity.
        if started.elapsed()>=timeout{return Err(NativeProviderError::Timeout);}
        let mut stdin=child.stdin.take().ok_or(NativeProviderError::Protocol)?;
        let mut stdout=child.stdout.take().ok_or(NativeProviderError::Protocol)?;
        let write=async move {
            let result=stdin.write_all(&input).await.map_err(|_|NativeProviderError::Protocol);
            drop(stdin);
            result
        };
        tokio::pin!(write);
        let mut frame=SecretFrame::new();
        let mut written=false;
        let mut eof=false;
        let mut status:Option<std::process::ExitStatus>=None;
        loop {
            // Exactly one public-only watch check is in flight per operation.
            let current=std::sync::Arc::clone(&watch);
            public_check(deadline,move||current()).await?;
            if started.elapsed()>=timeout{return Err(NativeProviderError::Timeout);}
            if status.is_some_and(|status|!status.success()){return Err(NativeProviderError::Denied);}
            if written && eof && status.is_some(){return Ok(frame);}
            tokio::select! {
                biased;
                _=tokio::time::sleep_until(deadline)=>return Err(NativeProviderError::Timeout),
                result=&mut write,if !written=>{result?;written=true;},
                result=stdout.read(&mut frame.bytes[frame.length..]),if !eof=>{
                    let count=result.map_err(|_|NativeProviderError::Protocol)?;
                    eof=count==0;frame.read_count(count);
                    if frame.length==107{return Err(NativeProviderError::Protocol);}
                },
                result=child.wait(),if status.is_none()=>{status=Some(result.map_err(|_|NativeProviderError::Unavailable)?);},
                _=tokio::time::sleep(Duration::from_millis(5))=>{},
            }
        }
    }.await;
    // The inner operation scope has dropped every pending read and, on failure,
    // the sole secret frame BEFORE even this bounded process cleanup begins.
    if result.is_err() {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
    }
    result
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
