//! Process-local context acquisition only; no action, signing or audit retries.

use super::{OperatorRuntimeError, fresh_wall_clock};
use ea_types::UnixMillis;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};

type GateRegistry = Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>;
static GATES: OnceLock<GateRegistry> = OnceLock::new();

pub(super) enum AcquisitionTime {
    Explicit(UnixMillis),
    FreshWallClock,
}
impl AcquisitionTime {
    pub(super) fn value(self) -> Result<UnixMillis, OperatorRuntimeError> {
        match self {
            Self::Explicit(now) => Ok(now),
            Self::FreshWallClock => fresh_wall_clock(),
        }
    }
}

pub(super) fn acquire<R>(
    database: &Path,
    time: AcquisitionTime,
    work: impl FnOnce(UnixMillis) -> Result<R, OperatorRuntimeError>,
) -> Result<R, OperatorRuntimeError> {
    if !database
        .try_exists()
        .map_err(|_| OperatorRuntimeError::Io)?
    {
        return Err(OperatorRuntimeError::DatabaseMissing);
    }
    let canonical = database
        .canonicalize()
        .map_err(|_| OperatorRuntimeError::Io)?;
    let gate = {
        let mut gates = GATES
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .map_err(|_| OperatorRuntimeError::State(ea_trust::StateStoreError::Unavailable))?;
        gates.retain(|_, gate| gate.strong_count() != 0);
        if let Some(gate) = gates.get(&canonical).and_then(Weak::upgrade) {
            gate
        } else {
            let gate = Arc::new(Mutex::new(()));
            gates.insert(canonical, Arc::downgrade(&gate));
            gate
        }
    };
    let _guard = gate
        .lock()
        .map_err(|_| OperatorRuntimeError::State(ea_trust::StateStoreError::Unavailable))?;
    // Only the private runtime acquisition body is called here. Its existing
    // native watcher, archive and trust gates still decide authority. An error
    // is returned exactly once, including conflicts from other processes.
    work(time.value()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator_runtime::{OperatorRuntimeError, fresh_wall_clock};
    use ea_types::UnixMillis;
    use std::{fs, path::PathBuf, sync::mpsc, thread, time::Duration};

    struct Files(PathBuf);
    impl Files {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!("ea-context-{}", hex::encode(nonce)));
            fs::create_dir(&path).unwrap();
            fs::create_dir(path.join("alias")).unwrap();
            fs::write(path.join("one.sqlite"), []).unwrap();
            fs::write(path.join("two.sqlite"), []).unwrap();
            Self(path)
        }
    }
    impl Drop for Files {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // A missing/shared-by-literal-path gate lets the second context enter while
    // the first still owns the same canonical database acquisition.
    #[test]
    fn canonical_same_database_waits_before_acquiring_current_time() {
        let files = Files::new();
        let first_path = files.0.join("one.sqlite");
        let alias = files.0.join("alias/../one.sqlite");
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first = thread::spawn(move || {
            acquire(
                &first_path,
                AcquisitionTime::Explicit(UnixMillis::new(17)),
                |now| {
                    assert_eq!(now, UnixMillis::new(17));
                    held_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(())
                },
            )
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let second = thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            acquire(&alias, AcquisitionTime::FreshWallClock, |now| {
                entered_tx.send(now).unwrap();
                Ok(())
            })
        });
        attempt_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let early = entered_rx.recv_timeout(Duration::from_millis(200)).ok();
        let released_at = fresh_wall_clock().unwrap();
        release_tx.send(()).unwrap();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
        assert!(
            early.is_none(),
            "same database admitted a competing context before release"
        );
        let selected_at = entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            selected_at >= released_at,
            "fresh clock was taken before waiting for acquisition"
        );
    }

    #[test]
    fn unrelated_database_is_independent_and_explicit_time_is_not_replaced() {
        let files = Files::new();
        let first_path = files.0.join("one.sqlite");
        let other = files.0.join("two.sqlite");
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first = thread::spawn(move || {
            acquire(&first_path, AcquisitionTime::FreshWallClock, |_| {
                held_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(())
            })
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let second = thread::spawn(move || {
            let result = acquire(&other, AcquisitionTime::Explicit(UnixMillis::new(-93)), Ok);
            done_tx.send(result).unwrap();
        });
        let observed = done_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();
        first.join().unwrap().unwrap();
        second.join().unwrap();
        assert_eq!(observed.unwrap().unwrap(), UnixMillis::new(-93));
    }

    #[test]
    fn failed_context_is_never_retried_and_releases_acquisition() {
        let files = Files::new();
        let path = files.0.join("one.sqlite");
        let mut calls = 0;
        let result = acquire(&path, AcquisitionTime::FreshWallClock, |_| {
            calls += 1;
            Err::<(), _>(OperatorRuntimeError::Expired)
        });
        assert!(matches!(result, Err(OperatorRuntimeError::Expired)));
        assert_eq!(calls, 1);
        assert_eq!(
            acquire(&path, AcquisitionTime::Explicit(UnixMillis::new(5)), Ok).unwrap(),
            UnixMillis::new(5)
        );
    }
}
