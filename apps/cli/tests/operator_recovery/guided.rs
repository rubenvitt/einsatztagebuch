use super::*;
use ea_admin::recovery_test_runtime::{
    RecoveryMediumInput, RecoveryMediumObservation, RecoveryMediumRequest,
    RecoveryNativeSigningSlot, RecoveryTestAbort, RecoveryTestGuide,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct PublicGuide {
    active: Arc<AtomicBool>,
    database: Arc<ea_local_store::EncryptedDatabase>,
    cancel_wait: bool,
    provider_directory: Option<PathBuf>,
    worker: Option<std::thread::JoinHandle<bool>>,
    run_id: Option<[u8; 16]>,
    requests: std::collections::BTreeSet<Hash32>,
    observations: usize,
}
impl RecoveryTestGuide for PublicGuide {
    fn request_medium(
        &mut self,
        request: &RecoveryMediumRequest,
    ) -> Result<Option<RecoveryMediumInput>, RecoveryTestAbort> {
        // This executes while the guide is waiting for user input. A runtime
        // must not hold the SQLCipher mutex/transaction through this callback.
        let db = self.database.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            tx.send(
                db.query_row("SELECT count(*) FROM recovery_test_report", &[])
                    .is_ok(),
            )
            .unwrap();
        });
        assert!(rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap());
        if let Some(id) = self.run_id {
            assert_eq!(id, request.run_id());
        } else {
            self.run_id = Some(request.run_id());
        }
        assert!(self.requests.insert(request.request_id()));
        assert!(request.request_id() != Hash32::ZERO);
        if self.cancel_wait {
            self.active.store(false, Ordering::Release);
            return Ok(None);
        }
        if request.role() == ea_recovery::RecoveryKeyRole::OrganizationAdmin
            && request.protection() == ea_format::KeyProtectionProfileV1::OsWrapped
            && let Some(directory) = &self.provider_directory
        {
            let directory = directory.clone();
            let marker = directory.join("recovery-test-signature-paused");
            if marker.exists() {
                fs::remove_file(marker).unwrap();
            }
            fs::write(directory.join("hold-recovery-test-signature"), b"").unwrap();
            let active = self.active.clone();
            self.worker = Some(std::thread::spawn(move || {
                // Arrival includes the real before-provider authority and
                // native presence work; the provider pause itself stays 5s.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                let observed = loop {
                    if directory.join("recovery-test-signature-paused").exists() {
                        break true;
                    }
                    if std::time::Instant::now() >= deadline {
                        break false;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                };
                active.store(false, Ordering::Release);
                fs::remove_file(directory.join("hold-recovery-test-signature")).unwrap();
                observed
            }));
            return Ok(Some(RecoveryMediumInput::NativeSigningSlot(
                RecoveryNativeSigningSlot::Admin,
            )));
        }
        Ok(None)
    }
    fn medium_result(
        &mut self,
        result: &RecoveryMediumObservation,
    ) -> Result<(), RecoveryTestAbort> {
        assert_eq!(Some(result.run_id()), self.run_id);
        assert!(self.requests.contains(&result.request_id()));
        self.observations += 1;
        Ok(())
    }
    fn ensure_active(&self) -> Result<(), RecoveryTestAbort> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(RecoveryTestAbort)
        }
    }
}
fn report_counts(runtime: &RecoveryTestRuntime) -> (i64, i64) {
    let db = runtime.runtime().database();
    (
        db.query_row("SELECT count(*) FROM recovery_test_report", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        db.query_row("SELECT count(*) FROM recovery_test_failure", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
    )
}

struct CancelAfterVisibleCommit {
    // Test instrumentation only. A separate WAL reader deterministically
    // observes the durable terminal point; production guards remain atomic,
    // pure and nonblocking and must never enter the database.
    observer: ea_local_store::EncryptedDatabase,
    failures_before: i64,
    saw_committed: AtomicBool,
}
impl RecoveryTestGuide for CancelAfterVisibleCommit {
    fn request_medium(
        &mut self,
        _: &RecoveryMediumRequest,
    ) -> Result<Option<RecoveryMediumInput>, RecoveryTestAbort> {
        Ok(None)
    }
    fn medium_result(
        &mut self,
        _: &RecoveryMediumObservation,
    ) -> Result<(), RecoveryTestAbort> {
        Ok(())
    }
    fn ensure_active(&self) -> Result<(), RecoveryTestAbort> {
        let visible = self.observer
            .query_row("SELECT count(*) FROM recovery_test_failure", &[])
            .unwrap().unwrap().integer(0).unwrap();
        if visible > self.failures_before {
            self.saw_committed.store(true, Ordering::Release);
            Err(RecoveryTestAbort)
        } else {
            Ok(())
        }
    }
}

#[test]
#[ignore = "actual native WAL commit observation; deterministic kernel cancellation race only"]
fn portable_native_cancellation_after_visible_commit_preserves_durable_terminal_result() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let mut runtime = open_portable_target(&export, &target);
    let restored = runtime.reopen_restored_source(
        &inventory, &target.join("restored-sources.sqlite"),
    ).unwrap();
    let before = report_counts(&runtime);
    let provider = runtime.runtime().signing_provider();
    let observer = ea_local_store::EncryptedDatabase::open_existing(
        &runtime.runtime().config().database_path,
        provider.as_ref(),
        &provider.handle(ea_key_provider::SecretPurpose::LocalDatabaseKey),
    ).unwrap();
    let mut guide = CancelAfterVisibleCommit {
        observer,
        failures_before: before.1,
        saw_committed: AtomicBool::new(false),
    };
    let result = runtime.run_restored_test_guided(&restored, &inventory, &mut guide);
    assert_eq!(report_counts(&runtime), (before.0, before.1 + 1),
        "the exact failure was durably committed before the simulated cancellation");
    // Explicitly deliver the late denial even when the corrected kernel has
    // no postcommit guard call. The original RED returned Cancelled already;
    // the same result expectation must now preserve the committed report.
    assert!(guide.ensure_active().is_err());
    assert!(guide.saw_committed.load(Ordering::Acquire));
    let ea_admin::recovery_test_runtime::RecoveryTestOutcome::Failed(report) =
        result.expect("cancellation after durable commit cannot erase its terminal result")
    else { panic!("missing media remain Failed, never Completed"); };
    let exact = report.exact_envelope().to_vec();
    restored.verify_unchanged().unwrap();
    drop(guide);
    drop(restored);
    drop(runtime);
    let mut reopened = open_portable_target(&export, &target);
    let durable = reopened.read_failed_report(
        &inventory, &target.join("restored-sources.sqlite"),
    ).unwrap().unwrap();
    assert_eq!(durable.exact_envelope(), exact);
    assert_eq!(report_counts(&reopened), (before.0, before.1 + 1));
}

#[test]
#[ignore = "actual retained foreign-machine fixture, no fabricated machine or report"]
fn portable_native_guided_abort_during_wait_or_provider_publishes_no_result() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    for provider in [false, true] {
        let mut runtime = open_portable_target(&export, &target);
        let restored = runtime
            .reopen_restored_source(&inventory, &target.join("restored-sources.sqlite"))
            .unwrap();
        let before = report_counts(&runtime);
        let mut guide = PublicGuide {
            active: Arc::new(AtomicBool::new(true)),
            database: runtime.runtime().database().clone(),
            cancel_wait: !provider,
            provider_directory: provider.then(|| target.clone()),
            worker: None,
            run_id: None,
            requests: Default::default(),
            observations: 0,
        };
        let error = match runtime.run_restored_test_guided(&restored, &inventory, &mut guide) {
            Ok(_) => panic!("cancelled run cannot finish"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "EA-RECOVERY-TEST-CANCELLED");
        assert!(guide.run_id.is_some(), "actual input callback ran");
        if provider {
            assert!(
                guide.worker.take().unwrap().join().unwrap(),
                "actual provider was paused"
            );
        } else {
            assert_eq!(guide.observations, 0);
        }
        assert_eq!(report_counts(&runtime), before);
        restored.verify_unchanged().unwrap();
        drop(restored);
        drop(runtime);
        assert_eq!(
            report_counts(&open_portable_target(&export, &target)),
            before
        );
    }
}

#[test]
#[ignore = "actual foreign-machine batch and guide share durable report kernel"]
fn portable_native_guided_and_batch_missing_media_have_identical_facts() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let mut runtime = open_portable_target(&export, &target);
    let restored = runtime
        .reopen_restored_source(&inventory, &target.join("restored-sources.sqlite"))
        .unwrap();
    let ea_admin::recovery_test_runtime::RecoveryTestOutcome::Failed(batch) = runtime
        .run_restored_test_report(&restored, &inventory, &[])
        .unwrap()
    else {
        panic!("missing")
    };
    let mut guide = PublicGuide {
        active: Arc::new(AtomicBool::new(true)),
        database: runtime.runtime().database().clone(),
        cancel_wait: false,
        provider_directory: None,
        worker: None,
        run_id: None,
        requests: Default::default(),
        observations: 0,
    };
    let ea_admin::recovery_test_runtime::RecoveryTestOutcome::Failed(guided) = runtime
        .run_restored_test_guided(&restored, &inventory, &mut guide)
        .unwrap()
    else {
        panic!("missing")
    };
    let batch: Value = serde_json::from_slice(batch.public_report()).unwrap();
    let guided: Value = serde_json::from_slice(guided.public_report()).unwrap();
    assert_eq!(batch["media"], guided["media"]);
    assert_eq!(guided["testId"], hex::encode(guide.run_id.unwrap()));
    assert_eq!(guide.observations, inventory.media().len());
}

fn renew_actual_portable_posture(target: &Path, lifetime_ms: i64) {
    let native =
        NativeOperatorProvider::open_test_fixture(target.join("ea-native-operator"), false)
            .unwrap();
    let host = Arc::from(
        ea_key_provider::SupportMatrixRow::current_host()
            .unwrap()
            .posture_provider(),
    );
    let runtime = OperatorRuntime::open_with_test_native_and_posture(
        OperatorRuntimeConfig::load(&target.join("operator.json")).unwrap(),
        &target.join("independent-anchor.etb"),
        support::live_clock(),
        false,
        native,
        host,
    )
    .unwrap();
    let context = runtime.posture_target_context().unwrap();
    let exact = runtime
        .issue_posture_document(
            &context,
            ea_crypto::object_hash(b"T9 Linux isolated software lifecycle prerequisites"),
            lifetime_ms,
        )
        .unwrap();
    runtime.import_posture_document(&exact).unwrap();
}
struct LongGuide {
    target: PathBuf,
    media: std::collections::BTreeMap<ObjectHash, RecoveryMediumInput>,
    waited: usize,
    expire: bool,
    run_id: Option<[u8; 16]>,
    observed: usize,
}
struct LongFixtureWatch(PathBuf);
impl LongFixtureWatch {
    fn open(target: &Path) -> Self {
        let path = target.join("long-recovery-run");
        fs::write(&path, b"bounded T9 long-run watcher fixture").unwrap();
        Self(path)
    }
}
impl Drop for LongFixtureWatch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
impl RecoveryTestGuide for LongGuide {
    fn request_medium(
        &mut self,
        request: &RecoveryMediumRequest,
    ) -> Result<Option<RecoveryMediumInput>, RecoveryTestAbort> {
        if self.run_id.is_none() {
            self.run_id = Some(request.run_id());
        }
        if self.waited < 2 {
            self.waited += 1;
            if self.expire {
                renew_actual_portable_posture(&self.target, 5_000);
                std::thread::sleep(std::time::Duration::from_secs(7));
                return Ok(None);
            }
            let until = std::time::Instant::now() + std::time::Duration::from_secs(155);
            while let Some(remaining) = until.checked_duration_since(std::time::Instant::now()) {
                // This separate documentation action keeps actual posture current.
                // Only the kernel's real medium reauthentication BETWEEN
                // the two waits may renew its own continuous watch activity.
                renew_actual_portable_posture(&self.target, 300_000);
                std::thread::sleep(remaining.min(std::time::Duration::from_secs(30)));
            }
        }
        assert_eq!(self.run_id, Some(request.run_id()));
        renew_actual_portable_posture(&self.target, 300_000);
        Ok(self.media.remove(&request.medium_id_hash()))
    }
    fn medium_result(
        &mut self,
        result: &RecoveryMediumObservation,
    ) -> Result<(), RecoveryTestAbort> {
        assert_eq!(
            result.status(),
            ea_admin::recovery_test_runtime::RecoveryMediumStatus::Passed
        );
        self.observed += 1;
        Ok(())
    }
    fn ensure_active(&self) -> Result<(), RecoveryTestAbort> {
        Ok(())
    }
}

#[test]
#[ignore = "real >5min waiting plus every actual native/backup medium; root-owned foreign-machine fixture"]
fn portable_native_long_guided_run_keeps_fresh_actions_and_real_completion_time() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let _watch = LongFixtureWatch::open(&target);
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let mapping: Vec<Value> =
        serde_json::from_slice(&fs::read(export.join("media.json")).unwrap()).unwrap();
    let media = inventory
        .media()
        .iter()
        .map(|medium| {
            let row = mapping
                .iter()
                .find(|row| row["mediumId"] == medium.id())
                .unwrap();
            let input = if row.get("nativeSlot").is_some() {
                RecoveryMediumInput::NativeSigningSlot(RecoveryNativeSigningSlot::Admin)
            } else {
                RecoveryMediumInput::Offline(ea_recovery::KeySourceSpec::Container {
                    path: export.join(row["container"].as_str().unwrap()),
                    passphrase_file: export.join(row["passphraseFile"].as_str().unwrap()),
                })
            };
            (medium.pseudonymous_id_hash(), input)
        })
        .collect();
    let mut runtime = open_portable_target(&export, &target);
    let restored_path = target.join("restored-sources.sqlite");
    let restored = runtime
        .reopen_restored_source(&inventory, &restored_path)
        .unwrap();
    let before = report_counts(&runtime);
    let mut guide = LongGuide {
        target: target.clone(),
        media,
        waited: 0,
        expire: false,
        run_id: None,
        observed: 0,
    };
    let started = std::time::Instant::now();
    let result = runtime
        .run_restored_test_guided(&restored, &inventory, &mut guide)
        .unwrap();
    let ea_admin::recovery_test_runtime::RecoveryTestOutcome::Completed(report) = result else {
        panic!("all actual media passed")
    };
    assert_eq!(guide.waited, 2);
    assert!(started.elapsed() > std::time::Duration::from_secs(300));
    let public: Value = serde_json::from_slice(report.public_report()).unwrap();
    assert!(report.completed_at().get() - public["effectiveNow"].as_i64().unwrap() > 300_000);
    assert_eq!(public["testId"], hex::encode(guide.run_id.unwrap()));
    assert_eq!(guide.observed, inventory.media().len());
    assert_eq!(report.tested_media_count(), inventory.media().len());
    assert_eq!(report_counts(&runtime), (before.0 + 1, before.1));
    let exact = report.exact_envelope().to_vec();
    restored.verify_unchanged().unwrap();
    drop(restored);
    drop(runtime);
    let mut reopened = open_portable_target(&export, &target);
    assert_eq!(
        reopened
            .read_completed_report(&inventory, &restored_path)
            .unwrap()
            .unwrap()
            .exact_envelope(),
        exact
    );
    if let Some(path) = std::env::var_os("EA_T9_LONG_COMPLETION_EXPORT") {
        write_private(Path::new(&path), &exact);
    }
}

#[test]
#[ignore = "actual signed admission expires during user wait; no report or status mutation"]
fn portable_native_long_wait_does_not_override_expired_action_admission() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let mut runtime = open_portable_target(&export, &target);
    let restored = runtime
        .reopen_restored_source(&inventory, &target.join("restored-sources.sqlite"))
        .unwrap();
    let before = report_counts(&runtime);
    let mut guide = LongGuide {
        target: target.clone(),
        media: Default::default(),
        waited: 0,
        expire: true,
        run_id: None,
        observed: 0,
    };
    let error = match runtime.run_restored_test_guided(&restored, &inventory, &mut guide) {
        Ok(_) => panic!("expired admission cannot finish"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "EA-OPERATOR-POSTURE");
    assert_eq!(guide.waited, 1);
    assert_eq!(guide.observed, 0);
    assert_eq!(report_counts(&runtime), before);
    restored.verify_unchanged().unwrap();
    drop(restored);
    drop(runtime);
    assert_eq!(
        report_counts(&open_portable_target(&export, &target)),
        before
    );
}

struct InactiveGuide {
    target: PathBuf,
    requests: usize,
}
impl RecoveryTestGuide for InactiveGuide {
    fn request_medium(
        &mut self,
        _: &RecoveryMediumRequest,
    ) -> Result<Option<RecoveryMediumInput>, RecoveryTestAbort> {
        self.requests += 1;
        let until = std::time::Instant::now() + std::time::Duration::from_secs(305);
        while let Some(remaining) = until.checked_duration_since(std::time::Instant::now()) {
            // A DIFFERENT native provider/watch documents current prerequisites.
            // It provides no verified activity to the blocked original watch.
            renew_actual_portable_posture(&self.target, 300_000);
            std::thread::sleep(remaining.min(std::time::Duration::from_secs(30)));
        }
        Ok(None)
    }
    fn medium_result(&mut self, _: &RecoveryMediumObservation) -> Result<(), RecoveryTestAbort> {
        panic!("the idle original session cannot reach any medium result")
    }
    fn ensure_active(&self) -> Result<(), RecoveryTestAbort> {
        Ok(())
    }
}

#[test]
#[ignore = "actual single305s inactivity with current posture and an unchanged foreign-machine source"]
fn portable_native_inactive_wait_expires_same_watch_without_changing_reports() {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let _watch = LongFixtureWatch::open(&target);
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let mut runtime = open_portable_target(&export, &target);
    let restored = runtime
        .reopen_restored_source(&inventory, &target.join("restored-sources.sqlite"))
        .unwrap();
    let before = report_counts(&runtime);
    let old_native = Arc::clone(runtime.runtime().native());
    let mut guide = InactiveGuide {
        target: target.clone(),
        requests: 0,
    };
    let started = std::time::Instant::now();
    let error = match runtime.run_restored_test_guided(&restored, &inventory, &mut guide) {
        Ok(_) => panic!("an inactive session cannot produce any report"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "EA-OPERATOR-NATIVE-LOCKED");
    assert!(started.elapsed() > std::time::Duration::from_secs(300));
    assert_eq!(guide.requests, 1);
    assert_eq!(report_counts(&runtime), before);
    assert!(old_native.ensure_session_active().is_err());
    restored.verify_unchanged().unwrap();
    drop(restored);
    drop(runtime);
    // This is an explicit new login in the fixture, not automatic revival.
    let reopened = open_portable_target(&export, &target);
    assert_eq!(report_counts(&reopened), before);
    reopened.runtime().native().ensure_session_active().unwrap();
    assert!(old_native.ensure_session_active().is_err());
}
