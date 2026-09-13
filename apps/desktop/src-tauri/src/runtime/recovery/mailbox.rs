use ea_admin::recovery_test_runtime::RecoveryTestAbort;
use ea_ui_contracts::{
    RecoveryMediumObservationView, RecoveryMediumRequestView, RecoveryReportView, RecoveryRunView,
};
use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MediumChoice {
    UseConfiguredSource,
    Missing,
}

pub(super) struct Mailbox {
    operation: String,
    epoch: Arc<AtomicU64>,
    expected: u64,
    cancelled: AtomicBool,
    worker_finished: AtomicBool,
    progress: Mutex<Progress>,
    changed: Condvar,
}
struct Progress {
    view: RecoveryRunView,
    choice: Option<MediumChoice>,
}
impl Mailbox {
    pub(super) fn is_running(&self) -> bool {
        !self.worker_finished.load(Ordering::SeqCst)
    }
    pub(super) fn finish(
        &self,
        result: Result<RecoveryReportView, String>,
    ) -> Result<(), RecoveryTestAbort> {
        // Only the worker's final return path calls finish, including after a
        // cancellation. Public terminal state alone never releases this slot.
        let mut state = self.progress.lock().map_err(|_| RecoveryTestAbort)?;
        if self.worker_finished.load(Ordering::SeqCst) {
            return Err(RecoveryTestAbort);
        }
        state.choice = None;
        state.view.request = None;
        match result {
            Ok(report) => {
                // The worker can return a report only after the kernel's
                // successful durable commit. A later cancel/epoch change
                // cannot revoke history; every IPC read still gates identity.
                state.view.phase_code = if report.completed { 3 } else { 4 };
                state.view.report = Some(report);
                state.view.error_code = None;
            }
            Err(error) => {
                state.view.phase_code = if error == "EA-RECOVERY-TEST-CANCELLED" {
                    5
                } else {
                    6
                };
                state.view.error_code = Some(error);
            }
        }
        self.worker_finished.store(true, Ordering::SeqCst);
        self.changed.notify_all();
        Ok(())
    }
    pub(super) fn observe(
        &self,
        observation: RecoveryMediumObservationView,
    ) -> Result<(), RecoveryTestAbort> {
        self.ensure_active()?;
        let mut state = self.progress.lock().map_err(|_| RecoveryTestAbort)?;
        self.ensure_active()?;
        if state.view.phase_code != 2
            || state.choice.is_some()
            || state.view.request.as_ref() != Some(&observation.request)
        {
            return Err(RecoveryTestAbort);
        }
        state.view.observations.push(observation);
        state.view.request = None;
        state.view.phase_code = 0;
        Ok(())
    }
    pub(super) fn new(id: String, epoch: Arc<AtomicU64>, expected: u64) -> Self {
        Self {
            operation: id.clone(),
            epoch,
            expected,
            cancelled: AtomicBool::new(false),
            worker_finished: AtomicBool::new(false),
            progress: Mutex::new(Progress {
                view: RecoveryRunView {
                    operation_id: id,
                    phase_code: 0,
                    request: None,
                    observations: Vec::new(),
                    report: None,
                    error_code: None,
                },
                choice: None,
            }),
            changed: Condvar::new(),
        }
    }
    pub(super) fn ensure_active(&self) -> Result<(), RecoveryTestAbort> {
        if self.cancelled.load(Ordering::SeqCst)
            || self.expected & 1 != 0
            || self.epoch.load(Ordering::SeqCst) != self.expected
        {
            Err(RecoveryTestAbort)
        } else {
            Ok(())
        }
    }
    pub(super) fn view(&self) -> Result<RecoveryRunView, RecoveryTestAbort> {
        let mut state = self.progress.lock().map_err(|_| RecoveryTestAbort)?;
        if self.ensure_active().is_err() && state.view.phase_code < 3 {
            Self::mark_cancel_requested(&mut state);
        }
        Ok(state.view.clone())
    }
    fn mark_cancel_requested(state: &mut Progress) {
        state.choice = None;
        state.view.request = None;
        state.view.phase_code = 7;
        state.view.error_code = None;
    }
    pub(super) fn request(
        &self,
        request: RecoveryMediumRequestView,
    ) -> Result<MediumChoice, RecoveryTestAbort> {
        self.ensure_active()?;
        let mut state = self.progress.lock().map_err(|_| RecoveryTestAbort)?;
        if state.view.phase_code != 0 || state.view.request.is_some() || state.choice.is_some() {
            return Err(RecoveryTestAbort);
        }
        state.view.request = Some(request);
        state.view.phase_code = 1;
        loop {
            if self.ensure_active().is_err() {
                Self::mark_cancel_requested(&mut state);
                return Err(RecoveryTestAbort);
            }
            if let Some(choice) = state.choice.take() {
                return Ok(choice);
            }
            // The timeout observes native epoch changes without relying on a
            // renderer callback or acquiring the worker's runtime/DB mutex.
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(100))
                .map_err(|_| RecoveryTestAbort)?
                .0;
        }
    }
    pub(super) fn submit(
        &self,
        operation: &str,
        run: &str,
        request: &str,
        choice: MediumChoice,
    ) -> Result<(), RecoveryTestAbort> {
        self.ensure_active()?;
        let mut state = self.progress.lock().map_err(|_| RecoveryTestAbort)?;
        self.ensure_active()?;
        if operation != self.operation
            || state.view.phase_code != 1
            || state.choice.is_some()
            || !state
                .view
                .request
                .as_ref()
                .is_some_and(|pending| pending.run_id == run && pending.request_id == request)
        {
            return Err(RecoveryTestAbort);
        }
        state.choice = Some(choice);
        state.view.phase_code = 2;
        self.changed.notify_all();
        Ok(())
    }
    pub(super) fn cancel(&self, operation: &str) -> Result<(), RecoveryTestAbort> {
        if operation != self.operation {
            return Err(RecoveryTestAbort);
        }
        let mut state = self.progress.lock().map_err(|_| RecoveryTestAbort)?;
        // A cancellation after a terminal persisted result cannot rewrite it.
        if self.worker_finished.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.cancelled.store(true, Ordering::SeqCst);
        Self::mark_cancel_requested(&mut state);
        self.changed.notify_all();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::Ordering,
        time::{Duration, Instant},
    };

    fn request() -> RecoveryMediumRequestView {
        RecoveryMediumRequestView {
            run_id: "11".repeat(16),
            request_id: "22".repeat(32),
            medium_id_hash: "33".repeat(32),
            index: 1,
            total: 2,
            role_code: "root-signing".into(),
            certificate_hash: "44".repeat(32),
            expected_thumbprint: "55".repeat(32),
            protection_code: 1,
            test_kind_code: "sign-challenge".into(),
        }
    }
    fn wait_for_request(mailbox: &Mailbox) -> RecoveryRunView {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let view = mailbox
                .view()
                .expect("public progress remains readable while waiting");
            if view.phase_code == 1 {
                return view;
            }
            assert!(Instant::now() < deadline, "worker did not publish request");
            std::thread::yield_now();
        }
    }
    #[test]
    fn requested_cancel_waits_for_worker_and_preserves_its_durable_terminal_result() {
        for completed in [false, true] {
            let mailbox = Mailbox::new("operation".into(), Arc::new(AtomicU64::new(0)), 0);
            mailbox.cancel("operation").unwrap();
            let pending = mailbox.view().unwrap();
            assert_eq!(
                pending.phase_code, 7,
                "cancellation is not yet a native outcome"
            );
            assert!(pending.report.is_none());
            assert!(pending.error_code.is_none());
            assert!(mailbox.is_running());
            let mut committed = report();
            committed.completed = completed;
            committed.next_due_at_ms = completed.then_some(1_700_086_400_000);
            mailbox.finish(Ok(committed.clone())).unwrap();
            let terminal = mailbox.view().unwrap();
            assert_eq!(terminal.phase_code, if completed { 3 } else { 4 });
            assert_eq!(terminal.report, Some(committed));
            assert!(terminal.error_code.is_none());
            assert!(!mailbox.is_running());
        }
    }
    #[test]
    fn a_worker_that_aborts_without_a_commit_confirms_cancelled_only_on_return() {
        let mailbox = Mailbox::new("operation".into(), Arc::new(AtomicU64::new(0)), 0);
        mailbox.cancel("operation").unwrap();
        assert_eq!(mailbox.view().unwrap().phase_code, 7);
        mailbox
            .finish(Err("EA-RECOVERY-TEST-CANCELLED".into()))
            .unwrap();
        let terminal = mailbox.view().unwrap();
        assert_eq!(terminal.phase_code, 5);
        assert!(terminal.report.is_none());
        assert!(!mailbox.is_running());
    }
    #[test]
    fn only_the_exact_pending_request_can_consume_one_user_choice() {
        let mailbox = Arc::new(Mailbox::new(
            "operation".into(),
            Arc::new(AtomicU64::new(0)),
            0,
        ));
        let worker_mailbox = mailbox.clone();
        let worker = std::thread::spawn(move || worker_mailbox.request(request()));
        let view = wait_for_request(&mailbox);
        assert_eq!(view.request.as_ref().unwrap(), &request());
        for (operation, run, req) in [
            ("old-operation", "11".repeat(16), "22".repeat(32)),
            ("operation", "99".repeat(16), "22".repeat(32)),
            ("operation", "11".repeat(16), "99".repeat(32)),
        ] {
            assert!(
                mailbox
                    .submit(operation, &run, &req, MediumChoice::Missing)
                    .is_err()
            );
        }
        mailbox
            .submit(
                "operation",
                &"11".repeat(16),
                &"22".repeat(32),
                MediumChoice::UseConfiguredSource,
            )
            .unwrap();
        assert!(
            mailbox
                .submit(
                    "operation",
                    &"11".repeat(16),
                    &"22".repeat(32),
                    MediumChoice::Missing
                )
                .is_err()
        );
        assert_eq!(
            worker.join().unwrap().unwrap(),
            MediumChoice::UseConfiguredSource
        );
        assert_eq!(mailbox.view().unwrap().phase_code, 2);
    }
    #[test]
    fn cancel_wakes_the_waiter_without_a_native_runtime_lock() {
        let mailbox = Arc::new(Mailbox::new(
            "operation".into(),
            Arc::new(AtomicU64::new(0)),
            0,
        ));
        let worker_mailbox = mailbox.clone();
        let worker = std::thread::spawn(move || worker_mailbox.request(request()));
        wait_for_request(&mailbox);
        assert!(mailbox.cancel("another-operation").is_err());
        mailbox.cancel("operation").unwrap();
        assert!(worker.join().unwrap().is_err());
        let view = mailbox.view().unwrap();
        assert_eq!(view.phase_code, 7);
        assert!(view.report.is_none());
        assert!(view.request.is_none());
    }
    #[test]
    fn changed_epoch_aborts_wait_even_if_session_has_already_been_unlocked_again() {
        let epoch = Arc::new(AtomicU64::new(0));
        let mailbox = Arc::new(Mailbox::new("operation".into(), epoch.clone(), 0));
        let worker_mailbox = mailbox.clone();
        let worker = std::thread::spawn(move || worker_mailbox.request(request()));
        wait_for_request(&mailbox);
        epoch.store(2, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !worker.is_finished() {
            assert!(
                Instant::now() < deadline,
                "epoch change did not release worker"
            );
            std::thread::yield_now();
        }
        assert!(worker.join().unwrap().is_err());
        assert!(
            mailbox
                .submit(
                    "operation",
                    &"11".repeat(16),
                    &"22".repeat(32),
                    MediumChoice::Missing
                )
                .is_err()
        );
    }
    #[test]
    fn a_previous_answer_cannot_confirm_the_next_medium_and_only_actual_observations_advance() {
        let mailbox = Arc::new(Mailbox::new(
            "operation".into(),
            Arc::new(AtomicU64::new(0)),
            0,
        ));
        let worker_mailbox = mailbox.clone();
        let worker = std::thread::spawn(move || worker_mailbox.request(request()));
        wait_for_request(&mailbox);
        mailbox
            .submit(
                "operation",
                &"11".repeat(16),
                &"22".repeat(32),
                MediumChoice::Missing,
            )
            .unwrap();
        worker.join().unwrap().unwrap();
        assert!(mailbox.view().unwrap().observations.is_empty());
        let observation = RecoveryMediumObservationView {
            request: request(),
            result_code: 1,
            observed_thumbprint: None,
            error_code: Some("EA-RECOVERY-TEST-INCOMPLETE".into()),
        };
        let mut mismatched = observation.clone();
        mismatched.request.request_id = "99".repeat(32);
        assert!(mailbox.observe(mismatched).is_err());
        mailbox.observe(observation.clone()).unwrap();
        assert_eq!(mailbox.view().unwrap().observations, vec![observation]);
        let worker_mailbox = mailbox.clone();
        let worker = std::thread::spawn(move || {
            let mut next = request();
            next.request_id = "66".repeat(32);
            next.medium_id_hash = "77".repeat(32);
            next.index = 2;
            worker_mailbox.request(next)
        });
        wait_for_request(&mailbox);
        assert!(
            mailbox
                .submit(
                    "operation",
                    &"11".repeat(16),
                    &"22".repeat(32),
                    MediumChoice::Missing
                )
                .is_err()
        );
        mailbox
            .submit(
                "operation",
                &"11".repeat(16),
                &"66".repeat(32),
                MediumChoice::UseConfiguredSource,
            )
            .unwrap();
        assert_eq!(
            worker.join().unwrap().unwrap(),
            MediumChoice::UseConfiguredSource
        );
    }
    #[test]
    fn cancelled_or_closed_epoch_still_denies_new_work_but_preserves_a_committed_report() {
        for close_epoch in [false, true] {
            let epoch = Arc::new(AtomicU64::new(0));
            let mailbox = Mailbox::new("operation".into(), epoch.clone(), 0);
            if close_epoch {
                epoch.store(1, Ordering::SeqCst);
            } else {
                mailbox.cancel("operation").unwrap();
            }
            assert!(mailbox.ensure_active().is_err());
            mailbox.finish(Ok(report())).unwrap();
            let view = mailbox.view().unwrap();
            assert_eq!(view.phase_code, 3);
            assert_eq!(view.report, Some(report()));
            assert!(mailbox.ensure_active().is_err());
        }
    }
    fn report() -> RecoveryReportView {
        RecoveryReportView {
            completed: true,
            exact_public_report_json: "{}".into(),
            envelope_hash: "aa".repeat(32),
            source_envelope_hash: "bb".repeat(32),
            audit_id: "cc".repeat(16),
            finished_at_ms: 1_700_000_000_000,
            next_due_at_ms: Some(1_700_086_400_000),
        }
    }
    #[test]
    fn terminal_persisted_result_is_not_overwritten_by_late_cancel_or_second_finish() {
        let mailbox = Mailbox::new("operation".into(), Arc::new(AtomicU64::new(0)), 0);
        mailbox.finish(Ok(report())).unwrap();
        mailbox.cancel("operation").unwrap();
        assert!(mailbox.finish(Err("late failure".into())).is_err());
        let view = mailbox.view().unwrap();
        assert_eq!(view.phase_code, 3);
        assert_eq!(view.report, Some(report()));
    }
    #[test]
    fn cancellation_does_not_release_the_worker_slot_before_native_work_returns() {
        let mailbox = Mailbox::new("operation".into(), Arc::new(AtomicU64::new(0)), 0);
        assert!(mailbox.is_running());
        mailbox.cancel("operation").unwrap();
        assert!(
            mailbox.is_running(),
            "cancel must not admit a concurrent native worker"
        );
        mailbox
            .finish(Err("EA-RECOVERY-TEST-CANCELLED".into()))
            .unwrap();
        assert!(!mailbox.is_running());
    }
}
