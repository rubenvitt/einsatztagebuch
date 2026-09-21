//! A recovery worker owns its native runtime. Public progress and correlated
//! input are separate from the private handoff of an actual native role proof.
mod config;
mod guide;
mod mailbox;
mod session;

use super::{CONFIG_ERROR, NativeDesktopRuntime};
use crate::{
    commands::CommandError,
    state::{RecoveryAdministrationPort, RecoveryMediumChoice, RuntimeSessionPort},
};
use config::{Config, read};
use ea_admin::{
    operator_runtime::OperatorRuntime,
    recovery_test_runtime::{
        RecoverySourceRestore, RecoveryTestGuide, RecoveryTestOutcome, RecoveryTestRuntime,
        parse_recovery_archive_profile, parse_recovery_media_sources,
    },
};
use ea_ui_contracts::{RecoveryAdministrationView, RecoveryReportView};
use guide::{DesktopGuide, hex};
use mailbox::{Mailbox, MediumChoice};
use std::{
    path::Path,
    sync::{Arc, Mutex, atomic::Ordering},
};

#[derive(Clone, Default)]
struct Reports {
    success: Option<RecoveryReportView>,
    failure: Option<RecoveryReportView>,
}
pub(super) struct RecoveryResources {
    config: Config,
    slot: Mutex<Option<Arc<Mailbox>>>,
    reports: Arc<Mutex<Reports>>,
    role_sessions: Arc<session::RoleSessionInbox>,
}
fn error(code: &'static str) -> CommandError {
    CommandError::new(code)
}
fn cancelled(_: ea_admin::recovery_test_runtime::RecoveryTestAbort) -> CommandError {
    error("EA-RECOVERY-TEST-CANCELLED")
}
fn runtime_error(error: ea_admin::recovery_test_runtime::RecoveryRuntimeError) -> CommandError {
    CommandError::new(error.code())
}
impl RecoveryResources {
    pub(super) fn open(
        path: &Path,
        runtime: &ea_admin::operator_runtime::writer::InteractiveOperatorRuntime,
    ) -> Result<Self, CommandError> {
        if runtime.config().role != ea_format::OperatorRoleV1::OrganizationAdmin {
            return Err(error(CONFIG_ERROR));
        }
        Ok(Self {
            config: Config::load(path)?,
            slot: Mutex::new(None),
            reports: Arc::new(Mutex::new(Reports::default())),
            role_sessions: Arc::new(session::RoleSessionInbox::default()),
        })
    }
    pub(super) fn role_session(
        &self,
        epoch: u64,
    ) -> Result<Option<Arc<ea_operator::OperatorSessionProof>>, CommandError> {
        self.role_sessions.for_epoch(epoch)
    }
    fn current(&self) -> Result<Option<Arc<Mailbox>>, CommandError> {
        Ok(self
            .slot
            .lock()
            .map_err(|_| error("EA-DESKTOP-RUNTIME-LOCK"))?
            .clone())
    }
    fn snapshot(&self) -> Result<RecoveryAdministrationView, CommandError> {
        let run = self
            .current()?
            .map(|mailbox| mailbox.view().map_err(cancelled))
            .transpose()?;
        let reports = self
            .reports
            .lock()
            .map_err(|_| error("EA-DESKTOP-RUNTIME-LOCK"))?
            .clone();
        Ok(RecoveryAdministrationView {
            last_success: reports.success,
            last_failure: reports.failure,
            run,
        })
    }
}
fn inventory(config: &Config) -> Result<ea_recovery::KeyInventory, CommandError> {
    ea_recovery::KeyInventory::parse(&read(&config.key_inventory_path, 1024 * 1024)?)
        .map_err(|error| CommandError::new(error.code()))
}
fn service(config: &Config, runtime: OperatorRuntime) -> Result<RecoveryTestRuntime, CommandError> {
    let profile = parse_recovery_archive_profile(&read(&config.archive_profile_path, 65_536)?)
        .map_err(runtime_error)?;
    let archive_config = ea_admin::native_archive::NativeArchiveConfig::for_runtime_database(
        profile,
        &runtime.config().database_path,
    );
    RecoveryTestRuntime::with_archive_config(runtime, archive_config).map_err(runtime_error)
}
fn read_reports(
    config: &Config,
    service: &mut RecoveryTestRuntime,
    inventory: &ea_recovery::KeyInventory,
) -> Result<Reports, CommandError> {
    if !config
        .restored_source_database_path
        .try_exists()
        .map_err(|_| error(CONFIG_ERROR))?
    {
        return Ok(Reports::default());
    }
    Ok(Reports {
        success: service
            .read_completed_report(inventory, &config.restored_source_database_path)
            .map_err(runtime_error)?
            .as_ref()
            .map(completed)
            .transpose()?,
        failure: service
            .read_failed_report(inventory, &config.restored_source_database_path)
            .map_err(runtime_error)?
            .as_ref()
            .map(failed)
            .transpose()?,
    })
}
fn completed(
    value: &ea_recovery::VerifiedCompletedRecoveryReport,
) -> Result<RecoveryReportView, CommandError> {
    Ok(RecoveryReportView {
        completed: true,
        exact_public_report_json: std::str::from_utf8(value.public_report())
            .map_err(|_| error("EA-DESKTOP-RECOVERY-WIRE-VALUE"))?
            .into(),
        envelope_hash: hex(value.envelope_hash().as_bytes()),
        source_envelope_hash: hex(value.source_envelope_hash().as_bytes()),
        audit_id: hex(value.audit_id().as_bytes()),
        finished_at_ms: value.completed_at().get(),
        next_due_at_ms: Some(value.next_due_at().get()),
    })
}
fn failed(
    value: &ea_recovery::VerifiedFailedRecoveryReport,
) -> Result<RecoveryReportView, CommandError> {
    Ok(RecoveryReportView {
        completed: false,
        exact_public_report_json: std::str::from_utf8(value.public_report())
            .map_err(|_| error("EA-DESKTOP-RECOVERY-WIRE-VALUE"))?
            .into(),
        envelope_hash: hex(value.envelope_hash().as_bytes()),
        source_envelope_hash: hex(value.source_envelope_hash().as_bytes()),
        audit_id: hex(value.audit_id().as_bytes()),
        finished_at_ms: value.failed_at().get(),
        next_due_at_ms: None,
    })
}
fn worker(
    config: &Config,
    runtime: OperatorRuntime,
    mailbox: Arc<Mailbox>,
    cache: &Mutex<Reports>,
    role_sessions: Arc<session::RoleSessionInbox>,
    epoch: u64,
) -> Result<RecoveryReportView, CommandError> {
    mailbox.ensure_active().map_err(cancelled)?;
    let inventory = inventory(config)?;
    let mut service = service(config, runtime)?;
    let mut sources =
        parse_recovery_media_sources(&read(&config.media_sources_path, 1024 * 1024)?, &inventory)
            .map_err(runtime_error)?;
    let media_directory = config
        .media_sources_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    for row in &mut sources {
        config::resolve_medium_source(&mut row.source, media_directory)?;
    }
    let mut observer = session::SessionObserver {
        epoch,
        mailbox: mailbox.clone(),
        inbox: role_sessions,
    };
    let mut guide = DesktopGuide {
        mailbox,
        media: sources,
        pending: None,
    };
    guide.ensure_active().map_err(cancelled)?;
    *cache.lock().map_err(|_| error("EA-DESKTOP-RUNTIME-LOCK"))? =
        read_reports(config, &mut service, &inventory)?;
    let restored = if config
        .restored_source_database_path
        .try_exists()
        .map_err(|_| error(CONFIG_ERROR))?
    {
        service
            .reopen_restored_source(&inventory, &config.restored_source_database_path)
            .map_err(runtime_error)?
    } else {
        let restore = config
            .initial_restore
            .as_ref()
            .ok_or_else(|| error("EA-RECOVERY-TEST-INCOMPLETE"))?;
        let exact = read(&restore.exact_source_path, 512 * 1024)?;
        let phrase = ea_recovery::read_secret_file(&restore.passphrase_file)
            .map_err(|error| CommandError::new(error.code()))?;
        guide.ensure_active().map_err(cancelled)?;
        service
            .restore_source(RecoverySourceRestore {
                inventory: &inventory,
                exact_source: &exact,
                snapshot: &restore.snapshot_path,
                passphrase: &phrase,
                target: &config.restored_source_database_path,
            })
            .map_err(runtime_error)?
    };
    guide.ensure_active().map_err(cancelled)?;
    let outcome = service
        .run_restored_test_guided_with_session_observer(
            &restored,
            &inventory,
            &mut guide,
            &mut observer,
        )
        .map_err(runtime_error)?;
    let observed = match outcome {
        RecoveryTestOutcome::Completed(report) => completed(&report)?,
        RecoveryTestOutcome::Failed(report) => failed(&report)?,
    };
    // The verified kernel outcome already includes the successful durable
    // commit. Later cancellation or expired authority may block a fresh read,
    // but cannot turn that historical result into a refused/cancelled run.
    // Idle IPC reads reopen and verify persistence under their own fresh gates.
    let mut reports = cache.lock().map_err(|_| error("EA-DESKTOP-RUNTIME-LOCK"))?;
    if observed.completed {
        reports.success = Some(observed.clone());
    } else {
        reports.failure = Some(observed.clone());
    }
    Ok(observed)
}
impl NativeDesktopRuntime {
    fn recovery_context(&self) -> Result<(u64, OperatorRuntime), CommandError> {
        let epoch = self.session_epoch.load(Ordering::SeqCst);
        if epoch & 1 != 0
            || self.verified_role()? != Some(ea_format::OperatorRoleV1::OrganizationAdmin)
        {
            return Err(error("EA-DESKTOP-ADMINISTRATION-FORBIDDEN"));
        }
        let inner = self
            .inner
            .lock()
            .map_err(|_| error("EA-DESKTOP-RUNTIME-LOCK"))?;
        let current = inner.runtime.current().ok_or_else(|| error(CONFIG_ERROR))?;
        let runtime = current
            .reopened_for_action()
            .map_err(|error| CommandError::new(error.code()))?;
        if self.session_epoch.load(Ordering::SeqCst) != epoch {
            return Err(error("EA-DESKTOP-SESSION-LOCKED"));
        }
        Ok((epoch, runtime))
    }
    fn recovery_resources(&self) -> Result<&RecoveryResources, CommandError> {
        if self.verified_role()? != Some(ea_format::OperatorRoleV1::OrganizationAdmin) {
            return Err(error("EA-DESKTOP-ADMINISTRATION-FORBIDDEN"));
        }
        self.recovery
            .as_ref()
            .ok_or_else(|| error("EA-DESKTOP-RECOVERY-UNAVAILABLE"))
    }
}
impl RecoveryAdministrationPort for NativeDesktopRuntime {
    fn read(&self) -> Result<RecoveryAdministrationView, CommandError> {
        let resources = self.recovery_resources()?;
        if resources
            .current()?
            .is_some_and(|mailbox| mailbox.is_running())
        {
            // The command role gate and host watcher are independent of the
            // worker. Do not acquire its DB/backend lock during user input.
            return resources.snapshot();
        }
        let (epoch, runtime) = self.recovery_context()?;
        let inventory = inventory(&resources.config)?;
        let mut service = service(&resources.config, runtime)?;
        let reports = read_reports(&resources.config, &mut service, &inventory)?;
        if self.session_epoch.load(Ordering::SeqCst) != epoch {
            return Err(error("EA-DESKTOP-SESSION-LOCKED"));
        }
        *resources
            .reports
            .lock()
            .map_err(|_| error("EA-DESKTOP-RUNTIME-LOCK"))? = reports;
        resources.snapshot()
    }
    fn start(&self) -> Result<RecoveryAdministrationView, CommandError> {
        let (epoch, runtime) = self.recovery_context()?;
        let resources = self.recovery_resources()?;
        let mut slot = resources
            .slot
            .lock()
            .map_err(|_| error("EA-DESKTOP-RUNTIME-LOCK"))?;
        if slot.as_ref().is_some_and(|previous| previous.is_running()) {
            return Err(error("EA-DESKTOP-RECOVERY-BUSY"));
        }
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| error("EA-DESKTOP-RECOVERY-ENTROPY"))?;
        let mailbox = Arc::new(Mailbox::new(hex(&id), self.session_epoch.clone(), epoch));
        *slot = Some(mailbox.clone());
        drop(slot);
        let config = resources.config.clone();
        let cache = resources.reports.clone();
        let role_sessions = resources.role_sessions.clone();
        let worker_mailbox = mailbox.clone();
        let spawned = std::thread::Builder::new()
            .name("native-recovery-test".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker(
                        &config,
                        runtime,
                        worker_mailbox.clone(),
                        &cache,
                        role_sessions,
                        epoch,
                    )
                }))
                .unwrap_or_else(|_| Err(error("EA-DESKTOP-RECOVERY-WORKER")));
                let _ = worker_mailbox.finish(result.map_err(|error| error.code.to_owned()));
            });
        if spawned.is_err() {
            let _ = mailbox.finish(Err("EA-DESKTOP-RECOVERY-WORKER".into()));
        }
        resources.snapshot()
    }
    fn submit(
        &self,
        operation: &str,
        run: &str,
        request: &str,
        choice: RecoveryMediumChoice,
    ) -> Result<RecoveryAdministrationView, CommandError> {
        let resources = self.recovery_resources()?;
        let mailbox = resources
            .current()?
            .ok_or_else(|| error("EA-DESKTOP-RECOVERY-NO-RUN"))?;
        mailbox
            .submit(
                operation,
                run,
                request,
                match choice {
                    RecoveryMediumChoice::UseConfiguredSource => MediumChoice::UseConfiguredSource,
                    RecoveryMediumChoice::Missing => MediumChoice::Missing,
                },
            )
            .map_err(cancelled)?;
        resources.snapshot()
    }
    fn cancel(&self, operation: &str) -> Result<RecoveryAdministrationView, CommandError> {
        let resources = self.recovery_resources()?;
        resources
            .current()?
            .ok_or_else(|| error("EA-DESKTOP-RECOVERY-NO-RUN"))?
            .cancel(operation)
            .map_err(cancelled)?;
        resources.snapshot()
    }
}
