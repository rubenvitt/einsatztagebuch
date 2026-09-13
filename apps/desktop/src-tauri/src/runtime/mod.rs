//! Native desktop composition. Configuration carries public references only;
//! authority comes from the installed helper, current signed archive and proofs.

mod archive_config;
mod administration;
mod destruction;
pub mod destruction_transport;
mod drafts;
mod recovery;
mod writer;
mod writer_config;

use crate::{
    commands::CommandError,
    state::{DesktopState, ReauthPort, RuntimeSessionPort, SessionState},
};
use ea_admin::{
    VerifiedOperatorSession,
    native_provider::NativeOperatorProvider,
    operator_runtime::{OperatorRuntimeConfig, writer::InteractiveOperatorRuntime},
};
use ea_format::OperatorRoleV1;
use ea_operator::ReauthPurpose;
use ea_types::UnixMillis;
use std::{
    collections::HashMap,
    ffi::OsString,
    path::PathBuf,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const CONFIG_ERROR: &str = "EA-DESKTOP-LAUNCH-CONFIG";

/// Explicit independent anchor and public operator configuration. Neither a
/// helper path, account identity nor an invented role is accepted at launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopLaunchConfig {
    pub operator_config: PathBuf,
    pub trust_anchor: PathBuf,
    pub writer_config: Option<PathBuf>,
    pub destruction_config: Option<PathBuf>,
    pub recovery_config: Option<PathBuf>,
    pub administration_config: Option<PathBuf>,
}
impl DesktopLaunchConfig {
    /// `arguments` excludes the executable name. An ordinary unconfigured
    /// launch is supported; a half configuration is an error, never a fallback.
    pub fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Option<Self>, CommandError> {
        let mut arguments = arguments.into_iter();
        let mut operator_config = None;
        let mut trust_anchor = None;
        let mut writer_config = None;
        let mut destruction_config = None;
        let mut recovery_config = None;
        let mut administration_config = None;
        while let Some(flag) = arguments.next() {
            let slot = if flag == "--operator-config" {
                &mut operator_config
            } else if flag == "--trust-anchor" {
                &mut trust_anchor
            } else if flag == "--writer-config" {
                &mut writer_config
            } else if flag == "--destruction-config" {
                &mut destruction_config
            } else if flag == "--administration-config" {
                &mut administration_config
            } else if flag == "--recovery-config" {
                &mut recovery_config
            } else {
                return Err(CommandError::new(CONFIG_ERROR));
            };
            if slot.is_some() {
                return Err(CommandError::new(CONFIG_ERROR));
            }
            let value = arguments
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| CommandError::new(CONFIG_ERROR))?;
            if value.to_string_lossy().starts_with("--") {
                return Err(CommandError::new(CONFIG_ERROR));
            }
            *slot = Some(PathBuf::from(value));
        }
        match (operator_config, trust_anchor) {
            (None, None)
                if writer_config.is_none()
                    && destruction_config.is_none()
                    && recovery_config.is_none()
                    && administration_config.is_none() =>
            {
                Ok(None)
            }
            (Some(operator_config), Some(trust_anchor)) => Ok(Some(Self {
                operator_config,
                trust_anchor,
                writer_config,
                destruction_config,
                recovery_config,
                administration_config,
            })),
            _ => Err(CommandError::new(CONFIG_ERROR)),
        }
    }
}

pub(crate) fn now() -> Result<UnixMillis, CommandError> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_millis()).ok())
        .ok_or_else(|| CommandError::new("EA-DESKTOP-CLOCK"))?;
    Ok(UnixMillis::new(value))
}

struct NativeState {
    runtime: InteractiveOperatorRuntime,
    sessions: HashMap<ReauthPurpose, VerifiedOperatorSession>,
    preview: Option<ea_writer::FinalizationPreview>,
    stale_receipt: Option<ea_writer::StaleRegistryAcknowledgement>,
}
impl NativeState {
    fn invalidate(&mut self) {
        self.sessions.clear();
        self.preview = None;
        self.stale_receipt = None;
    }
    fn refresh(&mut self) -> Result<(), CommandError> {
        if self.preview.is_some() {
            let result = self.runtime.reopened_for_action().and_then(|fresh| {
                fresh.ensure_current()?;
                Ok(fresh)
            });
            let fresh = match result {
                Ok(fresh) => fresh,
                Err(error) => {
                    self.invalidate();
                    return Err(CommandError::new(error.code()));
                }
            };
            if fresh.head().registry_head_hash() != self.runtime.head().registry_head_hash()
                || fresh.head().registry_version() != self.runtime.head().registry_version()
                || fresh.next_sequence() != self.runtime.next_sequence()
                || !fresh
                    .head()
                    .preexisting_effective_now()
                    .has_same_persisted_bounds(self.runtime.head().preexisting_effective_now())
            {
                self.invalidate();
                self.runtime = fresh;
                return Err(CommandError::new(crate::commands::PREVIEW_MISMATCH));
            }
            // Preview commits its selected time and recordId. Retain that input
            // only under unchanged durable bounds, and expire held proofs using
            // the freshly selected authority time before any plaintext access.
            self.sessions.retain(|purpose, session| {
                fresh
                    .verify_session_proof(*purpose, session.proof())
                    .is_ok()
            });
            let result = self
                .runtime
                .ensure_current()
                .map_err(|error| CommandError::new(error.code()));
            if result.is_err() {
                self.invalidate();
            }
            return result;
        }
        let result = self
            .runtime
            .refresh_for_action()
            .and_then(|()| self.runtime.ensure_current())
            .map_err(|error| CommandError::new(error.code()));
        if result.is_err() {
            self.invalidate();
        }
        result
    }
    fn verify(
        &self,
        purpose: ReauthPurpose,
        session: &VerifiedOperatorSession,
    ) -> Result<(), CommandError> {
        self.runtime
            .verify_session_proof(purpose, session.proof())
            .map_err(|error| CommandError::new(error.code()))
    }
}

pub struct NativeDesktopRuntime {
    launch: DesktopLaunchConfig,
    role: OperatorRoleV1,
    master_data: Arc<ea_draft::MasterDataRepository>,
    writer: Option<writer::WriterResources>,
    destruction: Option<Mutex<destruction::DestructionResources>>,
    recovery: Option<recovery::RecoveryResources>,
    administration: Option<administration::AdministrationResources>,
    inner: Mutex<NativeState>,
    watcher: RwLock<Arc<NativeOperatorProvider>>,
    // The low bit closes authority immediately. The remaining bits prevent a
    // proof from a dialog already in flight from reopening a locked session.
    session_epoch: Arc<AtomicU64>,
}
impl NativeDesktopRuntime {
    /// Normal startup never initializes keys, installation state or a database.
    pub fn open(launch: DesktopLaunchConfig) -> Result<Arc<Self>, CommandError> {
        let runtime = Self::open_runtime(&launch)?;
        Self::assemble(launch, runtime)
    }
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_with_test_runtime(
        launch: DesktopLaunchConfig,
        runtime: impl Into<InteractiveOperatorRuntime>,
    ) -> Result<Arc<Self>, CommandError> {
        Self::assemble(launch, runtime.into())
    }
    fn assemble(
        launch: DesktopLaunchConfig,
        runtime: InteractiveOperatorRuntime,
    ) -> Result<Arc<Self>, CommandError> {
        Self::assemble_with_destruction(launch, runtime, None)
    }
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_with_test_destruction_runtime(
        launch: DesktopLaunchConfig,
        controller: ea_admin::operator_runtime::OperatorRuntime,
        destruction: ea_admin::destruction_runtime::DestructionRuntime,
    ) -> Result<Arc<Self>, CommandError> {
        Self::assemble_with_destruction(
            launch,
            controller.into(),
            Some(destruction::DestructionResources::with_local_test_runtime(destruction)),
        )
    }
    /// Only the fixture process chooses a native helper. Production loads the installed provider.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_with_test_destruction_configuration(
        launch: DesktopLaunchConfig,
        controller: ea_admin::operator_runtime::OperatorRuntime,
        custodian: Arc<NativeOperatorProvider>,
    ) -> Result<Arc<Self>, CommandError> {
        let resources = destruction::DestructionResources::open_with_test_custodian(
            launch.destruction_config.as_deref().ok_or_else(|| CommandError::new(CONFIG_ERROR))?,
            &controller,
            &launch.trust_anchor,
            custodian,
        )?;
        Self::assemble_with_destruction(launch, controller.into(), Some(resources))
    }
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_with_test_destruction_reopen_configuration(
        launch: DesktopLaunchConfig,
        controller: ea_admin::operator_runtime::OperatorRuntime,
        custodian_helper: &std::path::Path,
    ) -> Result<Arc<Self>, CommandError> {
        let resources = destruction::DestructionResources::open_with_test_custodian_path(
            launch.destruction_config.as_deref().ok_or_else(|| CommandError::new(CONFIG_ERROR))?,
            &controller,
            &launch.trust_anchor,
            custodian_helper,
        )?;
        Self::assemble_with_destruction(launch, controller.into(), Some(resources))
    }
    fn assemble_with_destruction(
        launch: DesktopLaunchConfig,
        runtime: InteractiveOperatorRuntime,
        provided: Option<destruction::DestructionResources>,
    ) -> Result<Arc<Self>, CommandError> {
        if runtime.config().role == OperatorRoleV1::Reader || runtime.config().authority {
            return Err(CommandError::new(CONFIG_ERROR));
        }
        if provided.is_some() && runtime.config().role != OperatorRoleV1::OrganizationAdmin {
            return Err(CommandError::new(CONFIG_ERROR));
        }
        Ok(Arc::new(Self {
            administration: launch.administration_config.as_deref()
                .map(|path| administration::AdministrationResources::open(path, &runtime))
                .transpose()?,
            recovery: launch
                .recovery_config
                .as_deref()
                .map(|path| recovery::RecoveryResources::open(path, &runtime))
                .transpose()?,
            destruction: match provided {
                Some(resources) => Some(Mutex::new(resources)),
                None => launch
                    .destruction_config
                    .as_deref()
                    .map(|path| {
                        destruction::DestructionResources::open(
                            path,
                            runtime
                                .current()
                                .ok_or_else(|| CommandError::new(CONFIG_ERROR))?,
                            &launch.trust_anchor,
                        )
                        .map(Mutex::new)
                    })
                    .transpose()?,
            },
            writer: launch
                .writer_config
                .as_deref()
                .map(|path| writer::WriterResources::open(path, &runtime))
                .transpose()?,
            launch,
            role: runtime.config().role,
            master_data: Arc::new(ea_draft::MasterDataRepository::new(
                runtime.database().clone(),
            )),
            watcher: RwLock::new(runtime.native().clone()),
            session_epoch: Arc::new(AtomicU64::new(0)),
            inner: Mutex::new(NativeState {
                runtime,
                sessions: HashMap::new(),
                preview: None,
                stale_receipt: None,
            }),
        }))
    }
    fn open_runtime(
        launch: &DesktopLaunchConfig,
    ) -> Result<InteractiveOperatorRuntime, CommandError> {
        let config = OperatorRuntimeConfig::load(&launch.operator_config)
            .map_err(|error| CommandError::new(error.code()))?;
        InteractiveOperatorRuntime::open(config, &launch.trust_anchor, now()?)
            .map_err(|error| CommandError::new(error.code()))
    }
    pub fn desktop_state(self: &Arc<Self>) -> DesktopState {
        let state = if self.role == OperatorRoleV1::Writer {
            DesktopState::new(
                SessionState::new(None, None),
                self.writer.as_ref().map(|_| {
                    self.clone() as Arc<dyn crate::state::StartupRecoveryPort + Send + Sync>
                }),
                Some(self.master_data.clone()),
                Some(self.clone()),
                None,
                self.writer.as_ref().map(|_| {
                    self.clone() as Arc<dyn crate::state::WriterFinalizePort + Send + Sync>
                }),
            )
            .with_discard(self.clone())
        } else {
            DesktopState::new(SessionState::new(None, None), None, None, None, None, None)
        };
        let state = if self.destruction.is_some() {
            state.with_destruction(self.clone()).with_destruction_evidence(self.clone())
        } else {
            state
        };
        let state = if self.administration.is_some() {
            state.with_administration(self.clone())
        } else {
            state
        };
        let state = if self.recovery.is_some() {
            state.with_recovery(self.clone())
        } else {
            state
        };
        state
            .with_runtime_session(self.clone())
            .with_reauth(self.clone())
    }
    /// Bounded native watcher coverage, independent of any UI callback. The
    /// caller announces a failure only after `invalidate` closed all authority.
    /// This never waits for the runtime mutex held by a native presence dialog.
    pub fn check_native_session(&self) -> Result<(), CommandError> {
        let native = {
            let guard = self
                .watcher
                .read()
                .map_err(|_| CommandError::new("EA-DESKTOP-RUNTIME-LOCK"))?;
            Arc::clone(&guard)
        };
        let result = native
            .ensure_session_active()
            .map_err(|error| CommandError::new(error.code()));
        if result.is_err() {
            let current = self
                .watcher
                .read()
                .map_err(|_| CommandError::new("EA-DESKTOP-RUNTIME-LOCK"))?;
            // An old check must not invalidate a newly established watch. Keep
            // the read guard through invalidation so replacement cannot race.
            if !Arc::ptr_eq(&native, &current) {
                return Ok(());
            }
            self.invalidate();
        }
        result
    }
}
impl RuntimeSessionPort for NativeDesktopRuntime {
    fn login(&self) -> Result<(), CommandError> {
        let purpose = match self.role {
            OperatorRoleV1::Writer => ReauthPurpose::Finalize,
            OperatorRoleV1::OrganizationAdmin => ReauthPurpose::AdminRootCeremony,
            OperatorRoleV1::Reader => return Err(CommandError::new(CONFIG_ERROR)),
        };
        self.reauthenticate(purpose)
    }
    fn verified_role(&self) -> Result<Option<OperatorRoleV1>, CommandError> {
        let epoch = self.session_epoch.load(Ordering::SeqCst);
        if epoch & 1 != 0 {
            return Ok(None);
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CommandError::new("EA-DESKTOP-RUNTIME-LOCK"))?;
        if self.session_epoch.load(Ordering::SeqCst) != epoch {
            return Ok(None);
        }
        let recovery_session = self
            .recovery
            .as_ref()
            .map(|resources| resources.role_session(epoch))
            .transpose()?
            .flatten();
        if inner.sessions.is_empty() && recovery_session.is_none() {
            return Ok(None);
        }
        inner.refresh()?;
        let valid = inner
            .sessions
            .iter()
            .any(|(purpose, session)| inner.verify(*purpose, session).is_ok())
            || recovery_session.as_ref().is_some_and(|proof| {
                // The worker shares the very same sealed RecoveryTest proof.
                // It can maintain the UI role only through the normal fresh
                // verifier; no action-purpose session or deadline is replaced.
                inner
                    .runtime
                    .verify_session_proof(ReauthPurpose::RecoveryTest, proof.as_ref())
                    .is_ok()
            });
        if !valid || self.session_epoch.load(Ordering::SeqCst) != epoch {
            inner.invalidate();
            return Ok(None);
        }
        Ok(Some(inner.runtime.config().role))
    }
    fn invalidate(&self) {
        let _ = self
            .session_epoch
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |epoch| {
                Some(epoch.wrapping_add(2) | 1)
            });
        // A dialog can still own the state, but all access is already closed by
        // the epoch. That dialog clears retained proofs before releasing it.
        match self.inner.try_lock() {
            Ok(mut inner) => inner.invalidate(),
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner().invalidate(),
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
    }
}
impl ReauthPort for NativeDesktopRuntime {
    fn reauthenticate(&self, purpose: ReauthPurpose) -> Result<(), CommandError> {
        if purpose == ReauthPurpose::GoLivePostureDocumentation {
            return Err(CommandError::new("EA-DESKTOP-REAUTH-PURPOSE"));
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CommandError::new("EA-DESKTOP-RUNTIME-LOCK"))?;
        let epoch = self.session_epoch.load(Ordering::SeqCst);
        inner.sessions.remove(&purpose);
        if !matches!(
            purpose,
            ReauthPurpose::Finalize | ReauthPurpose::RegistryStaleFinalize
        ) {
            inner.preview = None;
            inner.stale_receipt = None;
        }
        if purpose == ReauthPurpose::RegistryStaleFinalize {
            inner.stale_receipt = None;
        }
        if epoch & 1 != 0 || inner.runtime.native().ensure_session_active().is_err() {
            // Only this explicit user-requested login may replace a dead watch.
            inner.invalidate();
            let fresh = Self::open_runtime(&self.launch)?;
            if fresh.config().role != inner.runtime.config().role
                || fresh.config().device_certificate_hash
                    != inner.runtime.config().device_certificate_hash
                || fresh.config().binding_object_hash != inner.runtime.config().binding_object_hash
                || fresh.config().archive_directory != inner.runtime.config().archive_directory
                || fresh.config().database_path != inner.runtime.config().database_path
                || fresh.anchor().trust_anchor_hash() != inner.runtime.anchor().trust_anchor_hash()
            {
                return Err(CommandError::new(CONFIG_ERROR));
            }
            *self
                .watcher
                .write()
                .map_err(|_| CommandError::new("EA-DESKTOP-RUNTIME-LOCK"))? =
                fresh.native().clone();
            inner.runtime = fresh;
        }
        inner.refresh()?;
        let session = if purpose == ReauthPurpose::RegistryStaleFinalize {
            let context = inner
                .preview
                .as_ref()
                .ok_or_else(|| CommandError::new(crate::commands::PREVIEW_NOT_ISSUED))?
                .preview_hash();
            inner.runtime.reauthenticate_for_context(purpose, context)
        } else {
            inner.runtime.reauthenticate_for(purpose)
        }
        .map_err(|error| CommandError::new(error.code()));
        let session = match session {
            Ok(session) => session,
            Err(error) => {
                inner.invalidate();
                return Err(error);
            }
        };
        inner.sessions.insert(purpose, session);
        if self
            .session_epoch
            .compare_exchange(epoch, epoch & !1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            inner.invalidate();
            return Err(CommandError::new("EA-DESKTOP-SESSION-LOCKED"));
        }
        Ok(())
    }
}

/// Polls fresh coverage acknowledgements of the OS subscription. Cryptographic
/// provider operations independently enforce that subscription before and after
/// each call; this monitor closes idle UI sessions and clears retained proofs.
pub struct NativeSessionMonitor(Arc<std::sync::atomic::AtomicBool>);
impl NativeSessionMonitor {
    pub fn start(
        native: Arc<NativeDesktopRuntime>,
        state: DesktopState,
        announce: impl Fn() + Send + 'static,
    ) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        std::thread::spawn(move || {
            let mut announced = false;
            while !stopping.load(Ordering::SeqCst) {
                if native.check_native_session().is_err() {
                    if !announced {
                        crate::honor_session_lock(&state, &announce);
                        announced = true;
                    }
                } else {
                    announced = false;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
        Self(stop)
    }
    pub fn stop(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
impl Drop for NativeSessionMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn administration_launch_is_explicit_complete_and_never_silently_ignored() {
        let args=["--operator-config","operator.json","--trust-anchor","anchor.cbor",
            "--administration-config","administration.json"];
        let launch=super::DesktopLaunchConfig::parse(args.map(std::ffi::OsString::from)).unwrap().unwrap();
        assert_eq!(launch.administration_config,Some(std::path::PathBuf::from("administration.json")));
        for args in [
            vec!["--administration-config","administration.json"],
            vec!["--operator-config","operator.json","--administration-config","administration.json"],
            vec!["--operator-config","operator.json","--trust-anchor","anchor.cbor","--administration-config"],
            vec!["--operator-config","operator.json","--trust-anchor","anchor.cbor","--administration-config","a.json","--administration-config","b.json"],
        ] {
            assert!(super::DesktopLaunchConfig::parse(args.into_iter().map(std::ffi::OsString::from)).is_err());
        }
    }
    #[test]
    fn explicit_recovery_configuration_is_accepted_only_with_independent_operator_and_anchor() {
        let args = [
            "--operator-config",
            "operator.json",
            "--trust-anchor",
            "anchor.cbor",
            "--recovery-config",
            "recovery.json",
        ];
        assert!(
            super::DesktopLaunchConfig::parse(args.map(std::ffi::OsString::from))
                .unwrap()
                .is_some()
        );
        for args in [
            vec!["--recovery-config", "recovery.json"],
            vec![
                "--operator-config",
                "operator.json",
                "--recovery-config",
                "recovery.json",
            ],
            vec![
                "--operator-config",
                "operator.json",
                "--trust-anchor",
                "anchor.cbor",
                "--recovery-config",
                "a",
                "--recovery-config",
                "b",
            ],
        ] {
            assert!(
                super::DesktopLaunchConfig::parse(args.into_iter().map(std::ffi::OsString::from))
                    .is_err()
            );
        }
    }
    use super::*;
    fn parse(args: &[&str]) -> Result<Option<DesktopLaunchConfig>, CommandError> {
        DesktopLaunchConfig::parse(args.iter().map(OsString::from))
    }
    #[test]
    fn destruction_configuration_requires_the_same_explicit_operator_and_anchor() {
        assert!(parse(&["--destruction-config", "destruction.json"]).is_err());
        assert!(
            parse(&[
                "--operator-config",
                "operator.json",
                "--trust-anchor",
                "anchor.etb",
                "--destruction-config",
                "destruction.json",
            ])
            .is_ok()
        );
        assert!(
            parse(&[
                "--operator-config",
                "operator.json",
                "--trust-anchor",
                "anchor.etb",
                "--destruction-config",
                "one.json",
                "--destruction-config",
                "two.json",
            ])
            .is_err()
        );
    }
    #[test]
    fn explicit_independent_anchor_is_mandatory_for_a_configured_start() {
        assert_eq!(parse(&[]).unwrap(), None);
        assert_eq!(
            parse(&[
                "--operator-config",
                "operator.json",
                "--trust-anchor",
                "anchor.etb"
            ])
            .unwrap(),
            Some(DesktopLaunchConfig {
                operator_config: "operator.json".into(),
                trust_anchor: "anchor.etb".into(),
                writer_config: None,
                destruction_config: None,
                recovery_config: None,
                administration_config: None,
            })
        );
        for args in [
            vec!["--operator-config", "private-canary"],
            vec!["--trust-anchor", "a"],
            vec!["--operator-config", "--trust-anchor", "a"],
            vec!["--helper", "private-canary"],
            vec!["--role", "writer"],
            vec!["--operator-config", "a", "--operator-config", "b"],
        ] {
            assert_eq!(parse(&args).unwrap_err().code, CONFIG_ERROR);
        }
    }
}
