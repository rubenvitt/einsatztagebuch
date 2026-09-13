//! Desktop projections from an admitted native administration view.
//! The host obtains the view while holding its existing runtime/session lock.
use crate::commands::CommandError;
use ea_admin::administration_runtime::views::AdministrationView;
use ea_types::ObjectHash;
use ea_ui_contracts::{
    PolicyProfileView, RegistryHealthView, RevocationEffectView, RevocationTargetClass,
    WriterTransitionView,
};
use ea_writer::StaleDecision;

pub(super) fn policy_profile(view: &AdministrationView<'_>) -> PolicyProfileView {
    let policy = view.policy();
    let head = view.head();
    PolicyProfileView {
        operating_profile: policy.operating_profile,
        max_registry_age_ms: policy.max_registry_age_ms,
        max_future_clock_skew_ms: policy.max_future_clock_skew_ms,
        registry_expiry_behavior: policy.registry_expiry_behavior,
        evidence_max_delay_ms: policy.evidence_max_delay_ms,
        reader_inactivity_ms: policy.reader_inactivity_ms,
        reader_trust_refresh_ms: policy.reader_trust_refresh_ms,
        reader_history_access_allowed: policy.reader_history_access_allowed,
        backup_frequency_ms: policy.backup_frequency_ms,
        restore_test_interval_ms: policy.restore_test_interval_ms,
        minimum_retention_ms: policy.retention_policy.minimum_retention_ms,
        destruction_enabled: policy.retention_policy.destruction_enabled,
        effective_from_sequence: policy.effective_from_sequence,
        lease_valid_through_sequence: head.valid_through_sequence(),
        not_after_ms: head.not_after(),
    }
}
pub(super) fn registry_health(view: &AdministrationView<'_>) -> RegistryHealthView {
    let head = view.head();
    RegistryHealthView {
        registry_version: head.registry_version(),
        head_hash: hex_hash(head.registry_head_hash().as_bytes()),
        registry_age_ms: view.registry_age_ms(),
        max_registry_age_ms: view.policy().max_registry_age_ms,
        lease_valid_through_sequence: head.valid_through_sequence(),
        next_sequence: head.proposed_sequence(),
        not_after_ms: head.not_after(),
        // The current-only native view has just selected this head. Expired
        // authority cannot produce the view; Writer's stale exception is separate.
        stale_decision: StaleDecision::Fresh,
    }
}
fn transition_view(
    value: &ea_admin::administration_runtime::transition::AdministrationWriterTransition,
) -> WriterTransitionView {
    WriterTransitionView {
        ceremony_id: value.ceremony_id().map(|id| hex_hash(id.as_bytes())),
        phase: value.phase(),
        current_writer_hash: hex_hash(value.current_writer().as_bytes()),
        new_writer_hash: value.new_writer().map(|hash| hex_hash(hash.as_bytes())),
        effective_from_sequence: value.effective_from(),
    }
}
pub(super) fn revocation_effect(
    view: &AdministrationView<'_>,
    target: ObjectHash,
) -> Result<RevocationEffectView, CommandError> {
    let effect = view
        .revocation_effect(target)
        .map_err(|e| CommandError::new(e.code()))?;
    let target_class = match effect.target_class() {
        ea_admin::revocation::RevocationTargetClass::NonAdminDevice => {
            RevocationTargetClass::NonAdminDevice
        }
        ea_admin::revocation::RevocationTargetClass::OperatorBinding => {
            RevocationTargetClass::OperatorBinding
        }
        ea_admin::revocation::RevocationTargetClass::Component => RevocationTargetClass::Component,
    };
    Ok(RevocationEffectView {
        target_class,
        target_hash: hex_hash(target.as_bytes()),
        stops_new_grants_from_sequence: effect.stops_new_grants_from(),
        recalls_issued_grants: effect.recalls_issued_grants(),
        recalls_decrypted_plaintext: effect.recalls_decrypted_plaintext(),
    })
}
fn hex_hash(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("writing to String");
    }
    text
}

// Only public file references and the explicit real backend profile are configured.
// Neither ready flags, operator identities nor signing material are accepted here.
use super::{NativeDesktopRuntime, NativeState, archive_config::ProfileConfig};
use crate::state::AdministrationPort;
use ea_admin::{
    TrustCeremonyKind, TrustCeremonyStep, VerifiedOperatorSession,
    administration_runtime::{self as admin, FingerprintSubjectV1, TrustCeremonyRoundV1},
    operator_runtime::{OperatorRuntime, OperatorRuntimeError, writer::InteractiveOperatorRuntime},
};
use ea_archive::ArchiveBackendProfileV1;
use ea_format::{CertificateKindV1, ClockReleaseJustificationV1, OperatorRoleV1};
use ea_operator::ReauthPurpose;
use ea_ui_contracts::{
    ClockReleaseOfferView, ClockReleaseOutcomeView, PendingDeviceRequestView, TrustCeremonyView,
};
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

const RESOURCE_ERROR: &str = "EA-DESKTOP-ADMINISTRATION-CONFIG";
const SESSION_ERROR: &str = "EA-DESKTOP-SESSION-LOCKED";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    registration_inbox: PathBuf,
    archive_profile: ProfileConfig,
    policy_intent: Option<PathBuf>,
    key_inventory: Option<PathBuf>,
}
pub(super) struct AdministrationResources {
    registration_inbox: PathBuf,
    profile: ArchiveBackendProfileV1,
    policy_intent: Option<PathBuf>,
    key_inventory: Option<PathBuf>,
}
impl AdministrationResources {
    pub(super) fn open(
        path: &Path,
        runtime: &InteractiveOperatorRuntime,
    ) -> Result<Self, CommandError> {
        if runtime.config().role != OperatorRoleV1::OrganizationAdmin
            || runtime.config().authority
            || runtime.current().is_none()
            || runtime.config().ceremony_exchange_directory.is_none()
            || runtime.config().admin_certificate_hash.is_none()
            || runtime.config().admin_binding_object_hash.is_none()
        {
            return Err(CommandError::new(RESOURCE_ERROR));
        }
        let config: Config = serde_json::from_slice(&read_public(path, 65_536)?)
            .map_err(|_| CommandError::new(RESOURCE_ERROR))?;
        if config.version != 1 {
            return Err(CommandError::new(RESOURCE_ERROR));
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let resolve = |value: PathBuf| {
            if value.as_os_str().is_empty() {
                return Err(CommandError::new(RESOURCE_ERROR));
            }
            Ok(if value.is_absolute() {
                value
            } else {
                parent.join(value)
            })
        };
        let registration_inbox = resolve(config.registration_inbox)?;
        let metadata = std::fs::symlink_metadata(&registration_inbox)
            .map_err(|_| CommandError::new(RESOURCE_ERROR))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(CommandError::new(RESOURCE_ERROR));
        }
        Ok(Self {
            registration_inbox,
            profile: config.archive_profile.into_profile(),
            policy_intent: config.policy_intent.map(resolve).transpose()?,
            key_inventory: config.key_inventory.map(resolve).transpose()?,
        })
    }
}
fn read_public(path: &Path, limit: u64) -> Result<Vec<u8>, CommandError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| CommandError::new(RESOURCE_ERROR))?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CommandError::new(RESOURCE_ERROR))?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err(CommandError::new(RESOURCE_ERROR));
    }
    Ok(bytes)
}
fn runtime_error(error: OperatorRuntimeError) -> CommandError {
    CommandError::new(error.code())
}
fn hash(text: &str) -> Result<ObjectHash, CommandError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(CommandError::new("EA-ADMINISTRATION-IDENTIFIER"));
    }
    ea_admin::parse_human_readable_fingerprint(text)
        .map_err(|_| CommandError::new("EA-ADMINISTRATION-IDENTIFIER"))
}
fn ceremony_view(value: admin::ceremony::AdministrationCeremony) -> TrustCeremonyView {
    TrustCeremonyView {
        ceremony_id: hex_hash(value.id().as_bytes()),
        kind: value.kind(),
        step: value.step(),
        target_fingerprint: value
            .target_fingerprint()
            .as_ref()
            .map(ea_admin::human_readable_fingerprint),
        exchange_file_name: value.exchange_file_name().map(str::to_owned),
        round: value.round(),
        linked_ceremony_id: value.linked_ceremony_id().map(|id| hex_hash(id.as_bytes())),
        fingerprint_subject: value.fingerprint_subject(),
    }
}
impl NativeDesktopRuntime {
    /// Structural observation only; requires the existing CurrentAdmin session.
    pub fn diagnose_prepared_writer(
        &self,
    ) -> Result<Option<ea_writer::PreparedMarkerDiagnosisV1>, CommandError> {
        self.diagnose_prepared_writer_impl(|| {})
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn diagnose_prepared_writer_with_test_after_profile(
        &self,
        after_profile: impl FnOnce(),
    ) -> Result<Option<ea_writer::PreparedMarkerDiagnosisV1>, CommandError> {
        self.diagnose_prepared_writer_impl(after_profile)
    }

    fn diagnose_prepared_writer_impl(
        &self,
        after_profile: impl FnOnce(),
    ) -> Result<Option<ea_writer::PreparedMarkerDiagnosisV1>, CommandError> {
        if self.role != OperatorRoleV1::OrganizationAdmin {
            return Err(CommandError::new(crate::commands::ADMINISTRATION_FORBIDDEN));
        }
        let owner = self.destruction.as_ref().ok_or_else(|| {
            CommandError::new(crate::commands::ADMINISTRATION_UNAVAILABLE)
        })?;
        self.administration_action(None, |admin, _, resources| {
            let owner = owner.lock().map_err(|_| CommandError::new("EA-DESKTOP-RUNTIME-LOCK"))?;
            let port = owner.runtime.writer_prepared_diagnosis();
            #[cfg(feature = "test-support")]
            let result = port.diagnose_with_test_after_profile(admin, &resources.profile, after_profile);
            #[cfg(not(feature = "test-support"))]
            let result = {
                after_profile();
                port.diagnose(admin, &resources.profile)
            };
            result.map_err(|e| CommandError::new(e.code()))
        })
    }

    fn administration_action<T>(
        &self,
        purpose: Option<ReauthPurpose>,
        action: impl FnOnce(
            &mut OperatorRuntime,
            Option<&VerifiedOperatorSession>,
            &AdministrationResources,
        ) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        if self.role != OperatorRoleV1::OrganizationAdmin {
            return Err(CommandError::new(crate::commands::ADMINISTRATION_FORBIDDEN));
        }
        let resources = self
            .administration
            .as_ref()
            .ok_or_else(|| CommandError::new(crate::commands::ADMINISTRATION_UNAVAILABLE))?;
        let epoch = self.session_epoch.load(Ordering::SeqCst);
        if epoch & 1 != 0 {
            return Err(CommandError::new(SESSION_ERROR));
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CommandError::new("EA-DESKTOP-RUNTIME-LOCK"))?;
        if self.session_epoch.load(Ordering::SeqCst) != epoch || inner.sessions.is_empty() {
            return Err(CommandError::new(SESSION_ERROR));
        }
        inner.refresh()?;
        if !inner
            .sessions
            .iter()
            .any(|(p, s)| inner.verify(*p, s).is_ok())
        {
            inner.invalidate();
            return Err(CommandError::new(SESSION_ERROR));
        }
        if let Some(purpose) = purpose {
            let session = inner
                .sessions
                .get(&purpose)
                .ok_or_else(|| CommandError::new(crate::commands::REAUTH_REQUIRED))?;
            inner.verify(purpose, session)?;
        }
        let NativeState {
            runtime, sessions, ..
        } = &mut *inner;
        let InteractiveOperatorRuntime::Current(runtime) = runtime else {
            return Err(CommandError::new(crate::commands::ADMINISTRATION_FORBIDDEN));
        };
        if runtime.config().authority {
            return Err(CommandError::new(crate::commands::ADMINISTRATION_FORBIDDEN));
        }
        let result = action(runtime, purpose.and_then(|p| sessions.get(&p)), resources);
        // No view or success from a completed blocking operation may outlive a
        // native session lock. The core signs/publishes under its own fresh gate.
        self.check_native_session()?;
        if self.session_epoch.load(Ordering::SeqCst) != epoch {
            inner.invalidate();
            return Err(CommandError::new(SESSION_ERROR));
        }
        inner.refresh()?;
        if !inner
            .sessions
            .iter()
            .any(|(p, s)| inner.verify(*p, s).is_ok())
        {
            inner.invalidate();
            return Err(CommandError::new(SESSION_ERROR));
        }
        result
    }
}
impl AdministrationPort for NativeDesktopRuntime {
    fn diagnose_writer_lock(
        &self,
    ) -> Result<ea_ui_contracts::LocalWriterLockDiagnosis, CommandError> {
        self.administration_action(None, |runtime, _, resources| {
            runtime.ensure_current().map_err(runtime_error)?;
            if !matches!(resources.profile, ArchiveBackendProfileV1::LocalPath(_)) {
                return Err(CommandError::new(RESOURCE_ERROR));
            }
            ea_archive::BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields())
                .require(
                    resources
                        .profile
                        .profile_hash()
                        .map_err(|error| CommandError::new(error.code()))?,
                )
                .map_err(|error| CommandError::new(error.code()))?;
            let diagnosis =
                ea_archive_fs::diagnose_local_writer_lock(&runtime.config().archive_directory);
            runtime.ensure_current().map_err(runtime_error)?;
            Ok(diagnosis)
        })
    }

    fn open_ceremonies(&self) -> Result<Vec<TrustCeremonyView>, CommandError> {
        self.administration_action(None, |runtime, _, _| {
            admin::ceremony::open_ceremonies(runtime)
                .map(|values| values.into_iter().map(ceremony_view).collect())
                .map_err(runtime_error)
        })
    }
    fn pending_device_requests(&self) -> Result<Vec<PendingDeviceRequestView>, CommandError> {
        self.administration_action(None, |runtime, _, resources| {
            admin::inbox::pending_registrations(runtime, &resources.registration_inbox)
                .map_err(runtime_error)?
                .into_iter()
                .map(|request| {
                    let code = match request.certificate_kind() {
                        CertificateKindV1::Writer => "EA-CERT-WRITER-DEVICE",
                        CertificateKindV1::Reader => "EA-CERT-READER-DEVICE",
                        _ => return Err(CommandError::new("EA-ADMINISTRATION-REQUEST-KIND")),
                    };
                    Ok(PendingDeviceRequestView {
                        request_id: hex_hash(request.request_hash().as_bytes()),
                        certificate_kind_code: code.into(),
                        fingerprint: ea_admin::human_readable_fingerprint(&request.request_hash()),
                        received_at_ms: request.received_at(),
                        fingerprint_subject: FingerprintSubjectV1::RegistrationRequest,
                    })
                })
                .collect()
        })
    }
    fn ceremony(&self, id: &str) -> Result<TrustCeremonyView, CommandError> {
        let id = hash(id)?;
        self.administration_action(None, |runtime, _, _| {
            admin::ceremony::load(runtime, id)
                .map(ceremony_view)
                .map_err(runtime_error)
        })
    }
    fn begin_ceremony(
        &self,
        request_id: &str,
        kind: TrustCeremonyKind,
    ) -> Result<TrustCeremonyView, CommandError> {
        self.administration_action(None, |runtime, _, resources| {
            let value = match kind {
                TrustCeremonyKind::DeviceApprove => {
                    let request_hash = hash(request_id)?;
                    let pending =
                        admin::inbox::pending_registrations(runtime, &resources.registration_inbox)
                            .map_err(runtime_error)?;
                    let row = pending
                        .iter()
                        .find(|row| row.request_hash() == request_hash)
                        .ok_or_else(|| CommandError::new("EA-ADMINISTRATION-REQUEST-MISSING"))?;
                    admin::ceremony::load(runtime, row.ceremony_id())
                }
                TrustCeremonyKind::DeviceRevoke => {
                    admin::ceremony::begin_revoke(runtime, hash(request_id)?)
                }
                TrustCeremonyKind::PolicyChange => {
                    if request_id != "policy-profile" {
                        return Err(CommandError::new("EA-ADMINISTRATION-IDENTIFIER"));
                    }
                    let path = resources.policy_intent.as_deref().ok_or_else(|| {
                        CommandError::new("EA-ADMINISTRATION-POLICY-INTENT-REQUIRED")
                    })?;
                    admin::ceremony::begin_policy(runtime, &read_public(path, 65_536)?)
                }
                TrustCeremonyKind::WriterTransition => {
                    // The transition JSON prepares and persists the exact round.
                    // A button cannot manufacture another transition from a hash.
                    let id = hash(request_id)?;
                    let value = admin::ceremony::load(runtime, id).map_err(runtime_error)?;
                    if value.kind() != kind {
                        return Err(CommandError::new("EA-ADMINISTRATION-REQUEST-KIND"));
                    }
                    Ok(value)
                }
            }
            .map_err(runtime_error)?;
            Ok(ceremony_view(value))
        })
    }
    fn confirm_fingerprint(
        &self,
        id: &str,
        reported: &ObjectHash,
    ) -> Result<TrustCeremonyView, CommandError> {
        let id = hash(id)?;
        self.administration_action(None, |runtime, _, _| {
            admin::ceremony::confirm_registration_fingerprint(runtime, id, *reported)
                .map(ceremony_view)
                .map_err(runtime_error)
        })
    }
    fn authorize(&self, id: &str) -> Result<TrustCeremonyView, CommandError> {
        let id = hash(id)?;
        self.administration_action(
            Some(ReauthPurpose::AdminRootCeremony),
            |runtime, session, _| {
                admin::authorization::authorize(
                    runtime,
                    id,
                    session.ok_or_else(|| CommandError::new(crate::commands::REAUTH_REQUIRED))?,
                )
                .map(ceremony_view)
                .map_err(runtime_error)
            },
        )
    }
    fn export_request(&self, id: &str) -> Result<TrustCeremonyView, CommandError> {
        let id = hash(id)?;
        self.administration_action(None, |runtime, _, _| {
            admin::exchange::export_request(runtime, id)
                .map(ceremony_view)
                .map_err(runtime_error)
        })
    }
    fn import_reply(&self, id: &str) -> Result<TrustCeremonyView, CommandError> {
        let id = hash(id)?;
        self.administration_action(None, |runtime, _, _| {
            admin::exchange::import_reply(runtime, id)
                .map(ceremony_view)
                .map_err(runtime_error)
        })
    }
    fn publish(&self, id: &str) -> Result<TrustCeremonyView, CommandError> {
        let id = hash(id)?;
        self.administration_action(
            Some(ReauthPurpose::AdminRootCeremony),
            |runtime, session, resources| {
                admin::publication::publish(
                    runtime,
                    id,
                    &resources.profile,
                    session.ok_or_else(|| CommandError::new(crate::commands::REAUTH_REQUIRED))?,
                )
                .map(ceremony_view)
                .map_err(runtime_error)
            },
        )
    }
    fn policy_profile(&self) -> Result<PolicyProfileView, CommandError> {
        self.administration_action(None, |runtime, _, _| {
            admin::views::current_view(runtime)
                .map(|view| policy_profile(&view))
                .map_err(runtime_error)
        })
    }
    fn registry_health(&self) -> Result<RegistryHealthView, CommandError> {
        self.administration_action(None, |runtime, _, _| {
            admin::views::current_view(runtime)
                .map(|view| registry_health(&view))
                .map_err(runtime_error)
        })
    }
    fn go_live_checklist(&self) -> Result<ea_admin::GoLiveChecklist, CommandError> {
        self.administration_action(None,|runtime,_,resources| {
            let fresh=runtime.reopened_for_action().map_err(runtime_error)?;
            let mut projection_error=None;
            let result=if let Some(path)=&resources.key_inventory {
                let inventory=ea_recovery::KeyInventory::parse(&read_public(path,1024*1024)?)
                    .map_err(|error| CommandError::new(error.code()))?;
                let mut service=ea_admin::recovery_test_runtime::RecoveryTestRuntime::new(fresh,resources.profile.clone())
                    .map_err(|error| CommandError::new(error.code()))?;
                service.evaluate_current_go_live(Some(&inventory), |runtime, proof| {
                    capture_projection(&mut projection_error, runtime, proof)
                })
            } else {
                ea_admin::recovery_test_runtime::RecoveryTestRuntime::evaluate_go_live_without_inventory(
                    fresh,|runtime| capture_projection(&mut projection_error, runtime, None))
            }.map_err(|error| CommandError::new(error.code()))?;
            if let Some(error)=projection_error { return Err(error); }
            Ok(result)
        })
    }
    fn clock_release_offer(&self) -> Result<ClockReleaseOfferView, CommandError> {
        self.administration_action(None, |runtime, _, _| {
            let availability = runtime
                .clock_release_availability(super::now()?)
                .map_err(|error| CommandError::new(error.code()))?;
            if availability == ea_admin::clock_release::ClockReleaseAvailability::Offered {
                // Current admission must never be relaxed to enter the blocked
                // repair flow. Its separate opaque admission is still required.
                return Err(CommandError::new("EA-ADMINISTRATION-CLOCK-REPAIR-REQUIRED"));
            }
            Ok(ClockReleaseOfferView {
                availability,
                floor_ms: None,
                observed_wall_clock_ms: None,
                max_future_clock_skew_ms: None,
                expires_at_ms: None,
                justifications: Vec::new(),
            })
        })
    }
    fn clock_release_issue(
        &self,
        _justification: ClockReleaseJustificationV1,
    ) -> Result<ClockReleaseOutcomeView, CommandError> {
        self.administration_action(Some(ReauthPurpose::ClockSkewRelease), |_, _, _| {
            Err(CommandError::new("EA-ADMINISTRATION-CLOCK-REPAIR-REQUIRED"))
        })
    }
    fn writer_transition_state(&self) -> Result<WriterTransitionView, CommandError> {
        self.administration_action(None, |runtime, _, _| {
            admin::transition::current_transition(runtime)
                .map(|value| transition_view(&value))
                .map_err(runtime_error)
        })
    }
    fn writer_transition_prepare(
        &self,
        request_json: &str,
    ) -> Result<WriterTransitionView, CommandError> {
        self.administration_action(None, |runtime, _, _| {
            admin::ceremony::begin_writer_transition(runtime, request_json.as_bytes())
                .map_err(runtime_error)?;
            admin::transition::current_transition(runtime)
                .map(|value| transition_view(&value))
                .map_err(runtime_error)
        })
    }
    fn writer_transition_activate(&self) -> Result<WriterTransitionView, CommandError> {
        self.administration_action(
            Some(ReauthPurpose::AdminRootCeremony),
            |runtime, session, resources| {
                let transition =
                    admin::transition::current_transition(runtime).map_err(runtime_error)?;
                let id = transition
                    .ceremony_id()
                    .ok_or_else(|| CommandError::new(crate::commands::TRANSITION_NOT_PREPARED))?;
                let pending = admin::ceremony::load(runtime, id).map_err(runtime_error)?;
                if pending.round() != TrustCeremonyRoundV1::ActivateRegistry
                    || pending.step() != TrustCeremonyStep::RootReplyImported
                {
                    return Err(CommandError::new(
                        crate::commands::CEREMONY_STEP_OUT_OF_ORDER,
                    ));
                }
                admin::publication::publish(
                    runtime,
                    id,
                    &resources.profile,
                    session.ok_or_else(|| CommandError::new(crate::commands::REAUTH_REQUIRED))?,
                )
                .map_err(runtime_error)?;
                admin::transition::current_transition(runtime)
                    .map(|value| transition_view(&value))
                    .map_err(runtime_error)
            },
        )
    }
    fn revocation_effect(&self, target: &ObjectHash) -> Result<RevocationEffectView, CommandError> {
        self.administration_action(None, |runtime, _, _| {
            let view = admin::views::current_view(runtime).map_err(runtime_error)?;
            revocation_effect(&view, *target)
        })
    }
}
fn capture_projection<'a>(
    error: &mut Option<CommandError>,
    runtime: &'a OperatorRuntime,
    proof: Option<ea_admin::go_live::RecoveryTestFreshness<'a>>,
) -> ea_admin::GoLiveChecklist {
    match go_live_projection(runtime, proof) {
        Ok(checklist) => checklist,
        Err(value) => {
            *error = Some(value);
            unknown_checklist()
        }
    }
}
fn unknown_checklist() -> ea_admin::GoLiveChecklist {
    ea_admin::go_live::evaluate_go_live(&ea_admin::go_live::GoLiveEvidence {
        active_admin_count: None,
        key_backups: None,
        registry: None,
        policy_present: None,
        evidence_policy_present: None,
        last_recovery_test: None,
        writer_transition: None,
        device_posture: None,
    })
}
fn go_live_projection(
    runtime: &OperatorRuntime,
    recovery: Option<ea_admin::go_live::RecoveryTestFreshness<'_>>,
) -> Result<ea_admin::GoLiveChecklist, CommandError> {
    use ea_admin::go_live::{
        GoLiveEvidence, RegistryFreshness, evaluate_go_live_with_posture_admission,
    };
    let posture = runtime.device_posture_report().map_err(runtime_error)?;
    let admission = runtime.posture_admission().ok();
    let head = runtime.head();
    let policy = head.policy_fields();
    let now = head.preexisting_effective_now().value();
    let age = u64::try_from((i128::from(now.get()) - i128::from(head.issued_at().get())).max(0))
        .unwrap_or(u64::MAX);
    let transition = admin::transition::observe_transition(runtime).map_err(runtime_error)?;
    Ok(evaluate_go_live_with_posture_admission(
        &GoLiveEvidence {
            active_admin_count: Some(
                head.active_certificates()
                    .filter(|(_, fields)| {
                        fields.certificate_kind == CertificateKindV1::OrganizationAdmin
                    })
                    .count(),
            ),
            // Only the Root setup coordinator owns the two independent bootstrap
            // media proofs. A Source report or caller configuration cannot replace them.
            key_backups: None,
            registry: Some(RegistryFreshness {
                age_ms: age,
                max_age_ms: policy.max_registry_age_ms,
                next_sequence: runtime.next_sequence(),
                lease_valid_through: head.valid_through_sequence(),
                not_after: head.not_after(),
                now,
            }),
            policy_present: Some(true),
            evidence_policy_present: Some(true),
            last_recovery_test: recovery,
            writer_transition: Some(transition.phase()),
            device_posture: Some(&posture),
        },
        admission.as_ref(),
    ))
}
