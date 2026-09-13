//! Purpose-only native Clock repair. No ordinary operator authority is returned.
use super::*;
use ea_archive::ArchiveSource;
use ea_audit::{AuditError, SignedLocalAuditEvent};
use ea_format::ClockReleaseJustificationV1;
use ea_trust::ClockReleaseError;
use ea_trust::{ClockRepairRegistryAuthority, verify_clock_repair_authority};
use std::cell::Cell;

pub enum ClockRepairRuntimeError {
    Runtime(OperatorRuntimeError),
    Clock(ClockReleaseError),
    Audit(AuditError),
}
impl ClockRepairRuntimeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Runtime(e) => e.code(),
            Self::Clock(e) => e.code(),
            Self::Audit(e) => e.code(),
        }
    }
}
impl fmt::Display for ClockRepairRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl fmt::Debug for ClockRepairRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for ClockRepairRuntimeError {}
pub struct CompletedClockRepair {
    login: SignedLocalAuditEvent,
    release: SignedLocalAuditEvent,
}
impl CompletedClockRepair {
    pub fn login(&self) -> &SignedLocalAuditEvent {
        &self.login
    }
    pub fn release(&self) -> &SignedLocalAuditEvent {
        &self.release
    }
}
impl From<OperatorRuntimeError> for ClockRepairRuntimeError {
    fn from(error: OperatorRuntimeError) -> Self {
        Self::Runtime(error)
    }
}
impl From<ClockReleaseError> for ClockRepairRuntimeError {
    fn from(error: ClockReleaseError) -> Self {
        Self::Clock(error)
    }
}
impl From<AuditError> for ClockRepairRuntimeError {
    fn from(error: AuditError) -> Self {
        Self::Audit(error)
    }
}

/// Owns only the exact blocked source and purpose-specific admission. It cannot
/// return OperatorRuntime, SelectedRegistryHead, or a general session.
pub struct ClockRepairRuntime {
    resources: RuntimeResources,
    authority: ClockRepairRegistryAuthority,
    source_hash: ObjectHash,
    last_wall: Cell<UnixMillis>,
}
impl ClockRepairRuntime {
    pub fn open(
        config: OperatorRuntimeConfig,
        anchor: &Path,
    ) -> Result<Self, ClockRepairRuntimeError> {
        Self::open_using(
            config,
            anchor,
            NativeOperatorProvider::open_installed,
            Arc::from(
                SupportMatrixRow::current_host()
                    .ok_or(OperatorRuntimeError::Posture)?
                    .posture_provider(),
            ),
        )
    }
    #[cfg(feature = "test-support")]
    pub fn open_with_test_native(
        config: OperatorRuntimeConfig,
        anchor: &Path,
        native: Arc<NativeOperatorProvider>,
    ) -> Result<Self, ClockRepairRuntimeError> {
        Self::open_using(
            config,
            anchor,
            |_| Ok(native),
            Arc::new(super::FixturePassingPosture),
        )
    }
    fn open_using(
        config: OperatorRuntimeConfig,
        anchor: &Path,
        open_native: impl FnOnce(bool) -> Result<Arc<NativeOperatorProvider>, NativeProviderError>,
        posture: Arc<dyn DevicePostureProvider>,
    ) -> Result<Self, ClockRepairRuntimeError> {
        if config.role != OperatorRoleV1::OrganizationAdmin
            || config.purpose != ReauthPurpose::ClockSkewRelease
            || config.authority
            || config.target_certificate_hash.is_some()
        {
            return Err(OperatorRuntimeError::Config.into());
        }
        let database = config.database_path.clone();
        // Only short context acquisition is serialized. No presence, signing or
        // successful audit is performed under this gate.
        super::acquisition::acquire(
            &database,
            super::acquisition::AcquisitionTime::FreshWallClock,
            |now| {
                Ok((|| -> Result<Self, ClockRepairRuntimeError> {
                    let mut resources =
                        open_resources(config, anchor, now, false, open_native, posture)?;
                    let authority = prepare_authority(
                        &resources.snapshot,
                        &mut resources.store,
                        resources.device_id,
                        &resources.config,
                        now,
                    )?;
                    let source_hash = snapshot_hash(&resources.snapshot)?;
                    let runtime = Self {
                        resources,
                        authority,
                        source_hash,
                        last_wall: Cell::new(now),
                    };
                    runtime.check_local()?;
                    Ok(runtime)
                })())
            },
        )?
    }
    fn check_local(&self) -> Result<(), ClockRepairRuntimeError> {
        let r = &self.resources;
        r.native
            .ensure_session_active()
            .map_err(OperatorRuntimeError::from)?;
        let public = r
            .native
            .public_key(NativeSigningSlot::Admin)
            .map_err(OperatorRuntimeError::from)?
            .ok_or(OperatorRuntimeError::SignerMismatch)?;
        let cert = self.authority.certificate_fields();
        if cert.device_id != r.device_id
            || cert.signing_key_thumbprint != Some(public.thumbprint())
            || cert.signing_public_cose_key.as_deref()
                != Some(public.to_deterministic_cbor().as_slice())
        {
            return Err(OperatorRuntimeError::SignerMismatch.into());
        }
        let binding = self.authority.binding_fields();
        if r.native
            .os_account_binding_hash(self.authority.organization_id(), r.device_id)
            .map_err(OperatorRuntimeError::from)?
            != binding.os_account_binding_hash
            || r.native
                .operator_instance_public_key()
                .map_err(OperatorRuntimeError::from)?
                .is_none_or(|key| key.thumbprint() != binding.operator_instance_key_thumbprint)
        {
            return Err(OperatorRuntimeError::Operator(OperatorError::AccountMismatch).into());
        }
        let profile = crate::operator_profile::load(&r.database)
            .map_err(OperatorRuntimeError::from)?
            .ok_or(OperatorRuntimeError::Config)?;
        if profile.operator_binding_object_hash() != self.authority.binding_hash() {
            return Err(OperatorRuntimeError::Config.into());
        }
        crate::operator_profile::verify_operator_snapshot(&profile, binding)
            .map_err(OperatorRuntimeError::from)?;
        let report = r.posture.report().map_err(OperatorRuntimeError::from)?;
        if PostureRequirement::ALL.into_iter().any(|requirement| {
            !matches!(
                report.check(requirement),
                ea_key_provider::PostureCheck::Pass { .. }
            )
        }) {
            return Err(OperatorRuntimeError::Posture.into());
        }
        r.native
            .ensure_session_active()
            .map_err(OperatorRuntimeError::from)?;
        Ok(())
    }
    fn recheck(&self) -> Result<UnixMillis, ClockRepairRuntimeError> {
        let now = fresh_wall_clock()?;
        if now < self.last_wall.get() {
            return Err(OperatorRuntimeError::Expired.into());
        }
        self.last_wall.set(now);
        validate_freshness(
            self.resources.opened.elapsed(),
            now,
            self.authority.raw_now(),
            self.authority.valid_until(),
        )?;
        self.check_local()?;
        let snapshot = OperatorArchiveSnapshot::open(
            &self.resources.config.archive_directory,
            &self.resources.anchor_path,
            now,
        )?;
        if snapshot_hash(&snapshot)? != self.source_hash {
            return Err(OperatorRuntimeError::Archive.into());
        }
        let mut store = self.resources.store.clone();
        let key = TrustStateKey {
            organization_id: snapshot.anchor.organization_id(),
            device_id: self.resources.device_id,
        };
        let trust = verify_trust(
            &snapshot.anchor,
            &snapshot.inventory,
            load_trust_state(&mut store, key).map_err(OperatorRuntimeError::from)?,
        )
        .map_err(OperatorRuntimeError::from)?;
        let candidate = verify_registry_candidate(&trust, snapshot.next_sequence)
            .map_err(OperatorRuntimeError::from)?;
        let sources = signed_times(&snapshot, &candidate);
        let block = prepare_local_time(&mut store, &candidate, now, &sources)
            .map_err(OperatorRuntimeError::from)?;
        self.authority.require_same_state(&candidate, &block)?;
        Ok(now)
    }
    pub fn release(
        self,
        _justification: ClockReleaseJustificationV1,
    ) -> Result<CompletedClockRepair, ClockRepairRuntimeError> {
        self.recheck()?;
        Err(ClockRepairRuntimeError::Runtime(
            OperatorRuntimeError::Expired,
        ))
    }
}
fn signed_times(
    snapshot: &OperatorArchiveSnapshot,
    candidate: &ea_trust::RegistryCandidate,
) -> Vec<ea_trust::VerifiedSignedTime> {
    let mut sources = Vec::new();
    if let Some(authority) = candidate.preexisting_authority() {
        for receipt in snapshot.inventory.receipts() {
            if let Ok(source) = verify_receipt_time(authority, receipt) {
                sources.push(source);
            }
        }
        for evidence in snapshot.inventory.evidence() {
            if let Ok(source) = verify_checkpoint_time(authority, evidence) {
                sources.push(source);
            }
        }
    }
    sources
}
fn prepare_authority(
    snapshot: &OperatorArchiveSnapshot,
    store: &mut OperatorTrustStateStore,
    device_id: DeviceId,
    config: &OperatorRuntimeConfig,
    now: UnixMillis,
) -> Result<ClockRepairRegistryAuthority, ClockRepairRuntimeError> {
    let key = TrustStateKey {
        organization_id: snapshot.anchor.organization_id(),
        device_id,
    };
    let trust = verify_trust(
        &snapshot.anchor,
        &snapshot.inventory,
        load_trust_state(store, key).map_err(OperatorRuntimeError::from)?,
    )
    .map_err(OperatorRuntimeError::from)?;
    let candidate = verify_registry_candidate(&trust, snapshot.next_sequence)
        .map_err(OperatorRuntimeError::from)?;
    let sources = signed_times(snapshot, &candidate);
    let block =
        prepare_local_time(store, &candidate, now, &sources).map_err(OperatorRuntimeError::from)?;
    Ok(verify_clock_repair_authority(
        &candidate,
        &block,
        config.device_certificate_hash,
        config.binding_object_hash,
    )?)
}
fn snapshot_hash(
    snapshot: &OperatorArchiveSnapshot,
) -> Result<ObjectHash, ClockRepairRuntimeError> {
    let mut entries = Vec::new();
    snapshot
        .source
        .visit_blobs(&mut |blob| {
            entries.push((
                blob.path_hint().to_owned(),
                ea_crypto::object_hash(blob.bytes()),
            ));
            Ok(())
        })
        .map_err(|_| OperatorRuntimeError::Archive)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|e| e.bytes(snapshot.anchor.trust_anchor_hash().as_bytes()))
        .and_then(|e| e.array(entries.len() as u64))
        .map_err(|_| OperatorRuntimeError::Archive)?;
    for (path, hash) in entries {
        encoder
            .array(2)
            .and_then(|e| e.str(&path))
            .and_then(|e| e.bytes(hash.as_bytes()))
            .map_err(|_| OperatorRuntimeError::Archive)?;
    }
    Ok(ea_crypto::object_hash(&encoder.into_writer()))
}
