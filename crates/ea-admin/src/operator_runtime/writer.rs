//! Native R62 restart context, isolated from ordinary administrative authority.
use super::*;
use ea_operator::{OperatorSessionProof, verify_current_session, verify_writer_session};
use ea_trust::{StaleWriterRegistryHead, WriterRegistryHeadRef};

/// The native shell may use the ordinary runtime or the sealed Writer exception.
/// Only the Current variant can supply general current Registry authority.
pub enum InteractiveOperatorRuntime {
    Current(OperatorRuntime),
    StaleWriter(StaleWriterRuntime),
}
impl From<OperatorRuntime> for InteractiveOperatorRuntime {
    fn from(value: OperatorRuntime) -> Self {
        Self::Current(value)
    }
}
impl InteractiveOperatorRuntime {
    pub fn open(
        config: OperatorRuntimeConfig,
        anchor: &Path,
        now: UnixMillis,
    ) -> Result<Self, OperatorRuntimeError> {
        let native = NativeOperatorProvider::open_installed(false)?;
        let posture = Arc::from(
            SupportMatrixRow::current_host()
                .ok_or(OperatorRuntimeError::Posture)?
                .posture_provider(),
        );
        Self::open_using(config, anchor, now, native, posture)
    }
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_with_test_native(
        config: OperatorRuntimeConfig,
        anchor: &Path,
        now: UnixMillis,
        native: Arc<NativeOperatorProvider>,
    ) -> Result<Self, OperatorRuntimeError> {
        Self::open_using(config, anchor, now, native, Arc::new(FixturePassingPosture))
    }
    fn open_using(
        config: OperatorRuntimeConfig,
        anchor: &Path,
        now: UnixMillis,
        native: Arc<NativeOperatorProvider>,
        posture: Arc<dyn DevicePostureProvider>,
    ) -> Result<Self, OperatorRuntimeError> {
        Self::acquire_using(
            config,
            anchor,
            acquisition::AcquisitionTime::Explicit(now),
            native,
            posture,
        )
    }
    fn acquire_using(
        config: OperatorRuntimeConfig,
        anchor: &Path,
        time: acquisition::AcquisitionTime,
        native: Arc<NativeOperatorProvider>,
        posture: Arc<dyn DevicePostureProvider>,
    ) -> Result<Self, OperatorRuntimeError> {
        let path = config.database_path.clone();
        acquisition::acquire(&path, time, |now| {
            Self::open_without_acquisition(config, anchor, now, native, posture)
        })
    }
    fn open_without_acquisition(
        config: OperatorRuntimeConfig,
        anchor: &Path,
        now: UnixMillis,
        native: Arc<NativeOperatorProvider>,
        posture: Arc<dyn DevicePostureProvider>,
    ) -> Result<Self, OperatorRuntimeError> {
        match OperatorRuntime::open_without_acquisition(
            config.clone(),
            anchor,
            now,
            false,
            |_| Ok(native.clone()),
            posture.clone(),
        ) {
            Ok(current) => Ok(Self::Current(current)),
            Err(
                OperatorRuntimeError::Registry(RegistryError::Stale)
                | OperatorRuntimeError::Expired,
            ) if config.role == OperatorRoleV1::Writer
                && config.purpose.is_writer_purpose()
                && !config.authority =>
            {
                StaleWriterRuntime::open_using(config, anchor, now, native, posture)
                    .map(Self::StaleWriter)
            }
            Err(error) => Err(error),
        }
    }
    /// No conversion from the stale variant is possible.
    pub fn current(&self) -> Option<&OperatorRuntime> {
        match self {
            Self::Current(r) => Some(r),
            Self::StaleWriter(_) => None,
        }
    }
    pub fn head(&self) -> WriterRegistryHeadRef<'_> {
        match self {
            Self::Current(r) => r.head().into(),
            Self::StaleWriter(r) => r.head.as_writer(),
        }
    }
    pub fn config(&self) -> &OperatorRuntimeConfig {
        match self {
            Self::Current(r) => r.config(),
            Self::StaleWriter(r) => &r.resources.config,
        }
    }
    pub fn native(&self) -> &Arc<NativeOperatorProvider> {
        match self {
            Self::Current(r) => r.native(),
            Self::StaleWriter(r) => &r.resources.native,
        }
    }
    pub fn database(&self) -> &Arc<EncryptedDatabase> {
        match self {
            Self::Current(r) => r.database(),
            Self::StaleWriter(r) => &r.resources.database,
        }
    }
    pub fn signing_provider(&self) -> &Arc<NativeKeyProvider> {
        match self {
            Self::Current(r) => r.signing_provider(),
            Self::StaleWriter(r) => &r.resources.signer,
        }
    }
    pub fn anchor(&self) -> &TrustAnchorV1 {
        match self {
            Self::Current(r) => r.anchor(),
            Self::StaleWriter(r) => r.resources.snapshot.anchor(),
        }
    }
    pub fn next_sequence(&self) -> ChainSequence {
        match self {
            Self::Current(r) => r.next_sequence(),
            Self::StaleWriter(r) => r.resources.snapshot.next_sequence(),
        }
    }
    pub fn ensure_current(&self) -> Result<(), OperatorRuntimeError> {
        match self {
            Self::Current(r) => r.ensure_current(),
            Self::StaleWriter(r) => r.ensure_writer_ready(),
        }
    }
    pub fn reopened_for_action(&self) -> Result<Self, OperatorRuntimeError> {
        self.native().ensure_session_active()?;
        let (anchor, posture) = match self {
            Self::Current(r) => (&r.anchor_path, &r.posture),
            Self::StaleWriter(r) => (&r.resources.anchor_path, &r.resources.posture),
        };
        Self::acquire_using(
            self.config().clone(),
            anchor,
            acquisition::AcquisitionTime::FreshWallClock,
            self.native().clone(),
            posture.clone(),
        )
    }
    pub fn refresh_for_action(&mut self) -> Result<(), OperatorRuntimeError> {
        *self = self.reopened_for_action()?;
        Ok(())
    }
    pub fn reauthenticate_for(
        &self,
        purpose: ReauthPurpose,
    ) -> Result<VerifiedOperatorSession, OperatorRuntimeError> {
        match self {
            Self::Current(r) => r.reauthenticate_for(purpose),
            Self::StaleWriter(r) => r.reauthenticate(purpose, None),
        }
    }
    pub fn reauthenticate_for_context(
        &self,
        purpose: ReauthPurpose,
        context: Hash32,
    ) -> Result<VerifiedOperatorSession, OperatorRuntimeError> {
        match self {
            Self::Current(r) => r.reauthenticate_for_context(purpose, context),
            Self::StaleWriter(r) => r.reauthenticate(purpose, Some(context)),
        }
    }
    pub fn verify_session_proof(
        &self,
        purpose: ReauthPurpose,
        proof: &OperatorSessionProof,
    ) -> Result<(), OperatorRuntimeError> {
        self.ensure_current()?;
        match self {
            Self::Current(r) => verify_current_session(
                r.head(),
                r.config.device_certificate_hash,
                r.config.role,
                proof,
                purpose,
                r.native.as_ref(),
            )?,
            Self::StaleWriter(r) => verify_writer_session(
                r.head.as_writer(),
                r.resources.config.device_certificate_hash,
                proof,
                purpose,
                r.resources.native.as_ref(),
            )?,
        }
        Ok(())
    }
}

/// No SelectedRegistryHead, administrative service or unchecked constructor.
pub struct StaleWriterRuntime {
    resources: RuntimeResources,
    head: StaleWriterRegistryHead,
    local_device: VerifiedLocalDeviceIdentity,
    account_hash: Hash32,
}
impl StaleWriterRuntime {
    fn open_using(
        config: OperatorRuntimeConfig,
        anchor: &Path,
        now: UnixMillis,
        native: Arc<NativeOperatorProvider>,
        posture: Arc<dyn DevicePostureProvider>,
    ) -> Result<Self, OperatorRuntimeError> {
        if config.role != OperatorRoleV1::Writer
            || !config.purpose.is_writer_purpose()
            || config.authority
        {
            return Err(OperatorRuntimeError::Config);
        }
        let mut resources = open_resources(config, anchor, now, false, |_| Ok(native), posture)?;
        let key = TrustStateKey {
            organization_id: resources.snapshot.anchor().organization_id(),
            device_id: resources.device_id,
        };
        let head = select_stale_writer(&resources.snapshot, &mut resources.store, key, now)?;
        let view = head.as_writer();
        let public = resources
            .native
            .public_key(NativeSigningSlot::Writer)?
            .ok_or(OperatorRuntimeError::SignerMismatch)?;
        let certificate = resources.config.device_certificate_hash;
        let fields = view
            .active_certificate_fields(certificate)
            .ok_or(OperatorError::DeviceCertificateNotActive)?;
        if fields.certificate_kind != CertificateKindV1::Writer
            || fields.signing_key_thumbprint != Some(public.thumbprint())
            || fields.signing_public_cose_key.as_deref()
                != Some(public.to_deterministic_cbor().as_slice())
        {
            return Err(OperatorRuntimeError::SignerMismatch);
        }
        let local_device =
            VerifiedLocalDeviceIdentity::verify_writer(view, certificate, resources.device_id)?;
        let account_hash = resources
            .native
            .os_account_binding_hash(key.organization_id, resources.device_id)?;
        let runtime = Self {
            resources,
            head,
            local_device,
            account_hash,
        };
        runtime.ensure_writer_ready()?;
        Ok(runtime)
    }
    fn ensure_writer_ready(&self) -> Result<(), OperatorRuntimeError> {
        let r = &self.resources;
        let view = self.head.as_writer();
        let time = view.preexisting_effective_now();
        let end = time
            .wall_clock_ceiling()
            .map(|value| UnixMillis::new(value.get().saturating_add(1)))
            .into_iter()
            .chain(time.successor_ready_at())
            .min()
            .unwrap_or(UnixMillis::new(i64::MAX));
        validate_freshness(r.opened.elapsed(), fresh_wall_clock()?, time.value(), end)?;
        r.native.ensure_session_active()?;
        if r.native
            .os_account_binding_hash(r.snapshot.anchor().organization_id(), r.device_id)?
            != self.account_hash
        {
            return Err(OperatorError::AccountMismatch.into());
        }
        // Signed Unknown documentation expires no later than Registry.notAfter.
        // It cannot extend the stale exception; only current measured Pass does.
        if !r
            .posture
            .report()
            .map_err(|_| OperatorRuntimeError::Posture)?
            .is_production_ready()
        {
            return Err(OperatorRuntimeError::Posture);
        }
        Ok(())
    }
    fn ensure_same_action_authority(&self) -> Result<(), OperatorRuntimeError> {
        self.ensure_writer_ready()?;
        let r = &self.resources;
        let fresh = InteractiveOperatorRuntime::acquire_using(
            r.config.clone(),
            &r.anchor_path,
            acquisition::AcquisitionTime::FreshWallClock,
            r.native.clone(),
            r.posture.clone(),
        )?;
        fresh.ensure_current()?;
        let expected = self.head.as_writer();
        if fresh.head().registry_head_hash() != expected.registry_head_hash()
            || fresh.head().registry_version() != expected.registry_version()
            || fresh.next_sequence() != r.snapshot.next_sequence()
            || !fresh
                .head()
                .preexisting_effective_now()
                .has_same_persisted_bounds(expected.preexisting_effective_now())
        {
            return Err(OperatorError::ProofMismatch.into());
        }
        Ok(())
    }
    fn reauthenticate(
        &self,
        purpose: ReauthPurpose,
        context: Option<Hash32>,
    ) -> Result<VerifiedOperatorSession, OperatorRuntimeError> {
        if !purpose.is_writer_purpose() {
            return Err(OperatorError::RoleMismatch.into());
        }
        self.ensure_writer_ready()?;
        let r = &self.resources;
        let audit = SignedLocalAuditService::new(
            Arc::new(SqliteLocalAuditRepository::new(r.database.clone())),
            r.signer.clone(),
            r.signer.handle(SecretPurpose::WriterSigningKey),
            ObjectHash::try_from(r.config.device_certificate_hash.as_bytes().as_slice())
                .expect("fixed certificate hash"),
            self.head.as_writer().preexisting_effective_now().value(),
        );
        let presence = StalePresence(self);
        let service = crate::operator::WriterOperatorSessionService::new(
            self.head.as_writer(),
            &audit,
            self.local_device,
        );
        let session = service.verify_session(
            VerifySessionRequest {
                database: &r.database,
                binding_object_hash: r.config.binding_object_hash,
                device_certificate_hash: r.config.device_certificate_hash,
                role: OperatorRoleV1::Writer,
                purpose,
                account: r.native.clone(),
                authenticator: &presence,
            },
            context,
        )?;
        self.ensure_same_action_authority()?;
        r.native.record_verified_session(&session)?;
        Ok(session)
    }
}
struct StalePresence<'a>(&'a StaleWriterRuntime);
impl OperatorPresence for StalePresence<'_> {
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        prove_with_deadline(self.0.resources.native.as_ref(), challenge, || {
            self.0.ensure_same_action_authority()
        })
    }
}
fn select_stale_writer(
    snapshot: &OperatorArchiveSnapshot,
    store: &mut OperatorTrustStateStore,
    key: TrustStateKey,
    now: UnixMillis,
) -> Result<StaleWriterRegistryHead, OperatorRuntimeError> {
    for _ in 0..=snapshot.inventory.trust().len() {
        let trust = verify_trust(
            &snapshot.anchor,
            &snapshot.inventory,
            load_trust_state(store, key)?,
        )?;
        let candidate = verify_registry_candidate(&trust, snapshot.next_sequence)?;
        let mut sources = Vec::new();
        if let Some(authority) = candidate.preexisting_authority() {
            for receipt in snapshot.inventory.receipts() {
                if let Ok(time) = verify_receipt_time(authority, receipt) {
                    sources.push(time);
                }
            }
            for evidence in snapshot.inventory.evidence() {
                if let Ok(time) = verify_checkpoint_time(authority, evidence) {
                    sources.push(time);
                }
            }
        }
        let time = prepare_local_time(store, &candidate, now, &sources)?;
        let pending = match select_registry_head(candidate, time, None) {
            Ok(RegistrySelectionOutcome::Advanced(_)) => continue,
            Ok(RegistrySelectionOutcome::Selected(_)) => return Err(OperatorRuntimeError::Expired),
            Ok(RegistrySelectionOutcome::PendingFuture(pending)) => Some(pending),
            Err(RegistryError::Stale) => None,
            Err(error) => return Err(error.into()),
        };
        // Re-read the exact committed pin/revision after independent time writes.
        let trust = verify_trust(
            &snapshot.anchor,
            &snapshot.inventory,
            load_trust_state(store, key)?,
        )?;
        let candidate = if let Some(pending) = pending {
            ea_trust::verify_current_head_fallback(&trust, pending)?
        } else {
            verify_registry_candidate(&trust, snapshot.next_sequence)?
        };
        let time = prepare_local_time(store, &candidate, now, &[])?;
        return Ok(ea_trust::select_stale_writer_registry_head(
            candidate, time,
        )?);
    }
    Err(OperatorRuntimeError::Sequence)
}
