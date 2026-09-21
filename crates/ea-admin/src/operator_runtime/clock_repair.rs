//! Purpose-only native Clock repair. No ordinary operator authority is returned.
use super::*;
use ea_archive::ArchiveSource;
use ea_audit::{AuditError, ClockRepairAuditService, SignedLocalAuditEvent};
use ea_format::ClockReleaseJustificationV1;
use ea_local_store::{StoreError, StoreValue};
use ea_trust::{ClockReleaseError, TrustStateStore as _};
use ea_trust::{ClockRepairRegistryAuthority, verify_clock_repair_authority};
use std::cell::{Cell, RefCell};

pub enum ClockRepairRuntimeError {
    Runtime(OperatorRuntimeError),
    Clock(ClockReleaseError),
    Audit(AuditError),
    /// Für dieselbe blockierende unabhängige Zeitreferenz und denselben
    /// gepinnten Head ist bereits eine Freigabe dauerhaft verbraucht.
    ///
    /// Eine wiederholt neu signierte Freigabe wäre eine permanente
    /// Clock-Ausnahme statt einer tatsächlichen Zeitkorrektur; der Pfad
    /// verweigert deshalb fail-closed VOR Präsenz und vor jedem Audit.
    ///
    /// `EA-SKEW-` statt `EA-TRUST-CLOCK-RELEASE-`: der Befund stammt nicht vom
    /// Freigabekern, sondern aus dem dauerhaften lokalen Audit dieser Schicht
    /// (Begründung der Familie in `crate::clock_release`). Er ist auch nicht
    /// `EA-TRUST-CLOCK-RELEASE-REPLAY`: dort werden exakt dieselben Bytes
    /// wieder eingespielt, hier wäre es eine neue Freigabe mit neuer Nonce.
    AlreadyReleased,
}
impl ClockRepairRuntimeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Runtime(e) => e.code(),
            Self::Clock(e) => e.code(),
            Self::Audit(e) => e.code(),
            Self::AlreadyReleased => "EA-SKEW-ALREADY-RELEASED",
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
        Self::open_with_test_native_and_posture(
            config,
            anchor,
            native,
            Arc::new(super::FixturePassingPosture),
        )
    }
    /// Nur für Fixtures: der installierte Pfad wählt immer den tatsächlichen
    /// Host-Adapter und kann keinen Bericht aus Konfiguration übernehmen.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_with_test_native_and_posture(
        config: OperatorRuntimeConfig,
        anchor: &Path,
        native: Arc<NativeOperatorProvider>,
        posture: Arc<dyn DevicePostureProvider>,
    ) -> Result<Self, ClockRepairRuntimeError> {
        Self::open_using(config, anchor, |_| Ok(native), posture)
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
                        open_resources(config, anchor, now, false, open_native, posture, None)?;
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
                    runtime.require_unreleased_situation()?;
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
        justification: ClockReleaseJustificationV1,
    ) -> Result<CompletedClockRepair, ClockRepairRuntimeError> {
        // Erneut hier: eine vor dem ersten Consume geöffnete Laufzeit darf
        // dieselbe Sperrsituation nicht ein zweites Mal freigeben.
        self.require_unreleased_situation()?;
        self.recheck()?;
        let r = &self.resources;
        let profile = crate::operator_profile::load(&r.database)
            .map_err(OperatorRuntimeError::from)?
            .ok_or(OperatorRuntimeError::Config)?;
        let public = r
            .native
            .public_key(NativeSigningSlot::Admin)
            .map_err(OperatorRuntimeError::from)?
            .ok_or(OperatorRuntimeError::SignerMismatch)?;
        let local = ea_operator::ClockRepairProfileSnapshot {
            organization_id: profile.organization_id(),
            operator_subject_id: profile.operator_subject_id(),
            binding_hash: profile.operator_binding_object_hash(),
            display_name: profile.display_name(),
            function_label: profile.function_label(),
            salt: profile.profile_commitment_salt(),
        };
        let failure = RefCell::new(None);
        let proof = ea_operator::authenticate_clock_repair(
            &self.authority,
            r.native.as_ref(),
            &public,
            &local,
            |challenge| {
                let check = || {
                    self.recheck().map_err(|error| {
                        failure.replace(Some(error));
                        OperatorError::PresenceProofInvalid
                    })
                };
                check()?;
                let signature =
                    OperatorPresence::prove_presence_and_sign(r.native.as_ref(), challenge)?;
                check()?;
                Ok(signature)
            },
        );
        if let Some(error) = failure.into_inner() {
            return Err(error);
        }
        let proof = proof.map_err(OperatorRuntimeError::from)?;
        let expires = proof.expires_at();
        let audit = ClockRepairAuditService::new(
            Arc::new(SqliteLocalAuditRepository::new(r.database.clone())),
            r.signer.clone(),
            r.signer.handle(SecretPurpose::WriterSigningKey),
        );
        let login = self.checked_audit(|check| audit.record_login_checked(&proof, check))?;
        if !proof.is_valid_at(self.recheck()?) {
            return Err(OperatorRuntimeError::Expired.into());
        }
        r.native
            .record_verified_clock_presence(&proof, &login)
            .map_err(OperatorRuntimeError::from)?;
        let release = self.checked_audit(|check| {
            audit.record_release_checked(proof, &login, justification, check)
        })?;
        // Letzte Nachprüfung VOR dem dauerhaften Consume: `recheck` umfasst
        // `check_local` (Watch, Signer, Bindung, Profil, gemessene Posture)
        // und die frische Walltime gegen den Ablauf der Präsenz.
        if self.recheck()? >= expires {
            return Err(OperatorRuntimeError::Expired.into());
        }
        self.consume_exact_release(&release)?;
        // Nach dem Consume sind Revision, Replay-Nonce und beide Audits
        // dauerhaft. Hier darf keine Prüfung mehr auf `Err` gehen, sonst
        // meldete `release` eine Freigabe als gescheitert, die gebucht ist.
        // Der Selector hat genau eine Auswertung verbraucht; seine allgemeine
        // Autorität wird nie zurückgegeben, und ein Reopen mit derselben alten
        // Referenz bleibt gesperrt.
        Ok(CompletedClockRepair {
            login: login.into_event(),
            release,
        })
    }

    fn checked_audit<T>(
        &self,
        operation: impl FnOnce(
            &mut dyn FnMut() -> Result<UnixMillis, AuditError>,
        ) -> Result<T, AuditError>,
    ) -> Result<T, ClockRepairRuntimeError> {
        let mut failure = None;
        let result = operation(&mut || {
            self.recheck().map_err(|error| {
                failure = Some(error);
                AuditError::SessionExpired
            })
        });
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(result?)
    }

    /// Verweigert, wenn für die aktuell blockierende unabhängige Referenz und
    /// den aktuell gepinnten Head bereits eine Freigabe verbraucht wurde.
    ///
    /// Nutzt ausschließlich vorhandenen dauerhaften Zustand: die signierten
    /// `ClockSkewRelease`/`Accepted`-Audits (ihr Kontext trägt Referenz und
    /// Head) und die Replay-Tabelle des Trust-Stores (ihre Nonce belegt den
    /// Consume). Ein Accepted-Audit ohne Consume — ein Abbruch vor dem Consume
    /// — sperrt nicht: dann wurde nichts freigegeben.
    fn require_unreleased_situation(&self) -> Result<(), ClockRepairRuntimeError> {
        let r = &self.resources;
        let key = TrustStateKey {
            organization_id: self.authority.organization_id(),
            device_id: r.device_id,
        };
        let record = r
            .store
            .clone()
            .load(key)
            .map_err(OperatorRuntimeError::from)?;
        let reference = record
            .trusted_time()
            .independent_reference()
            .ok_or(ClockReleaseError::Mismatch)?;
        let pin = *record.pinned_head().ok_or(ClockReleaseError::Mismatch)?;
        let spent = r
            .database
            .transaction(|tx| -> Result<bool, StoreError> {
                let mut after = 0_i64;
                while let Some(row) = tx.query_row(
                    "SELECT insertion_sequence,exact_bytes FROM local_audit_event \
                     WHERE insertion_sequence>?1 ORDER BY insertion_sequence LIMIT 1",
                    &[StoreValue::Integer(after)],
                )? {
                    after = row.integer(0)?;
                    // Andere Audit-Arten sind hier ohne Belang.
                    let Ok(audit) = ea_format::decode_clock_release_audit(row.blob(1)?) else {
                        continue;
                    };
                    let context = audit.context();
                    let signed = context.independent_reference();
                    if audit.organization_id() != key.organization_id
                        || audit.target_device_id() != key.device_id
                        || audit.outcome() != ea_format::LocalAuditOutcomeV1::Accepted
                        || context.registry_version() != pin.registry_version()
                        || context.registry_head_hash() != pin.registry_head_hash()
                        || signed.object_hash() != reference.object_hash()
                        || signed.verified_time() != reference.verified_time()
                    {
                        continue;
                    }
                    if tx
                        .query_row(
                            "SELECT 1 FROM operator_clock_release_replay \
                             WHERE organization_id=?1 AND device_id=?2 AND nonce=?3",
                            &[
                                StoreValue::Blob(key.organization_id.as_bytes().to_vec()),
                                StoreValue::Blob(key.device_id.as_bytes().to_vec()),
                                StoreValue::Blob(audit.nonce().to_vec()),
                            ],
                        )?
                        .is_some()
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            })
            .map_err(OperatorRuntimeError::from)?;
        if spent {
            return Err(ClockRepairRuntimeError::AlreadyReleased);
        }
        Ok(())
    }

    fn consume_exact_release(
        &self,
        release: &SignedLocalAuditEvent,
    ) -> Result<(), ClockRepairRuntimeError> {
        // Reconstruct the audit's original blocked evaluation only for the
        // unchanged historical verifier and one-use CAS selector. Fresh live
        // issuance has already been rechecked; this is never current admission.
        let audit = ea_format::decode_clock_release_audit(release.exact_bytes())
            .map_err(|_| ClockReleaseError::Mismatch)?;
        let snapshot = &self.resources.snapshot;
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
        let sources = signed_times(snapshot, &candidate);
        let mut block = prepare_local_time(
            &mut store,
            &candidate,
            audit.context().observed_os_wall_clock(),
            &sources,
        )
        .map_err(OperatorRuntimeError::from)?;
        self.authority.require_same_state(&candidate, &block)?;
        let release =
            ea_trust::verify_clock_release(&candidate, &mut block, release.exact_bytes())?;
        match select_registry_head(candidate, block, Some(release))
            .map_err(OperatorRuntimeError::from)?
        {
            RegistrySelectionOutcome::Selected(head)
                if head.registry_head_hash() == self.authority.registry_head_hash() =>
            {
                Ok(())
            }
            // Nach `require_same_state` bei derselben Auswertungszeit sind
            // `Advanced` (stale/Lease) und ein abweichender Head bereits vor
            // dem Commit ausgeschlossen (`require_fresh_event`); dieser Arm
            // ist reine Abwehr und im geprüften Pfad nicht erreichbar.
            _ => Err(ClockReleaseError::Mismatch.into()),
        }
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
