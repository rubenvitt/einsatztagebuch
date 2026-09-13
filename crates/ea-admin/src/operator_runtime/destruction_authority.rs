//! Refusal-only native revalidation while the caller holds Writer SQLCipher.
//! No CurrentHead, session or signing authority is issued from this module.
use super::*;
use ea_destruction::{DestructionError, LocalActionAuthorityGuard};
use ea_local_store::{StoreTransaction, StoreValue};
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistrySelectionCommit,
    TrustStateStore,
};

pub(crate) struct HeldDestructionAuthority<'a> {
    controller: HeldParticipant<'a>,
    custodian: HeldParticipant<'a>,
    refusal_cutoff: Option<UnixMillis>,
}
struct HeldParticipant<'a> {
    runtime: &'a OperatorRuntime,
    posture: DevicePostureReport,
    evidence_hash: Option<ObjectHash>,
    evidence_deadline: Option<UnixMillis>,
}
impl<'a> HeldDestructionAuthority<'a> {
    pub(crate) fn capture(
        controller: &'a OperatorRuntime,
        custodian: &'a OperatorRuntime,
    ) -> Result<Self, OperatorRuntimeError> {
        Ok(Self {
            controller: HeldParticipant::capture(controller)?,
            custodian: HeldParticipant::capture(custodian)?,
            refusal_cutoff: None,
        })
    }
    /// Additional refusal only; ordinary and Complete captures remain unchanged.
    pub(crate) fn capture_before(
        controller: &'a OperatorRuntime,
        custodian: &'a OperatorRuntime,
        cutoff: UnixMillis,
    ) -> Result<Self, OperatorRuntimeError> {
        let mut held = Self::capture(controller, custodian)?;
        held.refusal_cutoff = Some(cutoff);
        Ok(held)
    }
}
impl LocalActionAuthorityGuard for HeldDestructionAuthority<'_> {
    fn check_in(&mut self, tx: &StoreTransaction<'_>) -> Result<(), DestructionError> {
        self.controller
            .check(None, self.refusal_cutoff)
            .and_then(|_| self.custodian.check(Some(tx), self.refusal_cutoff))
            .map_err(|_| DestructionError::Operator)
    }
    fn check_before_effect(&mut self) -> Result<(), DestructionError> {
        self.controller
            .check(None, self.refusal_cutoff)
            .and_then(|_| self.custodian.check(None, self.refusal_cutoff))
            .map_err(|_| DestructionError::Operator)
    }
}
impl<'a> HeldParticipant<'a> {
    fn capture(runtime: &'a OperatorRuntime) -> Result<Self, OperatorRuntimeError> {
        runtime.ensure_same_action_authority()?;
        let admission = runtime.posture_admission_for_report()?;
        Ok(Self {
            runtime,
            posture: runtime.device_posture_report()?,
            evidence_hash: admission.document_hash(),
            evidence_deadline: admission.valid_until(),
        })
    }
    fn check(
        &self,
        tx: Option<&StoreTransaction<'_>>,
        cutoff: Option<UnixMillis>,
    ) -> Result<(), OperatorRuntimeError> {
        let runtime = self.runtime;
        // These checks do not acquire the SQLCipher connection mutex.
        runtime.ensure_fresh_context()?;
        runtime.native.ensure_session_active()?;
        let public = runtime
            .native
            .public_key(role_slot(runtime.config.role)?)?
            .ok_or(OperatorRuntimeError::SignerMismatch)?;
        verify_local_signing_identity(
            &runtime.head,
            runtime.config.device_certificate_hash,
            runtime.config.role,
            &public,
        )?;
        if runtime.device_posture_report()? != self.posture {
            return Err(OperatorRuntimeError::Posture);
        }
        let raw = fresh_wall_clock()?;
        let now = self.observation_now(raw)?;
        Self::require_before(cutoff, now)?;
        if self
            .evidence_deadline
            .is_some_and(|deadline| now >= deadline)
            || runtime
                .head
                .preexisting_effective_now()
                .wall_clock_ceiling()
                .is_some_and(|ceiling| now > ceiling)
            || runtime
                .head
                .preexisting_effective_now()
                .successor_ready_at()
                .is_some_and(|ready| now >= ready)
        {
            return Err(OperatorRuntimeError::Expired);
        }
        let query = |sql: &str, parameters: &[StoreValue]| match tx {
            Some(tx) => tx.query_row(sql, parameters),
            None => runtime.database.query_row(sql, parameters),
        };
        if let Some(hash) = self.evidence_hash {
            let row = query(
                "SELECT object_hash,exact_envelope FROM go_live_posture_evidence WHERE singleton=0",
                &[],
            )?
            .ok_or(OperatorRuntimeError::Posture)?;
            if row.blob(0)? != hash.as_bytes() || ea_crypto::object_hash(row.blob(1)?) != hash {
                return Err(OperatorRuntimeError::Posture);
            }
            if let Some(row) = query(
                "SELECT last_observed_wall FROM go_live_posture_clock WHERE installation_id=?1",
                &[StoreValue::Blob(
                    runtime.native.installation_id().as_bytes().to_vec(),
                )],
            )? && raw.get() < row.integer(0)?
            {
                return Err(OperatorRuntimeError::Posture);
            }
        }
        let key = TrustStateKey {
            organization_id: runtime.anchor().organization_id(),
            device_id: runtime.device_id,
        };
        let record = match tx {
            Some(tx) => runtime.store.read_record_in(tx)?,
            None => runtime.store.clone().load(key)?,
        };
        if record.trusted_time() != runtime.trust.trusted_time()
            || record.pinned_head().copied() != runtime.trust.pinned_head().copied()
        {
            return Err(OperatorError::ProofMismatch.into());
        }
        // This ordinary public verifier already accepts matching EIP+EDS
        // identities. No source projection or special bootstrap exception.
        let snapshot = OperatorArchiveSnapshot::open(
            &runtime.config.archive_directory,
            &runtime.anchor_path,
            raw,
        )?;
        if snapshot.next_sequence() != runtime.next_sequence()
            || snapshot.anchor.trust_anchor_hash() != runtime.anchor().trust_anchor_hash()
        {
            return Err(OperatorError::ProofMismatch.into());
        }
        let mut readonly = ReadOnlyRecord { key, record };
        let trust = verify_trust(
            &snapshot.anchor,
            &snapshot.inventory,
            load_trust_state(&mut readonly, key)?,
        )?;
        let catalog = ea_trust::verify_catalog_custody_authority(&trust)?;
        if catalog.registry_head_hash()
            != ea_trust::verify_catalog_custody_authority(&runtime.trust)?.registry_head_hash()
        {
            return Err(OperatorError::ProofMismatch.into());
        }
        let candidate = verify_registry_candidate(&trust, snapshot.next_sequence)?;
        let mut sources = Vec::new();
        if let Some(authority) = candidate.preexisting_authority() {
            for receipt in snapshot.inventory.receipts() {
                if let Ok(source) = verify_receipt_time(authority, receipt) {
                    sources.push(source)
                }
            }
            for evidence in snapshot.inventory.evidence() {
                if let Ok(source) = verify_checkpoint_time(authority, evidence) {
                    sources.push(source)
                }
            }
        }
        // A newly verified time statement requiring a durable change is denied
        // here; reopen and reauthenticate outside this transaction. No selection
        // occurs and no action authority is minted from this read-only record.
        let _checked = prepare_local_time(&mut readonly, &candidate, raw, &sources)?;
        runtime.ensure_fresh_context()?;
        // Native and archive checks above may block. Pending alone repeats
        // the existing observation formula after them; it creates no time proof.
        if cutoff.is_some() {
            Self::require_before(cutoff, self.observation_now(fresh_wall_clock()?)?)?;
        }
        Ok(())
    }
    fn observation_now(&self, raw: UnixMillis) -> Result<UnixMillis, OperatorRuntimeError> {
        let runtime = self.runtime;
        let elapsed = i64::try_from(runtime.opened.elapsed().as_millis())
            .map_err(|_| OperatorRuntimeError::Expired)?;
        let now = UnixMillis::new(
            raw.get().max(
                runtime
                    .head
                    .preexisting_effective_now()
                    .value()
                    .get()
                    .checked_add(elapsed)
                    .ok_or(OperatorRuntimeError::Expired)?,
            ),
        );
        Ok(now)
    }
    fn require_before(
        cutoff: Option<UnixMillis>,
        now: UnixMillis,
    ) -> Result<(), OperatorRuntimeError> {
        if cutoff.is_some_and(|cutoff| now >= cutoff) {
            return Err(OperatorRuntimeError::Expired);
        }
        Ok(())
    }
}
struct ReadOnlyRecord {
    key: TrustStateKey,
    record: PersistedTrustRecord,
}
impl TrustStateStore for ReadOnlyRecord {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(PersistedTrustRecord::new(
            self.record.revision(),
            self.record.trusted_time().clone(),
            self.record.pinned_head().copied(),
        ))
    }
    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
}
