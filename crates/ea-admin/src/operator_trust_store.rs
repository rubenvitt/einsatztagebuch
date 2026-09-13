//! Durable writer trust state in the host's SQLCipher database.
//!
//! Schema ownership stays in `ea-local-store` (migration 0005). Every mutation
//! reads and checks the durable record inside `BEGIN IMMEDIATE`, including
//! callers using different connections or processes. No process-local cache
//! participates in revision or replay decisions.
use std::sync::Arc;

use ea_local_store::{EncryptedDatabase, StoreError, StoreRow, StoreTransaction, StoreValue};
use ea_time::{
    IndependentTimeInput, IndependentTimeKind, TrustedTimeState, merge_independent_references,
};
use ea_trust::{
    AdminAuthorizationReplayDimension, AdminAuthorizationReplayKey, ClockReleaseReplayKey,
    IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin, RegistrySelectionCommit,
    StateStoreError, TrustStateKey, TrustStateStore,
};
use ea_types::{ChainId, Hash32, ObjectHash, RegistryVersion, UnixMillis};

const READ_RECORD: &str = "SELECT chain_id, trust_anchor_hash, revision, floor_ms, \
    independent_kind, independent_hash, independent_time_ms, pin_version, pin_hash, \
    independent_kind IS NULL, independent_hash IS NULL, independent_time_ms IS NULL, \
    pin_version IS NULL, pin_hash IS NULL \
    FROM operator_trust_state WHERE organization_id=?1 AND device_id=?2";

/// Trust state for one organization/device, bound to one chain and exact anchor.
///
/// Open this store before `ea_trust::load_trust_state` / `verify_trust`. Use the
/// configured, fingerprint-verified anchor for the chain and anchor arguments.
/// Independent-time and registry commits must come from `ea-trust`; this adapter
/// supplies persistence, not another source of trust authority.
#[derive(Clone)]
pub struct OperatorTrustStateStore {
    database: Arc<EncryptedDatabase>,
    key: TrustStateKey,
    chain_id: ChainId,
    trust_anchor_hash: Hash32,
}

impl OperatorTrustStateStore {
    /// Initializes a previously absent row at revision zero without a head pin.
    ///
    /// `initial_floor` is used only on first initialization. Reopening never
    /// replaces the floor, independent reference, pin, revision, or replay rows.
    /// A different chain/anchor for an existing organization/device is rejected;
    /// it cannot silently create a fresh trust context and bypass the old pin.
    ///
    /// # Errors
    ///
    /// `Conflict` for an existing, differently bound context, `Unavailable` for
    /// a missing schema or failed/malformed database read, and
    /// `MonotonicityViolation` for an invalid persisted time state.
    pub fn open(
        database: Arc<EncryptedDatabase>,
        key: TrustStateKey,
        chain_id: ChainId,
        trust_anchor_hash: Hash32,
        initial_floor: UnixMillis,
    ) -> Result<Self, StateStoreError> {
        let store = Self {
            database,
            key,
            chain_id,
            trust_anchor_hash,
        };
        store.transaction(|tx| {
            tx.execute(
                "INSERT INTO operator_trust_state \
                 (organization_id,device_id,chain_id,trust_anchor_hash,revision,floor_ms) \
                 VALUES (?1,?2,?3,?4,?5,?6) \
                 ON CONFLICT(organization_id,device_id) DO NOTHING",
                &[
                    blob(key.organization_id.as_bytes()),
                    blob(key.device_id.as_bytes()),
                    blob(chain_id.as_bytes()),
                    blob(trust_anchor_hash.as_bytes()),
                    blob(&0_u64.to_be_bytes()),
                    StoreValue::Integer(initial_floor.get()),
                ],
            )?;
            store.read_in(tx)?;
            Ok(())
        })?;
        Ok(store)
    }

    fn parameters(&self) -> [StoreValue; 2] {
        [
            blob(self.key.organization_id.as_bytes()),
            blob(self.key.device_id.as_bytes()),
        ]
    }

    fn require_key(&self, key: TrustStateKey) -> Result<(), StateStoreError> {
        if key == self.key {
            Ok(())
        } else {
            Err(StateStoreError::Conflict)
        }
    }

    fn require_clock_key(&self, key: &ClockReleaseReplayKey) -> Result<(), StateStoreError> {
        self.require_key(TrustStateKey {
            organization_id: key.organization_id(),
            device_id: key.target_device_id(),
        })
    }

    fn transaction<R>(
        &self,
        work: impl FnOnce(&StoreTransaction<'_>) -> Result<R, TransactionError>,
    ) -> Result<R, StateStoreError> {
        self.database.transaction(work).map_err(|error| error.0)
    }

    /// Read this exact runtime-bound record through the caller's existing
    /// transaction. This neither re-locks the database nor creates authority.
    pub(crate) fn read_record_in(&self,tx:&StoreTransaction<'_>)->Result<PersistedTrustRecord,StateStoreError>{
        self.read_in(tx).map_err(|error|error.0)
    }
    fn read_in(&self, tx: &StoreTransaction<'_>) -> Result<PersistedTrustRecord, TransactionError> {
        self.decode(tx.query_row(READ_RECORD, &self.parameters())?)
            .map_err(Into::into)
    }

    fn decode(&self, row: Option<StoreRow>) -> Result<PersistedTrustRecord, StateStoreError> {
        let row = row.ok_or(StateStoreError::Unavailable)?;
        if row.blob(0).map_err(unavailable)? != self.chain_id.as_bytes()
            || row.blob(1).map_err(unavailable)? != self.trust_anchor_hash.as_bytes()
        {
            return Err(StateStoreError::Conflict);
        }
        let reference = match null_flags(&row, [9, 10, 11])? {
            [true, true, true] => None,
            [false, false, false] => {
                let kind = match row.integer(4).map_err(unavailable)? {
                    0 => IndependentTimeKind::Receipt,
                    1 => IndependentTimeKind::Checkpoint,
                    2 => IndependentTimeKind::Tsa,
                    _ => return Err(StateStoreError::Unavailable),
                };
                Some(IndependentTimeInput::new(
                    kind,
                    object_hash(&row, 5)?,
                    UnixMillis::new(row.integer(6).map_err(unavailable)?),
                ))
            }
            _ => return Err(StateStoreError::Unavailable),
        };
        let time = TrustedTimeState::from_persisted(
            UnixMillis::new(row.integer(3).map_err(unavailable)?),
            reference,
        )
        .map_err(|_| StateStoreError::MonotonicityViolation)?;
        let pin = match null_flags(&row, [12, 13])? {
            [true, true] => None,
            [false, false] => Some(RegistryHeadPin::new(
                RegistryVersion::new(unsigned(&row, 7)?),
                object_hash(&row, 8)?,
            )),
            _ => return Err(StateStoreError::Unavailable),
        };
        Ok(PersistedTrustRecord::new(unsigned(&row, 2)?, time, pin))
    }

    fn commit(
        &self,
        key: TrustStateKey,
        expected_revision: u64,
        next_time: &TrustedTimeState,
        next_pin: Option<RegistryHeadPin>,
        replay: Option<&ClockReleaseReplayKey>,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.require_key(key)?;
        if let Some(replay) = replay {
            self.require_clock_key(replay)?;
        }
        self.transaction(|tx| {
            let current = self.read_in(tx)?;
            if current.revision() != expected_revision {
                return Err(StateStoreError::Conflict.into());
            }
            require_monotonic_time(current.trusted_time(), next_time)?;
            // Independent time never clears or replaces a registry head.
            let pin = next_pin.or(current.pinned_head().copied());
            if let (Some(current), Some(next)) = (current.pinned_head(), pin)
                && (next.registry_version() < current.registry_version()
                    || (next.registry_version() == current.registry_version()
                        && next.registry_head_hash() != current.registry_head_hash()))
            {
                return Err(StateStoreError::MonotonicityViolation.into());
            }
            let revision = expected_revision
                .checked_add(1)
                .ok_or(StateStoreError::MonotonicityViolation)?;
            if let Some(replay) = replay {
                let inserted = tx.execute(
                    "INSERT INTO operator_clock_release_replay (organization_id,device_id,nonce) \
                     VALUES (?1,?2,?3) ON CONFLICT(organization_id,device_id,nonce) DO NOTHING",
                    &clock_parameters(replay),
                )?;
                if inserted == 0 {
                    return Err(StateStoreError::ReplayAlreadyConsumed.into());
                }
                if inserted != 1 {
                    return Err(StateStoreError::Unavailable.into());
                }
            }
            let reference = next_time.independent_reference();
            let changed = tx.execute(
                "UPDATE operator_trust_state SET revision=?1,floor_ms=?2, \
                 independent_kind=?3,independent_hash=?4,independent_time_ms=?5, \
                 pin_version=?6,pin_hash=?7 \
                 WHERE organization_id=?8 AND device_id=?9 AND revision=?10 \
                 AND chain_id=?11 AND trust_anchor_hash=?12",
                &[
                    blob(&revision.to_be_bytes()),
                    StoreValue::Integer(next_time.floor().get()),
                    reference.map_or(StoreValue::Null, |r| StoreValue::Integer(r.kind() as i64)),
                    reference.map_or(StoreValue::Null, |r| blob(r.object_hash().as_bytes())),
                    reference.map_or(StoreValue::Null, |r| {
                        StoreValue::Integer(r.verified_time().get())
                    }),
                    pin.map_or(StoreValue::Null, |p| {
                        blob(&p.registry_version().get().to_be_bytes())
                    }),
                    pin.map_or(StoreValue::Null, |p| {
                        blob(p.registry_head_hash().as_bytes())
                    }),
                    blob(key.organization_id.as_bytes()),
                    blob(key.device_id.as_bytes()),
                    blob(&expected_revision.to_be_bytes()),
                    blob(self.chain_id.as_bytes()),
                    blob(self.trust_anchor_hash.as_bytes()),
                ],
            )?;
            if changed != 1 {
                return Err(StateStoreError::Conflict.into());
            }
            Ok(PersistedTrustRecord::new(revision, next_time.clone(), pin))
        })
    }
}

impl TrustStateStore for OperatorTrustStateStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        self.require_key(key)?;
        self.decode(
            self.database
                .query_row(READ_RECORD, &self.parameters())
                .map_err(unavailable)?,
        )
    }
    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.commit(key, revision, commit.next_trusted_time(), None, None)
    }
    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.require_clock_key(key)?;
        self.transaction(|tx| {
            self.read_in(tx)?;
            Ok(tx
                .query_row(
                    "SELECT 1 FROM operator_clock_release_replay \
                 WHERE organization_id=?1 AND device_id=?2 AND nonce=?3",
                    &clock_parameters(key),
                )?
                .is_some())
        })
    }
    fn admin_authorization_consumed(
        &mut self,
        key: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError> {
        if key.organization_id() != self.key.organization_id {
            return Err(StateStoreError::Conflict);
        }
        let (dimension, value) = match key.dimension() {
            AdminAuthorizationReplayDimension::AuthorizationId(id) => (0, blob(id.as_bytes())),
            AdminAuthorizationReplayDimension::Nonce(nonce) => (1, blob(&nonce)),
        };
        self.transaction(|tx| {
            self.read_in(tx)?;
            // Only a duplicate PRIMARY KEY means "already consumed". Schema,
            // trigger, and I/O failures must never be mistaken for freshness.
            let inserted = tx.execute(
                "INSERT INTO operator_admin_replay (organization_id,dimension,replay_value) \
                 VALUES (?1,?2,?3) ON CONFLICT(organization_id,dimension,replay_value) DO NOTHING",
                &[
                    blob(key.organization_id().as_bytes()),
                    StoreValue::Integer(dimension),
                    value,
                ],
            )?;
            match inserted {
                0 => Ok(true),
                1 => Ok(false),
                _ => Err(StateStoreError::Unavailable.into()),
            }
        })
    }
    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.commit(
            key,
            revision,
            commit.next_trusted_time(),
            Some(*commit.next_head()),
            commit.replay_key(),
        )
    }
}

fn require_monotonic_time(
    current: &TrustedTimeState,
    next: &TrustedTimeState,
) -> Result<(), StateStoreError> {
    if next.floor() < current.floor() {
        return Err(StateStoreError::MonotonicityViolation);
    }
    // Reuse ea-time's complete preference order (time, source kind, hash) rather
    // than silently dropping its equal-time tie-break rules in this adapter.
    let input = current.independent_reference().map(|reference| {
        IndependentTimeInput::new(
            reference.kind(),
            reference.object_hash(),
            reference.verified_time(),
        )
    });
    let merged = merge_independent_references(next, input.as_slice())
        .map_err(|_| StateStoreError::MonotonicityViolation)?;
    if merged.state() != next {
        return Err(StateStoreError::MonotonicityViolation);
    }
    Ok(())
}

fn clock_parameters(key: &ClockReleaseReplayKey) -> [StoreValue; 3] {
    [
        blob(key.organization_id().as_bytes()),
        blob(key.target_device_id().as_bytes()),
        blob(key.nonce()),
    ]
}

fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}

fn unsigned(row: &StoreRow, index: usize) -> Result<u64, StateStoreError> {
    let bytes = row
        .blob(index)
        .map_err(unavailable)?
        .try_into()
        .map_err(|_| StateStoreError::Unavailable)?;
    Ok(u64::from_be_bytes(bytes))
}

fn object_hash(row: &StoreRow, index: usize) -> Result<ObjectHash, StateStoreError> {
    ObjectHash::try_from(row.blob(index).map_err(unavailable)?)
        .map_err(|_| StateStoreError::Unavailable)
}

fn null_flags<const N: usize>(
    row: &StoreRow,
    indices: [usize; N],
) -> Result<[bool; N], StateStoreError> {
    let mut flags = [false; N];
    for (flag, index) in flags.iter_mut().zip(indices) {
        *flag = match row.integer(index).map_err(unavailable)? {
            0 => false,
            1 => true,
            _ => return Err(StateStoreError::Unavailable),
        };
    }
    Ok(flags)
}

const fn unavailable(_: StoreError) -> StateStoreError {
    StateStoreError::Unavailable
}

// Neither external error type can implement From for the other here. Keep the
// transaction bridge local and preserve domain failures through rollback.
struct TransactionError(StateStoreError);
impl From<StateStoreError> for TransactionError {
    fn from(error: StateStoreError) -> Self {
        Self(error)
    }
}
impl From<StoreError> for TransactionError {
    fn from(error: StoreError) -> Self {
        Self(unavailable(error))
    }
}
