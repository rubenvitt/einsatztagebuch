//! Native backup/recovery composition. Public source claims never replace the
//! independent anchor, current operator, measured machine or actual store.
use crate::operator_runtime::{OperatorRuntime, OperatorRuntimeError};
use ea_archive::{ArchiveBackend, ArchiveBackendProfileV1, BoundArchiveProfilePolicyV1};
use ea_archive_fs::{CapabilityTestVectorV1, LocalPathBackend};
use ea_audit::{AuditActorProof, SqliteLocalAuditRepository, TypedLocalAuditEvent};
use ea_crypto::{SecretVec, object_hash};
use ea_format::{GenericAuditContextV1, LocalAuditActionV1, LocalAuditOutcomeV1, OperatorRoleV1};
use ea_local_store::{StoreError, StoreValue};
use ea_operator::ReauthPurpose;
use ea_recovery::{
    FsArchiveSource, KeyInventory, RecoveryBackupKdf, RecoveryProbeBinding, RecoverySourceCore,
    RecoverySourceFields, RecoveryTestError, VerifiedRecoverySource,
};
use ea_types::ObjectHash;
use std::path::Path;

pub enum RecoveryRuntimeError {
    Runtime(OperatorRuntimeError),
    Test(RecoveryTestError),
    Store(StoreError),
    Backend(ea_archive::ArchiveBackendError),
    Aborted,
}
impl RecoveryRuntimeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Runtime(e) => e.code(),
            Self::Test(e) => e.code(),
            Self::Store(e) => e.code(),
            Self::Backend(e) => e.code(),
            Self::Aborted => "EA-RECOVERY-TEST-CANCELLED",
        }
    }
}
impl std::fmt::Display for RecoveryRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::fmt::Debug for RecoveryRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for RecoveryRuntimeError {}
impl From<RecoveryTestAbort> for RecoveryRuntimeError {
    fn from(_: RecoveryTestAbort) -> Self {
        Self::Aborted
    }
}
impl From<OperatorRuntimeError> for RecoveryRuntimeError {
    fn from(e: OperatorRuntimeError) -> Self {
        Self::Runtime(e)
    }
}
impl From<RecoveryTestError> for RecoveryRuntimeError {
    fn from(e: RecoveryTestError) -> Self {
        Self::Test(e)
    }
}
impl From<StoreError> for RecoveryRuntimeError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<ea_archive::ArchiveBackendError> for RecoveryRuntimeError {
    fn from(e: ea_archive::ArchiveBackendError) -> Self {
        Self::Backend(e)
    }
}

pub struct RecoveryTestRuntime {
    runtime: OperatorRuntime,
    backend: LocalPathBackend,
}
/// Only a completed report can be consumed by the readiness path. A failed
/// report is independently signed durable diagnosis.
pub enum RecoveryTestOutcome {
    Completed(ea_recovery::VerifiedCompletedRecoveryReport),
    Failed(ea_recovery::VerifiedFailedRecoveryReport),
}
pub struct RecoverySourceCapture<'a> {
    pub inventory: &'a KeyInventory,
    pub probes: Vec<RecoveryProbeBinding>,
    pub snapshot: &'a Path,
    pub passphrase: &'a SecretVec,
}
impl RecoveryTestRuntime {
    pub fn with_archive_config(runtime: OperatorRuntime, config: crate::native_archive::NativeArchiveConfig) -> Result<Self, RecoveryRuntimeError> {
        Self::new(runtime, config.profile)
    }
    pub fn archive_profile_hash(&self) -> Result<ea_types::Hash32, RecoveryRuntimeError> {
        Ok(self.backend.profile_hash()?)
    }
    /// A concrete backend rooted at the same verified native runtime path. A
    /// controlled-network profile is explicitly unsupported here, never cast to
    /// local or stripped of its local durable commit-component obligations.
    pub fn new(
        runtime: OperatorRuntime,
        profile: ArchiveBackendProfileV1,
    ) -> Result<Self, RecoveryRuntimeError> {
        runtime.ensure_current()?;
        if runtime.config().role != OperatorRoleV1::OrganizationAdmin {
            return Err(RecoveryTestError::Operator.into());
        }
        let vector = match &profile {
            ArchiveBackendProfileV1::LocalPath(p) => p.capability_test_vector_id.clone(),
            ArchiveBackendProfileV1::ControlledNetworkPath(_) => {
                return Err(RecoveryTestError::Source.into());
            }
        };
        let backend = LocalPathBackend::open(
            runtime.config().archive_directory.clone(),
            profile,
            &BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields()),
        )?;
        let measured = backend.run_capability_test(&CapabilityTestVectorV1::new(
            &vector,
            b"EINSATZARCHIV-RECOVERY-CAPABILITY-v1",
        )?)?;
        if !measured.exclusive_create_without_overwrite()
            || !measured.byte_conflict_detection()
            || !measured.same_filesystem_atomic_rename()
            || !measured.file_flush()
            || !measured.directory_flush()
            || !measured.exclusive_writer_lock()
        {
            return Err(RecoveryTestError::Source.into());
        }
        runtime.ensure_current()?;
        Ok(Self { runtime, backend })
    }
    pub fn runtime(&self) -> &OperatorRuntime {
        &self.runtime
    }
    pub fn capture_source(
        &mut self,
        request: RecoverySourceCapture<'_>,
    ) -> Result<VerifiedRecoverySource, RecoveryRuntimeError> {
        let _writer = self.backend.acquire_writer_lock()?;
        self.runtime.refresh_for_action()?;
        self.runtime.ensure_current()?;
        BoundArchiveProfilePolicyV1::from_policy(self.runtime.head().policy_fields())
            .require(self.backend.profile_hash()?)?;
        let before = self
            .runtime
            .reauthenticate_for(ReauthPurpose::RecoveryTest)?;
        if !before.proof().is_valid_for(
            ReauthPurpose::RecoveryTest,
            self.runtime.head().preexisting_effective_now(),
        ) {
            return Err(RecoveryTestError::Operator.into());
        }
        let machine = ea_key_provider::measure_native_machine_identity()
            .map_err(|_| RecoveryTestError::Machine)?;
        let source = FsArchiveSource::open(&self.runtime.config().archive_directory)
            .map_err(|_| RecoveryTestError::Source)?;
        let inventory_hash = ea_recovery::recovery_archive_inventory_hash(&source)?;
        let probe = ea_recovery::RecoveryArchiveProbe::verify(
            &source,
            self.runtime.anchor(),
            self.runtime.head().preexisting_effective_now().value(),
        )?;
        let tip = probe.verified_public_chain_head();
        if tip.sequence().get().checked_add(1) != Some(self.runtime.next_sequence().get()) {
            return Err(RecoveryTestError::Source.into());
        }
        let kdf = RecoveryBackupKdf::fresh()?;
        let key = kdf.derive(request.passphrase)?;
        self.runtime.ensure_current()?;
        let snapshot = self
            .runtime
            .database()
            .snapshot_with_backup_key(request.snapshot, &key)?;
        drop(key);
        self.runtime.ensure_current()?;
        let after = FsArchiveSource::open(&self.runtime.config().archive_directory)
            .map_err(|_| RecoveryTestError::Source)?;
        if ea_recovery::recovery_archive_inventory_hash(&after)? != inventory_hash
            || ea_key_provider::measure_native_machine_identity()
                .map_err(|_| RecoveryTestError::Machine)?
                != machine
        {
            return Err(RecoveryTestError::Source.into());
        }
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| RecoveryTestError::Entropy)?;
        let head = self.runtime.head();
        let core = RecoverySourceCore::new(RecoverySourceFields {
            source_id: id,
            organization_id: *self.runtime.anchor().organization_id().as_bytes(),
            chain_id: *self.runtime.anchor().chain_id().as_bytes(),
            anchor_hash: *self.runtime.anchor().trust_anchor_hash().as_bytes(),
            source_machine: *machine.fingerprint().as_bytes(),
            source_installation: *self.runtime.native().installation_id().as_bytes(),
            registry_version: head.registry_version().get(),
            registry_head: *head.registry_head_hash().as_bytes(),
            proposed_sequence: head.proposed_sequence().get(),
            effective_now: head.preexisting_effective_now().value().get(),
            inventory_hash: *request.inventory.exact_hash().as_bytes(),
            archive_inventory_hash: inventory_hash,
            tip_sequence: tip.sequence().get(),
            tip_entry_hash: *tip.entry_hash().as_bytes(),
            snapshot_hash: *snapshot.ciphertext_hash(),
            migrations_hash: *snapshot.migrations_hash(),
            kdf,
            probes: request.probes,
        })?;
        let session = self
            .runtime
            .reauthenticate_for_context(ReauthPurpose::RecoveryTest, core.context_hash())?;
        self.runtime.ensure_current()?;
        let audit = self
            .runtime
            .audit_service()
            .prepare_signed(
                AuditActorProof::OperatorSession(session.proof()),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(
                        ObjectHash::from(core.context_hash()),
                    ))),
                    outcome: LocalAuditOutcomeV1::Accepted,
                },
            )
            .map_err(|_| RecoveryTestError::Audit)?;
        let envelope = ea_recovery::recovery_source_envelope(&core, audit.exact_bytes())?;
        let verified = ea_recovery::verify_recovery_source(
            &envelope,
            &source,
            self.runtime.anchor(),
            request.inventory,
            head.preexisting_effective_now().value(),
        )?;
        self.runtime.ensure_current()?;
        self.runtime.database().transaction::<_,RecoveryRuntimeError>(|tx| {
            SqliteLocalAuditRepository::append_prepared_in(tx,&audit).map_err(|_|RecoveryTestError::Audit)?;
            tx.execute("INSERT INTO recovery_source_scope(source_hash,exact_envelope,capture_audit_event_id) VALUES(?1,?2,?3)",&[StoreValue::Blob(object_hash(&envelope).as_bytes().to_vec()),StoreValue::Blob(envelope.clone()),StoreValue::Blob(audit.id().as_bytes().to_vec())])?;
            Ok(())
        })?;
        self.runtime.ensure_current()?;
        Ok(verified)
    }
}

pub struct RecoverySourceRestore<'a> {
    pub inventory: &'a KeyInventory,
    pub exact_source: &'a [u8],
    pub snapshot: &'a Path,
    pub passphrase: &'a SecretVec,
    pub target: &'a Path,
}
/// Only the native service can obtain an actual restored database handle.
pub struct RestoredRecoverySource {
    database: ea_local_store::EncryptedDatabase,
    scope: VerifiedRecoverySource,
    content_hash: [u8; 32],
}
impl RecoveryTestRuntime {
    pub fn restore_source(
        &mut self,
        request: RecoverySourceRestore<'_>,
    ) -> Result<RestoredRecoverySource, RecoveryRuntimeError> {
        let _writer = self.backend.acquire_writer_lock()?;
        self.runtime.refresh_for_action()?;
        self.runtime.ensure_current()?;
        let source = FsArchiveSource::open(&self.runtime.config().archive_directory)
            .map_err(|_| RecoveryTestError::Source)?;
        let scope = ea_recovery::verify_recovery_source(
            request.exact_source,
            &source,
            self.runtime.anchor(),
            request.inventory,
            self.runtime.head().preexisting_effective_now().value(),
        )?;
        let machine = ea_key_provider::measure_native_machine_identity()
            .map_err(|_| RecoveryTestError::Machine)?;
        if scope.core().fields().source_machine == *machine.fingerprint().as_bytes()
            || scope.core().fields().source_installation
                == *self.runtime.native().installation_id().as_bytes()
        {
            return Err(RecoveryTestError::Machine.into());
        }
        let before = self
            .runtime
            .reauthenticate_for(ReauthPurpose::RecoveryTest)?;
        if !before.proof().is_valid_for(
            ReauthPurpose::RecoveryTest,
            self.runtime.head().preexisting_effective_now(),
        ) {
            return Err(RecoveryTestError::Operator.into());
        }
        let source_hash = scope.envelope_hash();
        let f = scope.core().fields();
        let key = f.kdf.derive(request.passphrase)?;
        let provider = self.runtime.signing_provider();
        let restored = ea_local_store::EncryptedDatabase::restore_with_backup_key(
            request.snapshot,
            f.snapshot_hash,
            f.migrations_hash,
            &key,
            request.target,
            provider.as_ref(),
            &provider.handle(ea_key_provider::SecretPurpose::LocalDatabaseKey),
        )?;
        drop(key);
        let content_hash = restored.recovery_source_content_hash()?;
        self.runtime.ensure_current()?;
        let after_source = FsArchiveSource::open(&self.runtime.config().archive_directory)
            .map_err(|_| RecoveryTestError::Source)?;
        if ea_recovery::recovery_archive_inventory_hash(&after_source)? != f.archive_inventory_hash
            || ea_key_provider::measure_native_machine_identity()
                .map_err(|_| RecoveryTestError::Machine)?
                != machine
        {
            return Err(RecoveryTestError::Source.into());
        }
        let binding = RestoreBinding {
            source_hash: *source_hash.as_bytes(),
            snapshot_hash: f.snapshot_hash,
            migrations_hash: f.migrations_hash,
            machine: *machine.fingerprint().as_bytes(),
            installation: *self.runtime.native().installation_id().as_bytes(),
            content_hash,
            registry_version: self.runtime.head().registry_version().get(),
            registry_head: *self.runtime.head().registry_head_hash().as_bytes(),
            sequence: self.runtime.next_sequence().get(),
        };
        let context = binding.context_hash()?;
        let session = self
            .runtime
            .reauthenticate_for_context(ReauthPurpose::RecoveryTest, context)?;
        self.runtime.ensure_current()?;
        if restored.recovery_source_content_hash()? != content_hash {
            return Err(RecoveryTestError::Source.into());
        }
        let audit = self
            .runtime
            .audit_service()
            .prepare_signed(
                AuditActorProof::OperatorSession(session.proof()),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(
                        ObjectHash::from(context),
                    ))),
                    outcome: LocalAuditOutcomeV1::Accepted,
                },
            )
            .map_err(|_| RecoveryTestError::Audit)?;
        let historical = ea_verify::historical_registry_head(
            self.runtime.inventory(),
            self.runtime.anchor(),
            self.runtime.head().registry_version(),
            self.runtime.head().registry_head_hash(),
            self.runtime.next_sequence(),
            self.runtime.head().preexisting_effective_now().value(),
        )
        .ok_or(RecoveryTestError::Source)?;
        ea_recovery::verify_recovery_audit_context(
            audit.exact_bytes(),
            &historical,
            context,
            self.runtime.head().preexisting_effective_now().value(),
            LocalAuditOutcomeV1::Accepted,
        )?;
        self.runtime.database().transaction::<_, RecoveryRuntimeError>(|tx| {
            SqliteLocalAuditRepository::append_prepared_in(tx, &audit)
                .map_err(|_| RecoveryTestError::Audit)?;
            tx.execute(
                "INSERT INTO recovery_restore_binding(singleton,source_hash,exact_envelope,snapshot_hash,migrations_hash,target_machine,target_installation,restored_content_hash,registry_version,registry_head,proposed_sequence,restore_audit_event_id) VALUES(0,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                &[
                    StoreValue::Blob(binding.source_hash.to_vec()),
                    StoreValue::Blob(scope.exact_envelope().to_vec()),
                    StoreValue::Blob(binding.snapshot_hash.to_vec()),
                    StoreValue::Blob(binding.migrations_hash.to_vec()),
                    StoreValue::Blob(binding.machine.to_vec()),
                    StoreValue::Blob(binding.installation.to_vec()),
                    StoreValue::Blob(binding.content_hash.to_vec()),
                    StoreValue::Integer(i64::try_from(binding.registry_version).map_err(|_| RecoveryTestError::Source)?),
                    StoreValue::Blob(binding.registry_head.to_vec()),
                    StoreValue::Integer(i64::try_from(binding.sequence).map_err(|_| RecoveryTestError::Source)?),
                    StoreValue::Blob(audit.id().as_bytes().to_vec()),
                ],
            )?;
            Ok(())
        })?;
        self.runtime.ensure_current()?;
        Ok(RestoredRecoverySource {
            database: restored,
            scope,
            content_hash,
        })
    }
}

impl RestoredRecoverySource {
    pub fn source_envelope_hash(&self) -> ObjectHash {
        self.scope.envelope_hash()
    }
    pub fn restored_content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }
    /// Re-read the actual complete source store. The database itself is not
    /// exposed as a mutable operational store by this recovery-test handle.
    pub fn verify_unchanged(&self) -> Result<(), RecoveryRuntimeError> {
        if self.database.recovery_source_content_hash()? != self.content_hash {
            return Err(RecoveryTestError::Source.into());
        }
        Ok(())
    }
}

// Kept in the target authorization database, never inserted into or used to
// rewrite the restored source. Every retained value is covered by the signed
// RecoveryTest/Accepted event; Accepted records restoration, not completion.
struct RestoreBinding {
    source_hash: [u8; 32],
    snapshot_hash: [u8; 32],
    migrations_hash: [u8; 32],
    machine: [u8; 32],
    installation: [u8; 32],
    content_hash: [u8; 32],
    registry_version: u64,
    registry_head: [u8; 32],
    sequence: u64,
}
impl RestoreBinding {
    fn context_hash(&self) -> Result<ea_types::Hash32, RecoveryTestError> {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(11)
            .and_then(|e| e.str("EINSATZARCHIV-RECOVERY-RESTORE-v1"))
            .and_then(|e| e.u8(1))
            .and_then(|e| e.bytes(&self.source_hash))
            .and_then(|e| e.bytes(&self.snapshot_hash))
            .and_then(|e| e.bytes(&self.migrations_hash))
            .and_then(|e| e.bytes(&self.machine))
            .and_then(|e| e.bytes(&self.installation))
            .and_then(|e| e.bytes(&self.content_hash))
            .and_then(|e| e.u64(self.registry_version))
            .and_then(|e| e.bytes(&self.registry_head))
            .and_then(|e| e.u64(self.sequence))
            .map_err(|_| RecoveryTestError::Source)?;
        ea_types::Hash32::try_from(object_hash(&e.into_writer()).as_bytes().as_slice())
            .map_err(|_| RecoveryTestError::Source)
    }
}

pub struct RecoveryTestMediumSource {
    pub medium_id_hash: ObjectHash,
    pub source: RecoveryMediumInput,
}
pub enum RecoveryMediumInput {
    Offline(ea_recovery::KeySourceSpec),
    NativeSigningSlot(RecoveryNativeSigningSlot),
}
impl RecoveryTestRuntime {
    pub fn reopen_restored_source(
        &mut self,
        inventory: &KeyInventory,
        path: &Path,
    ) -> Result<RestoredRecoverySource, RecoveryRuntimeError> {
        let _writer = self.backend.acquire_writer_lock()?;
        self.runtime.refresh_for_action()?;
        self.runtime
            .reauthenticate_for(ReauthPurpose::RecoveryTest)?;
        let restored = self.open_bound_sources(inventory, path)?;
        self.runtime
            .reauthenticate_for(ReauthPurpose::RecoveryTest)?;
        restored.verify_unchanged()?;
        Ok(restored)
    }
}

mod execution;
mod guided;
pub use guided::{
    RecoveryMediumObservation, RecoveryMediumRequest, RecoveryMediumStatus, RecoveryTestAbort,
    RecoverySessionObserver, RecoveryTestGuide,
};

mod inputs;
pub use inputs::{parse_recovery_archive_profile, parse_recovery_media_sources};

mod import;
mod native_medium;
pub use native_medium::RecoveryNativeSigningSlot;
