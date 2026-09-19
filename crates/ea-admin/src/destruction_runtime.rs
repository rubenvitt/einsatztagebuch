//! Current native Admin controller plus an explicitly separate local Writer custodian.
mod claims;
mod completion;
mod evidence_writer;
mod execution;
mod failure;
mod pending;
mod retry;
pub use evidence_writer::{NativeEvidenceWriter, NativeEvidenceWriterError};
mod custodian;
mod exchange;
pub use exchange::{NativeDestructionEventBytes, NativeDestructionExchange};
mod reader_delivery;
pub use reader_delivery::NativeReaderDestructionDelivery;
mod import;
pub use import::{
    MAX_NATIVE_DESTRUCTION_IMPORT_OBJECTS, MAX_NATIVE_DESTRUCTION_IMPORT_TOTAL_BYTES,
};
mod guard;
mod observations;
mod prepare;
mod status;
use crate::{VerifiedOperatorSession, operator_runtime::OperatorRuntime};
use ea_archive::{ArchiveBackendProfileV1, BoundArchiveProfilePolicyV1};
use ea_archive_fs::LocalPathBackend;
use ea_crypto::{CoseSigner, object_hash};
use ea_destruction::{
    DestructionError, SqliteDestructionJobs, SqliteDestructionRepository, SqliteManagedCustody,
};
use ea_format::{CertificateKindV1, OperatorRoleV1};
use ea_operator::ReauthPurpose;
use ea_recovery::{KeySourceSpec, ResolvedSigningKey, resolve_signing_key};
use ea_types::{CertificateHash, DestructionId, DeviceId, ObjectHash};
use std::{collections::BTreeSet, sync::Arc};

pub use ea_destruction::{DestructionState, ServerReservationPort};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDestructionError {
    Core(DestructionError),
    Configuration,
    ComponentSource,
    UnsupportedPkcs11,
    Session,
    FilesystemCapabilities,
    /// 4→1 refused: the signed job has no Server duty or no per-call
    /// authenticated server reservation was offered (DRK-319, only Part S).
    RetryNoServerDuty,
    /// 4→1 refused permanently in v0.1: the open duty concerns a Reader
    /// (Ruling G1), including a Reader confirmed only after state4 (G4).
    RetryReaderDuty,
}
impl NativeDestructionError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Core(e) => e.code(),
            Self::Configuration => "EA-DESTRUCTION-NATIVE-CONFIG",
            Self::ComponentSource => "EA-DESTRUCTION-COMPONENT-CONTAINER",
            Self::UnsupportedPkcs11 => "EA-DESTRUCTION-COMPONENT-PKCS11-UNAVAILABLE",
            Self::Session => "EA-DESTRUCTION-NATIVE-SESSION",
            Self::FilesystemCapabilities => "EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS",
            Self::RetryNoServerDuty => "EA-DESTRUCTION-RETRY-NO-SERVER-DUTY",
            Self::RetryReaderDuty => "EA-DESTRUCTION-RETRY-READER-DUTY",
        }
    }
}
impl std::fmt::Display for NativeDestructionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for NativeDestructionError {}
impl From<DestructionError> for NativeDestructionError {
    fn from(e: DestructionError) -> Self {
        Self::Core(e)
    }
}
impl From<ea_local_store::StoreError> for NativeDestructionError {
    fn from(_: ea_local_store::StoreError) -> Self {
        Self::Core(DestructionError::Storage)
    }
}
impl From<ea_crypto::CryptoError> for NativeDestructionError {
    fn from(_: ea_crypto::CryptoError) -> Self {
        Self::Core(DestructionError::Signature)
    }
}
impl From<ea_format::FormatError> for NativeDestructionError {
    fn from(_: ea_format::FormatError) -> Self {
        Self::Core(DestructionError::Format)
    }
}
type Error = NativeDestructionError;

pub struct NativeLocalHolder {
    backend: LocalPathBackend,
    custody_certificate: CertificateHash,
}
impl NativeLocalHolder {
    pub fn open(
        custodian: &OperatorRuntime,
        path: std::path::PathBuf,
        profile: ArchiveBackendProfileV1,
        certificate: CertificateHash,
    ) -> Result<Self, Error> {
        let ArchiveBackendProfileV1::LocalPath(local) = &profile else {
            return Err(Error::Configuration);
        };
        let vector = ea_archive_fs::CapabilityTestVectorV1::new(
            &local.capability_test_vector_id,
            b"EINSATZARCHIV-NATIVE-CAPABILITY-v1",
        )
        .map_err(|_| Error::FilesystemCapabilities)?;
        let backend = LocalPathBackend::open(
            path,
            profile,
            &BoundArchiveProfilePolicyV1::from_policy(custodian.head().policy_fields()),
        )
        .map_err(|_| Error::Configuration)?;
        if !backend
            .run_capability_test(&vector)
            .map_err(|_| Error::FilesystemCapabilities)?
            .all_proven()
        {
            return Err(Error::FilesystemCapabilities);
        }
        Ok(Self {
            backend,
            custody_certificate: certificate,
        })
    }
}
pub enum NativeDestructionDelivery<'a> {
    AuthenticatedServer(&'a mut dyn ServerReservationPort),
    NoRegisteredServer,
}
pub struct NativeDestructionAdministration {
    pub privacy_decision_enabled: bool,
    pub policy_hash: ObjectHash,
    pub known_destruction_ids: Vec<DestructionId>,
}
pub struct NativeDestructionTarget {
    pub entry_hash: ea_types::EntryHash,
    pub chain_sequence: ea_types::ChainSequence,
    /// Exact expected stub observed in the configured primary archive.
    pub stub_object_hash: Option<ObjectHash>,
}
pub struct NativeDestructionStatus {
    pub destruction_id: DestructionId,
    pub authorization_hash: ObjectHash,
    pub state: DestructionState,
    pub scope_code: u64,
    pub legal_reason_code: u64,
    pub targets: Vec<NativeDestructionTarget>,
    pub controller_device_id: DeviceId,
    pub custodian_device_id: DeviceId,
    pub preflight_hash: Option<ObjectHash>,
    /// Normal committed Writer Evidence, never merely a prepared SQL row.
    pub evidence_entry_hash: Option<ea_types::EntryHash>,
    pub preflight_report_json: Option<String>,
    pub replicas: Vec<NativeDestructionReplica>,
    pub approver_certificate_hashes: Vec<CertificateHash>,
    pub privacy_decision_enabled: bool,
    pub policy_hash: ObjectHash,
}
pub struct NativeDestructionReplica {
    pub device_id: DeviceId,
    pub kind: ea_destruction::ManagedReplicaKind,
    pub attestation_hash: Option<ObjectHash>,
    pub result: ea_destruction::EvidenceReplicaStatus,
    pub backup_expiry_at: Option<ea_types::UnixMillis>,
}
/// An additional host refusal boundary. Success never supplies native authority.
pub trait DestructionHostGuard: Send + Sync {
    fn require_open(&self) -> Result<(), NativeDestructionError>;
}
pub struct DestructionRuntime {
    controller: OperatorRuntime,
    custodian: OperatorRuntime,
    holders: Vec<NativeLocalHolder>,
    component: CertificateHash,
    signer: CoseSigner,
    session: Option<VerifiedOperatorSession>,
    host_guard: Option<Arc<dyn DestructionHostGuard>>,
}
impl DestructionRuntime {
    pub fn new(
        controller: OperatorRuntime,
        custodian: OperatorRuntime,
        holders: Vec<NativeLocalHolder>,
        component: CertificateHash,
        source: KeySourceSpec,
    ) -> Result<Self, Error> {
        // Never silently downgrade a selected hardware or plaintext source.
        match &source {
            KeySourceSpec::Pkcs11 { .. } => return Err(Error::UnsupportedPkcs11),
            KeySourceSpec::File(_) => return Err(Error::ComponentSource),
            KeySourceSpec::Container { .. } => {}
        }
        let ResolvedSigningKey::Software(signer) =
            resolve_signing_key(&source).map_err(|_| Error::ComponentSource)?
        else {
            return Err(Error::UnsupportedPkcs11);
        };
        let result = Self {
            controller,
            custodian,
            holders,
            component,
            signer,
            session: None,
            host_guard: None,
        };
        result.validate_current()?;
        Ok(result)
    }
    /// Borrow the already admitted Writer for structural local observation.
    /// No Destruction session, refresh, Evidence facade or Writer service is used.
    pub fn writer_prepared_diagnosis(
        &self,
    ) -> crate::operator_runtime::prepared_diagnosis::WriterPreparedDiagnosis<'_> {
        crate::operator_runtime::prepared_diagnosis::WriterPreparedDiagnosis::new(&self.custodian)
    }

    pub fn set_host_guard(&mut self, guard: Arc<dyn DestructionHostGuard>) {
        self.host_guard = Some(guard);
    }
    fn check_host(&self) -> Result<(), Error> {
        self.host_guard
            .as_ref()
            .map_or(Ok(()), |guard| guard.require_open())
    }
    pub fn lock(&mut self) {
        self.session = None;
    }
    pub fn unlock(&mut self) -> Result<(), Error> {
        self.session = None;
        self.refresh()?;
        let session = self
            .controller
            .reauthenticate_for(ReauthPurpose::Destruction)
            .map_err(|_| Error::Session)?;
        self.check_host()?;
        self.require_same_fresh_action()?;
        self.session = Some(session);
        Ok(())
    }
    fn refresh(&mut self) -> Result<(), Error> {
        self.check_host()?;
        let result = (|| {
            self.controller
                .refresh_for_action()
                .map_err(|_| Error::Session)?;
            self.custodian
                .refresh_for_action()
                .map_err(|_| Error::Session)?;
            self.validate_current()
        })();
        if result.is_err() {
            self.session = None;
        }
        result
    }
    fn require_same_fresh_action(&self) -> Result<(), Error> {
        self.check_host()?;
        self.validate_current()?;
        for runtime in [&self.controller, &self.custodian] {
            let fresh = runtime.reopened_for_action().map_err(|_| Error::Session)?;
            fresh.ensure_current().map_err(|_| Error::Session)?;
            if fresh.head().registry_head_hash() != runtime.head().registry_head_hash()
                || fresh.next_sequence() != runtime.next_sequence()
                || ea_trust::verify_catalog_custody_authority(fresh.trust())
                    .map_err(|_| DestructionError::Registry)?
                    .registry_head_hash()
                    != ea_trust::verify_catalog_custody_authority(runtime.trust())
                        .map_err(|_| DestructionError::Registry)?
                        .registry_head_hash()
                || !fresh
                    .head()
                    .preexisting_effective_now()
                    .has_same_persisted_bounds(runtime.head().preexisting_effective_now())
            {
                return Err(Error::Session);
            }
        }
        self.check_host()
    }
    fn require_session(&self) -> Result<&VerifiedOperatorSession, Error> {
        self.validate_current()?;
        let session = self.session.as_ref().ok_or(Error::Session)?;
        ea_operator::verify_current_session(
            self.controller.head(),
            self.controller.config().device_certificate_hash,
            OperatorRoleV1::OrganizationAdmin,
            session.proof(),
            ReauthPurpose::Destruction,
            self.controller.native().as_ref(),
        )
        .map_err(|_| Error::Session)?;
        self.check_host()?;
        Ok(session)
    }
    fn validate_current(&self) -> Result<(), Error> {
        self.check_host()?;
        self.controller
            .ensure_current()
            .map_err(|_| Error::Session)?;
        self.custodian
            .ensure_current()
            .map_err(|_| Error::Session)?;
        let admin = self.controller.config();
        let writer = self.custodian.config();
        if admin.role != OperatorRoleV1::OrganizationAdmin
            || writer.role != OperatorRoleV1::Writer
            || admin.authority
            || writer.authority
            || self.controller.anchor().trust_anchor_hash()
                != self.custodian.anchor().trust_anchor_hash()
            || self.controller.head().registry_head_hash()
                != self.custodian.head().registry_head_hash()
            || self.controller.next_sequence() != self.custodian.next_sequence()
            || self.custodian.head().current_writer_certificate_hash()
                != Some(writer.device_certificate_hash)
        {
            return Err(Error::Configuration);
        }
        let root =
            std::fs::canonicalize(&writer.archive_directory).map_err(|_| Error::Configuration)?;
        if std::fs::canonicalize(&admin.archive_directory).map_err(|_| Error::Configuration)?
            != root
        {
            return Err(Error::Configuration);
        }
        if std::fs::canonicalize(&admin.database_path).map_err(|_| Error::Configuration)?
            == std::fs::canonicalize(&writer.database_path).map_err(|_| Error::Configuration)?
        {
            return Err(Error::Configuration);
        }
        let head = self.custodian.head();
        let writer_fields = head
            .active_certificate_fields(writer.device_certificate_hash)
            .ok_or(Error::Configuration)?;
        let admin_fields = head
            .active_certificate_fields(admin.device_certificate_hash)
            .ok_or(Error::Configuration)?;
        let component = head
            .active_certificate_fields(self.component)
            .ok_or(Error::Configuration)?;
        let public = self.signer.public_key()?;
        if component.certificate_kind != CertificateKindV1::DeletionAttest
            || component.device_id != writer_fields.device_id
            || !component.capabilities.iter().any(|c| c == "deletionAttest")
            || component.signing_key_thumbprint != Some(public.thumbprint())
            || component.signing_public_cose_key.as_deref()
                != Some(public.to_deterministic_cbor().as_slice())
            || writer_fields.signing_key_thumbprint == Some(public.thumbprint())
            || admin_fields.signing_key_thumbprint == Some(public.thumbprint())
        {
            return Err(Error::Configuration);
        }
        let mut roots = BTreeSet::new();
        for holder in &self.holders {
            let fields = head
                .known_certificate_fields()
                .find(|(hash, _)| *hash == holder.custody_certificate)
                .map(|(_, f)| f)
                .ok_or(Error::Configuration)?;
            if fields.certificate_kind != CertificateKindV1::Writer
                || fields.device_id != writer_fields.device_id
                || !head
                    .policy_fields()
                    .allowed_archive_profile_hashes
                    .contains(
                        &holder
                            .backend
                            .profile_hash()
                            .map_err(|_| Error::Configuration)?,
                    )
                || !roots.insert(
                    std::fs::canonicalize(holder.backend.root())
                        .map_err(|_| Error::Configuration)?,
                )
            {
                return Err(Error::Configuration);
            }
        }
        if !roots.contains(&root) {
            return Err(Error::Configuration);
        }
        self.check_host()
    }
    fn primary(&self) -> Result<&LocalPathBackend, Error> {
        let root = std::fs::canonicalize(&self.custodian.config().archive_directory)
            .map_err(|_| Error::Configuration)?;
        self.holders
            .iter()
            .find(|h| std::fs::canonicalize(h.backend.root()).ok().as_ref() == Some(&root))
            .map(|h| &h.backend)
            .ok_or(Error::Configuration)
    }
    fn repository(&self) -> SqliteDestructionRepository {
        SqliteDestructionRepository::new(self.custodian.database().clone())
    }
    fn jobs(&self) -> SqliteDestructionJobs {
        SqliteDestructionJobs::new(self.custodian.database().clone())
    }
    fn custody(&self) -> SqliteManagedCustody {
        SqliteManagedCustody::new(self.custodian.database().clone())
    }
    fn native<'a>(
        &'a self,
        audit: &'a ea_audit::SignedLocalAuditService,
        repository: &'a SqliteDestructionRepository,
    ) -> ea_destruction::DestructionRequestService<'a> {
        ea_destruction::DestructionRequestService {
            head: self.controller.head(),
            certificate: self.controller.config().device_certificate_hash,
            role: OperatorRoleV1::OrganizationAdmin,
            account: self.controller.native().as_ref(),
            audit,
            repository,
        }
    }
    fn event(
        &self,
        auth: &ea_destruction::VerifiedDestructionAuthorization,
        from: Option<u8>,
        to: u8,
        previous: Option<ObjectHash>,
    ) -> Result<Vec<u8>, Error> {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| Error::Core(DestructionError::Storage))?;
        let payload = ea_format::TrustPayloadV1::destruction_transition(
            ea_format::DestructionTransitionFieldsV1 {
                destruction_id: auth.fields().destruction_id,
                destruction_authorization_object_hash: auth.object_hash(),
                event_id: ea_types::EventId::try_from(id.as_slice())
                    .map_err(|_| Error::Configuration)?,
                previous_event_object_hash: previous,
                from_state: from,
                to_state: to,
                trigger_code: if from == Some(4) && to == 1 {
                    5
                } else {
                    u64::from(to)
                },
                executed_at: self.controller.head().preexisting_effective_now().value(),
            },
        )?;
        let signature = self.signer.sign_destruction_transition_digest(
            self.component,
            payload.exact_digest_input(),
            auth.exact_bytes(),
        )?;
        Ok(
            ea_format::encode_trust(&ea_format::TrustObjectV1::new(payload, vec![signature])?)?
                .as_bytes()
                .to_vec(),
        )
    }
}
fn blob(bytes: &[u8]) -> ea_local_store::StoreValue {
    ea_local_store::StoreValue::Blob(bytes.to_vec())
}
