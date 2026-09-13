//! A borrowed local observation, never a repair or Writer authority.
use super::*;
use ea_archive::{ArchiveBackendProfileV1, BoundArchiveProfilePolicyV1};
use ea_draft::DraftError;

pub enum PreparedDiagnosisError {
    Runtime(OperatorRuntimeError),
    Draft(DraftError),
}
impl PreparedDiagnosisError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Runtime(e) => e.code(),
            Self::Draft(e) => e.code(),
        }
    }
}
impl fmt::Debug for PreparedDiagnosisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl From<OperatorRuntimeError> for PreparedDiagnosisError {
    fn from(e: OperatorRuntimeError) -> Self {
        Self::Runtime(e)
    }
}
impl From<StoreError> for PreparedDiagnosisError {
    fn from(e: StoreError) -> Self {
        Self::Runtime(e.into())
    }
}
impl From<DraftError> for PreparedDiagnosisError {
    fn from(e: DraftError) -> Self {
        Self::Draft(e)
    }
}
impl From<OperatorLifecycleError> for PreparedDiagnosisError {
    fn from(e: OperatorLifecycleError) -> Self {
        Self::Runtime(e.into())
    }
}

/// Holds the actual already admitted Writer, without exposing its DB or keys.
/// The caller must separately enforce the host's CurrentAdmin session/epoch.
pub struct WriterPreparedDiagnosis<'a> {
    writer: &'a OperatorRuntime,
}
impl<'a> WriterPreparedDiagnosis<'a> {
    pub(crate) fn new(writer: &'a OperatorRuntime) -> Self {
        Self { writer }
    }

    /// Profile, routing, migration and marker share one local SQLite snapshot.
    /// BEGIN IMMEDIATE reserves SQLite writes; it is not an archive-file lock.
    pub fn diagnose(
        &self,
        admin: &OperatorRuntime,
        profile: &ArchiveBackendProfileV1,
    ) -> Result<Option<ea_writer::PreparedMarkerDiagnosisV1>, PreparedDiagnosisError> {
        self.diagnose_impl(admin, profile, || {})
    }

    /// Per-call barrier for actual SQLite/host-race witnesses only.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn diagnose_with_test_after_profile(
        &self,
        admin: &OperatorRuntime,
        profile: &ArchiveBackendProfileV1,
        after_profile: impl FnOnce(),
    ) -> Result<Option<ea_writer::PreparedMarkerDiagnosisV1>, PreparedDiagnosisError> {
        self.diagnose_impl(admin, profile, after_profile)
    }

    fn diagnose_impl(
        &self,
        admin: &OperatorRuntime,
        profile: &ArchiveBackendProfileV1,
        after_profile: impl FnOnce(),
    ) -> Result<Option<ea_writer::PreparedMarkerDiagnosisV1>, PreparedDiagnosisError> {
        self.require_context(admin, profile)?;
        let writer = self.writer;
        let fields = writer.verify_bound_operator_identity(writer.config.binding_object_hash)?;
        let marker = writer
            .database
            .transaction(|tx| -> Result<_, PreparedDiagnosisError> {
                crate::operator_profile::verify_in(tx, writer.config.binding_object_hash, fields)?;
                after_profile();
                Ok(ea_draft::read_unscoped_prepared_finalization_marker_in(tx)?)
            })?;
        let diagnosis = marker.map(|m| ea_writer::diagnose_prepared_marker(m.as_bytes()));
        self.require_context(admin, profile)?;
        Ok(diagnosis)
    }

    fn require_context(
        &self,
        admin: &OperatorRuntime,
        profile: &ArchiveBackendProfileV1,
    ) -> Result<(), OperatorRuntimeError> {
        let writer = self.writer;
        if admin.config.role != OperatorRoleV1::OrganizationAdmin
            || admin.config.authority
            || writer.config.role != OperatorRoleV1::Writer
            || writer.config.authority
            || admin.anchor().trust_anchor_hash() != writer.anchor().trust_anchor_hash()
            || admin.head.registry_head_hash() != writer.head.registry_head_hash()
            || admin.head.registry_version() != writer.head.registry_version()
            || admin.next_sequence() != writer.next_sequence()
            || writer.head.current_writer_certificate_hash()
                != Some(writer.config.device_certificate_hash)
            || !matches!(profile, ArchiveBackendProfileV1::LocalPath(_))
        {
            return Err(OperatorRuntimeError::Config);
        }
        for runtime in [admin, writer] {
            runtime.native.ensure_session_active()?;
            // Exactly the existing verifier, but never persist a clock observation.
            runtime.posture_admission_for_report()?;
            runtime.ensure_fresh_context()?;
        }
        if std::fs::canonicalize(&admin.config.archive_directory)
            .map_err(|_| OperatorRuntimeError::Io)?
            != std::fs::canonicalize(&writer.config.archive_directory)
                .map_err(|_| OperatorRuntimeError::Io)?
            || std::fs::canonicalize(&admin.config.database_path)
                .map_err(|_| OperatorRuntimeError::Io)?
                == std::fs::canonicalize(&writer.config.database_path)
                    .map_err(|_| OperatorRuntimeError::Io)?
        {
            return Err(OperatorRuntimeError::Config);
        }
        BoundArchiveProfilePolicyV1::from_policy(admin.head.policy_fields())
            .require(
                profile
                    .profile_hash()
                    .map_err(|_| OperatorRuntimeError::Config)?,
            )
            .map_err(|_| OperatorRuntimeError::Config)?;
        let public = writer
            .native
            .public_key(role_slot(OperatorRoleV1::Writer)?)?
            .ok_or(OperatorRuntimeError::SignerMismatch)?;
        verify_local_signing_identity(
            &writer.head,
            writer.config.device_certificate_hash,
            OperatorRoleV1::Writer,
            &public,
        )?;
        writer.verify_bound_operator_identity(writer.config.binding_object_hash)?;
        writer.native.ensure_session_active()?;
        writer.ensure_fresh_context()?;
        Ok(())
    }
}
