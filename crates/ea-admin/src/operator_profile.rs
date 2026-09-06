//! Administrative writer for the existing SQLCipher singleton; draft access stays read-only.
use crate::operator::OperatorLifecycleError;
use ea_draft::{OperatorProfile, OperatorProfileRepository};
use ea_format::OperatorBindingFieldsV1;
use ea_local_store::{EncryptedDatabase, StoreTransaction, StoreValue};
use ea_types::{Hash32, ObjectHash, OperatorSubjectId, OrganizationId};
use std::sync::Arc;

pub(crate) fn load(
    database: &Arc<EncryptedDatabase>,
) -> Result<Option<OperatorProfile>, OperatorLifecycleError> {
    OperatorProfileRepository::new(database.clone())
        .load()
        .map_err(|e| match e {
            ea_draft::DraftError::Store(e) => OperatorLifecycleError::Store(e),
            _ => OperatorLifecycleError::ProfileCommitment,
        })
}

pub fn verify_operator_snapshot(
    profile: &OperatorProfile,
    binding: &OperatorBindingFieldsV1,
) -> Result<(), OperatorLifecycleError> {
    if profile.organization_id() != binding.organization_id
        || profile.operator_subject_id() != binding.operator_subject_id
        || commitment(
            profile.organization_id(),
            profile.operator_subject_id(),
            profile.display_name(),
            profile.function_label(),
            profile.profile_commitment_salt(),
        )? != binding.operator_profile_commitment
    {
        return Err(OperatorLifecycleError::ProfileCommitment);
    }
    Ok(())
}

pub(crate) fn commitment(
    org: OrganizationId,
    subject: OperatorSubjectId,
    name: &str,
    function: &str,
    salt: &[u8; 32],
) -> Result<Hash32, OperatorLifecycleError> {
    Ok(ea_crypto::operator_profile_commitment(
        org, subject, name, function, salt,
    ))
}

pub(crate) struct PendingProfile {
    pub organization: OrganizationId,
    pub subject: OperatorSubjectId,
    pub name: String,
    pub function: String,
    pub salt: [u8; 32],
}
impl PendingProfile {
    pub fn commitment(&self) -> Result<Hash32, OperatorLifecycleError> {
        commitment(
            self.organization,
            self.subject,
            &self.name,
            &self.function,
            &self.salt,
        )
    }
    /// Called only after authorized signing and durable Accepted lifecycle audit.
    /// Compare the complete old snapshot so a concurrent administrative writer wins safely.
    pub fn persist_in(
        &self,
        tx: &StoreTransaction<'_>,
        binding: ObjectHash,
        expected: Option<&OperatorProfile>,
    ) -> Result<(), OperatorLifecycleError> {
        let mut params = vec![
            StoreValue::Blob(self.organization.as_bytes().to_vec()),
            StoreValue::Blob(self.subject.as_bytes().to_vec()),
            StoreValue::Text(self.name.clone()),
            StoreValue::Text(self.function.clone()),
            StoreValue::Blob(self.salt.to_vec()),
            StoreValue::Blob(binding.as_bytes().to_vec()),
        ];
        let count = if let Some(old) = expected {
            params.extend([
                StoreValue::Blob(old.organization_id().as_bytes().to_vec()),
                StoreValue::Blob(old.operator_subject_id().as_bytes().to_vec()),
                StoreValue::Text(old.display_name().to_owned()),
                StoreValue::Text(old.function_label().to_owned()),
                StoreValue::Blob(old.profile_commitment_salt().to_vec()),
                StoreValue::Blob(old.operator_binding_object_hash().as_bytes().to_vec()),
            ]);
            tx.execute("UPDATE operator_profile SET organization_id=?1, operator_subject_id=?2, display_name=?3, function_label=?4, profile_commitment_salt=?5, operator_binding_object_hash=?6 WHERE singleton=0 AND organization_id=?7 AND operator_subject_id=?8 AND display_name=?9 AND function_label=?10 AND profile_commitment_salt=?11 AND operator_binding_object_hash=?12",&params)?
        } else {
            tx.execute("INSERT INTO operator_profile SELECT 0,?1,?2,?3,?4,?5,?6 WHERE NOT EXISTS (SELECT 1 FROM operator_profile)",&params)?
        };
        if count != 1 {
            return Err(OperatorLifecycleError::ProfileConflict);
        }
        Ok(())
    }
}

pub(crate) fn verify_in(
    tx: &StoreTransaction<'_>,
    binding_hash: ObjectHash,
    fields: &OperatorBindingFieldsV1,
) -> Result<(), OperatorLifecycleError> {
    let row = tx.query_row("SELECT organization_id,operator_subject_id,display_name,function_label,profile_commitment_salt,operator_binding_object_hash FROM operator_profile WHERE singleton=0", &[])?
        .ok_or(OperatorLifecycleError::ProfileMissing)?;
    let salt: &[u8; 32] = row
        .blob(4)?
        .try_into()
        .map_err(|_| OperatorLifecycleError::ProfileCommitment)?;
    if row.blob(0)? != fields.organization_id.as_bytes()
        || row.blob(1)? != fields.operator_subject_id.as_bytes()
        || row.blob(5)? != binding_hash.as_bytes()
        || ea_crypto::operator_profile_commitment(
            fields.organization_id,
            fields.operator_subject_id,
            row.text(2)?,
            row.text(3)?,
            salt,
        ) != fields.operator_profile_commitment
    {
        return Err(OperatorLifecycleError::ProfileCommitment);
    }
    Ok(())
}
