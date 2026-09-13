//! Local draft routing only. These references never establish trust authority.
use crate::{AutosaveDraftRepository, DraftError};
use ea_types::{DestructionId, Id16, ObjectHash, OrganizationId};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EvidenceDraftSource {
    organization_id: OrganizationId,
    destruction_id: DestructionId,
    authorization_hash: ObjectHash,
    preflight_hash: ObjectHash,
}
impl EvidenceDraftSource {
    pub const fn new(organization_id: OrganizationId, destruction_id: DestructionId, authorization_hash: ObjectHash, preflight_hash: ObjectHash) -> Self {
        Self { organization_id, destruction_id, authorization_hash, preflight_hash }
    }
    pub const fn organization_id(&self) -> OrganizationId { self.organization_id }
    pub const fn destruction_id(&self) -> DestructionId { self.destruction_id }
    pub const fn authorization_hash(&self) -> ObjectHash { self.authorization_hash }
    pub const fn preflight_hash(&self) -> ObjectHash { self.preflight_hash }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EvidenceDraftBinding {
    draft_id: Id16,
    source: EvidenceDraftSource,
}
impl EvidenceDraftBinding {
    pub const fn draft_id(&self) -> Id16 { self.draft_id }
    pub const fn source(&self) -> EvidenceDraftSource { self.source }
    pub const fn destruction_id(&self) -> DestructionId { self.source.destruction_id }
    pub const fn authorization_hash(&self) -> ObjectHash { self.source.authorization_hash }
    pub const fn preflight_hash(&self) -> ObjectHash { self.source.preflight_hash }
}
use crate::DraftRepository;
use ea_crypto::object_hash;
use ea_local_store::{StoreTransaction, StoreValue as V};

fn blob(value: &[u8]) -> V { V::Blob(value.to_vec()) }

pub(crate) fn read_binding(tx: &StoreTransaction<'_>) -> Result<Option<EvidenceDraftBinding>, DraftError> {
    if tx.query_row("SELECT name FROM sqlite_master WHERE type='table' AND name='writer_evidence_draft'", &[])?.is_none() {
        if tx.query_row("SELECT version FROM schema_migration WHERE version=25", &[])?.is_some() {
            return Err(DraftError::EvidenceBinding);
        }
        return Ok(None);
    }
    let Some(row) = tx.query_row("SELECT e.draft_id,e.organization_id,e.destruction_id,e.authorization_hash,e.preflight_hash,d.draft_id FROM writer_evidence_draft e LEFT JOIN draft d USING(singleton) WHERE e.singleton=0", &[])? else { return Ok(None); };
    if row.blob(0)? != row.blob(5)? { return Err(DraftError::EvidenceBinding); }
    let source = EvidenceDraftSource::new(
        OrganizationId::try_from(row.blob(1)?).map_err(|_|DraftError::EvidenceBinding)?,
        DestructionId::try_from(row.blob(2)?).map_err(|_|DraftError::EvidenceBinding)?,
        ObjectHash::try_from(row.blob(3)?).map_err(|_|DraftError::EvidenceBinding)?,
        ObjectHash::try_from(row.blob(4)?).map_err(|_|DraftError::EvidenceBinding)?,
    );
    require_job(tx, source)?;
    Ok(Some(EvidenceDraftBinding {
        draft_id: Id16::try_from(row.blob(0)?).map_err(|_|DraftError::EvidenceBinding)?,
        source,
    }))
}
fn require_job(tx: &StoreTransaction<'_>, source: EvidenceDraftSource) -> Result<(), DraftError> {
    let row = tx.query_row("SELECT authorization_hash,exact_core FROM destruction_job WHERE organization_id=?1 AND destruction_id=?2",
        &[blob(source.organization_id.as_bytes()),blob(source.destruction_id.as_bytes())])?.ok_or(DraftError::EvidenceBinding)?;
    if row.blob(0)? != source.authorization_hash.as_bytes() || object_hash(row.blob(1)?) != source.preflight_hash { return Err(DraftError::EvidenceBinding); }
    Ok(())
}
impl AutosaveDraftRepository {
    /// Persist local routing only after authenticated evidence admission.
    /// Presence/cryptographic proof remain mandatory at the Writer service.
    pub fn reserve_evidence_draft(&self, source: EvidenceDraftSource) -> Result<EvidenceDraftBinding, DraftError> {
        let _lock = self.acquire_draft_lock()?;
        if let Some(existing) = self.evidence_binding()? {
            return if existing.source == source { Ok(existing) } else { Err(DraftError::EvidenceBinding) };
        }
        if self.pending_discard()?.is_some() || self.prepared_finalization_marker()?.is_some() {
            return Err(DraftError::EvidenceOccupied);
        }
        let draft = self.load_or_create()?;
        if !draft.notes().is_empty() { return Err(DraftError::EvidenceOccupied); }
        self.database.transaction(|tx| {
            self.require_evidence_access(tx)?;
            require_job(tx, source)?;
            let row = tx.query_row("SELECT draft_id,save_revision FROM draft WHERE singleton=0", &[])?.ok_or(DraftError::NoDraft)?;
            if row.blob(0)? != draft.draft_id().as_bytes() || row.integer(1)? != i64::try_from(draft.revision()).map_err(|_|DraftError::RevisionConflict)? {
                return Err(DraftError::RevisionConflict);
            }
            if tx.query_row("SELECT kind FROM draft_transition WHERE singleton=0",&[])?.is_some() { return Err(DraftError::EvidenceOccupied); }
            tx.execute("INSERT INTO writer_evidence_draft(singleton,draft_id,organization_id,destruction_id,authorization_hash,preflight_hash) VALUES(0,?1,?2,?3,?4,?5)",
                &[blob(draft.draft_id().as_bytes()),blob(source.organization_id.as_bytes()),blob(source.destruction_id.as_bytes()),blob(source.authorization_hash.as_bytes()),blob(source.preflight_hash.as_bytes())])?;
            read_binding(tx)?.ok_or(DraftError::EvidenceBinding)
        })
    }
    /// Public pseudonymous routing; this is not a trust or presence proof.
    pub fn evidence_binding(&self) -> Result<Option<EvidenceDraftBinding>, DraftError> {
        self.database.transaction(read_binding)
    }
    pub fn for_evidence_draft(&self, binding: EvidenceDraftBinding) -> Result<Self, DraftError> {
        if self.evidence_binding()? != Some(binding) { return Err(DraftError::EvidenceBinding); }
        Ok(Self { database: self.database.clone(), provider: self.provider.clone(), evidence: Some(binding) })
    }
    pub(crate) fn require_evidence_access(&self, tx: &StoreTransaction<'_>) -> Result<(), DraftError> {
        require_evidence_access_in(tx, self.evidence)
    }

    pub(crate) fn check_evidence_access(&self) -> Result<(), DraftError> {
        self.database.transaction(|tx|self.require_evidence_access(tx))
    }
}

pub(crate) fn require_evidence_access_in(
    tx: &StoreTransaction<'_>,
    expected: Option<EvidenceDraftBinding>,
) -> Result<(), DraftError> {
    match (expected, read_binding(tx)?) {
        (None, None) => Ok(()),
        (Some(expected), Some(actual)) if expected == actual => Ok(()),
        (None, Some(_)) => Err(DraftError::EvidenceReserved),
        _ => Err(DraftError::EvidenceBinding),
    }
}
