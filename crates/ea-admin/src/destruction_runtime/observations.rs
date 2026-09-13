//! Actual primary-archive observations bound to the verified immutable job.
use super::status::SavedDestruction;
use super::*;
use ea_archive::{ArchiveBackend, ArchiveInventory};
use ea_types::EntryHash;
use std::collections::BTreeMap;
impl DestructionRuntime {
    pub(super) fn observe_artifacts(
        &self,
        saved: &SavedDestruction,
    ) -> Result<(BTreeMap<EntryHash, ObjectHash>, Option<EntryHash>), Error> {
        let Some(job) = &saved.job else {
            return Ok((BTreeMap::new(), None));
        };
        let device = self
            .custodian
            .head()
            .active_certificate_fields(self.custodian.config().device_certificate_hash)
            .ok_or(Error::Configuration)?
            .device_id;
        if saved.attestations.iter().any(|claim| {
            claim.fields().replica_id == *device.as_bytes() && claim.fields().result == 0
        }) {
            // A signed old claim cannot hide presently reintroduced local bytes.
            let projection = ea_destruction::project_imported_evidence(job, &saved.attestations)?;
            for holder in &self.holders {
                let _lock = holder
                    .backend
                    .acquire_writer_lock()
                    .map_err(|_| DestructionError::Storage)?;
                projection.validate_archive(&holder.backend.as_archive_source())?;
                projection.validate_managed_archive(&holder.backend)?;
            }
        }
        let backend = self.primary()?;
        let _lock = backend
            .acquire_writer_lock()
            .map_err(|_| DestructionError::Storage)?;
        let source = backend.as_archive_source();
        let inventory = ArchiveInventory::build(&source).map_err(|_| DestructionError::Storage)?;
        let stubs = present_target_stubs(job, &inventory)?;
        let mut latest = None;
        for row in self.rows("SELECT entry_hash,entry_object_hash,exact_binding,binding_hash FROM writer_destruction_evidence ORDER BY entry_hash",&[])?{
            let mut d=minicbor::Decoder::new(row.blob(2)?);
            if d.array().map_err(|_|DestructionError::Format)?!=Some(8)
                || d.str().map_err(|_|DestructionError::Format)?!="EINSATZARCHIV-WRITER-DESTRUCTION-BINDING-v1"
            {return Err(DestructionError::Format.into())}
            d.skip().map_err(|_|DestructionError::Format)?;
            d.skip().map_err(|_|DestructionError::Format)?;
            if d.bytes().map_err(|_|DestructionError::Format)?!=saved.auth.fields().destruction_id.as_bytes(){continue}
            if d.bytes().map_err(|_|DestructionError::Format)?!=saved.auth.object_hash().as_bytes()
                || d.bytes().map_err(|_|DestructionError::Format)?!=job.job_hash().as_bytes()
                || object_hash(row.blob(2)?).as_bytes()!=row.blob(3)?
            {return Err(DestructionError::SecurityConflict.into())}
            let entry_hash=EntryHash::try_from(row.blob(0)?).map_err(|_|DestructionError::Format)?;
            let Some(entry)=inventory.entries().iter().find(|entry|entry.value().entry_hash()==entry_hash) else {continue};
            if entry.object_hash().as_bytes()!=row.blob(1)?{return Err(DestructionError::SecurityConflict.into())}
            let report=ea_verify::verify_archive(&source,self.controller.anchor(),ea_verify::VerifyOptions::new(self.controller.head().preexisting_effective_now().value())).map_err(|_|DestructionError::Target)?;
            let public=report.verified_public_chain_head().ok_or(DestructionError::Target)?;
            if public.sequence()<entry.value().manifest().fields().chain_sequence{return Err(DestructionError::Target.into())}
            // Prepared rows alone never become observations. This rechecks the
            // existing exact job/custody/source fence for committed bytes.
            self.jobs().validate_prepared_evidence(entry.exact_bytes().as_bytes(),&source,backend)?;
            let sequence=entry.value().manifest().fields().chain_sequence;
            if latest.is_none_or(|(old,_)|sequence>old){latest=Some((sequence,entry_hash))}
        }
        Ok((stubs, latest.map(|(_, entry)| entry)))
    }
}

// Pure archive observations only: caller owns every holder lock and the Writer
// transaction. This helper never reenters Writer/Native/evidence admission.
pub(super) fn validate_failure_holder(
    job: &ea_destruction::VerifiedImportedPreflight,
    projection: &ea_destruction::VerifiedDestructionEvidence,
    has_local_success: bool,
    holder: &NativeLocalHolder,
) -> Result<(), Error> {
    let source = holder.backend.as_archive_source();
    let inventory = ArchiveInventory::build(&source).map_err(|_| DestructionError::Storage)?;
    present_target_stubs(job, &inventory)?;
    if has_local_success {
        projection.validate_archive(&source)?;
        projection.validate_managed_archive(&holder.backend)?;
    }
    Ok(())
}
fn present_target_stubs(
    job: &ea_destruction::VerifiedImportedPreflight,
    inventory: &ArchiveInventory,
) -> Result<BTreeMap<EntryHash, ObjectHash>, Error> {
    if !inventory.format_errors().is_empty() {
        return Err(DestructionError::Format.into());
    }
    let mut stubs = BTreeMap::new();
    for target in job.targets() {
        for parsed in inventory
            .destroyed()
            .iter()
            .filter(|parsed| parsed.value().entry_hash() == target.entry_hash())
        {
            if parsed.exact_bytes().as_bytes() != target.exact_stub_bytes() {
                return Err(DestructionError::SecurityConflict.into());
            }
            stubs.insert(target.entry_hash(), parsed.object_hash());
        }
    }
    Ok(stubs)
}
