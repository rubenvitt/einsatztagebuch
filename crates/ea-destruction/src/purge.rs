//! Exact authorized acquisition-source cleanup. The retained token is not anonymity.
use crate::{
    DestructionError as Error, DestructionExecutionContext, DestructionRequestService,
    DurableDestructionStart, LocalDestructionExecution, SqliteDestructionJobs,
};
use ea_archive::ArchiveBackend;
use ea_draft::IncidentNumberRegister;
use ea_local_store::{StoreTransaction, StoreValue};
use ea_operator::OperatorSessionProof;
use ea_types::{EntryHash, ObjectHash, OrganizationId};
use minicbor::Encoder;
pub struct MeasuredAcquisitionRemoval {
    exact: Vec<u8>,
}
impl MeasuredAcquisitionRemoval {
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquisitionPurgeCheckpoint {
    TokenRetained,
    PermitsInserted,
    SourceDeleted,
    PermitsRemoved,
    Committed,
    Compacted,
}
impl SqliteDestructionJobs {
    pub fn purge_local_acquisition(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        start: &DurableDestructionStart,
        native: &DestructionRequestService<'_>,
        proof: &OperatorSessionProof,
        local: &LocalDestructionExecution<'_>,
    ) -> Result<MeasuredAcquisitionRemoval, Error> {
        self.purge_local_acquisition_with_progress(
            context,
            start,
            native,
            proof,
            local,
            &mut |_| Ok(()),
        )
    }
    /// Cancellation/observability only; callbacks cannot authorize a row and
    /// must not reenter the same SQLCipher connection.
    pub fn purge_local_acquisition_with_progress(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        start: &DurableDestructionStart,
        native: &DestructionRequestService<'_>,
        proof: &OperatorSessionProof,
        local: &LocalDestructionExecution<'_>,
        progress: &mut dyn FnMut(AcquisitionPurgeCheckpoint) -> Result<(), Error>,
    ) -> Result<MeasuredAcquisitionRemoval, Error> {
        self.purge_local_acquisition_guarded(
            context,
            start,
            native,
            proof,
            local,
            progress,
            &mut crate::local::NoAdditionalAuthorityGuard,
        )
    }
    // Preserve the existing typed action arguments; the additional guard only refuses.
    #[allow(clippy::too_many_arguments)]
    pub fn purge_local_acquisition_guarded(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        start: &DurableDestructionStart,
        native: &DestructionRequestService<'_>,
        proof: &OperatorSessionProof,
        local: &LocalDestructionExecution<'_>,
        progress: &mut dyn FnMut(AcquisitionPurgeCheckpoint) -> Result<(), Error>,
        guard: &mut dyn crate::LocalActionAuthorityGuard,
    ) -> Result<MeasuredAcquisitionRemoval, Error> {
        let measured = self.execute_local_guarded(
            context,
            start,
            native,
            proof,
            local,
            &mut |_| Ok(()),
            guard,
        )?;
        let resumed = native.resume_original(
            context.resumed.request().authorization(),
            context.resumed.authorization_head(),
            proof,
        )?;
        crate::preflight::check_authority(&resumed, context.custody, local.component_certificate)?;
        let _writer = local
            .backend
            .acquire_writer_lock()
            .map_err(|_| Error::Storage)?;
        let auth = resumed.request().authorization();
        let exact = encode(
            start.job_hash(),
            measured.location_id(),
            context
                .job
                .preflight()
                .targets
                .iter()
                .map(|target| target.entry),
        )?;
        self.database.query_row("PRAGMA secure_delete=ON", &[])?;
        self.database.transaction(|tx| {
            crate::inventory::require_durable(tx)?;
            crate::inventory::require_unchanged_in(tx,context.custody)?;
            if tx.query_row("PRAGMA secure_delete",&[])?.ok_or(Error::Storage)?.integer(0)?!=1 {return Err(Error::Storage);}
            guard.check_in(tx)?;
            require_no_permits(tx)?;
            if let Some(row)=tx.query_row("SELECT exact_measurement FROM destruction_acquisition_purge WHERE job_hash=?1",&[blob(start.job_hash().as_bytes())])?
                && row.blob(0)?!=exact {
                return Err(Error::SecurityConflict);
            }
            for target in &context.job.preflight().targets {
                let sequence=auth.fields().targets.iter().find(|value|value.entry_hash()==target.entry.as_bytes()).ok_or(Error::Target)?.chain_sequence();
                guard.check_in(tx)?;
                purge_target(tx,target.entry,target.original,sequence,auth.fields().organization_id,progress)?;
            }
            require_no_permits(tx)?;
            tx.execute("INSERT INTO destruction_acquisition_purge(job_hash,organization_id,destruction_id,exact_measurement) VALUES(?1,?2,?3,?4) ON CONFLICT(job_hash) DO NOTHING",&[blob(start.job_hash().as_bytes()),blob(auth.fields().organization_id.as_bytes()),blob(auth.fields().destruction_id.as_bytes()),blob(&exact)])?;
            Ok::<_,Error>(())
        })?;
        progress(AcquisitionPurgeCheckpoint::Committed)?;
        // A committed purge with failed maintenance is incomplete. Retrying
        // repeats the observed checkpoint/vacuum and never invents old source.
        self.database.compact_after_authorized_destruction()?;
        progress(AcquisitionPurgeCheckpoint::Compacted)?;
        let row = self
            .database
            .query_row(
                "SELECT exact_measurement FROM destruction_acquisition_purge WHERE job_hash=?1",
                &[blob(start.job_hash().as_bytes())],
            )?
            .ok_or(Error::Storage)?;
        if row.blob(0)? != exact {
            return Err(Error::SecurityConflict);
        }
        self.database.transaction(|tx| {
            require_no_permits(tx)?;
            for target in &context.job.preflight().targets {
                if tx
                    .query_row(
                        "SELECT 1 FROM writer_original_identity WHERE entry_hash=?1",
                        &[blob(target.entry.as_bytes())],
                    )?
                    .is_some()
                {
                    return Err(Error::Storage);
                }
            }
            Ok::<_, Error>(())
        })?;
        Ok(MeasuredAcquisitionRemoval { exact })
    }
}

fn purge_target(
    tx: &StoreTransaction<'_>,
    entry: EntryHash,
    original: ObjectHash,
    sequence: u64,
    organization: OrganizationId,
    progress: &mut dyn FnMut(AcquisitionPurgeCheckpoint) -> Result<(), Error>,
) -> Result<(), Error> {
    let key = [blob(entry.as_bytes())];
    let Some(row)=tx.query_row("SELECT object_hash,sequence,organization_id,civil_year FROM writer_original_identity WHERE entry_hash=?1",&key)? else {return Ok(());};
    if row.blob(0)? != original.as_bytes()
        || u64::try_from(row.integer(1)?).ok() != Some(sequence)
        || row.blob(2)? != organization.as_bytes()
    {
        return Err(Error::SecurityConflict);
    }
    let year = i32::try_from(row.integer(3)?).map_err(|_| Error::Storage)?;
    // No ordinary String/Vec copy of the acquired incident number escapes.
    let number=tx.query_row("SELECT CAST(incident_number AS BLOB) FROM writer_original_identity WHERE entry_hash=?1",&key)?.ok_or(Error::Storage)?.into_secret_blob()?;
    number.with_exposed(|bytes|->Result<(),Error> {
        let number=std::str::from_utf8(bytes).map_err(|_|Error::Storage)?;
        IncidentNumberRegister::retain_for_destruction_in(tx,organization,year,number).map_err(|_|Error::Storage)?;
        progress(AcquisitionPurgeCheckpoint::TokenRetained)?;
        tx.execute("INSERT INTO destruction_identity_purge_permit SELECT * FROM writer_original_identity WHERE entry_hash=?1",&key)?;
        let mut after=0i64;
        while let Some(row)=tx.query_row("SELECT claim_id FROM writer_incident_claim WHERE organization_id=?1 AND civil_year=?2 AND claim_id>?3 ORDER BY claim_id LIMIT 1",&[blob(organization.as_bytes()),StoreValue::Integer(i64::from(year)),StoreValue::Integer(after)])? {
            after=row.integer(0)?;
            let claim_number=tx.query_row("SELECT CAST(incident_number AS BLOB) FROM writer_incident_claim WHERE claim_id=?1",&[StoreValue::Integer(after)])?.ok_or(Error::Storage)?.into_secret_blob()?;
            let same=claim_number.with_exposed(|bytes| std::str::from_utf8(bytes).map(|value|IncidentNumberRegister::same_number(value,number)).map_err(|_|Error::Storage))?;
            if same {tx.execute("INSERT INTO destruction_claim_purge_permit SELECT * FROM writer_incident_claim WHERE claim_id=?1",&[StoreValue::Integer(after)])?;}
        }
        progress(AcquisitionPurgeCheckpoint::PermitsInserted)?;
        tx.execute("DELETE FROM writer_incident_claim_released WHERE claim_id IN (SELECT claim_id FROM destruction_claim_purge_permit)",&[])?;
        tx.execute("DELETE FROM writer_incident_claim WHERE claim_id IN (SELECT claim_id FROM destruction_claim_purge_permit)",&[])?;
        tx.execute("DELETE FROM writer_original_published WHERE entry_hash=?1",&key)?;
        IncidentNumberRegister::release_in(tx,organization,year,number).map_err(|_|Error::Storage)?;
        tx.execute("DELETE FROM writer_original_identity WHERE entry_hash=?1",&key)?;
        progress(AcquisitionPurgeCheckpoint::SourceDeleted)?;
        tx.execute("DELETE FROM destruction_claim_purge_permit",&[])?;
        tx.execute("DELETE FROM destruction_identity_purge_permit",&[])?;
        progress(AcquisitionPurgeCheckpoint::PermitsRemoved)?;
        Ok(())
    })
}
fn require_no_permits(tx: &StoreTransaction<'_>) -> Result<(), Error> {
    if tx.query_row("SELECT (SELECT count(*) FROM destruction_identity_purge_permit)+(SELECT count(*) FROM destruction_claim_purge_permit)",&[])?.ok_or(Error::Storage)?.integer(0)?!=0 {return Err(Error::SecurityConflict);}
    Ok(())
}
fn encode(
    job: ObjectHash,
    location: ObjectHash,
    entries: impl ExactSizeIterator<Item = EntryHash>,
) -> Result<Vec<u8>, Error> {
    let mut exact = Vec::new();
    let mut e = Encoder::new(&mut exact);
    e.array(4)
        .map_err(|_| Error::Format)?
        .str("EINSATZARCHIV-ACQUISITION-PURGE-v1")
        .map_err(|_| Error::Format)?
        .bytes(job.as_bytes())
        .map_err(|_| Error::Format)?
        .bytes(location.as_bytes())
        .map_err(|_| Error::Format)?
        .array(entries.len() as u64)
        .map_err(|_| Error::Format)?;
    for entry in entries {
        e.bytes(entry.as_bytes()).map_err(|_| Error::Format)?;
    }
    Ok(exact)
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
