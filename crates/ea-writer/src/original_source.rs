//! Retained encrypted acquisition source, like the incident-number register.
//! This is backed up with that register; it is not reconstructible from public
//! archive metadata and never substitutes for signed archive verification.

use ea_draft::IncidentNumberRegister;
use ea_local_store::StoreValue;
use ea_types::{ChainSequence, OrganizationId, RecordId};

use crate::{
    WriterError, WriterService, finalize::ClaimedIncidentNumber, marker::PreparedTransactionV1,
};

pub(crate) struct OriginalIncidentIdentity {
    pub(crate) record_id: RecordId,
    pub(crate) organization_id: OrganizationId,
    pub(crate) year: i32,
    pub(crate) number: String,
    pub(crate) sequence: ChainSequence,
}

impl WriterService<'_> {
    fn ensure_original_source(&self) -> Result<(), WriterError> {
        self.incident_numbers.database_handle().transaction(|tx| {
            tx.execute("CREATE TABLE IF NOT EXISTS writer_incident_claim (claim_id INTEGER PRIMARY KEY AUTOINCREMENT, draft_id BLOB NOT NULL, draft_revision INTEGER NOT NULL, organization_id BLOB NOT NULL, civil_year INTEGER NOT NULL, incident_number TEXT NOT NULL)", &[])?;
            tx.execute("CREATE TABLE IF NOT EXISTS writer_incident_claim_released (claim_id INTEGER PRIMARY KEY REFERENCES writer_incident_claim(claim_id))", &[])?;
            tx.execute("CREATE TABLE IF NOT EXISTS writer_original_identity (entry_hash BLOB PRIMARY KEY NOT NULL, object_hash BLOB NOT NULL, record_id BLOB NOT NULL, sequence INTEGER NOT NULL, organization_id BLOB NOT NULL, civil_year INTEGER NOT NULL, incident_number TEXT NOT NULL)", &[])?;
            tx.execute("CREATE TABLE IF NOT EXISTS writer_original_published (entry_hash BLOB PRIMARY KEY NOT NULL REFERENCES writer_original_identity(entry_hash))", &[])?;
            for table in ["writer_incident_claim", "writer_incident_claim_released", "writer_original_identity", "writer_original_published"] {
                for operation in ["UPDATE", "DELETE"] {
                    tx.execute(&format!("CREATE TRIGGER IF NOT EXISTS {table}_no_{operation} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, 'append-only'); END"), &[])?;
                }
            }
            Ok::<_, WriterError>(())
        })
    }

    pub(crate) fn claim_original_number(
        &self,
        claim: &ClaimedIncidentNumber,
    ) -> Result<i64, WriterError> {
        self.ensure_original_source()?;
        let draft = self.repository.load_or_create()?;
        self.incident_numbers.database_handle().transaction(|tx| {
            let row = tx.query_row("SELECT draft_id,save_revision FROM draft WHERE singleton=0", &[])?.ok_or(WriterError::PreparedFinalizationInconsistent)?;
            if row.blob(0)? != draft.draft_id().as_bytes() || u64::try_from(row.integer(1)?).ok() != Some(draft.revision()) { return Err(WriterError::PreparedFinalizationInconsistent); }
            IncidentNumberRegister::claim_in(tx, claim.organization_id, claim.local_civil_year, &claim.human_incident_number)
                .map_err(|error| match error { ea_draft::DraftError::IncidentNumberTaken => WriterError::IncidentNumberTaken, other => WriterError::Draft(other) })?;
            tx.execute("INSERT INTO writer_incident_claim(draft_id,draft_revision,organization_id,civil_year,incident_number) VALUES(?1,?2,?3,?4,?5)", &[
                StoreValue::Blob(draft.draft_id().as_bytes().to_vec()), StoreValue::Integer(i64::try_from(draft.revision()).map_err(|_| WriterError::PreparedFinalizationInconsistent)?),
                StoreValue::Blob(claim.organization_id.as_bytes().to_vec()), StoreValue::Integer(i64::from(claim.local_civil_year)), StoreValue::Text(claim.human_incident_number.clone()),
            ])?;
            Ok(tx.query_row("SELECT last_insert_rowid()", &[])?.ok_or(WriterError::PreparedFinalizationInconsistent)?.integer(0)?)
        })
    }

    pub(crate) fn release_original_claim(&self, claim_id: i64) -> Result<(), WriterError> {
        self.incident_numbers.database_handle().transaction(|tx| {
            let Some(row) = tx.query_row("SELECT organization_id,civil_year,incident_number FROM writer_incident_claim c WHERE claim_id=?1 AND NOT EXISTS(SELECT 1 FROM writer_incident_claim_released r WHERE r.claim_id=c.claim_id)", &[StoreValue::Integer(claim_id)])? else { return Ok(()); };
            IncidentNumberRegister::release_in(tx, OrganizationId::try_from(row.blob(0)?).map_err(|_| WriterError::PreparedFinalizationInconsistent)?, i32::try_from(row.integer(1)?).map_err(|_| WriterError::PreparedFinalizationInconsistent)?, row.text(2)?)?;
            tx.execute("INSERT INTO writer_incident_claim_released(claim_id) VALUES(?1)", &[StoreValue::Integer(claim_id)])?;
            Ok(())
        })
    }

    pub(crate) fn recover_original_claims(&self) -> Result<(), WriterError> {
        let db = self.incident_numbers.database_handle();
        if db
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='writer_incident_claim'",
                &[],
            )?
            .is_none()
        {
            return Ok(());
        }
        // Query the current source identity first; committed claims of replaced
        // drafts require neither decryption nor a release on every startup.
        if db.query_row("SELECT 1 FROM writer_incident_claim c JOIN draft d ON d.draft_id=c.draft_id AND d.save_revision>=c.draft_revision WHERE NOT EXISTS(SELECT 1 FROM writer_incident_claim_released r WHERE r.claim_id=c.claim_id) LIMIT 1", &[])?.is_none() { return Ok(()); }
        let draft = self.repository.load_or_create()?;
        loop {
            let Some(row) = db.query_row("SELECT claim_id FROM writer_incident_claim c WHERE draft_id=?1 AND draft_revision<=?2 AND NOT EXISTS(SELECT 1 FROM writer_incident_claim_released r WHERE r.claim_id=c.claim_id) LIMIT 1", &[
                StoreValue::Blob(draft.draft_id().as_bytes().to_vec()), StoreValue::Integer(i64::try_from(draft.revision()).map_err(|_| WriterError::PreparedFinalizationInconsistent)?),
            ])? else { return Ok(()); };
            self.release_original_claim(row.integer(0)?)?;
        }
    }

    pub(crate) fn record_original_identity(
        &self,
        identity: &OriginalIncidentIdentity,
        transaction: &PreparedTransactionV1,
    ) -> Result<(), WriterError> {
        self.ensure_original_source()?;
        self.incident_numbers.database_handle().execute("INSERT INTO writer_original_identity(entry_hash,object_hash,record_id,sequence,organization_id,civil_year,incident_number) VALUES(?1,?2,?3,?4,?5,?6,?7)", &[
            StoreValue::Blob(transaction.entry_hash.as_bytes().to_vec()), StoreValue::Blob(transaction.entry_object_hash.as_bytes().to_vec()), StoreValue::Blob(identity.record_id.as_bytes().to_vec()),
            StoreValue::Integer(i64::try_from(identity.sequence.get()).map_err(|_| WriterError::OriginalIdentityMismatch)?), StoreValue::Blob(identity.organization_id.as_bytes().to_vec()),
            StoreValue::Integer(i64::from(identity.year)), StoreValue::Text(identity.number.clone()),
        ])?;
        Ok(())
    }

    pub(crate) fn confirm_original_publication(
        &self,
        transaction: &PreparedTransactionV1,
    ) -> Result<(), WriterError> {
        let db = self.incident_numbers.database_handle();
        if db.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name='writer_original_identity'", &[])?.is_none() { return Ok(()); }
        db.transaction(|tx| {
            let Some(row) = tx.query_row(
                "SELECT object_hash,sequence FROM writer_original_identity WHERE entry_hash=?1",
                &[StoreValue::Blob(transaction.entry_hash.as_bytes().to_vec())],
            )?
            else {
                return Ok(());
            };
            if row.blob(0)? != transaction.entry_object_hash.as_bytes()
                || u64::try_from(row.integer(1)?).ok() != Some(transaction.sequence.get())
            {
                return Err(WriterError::OriginalIdentityMismatch);
            }
            tx.execute(
                "INSERT OR IGNORE INTO writer_original_published(entry_hash) VALUES(?1)",
                &[StoreValue::Blob(transaction.entry_hash.as_bytes().to_vec())],
            )?;
            Ok(())
        })
    }
}
