//! Signed one-use local receipts. Issuance and audit append commit together;
//! consumption commits before any secret or prepared transaction is created.
//! Consumption is never undone, including after a reversible failure.

use std::sync::Arc;

use ea_audit::{
    AuditActorProof, PreparedLocalAuditEvent, SignedLocalAuditService, SqliteLocalAuditRepository,
    TypedLocalAuditEvent,
};
use ea_format::{LocalAuditActionV1, LocalAuditOutcomeV1, StaleRegistryContextV1};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_operator::OperatorSessionProof;
use ea_types::{EventId, UnixMillis};

use crate::{FinalizationPreview, WriterError, WriterService};

/// Opaque receipt issued only after a verified native challenge and durable
/// signed audit. Deliberately neither deserializable nor freely constructible.
pub struct StaleRegistryAcknowledgement {
    pub(crate) event: PreparedLocalAuditEvent,
    pub(crate) proof: OperatorSessionProof,
    pub(crate) acknowledged_at: UnixMillis,
}

impl StaleRegistryAcknowledgement {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event.id()
    }
}

impl core::fmt::Debug for StaleRegistryAcknowledgement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StaleRegistryAcknowledgement(<signed>)")
    }
}

/// Writer-owned append-only receipt bookkeeping in the encrypted local store.
/// The existing local audit table remains the authoritative signed record.
#[derive(Clone)]
pub struct StaleRegistryStore {
    database: Arc<EncryptedDatabase>,
}

impl StaleRegistryStore {
    /// Initialize the additive local schema without changing archived formats.
    pub fn new(database: Arc<EncryptedDatabase>) -> Result<Self, WriterError> {
        database.transaction(|tx| {
            tx.execute("CREATE TABLE IF NOT EXISTS writer_stale_receipt (event_id BLOB PRIMARY KEY NOT NULL, presence_hash BLOB UNIQUE NOT NULL)", &[])?;
            tx.execute("CREATE TABLE IF NOT EXISTS writer_stale_consumption (event_id BLOB PRIMARY KEY NOT NULL REFERENCES writer_stale_receipt(event_id))", &[])?;
            tx.execute("CREATE TABLE IF NOT EXISTS writer_stale_prepared (entry_hash BLOB PRIMARY KEY NOT NULL, event_id BLOB UNIQUE NOT NULL REFERENCES writer_stale_consumption(event_id), organization_id BLOB NOT NULL, civil_year INTEGER NOT NULL, incident_number TEXT NOT NULL)", &[])?;
            tx.execute("CREATE TABLE IF NOT EXISTS writer_stale_claim (event_id BLOB PRIMARY KEY NOT NULL REFERENCES writer_stale_consumption(event_id), draft_id BLOB NOT NULL, draft_revision INTEGER NOT NULL, organization_id BLOB NOT NULL, civil_year INTEGER NOT NULL, incident_number TEXT NOT NULL)", &[])?;
            tx.execute("CREATE TABLE IF NOT EXISTS writer_stale_claim_released (event_id BLOB PRIMARY KEY NOT NULL REFERENCES writer_stale_claim(event_id))", &[])?;
            for table in ["writer_stale_receipt", "writer_stale_consumption", "writer_stale_prepared", "writer_stale_claim", "writer_stale_claim_released"] {
                for operation in ["UPDATE", "DELETE"] {
                    tx.execute(&format!("CREATE TRIGGER IF NOT EXISTS {table}_no_{operation} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, 'append-only'); END"), &[])?;
                }
            }
            Ok::<_, WriterError>(())
        })?;
        Ok(Self { database })
    }

    pub(crate) fn claim_number(
        &self,
        register: &ea_draft::IncidentNumberRegister,
        event_id: EventId,
        draft: &ea_draft::Draft,
        claim: &crate::finalize::ClaimedIncidentNumber,
    ) -> Result<(), WriterError> {
        if !register.uses_database(&self.database) {
            return Err(WriterError::PreparedFinalizationInconsistent);
        }
        self.database.transaction(|tx| {
            // The decrypted witness must describe this store's current draft,
            // not a draft supplied by a different repository. Both locks are held.
            let row = tx.query_row("SELECT draft_id,save_revision FROM draft WHERE singleton=0", &[])?
                .ok_or(WriterError::PreparedFinalizationInconsistent)?;
            if row.blob(0)? != draft.draft_id().as_bytes()
                || u64::try_from(row.integer(1)?).ok() != Some(draft.revision()) {
                return Err(WriterError::PreparedFinalizationInconsistent);
            }
            ea_draft::IncidentNumberRegister::claim_in(tx, claim.organization_id, claim.local_civil_year, &claim.human_incident_number)
                .map_err(|error| match error {
                    ea_draft::DraftError::IncidentNumberTaken => WriterError::IncidentNumberTaken,
                    other => WriterError::Draft(other),
                })?;
            tx.execute("INSERT INTO writer_stale_claim(event_id,draft_id,draft_revision,organization_id,civil_year,incident_number) VALUES(?1,?2,?3,?4,?5,?6)", &[
                StoreValue::Blob(event_id.as_bytes().to_vec()), StoreValue::Blob(draft.draft_id().as_bytes().to_vec()),
                StoreValue::Integer(i64::try_from(draft.revision()).map_err(|_| WriterError::PreparedFinalizationInconsistent)?),
                StoreValue::Blob(claim.organization_id.as_bytes().to_vec()), StoreValue::Integer(i64::from(claim.local_civil_year)),
                StoreValue::Text(claim.human_incident_number.clone()),
            ])?;
            Ok(())
        })
    }

    pub(crate) fn release_claim(&self, event_id: EventId) -> Result<(), WriterError> {
        self.database.transaction(|tx| {
            let Some(row) = tx.query_row("SELECT organization_id,civil_year,incident_number FROM writer_stale_claim c WHERE event_id=?1 AND NOT EXISTS(SELECT 1 FROM writer_stale_claim_released r WHERE r.event_id=c.event_id)", &[StoreValue::Blob(event_id.as_bytes().to_vec())])? else { return Ok(()); };
            let organization = ea_types::OrganizationId::try_from(row.blob(0)?).map_err(|_| WriterError::PreparedFinalizationInconsistent)?;
            let year = i32::try_from(row.integer(1)?).map_err(|_| WriterError::PreparedFinalizationInconsistent)?;
            ea_draft::IncidentNumberRegister::release_in(tx, organization, year, row.text(2)?)?;
            // Atomic resolution prevents a repeated recovery of this old
            // attempt from erasing a later claim of the same number.
            tx.execute("INSERT INTO writer_stale_claim_released(event_id) VALUES(?1)", &[StoreValue::Blob(event_id.as_bytes().to_vec())])?;
            Ok(())
        })
    }

    pub(crate) fn recover_reversible_claims(
        &self,
        draft: &ea_draft::Draft,
    ) -> Result<(), WriterError> {
        loop {
            let Some(row) = self.database.query_row("SELECT c.event_id FROM writer_stale_claim c WHERE c.draft_id=?1 AND c.draft_revision<=?2 AND NOT EXISTS(SELECT 1 FROM writer_stale_claim_released r WHERE r.event_id=c.event_id) LIMIT 1", &[
                StoreValue::Blob(draft.draft_id().as_bytes().to_vec()),
                StoreValue::Integer(i64::try_from(draft.revision()).map_err(|_| WriterError::PreparedFinalizationInconsistent)?),
            ])? else { return Ok(()); };
            let event_id = EventId::try_from(row.blob(0)?)
                .map_err(|_| WriterError::PreparedFinalizationInconsistent)?;
            self.release_claim(event_id)?;
        }
    }

    pub(crate) fn has_unreleased_claims(&self) -> Result<bool, WriterError> {
        Ok(self.database.query_row("SELECT 1 FROM writer_stale_claim c WHERE NOT EXISTS(SELECT 1 FROM writer_stale_claim_released r WHERE r.event_id=c.event_id) LIMIT 1", &[])?.is_some())
    }

    pub(crate) fn require_unused(
        &self,
        ack: &StaleRegistryAcknowledgement,
    ) -> Result<(), WriterError> {
        let row = self.database.query_row(
            "SELECT a.exact_bytes FROM writer_stale_receipt r JOIN local_audit_event a ON a.event_id = r.event_id WHERE r.event_id = ?1 AND NOT EXISTS (SELECT 1 FROM writer_stale_consumption c WHERE c.event_id = r.event_id)",
            &[StoreValue::Blob(ack.event_id().as_bytes().to_vec())],
        )?.ok_or(WriterError::StaleAckReplay)?;
        if row.blob(0)? != ack.event.exact_bytes() {
            return Err(WriterError::StaleAckPreviewMismatch);
        }
        Ok(())
    }

    pub(crate) fn consume(&self, ack: &StaleRegistryAcknowledgement) -> Result<(), WriterError> {
        self.database.transaction(|tx| {
            let changed = tx.execute(
                "INSERT INTO writer_stale_consumption(event_id) SELECT r.event_id FROM writer_stale_receipt r JOIN local_audit_event a ON a.event_id=r.event_id WHERE r.event_id=?1 AND a.exact_bytes=?2 AND NOT EXISTS(SELECT 1 FROM writer_stale_consumption c WHERE c.event_id=r.event_id)",
                &[StoreValue::Blob(ack.event_id().as_bytes().to_vec()), StoreValue::Blob(ack.event.exact_bytes().to_vec())],
            )?;
            if changed != 1 { return Err(WriterError::StaleAckReplay); }
            Ok(())
        })
    }

    pub(crate) fn record_prepared_claim(
        &self,
        event_id: EventId,
        entry_hash: ea_types::EntryHash,
        claim: &crate::finalize::ClaimedIncidentNumber,
    ) -> Result<(), WriterError> {
        self.database.execute("INSERT INTO writer_stale_prepared(entry_hash,event_id,organization_id,civil_year,incident_number) VALUES(?1,?2,?3,?4,?5)", &[
            StoreValue::Blob(entry_hash.as_bytes().to_vec()), StoreValue::Blob(event_id.as_bytes().to_vec()),
            StoreValue::Blob(claim.organization_id.as_bytes().to_vec()), StoreValue::Integer(i64::from(claim.local_civil_year)),
            StoreValue::Text(claim.human_incident_number.clone()),
        ])?;
        Ok(())
    }
}

impl WriterService<'_> {
    pub(crate) fn issue_stale_receipt(
        &self,
        proof: OperatorSessionProof,
        preview: &FinalizationPreview,
        now: UnixMillis,
    ) -> Result<StaleRegistryAcknowledgement, WriterError> {
        let store = self
            .stale_store
            .as_ref()
            .ok_or(WriterError::StaleAckRequired)?;
        let audit = SignedLocalAuditService::new(
            Arc::new(SqliteLocalAuditRepository::new(Arc::clone(&store.database))),
            Arc::clone(&self.key_provider),
            self.binding.writer_signing_handle,
            ea_types::ObjectHash::try_from(
                self.binding.writer_certificate_hash.as_bytes().as_slice(),
            )
            .map_err(|_| WriterError::StaleAckPreviewMismatch)?,
            now,
        );
        let event = audit.prepare_signed(
            AuditActorProof::OperatorSession(&proof),
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::RegistryStaleWarnAcceptance(
                    StaleRegistryContextV1::new(
                        self.head.registry_head_hash(),
                        self.head.policy_object_hash(),
                        preview.proposed_sequence(),
                        self.head.not_after(),
                        now,
                        preview.preview_hash(),
                    ),
                ),
                outcome: LocalAuditOutcomeV1::Accepted,
            },
        )?;
        // An encoding success is not signature verification. Reject a wrong
        // or malfunctioning signer before persisting any privileged receipt.
        let decoded = ea_format::decode_local_audit_event(event.exact_bytes())?;
        let mut decoder = minicbor::Decoder::new(event.exact_bytes());
        decoder
            .array()
            .map_err(|_| WriterError::StaleAckPreviewMismatch)?;
        decoder
            .skip()
            .map_err(|_| WriterError::StaleAckPreviewMismatch)?;
        let signature = &event.exact_bytes()[decoder.position()..];
        let context = ea_crypto::VerificationContext::local_audit(
            decoded.exact_core(),
            self.head.proposed_sequence(),
            ea_crypto::SignerRole::Writer,
            self.head.registry_version(),
        )?;
        ea_crypto::verify_cose_sign1(signature, &self.head, &context)?;
        store.database.transaction(|tx| {
            let presence = ea_crypto::object_hash(proof.challenge_nonce());
            if tx
                .query_row(
                    "SELECT 1 FROM writer_stale_receipt WHERE presence_hash=?1",
                    &[StoreValue::Blob(presence.as_bytes().to_vec())],
                )?
                .is_some()
            {
                return Err(WriterError::StaleAckReplay);
            }
            SqliteLocalAuditRepository::append_prepared_in(tx, &event)?;
            tx.execute(
                "INSERT INTO writer_stale_receipt(event_id,presence_hash) VALUES(?1,?2)",
                &[
                    StoreValue::Blob(event.id().as_bytes().to_vec()),
                    StoreValue::Blob(presence.as_bytes().to_vec()),
                ],
            )?;
            Ok::<_, WriterError>(())
        })?;
        Ok(StaleRegistryAcknowledgement {
            event,
            proof,
            acknowledged_at: now,
        })
    }
}
