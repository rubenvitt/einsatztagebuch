//! Normal immutable amendments. Import coordinates carry no authority: the
//! original signed archive and Writer-origin acquisition source must agree.

use ea_archive::{ArchiveBlob, is_staging_path};
use ea_local_store::StoreValue;
use ea_schema::{AmendmentChangeV1, NativeSourceV1};
use ea_types::{ChainSequence, EntryHash, ObjectHash, RecordId, UnixMillis};

use crate::{WriterError, WriterService};

/// The existing cleartext-free handoff wire, deliberately untrusted.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OriginalReferenceV1 {
    pub original_record_id: RecordId,
    pub original_entry_hash: EntryHash,
    pub original_sequence: ChainSequence,
}

pub struct AmendmentContentV1 {
    pub timezone: String,
    pub source: NativeSourceV1,
    pub reason: String,
    pub changes: Vec<AmendmentChangeV1>,
}

/// Minted only by `prepare_amendment`, never by a DTO or public constructor.
pub struct AmendmentInputV1 {
    pub(crate) original: OriginalReferenceV1,
    pub(crate) original_object_hash: ObjectHash,
    pub(crate) original_incident_number: String,
    pub(crate) content: AmendmentContentV1,
}

impl WriterService<'_> {
    pub fn prepare_amendment(
        &self,
        reference: OriginalReferenceV1,
        content: AmendmentContentV1,
        anchor: &ea_trust::TrustAnchorV1,
        now: UnixMillis,
    ) -> Result<AmendmentInputV1, WriterError> {
        let _writer_lock = self.backend.acquire_writer_lock()?;
        let _draft_lock = self.repository.acquire_draft_lock()?;
        if self.repository.prepared_finalization_marker()?.is_some() {
            return Err(WriterError::PreparedFinalizationPresent);
        }
        let (object_hash, number) = self.original_identity(reference)?;
        if anchor.chain_id() != self.binding.chain_id {
            return Err(WriterError::OriginalArchiveUnverified);
        }
        let report =
            ea_verify::verify_archive(self.source, anchor, ea_verify::VerifyOptions::new(now))
                .map_err(|_| WriterError::OriginalArchiveUnverified)?;
        if !report.is_fully_verified()
            || !report.object_results().any(|result| {
                result.object_hash() == object_hash
                    && result.result() == ea_verify::ObjectResultKindV1::Valid
            })
        {
            return Err(WriterError::OriginalArchiveUnverified);
        }
        self.require_original_bytes(reference, object_hash)?;
        Ok(AmendmentInputV1 {
            original: reference,
            original_object_hash: object_hash,
            original_incident_number: number,
            content,
        })
    }

    pub(crate) fn original_identity(
        &self,
        reference: OriginalReferenceV1,
    ) -> Result<(ObjectHash, String), WriterError> {
        let db = self.incident_numbers.database_handle();
        if db.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name='writer_original_identity'", &[])?.is_none() {
            return Err(WriterError::OriginalIdentityMissing);
        }
        let row = db.query_row("SELECT i.record_id,i.sequence,i.object_hash,i.incident_number,i.organization_id,i.civil_year FROM writer_original_identity i JOIN writer_original_published p ON p.entry_hash=i.entry_hash WHERE i.entry_hash=?1", &[
            StoreValue::Blob(reference.original_entry_hash.as_bytes().to_vec()),
        ])?.ok_or(WriterError::OriginalIdentityMissing)?;
        if row.blob(0)? != reference.original_record_id.as_bytes()
            || u64::try_from(row.integer(1)?).ok() != Some(reference.original_sequence.get())
        {
            return Err(WriterError::OriginalIdentityMismatch);
        }
        let organization = ea_types::OrganizationId::try_from(row.blob(4)?)
            .map_err(|_| WriterError::OriginalIdentityMismatch)?;
        let year =
            i32::try_from(row.integer(5)?).map_err(|_| WriterError::OriginalIdentityMismatch)?;
        let number = row.text(3)?;
        if organization != self.head.policy_fields().organization_id
            || !self.incident_numbers.contains(organization, year, number)?
        {
            return Err(WriterError::OriginalIdentityMismatch);
        }
        Ok((
            ObjectHash::try_from(row.blob(2)?)
                .map_err(|_| WriterError::OriginalIdentityMismatch)?,
            number.to_owned(),
        ))
    }

    pub(crate) fn require_original_bytes(
        &self,
        reference: OriginalReferenceV1,
        object_hash: ObjectHash,
    ) -> Result<(), WriterError> {
        let mut found = false;
        self.source.visit_blobs(&mut |blob: ArchiveBlob<'_>| {
            if !is_staging_path(blob.path_hint())
                && ea_crypto::object_hash(blob.bytes()) == object_hash
                && let Ok(ea_format::ParsedArchiveObject::Entry(entry)) =
                    ea_format::decode_exact_object(blob.bytes())
            {
                found = entry.value().entry_hash() == reference.original_entry_hash
                    && entry.value().manifest().fields().chain_sequence
                        == reference.original_sequence
                    && entry.value().manifest().fields().chain_id == self.binding.chain_id;
            }
            Ok(())
        })?;
        if found {
            Ok(())
        } else {
            Err(WriterError::OriginalArchiveUnverified)
        }
    }
}
