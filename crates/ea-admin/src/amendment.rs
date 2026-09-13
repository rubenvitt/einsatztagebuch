//! Import a Reader correction reference through the normal Writer service.
//! The DTO has no authority: the Writer resolves its retained encrypted
//! origin source and independently verifies the original signed archive.
use ea_reader::CorrectionReference;
use ea_trust::TrustAnchorV1;
use ea_types::UnixMillis;
use ea_writer::{
    AmendmentContentV1, AmendmentInputV1, OriginalReferenceV1, WriterError, WriterService,
};

pub struct AmendmentDraftService<'a, 'writer> {
    writer: &'a WriterService<'writer>,
    anchor: &'a TrustAnchorV1,
}

impl<'a, 'writer> AmendmentDraftService<'a, 'writer> {
    #[must_use]
    pub const fn new(writer: &'a WriterService<'writer>, anchor: &'a TrustAnchorV1) -> Self {
        Self { writer, anchor }
    }

    /// Requires the exact published original source. Missing source backups
    /// are reported as EA-WRITER-ORIGINAL-IDENTITY-MISSING; public archive
    /// metadata cannot recover the encrypted record identity or number.
    pub fn create_from_reference(
        &self,
        reference: CorrectionReference,
        content: AmendmentContentV1,
        observed_now: UnixMillis,
    ) -> Result<AmendmentInputV1, WriterError> {
        self.writer.prepare_amendment(
            OriginalReferenceV1 {
                original_record_id: reference.original_record_id,
                original_entry_hash: reference.original_entry_hash,
                original_sequence: reference.original_sequence,
            },
            content,
            self.anchor,
            observed_now,
        )
    }
}
