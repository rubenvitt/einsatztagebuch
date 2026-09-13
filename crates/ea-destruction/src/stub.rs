//! Exact original identity is preserved; constructing a Stub never authorizes removal.
use crate::{DestructionError, VerifiedDestructionAuthorization, VerifiedDestructionTarget};
use ea_format::{
    DestroyedEntryStubV1, EntryPackageV1, ExactObjectBytes, Parsed, ParsedArchiveObject,
    decode_exact_object, encode_destroyed_entry_stub,
};

/// Construct only from an original whose Writer signature and exact target
/// identity were checked against this authorization. Physical removal also
/// requires native execution admission, verified pre-state, delivery blocking,
/// a durable managed job and a flushed/re-read copy of these exact Stub bytes.
pub fn build_stub(
    entry: &Parsed<EntryPackageV1>,
    auth: &VerifiedDestructionAuthorization,
    target: &VerifiedDestructionTarget,
) -> Result<ExactObjectBytes, DestructionError> {
    if target.authorization_hash() != auth.object_hash()
        || target.entry_hash() != entry.value().entry_hash()
        || !auth.fields().targets.iter().any(|t| {
            t.entry_hash() == entry.value().entry_hash().as_bytes()
                && t.chain_sequence() == entry.value().manifest().fields().chain_sequence.get()
        })
    {
        return Err(DestructionError::Target);
    }
    let stub = DestroyedEntryStubV1::new(
        entry.value().signed_manifest().clone(),
        entry.value().writer_signature().to_vec(),
        entry.object_hash(),
        auth.fields().destruction_id,
        auth.object_hash(),
    )?;
    Ok(encode_destroyed_entry_stub(&stub)?)
}

/// Check re-read bytes against the exact expected original and authorization.
/// This authenticates the content; it deliberately makes no durability claim.
pub fn verify_stub_against_original(
    exact: &[u8],
    entry: &Parsed<EntryPackageV1>,
    auth: &VerifiedDestructionAuthorization,
    target: &VerifiedDestructionTarget,
) -> Result<(), DestructionError> {
    let ParsedArchiveObject::Destroyed(_) = decode_exact_object(exact)? else {
        return Err(DestructionError::Format);
    };
    if build_stub(entry, auth, target)?.as_bytes() != exact {
        return Err(DestructionError::Target);
    }
    Ok(())
}
