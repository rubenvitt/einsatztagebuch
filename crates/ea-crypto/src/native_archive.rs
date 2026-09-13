//! Internal native storage identity, not a new signing or archive family.
use ea_types::Hash32;

/// Path-, installation- and policy-version-independent identity for one exact
/// independent anchor and canonical full archive profile.
#[must_use]
pub fn native_archive_component_namespace(anchor_hash: Hash32, profile_hash: Hash32) -> Hash32 {
    crate::digest::sha256_parts(&[
        b"EINSATZARCHIV-NATIVE-ARCHIVE-COMPONENT-v1",
        &[0],
        anchor_hash.as_bytes(),
        profile_hash.as_bytes(),
    ])
}
