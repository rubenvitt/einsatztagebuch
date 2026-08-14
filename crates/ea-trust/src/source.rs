use std::sync::Arc;

use ea_types::ObjectHash;

use crate::TrustSourceError;

pub const MAX_TRUST_OBJECTS_V1: usize = 65_536;
pub const MAX_TOTAL_TRUST_OBJECT_BYTES_V1: usize = 268_435_456;

pub trait TrustObjectSource {
    fn visit_trust_object_hashes(
        &self,
        visitor: &mut dyn FnMut(ObjectHash) -> Result<(), TrustSourceError>,
    ) -> Result<(), TrustSourceError>;

    fn read_exact_trust_object(
        &self,
        object_hash: ObjectHash,
    ) -> Result<Option<Arc<[u8]>>, TrustSourceError>;
}
