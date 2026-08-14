use ea_format::PolicyFieldsV1;
use ea_types::ObjectHash;

#[derive(Clone)]
pub(crate) struct ResolvedPolicy {
    pub(crate) object_hash: ObjectHash,
    pub(crate) fields: PolicyFieldsV1,
}
