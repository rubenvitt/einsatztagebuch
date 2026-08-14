use ea_format::OperatorBindingFieldsV1;
use ea_types::ObjectHash;

#[derive(Clone)]
pub(crate) struct ActiveOperatorBinding {
    pub(crate) object_hash: ObjectHash,
    pub(crate) fields: OperatorBindingFieldsV1,
}
