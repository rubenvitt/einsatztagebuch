use ea_format::{DeviceCertificateFieldsV1, RootCertificateFieldsV1};
use ea_types::ObjectHash;

pub(crate) struct RootAuthority {
    pub(crate) object_hash: ObjectHash,
    pub(crate) fields: RootCertificateFieldsV1,
}

pub(crate) struct ActiveCertificate {
    pub(crate) object_hash: ObjectHash,
    pub(crate) fields: DeviceCertificateFieldsV1,
}
