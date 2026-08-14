#![forbid(unsafe_code)]

mod eag;
mod ecp;
mod eds;
mod eip;
mod esr;
mod etb;
mod object;
mod parser;

pub use eag::{
    GrantBodyFieldsV1, GrantBodyV1, GrantKindV1, GrantPlanItemV1, GrantPlanV1, GrantPurposeV1,
    GrantV1,
};
pub use ecp::{
    CheckpointCoreFieldsV1, CheckpointCoreV1, EvidenceKindV1, EvidenceObjectV1,
    RenewalCoreFieldsV1, RenewalCoreV1, Rfc3161EvidenceFieldsV1,
};
pub use eds::DestroyedEntryStubV1;
pub use eip::{EntryPackageV1, ManifestCoreFieldsV1, ManifestCoreV1, SignedManifestV1};
pub use esr::{ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1};
pub use etb::{
    CertificateKindV1, DeletionAttestationFieldsV1, DestructionAuthorizationFieldsV1,
    DestructionTargetV1, DestructionTransitionFieldsV1, DeviceCertificateFieldsV1,
    FreeTextPolicyFieldsV1, GrantAuthorizationFieldsV1, KeyProtectionProfileV1,
    OperatorBindingFieldsV1, OperatorRoleV1, OrganizationAdminAuthorizationFieldsV1,
    PolicyFieldsV1, RegistryChangeV1, RegistryEventFieldsV1, RetentionPolicyFieldsV1,
    RootCertificateFieldsV1, TrustObjectV1, TrustPayloadV1, TrustSubtypeV1,
    WriterTransitionFieldsV1, validate_destruction_targets,
};
pub use object::{ExactObjectBytes, FormatError, Parsed, ParsedArchiveObject};
pub use parser::{
    EAG_MAX_RAW_BYTES_V1, EAG_PREFIX_V1, ECP_MAX_RAW_BYTES_V1, ECP_PREFIX_V1, EDS_MAX_RAW_BYTES_V1,
    EDS_PREFIX_V1, EIP_MAX_RAW_BYTES_V1, EIP_PREFIX_V1, ESR_MAX_RAW_BYTES_V1, ESR_PREFIX_V1,
    ETB_MAX_RAW_BYTES_V1, ETB_PREFIX_V1, MAX_ARCHIVE_OBJECT_BYTES_V1, decode_exact_object,
    encode_destroyed_entry_stub, encode_entry_package, encode_evidence, encode_grant,
    encode_receipt, encode_trust,
};
