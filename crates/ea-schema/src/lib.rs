#![forbid(unsafe_code)]

mod decode;
mod encode;
mod error;
mod model;
mod registry;
mod transform;
mod v1;

pub use error::{SchemaError, UnsupportedSchema};
pub use model::{
    AmendmentChangeV1, AmendmentV1, CommonHeaderV1, CoordinatesV1, DestructionEvidenceV1,
    DestructionExecutionResultV1, DestructionStubBindingV1, DestructionTargetV1,
    ExternalOrganizationV1, GenesisV1, ImportedProvenanceV1, IncidentUniquenessKey, IncidentV1,
    KeyTransitionV1, KeywordV1, LocationV1, MasterDataRevisionV1, NativeSourceV1, OccurredAtV1,
    OperatorSnapshotV1, PatientCount, PayloadV1, PersonnelSnapshotV1, ReplicaResultV1,
    ReplicaStateV1, SNAPSHOT_TEXT_MAX_CHARS_V1, StructuredAddressV1, ValidatedPayload,
    VehicleSnapshotV1,
};
pub use registry::{SchemaDescriptor, SchemaRegistry};
pub use transform::DerivedView;
pub use v1::{
    IANA_TZDB_VERSION_V1, PAYLOAD_PLAINTEXT_MAX_BYTES_V1, SCHEMA_VERSION_V1, SUITE_ID_V1,
    encode_payload,
};
