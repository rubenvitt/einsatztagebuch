use core::cmp::Ordering;

use ea_crypto::{ContentType, parse_cose_sign1, trust_digest};
use ea_types::{
    AuthorizationId, CertificateHash, ChainId, ChainSequence, DestructionId, DeviceId, EntryHash,
    EventId, Hash32, KeyThumbprint, ObjectHash, OperatorSubjectId, OrganizationId, RegistryVersion,
    UnixMillis,
};
use minicbor::{Decoder, Encoder, data::Type};

use crate::object::{
    FormatError, bytes_exact, exact_array_length, exact_item, expect_array_length,
    expect_empty_array, finish, optional_bytes_exact,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustSubtypeV1 {
    RootCertificate,
    DeviceCertificate,
    OperatorBinding,
    OrganizationAdminAuthorization,
    RegistryEvent,
    Policy,
    WriterTransition,
    GrantAuthorization,
    DestructionAuthorization,
    DestructionTransition,
    DeletionAttestation,
}

impl TrustSubtypeV1 {
    fn from_str(value: &str) -> Result<Self, FormatError> {
        match value {
            "rootCertificate" => Ok(Self::RootCertificate),
            "deviceCertificate" => Ok(Self::DeviceCertificate),
            "operatorBinding" => Ok(Self::OperatorBinding),
            "organizationAdminAuthorization" => Ok(Self::OrganizationAdminAuthorization),
            "registryEvent" => Ok(Self::RegistryEvent),
            "policy" => Ok(Self::Policy),
            "writerTransition" => Ok(Self::WriterTransition),
            "grantAuthorization" => Ok(Self::GrantAuthorization),
            "destructionAuthorization" => Ok(Self::DestructionAuthorization),
            "destructionTransition" => Ok(Self::DestructionTransition),
            "deletionAttestation" => Ok(Self::DeletionAttestation),
            _ => Err(FormatError::TagMismatch),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootCertificate => "rootCertificate",
            Self::DeviceCertificate => "deviceCertificate",
            Self::OperatorBinding => "operatorBinding",
            Self::OrganizationAdminAuthorization => "organizationAdminAuthorization",
            Self::RegistryEvent => "registryEvent",
            Self::Policy => "policy",
            Self::WriterTransition => "writerTransition",
            Self::GrantAuthorization => "grantAuthorization",
            Self::DestructionAuthorization => "destructionAuthorization",
            Self::DestructionTransition => "destructionTransition",
            Self::DeletionAttestation => "deletionAttestation",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CertificateKindV1 {
    Writer = 0,
    Reader = 1,
    OrganizationAdmin = 2,
    KeyApprover = 3,
    RecoveryRecipient = 4,
    HistoricalGrantAuthority = 5,
    ServerReceipt = 6,
    DeletionAttest = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KeyProtectionProfileV1 {
    OsWrapped = 0,
    HardwareNonExportable = 1,
    OfflineEncryptedContainer = 2,
    Pkcs11 = 3,
    ServerSecretStoreOrHsm = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperatorRoleV1 {
    Writer = 0,
    Reader = 1,
    OrganizationAdmin = 2,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RootCertificateFieldsV1 {
    pub organization_id: OrganizationId,
    pub root_public_cose_key: Vec<u8>,
    pub root_key_thumbprint: KeyThumbprint,
    pub previous_root_certificate_object_hash: Option<ObjectHash>,
    pub effective_from_registry_version: RegistryVersion,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeviceCertificateFieldsV1 {
    pub organization_id: OrganizationId,
    pub device_id: DeviceId,
    pub certificate_kind: CertificateKindV1,
    pub signing_public_cose_key: Option<Vec<u8>>,
    pub kem_public_cose_key: Option<Vec<u8>>,
    pub signing_key_thumbprint: Option<KeyThumbprint>,
    pub kem_key_thumbprint: Option<KeyThumbprint>,
    pub capabilities: Vec<String>,
    pub key_protection_profile: KeyProtectionProfileV1,
    pub effective_from_sequence: ChainSequence,
    pub revoked_from_sequence: Option<ChainSequence>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OperatorBindingFieldsV1 {
    pub organization_id: OrganizationId,
    pub operator_subject_id: OperatorSubjectId,
    pub operator_profile_commitment: Hash32,
    pub device_certificate_hash: CertificateHash,
    pub operator_role: OperatorRoleV1,
    pub os_account_binding_hash: Hash32,
    pub operator_instance_key_thumbprint: KeyThumbprint,
    pub effective_from_sequence: ChainSequence,
    pub revoked_from_sequence: Option<ChainSequence>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OrganizationAdminAuthorizationFieldsV1 {
    pub authorization_id: AuthorizationId,
    pub organization_id: OrganizationId,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: Hash32,
    pub admin_key_thumbprint: KeyThumbprint,
    pub admin_certificate_hash: CertificateHash,
    pub admin_operator_binding_object_hash: ObjectHash,
    pub action_code: u8,
    pub target_trust_subtype: TrustSubtypeV1,
    pub authorized_trust_core_hash: Hash32,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
    pub nonce: [u8; 32],
}

#[derive(Clone, Eq, PartialEq)]
pub enum RegistryChangeV1 {
    Certificate {
        object_hash: ObjectHash,
    },
    Target {
        target_kind: u8,
        object_hash: ObjectHash,
    },
    Policy {
        object_hash: ObjectHash,
    },
    WriterTransition {
        object_hash: ObjectHash,
    },
    OperatorBinding {
        object_hash: ObjectHash,
    },
    AdminCertificate {
        object_hash: ObjectHash,
        effect: u8,
    },
    RootCertificate {
        object_hash: ObjectHash,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub struct RegistryEventFieldsV1 {
    pub organization_id: OrganizationId,
    pub registry_version: RegistryVersion,
    pub previous_registry_hash: Option<Hash32>,
    pub effective_from_sequence: ChainSequence,
    pub valid_through_sequence: ChainSequence,
    pub issued_at: UnixMillis,
    pub not_before: UnixMillis,
    pub not_after: UnixMillis,
    pub policy_object_hash: ObjectHash,
    pub change: RegistryChangeV1,
    pub root_key_thumbprint: KeyThumbprint,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RetentionPolicyFieldsV1 {
    pub minimum_retention_ms: Option<u64>,
    pub destruction_enabled: bool,
    pub eds_privacy_decision_document_hash: Option<Hash32>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct FreeTextPolicyFieldsV1 {
    pub free_text_allowed: bool,
    pub rule_set_version: String,
    pub local_pattern_warning_enabled: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PolicyFieldsV1 {
    pub organization_id: OrganizationId,
    pub policy_version: u64,
    pub previous_policy_object_hash: Option<ObjectHash>,
    pub operating_profile: u8,
    pub max_registry_age_ms: u64,
    pub max_future_clock_skew_ms: u64,
    pub registry_expiry_behavior: u8,
    pub evidence_max_delay_ms: u64,
    pub reader_inactivity_ms: u64,
    pub reader_history_access_allowed: bool,
    pub allowed_archive_profile_hashes: Vec<Hash32>,
    pub backup_frequency_ms: u64,
    pub restore_test_interval_ms: u64,
    pub retention_policy: RetentionPolicyFieldsV1,
    pub free_text_policy: FreeTextPolicyFieldsV1,
    pub allowed_crypto_suite_ids: Vec<String>,
    pub allowed_format_versions: Vec<u64>,
    pub effective_from_sequence: ChainSequence,
}

#[derive(Clone, Eq, PartialEq)]
pub struct WriterTransitionFieldsV1 {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub old_writer_certificate_hash: CertificateHash,
    pub new_writer_certificate_hash: CertificateHash,
    pub effective_from_sequence: ChainSequence,
    pub previous_entry_hash: EntryHash,
    pub reason_code: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GrantAuthorizationFieldsV1 {
    pub authorization_id: AuthorizationId,
    pub organization_id: OrganizationId,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: Hash32,
    pub authorization_sequence: u64,
    pub entry_hashes: Vec<EntryHash>,
    pub recipient_key_thumbprint: KeyThumbprint,
    pub recipient_certificate_hash: CertificateHash,
    pub expires_at: UnixMillis,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DestructionAuthorizationFieldsV1 {
    pub destruction_id: DestructionId,
    pub organization_id: OrganizationId,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: Hash32,
    pub authorization_sequence: u64,
    pub targets: Vec<DestructionTargetV1>,
    pub scope_code: u64,
    pub legal_reason_code: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DestructionTransitionFieldsV1 {
    pub destruction_id: DestructionId,
    pub destruction_authorization_object_hash: ObjectHash,
    pub event_id: EventId,
    pub previous_event_object_hash: Option<ObjectHash>,
    pub from_state: Option<u8>,
    pub to_state: u8,
    pub trigger_code: u64,
    pub executed_at: UnixMillis,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeletionAttestationFieldsV1 {
    pub destruction_id: DestructionId,
    pub destruction_authorization_object_hash: ObjectHash,
    pub replica_id: [u8; 16],
    pub replica_kind: u64,
    pub removed_object_hashes: Vec<ObjectHash>,
    pub result: u8,
    pub backup_expiry_at: Option<UnixMillis>,
    pub executed_at: UnixMillis,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TrustPayloadV1 {
    subtype: TrustSubtypeV1,
    payload_kind: PayloadKind,
    exact_payload: Vec<u8>,
    exact_digest_input: Vec<u8>,
}

impl TrustPayloadV1 {
    pub fn initial_root_certificate(fields: RootCertificateFieldsV1) -> Result<Self, FormatError> {
        if fields.previous_root_certificate_object_hash.is_some() {
            return Err(FormatError::Shape);
        }
        Self::from_encoded(
            TrustSubtypeV1::RootCertificate,
            PayloadKind::InitialRoot,
            encode_root_certificate(&fields)?,
        )
    }

    pub fn authorized_root_certificate(
        fields: RootCertificateFieldsV1,
        admin_authorization_object_hash: ObjectHash,
    ) -> Result<Self, FormatError> {
        if fields.previous_root_certificate_object_hash.is_none() {
            return Err(FormatError::Shape);
        }
        let core = encode_root_certificate(&fields)?;
        Self::from_encoded(
            TrustSubtypeV1::RootCertificate,
            PayloadKind::Other,
            encode_authorized_payload(&core, admin_authorization_object_hash)?,
        )
    }

    pub fn initial_admin_device_certificate(
        fields: DeviceCertificateFieldsV1,
    ) -> Result<Self, FormatError> {
        if fields.certificate_kind != CertificateKindV1::OrganizationAdmin {
            return Err(FormatError::Shape);
        }
        Self::from_encoded(
            TrustSubtypeV1::DeviceCertificate,
            PayloadKind::InitialAdminDirect,
            encode_device_certificate(&fields)?,
        )
    }

    pub fn authorized_device_certificate(
        fields: DeviceCertificateFieldsV1,
        admin_authorization_object_hash: ObjectHash,
    ) -> Result<Self, FormatError> {
        let core = encode_device_certificate(&fields)?;
        Self::from_encoded(
            TrustSubtypeV1::DeviceCertificate,
            PayloadKind::Other,
            encode_authorized_payload(&core, admin_authorization_object_hash)?,
        )
    }

    pub fn initial_admin_operator_binding(
        fields: OperatorBindingFieldsV1,
    ) -> Result<Self, FormatError> {
        if fields.operator_role != OperatorRoleV1::OrganizationAdmin {
            return Err(FormatError::Shape);
        }
        Self::from_encoded(
            TrustSubtypeV1::OperatorBinding,
            PayloadKind::InitialAdminDirect,
            encode_operator_binding(&fields)?,
        )
    }

    pub fn authorized_operator_binding(
        fields: OperatorBindingFieldsV1,
        admin_authorization_object_hash: ObjectHash,
    ) -> Result<Self, FormatError> {
        let core = encode_operator_binding(&fields)?;
        Self::from_encoded(
            TrustSubtypeV1::OperatorBinding,
            PayloadKind::Other,
            encode_authorized_payload(&core, admin_authorization_object_hash)?,
        )
    }

    pub fn organization_admin_authorization(
        fields: OrganizationAdminAuthorizationFieldsV1,
    ) -> Result<Self, FormatError> {
        let exact_payload = encode_organization_admin_authorization(&fields)?;
        Self::from_encoded(
            TrustSubtypeV1::OrganizationAdminAuthorization,
            PayloadKind::Other,
            exact_payload,
        )
    }

    pub fn registry_event(
        fields: RegistryEventFieldsV1,
        admin_authorization_object_hash: ObjectHash,
    ) -> Result<Self, FormatError> {
        let core = encode_registry_event(&fields)?;
        Self::from_encoded(
            TrustSubtypeV1::RegistryEvent,
            PayloadKind::Other,
            encode_authorized_payload(&core, admin_authorization_object_hash)?,
        )
    }

    pub fn policy(
        fields: PolicyFieldsV1,
        admin_authorization_object_hash: ObjectHash,
    ) -> Result<Self, FormatError> {
        let core = encode_policy(&fields)?;
        Self::from_encoded(
            TrustSubtypeV1::Policy,
            PayloadKind::Other,
            encode_authorized_payload(&core, admin_authorization_object_hash)?,
        )
    }

    pub fn writer_transition(
        fields: WriterTransitionFieldsV1,
        admin_authorization_object_hash: ObjectHash,
    ) -> Result<Self, FormatError> {
        let core = encode_writer_transition(&fields)?;
        Self::from_encoded(
            TrustSubtypeV1::WriterTransition,
            PayloadKind::Other,
            encode_authorized_payload(&core, admin_authorization_object_hash)?,
        )
    }

    pub fn grant_authorization(fields: GrantAuthorizationFieldsV1) -> Result<Self, FormatError> {
        Self::from_encoded(
            TrustSubtypeV1::GrantAuthorization,
            PayloadKind::Other,
            encode_grant_authorization(&fields)?,
        )
    }

    pub fn destruction_authorization(
        fields: DestructionAuthorizationFieldsV1,
    ) -> Result<Self, FormatError> {
        Self::from_encoded(
            TrustSubtypeV1::DestructionAuthorization,
            PayloadKind::Other,
            encode_destruction_authorization(&fields)?,
        )
    }

    pub fn destruction_transition(
        fields: DestructionTransitionFieldsV1,
    ) -> Result<Self, FormatError> {
        Self::from_encoded(
            TrustSubtypeV1::DestructionTransition,
            PayloadKind::Other,
            encode_destruction_transition(&fields)?,
        )
    }

    pub fn deletion_attestation(fields: DeletionAttestationFieldsV1) -> Result<Self, FormatError> {
        Self::from_encoded(
            TrustSubtypeV1::DeletionAttestation,
            PayloadKind::Other,
            encode_deletion_attestation(&fields)?,
        )
    }

    #[must_use]
    pub const fn subtype(&self) -> TrustSubtypeV1 {
        self.subtype
    }

    #[must_use]
    pub fn exact_payload(&self) -> &[u8] {
        &self.exact_payload
    }

    #[must_use]
    pub fn exact_digest_input(&self) -> &[u8] {
        &self.exact_digest_input
    }

    fn from_validated(
        subtype: TrustSubtypeV1,
        payload_kind: PayloadKind,
        exact_payload: Vec<u8>,
    ) -> Result<Self, FormatError> {
        let exact_digest_input = trust_digest_input(subtype, &exact_payload)?;
        Ok(Self {
            subtype,
            payload_kind,
            exact_payload,
            exact_digest_input,
        })
    }

    fn from_encoded(
        subtype: TrustSubtypeV1,
        expected_kind: PayloadKind,
        exact_payload: Vec<u8>,
    ) -> Result<Self, FormatError> {
        let actual_kind = validate_payload(subtype, &exact_payload)?;
        if actual_kind != expected_kind {
            return Err(FormatError::Shape);
        }
        Self::from_validated(subtype, actual_kind, exact_payload)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TrustObjectV1 {
    subtype: TrustSubtypeV1,
    exact_payload: Vec<u8>,
    signatures: Vec<Vec<u8>>,
    exact_body: Vec<u8>,
}

impl TrustObjectV1 {
    pub fn new(payload: TrustPayloadV1, signatures: Vec<Vec<u8>>) -> Result<Self, FormatError> {
        let signature_count = u64::try_from(signatures.len()).map_err(|_| FormatError::Shape)?;
        validate_signature_count(payload.subtype, payload.payload_kind, signature_count)?;
        for signature in &signatures {
            validate_trust_signature(signature, payload.payload_kind, &payload.exact_digest_input)?;
        }
        let exact_body = encode_trust_body(payload.subtype, &payload.exact_payload, &signatures)?;
        Ok(Self {
            subtype: payload.subtype,
            exact_payload: payload.exact_payload,
            signatures,
            exact_body,
        })
    }

    #[must_use]
    pub const fn subtype(&self) -> TrustSubtypeV1 {
        self.subtype
    }

    #[must_use]
    pub fn exact_payload(&self) -> &[u8] {
        &self.exact_payload
    }

    #[must_use]
    pub fn signatures(&self) -> &[Vec<u8>] {
        &self.signatures
    }

    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.exact_body
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DestructionTargetV1 {
    entry_hash: [u8; 32],
    chain_sequence: u64,
}

impl DestructionTargetV1 {
    #[must_use]
    pub const fn new(entry_hash: [u8; 32], chain_sequence: u64) -> Self {
        Self {
            entry_hash,
            chain_sequence,
        }
    }

    #[must_use]
    pub const fn entry_hash(&self) -> &[u8; 32] {
        &self.entry_hash
    }

    #[must_use]
    pub const fn chain_sequence(&self) -> u64 {
        self.chain_sequence
    }
}

pub fn validate_destruction_targets(targets: &[DestructionTargetV1]) -> Result<(), FormatError> {
    if targets.is_empty() {
        return Err(FormatError::Shape);
    }
    for pair in targets.windows(2) {
        match pair[0].entry_hash.cmp(&pair[1].entry_hash) {
            Ordering::Greater => return Err(FormatError::Unsorted),
            Ordering::Equal => return Err(FormatError::Duplicate),
            Ordering::Less => {}
        }
    }
    Ok(())
}

pub(crate) fn parse_body(input: &[u8]) -> Result<TrustObjectV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 3)?;
    let subtype_text = decoder.str().map_err(|_| FormatError::Shape)?;
    let subtype = TrustSubtypeV1::from_str(subtype_text)?;
    let payload = exact_item(input, &mut decoder)?;
    let payload_kind = validate_payload(subtype, payload)?;
    let signature_count = exact_array_length(&mut decoder)?;
    validate_signature_count(subtype, payload_kind, signature_count)?;
    let capacity = usize::try_from(signature_count).map_err(|_| FormatError::Shape)?;
    let mut signatures = Vec::with_capacity(capacity);
    let digest_input = trust_digest_input(subtype, payload)?;
    for _ in 0..signature_count {
        let signature = exact_item(input, &mut decoder)?;
        validate_trust_signature(signature, payload_kind, &digest_input)?;
        signatures.push(signature.to_vec());
    }
    finish(&decoder, input)?;
    Ok(TrustObjectV1 {
        subtype,
        exact_payload: payload.to_vec(),
        signatures,
        exact_body: input.to_vec(),
    })
}

fn validate_trust_signature(
    signature: &[u8],
    payload_kind: PayloadKind,
    exact_digest_input: &[u8],
) -> Result<(), FormatError> {
    let expected_digest = trust_digest(exact_digest_input);
    let parsed = parse_cose_sign1(signature, &[]).map_err(|_| FormatError::Cose)?;
    if parsed.content_type() != ContentType::TrustDigest
        || parsed.payload() != expected_digest.as_bytes()
        || (payload_kind == PayloadKind::InitialRoot) != parsed.certificate_hash().is_none()
    {
        return Err(FormatError::Cose);
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PayloadKind {
    InitialRoot,
    InitialAdminDirect,
    Other,
}

fn encode_organization_admin_authorization(
    fields: &OrganizationAdminAuthorizationFieldsV1,
) -> Result<Vec<u8>, FormatError> {
    if fields.action_code > 6
        || fields.issued_at >= fields.expires_at
        || !matches!(
            fields.target_trust_subtype,
            TrustSubtypeV1::DeviceCertificate
                | TrustSubtypeV1::OperatorBinding
                | TrustSubtypeV1::RegistryEvent
                | TrustSubtypeV1::Policy
                | TrustSubtypeV1::WriterTransition
                | TrustSubtypeV1::RootCertificate
        )
    {
        return Err(FormatError::Shape);
    }
    let mut exact = Vec::with_capacity(512);
    Encoder::new(&mut exact)
        .array(15)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.authorization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.registry_version.get()))
        .and_then(|encoder| encoder.bytes(fields.registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.admin_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.admin_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.admin_operator_binding_object_hash.as_bytes()))
        .and_then(|encoder| encoder.u8(fields.action_code))
        .and_then(|encoder| encoder.str(fields.target_trust_subtype.as_str()))
        .and_then(|encoder| encoder.bytes(fields.authorized_trust_core_hash.as_bytes()))
        .and_then(|encoder| encoder.i64(fields.issued_at.get()))
        .and_then(|encoder| encoder.i64(fields.expires_at.get()))
        .and_then(|encoder| encoder.bytes(&fields.nonce))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_root_certificate(fields: &RootCertificateFieldsV1) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(256);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(7)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(&fields.root_public_cose_key))
        .and_then(|encoder| encoder.bytes(fields.root_key_thumbprint.as_bytes()))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_bytes(
        &mut encoder,
        fields
            .previous_root_certificate_object_hash
            .as_ref()
            .map(|value| value.as_bytes().as_slice()),
    )?;
    encoder
        .u64(fields.effective_from_registry_version.get())
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_device_certificate(fields: &DeviceCertificateFieldsV1) -> Result<Vec<u8>, FormatError> {
    let capability_count =
        u64::try_from(fields.capabilities.len()).map_err(|_| FormatError::Shape)?;
    let mut exact = Vec::with_capacity(512);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(13)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.device_id.as_bytes()))
        .and_then(|encoder| encoder.u8(fields.certificate_kind as u8))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_vec(&mut encoder, fields.signing_public_cose_key.as_deref())?;
    encode_optional_vec(&mut encoder, fields.kem_public_cose_key.as_deref())?;
    encode_optional_bytes(
        &mut encoder,
        fields
            .signing_key_thumbprint
            .as_ref()
            .map(|value| value.as_bytes().as_slice()),
    )?;
    encode_optional_bytes(
        &mut encoder,
        fields
            .kem_key_thumbprint
            .as_ref()
            .map(|value| value.as_bytes().as_slice()),
    )?;
    encoder
        .array(capability_count)
        .map_err(|_| FormatError::Shape)?;
    for capability in &fields.capabilities {
        encoder.str(capability).map_err(|_| FormatError::Shape)?;
    }
    encoder
        .u8(fields.key_protection_profile as u8)
        .and_then(|encoder| encoder.u64(fields.effective_from_sequence.get()))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_u64(
        &mut encoder,
        fields.revoked_from_sequence.map(ChainSequence::get),
    )?;
    encoder.array(0).map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_operator_binding(fields: &OperatorBindingFieldsV1) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(384);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(11)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.operator_subject_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.operator_profile_commitment.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.device_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.u8(fields.operator_role as u8))
        .and_then(|encoder| encoder.bytes(fields.os_account_binding_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.operator_instance_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.effective_from_sequence.get()))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_u64(
        &mut encoder,
        fields.revoked_from_sequence.map(ChainSequence::get),
    )?;
    encoder.array(0).map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_authorized_payload(
    core: &[u8],
    admin_authorization_object_hash: ObjectHash,
) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(core.len().saturating_add(40));
    Encoder::new(&mut exact)
        .array(2)
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(core);
    Encoder::new(&mut exact)
        .bytes(admin_authorization_object_hash.as_bytes())
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_registry_event(fields: &RegistryEventFieldsV1) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(512);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(13)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.registry_version.get()))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_bytes(
        &mut encoder,
        fields
            .previous_registry_hash
            .as_ref()
            .map(|value| value.as_bytes().as_slice()),
    )?;
    encoder
        .u64(fields.effective_from_sequence.get())
        .and_then(|encoder| encoder.u64(fields.valid_through_sequence.get()))
        .and_then(|encoder| encoder.i64(fields.issued_at.get()))
        .and_then(|encoder| encoder.i64(fields.not_before.get()))
        .and_then(|encoder| encoder.i64(fields.not_after.get()))
        .and_then(|encoder| encoder.bytes(fields.policy_object_hash.as_bytes()))
        .map_err(|_| FormatError::Shape)?;
    encode_registry_change(&mut encoder, &fields.change)?;
    encoder
        .bytes(fields.root_key_thumbprint.as_bytes())
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_registry_change(
    encoder: &mut Encoder<&mut Vec<u8>>,
    change: &RegistryChangeV1,
) -> Result<(), FormatError> {
    match change {
        RegistryChangeV1::Certificate { object_hash } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u8(0))
                .and_then(|encoder| encoder.bytes(object_hash.as_bytes()))
                .map_err(|_| FormatError::Shape)?;
        }
        RegistryChangeV1::Target {
            target_kind,
            object_hash,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u8(1))
                .and_then(|encoder| encoder.u8(*target_kind))
                .and_then(|encoder| encoder.bytes(object_hash.as_bytes()))
                .map_err(|_| FormatError::Shape)?;
        }
        RegistryChangeV1::Policy { object_hash } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u8(2))
                .and_then(|encoder| encoder.bytes(object_hash.as_bytes()))
                .map_err(|_| FormatError::Shape)?;
        }
        RegistryChangeV1::WriterTransition { object_hash } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u8(3))
                .and_then(|encoder| encoder.bytes(object_hash.as_bytes()))
                .map_err(|_| FormatError::Shape)?;
        }
        RegistryChangeV1::OperatorBinding { object_hash } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u8(4))
                .and_then(|encoder| encoder.bytes(object_hash.as_bytes()))
                .map_err(|_| FormatError::Shape)?;
        }
        RegistryChangeV1::AdminCertificate {
            object_hash,
            effect,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u8(5))
                .and_then(|encoder| encoder.bytes(object_hash.as_bytes()))
                .and_then(|encoder| encoder.u8(*effect))
                .map_err(|_| FormatError::Shape)?;
        }
        RegistryChangeV1::RootCertificate { object_hash } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u8(6))
                .and_then(|encoder| encoder.bytes(object_hash.as_bytes()))
                .map_err(|_| FormatError::Shape)?;
        }
    }
    Ok(())
}

fn encode_policy(fields: &PolicyFieldsV1) -> Result<Vec<u8>, FormatError> {
    let archive_count = u64::try_from(fields.allowed_archive_profile_hashes.len())
        .map_err(|_| FormatError::Shape)?;
    let suite_count =
        u64::try_from(fields.allowed_crypto_suite_ids.len()).map_err(|_| FormatError::Shape)?;
    let version_count =
        u64::try_from(fields.allowed_format_versions.len()).map_err(|_| FormatError::Shape)?;
    let mut exact = Vec::with_capacity(1024);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(21)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.policy_version))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_bytes(
        &mut encoder,
        fields
            .previous_policy_object_hash
            .as_ref()
            .map(|value| value.as_bytes().as_slice()),
    )?;
    encoder
        .u8(fields.operating_profile)
        .and_then(|encoder| encoder.u64(fields.max_registry_age_ms))
        .and_then(|encoder| encoder.u64(fields.max_future_clock_skew_ms))
        .and_then(|encoder| encoder.u8(fields.registry_expiry_behavior))
        .and_then(|encoder| encoder.u64(fields.evidence_max_delay_ms))
        .and_then(|encoder| encoder.u64(fields.reader_inactivity_ms))
        .and_then(|encoder| encoder.bool(fields.reader_history_access_allowed))
        .and_then(|encoder| encoder.array(archive_count))
        .map_err(|_| FormatError::Shape)?;
    for hash in &fields.allowed_archive_profile_hashes {
        encoder
            .bytes(hash.as_bytes())
            .map_err(|_| FormatError::Shape)?;
    }
    encoder
        .u8(0)
        .and_then(|encoder| encoder.u64(fields.backup_frequency_ms))
        .and_then(|encoder| encoder.u64(fields.restore_test_interval_ms))
        .and_then(|encoder| encoder.array(3))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_u64(&mut encoder, fields.retention_policy.minimum_retention_ms)?;
    encoder
        .bool(fields.retention_policy.destruction_enabled)
        .map_err(|_| FormatError::Shape)?;
    encode_optional_bytes(
        &mut encoder,
        fields
            .retention_policy
            .eds_privacy_decision_document_hash
            .as_ref()
            .map(|value| value.as_bytes().as_slice()),
    )?;
    encoder
        .array(3)
        .and_then(|encoder| encoder.bool(fields.free_text_policy.free_text_allowed))
        .and_then(|encoder| encoder.str(&fields.free_text_policy.rule_set_version))
        .and_then(|encoder| encoder.bool(fields.free_text_policy.local_pattern_warning_enabled))
        .and_then(|encoder| encoder.array(suite_count))
        .map_err(|_| FormatError::Shape)?;
    for suite in &fields.allowed_crypto_suite_ids {
        encoder.str(suite).map_err(|_| FormatError::Shape)?;
    }
    encoder
        .array(version_count)
        .map_err(|_| FormatError::Shape)?;
    for version in &fields.allowed_format_versions {
        encoder.u64(*version).map_err(|_| FormatError::Shape)?;
    }
    encoder
        .u64(fields.effective_from_sequence.get())
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_writer_transition(fields: &WriterTransitionFieldsV1) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(384);
    Encoder::new(&mut exact)
        .array(9)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.chain_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.old_writer_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.new_writer_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.effective_from_sequence.get()))
        .and_then(|encoder| encoder.bytes(fields.previous_entry_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.reason_code))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_grant_authorization(fields: &GrantAuthorizationFieldsV1) -> Result<Vec<u8>, FormatError> {
    let entry_count = u64::try_from(fields.entry_hashes.len()).map_err(|_| FormatError::Shape)?;
    let mut exact = Vec::with_capacity(
        fields
            .entry_hashes
            .len()
            .saturating_mul(36)
            .saturating_add(512),
    );
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(12)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.authorization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.registry_version.get()))
        .and_then(|encoder| encoder.bytes(fields.registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.authorization_sequence))
        .and_then(|encoder| encoder.array(entry_count))
        .map_err(|_| FormatError::Shape)?;
    for hash in &fields.entry_hashes {
        encoder
            .bytes(hash.as_bytes())
            .map_err(|_| FormatError::Shape)?;
    }
    encoder
        .bytes(fields.recipient_key_thumbprint.as_bytes())
        .and_then(|encoder| encoder.bytes(fields.recipient_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.i64(fields.expires_at.get()))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_destruction_authorization(
    fields: &DestructionAuthorizationFieldsV1,
) -> Result<Vec<u8>, FormatError> {
    validate_destruction_targets(&fields.targets)?;
    let target_count = u64::try_from(fields.targets.len()).map_err(|_| FormatError::Shape)?;
    let mut exact = Vec::with_capacity(fields.targets.len().saturating_mul(48).saturating_add(384));
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(10)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.destruction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.registry_version.get()))
        .and_then(|encoder| encoder.bytes(fields.registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.authorization_sequence))
        .and_then(|encoder| encoder.array(target_count))
        .map_err(|_| FormatError::Shape)?;
    for target in &fields.targets {
        encoder
            .array(2)
            .and_then(|encoder| encoder.bytes(target.entry_hash()))
            .and_then(|encoder| encoder.u64(target.chain_sequence()))
            .map_err(|_| FormatError::Shape)?;
    }
    encoder
        .u64(fields.scope_code)
        .and_then(|encoder| encoder.u64(fields.legal_reason_code))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_destruction_transition(
    fields: &DestructionTransitionFieldsV1,
) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(320);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(10)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.destruction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.destruction_authorization_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.event_id.as_bytes()))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_bytes(
        &mut encoder,
        fields
            .previous_event_object_hash
            .as_ref()
            .map(|value| value.as_bytes().as_slice()),
    )?;
    encode_optional_u8(&mut encoder, fields.from_state)?;
    encoder
        .u8(fields.to_state)
        .and_then(|encoder| encoder.u64(fields.trigger_code))
        .and_then(|encoder| encoder.i64(fields.executed_at.get()))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_deletion_attestation(
    fields: &DeletionAttestationFieldsV1,
) -> Result<Vec<u8>, FormatError> {
    let removed_count =
        u64::try_from(fields.removed_object_hashes.len()).map_err(|_| FormatError::Shape)?;
    let mut exact = Vec::with_capacity(
        fields
            .removed_object_hashes
            .len()
            .saturating_mul(36)
            .saturating_add(384),
    );
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(10)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.destruction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.destruction_authorization_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(&fields.replica_id))
        .and_then(|encoder| encoder.u64(fields.replica_kind))
        .and_then(|encoder| encoder.array(removed_count))
        .map_err(|_| FormatError::Shape)?;
    for hash in &fields.removed_object_hashes {
        encoder
            .bytes(hash.as_bytes())
            .map_err(|_| FormatError::Shape)?;
    }
    encoder.u8(fields.result).map_err(|_| FormatError::Shape)?;
    if let Some(value) = fields.backup_expiry_at {
        encoder.i64(value.get()).map_err(|_| FormatError::Shape)?;
    } else {
        encoder.null().map_err(|_| FormatError::Shape)?;
    }
    encoder
        .i64(fields.executed_at.get())
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_optional_vec(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<&[u8]>,
) -> Result<(), FormatError> {
    encode_optional_bytes(encoder, value)
}

fn encode_optional_bytes(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<&[u8]>,
) -> Result<(), FormatError> {
    if let Some(value) = value {
        encoder.bytes(value).map_err(|_| FormatError::Shape)?;
    } else {
        encoder.null().map_err(|_| FormatError::Shape)?;
    }
    Ok(())
}

fn encode_optional_u64(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<u64>,
) -> Result<(), FormatError> {
    if let Some(value) = value {
        encoder.u64(value).map_err(|_| FormatError::Shape)?;
    } else {
        encoder.null().map_err(|_| FormatError::Shape)?;
    }
    Ok(())
}

fn encode_optional_u8(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<u8>,
) -> Result<(), FormatError> {
    if let Some(value) = value {
        encoder.u8(value).map_err(|_| FormatError::Shape)?;
    } else {
        encoder.null().map_err(|_| FormatError::Shape)?;
    }
    Ok(())
}

fn encode_trust_body(
    subtype: TrustSubtypeV1,
    payload: &[u8],
    signatures: &[Vec<u8>],
) -> Result<Vec<u8>, FormatError> {
    let signature_count = u64::try_from(signatures.len()).map_err(|_| FormatError::Shape)?;
    let mut exact = Vec::with_capacity(
        payload
            .len()
            .saturating_add(signatures.iter().map(Vec::len).sum::<usize>())
            .saturating_add(64),
    );
    Encoder::new(&mut exact)
        .array(3)
        .and_then(|encoder| encoder.str(subtype.as_str()))
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(payload);
    Encoder::new(&mut exact)
        .array(signature_count)
        .map_err(|_| FormatError::Shape)?;
    for signature in signatures {
        exact.extend_from_slice(signature);
    }
    Ok(exact)
}

fn validate_payload(subtype: TrustSubtypeV1, payload: &[u8]) -> Result<PayloadKind, FormatError> {
    match subtype {
        TrustSubtypeV1::RootCertificate => validate_root_payload(payload),
        TrustSubtypeV1::DeviceCertificate => validate_device_payload(payload),
        TrustSubtypeV1::OperatorBinding => validate_operator_payload(payload),
        TrustSubtypeV1::OrganizationAdminAuthorization => {
            validate_admin_authorization(payload)?;
            Ok(PayloadKind::Other)
        }
        TrustSubtypeV1::RegistryEvent => {
            validate_authorized(payload, validate_registry_event)?;
            Ok(PayloadKind::Other)
        }
        TrustSubtypeV1::Policy => {
            validate_authorized(payload, validate_policy)?;
            Ok(PayloadKind::Other)
        }
        TrustSubtypeV1::WriterTransition => {
            validate_authorized(payload, validate_writer_transition)?;
            Ok(PayloadKind::Other)
        }
        TrustSubtypeV1::GrantAuthorization => {
            validate_grant_authorization(payload)?;
            Ok(PayloadKind::Other)
        }
        TrustSubtypeV1::DestructionAuthorization => {
            validate_destruction_authorization(payload)?;
            Ok(PayloadKind::Other)
        }
        TrustSubtypeV1::DestructionTransition => {
            validate_destruction_transition(payload)?;
            Ok(PayloadKind::Other)
        }
        TrustSubtypeV1::DeletionAttestation => {
            validate_deletion_attestation(payload)?;
            Ok(PayloadKind::Other)
        }
    }
}

fn validate_signature_count(
    subtype: TrustSubtypeV1,
    payload_kind: PayloadKind,
    count: u64,
) -> Result<(), FormatError> {
    let valid = match subtype {
        TrustSubtypeV1::RootCertificate | TrustSubtypeV1::OrganizationAdminAuthorization => {
            count == 1
        }
        TrustSubtypeV1::DeviceCertificate | TrustSubtypeV1::OperatorBinding
            if payload_kind == PayloadKind::InitialAdminDirect =>
        {
            count == 1
        }
        TrustSubtypeV1::GrantAuthorization | TrustSubtypeV1::DestructionAuthorization => count >= 2,
        _ => count >= 1,
    };
    if !valid {
        return Err(FormatError::Shape);
    }
    Ok(())
}

fn payload_wraps_core(input: &[u8]) -> Result<bool, FormatError> {
    let mut decoder = Decoder::new(input);
    exact_array_length(&mut decoder)?;
    Ok(decoder.datatype().map_err(|_| FormatError::Shape)? == Type::Array)
}

fn validate_root_payload(input: &[u8]) -> Result<PayloadKind, FormatError> {
    if payload_wraps_core(input)? {
        validate_authorized(input, |core| validate_root_core(core, false))?;
        Ok(PayloadKind::Other)
    } else {
        validate_root_core(input, true)?;
        Ok(PayloadKind::InitialRoot)
    }
}

fn validate_device_payload(input: &[u8]) -> Result<PayloadKind, FormatError> {
    if payload_wraps_core(input)? {
        validate_authorized(input, |core| validate_device_core(core, None))?;
        Ok(PayloadKind::Other)
    } else {
        validate_device_core(input, Some(2))?;
        Ok(PayloadKind::InitialAdminDirect)
    }
}

fn validate_operator_payload(input: &[u8]) -> Result<PayloadKind, FormatError> {
    if payload_wraps_core(input)? {
        validate_authorized(input, |core| validate_operator_core(core, None))?;
        Ok(PayloadKind::Other)
    } else {
        validate_operator_core(input, Some(2))?;
        Ok(PayloadKind::InitialAdminDirect)
    }
}

fn validate_authorized(
    input: &[u8],
    validate_core: impl FnOnce(&[u8]) -> Result<(), FormatError>,
) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 2)?;
    let core = exact_item(input, &mut decoder)?;
    validate_core(core)?;
    bytes_exact(&mut decoder, 32)?;
    finish(&decoder, input)
}

fn validate_root_core(input: &[u8], initial: bool) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 7)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    decoder.bytes().map_err(|_| FormatError::Shape)?;
    bytes_exact(&mut decoder, 32)?;
    let previous = optional_bytes_exact(&mut decoder, 32)?.is_some();
    if initial == previous {
        return Err(FormatError::Shape);
    }
    decoder.u64().map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_device_core(input: &[u8], required_kind: Option<u64>) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 13)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    bytes_exact(&mut decoder, 16)?;
    let kind = decoder.u64().map_err(|_| FormatError::Shape)?;
    if kind > 7 || required_kind.is_some_and(|required| required != kind) {
        return Err(FormatError::Shape);
    }
    optional_unbounded_bstr(&mut decoder)?;
    optional_unbounded_bstr(&mut decoder)?;
    optional_bytes_exact(&mut decoder, 32)?;
    optional_bytes_exact(&mut decoder, 32)?;
    validate_sorted_texts(&mut decoder, false)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? > 4 {
        return Err(FormatError::Shape);
    }
    let effective = decoder.u64().map_err(|_| FormatError::Shape)?;
    let revoked = optional_uint(&mut decoder)?;
    if revoked.is_some_and(|value| value <= effective) {
        return Err(FormatError::Shape);
    }
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_operator_core(input: &[u8], required_role: Option<u64>) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 11)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    bytes_exact(&mut decoder, 16)?;
    bytes_exact(&mut decoder, 32)?;
    bytes_exact(&mut decoder, 32)?;
    let role = decoder.u64().map_err(|_| FormatError::Shape)?;
    if role > 2 || required_role.is_some_and(|required| required != role) {
        return Err(FormatError::Shape);
    }
    bytes_exact(&mut decoder, 32)?;
    bytes_exact(&mut decoder, 32)?;
    let effective = decoder.u64().map_err(|_| FormatError::Shape)?;
    let revoked = optional_uint(&mut decoder)?;
    if revoked.is_some_and(|value| value <= effective) {
        return Err(FormatError::Shape);
    }
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_admin_authorization(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 15)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    bytes_exact(&mut decoder, 16)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    for _ in 0..4 {
        bytes_exact(&mut decoder, 32)?;
    }
    if decoder.u64().map_err(|_| FormatError::Shape)? > 6 {
        return Err(FormatError::Shape);
    }
    if !matches!(
        decoder.str().map_err(|_| FormatError::Shape)?,
        "deviceCertificate"
            | "operatorBinding"
            | "registryEvent"
            | "policy"
            | "writerTransition"
            | "rootCertificate"
    ) {
        return Err(FormatError::TagMismatch);
    }
    bytes_exact(&mut decoder, 32)?;
    let issued = decoder.i64().map_err(|_| FormatError::Shape)?;
    let expires = decoder.i64().map_err(|_| FormatError::Shape)?;
    if issued >= expires {
        return Err(FormatError::Shape);
    }
    bytes_exact(&mut decoder, 32)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_registry_event(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 13)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    optional_bytes_exact(&mut decoder, 32)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    decoder.i64().map_err(|_| FormatError::Shape)?;
    decoder.i64().map_err(|_| FormatError::Shape)?;
    decoder.i64().map_err(|_| FormatError::Shape)?;
    bytes_exact(&mut decoder, 32)?;
    validate_registry_change(&mut decoder)?;
    bytes_exact(&mut decoder, 32)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_registry_change(decoder: &mut Decoder<'_>) -> Result<(), FormatError> {
    let length = exact_array_length(decoder)?;
    let tag = decoder.u64().map_err(|_| FormatError::Shape)?;
    match (tag, length) {
        (0 | 2 | 3 | 4 | 6, 2) => {
            bytes_exact(decoder, 32)?;
        }
        (1, 3) => {
            if decoder.u64().map_err(|_| FormatError::Shape)? > 2 {
                return Err(FormatError::Shape);
            }
            bytes_exact(decoder, 32)?;
        }
        (5, 3) => {
            bytes_exact(decoder, 32)?;
            if decoder.u64().map_err(|_| FormatError::Shape)? > 1 {
                return Err(FormatError::Shape);
            }
        }
        _ => return Err(FormatError::TagMismatch),
    }
    Ok(())
}

fn validate_policy(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 21)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    optional_bytes_exact(&mut decoder, 32)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? > 1 {
        return Err(FormatError::Shape);
    }
    decoder.u64().map_err(|_| FormatError::Shape)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? > 1 {
        return Err(FormatError::Shape);
    }
    decoder.u64().map_err(|_| FormatError::Shape)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    decoder.bool().map_err(|_| FormatError::Shape)?;
    validate_sorted_hashes(&mut decoder, true)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 0 {
        return Err(FormatError::TagMismatch);
    }
    decoder.u64().map_err(|_| FormatError::Shape)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    validate_retention(&mut decoder)?;
    validate_free_text(&mut decoder)?;
    validate_sorted_texts(&mut decoder, true)?;
    validate_sorted_uints(&mut decoder, true)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_retention(decoder: &mut Decoder<'_>) -> Result<(), FormatError> {
    expect_array_length(decoder, 3)?;
    optional_uint(decoder)?;
    decoder.bool().map_err(|_| FormatError::Shape)?;
    optional_bytes_exact(decoder, 32)?;
    Ok(())
}

fn validate_free_text(decoder: &mut Decoder<'_>) -> Result<(), FormatError> {
    expect_array_length(decoder, 3)?;
    decoder.bool().map_err(|_| FormatError::Shape)?;
    decoder.str().map_err(|_| FormatError::Shape)?;
    decoder.bool().map_err(|_| FormatError::Shape)?;
    Ok(())
}

fn validate_writer_transition(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 9)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    bytes_exact(&mut decoder, 16)?;
    bytes_exact(&mut decoder, 32)?;
    bytes_exact(&mut decoder, 32)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    bytes_exact(&mut decoder, 32)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_grant_authorization(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 12)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    bytes_exact(&mut decoder, 16)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    bytes_exact(&mut decoder, 32)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    validate_sorted_hashes(&mut decoder, true)?;
    bytes_exact(&mut decoder, 32)?;
    bytes_exact(&mut decoder, 32)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
        return Err(FormatError::TagMismatch);
    }
    decoder.i64().map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_destruction_authorization(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 10)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    bytes_exact(&mut decoder, 16)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    bytes_exact(&mut decoder, 32)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    let length = exact_array_length(&mut decoder)?;
    if length == 0 {
        return Err(FormatError::Shape);
    }
    let capacity = usize::try_from(length).map_err(|_| FormatError::Shape)?;
    let mut targets = Vec::with_capacity(capacity);
    for _ in 0..length {
        expect_array_length(&mut decoder, 2)?;
        let entry_hash = bytes_exact(&mut decoder, 32)?
            .try_into()
            .map_err(|_| FormatError::Shape)?;
        let sequence = decoder.u64().map_err(|_| FormatError::Shape)?;
        targets.push(DestructionTargetV1::new(entry_hash, sequence));
    }
    validate_destruction_targets(&targets)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_destruction_transition(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 10)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    bytes_exact(&mut decoder, 32)?;
    bytes_exact(&mut decoder, 16)?;
    optional_bytes_exact(&mut decoder, 32)?;
    let from = optional_uint(&mut decoder)?;
    if from.is_some_and(|value| value > 4) {
        return Err(FormatError::Shape);
    }
    if decoder.u64().map_err(|_| FormatError::Shape)? > 4 {
        return Err(FormatError::Shape);
    }
    decoder.u64().map_err(|_| FormatError::Shape)?;
    decoder.i64().map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_deletion_attestation(input: &[u8]) -> Result<(), FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 10)?;
    expect_version(&mut decoder)?;
    bytes_exact(&mut decoder, 16)?;
    bytes_exact(&mut decoder, 32)?;
    bytes_exact(&mut decoder, 16)?;
    decoder.u64().map_err(|_| FormatError::Shape)?;
    validate_sorted_hashes(&mut decoder, false)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? > 2 {
        return Err(FormatError::Shape);
    }
    match decoder.datatype().map_err(|_| FormatError::Shape)? {
        Type::Null => decoder.null().map_err(|_| FormatError::Shape)?,
        _ => {
            decoder.i64().map_err(|_| FormatError::Shape)?;
        }
    }
    decoder.i64().map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)
}

fn validate_sorted_hashes(
    decoder: &mut Decoder<'_>,
    require_nonempty: bool,
) -> Result<(), FormatError> {
    let length = exact_array_length(decoder)?;
    if require_nonempty && length == 0 {
        return Err(FormatError::Shape);
    }
    let mut previous: Option<[u8; 32]> = None;
    for _ in 0..length {
        let current: [u8; 32] = bytes_exact(decoder, 32)?
            .try_into()
            .map_err(|_| FormatError::Shape)?;
        if let Some(previous) = previous {
            match previous.cmp(&current) {
                Ordering::Equal => return Err(FormatError::Duplicate),
                Ordering::Greater => return Err(FormatError::Unsorted),
                Ordering::Less => {}
            }
        }
        previous = Some(current);
    }
    Ok(())
}

fn validate_sorted_texts(
    decoder: &mut Decoder<'_>,
    require_nonempty: bool,
) -> Result<(), FormatError> {
    let length = exact_array_length(decoder)?;
    if require_nonempty && length == 0 {
        return Err(FormatError::Shape);
    }
    let mut previous: Option<&[u8]> = None;
    for _ in 0..length {
        let current = decoder.str().map_err(|_| FormatError::Shape)?.as_bytes();
        if let Some(previous) = previous {
            match previous.cmp(current) {
                Ordering::Equal => return Err(FormatError::Duplicate),
                Ordering::Greater => return Err(FormatError::Unsorted),
                Ordering::Less => {}
            }
        }
        previous = Some(current);
    }
    Ok(())
}

fn validate_sorted_uints(
    decoder: &mut Decoder<'_>,
    require_nonempty: bool,
) -> Result<(), FormatError> {
    let length = exact_array_length(decoder)?;
    if require_nonempty && length == 0 {
        return Err(FormatError::Shape);
    }
    let mut previous: Option<u64> = None;
    for _ in 0..length {
        let current = decoder.u64().map_err(|_| FormatError::Shape)?;
        if let Some(previous) = previous {
            match previous.cmp(&current) {
                Ordering::Equal => return Err(FormatError::Duplicate),
                Ordering::Greater => return Err(FormatError::Unsorted),
                Ordering::Less => {}
            }
        }
        previous = Some(current);
    }
    Ok(())
}

fn optional_uint(decoder: &mut Decoder<'_>) -> Result<Option<u64>, FormatError> {
    if decoder.datatype().map_err(|_| FormatError::Shape)? == Type::Null {
        decoder.null().map_err(|_| FormatError::Shape)?;
        Ok(None)
    } else {
        decoder.u64().map(Some).map_err(|_| FormatError::Shape)
    }
}

fn optional_unbounded_bstr(decoder: &mut Decoder<'_>) -> Result<(), FormatError> {
    if decoder.datatype().map_err(|_| FormatError::Shape)? == Type::Null {
        decoder.null().map_err(|_| FormatError::Shape)?;
    } else {
        decoder.bytes().map_err(|_| FormatError::Shape)?;
    }
    Ok(())
}

fn expect_version(decoder: &mut Decoder<'_>) -> Result<(), FormatError> {
    if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
        return Err(FormatError::UnknownVersion);
    }
    Ok(())
}

fn trust_digest_input(
    subtype: TrustSubtypeV1,
    exact_payload: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::with_capacity(exact_payload.len().saturating_add(48));
    Encoder::new(&mut bytes)
        .array(2)
        .and_then(|encoder| encoder.str(subtype.as_str()))
        .map_err(|_| FormatError::Shape)?;
    bytes.extend_from_slice(exact_payload);
    Ok(bytes)
}
