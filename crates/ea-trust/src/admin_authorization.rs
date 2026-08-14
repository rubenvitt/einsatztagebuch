use std::collections::BTreeSet;

use ea_crypto::{CoseVerifier, VerificationContext, authorized_trust_digest, parse_cose_sign1};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, OperatorRoleV1, RegistryChangeV1, TrustObjectV1,
    TrustSubtypeV1,
};
use ea_types::{
    AuthorizationId, CertificateHash, ChainSequence, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, SubjectId, UnixMillis,
};
use minicbor::Encoder;

use crate::{
    TrustError,
    resolver::{PreviousHeadResolver, PreviousHeadState},
};

#[derive(Default)]
pub(crate) struct AdminAuthorizationReplay {
    authorization_ids: BTreeSet<AuthorizationId>,
    nonces: BTreeSet<[u8; 32]>,
}

pub struct VerifiedAdminAuthorization {
    inner: VerifiedAuthorizationInner,
}

struct VerifiedAuthorizationInner {
    authorization_object_hash: ObjectHash,
    target_object_hash: ObjectHash,
    previous_registry_version: RegistryVersion,
    previous_registry_head_hash: Hash32,
    signer_authority_subject_id: SubjectId,
}

impl VerifiedAdminAuthorization {
    #[must_use]
    pub const fn authorization_object_hash(&self) -> ObjectHash {
        self.inner.authorization_object_hash
    }

    #[must_use]
    pub const fn target_object_hash(&self) -> ObjectHash {
        self.inner.target_object_hash
    }

    #[must_use]
    pub const fn previous_registry_version(&self) -> RegistryVersion {
        self.inner.previous_registry_version
    }

    #[must_use]
    pub const fn previous_registry_head_hash(&self) -> Hash32 {
        self.inner.previous_registry_head_hash
    }

    #[must_use]
    pub const fn signer_authority_subject_id(&self) -> SubjectId {
        self.inner.signer_authority_subject_id
    }
}

struct TargetDescriptor {
    subtype: TrustSubtypeV1,
    authorization_object_hash: ObjectHash,
    authorized_core_hash: Hash32,
    organization_id: OrganizationId,
    required_action: u8,
    event_issued_at: Option<UnixMillis>,
    admin_target_subject: Option<SubjectId>,
}

pub(crate) fn verify_admin_authorization(
    state: &PreviousHeadState,
    authorization_object_hash: ObjectHash,
    target_object_hash: ObjectHash,
    authorization_use_time: UnixMillis,
    pre_transition_sequence: ChainSequence,
    replay: &mut AdminAuthorizationReplay,
) -> Result<VerifiedAdminAuthorization, TrustError> {
    let authorization_record = state
        .catalog_object(authorization_object_hash)
        .ok_or(TrustError::Source)?;
    let target_record = state
        .catalog_object(target_object_hash)
        .ok_or(TrustError::Source)?;
    if authorization_record.object_hash() != authorization_object_hash
        || target_record.object_hash() != target_object_hash
    {
        return Err(TrustError::Source);
    }

    let authorization = authorization_record.value();
    let authorization_fields = match authorization
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    {
        DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) => fields,
        _ => return Err(TrustError::ActionMismatch),
    };
    let target = target_record.value();
    let descriptor = describe_target(state, target, pre_transition_sequence)?;

    if descriptor.authorization_object_hash != authorization_object_hash
        || descriptor.subtype != authorization_fields.target_trust_subtype
        || descriptor.authorized_core_hash != authorization_fields.authorized_trust_core_hash
        || descriptor.required_action != authorization_fields.action_code
        || descriptor.organization_id != authorization_fields.organization_id
        || authorization_fields.organization_id != state.root.fields.organization_id
        || authorization_fields.registry_version != state.registry_version
        || authorization_fields.registry_head_hash != state.registry_head_hash
        || descriptor
            .event_issued_at
            .is_some_and(|issued_at| issued_at != authorization_use_time)
    {
        return Err(TrustError::ActionMismatch);
    }

    let certificate = state
        .admin_certificates
        .get(&authorization_fields.admin_certificate_hash)
        .ok_or(TrustError::Signature)?;
    if certificate.fields.organization_id != authorization_fields.organization_id
        || certificate.fields.certificate_kind != CertificateKindV1::OrganizationAdmin
        || certificate.fields.signing_key_thumbprint
            != Some(authorization_fields.admin_key_thumbprint)
        || !certificate
            .fields
            .capabilities
            .iter()
            .any(|capability| capability == "organizationAdminApprove")
    {
        return Err(TrustError::Signature);
    }
    require_active(
        certificate.fields.effective_from_sequence,
        certificate.fields.revoked_from_sequence,
        pre_transition_sequence,
    )?;

    if authorization.signatures().len() != 1 {
        return Err(TrustError::Signature);
    }
    let authorization_context =
        VerificationContext::organization_admin_trust_digest(authorization.exact_digest_input())
            .map_err(|_| TrustError::Signature)?;
    let verified_signer = CoseVerifier::verify_normal(
        &authorization.signatures()[0],
        &PreviousHeadResolver::new(state),
        &authorization_context,
    )
    .map_err(|_| TrustError::Signature)?;
    let signer_subject = verified_signer
        .authority_subject_id()
        .ok_or(TrustError::SubjectMismatch)?;
    if certificate.fields.authority_subject_id != Some(signer_subject) {
        return Err(TrustError::SubjectMismatch);
    }

    let binding = state
        .admin_bindings
        .get(&authorization_fields.admin_operator_binding_object_hash)
        .ok_or(TrustError::SubjectMismatch)?;
    if binding.fields.organization_id != authorization_fields.organization_id
        || binding.fields.operator_role != OperatorRoleV1::OrganizationAdmin
        || binding.fields.device_certificate_hash != authorization_fields.admin_certificate_hash
        || binding.fields.operator_subject_id.as_bytes() != signer_subject.as_bytes()
    {
        return Err(TrustError::SubjectMismatch);
    }
    require_active(
        binding.fields.effective_from_sequence,
        binding.fields.revoked_from_sequence,
        pre_transition_sequence,
    )?;

    if descriptor.admin_target_subject == Some(signer_subject) {
        return Err(TrustError::SelfAuthorization);
    }
    if authorization_use_time < authorization_fields.issued_at {
        return Err(TrustError::AuthNotYetValid);
    }
    if authorization_use_time > authorization_fields.expires_at {
        return Err(TrustError::AuthExpired);
    }

    verify_target_root_signatures(state, target, authorization_record.exact_bytes().as_bytes())?;

    if replay
        .authorization_ids
        .contains(&authorization_fields.authorization_id)
        || replay.nonces.contains(&authorization_fields.nonce)
    {
        return Err(TrustError::AuthReplay);
    }
    replay
        .authorization_ids
        .insert(authorization_fields.authorization_id);
    replay.nonces.insert(authorization_fields.nonce);

    Ok(VerifiedAdminAuthorization {
        inner: VerifiedAuthorizationInner {
            authorization_object_hash,
            target_object_hash,
            previous_registry_version: state.registry_version,
            previous_registry_head_hash: state.registry_head_hash,
            signer_authority_subject_id: signer_subject,
        },
    })
}

fn describe_target(
    state: &PreviousHeadState,
    target: &TrustObjectV1,
    at_sequence: ChainSequence,
) -> Result<TargetDescriptor, TrustError> {
    match target.decoded_payload().map_err(|_| TrustError::Source)? {
        DecodedTrustPayloadV1::AuthorizedRoot(core) => descriptor(
            target.subtype(),
            core.authorization_object_hash(),
            core.exact_core(),
            core.fields().organization_id,
            6,
            None,
            None,
        ),
        DecodedTrustPayloadV1::AuthorizedDevice(core) => {
            let fields = core.fields();
            let (required_action, admin_target_subject) =
                if fields.certificate_kind == CertificateKindV1::OrganizationAdmin {
                    (
                        5,
                        Some(
                            fields
                                .authority_subject_id
                                .ok_or(TrustError::ActionMismatch)?,
                        ),
                    )
                } else {
                    (0, None)
                };
            descriptor(
                target.subtype(),
                core.authorization_object_hash(),
                core.exact_core(),
                fields.organization_id,
                required_action,
                None,
                admin_target_subject,
            )
        }
        DecodedTrustPayloadV1::AuthorizedOperatorBinding(core) => descriptor(
            target.subtype(),
            core.authorization_object_hash(),
            core.exact_core(),
            core.fields().organization_id,
            4,
            None,
            None,
        ),
        DecodedTrustPayloadV1::RegistryEvent(core) => {
            let fields = core.fields();
            let (required_action, admin_target_subject) = match &fields.change {
                RegistryChangeV1::Certificate { .. } => (0, None),
                RegistryChangeV1::Target { object_hash, .. } => {
                    require_non_admin_revocation_target(state, *object_hash)?;
                    (1, None)
                }
                RegistryChangeV1::Policy { .. } => (2, None),
                RegistryChangeV1::WriterTransition { .. } => (3, None),
                RegistryChangeV1::OperatorBinding { .. } => (4, None),
                RegistryChangeV1::AdminCertificate {
                    object_hash,
                    effect,
                } => (
                    5,
                    Some(admin_change_target_subject(
                        state,
                        *object_hash,
                        *effect,
                        at_sequence,
                    )?),
                ),
                RegistryChangeV1::RootCertificate { .. } => (6, None),
            };
            descriptor(
                target.subtype(),
                core.authorization_object_hash(),
                core.exact_core(),
                fields.organization_id,
                required_action,
                Some(fields.issued_at),
                admin_target_subject,
            )
        }
        DecodedTrustPayloadV1::Policy(core) => descriptor(
            target.subtype(),
            core.authorization_object_hash(),
            core.exact_core(),
            core.fields().organization_id,
            2,
            None,
            None,
        ),
        DecodedTrustPayloadV1::WriterTransition(core) => descriptor(
            target.subtype(),
            core.authorization_object_hash(),
            core.exact_core(),
            core.fields().organization_id,
            3,
            None,
            None,
        ),
        _ => Err(TrustError::ActionMismatch),
    }
}

fn descriptor(
    subtype: TrustSubtypeV1,
    authorization_object_hash: ObjectHash,
    exact_core: &[u8],
    organization_id: OrganizationId,
    required_action: u8,
    event_issued_at: Option<UnixMillis>,
    admin_target_subject: Option<SubjectId>,
) -> Result<TargetDescriptor, TrustError> {
    Ok(TargetDescriptor {
        subtype,
        authorization_object_hash,
        authorized_core_hash: exact_authorized_core_hash(subtype, exact_core)?,
        organization_id,
        required_action,
        event_issued_at,
        admin_target_subject,
    })
}

fn exact_authorized_core_hash(
    subtype: TrustSubtypeV1,
    exact_core: &[u8],
) -> Result<Hash32, TrustError> {
    let mut exact_input = Vec::with_capacity(exact_core.len().saturating_add(40));
    Encoder::new(&mut exact_input)
        .array(2)
        .and_then(|encoder| encoder.str(subtype.as_str()))
        .map_err(|_| TrustError::Source)?;
    exact_input.extend_from_slice(exact_core);
    Ok(authorized_trust_digest(&exact_input))
}

fn require_active(
    effective_from: ChainSequence,
    revoked_from: Option<ChainSequence>,
    at_sequence: ChainSequence,
) -> Result<(), TrustError> {
    if at_sequence < effective_from || revoked_from.is_some_and(|revoked| at_sequence >= revoked) {
        return Err(TrustError::SignerInactive);
    }
    Ok(())
}

fn admin_change_target_subject(
    state: &PreviousHeadState,
    object_hash: ObjectHash,
    effect: u8,
    at_sequence: ChainSequence,
) -> Result<SubjectId, TrustError> {
    match effect {
        0 => match state
            .catalog_object(object_hash)
            .ok_or(TrustError::ActionMismatch)?
            .value()
            .decoded_payload()
            .map_err(|_| TrustError::Source)?
        {
            DecodedTrustPayloadV1::AuthorizedDevice(core)
                if core.fields().certificate_kind == CertificateKindV1::OrganizationAdmin =>
            {
                core.fields()
                    .authority_subject_id
                    .ok_or(TrustError::ActionMismatch)
            }
            _ => Err(TrustError::ActionMismatch),
        },
        1 => {
            let certificate = state
                .admin_certificates
                .get(&CertificateHash::from(object_hash))
                .ok_or(TrustError::ActionMismatch)?;
            if certificate.fields.certificate_kind != CertificateKindV1::OrganizationAdmin
                || at_sequence < certificate.fields.effective_from_sequence
                || certificate
                    .fields
                    .revoked_from_sequence
                    .is_some_and(|revoked| at_sequence >= revoked)
            {
                return Err(TrustError::ActionMismatch);
            }
            certificate
                .fields
                .authority_subject_id
                .ok_or(TrustError::ActionMismatch)
        }
        _ => Err(TrustError::ActionMismatch),
    }
}

fn require_non_admin_revocation_target(
    state: &PreviousHeadState,
    object_hash: ObjectHash,
) -> Result<(), TrustError> {
    if state
        .admin_certificates
        .contains_key(&CertificateHash::from(object_hash))
    {
        return Err(TrustError::ActionMismatch);
    }
    let Some(record) = state.catalog_object(object_hash) else {
        return Ok(());
    };
    match record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    {
        DecodedTrustPayloadV1::InitialAdminDevice(_) => Err(TrustError::ActionMismatch),
        DecodedTrustPayloadV1::AuthorizedDevice(core)
            if core.fields().certificate_kind == CertificateKindV1::OrganizationAdmin =>
        {
            Err(TrustError::ActionMismatch)
        }
        _ => Ok(()),
    }
}

fn verify_target_root_signatures(
    state: &PreviousHeadState,
    target: &TrustObjectV1,
    exact_authorization_object: &[u8],
) -> Result<(), TrustError> {
    if target.signatures().is_empty() {
        return Err(TrustError::Signature);
    }
    let context = VerificationContext::root_trust_digest(
        target.exact_digest_input(),
        CertificateHash::from(state.root.object_hash),
        Some(exact_authorization_object),
    )
    .map_err(|_| TrustError::Signature)?;
    let resolver = PreviousHeadResolver::new(state);
    let mut previous_certificate_hash = None;
    for signature in target.signatures() {
        let parsed = parse_cose_sign1(signature, &[]).map_err(|_| TrustError::Signature)?;
        let certificate_hash = parsed.certificate_hash().ok_or(TrustError::Signature)?;
        if previous_certificate_hash.is_some_and(|previous| previous >= certificate_hash) {
            return Err(TrustError::Signature);
        }
        CoseVerifier::verify_normal(signature, &resolver, &context)
            .map_err(|_| TrustError::Signature)?;
        previous_certificate_hash = Some(certificate_hash);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ea_crypto::{
        CanonicalPublicCoseKey, ContentType, ProtectedHeader, authorized_trust_digest, object_hash,
        parse_cose_sign1, trust_digest,
    };
    use ea_format::{
        CertificateKindV1, DeviceCertificateFieldsV1, KeyProtectionProfileV1,
        OperatorBindingFieldsV1, OperatorRoleV1, OrganizationAdminAuthorizationFieldsV1,
        RegistryChangeV1, RegistryEventFieldsV1, TrustObjectV1, TrustPayloadV1, TrustSubtypeV1,
        encode_trust,
    };
    use ea_time::TrustedTimeState;
    use ea_types::{
        AuthorizationId, CertificateHash, ChainSequence, DeviceId, Hash32, KeyThumbprint,
        ObjectHash, OperatorSubjectId, RegistryVersion, SubjectId, UnixMillis,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use minicbor::{Decoder, Encoder};

    use crate::{
        PersistedTrustRecord, RegistryHeadPin, TrustError, TrustStateKey, VerifiedTrust,
        certificate::ActiveCertificate,
        decode_trust_anchor, load_trust_state,
        operator_binding::ActiveOperatorBinding,
        resolver::{
            PreviousHeadState,
            tests::{
                ADMIN_PUBLIC, ADMIN_TWO_PUBLIC, CatalogSource, ROOT_SECRET, SnapshotStore,
                exact_admin_binding, exact_admin_certificate, exact_anchor, exact_root_certificate,
                hash32, key_thumbprint, organization,
            },
        },
        verify_trust,
    };

    use super::{AdminAuthorizationReplay, VerifiedAdminAuthorization, verify_admin_authorization};

    const ADMIN_ONE_SECRET: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];
    const ADMIN_THREE_PUBLIC: [u8; 32] = [
        0x27, 0x81, 0x17, 0xfc, 0x14, 0x4c, 0x72, 0x34, 0x0f, 0x67, 0xd0, 0xf2, 0x31, 0x6e, 0x83,
        0x86, 0xce, 0xff, 0xbf, 0x2b, 0x24, 0x28, 0xc9, 0xc5, 0x1f, 0xef, 0x7c, 0x59, 0x7f, 0x1d,
        0x42, 0x6e,
    ];
    const ADMIN_THREE_SECRET: [u8; 32] = [
        0xf5, 0xe5, 0x76, 0x7c, 0xf1, 0x53, 0x31, 0x95, 0x17, 0x63, 0x0f, 0x22, 0x68, 0x76, 0xb8,
        0x6c, 0x81, 0x60, 0xcc, 0x58, 0x3b, 0xc0, 0x13, 0x74, 0x4c, 0x6b, 0xf2, 0x55, 0xf5, 0xcc,
        0x0e, 0xe5,
    ];

    #[derive(Clone, Copy)]
    enum SignatureActor {
        Root,
        AdminOne,
        AdminThree,
    }

    #[derive(Clone, Copy)]
    enum TargetSpec {
        AdminDevice { subject: u8, device: u8 },
        RevokeAdmin { index: usize },
        ChangeOneAdmin { index: usize },
    }

    #[derive(Clone)]
    struct CaseSpec {
        authorization_id: u8,
        nonce: u8,
        action: u8,
        target_subtype_override: Option<TrustSubtypeV1>,
        core_hash_override: Option<Hash32>,
        state_registry_version: RegistryVersion,
        state_registry_head_hash: Hash32,
        authorization_registry_version: RegistryVersion,
        authorization_registry_head_hash: Hash32,
        admin_certificate_index: usize,
        admin_binding_index: usize,
        admin_key_thumbprint_override: Option<KeyThumbprint>,
        admin_signature_actor: SignatureActor,
        mutate_admin_signature: bool,
        target_signature_actor: SignatureActor,
        mutate_target_signature: bool,
        add_invalid_target_signature: bool,
        add_valid_admin_target_signature: bool,
        add_duplicate_root_signature: bool,
        target_authorization_hash_override: Option<ObjectHash>,
        activate_prepared_admin: bool,
        target: TargetSpec,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
        event_issued_at: UnixMillis,
        use_time: UnixMillis,
        pre_transition_sequence: ChainSequence,
        admin_effective_from: ChainSequence,
        admin_revoked_from: Option<ChainSequence>,
        binding_effective_from: ChainSequence,
        binding_revoked_from: Option<ChainSequence>,
    }

    impl Default for CaseSpec {
        fn default() -> Self {
            Self {
                authorization_id: 0xa1,
                nonce: 0xb1,
                action: 5,
                target_subtype_override: None,
                core_hash_override: None,
                state_registry_version: RegistryVersion::new(0),
                state_registry_head_hash: Hash32::ZERO,
                authorization_registry_version: RegistryVersion::new(0),
                authorization_registry_head_hash: Hash32::ZERO,
                admin_certificate_index: 0,
                admin_binding_index: 0,
                admin_key_thumbprint_override: None,
                admin_signature_actor: SignatureActor::AdminOne,
                mutate_admin_signature: false,
                target_signature_actor: SignatureActor::Root,
                mutate_target_signature: false,
                add_invalid_target_signature: false,
                add_valid_admin_target_signature: false,
                add_duplicate_root_signature: false,
                target_authorization_hash_override: None,
                activate_prepared_admin: false,
                target: TargetSpec::AdminDevice {
                    subject: 0x43,
                    // Sharing the signer device is explicitly permitted when subjects differ.
                    device: 0x51,
                },
                issued_at: UnixMillis::new(100),
                expires_at: UnixMillis::new(200),
                event_issued_at: UnixMillis::new(100),
                use_time: UnixMillis::new(100),
                pre_transition_sequence: ChainSequence::new(0),
                admin_effective_from: ChainSequence::new(0),
                admin_revoked_from: None,
                binding_effective_from: ChainSequence::new(0),
                binding_revoked_from: None,
            }
        }
    }

    struct Fixture {
        verified: VerifiedTrust,
        authorization_hash: ObjectHash,
        target_hash: ObjectHash,
        use_time: UnixMillis,
        pre_transition_sequence: ChainSequence,
    }

    type VerifyAuthorizationFn = fn(
        &PreviousHeadState,
        ObjectHash,
        ObjectHash,
        UnixMillis,
        ChainSequence,
        &mut AdminAuthorizationReplay,
    ) -> Result<VerifiedAdminAuthorization, TrustError>;

    #[test]
    fn admin_authorization_historical_matrix_is_closed() {
        let _closed_verifier: VerifyAuthorizationFn = verify_admin_authorization;

        for use_time in [UnixMillis::new(100), UnixMillis::new(200)] {
            let fixture = build_fixture(&CaseSpec {
                use_time,
                ..CaseSpec::default()
            });
            expect_success(&fixture, &mut AdminAuthorizationReplay::default());
        }

        for (use_time, expected) in [
            (UnixMillis::new(99), TrustError::AuthNotYetValid),
            (UnixMillis::new(201), TrustError::AuthExpired),
        ] {
            let fixture = build_fixture(&CaseSpec {
                use_time,
                ..CaseSpec::default()
            });
            expect_error(&fixture, &mut AdminAuthorizationReplay::default(), expected);
        }

        let invalid_shape = TrustPayloadV1::organization_admin_authorization(authorization_fields(
            &CaseSpec {
                issued_at: UnixMillis::new(200),
                expires_at: UnixMillis::new(200),
                ..CaseSpec::default()
            },
            hash32(0x99),
            CertificateHash::try_from(&[0x11; 32][..]).unwrap(),
            ObjectHash::from(hash32(0x12)),
            key_thumbprint(0x13),
            TrustSubtypeV1::DeviceCertificate,
        ))
        .err()
        .expect("issuedAt >= expiresAt must be rejected before proof construction");
        assert_eq!(invalid_shape.code(), "EA-FORMAT-SHAPE");

        let historical_head = build_fixture(&CaseSpec {
            state_registry_version: RegistryVersion::new(7),
            state_registry_head_hash: hash32(0x77),
            authorization_registry_version: RegistryVersion::new(7),
            authorization_registry_head_hash: hash32(0x77),
            ..CaseSpec::default()
        });
        expect_success(&historical_head, &mut AdminAuthorizationReplay::default());

        let attacks = [
            (
                "historical authorization version must match the Previous Head",
                CaseSpec {
                    state_registry_version: RegistryVersion::new(7),
                    state_registry_head_hash: hash32(0x77),
                    authorization_registry_version: RegistryVersion::new(8),
                    authorization_registry_head_hash: hash32(0x77),
                    ..CaseSpec::default()
                },
                TrustError::ActionMismatch,
            ),
            (
                "historical authorization hash must match the Previous Head",
                CaseSpec {
                    state_registry_version: RegistryVersion::new(7),
                    state_registry_head_hash: hash32(0x77),
                    authorization_registry_version: RegistryVersion::new(7),
                    authorization_registry_head_hash: hash32(0x78),
                    ..CaseSpec::default()
                },
                TrustError::ActionMismatch,
            ),
            (
                "Registry version is not the Previous Head",
                CaseSpec {
                    authorization_registry_version: RegistryVersion::new(9),
                    ..CaseSpec::default()
                },
                TrustError::ActionMismatch,
            ),
            (
                "persisted unverified pin is never the Registry-0 head",
                CaseSpec {
                    authorization_registry_head_hash: hash32(0x99),
                    ..CaseSpec::default()
                },
                TrustError::ActionMismatch,
            ),
            (
                "Root cannot replace the Admin authorization signature",
                CaseSpec {
                    admin_signature_actor: SignatureActor::Root,
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                "Admin cannot replace the target Root signature",
                CaseSpec {
                    target_signature_actor: SignatureActor::AdminOne,
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                "authorization signature mutation",
                CaseSpec {
                    mutate_admin_signature: true,
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                "target signature mutation",
                CaseSpec {
                    mutate_target_signature: true,
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                "an unauthenticated extra target signature cannot be ignored",
                CaseSpec {
                    add_invalid_target_signature: true,
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                "a cryptographically valid Admin signature is not target Root authority",
                CaseSpec {
                    add_valid_admin_target_signature: true,
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                "duplicate Previous-Root signatures are not a canonical signer set",
                CaseSpec {
                    add_duplicate_root_signature: true,
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                "wrong authorized core hash",
                CaseSpec {
                    core_hash_override: Some(hash32(0x98)),
                    ..CaseSpec::default()
                },
                TrustError::ActionMismatch,
            ),
            (
                "wrong action derived from an Admin target",
                CaseSpec {
                    action: 0,
                    ..CaseSpec::default()
                },
                TrustError::ActionMismatch,
            ),
            (
                "wrong target subtype",
                CaseSpec {
                    target_subtype_override: Some(TrustSubtypeV1::OperatorBinding),
                    action: 4,
                    ..CaseSpec::default()
                },
                TrustError::ActionMismatch,
            ),
            (
                "target wrapper points at another authorization",
                CaseSpec {
                    target_authorization_hash_override: Some(ObjectHash::from(hash32(0x97))),
                    ..CaseSpec::default()
                },
                TrustError::ActionMismatch,
            ),
            (
                "wrong Admin key thumbprint",
                CaseSpec {
                    admin_key_thumbprint_override: Some(key_thumbprint(0x96)),
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                "wrong Admin certificate",
                CaseSpec {
                    admin_certificate_index: 1,
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                "a prepared Admin in the catalog is not Previous-Head authority",
                CaseSpec {
                    admin_certificate_index: 2,
                    admin_binding_index: 2,
                    admin_signature_actor: SignatureActor::AdminThree,
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                "certificate and Binding are not correlated",
                CaseSpec {
                    admin_binding_index: 1,
                    ..CaseSpec::default()
                },
                TrustError::SubjectMismatch,
            ),
            (
                "certificate is not yet active",
                CaseSpec {
                    admin_effective_from: ChainSequence::new(1),
                    ..CaseSpec::default()
                },
                TrustError::SignerInactive,
            ),
            (
                "certificate is inactive at the revocation boundary",
                CaseSpec {
                    admin_revoked_from: Some(ChainSequence::new(1)),
                    pre_transition_sequence: ChainSequence::new(1),
                    ..CaseSpec::default()
                },
                TrustError::SignerInactive,
            ),
            (
                "Binding is not yet active",
                CaseSpec {
                    binding_effective_from: ChainSequence::new(1),
                    ..CaseSpec::default()
                },
                TrustError::SignerInactive,
            ),
            (
                "Binding is inactive at the revocation boundary",
                CaseSpec {
                    binding_revoked_from: Some(ChainSequence::new(1)),
                    pre_transition_sequence: ChainSequence::new(1),
                    ..CaseSpec::default()
                },
                TrustError::SignerInactive,
            ),
            (
                "a distinct certificate/key/device cannot hide the same Admin person",
                CaseSpec {
                    target: TargetSpec::AdminDevice {
                        subject: 0x41,
                        device: 0x61,
                    },
                    ..CaseSpec::default()
                },
                TrustError::SelfAuthorization,
            ),
            (
                "Change 5 Effect 1 cannot revoke the signing Admin",
                CaseSpec {
                    target: TargetSpec::RevokeAdmin { index: 0 },
                    event_issued_at: UnixMillis::new(100),
                    ..CaseSpec::default()
                },
                TrustError::SelfAuthorization,
            ),
            (
                "another active certificate cannot hide the signing Admin subject",
                CaseSpec {
                    activate_prepared_admin: true,
                    target: TargetSpec::RevokeAdmin { index: 2 },
                    event_issued_at: UnixMillis::new(100),
                    ..CaseSpec::default()
                },
                TrustError::SelfAuthorization,
            ),
            (
                "Change 1 cannot revoke an Admin certificate",
                CaseSpec {
                    action: 1,
                    target: TargetSpec::ChangeOneAdmin { index: 1 },
                    ..CaseSpec::default()
                },
                TrustError::ActionMismatch,
            ),
        ];
        for (label, spec, expected) in attacks {
            let fixture = build_fixture(&spec);
            expect_error(&fixture, &mut AdminAuthorizationReplay::default(), expected);
            assert!(!label.is_empty());
        }

        let other_admin_revocation = build_fixture(&CaseSpec {
            target: TargetSpec::RevokeAdmin { index: 1 },
            event_issued_at: UnixMillis::new(200),
            use_time: UnixMillis::new(200),
            ..CaseSpec::default()
        });
        expect_success(
            &other_admin_revocation,
            &mut AdminAuthorizationReplay::default(),
        );

        for future_revocation in [
            CaseSpec {
                admin_revoked_from: Some(ChainSequence::new(1)),
                ..CaseSpec::default()
            },
            CaseSpec {
                binding_revoked_from: Some(ChainSequence::new(1)),
                ..CaseSpec::default()
            },
        ] {
            let fixture = build_fixture(&future_revocation);
            expect_success(&fixture, &mut AdminAuthorizationReplay::default());
        }

        let event_time_mismatch = build_fixture(&CaseSpec {
            target: TargetSpec::RevokeAdmin { index: 1 },
            event_issued_at: UnixMillis::new(150),
            use_time: UnixMillis::new(151),
            ..CaseSpec::default()
        });
        expect_error(
            &event_time_mismatch,
            &mut AdminAuthorizationReplay::default(),
            TrustError::ActionMismatch,
        );

        let base = build_fixture(&CaseSpec::default());
        let mut replay = AdminAuthorizationReplay::default();
        expect_success(&base, &mut replay);
        expect_error(&base, &mut replay, TrustError::AuthReplay);

        let same_id_other_nonce = build_fixture(&CaseSpec {
            nonce: 0xb2,
            ..CaseSpec::default()
        });
        expect_error(&same_id_other_nonce, &mut replay, TrustError::AuthReplay);
        let fresh_id_with_unconsumed_nonce = build_fixture(&CaseSpec {
            authorization_id: 0xa2,
            nonce: 0xb2,
            ..CaseSpec::default()
        });
        expect_success(&fresh_id_with_unconsumed_nonce, &mut replay);

        let mut nonce_replay = AdminAuthorizationReplay::default();
        expect_success(&base, &mut nonce_replay);
        let other_id_same_nonce = build_fixture(&CaseSpec {
            authorization_id: 0xa2,
            ..CaseSpec::default()
        });
        expect_error(
            &other_id_same_nonce,
            &mut nonce_replay,
            TrustError::AuthReplay,
        );
        let unconsumed_id_with_fresh_nonce = build_fixture(&CaseSpec {
            authorization_id: 0xa2,
            nonce: 0xb2,
            ..CaseSpec::default()
        });
        expect_success(&unconsumed_id_with_fresh_nonce, &mut nonce_replay);

        let failed_does_not_consume = build_fixture(&CaseSpec::default());
        let mut staged = AdminAuthorizationReplay::default();
        let failed = verify_admin_authorization(
            &failed_does_not_consume.verified.inner.previous_head,
            failed_does_not_consume.authorization_hash,
            failed_does_not_consume.target_hash,
            UnixMillis::new(99),
            failed_does_not_consume.pre_transition_sequence,
            &mut staged,
        )
        .err()
        .expect("the out-of-range attempt must fail");
        assert_eq!(failed, TrustError::AuthNotYetValid);
        expect_success(&failed_does_not_consume, &mut staged);

        for (late_failure, expected) in [
            (
                CaseSpec {
                    mutate_target_signature: true,
                    ..CaseSpec::default()
                },
                TrustError::Signature,
            ),
            (
                CaseSpec {
                    admin_binding_index: 1,
                    ..CaseSpec::default()
                },
                TrustError::SubjectMismatch,
            ),
            (
                CaseSpec {
                    action: 0,
                    ..CaseSpec::default()
                },
                TrustError::ActionMismatch,
            ),
            (
                CaseSpec {
                    target: TargetSpec::AdminDevice {
                        subject: 0x41,
                        device: 0x61,
                    },
                    ..CaseSpec::default()
                },
                TrustError::SelfAuthorization,
            ),
        ] {
            let invalid = build_fixture(&late_failure);
            let mut staged = AdminAuthorizationReplay::default();
            let error = verify_admin_authorization(
                &invalid.verified.inner.previous_head,
                invalid.authorization_hash,
                invalid.target_hash,
                invalid.use_time,
                invalid.pre_transition_sequence,
                &mut staged,
            )
            .err()
            .expect("late proof failure must fail closed");
            assert_eq!(error, expected);
            let valid = build_fixture(&CaseSpec::default());
            expect_success(&valid, &mut staged);
        }

        for error in [
            TrustError::SelfAuthorization,
            TrustError::AuthReplay,
            TrustError::AuthNotYetValid,
            TrustError::AuthExpired,
            TrustError::ActionMismatch,
        ] {
            assert_eq!(error.to_string(), error.code());
            assert_eq!(format!("{error:?}"), error.code());
        }
    }

    fn expect_success(fixture: &Fixture, replay: &mut AdminAuthorizationReplay) {
        let proof = verify_admin_authorization(
            &fixture.verified.inner.previous_head,
            fixture.authorization_hash,
            fixture.target_hash,
            fixture.use_time,
            fixture.pre_transition_sequence,
            replay,
        )
        .expect("the complete historical proof must succeed");
        assert!(proof.authorization_object_hash() == fixture.authorization_hash);
        assert!(proof.target_object_hash() == fixture.target_hash);
        assert!(
            proof.previous_registry_version()
                == fixture.verified.inner.previous_head.registry_version
        );
        assert!(
            proof.previous_registry_head_hash()
                == fixture.verified.inner.previous_head.registry_head_hash
        );
        assert!(proof.signer_authority_subject_id().as_bytes() == &[0x41; 16]);
    }

    fn expect_error(
        fixture: &Fixture,
        replay: &mut AdminAuthorizationReplay,
        expected: TrustError,
    ) {
        let error = verify_admin_authorization(
            &fixture.verified.inner.previous_head,
            fixture.authorization_hash,
            fixture.target_hash,
            fixture.use_time,
            fixture.pre_transition_sequence,
            replay,
        )
        .err()
        .expect("attack must fail closed");
        assert_eq!(error, expected);
    }

    fn build_fixture(spec: &CaseSpec) -> Fixture {
        let root_bytes = exact_root_certificate();
        let root_hash = object_hash(&root_bytes);
        let root_certificate_hash = CertificateHash::from(root_hash);
        let admin_bytes =
            exact_admin_certificate(root_certificate_hash, ADMIN_PUBLIC, 0x51, 0x41, None);
        let second_admin_bytes =
            exact_admin_certificate(root_certificate_hash, ADMIN_TWO_PUBLIC, 0x52, 0x42, None);
        let bootstrap_admin_hashes = [object_hash(&admin_bytes), object_hash(&second_admin_bytes)];
        let binding_bytes = exact_admin_binding(
            root_certificate_hash,
            CertificateHash::from(bootstrap_admin_hashes[0]),
            0x41,
            0x81,
            0x91,
            None,
        );
        let second_binding_bytes = exact_admin_binding(
            root_certificate_hash,
            CertificateHash::from(bootstrap_admin_hashes[1]),
            0x42,
            0x82,
            0x92,
            None,
        );
        let bootstrap_binding_hashes = [
            object_hash(&binding_bytes),
            object_hash(&second_binding_bytes),
        ];

        let prepared_certificate_fields = DeviceCertificateFieldsV1 {
            organization_id: organization(),
            device_id: DeviceId::try_from(&[0x63; 16][..]).unwrap(),
            certificate_kind: CertificateKindV1::OrganizationAdmin,
            signing_public_cose_key: Some(
                CanonicalPublicCoseKey::ed25519(ADMIN_THREE_PUBLIC)
                    .unwrap()
                    .to_deterministic_cbor(),
            ),
            kem_public_cose_key: None,
            signing_key_thumbprint: Some(admin_key(2).thumbprint()),
            kem_key_thumbprint: None,
            capabilities: vec!["organizationAdminApprove".into()],
            key_protection_profile: KeyProtectionProfileV1::OsWrapped,
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence: None,
            authority_subject_id: Some(SubjectId::try_from(&[0x41; 16][..]).unwrap()),
        };
        let provisional_prepared_certificate = TrustPayloadV1::authorized_device_certificate(
            prepared_certificate_fields.clone(),
            ObjectHash::from(Hash32::ZERO),
        )
        .unwrap();
        let prepared_certificate_authorization_bytes = exact_prepared_authorization(
            &provisional_prepared_certificate,
            5,
            0xc1,
            0xd1,
            CertificateHash::from(bootstrap_admin_hashes[0]),
            bootstrap_binding_hashes[0],
        );
        let prepared_certificate_payload = TrustPayloadV1::authorized_device_certificate(
            prepared_certificate_fields.clone(),
            object_hash(&prepared_certificate_authorization_bytes),
        )
        .unwrap();
        let prepared_certificate_signature = signed_normal(
            SignatureActor::Root,
            root_certificate_hash,
            trust_digest(prepared_certificate_payload.exact_digest_input()).as_bytes(),
        );
        let prepared_certificate_bytes = encode_trust(
            &TrustObjectV1::new(
                prepared_certificate_payload,
                vec![prepared_certificate_signature],
            )
            .unwrap(),
        )
        .unwrap()
        .into_vec();
        let prepared_certificate_hash = object_hash(&prepared_certificate_bytes);

        let prepared_binding_fields = OperatorBindingFieldsV1 {
            organization_id: organization(),
            operator_subject_id: OperatorSubjectId::try_from(&[0x41; 16][..]).unwrap(),
            operator_profile_commitment: hash32(0x84),
            device_certificate_hash: CertificateHash::from(prepared_certificate_hash),
            operator_role: OperatorRoleV1::OrganizationAdmin,
            os_account_binding_hash: hash32(0x85),
            operator_instance_key_thumbprint: key_thumbprint(0x86),
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence: None,
        };
        let provisional_prepared_binding = TrustPayloadV1::authorized_operator_binding(
            prepared_binding_fields.clone(),
            ObjectHash::from(Hash32::ZERO),
        )
        .unwrap();
        let prepared_binding_authorization_bytes = exact_prepared_authorization(
            &provisional_prepared_binding,
            4,
            0xc2,
            0xd2,
            CertificateHash::from(bootstrap_admin_hashes[0]),
            bootstrap_binding_hashes[0],
        );
        let prepared_binding_payload = TrustPayloadV1::authorized_operator_binding(
            prepared_binding_fields.clone(),
            object_hash(&prepared_binding_authorization_bytes),
        )
        .unwrap();
        let prepared_binding_signature = signed_normal(
            SignatureActor::Root,
            root_certificate_hash,
            trust_digest(prepared_binding_payload.exact_digest_input()).as_bytes(),
        );
        let prepared_binding_bytes = encode_trust(
            &TrustObjectV1::new(prepared_binding_payload, vec![prepared_binding_signature])
                .unwrap(),
        )
        .unwrap()
        .into_vec();
        let prepared_binding_hash = object_hash(&prepared_binding_bytes);

        let admin_hashes = [
            bootstrap_admin_hashes[0],
            bootstrap_admin_hashes[1],
            prepared_certificate_hash,
        ];
        let binding_hashes = [
            bootstrap_binding_hashes[0],
            bootstrap_binding_hashes[1],
            prepared_binding_hash,
        ];

        let provisional_target = target_payload(
            spec,
            ObjectHash::from(Hash32::ZERO),
            &admin_hashes,
            root_key().thumbprint(),
        );
        let core_hash = spec.core_hash_override.unwrap_or_else(|| {
            authorized_trust_digest(&authorized_core_input(&provisional_target))
        });
        let actual_target_subtype = provisional_target.subtype();
        let authorization = TrustPayloadV1::organization_admin_authorization(authorization_fields(
            spec,
            core_hash,
            CertificateHash::from(admin_hashes[spec.admin_certificate_index]),
            binding_hashes[spec.admin_binding_index],
            spec.admin_key_thumbprint_override
                .unwrap_or_else(|| admin_key(spec.admin_certificate_index).thumbprint()),
            spec.target_subtype_override
                .unwrap_or(actual_target_subtype),
        ))
        .expect("test authorization shape must be valid");
        let mut authorization_signature =
            sign_admin_authorization(spec, &authorization, root_certificate_hash, &admin_hashes);
        if spec.mutate_admin_signature {
            let last = authorization_signature.len() - 1;
            authorization_signature[last] ^= 1;
        }
        let authorization_bytes = encode_trust(
            &TrustObjectV1::new(authorization, vec![authorization_signature]).unwrap(),
        )
        .unwrap()
        .into_vec();
        let authorization_hash = object_hash(&authorization_bytes);

        let linked_authorization_hash = spec
            .target_authorization_hash_override
            .unwrap_or(authorization_hash);
        let target = target_payload(
            spec,
            linked_authorization_hash,
            &admin_hashes,
            root_key().thumbprint(),
        );
        let mut target_signature = root_sign_target(
            spec.target_signature_actor,
            root_certificate_hash,
            &target,
            &admin_hashes,
        );
        if spec.mutate_target_signature {
            let last = target_signature.len() - 1;
            target_signature[last] ^= 1;
        }
        let mut target_signatures = vec![target_signature];
        if spec.add_invalid_target_signature {
            target_signatures.push(opaque_signature(
                admin_key(0).thumbprint(),
                CertificateHash::from(admin_hashes[0]),
                trust_digest(target.exact_digest_input()).as_bytes(),
            ));
        }
        if spec.add_valid_admin_target_signature {
            target_signatures.push(signed_normal(
                SignatureActor::AdminOne,
                CertificateHash::from(admin_hashes[0]),
                trust_digest(target.exact_digest_input()).as_bytes(),
            ));
        }
        if spec.add_duplicate_root_signature {
            target_signatures.push(target_signatures[0].clone());
        }
        target_signatures.sort_by_key(|signature| {
            let parsed = parse_cose_sign1(signature, &[]).unwrap();
            (parsed.certificate_hash(), parsed.key_thumbprint())
        });
        let target_bytes = encode_trust(&TrustObjectV1::new(target, target_signatures).unwrap())
            .unwrap()
            .into_vec();
        let target_hash = object_hash(&target_bytes);

        let source = CatalogSource::new([
            root_bytes,
            admin_bytes,
            second_admin_bytes,
            binding_bytes,
            second_binding_bytes,
            prepared_certificate_authorization_bytes,
            prepared_certificate_bytes,
            prepared_binding_authorization_bytes,
            prepared_binding_bytes,
            authorization_bytes,
            target_bytes,
        ]);
        let anchor = decode_trust_anchor(&exact_anchor(
            root_hash,
            &admin_hashes[..2],
            &binding_hashes[..2],
        ))
        .unwrap();
        let state_key = TrustStateKey {
            organization_id: organization(),
            device_id: DeviceId::try_from(&[0xf0; 16][..]).unwrap(),
        };
        let mut store = SnapshotStore {
            key: state_key,
            record: Some(PersistedTrustRecord::new(
                7,
                TrustedTimeState::initial(UnixMillis::new(1_700_000_000_000)),
                Some(RegistryHeadPin::new(RegistryVersion::new(9), target_hash)),
            )),
        };
        let snapshot = load_trust_state(&mut store, state_key).unwrap();
        let mut verified = verify_trust(&anchor, &source, snapshot).unwrap();
        drop(source);

        let inner = Arc::get_mut(&mut verified.inner).expect("fixture proof is uniquely owned");
        let previous = &mut inner.previous_head;
        previous.registry_version = spec.state_registry_version;
        previous.registry_head_hash = spec.state_registry_head_hash;
        if spec.activate_prepared_admin {
            previous.admin_certificates.insert(
                CertificateHash::from(prepared_certificate_hash),
                ActiveCertificate {
                    object_hash: prepared_certificate_hash,
                    fields: prepared_certificate_fields,
                },
            );
            previous.admin_bindings.insert(
                prepared_binding_hash,
                ActiveOperatorBinding {
                    object_hash: prepared_binding_hash,
                    fields: prepared_binding_fields,
                },
            );
        }
        if let Some(active_certificate) = previous.admin_certificates.get_mut(
            &CertificateHash::from(admin_hashes[spec.admin_certificate_index]),
        ) {
            active_certificate.fields.effective_from_sequence = spec.admin_effective_from;
            active_certificate.fields.revoked_from_sequence = spec.admin_revoked_from;
        }
        if let Some(active_binding) = previous
            .admin_bindings
            .get_mut(&binding_hashes[spec.admin_binding_index])
        {
            active_binding.fields.effective_from_sequence = spec.binding_effective_from;
            active_binding.fields.revoked_from_sequence = spec.binding_revoked_from;
        }

        Fixture {
            verified,
            authorization_hash,
            target_hash,
            use_time: spec.use_time,
            pre_transition_sequence: spec.pre_transition_sequence,
        }
    }

    fn authorization_fields(
        spec: &CaseSpec,
        authorized_trust_core_hash: Hash32,
        admin_certificate_hash: CertificateHash,
        admin_operator_binding_object_hash: ObjectHash,
        admin_key_thumbprint: KeyThumbprint,
        target_trust_subtype: TrustSubtypeV1,
    ) -> OrganizationAdminAuthorizationFieldsV1 {
        OrganizationAdminAuthorizationFieldsV1 {
            authorization_id: AuthorizationId::try_from(&[spec.authorization_id; 16][..]).unwrap(),
            organization_id: organization(),
            registry_version: spec.authorization_registry_version,
            registry_head_hash: spec.authorization_registry_head_hash,
            admin_key_thumbprint,
            admin_certificate_hash,
            admin_operator_binding_object_hash,
            action_code: spec.action,
            target_trust_subtype,
            authorized_trust_core_hash,
            issued_at: spec.issued_at,
            expires_at: spec.expires_at,
            nonce: [spec.nonce; 32],
        }
    }

    fn exact_prepared_authorization(
        provisional_target: &TrustPayloadV1,
        action_code: u8,
        authorization_id: u8,
        nonce: u8,
        admin_certificate_hash: CertificateHash,
        admin_binding_hash: ObjectHash,
    ) -> Vec<u8> {
        let authorization = TrustPayloadV1::organization_admin_authorization(
            OrganizationAdminAuthorizationFieldsV1 {
                authorization_id: AuthorizationId::try_from(&[authorization_id; 16][..]).unwrap(),
                organization_id: organization(),
                registry_version: RegistryVersion::new(0),
                registry_head_hash: Hash32::ZERO,
                admin_key_thumbprint: admin_key(0).thumbprint(),
                admin_certificate_hash,
                admin_operator_binding_object_hash: admin_binding_hash,
                action_code,
                target_trust_subtype: provisional_target.subtype(),
                authorized_trust_core_hash: authorized_trust_digest(&authorized_core_input(
                    provisional_target,
                )),
                issued_at: UnixMillis::new(10),
                expires_at: UnixMillis::new(500),
                nonce: [nonce; 32],
            },
        )
        .unwrap();
        let signature = signed_normal(
            SignatureActor::AdminOne,
            admin_certificate_hash,
            trust_digest(authorization.exact_digest_input()).as_bytes(),
        );
        encode_trust(&TrustObjectV1::new(authorization, vec![signature]).unwrap())
            .unwrap()
            .into_vec()
    }

    fn target_payload(
        spec: &CaseSpec,
        authorization_hash: ObjectHash,
        admin_hashes: &[ObjectHash; 3],
        root_key_thumbprint: KeyThumbprint,
    ) -> TrustPayloadV1 {
        match spec.target {
            TargetSpec::AdminDevice { subject, device } => {
                TrustPayloadV1::authorized_device_certificate(
                    DeviceCertificateFieldsV1 {
                        organization_id: organization(),
                        device_id: DeviceId::try_from(&[device; 16][..]).unwrap(),
                        certificate_kind: CertificateKindV1::OrganizationAdmin,
                        signing_public_cose_key: Some(
                            CanonicalPublicCoseKey::ed25519(ADMIN_THREE_PUBLIC)
                                .unwrap()
                                .to_deterministic_cbor(),
                        ),
                        kem_public_cose_key: None,
                        signing_key_thumbprint: Some(
                            CanonicalPublicCoseKey::ed25519(ADMIN_THREE_PUBLIC)
                                .unwrap()
                                .thumbprint(),
                        ),
                        kem_key_thumbprint: None,
                        capabilities: vec!["organizationAdminApprove".into()],
                        key_protection_profile: KeyProtectionProfileV1::OsWrapped,
                        effective_from_sequence: ChainSequence::new(1),
                        revoked_from_sequence: None,
                        authority_subject_id: Some(
                            SubjectId::try_from(&[subject; 16][..]).unwrap(),
                        ),
                    },
                    authorization_hash,
                )
                .unwrap()
            }
            TargetSpec::RevokeAdmin { index } => TrustPayloadV1::registry_event(
                registry_event_fields(
                    spec,
                    root_key_thumbprint,
                    RegistryChangeV1::AdminCertificate {
                        object_hash: admin_hashes[index],
                        effect: 1,
                    },
                ),
                authorization_hash,
            )
            .unwrap(),
            TargetSpec::ChangeOneAdmin { index } => TrustPayloadV1::registry_event(
                registry_event_fields(
                    spec,
                    root_key_thumbprint,
                    RegistryChangeV1::Target {
                        target_kind: 0,
                        object_hash: admin_hashes[index],
                    },
                ),
                authorization_hash,
            )
            .unwrap(),
        }
    }

    fn registry_event_fields(
        spec: &CaseSpec,
        root_key_thumbprint: KeyThumbprint,
        change: RegistryChangeV1,
    ) -> RegistryEventFieldsV1 {
        RegistryEventFieldsV1 {
            organization_id: organization(),
            registry_version: RegistryVersion::new(1),
            previous_registry_hash: None,
            effective_from_sequence: ChainSequence::new(1),
            valid_through_sequence: ChainSequence::new(100),
            issued_at: spec.event_issued_at,
            not_before: UnixMillis::new(90),
            not_after: UnixMillis::new(500),
            policy_object_hash: ObjectHash::from(hash32(0x55)),
            change,
            root_key_thumbprint,
        }
    }

    fn authorized_core_input(payload: &TrustPayloadV1) -> Vec<u8> {
        let exact = payload.exact_payload();
        let mut decoder = Decoder::new(exact);
        assert_eq!(decoder.array().unwrap(), Some(2));
        let core_start = decoder.position();
        decoder.skip().unwrap();
        let core_end = decoder.position();
        assert_eq!(decoder.bytes().unwrap().len(), 32);
        assert_eq!(decoder.position(), exact.len());

        let mut input = Vec::new();
        Encoder::new(&mut input)
            .array(2)
            .unwrap()
            .str(payload.subtype().as_str())
            .unwrap();
        input.extend_from_slice(&exact[core_start..core_end]);
        input
    }

    fn sign_admin_authorization(
        spec: &CaseSpec,
        payload: &TrustPayloadV1,
        root_certificate_hash: CertificateHash,
        admin_hashes: &[ObjectHash; 3],
    ) -> Vec<u8> {
        signed_normal(
            spec.admin_signature_actor,
            actor_certificate_hash(
                spec.admin_signature_actor,
                root_certificate_hash,
                admin_hashes,
            ),
            trust_digest(payload.exact_digest_input()).as_bytes(),
        )
    }

    fn root_sign_target(
        actor: SignatureActor,
        root_hash: CertificateHash,
        payload: &TrustPayloadV1,
        admin_hashes: &[ObjectHash; 3],
    ) -> Vec<u8> {
        signed_normal(
            actor,
            actor_certificate_hash(actor, root_hash, admin_hashes),
            trust_digest(payload.exact_digest_input()).as_bytes(),
        )
    }

    fn actor_certificate_hash(
        actor: SignatureActor,
        root_hash: CertificateHash,
        admin_hashes: &[ObjectHash; 3],
    ) -> CertificateHash {
        match actor {
            SignatureActor::Root => root_hash,
            SignatureActor::AdminOne => CertificateHash::from(admin_hashes[0]),
            SignatureActor::AdminThree => CertificateHash::from(admin_hashes[2]),
        }
    }

    fn signed_normal(
        actor: SignatureActor,
        certificate_hash: CertificateHash,
        payload: &[u8],
    ) -> Vec<u8> {
        let protected = ProtectedHeader::normal(
            ContentType::TrustDigest,
            actor_key(actor).thumbprint(),
            certificate_hash,
        );
        let signature = SigningKey::from_bytes(actor_secret(actor))
            .sign(&protected.sig_structure_bytes(payload))
            .to_bytes();
        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .tag(minicbor::data::Tag::new(18))
            .unwrap()
            .array(4)
            .unwrap()
            .bytes(&protected.to_deterministic_cbor())
            .unwrap()
            .map(0)
            .unwrap()
            .bytes(payload)
            .unwrap()
            .bytes(&signature)
            .unwrap();
        encoded
    }

    fn opaque_signature(
        key_thumbprint: KeyThumbprint,
        certificate_hash: CertificateHash,
        payload: &[u8],
    ) -> Vec<u8> {
        let protected =
            ProtectedHeader::normal(ContentType::TrustDigest, key_thumbprint, certificate_hash)
                .to_deterministic_cbor();
        let mut signature = Vec::new();
        Encoder::new(&mut signature)
            .tag(minicbor::data::Tag::new(18))
            .unwrap()
            .array(4)
            .unwrap()
            .bytes(&protected)
            .unwrap()
            .map(0)
            .unwrap()
            .bytes(payload)
            .unwrap()
            .bytes(&[0x5a; 64])
            .unwrap();
        signature
    }

    fn actor_secret(actor: SignatureActor) -> &'static [u8; 32] {
        match actor {
            SignatureActor::Root => &ROOT_SECRET,
            SignatureActor::AdminOne => &ADMIN_ONE_SECRET,
            SignatureActor::AdminThree => &ADMIN_THREE_SECRET,
        }
    }

    fn actor_key(actor: SignatureActor) -> CanonicalPublicCoseKey {
        match actor {
            SignatureActor::Root => root_key(),
            SignatureActor::AdminOne => admin_key(0),
            SignatureActor::AdminThree => admin_key(2),
        }
    }

    fn root_key() -> CanonicalPublicCoseKey {
        CanonicalPublicCoseKey::ed25519(crate::resolver::tests::ROOT_PUBLIC).unwrap()
    }

    fn admin_key(index: usize) -> CanonicalPublicCoseKey {
        CanonicalPublicCoseKey::ed25519([ADMIN_PUBLIC, ADMIN_TWO_PUBLIC, ADMIN_THREE_PUBLIC][index])
            .unwrap()
    }
}
