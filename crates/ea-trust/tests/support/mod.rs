#![allow(dead_code)]

use std::{collections::BTreeMap, sync::Arc};

use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, CoseSigner, ProtectedHeader, SecretBytes,
    authorized_trust_digest, bootstrap_anchor_hash, object_hash, trust_digest,
};
use ea_format::{
    CertificateKindV1, DeviceCertificateFieldsV1, FreeTextPolicyFieldsV1, KeyProtectionProfileV1,
    OperatorBindingFieldsV1, OperatorRoleV1, OrganizationAdminAuthorizationFieldsV1,
    PolicyFieldsV1, RegistryChangeV1, RegistryEventFieldsV1, RetentionPolicyFieldsV1,
    RootCertificateFieldsV1, TrustObjectV1, TrustPayloadV1, TrustSubtypeV1,
    WriterTransitionFieldsV1, encode_trust,
};
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, StateStoreError, TrustObjectSource, TrustSourceError, TrustStateKey,
    TrustStateStore, VerifiedTrust, decode_trust_anchor, load_trust_state, verify_trust,
};
use ea_types::{
    AuthorizationId, CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, Hash32,
    KeyThumbprint, ObjectHash, OperatorSubjectId, OrganizationId, RegistryVersion, SubjectId,
    UnixMillis,
};
use ed25519_dalek::{Signer as _, SigningKey};
use minicbor::{Decoder, Encoder};

const ROOT_SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const ADMIN_ONE_SECRET: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];
const ADMIN_TWO_SECRET: [u8; 32] = [
    0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
    0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
];
const ROTATED_ROOT_SECRET: [u8; 32] = [
    0xf5, 0xe5, 0x76, 0x7c, 0xf1, 0x53, 0x31, 0x95, 0x17, 0x63, 0x0f, 0x22, 0x68, 0x76, 0xb8, 0x6c,
    0x81, 0x60, 0xcc, 0x58, 0x3b, 0xc0, 0x13, 0x74, 0x4c, 0x6b, 0xf2, 0x55, 0xf5, 0xcc, 0x0e, 0xe5,
];
const NEW_ADMIN_SECRET: [u8; 32] = [
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
];

#[derive(Clone, Copy)]
pub enum PreviousHash {
    Exact,
    Null,
    Value(Hash32),
}

#[derive(Clone)]
pub enum ChangeOverride {
    Exact,
    CertificateFromDirect,
    TargetFromDirect(u8),
    PolicyFromDirect,
    WriterTransitionFromDirect,
    OperatorBindingFromDirect,
    AdminFromDirect(u8),
    RootFromDirect,
    Raw(RegistryChangeV1),
}

#[derive(Clone, Copy)]
pub enum RootSigner {
    Previous,
    Rotated,
    Corrupt,
}

#[derive(Clone, Copy)]
pub enum AuthorizationSigner {
    InitialAdmin,
    NewAdmin {
        certificate_hash: ObjectHash,
        binding_hash: ObjectHash,
    },
}

#[derive(Clone)]
pub struct HeadOptions {
    pub registry_version: Option<u64>,
    pub previous_hash: PreviousHash,
    pub effective_from: Option<u64>,
    pub valid_through: Option<u64>,
    pub issued_at: UnixMillis,
    pub not_before: UnixMillis,
    pub not_after: UnixMillis,
    pub policy_hash_override: Option<ObjectHash>,
    pub root_key_thumbprint_override: Option<KeyThumbprint>,
    pub policy_max_registry_age_ms_override: Option<u64>,
    pub certificate_capabilities_override: Option<Vec<String>>,
    pub revoked_from_sequence: Option<ChainSequence>,
    pub binding_instance_key_thumbprint_override: Option<KeyThumbprint>,
    pub writer_chain_id_override: Option<ChainId>,
    pub change_override: ChangeOverride,
    pub direct_authorization_action: Option<u8>,
    pub event_authorization_action: Option<u8>,
    pub direct_authorization_subtype: Option<TrustSubtypeV1>,
    pub event_authorization_subtype: Option<TrustSubtypeV1>,
    pub direct_authorization_basis: Option<(RegistryVersion, Hash32)>,
    pub event_authorization_basis: Option<(RegistryVersion, Hash32)>,
    pub direct_authorization_id: Option<u8>,
    pub event_authorization_id: Option<u8>,
    pub direct_nonce: Option<u8>,
    pub event_nonce: Option<u8>,
    pub omit_direct_object: bool,
    pub omit_direct_authorization: bool,
    pub omit_event_authorization: bool,
    pub root_signer: RootSigner,
    pub authorization_signer: AuthorizationSigner,
}

impl Default for HeadOptions {
    fn default() -> Self {
        Self {
            registry_version: None,
            previous_hash: PreviousHash::Exact,
            effective_from: None,
            valid_through: None,
            issued_at: UnixMillis::new(100),
            not_before: UnixMillis::new(90),
            not_after: UnixMillis::new(10_000),
            policy_hash_override: None,
            root_key_thumbprint_override: None,
            policy_max_registry_age_ms_override: None,
            certificate_capabilities_override: None,
            revoked_from_sequence: None,
            binding_instance_key_thumbprint_override: None,
            writer_chain_id_override: None,
            change_override: ChangeOverride::Exact,
            direct_authorization_action: None,
            event_authorization_action: None,
            direct_authorization_subtype: None,
            event_authorization_subtype: None,
            direct_authorization_basis: None,
            event_authorization_basis: None,
            direct_authorization_id: None,
            event_authorization_id: None,
            direct_nonce: None,
            event_nonce: None,
            omit_direct_object: false,
            omit_direct_authorization: false,
            omit_event_authorization: false,
            root_signer: RootSigner::Previous,
            authorization_signer: AuthorizationSigner::InitialAdmin,
        }
    }
}

#[derive(Clone)]
pub enum ActionSpec {
    Policy {
        policy_version: Option<u64>,
        previous_policy_hash: Option<Option<ObjectHash>>,
        effective_from: Option<u64>,
    },
    Device {
        kind: CertificateKindV1,
        marker: u8,
        effective_from: Option<u64>,
    },
    Revoke {
        target_kind: u8,
        object_hash: ObjectHash,
    },
    WriterTransition {
        old_writer: ObjectHash,
        new_writer: ObjectHash,
        effective_from: Option<u64>,
    },
    OperatorBinding {
        certificate_hash: ObjectHash,
        role: OperatorRoleV1,
        marker: u8,
        effective_from: Option<u64>,
    },
    AdminIssue {
        marker: u8,
        effective_from: Option<u64>,
    },
    AdminRevoke {
        object_hash: ObjectHash,
    },
    RootRotate {
        previous_root_hash: Option<ObjectHash>,
        effective_version: Option<u64>,
    },
}

impl ActionSpec {
    fn action_code(&self) -> u8 {
        match self {
            Self::Device { .. } => 0,
            Self::Revoke { .. } => 1,
            Self::Policy { .. } => 2,
            Self::WriterTransition { .. } => 3,
            Self::OperatorBinding { .. } => 4,
            Self::AdminIssue { .. } | Self::AdminRevoke { .. } => 5,
            Self::RootRotate { .. } => 6,
        }
    }

    fn has_direct_target(&self) -> bool {
        !matches!(self, Self::Revoke { .. } | Self::AdminRevoke { .. })
    }
}

#[derive(Clone, Copy)]
pub struct BuiltHead {
    pub version: RegistryVersion,
    pub object_hash: ObjectHash,
    pub direct_object_hash: Option<ObjectHash>,
    pub effective_from: ChainSequence,
    pub valid_through: ChainSequence,
}

#[derive(Clone, Copy)]
pub enum Pin {
    None,
    Head(usize),
    Exact(RegistryVersion, ObjectHash),
}

#[derive(Clone)]
struct RootActor {
    secret: [u8; 32],
    key: CanonicalPublicCoseKey,
    object_hash: ObjectHash,
}

#[derive(Clone)]
struct LineState {
    version: RegistryVersion,
    head_hash: Hash32,
    effective_from: ChainSequence,
    valid_through: ChainSequence,
    policy_hash: Option<ObjectHash>,
    policy_version: u64,
    root: RootActor,
}

#[derive(Clone)]
pub struct RegistryLineBuilder {
    objects: Vec<Vec<u8>>,
    anchor_bytes: Vec<u8>,
    admin_hash: ObjectHash,
    admin_binding_hash: ObjectHash,
    state: LineState,
    heads: Vec<BuiltHead>,
    transition_count: u8,
}

impl RegistryLineBuilder {
    pub fn new() -> Self {
        Self::with_first_admin_revoked_from(None)
    }

    pub fn with_first_admin_revoked_from(revoked_from_sequence: Option<ChainSequence>) -> Self {
        let root_key = key_from_secret(ROOT_SECRET);
        let root_payload = TrustPayloadV1::initial_root_certificate(RootCertificateFieldsV1 {
            organization_id: organization(),
            root_public_cose_key: root_key.to_deterministic_cbor(),
            root_key_thumbprint: root_key.thumbprint(),
            previous_root_certificate_object_hash: None,
            effective_from_registry_version: RegistryVersion::new(1),
        })
        .unwrap();
        let root_signature = CoseSigner::from_secret(SecretBytes::new(ROOT_SECRET))
            .sign_initial_root(trust_digest(root_payload.exact_digest_input()).as_bytes())
            .unwrap();
        let root_bytes = exact_object(root_payload, vec![root_signature]);
        let root_hash = object_hash(&root_bytes);
        let root_certificate_hash = CertificateHash::from(root_hash);

        let admin_one = initial_admin_certificate(
            root_certificate_hash,
            ADMIN_ONE_SECRET,
            0x51,
            0x41,
            revoked_from_sequence,
        );
        let admin_two =
            initial_admin_certificate(root_certificate_hash, ADMIN_TWO_SECRET, 0x52, 0x42, None);
        let admin_one_hash = object_hash(&admin_one);
        let admin_two_hash = object_hash(&admin_two);
        let binding_one = initial_admin_binding(
            root_certificate_hash,
            CertificateHash::from(admin_one_hash),
            0x41,
            0x81,
            0x91,
            revoked_from_sequence,
        );
        let binding_two = initial_admin_binding(
            root_certificate_hash,
            CertificateHash::from(admin_two_hash),
            0x42,
            0x82,
            0x92,
            None,
        );
        let binding_one_hash = object_hash(&binding_one);
        let binding_two_hash = object_hash(&binding_two);
        let anchor_bytes = exact_anchor(
            root_hash,
            &[admin_one_hash, admin_two_hash],
            &[binding_one_hash, binding_two_hash],
        );

        Self {
            objects: vec![root_bytes, admin_one, admin_two, binding_one, binding_two],
            anchor_bytes,
            admin_hash: admin_one_hash,
            admin_binding_hash: binding_one_hash,
            state: LineState {
                version: RegistryVersion::new(0),
                head_hash: Hash32::ZERO,
                effective_from: ChainSequence::new(0),
                valid_through: ChainSequence::new(0),
                policy_hash: None,
                policy_version: 0,
                root: RootActor {
                    secret: ROOT_SECRET,
                    key: root_key,
                    object_hash: root_hash,
                },
            },
            heads: Vec::new(),
            transition_count: 0,
        }
    }

    pub fn heads(&self) -> &[BuiltHead] {
        &self.heads
    }

    pub fn current_policy_hash(&self) -> Option<ObjectHash> {
        self.state.policy_hash
    }

    pub fn bootstrap_admin_hash(&self) -> ObjectHash {
        self.admin_hash
    }

    pub fn current_root_hash(&self) -> ObjectHash {
        self.state.root.object_hash
    }

    pub fn exact_object_bytes(&self, target: ObjectHash) -> &[u8] {
        self.objects
            .iter()
            .find(|bytes| object_hash(bytes) == target)
            .map(Vec::as_slice)
            .expect("fixture object must remain in the catalog")
    }

    pub fn push(&mut self, action: ActionSpec, options: HeadOptions) -> BuiltHead {
        let previous = self.state.clone();
        let next_default = previous.version.get().saturating_add(1);
        let version = RegistryVersion::new(options.registry_version.unwrap_or(next_default));
        let effective_from = ChainSequence::new(options.effective_from.unwrap_or_else(|| {
            if previous.version == RegistryVersion::new(0) {
                1
            } else {
                previous.valid_through.get().saturating_add(1)
            }
        }));
        let valid_through = ChainSequence::new(
            options
                .valid_through
                .unwrap_or_else(|| effective_from.get().saturating_add(99)),
        );
        let marker = self.transition_count;
        self.transition_count = self.transition_count.wrapping_add(1);
        let direct_id = options
            .direct_authorization_id
            .unwrap_or(0x20_u8.wrapping_add(marker.wrapping_mul(2)));
        let event_id = options
            .event_authorization_id
            .unwrap_or(0x21_u8.wrapping_add(marker.wrapping_mul(2)));
        let direct_nonce = options.direct_nonce.unwrap_or(direct_id.wrapping_add(0x40));
        let event_nonce = options.event_nonce.unwrap_or(event_id.wrapping_add(0x40));
        let (authorization_secret, authorization_admin_hash, authorization_binding_hash) =
            match options.authorization_signer {
                AuthorizationSigner::InitialAdmin => {
                    (ADMIN_ONE_SECRET, self.admin_hash, self.admin_binding_hash)
                }
                AuthorizationSigner::NewAdmin {
                    certificate_hash,
                    binding_hash,
                } => (NEW_ADMIN_SECRET, certificate_hash, binding_hash),
            };

        let mut direct_bytes = None;
        let mut direct_authorization_bytes = None;
        let mut direct_hash = None;
        if action.has_direct_target() {
            let provisional = direct_payload(
                &action,
                ObjectHash::from(Hash32::ZERO),
                effective_from,
                version,
                &previous,
                &options,
            );
            let (basis_version, basis_hash) = options
                .direct_authorization_basis
                .unwrap_or((previous.version, previous.head_hash));
            let authorization = exact_authorization(
                &provisional,
                options
                    .direct_authorization_action
                    .unwrap_or(action.action_code()),
                options
                    .direct_authorization_subtype
                    .unwrap_or(provisional.subtype()),
                direct_id,
                direct_nonce,
                basis_version,
                basis_hash,
                options.issued_at,
                authorization_secret,
                authorization_admin_hash,
                authorization_binding_hash,
            );
            let authorization_hash = object_hash(&authorization);
            let payload = direct_payload(
                &action,
                authorization_hash,
                effective_from,
                version,
                &previous,
                &options,
            );
            let signature = signed_normal(
                previous.root.secret,
                &previous.root.key,
                CertificateHash::from(previous.root.object_hash),
                trust_digest(payload.exact_digest_input()).as_bytes(),
            );
            let bytes = exact_object(payload, vec![signature]);
            direct_hash = Some(object_hash(&bytes));
            direct_bytes = Some(bytes);
            direct_authorization_bytes = Some(authorization);
        }

        let exact_change = exact_change(&action, direct_hash);
        let change = overridden_change(&options.change_override, direct_hash, exact_change);
        let target_policy = options
            .policy_hash_override
            .unwrap_or_else(|| match action {
                ActionSpec::Policy { .. } => {
                    direct_hash.expect("Policy transition has a direct target")
                }
                _ => previous
                    .policy_hash
                    .unwrap_or_else(|| ObjectHash::from(Hash32::ZERO)),
            });
        let previous_registry_hash = match options.previous_hash {
            PreviousHash::Exact if previous.version == RegistryVersion::new(0) => None,
            PreviousHash::Exact => Some(previous.head_hash),
            PreviousHash::Null => None,
            PreviousHash::Value(value) => Some(value),
        };
        let fields = RegistryEventFieldsV1 {
            organization_id: organization(),
            registry_version: version,
            previous_registry_hash,
            effective_from_sequence: effective_from,
            valid_through_sequence: valid_through,
            issued_at: options.issued_at,
            not_before: options.not_before,
            not_after: options.not_after,
            policy_object_hash: target_policy,
            change,
            root_key_thumbprint: options
                .root_key_thumbprint_override
                .unwrap_or_else(|| previous.root.key.thumbprint()),
        };
        let provisional_event =
            TrustPayloadV1::registry_event(fields.clone(), ObjectHash::from(Hash32::ZERO)).unwrap();
        let (event_basis_version, event_basis_hash) = options
            .event_authorization_basis
            .unwrap_or((previous.version, previous.head_hash));
        let event_authorization = exact_authorization(
            &provisional_event,
            options
                .event_authorization_action
                .unwrap_or(action.action_code()),
            options
                .event_authorization_subtype
                .unwrap_or(TrustSubtypeV1::RegistryEvent),
            event_id,
            event_nonce,
            event_basis_version,
            event_basis_hash,
            options.issued_at,
            authorization_secret,
            authorization_admin_hash,
            authorization_binding_hash,
        );
        let event_authorization_hash = object_hash(&event_authorization);
        let event_payload =
            TrustPayloadV1::registry_event(fields, event_authorization_hash).unwrap();
        let (event_secret, event_key) = match options.root_signer {
            RootSigner::Previous | RootSigner::Corrupt => {
                (previous.root.secret, previous.root.key.clone())
            }
            RootSigner::Rotated => (ROTATED_ROOT_SECRET, key_from_secret(ROTATED_ROOT_SECRET)),
        };
        let mut event_signature = signed_normal(
            event_secret,
            &event_key,
            CertificateHash::from(match options.root_signer {
                RootSigner::Rotated => direct_hash.unwrap_or(previous.root.object_hash),
                RootSigner::Previous | RootSigner::Corrupt => previous.root.object_hash,
            }),
            trust_digest(event_payload.exact_digest_input()).as_bytes(),
        );
        if matches!(options.root_signer, RootSigner::Corrupt) {
            let last = event_signature.len() - 1;
            event_signature[last] ^= 1;
        }
        let event_bytes = exact_object(event_payload, vec![event_signature]);
        let event_hash = object_hash(&event_bytes);

        if !options.omit_direct_authorization
            && let Some(bytes) = direct_authorization_bytes
        {
            self.objects.push(bytes);
        }
        if !options.omit_direct_object
            && let Some(bytes) = direct_bytes
        {
            self.objects.push(bytes);
        }
        if !options.omit_event_authorization {
            self.objects.push(event_authorization);
        }
        self.objects.push(event_bytes);

        let built = BuiltHead {
            version,
            object_hash: event_hash,
            direct_object_hash: direct_hash,
            effective_from,
            valid_through,
        };
        self.heads.push(built);
        self.state.version = version;
        self.state.head_hash = hash32_from_object(event_hash);
        self.state.effective_from = effective_from;
        self.state.valid_through = valid_through;
        if let ActionSpec::Policy { policy_version, .. } = action {
            self.state.policy_hash = direct_hash;
            self.state.policy_version = policy_version.unwrap_or(previous.policy_version + 1);
        }
        if matches!(action, ActionSpec::RootRotate { .. }) {
            self.state.root = RootActor {
                secret: ROTATED_ROOT_SECRET,
                key: key_from_secret(ROTATED_ROOT_SECRET),
                object_hash: direct_hash.expect("Root rotation has a direct target"),
            };
        }
        built
    }

    pub fn add_branch(&mut self, action: ActionSpec, options: HeadOptions) -> BuiltHead {
        let base_len = self.objects.len();
        let mut branch = self.clone();
        let head = branch.push(action, options);
        self.objects.extend(branch.objects.drain(base_len..));
        head
    }

    pub fn add_prepared(&mut self, action: ActionSpec) -> ObjectHash {
        assert!(action.has_direct_target());
        let base_len = self.objects.len();
        let mut branch = self.clone();
        let head = branch.push(action, HeadOptions::default());
        let mut added = branch.objects.drain(base_len..);
        self.objects
            .push(added.next().expect("prepared authorization object"));
        self.objects
            .push(added.next().expect("prepared direct target object"));
        head.direct_object_hash.expect("direct target hash")
    }

    pub fn remove_object(&mut self, target: ObjectHash) {
        self.objects.retain(|bytes| object_hash(bytes) != target);
    }

    pub fn verified(&self, pin: Pin) -> VerifiedTrust {
        self.verified_with_floor(pin, UnixMillis::new(1_700_000_000_000))
    }

    pub fn verified_with_floor(&self, pin: Pin, floor: UnixMillis) -> VerifiedTrust {
        let anchor = decode_trust_anchor(&self.anchor_bytes).unwrap();
        let source = CatalogSource::new(self.objects.iter().cloned());
        let pin = match pin {
            Pin::None => None,
            Pin::Head(index) => {
                let head = self.heads[index];
                Some(RegistryHeadPin::new(head.version, head.object_hash))
            }
            Pin::Exact(version, hash) => Some(RegistryHeadPin::new(version, hash)),
        };
        let key = TrustStateKey {
            organization_id: organization(),
            device_id: DeviceId::try_from(&[0xf0; 16][..]).unwrap(),
        };
        let mut store = SnapshotStore {
            key,
            record: Some(PersistedTrustRecord::new(
                17,
                TrustedTimeState::initial(floor),
                pin,
            )),
        };
        let snapshot = load_trust_state(&mut store, key).unwrap();
        verify_trust(&anchor, &source, snapshot).unwrap()
    }
}

fn direct_payload(
    action: &ActionSpec,
    authorization_hash: ObjectHash,
    event_effective: ChainSequence,
    event_version: RegistryVersion,
    previous: &LineState,
    options: &HeadOptions,
) -> TrustPayloadV1 {
    match action {
        ActionSpec::Policy {
            policy_version,
            previous_policy_hash,
            effective_from,
        } => TrustPayloadV1::policy(
            policy_fields(
                policy_version.unwrap_or(previous.policy_version + 1),
                previous_policy_hash.unwrap_or(previous.policy_hash),
                ChainSequence::new(effective_from.unwrap_or(event_effective.get())),
                options
                    .policy_max_registry_age_ms_override
                    .unwrap_or(86_400_000),
            ),
            authorization_hash,
        )
        .unwrap(),
        ActionSpec::Device {
            kind,
            marker,
            effective_from,
        } => {
            let signing_key = (!matches!(kind, CertificateKindV1::RecoveryRecipient))
                .then(|| key_from_secret(NEW_ADMIN_SECRET));
            let kem_key = matches!(
                kind,
                CertificateKindV1::Reader | CertificateKindV1::RecoveryRecipient
            )
            .then(|| CanonicalPublicCoseKey::x25519([0xa5; 32]).unwrap());
            let authority_subject_id = matches!(
                kind,
                CertificateKindV1::OrganizationAdmin | CertificateKindV1::KeyApprover
            )
            .then(|| SubjectId::try_from(&[*marker; 16][..]).unwrap());
            TrustPayloadV1::authorized_device_certificate(
                DeviceCertificateFieldsV1 {
                    organization_id: organization(),
                    device_id: DeviceId::try_from(&[marker.wrapping_add(0x40); 16][..]).unwrap(),
                    certificate_kind: *kind,
                    signing_public_cose_key: signing_key
                        .as_ref()
                        .map(CanonicalPublicCoseKey::to_deterministic_cbor),
                    kem_public_cose_key: kem_key
                        .as_ref()
                        .map(CanonicalPublicCoseKey::to_deterministic_cbor),
                    signing_key_thumbprint: signing_key
                        .as_ref()
                        .map(CanonicalPublicCoseKey::thumbprint),
                    kem_key_thumbprint: kem_key.as_ref().map(CanonicalPublicCoseKey::thumbprint),
                    capabilities: options
                        .certificate_capabilities_override
                        .clone()
                        .unwrap_or_else(|| capabilities(*kind)),
                    key_protection_profile: KeyProtectionProfileV1::OsWrapped,
                    effective_from_sequence: ChainSequence::new(
                        effective_from.unwrap_or(event_effective.get()),
                    ),
                    revoked_from_sequence: options.revoked_from_sequence,
                    authority_subject_id,
                },
                authorization_hash,
            )
            .unwrap()
        }
        ActionSpec::WriterTransition {
            old_writer,
            new_writer,
            effective_from,
        } => TrustPayloadV1::writer_transition(
            WriterTransitionFieldsV1 {
                organization_id: organization(),
                chain_id: options.writer_chain_id_override.unwrap_or_else(chain_id),
                old_writer_certificate_hash: CertificateHash::from(*old_writer),
                new_writer_certificate_hash: CertificateHash::from(*new_writer),
                effective_from_sequence: ChainSequence::new(
                    effective_from.unwrap_or(event_effective.get()),
                ),
                previous_entry_hash: EntryHash::from(hash32(0x35)),
                reason_code: 1,
            },
            authorization_hash,
        )
        .unwrap(),
        ActionSpec::OperatorBinding {
            certificate_hash,
            role,
            marker,
            effective_from,
        } => TrustPayloadV1::authorized_operator_binding(
            OperatorBindingFieldsV1 {
                organization_id: organization(),
                operator_subject_id: OperatorSubjectId::try_from(&[*marker; 16][..]).unwrap(),
                operator_profile_commitment: hash32(marker.wrapping_add(1)),
                device_certificate_hash: CertificateHash::from(*certificate_hash),
                operator_role: *role,
                os_account_binding_hash: hash32(marker.wrapping_add(2)),
                operator_instance_key_thumbprint: options
                    .binding_instance_key_thumbprint_override
                    .unwrap_or_else(|| KeyThumbprint::from(hash32(marker.wrapping_add(3)))),
                effective_from_sequence: ChainSequence::new(
                    effective_from.unwrap_or(event_effective.get()),
                ),
                revoked_from_sequence: options.revoked_from_sequence,
            },
            authorization_hash,
        )
        .unwrap(),
        ActionSpec::AdminIssue {
            marker,
            effective_from,
        } => {
            let key = key_from_secret(NEW_ADMIN_SECRET);
            TrustPayloadV1::authorized_device_certificate(
                DeviceCertificateFieldsV1 {
                    organization_id: organization(),
                    device_id: DeviceId::try_from(&[marker.wrapping_add(0x40); 16][..]).unwrap(),
                    certificate_kind: CertificateKindV1::OrganizationAdmin,
                    signing_public_cose_key: Some(key.to_deterministic_cbor()),
                    kem_public_cose_key: None,
                    signing_key_thumbprint: Some(key.thumbprint()),
                    kem_key_thumbprint: None,
                    capabilities: options
                        .certificate_capabilities_override
                        .clone()
                        .unwrap_or_else(|| vec!["organizationAdminApprove".into()]),
                    key_protection_profile: KeyProtectionProfileV1::OsWrapped,
                    effective_from_sequence: ChainSequence::new(
                        effective_from.unwrap_or(event_effective.get()),
                    ),
                    revoked_from_sequence: options.revoked_from_sequence,
                    authority_subject_id: Some(SubjectId::try_from(&[*marker; 16][..]).unwrap()),
                },
                authorization_hash,
            )
            .unwrap()
        }
        ActionSpec::RootRotate {
            previous_root_hash,
            effective_version,
        } => {
            let key = key_from_secret(ROTATED_ROOT_SECRET);
            TrustPayloadV1::authorized_root_certificate(
                RootCertificateFieldsV1 {
                    organization_id: organization(),
                    root_public_cose_key: key.to_deterministic_cbor(),
                    root_key_thumbprint: key.thumbprint(),
                    previous_root_certificate_object_hash: Some(
                        previous_root_hash.unwrap_or(previous.root.object_hash),
                    ),
                    effective_from_registry_version: RegistryVersion::new(
                        effective_version.unwrap_or(event_version.get()),
                    ),
                },
                authorization_hash,
            )
            .unwrap()
        }
        ActionSpec::Revoke { .. } | ActionSpec::AdminRevoke { .. } => {
            panic!("revocations have no direct target")
        }
    }
}

fn exact_change(action: &ActionSpec, direct_hash: Option<ObjectHash>) -> RegistryChangeV1 {
    match action {
        ActionSpec::Policy { .. } => RegistryChangeV1::Policy {
            object_hash: direct_hash.unwrap(),
        },
        ActionSpec::Device { .. } => RegistryChangeV1::Certificate {
            object_hash: direct_hash.unwrap(),
        },
        ActionSpec::Revoke {
            target_kind,
            object_hash,
        } => RegistryChangeV1::Target {
            target_kind: *target_kind,
            object_hash: *object_hash,
        },
        ActionSpec::WriterTransition { .. } => RegistryChangeV1::WriterTransition {
            object_hash: direct_hash.unwrap(),
        },
        ActionSpec::OperatorBinding { .. } => RegistryChangeV1::OperatorBinding {
            object_hash: direct_hash.unwrap(),
        },
        ActionSpec::AdminIssue { .. } => RegistryChangeV1::AdminCertificate {
            object_hash: direct_hash.unwrap(),
            effect: 0,
        },
        ActionSpec::AdminRevoke { object_hash } => RegistryChangeV1::AdminCertificate {
            object_hash: *object_hash,
            effect: 1,
        },
        ActionSpec::RootRotate { .. } => RegistryChangeV1::RootCertificate {
            object_hash: direct_hash.unwrap(),
        },
    }
}

fn overridden_change(
    override_: &ChangeOverride,
    direct_hash: Option<ObjectHash>,
    exact: RegistryChangeV1,
) -> RegistryChangeV1 {
    let direct = direct_hash.unwrap_or_else(|| ObjectHash::from(hash32(0xee)));
    match override_ {
        ChangeOverride::Exact => exact,
        ChangeOverride::CertificateFromDirect => RegistryChangeV1::Certificate {
            object_hash: direct,
        },
        ChangeOverride::TargetFromDirect(target_kind) => RegistryChangeV1::Target {
            target_kind: *target_kind,
            object_hash: direct,
        },
        ChangeOverride::PolicyFromDirect => RegistryChangeV1::Policy {
            object_hash: direct,
        },
        ChangeOverride::WriterTransitionFromDirect => RegistryChangeV1::WriterTransition {
            object_hash: direct,
        },
        ChangeOverride::OperatorBindingFromDirect => RegistryChangeV1::OperatorBinding {
            object_hash: direct,
        },
        ChangeOverride::AdminFromDirect(effect) => RegistryChangeV1::AdminCertificate {
            object_hash: direct,
            effect: *effect,
        },
        ChangeOverride::RootFromDirect => RegistryChangeV1::RootCertificate {
            object_hash: direct,
        },
        ChangeOverride::Raw(change) => change.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn exact_authorization(
    target: &TrustPayloadV1,
    action_code: u8,
    target_subtype: TrustSubtypeV1,
    id: u8,
    nonce: u8,
    registry_version: RegistryVersion,
    registry_head_hash: Hash32,
    issued_at: UnixMillis,
    admin_secret: [u8; 32],
    admin_hash: ObjectHash,
    admin_binding_hash: ObjectHash,
) -> Vec<u8> {
    let payload =
        TrustPayloadV1::organization_admin_authorization(OrganizationAdminAuthorizationFieldsV1 {
            authorization_id: AuthorizationId::try_from(&[id; 16][..]).unwrap(),
            organization_id: organization(),
            registry_version,
            registry_head_hash,
            admin_key_thumbprint: key_from_secret(admin_secret).thumbprint(),
            admin_certificate_hash: CertificateHash::from(admin_hash),
            admin_operator_binding_object_hash: admin_binding_hash,
            action_code,
            target_trust_subtype: target_subtype,
            authorized_trust_core_hash: authorized_trust_digest(&authorized_core_input(target)),
            issued_at,
            expires_at: UnixMillis::new(issued_at.get().checked_add(1_000).unwrap()),
            nonce: [nonce; 32],
        })
        .unwrap();
    let key = key_from_secret(admin_secret);
    let signature = signed_normal(
        admin_secret,
        &key,
        CertificateHash::from(admin_hash),
        trust_digest(payload.exact_digest_input()).as_bytes(),
    );
    exact_object(payload, vec![signature])
}

fn policy_fields(
    policy_version: u64,
    previous_policy_object_hash: Option<ObjectHash>,
    effective_from_sequence: ChainSequence,
    max_registry_age_ms: u64,
) -> PolicyFieldsV1 {
    PolicyFieldsV1 {
        organization_id: organization(),
        policy_version,
        previous_policy_object_hash,
        operating_profile: 0,
        max_registry_age_ms,
        max_future_clock_skew_ms: 300_000,
        registry_expiry_behavior: 0,
        evidence_max_delay_ms: 60_000,
        reader_inactivity_ms: 900_000,
        reader_history_access_allowed: true,
        allowed_archive_profile_hashes: vec![hash32(0xa1)],
        backup_frequency_ms: 86_400_000,
        restore_test_interval_ms: 2_592_000_000,
        retention_policy: RetentionPolicyFieldsV1 {
            minimum_retention_ms: Some(86_400_000),
            destruction_enabled: true,
            eds_privacy_decision_document_hash: Some(hash32(0xa2)),
        },
        free_text_policy: FreeTextPolicyFieldsV1 {
            free_text_allowed: false,
            rule_set_version: "fixture-v1".into(),
            local_pattern_warning_enabled: true,
        },
        allowed_crypto_suite_ids: vec!["EINSATZARCHIV-SUITE-1".into()],
        allowed_format_versions: vec![1],
        effective_from_sequence,
    }
}

fn capabilities(kind: CertificateKindV1) -> Vec<String> {
    match kind {
        CertificateKindV1::OrganizationAdmin => vec!["organizationAdminApprove".into()],
        CertificateKindV1::Writer => vec!["initialGrant".into()],
        CertificateKindV1::Reader | CertificateKindV1::RecoveryRecipient => Vec::new(),
        CertificateKindV1::KeyApprover => vec!["historicalGrantApprove".into()],
        CertificateKindV1::HistoricalGrantAuthority => vec!["historicalGrant".into()],
        CertificateKindV1::ServerReceipt => vec!["serverReceipt".into()],
        CertificateKindV1::DeletionAttest => vec!["deletionAttest".into()],
    }
}

fn initial_admin_certificate(
    root_hash: CertificateHash,
    secret: [u8; 32],
    device: u8,
    subject: u8,
    revoked_from_sequence: Option<ChainSequence>,
) -> Vec<u8> {
    let key = key_from_secret(secret);
    let payload = TrustPayloadV1::initial_admin_device_certificate(DeviceCertificateFieldsV1 {
        organization_id: organization(),
        device_id: DeviceId::try_from(&[device; 16][..]).unwrap(),
        certificate_kind: CertificateKindV1::OrganizationAdmin,
        signing_public_cose_key: Some(key.to_deterministic_cbor()),
        kem_public_cose_key: None,
        signing_key_thumbprint: Some(key.thumbprint()),
        kem_key_thumbprint: None,
        capabilities: vec!["organizationAdminApprove".into()],
        key_protection_profile: KeyProtectionProfileV1::OsWrapped,
        effective_from_sequence: ChainSequence::new(0),
        revoked_from_sequence,
        authority_subject_id: Some(SubjectId::try_from(&[subject; 16][..]).unwrap()),
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(ROOT_SECRET))
        .sign_initial_admin_trust_digest(root_hash, payload.exact_digest_input())
        .unwrap();
    exact_object(payload, vec![signature])
}

fn initial_admin_binding(
    root_hash: CertificateHash,
    admin_hash: CertificateHash,
    subject: u8,
    os_account: u8,
    instance: u8,
    revoked_from_sequence: Option<ChainSequence>,
) -> Vec<u8> {
    let payload = TrustPayloadV1::initial_admin_operator_binding(OperatorBindingFieldsV1 {
        organization_id: organization(),
        operator_subject_id: OperatorSubjectId::try_from(&[subject; 16][..]).unwrap(),
        operator_profile_commitment: hash32(subject.wrapping_add(0x30)),
        device_certificate_hash: admin_hash,
        operator_role: OperatorRoleV1::OrganizationAdmin,
        os_account_binding_hash: hash32(os_account),
        operator_instance_key_thumbprint: KeyThumbprint::from(hash32(instance)),
        effective_from_sequence: ChainSequence::new(0),
        revoked_from_sequence,
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(ROOT_SECRET))
        .sign_initial_admin_trust_digest(root_hash, payload.exact_digest_input())
        .unwrap();
    exact_object(payload, vec![signature])
}

fn exact_object(payload: TrustPayloadV1, signatures: Vec<Vec<u8>>) -> Vec<u8> {
    encode_trust(&TrustObjectV1::new(payload, signatures).unwrap())
        .unwrap()
        .into_vec()
}

fn signed_normal(
    secret: [u8; 32],
    key: &CanonicalPublicCoseKey,
    certificate_hash: CertificateHash,
    payload: &[u8],
) -> Vec<u8> {
    let protected =
        ProtectedHeader::normal(ContentType::TrustDigest, key.thumbprint(), certificate_hash);
    let signature = SigningKey::from_bytes(&secret)
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

fn exact_anchor(
    root_hash: ObjectHash,
    admin_hashes: &[ObjectHash],
    binding_hashes: &[ObjectHash],
) -> Vec<u8> {
    let root_key = key_from_secret(ROOT_SECRET);
    let root_key_bytes = root_key.to_deterministic_cbor();
    let mut admin_hashes = admin_hashes.to_vec();
    let mut binding_hashes = binding_hashes.to_vec();
    admin_hashes.sort_unstable();
    binding_hashes.sort_unstable();
    let mut pre_anchor = Vec::new();
    let mut encoder = Encoder::new(&mut pre_anchor);
    encoder
        .array(10)
        .unwrap()
        .str("EINSATZARCHIV-TRUST-ANCHOR-PRE-v1")
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(organization().as_bytes())
        .unwrap()
        .bytes(chain_id().as_bytes())
        .unwrap()
        .bytes(&root_key_bytes)
        .unwrap()
        .bytes(root_key.thumbprint().as_bytes())
        .unwrap()
        .bytes(root_hash.as_bytes())
        .unwrap()
        .array(u64::try_from(admin_hashes.len()).unwrap())
        .unwrap();
    for hash in &admin_hashes {
        encoder.bytes(hash.as_bytes()).unwrap();
    }
    encoder
        .array(u64::try_from(binding_hashes.len()).unwrap())
        .unwrap();
    for hash in &binding_hashes {
        encoder.bytes(hash.as_bytes()).unwrap();
    }
    encoder.array(0).unwrap();

    let mut anchor = Vec::new();
    let mut encoder = Encoder::new(&mut anchor);
    encoder
        .array(12)
        .unwrap()
        .str("EINSATZARCHIV-TRUST-ANCHOR-v1")
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(bootstrap_anchor_hash(&pre_anchor).as_bytes())
        .unwrap()
        .bytes(organization().as_bytes())
        .unwrap()
        .bytes(chain_id().as_bytes())
        .unwrap()
        .bytes(&root_key_bytes)
        .unwrap()
        .bytes(root_key.thumbprint().as_bytes())
        .unwrap()
        .bytes(root_hash.as_bytes())
        .unwrap()
        .array(u64::try_from(admin_hashes.len()).unwrap())
        .unwrap();
    for hash in &admin_hashes {
        encoder.bytes(hash.as_bytes()).unwrap();
    }
    encoder
        .array(u64::try_from(binding_hashes.len()).unwrap())
        .unwrap();
    for hash in &binding_hashes {
        encoder.bytes(hash.as_bytes()).unwrap();
    }
    encoder.bytes(&[0x44; 32]).unwrap().array(0).unwrap();
    anchor
}

fn key_from_secret(secret: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(*SigningKey::from_bytes(&secret).verifying_key().as_bytes())
        .unwrap()
}

pub fn organization() -> OrganizationId {
    OrganizationId::try_from(&[0x21; 16][..]).unwrap()
}

fn chain_id() -> ChainId {
    ChainId::try_from(&[0x31; 16][..]).unwrap()
}

pub fn hash32(byte: u8) -> Hash32 {
    Hash32::try_from(&[byte; 32][..]).unwrap()
}

pub fn object_hash_marker(byte: u8) -> ObjectHash {
    ObjectHash::from(hash32(byte))
}

pub fn authorized_device_signing_key_thumbprint() -> KeyThumbprint {
    key_from_secret(NEW_ADMIN_SECRET).thumbprint()
}

fn hash32_from_object(value: ObjectHash) -> Hash32 {
    Hash32::try_from(value.as_bytes().as_slice()).unwrap()
}

struct CatalogSource(BTreeMap<ObjectHash, Arc<[u8]>>);

impl CatalogSource {
    fn new(objects: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self(
            objects
                .into_iter()
                .map(|bytes| (object_hash(&bytes), Arc::<[u8]>::from(bytes)))
                .collect(),
        )
    }
}

impl TrustObjectSource for CatalogSource {
    fn visit_trust_object_hashes(
        &self,
        visitor: &mut dyn FnMut(ObjectHash) -> Result<(), TrustSourceError>,
    ) -> Result<(), TrustSourceError> {
        for hash in self.0.keys().rev().copied() {
            visitor(hash)?;
        }
        Ok(())
    }

    fn read_exact_trust_object(
        &self,
        object_hash: ObjectHash,
    ) -> Result<Option<Arc<[u8]>>, TrustSourceError> {
        Ok(self.0.get(&object_hash).map(Arc::clone))
    }
}

struct SnapshotStore {
    key: TrustStateKey,
    record: Option<PersistedTrustRecord>,
}

impl TrustStateStore for SnapshotStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Unavailable);
        }
        self.record.take().ok_or(StateStoreError::Unavailable)
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
}
