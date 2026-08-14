use std::{cell::Cell, collections::BTreeMap, sync::Arc};

use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, CoseSigner, ProtectedHeader, SecretBytes,
    bootstrap_anchor_hash, object_hash, trust_digest,
};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, DeviceCertificateFieldsV1, KeyProtectionProfileV1,
    OperatorBindingFieldsV1, OperatorRoleV1, ParsedArchiveObject, RootCertificateFieldsV1,
    TrustObjectV1, TrustPayloadV1, encode_trust,
};
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, StateStoreError, TrustError, TrustObjectSource, TrustSourceError,
    TrustStateKey, TrustStateSnapshot, TrustStateStore, decode_trust_anchor, load_trust_state,
    verify_trust,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, Hash32, KeyThumbprint, ObjectHash,
    OperatorSubjectId, OrganizationId, RegistryVersion, SubjectId, UnixMillis,
};
use minicbor::{Decoder, Encoder};

const ROOT_SECRET_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ROOT_PUBLIC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ADMIN_ONE_PUBLIC_HEX: &str =
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const ADMIN_TWO_PUBLIC_HEX: &str =
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
const ADMIN_THREE_PUBLIC_HEX: &str =
    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e";
const OTHER_SECRET_HEX: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

#[test]
fn valid_bootstrap_pairs_are_hash_paired_and_keep_same_device_admins_distinct() {
    let mut spec = BootstrapSpec::valid();
    spec.certificates[1].device_id = spec.certificates[0].device_id;
    let fixture = (0_u8..=u8::MAX)
        .find_map(|marker| {
            spec.bindings[0].operator_profile_commitment = hash32(marker);
            let fixture = build_fixture(&spec);
            anchor_pairing_is_crossed(&fixture).then_some(fixture)
        })
        .expect("fixture search must find a sorted Anchor order that defeats positional zip");

    let verified = verify_trust(&fixture.anchor, &fixture.source, fixture.snapshot)
        .expect("two valid Root-signed Anchor-pinned Admin pairs must verify");
    assert!(
        verified
            .pinned_head()
            .is_some_and(|pin| pin.registry_head_hash() == fixture.prepared_certificate_hash)
    );
    let prepared = fixture
        .source
        .objects
        .get(&fixture.prepared_certificate_hash)
        .expect("the authorized but unactivated certificate remains cataloged");
    let prepared = match ea_format::decode_exact_object(prepared).unwrap() {
        ParsedArchiveObject::Trust(parsed) => parsed,
        _ => panic!("prepared certificate must remain an ETB Trust object"),
    };
    assert!(matches!(
        prepared.value().decoded_payload().unwrap(),
        DecodedTrustPayloadV1::AuthorizedDevice(_)
    ));
    assert_eq!(fixture.source.visits.get(), 1);
    assert_eq!(fixture.source.total_reads(), fixture.source.objects.len());
    assert!(
        fixture
            .source
            .reads
            .borrow()
            .values()
            .all(|count| *count == 1)
    );
}

#[test]
fn every_direct_initial_bootstrap_object_must_be_anchor_pinned() {
    let mut missing_root = BootstrapSpec::valid();
    missing_root.include_root = false;

    let mut unpinned_root = BootstrapSpec::valid();
    unpinned_root.extra_root = true;

    let mut unpinned_complete_pair = BootstrapSpec::valid();
    unpinned_complete_pair
        .certificates
        .push(CertificateSpec::new(2));
    unpinned_complete_pair
        .bindings
        .push(BindingSpec::new(2, 0x43));

    let mut unpinned_admin_only = BootstrapSpec::valid();
    unpinned_admin_only
        .certificates
        .push(CertificateSpec::new(2));

    let mut unpinned_binding_only = BootstrapSpec::valid();
    let mut extra_binding = BindingSpec::new(0, 0x41);
    extra_binding.operator_profile_commitment = hash32(0x73);
    extra_binding.os_account_binding_hash = hash32(0x83);
    extra_binding.operator_instance_key_thumbprint = key_thumbprint(0x93);
    unpinned_binding_only.bindings.push(extra_binding);

    for (label, spec) in [
        ("missing pinned direct Root", missing_root),
        ("unpinned direct Root", unpinned_root),
        (
            "unpinned complete direct Admin certificate/Binding pair",
            unpinned_complete_pair,
        ),
        (
            "unpinned direct Admin certificate only",
            unpinned_admin_only,
        ),
        ("unpinned direct Admin Binding only", unpinned_binding_only),
    ] {
        assert_rejected(label, &spec, "EA-TRUST-ANCHOR-PIN");
    }
}

#[test]
fn root_key_thumbprint_object_hash_and_pop_are_independently_pinned() {
    let mut wrong_key = BootstrapSpec::valid();
    wrong_key.root_certificate_key = KeyFixture::AdminOne;

    let mut wrong_thumbprint = BootstrapSpec::valid();
    wrong_thumbprint.root_thumbprint_override = Some(key_thumbprint(0xa1));

    let mut wrong_object_hash = BootstrapSpec::valid();
    wrong_object_hash.root_pin = RootPin::FirstAdminCertificate;

    let mut bad_pop = BootstrapSpec::valid();
    bad_pop.mutate_root_signature = true;

    let mut wrong_profile = BootstrapSpec::valid();
    wrong_profile.normal_root_signature_profile = true;

    let mut coherent_foreign_organization = BootstrapSpec::valid();
    coherent_foreign_organization.root_certificate_organization = organization_id(0x99);
    for certificate in &mut coherent_foreign_organization.certificates {
        certificate.organization_id = organization_id(0x99);
    }
    for binding in &mut coherent_foreign_organization.bindings {
        binding.organization_id = organization_id(0x99);
    }

    for (label, spec, code) in [
        ("Root public key mismatch", wrong_key, "EA-TRUST-ANCHOR-PIN"),
        (
            "Root thumbprint mismatch",
            wrong_thumbprint,
            "EA-TRUST-ANCHOR-PIN",
        ),
        (
            "Root object-hash mismatch",
            wrong_object_hash,
            "EA-TRUST-ANCHOR-PIN",
        ),
        (
            "Root proof-of-possession mutation",
            bad_pop,
            "EA-TRUST-SIGNATURE",
        ),
        (
            "normal certificate-bound profile on initial Root",
            wrong_profile,
            "EA-TRUST-SOURCE",
        ),
        (
            "self-consistent foreign bootstrap organization",
            coherent_foreign_organization,
            "EA-TRUST-ANCHOR-PIN",
        ),
    ] {
        assert_rejected(label, &spec, code);
    }
}

#[test]
fn bootstrap_requires_two_complete_pairs_and_distinct_authority_subjects() {
    let mut one_pair = BootstrapSpec::valid();
    one_pair.omit_certificates.push(1);
    one_pair.omit_bindings.push(1);

    let mut missing_certificate = BootstrapSpec::valid();
    missing_certificate.omit_certificates.push(1);

    let mut missing_binding = BootstrapSpec::valid();
    missing_binding.omit_bindings.push(1);

    let mut repeated_subject = BootstrapSpec::valid();
    repeated_subject.certificates[1].authority_subject = subject_id(0x41);
    repeated_subject.bindings[1].operator_subject = operator_subject_id(0x41);

    let mut null_subject = BootstrapSpec::valid();
    null_subject.certificates[0].wire_mutation = Some(CertificateWireMutation::NullSubject);

    for (label, spec, code) in [
        (
            "only one available Admin pair",
            one_pair,
            "EA-TRUST-ANCHOR-PIN",
        ),
        (
            "missing one pinned Admin certificate",
            missing_certificate,
            "EA-TRUST-ANCHOR-PIN",
        ),
        (
            "missing one pinned Admin Binding",
            missing_binding,
            "EA-TRUST-ANCHOR-PIN",
        ),
        (
            "two certificates for one authority subject",
            repeated_subject,
            "EA-TRUST-SUBJECT-MISMATCH",
        ),
        (
            "null Admin authority subject",
            null_subject,
            "EA-TRUST-SOURCE",
        ),
    ] {
        assert_rejected(label, &spec, code);
    }
}

#[test]
fn binding_pairs_by_certificate_hash_and_exact_subject_not_list_position() {
    let mut wrong_subject = BootstrapSpec::valid();
    wrong_subject.bindings[0].operator_subject = operator_subject_id(0x43);

    let mut points_at_another_certificate = BootstrapSpec::valid();
    points_at_another_certificate.bindings[0].certificate_index = 1;

    let mut typed_pin_confusion = BootstrapSpec::valid();
    typed_pin_confusion.swap_typed_pin_hashes = true;

    for (label, spec, code) in [
        (
            "certificate authoritySubjectId differs from Binding operatorSubjectId",
            wrong_subject,
            "EA-TRUST-SUBJECT-MISMATCH",
        ),
        (
            "Binding points at another certificate",
            points_at_another_certificate,
            "EA-TRUST-BOOTSTRAP-PAIR",
        ),
        (
            "certificate and Binding pin lists are type-confused",
            typed_pin_confusion,
            "EA-TRUST-ANCHOR-PIN",
        ),
    ] {
        assert_rejected(label, &spec, code);
    }
}

#[test]
fn organization_role_capability_and_state_organization_fail_closed() {
    let mut wrong_certificate_organization = BootstrapSpec::valid();
    wrong_certificate_organization.certificates[0].organization_id = organization_id(0x99);

    let mut wrong_binding_organization = BootstrapSpec::valid();
    wrong_binding_organization.bindings[0].organization_id = organization_id(0x99);

    let mut wrong_role = BootstrapSpec::valid();
    wrong_role.bindings[0].wire_mutation = Some(BindingWireMutation::ReaderRole);

    let mut wrong_certificate_kind = BootstrapSpec::valid();
    wrong_certificate_kind.certificates[0].wire_mutation =
        Some(CertificateWireMutation::ReaderKind);

    let mut missing_capability = BootstrapSpec::valid();
    missing_capability.certificates[0].capabilities.clear();

    for (label, spec, code) in [
        (
            "wrong certificate organization",
            wrong_certificate_organization,
            "EA-TRUST-SIGNATURE",
        ),
        (
            "wrong Binding organization",
            wrong_binding_organization,
            "EA-TRUST-SIGNATURE",
        ),
        (
            "wrong direct certificate kind",
            wrong_certificate_kind,
            "EA-TRUST-SOURCE",
        ),
        ("wrong direct Binding role", wrong_role, "EA-TRUST-SOURCE"),
        (
            "missing organizationAdminApprove capability",
            missing_capability,
            "EA-TRUST-BOOTSTRAP-PAIR",
        ),
    ] {
        assert_rejected(label, &spec, code);
    }
}

#[test]
fn state_organization_mismatch_fails_before_catalog_discovery_or_reads() {
    let mut spec = BootstrapSpec::valid();
    spec.snapshot_organization = organization_id(0x98);
    let fixture = build_fixture(&spec);

    let error = match verify_trust(&fixture.anchor, &fixture.source, fixture.snapshot) {
        Ok(_) => panic!("a foreign state organization must fail closed"),
        Err(error) => error,
    };
    assert_static_error(
        "state organization differs from Anchor",
        error,
        "EA-TRUST-BOOTSTRAP-PAIR",
    );
    assert_eq!(fixture.source.visits.get(), 0);
    assert_eq!(fixture.source.total_reads(), 0);
}

#[test]
fn bootstrap_admin_keys_accounts_and_instance_keys_are_independently_distinct() {
    let mut shared_admin_key = BootstrapSpec::valid();
    shared_admin_key.certificates[1].signing_key = KeyFixture::AdminOne;

    let mut shared_os_account = BootstrapSpec::valid();
    shared_os_account.bindings[1].os_account_binding_hash = hash32(0x81);

    let mut shared_instance_key = BootstrapSpec::valid();
    shared_instance_key.bindings[1].operator_instance_key_thumbprint = key_thumbprint(0x91);

    let mut instance_is_admin_signing_key = BootstrapSpec::valid();
    instance_is_admin_signing_key.bindings[0].operator_instance_key_thumbprint =
        public_key(KeyFixture::AdminOne).thumbprint();

    for (label, spec) in [
        ("shared Admin signing key", shared_admin_key),
        ("shared OS-account Binding", shared_os_account),
        ("shared operator-instance key", shared_instance_key),
        (
            "operator-instance key equals Admin signing key",
            instance_is_admin_signing_key,
        ),
    ] {
        assert_rejected(label, &spec, "EA-TRUST-BOOTSTRAP-PAIR");
    }
}

#[test]
fn bootstrap_pairs_must_be_effective_at_sequence_zero() {
    let mut future_certificate = BootstrapSpec::valid();
    future_certificate.certificates[0].effective_from_sequence = ChainSequence::new(1);
    future_certificate.certificates[0].revoked_from_sequence = None;

    let mut future_binding = BootstrapSpec::valid();
    future_binding.bindings[0].effective_from_sequence = ChainSequence::new(1);
    future_binding.bindings[0].revoked_from_sequence = None;

    for (label, spec) in [
        ("future Admin certificate", future_certificate),
        ("future Admin Binding", future_binding),
    ] {
        assert_rejected(label, &spec, "EA-TRUST-SIGNER-INACTIVE");
    }
}

#[test]
fn initial_admin_signatures_bind_root_key_certificate_hash_profile_and_payload() {
    let mut wrong_signer = BootstrapSpec::valid();
    wrong_signer.certificates[0].signature_mode = SignatureMode::WrongSigner;

    let mut wrong_root_hash = BootstrapSpec::valid();
    wrong_root_hash.bindings[0].signature_mode = SignatureMode::WrongCertificateHash;

    let mut mutated_signature = BootstrapSpec::valid();
    mutated_signature.certificates[0].signature_mode = SignatureMode::Mutated;

    let mut initial_root_profile = BootstrapSpec::valid();
    initial_root_profile.bindings[0].signature_mode = SignatureMode::InitialRootProfile;

    for (label, spec, code) in [
        ("non-Root signing key", wrong_signer, "EA-TRUST-SIGNATURE"),
        (
            "wrong protected Root certificate hash",
            wrong_root_hash,
            "EA-TRUST-SIGNATURE",
        ),
        (
            "mutated Admin certificate signature",
            mutated_signature,
            "EA-TRUST-SIGNATURE",
        ),
        (
            "hashless initial-Root profile on Admin Binding",
            initial_root_profile,
            "EA-TRUST-SOURCE",
        ),
    ] {
        assert_rejected(label, &spec, code);
    }
}

fn assert_rejected(label: &str, spec: &BootstrapSpec, expected_code: &'static str) {
    let fixture = build_fixture(spec);
    let error = match verify_trust(&fixture.anchor, &fixture.source, fixture.snapshot) {
        Ok(_) => panic!("{label} must fail closed"),
        Err(error) => error,
    };
    assert_static_error(label, error, expected_code);
}

fn assert_static_error(label: &str, error: TrustError, expected_code: &'static str) {
    assert_eq!(error.code(), expected_code, "{label}");
    assert_eq!(error.to_string(), expected_code, "{label}");
    assert_eq!(format!("{error:?}"), expected_code, "{label}");
}

#[derive(Clone, Copy)]
enum KeyFixture {
    Root,
    AdminOne,
    AdminTwo,
    AdminThree,
}

#[derive(Clone, Copy)]
enum SignatureMode {
    Correct,
    WrongSigner,
    WrongCertificateHash,
    Mutated,
    InitialRootProfile,
}

#[derive(Clone, Copy)]
enum CertificateWireMutation {
    NullSubject,
    ReaderKind,
}

#[derive(Clone, Copy)]
enum BindingWireMutation {
    ReaderRole,
}

#[derive(Clone)]
struct CertificateSpec {
    organization_id: OrganizationId,
    device_id: DeviceId,
    signing_key: KeyFixture,
    capabilities: Vec<String>,
    effective_from_sequence: ChainSequence,
    revoked_from_sequence: Option<ChainSequence>,
    authority_subject: SubjectId,
    signature_mode: SignatureMode,
    wire_mutation: Option<CertificateWireMutation>,
}

impl CertificateSpec {
    fn new(index: usize) -> Self {
        let (key, subject, device) = match index {
            0 => (KeyFixture::AdminOne, 0x41, 0x51),
            1 => (KeyFixture::AdminTwo, 0x42, 0x52),
            _ => (KeyFixture::AdminThree, 0x43, 0x53),
        };
        Self {
            organization_id: organization_id(0x21),
            device_id: device_id(device),
            signing_key: key,
            capabilities: vec!["organizationAdminApprove".into()],
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence: (index == 0).then(|| ChainSequence::new(1)),
            authority_subject: subject_id(subject),
            signature_mode: SignatureMode::Correct,
            wire_mutation: None,
        }
    }
}

#[derive(Clone)]
struct BindingSpec {
    organization_id: OrganizationId,
    operator_subject: OperatorSubjectId,
    certificate_index: usize,
    operator_profile_commitment: Hash32,
    os_account_binding_hash: Hash32,
    operator_instance_key_thumbprint: KeyThumbprint,
    effective_from_sequence: ChainSequence,
    revoked_from_sequence: Option<ChainSequence>,
    signature_mode: SignatureMode,
    wire_mutation: Option<BindingWireMutation>,
}

impl BindingSpec {
    fn new(certificate_index: usize, subject: u8) -> Self {
        let offset = u8::try_from(certificate_index).unwrap();
        Self {
            organization_id: organization_id(0x21),
            operator_subject: operator_subject_id(subject),
            certificate_index,
            operator_profile_commitment: hash32(0x71),
            os_account_binding_hash: hash32(0x81 + offset),
            operator_instance_key_thumbprint: key_thumbprint(0x91 + offset),
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence: (certificate_index == 0).then(|| ChainSequence::new(1)),
            signature_mode: SignatureMode::Correct,
            wire_mutation: None,
        }
    }
}

#[derive(Clone, Copy)]
enum RootPin {
    Actual,
    FirstAdminCertificate,
}

#[derive(Clone)]
struct BootstrapSpec {
    anchor_organization: OrganizationId,
    snapshot_organization: OrganizationId,
    root_certificate_organization: OrganizationId,
    root_certificate_key: KeyFixture,
    root_effective_from_registry_version: RegistryVersion,
    root_thumbprint_override: Option<KeyThumbprint>,
    root_pin: RootPin,
    include_root: bool,
    mutate_root_signature: bool,
    normal_root_signature_profile: bool,
    extra_root: bool,
    certificates: Vec<CertificateSpec>,
    bindings: Vec<BindingSpec>,
    pinned_certificates: Vec<usize>,
    pinned_bindings: Vec<usize>,
    swap_typed_pin_hashes: bool,
    omit_certificates: Vec<usize>,
    omit_bindings: Vec<usize>,
}

impl BootstrapSpec {
    fn valid() -> Self {
        Self {
            anchor_organization: organization_id(0x21),
            snapshot_organization: organization_id(0x21),
            root_certificate_organization: organization_id(0x21),
            root_certificate_key: KeyFixture::Root,
            root_effective_from_registry_version: RegistryVersion::new(1),
            root_thumbprint_override: None,
            root_pin: RootPin::Actual,
            include_root: true,
            mutate_root_signature: false,
            normal_root_signature_profile: false,
            extra_root: false,
            certificates: vec![CertificateSpec::new(0), CertificateSpec::new(1)],
            bindings: vec![BindingSpec::new(0, 0x41), BindingSpec::new(1, 0x42)],
            pinned_certificates: vec![0, 1],
            pinned_bindings: vec![0, 1],
            swap_typed_pin_hashes: false,
            omit_certificates: Vec::new(),
            omit_bindings: Vec::new(),
        }
    }
}

struct Fixture {
    anchor: ea_trust::TrustAnchorV1,
    source: MemorySource,
    snapshot: TrustStateSnapshot,
    prepared_certificate_hash: ObjectHash,
}

fn build_fixture(spec: &BootstrapSpec) -> Fixture {
    let root_key = public_key(spec.root_certificate_key);
    let root_thumbprint = spec
        .root_thumbprint_override
        .unwrap_or_else(|| root_key.thumbprint());
    let root_payload = TrustPayloadV1::initial_root_certificate(RootCertificateFieldsV1 {
        organization_id: spec.root_certificate_organization,
        root_public_cose_key: root_key.to_deterministic_cbor(),
        root_key_thumbprint: root_thumbprint,
        previous_root_certificate_object_hash: None,
        effective_from_registry_version: spec.root_effective_from_registry_version,
    })
    .unwrap();
    let root_digest = trust_digest(root_payload.exact_digest_input());
    let root_signature = if spec.normal_root_signature_profile {
        structural_normal_trust_cose(
            root_key.thumbprint(),
            CertificateHash::from(object_hash(b"non-bootstrap Root profile")),
            root_digest.as_bytes(),
        )
    } else {
        signer_for_key(spec.root_certificate_key)
            .sign_initial_root(root_digest.as_bytes())
            .unwrap()
    };
    let mut root_bytes = if spec.normal_root_signature_profile {
        raw_trust_object(&root_payload, &root_signature)
    } else {
        encode_trust(&TrustObjectV1::new(root_payload, vec![root_signature]).unwrap())
            .unwrap()
            .into_vec()
    };
    if spec.mutate_root_signature {
        *root_bytes.last_mut().unwrap() ^= 1;
    }
    let root_hash = object_hash(&root_bytes);
    let root_certificate_hash = CertificateHash::from(root_hash);

    let mut certificate_bytes = Vec::with_capacity(spec.certificates.len());
    let mut certificate_hashes = Vec::with_capacity(spec.certificates.len());
    for certificate in &spec.certificates {
        let key = public_key(certificate.signing_key);
        let payload = TrustPayloadV1::initial_admin_device_certificate(DeviceCertificateFieldsV1 {
            organization_id: certificate.organization_id,
            device_id: certificate.device_id,
            certificate_kind: CertificateKindV1::OrganizationAdmin,
            signing_public_cose_key: Some(key.to_deterministic_cbor()),
            kem_public_cose_key: None,
            signing_key_thumbprint: Some(key.thumbprint()),
            kem_key_thumbprint: None,
            capabilities: certificate.capabilities.clone(),
            key_protection_profile: KeyProtectionProfileV1::OsWrapped,
            effective_from_sequence: certificate.effective_from_sequence,
            revoked_from_sequence: certificate.revoked_from_sequence,
            authority_subject_id: Some(certificate.authority_subject),
        })
        .unwrap();
        let mut exact = signed_initial_admin_object(
            &payload,
            root_certificate_hash,
            certificate.signature_mode,
        );
        let wire_mutated = match certificate.wire_mutation {
            Some(CertificateWireMutation::NullSubject) => {
                replace_payload_item(&mut exact, 12, &[0xf6]);
                true
            }
            Some(CertificateWireMutation::ReaderKind) => {
                replace_payload_item(&mut exact, 3, &[0x01]);
                true
            }
            None => false,
        };
        if wire_mutated {
            exact = rebuild_with_matching_structural_signature(
                &exact,
                "deviceCertificate",
                root_certificate_hash,
            );
        }
        certificate_hashes.push(object_hash(&exact));
        certificate_bytes.push(exact);
    }

    let mut binding_bytes = Vec::with_capacity(spec.bindings.len());
    let mut binding_hashes = Vec::with_capacity(spec.bindings.len());
    for binding in &spec.bindings {
        let target_hash = certificate_hashes[binding.certificate_index];
        let payload = TrustPayloadV1::initial_admin_operator_binding(OperatorBindingFieldsV1 {
            organization_id: binding.organization_id,
            operator_subject_id: binding.operator_subject,
            operator_profile_commitment: binding.operator_profile_commitment,
            device_certificate_hash: CertificateHash::from(target_hash),
            operator_role: OperatorRoleV1::OrganizationAdmin,
            os_account_binding_hash: binding.os_account_binding_hash,
            operator_instance_key_thumbprint: binding.operator_instance_key_thumbprint,
            effective_from_sequence: binding.effective_from_sequence,
            revoked_from_sequence: binding.revoked_from_sequence,
        })
        .unwrap();
        let mut exact =
            signed_initial_admin_object(&payload, root_certificate_hash, binding.signature_mode);
        if let Some(BindingWireMutation::ReaderRole) = binding.wire_mutation {
            replace_payload_item(&mut exact, 5, &[0x01]);
            exact = rebuild_with_matching_structural_signature(
                &exact,
                "operatorBinding",
                root_certificate_hash,
            );
        }
        binding_hashes.push(object_hash(&exact));
        binding_bytes.push(exact);
    }

    let prepared_certificate = prepared_authorized_device_object(root_certificate_hash);
    let prepared_certificate_hash = object_hash(&prepared_certificate);
    let mut objects = vec![prepared_certificate];
    if spec.include_root {
        objects.push(root_bytes);
    }
    if spec.extra_root {
        objects.push(extra_root_object(spec.anchor_organization));
    }
    for (index, bytes) in certificate_bytes.into_iter().enumerate() {
        if !spec.omit_certificates.contains(&index) {
            objects.push(bytes);
        }
    }
    for (index, bytes) in binding_bytes.into_iter().enumerate() {
        if !spec.omit_bindings.contains(&index) {
            objects.push(bytes);
        }
    }

    let anchor_root_hash = match spec.root_pin {
        RootPin::Actual => root_hash,
        RootPin::FirstAdminCertificate => certificate_hashes[0],
    };
    let mut pinned_certificates: Vec<ObjectHash> = spec
        .pinned_certificates
        .iter()
        .map(|index| certificate_hashes[*index])
        .collect();
    let mut pinned_bindings: Vec<ObjectHash> = spec
        .pinned_bindings
        .iter()
        .map(|index| binding_hashes[*index])
        .collect();
    if spec.swap_typed_pin_hashes {
        std::mem::swap(&mut pinned_certificates[0], &mut pinned_bindings[0]);
    }
    pinned_certificates.sort_unstable();
    pinned_bindings.sort_unstable();
    let anchor_key = public_key(KeyFixture::Root);
    let anchor_bytes = encode_anchor(
        spec.anchor_organization,
        anchor_key,
        anchor_root_hash,
        &pinned_certificates,
        &pinned_bindings,
    );
    let anchor = decode_trust_anchor(&anchor_bytes).unwrap();
    Fixture {
        anchor,
        source: MemorySource::new(objects),
        snapshot: snapshot(spec.snapshot_organization, prepared_certificate_hash),
        prepared_certificate_hash,
    }
}

fn anchor_pairing_is_crossed(fixture: &Fixture) -> bool {
    let certificate_hashes = fixture.anchor.initial_admin_certificate_object_hashes();
    let binding_hashes = fixture
        .anchor
        .initial_admin_operator_binding_object_hashes();
    assert_eq!(certificate_hashes.len(), binding_hashes.len());
    let mut targets_in_binding_order = Vec::new();
    for binding_hash in binding_hashes {
        let exact = fixture.source.objects.get(binding_hash).unwrap();
        let parsed = match ea_format::decode_exact_object(exact).unwrap() {
            ParsedArchiveObject::Trust(parsed) => parsed,
            _ => panic!("pinned Binding must be Trust"),
        };
        let fields = match parsed.value().decoded_payload().unwrap() {
            DecodedTrustPayloadV1::InitialAdminOperatorBinding(fields) => fields,
            _ => panic!("pinned Binding must use the direct Admin form"),
        };
        assert!(
            certificate_hashes
                .iter()
                .any(|hash| hash.as_bytes() == fields.device_certificate_hash.as_bytes())
        );
        targets_in_binding_order.push(fields.device_certificate_hash);
    }
    let mut unique_targets = targets_in_binding_order.clone();
    unique_targets.sort_unstable();
    unique_targets.dedup();
    assert_eq!(unique_targets.len(), certificate_hashes.len());
    targets_in_binding_order
        .iter()
        .zip(certificate_hashes)
        .any(|(target, certificate)| target.as_bytes() != certificate.as_bytes())
}

fn signed_initial_admin_object(
    payload: &TrustPayloadV1,
    root_certificate_hash: CertificateHash,
    mode: SignatureMode,
) -> Vec<u8> {
    let signing_hash = if matches!(mode, SignatureMode::WrongCertificateHash) {
        CertificateHash::from(object_hash(b"wrong Root certificate hash"))
    } else {
        root_certificate_hash
    };
    let signer = if matches!(mode, SignatureMode::WrongSigner) {
        other_signer()
    } else {
        root_signer()
    };
    let signature = if matches!(mode, SignatureMode::InitialRootProfile) {
        signer
            .sign_initial_root(trust_digest(payload.exact_digest_input()).as_bytes())
            .unwrap()
    } else {
        signer
            .sign_initial_admin_trust_digest(signing_hash, payload.exact_digest_input())
            .unwrap()
    };
    if matches!(mode, SignatureMode::InitialRootProfile) {
        return raw_trust_object(payload, &signature);
    }
    let mut exact = encode_trust(&TrustObjectV1::new(payload.clone(), vec![signature]).unwrap())
        .unwrap()
        .into_vec();
    if matches!(mode, SignatureMode::Mutated) {
        *exact.last_mut().unwrap() ^= 1;
    }
    exact
}

fn raw_trust_object(payload: &TrustPayloadV1, signature: &[u8]) -> Vec<u8> {
    raw_trust_object_parts(
        payload.subtype().as_str(),
        payload.exact_payload(),
        signature,
    )
}

fn raw_trust_object_parts(subtype: &str, payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut exact = Vec::new();
    Encoder::new(&mut exact)
        .array(5)
        .and_then(|encoder| encoder.bytes(b"EA1\0"))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.array(3))
        .and_then(|encoder| encoder.str(subtype))
        .unwrap();
    exact.extend_from_slice(payload);
    Encoder::new(&mut exact).array(1).unwrap();
    exact.extend_from_slice(signature);
    exact
}

fn rebuild_with_matching_structural_signature(
    exact: &[u8],
    subtype: &str,
    root_certificate_hash: CertificateHash,
) -> Vec<u8> {
    let payload = exact_trust_payload(exact);
    let mut digest_input = Vec::new();
    Encoder::new(&mut digest_input)
        .array(2)
        .and_then(|encoder| encoder.str(subtype))
        .unwrap();
    digest_input.extend_from_slice(&payload);
    let signature = structural_normal_trust_cose(
        public_key(KeyFixture::Root).thumbprint(),
        root_certificate_hash,
        trust_digest(&digest_input).as_bytes(),
    );
    raw_trust_object_parts(subtype, &payload, &signature)
}

fn exact_trust_payload(exact: &[u8]) -> Vec<u8> {
    let mut decoder = Decoder::new(exact);
    assert_eq!(decoder.array().unwrap(), Some(5));
    decoder.bytes().unwrap();
    decoder.u64().unwrap();
    decoder.u64().unwrap();
    assert_eq!(decoder.array().unwrap(), Some(0));
    assert_eq!(decoder.array().unwrap(), Some(3));
    decoder.str().unwrap();
    let start = decoder.position();
    decoder.skip().unwrap();
    exact[start..decoder.position()].to_vec()
}

fn structural_normal_trust_cose(
    key_thumbprint: KeyThumbprint,
    certificate_hash: CertificateHash,
    payload: &[u8],
) -> Vec<u8> {
    let protected =
        ProtectedHeader::normal(ContentType::TrustDigest, key_thumbprint, certificate_hash)
            .to_deterministic_cbor();
    let mut exact = Vec::new();
    Encoder::new(&mut exact)
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
    exact
}

fn extra_root_object(organization_id: OrganizationId) -> Vec<u8> {
    let key = public_key(KeyFixture::Root);
    let payload = TrustPayloadV1::initial_root_certificate(RootCertificateFieldsV1 {
        organization_id,
        root_public_cose_key: key.to_deterministic_cbor(),
        root_key_thumbprint: key.thumbprint(),
        previous_root_certificate_object_hash: None,
        effective_from_registry_version: RegistryVersion::new(2),
    })
    .unwrap();
    let signature = root_signer()
        .sign_initial_root(trust_digest(payload.exact_digest_input()).as_bytes())
        .unwrap();
    encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
        .unwrap()
        .into_vec()
}

fn prepared_authorized_device_object(root_certificate_hash: CertificateHash) -> Vec<u8> {
    let key = public_key(KeyFixture::AdminThree);
    let payload = TrustPayloadV1::authorized_device_certificate(
        DeviceCertificateFieldsV1 {
            organization_id: organization_id(0x21),
            device_id: device_id(0x63),
            certificate_kind: CertificateKindV1::Writer,
            signing_public_cose_key: Some(key.to_deterministic_cbor()),
            kem_public_cose_key: None,
            signing_key_thumbprint: Some(key.thumbprint()),
            kem_key_thumbprint: None,
            capabilities: vec!["initialGrant".into()],
            key_protection_profile: KeyProtectionProfileV1::OsWrapped,
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence: None,
            authority_subject_id: None,
        },
        object_hash(b"prepared authorization that Task 6 must verify"),
    )
    .unwrap();
    let signature = structural_normal_trust_cose(
        public_key(KeyFixture::Root).thumbprint(),
        root_certificate_hash,
        trust_digest(payload.exact_digest_input()).as_bytes(),
    );
    encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
        .unwrap()
        .into_vec()
}

fn replace_payload_item(exact: &mut Vec<u8>, item_index: usize, replacement: &[u8]) {
    let mut decoder = Decoder::new(exact);
    assert_eq!(decoder.array().unwrap(), Some(5));
    decoder.bytes().unwrap();
    decoder.u64().unwrap();
    decoder.u64().unwrap();
    assert_eq!(decoder.array().unwrap(), Some(0));
    assert_eq!(decoder.array().unwrap(), Some(3));
    decoder.str().unwrap();
    decoder.array().unwrap();
    for _ in 0..item_index {
        decoder.skip().unwrap();
    }
    let start = decoder.position();
    decoder.skip().unwrap();
    let end = decoder.position();
    exact.splice(start..end, replacement.iter().copied());
}

fn encode_anchor(
    organization_id: OrganizationId,
    root_key: CanonicalPublicCoseKey,
    root_certificate_hash: ObjectHash,
    admin_certificates: &[ObjectHash],
    admin_bindings: &[ObjectHash],
) -> Vec<u8> {
    let root_key_bytes = root_key.to_deterministic_cbor();
    let root_thumbprint = root_key.thumbprint();
    let chain_id = chain_id(0x31);
    let mut pre = Vec::new();
    let mut encoder = Encoder::new(&mut pre);
    encoder
        .array(10)
        .unwrap()
        .str("EINSATZARCHIV-TRUST-ANCHOR-PRE-v1")
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(organization_id.as_bytes())
        .unwrap()
        .bytes(chain_id.as_bytes())
        .unwrap()
        .bytes(&root_key_bytes)
        .unwrap()
        .bytes(root_thumbprint.as_bytes())
        .unwrap()
        .bytes(root_certificate_hash.as_bytes())
        .unwrap()
        .array(u64::try_from(admin_certificates.len()).unwrap())
        .unwrap();
    for hash in admin_certificates {
        encoder.bytes(hash.as_bytes()).unwrap();
    }
    encoder
        .array(u64::try_from(admin_bindings.len()).unwrap())
        .unwrap();
    for hash in admin_bindings {
        encoder.bytes(hash.as_bytes()).unwrap();
    }
    encoder.array(0).unwrap();
    let pre_hash = bootstrap_anchor_hash(&pre);

    let mut final_anchor = Vec::new();
    let mut encoder = Encoder::new(&mut final_anchor);
    encoder
        .array(12)
        .unwrap()
        .str("EINSATZARCHIV-TRUST-ANCHOR-v1")
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(pre_hash.as_bytes())
        .unwrap()
        .bytes(organization_id.as_bytes())
        .unwrap()
        .bytes(chain_id.as_bytes())
        .unwrap()
        .bytes(&root_key_bytes)
        .unwrap()
        .bytes(root_thumbprint.as_bytes())
        .unwrap()
        .bytes(root_certificate_hash.as_bytes())
        .unwrap()
        .array(u64::try_from(admin_certificates.len()).unwrap())
        .unwrap();
    for hash in admin_certificates {
        encoder.bytes(hash.as_bytes()).unwrap();
    }
    encoder
        .array(u64::try_from(admin_bindings.len()).unwrap())
        .unwrap();
    for hash in admin_bindings {
        encoder.bytes(hash.as_bytes()).unwrap();
    }
    encoder.bytes(&[0x44; 32]).unwrap().array(0).unwrap();
    final_anchor
}

struct MemorySource {
    hashes: Vec<ObjectHash>,
    objects: BTreeMap<ObjectHash, Arc<[u8]>>,
    visits: Cell<usize>,
    reads: std::cell::RefCell<BTreeMap<ObjectHash, usize>>,
}

impl MemorySource {
    fn new(objects: Vec<Vec<u8>>) -> Self {
        let mut by_hash = BTreeMap::new();
        let mut hashes = Vec::new();
        for bytes in objects {
            let hash = object_hash(&bytes);
            assert!(by_hash.insert(hash, Arc::from(bytes)).is_none());
            hashes.push(hash);
        }
        hashes.reverse();
        Self {
            hashes,
            objects: by_hash,
            visits: Cell::new(0),
            reads: std::cell::RefCell::new(BTreeMap::new()),
        }
    }

    fn total_reads(&self) -> usize {
        self.reads.borrow().values().sum()
    }
}

impl TrustObjectSource for MemorySource {
    fn visit_trust_object_hashes(
        &self,
        visitor: &mut dyn FnMut(ObjectHash) -> Result<(), TrustSourceError>,
    ) -> Result<(), TrustSourceError> {
        self.visits.set(self.visits.get() + 1);
        for hash in &self.hashes {
            visitor(*hash)?;
        }
        Ok(())
    }

    fn read_exact_trust_object(
        &self,
        object_hash: ObjectHash,
    ) -> Result<Option<Arc<[u8]>>, TrustSourceError> {
        *self.reads.borrow_mut().entry(object_hash).or_default() += 1;
        Ok(self.objects.get(&object_hash).cloned())
    }
}

struct SnapshotStore {
    record: Option<PersistedTrustRecord>,
}

impl TrustStateStore for SnapshotStore {
    fn load(&mut self, _key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
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

fn snapshot(
    organization_id: OrganizationId,
    prepared_certificate_hash: ObjectHash,
) -> TrustStateSnapshot {
    let key = TrustStateKey {
        organization_id,
        device_id: device_id(0xf0),
    };
    let mut store = SnapshotStore {
        record: Some(PersistedTrustRecord::new(
            7,
            TrustedTimeState::initial(UnixMillis::new(1_700_000_000_000)),
            Some(RegistryHeadPin::new(
                RegistryVersion::new(9),
                prepared_certificate_hash,
            )),
        )),
    };
    load_trust_state(&mut store, key).unwrap()
}

fn root_signer() -> CoseSigner {
    CoseSigner::from_secret(SecretBytes::new(array32(ROOT_SECRET_HEX)))
}

fn other_signer() -> CoseSigner {
    CoseSigner::from_secret(SecretBytes::new(array32(OTHER_SECRET_HEX)))
}

fn signer_for_key(fixture: KeyFixture) -> CoseSigner {
    match fixture {
        KeyFixture::Root => root_signer(),
        KeyFixture::AdminOne => other_signer(),
        KeyFixture::AdminTwo | KeyFixture::AdminThree => {
            panic!("fixture has no private signer for this public key")
        }
    }
}

fn public_key(fixture: KeyFixture) -> CanonicalPublicCoseKey {
    let literal = match fixture {
        KeyFixture::Root => ROOT_PUBLIC_HEX,
        KeyFixture::AdminOne => ADMIN_ONE_PUBLIC_HEX,
        KeyFixture::AdminTwo => ADMIN_TWO_PUBLIC_HEX,
        KeyFixture::AdminThree => ADMIN_THREE_PUBLIC_HEX,
    };
    CanonicalPublicCoseKey::ed25519(array32(literal)).unwrap()
}

fn organization_id(byte: u8) -> OrganizationId {
    OrganizationId::try_from([byte; 16].as_slice()).unwrap()
}

fn chain_id(byte: u8) -> ChainId {
    ChainId::try_from([byte; 16].as_slice()).unwrap()
}

fn device_id(byte: u8) -> DeviceId {
    DeviceId::try_from([byte; 16].as_slice()).unwrap()
}

fn subject_id(byte: u8) -> SubjectId {
    SubjectId::try_from([byte; 16].as_slice()).unwrap()
}

fn operator_subject_id(byte: u8) -> OperatorSubjectId {
    OperatorSubjectId::try_from([byte; 16].as_slice()).unwrap()
}

fn hash32(byte: u8) -> Hash32 {
    Hash32::try_from([byte; 32].as_slice()).unwrap()
}

fn key_thumbprint(byte: u8) -> KeyThumbprint {
    KeyThumbprint::try_from([byte; 32].as_slice()).unwrap()
}

fn array32(literal: &str) -> [u8; 32] {
    decode_hex(literal).try_into().unwrap()
}

fn decode_hex(literal: &str) -> Vec<u8> {
    assert!(literal.len().is_multiple_of(2));
    literal
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("hex fixture must be lowercase"),
    }
}
