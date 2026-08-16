mod support;

use ea_crypto::{
    CoseSigner, CoseVerifier, CryptoError, RecoveryVerificationContext, SecretBytes,
    SignerCertificateResolver, SignerRole, object_hash,
};
use ea_format::{CertificateKindV1, DeviceCertificateFieldsV1, OperatorBindingFieldsV1};
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError,
    TrustStateKey, TrustStateStore, prepare_local_time, select_registry_head,
    verify_registry_candidate,
};
use ea_types::{CertificateHash, ChainSequence, Hash32, ObjectHash, RegistryVersion, UnixMillis};

use support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

const DEVICE_SECRET: [u8; 32] = [
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
];
const ADMIN_ONE_SECRET: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];
const ROTATED_ROOT_SECRET: [u8; 32] = [
    0xf5, 0xe5, 0x76, 0x7c, 0xf1, 0x53, 0x31, 0x95, 0x17, 0x63, 0x0f, 0x22, 0x68, 0x76, 0xb8, 0x6c,
    0x81, 0x60, 0xcc, 0x58, 0x3b, 0xc0, 0x13, 0x74, 0x4c, 0x6b, 0xf2, 0x55, 0xf5, 0xcc, 0x0e, 0xe5,
];

#[derive(Clone)]
struct ModelRecord {
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
}

impl ModelRecord {
    fn persisted(&self) -> PersistedTrustRecord {
        PersistedTrustRecord::new(self.revision, self.trusted_time.clone(), self.pinned_head)
    }
}

struct ModelStore {
    key: TrustStateKey,
    record: ModelRecord,
    next_revision: u64,
}

impl TrustStateStore for ModelStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(self.record.persisted())
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
        Ok(false)
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key || expected_revision != self.record.revision {
            return Err(StateStoreError::Conflict);
        }
        self.record = ModelRecord {
            revision: self.next_revision,
            trusted_time: commit.next_trusted_time().clone(),
            pinned_head: Some(*commit.next_head()),
        };
        Ok(self.record.persisted())
    }
}

#[derive(Clone, Copy)]
struct ActiveHashes {
    policy: ObjectHash,
    old_root: CertificateHash,
    current_root: CertificateHash,
    admin: CertificateHash,
    old_writer: CertificateHash,
    writer: CertificateHash,
    reader: CertificateHash,
    key_approver: CertificateHash,
    recovery: CertificateHash,
    historical: CertificateHash,
    server: CertificateHash,
    deletion: CertificateHash,
    reader_binding: ObjectHash,
    admin_binding: ObjectHash,
    prepared: CertificateHash,
}

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

fn hash_of_direct(head: support::BuiltHead) -> CertificateHash {
    CertificateHash::from(head.direct_object_hash.expect("fixture direct certificate"))
}

fn certificate_object_hash(hash: CertificateHash) -> ObjectHash {
    ObjectHash::try_from(hash.as_bytes().as_slice()).expect("certificate hashes are object hashes")
}

fn selected_fixture(proposed_sequence: ChainSequence) -> (SelectedRegistryHead, ActiveHashes) {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(10),
            ..HeadOptions::default()
        },
    );
    let old_root = CertificateHash::from(line.current_root_hash());
    let old_writer_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(11),
            valid_through: Some(20),
            ..HeadOptions::default()
        },
    );
    let writer_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(21),
            valid_through: Some(30),
            ..HeadOptions::default()
        },
    );
    let old_writer = hash_of_direct(old_writer_head);
    let writer = hash_of_direct(writer_head);
    line.push(
        ActionSpec::WriterTransition {
            old_writer: certificate_object_hash(old_writer),
            new_writer: certificate_object_hash(writer),
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(31),
            valid_through: Some(40),
            ..HeadOptions::default()
        },
    );
    let reader_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x63,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(41),
            valid_through: Some(50),
            ..HeadOptions::default()
        },
    );
    let reader = hash_of_direct(reader_head);
    let reader_binding_head = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: certificate_object_hash(reader),
            role: ea_format::OperatorRoleV1::Reader,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(51),
            valid_through: Some(60),
            ..HeadOptions::default()
        },
    );
    let key_approver_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::KeyApprover,
            marker: 0x64,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(61),
            valid_through: Some(70),
            ..HeadOptions::default()
        },
    );
    let recovery_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::RecoveryRecipient,
            marker: 0x65,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(71),
            valid_through: Some(80),
            ..HeadOptions::default()
        },
    );
    let historical_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::HistoricalGrantAuthority,
            marker: 0x66,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(81),
            valid_through: Some(90),
            ..HeadOptions::default()
        },
    );
    let server_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x67,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(91),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    let deletion_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::DeletionAttest,
            marker: 0x68,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(101),
            valid_through: Some(110),
            ..HeadOptions::default()
        },
    );
    let rotation_head = line.push(
        ActionSpec::RootRotate {
            previous_root_hash: None,
            effective_version: None,
        },
        HeadOptions {
            effective_from: Some(111),
            valid_through: Some(200),
            ..HeadOptions::default()
        },
    );
    let current_root = CertificateHash::from(line.current_root_hash());
    let prepared = CertificateHash::from(line.add_prepared(ActionSpec::Device {
        kind: CertificateKindV1::Reader,
        marker: 0x69,
        effective_from: Some(130),
    }));
    let key = support::state_key();
    let trusted_time = TrustedTimeState::initial(UnixMillis::new(1_000));
    let trust = line.verified_with_record(Pin::Head(11), 17, trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, proposed_sequence).unwrap();
    let mut store = ModelStore {
        key,
        record: ModelRecord {
            revision: 17,
            trusted_time,
            pinned_head: Some(RegistryHeadPin::new(
                rotation_head.version,
                rotation_head.object_hash,
            )),
        },
        next_revision: 41,
    };
    let local_time =
        prepare_local_time(&mut store, &candidate, UnixMillis::new(1_000), &[]).unwrap();
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the authority fixture must select its current Head");
    };
    (
        selected,
        ActiveHashes {
            policy: line.current_policy_hash().expect("selected target Policy"),
            old_root,
            current_root,
            admin: CertificateHash::from(line.bootstrap_admin_hash()),
            old_writer,
            writer,
            reader,
            key_approver: hash_of_direct(key_approver_head),
            recovery: hash_of_direct(recovery_head),
            historical: hash_of_direct(historical_head),
            server: hash_of_direct(server_head),
            deletion: hash_of_direct(deletion_head),
            reader_binding: reader_binding_head
                .direct_object_hash
                .expect("reader binding object"),
            admin_binding: line.bootstrap_admin_binding_hash(),
            prepared,
        },
    )
}

fn select_current_head(
    line: &RegistryLineBuilder,
    head_index: usize,
    proposed_sequence: ChainSequence,
) -> SelectedRegistryHead {
    let head = line.heads()[head_index];
    let key = support::state_key();
    let trusted_time = TrustedTimeState::initial(UnixMillis::new(1_000));
    let trust = line.verified_with_record(Pin::Head(head_index), 17, trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, proposed_sequence).unwrap();
    let mut store = ModelStore {
        key,
        record: ModelRecord {
            revision: 17,
            trusted_time,
            pinned_head: Some(RegistryHeadPin::new(head.version, head.object_hash)),
        },
        next_revision: 43,
    };
    let local_time =
        prepare_local_time(&mut store, &candidate, UnixMillis::new(1_000), &[]).unwrap();
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the helper requires a current operation-authoritative Head");
    };
    selected
}

fn verify_recovery_profile(
    selected: &SelectedRegistryHead,
    certificate_hash: CertificateHash,
    secret: [u8; 32],
    role: SignerRole,
    sequence: ChainSequence,
    registry: RegistryVersion,
) -> Result<(), CryptoError> {
    let challenge = [0x5a; 32];
    let exact = CoseSigner::from_secret(SecretBytes::new(secret))
        .sign_recovery_test(certificate_hash, SecretBytes::new(challenge))?;
    let context = RecoveryVerificationContext::new(
        certificate_hash,
        support::organization(),
        role,
        sequence,
        registry,
        SecretBytes::new(challenge),
    );
    CoseVerifier::verify_recovery_test(&exact, selected, &context).map(|_| ())
}

fn assert_selected_registry_authority_contract(selected: &SelectedRegistryHead) {
    let _: ChainSequence = selected.proposed_sequence();
    let _: Option<&DeviceCertificateFieldsV1> =
        selected.active_certificate_fields(CertificateHash::from(ObjectHash::from(Hash32::ZERO)));
    let _: Option<&[String]> =
        selected.active_capabilities(CertificateHash::from(ObjectHash::from(Hash32::ZERO)));
    let _: Option<&OperatorBindingFieldsV1> =
        selected.active_operator_binding_fields(ObjectHash::from(Hash32::ZERO));
    let _: &dyn SignerCertificateResolver = selected;
}

#[test]
fn selected_registry_head_resolves_every_active_certificate_kind_at_one_exact_sequence() {
    let selected_sequence = ChainSequence::new(120);
    let (selected, hashes) = selected_fixture(selected_sequence);
    assert_selected_registry_authority_contract(&selected);
    assert_eq!(selected.proposed_sequence(), selected_sequence);

    let cases = [
        (hashes.writer, DEVICE_SECRET, SignerRole::Writer),
        (hashes.reader, DEVICE_SECRET, SignerRole::Reader),
        (
            hashes.admin,
            ADMIN_ONE_SECRET,
            SignerRole::OrganizationAdmin,
        ),
        (hashes.key_approver, DEVICE_SECRET, SignerRole::KeyApprover),
        (
            hashes.historical,
            DEVICE_SECRET,
            SignerRole::HistoricalGrantAuthority,
        ),
        (hashes.server, DEVICE_SECRET, SignerRole::ServerReceipt),
        (hashes.deletion, DEVICE_SECRET, SignerRole::DeletionAttest),
        (hashes.current_root, ROTATED_ROOT_SECRET, SignerRole::Root),
    ];
    for (certificate_hash, secret, role) in cases {
        verify_recovery_profile(
            &selected,
            certificate_hash,
            secret,
            role,
            selected_sequence,
            selected.registry_version(),
        )
        .unwrap_or_else(|error| panic!("{role:?}: {}", error.code()));
    }

    let reader = selected
        .active_certificate_fields(hashes.reader)
        .expect("the activated Reader must be queryable");
    assert_eq!(reader.certificate_kind, CertificateKindV1::Reader);
    assert_eq!(
        selected
            .active_certificate_fields(hashes.recovery)
            .map(|certificate| certificate.certificate_kind),
        Some(CertificateKindV1::RecoveryRecipient)
    );
    let resolved_recovery =
        SignerCertificateResolver::resolve(&selected, hashes.recovery, selected.registry_version())
            .unwrap();
    assert!(
        CertificateHash::from(object_hash(resolved_recovery.exact_certificate_bytes))
            == hashes.recovery
    );
    assert_eq!(
        resolved_recovery.registry_effective_from_sequence,
        selected_sequence
    );
    assert_eq!(
        resolved_recovery.registry_revoked_from_sequence,
        Some(ChainSequence::new(121))
    );
    assert!(selected.policy_object_hash() == hashes.policy);
    assert_eq!(selected.policy_fields().policy_version, 1);
    assert_eq!(
        selected.policy_fields().effective_from_sequence,
        ChainSequence::new(1)
    );
    assert_eq!(selected.active_capabilities(hashes.reader), Some(&[][..]));
    assert_eq!(selected.active_capabilities(hashes.recovery), Some(&[][..]));
    assert_eq!(
        selected.active_capabilities(hashes.admin),
        Some(&[String::from("organizationAdminApprove")][..])
    );
    assert_eq!(
        selected.active_capabilities(hashes.writer),
        Some(&[String::from("initialGrant")][..])
    );
    assert_eq!(
        selected.active_capabilities(hashes.key_approver),
        Some(&[String::from("historicalGrantApprove")][..])
    );
    assert_eq!(
        selected.active_capabilities(hashes.historical),
        Some(&[String::from("historicalGrant")][..])
    );
    assert_eq!(
        selected.active_capabilities(hashes.server),
        Some(&[String::from("serverReceipt")][..])
    );
    assert_eq!(
        selected.active_capabilities(hashes.deletion),
        Some(&[String::from("deletionAttest")][..])
    );
    assert!(
        selected
            .active_operator_binding_fields(hashes.reader_binding)
            .map(|binding| binding.device_certificate_hash)
            == Some(hashes.reader)
    );
    assert!(
        selected
            .active_operator_binding_fields(hashes.admin_binding)
            .map(|binding| binding.device_certificate_hash)
            == Some(hashes.admin)
    );
    assert!(
        selected
            .active_certificate_fields(hashes.old_writer)
            .is_none()
    );
    assert!(
        selected
            .active_certificate_fields(hashes.prepared)
            .is_none()
    );
    assert_eq!(
        SignerCertificateResolver::resolve(&selected, hashes.old_root, selected.registry_version())
            .err()
            .map(CryptoError::code),
        Some("EA-TRUST-SIGNER-UNRESOLVED")
    );
}

#[test]
fn selected_resolver_is_clipped_to_the_exact_sequence_and_registry() {
    let selected_sequence = ChainSequence::new(120);
    let (selected, hashes) = selected_fixture(selected_sequence);
    let resolved =
        SignerCertificateResolver::resolve(&selected, hashes.reader, selected.registry_version())
            .unwrap();
    assert_eq!(resolved.registry_effective_from_sequence, selected_sequence);
    assert_eq!(
        resolved.registry_revoked_from_sequence,
        Some(ChainSequence::new(121))
    );

    for sequence in [ChainSequence::new(119), ChainSequence::new(121)] {
        assert_eq!(
            verify_recovery_profile(
                &selected,
                hashes.reader,
                DEVICE_SECRET,
                SignerRole::Reader,
                sequence,
                selected.registry_version(),
            )
            .unwrap_err()
            .code(),
            "EA-TRUST-SIGNER-UNAUTHORIZED"
        );
    }
    for registry in [
        RegistryVersion::new(selected.registry_version().get() - 1),
        RegistryVersion::new(selected.registry_version().get() + 1),
    ] {
        assert_eq!(
            verify_recovery_profile(
                &selected,
                hashes.reader,
                DEVICE_SECRET,
                SignerRole::Reader,
                selected_sequence,
                registry,
            )
            .unwrap_err()
            .code(),
            "EA-TRUST-SIGNER-UNRESOLVED"
        );
    }
}

#[test]
fn direct_root_successor_exposes_candidate_authority_not_previous_authority() {
    let mut line = RegistryLineBuilder::new();
    let previous = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(10),
            ..HeadOptions::default()
        },
    );
    let old_root = CertificateHash::from(line.current_root_hash());
    let successor = line.push(
        ActionSpec::RootRotate {
            previous_root_hash: None,
            effective_version: None,
        },
        HeadOptions {
            effective_from: Some(11),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    let new_root = CertificateHash::from(line.current_root_hash());
    let key = support::state_key();
    let trusted_time = TrustedTimeState::initial(UnixMillis::new(1_000));
    let trust = line.verified_with_record(Pin::Head(0), 17, trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(20)).unwrap();
    let mut store = ModelStore {
        key,
        record: ModelRecord {
            revision: 17,
            trusted_time,
            pinned_head: Some(RegistryHeadPin::new(previous.version, previous.object_hash)),
        },
        next_revision: 47,
    };
    let local_time =
        prepare_local_time(&mut store, &candidate, UnixMillis::new(1_000), &[]).unwrap();
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("the direct Root successor must be selected");
    };

    assert!(selected.registry_version() == successor.version);
    assert!(selected.registry_head_hash() == successor.object_hash);
    verify_recovery_profile(
        &selected,
        new_root,
        ROTATED_ROOT_SECRET,
        SignerRole::Root,
        ChainSequence::new(20),
        successor.version,
    )
    .unwrap();
    let resolved_root =
        SignerCertificateResolver::resolve(&selected, new_root, successor.version).unwrap();
    assert_eq!(
        resolved_root.registry_effective_from_sequence,
        ChainSequence::new(20)
    );
    assert_eq!(
        resolved_root.registry_revoked_from_sequence,
        Some(ChainSequence::new(21))
    );
    for sequence in [ChainSequence::new(19), ChainSequence::new(21)] {
        assert_eq!(
            verify_recovery_profile(
                &selected,
                new_root,
                ROTATED_ROOT_SECRET,
                SignerRole::Root,
                sequence,
                successor.version,
            )
            .unwrap_err()
            .code(),
            "EA-TRUST-SIGNER-UNAUTHORIZED"
        );
    }
    for registry in [
        RegistryVersion::new(successor.version.get() - 1),
        RegistryVersion::new(successor.version.get() + 1),
    ] {
        assert_eq!(
            SignerCertificateResolver::resolve(&selected, new_root, registry)
                .err()
                .expect("the Root resolver must reject an adjacent Registry")
                .code(),
            "EA-TRUST-SIGNER-UNRESOLVED"
        );
    }
    assert_eq!(
        SignerCertificateResolver::resolve(&selected, old_root, successor.version)
            .err()
            .expect("the previous Root must not resolve")
            .code(),
        "EA-TRUST-SIGNER-UNRESOLVED"
    );
}

#[test]
fn standby_writer_is_not_authority_even_while_its_wire_schedule_is_active() {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(10),
            ..HeadOptions::default()
        },
    );
    let current = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(11),
            valid_through: Some(20),
            ..HeadOptions::default()
        },
    );
    let current_writer = hash_of_direct(current);
    let current_binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: certificate_object_hash(current_writer),
            role: ea_format::OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(21),
            valid_through: Some(30),
            ..HeadOptions::default()
        },
    );
    let current_binding = current_binding
        .direct_object_hash
        .expect("current Writer Binding");
    let standby = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(31),
            valid_through: Some(40),
            ..HeadOptions::default()
        },
    );
    let standby = hash_of_direct(standby);
    let standby_binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: certificate_object_hash(standby),
            role: ea_format::OperatorRoleV1::Writer,
            marker: 0x72,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(41),
            valid_through: Some(50),
            ..HeadOptions::default()
        },
    );
    let standby_binding = standby_binding
        .direct_object_hash
        .expect("standby Writer Binding");
    let selected = select_current_head(&line, 4, ChainSequence::new(45));

    assert!(selected.active_certificate_fields(current_writer).is_some());
    assert!(
        selected
            .active_operator_binding_fields(current_binding)
            .is_some()
    );
    assert!(selected.active_certificate_fields(standby).is_none());
    assert_eq!(selected.active_capabilities(standby), None);
    assert!(
        selected
            .active_operator_binding_fields(standby_binding)
            .is_none()
    );
    assert_eq!(
        SignerCertificateResolver::resolve(&selected, standby, selected.registry_version())
            .err()
            .expect("the standby Writer must not resolve")
            .code(),
        "EA-TRUST-SIGNER-UNRESOLVED"
    );
}

#[test]
fn revoked_certificate_and_its_still_live_binding_are_both_non_authoritative() {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(10),
            ..HeadOptions::default()
        },
    );
    let reader = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x63,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(11),
            valid_through: Some(20),
            ..HeadOptions::default()
        },
    );
    let reader = hash_of_direct(reader);
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: certificate_object_hash(reader),
            role: ea_format::OperatorRoleV1::Reader,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(21),
            valid_through: Some(29),
            ..HeadOptions::default()
        },
    );
    let binding = binding.direct_object_hash.expect("Reader Binding");
    line.push(
        ActionSpec::Revoke {
            target_kind: 0,
            object_hash: certificate_object_hash(reader),
        },
        HeadOptions {
            effective_from: Some(30),
            valid_through: Some(40),
            ..HeadOptions::default()
        },
    );
    let selected = select_current_head(&line, 3, ChainSequence::new(30));

    assert!(selected.active_certificate_fields(reader).is_none());
    assert_eq!(selected.active_capabilities(reader), None);
    assert!(selected.active_operator_binding_fields(binding).is_none());
    assert_eq!(
        SignerCertificateResolver::resolve(&selected, reader, selected.registry_version())
            .err()
            .expect("the revoked Reader must not resolve")
            .code(),
        "EA-TRUST-SIGNER-UNRESOLVED"
    );
}

#[test]
fn binding_revoked_at_the_selected_sequence_is_not_visible() {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(10),
            ..HeadOptions::default()
        },
    );
    let reader = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x63,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(11),
            valid_through: Some(20),
            ..HeadOptions::default()
        },
    );
    let reader = hash_of_direct(reader);
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: certificate_object_hash(reader),
            role: ea_format::OperatorRoleV1::Reader,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(21),
            valid_through: Some(29),
            ..HeadOptions::default()
        },
    );
    let binding = binding.direct_object_hash.expect("Reader Binding");
    line.push(
        ActionSpec::Revoke {
            target_kind: 1,
            object_hash: binding,
        },
        HeadOptions {
            effective_from: Some(30),
            valid_through: Some(40),
            ..HeadOptions::default()
        },
    );
    let selected = select_current_head(&line, 3, ChainSequence::new(30));

    assert!(selected.active_certificate_fields(reader).is_some());
    assert!(selected.active_operator_binding_fields(binding).is_none());
}

#[test]
fn certificate_and_binding_are_visible_at_exact_start_and_last_active_sequence() {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(10),
            ..HeadOptions::default()
        },
    );
    let reader = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x63,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(11),
            valid_through: Some(20),
            revoked_from_sequence: Some(ChainSequence::new(31)),
            ..HeadOptions::default()
        },
    );
    let reader = hash_of_direct(reader);
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: certificate_object_hash(reader),
            role: ea_format::OperatorRoleV1::Reader,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(21),
            valid_through: Some(100),
            revoked_from_sequence: Some(ChainSequence::new(31)),
            ..HeadOptions::default()
        },
    );
    let binding = binding.direct_object_hash.expect("Reader Binding");

    let at_certificate_start = select_current_head(&line, 1, ChainSequence::new(11));
    assert!(
        at_certificate_start
            .active_certificate_fields(reader)
            .is_some()
    );

    let at_binding_start = select_current_head(&line, 2, ChainSequence::new(21));
    assert!(
        at_binding_start
            .active_operator_binding_fields(binding)
            .is_some()
    );

    let at_last_active = select_current_head(&line, 2, ChainSequence::new(30));
    assert!(at_last_active.active_certificate_fields(reader).is_some());
    assert!(
        at_last_active
            .active_operator_binding_fields(binding)
            .is_some()
    );
    verify_recovery_profile(
        &at_last_active,
        reader,
        DEVICE_SECRET,
        SignerRole::Reader,
        ChainSequence::new(30),
        at_last_active.registry_version(),
    )
    .unwrap();

    let at_revocation = select_current_head(&line, 2, ChainSequence::new(31));
    assert!(at_revocation.active_certificate_fields(reader).is_none());
    assert!(
        at_revocation
            .active_operator_binding_fields(binding)
            .is_none()
    );
    assert_eq!(
        SignerCertificateResolver::resolve(
            &at_revocation,
            reader,
            at_revocation.registry_version(),
        )
        .err()
        .expect("the Reader must not resolve at its revocation sequence")
        .code(),
        "EA-TRUST-SIGNER-UNRESOLVED"
    );
}

#[test]
fn selected_sequence_max_clips_without_overflow() {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(u64::MAX),
            ..HeadOptions::default()
        },
    );
    let selected = select_current_head(&line, 0, ChainSequence::new(u64::MAX));
    let admin = CertificateHash::from(line.bootstrap_admin_hash());
    let root = CertificateHash::from(line.current_root_hash());
    let resolved =
        SignerCertificateResolver::resolve(&selected, admin, selected.registry_version()).unwrap();
    let resolved_root =
        SignerCertificateResolver::resolve(&selected, root, selected.registry_version()).unwrap();

    assert_eq!(selected.proposed_sequence(), ChainSequence::new(u64::MAX));
    assert_eq!(
        resolved.registry_effective_from_sequence,
        ChainSequence::new(u64::MAX)
    );
    assert_eq!(resolved.registry_revoked_from_sequence, None);
    assert_eq!(
        resolved_root.registry_effective_from_sequence,
        ChainSequence::new(u64::MAX)
    );
    assert_eq!(resolved_root.registry_revoked_from_sequence, None);
    verify_recovery_profile(
        &selected,
        admin,
        ADMIN_ONE_SECRET,
        SignerRole::OrganizationAdmin,
        ChainSequence::new(u64::MAX),
        selected.registry_version(),
    )
    .unwrap();
}

/// Ohne Aufzaehlung ist der initiale Grant-Plan (design.md §14.1 Gate 6,
/// `grant-plan`) nicht rekonstruierbar: er braucht die MENGE aller zur
/// Eintragssequenz aktiven Empfaenger, waehrend `active_certificate_fields`
/// und `active_capabilities` nur Punktabfragen sind.
#[test]
fn a_selected_head_enumerates_every_active_certificate_deterministically() {
    let selected_sequence = ChainSequence::new(120);
    let (selected, hashes) = selected_fixture(selected_sequence);

    let enumerated: Vec<CertificateHash> = selected
        .active_certificates()
        .map(|(hash, _)| hash)
        .collect();

    // Deterministisch: streng aufsteigend nach CertificateHash, keine Duplikate.
    let mut sorted = enumerated.clone();
    sorted.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    sorted.dedup_by(|left, right| left.as_bytes() == right.as_bytes());
    assert_eq!(
        enumerated.len(),
        sorted.len(),
        "enumeration must be duplicate-free"
    );
    for (position, hash) in enumerated.iter().enumerate() {
        assert_eq!(
            hash.as_bytes(),
            sorted[position].as_bytes(),
            "enumeration must be sorted bytewise ascending"
        );
    }

    // Die Aufzaehlung stimmt exakt mit der Punktabfrage ueberein — in beide
    // Richtungen, sonst waere sie eine zweite, driftende Wahrheit.
    for (hash, fields) in selected.active_certificates() {
        let point = selected
            .active_certificate_fields(hash)
            .expect("every enumerated certificate must resolve pointwise");
        assert_eq!(
            point.certificate_kind, fields.certificate_kind,
            "enumeration and point lookup must agree"
        );
    }
    for candidate in [
        hashes.reader,
        hashes.key_approver,
        hashes.recovery,
        hashes.historical,
        hashes.server,
        hashes.writer,
    ] {
        assert!(
            enumerated
                .iter()
                .any(|hash| hash.as_bytes() == candidate.as_bytes()),
            "an active certificate must appear in the enumeration"
        );
    }

    // Der abgeloeste Writer ist nicht aktiv und DARF nicht erscheinen.
    assert!(
        selected
            .active_certificate_fields(hashes.old_writer)
            .is_none(),
        "fixture precondition: the superseded writer is inactive"
    );
    assert!(
        !enumerated
            .iter()
            .any(|hash| hash.as_bytes() == hashes.old_writer.as_bytes()),
        "an inactive certificate must never be enumerated"
    );
}
