use std::sync::Arc;

use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, SecretBytes};
use ea_format::{
    CertificateKindV1, ClockReleaseAuditV1, ParsedArchiveObject, ReceiptCoreFieldsV1,
    ReceiptCoreV1, ReceiptV1, decode_clock_release_audit, decode_exact_object, encode_receipt,
};
use ea_time::{IndependentTimeKind, TrustedTimeState};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, Hash32, ObjectHash, UnixMillis,
};
use minicbor::Encoder;

use super::{ClockReleaseProof, VerifiedClockRelease, verify_clock_release};
use crate::{
    ClockReleaseReplayKey, IndependentTimeCommit, LocalTimeBlock, PersistedTrustRecord,
    RegistryCandidate, RegistryHeadPin, RegistrySelectionCommit, StateStoreError, TrustStateKey,
    TrustStateStore, VerifiedSignedTime, prepare_local_time, verify_receipt_time,
    verify_registry_candidate,
};

#[allow(clippy::duplicate_mod)]
#[path = "../../tests/support/mod.rs"]
mod support;

use support::{ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder};

const ADMIN_ONE_SECRET: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];
const SERVER_SECRET: [u8; 32] = [
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
];

struct TestStore {
    key: TrustStateKey,
    record: PersistedTrustRecord,
    independent_commits: usize,
    replay_queries: usize,
}

impl TrustStateStore for TestStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(PersistedTrustRecord::new(
            self.record.revision(),
            self.record.trusted_time().clone(),
            self.record.pinned_head().copied(),
        ))
    }

    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        self.independent_commits += 1;
        if key != self.key || expected_revision != self.record.revision() {
            return Err(StateStoreError::Conflict);
        }
        let revision = expected_revision
            .checked_add(7)
            .ok_or(StateStoreError::MonotonicityViolation)?;
        self.record = PersistedTrustRecord::new(
            revision,
            commit.next_trusted_time().clone(),
            self.record.pinned_head().copied(),
        );
        Ok(PersistedTrustRecord::new(
            self.record.revision(),
            self.record.trusted_time().clone(),
            self.record.pinned_head().copied(),
        ))
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.replay_queries += 1;
        Ok(false)
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

struct Fixture {
    candidate: RegistryCandidate,
    store: TestStore,
    source: VerifiedSignedTime,
    exact_audit: Vec<u8>,
    admin_certificate_hash: CertificateHash,
    admin_binding_hash: ObjectHash,
}

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

fn target_device() -> DeviceId {
    DeviceId::try_from(&[0x51; 16][..]).unwrap()
}

fn state_key() -> TrustStateKey {
    TrustStateKey {
        organization_id: support::organization(),
        device_id: target_device(),
    }
}

fn chain_id() -> ChainId {
    ChainId::try_from(&[0x31; 16][..]).unwrap()
}

fn hash32_from_object(hash: ObjectHash) -> Hash32 {
    Hash32::try_from(hash.as_bytes().as_slice()).unwrap()
}

fn server_key() -> CanonicalPublicCoseKey {
    use ed25519_dalek::SigningKey;

    CanonicalPublicCoseKey::ed25519(
        *SigningKey::from_bytes(&SERVER_SECRET)
            .verifying_key()
            .as_bytes(),
    )
    .unwrap()
}

fn receipt_source(
    candidate: &RegistryCandidate,
    authority_head: BuiltHead,
    server_certificate_hash: CertificateHash,
) -> (VerifiedSignedTime, ObjectHash) {
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: support::organization(),
        chain_id: chain_id(),
        chain_sequence: authority_head.effective_from,
        entry_hash: EntryHash::from(support::hash32(0x61)),
        entry_object_hash: ObjectHash::from(support::hash32(0x62)),
        previous_entry_hash: Some(EntryHash::from(support::hash32(0x60))),
        registry_version: authority_head.version,
        registry_head_hash: hash32_from_object(authority_head.object_hash),
        policy_object_hash: ObjectHash::from(support::hash32(0x63)),
        initial_grant_plan_hash: support::hash32(0x64),
        initial_grant_object_hashes: vec![ObjectHash::from(support::hash32(0x65))],
        accepted_at_server: UnixMillis::new(900),
        evidence_due_at: None,
        server_key_thumbprint: server_key().thumbprint(),
        server_certificate_hash,
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
        .sign_receipt(core.exact_bytes())
        .unwrap();
    let exact = encode_receipt(&ReceiptV1::new(core, signature).unwrap()).unwrap();
    let parsed = match decode_exact_object(exact.as_bytes()).unwrap() {
        ParsedArchiveObject::Receipt(receipt) => receipt,
        _ => panic!("private Clock Release fixture must remain an exact Receipt"),
    };
    let object_hash = parsed.object_hash();
    let proof = verify_receipt_time(
        candidate
            .preexisting_authority()
            .expect("H4 must retain H3 as the only time authority"),
        &parsed,
    )
    .unwrap();
    (proof, object_hash)
}

fn exact_clock_release_audit(
    candidate_head: BuiltHead,
    guard_policy_hash: ObjectHash,
    reference_hash: ObjectHash,
    admin_certificate_hash: ObjectHash,
    admin_binding_hash: ObjectHash,
) -> Vec<u8> {
    let mut core = Vec::new();
    Encoder::new(&mut core)
        .array(12)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&[0x01; 16])
        .unwrap()
        .bytes(support::organization().as_bytes())
        .unwrap()
        .bytes(target_device().as_bytes())
        .unwrap()
        .bytes(admin_binding_hash.as_bytes())
        .unwrap()
        .bytes(admin_certificate_hash.as_bytes())
        .unwrap()
        .u8(6)
        .unwrap()
        .u8(1)
        .unwrap()
        .i64(1_100)
        .unwrap()
        .array(2)
        .unwrap()
        .u8(2)
        .unwrap()
        .array(10)
        .unwrap()
        .i64(1_000)
        .unwrap()
        .i64(1_100)
        .unwrap()
        .u64(100)
        .unwrap()
        .u64(candidate_head.version.get())
        .unwrap()
        .bytes(candidate_head.object_hash.as_bytes())
        .unwrap()
        .bytes(guard_policy_hash.as_bytes())
        .unwrap()
        .array(3)
        .unwrap()
        .u8(0)
        .unwrap()
        .bytes(reference_hash.as_bytes())
        .unwrap()
        .i64(900)
        .unwrap()
        .u8(0)
        .unwrap()
        .i64(1_000)
        .unwrap()
        .i64(1_200)
        .unwrap()
        .bytes(&[0xd0; 32])
        .unwrap()
        .array(0)
        .unwrap();
    let cose = CoseSigner::from_secret(SecretBytes::new(ADMIN_ONE_SECRET))
        .sign_local_audit(&core)
        .unwrap();
    let mut exact = Vec::new();
    Encoder::new(&mut exact).array(2).unwrap();
    exact.extend_from_slice(&core);
    exact.extend_from_slice(&cose);
    exact
}

fn fixture() -> Fixture {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    let server_head = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x66,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    let authority_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(39),
            policy_max_future_clock_skew_ms_override: Some(100),
            ..HeadOptions::default()
        },
    );
    let guard_policy_hash = line.current_policy_hash().unwrap();
    let candidate_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(30),
            valid_through: Some(49),
            policy_max_future_clock_skew_ms_override: Some(9_999),
            ..HeadOptions::default()
        },
    );
    let key = state_key();
    let initial_time = TrustedTimeState::initial(UnixMillis::new(1_000));
    let trust = line.verified_with_time_and_key(Pin::Head(2), initial_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(30)).unwrap();
    let pin = RegistryHeadPin::new(authority_head.version, authority_head.object_hash);
    let (source, reference_hash) = receipt_source(
        &candidate,
        authority_head,
        CertificateHash::from(server_head.direct_object_hash.unwrap()),
    );
    let admin_certificate_hash = CertificateHash::from(line.bootstrap_admin_hash());
    let admin_binding_hash = line.bootstrap_admin_binding_hash();
    let exact_audit = exact_clock_release_audit(
        candidate_head,
        guard_policy_hash,
        reference_hash,
        line.bootstrap_admin_hash(),
        admin_binding_hash,
    );
    Fixture {
        candidate,
        store: TestStore {
            key,
            record: PersistedTrustRecord::new(17, initial_time, Some(pin)),
            independent_commits: 0,
            replay_queries: 0,
        },
        source,
        exact_audit,
        admin_certificate_hash,
        admin_binding_hash,
    }
}

fn assert_private_proof_contract(
    verified: &VerifiedClockRelease,
    candidate: &RegistryCandidate,
    local_time: &LocalTimeBlock<'_>,
    expected_audit: &ClockReleaseAuditV1,
) {
    let proof: &ClockReleaseProof = &verified.inner;

    assert!(Arc::ptr_eq(
        &proof.candidate_state,
        &candidate.candidate_state
    ));
    assert!(proof.state_key == local_time.state_key);
    assert_eq!(proof.expected_revision, local_time.expected_revision);
    assert!(proof.trusted_time == local_time.trusted_time);
    assert!(proof.pinned_head == local_time.pinned_head);
    assert!(proof.observed_os_wall_clock == local_time.observed_os_wall_clock);
    assert!(proof.proposed_sequence == local_time.proposed_sequence);
    assert!(proof.pre_transition_sequence == local_time.pre_transition_sequence);
    assert!(proof.raw_now == local_time.evaluation.raw_now());
    assert!(proof.warnings == *local_time.evaluation.warnings());
    assert!(proof.future_skew == local_time.evaluation.future_skew());

    assert_eq!(proof.audit.exact_core(), expected_audit.exact_core());
    assert_eq!(proof.audit.exact_cose(), expected_audit.exact_cose());
    assert_eq!(
        proof.audit.signature_bytes(),
        expected_audit.signature_bytes()
    );
    assert!(proof.audit.organization_id() == expected_audit.organization_id());
    assert!(proof.audit.target_device_id() == expected_audit.target_device_id());
    assert!(proof.audit.nonce() == expected_audit.nonce());
    assert!(proof.audit.context().registry_version() == local_time.candidate_registry_version);
    assert!(proof.audit.context().registry_head_hash() == local_time.candidate_registry_head_hash);
    assert!(
        proof.audit.context().guard_policy_object_hash() == local_time.guard_policy_object_hash
    );
    assert!(proof.audit.context().trusted_time_floor() == local_time.trusted_time.floor());
    assert!(proof.audit.context().observed_os_wall_clock() == local_time.observed_os_wall_clock);
    let reference = local_time
        .trusted_time
        .independent_reference()
        .expect("the blocked private proof fixture must retain one independent reference");
    assert_eq!(reference.kind(), IndependentTimeKind::Receipt);
    assert!(proof.audit.context().independent_reference().object_hash() == reference.object_hash());
    assert!(
        proof
            .audit
            .context()
            .independent_reference()
            .verified_time()
            == reference.verified_time()
    );

    assert!(proof.replay_key.organization_id() == expected_audit.organization_id());
    assert!(proof.replay_key.target_device_id() == expected_audit.target_device_id());
    assert!(proof.replay_key.nonce() == expected_audit.nonce());
}

#[test]
fn verified_clock_release_is_owned_nonzero_drop_state() {
    assert!(core::mem::needs_drop::<VerifiedClockRelease>());
    assert!(core::mem::size_of::<VerifiedClockRelease>() > 0);
}

#[test]
fn real_verify_path_owns_the_exact_audit_replay_candidate_and_returned_block_state() {
    let mut fixture = fixture();
    let expected_audit = decode_clock_release_audit(&fixture.exact_audit).unwrap();
    assert!(
        expected_audit.signer_certificate_object_hash().as_bytes()
            == fixture.admin_certificate_hash.as_bytes()
    );
    assert!(expected_audit.admin_operator_binding_object_hash() == fixture.admin_binding_hash);
    {
        let mut local_time = prepare_local_time(
            &mut fixture.store,
            &fixture.candidate,
            UnixMillis::new(1_100),
            core::slice::from_ref(&fixture.source),
        )
        .unwrap();
        assert_eq!(local_time.expected_revision, 24);
        let verified =
            verify_clock_release(&fixture.candidate, &mut local_time, &fixture.exact_audit)
                .unwrap();

        assert_private_proof_contract(&verified, &fixture.candidate, &local_time, &expected_audit);
    }
    assert_eq!(fixture.store.independent_commits, 1);
    assert_eq!(fixture.store.replay_queries, 1);
}

// The public rustdoc contract in `clock_release.rs` must additionally carry
// compile-fail examples for field construction, Clone, and passing raw audit
// bytes where a `VerifiedClockRelease` is required.
