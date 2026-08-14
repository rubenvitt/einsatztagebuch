use ea_crypto::{CryptoError, VerificationContext, parse_cose_sign1, verify_cose_sign1};
use ea_format::{DecodedEvidencePayloadV1, EvidenceKindV1, EvidenceObjectV1, Parsed, ReceiptV1};
use ea_time::{
    IndependentTimeInput, IndependentTimeKind, TimeError, TimeEvaluation, TrustedTimeState,
    evaluate_preexisting_time, merge_independent_references,
};
use ea_types::{ChainSequence, ObjectHash, RegistryVersion, UnixMillis};

use crate::{
    PreexistingRegistryAuthority, RegistryCandidate, RegistryHeadPin, TrustError, TrustStateKey,
    TrustStateStore,
    resolver::{PreviousHeadResolver, PreviousHeadState},
    state::{IndependentTimeCommit, map_store_error},
};

/// A signed independent time source verified against one exact previous Head.
///
/// The proof deliberately has no public raw-value constructor or field getter.
/// It is consumed by the later persistent time transition as an opaque value.
///
/// ```compile_fail
/// use ea_trust::VerifiedSignedTime;
/// fn duplicate(proof: VerifiedSignedTime) { let _ = proof.clone(); }
/// ```
pub struct VerifiedSignedTime {
    #[cfg_attr(not(test), allow(dead_code))]
    input: IndependentTimeInput,
    #[cfg_attr(not(test), allow(dead_code))]
    authority_head: RegistryHeadPin,
}

/// A candidate-bound local-time evaluation that keeps exclusive access to the
/// persistent store until Registry selection consumes it.
///
/// The block deliberately cannot be cloned:
///
/// ```compile_fail
/// use ea_trust::LocalTimeBlock;
/// fn duplicate(block: LocalTimeBlock<'_>) { let _ = block.clone(); }
/// ```
///
/// Its physical store borrow also prevents a competing write through the same
/// handle while the block is live:
///
/// ```compile_fail
/// use ea_trust::{
///     LocalTimeBlock, RegistryCandidate, TrustStateKey, TrustStateStore,
///     VerifiedSignedTime, prepare_local_time,
/// };
/// use ea_types::UnixMillis;
/// fn reborrow<'a>(
///     store: &'a mut dyn TrustStateStore,
///     key: TrustStateKey,
///     candidate: &RegistryCandidate,
///     sources: &[VerifiedSignedTime],
/// ) {
///     let block: LocalTimeBlock<'a> =
///         prepare_local_time(store, candidate, UnixMillis::new(0), sources).unwrap();
///     let _ = store.load(key);
///     drop(block);
/// }
/// ```
pub struct LocalTimeBlock<'store> {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) store: &'store mut dyn TrustStateStore,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) state_key: TrustStateKey,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) expected_revision: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) trusted_time: TrustedTimeState,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) pinned_head: Option<RegistryHeadPin>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) observed_os_wall_clock: UnixMillis,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) candidate_registry_version: RegistryVersion,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) candidate_registry_head_hash: ObjectHash,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) guard_policy_object_hash: ObjectHash,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) proposed_sequence: ChainSequence,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) pre_transition_sequence: ChainSequence,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) evaluation: TimeEvaluation,
}

pub fn prepare_local_time<'store>(
    store: &'store mut dyn TrustStateStore,
    candidate: &RegistryCandidate,
    os_wall_clock: UnixMillis,
    sources: &[VerifiedSignedTime],
) -> Result<LocalTimeBlock<'store>, TrustError> {
    let persisted = store.load(candidate.state_key).map_err(map_store_error)?;
    if persisted.revision() != candidate.state_revision
        || persisted.trusted_time() != &candidate.trusted_time
        || persisted.pinned_head().copied() != candidate.original_pin
    {
        return Err(TrustError::StateConflict);
    }

    for source in sources {
        if Some(source.authority_head) != candidate.original_pin {
            return Err(TrustError::StateConflict);
        }
    }

    let mut next_trusted_time = persisted.trusted_time().clone();
    let mut changed = false;
    for source in sources {
        let advance =
            merge_independent_references(&next_trusted_time, core::slice::from_ref(&source.input))
                .map_err(map_time_error)?;
        changed |= advance.changed();
        next_trusted_time = advance.state().clone();
    }

    let (expected_revision, trusted_time) = if changed {
        let commit = IndependentTimeCommit::new(next_trusted_time);
        let committed = store
            .commit_independent_time(candidate.state_key, candidate.state_revision, &commit)
            .map_err(map_store_error)?;
        if committed.revision() <= candidate.state_revision
            || committed.trusted_time() != commit.next_trusted_time()
            || committed.pinned_head().copied() != candidate.original_pin
        {
            return Err(TrustError::StateConflict);
        }
        (committed.revision(), committed.trusted_time().clone())
    } else {
        (persisted.revision(), persisted.trusted_time().clone())
    };

    let evaluation = evaluate_preexisting_time(
        os_wall_clock,
        &trusted_time,
        candidate.guard_policy.fields.max_future_clock_skew_ms,
    )
    .map_err(map_time_error)?;

    Ok(LocalTimeBlock {
        store,
        state_key: candidate.state_key,
        expected_revision,
        trusted_time,
        pinned_head: candidate.original_pin,
        observed_os_wall_clock: os_wall_clock,
        candidate_registry_version: candidate.registry_version(),
        candidate_registry_head_hash: candidate.registry_head_hash(),
        guard_policy_object_hash: candidate.guard_policy.object_hash,
        proposed_sequence: candidate.proposed_sequence,
        pre_transition_sequence: candidate.pre_transition_sequence,
        evaluation,
    })
}

const fn map_time_error(error: TimeError) -> TrustError {
    match error {
        TimeError::Overflow => TrustError::TimeOverflow,
        TimeError::StateMonotonicity => TrustError::StateMonotonicity,
        _ => TrustError::StateMonotonicity,
    }
}

pub fn verify_receipt_time(
    authority: &PreexistingRegistryAuthority,
    receipt: &Parsed<ReceiptV1>,
) -> Result<VerifiedSignedTime, TrustError> {
    let state = &authority.inner;
    let core = receipt.value().core();
    let fields = core.fields();
    if fields.organization_id != state.root.fields.organization_id
        || fields.registry_version != state.registry_version
        || fields.registry_head_hash != state.registry_head_hash
        || !head_covers_sequence(state, fields.chain_sequence)
    {
        return Err(TrustError::ActionMismatch);
    }

    let context =
        VerificationContext::receipt(core.exact_bytes()).map_err(|_| TrustError::Signature)?;
    verify_cose_sign1(
        receipt.value().server_signature(),
        &PreviousHeadResolver::new(state),
        &context,
    )
    .map_err(map_signed_time_crypto_error)?;

    Ok(VerifiedSignedTime {
        input: IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            receipt.object_hash(),
            fields.accepted_at_server,
        ),
        authority_head: authority_head(state),
    })
}

pub fn verify_checkpoint_time(
    authority: &PreexistingRegistryAuthority,
    evidence: &Parsed<EvidenceObjectV1>,
) -> Result<VerifiedSignedTime, TrustError> {
    if evidence.value().kind() != EvidenceKindV1::StandardCheckpoint {
        return Err(TrustError::TimeSourceUnsupported);
    }

    let DecodedEvidencePayloadV1::Standard { core, exact_cose } = evidence
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Signature)?
    else {
        return Err(TrustError::TimeSourceUnsupported);
    };
    let state = &authority.inner;
    let fields = core.fields();
    if fields.organization_id != state.root.fields.organization_id
        || fields.registry_head_hash != state.registry_head_hash
        || fields.covered_from_sequence > fields.covered_through_sequence
        || !head_covers_sequence(state, fields.covered_through_sequence)
    {
        return Err(TrustError::ActionMismatch);
    }

    let certificate_hash = parse_cose_sign1(&exact_cose, &[])
        .map_err(|_| TrustError::Signature)?
        .certificate_hash()
        .ok_or(TrustError::Signature)?;
    let context = VerificationContext::checkpoint(
        core.exact_bytes(),
        certificate_hash,
        state.registry_version,
    )
    .map_err(|_| TrustError::Signature)?;
    verify_cose_sign1(&exact_cose, &PreviousHeadResolver::new(state), &context)
        .map_err(map_signed_time_crypto_error)?;

    Ok(VerifiedSignedTime {
        input: IndependentTimeInput::new(
            IndependentTimeKind::Checkpoint,
            evidence.object_hash(),
            fields.issued_at_server,
        ),
        authority_head: authority_head(state),
    })
}

fn head_covers_sequence(state: &PreviousHeadState, sequence: ChainSequence) -> bool {
    state.effective_from_sequence <= sequence && sequence <= state.valid_through_sequence
}

fn authority_head(state: &PreviousHeadState) -> RegistryHeadPin {
    RegistryHeadPin::new(
        state.registry_version,
        ObjectHash::from(state.registry_head_hash),
    )
}

fn map_signed_time_crypto_error(error: CryptoError) -> TrustError {
    match error {
        CryptoError::SignerUnresolved | CryptoError::SignerUnauthorized => {
            TrustError::SignerInactive
        }
        _ => TrustError::Signature,
    }
}

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;

#[cfg(test)]
mod tests {
    use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, SecretBytes, object_hash};
    use ea_format::{
        CheckpointCoreFieldsV1, CheckpointCoreV1, EvidenceObjectV1, Parsed, ParsedArchiveObject,
        ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1, decode_exact_object, encode_evidence,
        encode_receipt,
    };
    use ea_time::{IndependentTimeKind, TrustedTimeState, merge_independent_references};
    use ea_types::{
        CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, RegistryVersion,
        UnixMillis,
    };

    use super::support::{self, ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder};
    use super::{VerifiedSignedTime, verify_checkpoint_time, verify_receipt_time};
    use crate::{
        ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryCandidate,
        RegistryHeadPin, RegistrySelectionCommit, StateStoreError, TrustStateKey, TrustStateStore,
        prepare_local_time, verify_registry_candidate,
    };

    const SERVER_SECRET: [u8; 32] = [
        0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91,
        0x1e, 0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca,
        0x3d, 0x42,
    ];

    struct Fixture {
        candidate: RegistryCandidate,
        head: BuiltHead,
        certificate_hash: CertificateHash,
    }

    fn policy() -> ActionSpec {
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        }
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
        let certificate_head = line.push(
            ActionSpec::Device {
                kind: ea_format::CertificateKindV1::ServerReceipt,
                marker: 0x69,
                effective_from: None,
            },
            HeadOptions {
                effective_from: Some(10),
                valid_through: Some(19),
                ..HeadOptions::default()
            },
        );
        let head = line.push(
            policy(),
            HeadOptions {
                effective_from: Some(20),
                valid_through: Some(29),
                ..HeadOptions::default()
            },
        );
        let trust = line.verified(Pin::Head(2));
        let candidate = verify_registry_candidate(&trust, ChainSequence::new(25)).unwrap();
        Fixture {
            candidate,
            head,
            certificate_hash: CertificateHash::from(certificate_head.direct_object_hash.unwrap()),
        }
    }

    fn successor_policy_fixture(guard_skew: u64, target_skew: u64) -> Fixture {
        let mut line = RegistryLineBuilder::new();
        line.push(
            policy(),
            HeadOptions {
                effective_from: Some(1),
                valid_through: Some(9),
                ..HeadOptions::default()
            },
        );
        let certificate_head = line.push(
            ActionSpec::Device {
                kind: ea_format::CertificateKindV1::ServerReceipt,
                marker: 0x69,
                effective_from: None,
            },
            HeadOptions {
                effective_from: Some(10),
                valid_through: Some(19),
                ..HeadOptions::default()
            },
        );
        let head = line.push(
            policy(),
            HeadOptions {
                effective_from: Some(20),
                valid_through: Some(29),
                policy_max_future_clock_skew_ms_override: Some(guard_skew),
                ..HeadOptions::default()
            },
        );
        line.push(
            policy(),
            HeadOptions {
                effective_from: Some(30),
                valid_through: Some(39),
                policy_max_future_clock_skew_ms_override: Some(target_skew),
                ..HeadOptions::default()
            },
        );
        let trust = line.verified(Pin::Head(2));
        let candidate = verify_registry_candidate(&trust, ChainSequence::new(30)).unwrap();
        Fixture {
            candidate,
            head,
            certificate_hash: CertificateHash::from(certificate_head.direct_object_hash.unwrap()),
        }
    }

    fn chain_id() -> ChainId {
        ChainId::try_from(&[0x31; 16][..]).unwrap()
    }

    fn head_hash(head: BuiltHead) -> Hash32 {
        Hash32::try_from(head.object_hash.as_bytes().as_slice()).unwrap()
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

    fn receipt(fixture: &Fixture) -> Parsed<ReceiptV1> {
        let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
            organization_id: support::organization(),
            chain_id: chain_id(),
            chain_sequence: ChainSequence::new(20),
            entry_hash: EntryHash::from(support::hash32(0x61)),
            entry_object_hash: ObjectHash::from(support::hash32(0x62)),
            previous_entry_hash: Some(EntryHash::from(support::hash32(0x60))),
            registry_version: fixture.head.version,
            registry_head_hash: head_hash(fixture.head),
            policy_object_hash: ObjectHash::from(support::hash32(0x63)),
            initial_grant_plan_hash: support::hash32(0x64),
            initial_grant_object_hashes: vec![ObjectHash::from(support::hash32(0x65))],
            accepted_at_server: UnixMillis::new(1_800_000_000_123),
            evidence_due_at: Some(UnixMillis::new(1_800_000_060_123)),
            server_key_thumbprint: server_key().thumbprint(),
            server_certificate_hash: fixture.certificate_hash,
        })
        .unwrap();
        let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
            .sign_receipt(core.exact_bytes())
            .unwrap();
        let exact = encode_receipt(&ReceiptV1::new(core, signature).unwrap()).unwrap();
        match decode_exact_object(exact.as_bytes()).unwrap() {
            ParsedArchiveObject::Receipt(receipt) => receipt,
            _ => panic!("the private Receipt contract fixture must remain exact .esr"),
        }
    }

    fn checkpoint(fixture: &Fixture) -> Parsed<EvidenceObjectV1> {
        let core = CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
            organization_id: support::organization(),
            chain_id: chain_id(),
            covered_from_sequence: ChainSequence::new(0),
            covered_through_sequence: ChainSequence::new(20),
            head_entry_hash: EntryHash::from(support::hash32(0x71)),
            registry_head_hash: head_hash(fixture.head),
            issued_at_server: UnixMillis::new(1_800_000_000_456),
            previous_evidence_hash: Some(ObjectHash::from(support::hash32(0x72))),
        })
        .unwrap();
        let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
            .sign_checkpoint(fixture.certificate_hash, core.exact_bytes())
            .unwrap();
        let exact = encode_evidence(&EvidenceObjectV1::standard(core, signature).unwrap()).unwrap();
        match decode_exact_object(exact.as_bytes()).unwrap() {
            ParsedArchiveObject::Evidence(checkpoint) => checkpoint,
            _ => panic!("the private Checkpoint contract fixture must remain exact .ecp"),
        }
    }

    fn assert_private_contract(
        proof: &VerifiedSignedTime,
        kind: IndependentTimeKind,
        object_hash: ObjectHash,
        verified_time: UnixMillis,
        authority_head: RegistryHeadPin,
    ) {
        let advance = merge_independent_references(
            &TrustedTimeState::initial(UnixMillis::new(i64::MIN)),
            std::slice::from_ref(&proof.input),
        )
        .unwrap();
        let reference = advance
            .state()
            .independent_reference()
            .expect("a verified signed-time proof must produce one exact reference");
        assert_eq!(reference.kind(), kind);
        assert!(reference.object_hash() == object_hash);
        assert!(reference.verified_time() == verified_time);
        assert!(proof.authority_head.registry_version() == authority_head.registry_version());
        assert!(proof.authority_head.registry_head_hash() == authority_head.registry_head_hash());
    }

    #[test]
    fn verified_signed_time_privately_binds_exact_outer_object_time_kind_and_authority_head() {
        let fixture = fixture();
        let authority = fixture.candidate.preexisting_authority().unwrap();
        let authority_head = RegistryHeadPin::new(fixture.head.version, fixture.head.object_hash);

        let receipt = receipt(&fixture);
        let accepted_at = receipt.value().core().fields().accepted_at_server;
        let evidence_due_at = receipt
            .value()
            .core()
            .fields()
            .evidence_due_at
            .expect("the fixture deliberately separates evidence due from acceptance");
        assert!(evidence_due_at != accepted_at);
        assert!(receipt.object_hash() != object_hash(receipt.value().core().exact_bytes()));
        let receipt_proof = verify_receipt_time(authority, &receipt).unwrap();
        assert_private_contract(
            &receipt_proof,
            IndependentTimeKind::Receipt,
            receipt.object_hash(),
            accepted_at,
            authority_head,
        );

        let checkpoint = checkpoint(&fixture);
        let ea_format::DecodedEvidencePayloadV1::Standard { core, .. } =
            checkpoint.value().decoded_payload().unwrap()
        else {
            panic!("the fixture must remain standard Checkpoint evidence");
        };
        assert!(checkpoint.object_hash() != object_hash(core.exact_bytes()));
        let checkpoint_proof = verify_checkpoint_time(authority, &checkpoint).unwrap();
        assert_private_contract(
            &checkpoint_proof,
            IndependentTimeKind::Checkpoint,
            checkpoint.object_hash(),
            core.fields().issued_at_server,
            authority_head,
        );
    }

    struct ReturningStore {
        key: TrustStateKey,
        record: PersistedTrustRecord,
        independent_commits: usize,
    }

    impl TrustStateStore for ReturningStore {
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
            self.record = PersistedTrustRecord::new(
                expected_revision + 7,
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

    #[test]
    fn local_time_block_privately_binds_returned_state_candidate_guard_and_evaluation() {
        let fixture = fixture();
        let receipt = receipt(&fixture);
        let receipt_hash = receipt.object_hash();
        let receipt_time = receipt.value().core().fields().accepted_at_server;
        let proof =
            verify_receipt_time(fixture.candidate.preexisting_authority().unwrap(), &receipt)
                .unwrap();
        let key = support::state_key();
        let pin = RegistryHeadPin::new(fixture.head.version, fixture.head.object_hash);
        let mut store = ReturningStore {
            key,
            record: PersistedTrustRecord::new(
                17,
                fixture.candidate.trusted_time.clone(),
                Some(pin),
            ),
            independent_commits: 0,
        };
        let expected_store_address = core::ptr::from_mut(&mut store).cast::<()>();
        let os_at_inclusive_limit = UnixMillis::new(receipt_time.get() + 300_000);
        let expected_time = TrustedTimeState::from_persisted(
            receipt_time,
            Some(ea_time::IndependentTimeInput::new(
                IndependentTimeKind::Receipt,
                receipt_hash,
                receipt_time,
            )),
        )
        .unwrap();
        let block = prepare_local_time(
            &mut store,
            &fixture.candidate,
            os_at_inclusive_limit,
            &[proof],
        )
        .unwrap();

        let actual_store_address = core::ptr::from_mut(&mut *block.store).cast::<()>();
        assert!(actual_store_address == expected_store_address);
        assert!(block.state_key == key);
        assert_eq!(block.expected_revision, 24);
        assert!(block.pinned_head == Some(pin));
        assert!(block.candidate_registry_version == fixture.candidate.registry_version());
        assert!(block.candidate_registry_head_hash == fixture.candidate.registry_head_hash());
        assert!(block.guard_policy_object_hash == fixture.candidate.guard_policy.object_hash);
        assert!(block.proposed_sequence == fixture.candidate.proposed_sequence);
        assert!(block.pre_transition_sequence == fixture.candidate.pre_transition_sequence);
        assert!(block.trusted_time == expected_time);
        assert_private_reference(&block, receipt_hash, receipt_time);
        assert!(block.observed_os_wall_clock == os_at_inclusive_limit);
        assert!(block.evaluation.raw_now() == os_at_inclusive_limit);
        assert!(!block.evaluation.warnings().clock_rollback());
        assert!(!block.evaluation.warnings().independent_time_unavailable());
        assert_eq!(
            block.evaluation.future_skew(),
            ea_time::FutureSkew::WithinLimit
        );
    }

    #[test]
    fn local_time_block_excludes_candidate_time_and_preserves_rollback_unavailable_and_blocked() {
        let mut line = RegistryLineBuilder::new();
        let head = line.push(
            policy(),
            HeadOptions {
                effective_from: Some(1),
                valid_through: Some(9),
                issued_at: UnixMillis::new(9_000_000_000_000),
                not_before: UnixMillis::new(8_999_999_999_500),
                not_after: UnixMillis::new(9_000_000_001_000),
                ..HeadOptions::default()
            },
        );
        let floor = UnixMillis::new(1_700_000_000_000);
        let trust = line.verified_with_floor(Pin::Head(0), floor);
        let candidate = verify_registry_candidate(&trust, ChainSequence::new(5)).unwrap();
        let pin = RegistryHeadPin::new(head.version, head.object_hash);
        let key = support::state_key();
        let mut store = ReturningStore {
            key,
            record: PersistedTrustRecord::new(17, TrustedTimeState::initial(floor), Some(pin)),
            independent_commits: 0,
        };
        let observed_os_wall_clock = UnixMillis::new(floor.get() - 1);
        let block =
            prepare_local_time(&mut store, &candidate, observed_os_wall_clock, &[]).unwrap();
        assert_eq!(block.expected_revision, 17);
        assert!(block.trusted_time.floor() == floor);
        assert!(block.observed_os_wall_clock == observed_os_wall_clock);
        assert!(block.evaluation.raw_now() == floor);
        assert!(block.observed_os_wall_clock != block.evaluation.raw_now());
        assert!(block.evaluation.raw_now() != candidate.head_event.issued_at);
        assert!(block.evaluation.raw_now() != candidate.head_event.not_before);
        assert!(block.evaluation.warnings().clock_rollback());
        assert!(block.evaluation.warnings().independent_time_unavailable());
        assert_eq!(
            block.evaluation.future_skew(),
            ea_time::FutureSkew::UnprovableWithoutIndependentReference,
        );

        let fixture = fixture();
        let receipt = receipt(&fixture);
        let receipt_time = receipt.value().core().fields().accepted_at_server;
        let proof =
            verify_receipt_time(fixture.candidate.preexisting_authority().unwrap(), &receipt)
                .unwrap();
        let pin = RegistryHeadPin::new(fixture.head.version, fixture.head.object_hash);
        let mut store = ReturningStore {
            key,
            record: PersistedTrustRecord::new(
                17,
                fixture.candidate.trusted_time.clone(),
                Some(pin),
            ),
            independent_commits: 0,
        };
        let blocked = prepare_local_time(
            &mut store,
            &fixture.candidate,
            UnixMillis::new(receipt_time.get() + 300_001),
            &[proof],
        )
        .unwrap();
        assert_eq!(
            blocked.evaluation.future_skew(),
            ea_time::FutureSkew::Blocked
        );
    }

    #[test]
    fn local_time_block_binds_the_transition_guard_policy_not_the_target_policy() {
        let fixture = successor_policy_fixture(0, 300);
        assert!(
            fixture.candidate.guard_policy.object_hash
                != fixture.candidate.target_policy.object_hash
        );
        let receipt = receipt(&fixture);
        let receipt_time = receipt.value().core().fields().accepted_at_server;
        let proof =
            verify_receipt_time(fixture.candidate.preexisting_authority().unwrap(), &receipt)
                .unwrap();
        let key = support::state_key();
        let pin = RegistryHeadPin::new(fixture.head.version, fixture.head.object_hash);
        let mut store = ReturningStore {
            key,
            record: PersistedTrustRecord::new(
                17,
                fixture.candidate.trusted_time.clone(),
                Some(pin),
            ),
            independent_commits: 0,
        };
        let block = prepare_local_time(
            &mut store,
            &fixture.candidate,
            UnixMillis::new(receipt_time.get() + 1),
            &[proof],
        )
        .unwrap();
        assert!(block.guard_policy_object_hash == fixture.candidate.guard_policy.object_hash);
        assert!(block.guard_policy_object_hash != fixture.candidate.target_policy.object_hash);
        assert_eq!(block.evaluation.future_skew(), ea_time::FutureSkew::Blocked);
    }

    #[test]
    fn source_authority_pin_requires_the_exact_version_even_when_the_hash_matches() {
        let fixture = fixture();
        let receipt = receipt(&fixture);
        let mut proof =
            verify_receipt_time(fixture.candidate.preexisting_authority().unwrap(), &receipt)
                .unwrap();
        let exact = proof.authority_head;
        proof.authority_head = RegistryHeadPin::new(
            RegistryVersion::new(exact.registry_version().get() + 1),
            exact.registry_head_hash(),
        );
        let key = support::state_key();
        let mut store = ReturningStore {
            key,
            record: PersistedTrustRecord::new(
                17,
                fixture.candidate.trusted_time.clone(),
                Some(exact),
            ),
            independent_commits: 0,
        };
        let error = prepare_local_time(
            &mut store,
            &fixture.candidate,
            UnixMillis::new(1_800_000_000_000),
            &[proof],
        )
        .err()
        .expect("same hash with a different authority version must fail closed");
        assert_eq!(error.code(), "EA-TRUST-STATE-CONFLICT");
        assert_eq!(store.independent_commits, 0);
    }

    fn assert_private_reference(
        block: &super::LocalTimeBlock<'_>,
        object_hash: ObjectHash,
        verified_time: UnixMillis,
    ) {
        let reference = block
            .trusted_time
            .independent_reference()
            .expect("the block must bind the selected independent reference");
        assert_eq!(reference.kind(), IndependentTimeKind::Receipt);
        assert!(reference.object_hash() == object_hash);
        assert!(reference.verified_time() == verified_time);
    }
}
