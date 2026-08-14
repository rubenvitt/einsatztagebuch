mod support;

use ea_crypto::{
    CanonicalPublicCoseKey, CoseSigner, ResolvedSigner, SecretBytes, SignerCertificateResolver,
    UnverifiedRfc3161TimeStampToken, VerificationContext, attach_rfc3161_ctt, object_hash,
    parse_cose_sign1, verify_cose_sign1,
};
use ea_format::{
    CheckpointCoreFieldsV1, CheckpointCoreV1, DecodedEvidencePayloadV1, EvidenceObjectV1, Parsed,
    ParsedArchiveObject, ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1, RenewalCoreFieldsV1,
    RenewalCoreV1, Rfc3161EvidenceFieldsV1, decode_exact_object, encode_evidence, encode_receipt,
};
use ea_time::{IndependentTimeInput, IndependentTimeKind};
use ea_trust::{
    PreexistingRegistryAuthority, RegistryCandidate, TrustError, VerifiedSignedTime,
    verify_checkpoint_time, verify_receipt_time, verify_registry_candidate,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};

use support::{ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder};

const SERVER_SECRET: [u8; 32] = [
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
];

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
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

struct AuthorityFixture {
    candidate: RegistryCandidate,
    head: BuiltHead,
    certificate_hash: CertificateHash,
    certificate_bytes: Vec<u8>,
}

impl AuthorityFixture {
    fn authority(&self) -> &ea_trust::PreexistingRegistryAuthority {
        self.candidate
            .preexisting_authority()
            .expect("a pinned Registry Head supplies preexisting authority")
    }
}

fn authority_fixture(
    capabilities: Option<Vec<String>>,
    revoked_from_sequence: Option<ChainSequence>,
) -> AuthorityFixture {
    authority_fixture_with_kind(
        ea_format::CertificateKindV1::ServerReceipt,
        capabilities,
        revoked_from_sequence,
    )
}

fn authority_fixture_with_kind(
    certificate_kind: ea_format::CertificateKindV1,
    capabilities: Option<Vec<String>>,
    revoked_from_sequence: Option<ChainSequence>,
) -> AuthorityFixture {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    let head = line.push(
        ActionSpec::Device {
            kind: certificate_kind,
            marker: 0x66,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(29),
            certificate_capabilities_override: capabilities,
            revoked_from_sequence,
            ..HeadOptions::default()
        },
    );
    let certificate_object_hash = head
        .direct_object_hash
        .expect("ServerReceipt activation has a direct certificate");
    let certificate_bytes = line.exact_object_bytes(certificate_object_hash).to_vec();
    let trust = line.verified(Pin::Head(1));
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(25))
        .expect("the pinned ServerReceipt authority must replay coherently");
    AuthorityFixture {
        candidate,
        head,
        certificate_hash: CertificateHash::from(certificate_object_hash),
        certificate_bytes,
    }
}

fn lease_authority_fixture() -> AuthorityFixture {
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
            marker: 0x68,
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
    let certificate_object_hash = certificate_head
        .direct_object_hash
        .expect("the earlier Head activates a ServerReceipt certificate");
    let certificate_bytes = line.exact_object_bytes(certificate_object_hash).to_vec();
    let trust = line.verified(Pin::Head(2));
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(25))
        .expect("the later Policy Head must retain the active ServerReceipt certificate");
    AuthorityFixture {
        candidate,
        head,
        certificate_hash: CertificateHash::from(certificate_object_hash),
        certificate_bytes,
    }
}

#[derive(Clone, Copy)]
struct ReceiptSpec {
    organization_id: OrganizationId,
    chain_sequence: ChainSequence,
    registry_version: RegistryVersion,
    registry_head_hash: Hash32,
    accepted_at_server: UnixMillis,
    evidence_due_at: Option<UnixMillis>,
    server_certificate_hash: CertificateHash,
}

impl ReceiptSpec {
    fn for_authority(fixture: &AuthorityFixture, chain_sequence: u64) -> Self {
        Self {
            organization_id: support::organization(),
            chain_sequence: ChainSequence::new(chain_sequence),
            registry_version: fixture.head.version,
            registry_head_hash: hash32_from_object(fixture.head.object_hash),
            accepted_at_server: UnixMillis::new(1_800_000_000_123),
            evidence_due_at: Some(UnixMillis::new(1_800_000_060_123)),
            server_certificate_hash: fixture.certificate_hash,
        }
    }
}

fn parsed_receipt(spec: ReceiptSpec) -> Parsed<ReceiptV1> {
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: spec.organization_id,
        chain_id: chain_id(),
        chain_sequence: spec.chain_sequence,
        entry_hash: EntryHash::from(support::hash32(0x31)),
        entry_object_hash: ObjectHash::from(support::hash32(0x32)),
        previous_entry_hash: Some(EntryHash::from(support::hash32(0x30))),
        registry_version: spec.registry_version,
        registry_head_hash: spec.registry_head_hash,
        policy_object_hash: ObjectHash::from(support::hash32(0x33)),
        initial_grant_plan_hash: support::hash32(0x34),
        initial_grant_object_hashes: vec![ObjectHash::from(support::hash32(0x35))],
        accepted_at_server: spec.accepted_at_server,
        evidence_due_at: spec.evidence_due_at,
        server_key_thumbprint: server_key().thumbprint(),
        server_certificate_hash: spec.server_certificate_hash,
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
        .sign_receipt(core.exact_bytes())
        .unwrap();
    let receipt = ReceiptV1::new(core, signature).unwrap();
    let bytes = encode_receipt(&receipt).unwrap();
    match decode_exact_object(bytes.as_bytes()).unwrap() {
        ParsedArchiveObject::Receipt(receipt) => receipt,
        _ => panic!("the .esr fixture must decode as a Receipt"),
    }
}

#[derive(Clone, Copy)]
struct CheckpointSpec {
    organization_id: OrganizationId,
    covered_from: ChainSequence,
    covered_through: ChainSequence,
    registry_head_hash: Hash32,
    issued_at_server: UnixMillis,
    server_certificate_hash: CertificateHash,
}

impl CheckpointSpec {
    fn for_authority(fixture: &AuthorityFixture, covered_from: u64, covered_through: u64) -> Self {
        Self {
            organization_id: support::organization(),
            covered_from: ChainSequence::new(covered_from),
            covered_through: ChainSequence::new(covered_through),
            registry_head_hash: hash32_from_object(fixture.head.object_hash),
            issued_at_server: UnixMillis::new(1_800_000_000_456),
            server_certificate_hash: fixture.certificate_hash,
        }
    }
}

fn checkpoint_core(spec: CheckpointSpec) -> CheckpointCoreV1 {
    CheckpointCoreV1::new(CheckpointCoreFieldsV1 {
        organization_id: spec.organization_id,
        chain_id: chain_id(),
        covered_from_sequence: spec.covered_from,
        covered_through_sequence: spec.covered_through,
        head_entry_hash: EntryHash::from(support::hash32(0x41)),
        registry_head_hash: spec.registry_head_hash,
        issued_at_server: spec.issued_at_server,
        previous_evidence_hash: Some(ObjectHash::from(support::hash32(0x42))),
    })
    .unwrap()
}

fn parsed_standard_checkpoint(spec: CheckpointSpec) -> Parsed<EvidenceObjectV1> {
    let core = checkpoint_core(spec);
    let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
        .sign_checkpoint(spec.server_certificate_hash, core.exact_bytes())
        .unwrap();
    parsed_evidence(EvidenceObjectV1::standard(core, signature).unwrap())
}

fn timestamp_fields() -> Rfc3161EvidenceFieldsV1 {
    Rfc3161EvidenceFieldsV1 {
        rfc3161_response_der: vec![0x30, 0],
        request_nonce: vec![0x44; 16],
        policy_oid_der: vec![0x06, 1, 0x2a],
        tsa_certificate_chain_der: vec![vec![0x30, 0]],
        revocation_data_der: Vec::new(),
        validation_data_der: Vec::new(),
    }
}

fn timestamped_signature(signature: Vec<u8>) -> Vec<u8> {
    let token_bytes = decode_hex(include_str!(
        "../../ea-format/tests/fixtures/rfc9921-token.hex"
    ));
    let token = UnverifiedRfc3161TimeStampToken::from_der(&token_bytes).unwrap();
    attach_rfc3161_ctt(&signature, &token).unwrap()
}

fn parsed_timestamp_checkpoint(spec: CheckpointSpec) -> Parsed<EvidenceObjectV1> {
    let core = checkpoint_core(spec);
    let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
        .sign_checkpoint(spec.server_certificate_hash, core.exact_bytes())
        .unwrap();
    parsed_evidence(
        EvidenceObjectV1::timestamp(core, timestamped_signature(signature), timestamp_fields())
            .unwrap(),
    )
}

fn parsed_renewal(fixture: &AuthorityFixture) -> Parsed<EvidenceObjectV1> {
    let core = RenewalCoreV1::new(RenewalCoreFieldsV1 {
        organization_id: support::organization(),
        chain_id: chain_id(),
        current_entry_hash: EntryHash::from(support::hash32(0x51)),
        previous_renewal_hash: None,
        renewal_input_hashes: vec![support::hash32(0x52)],
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(SERVER_SECRET))
        .sign_evidence_renewal(fixture.certificate_hash, core.exact_bytes())
        .unwrap();
    parsed_evidence(
        EvidenceObjectV1::renewal(core, timestamped_signature(signature), timestamp_fields())
            .unwrap(),
    )
}

fn parsed_evidence(evidence: EvidenceObjectV1) -> Parsed<EvidenceObjectV1> {
    let bytes = encode_evidence(&evidence).unwrap();
    match decode_exact_object(bytes.as_bytes()).unwrap() {
        ParsedArchiveObject::Evidence(evidence) => evidence,
        _ => panic!("the .ecp fixture must decode as Evidence"),
    }
}

fn parsed_corrupt_receipt_signature(receipt: &Parsed<ReceiptV1>) -> Parsed<ReceiptV1> {
    let mut bytes = receipt.exact_bytes().as_bytes().to_vec();
    let last = bytes
        .last_mut()
        .expect("the exact Receipt has a COSE signature byte");
    *last ^= 1;
    match decode_exact_object(&bytes).unwrap() {
        ParsedArchiveObject::Receipt(receipt) => receipt,
        _ => panic!("the corrupted .esr must remain a structurally valid Receipt"),
    }
}

fn parsed_corrupt_checkpoint_signature(
    evidence: &Parsed<EvidenceObjectV1>,
) -> Parsed<EvidenceObjectV1> {
    let mut bytes = evidence.exact_bytes().as_bytes().to_vec();
    let last = bytes
        .last_mut()
        .expect("the exact Checkpoint has a COSE signature byte");
    *last ^= 1;
    match decode_exact_object(&bytes).unwrap() {
        ParsedArchiveObject::Evidence(evidence) => evidence,
        _ => panic!("the corrupted .ecp must remain structurally valid Evidence"),
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("fixture contains non-hex input"),
        }
    }

    let bytes = input.trim().as_bytes();
    assert!(bytes.len().is_multiple_of(2));
    bytes
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

struct FixtureResolver<'a> {
    certificate_hash: CertificateHash,
    certificate_bytes: &'a [u8],
    registry_version: RegistryVersion,
    effective_from: ChainSequence,
}

impl SignerCertificateResolver for FixtureResolver<'_> {
    fn resolve(
        &self,
        certificate_hash: CertificateHash,
        bound_registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, ea_crypto::CryptoError> {
        if certificate_hash != self.certificate_hash || bound_registry != self.registry_version {
            return Err(ea_crypto::CryptoError::SignerUnresolved);
        }
        Ok(ResolvedSigner {
            exact_certificate_bytes: self.certificate_bytes,
            registry_effective_from_sequence: self.effective_from,
            registry_revoked_from_sequence: None,
            registry_revoked: false,
            root_line_accepted: true,
        })
    }
}

#[test]
fn signed_time_fixtures_are_exact_and_cryptographically_coherent() {
    let fixture = authority_fixture(None, None);
    let resolver = FixtureResolver {
        certificate_hash: fixture.certificate_hash,
        certificate_bytes: &fixture.certificate_bytes,
        registry_version: fixture.head.version,
        effective_from: fixture.head.effective_from,
    };

    let receipt = parsed_receipt(ReceiptSpec::for_authority(&fixture, 20));
    assert_eq!(receipt.exact_bytes().as_bytes()[6], 3);
    assert!(receipt.object_hash() == object_hash(receipt.exact_bytes().as_bytes()));
    let receipt_context =
        VerificationContext::receipt(receipt.value().core().exact_bytes()).unwrap();
    verify_cose_sign1(
        receipt.value().server_signature(),
        &resolver,
        &receipt_context,
    )
    .unwrap();

    let checkpoint = parsed_standard_checkpoint(CheckpointSpec::for_authority(&fixture, 0, 20));
    assert_eq!(checkpoint.exact_bytes().as_bytes()[6], 4);
    assert!(checkpoint.object_hash() == object_hash(checkpoint.exact_bytes().as_bytes()));
    let DecodedEvidencePayloadV1::Standard { core, exact_cose } =
        checkpoint.value().decoded_payload().unwrap()
    else {
        panic!("the fixture must be a standard Checkpoint");
    };
    let certificate_hash = parse_cose_sign1(&exact_cose, &[])
        .unwrap()
        .certificate_hash()
        .unwrap();
    let checkpoint_context =
        VerificationContext::checkpoint(core.exact_bytes(), certificate_hash, fixture.head.version)
            .unwrap();
    verify_cose_sign1(&exact_cose, &resolver, &checkpoint_context).unwrap();
}

fn expect_error(result: Result<VerifiedSignedTime, TrustError>, expected: TrustError) {
    let error = result
        .err()
        .expect("the invalid signed-time source must fail closed");
    assert_eq!(error.code(), expected.code());
    assert_eq!(error.to_string(), expected.code());
    assert_eq!(format!("{error:?}"), expected.code());
}

#[test]
fn public_api_accepts_only_preexisting_authority_and_typed_exact_objects() {
    let _: fn(
        &PreexistingRegistryAuthority,
        &Parsed<ReceiptV1>,
    ) -> Result<VerifiedSignedTime, TrustError> = verify_receipt_time;
    let _: fn(
        &PreexistingRegistryAuthority,
        &Parsed<EvidenceObjectV1>,
    ) -> Result<VerifiedSignedTime, TrustError> = verify_checkpoint_time;

    // A raw TSA/tag-2 value remains an arithmetic input, never a Task-8 proof.
    let unverified_tsa = IndependentTimeInput::new(
        IndependentTimeKind::Tsa,
        ObjectHash::from(support::hash32(0xf2)),
        UnixMillis::new(1_800_000_000_999),
    );
    assert!(
        unverified_tsa
            != IndependentTimeInput::new(
                IndependentTimeKind::Receipt,
                ObjectHash::from(support::hash32(0xf2)),
                UnixMillis::new(1_800_000_000_999),
            )
    );
}

#[test]
fn receipt_proof_binds_exact_object_server_time_and_lease_endpoints() {
    let fixture = authority_fixture(None, None);
    for sequence in [20, 29] {
        let receipt = parsed_receipt(ReceiptSpec::for_authority(&fixture, sequence));
        let _proof = verify_receipt_time(fixture.authority(), &receipt)
            .expect("an exact active ServerReceipt Receipt must verify");
    }
}

#[test]
fn receipt_rejects_semantic_head_organization_and_lease_mismatches() {
    let fixture = lease_authority_fixture();
    let valid = ReceiptSpec::for_authority(&fixture, 20);
    let invalid = [
        ReceiptSpec {
            organization_id: OrganizationId::try_from(&[0x22; 16][..]).unwrap(),
            ..valid
        },
        ReceiptSpec {
            registry_version: RegistryVersion::new(valid.registry_version.get() + 1),
            ..valid
        },
        ReceiptSpec {
            registry_head_hash: support::hash32(0xe1),
            ..valid
        },
        ReceiptSpec {
            chain_sequence: ChainSequence::new(19),
            ..valid
        },
        ReceiptSpec {
            chain_sequence: ChainSequence::new(30),
            ..valid
        },
    ];
    for spec in invalid {
        let receipt = parsed_receipt(spec);
        expect_error(
            verify_receipt_time(fixture.authority(), &receipt),
            TrustError::ActionMismatch,
        );
    }
}

#[test]
fn receipt_rejects_invalid_signature_missing_capability_and_inactive_certificate() {
    let fixture = authority_fixture(None, None);
    let receipt = parsed_receipt(ReceiptSpec::for_authority(&fixture, 20));
    let corrupt = parsed_corrupt_receipt_signature(&receipt);
    expect_error(
        verify_receipt_time(fixture.authority(), &corrupt),
        TrustError::Signature,
    );

    let no_capability = authority_fixture(Some(Vec::new()), None);
    let receipt = parsed_receipt(ReceiptSpec::for_authority(&no_capability, 20));
    expect_error(
        verify_receipt_time(no_capability.authority(), &receipt),
        TrustError::SignerInactive,
    );

    let wrong_role = authority_fixture_with_kind(
        ea_format::CertificateKindV1::Reader,
        Some(vec!["serverReceipt".into()]),
        None,
    );
    let receipt = parsed_receipt(ReceiptSpec::for_authority(&wrong_role, 20));
    expect_error(
        verify_receipt_time(wrong_role.authority(), &receipt),
        TrustError::SignerInactive,
    );

    let revoked = authority_fixture(None, Some(ChainSequence::new(25)));
    let receipt = parsed_receipt(ReceiptSpec::for_authority(&revoked, 25));
    expect_error(
        verify_receipt_time(revoked.authority(), &receipt),
        TrustError::SignerInactive,
    );
}

#[test]
fn checkpoint_proof_binds_exact_object_server_time_and_historical_range() {
    let fixture = authority_fixture(None, None);
    for (covered_from, covered_through) in [(0, 20), (29, 29)] {
        let checkpoint = parsed_standard_checkpoint(CheckpointSpec::for_authority(
            &fixture,
            covered_from,
            covered_through,
        ));
        let _proof = verify_checkpoint_time(fixture.authority(), &checkpoint)
            .expect("a standard Checkpoint with an active ServerReceipt signer must verify");
    }
}

#[test]
fn checkpoint_rejects_semantic_head_organization_and_range_mismatches() {
    let fixture = lease_authority_fixture();
    let valid = CheckpointSpec::for_authority(&fixture, 0, 20);
    let invalid = [
        CheckpointSpec {
            organization_id: OrganizationId::try_from(&[0x22; 16][..]).unwrap(),
            ..valid
        },
        CheckpointSpec {
            registry_head_hash: support::hash32(0xe2),
            ..valid
        },
        CheckpointSpec {
            covered_from: ChainSequence::new(21),
            covered_through: ChainSequence::new(20),
            ..valid
        },
        CheckpointSpec {
            covered_through: ChainSequence::new(19),
            ..valid
        },
        CheckpointSpec {
            covered_through: ChainSequence::new(30),
            ..valid
        },
    ];
    for spec in invalid {
        let checkpoint = parsed_standard_checkpoint(spec);
        expect_error(
            verify_checkpoint_time(fixture.authority(), &checkpoint),
            TrustError::ActionMismatch,
        );
    }
}

#[test]
fn checkpoint_rejects_invalid_signature_missing_capability_and_inactive_certificate() {
    let fixture = authority_fixture(None, None);
    let checkpoint = parsed_standard_checkpoint(CheckpointSpec::for_authority(&fixture, 0, 20));
    let corrupt = parsed_corrupt_checkpoint_signature(&checkpoint);
    expect_error(
        verify_checkpoint_time(fixture.authority(), &corrupt),
        TrustError::Signature,
    );

    let no_capability = authority_fixture(Some(Vec::new()), None);
    let checkpoint =
        parsed_standard_checkpoint(CheckpointSpec::for_authority(&no_capability, 0, 20));
    expect_error(
        verify_checkpoint_time(no_capability.authority(), &checkpoint),
        TrustError::SignerInactive,
    );

    let wrong_role = authority_fixture_with_kind(
        ea_format::CertificateKindV1::Reader,
        Some(vec!["serverReceipt".into()]),
        None,
    );
    let checkpoint = parsed_standard_checkpoint(CheckpointSpec::for_authority(&wrong_role, 0, 20));
    expect_error(
        verify_checkpoint_time(wrong_role.authority(), &checkpoint),
        TrustError::SignerInactive,
    );

    let revoked = authority_fixture(None, Some(ChainSequence::new(25)));
    let checkpoint = parsed_standard_checkpoint(CheckpointSpec::for_authority(&revoked, 0, 25));
    expect_error(
        verify_checkpoint_time(revoked.authority(), &checkpoint),
        TrustError::SignerInactive,
    );
}

#[test]
fn timestamp_and_renewal_evidence_are_distinctly_unsupported() {
    let fixture = authority_fixture(None, None);
    let timestamp = parsed_timestamp_checkpoint(CheckpointSpec::for_authority(&fixture, 0, 20));
    expect_error(
        verify_checkpoint_time(fixture.authority(), &timestamp),
        TrustError::TimeSourceUnsupported,
    );

    let renewal = parsed_renewal(&fixture);
    expect_error(
        verify_checkpoint_time(fixture.authority(), &renewal),
        TrustError::TimeSourceUnsupported,
    );
}

struct CandidateOnlyFixture {
    candidate: RegistryCandidate,
    authority_head: BuiltHead,
    candidate_certificate_hash: CertificateHash,
}

fn candidate_only_fixture() -> CandidateOnlyFixture {
    let mut line = RegistryLineBuilder::new();
    let authority_head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(29),
            ..HeadOptions::default()
        },
    );
    let candidate_head = line.push(
        ActionSpec::Device {
            kind: ea_format::CertificateKindV1::ServerReceipt,
            marker: 0x67,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(20),
            valid_through: Some(39),
            ..HeadOptions::default()
        },
    );
    let trust = line.verified(Pin::Head(0));
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(20))
        .expect("the successor certificate fixture must form a valid candidate");
    CandidateOnlyFixture {
        candidate,
        authority_head,
        candidate_certificate_hash: CertificateHash::from(
            candidate_head
                .direct_object_hash
                .expect("the candidate has a direct ServerReceipt certificate"),
        ),
    }
}

#[test]
fn candidate_only_server_certificate_cannot_bootstrap_receipt_or_checkpoint_time() {
    let fixture = candidate_only_fixture();
    let authority = fixture
        .candidate
        .preexisting_authority()
        .expect("the candidate borrows only its pinned previous Head");
    let receipt = parsed_receipt(ReceiptSpec {
        organization_id: support::organization(),
        chain_sequence: ChainSequence::new(20),
        registry_version: fixture.authority_head.version,
        registry_head_hash: hash32_from_object(fixture.authority_head.object_hash),
        accepted_at_server: UnixMillis::new(1_800_000_000_777),
        evidence_due_at: Some(UnixMillis::new(1_800_000_060_777)),
        server_certificate_hash: fixture.candidate_certificate_hash,
    });
    expect_error(
        verify_receipt_time(authority, &receipt),
        TrustError::SignerInactive,
    );

    let checkpoint = parsed_standard_checkpoint(CheckpointSpec {
        organization_id: support::organization(),
        covered_from: ChainSequence::new(0),
        covered_through: ChainSequence::new(20),
        registry_head_hash: hash32_from_object(fixture.authority_head.object_hash),
        issued_at_server: UnixMillis::new(1_800_000_000_888),
        server_certificate_hash: fixture.candidate_certificate_hash,
    });
    expect_error(
        verify_checkpoint_time(authority, &checkpoint),
        TrustError::SignerInactive,
    );
}

#[test]
fn bootstrap_candidate_exposes_no_signed_time_authority() {
    let mut line = RegistryLineBuilder::new();
    let head = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(19),
            ..HeadOptions::default()
        },
    );
    let trust = line.verified(Pin::None);
    let candidate = verify_registry_candidate(&trust, head.effective_from)
        .expect("the first Registry Head itself remains structurally valid");
    assert!(candidate.preexisting_authority().is_none());
}
