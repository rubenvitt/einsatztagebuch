use ea_crypto::{CryptoError, VerificationContext, parse_cose_sign1, verify_cose_sign1};
use ea_format::{DecodedEvidencePayloadV1, EvidenceKindV1, EvidenceObjectV1, Parsed, ReceiptV1};
use ea_time::{IndependentTimeInput, IndependentTimeKind};
use ea_types::{ChainSequence, ObjectHash};

use crate::{
    PreexistingRegistryAuthority, RegistryHeadPin, TrustError,
    resolver::{PreviousHeadResolver, PreviousHeadState},
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
        CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, UnixMillis,
    };

    use super::support::{self, ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder};
    use super::{VerifiedSignedTime, verify_checkpoint_time, verify_receipt_time};
    use crate::{RegistryCandidate, RegistryHeadPin, verify_registry_candidate};

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
}
