#![allow(dead_code)]
use super::support;
use ea_crypto::object_hash;
use ea_format::*;
use ea_types::*;
use support::archive_support::{ArchiveFixture, trust_support};

fn exact(payload: TrustPayloadV1, signature: Vec<u8>) -> Vec<u8> {
    encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
        .unwrap()
        .into_vec()
}

pub struct Fixture {
    pub original: support::destruction_v12::OriginalFixture,
    pub source: ArchiveFixture,
    pub stub_hash: ObjectHash,
}

pub fn fixture(bind_stub: bool, include_attestation: bool) -> Fixture {
    fixture_at(bind_stub, include_attestation, 1)
}
pub fn fixture_at(bind_stub: bool, include_attestation: bool, sequence: u64) -> Fixture {
    fixture_with_attestation(bind_stub, include_attestation, sequence, |_| {})
}
pub fn fixture_with_attestation(
    bind_stub: bool,
    include_attestation: bool,
    sequence: u64,
    edit: impl FnOnce(&mut DeletionAttestationFieldsV1),
) -> Fixture {
    let original = support::destruction_v12::OriginalFixture::new(support::COMPLETE_PLAINTEXT_V1);
    let auth = original.authorization();
    let ParsedArchiveObject::Trust(parsed_auth) = decode_exact_object(&auth).unwrap() else {
        panic!("auth")
    };
    let DecodedTrustPayloadV1::DestructionAuthorization(fields) =
        parsed_auth.value().decoded_payload().unwrap()
    else {
        panic!("auth")
    };
    let ParsedArchiveObject::Entry(entry) = decode_exact_object(&original.original_bytes).unwrap()
    else {
        panic!("entry")
    };
    let stub = DestroyedEntryStubV1::new(
        entry.value().signed_manifest().clone(),
        entry.value().writer_signature().to_vec(),
        entry.object_hash(),
        fields.destruction_id,
        object_hash(&auth),
    )
    .unwrap();
    let stub = encode_destroyed_entry_stub(&stub).unwrap();
    let stub_hash = object_hash(stub.as_bytes());
    let original_source = original.source();
    let inventory = ea_archive::ArchiveInventory::build(&original_source).unwrap();
    let binding = inventory.trust().iter().find(|object| matches!(object.value().decoded_payload(), Ok(DecodedTrustPayloadV1::AuthorizedOperatorBinding(fields)) if fields.fields().operator_role == OperatorRoleV1::Writer)).unwrap().object_hash();
    let mut source = ArchiveFixture::new();
    for (path, bytes) in original_source.blobs() {
        if bytes.starts_with(&ETB_PREFIX_V1) {
            source.push_exact_bytes(path, bytes.clone());
        }
    }
    source.push_exact_bytes("destructions/authorization.etb", auth.clone());
    source.push_exact_bytes("entries/original.eds", stub.into_vec());
    let mut previous = None;
    for state in [0, 1, 3] {
        let payload = TrustPayloadV1::destruction_transition(DestructionTransitionFieldsV1 {
            destruction_id: fields.destruction_id,
            destruction_authorization_object_hash: object_hash(&auth),
            event_id: EventId::try_from(&[0x80 + state; 16][..]).unwrap(),
            previous_event_object_hash: previous,
            from_state: match state {
                0 => None,
                1 => Some(0),
                _ => Some(1),
            },
            to_state: state,
            trigger_code: 0,
            executed_at: UnixMillis::new(800),
        })
        .unwrap();
        let signature = trust_support::authorized_device_signer()
            .sign_destruction_transition_digest(
                original.deletion,
                payload.exact_digest_input(),
                &auth,
            )
            .unwrap();
        let bytes = exact(payload, signature);
        previous = Some(object_hash(&bytes));
        source.push_exact_bytes(&format!("destructions/{state}.etb"), bytes);
    }
    let mut attestation_fields = DeletionAttestationFieldsV1 {
        destruction_id: fields.destruction_id,
        destruction_authorization_object_hash: object_hash(&auth),
        // DeletionAttest marker 0x73 has the signed DeviceId 0xb3.
        replica_id: [0xb3; 16],
        replica_kind: 0,
        removed_object_hashes: {
            let mut hashes = vec![
                entry.object_hash(),
                object_hash(&original.initial_grant_bytes),
            ];
            hashes.sort();
            hashes
        },
        result: 0,
        backup_expiry_at: None,
        executed_at: UnixMillis::new(800),
    };
    edit(&mut attestation_fields);
    let replica_id = attestation_fields.replica_id;
    let payload = TrustPayloadV1::deletion_attestation(attestation_fields).unwrap();
    let signature = trust_support::authorized_device_signer()
        .sign_deletion_attestation_digest(original.deletion, payload.exact_digest_input(), &auth)
        .unwrap();
    let attestation = exact(payload, signature);
    let attestation_hash = object_hash(&attestation);
    if include_attestation {
        source.push_exact_bytes("destructions/attestation.etb", attestation);
    }
    let header = ea_schema::CommonHeaderV1::new(
        RecordId::try_from(
            &[
                0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x72, 0x12, 0x92, 0x12, 0x12, 0x12, 0x12, 0x12,
                0x12, 0x12,
            ][..],
        )
        .unwrap(),
        UnixMillis::new(800),
        "Europe/Berlin",
        ea_schema::OperatorSnapshotV1::new(
            original.anchor.organization_id(),
            OperatorSubjectId::try_from(&[0x20; 16][..]).unwrap(),
            "Erika Beispiel",
            "Einsatzleitung",
            [0x30; 32],
            binding,
        )
        .unwrap(),
        ea_schema::NativeSourceV1::new("writer-native", 1).unwrap(),
        original.head().version,
    )
    .unwrap();
    let payload = ea_schema::PayloadV1::DestructionEvidence(
        ea_schema::DestructionEvidenceV1::new(
            header,
            fields.destruction_id,
            object_hash(&auth),
            0,
            vec![ea_schema::DestructionTargetV1::new(
                original.entry_hash,
                ChainSequence::new(0),
            )],
            vec![ea_schema::DestructionExecutionResultV1::new(
                original.entry_hash,
                true,
                0,
            )],
            vec![ea_schema::DestructionStubBindingV1::new(
                original.entry_hash,
                if bind_stub {
                    stub_hash
                } else {
                    ObjectHash::try_from(&[0xff; 32][..]).unwrap()
                },
            )],
            vec![ea_schema::ReplicaResultV1::successful(
                Id16::try_from(replica_id.as_slice()).unwrap(),
                attestation_hash,
            )],
        )
        .unwrap(),
    );
    original.append_evidence_at(
        &mut source,
        &ea_schema::encode_payload(&payload).unwrap(),
        sequence,
    );
    Fixture {
        original,
        source,
        stub_hash,
    }
}
