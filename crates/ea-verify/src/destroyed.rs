//! Two-stage Stub attribution. Signed original identity may be used to inspect
//! the later encrypted Evidence; only its exact authenticated binding releases
//! the final Stub result. Unreadable Evidence leaves a visible gap.
use crate::{DestructionStateV1, VerificationReportV1};
use ea_archive::ArchiveInventory;
use ea_chain::{ChainNode, ChainNodeKind};
use ea_crypto::{VerificationContext, verify_cose_sign1};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, DeletionAttestationFieldsV1, DestroyedEntryStubV1,
    EntryPackageV1, OperatorRoleV1, Parsed,
};
use ea_trust::TrustAnchorV1;
use ea_types::{ChainSequence, DestructionId, EntryHash, ObjectHash, UnixMillis};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn candidates<'a>(
    report: &VerificationReportV1,
    inventory: &'a ArchiveInventory,
    anchor: &TrustAnchorV1,
    now: UnixMillis,
) -> Vec<&'a Parsed<DestroyedEntryStubV1>> {
    inventory
        .destroyed()
        .iter()
        .filter(|stub| {
            if report.quarantined_objects.contains_key(&stub.object_hash()) {
                return false;
            }
            let value = stub.value();
            let fields = value.signed_manifest().manifest().fields();
            let Some(operation) = report.authorized_destructions.get(&value.destruction_id())
            else {
                return false;
            };
            if operation.state() == DestructionStateV1::Requested
                || operation.authorization_object_hash()
                    != value.destruction_authorization_object_hash()
            {
                return false;
            }
            let Some(authorization) = inventory
                .trust()
                .iter()
                .find(|object| object.object_hash() == operation.authorization_object_hash())
            else {
                return false;
            };
            let Ok(DecodedTrustPayloadV1::DestructionAuthorization(authorization)) =
                authorization.value().decoded_payload()
            else {
                return false;
            };
            if !authorization.targets.iter().any(|target| {
                target.entry_hash() == value.entry_hash().as_bytes()
                    && target.chain_sequence() == fields.chain_sequence.get()
            }) {
                return false;
            }
            let Some(head) = crate::historical::historical_registry_head(
                inventory,
                anchor,
                fields.registry_version,
                ObjectHash::try_from(fields.registry_head_hash.as_slice()).expect("fixed hash"),
                fields.chain_sequence,
                now,
            ) else {
                return false;
            };
            if fields.organization_id != anchor.organization_id()
                || fields.chain_id != anchor.chain_id()
                || !head
                    .active_certificate_fields(fields.writer_certificate_hash)
                    .is_some_and(|cert| cert.certificate_kind == CertificateKindV1::Writer)
                || !crate::entry::transition_claim_holds(fields, head.effective_writer_transition())
            {
                return false;
            }
            VerificationContext::record(value.signed_manifest().exact_bytes())
                .and_then(|context| verify_cose_sign1(value.writer_signature(), &head, &context))
                .is_ok()
        })
        .collect()
}

pub(crate) fn node(stub: &Parsed<DestroyedEntryStubV1>) -> ChainNode {
    let fields = stub.value().signed_manifest().manifest().fields();
    ChainNode {
        chain_id: fields.chain_id,
        chain_sequence: fields.chain_sequence,
        previous_entry_hash: fields.previous_entry_hash,
        entry_hash: stub.value().entry_hash(),
        object_hash: stub.object_hash(),
        writer_certificate_hash: fields.writer_certificate_hash,
        writer_transition_event_hash: fields.writer_transition_event_hash,
        kind: ChainNodeKind::DestroyedStub,
    }
}

pub(crate) struct VerifiedEvidence {
    pub(crate) sequence: ChainSequence,
    destruction_id: DestructionId,
    authorization: ObjectHash,
    scope: u64,
    targets: Vec<(EntryHash, ChainSequence)>,
    confirmed: BTreeSet<EntryHash>,
    stubs: BTreeMap<EntryHash, ObjectHash>,
    attestations: Vec<([u8; 16], ObjectHash)>,
}

/// Called only after all public entry/grant gates and a successful HPKE/AEAD.
/// Discard every personal/schema field; only public identifiers remain here.
pub(crate) fn inspect(
    bytes: &[u8],
    entry: &Parsed<EntryPackageV1>,
    inventory: &ArchiveInventory,
    anchor: &TrustAnchorV1,
    now: UnixMillis,
) -> Option<VerifiedEvidence> {
    let validated = ea_schema::SchemaRegistry::v1()
        .validate("ea.destruction-evidence", 1, bytes)
        .ok()?;
    let ea_schema::PayloadV1::DestructionEvidence(evidence) = validated.payload() else {
        return None;
    };
    let manifest = entry.value().manifest().fields();
    let head = crate::historical::historical_registry_head(
        inventory,
        anchor,
        manifest.registry_version,
        ObjectHash::try_from(manifest.registry_head_hash.as_slice()).ok()?,
        manifest.chain_sequence,
        now,
    )?;
    let header = evidence.header();
    let operator = header.operator();
    let binding = head.active_operator_binding_fields(operator.operator_binding_object_hash())?;
    if header.registry_version() != manifest.registry_version
        || operator.organization_id() != manifest.organization_id
        || binding.organization_id != operator.organization_id()
        || binding.operator_subject_id != operator.operator_subject_id()
        || binding.device_certificate_hash != manifest.writer_certificate_hash
        || binding.operator_role != OperatorRoleV1::Writer
        || ea_crypto::operator_profile_commitment(
            operator.organization_id(),
            operator.operator_subject_id(),
            operator.display_name(),
            operator.function_label(),
            operator.salt(),
        ) != binding.operator_profile_commitment
    {
        return None;
    }
    Some(VerifiedEvidence {
        sequence: manifest.chain_sequence,
        destruction_id: evidence.destruction_id(),
        authorization: evidence.authorization_object_hash(),
        scope: evidence.scope_code(),
        targets: evidence
            .targets()
            .iter()
            .map(|target| (target.entry_hash(), target.chain_sequence()))
            .collect(),
        confirmed: evidence
            .execution_results()
            .iter()
            .filter(|result| result.confirmed() && result.result_code() == 0)
            .map(|result| result.entry_hash())
            .collect(),
        stubs: evidence
            .stub_bindings()
            .iter()
            .map(|binding| (binding.entry_hash(), binding.stub_object_hash()))
            .collect(),
        attestations: evidence
            .replica_results()
            .iter()
            .filter_map(|replica| {
                replica
                    .state()
                    .deletion_attestation_object_hash()
                    .map(|hash| (*replica.replica_id().as_bytes(), hash))
            })
            .collect(),
    })
}

pub(crate) fn evidence_holds(
    stub: &Parsed<DestroyedEntryStubV1>,
    evidence: &[VerifiedEvidence],
    attestations: &BTreeMap<ObjectHash, DeletionAttestationFieldsV1>,
    inventory: &ArchiveInventory,
) -> bool {
    let value = stub.value();
    let Some(auth) = inventory
        .trust()
        .iter()
        .find(|object| object.object_hash() == value.destruction_authorization_object_hash())
    else {
        return false;
    };
    let Ok(DecodedTrustPayloadV1::DestructionAuthorization(auth)) = auth.value().decoded_payload()
    else {
        return false;
    };
    evidence.iter().any(|proof| {
        proof.destruction_id == value.destruction_id()
            && proof.authorization == value.destruction_authorization_object_hash()
            && proof.scope == auth.scope_code
            && proof.targets.len() == auth.targets.len()
            && proof
                .targets
                .iter()
                .zip(&auth.targets)
                .all(|((hash, sequence), target)| {
                    hash.as_bytes() == target.entry_hash()
                        && sequence.get() == target.chain_sequence()
                })
            && proof.confirmed.contains(&value.entry_hash())
            && proof.stubs.get(&value.entry_hash()) == Some(&stub.object_hash())
            && !proof.attestations.is_empty()
            && proof.attestations.iter().all(|(replica, hash)| {
                attestations.get(hash).is_some_and(|attestation| {
                    attestation.replica_id == *replica
                        && attestation.destruction_id == value.destruction_id()
                        && attestation.destruction_authorization_object_hash
                            == value.destruction_authorization_object_hash()
                        && attestation.result == 0
                        && attestation
                            .backup_expiry_at
                            .is_none_or(|deadline| deadline <= attestation.executed_at)
                })
            })
            && proof.attestations.iter().any(|(_, hash)| {
                attestations.get(hash).is_some_and(|attestation| {
                    attestation
                        .removed_object_hashes
                        .contains(&value.original_eip_object_hash())
                })
            })
    })
}
