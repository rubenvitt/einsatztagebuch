//! Historical operator attribution, before decrypted content is exposed.

use std::collections::BTreeMap;

use ea_archive::ArchiveInventory;
use ea_format::{ManifestCoreFieldsV1, OperatorBindingFieldsV1, OperatorRoleV1};
use ea_schema::{CommonHeaderV1, PayloadV1};
use ea_trust::{
    RegistrySelectionOutcome, SelectedRegistryHead, TrustAnchorV1, load_trust_state,
    prepare_local_time, select_registry_head, verify_registry_candidate, verify_trust,
};
use ea_types::{ObjectHash, UnixMillis};
use ea_verify::{EphemeralTrustStateStore, verification_state_key};

use crate::ReaderError;

/// Only authenticated, activated binding fields at this entry's sequence.
/// Retaining a SelectedRegistryHead per entry would also retain a separately
/// replayed copy of the entire trust catalog per entry. These small fields
/// keep that catalog out of the long-lived decryption witnesses.
pub(crate) struct HistoricalOperatorBindings(BTreeMap<ObjectHash, OperatorBindingFieldsV1>);

impl HistoricalOperatorBindings {
    fn from_head(head: &SelectedRegistryHead, inventory: &ArchiveInventory) -> Self {
        Self(
            inventory
                .trust()
                .iter()
                .filter_map(|object| {
                    let hash = object.object_hash();
                    head.active_operator_binding_fields(hash)
                        .map(|fields| (hash, fields.clone()))
                })
                .collect(),
        )
    }
}

/// Replays the authenticated line only as far as the manifest's exact head.
/// The anchor and clock are the same inputs as the archive report; this does
/// not introduce a weaker historical clock or use catalog membership as proof.
/// A later revocation must not replace this entry's historical attribution.
pub(crate) fn historical_bindings(
    anchor: &TrustAnchorV1,
    inventory: &ArchiveInventory,
    manifest: &ManifestCoreFieldsV1,
    effective_now: UnixMillis,
) -> Option<HistoricalOperatorBindings> {
    if anchor.organization_id() != manifest.organization_id
        || anchor.chain_id() != manifest.chain_id
    {
        return None;
    }
    let key = verification_state_key(anchor.organization_id());
    let mut store = EphemeralTrustStateStore::new(key, effective_now);
    let mut previous_version = None;
    for _ in 0..ea_trust::MAX_TRUST_OBJECTS_V1 {
        let snapshot = load_trust_state(&mut store, key).ok()?;
        let trust = verify_trust(anchor, inventory, snapshot).ok()?;
        let candidate = verify_registry_candidate(&trust, manifest.chain_sequence).ok()?;
        let version = candidate.registry_version();
        if version > manifest.registry_version
            || previous_version.is_some_and(|previous| version <= previous)
        {
            return None;
        }
        previous_version = Some(version);
        let target = version == manifest.registry_version;
        if target && *candidate.registry_head_hash().as_bytes() != manifest.registry_head_hash {
            return None;
        }
        let time = prepare_local_time(&mut store, &candidate, effective_now, &[]).ok()?;
        match select_registry_head(candidate, time, None).ok()? {
            RegistrySelectionOutcome::Selected(head) if target => {
                return Some(HistoricalOperatorBindings::from_head(&head, inventory));
            }
            RegistrySelectionOutcome::Advanced(_) if target => return None,
            RegistrySelectionOutcome::PendingFuture(_) => return None,
            RegistrySelectionOutcome::Selected(_) | RegistrySelectionOutcome::Advanced(_) => {}
        }
    }
    None
}

pub(crate) fn verify_snapshot(
    payload: &PayloadV1,
    manifest: &ManifestCoreFieldsV1,
    bindings: Option<&HistoricalOperatorBindings>,
) -> Result<(), ReaderError> {
    let header = header(payload);
    let operator = header.operator();
    let binding = bindings
        .and_then(|bindings| bindings.0.get(&operator.operator_binding_object_hash()))
        .ok_or(ReaderError::OperatorProfileCommitment)?;
    if header.registry_version() != manifest.registry_version
        || operator.organization_id() != manifest.organization_id
        || operator.organization_id() != binding.organization_id
        || operator.operator_subject_id() != binding.operator_subject_id
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
        return Err(ReaderError::OperatorProfileCommitment);
    }
    Ok(())
}

fn header(payload: &PayloadV1) -> &CommonHeaderV1 {
    match payload {
        PayloadV1::Genesis(value) => value.header(),
        PayloadV1::Incident(value) => value.header(),
        PayloadV1::Amendment(value) => value.header(),
        PayloadV1::KeyTransition(value) => value.header(),
        PayloadV1::DestructionEvidence(value) => value.header(),
    }
}
