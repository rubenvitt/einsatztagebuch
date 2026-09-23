//! Historical grants use the authorization's Registry, independently of Entry age.
use crate::state::{EphemeralTrustStateStore, verification_state_key};
use ea_archive::ArchiveInventory;
use ea_crypto::{VerificationContext, verify_cose_sign1};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, EntryPackageV1, GrantKindV1, GrantPurposeV1, GrantV1,
    Parsed,
};
use ea_trust::{GrantAuthorizationError, TrustAnchorV1};
use ea_types::{ChainSequence, ObjectHash, RegistryVersion, UnixMillis};

/// Reconstruct exact signed Registry authority from the archive's trust bytes.
pub fn historical_registry_head(
    inventory: &ArchiveInventory,
    anchor: &TrustAnchorV1,
    version: RegistryVersion,
    hash: ObjectHash,
    sequence: ChainSequence,
    _now: UnixMillis,
) -> Option<ea_trust::HistoricalRegistryAuthority> {
    let key = verification_state_key(anchor.organization_id());
    let mut store = EphemeralTrustStateStore::new(key, UnixMillis::new(0));
    // Dasselbe Gate `trust` wie der Prüflauf: auch die Escrow-Menge muss tragen.
    let trust = crate::trust_gate::verified_trust(&mut store, key, anchor, inventory)?;
    ea_trust::verify_historical_registry_authority(&trust, version, hash, sequence).ok()
}

/// Verify the original initial Recovery grant's exact Entry and Writer attribution.
pub fn verify_original_recovery_grant(
    inventory: &ArchiveInventory,
    anchor: &TrustAnchorV1,
    entry: &Parsed<EntryPackageV1>,
    original: &Parsed<GrantV1>,
    now: UnixMillis,
) -> Result<(), &'static str> {
    let fields = original.value().grant_body().fields();
    let manifest = entry.value().manifest().fields();
    if fields.kind != GrantKindV1::Initial
        || fields.purpose != GrantPurposeV1::Recovery
        || fields.entry_hash != entry.value().entry_hash()
        || fields.organization_id != anchor.organization_id()
        || fields.chain_id != manifest.chain_id
        || fields.issuer_certificate_hash != manifest.writer_certificate_hash
        || fields.registry_version != manifest.registry_version
        || fields.registry_head_hash.as_bytes() != &manifest.registry_head_hash
    {
        return Err("EA-GRANT-RECOVERY-MISMATCH");
    }
    let head = historical_registry_head(
        inventory,
        anchor,
        manifest.registry_version,
        ObjectHash::try_from(manifest.registry_head_hash.as_slice())
            .map_err(|_| "EA-GRANT-RECOVERY-MISMATCH")?,
        manifest.chain_sequence,
        now,
    )
    .ok_or("EA-GRANT-RECOVERY-MISMATCH")?;
    let context = VerificationContext::initial_grant(
        original.value().grant_body().exact_bytes(),
        manifest.chain_sequence,
    )
    .map_err(|_| "EA-GRANT-RECOVERY-MISMATCH")?;
    verify_cose_sign1(original.value().issuer_signature(), &head, &context)
        .map_err(|_| "EA-GRANT-RECOVERY-MISMATCH")?;
    Ok(())
}

pub(crate) fn verify_historical_grant(
    inventory: &ArchiveInventory,
    anchor: &TrustAnchorV1,
    entry: &Parsed<EntryPackageV1>,
    grant: &Parsed<GrantV1>,
    now: UnixMillis,
) -> Result<UnixMillis, &'static str> {
    let fields = grant.value().grant_body().fields();
    let hash = fields
        .grant_authorization_object_hash
        .ok_or("EA-GRANT-AUTHORIZATION-UNVERIFIABLE")?;
    let authorization = inventory
        .trust()
        .iter()
        .find(|p| p.object_hash() == hash)
        .ok_or("EA-GRANT-AUTHORIZATION-UNVERIFIABLE")?;
    let DecodedTrustPayloadV1::GrantAuthorization(auth) =
        authorization
            .value()
            .decoded_payload()
            .map_err(|_| "EA-GRANT-AUTHORIZATION-UNVERIFIABLE")?
    else {
        return Err("EA-GRANT-AUTHORIZATION-UNVERIFIABLE");
    };
    let head = historical_registry_head(
        inventory,
        anchor,
        auth.registry_version,
        ObjectHash::from(auth.registry_head_hash),
        ChainSequence::new(auth.authorization_sequence),
        now,
    )
    .ok_or("EA-GRANT-REGISTRY-STALE")?;
    let context = VerificationContext::historical_grant(
        grant.value().grant_body().exact_bytes(),
        ChainSequence::new(auth.authorization_sequence),
    )
    .map_err(|_| "EA-GRANT-ISSUER-UNAUTHORIZED")?;
    verify_cose_sign1(grant.value().issuer_signature(), &head, &context)
        .map_err(|_| "EA-GRANT-ISSUER-UNAUTHORIZED")?;
    let proof = ea_trust::verify_archived_grant_authorization(
        authorization.exact_bytes().as_bytes(),
        &head,
        now,
    )
    .map_err(|e| {
        if e == GrantAuthorizationError::Expired {
            "EA-GRANT-EXPIRED"
        } else {
            e.code()
        }
    })?;
    let auth = proof.fields();
    let recipient = head
        .active_certificate_fields(fields.recipient_certificate_hash)
        .ok_or("EA-GRANT-AUTHORIZATION-MISMATCH")?;
    if fields.kind != GrantKindV1::Historical
        || fields.purpose != GrantPurposeV1::Reader
        || fields.registry_version != auth.registry_version
        || fields.registry_head_hash != auth.registry_head_hash
        || fields.organization_id != anchor.organization_id()
        || fields.chain_id != anchor.chain_id()
        || fields.entry_hash != entry.value().entry_hash()
        || !auth.entry_hashes.contains(&fields.entry_hash)
        || auth.recipient_certificate_hash != fields.recipient_certificate_hash
        || auth.recipient_key_thumbprint != fields.recipient_key_thumbprint
        || recipient.certificate_kind != CertificateKindV1::Reader
        || recipient.kem_key_thumbprint != Some(fields.recipient_key_thumbprint)
    {
        return Err("EA-GRANT-AUTHORIZATION-MISMATCH");
    }
    let original_hash = fields
        .original_recovery_grant_object_hash
        .ok_or("EA-GRANT-RECOVERY-MISMATCH")?;
    let original = inventory
        .grants()
        .iter()
        .find(|p| p.object_hash() == original_hash)
        .ok_or("EA-GRANT-RECOVERY-MISMATCH")?;
    verify_original_recovery_grant(inventory, anchor, entry, original, now)?;
    Ok(auth.expires_at)
}

pub(crate) fn historical_registry_head_by_hash(
    inventory: &ArchiveInventory,
    anchor: &TrustAnchorV1,
    hash: ObjectHash,
    sequence: ChainSequence,
    now: UnixMillis,
) -> Option<ea_trust::HistoricalRegistryAuthority> {
    let event = inventory.trust().iter().find(|p| p.object_hash() == hash)?;
    let DecodedTrustPayloadV1::RegistryEvent(core) = event.value().decoded_payload().ok()? else {
        return None;
    };
    historical_registry_head(
        inventory,
        anchor,
        core.fields().registry_version,
        hash,
        sequence,
        now,
    )
}
