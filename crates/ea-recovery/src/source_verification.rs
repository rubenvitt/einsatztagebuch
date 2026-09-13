//! Verification of the existing signed audit envelope for a pre-loss scope.
use crate::{
    FsArchiveSource, KeyInventory, RecoveryArchiveProbe, RecoveryKeyRole, RecoverySourceCore,
    RecoveryTestError, RecoveryTestKind,
};
use ea_crypto::{SignerRole, VerificationContext, object_hash, verify_cose_sign1};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, LocalAuditActionV1, LocalAuditOutcomeV1,
    OperatorRoleV1,
};
use ea_trust::{HistoricalRegistryAuthority, TrustAnchorV1};
use ea_types::{CertificateHash, ChainSequence, ObjectHash, RegistryVersion, UnixMillis};

/// The exact source scope has passed signed archive, historical admin signature,
/// inventory/epoch coverage and immutable probe membership checks. It does not
/// claim possession of media, successful restore or readiness.
pub struct VerifiedRecoverySource {
    core: RecoverySourceCore,
    exact_envelope: Vec<u8>,
}
impl VerifiedRecoverySource {
    pub fn core(&self) -> &RecoverySourceCore {
        &self.core
    }
    pub fn exact_envelope(&self) -> &[u8] {
        &self.exact_envelope
    }
    pub fn envelope_hash(&self) -> ObjectHash {
        object_hash(&self.exact_envelope)
    }
}
pub fn recovery_source_envelope(
    core: &RecoverySourceCore,
    audit: &[u8],
) -> Result<Vec<u8>, RecoveryTestError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .and_then(|e| e.bytes(core.exact_bytes()))
        .and_then(|e| e.bytes(audit))
        .map_err(|_| RecoveryTestError::Source)?;
    Ok(e.into_writer())
}
pub fn verify_recovery_source(
    exact: &[u8],
    source: &FsArchiveSource,
    anchor: &TrustAnchorV1,
    keys: &KeyInventory,
    now: UnixMillis,
) -> Result<VerifiedRecoverySource, RecoveryTestError> {
    if exact.len() > 512 * 1024 {
        return Err(RecoveryTestError::Source);
    }
    let mut d = minicbor::Decoder::new(exact);
    if d.array().map_err(|_| RecoveryTestError::Source)? != Some(2) {
        return Err(RecoveryTestError::Source);
    }
    let core = RecoverySourceCore::from_exact(d.bytes().map_err(|_| RecoveryTestError::Source)?)?;
    let audit = d.bytes().map_err(|_| RecoveryTestError::Source)?;
    if d.position() != exact.len() || recovery_source_envelope(&core, audit)? != exact {
        return Err(RecoveryTestError::Source);
    }
    let f = core.fields();
    if f.organization_id != *anchor.organization_id().as_bytes()
        || f.chain_id != *anchor.chain_id().as_bytes()
        || f.anchor_hash != *anchor.trust_anchor_hash().as_bytes()
        || f.inventory_hash != *keys.exact_hash().as_bytes()
        || f.archive_inventory_hash != crate::recovery_archive_inventory_hash(source)?
        || f.effective_now > now.get()
    {
        return Err(RecoveryTestError::Source);
    }
    let probe = RecoveryArchiveProbe::verify(source, anchor, now)?;
    let tip = probe.verified_public_chain_head();
    if f.tip_sequence != tip.sequence().get() || f.tip_entry_hash != *tip.entry_hash().as_bytes() {
        return Err(RecoveryTestError::Source);
    }
    let head = ea_verify::historical_registry_head(
        probe.inventory(),
        anchor,
        RegistryVersion::new(f.registry_version),
        ObjectHash::try_from(f.registry_head.as_slice()).map_err(|_| RecoveryTestError::Source)?,
        ChainSequence::new(f.proposed_sequence),
        now,
    )
    .ok_or(RecoveryTestError::Source)?;
    verify_recovery_audit_context(
        audit,
        &head,
        core.context_hash(),
        UnixMillis::new(f.effective_now),
        LocalAuditOutcomeV1::Accepted,
    )?;
    verify_scope(&core, &probe, anchor, keys, &head, now)?;
    Ok(VerifiedRecoverySource {
        core,
        exact_envelope: exact.to_vec(),
    })
}
pub fn verify_recovery_audit_context(
    exact: &[u8],
    head: &HistoricalRegistryAuthority,
    context: ea_types::Hash32,
    time: UnixMillis,
    outcome: LocalAuditOutcomeV1,
) -> Result<(), RecoveryTestError> {
    let event = ea_format::decode_local_audit_event(exact).map_err(|_| RecoveryTestError::Audit)?;
    if event.organization_id() != head.organization_id()
        || event.effective_now() != time
        || event.outcome() != outcome
        || !matches!(event.action(),LocalAuditActionV1::RecoveryTest(c) if c.subject_object_hash()==Some(ObjectHash::from(context)))
    {
        return Err(RecoveryTestError::Audit);
    }
    let cert = CertificateHash::from(event.signer_certificate_object_hash());
    let fields = head
        .active_certificate_fields(cert)
        .ok_or(RecoveryTestError::Audit)?;
    let binding = head
        .active_operator_binding_fields(
            event
                .operator_binding_object_hash()
                .ok_or(RecoveryTestError::Audit)?,
        )
        .ok_or(RecoveryTestError::Audit)?;
    if fields.certificate_kind != CertificateKindV1::OrganizationAdmin
        || fields.device_id != event.device_id()
        || binding.device_certificate_hash != cert
        || binding.operator_role != OperatorRoleV1::OrganizationAdmin
        || binding.organization_id != head.organization_id()
    {
        return Err(RecoveryTestError::Audit);
    }
    let mut d = minicbor::Decoder::new(exact);
    d.array().map_err(|_| RecoveryTestError::Audit)?;
    d.skip().map_err(|_| RecoveryTestError::Audit)?;
    let start = d.position();
    d.skip().map_err(|_| RecoveryTestError::Audit)?;
    let context = VerificationContext::local_audit(
        event.exact_core(),
        head.proposed_sequence(),
        SignerRole::OrganizationAdmin,
        head.registry_version(),
    )
    .map_err(|_| RecoveryTestError::Audit)?;
    verify_cose_sign1(&exact[start..d.position()], head, &context)
        .map_err(|_| RecoveryTestError::Audit)?;
    Ok(())
}
fn verify_scope(
    core: &RecoverySourceCore,
    probe: &RecoveryArchiveProbe<'_>,
    anchor: &TrustAnchorV1,
    keys: &KeyInventory,
    head: &HistoricalRegistryAuthority,
    now: UnixMillis,
) -> Result<(), RecoveryTestError> {
    for role in RecoveryKeyRole::ALL {
        if !keys.media().iter().any(|m| m.role() == role) {
            return Err(RecoveryTestError::Incomplete);
        }
    }
    for medium in keys.media() {
        if medium.role() == RecoveryKeyRole::Root {
            if medium.test_kind() == RecoveryTestKind::RecoveryDecrypt
                || historical_signing_authority(
                    probe.inventory(),
                    anchor,
                    medium,
                    head.registry_version(),
                    now,
                )
                .is_none()
            {
                return Err(RecoveryTestError::Role);
            }
        } else if medium.role() != RecoveryKeyRole::RecoveryRecipient {
            let cert = head
                .known_certificate_fields()
                .find(|(hash, _)| *hash == medium.certificate())
                .map(|(_, fields)| fields)
                .ok_or(RecoveryTestError::Role)?;
            if head
                .active_certificate_fields(medium.certificate())
                .is_none()
                && historical_signing_authority(
                    probe.inventory(),
                    anchor,
                    medium,
                    head.registry_version(),
                    now,
                )
                .is_none()
            {
                return Err(RecoveryTestError::Role);
            }
            if crate::challenge::certificate_role(cert.certificate_kind) != medium.role()
                || cert.signing_key_thumbprint != Some(medium.expected_thumbprint())
                || medium.test_kind() == RecoveryTestKind::RecoveryDecrypt
            {
                return Err(RecoveryTestError::Role);
            }
        } else {
            let binding = core
                .fields()
                .probes
                .iter()
                .find(|p| p.medium_hash == *medium.pseudonymous_id_hash().as_bytes())
                .ok_or(RecoveryTestError::Incomplete)?;
            if binding.certificate_hash != *medium.certificate().as_bytes()
                || binding.key_thumbprint != *medium.expected_thumbprint().as_bytes()
                || medium.test_kind() != RecoveryTestKind::RecoveryDecrypt
            {
                return Err(RecoveryTestError::Role);
            }
            let entry = probe
                .inventory()
                .entries()
                .iter()
                .find(|entry| entry.value().entry_hash().as_bytes() == &binding.setup_entry_hash)
                .ok_or(RecoveryTestError::Incomplete)?;
            let grant = probe
                .inventory()
                .grants()
                .iter()
                .find(|grant| grant.object_hash().as_bytes() == &binding.initial_grant_hash)
                .ok_or(RecoveryTestError::Incomplete)?;
            let g = grant.value().grant_body().fields();
            if g.recipient_certificate_hash != medium.certificate()
                || g.recipient_key_thumbprint != medium.expected_thumbprint()
            {
                return Err(RecoveryTestError::Role);
            }
            ea_verify::verify_original_recovery_grant(probe.inventory(), anchor, entry, grant, now)
                .map_err(|_| RecoveryTestError::Archive)?;
        }
    }
    if core.fields().probes.len()
        != keys
            .media()
            .iter()
            .filter(|m| m.role() == RecoveryKeyRole::RecoveryRecipient)
            .count()
    {
        return Err(RecoveryTestError::Incomplete);
    }
    // Every currently active configured role certificate must have a media entry.
    // Every retained original Recovery epoch must also be covered, even after rotation.
    for object in probe.inventory().trust() {
        let hash = CertificateHash::from(object.object_hash());
        let payload = object
            .value()
            .decoded_payload()
            .map_err(|_| RecoveryTestError::Archive)?;
        let cert = match &payload {
            DecodedTrustPayloadV1::InitialAdminDevice(c) => Some(c),
            DecodedTrustPayloadV1::AuthorizedDevice(c) => Some(c.fields()),
            _ => None,
        };
        let root = match &payload {
            DecodedTrustPayloadV1::InitialRoot(fields) => Some(fields),
            DecodedTrustPayloadV1::AuthorizedRoot(core) => Some(core.fields()),
            _ => None,
        };
        if let Some(root) = root
            && historical_authority(
                probe.inventory(),
                anchor,
                (hash, RecoveryKeyRole::Root, root.root_key_thumbprint),
                head.registry_version(),
                now,
            )
            .is_some()
            && !keys.media().iter().any(|m| {
                m.role() == RecoveryKeyRole::Root
                    && m.certificate() == hash
                    && m.expected_thumbprint() == root.root_key_thumbprint
            })
        {
            return Err(RecoveryTestError::Incomplete);
        }
        if let Some(cert) = cert
            && head.active_certificate_fields(hash).is_some()
            && !keys.media().iter().any(|m| {
                m.certificate() == hash
                    && m.role() == crate::challenge::certificate_role(cert.certificate_kind)
            })
        {
            return Err(RecoveryTestError::Incomplete);
        }
    }
    for grant in probe.inventory().grants() {
        let g = grant.value().grant_body().fields();
        if g.purpose == ea_format::GrantPurposeV1::Recovery
            && !keys.media().iter().any(|m| {
                m.role() == RecoveryKeyRole::RecoveryRecipient
                    && m.certificate() == g.recipient_certificate_hash
                    && m.expected_thumbprint() == g.recipient_key_thumbprint
            })
        {
            return Err(RecoveryTestError::Incomplete);
        }
    }
    Ok(())
}

// Discovery selects only exact signed past snapshots and retains the existing
// successor/effective-sequence barrier. It can never return current authority.
pub(crate) fn historical_signing_authority(
    inventory: &ea_archive::ArchiveInventory,
    anchor: &TrustAnchorV1,
    medium: &crate::RecoveryMedium,
    through: RegistryVersion,
    now: UnixMillis,
) -> Option<HistoricalRegistryAuthority> {
    historical_authority(
        inventory,
        anchor,
        (
            medium.certificate(),
            medium.role(),
            medium.expected_thumbprint(),
        ),
        through,
        now,
    )
}
fn historical_authority(
    inventory: &ea_archive::ArchiveInventory,
    anchor: &TrustAnchorV1,
    identity: (CertificateHash, RecoveryKeyRole, ea_types::KeyThumbprint),
    through: RegistryVersion,
    now: UnixMillis,
) -> Option<HistoricalRegistryAuthority> {
    let (certificate, role, thumbprint) = identity;
    let mut routes = Vec::new();
    for object in inventory.trust() {
        if let Ok(DecodedTrustPayloadV1::RegistryEvent(core)) = object.value().decoded_payload() {
            let f = core.fields();
            if f.registry_version <= through {
                routes.push((
                    f.registry_version,
                    object.object_hash(),
                    f.effective_from_sequence,
                ));
            }
        }
    }
    routes.sort_by_key(|route| std::cmp::Reverse(route.0));
    for (version, hash, sequence) in routes {
        let Some(past) =
            ea_verify::historical_registry_head(inventory, anchor, version, hash, sequence, now)
        else {
            continue;
        };
        if role == RecoveryKeyRole::Root {
            use ea_crypto::SignerCertificateResolver;
            let Some(object) = inventory
                .trust()
                .iter()
                .find(|o| o.object_hash().as_bytes() == certificate.as_bytes())
            else {
                continue;
            };
            let Ok(payload) = object.value().decoded_payload() else {
                continue;
            };
            let root = match &payload {
                DecodedTrustPayloadV1::InitialRoot(fields) => fields,
                DecodedTrustPayloadV1::AuthorizedRoot(core) => core.fields(),
                _ => continue,
            };
            if root.root_key_thumbprint == thumbprint
                && past
                    .resolve(certificate, version)
                    .is_ok_and(|resolved| resolved.root_line_accepted)
            {
                return Some(past);
            }
        }
        if let Some(cert) = past.active_certificate_fields(certificate)
            && crate::challenge::certificate_role(cert.certificate_kind) == role
            && cert.signing_key_thumbprint == Some(thumbprint)
        {
            return Some(past);
        }
    }
    None
}
