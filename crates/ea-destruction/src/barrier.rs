//! Synchronous core boundary for an authenticated host reservation read.
use crate::{DestructionError as Error, VerifiedDestructionAuthorization};
use ea_types::{DestructionId, ObjectHash, OrganizationId};

/// Trusted host adapter: perform the actual authenticated GET, require HTTP
/// success, and supply its exact existing status frame. The server checks all
/// signed target reservations before returning success. No UI/cache adapter
/// or mere Stub observation may implement this port in production.
pub trait ServerReservationPort {
    fn read_current_status(
        &mut self,
        organization: OrganizationId,
        destruction: DestructionId,
    ) -> Result<Vec<u8>, Error>;
}
/// Exact reservation binding only. Does not confer native action authority,
/// attest to removal, or reconstruct a state from the unsigned status code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryBarrierEvidence {
    AuthenticatedServerReservation,
    VerifiedAbsenceOfRegisteredServers,
}
pub struct ConfirmedDeliveryBarrier {
    evidence: DeliveryBarrierEvidence,
    authorization: ObjectHash,
    destruction: DestructionId,
}
impl ConfirmedDeliveryBarrier {
    pub const fn evidence(&self) -> DeliveryBarrierEvidence {
        self.evidence
    }
    pub const fn authorization_hash(&self) -> ObjectHash {
        self.authorization
    }
    pub const fn destruction_id(&self) -> DestructionId {
        self.destruction
    }
}
pub fn confirm_delivery_barrier(
    auth: &VerifiedDestructionAuthorization,
    server: &mut dyn ServerReservationPort,
) -> Result<ConfirmedDeliveryBarrier, Error> {
    let exact =
        server.read_current_status(auth.fields().organization_id, auth.fields().destruction_id)?;
    let status =
        ea_sync_protocol::DestructionStatusResponseV1::decode(&exact).map_err(|_| Error::Format)?;
    if status.destruction_id() != auth.fields().destruction_id
        || status.authorization_object_hash() != auth.object_hash()
    {
        return Err(Error::SecurityConflict);
    }
    Ok(ConfirmedDeliveryBarrier {
        evidence: DeliveryBarrierEvidence::AuthenticatedServerReservation,
        authorization: auth.object_hash(),
        destruction: auth.fields().destruction_id,
    })
}

/// Local-only admission: proves absence from the complete verified historical
/// and present catalogs AND the signed, durable job denominator. This does not
/// claim that any server reserved targets or confirmed a removal.
pub fn confirm_no_registered_server(
    auth: &VerifiedDestructionAuthorization,
    original: &ea_trust::HistoricalRegistryAuthority,
    current: &ea_trust::SelectedRegistryHead,
    catalog: &ea_trust::VerifiedCatalogCustody,
    job: &crate::VerifiedImportedPreflight,
    custody: &crate::DurableManagedInventory,
) -> Result<ConfirmedDeliveryBarrier, Error> {
    use ea_format::CertificateKindV1;
    if job.authorization().exact_bytes() != auth.exact_bytes()
        || job.custody_bytes() != custody.exact_bytes()
        || original.organization_id() != current.policy_fields().organization_id
        || original.chain_id() != current.chain_id()
        || original.registry_version() != auth.fields().registry_version
        || original.registry_head_hash().as_bytes() != auth.fields().registry_head_hash.as_bytes()
        || original.proposed_sequence().get() != auth.fields().authorization_sequence
        || current.registry_version() < original.registry_version()
        || current.proposed_sequence() < original.proposed_sequence()
        || catalog.organization_id() != current.policy_fields().organization_id
        || catalog.chain_id() != current.chain_id()
        || catalog.registry_version() < current.registry_version()
        || job.replicas().is_empty()
    {
        return Err(Error::SecurityConflict);
    }
    let mut known = 0;
    for (hash, fields) in original
        .known_certificate_fields()
        .chain(current.known_certificate_fields())
        .chain(catalog.known_certificate_fields())
    {
        if fields.certificate_kind == CertificateKindV1::ServerReceipt {
            return Err(Error::Target);
        }
        if matches!(
            fields.certificate_kind,
            CertificateKindV1::Writer | CertificateKindV1::Reader
        ) {
            known += 1;
            if !job
                .replicas()
                .contains(&(hash, fields.device_id, fields.certificate_kind as u8))
            {
                return Err(Error::SecurityConflict);
            }
        }
    }
    if known == 0
        || job
            .replicas()
            .iter()
            .any(|(_, _, kind)| !matches!(kind, 0 | 1))
    {
        return Err(Error::Target);
    }
    Ok(ConfirmedDeliveryBarrier {
        evidence: DeliveryBarrierEvidence::VerifiedAbsenceOfRegisteredServers,
        authorization: auth.object_hash(),
        destruction: auth.fields().destruction_id,
    })
}
