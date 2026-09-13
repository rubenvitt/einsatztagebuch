//! Complete verified catalog history for custody only, never current authority.
use crate::{HistoricalRegistryAuthority, RegistryError, VerifiedTrust};
pub struct VerifiedCatalogCustody {
    pub(crate) historical: HistoricalRegistryAuthority,
}
impl VerifiedCatalogCustody {
    pub fn known_certificate_fields(
        &self,
    ) -> impl Iterator<
        Item = (
            ea_types::CertificateHash,
            &ea_format::DeviceCertificateFieldsV1,
        ),
    > {
        self.historical.known_certificate_fields()
    }
    pub fn registry_version(&self) -> ea_types::RegistryVersion {
        self.historical.registry_version()
    }
    pub fn registry_head_hash(&self) -> ea_types::ObjectHash {
        self.historical.registry_head_hash()
    }
    pub fn organization_id(&self) -> ea_types::OrganizationId {
        self.historical.organization_id()
    }
    pub fn chain_id(&self) -> ea_types::ChainId {
        self.historical.chain_id()
    }
}
pub fn verify_catalog_custody_authority(
    trust: &VerifiedTrust,
) -> Result<VerifiedCatalogCustody, RegistryError> {
    use ea_format::{DecodedTrustPayloadV1, TrustSubtypeV1};
    let mut latest = None;
    for hash in trust
        .inner
        .catalog
        .hashes_for_subtype(TrustSubtypeV1::RegistryEvent)
    {
        let record = trust
            .inner
            .catalog
            .get(hash)
            .ok_or(crate::TrustError::Source)?;
        let DecodedTrustPayloadV1::RegistryEvent(event) = record
            .value()
            .decoded_payload()
            .map_err(|_| crate::TrustError::Source)?
        else {
            return Err(crate::TrustError::Source.into());
        };
        let fields = event.fields();
        if fields.organization_id != trust.organization_id() {
            continue;
        }
        match latest {
            Some((version, _, _)) if fields.registry_version == version => {
                return Err(RegistryError::Fork);
            }
            Some((version, _, _)) if fields.registry_version < version => {}
            _ => {
                latest = Some((
                    fields.registry_version,
                    *hash,
                    fields.effective_from_sequence,
                ))
            }
        }
    }
    let (version, hash, sequence) = latest.ok_or(RegistryError::Gap)?;
    let historical = crate::verify_historical_registry_authority(trust, version, hash, sequence)?;
    Ok(VerifiedCatalogCustody { historical })
}
