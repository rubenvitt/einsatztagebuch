//! Closed internal Go-live posture documentation profile. Parsed fields are
//! signed claims, never native measurements or an admission proof.
use crate::{CryptoError, digest::sha256_parts};
use ea_cbor::{ParserLimits, validate};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};
use minicbor::{Decoder, Encoder};

pub const GO_LIVE_POSTURE_MAX_LIFETIME_MS: i64 = 86_400_000;
const DOMAIN: &str = "EINSATZARCHIV-GOLIVE-POSTURE-v1";

#[derive(Clone, Eq, PartialEq)]
pub struct GoLivePostureFields {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub target_installation_id: Hash32,
    pub target_account_hash: Hash32,
    pub target_device_id: DeviceId,
    pub target_certificate_hash: CertificateHash,
    pub target_binding_hash: ObjectHash,
    pub os_family: u8,
    pub os_build_hash: ObjectHash,
    pub documented_unknown_mask: u8,
    pub evidence_reference_hash: ObjectHash,
    pub issuer_certificate_hash: CertificateHash,
    pub issuer_binding_hash: ObjectHash,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: ObjectHash,
    pub issued_sequence: ChainSequence,
    pub issued_at: UnixMillis,
    pub valid_until: UnixMillis,
}
pub struct GoLivePostureCore {
    fields: GoLivePostureFields,
    exact: Vec<u8>,
}
impl GoLivePostureCore {
    pub fn new(fields: GoLivePostureFields) -> Result<Self, CryptoError> {
        let mut e = Encoder::new(Vec::new());
        let encoded = (|| -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
            e.array(20)?.str(DOMAIN)?.u8(1)?;
            e.bytes(fields.organization_id.as_bytes())?
                .bytes(fields.chain_id.as_bytes())?;
            e.bytes(fields.target_installation_id.as_bytes())?
                .bytes(fields.target_account_hash.as_bytes())?;
            e.bytes(fields.target_device_id.as_bytes())?
                .bytes(fields.target_certificate_hash.as_bytes())?
                .bytes(fields.target_binding_hash.as_bytes())?;
            e.u8(fields.os_family)?
                .bytes(fields.os_build_hash.as_bytes())?
                .u8(fields.documented_unknown_mask)?;
            e.bytes(fields.evidence_reference_hash.as_bytes())?
                .bytes(fields.issuer_certificate_hash.as_bytes())?
                .bytes(fields.issuer_binding_hash.as_bytes())?;
            e.u64(fields.registry_version.get())?
                .bytes(fields.registry_head_hash.as_bytes())?
                .u64(fields.issued_sequence.get())?;
            e.i64(fields.issued_at.get())?
                .i64(fields.valid_until.get())?;
            Ok(())
        })();
        encoded.map_err(|_| CryptoError::InvalidProtocolCore)?;
        Self::from_exact(&e.into_writer())
    }
    pub fn from_exact(exact: &[u8]) -> Result<Self, CryptoError> {
        validate(exact, ParserLimits::V1).map_err(|_| CryptoError::InvalidProtocolCore)?;
        let parsed = (|| -> Result<GoLivePostureFields, minicbor::decode::Error> {
            let mut d = Decoder::new(exact);
            if d.array()? != Some(20) || d.str()? != DOMAIN || d.u8()? != 1 {
                return Err(invalid());
            }
            macro_rules! id {
                ($kind:ty, $n:expr) => {
                    <$kind>::try_from(fixed::<$n>(&mut d)?.as_slice()).map_err(|_| invalid())?
                };
            }
            let fields = GoLivePostureFields {
                organization_id: id!(OrganizationId, 16),
                chain_id: id!(ChainId, 16),
                target_installation_id: id!(Hash32, 32),
                target_account_hash: id!(Hash32, 32),
                target_device_id: id!(DeviceId, 16),
                target_certificate_hash: id!(CertificateHash, 32),
                target_binding_hash: id!(ObjectHash, 32),
                os_family: d.u8()?,
                os_build_hash: id!(ObjectHash, 32),
                documented_unknown_mask: d.u8()?,
                evidence_reference_hash: id!(ObjectHash, 32),
                issuer_certificate_hash: id!(CertificateHash, 32),
                issuer_binding_hash: id!(ObjectHash, 32),
                registry_version: RegistryVersion::new(d.u64()?),
                registry_head_hash: id!(ObjectHash, 32),
                issued_sequence: ChainSequence::new(d.u64()?),
                issued_at: UnixMillis::new(d.i64()?),
                valid_until: UnixMillis::new(d.i64()?),
            };
            let duration = fields
                .valid_until
                .get()
                .checked_sub(fields.issued_at.get())
                .ok_or_else(invalid)?;
            if d.position() != exact.len()
                || !(1..=3).contains(&fields.os_family)
                || !(1..=15).contains(&fields.documented_unknown_mask)
                || !(1..=GO_LIVE_POSTURE_MAX_LIFETIME_MS).contains(&duration)
            {
                return Err(invalid());
            }
            Ok(fields)
        })()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
        Ok(Self {
            fields: parsed,
            exact: exact.to_vec(),
        })
    }
    pub fn fields(&self) -> &GoLivePostureFields {
        &self.fields
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub fn digest(&self) -> Hash32 {
        sha256_parts(&[DOMAIN.as_bytes(), &[0], &self.exact])
    }
}
fn invalid() -> minicbor::decode::Error {
    minicbor::decode::Error::message("invalid posture profile")
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], minicbor::decode::Error> {
    d.bytes()?.try_into().map_err(|_| invalid())
}
