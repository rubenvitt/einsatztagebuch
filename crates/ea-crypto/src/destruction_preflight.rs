//! Internal signed pre-state report profile. This is deliberately not an
//! archive ExactObject or Trust-wire family. Business/job proof validation
//! belongs to ea-destruction; this module fixes the sole signing byte profile.
use crate::digest::sha256_parts;
use crate::{CryptoError, object_hash};
use ea_cbor::{ParserLimits, validate};
use ea_types::{ChainSequence, Hash32, OrganizationId, RegistryVersion};
use minicbor::Decoder;

const DOMAIN: &str = "EINSATZARCHIV-DESTRUCTION-PREFLIGHT-v1";

/// Parsed, UNVERIFIED routing/binding data for native and WASM consumers.
/// This carries no current action authority or trusted time. Consumers must
/// verify the exact core's COSE context and compare all job/auth bindings.
pub struct ParsedDestructionPreflightCore<'a> {
    pub organization_id: [u8; 16],
    pub chain_id: [u8; 16],
    pub destruction_id: [u8; 16],
    pub authorization_hash: [u8; 32],
    pub inventory_hash: [u8; 32],
    pub report_hash: [u8; 32],
    pub report_json: &'a [u8],
    pub authorization_registry: u64,
    pub authorization_head: [u8; 32],
    pub authorization_sequence: u64,
    pub execution_registry: u64,
    pub execution_head: [u8; 32],
    pub execution_sequence: u64,
    pub observed_effective_now: i64,
}

pub(crate) struct PreflightBindings {
    pub digest: Hash32,
    pub organization_id: OrganizationId,
    pub registry: RegistryVersion,
    pub sequence: ChainSequence,
}

pub(crate) fn bindings(exact: &[u8]) -> Result<PreflightBindings, CryptoError> {
    let parsed = decode_destruction_preflight_core(exact)?;
    Ok(PreflightBindings {
        digest: sha256_parts(&[DOMAIN.as_bytes(), &[0], exact]),
        organization_id: OrganizationId::try_from(parsed.organization_id.as_slice())
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
        registry: RegistryVersion::new(parsed.execution_registry),
        sequence: ChainSequence::new(parsed.execution_sequence),
    })
}

pub fn decode_destruction_preflight_core(
    exact: &[u8],
) -> Result<ParsedDestructionPreflightCore<'_>, CryptoError> {
    validate(exact, ParserLimits::V1).map_err(|_| CryptoError::InvalidProtocolCore)?;
    (|| -> Result<_, minicbor::decode::Error> {
        let mut d = Decoder::new(exact);
        if d.array()? != Some(16) || d.str()? != DOMAIN || d.u64()? != 1 {
            return Err(minicbor::decode::Error::message(
                "invalid preflight profile",
            ));
        }
        let organization_id = fixed::<16>(&mut d)?;
        let chain_id = fixed::<16>(&mut d)?;
        let destruction_id = fixed::<16>(&mut d)?;
        let authorization_hash = fixed::<32>(&mut d)?;
        let inventory_hash = fixed::<32>(&mut d)?;
        let report_hash = fixed::<32>(&mut d)?;
        let report = d.bytes()?;
        if report.is_empty() || object_hash(report).as_bytes() != &report_hash {
            return Err(minicbor::decode::Error::message("invalid report hash"));
        }
        let authorization_registry = d.u64()?;
        let authorization_head = fixed::<32>(&mut d)?;
        let authorization_sequence = d.u64()?;
        let registry = d.u64()?;
        let execution_head = fixed::<32>(&mut d)?;
        let sequence = d.u64()?;
        let observed_effective_now = d.i64()?;
        if d.position() != exact.len()
            || registry < authorization_registry
            || sequence < authorization_sequence
        {
            return Err(minicbor::decode::Error::message(
                "invalid preflight context",
            ));
        }
        Ok(ParsedDestructionPreflightCore {
            organization_id,
            chain_id,
            destruction_id,
            authorization_hash,
            inventory_hash,
            report_hash,
            report_json: report,
            authorization_registry,
            authorization_head,
            authorization_sequence,
            execution_registry: registry,
            execution_head,
            execution_sequence: sequence,
            observed_effective_now,
        })
    })()
    .map_err(|_| CryptoError::InvalidProtocolCore)
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("invalid fixed bytes"))
}
