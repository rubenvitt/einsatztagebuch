//! Parsed public source claims are not a verified backup or readiness proof.
use crate::{RecoveryBackupKdf, RecoveryTestError};
use ea_crypto::object_hash;
use ea_types::Hash32;

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryProbeBinding {
    pub medium_hash: [u8; 32],
    pub certificate_hash: [u8; 32],
    pub key_thumbprint: [u8; 32],
    pub setup_entry_hash: [u8; 32],
    pub initial_grant_hash: [u8; 32],
}
pub struct RecoverySourceFields {
    pub source_id: [u8; 16],
    pub organization_id: [u8; 16],
    pub chain_id: [u8; 16],
    pub anchor_hash: [u8; 32],
    pub source_machine: [u8; 32],
    pub source_installation: [u8; 32],
    pub registry_version: u64,
    pub registry_head: [u8; 32],
    pub proposed_sequence: u64,
    pub effective_now: i64,
    pub inventory_hash: [u8; 32],
    pub archive_inventory_hash: [u8; 32],
    pub tip_sequence: u64,
    pub tip_entry_hash: [u8; 32],
    pub snapshot_hash: [u8; 32],
    pub migrations_hash: [u8; 32],
    pub kdf: RecoveryBackupKdf,
    pub probes: Vec<RecoveryProbeBinding>,
}
/// Exact syntax only. The native service independently verifies the signed
/// RecoveryTest/Accepted envelope before this can authorize a restore input.
pub struct RecoverySourceCore {
    fields: RecoverySourceFields,
    exact: Vec<u8>,
}
const DOMAIN: &str = "EINSATZARCHIV-RECOVERY-SOURCE-v1";
const CONTEXT: &[u8] = b"EINSATZARCHIV-RECOVERY-SOURCE-CONTEXT-v1";
const LIMIT: usize = 256 * 1024;
impl RecoverySourceCore {
    pub fn new(fields: RecoverySourceFields) -> Result<Self, RecoveryTestError> {
        let f = &fields;
        if f.source_id == [0; 16]
            || f.source_machine == [0; 32]
            || f.source_installation == [0; 32]
            || f.registry_version == 0
            || f.tip_sequence.checked_add(1) != Some(f.proposed_sequence)
            || f.effective_now < 0
            || f.probes.is_empty()
            || f.probes.len() > 1024
            || f.probes
                .windows(2)
                .any(|p| p[0].medium_hash >= p[1].medium_hash)
        {
            return Err(RecoveryTestError::Source);
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        let encoded = (|| {
            e.array(19)?
                .str(DOMAIN)?
                .u8(1)?
                .bytes(&f.source_id)?
                .bytes(&f.organization_id)?
                .bytes(&f.chain_id)?
                .bytes(&f.anchor_hash)?
                .bytes(&f.source_machine)?
                .bytes(&f.source_installation)?
                .u64(f.registry_version)?
                .bytes(&f.registry_head)?
                .u64(f.proposed_sequence)?
                .i64(f.effective_now)?
                .bytes(&f.inventory_hash)?
                .bytes(&f.archive_inventory_hash)?
                .array(2)?
                .u64(f.tip_sequence)?
                .bytes(&f.tip_entry_hash)?
                .bytes(&f.snapshot_hash)?
                .bytes(&f.migrations_hash)?
                .bytes(f.kdf.exact_bytes())?
                .array(f.probes.len() as u64)?;
            for p in &f.probes {
                e.array(5)?
                    .bytes(&p.medium_hash)?
                    .bytes(&p.certificate_hash)?
                    .bytes(&p.key_thumbprint)?
                    .bytes(&p.setup_entry_hash)?
                    .bytes(&p.initial_grant_hash)?;
            }
            Ok::<(), minicbor::encode::Error<std::convert::Infallible>>(())
        })();
        encoded.map_err(|_| RecoveryTestError::Source)?;
        let exact = e.into_writer();
        if exact.len() > LIMIT {
            return Err(RecoveryTestError::Source);
        }
        Ok(Self { fields, exact })
    }
    pub fn from_exact(exact: &[u8]) -> Result<Self, RecoveryTestError> {
        if exact.len() > LIMIT {
            return Err(RecoveryTestError::Source);
        }
        let parsed = (|| {
            let mut d = minicbor::Decoder::new(exact);
            if d.array()? != Some(19) || d.str()? != DOMAIN || d.u8()? != 1 {
                return Err(invalid());
            }
            let source_id = bytes(&mut d)?;
            let organization_id = bytes(&mut d)?;
            let chain_id = bytes(&mut d)?;
            let anchor_hash = bytes(&mut d)?;
            let source_machine = bytes(&mut d)?;
            let source_installation = bytes(&mut d)?;
            let registry_version = d.u64()?;
            let registry_head = bytes(&mut d)?;
            let proposed_sequence = d.u64()?;
            let effective_now = d.i64()?;
            let inventory_hash = bytes(&mut d)?;
            let archive_inventory_hash = bytes(&mut d)?;
            if d.array()? != Some(2) {
                return Err(invalid());
            }
            let tip_sequence = d.u64()?;
            let tip_entry_hash = bytes(&mut d)?;
            let snapshot_hash = bytes(&mut d)?;
            let migrations_hash = bytes(&mut d)?;
            let kdf = RecoveryBackupKdf::from_exact(d.bytes()?).map_err(|_| invalid())?;
            let count = d.array()?.ok_or_else(invalid)?;
            if count == 0 || count > 1024 {
                return Err(invalid());
            }
            let mut probes = Vec::with_capacity(count as usize);
            for _ in 0..count {
                if d.array()? != Some(5) {
                    return Err(invalid());
                }
                probes.push(RecoveryProbeBinding {
                    medium_hash: bytes(&mut d)?,
                    certificate_hash: bytes(&mut d)?,
                    key_thumbprint: bytes(&mut d)?,
                    setup_entry_hash: bytes(&mut d)?,
                    initial_grant_hash: bytes(&mut d)?,
                });
            }
            if d.position() != exact.len() {
                return Err(invalid());
            }
            Ok(RecoverySourceFields {
                source_id,
                organization_id,
                chain_id,
                anchor_hash,
                source_machine,
                source_installation,
                registry_version,
                registry_head,
                proposed_sequence,
                effective_now,
                inventory_hash,
                archive_inventory_hash,
                tip_sequence,
                tip_entry_hash,
                snapshot_hash,
                migrations_hash,
                kdf,
                probes,
            })
        })()
        .map_err(|_: minicbor::decode::Error| RecoveryTestError::Source)?;
        let result = Self::new(parsed)?;
        if result.exact != exact {
            return Err(RecoveryTestError::Source);
        }
        Ok(result)
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub fn fields(&self) -> &RecoverySourceFields {
        &self.fields
    }
    pub fn context_hash(&self) -> Hash32 {
        let mut input = Vec::with_capacity(CONTEXT.len() + self.exact.len());
        input.extend_from_slice(CONTEXT);
        input.extend_from_slice(&self.exact);
        Hash32::try_from(object_hash(&input).as_bytes().as_slice()).expect("hash width")
    }
}
fn invalid() -> minicbor::decode::Error {
    minicbor::decode::Error::message("invalid recovery source")
}
fn bytes<const N: usize>(
    d: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], minicbor::decode::Error> {
    d.bytes()?.try_into().map_err(|_| invalid())
}

/// Fingerprint the committed exact archive objects, including their canonical
/// relative placement. A hash is a scope measurement, never verification.
pub fn recovery_archive_inventory_hash(
    source: &crate::FsArchiveSource,
) -> Result<[u8; 32], RecoveryTestError> {
    use ea_archive::ArchiveSource;
    let mut rows = Vec::new();
    source
        .visit_blobs(&mut |blob| {
            if ea_format::decode_exact_object(blob.bytes()).is_ok() {
                rows.push((
                    blob.path_hint().to_owned(),
                    *object_hash(blob.bytes()).as_bytes(),
                ));
            }
            Ok(())
        })
        .map_err(|_| RecoveryTestError::Archive)?;
    rows.sort();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(rows.len() as u64)
        .map_err(|_| RecoveryTestError::Archive)?;
    for (path, hash) in rows {
        e.array(2)
            .and_then(|e| e.str(&path))
            .and_then(|e| e.bytes(&hash))
            .map_err(|_| RecoveryTestError::Archive)?;
    }
    Ok(*object_hash(&e.into_writer()).as_bytes())
}
