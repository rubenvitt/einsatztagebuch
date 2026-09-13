//! Read-only validation of the approved signed job profile. Current action,
//! provider inventory and durable execution are separate mandatory gates.
use crate::{DestructionError as Error, VerifiedDestructionAuthorization};
use ea_crypto::{
    VerificationContext, decode_destruction_preflight_core, object_hash, verify_cose_sign1,
};
use ea_format::{CertificateKindV1, ExactObjectBytes, ParsedArchiveObject, decode_exact_object};
use ea_sync_protocol::{DestructionJobUploadV1, PROTOCOL_PARSER_LIMITS_V1};
use ea_trust::HistoricalRegistryAuthority;
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, ObjectHash, RegistryVersion,
};
use minicbor::Decoder;
use std::collections::BTreeSet;

pub struct ImportedPreflightTarget {
    entry: EntryHash,
    original: ObjectHash,
    stub: ExactObjectBytes,
    sequence: ChainSequence,
}
impl ImportedPreflightTarget {
    pub fn entry_hash(&self) -> EntryHash {
        self.entry
    }
    pub fn original_object_hash(&self) -> ObjectHash {
        self.original
    }
    pub fn exact_stub_bytes(&self) -> &[u8] {
        self.stub.as_bytes()
    }
    pub fn sequence(&self) -> ChainSequence {
        self.sequence
    }
}
/// Unverified routing only; obtaining this never authorizes any action.
pub struct PreflightTargetContext {
    pub registry: RegistryVersion,
    pub head: ObjectHash,
    pub sequence: ChainSequence,
}
pub fn preflight_target_contexts(
    upload: &DestructionJobUploadV1,
) -> Result<Vec<PreflightTargetContext>, Error> {
    let (targets, _, _) = decode_inventory(upload.inventory_bytes())?;
    targets
        .into_iter()
        .map(|t| {
            let ParsedArchiveObject::Destroyed(stub) = decode_exact_object(t.stub.as_bytes())?
            else {
                return Err(Error::Format);
            };
            let fields = stub.value().signed_manifest().manifest().fields();
            Ok(PreflightTargetContext {
                registry: fields.registry_version,
                head: ObjectHash::try_from(fields.registry_head_hash.as_slice())
                    .map_err(|_| Error::Format)?,
                sequence: fields.chain_sequence,
            })
        })
        .collect()
}

pub struct VerifiedImportedPreflight {
    upload: DestructionJobUploadV1,
    auth: VerifiedDestructionAuthorization,
    targets: Vec<ImportedPreflightTarget>,
    custody: Vec<u8>,
    replicas: Vec<(CertificateHash, DeviceId, u8)>,
    removals: Vec<ObjectHash>,
    chain: ChainId,
}
impl VerifiedImportedPreflight {
    pub fn verify(
        upload: &DestructionJobUploadV1,
        auth: &VerifiedDestructionAuthorization,
        original: &HistoricalRegistryAuthority,
        execution: &HistoricalRegistryAuthority,
        target_authorities: &[HistoricalRegistryAuthority],
    ) -> Result<Self, Error> {
        let core = decode_destruction_preflight_core(upload.core_bytes())?;
        let fields = auth.fields();
        if core.organization_id != *fields.organization_id.as_bytes()
            || core.chain_id != *original.chain_id().as_bytes()
            || original.chain_id() != execution.chain_id()
            || core.destruction_id != *fields.destruction_id.as_bytes()
            || core.authorization_hash != *auth.object_hash().as_bytes()
            || core.inventory_hash != *object_hash(upload.inventory_bytes()).as_bytes()
            || core.authorization_registry != fields.registry_version.get()
            || core.authorization_head != *fields.registry_head_hash.as_bytes()
            || core.authorization_sequence != fields.authorization_sequence
            || original.registry_version() != fields.registry_version
            || original.registry_head_hash().as_bytes() != fields.registry_head_hash.as_bytes()
            || original.proposed_sequence().get() != fields.authorization_sequence
            || core.execution_registry != execution.registry_version().get()
            || core.execution_head != *execution.registry_head_hash().as_bytes()
            || core.execution_sequence != execution.proposed_sequence().get()
            || core.observed_effective_now < 0
        {
            return Err(Error::Registry);
        }
        let cert = original
            .active_certificate_fields(upload.certificate_hash())
            .ok_or(Error::Signature)?;
        if cert.certificate_kind != CertificateKindV1::DeletionAttest
            || !cert.capabilities.iter().any(|v| v == "deletionAttest")
        {
            return Err(Error::Signature);
        }
        let context = VerificationContext::destruction_preflight_report(
            upload.core_bytes(),
            upload.certificate_hash(),
        )?;
        verify_cose_sign1(upload.signature_bytes(), execution, &context)?;
        let (targets, custody, removals) = decode_inventory(upload.inventory_bytes())?;
        if targets.len() != fields.targets.len() || targets.len() != target_authorities.len() {
            return Err(Error::Target);
        }
        for ((target, expected), authority) in
            targets.iter().zip(&fields.targets).zip(target_authorities)
        {
            let ParsedArchiveObject::Destroyed(parsed) =
                decode_exact_object(target.stub.as_bytes())?
            else {
                return Err(Error::Format);
            };
            let stub = parsed.value();
            let manifest = stub.signed_manifest().manifest().fields();
            if target.entry.as_bytes() != expected.entry_hash()
                || target.sequence.get() != expected.chain_sequence()
                || stub.entry_hash() != target.entry
                || stub.original_eip_object_hash() != target.original
                || stub.destruction_id() != fields.destruction_id
                || stub.destruction_authorization_object_hash() != auth.object_hash()
                || manifest.organization_id != fields.organization_id
                || manifest.chain_id != execution.chain_id()
                || manifest.registry_version != authority.registry_version()
                || manifest.registry_head_hash != *authority.registry_head_hash().as_bytes()
                || manifest.chain_sequence != authority.proposed_sequence()
                || manifest.chain_sequence != target.sequence
                || authority.organization_id() != fields.organization_id
                || authority.chain_id() != execution.chain_id()
            {
                return Err(Error::Target);
            }
            let context = VerificationContext::record(stub.signed_manifest().exact_bytes())?;
            verify_cose_sign1(stub.writer_signature(), authority, &context)?;
        }
        ea_verify::verify_destruction_preflight_report(
            core.report_json,
            execution.chain_id(),
            &targets
                .iter()
                .map(|t| (t.entry, t.sequence, t.original))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| Error::Target)?;
        let replicas = verify_custody(&custody, auth, execution, &targets)?;
        Ok(Self {
            upload: upload.clone(),
            auth: auth.clone(),
            targets,
            custody,
            replicas,
            removals,
            chain: execution.chain_id(),
        })
    }
    pub fn authorization(&self) -> &VerifiedDestructionAuthorization {
        &self.auth
    }
    pub fn job_hash(&self) -> ObjectHash {
        object_hash(self.upload.core_bytes())
    }
    pub fn exact_upload(&self) -> &[u8] {
        self.upload.exact_bytes()
    }
    pub fn targets(&self) -> &[ImportedPreflightTarget] {
        &self.targets
    }
    pub fn custody_bytes(&self) -> &[u8] {
        &self.custody
    }
    pub fn replicas(&self) -> &[(CertificateHash, DeviceId, u8)] {
        &self.replicas
    }
    pub fn removal_object_hashes(&self) -> &[ObjectHash] {
        &self.removals
    }
    pub fn chain_id(&self) -> ChainId {
        self.chain
    }
    pub fn core_bytes(&self) -> &[u8] {
        self.upload.core_bytes()
    }
    pub fn certificate_hash(&self) -> CertificateHash {
        self.upload.certificate_hash()
    }
}
fn verify_custody(
    exact: &[u8],
    auth: &VerifiedDestructionAuthorization,
    execution: &HistoricalRegistryAuthority,
    targets: &[ImportedPreflightTarget],
) -> Result<Vec<(CertificateHash, DeviceId, u8)>, Error> {
    ea_cbor::validate(exact, PROTOCOL_PARSER_LIMITS_V1).map_err(|_| Error::Format)?;
    let mut d = Decoder::new(exact);
    let f = auth.fields();
    let mut records = Vec::new();
    let mut replicas = BTreeSet::new();
    let mut holders = Vec::new();
    (|| -> Result<(), minicbor::decode::Error> {
        if d.array()? != Some(6)
            || d.str()? != "EINSATZARCHIV-MANAGED-CUSTODY-v1"
            || d.bytes()? != f.organization_id.as_bytes()
            || d.bytes()? != f.destruction_id.as_bytes()
            || d.bytes()? != auth.object_hash().as_bytes()
            || d.bytes()? != execution.chain_id().as_bytes()
        {
            return Err(bad());
        }
        let count = d.array()?.ok_or_else(bad)?;
        if count == 0 || count > 10_000 {
            return Err(bad());
        }
        for _ in 0..count {
            let exact_record = d.bytes()?;
            ea_cbor::validate(exact_record, PROTOCOL_PARSER_LIMITS_V1).map_err(|_| bad())?;
            if records.last().is_some_and(|previous: &Vec<u8>| {
                object_hash(previous) >= object_hash(exact_record)
            }) {
                return Err(bad());
            }
            records.push(exact_record.to_vec());
            let mut r = Decoder::new(exact_record);
            let length = r.array()?.ok_or_else(bad)?;
            let record_kind = r.u8()?;
            if length
                != match record_kind {
                    0 => 4,
                    1 => 6,
                    2 => 9,
                    _ => return Err(bad()),
                }
            {
                return Err(bad());
            }
            let cert = CertificateHash::try_from(r.bytes()?).map_err(|_| bad())?;
            let device = DeviceId::try_from(r.bytes()?).map_err(|_| bad())?;
            let kind = r.u8()?;
            if !matches!(kind, 0 | 1 | 6) {
                return Err(bad());
            }
            let known = execution
                .known_certificate_fields()
                .find(|(hash, _)| *hash == cert)
                .map(|(_, f)| f)
                .ok_or_else(bad)?;
            if known.device_id != device || known.certificate_kind as u8 != kind {
                return Err(bad());
            }
            if record_kind == 0 {
                if !replicas.insert((cert, device, kind)) {
                    return Err(bad());
                }
            } else {
                holders.push((cert, device, kind));
                if r.bytes()?.len() != 32 || r.bytes()?.len() != 32 {
                    return Err(bad());
                }
            }
            if record_kind == 2 {
                if r.bytes()?.len() != 32 {
                    return Err(bad());
                }
                let entry = r.bytes()?;
                if !targets.iter().any(|t| t.entry.as_bytes() == entry) || !matches!(r.u8()?, 1 | 2)
                {
                    return Err(bad());
                }
            }
            if r.position() != exact_record.len() {
                return Err(bad());
            }
        }
        if d.position() != exact.len() || holders.iter().any(|record| !replicas.contains(record)) {
            return Err(bad());
        }
        Ok(())
    })()
    .map_err(|_| Error::Format)?;
    let expected: BTreeSet<_> = execution
        .known_certificate_fields()
        .filter(|(_, c)| {
            matches!(
                c.certificate_kind,
                CertificateKindV1::Writer
                    | CertificateKindV1::Reader
                    | CertificateKindV1::ServerReceipt
            )
        })
        .map(|(hash, c)| (hash, c.device_id, c.certificate_kind as u8))
        .collect();
    if expected != replicas {
        return Err(Error::SecurityConflict);
    }
    Ok(replicas.into_iter().collect())
}
type InventoryParts = (Vec<ImportedPreflightTarget>, Vec<u8>, Vec<ObjectHash>);
fn decode_inventory(exact: &[u8]) -> Result<InventoryParts, Error> {
    ea_cbor::validate(exact, PROTOCOL_PARSER_LIMITS_V1).map_err(|_| Error::Format)?;
    let mut d = Decoder::new(exact);
    let mut targets = Vec::new();
    let mut removals = Vec::new();
    let mut paths = BTreeSet::new();
    (|| -> Result<_, minicbor::decode::Error> {
        if d.array()? != Some(4) || d.str()? != "EINSATZARCHIV-DESTRUCTION-JOB-INVENTORY-v1" {
            return Err(bad());
        }
        let custody = d.bytes()?.to_vec();
        let count = d.array()?.ok_or_else(bad)?;
        if count == 0 || count > 10_000 {
            return Err(bad());
        }
        for _ in 0..count {
            if d.array()? != Some(3) {
                return Err(bad());
            }
            let entry = EntryHash::try_from(d.bytes()?).map_err(|_| bad())?;
            let original = ObjectHash::try_from(d.bytes()?).map_err(|_| bad())?;
            let ParsedArchiveObject::Destroyed(stub) =
                decode_exact_object(d.bytes()?).map_err(|_| bad())?
            else {
                return Err(bad());
            };
            if targets
                .last()
                .is_some_and(|previous: &ImportedPreflightTarget| previous.entry >= entry)
            {
                return Err(bad());
            }
            let sequence = stub
                .value()
                .signed_manifest()
                .manifest()
                .fields()
                .chain_sequence;
            targets.push(ImportedPreflightTarget {
                entry,
                original,
                sequence,
                stub: stub.exact_bytes().clone(),
            });
        }
        let count = d.array()?.ok_or_else(bad)?;
        if count == 0 || count > 10_000 {
            return Err(bad());
        }
        for _ in 0..count {
            if d.array()? != Some(2) {
                return Err(bad());
            }
            let hash = ObjectHash::try_from(d.bytes()?).map_err(|_| bad())?;
            if removals.last().is_some_and(|previous| *previous >= hash) {
                return Err(bad());
            }
            removals.push(hash);
            let count = d.array()?.ok_or_else(bad)?;
            if count == 0 || count > 10_000 {
                return Err(bad());
            }
            let mut previous = None;
            for _ in 0..count {
                let path = d.str()?.to_owned();
                if previous.as_ref().is_some_and(|p| p >= &path)
                    || !paths.insert(path.clone())
                    || path.is_empty()
                    || path.as_bytes().contains(&0)
                {
                    return Err(bad());
                }
                previous = Some(path);
            }
        }
        if d.position() != exact.len() || targets.iter().any(|t| !removals.contains(&t.original)) {
            return Err(bad());
        }
        Ok((targets, custody, removals))
    })()
    .map_err(|_| Error::Format)
}
fn bad() -> minicbor::decode::Error {
    minicbor::decode::Error::message("invalid bound preflight")
}
