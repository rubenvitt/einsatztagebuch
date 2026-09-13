//! Exact full pre-state verification and a typed internal component signature.
//! Preparing this value performs no removal and proves no durable write.
use crate::{
    DestructionError as Error, DurableManagedInventory, ResumedDestruction,
    VerifiedDestructionTarget, build_stub,
};
use ea_archive::{
    ArchiveBlob, ArchiveError, ArchiveInventory, ArchiveSource, MAX_ARCHIVE_BLOBS_V1,
    MAX_TOTAL_ARCHIVE_BYTES_V1,
};
use ea_crypto::{CoseSigner, VerificationContext, object_hash, verify_cose_sign1};
use ea_format::{CertificateKindV1, ExactObjectBytes};
use ea_trust::TrustAnchorV1;
use ea_types::{CertificateHash, EntryHash, ObjectHash};
use minicbor::{Decoder, Encoder};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct PlannedTarget {
    pub entry: EntryHash,
    pub original: ObjectHash,
    pub stub: ExactObjectBytes,
}
pub struct SignedDestructionPreflight {
    pub(crate) targets: Vec<PlannedTarget>,
    pub(crate) removals: Vec<(ObjectHash, Vec<String>)>,
    pub(crate) hashes: Vec<ObjectHash>,
    pub(crate) report: String,
    pub(crate) inventory: Vec<u8>,
    pub(crate) core: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) certificate: CertificateHash,
}
impl SignedDestructionPreflight {
    pub const fn certificate_hash(&self) -> CertificateHash {
        self.certificate
    }
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
    pub fn removal_object_hashes(&self) -> &[ObjectHash] {
        &self.hashes
    }
    pub fn report_json(&self) -> &str {
        &self.report
    }
    pub fn exact_inventory_bytes(&self) -> &[u8] {
        &self.inventory
    }
    pub fn exact_core_bytes(&self) -> &[u8] {
        &self.core
    }
    pub fn exact_signature_bytes(&self) -> &[u8] {
        &self.signature
    }
}

pub fn prepare_preflight(
    resumed: &ResumedDestruction<'_>,
    custody: &DurableManagedInventory,
    source: &dyn ArchiveSource,
    anchor: &TrustAnchorV1,
    certificate: CertificateHash,
    signer: &CoseSigner,
) -> Result<SignedDestructionPreflight, Error> {
    check_authority(resumed, custody, certificate)?;
    let auth = resumed.request().authorization();
    if anchor.organization_id() != auth.fields().organization_id
        || anchor.chain_id() != resumed.current_head().chain_id()
    {
        return Err(Error::Registry);
    }
    // One bounded captured byte set feeds all checks; a changing source cannot
    // substitute target bytes between the report and the exact removal plan.
    let captured = Captured::read(source)?;
    let report = ea_verify::verify_archive(
        &captured,
        anchor,
        ea_verify::VerifyOptions::new(resumed.current_head().preexisting_effective_now().value()),
    )
    .map_err(|_| Error::Target)?;
    if !report.is_fully_verified() {
        return Err(Error::Target);
    }
    let archive = ArchiveInventory::build(&captured).map_err(|_| Error::Target)?;
    let mut targets = Vec::new();
    let mut removal_hashes = BTreeSet::new();
    for target in &auth.fields().targets {
        let entry = archive
            .entries()
            .iter()
            .find(|entry| entry.value().entry_hash().as_bytes() == target.entry_hash())
            .ok_or(Error::Target)?;
        let proof = VerifiedDestructionTarget::from_preflight(auth, entry, &report)?;
        let stub = build_stub(entry, auth, &proof)?;
        targets.push(PlannedTarget {
            entry: entry.value().entry_hash(),
            original: entry.object_hash(),
            stub,
        });
        removal_hashes.insert(entry.object_hash());
        for grant in archive.grants().iter().filter(|grant| {
            grant.value().grant_body().fields().entry_hash == entry.value().entry_hash()
        }) {
            removal_hashes.insert(grant.object_hash());
        }
    }
    let mut paths: BTreeMap<ObjectHash, Vec<String>> = BTreeMap::new();
    for (path, bytes) in &captured.blobs {
        let hash = object_hash(bytes);
        if removal_hashes.contains(&hash) {
            paths.entry(hash).or_default().push(path.clone());
        }
    }
    let removals: Vec<_> = paths.into_iter().collect();
    if removals.len() != removal_hashes.len() {
        return Err(Error::Target);
    }
    let inventory = encode_inventory(custody, &targets, &removals)?;
    let report = report.to_canonical_json().map_err(|_| Error::Format)?;
    let core = encode_core(resumed, &inventory, &report)?;
    let signature = signer.sign_destruction_preflight_report(certificate, &core)?;
    let result = SignedDestructionPreflight {
        targets,
        removals,
        hashes: removal_hashes.into_iter().collect(),
        report,
        inventory,
        core,
        signature,
        certificate,
    };
    verify_preflight(&result, resumed, custody)?;
    Ok(result)
}

/// Check the newly prepared same-invocation proof. Historical restart verifies
/// its saved execution context separately and still requires fresh native
/// authority. This helper deliberately does not mint a durability capability.
pub fn verify_preflight(
    preflight: &SignedDestructionPreflight,
    resumed: &ResumedDestruction<'_>,
    custody: &DurableManagedInventory,
) -> Result<(), Error> {
    check_authority(resumed, custody, preflight.certificate)?;
    if preflight.inventory != encode_inventory(custody, &preflight.targets, &preflight.removals)?
        || preflight.core != encode_core(resumed, &preflight.inventory, &preflight.report)?
    {
        return Err(Error::SecurityConflict);
    }
    let context =
        VerificationContext::destruction_preflight_report(&preflight.core, preflight.certificate)?;
    verify_cose_sign1(&preflight.signature, resumed.current_head(), &context)?;
    Ok(())
}

pub(crate) fn check_authority(
    resumed: &ResumedDestruction<'_>,
    custody: &DurableManagedInventory,
    certificate: CertificateHash,
) -> Result<(), Error> {
    check_original_authority(resumed, custody, certificate)?;
    let fields = resumed
        .current_head()
        .active_certificate_fields(certificate)
        .ok_or(Error::Signature)?;
    if fields.certificate_kind != CertificateKindV1::DeletionAttest
        || !fields.capabilities.iter().any(|c| c == "deletionAttest")
    {
        return Err(Error::Signature);
    }
    Ok(())
}
/// Archival report attribution only. Current action authority is checked
/// separately on the component that actually performs the new action.
pub(crate) fn check_original_authority(
    resumed: &ResumedDestruction<'_>,
    custody: &DurableManagedInventory,
    certificate: CertificateHash,
) -> Result<(), Error> {
    let auth = resumed.request().authorization();
    let mut d = Decoder::new(custody.exact_bytes());
    let bound = (|| -> Result<bool, minicbor::decode::Error> {
        Ok(d.array()? == Some(6)
            && d.str()? == "EINSATZARCHIV-MANAGED-CUSTODY-v1"
            && d.bytes()? == auth.fields().organization_id.as_bytes()
            && d.bytes()? == auth.fields().destruction_id.as_bytes()
            && d.bytes()? == auth.object_hash().as_bytes()
            && d.bytes()? == resumed.current_head().chain_id().as_bytes())
    })()
    .map_err(|_| Error::Format)?;
    if !bound {
        return Err(Error::SecurityConflict);
    }
    let fields = resumed
        .authorization_head()
        .active_certificate_fields(certificate)
        .ok_or(Error::Signature)?;
    if fields.certificate_kind != CertificateKindV1::DeletionAttest
        || !fields.capabilities.iter().any(|c| c == "deletionAttest")
    {
        return Err(Error::Signature);
    }
    Ok(())
}
pub(crate) fn encode_inventory(
    custody: &DurableManagedInventory,
    targets: &[PlannedTarget],
    removals: &[(ObjectHash, Vec<String>)],
) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    let mut e = Encoder::new(&mut bytes);
    e.array(4)
        .map_err(|_| Error::Format)?
        .str("EINSATZARCHIV-DESTRUCTION-JOB-INVENTORY-v1")
        .map_err(|_| Error::Format)?;
    e.bytes(custody.exact_bytes())
        .map_err(|_| Error::Format)?
        .array(targets.len() as u64)
        .map_err(|_| Error::Format)?;
    for target in targets {
        e.array(3)
            .map_err(|_| Error::Format)?
            .bytes(target.entry.as_bytes())
            .map_err(|_| Error::Format)?
            .bytes(target.original.as_bytes())
            .map_err(|_| Error::Format)?
            .bytes(target.stub.as_bytes())
            .map_err(|_| Error::Format)?;
    }
    e.array(removals.len() as u64).map_err(|_| Error::Format)?;
    for (hash, paths) in removals {
        e.array(2)
            .map_err(|_| Error::Format)?
            .bytes(hash.as_bytes())
            .map_err(|_| Error::Format)?
            .array(paths.len() as u64)
            .map_err(|_| Error::Format)?;
        for path in paths {
            e.str(path).map_err(|_| Error::Format)?;
        }
    }
    Ok(bytes)
}
fn encode_core(
    resumed: &ResumedDestruction<'_>,
    inventory: &[u8],
    report: &str,
) -> Result<Vec<u8>, Error> {
    let fields = resumed.request().authorization().fields();
    let current = resumed.current_head();
    let mut bytes = Vec::new();
    let mut e = Encoder::new(&mut bytes);
    e.array(16)
        .map_err(|_| Error::Format)?
        .str("EINSATZARCHIV-DESTRUCTION-PREFLIGHT-v1")
        .map_err(|_| Error::Format)?
        .u8(1)
        .map_err(|_| Error::Format)?;
    for field in [
        fields.organization_id.as_bytes().as_slice(),
        current.chain_id().as_bytes(),
        fields.destruction_id.as_bytes(),
        resumed.request().authorization().object_hash().as_bytes(),
        object_hash(inventory).as_bytes(),
        object_hash(report.as_bytes()).as_bytes(),
        report.as_bytes(),
    ] {
        e.bytes(field).map_err(|_| Error::Format)?;
    }
    e.u64(fields.registry_version.get())
        .map_err(|_| Error::Format)?
        .bytes(fields.registry_head_hash.as_bytes())
        .map_err(|_| Error::Format)?
        .u64(fields.authorization_sequence)
        .map_err(|_| Error::Format)?
        .u64(current.registry_version().get())
        .map_err(|_| Error::Format)?
        .bytes(current.registry_head_hash().as_bytes())
        .map_err(|_| Error::Format)?
        .u64(current.proposed_sequence().get())
        .map_err(|_| Error::Format)?
        .i64(current.preexisting_effective_now().value().get())
        .map_err(|_| Error::Format)?;
    Ok(bytes)
}
struct Captured {
    blobs: Vec<(String, Vec<u8>)>,
}
impl Captured {
    fn read(source: &dyn ArchiveSource) -> Result<Self, Error> {
        let mut blobs = BTreeMap::new();
        let mut total = 0usize;
        source
            .visit_blobs(&mut |blob| {
                total = total
                    .checked_add(blob.bytes().len())
                    .ok_or(ArchiveError::Unavailable)?;
                if blobs.len() >= MAX_ARCHIVE_BLOBS_V1
                    || total > MAX_TOTAL_ARCHIVE_BYTES_V1
                    || blobs
                        .insert(blob.path_hint().to_owned(), blob.bytes().to_vec())
                        .is_some()
                {
                    return Err(ArchiveError::Unavailable);
                }
                Ok(())
            })
            .map_err(|_| Error::Storage)?;
        Ok(Self {
            blobs: blobs.into_iter().collect(),
        })
    }
}
impl ArchiveSource for Captured {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for (path, bytes) in &self.blobs {
            visitor(ArchiveBlob::new(path, bytes))?;
        }
        Ok(())
    }
}
