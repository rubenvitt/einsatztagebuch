//! Immutable signed pre-state. Persistence is not removal authority.
use crate::{
    DestructionError as Error, DurableManagedInventory, ResumedDestruction,
    SignedDestructionPreflight, verify_preflight,
};
use ea_crypto::{
    VerificationContext, decode_destruction_preflight_core, object_hash, verify_cose_sign1,
};
use ea_format::{ParsedArchiveObject, decode_exact_object};
use ea_local_store::{EncryptedDatabase, StoreRow, StoreValue};
use ea_trust::{VerifiedTrust, verify_historical_registry_authority};
use ea_types::{CertificateHash, ChainSequence, EntryHash, ObjectHash, RegistryVersion};
use minicbor::Decoder;
use std::{collections::BTreeSet, sync::Arc};

const READ: &str = "SELECT authorization_hash,signer_certificate_hash,exact_inventory,exact_core,exact_signature FROM destruction_job WHERE organization_id=?1 AND destruction_id=?2";
pub struct SqliteDestructionJobs {
    pub(crate) database: Arc<EncryptedDatabase>,
}
/// Only minted after an immutable FULL-sync commit and authenticated re-read.
/// Fresh action admission and a real delivery barrier remain separate checks.
pub struct DurableDestructionJob {
    preflight: SignedDestructionPreflight,
}
impl DurableDestructionJob {
    pub fn preflight(&self) -> &SignedDestructionPreflight {
        &self.preflight
    }
}
impl SqliteDestructionJobs {
    pub fn new(database: Arc<EncryptedDatabase>) -> Self {
        Self { database }
    }

    pub fn persist(
        &self,
        preflight: &SignedDestructionPreflight,
        resumed: &ResumedDestruction<'_>,
        custody: &DurableManagedInventory,
        trust: &VerifiedTrust,
    ) -> Result<DurableDestructionJob, Error> {
        self.persist_guarded(
            preflight,
            resumed,
            custody,
            trust,
            &mut crate::local::NoAdditionalAuthorityGuard,
        )
    }
    pub fn persist_guarded(
        &self,
        preflight: &SignedDestructionPreflight,
        resumed: &ResumedDestruction<'_>,
        custody: &DurableManagedInventory,
        trust: &VerifiedTrust,
        guard: &mut dyn crate::LocalActionAuthorityGuard,
    ) -> Result<DurableDestructionJob, Error> {
        verify_preflight(preflight, resumed, custody)?;
        let auth = resumed.request().authorization();
        self.database.transaction(|tx| {
            guard.check_in(tx)?;
            crate::inventory::require_durable(tx)?;
            crate::inventory::require_unchanged_in(tx, custody)?;
            if let Some(row) = tx.query_row(READ, &key(resumed))? {
                if row.blob(0)? != auth.object_hash().as_bytes()
                    || row.blob(1)? != preflight.certificate.as_bytes()
                    || row.blob(2)? != preflight.inventory
                    || row.blob(3)? != preflight.core
                    || row.blob(4)? != preflight.signature {
                    return Err(Error::SecurityConflict);
                }
            } else {
                tx.execute("INSERT INTO destruction_job(organization_id,destruction_id,authorization_hash,signer_certificate_hash,exact_inventory,exact_core,exact_signature) VALUES(?1,?2,?3,?4,?5,?6,?7)", &[
                    blob(auth.fields().organization_id.as_bytes()), blob(auth.fields().destruction_id.as_bytes()),
                    blob(auth.object_hash().as_bytes()), blob(preflight.certificate.as_bytes()),
                    blob(&preflight.inventory), blob(&preflight.core), blob(&preflight.signature),
                ])?;
            }
            Ok::<_,Error>(())
        })?;
        // Outside the completed transaction: no durability capability escapes
        // if the committed exact bytes cannot be re-read and authenticated.
        self.load(resumed, custody, trust)?.ok_or(Error::Storage)
    }

    /// Reconstruct the authentic old pre-state without already removed EIPs.
    /// `resumed` supplies fresh current native authority; `trust` only supplies
    /// archival signature reconstruction for the stored execution head.
    pub fn load(
        &self,
        resumed: &ResumedDestruction<'_>,
        custody: &DurableManagedInventory,
        trust: &VerifiedTrust,
    ) -> Result<Option<DurableDestructionJob>, Error> {
        self.database.transaction(|tx| {
            crate::inventory::require_durable(tx)?;
            crate::inventory::require_unchanged_in(tx, custody)?;
            tx.query_row(READ, &key(resumed))?
                .map(|row| restore(row, resumed, custody, trust))
                .transpose()
        })
    }
}

fn restore(
    row: StoreRow,
    resumed: &ResumedDestruction<'_>,
    custody: &DurableManagedInventory,
    trust: &VerifiedTrust,
) -> Result<DurableDestructionJob, Error> {
    let auth = resumed.request().authorization();
    if row.blob(0)? != auth.object_hash().as_bytes() {
        return Err(Error::SecurityConflict);
    }
    let certificate = CertificateHash::try_from(row.blob(1)?).map_err(|_| Error::Format)?;
    crate::preflight::check_original_authority(resumed, custody, certificate)?;
    let inventory = row.blob(2)?.to_vec();
    let core = row.blob(3)?.to_vec();
    let signature = row.blob(4)?.to_vec();
    let parsed = decode_destruction_preflight_core(&core)?;
    let fields = auth.fields();
    if parsed.organization_id != *fields.organization_id.as_bytes()
        || parsed.chain_id != *resumed.current_head().chain_id().as_bytes()
        || parsed.destruction_id != *fields.destruction_id.as_bytes()
        || parsed.authorization_hash != *auth.object_hash().as_bytes()
        || parsed.inventory_hash != *object_hash(&inventory).as_bytes()
        || parsed.authorization_registry != fields.registry_version.get()
        || parsed.authorization_head
            != *resumed.authorization_head().registry_head_hash().as_bytes()
        || parsed.authorization_sequence != fields.authorization_sequence
        || parsed.execution_registry > resumed.current_head().registry_version().get()
        || parsed.execution_sequence > resumed.current_head().proposed_sequence().get()
        || parsed.observed_effective_now
            > resumed
                .current_head()
                .preexisting_effective_now()
                .value()
                .get()
    {
        return Err(Error::SecurityConflict);
    }
    let historical = verify_historical_registry_authority(
        trust,
        RegistryVersion::new(parsed.execution_registry),
        ObjectHash::try_from(parsed.execution_head.as_slice()).map_err(|_| Error::Format)?,
        ChainSequence::new(parsed.execution_sequence),
    )
    .map_err(|_| Error::Registry)?;
    let context = VerificationContext::destruction_preflight_report(&core, certificate)?;
    verify_cose_sign1(&signature, &historical, &context)?;
    let report = std::str::from_utf8(parsed.report_json)
        .map_err(|_| Error::Format)?
        .to_owned();
    let (targets, removals) = decode_inventory(&inventory, resumed, custody)?;
    let report_targets = targets
        .iter()
        .map(|target| {
            let authorized = auth
                .fields()
                .targets
                .iter()
                .find(|value| value.entry_hash() == target.entry.as_bytes())
                .ok_or(Error::Target)?;
            Ok((
                target.entry,
                ChainSequence::new(authorized.chain_sequence()),
                target.original,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    ea_verify::verify_destruction_preflight_report(
        report.as_bytes(),
        resumed.current_head().chain_id(),
        &report_targets,
    )
    .map_err(|_| Error::Target)?;
    let preflight = SignedDestructionPreflight {
        hashes: removals.iter().map(|(h, _)| *h).collect(),
        targets,
        removals,
        inventory,
        core,
        signature,
        report,
        certificate,
    };
    Ok(DurableDestructionJob { preflight })
}

type RemovalPlan = Vec<(ObjectHash, Vec<String>)>;
fn decode_inventory(
    exact: &[u8],
    resumed: &ResumedDestruction<'_>,
    custody: &DurableManagedInventory,
) -> Result<(Vec<crate::preflight::PlannedTarget>, RemovalPlan), Error> {
    let auth = resumed.request().authorization();
    let mut d = Decoder::new(exact);
    let mut targets = Vec::new();
    let mut removals = Vec::new();
    let mut entries = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let mut all_paths = BTreeSet::new();
    (|| -> Result<(), minicbor::decode::Error> {
        let invalid = || minicbor::decode::Error::message("invalid job inventory");
        if d.array()? != Some(4)
            || d.str()? != "EINSATZARCHIV-DESTRUCTION-JOB-INVENTORY-v1"
            || d.bytes()? != custody.exact_bytes()
        {
            return Err(invalid());
        }
        let count = d.array()?.ok_or_else(invalid)?;
        if count as usize != auth.fields().targets.len() {
            return Err(invalid());
        }
        for _ in 0..count {
            if d.array()? != Some(3) {
                return Err(invalid());
            }
            let entry = EntryHash::try_from(d.bytes()?).map_err(|_| invalid())?;
            let original = ObjectHash::try_from(d.bytes()?).map_err(|_| invalid())?;
            let stub_bytes = d.bytes()?;
            let ParsedArchiveObject::Destroyed(stub) =
                decode_exact_object(stub_bytes).map_err(|_| invalid())?
            else {
                return Err(invalid());
            };
            if !entries.insert(entry)
                || stub.value().entry_hash() != entry
                || stub.value().original_eip_object_hash() != original
                || stub.value().destruction_id() != auth.fields().destruction_id
                || stub.value().destruction_authorization_object_hash() != auth.object_hash()
                || !auth.fields().targets.iter().any(|t| {
                    t.entry_hash() == entry.as_bytes()
                        && t.chain_sequence()
                            == stub
                                .value()
                                .signed_manifest()
                                .manifest()
                                .fields()
                                .chain_sequence
                                .get()
                })
            {
                return Err(invalid());
            }
            targets.push(crate::preflight::PlannedTarget {
                entry,
                original,
                stub: stub.exact_bytes().clone(),
            });
        }
        let count = d.array()?.ok_or_else(invalid)?;
        if count == 0 || count > ea_archive::MAX_ARCHIVE_BLOBS_V1 as u64 {
            return Err(invalid());
        }
        for _ in 0..count {
            if d.array()? != Some(2) {
                return Err(invalid());
            }
            let hash = ObjectHash::try_from(d.bytes()?).map_err(|_| invalid())?;
            if !hashes.insert(hash) {
                return Err(invalid());
            }
            let count = d.array()?.ok_or_else(invalid)?;
            if count == 0 || count > ea_archive::MAX_ARCHIVE_BLOBS_V1 as u64 {
                return Err(invalid());
            }
            let mut paths = Vec::new();
            for _ in 0..count {
                let path = d.str()?.to_owned();
                if !all_paths.insert(path.clone()) {
                    return Err(invalid());
                }
                paths.push(path);
            }
            removals.push((hash, paths));
        }
        if d.position() != exact.len() || targets.iter().any(|t| !hashes.contains(&t.original)) {
            return Err(invalid());
        }
        Ok(())
    })()
    .map_err(|_| Error::Format)?;
    if crate::preflight::encode_inventory(custody, &targets, &removals)? != exact {
        return Err(Error::Format);
    }
    Ok((targets, removals))
}
fn key(resumed: &ResumedDestruction<'_>) -> [StoreValue; 2] {
    let f = resumed.request().authorization().fields();
    [
        blob(f.organization_id.as_bytes()),
        blob(f.destruction_id.as_bytes()),
    ]
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
