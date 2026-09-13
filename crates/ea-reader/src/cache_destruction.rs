//! Durable cache removal journal: deny replay before the first deletion,
//! then measure the whole managed namespace and reread the encrypted receipt.
use crate::{
    ReaderBlobKey, ReaderBlobStore, ReaderObjectCache, ReaderVaultError as Error, UnlockedVault,
    VerifiedReaderDestructionInstruction,
};
use ea_crypto::{
    AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes, SecretVec, aead_open, aead_seal, object_hash,
};
use ea_types::{DeviceId, EntryHash, ObjectHash};
use std::collections::BTreeSet;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Job {
    pub(crate) hash: ObjectHash,
    pub(crate) replica: DeviceId,
    pub(crate) targets: Vec<EntryHash>,
    pub(crate) instruction: Vec<u8>,
    pub(crate) removed: Vec<ObjectHash>,
    pub(crate) complete: bool,
}
pub struct ReaderCacheRemovalReceipt {
    job: ObjectHash,
    replica: DeviceId,
    removed: Vec<ObjectHash>,
}
impl ReaderCacheRemovalReceipt {
    pub fn job_hash(&self) -> ObjectHash {
        self.job
    }
    pub fn replica_id(&self) -> DeviceId {
        self.replica
    }
    pub fn removed_object_hashes(&self) -> &[ObjectHash] {
        &self.removed
    }
    /// No local encrypted holdings remain; this is not a v1 attestation.
    pub fn remaining_object_count(&self) -> usize {
        0
    }
}
pub struct ReaderCacheDestruction;
impl ReaderCacheDestruction {
    pub fn prepare(
        vault: &UnlockedVault,
        store: &mut dyn ReaderBlobStore,
        source: &dyn ea_archive::ArchiveSource,
        input: crate::ReaderDestructionInstructionBytes<'_>,
        now: ea_types::UnixMillis,
    ) -> Result<VerifiedReaderDestructionInstruction, &'static str> {
        crate::destruction_authority::prepare(vault, store, source, input, now)
    }
    pub fn authority_key(vault: &UnlockedVault) -> Result<ReaderBlobKey, Error> {
        Ok(ReaderBlobKey::new(&format!(
            "destruction-authority/v1/{}",
            hex::encode(vault.kem_key_thumbprint().as_bytes())
        ))?)
    }
    pub fn observed_authority_time(
        vault: &UnlockedVault,
        store: &dyn ReaderBlobStore,
    ) -> Result<ea_types::UnixMillis, &'static str> {
        crate::destruction_authority::observed_time(vault, store)
    }

    pub fn journal_key() -> Result<ReaderBlobKey, Error> {
        Ok(ReaderBlobKey::new("destruction/v1")?)
    }
    pub fn execute(
        vault: &UnlockedVault,
        store: &mut dyn ReaderBlobStore,
        instruction: &VerifiedReaderDestructionInstruction,
        source: impl ea_archive::ArchiveSource,
        now: ea_types::UnixMillis,
    ) -> Result<ReaderCacheRemovalReceipt, Error> {
        // Preparation is not a durable action capability. Recheck the exact
        // signed instruction against current source/cache, persistent pin/time
        // and this vault's monotone observations immediately before removal.
        let current = Self::prepare(
            vault,
            store,
            &source,
            instruction.input().map_err(|_| Error::Contents)?,
            now,
        )
        .map_err(|_| Error::Contents)?;
        drop(source);
        let instruction = &current;
        if !store.inventory_is_complete() || vault.kem_key_thumbprint() != instruction.reader {
            return Err(Error::Contents);
        }
        crate::destruction_authority::affirm_execution(vault, store, instruction)
            .map_err(|_| Error::Contents)?;
        let key = vault.cache_key()?;
        let mut jobs = read(store, &key)?;
        let targets: Vec<_> = instruction
            .targets
            .iter()
            .map(|(entry, _)| *entry)
            .collect();
        let observed = holdings(vault, store, &targets)?;
        let derived = secondary_keys(store, &targets)?;
        // A known original must match the signed pre-state object identity.
        for (hash, entry, is_entry) in &observed {
            if *is_entry
                && instruction
                    .targets
                    .iter()
                    .find(|(target, _)| target == entry)
                    .is_none_or(|(_, original)| original != hash)
            {
                return Err(Error::Contents);
            }
        }
        let index = match jobs.iter().position(|job| job.hash == instruction.job) {
            Some(index) => {
                if jobs[index].instruction != instruction.exact_instruction
                    || jobs[index].replica != instruction.replica
                    || jobs[index].targets != targets
                {
                    return Err(Error::Contents);
                }
                index
            }
            None => {
                jobs.push(Job {
                    hash: instruction.job,
                    replica: instruction.replica,
                    targets,
                    instruction: instruction.exact_instruction.clone(),
                    removed: Vec::new(),
                    complete: false,
                });
                jobs.len() - 1
            }
        };
        let mut all: BTreeSet<_> = jobs[index].removed.iter().copied().collect();
        all.extend(observed.iter().map(|(hash, _, _)| *hash));
        jobs[index].removed = all.into_iter().collect();
        jobs[index].complete = false;
        // Exact instruction + every observed holding survive any later crash.
        // A failed flush/reread performs no removal and releases no receipt.
        write(store, &key, &jobs)?;
        if read(store, &key)? != jobs {
            return Err(Error::Contents);
        }
        for (hash, _, _) in observed {
            store.delete(&crate::cache::cache_key(hash)?)?;
        }
        for key in derived {
            store.delete(&key)?;
        }
        if !holdings(vault, store, &jobs[index].targets)?.is_empty()
            || !secondary_keys(store, &jobs[index].targets)?.is_empty()
        {
            return Err(Error::Contents);
        }
        jobs[index].complete = true;
        write(store, &key, &jobs)?;
        Self::receipt(vault, store, instruction.job)?.ok_or(Error::Contents)
    }
    pub fn receipt(
        vault: &UnlockedVault,
        store: &dyn ReaderBlobStore,
        hash: ObjectHash,
    ) -> Result<Option<ReaderCacheRemovalReceipt>, Error> {
        if !store.inventory_is_complete() {
            return Err(Error::Contents);
        }
        let jobs = read(store, &vault.cache_key()?)?;
        let Some(job) = jobs
            .into_iter()
            .find(|job| job.hash == hash && job.complete)
        else {
            return Ok(None);
        };
        if !holdings(vault, store, &job.targets)?.is_empty()
            || !secondary_keys(store, &job.targets)?.is_empty()
        {
            return Err(Error::Contents);
        }
        Ok(Some(ReaderCacheRemovalReceipt {
            job: hash,
            replica: job.replica,
            removed: job.removed,
        }))
    }
}
pub(crate) fn secondary_keys(
    store: &dyn ReaderBlobStore,
    targets: &[EntryHash],
) -> Result<Vec<ReaderBlobKey>, Error> {
    let states: BTreeSet<_> = targets
        .iter()
        .map(|hash| format!("entry-state/{}", hex::encode(hash.as_bytes())))
        .collect();
    let mut remove = Vec::new();
    for key in store.keys()? {
        if store.get(&key)?.is_none() {
            continue;
        }
        let name = key.as_str();
        if states.contains(name)
            || name.starts_with("index/")
            || name.starts_with("search/")
            || name.starts_with("profile/")
        {
            remove.push(key);
        } else if !(crate::cache::object_hash_of(&key).is_some()
            || name.starts_with("entry-state/")
            || matches!(
                name,
                "destruction/v1"
                    | "vault/reader-vault-v1"
                    | "sync/cursor-v1"
                    | "sync/objects-v1"
                    | "audit-log"
                    | "trust-state/v1"
            )
            || name.starts_with("grant-time/v1/")
            || name.starts_with("destruction-authority/v1/")
            || crate::reader_attestation::is_attestation_key(&key))
        {
            // Unknown contents have no justified exclusion from local scope.
            return Err(Error::Contents);
        }
    }
    Ok(remove)
}
fn target(bytes: &[u8]) -> Option<(EntryHash, bool)> {
    match ea_format::decode_exact_object(bytes).ok()? {
        ea_format::ParsedArchiveObject::Entry(entry) => Some((entry.value().entry_hash(), true)),
        ea_format::ParsedArchiveObject::Grant(grant) => {
            Some((grant.value().grant_body().fields().entry_hash, false))
        }
        _ => None,
    }
}
pub(crate) fn holdings(
    vault: &UnlockedVault,
    store: &dyn ReaderBlobStore,
    targets: &[EntryHash],
) -> Result<Vec<(ObjectHash, EntryHash, bool)>, Error> {
    let cache = ReaderObjectCache::open(vault);
    let mut matches = Vec::new();
    for key in store.keys()? {
        let Some(hash) = crate::cache::object_hash_of(&key) else {
            continue;
        };
        let Some(bytes) = cache.get_unfiltered(store, hash)? else {
            continue;
        };
        if object_hash(&bytes) != hash || ea_format::decode_exact_object(&bytes).is_err() {
            return Err(Error::Contents);
        }
        if let Some((entry, is_entry)) = target(&bytes)
            && targets.contains(&entry)
        {
            matches.push((hash, entry, is_entry));
        }
    }
    Ok(matches)
}
pub(crate) fn denied(
    store: &dyn ReaderBlobStore,
    key: &SecretBytes<CEK_SIZE>,
    bytes: &[u8],
) -> Result<bool, Error> {
    let Some((entry, _)) = target(bytes) else {
        return Ok(false);
    };
    Ok(read(store, key)?
        .iter()
        .any(|job| job.targets.contains(&entry)))
}
fn encode(jobs: &[Job]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut e = minicbor::Encoder::new(&mut bytes);
    e.array(2)
        .unwrap()
        .str("EINSATZARCHIV-READER-REMOVAL-v1")
        .unwrap()
        .array(jobs.len() as u64)
        .unwrap();
    for job in jobs {
        e.array(6)
            .unwrap()
            .bytes(job.hash.as_bytes())
            .unwrap()
            .bytes(job.replica.as_bytes())
            .unwrap()
            .array(job.targets.len() as u64)
            .unwrap();
        for hash in &job.targets {
            e.bytes(hash.as_bytes()).unwrap();
        }
        e.bytes(&job.instruction)
            .unwrap()
            .array(job.removed.len() as u64)
            .unwrap();
        for hash in &job.removed {
            e.bytes(hash.as_bytes()).unwrap();
        }
        e.bool(job.complete).unwrap();
    }
    bytes
}
fn decode(bytes: &[u8]) -> Result<Vec<Job>, Error> {
    ea_cbor::validate(bytes, ea_cbor::ParserLimits::V1).map_err(|_| Error::Contents)?;
    let result = (|| -> Result<_, minicbor::decode::Error> {
        let mut d = minicbor::Decoder::new(bytes);
        let bad = || minicbor::decode::Error::message("invalid removal journal");
        if d.array()? != Some(2) || d.str()? != "EINSATZARCHIV-READER-REMOVAL-v1" {
            return Err(bad());
        }
        let mut jobs = Vec::new();
        for _ in 0..d.array()?.ok_or_else(bad)? {
            if d.array()? != Some(6) {
                return Err(bad());
            }
            let hash = ObjectHash::try_from(d.bytes()?).map_err(|_| bad())?;
            let replica = DeviceId::try_from(d.bytes()?).map_err(|_| bad())?;
            let mut targets = Vec::new();
            for _ in 0..d.array()?.ok_or_else(bad)? {
                targets.push(EntryHash::try_from(d.bytes()?).map_err(|_| bad())?);
            }
            let instruction = d.bytes()?.to_vec();
            let mut removed = Vec::new();
            for _ in 0..d.array()?.ok_or_else(bad)? {
                removed.push(ObjectHash::try_from(d.bytes()?).map_err(|_| bad())?);
            }
            let complete = d.bool()?;
            jobs.push(Job {
                hash,
                replica,
                targets,
                instruction,
                removed,
                complete,
            });
        }
        if d.position() != bytes.len() {
            return Err(bad());
        }
        Ok(jobs)
    })()
    .map_err(|_| Error::Contents)?;
    if encode(&result) != bytes {
        return Err(Error::Contents);
    }
    Ok(result)
}
pub(crate) fn read(
    store: &dyn ReaderBlobStore,
    key: &SecretBytes<CEK_SIZE>,
) -> Result<Vec<Job>, Error> {
    let address = ReaderCacheDestruction::journal_key()?;
    let Some(bytes) = store.get(&address)? else {
        return Ok(Vec::new());
    };
    if bytes.len() < AEAD_NONCE_SIZE {
        return Err(Error::Contents);
    }
    let (nonce, ciphertext) = bytes.split_at(AEAD_NONCE_SIZE);
    let nonce = nonce.try_into().map_err(|_| Error::Contents)?;
    let plaintext = aead_open(
        key,
        &SecretBytes::new(nonce),
        ciphertext,
        &crate::envelope::blob_aad(address.as_str().as_bytes()),
    )?;
    plaintext.with_exposed(decode)
}
fn write(
    store: &mut dyn ReaderBlobStore,
    key: &SecretBytes<CEK_SIZE>,
    jobs: &[Job],
) -> Result<(), Error> {
    let address = ReaderCacheDestruction::journal_key()?;
    let mut nonce = [0; AEAD_NONCE_SIZE];
    getrandom::fill(&mut nonce).map_err(|_| Error::Crypto(ea_crypto::CryptoError::LocalRng))?;
    let ciphertext = aead_seal(
        key,
        &SecretBytes::new(nonce),
        SecretVec::new(encode(jobs)),
        &crate::envelope::blob_aad(address.as_str().as_bytes()),
    )?;
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(&ciphertext);
    store.put(&address, &bytes)?;
    Ok(())
}
