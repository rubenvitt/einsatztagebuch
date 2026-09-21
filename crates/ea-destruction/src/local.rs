//! Actual registered local archive cleanup; measurements never claim global completion.
use crate::{
    DestructionError as Error, DestructionExecutionContext, DestructionRequestService,
    DurableDestructionStart, SqliteDestructionJobs,
};
use ea_archive::{ArchiveBackend, ArchivePath, DESTROYED_ENTRIES_DIR_V1, LAYOUT_PATHS_V1};
use ea_archive_fs::LocalPathBackend;
use ea_crypto::{CoseSigner, VerificationContext, object_hash, verify_cose_sign1};
use ea_format::{ParsedArchiveObject, decode_exact_object};
use ea_local_store::StoreValue;
use ea_operator::OperatorSessionProof;
use ea_types::{CertificateHash, DeviceId, EntryHash, ObjectHash};
use minicbor::{Decoder, Encoder};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
pub struct LocalDestructionExecution<'a> {
    pub backend: &'a LocalPathBackend,
    pub custody_certificate: CertificateHash,
    pub component_certificate: CertificateHash,
    pub signer: &'a CoseSigner,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalDestructionCheckpoint {
    BeforeStubCreate,
    StubCreated,
    StubFileFlushed,
    StubDirectoryFlushed,
    StubVerified,
    BeforeRemove,
    Removed,
    FinalScan,
    MeasurementCommitted,
}
/// Authenticated immutable job + observed local absence, durably recorded and
/// re-read. Other archives, SQL acquisition sources and backups remain separate.
pub struct MeasuredLocalRemoval {
    exact: Vec<u8>,
    removed: Vec<ObjectHash>,
    job: ObjectHash,
    location: ObjectHash,
    device: DeviceId,
}
impl MeasuredLocalRemoval {
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub fn removed_object_hashes(&self) -> &[ObjectHash] {
        &self.removed
    }
    pub const fn job_hash(&self) -> ObjectHash {
        self.job
    }
    pub const fn location_id(&self) -> ObjectHash {
        self.location
    }
    pub const fn replica_id(&self) -> DeviceId {
        self.device
    }
}
/// Additional native host refusal gate. It can only restrict an operation
/// already admitted by the original/current signatures and purpose-bound
/// native proof. The transaction reference must never be re-entered.
pub trait LocalActionAuthorityGuard {
    fn check_in(&mut self, transaction: &ea_local_store::StoreTransaction<'_>)
    -> Result<(), Error>;
    fn check_before_effect(&mut self) -> Result<(), Error>;
}
pub(crate) struct NoAdditionalAuthorityGuard;
impl LocalActionAuthorityGuard for NoAdditionalAuthorityGuard {
    fn check_in(
        &mut self,
        _transaction: &ea_local_store::StoreTransaction<'_>,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn check_before_effect(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
impl SqliteDestructionJobs {
    pub fn execute_local(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        start: &DurableDestructionStart,
        native: &DestructionRequestService<'_>,
        proof: &OperatorSessionProof,
        local: &LocalDestructionExecution<'_>,
        progress: &mut dyn FnMut(LocalDestructionCheckpoint) -> Result<(), Error>,
    ) -> Result<MeasuredLocalRemoval, Error> {
        // Reconstruct the persistent start. Its historical signature is not
        // today's authority. No value below claims global completion.
        self.execute_local_guarded(
            context,
            start,
            native,
            proof,
            local,
            progress,
            &mut NoAdditionalAuthorityGuard,
        )
    }
    // Preserve the existing typed action arguments; the additional guard only refuses.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_local_guarded(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        start: &DurableDestructionStart,
        native: &DestructionRequestService<'_>,
        proof: &OperatorSessionProof,
        local: &LocalDestructionExecution<'_>,
        progress: &mut dyn FnMut(LocalDestructionCheckpoint) -> Result<(), Error>,
        guard: &mut dyn LocalActionAuthorityGuard,
    ) -> Result<MeasuredLocalRemoval, Error> {
        // Reconstruct the persistent start. Its historical signature is not
        // today's authority. No value below claims global completion.
        let persisted = self.start_execution_guarded(
            context,
            start.event().exact_bytes(),
            native,
            proof,
            guard,
        )?;
        if persisted.job_hash() != start.job_hash() {
            return Err(Error::SecurityConflict);
        }
        let resumed = native.resume_original(
            context.resumed.request().authorization(),
            context.resumed.authorization_head(),
            proof,
        )?;
        crate::preflight::check_authority(&resumed, context.custody, local.component_certificate)?;
        let device = resumed
            .current_head()
            .active_certificate_fields(local.component_certificate)
            .ok_or(Error::Signature)?
            .device_id;
        let location = location_id(local.backend)?;
        let expected = registered_holdings(context.custody.exact_bytes(), local, location, device)?;
        let allowed: BTreeSet<_> = context
            .job
            .preflight()
            .removal_object_hashes()
            .iter()
            .copied()
            .collect();
        if !expected.is_subset(&allowed) {
            return Err(Error::SecurityConflict);
        }
        // Narrow key-match proof using the SAME verified typed digest. It is
        // neither a newly published event nor a fresh time/authority claim.
        let ParsedArchiveObject::Trust(event) = decode_exact_object(start.event().exact_bytes())?
        else {
            return Err(Error::Event);
        };
        let auth = resumed.request().authorization();
        let signature = local.signer.sign_destruction_transition_digest(
            local.component_certificate,
            event.value().exact_digest_input(),
            auth.exact_bytes(),
        )?;
        let signature_context = VerificationContext::destruction_transition_trust_digest(
            event.value().exact_digest_input(),
            auth.exact_bytes(),
            local.component_certificate,
        )?;
        verify_cose_sign1(
            &signature,
            &resumed.authorization_head(),
            &signature_context,
        )?;
        // Re-check native/current authority AFTER potentially external signing.
        let resumed = native.resume_original(auth, context.resumed.authorization_head(), proof)?;
        crate::preflight::check_authority(&resumed, context.custody, local.component_certificate)?;
        if !resumed
            .current_head()
            .policy_fields()
            .allowed_archive_profile_hashes
            .contains(&local.backend.profile_hash().map_err(|_| Error::Storage)?)
        {
            return Err(Error::Registry);
        }
        let _writer_lock = local
            .backend
            .acquire_writer_lock()
            .map_err(|_| Error::Storage)?;
        let preflight = context.job.preflight();
        let targets: BTreeSet<_> = preflight
            .targets
            .iter()
            .map(|target| target.entry)
            .collect();
        let removed: Vec<_> = expected.iter().copied().collect();
        let exact = encode_measurement(start.job_hash(), location, device, &removed)?;
        let key = [blob(start.job_hash().as_bytes()), blob(location.as_bytes())];
        // Same lock order as observation: writer, then SQLCipher. A new
        // registered holding cannot slip between this fence and measurement.
        self.database.transaction(|tx| {
            crate::inventory::require_durable(tx)?;
            crate::inventory::require_unchanged_in(tx,context.custody)?;
            guard.check_in(tx)?;
            let live = scan(local.backend,&targets,&expected,preflight)?;
            for exact in [auth.exact_bytes(),resumed.request().event().exact_bytes(),start.event().exact_bytes()] {
                publish_exact_trust(local.backend,exact)?;
            }
            for target in &preflight.targets {
                let path = stub_path(target.entry)?;
                progress(LocalDestructionCheckpoint::BeforeStubCreate)?;
                local.backend.create_if_absent(&path,&target.stub).map_err(|_|Error::Storage)?;
                progress(LocalDestructionCheckpoint::StubCreated)?;
                local.backend.sync_file(&path).map_err(|_|Error::Storage)?;
                progress(LocalDestructionCheckpoint::StubFileFlushed)?;
                local.backend.sync_directory(&path).map_err(|_|Error::Storage)?;
                progress(LocalDestructionCheckpoint::StubDirectoryFlushed)?;
                verify_stub(local.backend,&path,target.stub.as_bytes())?;
                progress(LocalDestructionCheckpoint::StubVerified)?;
            }
            for (relative,hash) in live {
                progress(LocalDestructionCheckpoint::BeforeRemove)?;
                guard.check_in(tx)?;
                verify_all_stubs(local.backend,preflight)?;
                let absolute = local.backend.root().join(&relative);
                if object_hash(&fs::read(&absolute).map_err(|_|Error::Storage)?)!=hash { return Err(Error::SecurityConflict); }
                local.backend.remove_if_present(&archive_path(&relative)?).map_err(|_|Error::Storage)?;
                // ArchivePath's directory is a layout directory. A nested
                // name additionally needs its immediate parent flushed. Only
                // Unix opens a directory as a file; elsewhere the durable
                // directory entry stays a promise of the host, as in
                // ea-archive-fs.
                #[cfg(unix)]
                fs::File::open(absolute.parent().ok_or(Error::Storage)?).and_then(|file|file.sync_all()).map_err(|_|Error::Storage)?;
                if absolute.try_exists().map_err(|_|Error::Storage)? { return Err(Error::Storage); }
                progress(LocalDestructionCheckpoint::Removed)?;
            }
            verify_all_stubs(local.backend,preflight)?;
            if !scan(local.backend,&targets,&expected,preflight)?.is_empty() { return Err(Error::Storage); }
            progress(LocalDestructionCheckpoint::FinalScan)?;
            if let Some(row)=tx.query_row("SELECT exact_measurement FROM destruction_local_measurement WHERE job_hash=?1 AND location_id=?2",&key)? {
                if row.blob(0)?!=exact { return Err(Error::SecurityConflict); }
            } else {
                tx.execute("INSERT INTO destruction_local_measurement(job_hash,location_id,organization_id,destruction_id,replica_id,exact_measurement) VALUES(?1,?2,?3,?4,?5,?6)",&[key[0].clone(),key[1].clone(),blob(auth.fields().organization_id.as_bytes()),blob(auth.fields().destruction_id.as_bytes()),blob(device.as_bytes()),blob(&exact)])?;
            }
            Ok::<_,Error>(())
        })?;
        progress(LocalDestructionCheckpoint::MeasurementCommitted)?;
        let reread = self.database.query_row("SELECT exact_measurement FROM destruction_local_measurement WHERE job_hash=?1 AND location_id=?2",&key)?.ok_or(Error::Storage)?;
        if reread.blob(0)? != exact
            || !scan(local.backend, &targets, &expected, preflight)?.is_empty()
        {
            return Err(Error::SecurityConflict);
        }
        verify_all_stubs(local.backend, preflight)?;
        Ok(MeasuredLocalRemoval {
            exact,
            removed,
            job: start.job_hash(),
            location,
            device,
        })
    }
}

pub(crate) fn location_id(backend: &LocalPathBackend) -> Result<ObjectHash, Error> {
    let root = fs::canonicalize(backend.root()).map_err(|_| Error::Storage)?;
    let mut exact = b"EINSATZARCHIV-MANAGED-ARCHIVE-LOCATION-v1\0".to_vec();
    exact.extend_from_slice(root.to_str().ok_or(Error::Storage)?.as_bytes());
    Ok(object_hash(&exact))
}
/// Caller holds the actual Writer lock. These are already-verified exact
/// operation bytes; no new authority or signature is manufactured here.
pub(crate) fn publish_exact_trust(backend: &LocalPathBackend, exact: &[u8]) -> Result<(), Error> {
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(exact)? else {
        return Err(Error::Format);
    };
    let path = ArchivePath::in_dir(
        ea_archive::DESTRUCTIONS_DIR_V1,
        &format!("{}.etb", hex(parsed.object_hash().as_bytes())),
    )
    .map_err(|_| Error::Storage)?;
    backend
        .create_if_absent(&path, parsed.exact_bytes())
        .map_err(|_| Error::Storage)?;
    backend.sync_file(&path).map_err(|_| Error::Storage)?;
    backend.sync_directory(&path).map_err(|_| Error::Storage)?;
    if fs::read(backend.root().join(path.as_str())).map_err(|_| Error::Storage)? != exact {
        return Err(Error::SecurityConflict);
    }
    Ok(())
}
pub(crate) fn registered_holdings(
    exact: &[u8],
    local: &LocalDestructionExecution<'_>,
    location: ObjectHash,
    device: DeviceId,
) -> Result<BTreeSet<ObjectHash>, Error> {
    let mut hashes = BTreeSet::new();
    let profile = local.backend.profile_hash().map_err(|_| Error::Storage)?;
    (|| -> Result<(), minicbor::decode::Error> {
        let bad = || minicbor::decode::Error::message("unregistered local custody");
        let mut d = Decoder::new(exact);
        if d.array()? != Some(6) {
            return Err(bad());
        }
        for _ in 0..5 {
            d.skip()?;
        }
        let count = d.array()?.ok_or_else(bad)?;
        let mut registered = false;
        for _ in 0..count {
            let mut r = Decoder::new(d.bytes()?);
            r.array()?;
            let kind = r.u8()?;
            let cert = r.bytes()?;
            let replica = r.bytes()?;
            r.u8()?;
            if kind == 0 {
                continue;
            }
            let record_profile = r.bytes()?;
            let record_location = r.bytes()?;
            let matched = replica == device.as_bytes()
                && record_profile == profile.as_bytes()
                && record_location == location.as_bytes();
            if matched && cert == local.custody_certificate.as_bytes() {
                registered = true;
            }
            if kind == 2 && matched {
                hashes.insert(ObjectHash::try_from(r.bytes()?).map_err(|_| bad())?);
            }
        }
        if !registered || d.position() != exact.len() {
            return Err(bad());
        }
        Ok(())
    })()
    .map_err(|_| Error::SecurityConflict)?;
    Ok(hashes)
}
fn stub_path(entry: EntryHash) -> Result<ArchivePath, Error> {
    ArchivePath::in_dir(
        DESTROYED_ENTRIES_DIR_V1,
        &format!("{}.eds", hex(entry.as_bytes())),
    )
    .map_err(|_| Error::Format)
}
fn verify_stub(
    backend: &LocalPathBackend,
    path: &ArchivePath,
    expected: &[u8],
) -> Result<(), Error> {
    let exact = fs::read(backend.root().join(path.as_str())).map_err(|_| Error::Storage)?;
    if exact != expected
        || !matches!(
            decode_exact_object(&exact)?,
            ParsedArchiveObject::Destroyed(_)
        )
    {
        return Err(Error::SecurityConflict);
    }
    Ok(())
}
pub(crate) fn verify_all_stubs(
    backend: &LocalPathBackend,
    preflight: &crate::SignedDestructionPreflight,
) -> Result<(), Error> {
    for target in &preflight.targets {
        verify_stub(backend, &stub_path(target.entry)?, target.stub.as_bytes())?;
    }
    Ok(())
}
fn archive_path(relative: &str) -> Result<ArchivePath, Error> {
    let directory = LAYOUT_PATHS_V1
        .iter()
        .filter(|dir| dir.ends_with('/') && relative.starts_with(**dir))
        .max_by_key(|dir| dir.len())
        .ok_or(Error::Storage)?;
    ArchivePath::in_dir(directory, &relative[directory.len()..]).map_err(|_| Error::Storage)
}
/// A complete physical walk includes staging and rejects links/unreadable
/// paths rather than silently reducing the measured managed scope.
pub(crate) fn scan(
    backend: &LocalPathBackend,
    targets: &BTreeSet<EntryHash>,
    allowed: &BTreeSet<ObjectHash>,
    preflight: &crate::SignedDestructionPreflight,
) -> Result<BTreeMap<String, ObjectHash>, Error> {
    let mut paths = Vec::new();
    walk(backend.root(), backend.root(), 0, &mut paths)?;
    // A damaged old object cannot become an unrelated/non-object file merely
    // because decoding it now fails. Original signed paths remain obligations.
    for (hash, original_paths) in &preflight.removals {
        if !allowed.contains(hash) {
            continue;
        }
        for relative in original_paths {
            archive_path(relative)?;
            match fs::read(backend.root().join(relative)) {
                Ok(exact) if object_hash(&exact) == *hash => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(Error::SecurityConflict),
            }
        }
    }
    let mut bytes_seen = 0u64;
    let mut removals = BTreeMap::new();
    for relative in paths {
        let absolute = backend.root().join(&relative);
        bytes_seen = bytes_seen
            .checked_add(fs::metadata(&absolute).map_err(|_| Error::Storage)?.len())
            .ok_or(Error::Storage)?;
        if bytes_seen > ea_archive::MAX_TOTAL_ARCHIVE_BYTES_V1 as u64 {
            return Err(Error::Storage);
        }
        let exact = fs::read(absolute).map_err(|_| Error::Storage)?;
        let hash = object_hash(&exact);
        let target = match decode_exact_object(&exact) {
            Ok(ParsedArchiveObject::Entry(entry)) => Some(entry.value().entry_hash()),
            Ok(ParsedArchiveObject::Grant(grant)) => {
                Some(grant.value().grant_body().fields().entry_hash)
            }
            _ => None,
        };
        if target.is_some_and(|entry| targets.contains(&entry)) || allowed.contains(&hash) {
            if !allowed.contains(&hash) {
                return Err(Error::SecurityConflict);
            }
            archive_path(&relative)?;
            removals.insert(relative, hash);
        }
    }
    Ok(removals)
}
fn walk(root: &Path, directory: &Path, depth: usize, paths: &mut Vec<String>) -> Result<(), Error> {
    if depth > 128 {
        return Err(Error::Storage);
    }
    for entry in fs::read_dir(directory).map_err(|_| Error::Storage)? {
        let entry = entry.map_err(|_| Error::Storage)?;
        let kind = entry.file_type().map_err(|_| Error::Storage)?;
        if kind.is_symlink() {
            return Err(Error::Storage);
        }
        if kind.is_dir() {
            walk(root, &entry.path(), depth + 1, paths)?;
        } else if kind.is_file() {
            paths.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| Error::Storage)?
                    .to_str()
                    .ok_or(Error::Storage)?
                    .to_owned(),
            );
            if paths.len() > ea_archive::MAX_ARCHIVE_BLOBS_V1 {
                return Err(Error::Storage);
            }
        } else {
            return Err(Error::Storage);
        }
    }
    Ok(())
}
pub(crate) fn encode_measurement(
    job: ObjectHash,
    location: ObjectHash,
    device: DeviceId,
    removed: &[ObjectHash],
) -> Result<Vec<u8>, Error> {
    let mut exact = Vec::new();
    let mut e = Encoder::new(&mut exact);
    e.array(5)
        .map_err(|_| Error::Format)?
        .str("EINSATZARCHIV-LOCAL-DESTRUCTION-MEASUREMENT-v1")
        .map_err(|_| Error::Format)?
        .bytes(job.as_bytes())
        .map_err(|_| Error::Format)?
        .bytes(location.as_bytes())
        .map_err(|_| Error::Format)?
        .bytes(device.as_bytes())
        .map_err(|_| Error::Format)?
        .array(removed.len() as u64)
        .map_err(|_| Error::Format)?;
    for hash in removed {
        e.bytes(hash.as_bytes()).map_err(|_| Error::Format)?;
    }
    Ok(exact)
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                DIGITS[(b >> 4) as usize] as char,
                DIGITS[(b & 15) as usize] as char,
            ]
        })
        .collect()
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
