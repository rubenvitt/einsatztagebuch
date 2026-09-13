//! SQLCipher-only immutable publication fence, captured before draft-key loss.
use super::*;
use ea_local_store::{EncryptedDatabase, StoreTransaction, StoreValue};
use minicbor::Encoder;
const DOMAIN: &str = "EINSATZARCHIV-WRITER-DESTRUCTION-BINDING-v1";
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}

impl VerifiedDestructionEvidence {
    /// Binds the normal Writer's exact prepared bytes to this native proof.
    /// This is local persistence; no new signing or current action authority.
    pub fn bind_prepared_entry(
        &self,
        database: &Arc<EncryptedDatabase>,
        exact_entry: &[u8],
    ) -> Result<(), Error> {
        let (_, custody) = self.fence.as_ref().ok_or(Error::Storage)?;
        let parsed = ea_format::decode_exact_object(exact_entry)?;
        let ea_format::ParsedArchiveObject::Entry(entry) = parsed else {
            return Err(Error::Format);
        };
        let fields = entry.value().manifest().fields();
        self.validate_for_writer(
            fields.organization_id,
            fields.chain_id,
            fields.chain_sequence,
            self.observed,
        )?;
        let mut exact = Vec::new();
        let mut e = Encoder::new(&mut exact);
        e.array(8)
            .map_err(|_| Error::Format)?
            .str(DOMAIN)
            .map_err(|_| Error::Format)?
            .bytes(self.organization.as_bytes())
            .map_err(|_| Error::Format)?
            .bytes(self.chain.as_bytes())
            .map_err(|_| Error::Format)?
            .bytes(self.destruction.as_bytes())
            .map_err(|_| Error::Format)?
            .bytes(self.authorization.as_bytes())
            .map_err(|_| Error::Format)?
            .bytes(self.job.ok_or(Error::Storage)?.as_bytes())
            .map_err(|_| Error::Format)?
            .bytes(custody.exact_bytes())
            .map_err(|_| Error::Format)?
            .array(self.targets.len() as u64)
            .map_err(|_| Error::Format)?;
        for (entry, sequence, stub) in &self.targets {
            e.array(3)
                .map_err(|_| Error::Format)?
                .bytes(entry.as_bytes())
                .map_err(|_| Error::Format)?
                .u64(sequence.get())
                .map_err(|_| Error::Format)?
                .bytes(stub.as_bytes())
                .map_err(|_| Error::Format)?;
        }
        database.transaction(|tx| {
            crate::inventory::require_durable(tx)?;
            crate::inventory::require_unchanged_in(tx, custody)?;
            // Reopened SQLCipher connections need not share an Arc. Require
            // the same immutable, previously authenticated durable job.
            let saved=tx.query_row("SELECT j.exact_core,j.authorization_hash,i.exact_bytes FROM destruction_job j JOIN destruction_inventory i USING(organization_id,destruction_id) WHERE j.organization_id=?1 AND j.destruction_id=?2", &[blob(self.organization.as_bytes()),blob(self.destruction.as_bytes())])?.ok_or(Error::Storage)?;
            if object_hash(saved.blob(0)?)!=self.job.ok_or(Error::Storage)? || saved.blob(1)?!=self.authorization.as_bytes() || saved.blob(2)?!=custody.exact_bytes(){return Err(Error::SecurityConflict)}
            let key = [blob(entry.value().entry_hash().as_bytes())];
            if let Some(row) = tx.query_row("SELECT entry_object_hash,exact_binding,binding_hash FROM writer_destruction_evidence WHERE entry_hash=?1", &key)? {
                if row.blob(0)? != entry.object_hash().as_bytes() || row.blob(1)? != exact || row.blob(2)? != object_hash(&exact).as_bytes() { return Err(Error::SecurityConflict); }
            } else {
                tx.execute("INSERT INTO writer_destruction_evidence(entry_hash,entry_object_hash,exact_binding,binding_hash) VALUES(?1,?2,?3,?4)", &[key[0].clone(),blob(entry.object_hash().as_bytes()),blob(&exact),blob(object_hash(&exact).as_bytes())])?;
            }
            Ok(())
        })
    }
}

impl SqliteDestructionJobs {
    /// Shared normal/recovery publication gate. The Writer holds its archive
    /// lock. Absence is valid for other normal payload types; the only native
    /// Evidence constructor durably binds before staging/key deletion.
    pub fn validate_prepared_evidence(
        &self,
        exact_entry: &[u8],
        source: &dyn ea_archive::ArchiveSource,
        backend: &dyn ea_archive::ArchiveBackend,
    ) -> Result<(), Error> {
        self.validate_prepared_evidence_binding(exact_entry, source, backend, None)
    }
    /// Require the exact durable Evidence source, including on recovery.
    /// A missing publication row is never an ordinary payload in this path.
    pub fn require_prepared_evidence_source(
        &self,
        exact_entry: &[u8],
        expected: ea_draft::EvidenceDraftSource,
        source: &dyn ea_archive::ArchiveSource,
        backend: &dyn ea_archive::ArchiveBackend,
    ) -> Result<(), Error> {
        self.validate_prepared_evidence_binding(exact_entry, source, backend, Some(expected))
    }
    fn validate_prepared_evidence_binding(
        &self,
        exact_entry: &[u8],
        source: &dyn ea_archive::ArchiveSource,
        backend: &dyn ea_archive::ArchiveBackend,
        expected: Option<ea_draft::EvidenceDraftSource>,
    ) -> Result<(), Error> {
        let parsed = ea_format::decode_exact_object(exact_entry)?;
        let ea_format::ParsedArchiveObject::Entry(entry) = parsed else {
            return Err(Error::Format);
        };
        self.database.transaction(|tx| {
            let Some(row)=tx.query_row("SELECT entry_object_hash,exact_binding,binding_hash FROM writer_destruction_evidence WHERE entry_hash=?1", &[blob(entry.value().entry_hash().as_bytes())])? else {return if expected.is_some() { Err(Error::SecurityConflict) } else { Ok(()) }};
            let exact=row.blob(1)?;
            if row.blob(0)?!=entry.object_hash().as_bytes() || row.blob(2)?!=object_hash(exact).as_bytes(){return Err(Error::SecurityConflict)}
            validate_binding(tx,exact,entry.value().manifest().fields(),source,backend,expected)
        })
    }
}

fn validate_binding(
    tx: &StoreTransaction<'_>,
    exact: &[u8],
    entry: &ea_format::ManifestCoreFieldsV1,
    source: &dyn ea_archive::ArchiveSource,
    backend: &dyn ea_archive::ArchiveBackend,
    expected: Option<ea_draft::EvidenceDraftSource>,
) -> Result<(), Error> {
    let mut d = Decoder::new(exact);
    if d.array().map_err(|_| Error::Format)? != Some(8)
        || d.str().map_err(|_| Error::Format)? != DOMAIN
    {
        return Err(Error::Format);
    }
    let org = OrganizationId::try_from(d.bytes().map_err(|_| Error::Format)?)
        .map_err(|_| Error::Format)?;
    let chain =
        ChainId::try_from(d.bytes().map_err(|_| Error::Format)?).map_err(|_| Error::Format)?;
    let id = d.bytes().map_err(|_| Error::Format)?;
    let auth = d.bytes().map_err(|_| Error::Format)?;
    let job = d.bytes().map_err(|_| Error::Format)?;
    let custody = d.bytes().map_err(|_| Error::Format)?;
    if let Some(expected) = expected
        && (org != expected.organization_id()
            || id != expected.destruction_id().as_bytes()
            || auth != expected.authorization_hash().as_bytes()
            || job != expected.preflight_hash().as_bytes())
    {
        return Err(Error::SecurityConflict);
    }

    if org != entry.organization_id
        || chain != entry.chain_id
        || id.len() != 16
        || auth.len() != 32
        || job.len() != 32
    {
        return Err(Error::SecurityConflict);
    }
    let count = d.array().map_err(|_| Error::Format)?.ok_or(Error::Format)?;
    if count == 0 || count > 10_000 {
        return Err(Error::Format);
    }
    let mut targets = BTreeMap::new();
    for _ in 0..count {
        if d.array().map_err(|_| Error::Format)? != Some(3) {
            return Err(Error::Format);
        }
        let hash = EntryHash::try_from(d.bytes().map_err(|_| Error::Format)?)
            .map_err(|_| Error::Format)?;
        let seq = d.u64().map_err(|_| Error::Format)?;
        let stub = ObjectHash::try_from(d.bytes().map_err(|_| Error::Format)?)
            .map_err(|_| Error::Format)?;
        if seq >= entry.chain_sequence.get() || targets.insert(hash, (seq, stub)).is_some() {
            return Err(Error::Target);
        }
    }
    if d.position() != exact.len() {
        return Err(Error::Format);
    }
    let row=tx.query_row("SELECT j.exact_core,j.exact_inventory,j.authorization_hash,i.exact_bytes FROM destruction_job j JOIN destruction_inventory i USING(organization_id,destruction_id) WHERE j.organization_id=?1 AND j.destruction_id=?2", &[blob(org.as_bytes()),blob(id)])?.ok_or(Error::Storage)?;
    if object_hash(row.blob(0)?).as_bytes() != job
        || row.blob(2)? != auth
        || row.blob(3)? != custody
    {
        return Err(Error::SecurityConflict);
    }
    let core = ea_crypto::decode_destruction_preflight_core(row.blob(0)?)?;
    if core.inventory_hash != *object_hash(row.blob(1)?).as_bytes() {
        return Err(Error::SecurityConflict);
    }
    let mut inv = Decoder::new(row.blob(1)?);
    if inv.array().map_err(|_| Error::Format)? != Some(4)
        || inv.str().map_err(|_| Error::Format)? != "EINSATZARCHIV-DESTRUCTION-JOB-INVENTORY-v1"
        || inv.bytes().map_err(|_| Error::Format)? != custody
        || inv.array().map_err(|_| Error::Format)? != Some(count)
    {
        return Err(Error::SecurityConflict);
    }
    for _ in 0..count {
        if inv.array().map_err(|_| Error::Format)? != Some(3) {
            return Err(Error::Format);
        }
        let hash = EntryHash::try_from(inv.bytes().map_err(|_| Error::Format)?)
            .map_err(|_| Error::Format)?;
        inv.bytes().map_err(|_| Error::Format)?;
        let stub = inv.bytes().map_err(|_| Error::Format)?;
        if targets
            .get(&hash)
            .is_none_or(|(_, expected)| *expected != object_hash(stub))
        {
            return Err(Error::SecurityConflict);
        }
    }
    let mut c = Decoder::new(custody);
    if c.array().map_err(|_| Error::Format)? != Some(6)
        || c.str().map_err(|_| Error::Format)? != "EINSATZARCHIV-MANAGED-CUSTODY-v1"
        || c.bytes().map_err(|_| Error::Format)? != org.as_bytes()
        || c.bytes().map_err(|_| Error::Format)? != id
        || c.bytes().map_err(|_| Error::Format)? != auth
        || c.bytes().map_err(|_| Error::Format)? != chain.as_bytes()
    {
        return Err(Error::SecurityConflict);
    }
    let records = crate::inventory::relevant_records(tx, org, &targets.keys().copied().collect())?;
    if c.array().map_err(|_| Error::Format)? != Some(records.len() as u64) {
        return Err(Error::SecurityConflict);
    }
    for record in records {
        if c.bytes().map_err(|_| Error::Format)? != record {
            return Err(Error::SecurityConflict);
        }
    }
    if c.position() != custody.len() {
        return Err(Error::Format);
    }
    let current = ea_archive::ArchiveInventory::build(source).map_err(|_| Error::Storage)?;
    if !current.format_errors().is_empty() {
        return Err(Error::Format);
    }
    require_no_managed_target_bytes(backend, &targets.keys().copied().collect())?;
    for (target, (_, stub)) in targets {
        if !current
            .destroyed()
            .iter()
            .any(|s| s.value().entry_hash() == target && s.object_hash() == stub)
            || current
                .entries()
                .iter()
                .any(|e| e.value().entry_hash() == target)
            || current
                .grants()
                .iter()
                .any(|g| g.value().grant_body().fields().entry_hash == target)
        {
            return Err(Error::Target);
        }
    }
    Ok(())
}
