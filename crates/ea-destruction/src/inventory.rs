//! Monotone operational custody; it never confers signing authority.
use crate::{DestructionError as Error, ResumedDestruction};
use ea_archive::{ArchiveBackend as _, ArchiveInventory};
use ea_crypto::object_hash;
use ea_format::{CertificateKindV1, ObjectTypeV1, ParsedArchiveObject};
use ea_local_store::{EncryptedDatabase, StoreTransaction, StoreValue};
use ea_trust::SelectedRegistryHead;
use ea_types::{CertificateHash, DeviceId, EntryHash, Hash32, ObjectHash, OrganizationId};
use minicbor::{Decoder, Encoder};
use std::{collections::BTreeSet, sync::Arc};

const MAX_RECORDS: usize = 10_000;
pub struct SqliteManagedCustody {
    database: Arc<EncryptedDatabase>,
}
pub struct ManagedArchiveRegistration {
    location: ObjectHash,
    profile: Hash32,
}
impl ManagedArchiveRegistration {
    pub const fn location_id(&self) -> ObjectHash {
        self.location
    }
    pub const fn profile_hash(&self) -> Hash32 {
        self.profile
    }
}

/// Durable operational denominator. This alone is neither execution
/// authority nor proof of any physical removal.
#[derive(Clone)]
pub struct DurableManagedInventory {
    organization: OrganizationId,
    records: Vec<Vec<u8>>,
    target_entries: BTreeSet<EntryHash>,
    exact: Vec<u8>,
}
impl DurableManagedInventory {
    pub fn known_replica_count(&self) -> usize {
        self.records
            .iter()
            .map(|bytes| {
                record_metadata(bytes)
                    .expect("private validated custody record")
                    .0
            })
            .collect::<BTreeSet<_>>()
            .len()
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub fn snapshot_hash(&self) -> ObjectHash {
        object_hash(&self.exact)
    }
}
impl SqliteManagedCustody {
    pub fn new(database: Arc<EncryptedDatabase>) -> Self {
        Self { database }
    }
    /// Read-only Writer custody observation; grants no destruction capability.
    pub fn observe_writer_archive(
        &self,
        head: ea_trust::WriterRegistryHeadRef<'_>,
        certificate: CertificateHash,
        backend: &ea_archive_fs::LocalPathBackend,
    ) -> Result<ManagedArchiveRegistration, Error> {
        if head.current_writer_certificate_hash() != Some(certificate)
            || head
                .active_certificate_fields(certificate)
                .is_none_or(|fields| fields.certificate_kind != CertificateKindV1::Writer)
        {
            return Err(Error::Registry);
        }
        self.observe_archive(head, certificate, backend)
    }
    /// Called at actual host profile opening and immediately before publication.
    /// Records physical holdings and a durable location obligation, not authority.
    pub fn observe_local_archive(
        &self,
        head: &SelectedRegistryHead,
        certificate: CertificateHash,
        backend: &ea_archive_fs::LocalPathBackend,
    ) -> Result<ManagedArchiveRegistration, Error> {
        self.observe_archive(head.into(), certificate, backend)
    }
    fn observe_archive(
        &self,
        head: ea_trust::WriterRegistryHeadRef<'_>,
        certificate: CertificateHash,
        backend: &ea_archive_fs::LocalPathBackend,
    ) -> Result<ManagedArchiveRegistration, Error> {
        let (_, fields) = head
            .known_certificate_fields()
            .find(|(hash, _)| *hash == certificate)
            .ok_or(Error::Registry)?;
        if !custodian_kind(fields.certificate_kind as u8) {
            return Err(Error::Registry);
        }
        let profile = backend.profile_hash().map_err(|_| Error::Storage)?;
        if !head
            .policy_fields()
            .allowed_archive_profile_hashes
            .contains(&profile)
        {
            return Err(Error::Registry);
        }
        let _lock = backend.acquire_writer_lock().map_err(|_| Error::Storage)?;
        let root = std::fs::canonicalize(backend.root()).map_err(|_| Error::Storage)?;
        let root = root.to_str().ok_or(Error::Storage)?;
        let mut location_preimage = b"EINSATZARCHIV-MANAGED-ARCHIVE-LOCATION-v1\0".to_vec();
        location_preimage.extend_from_slice(root.as_bytes());
        let location = object_hash(&location_preimage);
        let archive =
            ArchiveInventory::build(&backend.as_archive_source()).map_err(|_| Error::Storage)?;
        if !archive.format_errors().is_empty() {
            return Err(Error::Storage);
        }
        let mut holdings = BTreeSet::new();
        for entry in archive.entries() {
            holdings.insert((
                entry.object_hash(),
                entry.value().entry_hash(),
                ObjectTypeV1::Entry.code() as u8,
            ));
        }
        for grant in archive.grants() {
            holdings.insert((
                grant.object_hash(),
                grant.value().grant_body().fields().entry_hash,
                ObjectTypeV1::Grant.code() as u8,
            ));
        }
        // Staging is intentionally excluded from the public archive source,
        // but remains managed physical data and must enter this obligation.
        let staged = backend.staged_paths().map_err(|_| Error::Storage)?;
        if staged.len() > ea_archive::MAX_ARCHIVE_BLOBS_V1 {
            return Err(Error::Storage);
        }
        let mut staged_size = 0u64;
        for path in staged {
            let absolute = backend.root().join(path);
            staged_size = staged_size
                .checked_add(
                    std::fs::metadata(&absolute)
                        .map_err(|_| Error::Storage)?
                        .len(),
                )
                .ok_or(Error::Storage)?;
            if staged_size > ea_archive::MAX_TOTAL_ARCHIVE_BYTES_V1 as u64 {
                return Err(Error::Storage);
            }
            let bytes = std::fs::read(absolute).map_err(|_| Error::Storage)?;
            match ea_format::decode_exact_object(&bytes)? {
                ParsedArchiveObject::Entry(entry) => {
                    holdings.insert((
                        entry.object_hash(),
                        entry.value().entry_hash(),
                        ObjectTypeV1::Entry.code() as u8,
                    ));
                }
                ParsedArchiveObject::Grant(grant) => {
                    holdings.insert((
                        grant.object_hash(),
                        grant.value().grant_body().fields().entry_hash,
                        ObjectTypeV1::Grant.code() as u8,
                    ));
                }
                _ => {}
            }
        }
        let prefix = |e: &mut Encoder<&mut Vec<u8>>, code, arity| -> Result<(), Error> {
            e.array(arity)
                .map_err(|_| Error::Format)?
                .u8(code)
                .map_err(|_| Error::Format)?
                .bytes(certificate.as_bytes())
                .map_err(|_| Error::Format)?
                .bytes(fields.device_id.as_bytes())
                .map_err(|_| Error::Format)?
                .u8(fields.certificate_kind as u8)
                .map_err(|_| Error::Format)?
                .bytes(profile.as_bytes())
                .map_err(|_| Error::Format)?
                .bytes(location.as_bytes())
                .map_err(|_| Error::Format)?;
            Ok(())
        };
        let mut records = Vec::new();
        let mut bytes = Vec::new();
        prefix(&mut Encoder::new(&mut bytes), 1, 6)?;
        records.push(bytes);
        for (object, entry, kind) in holdings {
            let mut bytes = Vec::new();
            let mut e = Encoder::new(&mut bytes);
            prefix(&mut e, 2, 9)?;
            e.bytes(object.as_bytes())
                .map_err(|_| Error::Format)?
                .bytes(entry.as_bytes())
                .map_err(|_| Error::Format)?
                .u8(kind)
                .map_err(|_| Error::Format)?;
            records.push(bytes);
        }
        self.database.transaction(|tx| {
            require_durable(tx)?;
            observe_in(tx, head)?;
            for record in records {
                append_record(tx, fields.organization_id, &record)?;
            }
            Ok::<_, Error>(())
        })?;
        Ok(ManagedArchiveRegistration { location, profile })
    }

    /// Add every verified historically admitted storage component, including
    /// revoked ones. Reachability cannot participate in this denominator.
    pub fn observe_registry(&self, head: &SelectedRegistryHead) -> Result<(), Error> {
        self.database.transaction(|tx| {
            require_durable(tx)?;
            observe_in(tx, head.into())
        })
    }

    /// Append the complete verified catalog denominator, including published
    /// future holders. This records custody only, not current role authority.
    pub fn observe_catalog(&self, catalog: &ea_trust::VerifiedCatalogCustody) -> Result<(), Error> {
        self.database.transaction(|tx| {
            require_durable(tx)?;
            for (hash, certificate) in catalog.known_certificate_fields() {
                if !custodian_kind(certificate.certificate_kind as u8) {
                    continue;
                }
                let mut bytes = Vec::new();
                let mut e = Encoder::new(&mut bytes);
                e.array(4)
                    .map_err(|_| Error::Format)?
                    .u8(0)
                    .map_err(|_| Error::Format)?
                    .bytes(hash.as_bytes())
                    .map_err(|_| Error::Format)?
                    .bytes(certificate.device_id.as_bytes())
                    .map_err(|_| Error::Format)?
                    .u8(certificate.certificate_kind as u8)
                    .map_err(|_| Error::Format)?;
                append_record(tx, certificate.organization_id, &bytes)?;
            }
            Ok::<_, Error>(())
        })
    }
    /// Freeze once under the same SQLCipher write lock as reconciliation of
    /// registered custody. Exact replay succeeds; a changed denominator is a
    /// conflict requiring an explicit extension workflow, never replacement.
    pub fn freeze(
        &self,
        resumed: &ResumedDestruction<'_>,
    ) -> Result<DurableManagedInventory, Error> {
        let auth = resumed.request().authorization();
        let fields = auth.fields();
        // Learning custody must survive a rejected attempt to reuse an older
        // snapshot. Commit it first, then freeze/read under a new write lock.
        self.observe_registry(resumed.current_head())?;
        self.database.transaction(|tx| {
            require_durable(tx)?;
            let target_entries: BTreeSet<_> = fields.targets.iter().map(|t| EntryHash::try_from(t.entry_hash().as_slice()).map_err(|_| Error::Format)).collect::<Result<_,_>>()?;
            let records = relevant_records(tx, fields.organization_id, &target_entries)?;
            if records.is_empty() { return Err(Error::Storage); }
            let mut exact = Vec::new();
            let mut e = Encoder::new(&mut exact);
            e.array(6).map_err(|_| Error::Format)?;
            e.str("EINSATZARCHIV-MANAGED-CUSTODY-v1").map_err(|_| Error::Format)?;
            e.bytes(fields.organization_id.as_bytes()).map_err(|_| Error::Format)?;
            e.bytes(fields.destruction_id.as_bytes()).map_err(|_| Error::Format)?;
            e.bytes(auth.object_hash().as_bytes()).map_err(|_| Error::Format)?;
            e.bytes(resumed.current_head().chain_id().as_bytes()).map_err(|_| Error::Format)?;
            e.array(records.len() as u64).map_err(|_| Error::Format)?;
            for record in &records { e.bytes(record).map_err(|_| Error::Format)?; }
            let key = [blob(fields.organization_id.as_bytes()), blob(fields.destruction_id.as_bytes())];
            if let Some(row) = tx.query_row("SELECT authorization_hash,exact_bytes FROM destruction_inventory WHERE organization_id=?1 AND destruction_id=?2", &key)? {
                if row.blob(0)? != auth.object_hash().as_bytes() || row.blob(1)? != exact { return Err(Error::SecurityConflict); }
            } else {
                tx.execute("INSERT INTO destruction_inventory(organization_id,destruction_id,authorization_hash,exact_bytes) VALUES(?1,?2,?3,?4)", &[
                    key[0].clone(), key[1].clone(), blob(auth.object_hash().as_bytes()), blob(&exact)
                ])?;
            }
            Ok(DurableManagedInventory { organization: fields.organization_id, records, target_entries, exact })
        })
    }

    /// New knowledge invalidates an old snapshot. Completion persistence must
    /// perform this comparison inside its final transaction, under its fence.
    pub fn require_unchanged(&self, snapshot: &DurableManagedInventory) -> Result<(), Error> {
        self.database
            .transaction(|tx| require_unchanged_in(tx, snapshot))
    }
}
pub(crate) fn require_unchanged_in(
    tx: &StoreTransaction<'_>,
    snapshot: &DurableManagedInventory,
) -> Result<(), Error> {
    if relevant_records(tx, snapshot.organization, &snapshot.target_entries)? != snapshot.records {
        return Err(Error::SecurityConflict);
    }
    Ok(())
}
fn observe_in(
    tx: &StoreTransaction<'_>,
    head: ea_trust::WriterRegistryHeadRef<'_>,
) -> Result<(), Error> {
    for (hash, certificate) in head.known_certificate_fields() {
        if !matches!(
            certificate.certificate_kind,
            CertificateKindV1::Writer
                | CertificateKindV1::Reader
                | CertificateKindV1::ServerReceipt
        ) {
            continue;
        }
        let mut bytes = Vec::new();
        let mut e = Encoder::new(&mut bytes);
        e.array(4).map_err(|_| Error::Format)?;
        e.u8(0).map_err(|_| Error::Format)?;
        e.bytes(hash.as_bytes()).map_err(|_| Error::Format)?;
        e.bytes(certificate.device_id.as_bytes())
            .map_err(|_| Error::Format)?;
        e.u8(certificate.certificate_kind as u8)
            .map_err(|_| Error::Format)?;
        append_record(tx, certificate.organization_id, &bytes)?;
    }
    Ok(())
}
fn read_records(
    tx: &StoreTransaction<'_>,
    organization: OrganizationId,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut records = Vec::new();
    let mut after = Vec::new();
    while let Some(row) = tx.query_row("SELECT record_hash,exact_bytes FROM managed_custody WHERE organization_id=?1 AND record_hash>?2 ORDER BY record_hash LIMIT 1", &[blob(organization.as_bytes()), blob(&after)])? {
        if records.len() >= MAX_RECORDS { return Err(Error::Storage); }
        let bytes = row.blob(1)?.to_vec();
        after = row.blob(0)?.to_vec();
        if object_hash(&bytes).as_bytes() != after.as_slice() { return Err(Error::SecurityConflict); }
        record_metadata(&bytes)?;
        records.push(bytes);
    }
    Ok(records)
}
pub(crate) fn relevant_records(
    tx: &StoreTransaction<'_>,
    organization: OrganizationId,
    targets: &BTreeSet<EntryHash>,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut relevant = Vec::new();
    for record in read_records(tx, organization)? {
        if record_metadata(&record)?
            .1
            .is_none_or(|entry| targets.contains(&entry))
        {
            relevant.push(record);
        }
    }
    Ok(relevant)
}
fn append_record(
    tx: &StoreTransaction<'_>,
    organization: OrganizationId,
    bytes: &[u8],
) -> Result<(), Error> {
    record_metadata(bytes)?;
    tx.execute("INSERT INTO managed_custody(organization_id,record_hash,exact_bytes) VALUES(?1,?2,?3) ON CONFLICT(organization_id,record_hash) DO NOTHING", &[
        blob(organization.as_bytes()),blob(object_hash(bytes).as_bytes()),blob(bytes)
    ])?;
    Ok(())
}
fn custodian_kind(kind: u8) -> bool {
    [
        CertificateKindV1::Writer as u8,
        CertificateKindV1::Reader as u8,
        CertificateKindV1::ServerReceipt as u8,
    ]
    .contains(&kind)
}
fn record_metadata(bytes: &[u8]) -> Result<(DeviceId, Option<EntryHash>), Error> {
    (|| -> Result<_, minicbor::decode::Error> {
        let bad = || minicbor::decode::Error::message("invalid custody record");
        let mut d = Decoder::new(bytes);
        let arity = d.array()?.ok_or_else(bad)?;
        let code = d.u8()?;
        if !matches!((code, arity), (0, 4) | (1, 6) | (2, 9)) {
            return Err(bad());
        }
        let cert = d.bytes()?;
        if cert.len() != 32 {
            return Err(bad());
        }
        let device_bytes = d.bytes()?;
        let device = DeviceId::try_from(device_bytes).map_err(|_| bad())?;
        let kind = d.u8()?;
        if !custodian_kind(kind) {
            return Err(bad());
        }
        let mut canonical = Vec::new();
        let mut e = Encoder::new(&mut canonical);
        e.array(arity)
            .unwrap()
            .u8(code)
            .unwrap()
            .bytes(cert)
            .unwrap()
            .bytes(device_bytes)
            .unwrap()
            .u8(kind)
            .unwrap();
        if code > 0 {
            for _ in 0..2 {
                let value = d.bytes()?;
                if value.len() != 32 {
                    return Err(bad());
                }
                e.bytes(value).unwrap();
            }
        }
        let target = if code == 2 {
            let object = d.bytes()?;
            if object.len() != 32 {
                return Err(bad());
            }
            let entry = d.bytes()?;
            let hash = EntryHash::try_from(entry).map_err(|_| bad())?;
            let object_kind = d.u8()?;
            if ![
                ObjectTypeV1::Entry.code() as u8,
                ObjectTypeV1::Grant.code() as u8,
            ]
            .contains(&object_kind)
            {
                return Err(bad());
            }
            e.bytes(object)
                .unwrap()
                .bytes(entry)
                .unwrap()
                .u8(object_kind)
                .unwrap();
            Some(hash)
        } else {
            None
        };
        if d.position() != bytes.len() || canonical != bytes {
            return Err(bad());
        }
        Ok((device, target))
    })()
    .map_err(|_| Error::Format)
}
pub(crate) fn require_durable(tx: &StoreTransaction<'_>) -> Result<(), Error> {
    let sync = tx
        .query_row("PRAGMA synchronous", &[])?
        .ok_or(Error::Storage)?
        .integer(0)?;
    if matches!(sync, 2 | 3) {
        Ok(())
    } else {
        Err(Error::Storage)
    }
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
