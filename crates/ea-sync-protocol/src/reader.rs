//! Die lesenden Rahmen und der technische Cursor.
//!
//! Jede Objektliste ist bytweise nach `objectHash` sortiert und
//! duplikatfrei — die Ordnung steht auf der Leitung, nicht erst im
//! Verbraucher. Technische Listen sind NICHT autoritativ (`design.md` §13.2);
//! sie tragen ausschliesslich exakte Objektbytes und deren Hashes.

use core::fmt;

use ea_crypto::CryptoError;
use ea_format::ObjectTypeV1;
use ea_types::{
    ChainId, DestructionId, EntryHash, Hash32, ObjectHash, OrganizationId, RegistryVersion,
    UnixMillis,
};
use minicbor::Decoder;
use sha2::{Digest, Sha256};

use crate::{
    EndpointV1, MAX_CHECKPOINT_PAGE_OBJECTS_V1, MAX_GRANT_PAGE_OBJECTS_V1,
    MAX_READER_PAGE_BYTES_V1, MAX_READER_PAGE_OBJECTS_V1, MAX_TRUST_PAGE_EVENTS_V1,
    PROTOCOL_PARSER_LIMITS_V1, SyncProtocolError, cbor, cbor_read,
};

/// Ein Satz aus `objectHash` und den exakten Objektbytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ObjectRecordV1 {
    object_hash: ObjectHash,
    exact_object_bytes: Vec<u8>,
}

impl ObjectRecordV1 {
    #[must_use]
    pub const fn new(object_hash: ObjectHash, exact_object_bytes: Vec<u8>) -> Self {
        Self {
            object_hash,
            exact_object_bytes,
        }
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub fn exact_object_bytes(&self) -> &[u8] {
        &self.exact_object_bytes
    }
}

impl fmt::Debug for ObjectRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectRecordV1(<bound>)")
    }
}

/// Prueft Satzzahl, Bytesumme, Sortierung und Duplikatfreiheit einer
/// Objektliste — in genau dieser Reihenfolge, damit die Zaehl- und Bytegrenze
/// vor jeder Ordnungsaussage greift.
fn check_object_records(
    records: &[ObjectRecordV1],
    max_records: usize,
) -> Result<(), SyncProtocolError> {
    if records.len() > max_records {
        return Err(SyncProtocolError::ItemLimit);
    }
    let mut total = 0usize;
    for record in records {
        total = total
            .checked_add(record.exact_object_bytes.len())
            .ok_or(SyncProtocolError::BodyLimit)?;
        if total > MAX_READER_PAGE_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
    }
    check_hash_order(records.iter().map(|record| record.object_hash))
}

fn check_hash_order(hashes: impl Iterator<Item = ObjectHash>) -> Result<(), SyncProtocolError> {
    let mut previous: Option<ObjectHash> = None;
    for hash in hashes {
        if let Some(previous) = previous {
            match hash.as_bytes().cmp(previous.as_bytes()) {
                core::cmp::Ordering::Equal => return Err(SyncProtocolError::DuplicateObject),
                core::cmp::Ordering::Less => return Err(SyncProtocolError::UnsortedObjects),
                core::cmp::Ordering::Greater => {}
            }
        }
        previous = Some(hash);
    }
    Ok(())
}

fn encode_object_records(out: &mut Vec<u8>, records: &[ObjectRecordV1]) {
    cbor::array(out, records.len() as u64);
    for record in records {
        cbor::array(out, 2);
        cbor::bytes(out, record.object_hash.as_bytes());
        cbor::bytes(out, &record.exact_object_bytes);
    }
}

fn decode_object_records(
    decoder: &mut Decoder<'_>,
    max_records: usize,
) -> Result<Vec<ObjectRecordV1>, SyncProtocolError> {
    let count =
        usize::try_from(cbor_read::array(decoder)?).map_err(|_| SyncProtocolError::ItemLimit)?;
    if count > max_records {
        return Err(SyncProtocolError::ItemLimit);
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        cbor_read::expect_array(decoder, 2)?;
        let object_hash = ObjectHash::try_from(cbor_read::bytes_exact(decoder, 32)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        records.push(ObjectRecordV1::new(
            object_hash,
            cbor_read::bytes(decoder)?.to_vec(),
        ));
    }
    Ok(records)
}

fn encode_optional_bytes(out: &mut Vec<u8>, value: Option<&Vec<u8>>) {
    match value {
        Some(bytes) => cbor::bytes(out, bytes),
        None => cbor::null(out),
    }
}

/// `reader-batch-v1`.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderBatchV1 {
    chain_id: ChainId,
    requested_after_sequence: u64,
    requested_after_entry_hash: EntryHash,
    start_head_entry_hash: EntryHash,
    objects: Vec<ObjectRecordV1>,
    next_cursor: Option<Vec<u8>>,
    covered_through_sequence: u64,
    exact: Vec<u8>,
}

impl ReaderBatchV1 {
    pub fn new(
        chain_id: ChainId,
        requested_after_sequence: u64,
        requested_after_entry_hash: EntryHash,
        start_head_entry_hash: EntryHash,
        objects: Vec<ObjectRecordV1>,
        next_cursor: Option<Vec<u8>>,
        covered_through_sequence: u64,
    ) -> Result<Self, SyncProtocolError> {
        check_object_records(&objects, MAX_READER_PAGE_OBJECTS_V1)?;
        let mut exact = Vec::with_capacity(256);
        cbor::array(&mut exact, 9);
        cbor::uint(&mut exact, 1);
        cbor::bytes(&mut exact, chain_id.as_bytes());
        cbor::uint(&mut exact, requested_after_sequence);
        cbor::bytes(&mut exact, requested_after_entry_hash.as_bytes());
        cbor::bytes(&mut exact, start_head_entry_hash.as_bytes());
        encode_object_records(&mut exact, &objects);
        encode_optional_bytes(&mut exact, next_cursor.as_ref());
        cbor::uint(&mut exact, covered_through_sequence);
        cbor::empty_extension(&mut exact);
        Ok(Self {
            chain_id,
            requested_after_sequence,
            requested_after_entry_hash,
            start_head_entry_hash,
            objects,
            next_cursor,
            covered_through_sequence,
            exact,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        if bytes.len() > MAX_READER_PAGE_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 9)?;
        cbor_read::expect_version(&mut decoder)?;
        let chain_id = ChainId::try_from(cbor_read::bytes_exact(&mut decoder, 16)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let requested_after_sequence = cbor_read::uint(&mut decoder)?;
        let requested_after_entry_hash =
            EntryHash::try_from(cbor_read::bytes_exact(&mut decoder, 32)?)
                .map_err(|_| SyncProtocolError::FrameShape)?;
        let start_head_entry_hash = EntryHash::try_from(cbor_read::bytes_exact(&mut decoder, 32)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let objects = decode_object_records(&mut decoder, MAX_READER_PAGE_OBJECTS_V1)?;
        let next_cursor = cbor_read::optional_bytes(&mut decoder)?.map(<[u8]>::to_vec);
        let covered_through_sequence = cbor_read::uint(&mut decoder)?;
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let batch = Self::new(
            chain_id,
            requested_after_sequence,
            requested_after_entry_hash,
            start_head_entry_hash,
            objects,
            next_cursor,
            covered_through_sequence,
        )?;
        if batch.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(batch)
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn requested_after_sequence(&self) -> u64 {
        self.requested_after_sequence
    }

    #[must_use]
    pub const fn requested_after_entry_hash(&self) -> EntryHash {
        self.requested_after_entry_hash
    }

    #[must_use]
    pub const fn start_head_entry_hash(&self) -> EntryHash {
        self.start_head_entry_hash
    }

    #[must_use]
    pub fn objects(&self) -> &[ObjectRecordV1] {
        &self.objects
    }

    #[must_use]
    pub fn next_cursor(&self) -> Option<&[u8]> {
        self.next_cursor.as_deref()
    }

    #[must_use]
    pub const fn covered_through_sequence(&self) -> u64 {
        self.covered_through_sequence
    }
}

impl fmt::Debug for ReaderBatchV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderBatchV1(<bound>)")
    }
}

/// Ein Trust-Ereignis einer Registry-Seite.
#[derive(Clone, Eq, PartialEq)]
pub struct TrustEventRecordV1 {
    registry_version: RegistryVersion,
    object_hash: ObjectHash,
    exact_etb_bytes: Vec<u8>,
}

impl TrustEventRecordV1 {
    #[must_use]
    pub const fn new(
        registry_version: RegistryVersion,
        object_hash: ObjectHash,
        exact_etb_bytes: Vec<u8>,
    ) -> Self {
        Self {
            registry_version,
            object_hash,
            exact_etb_bytes,
        }
    }

    #[must_use]
    pub const fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub fn exact_etb_bytes(&self) -> &[u8] {
        &self.exact_etb_bytes
    }
}

impl fmt::Debug for TrustEventRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustEventRecordV1(<bound>)")
    }
}

/// `trust-registry-response-v1`.
///
/// Die Seite ist nach `registryVersion` AUFSTEIGEND geordnet, weil die
/// Registry eine Kette und keine Menge ist; ihre `objectHash`-Werte sind
/// trotzdem duplikatfrei.
#[derive(Clone, Eq, PartialEq)]
pub struct TrustRegistryResponseV1 {
    requested_after_version: RegistryVersion,
    events: Vec<TrustEventRecordV1>,
    exact: Vec<u8>,
}

impl TrustRegistryResponseV1 {
    pub fn new(
        requested_after_version: RegistryVersion,
        events: Vec<TrustEventRecordV1>,
    ) -> Result<Self, SyncProtocolError> {
        if events.len() > MAX_TRUST_PAGE_EVENTS_V1 {
            return Err(SyncProtocolError::ItemLimit);
        }
        for pair in events.windows(2) {
            match pair[0]
                .registry_version
                .get()
                .cmp(&pair[1].registry_version.get())
            {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => return Err(SyncProtocolError::DuplicateObject),
                core::cmp::Ordering::Greater => return Err(SyncProtocolError::UnsortedObjects),
            }
        }
        let mut object_hashes: Vec<ObjectHash> =
            events.iter().map(TrustEventRecordV1::object_hash).collect();
        object_hashes.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        check_hash_order(object_hashes.into_iter())?;
        let mut exact = Vec::with_capacity(256);
        cbor::array(&mut exact, 4);
        cbor::uint(&mut exact, 1);
        cbor::uint(&mut exact, requested_after_version.get());
        cbor::array(&mut exact, events.len() as u64);
        for event in &events {
            cbor::array(&mut exact, 3);
            cbor::uint(&mut exact, event.registry_version.get());
            cbor::bytes(&mut exact, event.object_hash.as_bytes());
            cbor::bytes(&mut exact, &event.exact_etb_bytes);
        }
        cbor::empty_extension(&mut exact);
        Ok(Self {
            requested_after_version,
            events,
            exact,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 4)?;
        cbor_read::expect_version(&mut decoder)?;
        let requested_after_version = RegistryVersion::new(cbor_read::uint(&mut decoder)?);
        let count = usize::try_from(cbor_read::array(&mut decoder)?)
            .map_err(|_| SyncProtocolError::ItemLimit)?;
        if count > MAX_TRUST_PAGE_EVENTS_V1 {
            return Err(SyncProtocolError::ItemLimit);
        }
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            cbor_read::expect_array(&mut decoder, 3)?;
            let registry_version = RegistryVersion::new(cbor_read::uint(&mut decoder)?);
            let object_hash = ObjectHash::try_from(cbor_read::bytes_exact(&mut decoder, 32)?)
                .map_err(|_| SyncProtocolError::FrameShape)?;
            events.push(TrustEventRecordV1::new(
                registry_version,
                object_hash,
                cbor_read::bytes(&mut decoder)?.to_vec(),
            ));
        }
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let response = Self::new(requested_after_version, events)?;
        if response.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(response)
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub const fn requested_after_version(&self) -> RegistryVersion {
        self.requested_after_version
    }

    #[must_use]
    pub fn events(&self) -> &[TrustEventRecordV1] {
        &self.events
    }
}

impl fmt::Debug for TrustRegistryResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustRegistryResponseV1(<bound>)")
    }
}

/// `grant-list-response-v1`.
#[derive(Clone, Eq, PartialEq)]
pub struct GrantListResponseV1 {
    entry_hash: EntryHash,
    grants: Vec<ObjectRecordV1>,
    exact: Vec<u8>,
}

impl GrantListResponseV1 {
    pub fn new(
        entry_hash: EntryHash,
        grants: Vec<ObjectRecordV1>,
    ) -> Result<Self, SyncProtocolError> {
        check_object_records(&grants, MAX_GRANT_PAGE_OBJECTS_V1)?;
        let mut exact = Vec::with_capacity(256);
        cbor::array(&mut exact, 4);
        cbor::uint(&mut exact, 1);
        cbor::bytes(&mut exact, entry_hash.as_bytes());
        encode_object_records(&mut exact, &grants);
        cbor::empty_extension(&mut exact);
        Ok(Self {
            entry_hash,
            grants,
            exact,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 4)?;
        cbor_read::expect_version(&mut decoder)?;
        let entry_hash = EntryHash::try_from(cbor_read::bytes_exact(&mut decoder, 32)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let grants = decode_object_records(&mut decoder, MAX_GRANT_PAGE_OBJECTS_V1)?;
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let response = Self::new(entry_hash, grants)?;
        if response.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(response)
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    #[must_use]
    pub fn grants(&self) -> &[ObjectRecordV1] {
        &self.grants
    }
}

impl fmt::Debug for GrantListResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GrantListResponseV1(<bound>)")
    }
}

/// `checkpoint-list-response-v1`.
#[derive(Clone, Eq, PartialEq)]
pub struct CheckpointListResponseV1 {
    requested_cursor: Option<Vec<u8>>,
    checkpoints: Vec<ObjectRecordV1>,
    next_cursor: Option<Vec<u8>>,
    exact: Vec<u8>,
}

impl CheckpointListResponseV1 {
    pub fn new(
        requested_cursor: Option<Vec<u8>>,
        checkpoints: Vec<ObjectRecordV1>,
        next_cursor: Option<Vec<u8>>,
    ) -> Result<Self, SyncProtocolError> {
        check_object_records(&checkpoints, MAX_CHECKPOINT_PAGE_OBJECTS_V1)?;
        let mut exact = Vec::with_capacity(256);
        cbor::array(&mut exact, 5);
        cbor::uint(&mut exact, 1);
        encode_optional_bytes(&mut exact, requested_cursor.as_ref());
        encode_object_records(&mut exact, &checkpoints);
        encode_optional_bytes(&mut exact, next_cursor.as_ref());
        cbor::empty_extension(&mut exact);
        Ok(Self {
            requested_cursor,
            checkpoints,
            next_cursor,
            exact,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 5)?;
        cbor_read::expect_version(&mut decoder)?;
        let requested_cursor = cbor_read::optional_bytes(&mut decoder)?.map(<[u8]>::to_vec);
        let checkpoints = decode_object_records(&mut decoder, MAX_CHECKPOINT_PAGE_OBJECTS_V1)?;
        let next_cursor = cbor_read::optional_bytes(&mut decoder)?.map(<[u8]>::to_vec);
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let response = Self::new(requested_cursor, checkpoints, next_cursor)?;
        if response.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(response)
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub fn requested_cursor(&self) -> Option<&[u8]> {
        self.requested_cursor.as_deref()
    }

    #[must_use]
    pub fn checkpoints(&self) -> &[ObjectRecordV1] {
        &self.checkpoints
    }

    #[must_use]
    pub fn next_cursor(&self) -> Option<&[u8]> {
        self.next_cursor.as_deref()
    }
}

impl fmt::Debug for CheckpointListResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointListResponseV1(<bound>)")
    }
}

/// Ein Eintrag des Exportmanifests: Objektart, Hash und Bytelaenge.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ExportObjectRecordV1 {
    object_type: ObjectTypeV1,
    object_hash: ObjectHash,
    byte_length: u64,
}

impl ExportObjectRecordV1 {
    #[must_use]
    pub const fn new(object_type: ObjectTypeV1, object_hash: ObjectHash, byte_length: u64) -> Self {
        Self {
            object_type,
            object_hash,
            byte_length,
        }
    }

    #[must_use]
    pub const fn object_type(&self) -> ObjectTypeV1 {
        self.object_type
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

impl fmt::Debug for ExportObjectRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportObjectRecordV1(<bound>)")
    }
}

/// Die geschlossene Menge der sechs Archivobjektarten als Wire-Code.
const fn object_type_from_code(code: u64) -> Result<ObjectTypeV1, SyncProtocolError> {
    match code {
        1 => Ok(ObjectTypeV1::Entry),
        2 => Ok(ObjectTypeV1::Grant),
        3 => Ok(ObjectTypeV1::Receipt),
        4 => Ok(ObjectTypeV1::Evidence),
        5 => Ok(ObjectTypeV1::Trust),
        6 => Ok(ObjectTypeV1::Destroyed),
        _ => Err(SyncProtocolError::FrameShape),
    }
}

/// `archive-export-manifest-v1` — der Abschluss des Exportstroms.
#[derive(Clone, Eq, PartialEq)]
pub struct ArchiveExportManifestV1 {
    organization_id: OrganizationId,
    sorted_objects: Vec<ExportObjectRecordV1>,
    export_cursor: Option<Vec<u8>>,
    exact: Vec<u8>,
}

impl ArchiveExportManifestV1 {
    pub fn new(
        organization_id: OrganizationId,
        sorted_objects: Vec<ExportObjectRecordV1>,
        export_cursor: Option<Vec<u8>>,
    ) -> Result<Self, SyncProtocolError> {
        if sorted_objects.len() > MAX_READER_PAGE_OBJECTS_V1 {
            return Err(SyncProtocolError::ItemLimit);
        }
        check_hash_order(sorted_objects.iter().map(ExportObjectRecordV1::object_hash))?;
        let mut exact = Vec::with_capacity(256);
        cbor::array(&mut exact, 5);
        cbor::uint(&mut exact, 1);
        cbor::bytes(&mut exact, organization_id.as_bytes());
        cbor::array(&mut exact, sorted_objects.len() as u64);
        for record in &sorted_objects {
            cbor::array(&mut exact, 3);
            cbor::uint(&mut exact, record.object_type.code());
            cbor::bytes(&mut exact, record.object_hash.as_bytes());
            cbor::uint(&mut exact, record.byte_length);
        }
        encode_optional_bytes(&mut exact, export_cursor.as_ref());
        cbor::empty_extension(&mut exact);
        Ok(Self {
            organization_id,
            sorted_objects,
            export_cursor,
            exact,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 5)?;
        cbor_read::expect_version(&mut decoder)?;
        let organization_id = OrganizationId::try_from(cbor_read::bytes_exact(&mut decoder, 16)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let count = usize::try_from(cbor_read::array(&mut decoder)?)
            .map_err(|_| SyncProtocolError::ItemLimit)?;
        if count > MAX_READER_PAGE_OBJECTS_V1 {
            return Err(SyncProtocolError::ItemLimit);
        }
        let mut sorted_objects = Vec::with_capacity(count);
        for _ in 0..count {
            cbor_read::expect_array(&mut decoder, 3)?;
            let object_type = object_type_from_code(cbor_read::uint(&mut decoder)?)?;
            let object_hash = ObjectHash::try_from(cbor_read::bytes_exact(&mut decoder, 32)?)
                .map_err(|_| SyncProtocolError::FrameShape)?;
            sorted_objects.push(ExportObjectRecordV1::new(
                object_type,
                object_hash,
                cbor_read::uint(&mut decoder)?,
            ));
        }
        let export_cursor = cbor_read::optional_bytes(&mut decoder)?.map(<[u8]>::to_vec);
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let manifest = Self::new(organization_id, sorted_objects, export_cursor)?;
        if manifest.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(manifest)
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub fn sorted_objects(&self) -> &[ExportObjectRecordV1] {
        &self.sorted_objects
    }

    #[must_use]
    pub fn export_cursor(&self) -> Option<&[u8]> {
        self.export_cursor.as_deref()
    }
}

impl fmt::Debug for ArchiveExportManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArchiveExportManifestV1(<bound>)")
    }
}

/// Die Domaenenkonstante des technischen Cursors.
///
/// Sie ist ADDITIV: die 24 eingefrorenen Domaenenkonstanten unter
/// `vectors/crypto/suite-1/domain-string/` kennen sie nicht, und keine von
/// ihnen wird durch sie beruehrt. Der Serverschluessel traegt damit zwei
/// getrennte Zwecke (`design.md`:221 nennt ihn bereits fuer Receipts UND
/// Checkpoints); die Zweckbindung laeuft ueber die Domaene, nicht ueber eine
/// achte `CertificateCapability`.
pub const TECHNICAL_CURSOR_DOMAIN_V1: &[u8] = b"EINSATZARCHIV-TECHNICAL-CURSOR-v1";

/// Der domaenengetrennte Digest ueber die exakten Cursor-Core-Bytes.
#[must_use]
pub fn technical_cursor_digest(exact_core: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(TECHNICAL_CURSOR_DOMAIN_V1);
    hasher.update(exact_core);
    let digest: [u8; 32] = hasher.finalize().into();
    Hash32::try_from(digest.as_slice()).expect("SHA-256 always emits exactly 32 bytes")
}

/// Der Serverschluessel als Signierer des technischen Cursors.
///
/// Die Ablage des Schluessels und die COSE-Huelle gehoeren dem
/// Serverschluessel-Port; diese Crate kennt nur den Digest und die Bytes, die
/// zurueckkommen.
pub trait TechnicalCursorSigner {
    fn sign_technical_cursor_digest(&self, digest: Hash32) -> Result<Vec<u8>, CryptoError>;
}

/// Die Gegenseite: sie prueft dieselbe Signatur ueber denselben Digest.
pub trait TechnicalCursorVerifier {
    fn verify_technical_cursor_digest(
        &self,
        digest: Hash32,
        signature: &[u8],
    ) -> Result<(), CryptoError>;
}

/// Die Felder eines technischen Cursors.
///
/// Klienten lesen ihn NICHT und vertrauen ihm nicht; er traegt keine fachliche
/// Angabe, sondern ausschliesslich technische Blaetterposition, Gueltigkeit und
/// Bindung.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TechnicalCursorFieldsV1 {
    pub organization_id: OrganizationId,
    pub endpoint: EndpointV1,
    pub chain_id: Option<ChainId>,
    pub start_head_entry_hash: Option<EntryHash>,
    pub last_technical_index: u64,
    pub expires_at: UnixMillis,
    pub nonce: [u8; 16],
}

impl fmt::Debug for TechnicalCursorFieldsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TechnicalCursorFieldsV1(<bound>)")
    }
}

/// Ein ausgestellter oder geoeffneter technischer Cursor.
#[derive(Clone, Eq, PartialEq)]
pub struct TechnicalCursorV1 {
    fields: TechnicalCursorFieldsV1,
    token: Vec<u8>,
}

impl TechnicalCursorV1 {
    /// Stellt einen Cursor aus: Core kodieren, Digest bilden, signieren
    /// lassen, beides zu `[core, signature]` rahmen.
    pub fn issue(
        fields: &TechnicalCursorFieldsV1,
        signer: &dyn TechnicalCursorSigner,
    ) -> Result<Self, SyncProtocolError> {
        let core = encode_cursor_core(fields);
        let signature = signer.sign_technical_cursor_digest(technical_cursor_digest(&core))?;
        let mut token = Vec::with_capacity(core.len() + signature.len() + 8);
        cbor::array(&mut token, 2);
        token.extend_from_slice(&core);
        cbor::bytes(&mut token, &signature);
        Ok(Self {
            fields: *fields,
            token,
        })
    }

    /// Oeffnet einen Cursor: Form, Signatur, Gueltigkeitsfenster und Bindung —
    /// in dieser Reihenfolge, damit ein fremder Cursor nicht ueber sein
    /// Ablaufdatum verraten wird.
    pub fn open(
        token: &[u8],
        verifier: &dyn TechnicalCursorVerifier,
        now: UnixMillis,
        endpoint: EndpointV1,
        organization_id: OrganizationId,
    ) -> Result<Self, SyncProtocolError> {
        let (fields, core, signature) = decode_cursor(token)?;
        verifier
            .verify_technical_cursor_digest(technical_cursor_digest(core), signature)
            .map_err(|_| SyncProtocolError::CursorInvalid)?;
        if now.get() > fields.expires_at.get() {
            return Err(SyncProtocolError::CursorExpired);
        }
        if fields.endpoint != endpoint || fields.organization_id != organization_id {
            return Err(SyncProtocolError::CursorScope);
        }
        Ok(Self {
            fields,
            token: token.to_vec(),
        })
    }

    /// Die opaken Bytes, die der Klient unveraendert zurueckschickt.
    #[must_use]
    pub fn token_bytes(&self) -> &[u8] {
        &self.token
    }

    #[must_use]
    pub const fn fields(&self) -> &TechnicalCursorFieldsV1 {
        &self.fields
    }

    #[must_use]
    pub const fn last_technical_index(&self) -> u64 {
        self.fields.last_technical_index
    }
}

impl fmt::Debug for TechnicalCursorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TechnicalCursorV1(<bound>)")
    }
}

fn encode_cursor_core(fields: &TechnicalCursorFieldsV1) -> Vec<u8> {
    let mut core = Vec::with_capacity(128);
    cbor::array(&mut core, 8);
    cbor::uint(&mut core, 1);
    cbor::bytes(&mut core, fields.organization_id.as_bytes());
    cbor::uint(&mut core, fields.endpoint.code());
    match &fields.chain_id {
        Some(chain_id) => cbor::bytes(&mut core, chain_id.as_bytes()),
        None => cbor::null(&mut core),
    }
    match &fields.start_head_entry_hash {
        Some(hash) => cbor::bytes(&mut core, hash.as_bytes()),
        None => cbor::null(&mut core),
    }
    cbor::uint(&mut core, fields.last_technical_index);
    cbor::int(&mut core, fields.expires_at.get());
    cbor::bytes(&mut core, &fields.nonce);
    core
}

type DecodedCursor<'a> = (TechnicalCursorFieldsV1, &'a [u8], &'a [u8]);

fn decode_cursor(token: &[u8]) -> Result<DecodedCursor<'_>, SyncProtocolError> {
    ea_cbor::validate(token, PROTOCOL_PARSER_LIMITS_V1)
        .map_err(|_| SyncProtocolError::CursorInvalid)?;
    let mut decoder = Decoder::new(token);
    cursor_shape(cbor_read::expect_array(&mut decoder, 2))?;
    let core = cursor_shape(cbor_read::exact_item(token, &mut decoder))?;
    let signature = cursor_shape(cbor_read::bytes(&mut decoder))?;
    cursor_shape(cbor_read::finish(&decoder, token))?;

    let mut core_decoder = Decoder::new(core);
    cursor_shape(cbor_read::expect_array(&mut core_decoder, 8))?;
    cursor_shape(cbor_read::expect_version(&mut core_decoder))?;
    let organization_id =
        OrganizationId::try_from(cursor_shape(cbor_read::bytes_exact(&mut core_decoder, 16))?)
            .map_err(|_| SyncProtocolError::CursorInvalid)?;
    let endpoint_code = cursor_shape(cbor_read::uint(&mut core_decoder))?;
    let endpoint = EndpointV1::ALL
        .into_iter()
        .find(|endpoint| endpoint.code() == endpoint_code)
        .ok_or(SyncProtocolError::CursorInvalid)?;
    let chain_id = cursor_shape(cbor_read::optional_bytes_exact(&mut core_decoder, 16))?
        .map(ChainId::try_from)
        .transpose()
        .map_err(|_| SyncProtocolError::CursorInvalid)?;
    let start_head_entry_hash =
        cursor_shape(cbor_read::optional_bytes_exact(&mut core_decoder, 32))?
            .map(EntryHash::try_from)
            .transpose()
            .map_err(|_| SyncProtocolError::CursorInvalid)?;
    let last_technical_index = cursor_shape(cbor_read::uint(&mut core_decoder))?;
    let expires_at = UnixMillis::new(cursor_shape(cbor_read::int(&mut core_decoder))?);
    let nonce: [u8; 16] = cursor_shape(cbor_read::bytes_exact(&mut core_decoder, 16))?
        .try_into()
        .map_err(|_| SyncProtocolError::CursorInvalid)?;
    cursor_shape(cbor_read::finish(&core_decoder, core))?;

    Ok((
        TechnicalCursorFieldsV1 {
            organization_id,
            endpoint,
            chain_id,
            start_head_entry_hash,
            last_technical_index,
            expires_at,
            nonce,
        },
        core,
        signature,
    ))
}

/// Ein unlesbarer Cursor ist fuer den Klienten IMMER derselbe Befund: er darf
/// den Token ohnehin nicht deuten, also verraet der Code nichts ueber die
/// Stelle, an der die Form brach.
fn cursor_shape<T>(result: Result<T, SyncProtocolError>) -> Result<T, SyncProtocolError> {
    result.map_err(|_| SyncProtocolError::CursorInvalid)
}

/// Die fuenf Zustaende von `destruction-state-v1`
/// (`schemas/archive/v1/trust.cddl`).
///
/// Der Wert bleibt eine Zahl statt einer eigenen Aufzaehlung, weil
/// `DestructionTransitionFieldsV1` in `ea-format` ihn ebenfalls als `u8`
/// fuehrt: eine zweite geschlossene Menge waere eine zweite Quelle fuer
/// denselben Wertebereich.
pub const MAX_DESTRUCTION_STATE_V1: u8 = 4;

/// `destruction-status-response-v1`.
#[derive(Clone, Eq, PartialEq)]
pub struct DestructionStatusResponseV1 {
    destruction_id: DestructionId,
    state: u8,
    authorization_object_hash: ObjectHash,
    transitions: Vec<ObjectRecordV1>,
    attestations: Vec<ObjectRecordV1>,
    exact: Vec<u8>,
}

impl DestructionStatusResponseV1 {
    pub fn new(
        destruction_id: DestructionId,
        state: u8,
        authorization_object_hash: ObjectHash,
        transitions: Vec<ObjectRecordV1>,
        attestations: Vec<ObjectRecordV1>,
    ) -> Result<Self, SyncProtocolError> {
        if state > MAX_DESTRUCTION_STATE_V1 {
            return Err(SyncProtocolError::FrameShape);
        }
        check_object_records(&transitions, MAX_READER_PAGE_OBJECTS_V1)?;
        check_object_records(&attestations, MAX_READER_PAGE_OBJECTS_V1)?;
        let mut exact = Vec::with_capacity(256);
        cbor::array(&mut exact, 7);
        cbor::uint(&mut exact, 1);
        cbor::bytes(&mut exact, destruction_id.as_bytes());
        cbor::uint(&mut exact, u64::from(state));
        cbor::bytes(&mut exact, authorization_object_hash.as_bytes());
        encode_object_records(&mut exact, &transitions);
        encode_object_records(&mut exact, &attestations);
        cbor::empty_extension(&mut exact);
        Ok(Self {
            destruction_id,
            state,
            authorization_object_hash,
            transitions,
            attestations,
            exact,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 7)?;
        cbor_read::expect_version(&mut decoder)?;
        let destruction_id = DestructionId::try_from(cbor_read::bytes_exact(&mut decoder, 16)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let state = u8::try_from(cbor_read::uint(&mut decoder)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let authorization_object_hash =
            ObjectHash::try_from(cbor_read::bytes_exact(&mut decoder, 32)?)
                .map_err(|_| SyncProtocolError::FrameShape)?;
        let transitions = decode_object_records(&mut decoder, MAX_READER_PAGE_OBJECTS_V1)?;
        let attestations = decode_object_records(&mut decoder, MAX_READER_PAGE_OBJECTS_V1)?;
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let response = Self::new(
            destruction_id,
            state,
            authorization_object_hash,
            transitions,
            attestations,
        )?;
        if response.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(response)
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub const fn destruction_id(&self) -> DestructionId {
        self.destruction_id
    }

    #[must_use]
    pub const fn state(&self) -> u8 {
        self.state
    }

    #[must_use]
    pub const fn authorization_object_hash(&self) -> ObjectHash {
        self.authorization_object_hash
    }

    #[must_use]
    pub fn transitions(&self) -> &[ObjectRecordV1] {
        &self.transitions
    }

    #[must_use]
    pub fn attestations(&self) -> &[ObjectRecordV1] {
        &self.attestations
    }
}

impl fmt::Debug for DestructionStatusResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DestructionStatusResponseV1(<bound>)")
    }
}
