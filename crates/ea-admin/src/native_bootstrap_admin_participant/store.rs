//! Private native-key-bound opener and immutable-input SQLCipher journal.
use super::*;
use ea_key_provider::{KeyHandle, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreError, StoreTransaction, StoreValue};
use std::{fs, path::PathBuf};
use zeroize::{Zeroize as _, Zeroizing};

const MAX_JOURNAL: usize = 4 * 1024 * 1024;
const SELECT: &str = "SELECT exact_journal FROM native_bootstrap_participant WHERE singleton=1";

pub(super) struct Journal {
    pub state: Vec<u8>,
    pub installation: Hash32,
    pub account: Hash32,
    pub identity: BootstrapAdminParticipantIdentity,
    pub commitment: Hash32,
    pub admin: Option<CanonicalPublicCoseKey>,
    pub operator: Option<CanonicalPublicCoseKey>,
}
impl Journal {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, OperatorLifecycleError> {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut encoder = minicbor::Encoder::new(&mut *bytes);
        let phase = if self.operator.is_some() {
            2
        } else if self.admin.is_some() {
            1
        } else {
            0
        };
        encoder
            .array(14)
            .and_then(|e| e.u8(1))
            .and_then(|e| e.u8(phase))
            .and_then(|e| e.bytes(&self.state))
            .and_then(|e| e.bytes(self.installation.as_bytes()))
            .and_then(|e| e.bytes(self.account.as_bytes()))
            .and_then(|e| e.bytes(self.identity.device.as_bytes()))
            .and_then(|e| e.bytes(self.identity.subject.as_bytes()))
            .and_then(|e| e.str(self.identity.name.as_str()))
            .and_then(|e| e.str(self.identity.function.as_str()))
            .and_then(|e| e.bytes(&*self.identity.salt))
            .and_then(|e| e.bytes(self.commitment.as_bytes()))
            .and_then(|e| {
                e.bytes(
                    &self
                        .admin
                        .as_ref()
                        .map(CanonicalPublicCoseKey::to_deterministic_cbor)
                        .unwrap_or_default(),
                )
            })
            .and_then(|e| {
                e.bytes(
                    &self
                        .operator
                        .as_ref()
                        .map(CanonicalPublicCoseKey::to_deterministic_cbor)
                        .unwrap_or_default(),
                )
            })
            // Handles are fixed by v1: OS provider, this installation,
            // Admin/WriterSigningKey and OperatorInstanceKey. No caller override.
            .and_then(|e| e.u8(1))
            .map_err(|_| OperatorLifecycleError::JournalConflict)?;
        if bytes.len() > MAX_JOURNAL {
            return Err(OperatorLifecycleError::JournalConflict);
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, OperatorLifecycleError> {
        let bad = || OperatorLifecycleError::JournalConflict;
        let mut decoder = minicbor::Decoder::new(bytes);
        if decoder.array().map_err(|_| bad())? != Some(14) || decoder.u8().map_err(|_| bad())? != 1
        {
            return Err(bad());
        }
        let phase = decoder.u8().map_err(|_| bad())?;
        let state = decoder.bytes().map_err(|_| bad())?.to_vec();
        let installation =
            Hash32::try_from(decoder.bytes().map_err(|_| bad())?).map_err(|_| bad())?;
        let account = Hash32::try_from(decoder.bytes().map_err(|_| bad())?).map_err(|_| bad())?;
        let device = DeviceId::try_from(decoder.bytes().map_err(|_| bad())?).map_err(|_| bad())?;
        let subject =
            OperatorSubjectId::try_from(decoder.bytes().map_err(|_| bad())?).map_err(|_| bad())?;
        let name = SecretText::from(decoder.str().map_err(|_| bad())?);
        let function = SecretText::from(decoder.str().map_err(|_| bad())?);
        let salt = Zeroizing::new(
            <[u8; 32]>::try_from(decoder.bytes().map_err(|_| bad())?).map_err(|_| bad())?,
        );
        let commitment =
            Hash32::try_from(decoder.bytes().map_err(|_| bad())?).map_err(|_| bad())?;
        let admin = decode_key(decoder.bytes().map_err(|_| bad())?)?;
        let operator = decode_key(decoder.bytes().map_err(|_| bad())?)?;
        if decoder.u8().map_err(|_| bad())? != 1
            || decoder.position() != bytes.len()
            || phase
                != if operator.is_some() {
                    2
                } else if admin.is_some() {
                    1
                } else {
                    0
                }
            || operator.is_some() && admin.is_none()
        {
            return Err(bad());
        }
        let (canonical_name, canonical_function) =
            OperatorSnapshotV1::normalize_profile_texts(name.as_str(), function.as_str());
        if name != canonical_name || function != canonical_function {
            return Err(bad());
        }
        let journal = Self {
            state,
            installation,
            account,
            identity: BootstrapAdminParticipantIdentity {
                device,
                subject,
                name,
                function,
                salt,
            },
            commitment,
            admin,
            operator,
        };
        if journal.encode()?.as_slice() != bytes {
            return Err(bad());
        }
        Ok(journal)
    }
    pub fn same_inputs(&self, other: &Self) -> bool {
        self.state == other.state
            && self.installation == other.installation
            && self.account == other.account
            && self.identity.device == other.identity.device
            && self.identity.subject == other.identity.subject
            && self.identity.name == other.identity.name
            && self.identity.function == other.identity.function
            && self.identity.salt == other.identity.salt
            && self.commitment == other.commitment
    }
}
fn decode_key(bytes: &[u8]) -> Result<Option<CanonicalPublicCoseKey>, OperatorLifecycleError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let key = CanonicalPublicCoseKey::from_deterministic_cbor(bytes)
        .map_err(|_| OperatorLifecycleError::JournalConflict)?;
    if !matches!(key, CanonicalPublicCoseKey::Ed25519(_)) {
        return Err(OperatorLifecycleError::JournalConflict);
    }
    Ok(Some(key))
}

/// Only this internal opener constructs the store; it retains the exact native
/// Arc and database handle. No public ArcDB-to-provenance conversion exists.
pub(super) struct NativeBootstrapParticipantStore {
    database: EncryptedDatabase,
    native: Arc<NativeOperatorProvider>,
    key: KeyHandle,
    path: PathBuf,
    metadata: fs::Metadata,
}
impl NativeBootstrapParticipantStore {
    pub fn open(
        path: &Path,
        native: &Arc<NativeOperatorProvider>,
    ) -> Result<Self, OperatorLifecycleError> {
        let metadata = shape(path)?;
        let provider = native.signing_provider(crate::native_provider::NativeSigningSlot::Admin);
        let key = provider.handle(SecretPurpose::LocalDatabaseKey);
        let database = EncryptedDatabase::open_existing(path, &provider, &key)?;
        let store = Self {
            database,
            native: Arc::clone(native),
            key,
            path: path.into(),
            metadata,
        };
        store.ensure_path()?;
        Ok(store)
    }
    pub fn ensure_path(&self) -> Result<(), OperatorLifecycleError> {
        let current = shape(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if self.metadata.dev() != current.dev() || self.metadata.ino() != current.ino() {
                return Err(OperatorLifecycleError::JournalConflict);
            }
        }
        #[cfg(not(unix))]
        let _ = (&self.metadata, current);
        Ok(())
    }
    pub fn transaction<R>(
        &self,
        work: impl FnOnce(&StoreTransaction<'_>) -> Result<R, OperatorLifecycleError>,
    ) -> Result<R, OperatorLifecycleError> {
        self.ensure_path()?;
        self.database.transaction(work)
    }
    pub fn confirm(&self, expected: &[u8]) -> Result<(), OperatorLifecycleError> {
        self.ensure_path()?;
        let provider = self
            .native
            .signing_provider(crate::native_provider::NativeSigningSlot::Admin);
        let reopened = EncryptedDatabase::open_existing(&self.path, &provider, &self.key)?;
        self.ensure_path()?;
        let actual =
            reopened.transaction(|tx| read(tx)?.ok_or(OperatorLifecycleError::JournalConflict))?;
        if actual.encode()?.as_slice() != expected {
            return Err(OperatorLifecycleError::JournalConflict);
        }
        Ok(())
    }
}
fn shape(path: &Path) -> Result<fs::Metadata, OperatorLifecycleError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| OperatorLifecycleError::Store(StoreError::Database))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(OperatorLifecycleError::Store(StoreError::Shape));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(OperatorLifecycleError::Store(StoreError::Shape));
        }
    }
    Ok(metadata)
}
pub(super) fn read(tx: &StoreTransaction<'_>) -> Result<Option<Journal>, OperatorLifecycleError> {
    let Some(row) = tx.query_row(
        "SELECT length(exact_journal) FROM native_bootstrap_participant WHERE singleton=1",
        &[],
    )?
    else {
        return Ok(None);
    };
    if !(1..=MAX_JOURNAL as i64).contains(&row.integer(0)?) {
        return Err(OperatorLifecycleError::JournalConflict);
    }
    let bytes = tx
        .query_row(SELECT, &[])?
        .ok_or(OperatorLifecycleError::JournalConflict)?
        .into_secret_blob()?;
    bytes.with_exposed(Journal::decode).map(Some)
}
pub(super) fn insert(
    tx: &StoreTransaction<'_>,
    journal: &Journal,
) -> Result<(), OperatorLifecycleError> {
    write(
        tx,
        "INSERT INTO native_bootstrap_participant(singleton, exact_journal) VALUES(1,?1)",
        journal,
        None,
    )
}
pub(super) fn update(
    tx: &StoreTransaction<'_>,
    journal: &Journal,
    previous: &[u8],
) -> Result<(), OperatorLifecycleError> {
    write(
        tx,
        "UPDATE native_bootstrap_participant SET exact_journal=?1 WHERE singleton=1 AND exact_journal=?2",
        journal,
        Some(previous),
    )
}
fn write(
    tx: &StoreTransaction<'_>,
    sql: &str,
    journal: &Journal,
    previous: Option<&[u8]>,
) -> Result<(), OperatorLifecycleError> {
    let encoded = journal.encode()?;
    let mut params = vec![StoreValue::Blob(encoded.to_vec())];
    if let Some(previous) = previous {
        params.push(StoreValue::Blob(previous.to_vec()));
    }
    let result = tx.execute(sql, &params);
    for value in &mut params {
        if let StoreValue::Blob(bytes) = value {
            bytes.zeroize();
        }
    }
    if result? != 1 {
        return Err(OperatorLifecycleError::JournalConflict);
    }
    Ok(())
}
