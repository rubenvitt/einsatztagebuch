//! Durable exact local commit bytes. This store is not archive, signer, or
//! publication authority; the normal verifier and Writer remain its consumers.

use crate::{AtRestEncryptedStoreV1, controlled_network::AT_REST_PROBE_RELATIVE_V1};
use ea_archive::{ArchiveBackendError, ArchivePath, LAYOUT_PATHS_V1};
use ea_local_store::{EncryptedDatabase, StoreError, StoreTransaction, StoreValue};
use ea_types::Hash32;
use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
    sync::Arc,
};

pub(crate) struct StorageFailure(pub(crate) ArchiveBackendError);
impl From<StoreError> for StorageFailure {
    fn from(_: StoreError) -> Self {
        Self(ArchiveBackendError::Io)
    }
}

pub struct SqliteCommitStore {
    database: Arc<EncryptedDatabase>,
    namespace: Hash32,
}
impl SqliteCommitStore {
    /// `namespace` identifies one archive/anchor/profile combination. Limits
    /// are pinned once and cannot be expanded by a second connection.
    pub fn new(
        database: Arc<EncryptedDatabase>,
        namespace: Hash32,
        maximum_objects: u64,
        maximum_bytes: u64,
    ) -> Result<Self, ArchiveBackendError> {
        let objects = i64::try_from(maximum_objects)
            .ok()
            .filter(|n| *n > 0)
            .ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
        let bytes = i64::try_from(maximum_bytes)
            .ok()
            .filter(|n| *n > 0)
            .ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
        if !database
            .has_migration(16)
            .map_err(|_| ArchiveBackendError::Io)?
        {
            return Err(ArchiveBackendError::MissingLocalCommitComponent);
        }
        database.transaction::<_, StorageFailure>(|tx| {
            let key = StoreValue::Blob(namespace.as_bytes().to_vec());
            if let Some(row) = tx.query_row("SELECT object_limit,byte_limit FROM local_commit_scope WHERE namespace=?1", std::slice::from_ref(&key))? {
                if row.integer(0)? != objects || row.integer(1)? != bytes {
                    return Err(StorageFailure(ArchiveBackendError::ByteConflict));
                }
            } else {
                tx.execute("INSERT INTO local_commit_scope(namespace,object_limit,byte_limit) VALUES(?1,?2,?3)", &[key, StoreValue::Integer(objects), StoreValue::Integer(bytes)])?;
            }
            Ok(())
        }).map_err(|error| error.0)?;
        Ok(Self {
            database,
            namespace,
        })
    }

    /// Opens only an already registered immutable scope. Unlike `new`, this
    /// method never creates a missing scope or changes its exact limits.
    pub fn open_existing(
        database: Arc<EncryptedDatabase>,
        namespace: Hash32,
        maximum_objects: u64,
        maximum_bytes: u64,
    ) -> Result<Self, ArchiveBackendError> {
        let objects = i64::try_from(maximum_objects)
            .ok()
            .filter(|n| *n > 0)
            .ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
        let bytes = i64::try_from(maximum_bytes)
            .ok()
            .filter(|n| *n > 0)
            .ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
        if !database
            .has_migration(16)
            .map_err(|_| ArchiveBackendError::Io)?
        {
            return Err(ArchiveBackendError::MissingLocalCommitComponent);
        }
        let row = database
            .query_row(
                "SELECT object_limit,byte_limit FROM local_commit_scope WHERE namespace=?1",
                &[StoreValue::Blob(namespace.as_bytes().to_vec())],
            )
            .map_err(|_| ArchiveBackendError::Io)?
            .ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
        if row.integer(0).map_err(|_| ArchiveBackendError::Io)? != objects
            || row.integer(1).map_err(|_| ArchiveBackendError::Io)? != bytes
        {
            return Err(ArchiveBackendError::ByteConflict);
        }
        Ok(Self {
            database,
            namespace,
        })
    }

    pub(crate) fn database(&self) -> &Arc<EncryptedDatabase> {
        &self.database
    }
    pub(crate) fn namespace(&self) -> Hash32 {
        self.namespace
    }
    pub(crate) fn params(&self, relative: &str) -> Result<Vec<StoreValue>, ArchiveBackendError> {
        validate_path(relative)?;
        Ok(vec![
            StoreValue::Blob(self.namespace.as_bytes().to_vec()),
            StoreValue::Text(relative.to_owned()),
        ])
    }

    pub fn read_exact(&self, relative: &str) -> Result<Option<Vec<u8>>, ArchiveBackendError> {
        let params = self.params(relative)?;
        let row = if relative == AT_REST_PROBE_RELATIVE_V1 {
            self.database.query_row("SELECT probe_bytes FROM local_commit_probe WHERE namespace=?1", &params[..1])
        } else {
            self.database.query_row("SELECT exact_bytes FROM local_commit_object WHERE namespace=?1 AND relative_path=?2", &params)
        }.map_err(|_| ArchiveBackendError::Io)?;
        row.map(|row| {
            row.blob(0)
                .map(ToOwned::to_owned)
                .map_err(|_| ArchiveBackendError::Io)
        })
        .transpose()
    }

    /// Error-preserving removal for actual completion/recovery consumers. The
    /// legacy measurement trait's `remove` cannot return a failure.
    pub fn remove_exact(&self, relative: &str) -> Result<(), ArchiveBackendError> {
        let params = self.params(relative)?;
        let result = if relative == AT_REST_PROBE_RELATIVE_V1 {
            self.database.execute(
                "DELETE FROM local_commit_probe WHERE namespace=?1",
                &params[..1],
            )
        } else {
            self.database.execute(
                "DELETE FROM local_commit_object WHERE namespace=?1 AND relative_path=?2",
                &params,
            )
        };
        result.map(|_| ()).map_err(|_| ArchiveBackendError::Io)
    }

    fn physical_files(&self) -> [PathBuf; 2] {
        let main = self.database.path().to_path_buf();
        let mut wal = main.as_os_str().to_os_string();
        wal.push("-wal");
        [main, PathBuf::from(wal)]
    }
}
impl AtRestEncryptedStoreV1 for SqliteCommitStore {
    fn put(&self, relative: &str, bytes: &[u8]) -> Result<(), ArchiveBackendError> {
        self.database
            .transaction::<_, StorageFailure>(|tx| self.put_in(tx, relative, bytes))
            .map_err(|error| error.0)
    }

    fn get(&self, relative: &str) -> Option<Vec<u8>> {
        self.read_exact(relative).ok().flatten()
    }

    fn bytes_at_rest(&self, relative: &str) -> Option<Vec<u8>> {
        self.read_exact(relative).ok()??;
        self.physical_bytes()
    }

    fn at_rest_contains(&self, relative: &str, needle: &[u8]) -> Option<bool> {
        self.read_exact(relative).ok()??;
        self.physical_contains(needle)
    }

    fn remove(&self, relative: &str) {
        let _ = self.remove_exact(relative);
    }
}

impl SqliteCommitStore {
    pub(crate) fn put_in(
        &self,
        tx: &StoreTransaction<'_>,
        relative: &str,
        bytes: &[u8],
    ) -> Result<(), StorageFailure> {
        let mut params = self.params(relative).map_err(StorageFailure)?;
        let probe = relative == AT_REST_PROBE_RELATIVE_V1;
        if probe && bytes.len() > 65_536 {
            return Err(StorageFailure(ArchiveBackendError::Path));
        }
        let row = if probe {
            tx.query_row(
                "SELECT probe_bytes FROM local_commit_probe WHERE namespace=?1",
                &params[..1],
            )?
        } else {
            tx.query_row("SELECT exact_bytes FROM local_commit_object WHERE namespace=?1 AND relative_path=?2", &params)?
        };
        if let Some(row) = row {
            return if row.blob(0)? == bytes {
                Ok(())
            } else {
                Err(StorageFailure(ArchiveBackendError::ByteConflict))
            };
        }
        if probe {
            tx.execute(
                "INSERT INTO local_commit_probe(namespace,probe_bytes) VALUES(?1,?2)",
                &[params[0].clone(), StoreValue::Blob(bytes.to_vec())],
            )?;
            return Ok(());
        }
        let limits = tx
            .query_row(
                "SELECT object_limit,byte_limit FROM local_commit_scope WHERE namespace=?1",
                &params[..1],
            )?
            .ok_or(StoreError::Shape)?;
        let used = tx.query_row("SELECT count(*),coalesce(sum(length(exact_bytes)),0) FROM local_commit_object WHERE namespace=?1", &params[..1])?.ok_or(StoreError::Shape)?;
        let length = i64::try_from(bytes.len())
            .map_err(|_| StorageFailure(ArchiveBackendError::PendingPublication))?;
        let maximum_bytes = limits.integer(1)?;
        if used.integer(0)? >= limits.integer(0)?
            || used
                .integer(1)?
                .checked_add(length)
                .is_none_or(|total| total > maximum_bytes)
        {
            return Err(StorageFailure(ArchiveBackendError::PendingPublication));
        }
        params.push(StoreValue::Blob(bytes.to_vec()));
        tx.execute(
            "INSERT INTO local_commit_object(namespace,relative_path,exact_bytes) VALUES(?1,?2,?3)",
            &params,
        )?;
        Ok(())
    }
    fn physical_bytes(&self) -> Option<Vec<u8>> {
        // The compatibility diagnostic is bounded. Production admission uses
        // the streaming search below and works for arbitrarily large databases.
        let mut output = Vec::new();
        for (index, path) in self.physical_files().iter().enumerate() {
            let mut file = match File::open(path) {
                Ok(file) => file,
                Err(error) if index == 1 && error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return None,
            };
            let len = usize::try_from(file.metadata().ok()?.len()).ok()?;
            if output.len().checked_add(len)? > 64 * 1024 * 1024 {
                return None;
            }
            output.try_reserve(len).ok()?;
            file.read_to_end(&mut output).ok()?;
        }
        (!output.is_empty()).then_some(output)
    }

    fn physical_contains(&self, needle: &[u8]) -> Option<bool> {
        if needle.is_empty() || needle.len() > 65_536 {
            return None;
        }
        let mut observed = 0_u64;
        for (index, path) in self.physical_files().iter().enumerate() {
            let file = match File::open(path) {
                Ok(file) => file,
                Err(error) if index == 1 && error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return None,
            };
            let (found, count) = contains_stream(file, needle).ok()?;
            observed = observed.checked_add(count)?;
            if found {
                return Some(true);
            }
        }
        (observed > 0).then_some(false)
    }
}

fn validate_path(relative: &str) -> Result<(), ArchiveBackendError> {
    if relative == AT_REST_PROBE_RELATIVE_V1 {
        return Ok(());
    }
    if relative.len() > 4096 || relative.contains('\0') {
        return Err(ArchiveBackendError::Path);
    }
    if ArchivePath::at_layout_file(relative).is_ok() {
        return Ok(());
    }
    for directory in LAYOUT_PATHS_V1.iter().filter(|path| path.ends_with('/')) {
        if let Some(suffix) = relative.strip_prefix(directory) {
            return ArchivePath::in_dir(directory, suffix).map(|_| ());
        }
    }
    Err(ArchiveBackendError::Path)
}

fn contains_stream(mut reader: impl Read, needle: &[u8]) -> io::Result<(bool, u64)> {
    let mut buffer = vec![0; 65_536 + needle.len() - 1];
    let mut retained = 0;
    let mut observed = 0;
    loop {
        let count = reader.read(&mut buffer[retained..])?;
        if count == 0 {
            return Ok((false, observed));
        }
        observed += count as u64;
        let available = retained + count;
        if buffer[..available]
            .windows(needle.len())
            .any(|part| part == needle)
        {
            return Ok((true, observed));
        }
        retained = (needle.len() - 1).min(available);
        buffer.copy_within(available - retained..available, 0);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn physical_canary_search_covers_read_boundaries() {
        let needle = b"boundary-canary";
        let mut bytes = vec![0; 65_530];
        bytes.extend_from_slice(needle);
        bytes.extend_from_slice(&[0; 50]);
        assert!(super::contains_stream(bytes.as_slice(), needle).unwrap().0);
        assert!(
            !super::contains_stream(bytes.as_slice(), b"absent")
                .unwrap()
                .0
        );
    }
}
