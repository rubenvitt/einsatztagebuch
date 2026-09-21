//! Local archive primitives on the same SQLCipher commit database.
use crate::{SqliteCommitStore, sqlcipher_commit::StorageFailure};
use ea_archive::{
    ArchiveBackend, ArchiveBackendError, ArchiveBlob, ArchiveError, ArchivePath, ArchiveSource,
    LAYOUT_PATHS_V1, MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1, WriterLock,
    WriterLockRelease,
};
use ea_format::ExactObjectBytes;
use ea_local_store::{StoreError, StoreTransaction, StoreValue};
use std::{
    fs::{self, File, OpenOptions},
    path::PathBuf,
    sync::Arc,
};

/// Die drei SQLCipher-Zusagen aus EA-CNA-WRT-4, jede einzeln ausgewiesen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlcipherCapabilityReportV1 {
    durable_wal_full: bool,
    physical_flush: bool,
    exclusive_writer_lock: bool,
}
impl SqlcipherCapabilityReportV1 {
    /// Nur wenn alle drei Zusagen gemessen wurden.
    #[must_use]
    pub const fn all_proven(&self) -> bool {
        self.durable_wal_full && self.physical_flush && self.exclusive_writer_lock
    }
    /// WAL-Journal und `synchronous=FULL` in einer schreibenden Transaktion.
    #[must_use]
    pub const fn durable_wal_full(&self) -> bool {
        self.durable_wal_full
    }
    /// Physischer Flush von Datenbank, WAL-Datei und Elternverzeichnis.
    #[must_use]
    pub const fn physical_flush(&self) -> bool {
        self.physical_flush
    }
    /// Exklusivität des Writer-Locks über zwei unabhängige Datei-Handles.
    #[must_use]
    pub const fn exclusive_writer_lock(&self) -> bool {
        self.exclusive_writer_lock
    }
}

pub struct SqlcipherArchiveBackend {
    store: SqliteCommitStore,
    database_path: PathBuf,
}
impl SqlcipherArchiveBackend {
    pub fn open(store: SqliteCommitStore) -> Result<Self, ArchiveBackendError> {
        if !store
            .database()
            .has_migration(26)
            .map_err(|_| ArchiveBackendError::Io)?
        {
            return Err(ArchiveBackendError::MissingLocalCommitComponent);
        }
        let database_path =
            fs::canonicalize(store.database().path()).map_err(|_| ArchiveBackendError::Io)?;
        let backend = Self {
            store,
            database_path,
        };
        backend.transaction(|_| Ok(()))?;
        Ok(backend)
    }
    /// Misst EA-CNA-WRT-4 an genau dieser Datenbank und schreibt dabei kein
    /// Objekt, kein Verzeichnis und keine Sondenzeile.
    ///
    /// Zuerst der Lock: der eigene Writer-Lock wird genommen, ein zweites,
    /// unabhängiges Handle auf dieselbe Lock-Datei darf ihn nicht bekommen und
    /// muss ihn nach der Freigabe bekommen. Danach eine schreibende
    /// Transaktion mit Dauerhaftigkeitsprüfung und physischem Flush.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::AlreadyLocked`], wenn ein anderer Writer den
    /// Lock hält; [`ArchiveBackendError::FlushFailed`], wenn WAL/FULL oder der
    /// physische Flush nicht belegt sind. Ein Fehler ist nie ein Teilbericht.
    pub fn run_capability_test(&self) -> Result<SqlcipherCapabilityReportV1, ArchiveBackendError> {
        let held = self.acquire_writer_lock()?;
        let second = OpenOptions::new()
            .write(true)
            .open(self.writer_lock_path())
            .map_err(|_| ArchiveBackendError::Io)?;
        let contended = second.try_lock().is_err();
        drop(held);
        let released = second.try_lock().is_ok();
        if released {
            let _ = second.unlock();
        }
        // Dieselbe schreibende Transaktion wie jeder Commit: `transaction`
        // verlangt WAL und FULL, `flush_physical` den Flush. Ein Fehlschlag
        // beider kommt als `FlushFailed` zurück und wird nicht zu `false`
        // umgedeutet.
        self.transaction(|_| self.flush_physical())?;
        Ok(SqlcipherCapabilityReportV1 {
            durable_wal_full: true,
            physical_flush: true,
            exclusive_writer_lock: contended && released,
        })
    }
    fn writer_lock_path(&self) -> PathBuf {
        let mut name = self.database_path.as_os_str().to_os_string();
        name.push(".archive-writer.lock");
        PathBuf::from(name)
    }
    fn transaction<T>(
        &self,
        work: impl FnOnce(&StoreTransaction<'_>) -> Result<T, StorageFailure>,
    ) -> Result<T, ArchiveBackendError> {
        self.store
            .database()
            .transaction(|tx| {
                require_durability(tx)?;
                work(tx)
            })
            .map_err(|e: StorageFailure| e.0)
    }
    fn namespace(&self) -> StoreValue {
        StoreValue::Blob(self.store.namespace().as_bytes().to_vec())
    }
    fn ensure_directory(
        &self,
        tx: &StoreTransaction<'_>,
        directory: &str,
    ) -> Result<(), StorageFailure> {
        if directory.is_empty() {
            return Ok(());
        }
        if !LAYOUT_PATHS_V1.contains(&directory) || !directory.ends_with('/') {
            return Err(StorageFailure(ArchiveBackendError::Path));
        }
        tx.execute(
            "INSERT OR IGNORE INTO local_commit_directory(namespace,directory) VALUES(?1,?2)",
            &[self.namespace(), StoreValue::Text(directory.to_owned())],
        )?;
        Ok(())
    }
    fn create(&self, path: &ArchivePath, bytes: &[u8]) -> Result<(), ArchiveBackendError> {
        self.transaction(|tx| {
            self.ensure_directory(tx, path.directory())?;
            self.store.put_in(tx, path.as_str(), bytes)
        })
    }
    fn flush_physical(&self) -> Result<(), StorageFailure> {
        // Held inside the same IMMEDIATE transaction, excluding other SQLite
        // writers/checkpoints. FULL commits and the actual physical flush both
        // remain necessary; an unsupported directory fsync fails closed.
        File::open(&self.database_path)
            .and_then(|f| f.sync_all())
            .map_err(|_| StorageFailure(ArchiveBackendError::FlushFailed))?;
        let mut wal = self.database_path.as_os_str().to_os_string();
        wal.push("-wal");
        match File::open(PathBuf::from(wal)) {
            Ok(file) => file
                .sync_all()
                .map_err(|_| StorageFailure(ArchiveBackendError::FlushFailed))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StorageFailure(ArchiveBackendError::FlushFailed)),
        }
        let parent = self
            .database_path
            .parent()
            .ok_or(StorageFailure(ArchiveBackendError::FlushFailed))?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| StorageFailure(ArchiveBackendError::FlushFailed))
    }
    fn flush(&self) -> Result<(), ArchiveBackendError> {
        self.transaction(|_| self.flush_physical())
    }
    fn snapshot(&self) -> Result<Vec<(String, Vec<u8>)>, ArchiveBackendError> {
        self.transaction(|tx| {
            let bound = tx.query_row("SELECT count(*),coalesce(sum(length(exact_bytes)),0) FROM local_commit_object WHERE namespace=?1", &[self.namespace()])?.ok_or(StoreError::Shape)?;
            let count = usize::try_from(bound.integer(0)?).map_err(|_| StoreError::Shape)?;
            let bytes = usize::try_from(bound.integer(1)?).map_err(|_| StoreError::Shape)?;
            if count > MAX_ARCHIVE_BLOBS_V1 || bytes > MAX_TOTAL_ARCHIVE_BYTES_V1 { return Err(StorageFailure(ArchiveBackendError::InventoryMismatch)); }
            let mut rows = Vec::new(); rows.try_reserve(count).map_err(|_| StoreError::Database)?;
            let mut last = String::new();
            while let Some(row) = tx.query_row("SELECT relative_path,exact_bytes FROM local_commit_object WHERE namespace=?1 AND relative_path>?2 COLLATE BINARY ORDER BY relative_path COLLATE BINARY LIMIT 1", &[self.namespace(), StoreValue::Text(last)])? {
                let relative = row.text(0)?.to_owned();
                self.store.params(&relative).map_err(StorageFailure)?;
                rows.push((relative.clone(), row.blob(1)?.to_vec())); last = relative;
                if rows.len() > count { return Err(StoreError::Shape.into()); }
            }
            if rows.len() != count { return Err(StoreError::Shape.into()); }
            Ok(rows)
        })
    }
}
fn require_durability(tx: &StoreTransaction<'_>) -> Result<(), StorageFailure> {
    let synchronous = tx
        .query_row("PRAGMA synchronous", &[])?
        .ok_or(StoreError::Shape)?;
    let journal = tx
        .query_row("PRAGMA journal_mode", &[])?
        .ok_or(StoreError::Shape)?;
    if synchronous.integer(0)? != 2 || journal.text(0)? != "wal" {
        return Err(StorageFailure(ArchiveBackendError::FlushFailed));
    }
    Ok(())
}
struct SqlcipherWriterLock(File);
impl WriterLockRelease for SqlcipherWriterLock {
    fn release(&self) {
        let _ = self.0.unlock();
    }
}
impl ArchiveBackend for SqlcipherArchiveBackend {
    fn create_if_absent(
        &self,
        path: &ArchivePath,
        bytes: &ExactObjectBytes,
    ) -> Result<(), ArchiveBackendError> {
        self.create(path, bytes.as_bytes())
    }
    fn create_non_object_if_absent(
        &self,
        path: &ArchivePath,
        bytes: &[u8],
    ) -> Result<(), ArchiveBackendError> {
        self.create(path, bytes)
    }
    fn staged_paths(&self) -> Result<Vec<String>, ArchiveBackendError> {
        Ok(self
            .snapshot()?
            .into_iter()
            .filter_map(|(path, _)| ea_archive::is_staging_path(&path).then_some(path))
            .collect())
    }
    fn visit_managed_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for (path, bytes) in self.snapshot().map_err(|_| ArchiveError::Unavailable)? {
            visitor(ArchiveBlob::new(&path, &bytes))?;
        }
        Ok(())
    }
    fn remove_if_present(&self, path: &ArchivePath) -> Result<(), ArchiveBackendError> {
        let params = self.store.params(path.as_str())?;
        self.transaction(|tx| {
            tx.execute(
                "DELETE FROM local_commit_object WHERE namespace=?1 AND relative_path=?2",
                &params,
            )?;
            Ok(())
        })?;
        self.flush()
    }
    fn sync_file(&self, path: &ArchivePath) -> Result<(), ArchiveBackendError> {
        let params = self.store.params(path.as_str())?;
        self.transaction(|tx| {
            if tx
                .query_row(
                    "SELECT 1 FROM local_commit_object WHERE namespace=?1 AND relative_path=?2",
                    &params,
                )?
                .is_none()
            {
                return Err(StorageFailure(ArchiveBackendError::FlushFailed));
            }
            self.flush_physical()
        })
    }
    fn sync_directory(&self, path: &ArchivePath) -> Result<(), ArchiveBackendError> {
        self.store.params(path.as_str())?;
        self.transaction(|tx| {
            if !path.directory().is_empty()
                && tx
                    .query_row(
                        "SELECT 1 FROM local_commit_directory WHERE namespace=?1 AND directory=?2",
                        &[
                            self.namespace(),
                            StoreValue::Text(path.directory().to_owned()),
                        ],
                    )?
                    .is_none()
            {
                return Err(StorageFailure(ArchiveBackendError::FlushFailed));
            }
            self.flush_physical()
        })
    }
    fn atomic_rename_same_fs(
        &self,
        from: &ArchivePath,
        to: &ArchivePath,
    ) -> Result<(), ArchiveBackendError> {
        let source = self.store.params(from.as_str())?;
        let target = self.store.params(to.as_str())?;
        self.transaction(|tx| {
            let bytes = tx.query_row("SELECT exact_bytes FROM local_commit_object WHERE namespace=?1 AND relative_path=?2", &source)?.ok_or(StoreError::Shape)?;
            if from == to { return Ok(()); }
            let existing = tx.query_row("SELECT exact_bytes FROM local_commit_object WHERE namespace=?1 AND relative_path=?2", &target)?;
            if let Some(existing) = &existing && existing.blob(0)? != bytes.blob(0)? { return Err(StorageFailure(ArchiveBackendError::ByteConflict)); }
            self.ensure_directory(tx, to.directory())?;
            // One transaction restores both names on any failure and permits
            // rename at capacity without temporarily exceeding pinned limits.
            tx.execute("DELETE FROM local_commit_object WHERE namespace=?1 AND relative_path=?2", &source)?;
            if existing.is_none() { self.store.put_in(tx, to.as_str(), bytes.blob(0)?)?; }
            Ok(())
        })?;
        self.flush()
    }
    fn create_directory_if_absent(&self, directory: &str) -> Result<(), ArchiveBackendError> {
        if directory.is_empty() {
            return Err(ArchiveBackendError::Path);
        }
        self.transaction(|tx| self.ensure_directory(tx, directory))?;
        self.flush()
    }
    fn acquire_writer_lock(&self) -> Result<WriterLock, ArchiveBackendError> {
        // All namespaces on the canonical native database share one Writer
        // lock. The existing separate DraftLock is neither replaced nor held.
        let path = self.writer_lock_path();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| ArchiveBackendError::AlreadyLocked)?;
        if !fs::symlink_metadata(&path)
            .map_err(|_| ArchiveBackendError::AlreadyLocked)?
            .file_type()
            .is_file()
        {
            return Err(ArchiveBackendError::AlreadyLocked);
        }
        file.try_lock()
            .map_err(|_| ArchiveBackendError::AlreadyLocked)?;
        Ok(WriterLock::new(Arc::new(SqlcipherWriterLock(file))))
    }
}
impl ArchiveSource for SqlcipherArchiveBackend {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for (path, bytes) in self.snapshot().map_err(|_| ArchiveError::Unavailable)? {
            if !ea_archive::is_staging_path(&path) {
                visitor(ArchiveBlob::new(&path, &bytes))?;
            }
        }
        Ok(())
    }
}
