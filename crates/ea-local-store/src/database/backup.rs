//! Complete encrypted operational sources. This primitive does not establish
//! that a backup is authorized or sufficient for Setup readiness: the caller
//! must verify its signed recovery report and hold native/Writer locks as well.
use super::{
    EncryptedDatabase, StoreError, migrations, overwrite_in_place, run_ignoring_rows,
    scalar_pragma, set_cipher_key,
};
use ea_crypto::{SecretBytes, SecretVec, object_hash};
use ea_key_provider::{KeyHandle, KeyProvider};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// Measured ciphertext and migration binding, not a recovery authorization.
pub struct EncryptedSnapshot {
    ciphertext_hash: [u8; 32],
    migrations_hash: [u8; 32],
}
impl EncryptedSnapshot {
    pub fn ciphertext_hash(&self) -> &[u8; 32] {
        &self.ciphertext_hash
    }
    pub fn migrations_hash(&self) -> &[u8; 32] {
        &self.migrations_hash
    }
}

impl EncryptedDatabase {
    /// Explicit derived backup secret, without inventing a native key handle.
    /// This low-level storage method makes no authorization claim.
    pub fn snapshot_with_backup_key(
        &self,
        target: &Path,
        key: &SecretBytes<32>,
    ) -> Result<EncryptedSnapshot, StoreError> {
        let key = key.with_exposed(|bytes| SecretVec::new(bytes.to_vec()));
        let mut connection = self.lock();
        validate(&connection)?;
        export(
            &mut connection,
            target,
            &key,
            TransactionBehavior::Immediate,
        )
    }

    /// A verified SourceManifest supplies both exact hashes. The target key is
    /// freshly provisioned by the native host and never exported to the backup.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_with_backup_key(
        source: &Path,
        expected_hash: [u8; 32],
        expected_migrations: [u8; 32],
        source_key: &SecretBytes<32>,
        target: &Path,
        target_provider: &dyn KeyProvider,
        target_key: &KeyHandle,
    ) -> Result<Self, StoreError> {
        if known_migration_prefix(expected_migrations).is_none() {
            return Err(StoreError::Migration);
        }
        let secret = source_key.with_exposed(|bytes| SecretVec::new(bytes.to_vec()));
        Self::restore_with_secret(
            source,
            expected_hash,
            expected_migrations,
            &secret,
            target,
            target_provider,
            target_key,
        )
    }
    /// Export every committed SQLCipher table, index and trigger, including
    /// operational sources which cannot be reconstructed from archive bytes.
    /// Holds the connection mutex and SQLite write reservation throughout the
    /// snapshot. The host also holds its native and Writer lifecycle locks.
    pub fn snapshot_encrypted(
        &self,
        target: &Path,
        provider: &dyn KeyProvider,
        key: &KeyHandle,
    ) -> Result<EncryptedSnapshot, StoreError> {
        let secret = provider.unwrap_database_key(key)?;
        let mut connection = self.lock();
        validate(&connection)?;
        export(
            &mut connection,
            target,
            &secret,
            TransactionBehavior::Immediate,
        )
    }

    /// Restore a hash-authenticated immutable ciphertext copy into a new target
    /// protected by the freshly provisioned target key. Never opens or replaces
    /// an existing target, never migrates/mutates the backup, and never combines
    /// source tables from different snapshots. The expected hash must originate
    /// from the caller's verified durable report, not an adjacent untrusted file.
    #[allow(clippy::too_many_arguments)] // Both independent providers and exact destinations are explicit.
    pub fn restore_encrypted_snapshot(
        source: &Path,
        expected_ciphertext_hash: [u8; 32],
        source_provider: &dyn KeyProvider,
        source_key: &KeyHandle,
        target: &Path,
        target_provider: &dyn KeyProvider,
        target_key: &KeyHandle,
    ) -> Result<Self, StoreError> {
        let source_secret = source_provider.unwrap_database_key(source_key)?;
        Self::restore_with_secret(
            source,
            expected_ciphertext_hash,
            migration_hash(migrations::MIGRATIONS.len()),
            &source_secret,
            target,
            target_provider,
            target_key,
        )
    }
    fn restore_with_secret(
        source: &Path,
        expected_ciphertext_hash: [u8; 32],
        expected_migrations: [u8;32],
        source_secret: &SecretVec,
        target: &Path,
        target_provider: &dyn KeyProvider,
        target_key: &KeyHandle,
    ) -> Result<Self, StoreError> {
        if target.try_exists().map_err(|_| StoreError::Database)? {
            return Err(StoreError::Constraint);
        }
        let bytes = read_ciphertext(source)?;
        if object_hash(&bytes).as_bytes() != &expected_ciphertext_hash {
            return Err(StoreError::Shape);
        }
        // Work from the exact verified bytes in a private directory. A source
        // replaced after hashing, or an adjacent WAL, cannot alter this input.
        let staging = PrivateDirectory::new(target.parent().ok_or(StoreError::Database)?)?;
        let input = staging.0.join("input.db");
        let mut file = create_new(&input)?;
        file.write_all(&bytes).map_err(|_| StoreError::Database)?;
        file.sync_all().map_err(|_| StoreError::Database)?;
        drop(file);
        drop(bytes);
        let target_secret = target_provider.unwrap_database_key(target_key)?;
        // ATTACH inherits the connection's write mode. The private exact copy
        // must permit writing the newly attached target; the original backup
        // has already been closed and is never opened by SQLite.
        let mut connection = Connection::open_with_flags(
            &input,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| StoreError::Database)?;
        source_secret.with_exposed(|bytes| set_cipher_key(&connection, bytes))?;
        run_ignoring_rows(&connection, "PRAGMA temp_store = MEMORY")?;
        if validate(&connection)? != expected_migrations {
            return Err(StoreError::Migration);
        }
        export(
            &mut connection,
            target,
            &target_secret,
            TransactionBehavior::Deferred,
        )?;
        drop(connection);
        drop(staging);
        Self::open_recovery_source_exact(target, expected_migrations, target_provider, target_key)
    }

    /// Opens only an existing, exact known historical schema as read-only proof
    /// material. Never applies migrations or supplies operational admission.
    pub fn open_recovery_source_exact(
        path:&Path, expected_migrations:[u8;32], provider:&dyn KeyProvider, key:&KeyHandle,
    )->Result<Self,StoreError> {
        if known_migration_prefix(expected_migrations).is_none() {return Err(StoreError::Migration);}
        let secret=provider.unwrap_database_key(key)?;
        let connection=Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_ONLY|OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .map_err(|_|StoreError::Database)?;
        secret.with_exposed(|bytes|set_cipher_key(&connection,bytes))?;
        run_ignoring_rows(&connection,"PRAGMA temp_store = MEMORY")?;
        run_ignoring_rows(&connection,"PRAGMA query_only = ON")?;
        if validate(&connection)?!=expected_migrations {return Err(StoreError::Migration);}
        let cipher_version=scalar_pragma(&connection,"PRAGMA cipher_version")?;
        Ok(Self{connection:std::sync::Mutex::new(connection),path:path.to_path_buf(),cipher_version})
    }
}

fn validate(connection: &Connection) -> Result<[u8;32], StoreError> {
    if scalar_pragma(connection, "PRAGMA cipher_version")?.is_empty() {
        return Err(StoreError::CipherUnavailable);
    }
    if !scalar_pragma(connection, "PRAGMA cipher_integrity_check")?.is_empty()
        || scalar_pragma(connection, "PRAGMA integrity_check")? != "ok"
    {
        return Err(StoreError::Database);
    }
    let mut statement = connection
        .prepare("SELECT version,name FROM schema_migration ORDER BY version")
        .map_err(|_| StoreError::Migration)?;
    let rows = statement
        .query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?)))
        .map_err(|_| StoreError::Migration)?;
    let actual = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::Migration)?;
    if actual.len() < 18 || actual.len() > migrations::MIGRATIONS.len()
        || actual
            .iter()
            .zip(migrations::MIGRATIONS)
            .any(|((version, name), expected)| {
                *version != expected.version || name != expected.name
            })
    {
        return Err(StoreError::Migration);
    }
    let (tokens,keys):(i64,i64)=connection.query_row("SELECT (SELECT count(*) FROM incident_number_retained_token),(SELECT count(*) FROM incident_number_retained_key WHERE singleton=0 AND length(key_bytes)=32)",[],|row|Ok((row.get(0)?,row.get(1)?))).map_err(|_|StoreError::Shape)?;
    if tokens > 0 && keys != 1 {
        return Err(StoreError::Shape);
    }
    Ok(migration_hash(actual.len()))
}

fn export(
    connection: &mut Connection,
    target: &Path,
    key: &SecretVec,
    behavior: TransactionBehavior,
) -> Result<EncryptedSnapshot, StoreError> {
    if key.len() != 32 {
        return Err(StoreError::KeyRequired);
    }
    let mut owned = OwnedTarget::new(target)?;
    let path = target.to_str().ok_or(StoreError::Database)?;
    // Binding, rather than SQL interpolation, keeps the key out of statement
    // text/error traces. Its temporary raw-key string is overwritten in place.
    let mut encoded = String::with_capacity(67);
    encoded.push_str("x'");
    key.with_exposed(|bytes| {
        for byte in bytes {
            encoded.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            encoded.push(char::from_digit(u32::from(byte & 15), 16).unwrap_or('0'));
        }
    });
    encoded.push('\'');
    let attached = connection
        .execute(
            "ATTACH DATABASE ?1 AS recovery_snapshot KEY ?2",
            rusqlite::params![path, encoded.as_str()],
        )
        .map_err(|_| StoreError::Database);
    overwrite_in_place(&mut encoded);
    attached?;
    let outcome = (|| {
        let transaction = connection
            .transaction_with_behavior(behavior)
            .map_err(|_| StoreError::Database)?;
        let migrations_hash=validate(&transaction)?;
        run_ignoring_rows(&transaction, "SELECT sqlcipher_export('recovery_snapshot')")?;
        if !scalar_pragma(
            &transaction,
            "PRAGMA recovery_snapshot.cipher_integrity_check",
        )?
        .is_empty()
            || scalar_pragma(&transaction, "PRAGMA recovery_snapshot.integrity_check")? != "ok"
        {
            return Err(StoreError::Database);
        }
        transaction.commit().map_err(|_| StoreError::Database)?;
        Ok::<_,StoreError>(migrations_hash)
    })();
    let detached = run_ignoring_rows(connection, "DETACH DATABASE recovery_snapshot");
    let migrations_hash=outcome?;
    detached?;
    File::open(target)
        .and_then(|file| file.sync_all())
        .map_err(|_| StoreError::Database)?;
    File::open(target.parent().ok_or(StoreError::Database)?)
        .and_then(|file| file.sync_all())
        .map_err(|_| StoreError::Database)?;
    let bytes = read_ciphertext(target)?;
    let receipt = EncryptedSnapshot {
        ciphertext_hash: *object_hash(&bytes).as_bytes(),
        migrations_hash,
    };
    owned.keep = true;
    Ok(receipt)
}
fn migration_hash(count:usize) -> [u8; 32] {
    let mut chain = Vec::new();
    for migration in &migrations::MIGRATIONS[..count] {
        chain.extend_from_slice(&migration.version.to_be_bytes());
        chain.extend_from_slice(object_hash(migration.sql.as_bytes()).as_bytes());
    }
    *object_hash(&chain).as_bytes()
}

fn known_migration_prefix(expected:[u8;32])->Option<usize> {
    (18..=migrations::MIGRATIONS.len()).find(|count|migration_hash(*count)==expected)
}

fn read_ciphertext(path: &Path) -> Result<Vec<u8>, StoreError> {
    const LIMIT: u64 = 512 * 1024 * 1024;
    let file = File::open(path).map_err(|_| StoreError::Database)?;
    if !file.metadata().map_err(|_| StoreError::Database)?.is_file() {
        return Err(StoreError::Shape);
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::Database)?;
    if bytes.is_empty() || bytes.len() as u64 > LIMIT {
        return Err(StoreError::Shape);
    }
    Ok(bytes)
}
fn create_new(path: &Path) -> Result<File, StoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            StoreError::Constraint
        } else {
            StoreError::Database
        }
    })
}
struct OwnedTarget {
    path: PathBuf,
    keep: bool,
}
impl OwnedTarget {
    fn new(path: &Path) -> Result<Self, StoreError> {
        drop(create_new(path)?);
        Ok(Self {
            path: path.to_path_buf(),
            keep: false,
        })
    }
}
impl Drop for OwnedTarget {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}
struct PrivateDirectory(PathBuf);
impl PrivateDirectory {
    fn new(parent: &Path) -> Result<Self, StoreError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StoreError::Database)?
            .as_nanos();
        let path = parent.join(format!(
            ".recovery-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        options.create(&path).map_err(|_| StoreError::Database)?;
        Ok(Self(path))
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl EncryptedDatabase {
    /// Read-only logical source commitment, independent of the encryption key,
    /// page layout and WAL placement. Every schema object and every table row
    /// participates. Only borrowed SQLite values enter the streaming digest;
    /// no private row value is copied into a Rust String/Vec or returned.
    pub fn recovery_source_content_hash(&self) -> Result<[u8; 32], StoreError> {
        let mut connection = self.lock();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| StoreError::Database)?;
        validate(&transaction)?;
        let mut hash = ea_crypto::StreamingObjectHasher::new();
        hash.update(b"EINSATZARCHIV-RECOVERY-RESTORED-SOURCES-v1");
        let mut schema=transaction.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type COLLATE BINARY,name COLLATE BINARY").map_err(|_|StoreError::Database)?;
        let mut rows = schema.query([]).map_err(|_| StoreError::Database)?;
        let mut tables = Vec::new();
        while let Some(row) = rows.next().map_err(|_| StoreError::Database)? {
            hash.update(&[1]);
            for column in 0..4 {
                hash_value(
                    &mut hash,
                    row.get_ref(column).map_err(|_| StoreError::Shape)?,
                );
            }
            if row
                .get_ref(0)
                .map_err(|_| StoreError::Shape)?
                .as_str()
                .map_err(|_| StoreError::Shape)?
                == "table"
            {
                tables.push(row.get::<_, String>(1).map_err(|_| StoreError::Shape)?);
            }
        }
        drop(rows);
        drop(schema);
        for table in tables {
            hash.update(&[2]);
            hash_value(&mut hash, rusqlite::types::ValueRef::Text(table.as_bytes()));
            let identifier = format!("\"{}\"", table.replace('"', "\"\""));
            let columns = transaction
                .prepare(&format!("SELECT * FROM {identifier} LIMIT 0"))
                .map_err(|_| StoreError::Database)?
                .column_count();
            hash.update(&(columns as u64).to_be_bytes());
            if columns == 0 {
                return Err(StoreError::Shape);
            }
            let order = (1..=columns)
                .map(|i| format!("{i} COLLATE BINARY"))
                .collect::<Vec<_>>()
                .join(",");
            let mut statement = transaction
                .prepare(&format!("SELECT * FROM {identifier} ORDER BY {order}"))
                .map_err(|_| StoreError::Database)?;
            let mut rows = statement.query([]).map_err(|_| StoreError::Database)?;
            while let Some(row) = rows.next().map_err(|_| StoreError::Database)? {
                hash.update(&[3]);
                for column in 0..columns {
                    hash_value(
                        &mut hash,
                        row.get_ref(column).map_err(|_| StoreError::Shape)?,
                    );
                }
            }
            hash.update(&[4]);
        }
        transaction.commit().map_err(|_| StoreError::Database)?;
        Ok(*hash.finish().as_bytes())
    }
}
fn hash_value(hash: &mut ea_crypto::StreamingObjectHasher, value: rusqlite::types::ValueRef<'_>) {
    use rusqlite::types::ValueRef;
    match value {
        ValueRef::Null => hash.update(&[0]),
        ValueRef::Integer(n) => {
            hash.update(&[1]);
            hash.update(&n.to_be_bytes());
        }
        ValueRef::Real(n) => {
            hash.update(&[2]);
            hash.update(&n.to_bits().to_be_bytes());
        }
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
            hash.update(&[if matches!(value, ValueRef::Text(_)) {
                3
            } else {
                4
            }]);
            hash.update(&(bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
    }
}
