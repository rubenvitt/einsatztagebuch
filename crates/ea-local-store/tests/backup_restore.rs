use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "ea-source-backup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn key(provider: &InMemoryKeyProvider) -> ea_key_provider::KeyHandle {
    provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap()
}

#[test]
fn independently_derived_backup_key_restores_without_a_fabricated_key_handle() {
    let temp = Temp::new();
    let native = InMemoryKeyProvider::new_for_test([61; 32]);
    let source_key = key(&native);
    let target_key = key(&native);
    let database =
        EncryptedDatabase::open(&temp.0.join("original.db"), &native, &source_key).unwrap();
    let backup_key = ea_crypto::SecretBytes::new([63; 32]);
    let backup = temp.0.join("snapshot.db");
    let snapshot = database
        .snapshot_with_backup_key(&backup, &backup_key)
        .unwrap();
    let target = temp.0.join("fresh.db");
    assert!(
        EncryptedDatabase::restore_with_backup_key(
            &backup,
            *snapshot.ciphertext_hash(),
            *snapshot.migrations_hash(),
            &ea_crypto::SecretBytes::new([64; 32]),
            &target,
            &native,
            &target_key
        )
        .is_err()
    );
    assert!(!target.exists());
    let mut wrong_migrations = *snapshot.migrations_hash();
    wrong_migrations[0] ^= 1;
    assert!(
        EncryptedDatabase::restore_with_backup_key(
            &backup,
            *snapshot.ciphertext_hash(),
            wrong_migrations,
            &backup_key,
            &target,
            &native,
            &target_key
        )
        .is_err()
    );
    assert!(!target.exists());
    let restored = EncryptedDatabase::restore_with_backup_key(
        &backup,
        *snapshot.ciphertext_hash(),
        *snapshot.migrations_hash(),
        &backup_key,
        &target,
        &native,
        &target_key,
    )
    .unwrap();
    assert!(restored.has_migration(15).unwrap());
    drop(restored);
    assert!(EncryptedDatabase::open_existing(&target, &native, &target_key).is_ok());
    assert!(
        EncryptedDatabase::restore_with_backup_key(
            &backup,
            *snapshot.ciphertext_hash(),
            *snapshot.migrations_hash(),
            &backup_key,
            &target,
            &native,
            &target_key
        )
        .is_err()
    );
}

#[test]
fn live_wal_snapshot_restores_all_sources_and_tombstones_under_a_fresh_database_key() {
    let temp = Temp::new();
    let source_provider = InMemoryKeyProvider::new_for_test([11; 32]);
    let source_key = key(&source_provider);
    let backup_provider = InMemoryKeyProvider::new_for_test([12; 32]);
    let backup_key = key(&backup_provider);
    let target_provider = InMemoryKeyProvider::new_for_test([13; 32]);
    let target_key = key(&target_provider);
    let db =
        EncryptedDatabase::open(&temp.0.join("source.db"), &source_provider, &source_key).unwrap();
    db.execute(
        "CREATE TABLE original_source (exact_source BLOB NOT NULL) STRICT",
        &[],
    )
    .unwrap();
    let canary = b"T9-EXACT-ORIGINAL-IDENTITY-SOURCE-NEVER-PLAINTEXT";
    db.transaction::<_, ea_local_store::StoreError>(|tx| {
        tx.execute(
            "INSERT INTO original_source VALUES (?1)",
            &[StoreValue::Blob(canary.to_vec())],
        )?;
        tx.execute(
            "INSERT INTO incident_number_retained_key VALUES (0,?1)",
            &[StoreValue::Blob(vec![91; 32])],
        )?;
        tx.execute(
            "INSERT INTO incident_number_retained_token VALUES (?1)",
            &[StoreValue::Blob(vec![92; 32])],
        )?;
        Ok(())
    })
    .unwrap();
    let backup = temp.0.join("snapshot.db");
    let receipt = db
        .snapshot_encrypted(&backup, &backup_provider, &backup_key)
        .unwrap();
    assert!(
        !fs::read(&backup)
            .unwrap()
            .windows(canary.len())
            .any(|w| w == canary)
    );
    assert_eq!(
        receipt.ciphertext_hash(),
        ea_crypto::object_hash(&fs::read(&backup).unwrap()).as_bytes()
    );
    db.execute("DELETE FROM original_source", &[]).unwrap();
    drop(db);
    let target = temp.0.join("fresh.db");
    let restored = EncryptedDatabase::restore_encrypted_snapshot(
        &backup,
        *receipt.ciphertext_hash(),
        &backup_provider,
        &backup_key,
        &target,
        &target_provider,
        &target_key,
    )
    .unwrap();
    assert_eq!(
        restored
            .query_row("SELECT exact_source FROM original_source", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        canary
    );
    assert_eq!(
        restored
            .query_row("SELECT key_bytes FROM incident_number_retained_key", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        &[91; 32]
    );
    assert_eq!(
        restored
            .query_row("SELECT token FROM incident_number_retained_token", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        &[92; 32]
    );
    assert!(
        restored
            .execute("DELETE FROM incident_number_retained_token", &[])
            .is_err()
    );
    assert!(restored.has_migration(15).unwrap());
    drop(restored);
    assert!(EncryptedDatabase::open_existing(&target, &source_provider, &source_key).is_err());
    let reopened =
        EncryptedDatabase::open_existing(&target, &target_provider, &target_key).unwrap();
    assert!(
        reopened
            .query_row("SELECT exact_source FROM original_source", &[])
            .unwrap()
            .is_some()
    );
    assert_eq!(
        receipt.ciphertext_hash(),
        ea_crypto::object_hash(&fs::read(&backup).unwrap()).as_bytes()
    );
}

#[test]
fn snapshot_and_restore_refuse_overwrite_wrong_key_tampering_and_incomplete_migrations() {
    let temp = Temp::new();
    let provider = InMemoryKeyProvider::new_for_test([21; 32]);
    let handle = key(&provider);
    let db = EncryptedDatabase::open(&temp.0.join("source.db"), &provider, &handle).unwrap();
    let snapshot = temp.0.join("backup.db");
    let receipt = db
        .snapshot_encrypted(&snapshot, &provider, &handle)
        .unwrap();
    let original = fs::read(&snapshot).unwrap();
    assert!(
        db.snapshot_encrypted(&snapshot, &provider, &handle)
            .is_err()
    );
    assert_eq!(fs::read(&snapshot).unwrap(), original);
    let occupied = temp.0.join("occupied.db");
    fs::write(&occupied, b"KEEP").unwrap();
    assert!(
        EncryptedDatabase::restore_encrypted_snapshot(
            &snapshot,
            *receipt.ciphertext_hash(),
            &provider,
            &handle,
            &occupied,
            &provider,
            &handle
        )
        .is_err()
    );
    assert_eq!(fs::read(&occupied).unwrap(), b"KEEP");
    let target = temp.0.join("target.db");
    let wrong = InMemoryKeyProvider::new_for_test([22; 32]);
    let wrong_key = key(&wrong);
    assert!(
        EncryptedDatabase::restore_encrypted_snapshot(
            &snapshot,
            *receipt.ciphertext_hash(),
            &wrong,
            &wrong_key,
            &target,
            &provider,
            &handle
        )
        .is_err()
    );
    assert!(!target.exists());
    let mut altered = original;
    altered[64] ^= 1;
    fs::write(&snapshot, &altered).unwrap();
    assert!(
        EncryptedDatabase::restore_encrypted_snapshot(
            &snapshot,
            *receipt.ciphertext_hash(),
            &provider,
            &handle,
            &target,
            &provider,
            &handle
        )
        .is_err()
    );
    assert!(!target.exists());
    db.execute("DELETE FROM schema_migration WHERE version=15", &[])
        .unwrap();
    assert!(
        db.snapshot_encrypted(&temp.0.join("incomplete.db"), &provider, &handle)
            .is_err()
    );
    assert!(!temp.0.join("incomplete.db").exists());
}

#[test]
fn restored_source_digest_is_key_independent_and_detects_schema_and_row_mutation() {
    let temp = Temp::new();
    let provider = InMemoryKeyProvider::new_for_test([71; 32]);
    let source_key = key(&provider);
    let target_key = key(&provider);
    let source =
        EncryptedDatabase::open(&temp.0.join("source.db"), &provider, &source_key).unwrap();
    source
        .execute(
            "CREATE TABLE private_source(n INTEGER, payload BLOB, note TEXT, value REAL)",
            &[],
        )
        .unwrap();
    source
        .execute(
            "INSERT INTO private_source VALUES(2,?1,?2,1.5)",
            &[
                StoreValue::Blob(vec![0, 1, 2]),
                StoreValue::Text("PRIVATE-SOURCE".into()),
            ],
        )
        .unwrap();
    source
        .execute("INSERT INTO private_source VALUES(1,NULL,NULL,NULL)", &[])
        .unwrap();
    let before = source.recovery_source_content_hash().unwrap();
    let key = ea_crypto::SecretBytes::new([72; 32]);
    let snapshot = temp.0.join("snapshot.db");
    let binding = source.snapshot_with_backup_key(&snapshot, &key).unwrap();
    let restored = EncryptedDatabase::restore_with_backup_key(
        &snapshot,
        *binding.ciphertext_hash(),
        *binding.migrations_hash(),
        &key,
        &temp.0.join("restored.db"),
        &provider,
        &target_key,
    )
    .unwrap();
    assert_eq!(restored.recovery_source_content_hash().unwrap(), before);
    drop(restored);
    let restored =
        EncryptedDatabase::open_existing(&temp.0.join("restored.db"), &provider, &target_key)
            .unwrap();
    assert_eq!(restored.recovery_source_content_hash().unwrap(), before);
    restored
        .execute(
            "UPDATE private_source SET payload=?1 WHERE n=2",
            &[StoreValue::Blob(vec![0, 1, 3])],
        )
        .unwrap();
    assert_ne!(restored.recovery_source_content_hash().unwrap(), before);
    restored
        .execute(
            "UPDATE private_source SET payload=?1 WHERE n=2",
            &[StoreValue::Blob(vec![0, 1, 2])],
        )
        .unwrap();
    assert_eq!(restored.recovery_source_content_hash().unwrap(), before);
    restored
        .execute(
            "CREATE TRIGGER changed BEFORE INSERT ON private_source BEGIN SELECT 1; END",
            &[],
        )
        .unwrap();
    assert_ne!(restored.recovery_source_content_hash().unwrap(), before);
}


fn historical_prefix_snapshot(path:&std::path::Path, count:usize) -> ([u8;32],[u8;32]) {
    let connection=rusqlite::Connection::open(path).unwrap();
    // Fixed public fixture secret, not a provider/export path.
    connection.execute_batch(&format!(r#"PRAGMA key = "x'{}'";"#,"5b".repeat(32))).unwrap();
    connection.execute_batch("CREATE TABLE schema_migration(version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_at_ms INTEGER NOT NULL) STRICT;").unwrap();
    let mut chain=Vec::new();
    for migration in &ea_local_store::migrations::MIGRATIONS[..count] {
        connection.execute_batch(migration.sql).unwrap();
        connection.execute("INSERT INTO schema_migration VALUES(?1,?2,0)",rusqlite::params![migration.version,migration.name]).unwrap();
        chain.extend_from_slice(&migration.version.to_be_bytes());
        chain.extend_from_slice(ea_crypto::object_hash(migration.sql.as_bytes()).as_bytes());
    }
    connection.execute("INSERT INTO incident_number_retained_key(singleton,key_bytes) VALUES(0,?1)",[&[0x71;32][..]]).unwrap();
    connection.execute("INSERT INTO incident_number_retained_token(token) VALUES(?1)",[&[0x72;32][..]]).unwrap();
    connection.close().unwrap();
    (*ea_crypto::object_hash(&fs::read(path).unwrap()).as_bytes(),*ea_crypto::object_hash(&chain).as_bytes())
}

#[test]
fn known_historical_migration_prefix_restores_exactly_without_upgrading_sources() {
    let temp=Temp::new();
    let snapshot=temp.0.join("historical.db");
    let (ciphertext,migrations)=historical_prefix_snapshot(&snapshot,18);
    let original=fs::read(&snapshot).unwrap();
    let provider=InMemoryKeyProvider::new_for_test([90;32]);
    let target_key=key(&provider);
    let target=temp.0.join("restored-prefix.db");
    let restored=EncryptedDatabase::restore_with_backup_key(
        &snapshot,ciphertext,migrations,&ea_crypto::SecretBytes::new([0x5b;32]),&target,&provider,&target_key,
    ).expect("the exact signed known migration prefix must remain a usable read-only recovery source");
    assert!(restored.has_migration(18).unwrap());
    assert!(!restored.has_migration(19).unwrap(),"restoration must not silently apply a later migration");
    assert_eq!(restored.query_row("SELECT key_bytes FROM incident_number_retained_key",&[]).unwrap().unwrap().blob(0).unwrap(),&[0x71;32]);
    assert_eq!(restored.query_row("SELECT count(*) FROM incident_number_retained_token",&[]).unwrap().unwrap().integer(0).unwrap(),1);
    assert!(restored.execute("CREATE TABLE unauthorized_write(value TEXT)",&[]).is_err(),"an exact recovery source handle is read-only");
    let digest=restored.recovery_source_content_hash().unwrap();
    drop(restored);
    let exact_target=fs::read(&target).unwrap();
    let reopened=EncryptedDatabase::open_recovery_source_exact(&target,migrations,&provider,&target_key).unwrap();
    assert_eq!(reopened.recovery_source_content_hash().unwrap(),digest);
    assert!(!reopened.has_migration(19).unwrap());
    assert!(reopened.execute("INSERT INTO incident_number_retained_token VALUES(?1)",&[StoreValue::Blob(vec![0x73;32])]).is_err());
    drop(reopened);
    assert_eq!(fs::read(&target).unwrap(),exact_target);
    assert_eq!(fs::read(&snapshot).unwrap(),original);
}


#[test]
fn historical_restore_rejects_unknown_mismatched_or_gapped_migration_prefixes() {
    let temp=Temp::new();
    let snapshot=temp.0.join("historical.db");
    let (ciphertext,migrations)=historical_prefix_snapshot(&snapshot,18);
    let (_,newer)=historical_prefix_snapshot(&temp.0.join("newer.db"),19);
    let provider=InMemoryKeyProvider::new_for_test([92;32]);
    let target_key=key(&provider);
    let target=temp.0.join("refused.db");
    for expected in [[0xff;32],newer] {
        assert!(EncryptedDatabase::restore_with_backup_key(
            &snapshot,ciphertext,expected,&ea_crypto::SecretBytes::new([0x5b;32]),&target,&provider,&target_key,
        ).is_err());
        assert!(!target.exists());
    }
    for (index,statement) in [
        "DELETE FROM schema_migration WHERE version=9",
        "UPDATE schema_migration SET name='foreign.sql' WHERE version=9",
        "INSERT INTO schema_migration VALUES(99,'future.sql',0)",
    ].into_iter().enumerate() {
        let malformed=temp.0.join(format!("malformed-{index}.db"));
        historical_prefix_snapshot(&malformed,18);
        let connection=rusqlite::Connection::open(&malformed).unwrap();
        connection.execute_batch(&format!(r#"PRAGMA key = "x'{}'";"#,"5b".repeat(32))).unwrap();
        connection.execute_batch(statement).unwrap();
        connection.close().unwrap();
        let hash=*ea_crypto::object_hash(&fs::read(&malformed).unwrap()).as_bytes();
        assert!(EncryptedDatabase::restore_with_backup_key(
            &malformed,hash,migrations,&ea_crypto::SecretBytes::new([0x5b;32]),&target,&provider,&target_key,
        ).is_err());
        assert!(!target.exists());
    }
}
