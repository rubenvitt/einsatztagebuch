use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};

#[test]
fn destruction_compaction_requires_secure_delete_and_observes_empty_freelist_and_wal() {
    let path =
        std::env::temp_dir().join(format!("ea-destruction-compaction-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let provider = InMemoryKeyProvider::new_for_test([0x72; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let db = EncryptedDatabase::open(&path.join("local.db"), &provider, &key).unwrap();
    db.execute("CREATE TABLE removable(exact BLOB NOT NULL) STRICT", &[])
        .unwrap();
    db.query_row("PRAGMA secure_delete=ON", &[]).unwrap();
    db.execute(
        "INSERT INTO removable VALUES(?1)",
        &[StoreValue::Blob(vec![0x7b; 128 * 1024])],
    )
    .unwrap();
    db.execute("DELETE FROM removable", &[]).unwrap();
    assert!(
        db.query_row("PRAGMA freelist_count", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap()
            > 0
    );
    db.compact_after_authorized_destruction().unwrap();
    assert_eq!(
        db.query_row("PRAGMA freelist_count", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    assert_eq!(
        std::fs::metadata(path.join("local.db-wal")).unwrap().len(),
        0
    );
    db.query_row("PRAGMA secure_delete=OFF", &[]).unwrap();
    assert!(db.compact_after_authorized_destruction().is_err());
    drop(db);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn an_uncheckpointable_live_transaction_cannot_be_reported_as_compacted() {
    let path = std::env::temp_dir().join(format!(
        "ea-destruction-busy-compaction-{}",
        std::process::id()
    ));
    std::fs::create_dir(&path).unwrap();
    let provider = InMemoryKeyProvider::new_for_test([0x73; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let db = EncryptedDatabase::open(&path.join("local.db"), &provider, &key).unwrap();
    let holder = EncryptedDatabase::open_existing(&path.join("local.db"), &provider, &key).unwrap();
    db.query_row("PRAGMA secure_delete=ON", &[]).unwrap();
    let ready = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    let result = std::thread::scope(|scope| {
        scope.spawn(|| {
            holder
                .transaction::<_, ea_local_store::StoreError>(|tx| {
                    tx.query_row("SELECT count(*) FROM schema_migration", &[])?;
                    ready.wait();
                    release.wait();
                    Ok(())
                })
                .unwrap();
        });
        ready.wait();
        let result = db.compact_after_authorized_destruction();
        release.wait();
        result
    });
    assert!(result.is_err());
    db.compact_after_authorized_destruction().unwrap();
    drop(holder);
    drop(db);
    std::fs::remove_dir_all(path).unwrap();
}
