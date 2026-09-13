mod support;
use ea_archive::ArchiveBackendError;
use ea_archive_fs::{AtRestEncryptedStoreV1, SqliteCommitStore};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_types::Hash32;
use std::sync::Arc;
#[test]
fn existing_scope_open_never_creates_or_changes_limits_and_retains_exact_bytes() {
    let (_guard, root) = support::temp_root("strict-existing-scope");
    let provider = InMemoryKeyProvider::new_for_test([0x71; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let db =
        Arc::new(EncryptedDatabase::open(&root.join("operator.sqlite"), &provider, &key).unwrap());
    let namespace = Hash32::try_from([0x72; 32].as_slice()).unwrap();
    let changes = || {
        db.query_row("SELECT total_changes()", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap()
    };
    let before = changes();
    assert!(matches!(
        SqliteCommitStore::open_existing(db.clone(), namespace, 2, 128),
        Err(ArchiveBackendError::MissingLocalCommitComponent)
    ));
    assert_eq!(changes(), before);
    // Explicit setup registration, separate from the existing-only production open.
    db.execute(
        "INSERT INTO local_commit_scope(namespace,object_limit,byte_limit) VALUES(?1,2,128)",
        &[StoreValue::Blob(namespace.as_bytes().to_vec())],
    )
    .unwrap();
    let before = changes();
    for (objects, bytes) in [(1, 128), (2, 127), (0, 128), (2, 0), (u64::MAX, 128)] {
        assert!(SqliteCommitStore::open_existing(db.clone(), namespace, objects, bytes).is_err());
    }
    assert_eq!(changes(), before);
    let store = SqliteCommitStore::open_existing(db.clone(), namespace, 2, 128).unwrap();
    store
        .put("entries/exact.eip", b"exact private bytes")
        .unwrap();
    drop(store);
    let before = changes();
    let reopened = SqliteCommitStore::open_existing(db.clone(), namespace, 2, 128).unwrap();
    assert_eq!(
        reopened.read_exact("entries/exact.eip").unwrap().as_deref(),
        Some(b"exact private bytes".as_slice())
    );
    assert_eq!(changes(), before);
}
