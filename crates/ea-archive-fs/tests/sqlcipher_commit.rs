mod support;

use ea_archive::ArchiveBackendError;
use ea_archive_fs::{
    AtRestEncryptedStoreV1, ControlledNetworkBackend, LocalCommitComponentV1, SqliteCommitStore,
};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_types::Hash32;
use std::sync::{Arc, Barrier};

#[test]
fn real_sqlcipher_commit_survives_reopen_and_meets_the_measured_network_contract() {
    let (_guard, root) = support::temp_root("native-sqlcipher-commit");
    let provider = InMemoryKeyProvider::new_for_test([0x41; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let path = root.join("operator.sqlite");
    let database = Arc::new(EncryptedDatabase::open(&path, &provider, &key).unwrap());
    let namespace = Hash32::try_from([0x42; 32].as_slice()).unwrap();
    let store = SqliteCommitStore::new(database.clone(), namespace, 2, 128).unwrap();
    let canary = b"EINSATZARCHIV-LOCAL-COMMIT-CANARY-PRIVATE";
    store.put("entries/canary.eip", canary).unwrap();
    assert_eq!(store.get("entries/canary.eip").unwrap(), canary);
    assert_eq!(
        store.at_rest_contains("entries/canary.eip", canary),
        Some(false)
    );
    assert_eq!(
        store.put("entries/canary.eip", b"changed"),
        Err(ArchiveBackendError::ByteConflict)
    );
    assert!(
        database
            .execute(
                "UPDATE local_commit_object SET exact_bytes=?1",
                &[StoreValue::Blob(b"changed".to_vec())]
            )
            .is_err()
    );
    drop(store);
    drop(database);
    let database = Arc::new(EncryptedDatabase::open_existing(&path, &provider, &key).unwrap());
    let store = SqliteCommitStore::new(database.clone(), namespace, 2, 128).unwrap();
    assert_eq!(store.get("entries/canary.eip").unwrap(), canary);
    let foreign = SqliteCommitStore::new(
        database,
        Hash32::try_from([0x43; 32].as_slice()).unwrap(),
        2,
        128,
    )
    .unwrap();
    assert!(foreign.get("entries/canary.eip").is_none());
    let backend = ControlledNetworkBackend::open(
        root.join("network"),
        Some(LocalCommitComponentV1::new(path, Box::new(store))),
        support::controlled_network_profile(),
        &support::policy_allowing_controlled_network(),
    )
    .unwrap();
    assert_eq!(
        backend.local_commit().read("entries/canary.eip").unwrap(),
        canary
    );
    assert!(!format!("{backend:?}").contains("operator.sqlite"));
}

#[test]
fn independent_connections_cannot_overwrite_or_exceed_the_durable_queue_limit() {
    let (_guard, root) = support::temp_root("native-sqlcipher-race");
    let provider = InMemoryKeyProvider::new_for_test([0x51; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let path = root.join("operator.sqlite");
    let namespace = Hash32::try_from([0x52; 32].as_slice()).unwrap();
    let first = Arc::new(
        SqliteCommitStore::new(
            Arc::new(EncryptedDatabase::open(&path, &provider, &key).unwrap()),
            namespace,
            1,
            4,
        )
        .unwrap(),
    );
    let second = Arc::new(
        SqliteCommitStore::new(
            Arc::new(EncryptedDatabase::open_existing(&path, &provider, &key).unwrap()),
            namespace,
            1,
            4,
        )
        .unwrap(),
    );
    let barrier = Arc::new(Barrier::new(2));
    let one = first.clone();
    let two = second.clone();
    let wait = barrier.clone();
    let left = std::thread::spawn(move || {
        wait.wait();
        one.put("entries/one.eip", b"1234")
    });
    let right = std::thread::spawn(move || {
        barrier.wait();
        two.put("entries/two.eip", b"5678")
    });
    let outcomes = [left.join().unwrap(), right.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    let (kept, bytes) = if first.get("entries/one.eip").is_some() {
        ("entries/one.eip", b"1234")
    } else {
        ("entries/two.eip", b"5678")
    };
    first.put(kept, bytes).unwrap();
    assert!(second.put("entries/overflow.eip", b"a").is_err());
    first.remove(kept);
    assert!(second.get(kept).is_none());
    second.put("entries/replacement.eip", b"abcd").unwrap();
    for path in [
        "../outside",
        "/absolute",
        "entries//bad",
        "entries/../bad",
        "entries/with\\backslash",
        "unknown/path",
    ] {
        assert!(first.put(path, b"x").is_err(), "{path}");
    }
}
