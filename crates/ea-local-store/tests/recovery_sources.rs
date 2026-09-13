use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};

#[test]
fn source_capture_restore_binding_and_final_report_are_separate_durable_sources() {
    let directory = std::env::temp_dir().join(format!("ea-recovery-ledger-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let provider = InMemoryKeyProvider::new_for_test([74; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let path = directory.join("sources.db");
    let database = EncryptedDatabase::open(&path, &provider, &key).unwrap();
    for table in [
        "recovery_source_scope",
        "recovery_restore_binding",
        "recovery_test_report",
        "recovery_test_failure",
    ] {
        assert_eq!(
            database
                .query_row(&format!("SELECT count(*) FROM {table}"), &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap(),
            0
        );
    }
    let hash = StoreValue::Blob(vec![75; 32]);
    let event = StoreValue::Blob(vec![76; 16]);
    let exact = StoreValue::Blob(vec![1]);
    assert!(
        database
            .execute(
                "INSERT INTO recovery_source_scope VALUES(?1,?2,?3)",
                &[hash.clone(), exact.clone(), event.clone()]
            )
            .is_err()
    );
    database
        .execute(
            "INSERT INTO local_audit_event(event_id,exact_bytes,object_hash) VALUES(?1,?2,?3)",
            &[event.clone(), exact.clone(), hash.clone()],
        )
        .unwrap();
    database
        .execute(
            "INSERT INTO recovery_source_scope VALUES(?1,?2,?3)",
            &[hash.clone(), exact.clone(), event.clone()],
        )
        .unwrap();
    assert!(
        database
            .execute("DELETE FROM recovery_source_scope", &[])
            .is_err()
    );
    assert!(
        database
            .execute(
                "UPDATE recovery_source_scope SET exact_envelope=?1",
                &[StoreValue::Blob(vec![2])]
            )
            .is_err()
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM recovery_test_report", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    database.execute("INSERT INTO recovery_test_failure VALUES(?1,?1,?1,?2,?3,100)",&[hash.clone(),exact.clone(),event.clone()]).unwrap();
    assert!(database.execute("UPDATE recovery_test_failure SET failed_at=101",&[]).is_err());
    assert!(database.execute("DELETE FROM recovery_test_failure",&[]).is_err());
    drop(database);
    let reopened = EncryptedDatabase::open_existing(&path, &provider, &key).unwrap();
    assert_eq!(
        reopened
            .query_row("SELECT source_hash FROM recovery_source_scope", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        &[75; 32]
    );
    assert_eq!(reopened.query_row("SELECT exact_report FROM recovery_test_failure",&[]).unwrap().unwrap().blob(0).unwrap(),&[1]);
    assert_eq!(reopened.query_row("SELECT count(*) FROM recovery_test_report",&[]).unwrap().unwrap().integer(0).unwrap(),0);
    drop(reopened);
    std::fs::remove_dir_all(&directory).unwrap();
}
