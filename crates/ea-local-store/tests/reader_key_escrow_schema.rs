//! Der dauerhafte Zustand des Reader-Key-Escrows (Profil §5 und §8, DRK-458).
//!
//! Publikation und Verbrauch sind append-only; eine Verbrauchszeile wird nie
//! zurückgesetzt. Das verschlüsselte Ergebnis ist die EINZIGE löschbare
//! Tabelle, höchstens eines je Autorisierung, immer an den Abdruck seines
//! Verbrauchs gebunden, und gelöscht wird nur mit einer Abschlusszeile davor.
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};

const DAY_MS: i64 = 86_400_000;

fn blob(fill: u8, length: usize) -> StoreValue {
    StoreValue::Blob(vec![fill; length])
}

fn database(name: &str) -> (std::path::PathBuf, EncryptedDatabase) {
    let directory = std::env::temp_dir().join(format!(
        "ea-escrow-schema-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let provider = InMemoryKeyProvider::new_for_test([91; 32]);
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let database = EncryptedDatabase::open(&directory.join("escrow.db"), &provider, &key).unwrap();
    (directory, database)
}

fn audit(database: &EncryptedDatabase, fill: u8) -> StoreValue {
    let event = blob(fill, 16);
    database
        .execute(
            "INSERT INTO local_audit_event(event_id,exact_bytes,object_hash) VALUES(?1,?2,?3)",
            &[event.clone(), blob(1, 1), blob(fill, 32)],
        )
        .unwrap();
    event
}

fn count(database: &EncryptedDatabase, table: &str) -> i64 {
    database
        .query_row(&format!("SELECT count(*) FROM {table}"), &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}

fn consume(database: &EncryptedDatabase, authorization: u8, transport: u8, event: StoreValue) {
    database
        .execute(
            "INSERT INTO reader_key_escrow_opening(authorization_object_hash,organization_id,escrow_object_hash,target_transport_key_thumbprint,consumed_at_ms,consume_audit_event_id) VALUES(?1,?2,?3,?4,?5,?6)",
            &[
                blob(authorization, 32),
                blob(0x10, 16),
                blob(0x20, 32),
                blob(transport, 32),
                StoreValue::Integer(1_000),
                event,
            ],
        )
        .unwrap();
}

fn store_result(
    database: &EncryptedDatabase,
    authorization: u8,
    transport: u8,
    stored_at: i64,
) -> Result<usize, ea_local_store::StoreError> {
    database.execute(
        "INSERT INTO reader_key_escrow_result(authorization_object_hash,target_transport_key_thumbprint,exact_envelope,stored_at_ms,expires_at_ms) VALUES(?1,?2,?3,?4,?5)",
        &[
            blob(authorization, 32),
            blob(transport, 32),
            blob(0x77, 300),
            StoreValue::Integer(stored_at),
            StoreValue::Integer(stored_at + DAY_MS),
        ],
    )
}

fn close(
    database: &EncryptedDatabase,
    authorization: u8,
    reason: i64,
    event: StoreValue,
) -> Result<usize, ea_local_store::StoreError> {
    database.execute(
        "INSERT INTO reader_key_escrow_result_closure(authorization_object_hash,reason,closed_at_ms,audit_event_id) VALUES(?1,?2,?3,?4)",
        &[
            blob(authorization, 32),
            StoreValue::Integer(reason),
            StoreValue::Integer(2_000),
            event,
        ],
    )
}

#[test]
fn the_escrow_tables_start_empty() {
    let (_directory, database) = database("empty");
    for table in [
        "reader_key_escrow_publication",
        "reader_key_escrow_opening",
        "reader_key_escrow_result",
        "reader_key_escrow_result_closure",
    ] {
        assert_eq!(count(&database, table), 0, "{table}");
    }
}

/// Die Publikation ist append-only und an ihre signierte Auditzeile gebunden.
#[test]
fn a_publication_row_is_immutable_and_bound_to_its_audit() {
    let (_directory, database) = database("publication");
    let insert = |event: StoreValue, package: u8| {
        database.execute(
            "INSERT INTO reader_key_escrow_publication(package_hash,organization_id,reader_certificate_hash,reader_subject_id,approval_object_hash,escrow_object_hash,exact_approval,exact_escrow,audit_event_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            &[
                blob(package, 32),
                blob(0x10, 16),
                blob(0x11, 32),
                blob(0x12, 16),
                blob(package.wrapping_add(1), 32),
                blob(package.wrapping_add(2), 32),
                blob(0x13, 100),
                blob(0x14, 100),
                event,
            ],
        )
    };
    assert!(insert(blob(0x99, 16), 0x40).is_err(), "no audit, no row");
    let event = audit(&database, 0x51);
    insert(event, 0x40).unwrap();
    for statement in [
        "UPDATE reader_key_escrow_publication SET exact_escrow=x'00'",
        "DELETE FROM reader_key_escrow_publication",
    ] {
        assert!(database.execute(statement, &[]).is_err(), "{statement}");
    }
    assert_eq!(count(&database, "reader_key_escrow_publication"), 1);
}

/// Eine Verbrauchszeile wird NIE zurückgesetzt.
#[test]
fn a_consumption_row_is_never_reset() {
    let (_directory, database) = database("opening");
    let event = audit(&database, 0x52);
    consume(&database, 0xa1, 0xb1, event);
    for statement in [
        "UPDATE reader_key_escrow_opening SET consumed_at_ms=0",
        "DELETE FROM reader_key_escrow_opening",
    ] {
        assert!(database.execute(statement, &[]).is_err(), "{statement}");
    }
    assert_eq!(count(&database, "reader_key_escrow_opening"), 1);
}

/// Das Ergebnis gehört zu genau einem Verbrauch mit GLEICHEM Abdruck: eine
/// Umverschlüsselung an einen anderen Schlüssel ist schon im Schema
/// ausgeschlossen, ebenso ein zweites Ergebnis und jede Änderung.
#[test]
fn a_result_is_bound_to_its_consumption_and_its_transport_key() {
    let (_directory, database) = database("result");
    assert!(
        store_result(&database, 0xa1, 0xb1, 1_000).is_err(),
        "no consumption, no result"
    );
    let event = audit(&database, 0x53);
    consume(&database, 0xa1, 0xb1, event);
    assert!(
        store_result(&database, 0xa1, 0xb2, 1_000).is_err(),
        "another transport key"
    );
    store_result(&database, 0xa1, 0xb1, 1_000).unwrap();
    assert!(
        store_result(&database, 0xa1, 0xb1, 1_001).is_err(),
        "one result per authorization"
    );
    assert!(
        database
            .execute(
                "UPDATE reader_key_escrow_result SET exact_envelope=x'00'",
                &[]
            )
            .is_err()
    );
    // Die Höchsthaltedauer steht im Schema: genau 86 400 000 ms.
    let second = audit(&database, 0x54);
    consume(&database, 0xa2, 0xb1, second);
    assert!(
        database
            .execute(
                "INSERT INTO reader_key_escrow_result(authorization_object_hash,target_transport_key_thumbprint,exact_envelope,stored_at_ms,expires_at_ms) VALUES(?1,?2,?3,?4,?5)",
                &[
                    blob(0xa2, 32),
                    blob(0xb1, 32),
                    blob(0x77, 300),
                    StoreValue::Integer(1_000),
                    StoreValue::Integer(1_000 + DAY_MS + 1),
                ],
            )
            .is_err()
    );
}

/// Gelöscht wird nur nach der Abschlusszeile; danach entsteht nie wieder ein
/// Ergebnis zu derselben Autorisierung.
#[test]
fn a_result_is_deleted_only_after_its_closure_and_never_recreated() {
    let (_directory, database) = database("closure");
    let consumed = audit(&database, 0x55);
    consume(&database, 0xa1, 0xb1, consumed);
    let closing = audit(&database, 0x56);
    assert!(
        close(&database, 0xa1, 0, closing.clone()).is_err(),
        "no result, nothing to close"
    );
    store_result(&database, 0xa1, 0xb1, 1_000).unwrap();
    assert!(
        database
            .execute("DELETE FROM reader_key_escrow_result", &[])
            .is_err(),
        "no deletion without a closure"
    );
    assert!(
        close(&database, 0xa1, 2, closing.clone()).is_err(),
        "reason 0 or 1"
    );
    close(&database, 0xa1, 0, closing).unwrap();
    database
        .execute("DELETE FROM reader_key_escrow_result", &[])
        .unwrap();
    assert_eq!(count(&database, "reader_key_escrow_result"), 0);
    assert!(
        store_result(&database, 0xa1, 0xb1, 3_000).is_err(),
        "a closed authorization never receives a result again"
    );
    for statement in [
        "UPDATE reader_key_escrow_result_closure SET reason=1",
        "DELETE FROM reader_key_escrow_result_closure",
    ] {
        assert!(database.execute(statement, &[]).is_err(), "{statement}");
    }
}
