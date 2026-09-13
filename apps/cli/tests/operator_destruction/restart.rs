use super::*;
#[test]
fn native_destruction_existing_requested_survives_restart_and_unrelated_head_advance() {
    let mut f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let (provider, key) = database_provider_for(true);
    let admin =
        EncryptedDatabase::open_existing(&f.admin_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    let auth = ea_crypto::object_hash(&f.authorization);
    admin.execute(&format!("CREATE TRIGGER refuse_requested_audit BEFORE INSERT ON local_audit_event WHEN instr(NEW.exact_bytes,X'{}')>0 BEGIN SELECT RAISE(ABORT,'fixture audit unavailable'); END",hex::encode(auth.as_bytes())),&[]).unwrap();
    assert!(runtime.prepare(&f.authorization).is_err());
    let (provider, key) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    let row = db
        .query_row(
            "SELECT exact_authorization,exact_event,audit_event_id FROM destruction_request",
            &[],
        )
        .unwrap()
        .unwrap();
    let exact = (
        row.blob(0).unwrap().to_vec(),
        row.blob(1).unwrap().to_vec(),
        row.blob(2).unwrap().to_vec(),
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_job", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    drop(runtime);
    admin
        .execute("DROP TRIGGER refuse_requested_audit", &[])
        .unwrap();
    f.advance_unrelated_head();
    let mut reopened = f.runtime();
    let status = reopened.prepare(&f.authorization).unwrap();
    assert_eq!(status.state.code(), 0);
    assert!(
        status.preflight_hash.is_some(),
        "same historical request gets a currently authorized preflight"
    );
    assert!(status.authorization_hash == auth);
    let row = db
        .query_row(
            "SELECT exact_authorization,exact_event,audit_event_id FROM destruction_request",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(row.blob(0).unwrap(), exact.0);
    assert_eq!(row.blob(1).unwrap(), exact.1);
    assert_eq!(row.blob(2).unwrap(), exact.2);
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_request", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
}
#[test]
fn native_destruction_new_request_cannot_select_an_obsolete_authorization_head() {
    let mut f = NativeDestructionFixture::without_server();
    f.advance_unrelated_head();
    assert!(f.runtime().prepare(&f.authorization).is_err());
    let (provider, key) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_request", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
}
