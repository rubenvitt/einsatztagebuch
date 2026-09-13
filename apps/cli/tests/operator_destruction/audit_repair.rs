use super::*;
use ea_admin::destruction_runtime::NativeDestructionDelivery;
#[test]
fn native_destruction_start_audit_copy_failure_repairs_exact_start_without_removal() {
    let f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    let (provider, key) = database_provider_for(true);
    let admin =
        EncryptedDatabase::open_existing(&f.admin_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    let auth = ea_crypto::object_hash(&f.authorization);
    admin.execute(&format!("CREATE TRIGGER refuse_started_audit BEFORE INSERT ON local_audit_event WHEN instr(NEW.exact_bytes,X'{}')>0 BEGIN SELECT RAISE(ABORT,'fixture start audit unavailable'); END",hex::encode(auth.as_bytes())),&[]).unwrap();
    assert!(
        runtime
            .start(
                requested.destruction_id,
                requested.preflight_hash.unwrap(),
                NativeDestructionDelivery::NoRegisteredServer
            )
            .is_err()
    );
    let (provider, key) = database_provider_for(false);
    let writer =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    let row=writer.query_row("SELECT e.exact_event,e.audit_event_id,a.exact_bytes FROM destruction_job_event e JOIN local_audit_event a ON e.audit_event_id=a.event_id",&[]).unwrap().unwrap();
    let exact_event = row.blob(0).unwrap().to_vec();
    let audit_id = row.blob(1).unwrap().to_vec();
    let exact_audit = row.blob(2).unwrap().to_vec();
    let inventory = ea_archive::ArchiveInventory::build(
        &ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap(),
    )
    .unwrap();
    assert_eq!(inventory.entries().len(), 1);
    assert_eq!(inventory.destroyed().len(), 0);
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM destruction_local_measurement", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    drop(runtime);
    admin
        .execute("DROP TRIGGER refuse_started_audit", &[])
        .unwrap();
    let mut reopened = f.runtime();
    assert_eq!(
        reopened
            .start(
                requested.destruction_id,
                requested.preflight_hash.unwrap(),
                NativeDestructionDelivery::NoRegisteredServer
            )
            .unwrap()
            .state
            .code(),
        1
    );
    let row = writer
        .query_row(
            "SELECT exact_event,audit_event_id FROM destruction_job_event",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(row.blob(0).unwrap(), exact_event);
    assert_eq!(row.blob(1).unwrap(), audit_id);
    let copied = admin
        .query_row(
            "SELECT exact_bytes FROM local_audit_event WHERE event_id=?1",
            &[ea_local_store::StoreValue::Blob(audit_id)],
        )
        .unwrap()
        .unwrap();
    assert_eq!(copied.blob(0).unwrap(), exact_audit);
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM destruction_job_event", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
}
