use super::*;
use ea_admin::destruction_runtime::NativeDestructionDelivery;
#[test]
fn native_destruction_no_server_refuses_verified_future_and_revoked_server_holdings() {
    for mode in [1, 2] {
        let f = NativeDestructionFixture::with_server_state(false, mode);
        let mut runtime = f.runtime();
        let requested = match runtime.prepare(&f.authorization) {
            Ok(value) => value,
            Err(ea_admin::destruction_runtime::NativeDestructionError::Core(
                ea_destruction::DestructionError::Format,
            )) if mode == 1 => {
                // The signed complete catalog knows this future server, while
                // the present signing context cannot validate its future
                // custody certificate. Refusal is never absence proof.
                continue;
            }
            Err(error) => panic!("server mode {mode}: {error}"),
        };
        assert!(
            requested
                .replicas
                .iter()
                .any(|replica| replica.kind == ea_destruction::ManagedReplicaKind::SyncServer)
        );
        assert!(
            runtime
                .start(
                    requested.destruction_id,
                    requested.preflight_hash.unwrap(),
                    NativeDestructionDelivery::NoRegisteredServer
                )
                .is_err(),
            "future/revoked server mode {mode} remains obligation"
        );
        assert_eq!(
            runtime
                .status(requested.destruction_id)
                .unwrap()
                .state
                .code(),
            0
        );
    }
}
#[test]
fn native_destruction_no_server_refuses_missing_durable_custody_snapshot() {
    let f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    let (provider, key) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    // Deliberately corrupt this isolated fixture's otherwise immutable store.
    // Production has no such path and leaves these triggers intact.
    db.execute("DROP TRIGGER destruction_inventory_no_update", &[])
        .unwrap();
    db.execute("UPDATE destruction_inventory SET exact_bytes=X'80'", &[])
        .unwrap();
    assert!(
        runtime
            .start(
                requested.destruction_id,
                requested.preflight_hash.unwrap(),
                NativeDestructionDelivery::NoRegisteredServer
            )
            .is_err(),
        "empty persisted custody is not proof that servers are absent"
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_job_event", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
}
