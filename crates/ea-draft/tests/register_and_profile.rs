//! Das Einsatznummernregister und die NUR LESENDE Profilzeile.

mod support;

use support::DraftHarness;

#[test]
fn retained_equality_token_survives_source_removal_reopen_and_nfc_without_linkage() {
    let harness = DraftHarness::new();
    let org = harness.organization_id();
    let register = harness.incident_number_register();
    register.claim(org, 2026, "Caf\u{e9}-17").unwrap();
    let database = register.database_handle();
    database
        .transaction(|tx| {
            ea_draft::IncidentNumberRegister::retain_for_destruction_in(
                tx,
                org,
                2026,
                "Cafe\u{301}-17",
            )?;
            // Test-only simulation of the later separately authorized exact purge.
            ea_draft::IncidentNumberRegister::release_in(tx, org, 2026, "Caf\u{e9}-17")
        })
        .unwrap();
    let remaining = database
        .query_row("SELECT count(*) FROM incident_number_register", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    assert_eq!(remaining, 0);
    let columns = database
        .query_row(
            "SELECT count(*) FROM pragma_table_info('incident_number_retained_token')",
            &[],
        )
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    assert_eq!(
        columns, 1,
        "token table carries no entry, object, record, job, org or year linkage"
    );
    drop(database);
    drop(register);
    let mut closed = harness.close_repo();
    let reopened = closed.reopen();
    let register = reopened.incident_number_register();
    assert!(register.contains(org, 2026, "Cafe\u{301}-17").unwrap());
    assert_eq!(
        register
            .claim(org, 2026, "Cafe\u{301}-17")
            .unwrap_err()
            .code(),
        "EA-DRAFT-INCIDENT-NUMBER-TAKEN"
    );
    register.claim(org, 2027, "Caf\u{e9}-17").unwrap();
    register.claim(org, 2026, "Cafe-17").unwrap();
    assert!(
        register
            .database_handle()
            .execute("DELETE FROM incident_number_retained_token", &[])
            .is_err()
    );
    assert!(
        register
            .database_handle()
            .execute(
                "UPDATE incident_number_retained_key SET key_bytes=zeroblob(32)",
                &[]
            )
            .is_err()
    );
}

#[test]
fn tokens_without_restored_key_fail_closed_and_retention_rolls_back_atomically() {
    use ea_local_store::{StoreError, StoreValue};
    let harness = DraftHarness::new();
    let register = harness.incident_number_register();
    let database = register.database_handle();
    let org = harness.organization_id();
    let aborted: Result<(), ea_draft::DraftError> = database.transaction(|tx| {
        ea_draft::IncidentNumberRegister::retain_for_destruction_in(tx, org, 2026, "2026-17")?;
        Err(ea_draft::DraftError::Store(StoreError::Database))
    });
    assert!(aborted.is_err());
    for table in [
        "incident_number_retained_key",
        "incident_number_retained_token",
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
    database
        .execute(
            "INSERT INTO incident_number_retained_token(token) VALUES(?1)",
            &[StoreValue::Blob(vec![0x49; 32])],
        )
        .unwrap();
    assert!(
        register.claim(org, 2026, "2026-17").is_err(),
        "a partial restore must not initialize a new equality key"
    );
    assert!(register.contains(org, 2026, "2026-17").is_err());
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM incident_number_retained_key", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
}

#[test]
fn the_register_rejects_a_second_claim_of_the_same_key_and_accepts_another_year() {
    let harness = DraftHarness::new();
    let register = harness.incident_number_register();
    register
        .claim(harness.organization_id(), 2026, "2026-0001")
        .unwrap();
    assert_eq!(
        register
            .claim(harness.organization_id(), 2026, "2026-0001")
            .unwrap_err()
            .code(),
        "EA-DRAFT-INCIDENT-NUMBER-TAKEN"
    );
    register
        .claim(harness.organization_id(), 2027, "2026-0001")
        .unwrap();
    assert!(
        register
            .contains(harness.organization_id(), 2026, "2026-0001")
            .unwrap()
    );
}

#[test]
fn the_operator_profile_row_is_readable_and_has_no_write_path() {
    let harness = DraftHarness::with_seeded_operator_profile();
    let profile = harness.operator_profile_repo().load().unwrap().unwrap();
    assert_eq!(profile.display_name(), "Ada Lovelace");
    // Byteweise verglichen und nicht ueber den Newtype: `ObjectHash` traegt in
    // diesem Bauwerk bewusst KEINE Formatierung, und `assert_eq!` verlangt
    // `Debug` fuer seine Fehlermeldung. Die Aussage ist dieselbe — dreissig
    // zwei Bytes gegen dreissig zwei Bytes desselben Typs.
    assert_eq!(
        profile.operator_binding_object_hash().as_bytes(),
        harness.bound_operator_binding_object_hash().as_bytes()
    );
}
