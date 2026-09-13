//! Actual NoServer Desktop IPC Failure-only transition and durable replay.
//! The overdue Reader backup is a certified synthetic claim: state4 records
//! missing timely confirmation, never a measured outage or physical removal.
use super::*;

#[test]
fn native_desktop_resume_marks_overdue_backup_incomplete_and_reopens_exact_history() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let host = desktop(&f);
    host.login().unwrap();
    let state = host.desktop_state();
    let prepared =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let process = &prepared["process"];
    let id = process["destructionId"].as_str().unwrap().to_owned();
    let job = process["preflight"]["jobHash"].as_str().unwrap().to_owned();
    let denominator = process["replicas"].as_array().unwrap().len();
    destruction_start_core(&state, &id, &job).unwrap();
    let running = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(
        running["process"]["state"], "inProgress",
        "a never attested duty alone is not routed to Failure"
    );
    assert!(
        running["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|replica| replica["resultCode"].is_null())
    );

    let db = super::super::completion::writer_database(&f);
    let overdue = super::super::pending::changed_reader_claim(&f, &db, |claim| {
        claim.result = 1;
        claim.backup_expiry_at = Some(UnixMillis::new(claim.executed_at.get() + 1));
    });
    let imported = serde_json::to_value(
        destruction_import_progress_core(&state, &id, &job, &[overdue]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        imported["process"]["state"], "inProgress",
        "imported overdue claims do not synthesize a signed transition"
    );
    assert!(
        imported["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|replica| replica["resultCode"] == 1 && replica["backupExpiryAt"].is_number())
    );
    drop(state);
    drop(host);

    let host = desktop(&f);
    host.login().unwrap();
    let state = host.desktop_state();
    let failed = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(failed["process"]["state"], "incompleteUnreachableReplica");
    assert_eq!(
        failed["process"]["preflight"],
        prepared["process"]["preflight"]
    );
    assert_eq!(
        failed["process"]["replicas"].as_array().unwrap().len(),
        denominator
    );
    assert!(
        failed["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .all(
                |replica| (replica["resultCode"] == 0 || replica["resultCode"] == 1)
                    && replica["attestationHash"].is_string()
            ),
        "the original duty set and exact claims stay visible"
    );
    assert!(
        failed["process"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|target| target["stubObjectHash"].is_string())
    );
    assert!(
        failed["process"]["evidenceEntryHash"].is_null(),
        "Failure does not replace normal Writer Evidence finalization"
    );
    let audits = db
        .query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    let persisted = db.query_row(
        "SELECT exact_context FROM destruction_import_batch ORDER BY insertion_sequence DESC LIMIT 1",
        &[],
    ).unwrap().unwrap().blob(0).unwrap().to_vec();
    let batches = db
        .query_row("SELECT count(*) FROM destruction_import_batch", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    drop(state);
    drop(host);

    let reopened = desktop(&f);
    reopened.login().unwrap();
    let state = reopened.desktop_state();
    let reconstructed =
        serde_json::to_value(destruction_read_core(&state, Some(&id)).unwrap()).unwrap();
    assert_eq!(reconstructed["process"], failed["process"]);
    let replayed = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(
        replayed["process"], failed["process"],
        "Resume in state4 neither retries nor re-signs"
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_import_batch", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        batches
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM local_audit_event", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        audits
    );
    assert_eq!(db.query_row(
        "SELECT exact_context FROM destruction_import_batch ORDER BY insertion_sequence DESC LIMIT 1",
        &[],
    ).unwrap().unwrap().blob(0).unwrap(), persisted);
}
