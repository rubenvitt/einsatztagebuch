//! Actual NoServer Desktop IPC completion. The Reader attestation is a
//! historically verified synthetic service input, not an OPFS execution claim.
use super::*;

#[test]
fn native_desktop_resume_closes_complete_no_server_job_and_reopens_exact_history() {
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
    let pending = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(pending["process"]["state"], "inProgress");
    assert!(
        pending["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|replica| replica["resultCode"].is_null())
    );

    let db = super::super::completion::writer_database(&f);
    let reader = super::super::completion::fixture_reader_claim(&f, &db);
    let imported = serde_json::to_value(
        destruction_import_progress_core(&state, &id, &job, &[reader]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        imported["process"]["state"], "inProgress",
        "imported complete claims do not synthesize a signed transition"
    );
    assert!(
        imported["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .all(|replica| replica["resultCode"] == 0)
    );
    drop(state);
    drop(host);

    let host = desktop(&f);
    host.login().unwrap();
    let state = host.desktop_state();
    let completed = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(completed["process"]["state"], "completeManagedScope");
    assert_eq!(
        completed["process"]["preflight"],
        prepared["process"]["preflight"]
    );
    assert_eq!(
        completed["process"]["replicas"].as_array().unwrap().len(),
        denominator
    );
    assert!(
        completed["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .all(|replica| replica["resultCode"] == 0 && replica["attestationHash"].is_string())
    );
    assert!(
        completed["process"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|target| target["stubObjectHash"].is_string())
    );
    assert!(
        completed["process"]["evidenceEntryHash"].is_null(),
        "completion does not replace normal Writer Evidence finalization"
    );
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
    assert_eq!(reconstructed["process"], completed["process"]);
    let replayed = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(replayed["process"], completed["process"]);
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_import_batch", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        batches
    );
    assert_eq!(db.query_row(
        "SELECT exact_context FROM destruction_import_batch ORDER BY insertion_sequence DESC LIMIT 1",
        &[],
    ).unwrap().unwrap().blob(0).unwrap(), persisted);
}
