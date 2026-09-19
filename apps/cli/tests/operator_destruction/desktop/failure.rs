//! Actual NoServer Desktop IPC (Ruling 13.09.2026): Resume never records
//! state4; only the explicit, separately confirmed action does. Overdue Reader
//! backups are certified synthetic claims: state4 records missing timely
//! confirmation, never a measured outage or physical removal.
use super::super::failure::{context, count, exact_failure_event};
use super::*;

const NOT_OFFERED: &str = "EA-DESTRUCTION-MARK-INCOMPLETE-NOT-OFFERED";

fn started_hash(db: &EncryptedDatabase) -> ObjectHash {
    ObjectHash::try_from(
        db.query_row("SELECT event_hash FROM destruction_job_event", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
    )
    .unwrap()
}
fn transition_time(exact: &[u8]) -> UnixMillis {
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DestructionTransition(fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    fields.executed_at
}
fn claim_deadline(exact: &[u8]) -> UnixMillis {
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    fields.backup_expiry_at.unwrap()
}
fn json(
    value: Result<
        ea_desktop::commands::destruction::DestructionAdministrationWire,
        ea_desktop::commands::CommandError,
    >,
) -> serde_json::Value {
    serde_json::to_value(value.unwrap()).unwrap()
}
/// Prepare, Start and the first Resume (local Writer cleanup) in one host.
fn cleaned(f: &NativeDestructionFixture) -> (String, String, serde_json::Value) {
    let host = desktop(f);
    host.login().unwrap();
    let state = host.desktop_state();
    let prepared = json(destruction_prepare_core(&state, &f.authorization));
    let id = prepared["process"]["destructionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let job = prepared["process"]["preflight"]["jobHash"]
        .as_str()
        .unwrap()
        .to_owned();
    destruction_start_core(&state, &id, &job).unwrap();
    let running = json(destruction_resume_core(&state, &id));
    assert_eq!(running["process"]["state"], "inProgress");
    (id, job, prepared)
}
fn assert_original_duty_set(failed: &serde_json::Value, prepared: &serde_json::Value) {
    assert_eq!(failed["process"]["state"], "incompleteUnreachableReplica");
    assert_eq!(
        failed["process"]["preflight"],
        prepared["process"]["preflight"]
    );
    assert_eq!(
        failed["process"]["replicas"].as_array().unwrap().len(),
        prepared["process"]["replicas"].as_array().unwrap().len()
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
}

#[test]
fn native_desktop_resume_keeps_an_elapsed_attested_deadline_open_and_only_the_explicit_action_records_state4()
 {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let (id, job, prepared) = cleaned(&f);
    let db = super::super::completion::writer_database(&f);
    let overdue = super::super::pending::changed_reader_claim(&f, &db, |claim| {
        claim.result = 1;
        claim.backup_expiry_at = Some(UnixMillis::new(claim.executed_at.get() + 1));
    });
    let deadline = claim_deadline(&overdue);
    {
        let host = desktop(&f);
        host.login().unwrap();
        let imported = json(destruction_import_progress_core(
            &host.desktop_state(),
            &id,
            &job,
            &[overdue],
        ));
        assert_eq!(imported["process"]["state"], "inProgress");
        assert!(
            imported["process"]["replicas"]
                .as_array()
                .unwrap()
                .iter()
                .any(|replica| replica["resultCode"] == 1
                    && replica["backupExpiryAt"] == deadline.get())
        );
    }

    let host = desktop(&f);
    host.login().unwrap();
    let state = host.desktop_state();
    let resumed = json(destruction_resume_core(&state, &id));
    assert_eq!(
        resumed["process"]["state"], "inProgress",
        "Resume never records state4, also after the attested deadline (D-3)"
    );
    let batches = count(&db, "destruction_import_batch");
    let audits = count(&db, "local_audit_event");

    // Offered, but the native core itself refuses a stale job binding.
    let refused = destruction_mark_incomplete_core(&state, &id, &"ef".repeat(32))
        .err()
        .expect("the native core refuses a stale job binding");
    assert_eq!(refused.code, "EA-DESTRUCTION-SECURITY-CONFLICT");
    assert_eq!(count(&db, "destruction_import_batch"), batches);
    assert_eq!(count(&db, "local_audit_event"), audits);
    let unchanged = json(destruction_read_core(&state, Some(&id)));
    assert_eq!(unchanged["process"], resumed["process"]);

    let failed = json(destruction_mark_incomplete_core(&state, &id, &job));
    assert_original_duty_set(&failed, &prepared);
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
    assert_eq!(count(&db, "destruction_import_batch"), batches + 1);
    let event = exact_failure_event(&f, &context(&db), 1, started_hash(&db));
    assert!(
        transition_time(&event) >= deadline,
        "the signed event itself is not earlier than the attested deadline"
    );
    let audits = count(&db, "local_audit_event");
    let batches = count(&db, "destruction_import_batch");
    let persisted = context(&db);
    drop(state);
    drop(host);

    let reopened = desktop(&f);
    reopened.login().unwrap();
    let state = reopened.desktop_state();
    assert_eq!(
        json(destruction_read_core(&state, Some(&id)))["process"],
        failed["process"]
    );
    // Ruling G2 (DRK-319): Resume in state4 never idles silently. Without a
    // server duty and server transport the retry is refused explicitly; it
    // neither retries nor re-signs (append check below).
    assert_eq!(
        destruction_resume_core(&state, &id)
            .err()
            .expect("no silent no-op in state4")
            .code,
        "EA-DESTRUCTION-RETRY-NO-SERVER-DUTY"
    );
    // A refused native action closes the session; a new explicit login follows.
    reopened.login().unwrap();
    assert_eq!(
        destruction_mark_incomplete_core(&state, &id, &job)
            .err()
            .expect("no offer in state4")
            .code,
        NOT_OFFERED
    );
    assert_eq!(count(&db, "destruction_import_batch"), batches);
    assert_eq!(count(&db, "local_audit_event"), audits);
    assert_eq!(context(&db), persisted);
    assert_eq!(
        json(destruction_read_core(&state, Some(&id)))["process"],
        failed["process"]
    );
}

#[test]
fn native_desktop_explicit_action_records_a_never_attested_reader_as_state4() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let (id, job, prepared) = cleaned(&f);
    let db = super::super::completion::writer_database(&f);
    let host = desktop(&f);
    host.login().unwrap();
    let state = host.desktop_state();
    let waiting = json(destruction_resume_core(&state, &id));
    assert_eq!(
        waiting["process"]["state"], "inProgress",
        "Resume does not act on a never attested duty"
    );
    let failed = json(destruction_mark_incomplete_core(&state, &id, &job));
    assert_original_duty_set(&failed, &prepared);
    assert!(
        failed["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|replica| replica["kindCode"] == 1
                && replica["resultCode"].is_null()
                && replica["attestationHash"].is_null()),
        "the never attested duty stays visible without any claim"
    );
    exact_failure_event(&f, &context(&db), 1, started_hash(&db));
    drop(state);
    drop(host);
    let reopened = desktop(&f);
    reopened.login().unwrap();
    assert_eq!(
        json(destruction_read_core(&reopened.desktop_state(), Some(&id)))["process"],
        failed["process"]
    );
}

#[test]
fn native_desktop_explicit_action_records_pending_backup_expiry_after_its_deadline_as_state4() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let host = desktop(&f);
    host.login().unwrap();
    let state = host.desktop_state();
    let prepared = json(destruction_prepare_core(&state, &f.authorization));
    let id = prepared["process"]["destructionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let job = prepared["process"]["preflight"]["jobHash"]
        .as_str()
        .unwrap()
        .to_owned();
    destruction_start_core(&state, &id, &job).unwrap();
    let db = super::super::completion::writer_database(&f);
    // A valid historical state2 while its signed +1ms bound ran.
    let original = super::super::import::changed_objects(
        &f,
        &db,
        |claim| {
            claim.backup_expiry_at = Some(UnixMillis::new(claim.executed_at.get() + 1));
        },
        |_| {},
    );
    let objects = super::super::import::with_reader_pending_original(&f, original);
    let deadline = claim_deadline(&objects[1]);
    let pending = json(destruction_import_progress_core(
        &state, &id, &job, &objects,
    ));
    assert_eq!(pending["process"]["state"], "pendingBackupExpiry");
    drop(state);
    drop(host);

    let host = desktop(&f);
    host.login().unwrap();
    let state = host.desktop_state();
    let resumed = json(destruction_resume_core(&state, &id));
    assert_eq!(
        resumed["process"]["state"], "pendingBackupExpiry",
        "Resume never records state4 from state2 after the deadline (D-3)"
    );
    assert!(
        resumed["process"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|target| target["stubObjectHash"].is_string())
    );
    let failed = json(destruction_mark_incomplete_core(&state, &id, &job));
    assert_original_duty_set(&failed, &prepared);
    let event = exact_failure_event(&f, &context(&db), 2, ea_crypto::object_hash(&objects[0]));
    assert!(
        transition_time(&event) >= deadline,
        "the signed 2→4 event is not earlier than the historical maximum"
    );
    drop(state);
    drop(host);
    let reopened = desktop(&f);
    reopened.login().unwrap();
    assert_eq!(
        json(destruction_read_core(&reopened.desktop_state(), Some(&id)))["process"],
        failed["process"]
    );
}
