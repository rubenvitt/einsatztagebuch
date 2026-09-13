//! Actual NoServer Desktop IPC Pending transition and durable replay.
//! Remote backup is a certified synthetic claim, not a physical WORM proof.
use super::*;

#[test]
fn native_desktop_resume_marks_pending_no_server_job_and_reopens_exact_history() {
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
    let exact_reader = super::super::completion::fixture_reader_claim(&f, &db);
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&exact_reader).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(mut fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    fields.result = 1;
    fields.backup_expiry_at = Some(UnixMillis::new(support::live_clock().get() + 300_000));
    let payload = ea_format::TrustPayloadV1::deletion_attestation(fields).unwrap();
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        READER_OPFS_COMPONENT_SECRET,
    ));
    let signature = signer
        .sign_deletion_attestation_digest(
            f.reader_opfs_component.unwrap(),
            payload.exact_digest_input(),
            &f.authorization,
        )
        .unwrap();
    let reader =
        ea_format::encode_trust(&ea_format::TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .as_bytes()
            .to_vec();
    let imported = serde_json::to_value(
        destruction_import_progress_core(&state, &id, &job, &[reader]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        imported["process"]["state"], "inProgress",
        "imported pending claims do not synthesize a signed transition"
    );
    assert!(
        imported["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|replica| replica["resultCode"] == 1)
    );
    drop(state);
    drop(host);

    let host = desktop(&f);
    host.login().unwrap();
    let state = host.desktop_state();
    let completed = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(completed["process"]["state"], "pendingBackupExpiry");
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
            .all(
                |replica| (replica["resultCode"] == 0 || replica["resultCode"] == 1)
                    && replica["attestationHash"].is_string()
            )
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
        "Pending does not replace normal Writer Evidence finalization"
    );
    assert!(
        completed["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["resultCode"] == 1 && r["backupExpiryAt"].is_number())
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
