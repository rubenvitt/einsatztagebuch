//! Real configured NativeDesktopRuntime -> existing destruction_action -> native
//! exporter -> IPC JSON. No Reader execution or file download is simulated here.
use super::*;
use ea_desktop::commands::destruction::destruction_export_reader_delivery_core;
use ea_sync_protocol::DestructionJobUploadV1;

fn bytes(value: &serde_json::Value, key: &str) -> Vec<u8> {
    serde_json::from_value(value[key].clone()).unwrap()
}
fn selection(prepared: &serde_json::Value) -> (String, String, String) {
    let process = &prepared["process"];
    (
        process["destructionId"].as_str().unwrap().to_owned(),
        process["preflight"]["jobHash"].as_str().unwrap().to_owned(),
        process["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kindCode"] == 1)
            .unwrap()["deviceId"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}
#[test]
fn native_configured_desktop_reader_delivery_exports_three_originals_and_reopens_without_unlock_bypass()
 {
    let f = NativeDestructionFixture::without_server();
    let (config, _) = custodian::configuration(&f);
    let host = custodian::configured(&f, &config);
    host.login().unwrap();
    let state = host.desktop_state();
    let prepared =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let (id, job, reader) = selection(&prepared);
    assert!(
        destruction_export_reader_delivery_core(&state, &id, &job, &reader).is_err(),
        "no Started event"
    );
    destruction_read_core(&state, Some(&id)).unwrap();
    let started = serde_json::to_value(destruction_start_core(&state, &id, &job).unwrap()).unwrap();
    let exported = serde_json::to_value(
        destruction_export_reader_delivery_core(&state, &id, &job, &reader).unwrap(),
    )
    .unwrap();
    assert_eq!(exported["destructionId"], id);
    assert_eq!(exported["jobHash"], job);
    assert_eq!(exported["readerId"], reader);
    assert_eq!(bytes(&exported, "exactAuthorization"), f.authorization);
    let (provider, key) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    let saved=db.query_row("SELECT exact_core,exact_signature,exact_inventory,signer_certificate_hash FROM destruction_job",&[]).unwrap().unwrap();
    let upload = DestructionJobUploadV1::decode(&bytes(&exported, "exactJobUpload")).unwrap();
    assert_eq!(upload.core_bytes(), saved.blob(0).unwrap());
    assert_eq!(upload.signature_bytes(), saved.blob(1).unwrap());
    assert_eq!(upload.inventory_bytes(), saved.blob(2).unwrap());
    assert_eq!(upload.certificate_hash().as_bytes(), saved.blob(3).unwrap());
    let saved_event = db
        .query_row(
            "SELECT exact_event FROM destruction_job_event ORDER BY insertion_sequence LIMIT 1",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        bytes(&exported, "exactInitiatingEvent"),
        saved_event.blob(0).unwrap()
    );
    let after = serde_json::to_value(destruction_read_core(&state, Some(&id)).unwrap()).unwrap();
    assert_eq!(
        after, started,
        "original export creates no Reader claim or progress"
    );
    drop(state);
    drop(host);
    let reopened = custodian::configured(&f, &config);
    reopened.login().unwrap();
    let state = reopened.desktop_state();
    assert!(
        destruction_export_reader_delivery_core(&state, &id, &job, &reader).is_err(),
        "Admin host login is not a Destruction unlock"
    );
    destruction_read_core(&state, Some(&id)).unwrap();
    let durable = serde_json::to_value(
        destruction_export_reader_delivery_core(&state, &id, &job, &reader).unwrap(),
    )
    .unwrap();
    assert_eq!(durable, exported);
    reopened.invalidate();
    assert_eq!(
        destruction_export_reader_delivery_core(&state, &id, &job, &reader)
            .err()
            .unwrap()
            .code,
        "EA-DESKTOP-ADMINISTRATION-FORBIDDEN"
    );
}
#[test]
fn native_configured_desktop_reader_delivery_refuses_changed_job_and_wrong_reader() {
    let f = NativeDestructionFixture::without_server();
    let (config, _) = custodian::configuration(&f);
    let host = custodian::configured(&f, &config);
    host.login().unwrap();
    let state = host.desktop_state();
    let prepared =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let (id, job, reader) = selection(&prepared);
    destruction_start_core(&state, &id, &job).unwrap();
    for (selected_id, selected_job, selected_reader) in [
        (id.clone(), "ff".repeat(32), reader.clone()),
        ("ee".repeat(16), job.clone(), reader.clone()),
        (
            id.clone(),
            job.clone(),
            prepared["process"]["custodianDeviceId"]
                .as_str()
                .unwrap()
                .to_owned(),
        ),
        (id.clone(), job.clone(), "dd".repeat(16)),
    ] {
        assert!(
            destruction_export_reader_delivery_core(
                &state,
                &selected_id,
                &selected_job,
                &selected_reader
            )
            .is_err()
        );
        let after =
            serde_json::to_value(destruction_read_core(&state, Some(&id)).unwrap()).unwrap();
        assert_eq!(after["process"]["preflight"]["jobHash"], job);
        assert_eq!(after["process"]["state"], "inProgress");
        assert!(after["process"]["evidenceEntryHash"].is_null());
    }
    assert!(destruction_export_reader_delivery_core(&state, &id, &job, &reader).is_ok());
}
