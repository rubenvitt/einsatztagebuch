//! Actual configured Desktop Pending transport over TLS/PG/S3. The retained
//! Reader backup is a certified synthetic claim, not actual remote WORM storage.
use super::*;

#[test]
fn native_desktop_pending_publishes_exact_transition_and_synchronize_preserves_it() {
    let began = std::time::Instant::now();
    let f = NativeDestructionFixture::with_reader_opfs();
    fs::write(f.admin_directory.join("long-recovery-run"), b"").unwrap();
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let prepared =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let id = prepared["process"]["destructionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let hash = prepared["process"]["preflight"]["jobHash"]
        .as_str()
        .unwrap()
        .to_owned();
    destruction_start_core(&state, &id, &hash).unwrap();
    drop(state);
    drop(host);
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let cleaned = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(cleaned["process"]["state"], "inProgress");
    assert!(
        cleaned["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kindCode"] == 1 && r["resultCode"].is_null())
    );
    eprintln!(
        "Pending transport: local cleanup and real server response {:?}",
        began.elapsed()
    );
    let db = super::super::super::super::completion::writer_database(&f);
    let reader = super::super::super::super::completion::fixture_reader_claim(&f, &db);
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&reader).unwrap() else {
        panic!()
    };
    let DecodedTrustPayloadV1::DeletionAttestation(mut fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    fields.result = 1;
    fields.backup_expiry_at = Some(ea_types::UnixMillis::new(
        support::live_clock().get() + 900_000,
    ));
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
        ea_desktop::commands::destruction::destruction_import_progress_core(
            &state,
            &id,
            &hash,
            &[reader],
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        imported["process"]["state"], "inProgress",
        "historical import does not produce a transition"
    );
    drop(state);
    drop(host);

    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let pending = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(pending["process"]["state"], "pendingBackupExpiry");
    assert_eq!(
        pending["process"]["preflight"],
        prepared["process"]["preflight"]
    );
    assert_eq!(
        pending["process"]["replicas"].as_array().unwrap().len(),
        prepared["process"]["replicas"].as_array().unwrap().len()
    );
    assert!(
        pending["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["attestationHash"].is_string()
                && ((r["kindCode"] == 1 && r["resultCode"] == 1)
                    || (r["kindCode"] != 1 && r["resultCode"] == 0)))
    );
    assert!(
        pending["process"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["stubObjectHash"].is_string())
    );
    assert!(pending["process"]["evidenceEntryHash"].is_null());
    let rows: Vec<(Vec<u8>, Vec<u8>)> = services.block_on(sqlx::query_as(
        "SELECT c.object_hash,c.exact_bytes FROM destruction_event_cores c JOIN destruction_transitions t USING(object_hash) WHERE t.to_state_code=2"
    ).fetch_all(server.database.pool())).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "exactly one actual server Pending transition"
    );
    assert_eq!(object_hash(&rows[0].1).as_bytes(), rows[0].0.as_slice());
    assert_eq!(
        fs::read(
            f.archive
                .join(ea_archive::DESTRUCTIONS_DIR_V1)
                .join(format!("{}.etb", hex(&rows[0].0)))
        )
        .unwrap(),
        rows[0].1
    );
    let stored_events = event_storage_snapshot(&services, &server);
    eprintln!(
        "Pending transport: native2 and exact server original {:?}",
        began.elapsed()
    );
    drop(state);
    drop(host);

    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let reopened = serde_json::to_value(destruction_read_core(&state, Some(&id)).unwrap()).unwrap();
    assert_eq!(reopened["process"], pending["process"]);
    let synchronized =
        serde_json::to_value(destruction_synchronize_core(&state, &id, &hash).unwrap()).unwrap();
    assert_eq!(synchronized["process"], pending["process"]);
    assert_eq!(
        event_storage_snapshot(&services, &server),
        stored_events,
        "synchronize preserves both complete server event tables"
    );
    assert_eq!(job_count(&services, &server), 1);
    eprintln!(
        "Pending transport: reopened and synchronization preserved exact events {:?}",
        began.elapsed()
    );
}
