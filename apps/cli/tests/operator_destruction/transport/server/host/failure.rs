//! Actual configured Desktop explicit Failure action over TLS/PG/S3 (Ruling
//! 13.09.2026). The overdue Reader original that exists only at the server is a
//! certified synthetic claim, never actual remote WORM storage or a measured
//! outage; the signed state4 claims no removal.
use super::*;
use ea_desktop::commands::destruction::destruction_mark_incomplete_core;

type TransitionRow = (Vec<u8>, Vec<u8>);

fn state4_transitions(
    services: &tokio::runtime::Runtime,
    server: &ServerFixture,
) -> Vec<TransitionRow> {
    services
        .block_on(
            sqlx::query_as(
                "SELECT c.object_hash,c.exact_bytes FROM destruction_event_cores c \
                 JOIN destruction_transitions t USING(object_hash) WHERE t.to_state_code=4",
            )
            .fetch_all(server.database.pool()),
        )
        .unwrap()
}

/// Relay one exact original to the registered server as the configured
/// component, without any local import: a server-only observation.
fn post_server_only_original(
    services: &tokio::runtime::Runtime,
    server: &ServerFixture,
    id: &str,
    exact: &[u8],
) {
    use super::super::common;
    let organization = trust_support::organization();
    let signer =
        ea_sync_protocol::RequestSigner::from_secret(ea_crypto::SecretBytes::new(COMPONENT_SECRET));
    let target = format!("/v1/destructions/{id}/events");
    let response = services.block_on(async {
        let nonce = common::fresh_challenge(&server.server, organization).await;
        let headers = common::signed_headers(&common::SignedCall {
            signer: &signer,
            endpoint: EndpointV1::DestructionEvents,
            authority: &server.server.authority,
            target: &target,
            body: Some(exact),
            organization_id: organization,
            request_id: <[u8; 16]>::try_from(&nonce[..16]).unwrap(),
            nonce,
            created: support::live_clock().get().div_euclid(1_000),
        });
        common::https_request(
            server.server.address,
            &server.server.authority,
            "POST",
            &target,
            &headers,
            exact,
        )
        .await
    });
    assert_eq!(
        response.status,
        EndpointV1::DestructionEvents.success_status(),
        "the registered server accepts the exact original"
    );
}

fn view(
    value: Result<
        ea_desktop::commands::destruction::DestructionAdministrationWire,
        ea_desktop::commands::CommandError,
    >,
) -> serde_json::Value {
    serde_json::to_value(value.unwrap()).unwrap()
}

/// Prepare, Start and the local Writer cleanup on the configured server host.
/// Returns the destruction id, the job hash and the cleaned view.
fn started_and_cleaned(
    f: &NativeDestructionFixture,
    server: &ServerFixture,
) -> (String, String, serde_json::Value) {
    let host = configured_host(f, server);
    let state = host.desktop_state();
    let prepared = view(destruction_prepare_core(&state, &f.authorization));
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
    let host = configured_host(f, server);
    let cleaned = view(destruction_resume_core(&host.desktop_state(), &id));
    assert_eq!(cleaned["process"]["state"], "inProgress");
    assert!(
        cleaned["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kindCode"] == 1 && r["resultCode"].is_null()),
        "the Reader is locally never attested: the action is offered"
    );
    assert!(
        cleaned["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kindCode"] == 2),
        "the job is bound to the registered server"
    );
    (id, hash, cleaned)
}

/// MI-1: a server-bound job reopened by a Desktop host without any server
/// transport (`no-registered-server`) must meet the same NoServer barrier as
/// Start and Resume before the final event is signed.
#[test]
fn native_desktop_explicit_failure_on_a_no_server_host_refuses_a_server_bound_job_before_signing()
{
    let f = NativeDestructionFixture::with_reader_opfs();
    fs::write(f.admin_directory.join("long-recovery-run"), b"").unwrap();
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let (id, hash, _) = started_and_cleaned(&f, &server);

    let db = super::super::super::super::completion::writer_database(&f);
    let batches = super::super::super::super::failure::count(&db, "destruction_import_batch");
    let audits = super::super::super::super::failure::count(&db, "local_audit_event");
    let local = super::super::super::super::desktop::desktop(&f);
    local.login().unwrap();
    let state = local.desktop_state();
    let before = view(destruction_read_core(&state, Some(&id)));
    assert_eq!(before["process"]["state"], "inProgress");
    let refused = destruction_mark_incomplete_core(&state, &id, &hash)
        .err()
        .expect("a NoServer host never signs state4 for a server-bound job");
    assert_eq!(refused.code, "EA-DESTRUCTION-TARGET");
    assert_eq!(
        super::super::super::super::failure::count(&db, "destruction_import_batch"),
        batches
    );
    assert_eq!(
        super::super::super::super::failure::count(&db, "local_audit_event"),
        audits
    );
    assert_eq!(
        view(destruction_read_core(&state, Some(&id)))["process"],
        before["process"],
        "the refused attempt committed nothing locally"
    );
    drop(state);
    drop(local);
    assert!(state4_transitions(&services, &server).is_empty());
}

/// MI-2: the configured action first reads and imports the actual server
/// claims. A Reader removal attested successfully so far only at the server
/// leaves nothing missing, so no final state4 may be signed.
#[test]
fn native_desktop_explicit_failure_imports_server_claims_before_deciding_and_refuses_without_a_reason()
 {
    let f = NativeDestructionFixture::with_reader_opfs();
    fs::write(f.admin_directory.join("long-recovery-run"), b"").unwrap();
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let (id, hash, cleaned) = started_and_cleaned(&f, &server);

    let db = super::super::super::super::completion::writer_database(&f);
    let success = super::super::super::super::completion::fixture_reader_claim(&f, &db);
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&success).unwrap() else {
        panic!()
    };
    let DecodedTrustPayloadV1::DeletionAttestation(claim) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    assert_eq!(claim.result, 0, "a successful removal claim");
    let success_hash = hex(object_hash(&success).as_bytes());
    post_server_only_original(&services, &server, &id, &success);

    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let before = view(destruction_read_core(&state, Some(&id)));
    assert_eq!(
        before["process"], cleaned["process"],
        "the server-only success claim is not local yet: the local view still offers the action"
    );
    let refused = destruction_mark_incomplete_core(&state, &id, &hash)
        .err()
        .expect("after importing the actual server claims nothing is missing");
    assert_eq!(refused.code, "EA-DESTRUCTION-MARK-INCOMPLETE-NOT-OFFERED");
    assert!(
        state4_transitions(&services, &server).is_empty(),
        "no state4 at the server"
    );
    let after = view(destruction_read_core(&state, Some(&id)));
    assert_eq!(after["process"]["state"], "inProgress", "no local state4");
    assert!(
        after["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kindCode"] == 1
                && r["resultCode"] == 0
                && r["attestationHash"] == success_hash.as_str()),
        "the read-only import durably kept the actual server claim"
    );
    drop(state);
    drop(host);
}

#[test]
fn native_desktop_explicit_failure_binds_servers_before_commit_then_publishes_and_imports_the_actual_reply()
 {
    let began = std::time::Instant::now();
    let f = NativeDestructionFixture::with_reader_opfs();
    fs::write(f.admin_directory.join("long-recovery-run"), b"").unwrap();
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let prepared = view(destruction_prepare_core(&state, &f.authorization));
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
    let cleaned = view(destruction_resume_core(&host.desktop_state(), &id));
    assert_eq!(cleaned["process"]["state"], "inProgress");
    assert!(
        cleaned["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kindCode"] == 1 && r["resultCode"].is_null())
    );
    assert!(
        cleaned["process"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["stubObjectHash"].is_string())
    );
    drop(host);
    eprintln!(
        "Failure transport: local cleanup and real server response {:?}",
        began.elapsed()
    );

    // Phase 1: a configured server set that differs from the job's required
    // servers is refused by the local binding check BEFORE the final commit.
    let unbound = configured_host_with(
        &f,
        &server,
        "desktop-server-destruction-unbound.json",
        vec![serde_json::json!({
            "device_id": "ab".repeat(16),
            "address": "127.0.0.1:9",
            "server_name": "localhost",
            "authority": "localhost:9",
            "ca_file": server.config.ca_file,
            "server_certificate_hash": "cd".repeat(32)
        })],
    );
    let refused = destruction_mark_incomplete_core(&unbound.desktop_state(), &id, &hash)
        .err()
        .expect("an unbound server configuration refuses before the commit");
    assert_eq!(refused.code, "EA-DESTRUCTION-TRANSPORT-BINDING");
    drop(unbound);
    assert!(state4_transitions(&services, &server).is_empty());

    // Phase 2: the overdue Reader original exists only at the server. The
    // action imports the actual server claims before it decides (MI-2), so the
    // decision itself already rests on this overdue claim, not on the stale
    // local "never attested" observation read below.
    let db = super::super::super::super::completion::writer_database(&f);
    let reader = super::super::super::super::pending::changed_reader_claim(&f, &db, |claim| {
        claim.result = 1;
        claim.backup_expiry_at = Some(ea_types::UnixMillis::new(claim.executed_at.get() + 1));
    });
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&reader).unwrap() else {
        panic!()
    };
    let DecodedTrustPayloadV1::DeletionAttestation(claim) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let deadline = claim.backup_expiry_at.unwrap();
    let reader_hash = hex(object_hash(&reader).as_bytes());
    post_server_only_original(&services, &server, &id, &reader);

    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let before = view(destruction_read_core(&state, Some(&id)));
    assert_eq!(
        before["process"]["state"], "inProgress",
        "the refused unbound attempt committed nothing locally"
    );
    assert!(
        before["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kindCode"] == 1 && r["resultCode"].is_null()),
        "before the action, the server-only original is not local yet"
    );
    let failed = view(destruction_mark_incomplete_core(&state, &id, &hash));
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
            .all(|t| t["stubObjectHash"].is_string())
    );
    assert!(failed["process"]["evidenceEntryHash"].is_null());
    assert!(
        failed["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kindCode"] == 1
                && r["resultCode"] == 1
                && r["attestationHash"] == reader_hash.as_str()),
        "the returned view is the imported actual server reply, not the local commit result"
    );
    let rows = state4_transitions(&services, &server);
    assert_eq!(rows.len(), 1, "exactly one actual server state4 transition");
    assert_eq!(object_hash(&rows[0].1).as_bytes(), rows[0].0.as_slice());
    assert_eq!(
        fs::read(
            f.archive
                .join(ea_archive::DESTRUCTIONS_DIR_V1)
                .join(format!("{}.etb", hex(&rows[0].0)))
        )
        .unwrap(),
        rows[0].1,
        "the server holds the exact local original"
    );
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&rows[0].1).unwrap() else {
        panic!()
    };
    let DecodedTrustPayloadV1::DestructionTransition(event) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    assert_eq!(event.from_state, Some(1));
    assert_eq!(event.to_state, 4);
    assert_eq!(event.trigger_code, 4);
    assert!(event.executed_at >= deadline);
    let stored_events = event_storage_snapshot(&services, &server);
    drop(state);
    drop(host);
    eprintln!(
        "Failure transport: bound commit, exact publish and import {:?}",
        began.elapsed()
    );

    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    assert_eq!(
        view(destruction_read_core(&state, Some(&id)))["process"],
        failed["process"]
    );
    assert_eq!(
        view(destruction_synchronize_core(&state, &id, &hash))["process"],
        failed["process"]
    );
    assert_eq!(
        event_storage_snapshot(&services, &server),
        stored_events,
        "synchronize preserves both complete server event tables"
    );
    assert_eq!(job_count(&services, &server), 1);
    eprintln!(
        "Failure transport: reopened and synchronization preserved exact events {:?}",
        began.elapsed()
    );
}
