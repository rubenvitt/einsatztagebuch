//! `POST /v1/destructions` und `GET /v1/destructions/{destructionId}` gegen
//! ECHTE Dienste.
//!
//! Diese Stufe baut von `design.md` §16.3 genau die drei Zusagen, die der
//! Server allein haelt: nur eine gueltige Mehr-Augen-Authorization wird
//! angenommen, der Vorgang beginnt im Zustand `requested`, und ab der Annahme
//! sind Auslieferung und Re-Grant fuer die Ziele GESPERRT. Den vollstaendigen
//! Zustandsautomaten liefert Stufe 5; die Ablage traegt ihn bereits
//! append-only.

mod common;

use common::{archive_objects, trust_closure};
use ea_sync_protocol::{DestructionRequestV1, DestructionStatusResponseV1, EndpointV1};
use ea_types::EntryHash;

/// Der Zustand `requested` (`destruction-state-v1`).
const STATE_REQUESTED: u8 = 0;
const AUTHORIZATION_EXPIRES_AT: i64 = 2_000;

/// Ein committeter Eintrag und eine Authorization ueber ihn.
struct Prepared {
    entry: common::CommittedEntry,
    marker: u8,
    upload: DestructionRequestV1,
    authorization_hash: ea_types::ObjectHash,
}

async fn prepare(
    ready: &common::ReadyServer,
    marker: u8,
    signers: &[(ea_types::CertificateHash, [u8; 32])],
) -> Prepared {
    let seeded = EntryHash::try_from(&common::READ_SEEDED_HEAD_ENTRY_HASH[..]).expect("32 bytes");
    let entry = common::commit_one_entry(
        ready,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded),
        marker,
    )
    .await;
    let authorization = archive_objects::destruction_authorization(
        &ready.closure,
        vec![(entry.entry_hash, entry.sequence)],
        marker,
        signers,
    );
    let authorization_hash = ea_crypto::object_hash(&authorization);
    let upload =
        DestructionRequestV1::new(authorization).expect("the destruction frame must build");
    Prepared {
        entry,
        marker,
        upload,
        authorization_hash,
    }
}

async fn post_destruction(
    ready: &common::ReadyServer,
    prepared: &Prepared,
    request_id: [u8; 16],
) -> common::HttpResponse {
    common::call(&common::ApiCall {
        ready,
        signer_seed: trust_closure::APPROVER_A_SEED,
        endpoint: EndpointV1::Destructions,
        target: EndpointV1::Destructions.path_template(),
        body: Some(prepared.upload.exact_bytes()),
        request_id,
    })
    .await
}

/// Eine gueltige Mehr-Augen-Authorization wird angenommen, beginnt bei
/// `requested` und SPERRT anschliessend Auslieferung und Re-Grant.
#[tokio::test]
async fn a_two_approver_authorization_is_accepted_and_blocks_delivery_and_regrant() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, 0x71, &approvers).await;

    // Vor der Vernichtung wird ausgeliefert.
    let before = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::EntryGrants,
        target: &archive_objects::entry_grants_path(prepared.entry.entry_hash),
        body: None,
        request_id: [0x81; 16],
    })
    .await;
    assert_eq!(before.status, 200);

    let accepted = post_destruction(&ready, &prepared, [0x82; 16]).await;
    assert_eq!(
        accepted.status,
        202,
        "an accepted destruction answers 202; the server answered {:?}",
        common::error_code(&accepted.body)
    );
    let status =
        DestructionStatusResponseV1::decode(&accepted.body).expect("the status frame must decode");
    assert_eq!(status.state(), STATE_REQUESTED);
    assert!(status.authorization_object_hash() == prepared.authorization_hash);
    assert!(
        status.transitions().is_empty() && status.attestations().is_empty(),
        "a fresh process carries neither transition nor attestation"
    );

    // Ab jetzt ist die Auslieferung gesperrt.
    let blocked = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::EntryGrants,
        target: &archive_objects::entry_grants_path(prepared.entry.entry_hash),
        body: None,
        request_id: [0x83; 16],
    })
    .await;
    assert_eq!(blocked.status, 422);
    assert_eq!(
        common::error_code(&blocked.body).as_deref(),
        Some("EA-DESTRUCTION-BLOCKED")
    );

    // Und der historische Re-Grant ebenso.
    let authorization = archive_objects::grant_authorization(
        &ready.closure,
        vec![prepared.entry.entry_hash],
        archive_objects::Recipient::reader(&ready.closure),
        AUTHORIZATION_EXPIRES_AT,
        0x72,
        &approvers,
    );
    let authorization_hash = common::seed_trust_object_bytes(&authorization).await;
    let grant = archive_objects::historical_grant_bytes(
        &ready.closure,
        prepared.entry.entry_hash,
        archive_objects::Recipient::reader(&ready.closure),
        prepared.entry.recovery_grant_object_hash,
        authorization_hash,
    );
    let upload =
        ea_sync_protocol::HistoricalGrantUploadV1::new(grant).expect("the upload frame must build");
    let refused = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::HISTORICAL_GRANT_AUTHORITY_SEED,
        endpoint: EndpointV1::HistoricalGrants,
        target: &archive_objects::historical_grant_path(prepared.entry.entry_hash),
        body: Some(upload.exact_bytes()),
        request_id: [0x84; 16],
    })
    .await;
    assert_eq!(refused.status, 422);
    assert_eq!(
        common::error_code(&refused.body).as_deref(),
        Some("EA-DESTRUCTION-BLOCKED"),
        "a running destruction blocks the historical re-grant"
    );

    database.cleanup().await;
}

/// Der gespeicherte Stand wird unveraendert wieder ausgegeben.
#[tokio::test]
async fn the_stored_destruction_state_is_delivered_on_its_own_endpoint() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, 0x73, &approvers).await;
    let accepted = post_destruction(&ready, &prepared, [0x85; 16]).await;
    assert_eq!(accepted.status, 202);

    let destruction_id = archive_objects::destruction_id_of(prepared.marker);
    let target = format!(
        "/v1/destructions/{}",
        hex::encode(destruction_id.as_bytes())
    );
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::DestructionStatus,
        target: &target,
        body: None,
        request_id: [0x86; 16],
    })
    .await;
    assert_eq!(
        response.status,
        200,
        "the status must be readable; the server answered {:?}",
        common::error_code(&response.body)
    );
    // Byteweise dieselbe Antwort wie beim Anlegen: der Stand kommt aus der
    // ABLAGE und nicht aus dem, was der Annahmepfad gerade gemeint hat.
    assert_eq!(response.body, accepted.body);

    database.cleanup().await;
}

/// ZWEIMAL derselbe Approver sind nicht zwei Approver — und der Vorgang
/// entsteht nicht.
#[tokio::test]
async fn a_destruction_signed_twice_by_the_same_approver_is_refused() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let doubled = [approvers[0], approvers[0]];
    let prepared = prepare(&ready, 0x74, &doubled).await;

    let response = post_destruction(&ready, &prepared, [0x87; 16]).await;
    assert_eq!(response.status, 422);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-DESTRUCTION-AUTHORIZATION-INSUFFICIENT")
    );

    let stored: (i64,) = sqlx::query_as("SELECT count(*) FROM destructions")
        .fetch_one(database.pool())
        .await
        .expect("counting the destructions must succeed");
    assert_eq!(stored.0, 0, "a refused authorization creates no process");

    // Und die Auslieferung bleibt offen: eine abgewiesene Authorization sperrt
    // nichts.
    let open = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::EntryGrants,
        target: &archive_objects::entry_grants_path(prepared.entry.entry_hash),
        body: None,
        request_id: [0x88; 16],
    })
    .await;
    assert_eq!(open.status, 200);

    database.cleanup().await;
}

/// Ein Aufrufer ohne `destructionApprove` erreicht den Dienst nicht.
#[tokio::test]
async fn a_caller_without_the_destruction_capability_is_refused() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, 0x75, &approvers).await;

    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::Destructions,
        target: EndpointV1::Destructions.path_template(),
        body: Some(prepared.upload.exact_bytes()),
        request_id: [0x89; 16],
    })
    .await;
    assert_eq!(response.status, 403);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-HTTP-CAPABILITY-MISSING")
    );

    database.cleanup().await;
}

/// Eine unbekannte Vernichtungskennung ist `404` — die eine Zeile der
/// Abbildung, die sie nennt.
#[tokio::test]
async fn an_unknown_destruction_id_is_not_found() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;

    let target = format!("/v1/destructions/{}", hex::encode([0x3d_u8; 16]));
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::DestructionStatus,
        target: &target,
        body: None,
        request_id: [0x8a; 16],
    })
    .await;
    assert_eq!(response.status, 404);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-DESTRUCTION-UNKNOWN")
    );

    database.cleanup().await;
}

/// Derselbe Vorgang zweimal ist idempotent — und legt keine zweite Zeile an.
#[tokio::test]
async fn the_same_destruction_twice_is_idempotent() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, 0x76, &approvers).await;

    let first = post_destruction(&ready, &prepared, [0x8b; 16]).await;
    assert_eq!(first.status, 202);
    let second = post_destruction(&ready, &prepared, [0x8c; 16]).await;
    assert_eq!(second.status, 202);
    assert_eq!(first.body, second.body, "the replay returns the same state");

    let stored: (i64,) = sqlx::query_as("SELECT count(*) FROM destructions")
        .fetch_one(database.pool())
        .await
        .expect("counting the destructions must succeed");
    assert_eq!(stored.0, 1);
    let targets: (i64,) = sqlx::query_as("SELECT count(*) FROM destruction_targets")
        .fetch_one(database.pool())
        .await
        .expect("counting the targets must succeed");
    assert_eq!(targets.0, 1);

    database.cleanup().await;
}

/// Die Sperre gilt auch fuer den LESESTAPEL — den Weg, ueber den ein Reader
/// tatsaechlich synchronisiert.
///
/// Der Stapel weist den Eintrag nicht ab: `design.md` §16.3, Schritt 6 haelt
/// fest, dass Kettenkontinuitaet pruefbar bleibt. Er liefert Eintrag,
/// Quittung, Checkpoint und Registrierungskopf weiter — und KEINEN Grant.
/// Ohne diese Zusage waere die Sperre wirkungslos: es gibt in dieser Stufe
/// noch keinen `.eds`-Stub, das `.eip` liegt unveraendert da.
#[tokio::test]
async fn a_running_destruction_also_withholds_the_grants_from_the_reader_batch() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, 0x77, &approvers).await;

    // Ab Kettenanfang: Sequenz null plus Nullhash.
    let target = format!(
        "/v1/chains/{}/entries?afterSequence=0&afterEntryHash={}",
        hex::encode(ready.closure.chain_id.as_bytes()),
        hex::encode([0_u8; 32])
    );

    // Vor der Vernichtung traegt der Stapel die Grants.
    let before = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ChainEntries,
        target: &target,
        body: None,
        request_id: [0x8d; 16],
    })
    .await;
    assert_eq!(before.status, 200);
    let batch = ea_sync_protocol::ReaderBatchV1::decode(&before.body).expect("the batch decodes");
    assert!(
        batch
            .objects()
            .iter()
            .any(|record| record.object_hash() == prepared.entry.reader_grant_object_hash),
        "the reader grant is delivered while no destruction runs"
    );

    let accepted = post_destruction(&ready, &prepared, [0x8e; 16]).await;
    assert_eq!(accepted.status, 202);

    // Danach: Eintrag ja, Grants nein.
    let after = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ChainEntries,
        target: &target,
        body: None,
        request_id: [0x8f; 16],
    })
    .await;
    assert_eq!(
        after.status,
        200,
        "the chain stays readable; the server answered {:?}",
        common::error_code(&after.body)
    );
    let batch = ea_sync_protocol::ReaderBatchV1::decode(&after.body).expect("the batch decodes");
    assert!(
        batch
            .objects()
            .iter()
            .any(|record| record.object_hash() == prepared.entry.entry_object_hash),
        "chain continuity stays verifiable through the batch"
    );
    for withheld in [
        prepared.entry.reader_grant_object_hash,
        prepared.entry.recovery_grant_object_hash,
    ] {
        assert!(
            !batch
                .objects()
                .iter()
                .any(|record| record.object_hash() == withheld),
            "no grant of a destruction target leaves the server"
        );
    }

    database.cleanup().await;
}
