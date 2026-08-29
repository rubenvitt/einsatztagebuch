//! `POST /v1/entries/{entryHash}/historical-grants` und
//! `GET /v1/entries/{entryHash}/grants` gegen ECHTE Dienste.
//!
//! Der Abschluss dieses Ziels traegt die Historical Grant Authority und ZWEI
//! Key Approver; ohne sie waere eine Mehr-Augen-`GrantAuthorization` gar nicht
//! baubar, und genau ihre Pruefung ist der Kern dieses Endpunkts.
//!
//! Die Autorisierung selbst reist NICHT im Koerper: `historical-grant-upload-v1`
//! traegt genau ein `.eag`. Das `.eag` NENNT sie ueber
//! `grant-authorization-object-hash`, und der Server loest sie
//! content-addressed auf — `design.md` §13.3 sagt „prueft […]
//! `GrantAuthorization`“, nicht „nimmt entgegen“.

mod common;

use common::{archive_objects, trust_closure};
use ea_sync_protocol::{EndpointV1, GrantListResponseV1};
use ea_types::EntryHash;

/// Die Frist der Autorisierung. Sie liegt HINTER der Standarduhr des Servers
/// (1 000) und VOR der des zweiten Servers (3 000).
const AUTHORIZATION_EXPIRES_AT: i64 = 2_000;
/// Die Uhr des zweiten Servers: hinter der Frist.
const AFTER_EXPIRY_MILLIS: i64 = 3_000;

/// Ein committeter Eintrag samt seiner Autorisierung und dem historischen
/// Grant, der sie nennt.
struct Prepared {
    entry: common::CommittedEntry,
    authorization_hash: ea_types::ObjectHash,
    grant_bytes: Vec<u8>,
    upload: ea_sync_protocol::HistoricalGrantUploadV1,
}

/// Baut die Kulisse: ein Eintrag, eine Autorisierung, ein `.eag`.
///
/// `signers` sind die Approver. Zwei UNTERSCHIEDLICHE sind der Normalfall;
/// derselbe zweimal ist der Fall, den der Server abweisen MUSS.
async fn prepare(
    ready: &common::ReadyServer,
    expires_at: i64,
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

    let authorization = archive_objects::grant_authorization(
        &ready.closure,
        vec![entry.entry_hash],
        archive_objects::Recipient::reader(&ready.closure),
        expires_at,
        marker,
        signers,
    );
    let authorization_hash = common::seed_trust_object_bytes(&authorization).await;

    let grant_bytes = archive_objects::historical_grant_bytes(
        &ready.closure,
        entry.entry_hash,
        archive_objects::Recipient::reader(&ready.closure),
        entry.recovery_grant_object_hash,
        authorization_hash,
    );
    let upload = ea_sync_protocol::HistoricalGrantUploadV1::new(grant_bytes.clone())
        .expect("the upload frame must build");
    Prepared {
        entry,
        authorization_hash,
        grant_bytes,
        upload,
    }
}

async fn post_grant(
    ready: &common::ReadyServer,
    prepared: &Prepared,
    request_id: [u8; 16],
    now_millis: i64,
) -> common::HttpResponse {
    let target = archive_objects::historical_grant_path(prepared.entry.entry_hash);
    common::call_at(
        &common::ApiCall {
            ready,
            signer_seed: trust_closure::HISTORICAL_GRANT_AUTHORITY_SEED,
            endpoint: EndpointV1::HistoricalGrants,
            target: &target,
            body: Some(prepared.upload.exact_bytes()),
            request_id,
        },
        now_millis,
    )
    .await
}

async fn get_grants(
    ready: &common::ReadyServer,
    entry_hash: EntryHash,
    request_id: [u8; 16],
    now_millis: i64,
) -> common::HttpResponse {
    let target = archive_objects::entry_grants_path(entry_hash);
    common::call_at(
        &common::ApiCall {
            ready,
            signer_seed: trust_closure::READER_SIGNING_SEED,
            endpoint: EndpointV1::EntryGrants,
            target: &target,
            body: None,
            request_id,
        },
        now_millis,
    )
    .await
}

/// Der Fall aus dem Aufgabenbrief: ein historischer Grant wird nach Ablauf
/// WEDER angenommen NOCH ausgeliefert.
///
/// Beide Haelften stehen in einem Fall, weil sie EINE Zusage sind
/// (`design.md` §13.3, letzter Absatz zum getrennten Endpunkt). Der zweite
/// Server hat dieselbe Datenbank und dieselbe Kette, nur eine spaetere Uhr.
#[tokio::test]
async fn a_historical_grant_is_neither_accepted_nor_delivered_after_expiry() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, AUTHORIZATION_EXPIRES_AT, 0x51, &approvers).await;

    // VOR der Frist: angenommen, `201`, ohne Koerper.
    let accepted = post_grant(
        &ready,
        &prepared,
        [0x61; 16],
        common::READ_SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(
        accepted.status,
        201,
        "a valid historical grant must be accepted; the server answered {:?}",
        common::error_code(&accepted.body)
    );
    assert!(accepted.body.is_empty(), "a 201 here carries no body");

    // Er ist ausgeliefert, solange die Frist laeuft.
    let delivered = get_grants(
        &ready,
        prepared.entry.entry_hash,
        [0x62; 16],
        common::READ_SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(delivered.status, 200);
    let page = GrantListResponseV1::decode(&delivered.body).expect("the grant list must decode");
    let historical = ea_crypto::object_hash(&prepared.grant_bytes);
    assert!(
        page.grants()
            .iter()
            .any(|record| record.object_hash() == historical),
        "the historical grant is delivered while its authorization runs"
    );

    // NACH der Frist: derselbe Bestand, eine spaetere Uhr.
    let later = common::respawn_read_server(&database, &ready.closure, AFTER_EXPIRY_MILLIS).await;

    let refused = post_grant(&later, &prepared, [0x63; 16], AFTER_EXPIRY_MILLIS).await;
    assert_eq!(refused.status, 422);
    assert_eq!(
        common::error_code(&refused.body).as_deref(),
        Some("EA-GRANT-EXPIRED"),
        "an expired authorization is refused on acceptance"
    );

    let after = get_grants(
        &later,
        prepared.entry.entry_hash,
        [0x64; 16],
        AFTER_EXPIRY_MILLIS,
    )
    .await;
    assert_eq!(after.status, 200);
    let page = GrantListResponseV1::decode(&after.body).expect("the grant list must decode");
    assert!(
        !page
            .grants()
            .iter()
            .any(|record| record.object_hash() == historical),
        "an expired historical grant is NOT delivered"
    );
    // Die initialen Grants bleiben: sie tragen keine Frist.
    assert_eq!(
        page.grants().len(),
        2,
        "the two initial grants keep being delivered"
    );

    database.cleanup().await;
}

/// ZWEIMAL derselbe Approver sind nicht zwei Approver.
///
/// `ea-format` erzwingt nur „mindestens zwei Signaturen“; dass es zwei
/// UNTERSCHIEDLICHE Zertifikate sind, ist die Aussage dieses Endpunkts
/// (`design.md` §16.2).
#[tokio::test]
async fn an_authorization_signed_twice_by_the_same_approver_is_refused() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let doubled = [approvers[0], approvers[0]];
    let prepared = prepare(&ready, AUTHORIZATION_EXPIRES_AT, 0x52, &doubled).await;

    let response = post_grant(
        &ready,
        &prepared,
        [0x65; 16],
        common::READ_SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(response.status, 422);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-GRANT-AUTHORIZATION-INSUFFICIENT")
    );

    database.cleanup().await;
}

/// Ein Aufrufer ohne `historicalGrant` erreicht den Dienst gar nicht.
///
/// Der Leser ist ein freigegebenes Geraet derselben Organisation — seine
/// Identitaet ist in Ordnung, seine Capability nicht. Das ist die 403-Zeile
/// der Abbildung und nicht die 401.
#[tokio::test]
async fn a_caller_without_the_historical_grant_capability_is_refused() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, AUTHORIZATION_EXPIRES_AT, 0x53, &approvers).await;

    let target = archive_objects::historical_grant_path(prepared.entry.entry_hash);
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::HistoricalGrants,
        target: &target,
        body: Some(prepared.upload.exact_bytes()),
        request_id: [0x66; 16],
    })
    .await;
    assert_eq!(response.status, 403);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-HTTP-CAPABILITY-MISSING")
    );

    // Und er hat nichts abgelegt.
    let stored: (i64,) = sqlx::query_as("SELECT count(*) FROM grants WHERE grant_kind_code = $1")
        .bind("historical")
        .fetch_one(database.pool())
        .await
        .expect("counting the grants must succeed");
    assert_eq!(stored.0, 0, "a refused caller stores nothing");

    database.cleanup().await;
}

/// Ein unbekannter Eintrag ist `404` — und der Endpunkt legt nichts an.
#[tokio::test]
async fn a_historical_grant_for_an_unknown_entry_is_not_found() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, AUTHORIZATION_EXPIRES_AT, 0x54, &approvers).await;

    let unknown = EntryHash::try_from(&[0x8e_u8; 32][..]).expect("32 bytes");
    let target = archive_objects::historical_grant_path(unknown);
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::HISTORICAL_GRANT_AUTHORITY_SEED,
        endpoint: EndpointV1::HistoricalGrants,
        target: &target,
        body: Some(prepared.upload.exact_bytes()),
        request_id: [0x67; 16],
    })
    .await;
    // Der Pfad nennt einen anderen Eintrag als das `.eag`; das faellt schon an
    // der Bindung, bevor der Eintrag gesucht wird.
    assert_eq!(response.status, 422);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-GRANT-INVALID")
    );

    database.cleanup().await;
}

/// Die Grantliste eines unbekannten Eintrags ist `404`.
#[tokio::test]
async fn the_grant_list_of_an_unknown_entry_is_not_found() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let unknown = EntryHash::try_from(&[0x8f_u8; 32][..]).expect("32 bytes");

    let response = get_grants(&ready, unknown, [0x68; 16], common::READ_SERVER_NOW_MILLIS).await;
    assert_eq!(response.status, 404);
    // Der Code ist der der LESEFLAECHE: die Grantliste ist eine Leseantwort,
    // und ein unbekannter Eintrag ist dort derselbe Befund wie beim
    // Lesestapel. `EA-GRANT-…` traegt der SCHREIBENDE Endpunkt.
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-READER-ENTRY-UNKNOWN")
    );

    database.cleanup().await;
}

/// Der historische Re-Grant veraendert `.eip`, Plan und Kettenkopf NICHT.
///
/// `design.md` §13.3 sagt das woertlich, und der Fall misst es: Eintragszeile
/// und Kettenkopf sind nach der Annahme byteweise dieselben.
#[tokio::test]
async fn a_historical_grant_changes_neither_the_entry_nor_the_chain_head() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, AUTHORIZATION_EXPIRES_AT, 0x55, &approvers).await;

    let before: (Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
        "SELECT (SELECT entry_object_hash FROM entries WHERE entry_hash = $1), \
         (SELECT head_entry_hash FROM chain_heads WHERE chain_id = $2), \
         (SELECT head_sequence FROM chain_heads WHERE chain_id = $2)",
    )
    .bind(&prepared.entry.entry_hash.as_bytes()[..])
    .bind(&ready.closure.chain_id.as_bytes()[..])
    .fetch_one(database.pool())
    .await
    .expect("reading the entry and head must succeed");

    let accepted = post_grant(
        &ready,
        &prepared,
        [0x69; 16],
        common::READ_SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(accepted.status, 201);

    let after: (Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
        "SELECT (SELECT entry_object_hash FROM entries WHERE entry_hash = $1), \
         (SELECT head_entry_hash FROM chain_heads WHERE chain_id = $2), \
         (SELECT head_sequence FROM chain_heads WHERE chain_id = $2)",
    )
    .bind(&prepared.entry.entry_hash.as_bytes()[..])
    .bind(&ready.closure.chain_id.as_bytes()[..])
    .fetch_one(database.pool())
    .await
    .expect("reading the entry and head must succeed");
    assert_eq!(before, after, "the historical re-grant moves nothing");

    // Die Autorisierung selbst wurde nicht in den Objektindex aufgenommen: sie
    // ist das Objekt, das der Grant NENNT, und nicht eines, das dieser
    // Endpunkt anlegt.
    let indexed: (i64,) =
        sqlx::query_as("SELECT count(*) FROM object_index WHERE object_hash = $1")
            .bind(&prepared.authorization_hash.as_bytes()[..])
            .fetch_one(database.pool())
            .await
            .expect("counting the index must succeed");
    assert_eq!(indexed.0, 0);

    database.cleanup().await;
}

/// Ein abgelaufener historischer Grant faellt auch aus dem LESESTAPEL.
///
/// `design.md` §13.3 sagt „abgelaufene Grants werden weder angenommen noch
/// ausgeliefert“ — ohne Einschraenkung auf einen Endpunkt. Der Lesestapel ist
/// der Weg, ueber den ein Reader tatsaechlich synchronisiert; ohne diese
/// Zusage waere die Filterung der Grantliste nur Zierde.
#[tokio::test]
async fn an_expired_historical_grant_is_absent_from_the_reader_batch_too() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, AUTHORIZATION_EXPIRES_AT, 0x56, &approvers).await;
    let accepted = post_grant(
        &ready,
        &prepared,
        [0x6a; 16],
        common::READ_SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(accepted.status, 201);
    let historical = ea_crypto::object_hash(&prepared.grant_bytes);

    let target = format!(
        "/v1/chains/{}/entries?afterSequence=0&afterEntryHash={}",
        hex::encode(ready.closure.chain_id.as_bytes()),
        hex::encode([0_u8; 32])
    );

    // Waehrend die Frist laeuft: der Stapel traegt ihn.
    let during = common::call_at(
        &common::ApiCall {
            ready: &ready,
            signer_seed: trust_closure::READER_SIGNING_SEED,
            endpoint: EndpointV1::ChainEntries,
            target: &target,
            body: None,
            request_id: [0x6b; 16],
        },
        common::READ_SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(during.status, 200);
    let batch = ea_sync_protocol::ReaderBatchV1::decode(&during.body).expect("the batch decodes");
    assert!(
        batch
            .objects()
            .iter()
            .any(|record| record.object_hash() == historical)
    );

    // Danach nicht mehr — derselbe Bestand, eine spaetere Uhr.
    let later = common::respawn_read_server(&database, &ready.closure, AFTER_EXPIRY_MILLIS).await;
    let after = common::call_at(
        &common::ApiCall {
            ready: &later,
            signer_seed: trust_closure::READER_SIGNING_SEED,
            endpoint: EndpointV1::ChainEntries,
            target: &target,
            body: None,
            request_id: [0x6c; 16],
        },
        AFTER_EXPIRY_MILLIS,
    )
    .await;
    assert_eq!(after.status, 200);
    let batch = ea_sync_protocol::ReaderBatchV1::decode(&after.body).expect("the batch decodes");
    assert!(
        !batch
            .objects()
            .iter()
            .any(|record| record.object_hash() == historical),
        "an expired historical grant is not delivered on ANY path"
    );
    // Die initialen Grants bleiben.
    assert!(
        batch
            .objects()
            .iter()
            .any(|record| record.object_hash() == prepared.entry.reader_grant_object_hash)
    );

    database.cleanup().await;
}

/// Ein `.eag`, das auf einen unbekannten Eintrag ZEIGT und an DESSEN Pfad
/// geht, ist `404` — die Zeile der Abbildung, die „unbekannter Eintrag“ nennt.
///
/// Der Fall daneben (`.eag` gegen einen fremden Pfad) faellt frueher, an der
/// Bindung. Beide Arme brauchen einen eigenen Zeugen, sonst bliebe einer
/// ungepinnt.
#[tokio::test]
async fn a_grant_bound_to_an_unknown_entry_is_not_found() {
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, true).await;
    let approvers = archive_objects::approvers(&ready.closure);
    let prepared = prepare(&ready, AUTHORIZATION_EXPIRES_AT, 0x57, &approvers).await;

    let unknown = EntryHash::try_from(&[0x9e_u8; 32][..]).expect("32 bytes");
    let grant = archive_objects::historical_grant_bytes(
        &ready.closure,
        unknown,
        archive_objects::Recipient::reader(&ready.closure),
        prepared.entry.recovery_grant_object_hash,
        prepared.authorization_hash,
    );
    let upload =
        ea_sync_protocol::HistoricalGrantUploadV1::new(grant).expect("the upload frame builds");
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::HISTORICAL_GRANT_AUTHORITY_SEED,
        endpoint: EndpointV1::HistoricalGrants,
        target: &archive_objects::historical_grant_path(unknown),
        body: Some(upload.exact_bytes()),
        request_id: [0x6d; 16],
    })
    .await;
    assert_eq!(response.status, 404);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-GRANT-ENTRY-UNKNOWN")
    );

    database.cleanup().await;
}
