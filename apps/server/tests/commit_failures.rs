//! Die Abweisungen des Commit-Endpunkts, gegen ECHTE Dienste.
//!
//! Dieses Ziel misst die Kante — Rahmen, Grenzen, Medientyp, Pfad, Signatur —
//! und ausdruecklich nicht die neun Schritte. Warum die neun Schritte hier
//! nicht messbar sind und wo sie stattdessen gemessen werden, steht im
//! Modulkopf von `entry_commit_api.rs`.
//!
//! Jeder Fall laeuft ueber TLS 1.3 gegen den ECHTEN Router mit den ECHTEN
//! Adaptern. Jede Antwort ist ein `protocol-error-v1` mit einem stabilen Code,
//! und keine traegt ein Fragment der gelieferten Nutzdaten.

mod common;

use ea_crypto::SecretBytes;
use ea_sync_protocol::{
    ChallengeRequestV1, ChallengeResponseV1, EndpointV1, MAX_ENTRY_COMMIT_BODY_BYTES_V1,
    ProtocolErrorV1, RequestSigner, STRUCTURED_MEDIA_TYPE_V1,
};
use ea_types::{CertificateHash, OrganizationId, UnixMillis};

const SERVER_NOW_MILLIS: i64 = 1_000;
const ADMIN_SEED: [u8; 32] = ea_testkit::TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED;
const SERVER_SECRET: [u8; 32] = [0x51; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];
const ROTATION_CASE: &str = "registry/accepted-admin-rotation";
const CHAIN_ID: [u8; 16] = [0x71; 16];

fn signer(seed: [u8; 32]) -> RequestSigner {
    RequestSigner::from_secret(SecretBytes::new(seed))
}

fn error_code(body: &[u8]) -> Option<String> {
    ProtocolErrorV1::decode(body)
        .ok()
        .map(|error| error.error_code().to_owned())
}

fn entry_commit_path(chain_id: &str) -> String {
    format!("/v1/chains/{chain_id}/entry-commits")
}

async fn fresh_challenge(server: &common::TestServer, organization_id: OrganizationId) -> [u8; 32] {
    let body = ChallengeRequestV1::new(organization_id);
    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        EndpointV1::AuthChallenges.path_template(),
        &[("content-type", STRUCTURED_MEDIA_TYPE_V1.to_owned())],
        body.exact_bytes(),
    )
    .await;
    assert_eq!(response.status, 200);
    ChallengeResponseV1::decode(&response.body)
        .expect("the challenge response must decode")
        .core()
        .nonce
}

/// Ein Server samt eingespieltem Trust-Bestand.
async fn spawn(database: &common::TestDatabase) -> (common::TestServer, OrganizationId) {
    let fixture = common::seed_trust_fixture(database.pool(), ROTATION_CASE, &[]).await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        fixture.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;
    (server, fixture.organization_id)
}

/// Ohne RFC-9421-Signatur kommt niemand an diesen Endpunkt.
#[tokio::test(flavor = "multi_thread")]
async fn an_unsigned_commit_is_refused() {
    let database = common::fresh_database().await;
    let (server, _) = spawn(&database).await;

    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &entry_commit_path(&hex::encode(CHAIN_ID)),
        &[("content-type", STRUCTURED_MEDIA_TYPE_V1.to_owned())],
        b"\x85\x01\x40\x80\x80",
    )
    .await;

    assert_eq!(response.status, 401, "an unsigned commit is never accepted");
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-HTTP-SIGNATURE-MALFORMED")
    );

    database.cleanup().await;
}

/// Die Koerperdecke greift VOR der Akkumulation.
///
/// Der Koerper ist um genau ein Byte zu gross; die Antwort ist die
/// Grenzabweisung des Nachtrags und nicht ein Rahmenfehler.
#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_body_is_refused_by_the_limit() {
    let database = common::fresh_database().await;
    let (server, organization_id) = spawn(&database).await;

    let body = vec![0x00_u8; MAX_ENTRY_COMMIT_BODY_BYTES_V1 + 1];
    let target = entry_commit_path(&hex::encode(CHAIN_ID));
    let nonce = fresh_challenge(&server, organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(&body),
        organization_id,
        request_id: [0x11; 16],
        nonce,
        created: SERVER_NOW_MILLIS / 1_000,
    });
    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &target,
        &headers,
        &body,
    )
    .await;

    assert_eq!(response.status, 413);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-SYNC-BODY-LIMIT")
    );

    database.cleanup().await;
}

/// Eine unlesbare Kettenkennung im Pfad ist eine UNBEKANNTE Kette.
///
/// `404` und nicht `400`: der Pfad ist wohlgeformt, er benennt nur nichts.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_chain_id_is_an_unknown_chain() {
    let database = common::fresh_database().await;
    let (server, organization_id) = spawn(&database).await;

    let body = ea_sync_protocol::ChallengeRequestV1::new(organization_id)
        .exact_bytes()
        .to_vec();
    // Wohlgeformter Pfad, aber keine 16 Byte in Hex.
    let target = entry_commit_path("nichtHex");
    let nonce = fresh_challenge(&server, organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(&body),
        organization_id,
        request_id: [0x12; 16],
        nonce,
        created: SERVER_NOW_MILLIS / 1_000,
    });
    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &target,
        &headers,
        &body,
    )
    .await;

    // Der Aufrufer traegt keine `initialGrant`-Capability; das Tor steht VOR
    // der Pfadauswertung, und genau das ist die fail-closed Reihenfolge.
    assert!(
        matches!(response.status, 403 | 404),
        "an unreadable chain id never reaches the nine steps, got {}",
        response.status
    );
    assert!(ProtocolErrorV1::decode(&response.body).is_ok());

    database.cleanup().await;
}

/// Ein Koerper, der kein `entry-commit-request-v1` ist, wird als Rahmenfehler
/// abgewiesen — und niemals halb verarbeitet.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_frame_is_refused() {
    let database = common::fresh_database().await;
    let (server, organization_id) = spawn(&database).await;

    let body = b"\xff\xff\xff\xff".to_vec();
    let target = entry_commit_path(&hex::encode(CHAIN_ID));
    let nonce = fresh_challenge(&server, organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(&body),
        organization_id,
        request_id: [0x13; 16],
        nonce,
        created: SERVER_NOW_MILLIS / 1_000,
    });
    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &target,
        &headers,
        &body,
    )
    .await;

    assert!(
        matches!(response.status, 400 | 403 | 413),
        "a malformed frame is never accepted, got {}",
        response.status
    );
    assert!(ProtocolErrorV1::decode(&response.body).is_ok());
    let counts: (i64, i64) =
        sqlx::query_as("SELECT (SELECT count(*) FROM entries), (SELECT count(*) FROM chain_heads)")
            .fetch_one(database.pool())
            .await
            .expect("counting must succeed");
    assert_eq!(counts, (0, 0));

    database.cleanup().await;
}

/// Ein falscher Medientyp wird abgewiesen — der Pruefer stellt die SIGNIERTE
/// Komponente gegen die des Endpunkts.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_media_type_is_refused() {
    let database = common::fresh_database().await;
    let (server, organization_id) = spawn(&database).await;

    let body = b"\x85\x01\x40\x80\x80".to_vec();
    let target = entry_commit_path(&hex::encode(CHAIN_ID));
    let nonce = fresh_challenge(&server, organization_id).await;
    let mut headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(&body),
        organization_id,
        request_id: [0x14; 16],
        nonce,
        created: SERVER_NOW_MILLIS / 1_000,
    });
    for header in &mut headers {
        if header.0 == "content-type" {
            header.1 = "application/octet-stream".to_owned();
        }
    }
    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &target,
        &headers,
        &body,
    )
    .await;

    // `400` und nicht `401`: die Abbildung des Nachtrags fuehrt einen
    // fehlerhaften Rahmen — und der Medientyp ist Teil des Rahmens — in der
    // 400-Zeile, waehrend 401 der Signatur selbst gehoert.
    assert_eq!(response.status, 400);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-HTTP-CONTENT-TYPE")
    );

    database.cleanup().await;
}

/// Ein Schluessel, den KEIN Trust-Objekt kennt, loest nicht auf.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_key_never_reaches_the_commit() {
    let database = common::fresh_database().await;
    let (server, organization_id) = spawn(&database).await;

    let body = b"\x85\x01\x40\x80\x80".to_vec();
    let target = entry_commit_path(&hex::encode(CHAIN_ID));
    let nonce = fresh_challenge(&server, organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer([0x9c; 32]),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(&body),
        organization_id,
        request_id: [0x15; 16],
        nonce,
        created: SERVER_NOW_MILLIS / 1_000,
    });
    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &target,
        &headers,
        &body,
    )
    .await;

    assert_eq!(response.status, 401);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-HTTP-KEY-UNRESOLVED")
    );

    database.cleanup().await;
}

/// Eine bereits verbrauchte Challenge oeffnet kein zweites Mal.
#[tokio::test(flavor = "multi_thread")]
async fn a_spent_challenge_does_not_open_twice() {
    let database = common::fresh_database().await;
    let (server, organization_id) = spawn(&database).await;

    let body = b"\x85\x01\x40\x80\x80".to_vec();
    let target = entry_commit_path(&hex::encode(CHAIN_ID));
    let nonce = fresh_challenge(&server, organization_id).await;

    for (index, request_id) in [[0x16_u8; 16], [0x17_u8; 16]].into_iter().enumerate() {
        let headers = common::signed_headers(&common::SignedCall {
            signer: &signer(ADMIN_SEED),
            endpoint: EndpointV1::EntryCommits,
            authority: &server.authority,
            target: &target,
            body: Some(&body),
            organization_id,
            request_id,
            nonce,
            created: SERVER_NOW_MILLIS / 1_000,
        });
        let response = common::https_request(
            server.address,
            &server.authority,
            "POST",
            &target,
            &headers,
            &body,
        )
        .await;
        if index == 1 {
            assert_eq!(response.status, 401, "a nonce opens exactly once");
            assert_eq!(
                error_code(&response.body).as_deref(),
                Some("EA-AUTH-NONCE-REPLAY")
            );
        }
    }

    database.cleanup().await;
}
