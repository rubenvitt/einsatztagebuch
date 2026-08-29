//! `POST /v1/chains/{chainId}/entry-commits` gegen ECHTE Dienste.
//!
//! Jeder Fall laeuft den ganzen Weg: TLS 1.3, Axum, die Adapter, PostgreSQL
//! und der Object Store. Ein `oneshot` gegen den Router prueefte eine
//! Abkuerzung, die es im Betrieb nicht gibt.
//!
//! # Die Reichweite dieses Ziels, ausgeschrieben
//!
//! Der Endpunkt verlangt die Capability `initialGrant`
//! (`crates/ea-sync-protocol/src/lib.rs`, `required_capability`). Der einzige
//! serverseitige Vertrauensbestand dieses Standes sind die EINGEFRORENEN
//! Vektoren unter `vectors/trust/v1/`, und in denen gibt es kein einziges
//! Zertifikat mit dieser Capability: der Erzeuger vergibt ausschliesslich
//! `organizationAdminApprove` (`crates/ea-testkit/src/lib.rs`:2711, :3241),
//! und es gibt dort weder ein `Writer`- noch ein `Reader`- noch ein
//! `RecoveryRecipient`-Zertifikat. `vectors/` und `crates/ea-testkit` sind
//! fuer diese Aufgabe eingefroren.
//!
//! Ein ANGENOMMENER Commit ist ueber diesen Weg deshalb nicht herstellbar, und
//! dieses Ziel behauptet es auch nicht. Es misst, was hier tatsaechlich
//! messbar ist: dass die Route gemountet ist, dass die signierte Anfrage den
//! ganzen Weg durch TLS, Signaturpruefung und Rahmendekodierung nimmt, und
//! dass sie am Capability-Tor fail-closed und mit dem eingefrorenen
//! Fehlerkoerper endet.
//!
//! Die neun Schritte selbst — Vollstaendigkeit der Empfaengermenge, Fork,
//! falscher Vorgaenger, unzulaessiger Writer, Bytekonflikt, Replay mit
//! bytegleicher Quittung, Datenbankabbruch, Object-Store-Ausfall und
//! Nebenlaeufigkeit — sind in `crates/ea-sync-server/tests/commit_service.rs`
//! gegen ECHTE Objekte und die ECHTE Signaturpruefung gemessen, mit Attrappen
//! ausschliesslich an den Ports.

mod common;

use ea_crypto::SecretBytes;
use ea_sync_protocol::{
    ChallengeRequestV1, ChallengeResponseV1, EndpointV1, EntryCommitOutcome, EntryCommitResponseV1,
    ProtocolErrorV1, RequestSigner, STRUCTURED_MEDIA_TYPE_V1,
};
use ea_types::{CertificateHash, OrganizationId, UnixMillis};

/// Innerhalb des `notBefore`/`notAfter`-Fensters der eingefrorenen Koepfe.
const SERVER_NOW_MILLIS: i64 = 1_000;
const ADMIN_SEED: [u8; 32] = ea_testkit::TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED;
const SERVER_SECRET: [u8; 32] = [0x51; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];
const ROTATION_CASE: &str = "registry/accepted-admin-rotation";

/// Die Kette, in die geschrieben wuerde.
const CHAIN_ID: [u8; 16] = [0x71; 16];

pub fn signer(seed: [u8; 32]) -> RequestSigner {
    RequestSigner::from_secret(SecretBytes::new(seed))
}

pub fn error_code(body: &[u8]) -> Option<String> {
    ProtocolErrorV1::decode(body)
        .ok()
        .map(|error| error.error_code().to_owned())
}

pub fn entry_commit_path(chain_id: [u8; 16]) -> String {
    format!("/v1/chains/{}/entry-commits", hex::encode(chain_id))
}

pub async fn fresh_challenge(
    server: &common::TestServer,
    organization_id: OrganizationId,
) -> [u8; 32] {
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

/// Ein syntaktisch gueltiger, vollstaendig gerahmter Commit-Koerper.
///
/// Die Objekte darin sind EINGEFRORENE Vektoren: ein `.eip` aus
/// `vectors/format/v1/valid` und ein `.eag` aus `vectors/grants/v1`. Sie
/// gehoeren ausdruecklich NICHT zum Trust-Bestand dieser Organisation — der
/// Koerper soll den Rahmen und den Weg pruefen, nicht die neun Schritte, die
/// er nach der Reichweitennotiz oben gar nicht erreicht.
pub fn framed_commit_body() -> Vec<u8> {
    use ea_format::{GrantPlanItemV1, GrantPlanV1, ParsedArchiveObject};

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    let entry = std::fs::read(root.join("format/v1/valid/eip/valid.bin"))
        .expect("the frozen entry vector must read");
    let grant = std::fs::read(root.join("grants/v1/grant/accepted-initial-reader.bin"))
        .expect("the frozen grant vector must read");

    let ParsedArchiveObject::Grant(parsed) =
        ea_format::decode_exact_object(&grant).expect("the frozen grant parses")
    else {
        panic!("the frozen grant vector is a grant");
    };
    let fields = parsed.value().grant_body().fields();
    // Der Plan wird aus dem GELIEFERTEN Grant gebildet, damit der Rahmen
    // konsistent ist. `GrantPlanV1::new` verlangt genau einen
    // Recovery-Empfaenger — der eingefrorene Reader-Grant allein ergaebe
    // keinen Plan, also traegt der Plan hier zusaetzlich einen
    // Recovery-Eintrag ueber denselben Empfaenger unter anderem Zweck.
    let plan = GrantPlanV1::new(vec![
        GrantPlanItemV1::new(
            fields.recipient_key_thumbprint,
            fields.recipient_certificate_hash,
            fields.purpose,
        ),
        GrantPlanItemV1::new(
            fields.issuer_key_thumbprint,
            fields.issuer_certificate_hash,
            ea_format::GrantPurposeV1::Recovery,
        ),
    ])
    .expect("the framed plan is well formed");
    ea_sync_protocol::EntryCommitRequestV1::new(entry, plan, vec![grant])
        .expect("the framed commit request is valid")
        .exact_bytes()
        .to_vec()
}

/// Die Route IST gemountet, und ein vollstaendig signierter Commit nimmt den
/// ganzen Weg — bis zum Capability-Tor.
///
/// Die Aussage ist doppelt: `404` traefe hier eine nicht gemountete Route,
/// `401` eine gescheiterte Signatur. Genau `403` mit
/// `EA-HTTP-CAPABILITY-MISSING` belegt, dass TLS, Routing, RFC-9421-Pruefung,
/// Challenge-Verbrauch und die Aufloesung des Zertifikats getragen haben und
/// dass allein die fehlende Capability den Commit verweigert.
#[tokio::test(flavor = "multi_thread")]
async fn a_signed_commit_reaches_the_capability_gate_of_the_mounted_route() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), ROTATION_CASE, &[]).await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        fixture.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;

    let body = framed_commit_body();
    let target = entry_commit_path(CHAIN_ID);
    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(&body),
        organization_id: fixture.organization_id,
        request_id: [0x01; 16],
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

    assert_eq!(
        response.status, 403,
        "an organizationAdminApprove certificate carries no initialGrant capability"
    );
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-HTTP-CAPABILITY-MISSING")
    );
    // Nichts ist entstanden: kein Eintrag, kein Kopf, keine Quittung.
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM entries), (SELECT count(*) FROM chain_heads), \
         (SELECT count(*) FROM receipts)",
    )
    .fetch_one(database.pool())
    .await
    .expect("counting must succeed");
    assert_eq!(counts, (0, 0, 0));

    database.cleanup().await;
}

/// Der Fehlerkoerper traegt KEIN Fragment der gelieferten Nutzdaten.
///
/// Gemessen und nicht behauptet: die Objektbytes des Koerpers kommen als
/// Kanarienvogel in die Suche.
#[tokio::test(flavor = "multi_thread")]
async fn the_error_body_carries_no_fragment_of_the_delivered_payload() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), ROTATION_CASE, &[]).await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        fixture.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;

    let body = framed_commit_body();
    let target = entry_commit_path(CHAIN_ID);
    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(&body),
        organization_id: fixture.organization_id,
        request_id: [0x02; 16],
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

    // Zweiunddreissig Byte aus der Mitte des Koerpers sind lang genug, um
    // zufaellige Treffer auszuschliessen.
    let canary = &body[body.len() / 2..body.len() / 2 + 32];
    assert!(
        !ea_testkit::contains_canary(&response.body, canary),
        "the error body must not echo the delivered payload"
    );
    assert!(ProtocolErrorV1::decode(&response.body).is_ok());

    database.cleanup().await;
}

/// `checkpoint-bytes` bleibt in DIESER Stufe `null`.
///
/// Eine Aussage ueber den Antwortrahmen und keine ueber einen Lauf: der
/// Handler setzt das Feld auf `None`, und der Standard-Checkpoint fuellt es
/// spaeter, ohne ein Receipt-Byte zu beruehren.
#[test]
fn the_response_frame_carries_a_null_checkpoint_in_this_stage() {
    let receipt = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors/receipts/v1/receipt/accepted-with-evidence-due.bin"),
    )
    .expect("the frozen receipt vector must read");
    let response = EntryCommitResponseV1::new(EntryCommitOutcome::Accepted, receipt.clone(), None);
    assert_eq!(response.checkpoint_bytes(), None);
    assert_eq!(response.receipt_bytes(), receipt.as_slice());

    let decoded = EntryCommitResponseV1::decode(response.exact_bytes())
        .expect("the response frame round-trips");
    assert_eq!(decoded.checkpoint_bytes(), None);
    assert_eq!(decoded.outcome(), EntryCommitOutcome::Accepted);
}
