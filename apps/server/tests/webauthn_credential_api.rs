//! `POST /v1/webauthn-credentials` gegen echte Dienste.
//!
//! Zwei Aussagen, und beide sind Sicherheitsaussagen:
//!
//! 1. Die Registrierung bindet die pseudonyme `subjectId` als `userHandle` und
//!    verbraucht dabei GENAU EINE Challenge; ein zweiter Versuch auf derselben
//!    Challenge scheitert.
//! 2. Sie verleiht dem Server KEINE Autoritaet: kein Trust-Objekt, kein
//!    Rollenintervall, kein freigegebenes Geraet
//!    (`web-reader-design.md` §6.4.1, :230-233).

mod common;

use ea_sync_protocol::{
    ChallengeRequestV1, ChallengeResponseV1, EndpointAuthentication, EndpointV1, ProtocolErrorV1,
    RequestSigner, STRUCTURED_MEDIA_TYPE_V1, WebauthnCredentialRegistrationV1,
};
use ea_types::{CertificateHash, SubjectId, UnixMillis};
use sqlx::{PgPool, Row};

/// Der Zeitpunkt, an dem dieser Test steht.
///
/// Er liegt INNERHALB des `notBefore`/`notAfter`-Fensters der eingefrorenen
/// Registry-Koepfe (`issuedAt` 100, `notAfter` 10 000). Die Wanduhr des
/// Rechners liegt Jahrzehnte daneben, und ein veralteter Kopf waehlte gar
/// nicht erst aus — deshalb steht die Serverzeit hier fest und wird nicht
/// gelesen.
const SERVER_NOW_MILLIS: i64 = 1_000;

/// Der Seed des ersten Organisationsadministrators der eingefrorenen Vektoren.
/// Sein Zertifikat ist unter dem ersten Registry-Head aktiv.
const ADMIN_SEED: [u8; 32] = ea_testkit::TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED;

const SERVER_SECRET: [u8; 32] = [0x51; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];

fn signer(seed: [u8; 32]) -> RequestSigner {
    RequestSigner::from_secret(ea_crypto::SecretBytes::new(seed))
}

/// Holt eine frische Challenge und gibt ihre Nonce heraus.
async fn fresh_challenge(
    server: &common::TestServer,
    organization_id: ea_types::OrganizationId,
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
    assert_eq!(
        response.status,
        200,
        "the challenge endpoint must answer 200; it answered {}",
        error_code(&response.body).unwrap_or_default()
    );
    ChallengeResponseV1::decode(&response.body)
        .expect("the challenge response must decode")
        .core()
        .nonce
}

/// Der stabile Code eines `protocol-error-v1`, sofern der Koerper einer ist.
fn error_code(body: &[u8]) -> Option<String> {
    ProtocolErrorV1::decode(body)
        .ok()
        .map(|error| error.error_code().to_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_registration_binds_the_subject_and_spends_its_challenge() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(
        database.pool(),
        "registry/accepted-bootstrap-and-first-head",
        &[],
    )
    .await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        fixture.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;

    // Der Bestand VOR der Registrierung. Die eingefrorenen Administratoren
    // sind selbst `deviceCertificate`-Objekte, also beweist eine absolute Null
    // nichts — beweisen laesst sich nur, dass sich NICHTS bewegt hat.
    let before = authority_snapshot(database.pool()).await;

    let subject = SubjectId::try_from(&[0x71_u8; 16][..]).expect("16 bytes");
    let registration =
        WebauthnCredentialRegistrationV1::new(subject, vec![0x81; 32], vec![0x82; 48])
            .expect("the registration frame must build");

    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let signer = signer(ADMIN_SEED);
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer,
        endpoint: EndpointV1::WebauthnCredentials,
        authority: &server.authority,
        target: EndpointV1::WebauthnCredentials.path_template(),
        body: Some(registration.exact_bytes()),
        organization_id: fixture.organization_id,
        request_id: [0x01; 16],
        nonce,
        created: 0,
    });
    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        EndpointV1::WebauthnCredentials.path_template(),
        &headers,
        registration.exact_bytes(),
    )
    .await;
    assert_eq!(
        response.status,
        201,
        "a signed credential registration must answer 201; it answered {:?}",
        error_code(&response.body)
    );

    // Die pseudonyme subjectId IST der userHandle.
    let stored: Vec<u8> = sqlx::query(
        "SELECT subject_id FROM webauthn_credentials WHERE organization_id = $1 \
         AND credential_id = $2",
    )
    .bind(&fixture.organization_id.as_bytes()[..])
    .bind(&[0x81_u8; 32][..])
    .fetch_one(database.pool())
    .await
    .expect("the credential must be stored")
    .get("subject_id");
    assert_eq!(
        stored,
        subject.as_bytes(),
        "the pseudonymous subjectId is the userHandle (web-reader-design.md §6.4.1)"
    );

    // Derselbe Request ein zweites Mal: die Challenge ist verbraucht.
    let replay = common::https_request(
        server.address,
        &server.authority,
        "POST",
        EndpointV1::WebauthnCredentials.path_template(),
        &headers,
        registration.exact_bytes(),
    )
    .await;
    assert_eq!(
        error_code(&replay.body).as_deref(),
        Some("EA-AUTH-NONCE-REPLAY"),
        "a spent challenge must be refused with its stable code"
    );
    assert_eq!(replay.status, 401);

    assert_eq!(
        authority_snapshot(database.pool()).await,
        before,
        "registering a credential grants NO role, capability or device authority and creates no \
         Trust entry (web-reader-design.md §6.4.1, :230-233)"
    );

    database.cleanup().await;
}

/// Die drei Stellen, an denen Autoritaet stehen KOENNTE.
///
/// Rollenintervalle, beantragte Geraete und Trust-Ereignisse. Die
/// Registrierung eines Credentials darf an keiner davon etwas aendern.
async fn authority_snapshot(pool: &PgPool) -> (i64, i64, i64) {
    let count = |statement: &'static str| async move {
        sqlx::query(statement)
            .fetch_one(pool)
            .await
            .expect("counting must succeed")
            .get::<i64, _>("n")
    };
    (
        count("SELECT count(*) AS n FROM role_intervals").await,
        count("SELECT count(*) AS n FROM pending_device_requests").await,
        count("SELECT count(*) AS n FROM trust_events").await,
    )
}

/// Der Endpunkt ist REGULAER signiert und keine der beiden Ausnahmen.
#[test]
fn the_credential_endpoint_is_a_signed_endpoint() {
    assert_eq!(
        EndpointV1::WebauthnCredentials.authentication(),
        EndpointAuthentication::Signed,
        "web-reader-design.md §6.4.1: the reader owns its key at registration time"
    );
    assert_eq!(EndpointV1::WebauthnCredentials.success_status(), 201);
}
