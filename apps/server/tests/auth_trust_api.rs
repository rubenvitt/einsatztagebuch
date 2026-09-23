//! Challenges, Geraeteantraege und Trust-Verteilung gegen echte Dienste.
//!
//! Jeder Fall laeuft den ganzen Weg: TLS 1.3, Axum, die Adapter, PostgreSQL
//! und der Object Store. Ein `oneshot` gegen den Router prueefte eine
//! Abkuerzung, die es im Betrieb nicht gibt.

mod common;

use ea_crypto::{CoseSigner, DeviceRegistrationRequestCoreV1, SecretBytes};
use ea_sync_protocol::{
    ChallengeRequestV1, ChallengeResponseV1, DeviceRegistrationRequestV1, EndpointAuthentication,
    EndpointV1, ProtocolErrorV1, RequestSigner, STRUCTURED_MEDIA_TYPE_V1, TrustEventUploadV1,
    TrustRegistryResponseV1, organization_tag,
};
use ea_types::{CertificateHash, DeviceId, OrganizationId, RegistryVersion, UnixMillis};
use sqlx::{PgPool, Row};

/// Innerhalb des `notBefore`/`notAfter`-Fensters der eingefrorenen Koepfe.
const SERVER_NOW_MILLIS: i64 = 1_000;
const ADMIN_SEED: [u8; 32] = ea_testkit::TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED;
/// Ein Schluessel, den KEIN Trust-Objekt kennt.
const UNKNOWN_DEVICE_SEED: [u8; 32] = [0x9c; 32];
const SERVER_SECRET: [u8; 32] = [0x51; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];

/// Der Fall, dessen zweiter Registry-Head zurueckgehalten und ueber den
/// Endpunkt nachgereicht wird.
const ROTATION_CASE: &str = "registry/accepted-admin-rotation";
const WITHHELD_HEAD: &str = "second-head-event.bin";

fn signer(seed: [u8; 32]) -> RequestSigner {
    RequestSigner::from_secret(SecretBytes::new(seed))
}

fn error_code(body: &[u8]) -> Option<String> {
    ProtocolErrorV1::decode(body)
        .ok()
        .map(|error| error.error_code().to_owned())
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
    assert_eq!(
        response.status, 200,
        "the challenge endpoint must answer 200"
    );
    ChallengeResponseV1::decode(&response.body)
        .expect("the challenge response must decode")
        .core()
        .nonce
}

/// Ein selbstsignierter Registrierungsantrag mit dem BEANTRAGTEN Schluessel.
fn registration_request(
    organization_id: OrganizationId,
    device: DeviceId,
    seed: [u8; 32],
) -> DeviceRegistrationRequestV1 {
    let request_signer = signer(seed);
    let core = DeviceRegistrationRequestCoreV1 {
        organization_id,
        device_id: device,
        requested_role: 0,
        signing_public_cose_key: request_signer.public_key(),
        kem_public_cose_key: None,
        supported_format_versions: vec![1],
        supported_suite_ids: vec![ea_types::SUITE_ID_V1.to_owned()],
    };
    let exact_core =
        ea_crypto::encode_device_registration_request_core(&core).expect("the core encodes");
    let signature = CoseSigner::from_secret(SecretBytes::new(seed))
        .sign_enrollment(&exact_core)
        .expect("the enrollment self-signature must succeed");
    DeviceRegistrationRequestV1::new(core, &signature).expect("the registration frame must build")
}

/// Eine Organisation ohne Trust-Bestand — fuer den Antragspfad reicht sie, denn
/// er traegt ausdruecklich KEINE Organisationsautoritaet.
async fn insert_bare_organization(pool: &PgPool, organization_id: OrganizationId) {
    sqlx::query(
        "INSERT INTO organizations (organization_id, root_key_thumbprint, created_at_millis) \
         VALUES ($1, $2, 0)",
    )
    .bind(&organization_id.as_bytes()[..])
    .bind(&[0x07_u8; 32][..])
    .execute(pool)
    .await
    .expect("the organization row is technical and must insert");
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_is_single_use_and_registration_remains_pending() {
    let database = common::fresh_database().await;
    let organization_id = OrganizationId::try_from(&[0x31_u8; 16][..]).expect("16 bytes");
    insert_bare_organization(database.pool(), organization_id).await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;

    let device = DeviceId::try_from(&[0x41_u8; 16][..]).expect("16 bytes");
    let request = registration_request(organization_id, device, UNKNOWN_DEVICE_SEED);
    let nonce = fresh_challenge(&server, organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(UNKNOWN_DEVICE_SEED),
        endpoint: EndpointV1::DeviceRegistrations,
        authority: &server.authority,
        target: EndpointV1::DeviceRegistrations.path_template(),
        body: Some(request.exact_bytes()),
        organization_id,
        request_id: [0x02; 16],
        nonce,
        created: 0,
    });

    let accepted = common::https_request(
        server.address,
        &server.authority,
        "POST",
        EndpointV1::DeviceRegistrations.path_template(),
        &headers,
        request.exact_bytes(),
    )
    .await;
    assert_eq!(
        accepted.status,
        202,
        "a proof-of-possession registration is ACCEPTED, not released; it answered {:?}",
        error_code(&accepted.body)
    );
    assert!(
        accepted.body.is_empty(),
        "202 carries no body (sync wire addendum)"
    );

    let state: String = sqlx::query(
        "SELECT request_state FROM pending_device_requests WHERE organization_id = $1 \
         AND device_id = $2",
    )
    .bind(&organization_id.as_bytes()[..])
    .bind(&device.as_bytes()[..])
    .fetch_one(database.pool())
    .await
    .expect("the pending request must exist")
    .get("request_state");
    assert_eq!(state, "pending");

    // Derselbe Antrag ein zweites Mal: die Challenge ist verbraucht.
    let replay = common::https_request(
        server.address,
        &server.authority,
        "POST",
        EndpointV1::DeviceRegistrations.path_template(),
        &headers,
        request.exact_bytes(),
    )
    .await;
    assert_eq!(
        error_code(&replay.body).as_deref(),
        Some("EA-AUTH-NONCE-REPLAY")
    );
    assert_eq!(replay.status, 401);

    assert!(
        !device_is_authorized(&server, organization_id, UNKNOWN_DEVICE_SEED).await,
        "a pending registration activates NO authority"
    );
    let roles: i64 = sqlx::query("SELECT count(*) AS n FROM role_intervals")
        .fetch_one(database.pool())
        .await
        .expect("counting role intervals must succeed")
        .get("n");
    assert_eq!(roles, 0, "no role interval may appear from a mere request");

    database.cleanup().await;
}

/// Darf dieses Geraet irgendetwas? Gefragt wird auf dem Weg, auf dem es
/// zaehlte: ein signierter Request an einen Endpunkt, der ein freigegebenes
/// Geraet verlangt.
async fn device_is_authorized(
    server: &common::TestServer,
    organization_id: OrganizationId,
    seed: [u8; 32],
) -> bool {
    let nonce = fresh_challenge(server, organization_id).await;
    let target = format!(
        "{}?afterVersion=0",
        EndpointV1::TrustRegistry.path_template()
    );
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(seed),
        endpoint: EndpointV1::TrustRegistry,
        authority: &server.authority,
        target: &target,
        body: None,
        organization_id,
        request_id: [0x03; 16],
        nonce,
        created: 0,
    });
    let response = common::https_request(
        server.address,
        &server.authority,
        "GET",
        &target,
        &headers,
        &[],
    )
    .await;
    response.status == 200
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_authorized_admin_publishes_a_trust_event_and_reads_the_exact_objects() {
    let database = common::fresh_database().await;
    let fixture =
        common::seed_trust_fixture(database.pool(), ROTATION_CASE, &[WITHHELD_HEAD]).await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        fixture.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;

    let withheld = fixture
        .withheld
        .first()
        .expect("the case withholds its second registry head")
        .clone();
    let upload = TrustEventUploadV1::new(withheld.clone()).expect("the upload frame must build");

    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::TrustEvents,
        authority: &server.authority,
        target: EndpointV1::TrustEvents.path_template(),
        body: Some(upload.exact_bytes()),
        organization_id: fixture.organization_id,
        request_id: [0x04; 16],
        nonce,
        created: 0,
    });
    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        EndpointV1::TrustEvents.path_template(),
        &headers,
        upload.exact_bytes(),
    )
    .await;
    assert_eq!(
        response.status,
        201,
        "organizationAdminApprove must be able to publish a valid .etb; it answered {:?}",
        error_code(&response.body)
    );

    // Die Registry-Linie liefert EXAKTE Objektbytes — nicht eine aus Zeilen
    // zusammengesetzte Fassung davon.
    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let target = format!(
        "{}?afterVersion=0",
        EndpointV1::TrustRegistry.path_template()
    );
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::TrustRegistry,
        authority: &server.authority,
        target: &target,
        body: None,
        organization_id: fixture.organization_id,
        request_id: [0x05; 16],
        nonce,
        created: 0,
    });
    let page = common::https_request(
        server.address,
        &server.authority,
        "GET",
        &target,
        &headers,
        &[],
    )
    .await;
    assert_eq!(page.status, 200, "{:?}", error_code(&page.body));
    let page = TrustRegistryResponseV1::decode(&page.body).expect("the registry page decodes");
    assert_eq!(page.events().len(), 2, "both heads are on the line");
    assert_eq!(page.events()[1].exact_etb_bytes(), withheld.as_slice());

    // Nach der Version des ersten Kopfes bleibt genau einer uebrig.
    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let target = format!(
        "{}?afterVersion=1",
        EndpointV1::TrustRegistry.path_template()
    );
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::TrustRegistry,
        authority: &server.authority,
        target: &target,
        body: None,
        organization_id: fixture.organization_id,
        request_id: [0x06; 16],
        nonce,
        created: 0,
    });
    let page = common::https_request(
        server.address,
        &server.authority,
        "GET",
        &target,
        &headers,
        &[],
    )
    .await;
    assert_eq!(page.status, 200);
    let page = TrustRegistryResponseV1::decode(&page.body).expect("the registry page decodes");
    assert_eq!(page.events().len(), 1);

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_unauthorized_caller_can_mutate_trust() {
    let database = common::fresh_database().await;
    let fixture =
        common::seed_trust_fixture(database.pool(), ROTATION_CASE, &[WITHHELD_HEAD]).await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        fixture.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;
    let upload = TrustEventUploadV1::new(
        fixture
            .withheld
            .first()
            .expect("the case withholds its second registry head")
            .clone(),
    )
    .expect("the upload frame must build");

    // 1. Ein Geraet, das kein Trust-Objekt kennt — der pending Fall.
    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(UNKNOWN_DEVICE_SEED),
        endpoint: EndpointV1::TrustEvents,
        authority: &server.authority,
        target: EndpointV1::TrustEvents.path_template(),
        body: Some(upload.exact_bytes()),
        organization_id: fixture.organization_id,
        request_id: [0x11; 16],
        nonce,
        created: 0,
    });
    let unknown = post_trust_event(&server, &headers, upload.exact_bytes()).await;
    assert_eq!(
        error_code(&unknown.body).as_deref(),
        Some("EA-HTTP-KEY-UNRESOLVED"),
        "an unreleased key resolves to nothing"
    );
    assert_eq!(unknown.status, 401);

    // 2. Eine fremde Organisation im `tag`.
    let foreign = OrganizationId::try_from(&[0x77_u8; 16][..]).expect("16 bytes");
    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::TrustEvents,
        authority: &server.authority,
        target: EndpointV1::TrustEvents.path_template(),
        body: Some(upload.exact_bytes()),
        organization_id: foreign,
        request_id: [0x12; 16],
        nonce,
        created: 0,
    });
    let wrong_organization = post_trust_event(&server, &headers, upload.exact_bytes()).await;
    assert!(
        matches!(wrong_organization.status, 401 | 403),
        "a foreign organization tag must never publish; it answered {}",
        wrong_organization.status
    );
    assert_ne!(
        organization_tag(foreign),
        organization_tag(fixture.organization_id)
    );

    // 3. Eine Nonce, die nie eine Challenge war.
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::TrustEvents,
        authority: &server.authority,
        target: EndpointV1::TrustEvents.path_template(),
        body: Some(upload.exact_bytes()),
        organization_id: fixture.organization_id,
        request_id: [0x13; 16],
        nonce: [0xee; 32],
        created: 0,
    });
    let invented = post_trust_event(&server, &headers, upload.exact_bytes()).await;
    assert_eq!(
        error_code(&invented.body).as_deref(),
        Some("EA-AUTH-CHALLENGE-UNKNOWN")
    );
    assert_eq!(invented.status, 401);

    // 4. Eine Signatur, deren Fenster laengst zu ist.
    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::TrustEvents,
        authority: &server.authority,
        target: EndpointV1::TrustEvents.path_template(),
        body: Some(upload.exact_bytes()),
        organization_id: fixture.organization_id,
        request_id: [0x14; 16],
        nonce,
        created: -10_000,
    });
    let stale = post_trust_event(&server, &headers, upload.exact_bytes()).await;
    assert_eq!(
        error_code(&stale.body).as_deref(),
        Some("EA-HTTP-REQUEST-EXPIRED")
    );
    assert_eq!(stale.status, 401);

    // Nach vier Verweigerungen steht die Registry-Linie unveraendert bei EINEM
    // Kopf: kein abgewiesener Aufrufer hat etwas geschrieben.
    let heads: i64 = sqlx::query("SELECT count(*) AS n FROM registry_events")
        .fetch_one(database.pool())
        .await
        .expect("counting registry heads must succeed")
        .get("n");
    assert_eq!(heads, 1, "no refused caller may have mutated Trust");

    database.cleanup().await;
}

async fn post_trust_event(
    server: &common::TestServer,
    headers: &[(&'static str, String)],
    body: &[u8],
) -> common::HttpResponse {
    common::https_request(
        server.address,
        &server.authority,
        "POST",
        EndpointV1::TrustEvents.path_template(),
        headers,
        body,
    )
    .await
}

/// Die Endpunktzusagen, gegen die dieser Task gebaut ist.
#[test]
fn the_five_endpoints_carry_the_authentication_the_addendum_records() {
    assert_eq!(
        EndpointV1::AuthChallenges.authentication(),
        EndpointAuthentication::Unsigned
    );
    assert_eq!(
        EndpointV1::DeviceRegistrations.authentication(),
        EndpointAuthentication::ProofOfPossession
    );
    assert_eq!(EndpointV1::DeviceRegistrations.required_capability(), None);
    assert_eq!(
        EndpointV1::TrustEvents.required_capability(),
        Some(ea_crypto::CertificateCapability::OrganizationAdminApprove)
    );
    assert_eq!(EndpointV1::TrustEvents.success_status(), 201);
    assert_eq!(EndpointV1::DeviceRegistrations.success_status(), 202);
}

/// Ein freigegebenes Geraet OHNE die geforderte Capability kommt an
/// `POST /v1/trust/events` nicht vorbei.
///
/// Der Fall steht als Einheitspruefung und nicht als HTTP-Fall, weil die
/// eingefrorenen Vektoren nur Zertifikate MIT `organizationAdminApprove`
/// kennen: ein Aufrufer ohne sie liesse sich aus ihnen nicht bauen, ohne die
/// eingefrorenen Bytes anzufassen. Geprueft wird deshalb genau die Kante, an
/// der die Entscheidung faellt — [`RequestVerifier::verify`] gegen die
/// Capability-Liste des aufgeloesten Zertifikats.
#[test]
fn a_released_device_without_the_capability_cannot_publish_a_trust_event() {
    use ea_crypto::CertificateCapability;
    use ea_sync_protocol::{
        DeviceDirectory, RegisteredDevice, ReplayStore, RequestIdV1, RequestParts, RequestVerifier,
        SignatureParametersV1, SignedRequestV1, body_digest, organization_tag,
    };

    struct OneDevice(RegisteredDevice);
    impl DeviceDirectory for OneDevice {
        fn lookup(&self, thumbprint: ea_types::KeyThumbprint) -> Option<RegisteredDevice> {
            (self.0.key_thumbprint() == thumbprint).then(|| self.0.clone())
        }
    }
    /// Verbraucht nichts — genau wie der Serverpfad, der die Einmalwerte
    /// danach in PostgreSQL holt.
    struct NeverReplayed;
    impl ReplayStore for NeverReplayed {
        fn claim_nonce(&mut self, _: &[u8; 32]) -> bool {
            true
        }
        fn claim_request_id(&mut self, _: RequestIdV1) -> bool {
            true
        }
    }

    let organization_id = OrganizationId::try_from(&[0x61_u8; 16][..]).expect("16 bytes");
    let request_signer = signer(UNKNOWN_DEVICE_SEED);
    // Freigegeben, mit Zertifikat, mit Organisationsbindung — und mit der
    // FALSCHEN Capability.
    let device = RegisteredDevice::new(
        organization_id,
        CertificateHash::try_from(&[0x62_u8; 32][..]).expect("32 bytes"),
        request_signer.public_key(),
        vec![CertificateCapability::InitialGrant],
    );

    let body = b"body";
    let authority = "sync.example.org";
    let parts = RequestParts {
        method: EndpointV1::TrustEvents.method(),
        authority: authority.to_owned(),
        target_uri: format!(
            "https://{authority}{}",
            EndpointV1::TrustEvents.path_template()
        ),
        content_type: EndpointV1::TrustEvents
            .request_media_type()
            .map(ToOwned::to_owned),
        body_digest: Some(body_digest(body)),
        request_id: RequestIdV1::try_from(&[0x63_u8; 16][..]).expect("16 bytes"),
    };
    let parameters =
        SignatureParametersV1::new(0, 300, [0x64; 32], organization_tag(organization_id));
    let signed: SignedRequestV1 = request_signer
        .sign(&parts, &parameters)
        .expect("signing must succeed");

    let directory = OneDevice(device);
    let verifier = RequestVerifier::new(
        EndpointV1::TrustEvents,
        authority,
        organization_id,
        1,
        &directory,
    );
    let refusal = verifier
        .verify(&signed, &mut NeverReplayed)
        .expect_err("a device without organizationAdminApprove must be refused");
    assert_eq!(refusal.code(), "EA-HTTP-CAPABILITY-MISSING");
    assert_eq!(refusal.http_status(), 403);
}

/// Zwei gleichzeitige authentisierte Requests derselben Organisation gelingen
/// BEIDE.
///
/// Die Aufloesung der Autoritaet ist lesend: sie laeuft ueber einen
/// Speicher, der nach der Antwort fort ist, und schreibt keine Zeile. Vorher
/// pinnte jeder Request den Kopf im persistenten Zustand, alle Requests einer
/// Organisation liefen ueber DIESELBE Zeile, und der Verlierer eines Rennens
/// bekam ein endgueltiges `401` mit „dein Schluessel ist unbekannt“ — obwohl
/// er nichts falsch gemacht hatte.
#[tokio::test(flavor = "multi_thread")]
async fn two_concurrent_authenticated_requests_both_succeed() {
    let database = common::fresh_database().await;
    let fixture =
        common::seed_trust_fixture(database.pool(), ROTATION_CASE, &[WITHHELD_HEAD]).await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        fixture.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;

    // Die Challenges VORHER holen: der Wettlauf soll um die Autoritaet gehen,
    // nicht um die Ausgabe der Nonce.
    let first_nonce = fresh_challenge(&server, fixture.organization_id).await;
    let second_nonce = fresh_challenge(&server, fixture.organization_id).await;
    let target = format!(
        "{}?afterVersion=0",
        EndpointV1::TrustRegistry.path_template()
    );

    let read = |nonce: [u8; 32], request_id: [u8; 16]| {
        let target = target.clone();
        let authority = server.authority.clone();
        let address = server.address;
        let organization_id = fixture.organization_id;
        async move {
            let headers = common::signed_headers(&common::SignedCall {
                signer: &signer(ADMIN_SEED),
                endpoint: EndpointV1::TrustRegistry,
                authority: &authority,
                target: &target,
                body: None,
                organization_id,
                request_id,
                nonce,
                created: 0,
            });
            common::https_request(address, &authority, "GET", &target, &headers, &[]).await
        }
    };

    let (first, second) = tokio::join!(
        read(first_nonce, [0x21; 16]),
        read(second_nonce, [0x22; 16])
    );
    assert_eq!(
        (first.status, second.status),
        (200, 200),
        "both concurrent callers must be authorized; they answered {:?} and {:?}",
        error_code(&first.body),
        error_code(&second.body)
    );

    // Und die lesende Aufloesung hat KEINE Zeile geschrieben.
    let rows: i64 = sqlx::query("SELECT count(*) AS n FROM trust_state")
        .fetch_one(database.pool())
        .await
        .expect("counting trust state rows must succeed")
        .get("n");
    assert_eq!(
        rows, 0,
        "authentication resolves authority read-only and must not pin the head"
    );

    database.cleanup().await;
}

/// Eine Challenge-Flut unter FREMDER Organisationskennung sperrt die
/// Organisation nicht aus.
///
/// Vorher zaehlte die Ratenbegrenzung je `organizationId` — ein Wert aus dem
/// UNSIGNIERTEN Koerper. Sechzig Anfragen mit der Kennung eines Opfers
/// erschoepften dessen Fenster, und weil jeder signierte Request eine frische
/// Challenge braucht, stand danach die ganze Organisation. Gezaehlt wird
/// jetzt je Gegenstelle.
#[tokio::test(flavor = "multi_thread")]
async fn a_flood_under_a_foreign_organization_id_does_not_lock_that_organization_out() {
    let database = common::fresh_database().await;
    let fixture =
        common::seed_trust_fixture(database.pool(), ROTATION_CASE, &[WITHHELD_HEAD]).await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        fixture.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;

    // Deutlich mehr als die frueher je Organisation erlaubten sechzig.
    let body = ChallengeRequestV1::new(fixture.organization_id);
    for _ in 0..65 {
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
            "the flood itself must not be what fails; it answered {:?}",
            error_code(&response.body)
        );
    }

    // Der legitime Aufrufer kommt weiterhin durch — Challenge UND signierter
    // Request.
    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let target = format!(
        "{}?afterVersion=0",
        EndpointV1::TrustRegistry.path_template()
    );
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::TrustRegistry,
        authority: &server.authority,
        target: &target,
        body: None,
        organization_id: fixture.organization_id,
        request_id: [0x23; 16],
        nonce,
        created: 0,
    });
    let response = common::https_request(
        server.address,
        &server.authority,
        "GET",
        &target,
        &headers,
        &[],
    )
    .await;
    assert_eq!(
        response.status,
        200,
        "a flood under the victim's own organization id must not lock it out; it answered {:?}",
        error_code(&response.body)
    );

    database.cleanup().await;
}

/// Kein ungeprueftes `.etb` kommt in den Bestand.
///
/// Drei Objekte, drei Gruende, dreimal `422` — und dreimal bleibt die
/// Registry-Linie bei ihrem einen Kopf.
#[tokio::test(flavor = "multi_thread")]
async fn no_unverified_trust_object_is_indexed() {
    let database = common::fresh_database().await;
    let fixture =
        common::seed_trust_fixture(database.pool(), ROTATION_CASE, &[WITHHELD_HEAD]).await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        fixture.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;

    let honest = fixture
        .withheld
        .first()
        .expect("the case withholds its second registry head")
        .clone();
    // Der Bestand VOR den drei Versuchen. Gemessen und nicht behauptet: eine
    // feste Zahl hier waere eine zweite Quelle fuer die Groesse des Vektors.
    let indexed_before = indexed_trust_objects(database.pool()).await;

    // 1. Dieselbe Kopfmeldung mit EINEM verdrehten Signaturbit.
    let mut tampered = honest.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        ea_format::decode_exact_object(&tampered).is_ok(),
        "the tampered object must still PARSE, so the refusal below is a trust finding and not a \
         framing one"
    );

    // 2. Eine Kopfmeldung, die der Administrator statt der Wurzel signiert hat
    //    — ein unzulaessiger Aussteller aus einem eingefrorenen Negativvektor.
    let wrong_signer =
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../vectors/trust/v1/registry/rejected-root-only-signed-by-admin/head-event.bin",
        ))
        .expect("the frozen negative vector must read");

    // 3. Ein Objekt, ueber das die geteilte Pruefung heute NICHTS beweisen
    //    kann: eine Administratorautorisierung, die kein Kopf nennt.
    let unprovable = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors/trust/v1/object/accepted-handmade-admin-authorization/admin-authorization.bin"),
    )
    .expect("the frozen object vector must read");

    for (index, (bytes, expected)) in [
        (tampered, "EA-TRUST-EVENT-INVALID"),
        (wrong_signer, "EA-TRUST-EVENT-INVALID"),
        (unprovable, "EA-TRUST-EVENT-UNVERIFIABLE"),
    ]
    .into_iter()
    .enumerate()
    {
        let upload = TrustEventUploadV1::new(bytes).expect("the upload frame must build");
        let nonce = fresh_challenge(&server, fixture.organization_id).await;
        let mut request_id = [0x30_u8; 16];
        request_id[15] = u8::try_from(index).expect("three cases fit in a byte");
        let headers = common::signed_headers(&common::SignedCall {
            signer: &signer(ADMIN_SEED),
            endpoint: EndpointV1::TrustEvents,
            authority: &server.authority,
            target: EndpointV1::TrustEvents.path_template(),
            body: Some(upload.exact_bytes()),
            organization_id: fixture.organization_id,
            request_id,
            nonce,
            created: 0,
        });
        let response = post_trust_event(&server, &headers, upload.exact_bytes()).await;
        assert_eq!(
            error_code(&response.body).as_deref(),
            Some(expected),
            "case {index} must be refused with its stable code"
        );
        assert_eq!(response.status, 422, "case {index}");
    }

    // Nichts davon ist im Bestand gelandet.
    let heads: i64 = sqlx::query("SELECT count(*) AS n FROM registry_events")
        .fetch_one(database.pool())
        .await
        .expect("counting registry heads must succeed")
        .get("n");
    assert_eq!(heads, 1, "no unverified object may join the registry line");
    assert_eq!(
        indexed_trust_objects(database.pool()).await,
        indexed_before,
        "the seeded catalogue must be unchanged; an unverified object is never indexed"
    );

    database.cleanup().await;
}

async fn indexed_trust_objects(pool: &PgPool) -> i64 {
    sqlx::query("SELECT count(*) AS n FROM trust_events")
        .fetch_one(pool)
        .await
        .expect("counting trust events must succeed")
        .get("n")
}

/// Eine Organisation wird VOLLSTAENDIG ueber den Endpunkt hochgezogen.
///
/// Nichts ausser dem Anker und den drei vom Anker BENANNTEN
/// Bootstrap-Objekten liegt vorher im Bestand — Policy, Autorisierungen und
/// beide Registrierungskoepfe kommen ueber `POST /v1/trust/events` herein, in
/// Abhaengigkeitsreihenfolge. Vorher war genau das unmoeglich: jedes dieser
/// Objekte war „nicht beweisbar“, und der Kopf, der sie braucht, fand sie
/// nicht.
///
/// Der erste Aufrufer authentisiert sich dabei gegen die vom ANKER benannten
/// Administratorzertifikate — es gibt noch keinen Kopf, gegen den er sich
/// sonst ausweisen koennte.
#[tokio::test(flavor = "multi_thread")]
async fn an_organization_bootstraps_its_whole_registry_line_through_the_endpoint() {
    // Alles ausser den drei ankerbenannten Objekten wird zurueckgehalten.
    const WITHHELD: [&str; 7] = [
        "policy-authorization.bin",
        "policy.bin",
        "head-authorization.bin",
        "head-event.bin",
        "rotation-authorization.bin",
        "admin-certificate-rotated.bin",
        "second-head-event.bin",
    ];
    // …und in GENAU dieser Reihenfolge nachgereicht: erst die Autorisierung,
    // dann ihr Ziel, dann der Kopf, der beide nennt.
    const ORDER: [&str; 8] = [
        "policy-authorization.bin",
        "policy.bin",
        "head-authorization.bin",
        "head-event.bin",
        "rotation-authorization.bin",
        "admin-certificate-rotated.bin",
        "second-head-authorization.bin",
        "second-head-event.bin",
    ];

    let database = common::fresh_database().await;
    let (fixture, withheld) = common::seed_trust_fixture_named(
        database.pool(),
        ROTATION_CASE,
        &[WITHHELD.as_slice(), &["second-head-authorization.bin"]].concat(),
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

    let heads_before: i64 = sqlx::query("SELECT count(*) AS n FROM registry_events")
        .fetch_one(database.pool())
        .await
        .expect("counting registry heads must succeed")
        .get("n");
    assert_eq!(heads_before, 0, "the organization starts without a head");

    for (index, name) in ORDER.iter().enumerate() {
        let bytes = withheld
            .iter()
            .find(|(withheld_name, _)| withheld_name == name)
            .map(|(_, bytes)| bytes.clone())
            .unwrap_or_else(|| panic!("{name} must be among the withheld objects"));
        let upload = TrustEventUploadV1::new(bytes).expect("the upload frame must build");
        let nonce = fresh_challenge(&server, fixture.organization_id).await;
        let mut request_id = [0x40_u8; 16];
        request_id[15] = u8::try_from(index).expect("eight objects fit in a byte");
        let headers = common::signed_headers(&common::SignedCall {
            signer: &signer(ADMIN_SEED),
            endpoint: EndpointV1::TrustEvents,
            authority: &server.authority,
            target: EndpointV1::TrustEvents.path_template(),
            body: Some(upload.exact_bytes()),
            organization_id: fixture.organization_id,
            request_id,
            nonce,
            created: 0,
        });
        let response = post_trust_event(&server, &headers, upload.exact_bytes()).await;
        assert_eq!(
            response.status,
            201,
            "step {index} ({name}) must be accepted; it answered {:?}",
            error_code(&response.body)
        );
    }

    // Beide Koepfe stehen jetzt auf der Linie, und die Antwort traegt die
    // EXAKTEN Bytes.
    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let target = format!(
        "{}?afterVersion=0",
        EndpointV1::TrustRegistry.path_template()
    );
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::TrustRegistry,
        authority: &server.authority,
        target: &target,
        body: None,
        organization_id: fixture.organization_id,
        request_id: [0x41; 16],
        nonce,
        created: 0,
    });
    let page = common::https_request(
        server.address,
        &server.authority,
        "GET",
        &target,
        &headers,
        &[],
    )
    .await;
    assert_eq!(page.status, 200, "{:?}", error_code(&page.body));
    let page = TrustRegistryResponseV1::decode(&page.body).expect("the registry page decodes");
    assert_eq!(
        page.events().len(),
        2,
        "both heads arrived through the endpoint"
    );

    database.cleanup().await;
}

/// Ein `registryEvent`, das nicht der naechste Kopf ist, nennt den, der es
/// waere.
///
/// Die Abbildung des Nachtrags fuehrt „erforderlicher neuerer Registry-Head“
/// unter `409`, und `protocol-error-v1` traegt Version und Hash an eigenen
/// Positionen. Ein Aufrufer, der nur `409` bekaeme, wuesste nicht, wohin.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_event_that_is_not_the_next_head_names_the_head_that_is() {
    let database = common::fresh_database().await;
    // Beide Koepfe liegen; der zweite ist also nicht mehr „der naechste“.
    let fixture = common::seed_trust_fixture(database.pool(), ROTATION_CASE, &[]).await;
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        fixture.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;

    // Der ERSTE Kopf, noch einmal eingereicht: gueltig, aber laengst ueberholt.
    let first_head = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors/trust/v1/registry/accepted-admin-rotation/head-event.bin"),
    )
    .expect("the frozen head must read");
    let upload = TrustEventUploadV1::new(first_head).expect("the upload frame must build");
    let nonce = fresh_challenge(&server, fixture.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::TrustEvents,
        authority: &server.authority,
        target: EndpointV1::TrustEvents.path_template(),
        body: Some(upload.exact_bytes()),
        organization_id: fixture.organization_id,
        request_id: [0x50; 16],
        nonce,
        created: 0,
    });
    let response = post_trust_event(&server, &headers, upload.exact_bytes()).await;
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-TRUST-EVENT-NOT-APPLICABLE")
    );
    assert_eq!(response.status, 409);
    let body = ProtocolErrorV1::decode(&response.body).expect("the error body decodes");
    assert_eq!(
        body.required_registry_version().map(RegistryVersion::get),
        Some(2),
        "the caller must be told WHICH head it needs first"
    );
    assert!(
        body.required_registry_head_hash().is_some(),
        "and under which hash"
    );
    assert!(!body.retryable(), "409 is not a technical failure");

    database.cleanup().await;
}

/// Der PERSISTENTE Registrierungspin ist der BODEN der Authentisierung.
///
/// Die Autoritaetsaufloesung laeuft auf einem fluechtigen Speicher — bewusst,
/// damit kein signierter Request eine Zeile schreibt. Genau deshalb sah sie
/// den Pin bisher gar nicht: waere der Katalog auf einen aelteren Stand
/// zurueckgefallen, haette sie die Zertifikate JENES Standes wieder als aktiv
/// gemeldet. Der Pin sagt, wie weit der Bestand nachweislich schon war; ein
/// Lauf dahinter ist ein Rueckfall.
///
/// Die Antwort ist ein ZUSTANDSBEFUND und kein Autorisierungsbefund: `503`
/// mit `EA-TRUST-STATE-CONFLICT`, wiederholbar. Ein `401` behauptete, mit dem
/// Schluessel des Aufrufers sei etwas nicht in Ordnung.
#[tokio::test(flavor = "multi_thread")]
async fn a_selected_head_behind_the_persisted_pin_is_refused() {
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

    // Ohne Pin traegt der Administrator seine Autoritaet.
    assert_eq!(
        read_registry(&server, fixture.organization_id, [0x28; 16])
            .await
            .status,
        200,
        "the baseline must authenticate, otherwise the case proves nothing"
    );

    // Ein Pin, der VOR dem gewaehlten Kopf liegt (die Linie steht auf 2),
    // aendert daran nichts.
    set_pin(database.pool(), fixture.organization_id, 1, [0x00; 32]).await;
    assert_eq!(
        read_registry(&server, fixture.organization_id, [0x29; 16])
            .await
            .status,
        200,
        "a pin below the selected head is no downgrade"
    );

    // Ein Pin JENSEITS jedes bekannten Kopfes ist der Rueckfall.
    set_pin(database.pool(), fixture.organization_id, 9_999, [0xd0; 32]).await;
    let response = read_registry(&server, fixture.organization_id, [0x2a; 16]).await;
    assert_eq!(
        response.status, 503,
        "a downgrade is a state finding and stays retryable"
    );
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-TRUST-STATE-CONFLICT")
    );

    database.cleanup().await;
}

/// Auch der Bootstrap-Zweig liegt UNTER einem bereits gespeicherten Kopf.
/// Der lesende Aufruf darf weder auf Ankerautoritaet zurueckfallen noch den
/// persistenten Stand umschreiben.
#[tokio::test(flavor = "multi_thread")]
async fn a_headless_catalog_behind_the_persisted_pin_is_refused() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(
        database.pool(),
        ROTATION_CASE,
        &["head-event.bin", WITHHELD_HEAD],
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
    assert_eq!(
        read_registry(&server, fixture.organization_id, [0x60; 16])
            .await
            .status,
        200,
        "the unpinned bootstrap authority must authenticate"
    );

    set_pin(database.pool(), fixture.organization_id, 1, [0xd1; 32]).await;
    let response = read_registry(&server, fixture.organization_id, [0x61; 16]).await;
    assert_eq!(response.status, 503);
    let error = ProtocolErrorV1::decode(&response.body).expect("the conflict body decodes");
    assert_eq!(error.error_code(), "EA-TRUST-STATE-CONFLICT");
    assert!(error.retryable());
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM trust_state")
        .fetch_one(database.pool())
        .await
        .expect("the fixture pin remains readable");
    assert_eq!(revision, 1, "authentication must not rewrite its pin floor");
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_same_version_pin_with_a_different_head_hash_is_refused_after_warming() {
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
    assert_eq!(
        read_registry(&server, fixture.organization_id, [0x62; 16])
            .await
            .status,
        200
    );
    set_pin(database.pool(), fixture.organization_id, 2, [0xd2; 32]).await;
    let response = read_registry(&server, fixture.organization_id, [0x63; 16]).await;
    assert_eq!(response.status, 503);
    let error = ProtocolErrorV1::decode(&response.body).expect("the conflict body decodes");
    assert_eq!(error.error_code(), "EA-TRUST-STATE-CONFLICT");
    assert!(error.retryable());
    database.cleanup().await;
}

/// Ein signierter Registry-Lesezugriff mit GENAU dieser Request-ID.
///
/// Eine eigene Funktion und nicht [`device_is_authorized`]: jene fuehrt eine
/// feste Request-ID, und ein zweiter Aufruf waere ein Einmalwertverbrauch und
/// damit ein `401`, das nichts ueber den Pin sagt.
async fn read_registry(
    server: &common::TestServer,
    organization_id: OrganizationId,
    request_id: [u8; 16],
) -> common::HttpResponse {
    let nonce = fresh_challenge(server, organization_id).await;
    let target = format!(
        "{}?afterVersion=0",
        EndpointV1::TrustRegistry.path_template()
    );
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(ADMIN_SEED),
        endpoint: EndpointV1::TrustRegistry,
        authority: &server.authority,
        target: &target,
        body: None,
        organization_id,
        request_id,
        nonce,
        created: 0,
    });
    common::https_request(
        server.address,
        &server.authority,
        "GET",
        &target,
        &headers,
        &[],
    )
    .await
}

/// Setzt den persistenten Pin des SERVERS von Hand.
///
/// Von Hand, weil der einzige schreibende Weg ihn nur VORWAERTS ruecken kann:
/// den Rueckfall, den dieser Fall braucht, kann der Server selbst gar nicht
/// erzeugen — genau darum muss er ihn erkennen.
async fn set_pin(
    pool: &PgPool,
    organization_id: OrganizationId,
    version: i64,
    head_hash: [u8; 32],
) {
    sqlx::query(
        "INSERT INTO trust_state (organization_id, device_id, revision, \
         trusted_floor_millis, pinned_registry_version, pinned_registry_head_hash) \
         VALUES ($1, $2, 1, 0, $3, $4) \
         ON CONFLICT (organization_id, device_id) DO UPDATE SET \
         pinned_registry_version = EXCLUDED.pinned_registry_version, \
         pinned_registry_head_hash = EXCLUDED.pinned_registry_head_hash",
    )
    .bind(&organization_id.as_bytes()[..])
    .bind(&einsatzarchiv_server::adapters::trust_authority::SERVER_TRUST_DEVICE_ID_V1[..])
    .bind(version)
    .bind(&head_hash[..])
    .execute(pool)
    .await
    .expect("writing the fixture pin must succeed");
}

// ---------------------------------------------------------------------------
// Reader-Key-Escrow (v1.1-Profil §3.1, §11; DRK-459)
// ---------------------------------------------------------------------------

use common::trust_closure;

/// Freigabefenster um die feste Serveruhr (höchstens 300 000 ms).
const ESCROW_APPROVAL_WINDOW: (i64, i64) = (
    common::READ_SERVER_NOW_MILLIS - 100,
    common::READ_SERVER_NOW_MILLIS + 200,
);
/// Die wurzelsignierte Zeit des Escrows, innerhalb des Freigabefensters.
const ESCROW_ISSUED_AT: i64 = common::READ_SERVER_NOW_MILLIS;
const ESCROW_RECOVERY_WINDOW: (i64, i64) = (
    common::READ_SERVER_NOW_MILLIS - 100,
    common::READ_SERVER_NOW_MILLIS + 800,
);
const FOREIGN_ORGANIZATION: [u8; 16] = [0x6f; 16];

/// Ein Server mit dem Abschluss, der den zweiten Reader und die Approver trägt.
async fn escrow_server(database: &common::TestDatabase) -> common::ReadyServer {
    common::stand_up_read_server_with_closure(
        database,
        common::READ_SERVER_NOW_MILLIS,
        trust_closure::build_with(true, true),
        None,
    )
    .await
}

/// Genau ein `.etb` über `POST /v1/trust/events`, signiert vom Administrator.
async fn post_escrow_object(
    ready: &common::ReadyServer,
    bytes: &[u8],
    marker: u8,
) -> common::HttpResponse {
    let upload = TrustEventUploadV1::new(bytes.to_vec()).expect("the upload frame must build");
    let mut request_id = [0xe5_u8; 16];
    request_id[15] = marker;
    common::call(&common::ApiCall {
        ready,
        signer_seed: ADMIN_SEED,
        endpoint: EndpointV1::TrustEvents,
        target: EndpointV1::TrustEvents.path_template(),
        body: Some(upload.exact_bytes()),
        request_id,
    })
    .await
}

/// Ob der Object Store Bytes unter diesem Hash hält.
async fn stored(hash: ea_types::ObjectHash) -> bool {
    common::object_store_client()
        .await
        .head_object()
        .bucket(common::INTEGRATION_BUCKET)
        .key(ea_sync_server::object_key(
            ea_format::ObjectTypeV1::Trust,
            hash,
        ))
        .send()
        .await
        .is_ok()
}

/// Pflichtzeuge (Profil §3.1 letzter Absatz, §11): ein Objekt jeder
/// Escrow-Familie mit FREMDER `organizationId` wird mit 403 abgewiesen, bevor
/// die geteilte Prüfung überhaupt läuft — keine Zeile, keine Bytes.
#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_organization_escrow_family_is_refused_before_validation() {
    let database = common::fresh_database().await;
    let ready = escrow_server(&database).await;
    let foreign = OrganizationId::try_from(&FOREIGN_ORGANIZATION[..]).expect("16 bytes");

    let mut core = trust_closure::escrow_core(
        &ready.closure,
        trust_closure::ESCROW_READER_SUBJECT,
        ESCROW_ISSUED_AT,
    );
    core.organization_id = foreign;
    let mut approval =
        trust_closure::escrow_approval_core(&ready.closure, 0x91, ESCROW_APPROVAL_WINDOW);
    approval.organization_id = foreign;
    let (approval_bytes, escrow_bytes) = trust_closure::escrow_objects(&core, &approval);
    let recovery_bytes = trust_closure::escrow_recovery_authorization(
        &ready.closure,
        &escrow_bytes,
        &core,
        0x92,
        ESCROW_RECOVERY_WINDOW,
        &[0, 1],
    );

    let indexed_before = indexed_trust_objects(database.pool()).await;
    for (marker, (name, bytes)) in [
        ("readerKeyEscrowApproval", approval_bytes),
        ("readerKeyEscrow", escrow_bytes),
        ("readerKeyEscrowRecoveryAuthorization", recovery_bytes),
    ]
    .into_iter()
    .enumerate()
    {
        let response =
            post_escrow_object(&ready, &bytes, u8::try_from(marker).expect("three cases")).await;
        assert_eq!(
            (response.status, error_code(&response.body).as_deref()),
            (403, Some("EA-TRUST-EVENT-ORGANIZATION")),
            "{name} of a foreign organization must be refused before validation"
        );
        assert!(
            !stored(ea_crypto::object_hash(&bytes)).await,
            "{name}: a refused object never reaches the object store"
        );
    }
    assert_eq!(
        indexed_trust_objects(database.pool()).await,
        indexed_before,
        "no row for a foreign-organization escrow object"
    );

    database.cleanup().await;
}

/// Eine v1.1-fähige Freigabe des Web-Bundles, direkt im Katalog: bis Scheibe
/// (f) gibt es keinen Annahmeweg für `webBundleRelease`.
async fn seed_capable_release(ready: &common::ReadyServer, database: &common::TestDatabase) {
    let release = trust_closure::web_bundle_release(
        &ready.closure,
        ea_trust::MIN_ESCROW_BUNDLE_VERSION,
        1,
        0xb1,
    );
    common::seed_indexed_trust_object(database.pool(), ready.closure.organization_id, &release)
        .await;
}

/// Ob `trust_events` eine Zeile für diese Bytes trägt.
async fn indexed(pool: &PgPool, bytes: &[u8]) -> bool {
    sqlx::query("SELECT count(*) AS n FROM trust_events WHERE object_hash = $1")
        .bind(&ea_crypto::object_hash(bytes).as_bytes()[..])
        .fetch_one(pool)
        .await
        .expect("counting a trust event must succeed")
        .get::<i64, _>("n")
        == 1
}

fn status_and_code(response: &common::HttpResponse) -> (u16, Option<String>) {
    (response.status, error_code(&response.body))
}

/// Der positive Weg (Profil §11 „Live-Server-Admission“): hinter einer
/// aktiven v1.1-fähigen Freigabe nimmt der Server erst die Publikationsfreigabe,
/// dann das Escrow, dann eine Öffnung mit zwei Approvern an — jedes über
/// seinen eigenen Einstieg des Trust-Kerns.
#[tokio::test(flavor = "multi_thread")]
async fn an_escrow_family_is_admitted_through_its_own_entry() {
    let database = common::fresh_database().await;
    let ready = escrow_server(&database).await;
    seed_capable_release(&ready, &database).await;

    let core = trust_closure::escrow_core(
        &ready.closure,
        trust_closure::ESCROW_READER_SUBJECT,
        ESCROW_ISSUED_AT,
    );
    let approval =
        trust_closure::escrow_approval_core(&ready.closure, 0xa1, ESCROW_APPROVAL_WINDOW);
    let (approval_bytes, escrow_bytes) = trust_closure::escrow_objects(&core, &approval);
    let recovery_bytes = trust_closure::escrow_recovery_authorization(
        &ready.closure,
        &escrow_bytes,
        &core,
        0xa2,
        ESCROW_RECOVERY_WINDOW,
        &[0, 1],
    );

    for (marker, (name, bytes)) in [
        ("readerKeyEscrowApproval", &approval_bytes),
        ("readerKeyEscrow", &escrow_bytes),
        ("readerKeyEscrowRecoveryAuthorization", &recovery_bytes),
    ]
    .into_iter()
    .enumerate()
    {
        let response =
            post_escrow_object(&ready, bytes, u8::try_from(marker).expect("three cases")).await;
        assert_eq!(status_and_code(&response), (201, None), "{name}");
        assert!(indexed(database.pool(), bytes).await, "{name} is indexed");
        assert!(
            stored(ea_crypto::object_hash(bytes)).await,
            "{name} is stored"
        );
    }

    // Eine byte-gleiche Wiederholung ist idempotent.
    let replay = post_escrow_object(&ready, &escrow_bytes, 0x10).await;
    assert_eq!(status_and_code(&replay), (201, None), "exact replay");

    database.cleanup().await;
}

/// Die Cutover-Vorbedingung (Profil §5, §11 „Publikation ohne aktive
/// v1.1-webBundleRelease“): ohne Freigabe, mit einer nicht v1.1-fähigen und
/// für ein Escrow, dessen Freigabe am Annahmeweg vorbei im Katalog liegt,
/// bleibt die Annahme zu — 422 NOT-VALID-NOW, keine Zeile.
#[tokio::test(flavor = "multi_thread")]
async fn the_escrow_gate_stays_shut_without_a_capable_release() {
    let database = common::fresh_database().await;
    let ready = escrow_server(&database).await;
    let core = trust_closure::escrow_core(
        &ready.closure,
        trust_closure::ESCROW_READER_SUBJECT,
        ESCROW_ISSUED_AT,
    );
    let approval =
        trust_closure::escrow_approval_core(&ready.closure, 0xa3, ESCROW_APPROVAL_WINDOW);
    let (approval_bytes, escrow_bytes) = trust_closure::escrow_objects(&core, &approval);

    // 1. Gar keine Freigabe.
    let response = post_escrow_object(&ready, &approval_bytes, 0).await;
    assert_eq!(
        status_and_code(&response),
        (422, Some("EA-TRUST-EVENT-NOT-VALID-NOW".to_owned())),
        "no release"
    );
    assert!(!indexed(database.pool(), &approval_bytes).await);

    // 2. Eine aktive Freigabe der eingefrorenen, nicht v1.1-fähigen Fassung.
    let old = trust_closure::web_bundle_release(&ready.closure, "2026.3.1", 1, 0xb2);
    common::seed_indexed_trust_object(database.pool(), ready.closure.organization_id, &old).await;
    let response = post_escrow_object(&ready, &approval_bytes, 1).await;
    assert_eq!(
        status_and_code(&response),
        (422, Some("EA-TRUST-EVENT-NOT-VALID-NOW".to_owned())),
        "an old bundle version"
    );
    assert!(!indexed(database.pool(), &approval_bytes).await);

    // 3. Das Escrow selbst ist ebenfalls gesperrt, auch wenn seine Freigabe
    //    (am Annahmeweg vorbei) im Katalog liegt.
    common::seed_indexed_trust_object(
        database.pool(),
        ready.closure.organization_id,
        &approval_bytes,
    )
    .await;
    let response = post_escrow_object(&ready, &escrow_bytes, 2).await;
    assert_eq!(
        status_and_code(&response),
        (422, Some("EA-TRUST-EVENT-NOT-VALID-NOW".to_owned())),
        "the escrow behind an old bundle version"
    );
    assert!(!indexed(database.pool(), &escrow_bytes).await);
    assert!(!stored(ea_crypto::object_hash(&escrow_bytes)).await);

    database.cleanup().await;
}

/// Review b, P3-2: die Freigabe wird einzeln und VOR ihrem Escrow angenommen,
/// nie im selben Zug. Ein Escrow ohne angenommene Freigabe ist ungültig.
#[tokio::test(flavor = "multi_thread")]
async fn an_escrow_before_its_approval_is_refused() {
    let database = common::fresh_database().await;
    let ready = escrow_server(&database).await;
    seed_capable_release(&ready, &database).await;
    let core = trust_closure::escrow_core(
        &ready.closure,
        trust_closure::ESCROW_READER_SUBJECT,
        ESCROW_ISSUED_AT,
    );
    let approval =
        trust_closure::escrow_approval_core(&ready.closure, 0xa4, ESCROW_APPROVAL_WINDOW);
    let (approval_bytes, escrow_bytes) = trust_closure::escrow_objects(&core, &approval);

    let early = post_escrow_object(&ready, &escrow_bytes, 0).await;
    assert_eq!(
        status_and_code(&early),
        (422, Some("EA-TRUST-EVENT-INVALID".to_owned())),
        "an escrow before its approval"
    );
    assert!(!indexed(database.pool(), &escrow_bytes).await);
    assert!(!stored(ea_crypto::object_hash(&escrow_bytes)).await);

    let approval_response = post_escrow_object(&ready, &approval_bytes, 1).await;
    assert_eq!(status_and_code(&approval_response), (201, None));
    let late = post_escrow_object(&ready, &escrow_bytes, 2).await;
    assert_eq!(status_and_code(&late), (201, None), "after its approval");

    database.cleanup().await;
}

/// Profil §11: abweichende Enrollment-Version, Freigabe genau auf dem
/// Randwert `expiresAt` und einen Tick danach, Öffnung mit nur einem Approver.
#[tokio::test(flavor = "multi_thread")]
async fn the_escrow_family_negatives_leave_no_row() {
    let database = common::fresh_database().await;
    let ready = escrow_server(&database).await;
    seed_capable_release(&ready, &database).await;
    let now = common::READ_SERVER_NOW_MILLIS;

    // Genau auf dem Randwert: abgelaufen ist erst `now > expiresAt`.
    let on_edge = trust_closure::escrow_approval_core(&ready.closure, 0xa5, (now - 300, now));
    let edge_core = trust_closure::escrow_core(&ready.closure, [0x5c; 16], now - 1);
    let (edge_approval, _) = trust_closure::escrow_objects(&edge_core, &on_edge);
    let response = post_escrow_object(&ready, &edge_approval, 0).await;
    assert_eq!(status_and_code(&response), (201, None), "expiresAt == now");

    // Einen Tick später.
    let past = trust_closure::escrow_approval_core(&ready.closure, 0xa6, (now - 301, now - 1));
    let past_core = trust_closure::escrow_core(&ready.closure, [0x5d; 16], now - 2);
    let (past_approval, _) = trust_closure::escrow_objects(&past_core, &past);
    let response = post_escrow_object(&ready, &past_approval, 1).await;
    assert_eq!(
        status_and_code(&response),
        (422, Some("EA-TRUST-EVENT-NOT-VALID-NOW".to_owned())),
        "expiresAt + 1 == now"
    );
    assert!(!indexed(database.pool(), &past_approval).await);

    // Abweichende Enrollment-Version: die Freigabe bindet genau diesen Core
    // und wird angenommen, das Escrow nicht.
    let mut drifted = trust_closure::escrow_core(
        &ready.closure,
        trust_closure::ESCROW_READER_SUBJECT,
        ESCROW_ISSUED_AT,
    );
    drifted.enrollment_registry_version =
        RegistryVersion::new(drifted.enrollment_registry_version.get() - 1);
    let approval =
        trust_closure::escrow_approval_core(&ready.closure, 0xa7, ESCROW_APPROVAL_WINDOW);
    let (drift_approval, drift_escrow) = trust_closure::escrow_objects(&drifted, &approval);
    let response = post_escrow_object(&ready, &drift_approval, 2).await;
    assert_eq!(status_and_code(&response), (201, None), "its approval");
    let response = post_escrow_object(&ready, &drift_escrow, 3).await;
    assert_eq!(
        status_and_code(&response),
        (422, Some("EA-TRUST-EVENT-INVALID".to_owned())),
        "a deviating enrollment version"
    );
    assert!(!indexed(database.pool(), &drift_escrow).await);

    // Eine Öffnung mit einem einzigen Approver über ein gültiges Escrow.
    let core = trust_closure::escrow_core(&ready.closure, [0x5e; 16], ESCROW_ISSUED_AT);
    let approval =
        trust_closure::escrow_approval_core(&ready.closure, 0xa8, ESCROW_APPROVAL_WINDOW);
    let (approval_bytes, escrow_bytes) = trust_closure::escrow_objects(&core, &approval);
    for (marker, bytes) in [(4, &approval_bytes), (5, &escrow_bytes)] {
        let response = post_escrow_object(&ready, bytes, marker).await;
        assert_eq!(
            status_and_code(&response),
            (201, None),
            "the escrow to open"
        );
    }
    let lonely = trust_closure::escrow_recovery_authorization(
        &ready.closure,
        &escrow_bytes,
        &core,
        0xa9,
        ESCROW_RECOVERY_WINDOW,
        // Das Format verlangt schon zwei Signaturen; ein Approver, der
        // zweimal zeichnet, bleibt eine Person.
        &[0, 0],
    );
    let response = post_escrow_object(&ready, &lonely, 6).await;
    assert_eq!(
        status_and_code(&response),
        (422, Some("EA-TRUST-EVENT-INVALID".to_owned())),
        "a recovery authorization signed twice by one approver"
    );
    assert!(!indexed(database.pool(), &lonely).await);

    database.cleanup().await;
}

/// Die echten Adapter hinter dem Endpunkt: Prüfung und Index.
async fn escrow_adapters(
    database: &common::TestDatabase,
    organization_id: OrganizationId,
) -> (
    einsatzarchiv_server::adapters::trust_authority::PostgresTrustAuthority,
    einsatzarchiv_server::adapters::postgres::PostgresRepository,
) {
    use std::sync::Arc;

    use einsatzarchiv_server::adapters::{
        clock::FixedClock, postgres::PostgresRepository, s3::S3ObjectStore,
        trust_authority::PostgresTrustAuthority,
    };
    let repository = Arc::new(PostgresRepository::new(database.pool().clone()));
    let client = common::object_store_client().await;
    let objects: Arc<dyn ea_sync_server::ObjectStore> = Arc::new(S3ObjectStore::new(
        client,
        common::INTEGRATION_BUCKET.to_owned(),
        organization_id,
        repository.clone(),
        repository,
        Arc::new(FixedClock(UnixMillis::new(common::READ_SERVER_NOW_MILLIS))),
    ));
    (
        PostgresTrustAuthority::new(database.pool().clone(), objects),
        PostgresRepository::new(database.pool().clone()),
    )
}

/// Ein Escrow zum selben Reader-Zertifikat mit eigener, bereits
/// angenommener Freigabe: `(freigabe, escrow)`.
fn rival_escrow(
    closure: &trust_closure::ExtendedClosure,
    id: u8,
    subject: [u8; 16],
) -> (Vec<u8>, Vec<u8>) {
    let core = trust_closure::escrow_core(closure, subject, ESCROW_ISSUED_AT);
    let approval = trust_closure::escrow_approval_core(closure, id, ESCROW_APPROVAL_WINDOW);
    trust_closure::escrow_objects(&core, &approval)
}

/// Der Katalogzaun (F7): zwei Escrows zum selben Reader-Zertifikat, beide
/// gegen DENSELBEN Katalogstand geprüft und einzeln gültig. Das erste wird
/// indiziert; das zweite darf danach nicht mehr auf dem alten Stand hinein,
/// sonst stünden zwei gültige Escrows im Katalog und jede weitere
/// Escrow-Annahme der Organisation scheiterte an `EscrowConflict`.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_escrow_checked_against_a_moved_catalog_is_not_indexed() {
    use ea_sync_server::{
        TrustEventCommandV1, TrustEventStore, TrustIndexOutcome, trust::TrustEventValidator,
    };

    let database = common::fresh_database().await;
    let ready = escrow_server(&database).await;
    seed_capable_release(&ready, &database).await;
    let organization_id = ready.closure.organization_id;
    let (approval_a, escrow_a) =
        rival_escrow(&ready.closure, 0xc1, trust_closure::ESCROW_READER_SUBJECT);
    let (approval_b, escrow_b) =
        rival_escrow(&ready.closure, 0xc2, trust_closure::ESCROW_READER_SUBJECT);
    for (marker, approval) in [(0, &approval_a), (1, &approval_b)] {
        let response = post_escrow_object(&ready, approval, marker).await;
        assert_eq!(status_and_code(&response), (201, None), "approval {marker}");
    }

    let (validator, index) = escrow_adapters(&database, organization_id).await;
    let now = UnixMillis::new(common::READ_SERVER_NOW_MILLIS);
    let validate = |bytes: Vec<u8>| {
        let validator = &validator;
        async move {
            validator
                .validate_exact_etb(organization_id, ea_crypto::object_hash(&bytes), &bytes, now)
                .await
                .expect("each escrow is valid on its own")
                .catalog_fence
                .expect("an escrow verdict is fenced on the catalog")
        }
    };
    let fence_a = validate(escrow_a.clone()).await;
    let fence_b = validate(escrow_b.clone()).await;
    assert_eq!(
        fence_a, fence_b,
        "both were checked against the same catalog"
    );

    let command = |bytes: &[u8], fence| TrustEventCommandV1 {
        organization_id,
        object_hash: ea_crypto::object_hash(bytes),
        size_bytes: u64::try_from(bytes.len()).expect("small"),
        subtype_code: "readerKeyEscrow".to_owned(),
        registry_version: None,
        effective_from: now,
        received_at: now,
        catalog_fence: Some(fence),
        reader_key_escrow: None,
    };
    common::seed_trust_object_bytes(&escrow_a).await;
    common::seed_trust_object_bytes(&escrow_b).await;
    assert_eq!(
        index
            .index_event(command(&escrow_a, fence_a))
            .await
            .expect("index"),
        TrustIndexOutcome::Indexed
    );
    assert_eq!(
        index
            .index_event(command(&escrow_b, fence_b))
            .await
            .expect("index"),
        TrustIndexOutcome::CatalogMoved,
        "the second verdict was reached against a catalog that no longer exists"
    );
    assert!(!indexed(database.pool(), &escrow_b).await);
    // Eine byte-gleiche Wiederholung bleibt idempotent, auch mit altem Zaun.
    assert_eq!(
        index
            .index_event(command(&escrow_a, fence_a))
            .await
            .expect("index"),
        TrustIndexOutcome::AlreadyIndexed
    );

    // Über den Endpunkt prüft die Wiederholung gegen die neue Menge und
    // endet mit dem eigentlichen Befund: zwei Escrows zu einem Zertifikat.
    let retry = post_escrow_object(&ready, &escrow_b, 2).await;
    assert_eq!(
        status_and_code(&retry),
        (409, Some("EA-TRUST-EVENT-CONFLICT".to_owned())),
        "the retry meets the admitted escrow"
    );
    assert!(!indexed(database.pool(), &escrow_b).await);

    database.cleanup().await;
}

/// Der Rückfallindex (F7): hat der Zaun einmal nicht gegriffen, hält die
/// Datenbank trotzdem höchstens ein Escrow je Reader-Zertifikat — als 409 und
/// nicht als wiederholbarer 503. Eine zweite Person-Zeile mit NEUEM Zertifikat
/// (der U2-Ersatz) bleibt möglich: die Personenkennung ist nicht eindeutig.
#[tokio::test(flavor = "multi_thread")]
async fn the_escrow_index_keeps_one_escrow_per_reader_certificate() {
    use ea_sync_server::{
        ReaderKeyEscrowIndexV1, TrustCatalogFenceV1, TrustEventCommandV1, TrustEventStore,
        TrustIndexOutcome,
    };

    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), ROTATION_CASE, &[]).await;
    let organization_id = fixture.organization_id;
    let index =
        einsatzarchiv_server::adapters::postgres::PostgresRepository::new(database.pool().clone());
    let now = UnixMillis::new(common::READ_SERVER_NOW_MILLIS);
    let pool = database.pool().clone();
    let fresh_fence = || {
        let pool = pool.clone();
        async move {
            TrustCatalogFenceV1 {
                catalog_revision: sqlx::query_scalar(
                    "SELECT trust_catalog_revision FROM organizations WHERE organization_id = $1",
                )
                .bind(&organization_id.as_bytes()[..])
                .fetch_one(&pool)
                .await
                .expect("the organization has a catalog revision"),
            }
        }
    };
    let command = |object: u8, certificate: u8, subject: u8, fence| TrustEventCommandV1 {
        organization_id,
        object_hash: ea_types::ObjectHash::try_from(&[object; 32][..]).expect("32 bytes"),
        size_bytes: 1,
        subtype_code: "readerKeyEscrow".to_owned(),
        registry_version: None,
        effective_from: now,
        received_at: now,
        catalog_fence: Some(fence),
        reader_key_escrow: Some(ReaderKeyEscrowIndexV1 {
            reader_certificate_object_hash: CertificateHash::try_from(&[certificate; 32][..])
                .expect("32 bytes"),
            reader_subject_id: ea_types::SubjectId::try_from(&[subject; 16][..]).expect("16 bytes"),
        }),
    };

    let first = index
        .index_event(command(0xd1, 0xc1, 0x51, fresh_fence().await))
        .await
        .expect("index");
    assert_eq!(first, TrustIndexOutcome::Indexed);
    let second = index
        .index_event(command(0xd2, 0xc1, 0x52, fresh_fence().await))
        .await;
    assert!(
        matches!(second, Ok(TrustIndexOutcome::Conflict)),
        "a second escrow of one certificate is a conflict, not an outage: {second:?}"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM trust_events WHERE object_hash = $1")
        .bind(&[0xd2_u8; 32][..])
        .fetch_one(database.pool())
        .await
        .expect("count");
    assert_eq!(rows, 0, "the conflicting escrow leaves no row behind");

    let replacement = index
        .index_event(command(0xd3, 0xc2, 0x51, fresh_fence().await))
        .await
        .expect("index");
    assert_eq!(
        replacement,
        TrustIndexOutcome::Indexed,
        "a new certificate of the same person is not blocked by the index"
    );
    let escrows: i64 = sqlx::query_scalar("SELECT count(*) FROM reader_key_escrows")
        .fetch_one(database.pool())
        .await
        .expect("count");
    assert_eq!(escrows, 2);

    // Eine Katalogreparatur leert `trust_events`; der Index bleibt
    // append-only. Dieselben Bytes kommen danach wieder hinein, ein anderes
    // Escrow zum selben Zertifikat weiterhin nicht.
    sqlx::query("TRUNCATE trust_events")
        .execute(database.pool())
        .await
        .expect("a catalog repair may truncate the trust events");
    let again = index
        .index_event(command(0xd1, 0xc1, 0x51, fresh_fence().await))
        .await
        .expect("index");
    assert_eq!(
        again,
        TrustIndexOutcome::Indexed,
        "the same escrow re-enters after a catalog repair"
    );
    let rival = index
        .index_event(command(0xd4, 0xc1, 0x51, fresh_fence().await))
        .await
        .expect("index");
    assert_eq!(rival, TrustIndexOutcome::Conflict);

    database.cleanup().await;
}
