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
