//! `PUT /v1/vault-blobs` und `POST /v1/vault-blobs/retrievals` gegen echte
//! Dienste (`web-reader-design.md` §6.4/§6.4.1).
//!
//! Vier Aussagen, und alle vier sind Sicherheitsaussagen:
//!
//! 1. Ohne gueltige, noch nicht verbrauchte WebAuthn-Assertion verlaesst KEIN
//!    Chiffrat den Server (:218-224).
//! 2. Der Endpunkt bietet KEINE Enumerationsflaeche: ein nie eingetragener
//!    Leser und ein Leser, dessen Assertion nicht traegt, bekommen denselben
//!    Status, denselben Code und — bis auf die global eindeutige
//!    `request-id` — dieselben Bytes (:228).
//! 3. Ein nicht steigender Signaturzaehler ist ein Replay und wird abgewiesen.
//! 4. Ein nicht gelisteter Origin bekommt UEBERHAUPT keinen
//!    `Access-Control-Allow-Origin` (§4.1, :70-75).
//!
//! Der Ablageweg ist regulaer RFC-9421-signiert: der Leser besitzt seinen
//! Ed25519-Schluessel im Moment des Enrollments. Nur der ABRUF laeuft aus
//! einem frischen Browser, dessen Vault — und damit der Signaturschluessel —
//! noch verschlossen ist (:213-216).

mod common;

use ea_sync_protocol::{
    ChallengeRequestV1, ChallengeResponseV1, EndpointAuthentication, EndpointV1,
    MAX_VAULT_BLOBS_PER_SUBJECT_V1, ProtocolErrorV1, RequestIdV1, RequestSigner,
    STRUCTURED_MEDIA_TYPE_V1, VaultBlobRetrievalRequestV1, VaultBlobRetrievalResponseV1,
    VaultBlobUploadV1, WebauthnCredentialRegistrationV1,
};
use ea_types::{CertificateHash, OrganizationId, SubjectId, UnixMillis};
use sha2::{Digest as _, Sha256};

/// Innerhalb des `notBefore`/`notAfter`-Fensters der eingefrorenen
/// Registry-Koepfe. Die Wanduhr des Rechners liegt Jahrzehnte daneben.
const SERVER_NOW_MILLIS: i64 = 1_000;
const SERVER_SECRET: [u8; 32] = [0x51; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];
const TRUST_CASE: &str = "registry/accepted-bootstrap-and-first-head";

/// Der Seed des ersten Organisationsadministrators der eingefrorenen Vektoren.
/// Sein Zertifikat ist unter dem ersten Registry-Head aktiv, und
/// `PUT /v1/vault-blobs` verlangt keine Capability, sondern ein freigegebenes
/// Geraet der Organisation.
const ADMIN_SEED: [u8; 32] = ea_testkit::TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED;

const READER_SUBJECT: [u8; 16] = [0x71; 16];
const OTHER_SUBJECT: [u8; 16] = [0x72; 16];
const NEVER_ENROLLED_SUBJECT: [u8; 16] = [0x73; 16];

/// Die Seeds der beiden Authenticators. Sie sind KEIN Geraeteschluessel: der
/// Authenticator signiert die Assertion, der Ed25519-Schluessel des Lesers
/// signiert die Requests. Beide Verwendungen bleiben getrennt (:226-228).
const READER_AUTHENTICATOR_SEED: [u8; 32] = [0x91; 32];
const OTHER_AUTHENTICATOR_SEED: [u8; 32] = [0x92; 32];
const NEVER_ENROLLED_AUTHENTICATOR_SEED: [u8; 32] = [0x93; 32];

const READER_CREDENTIAL_ID: [u8; 32] = [0x81; 32];
const OTHER_CREDENTIAL_ID: [u8; 32] = [0x82; 32];
const NEVER_ENROLLED_CREDENTIAL_ID: [u8; 32] = [0x83; 32];

/// Ein opakes Chiffrat. Der Server kennt weder Vault-Key noch PRF-Ausgabe, und
/// dieser Test auch nicht: die Bytes sind Fuellung und stehen fuer nichts.
const WRAPPED_BLOB: [u8; 96] = [0xd1; 96];
const SECOND_WRAPPED_BLOB: [u8; 96] = [0xd2; 96];

fn subject(bytes: [u8; 16]) -> SubjectId {
    SubjectId::try_from(&bytes[..]).expect("a subject id is 16 bytes")
}

fn signer(seed: [u8; 32]) -> RequestSigner {
    RequestSigner::from_secret(ea_crypto::SecretBytes::new(seed))
}

/// Der kanonische oeffentliche COSE-Schluessel eines Authenticators.
///
/// Der Server nimmt GENAU die kanonische Form dieses Arbeitsbereichs an
/// (`ea_crypto::CanonicalPublicCoseKey`): OKP, Ed25519. Sie ist die einzige
/// Form, die der Bestand kennt, und die Suite ist durchgehend Ed25519.
fn credential_public_cose_key(seed: [u8; 32]) -> Vec<u8> {
    ea_crypto::CanonicalPublicCoseKey::ed25519(ea_testkit::ed25519_public_key(&seed))
        .expect("a declared test seed yields a usable Ed25519 key")
        .to_deterministic_cbor()
}

/// Base64url ohne Fuellzeichen — die Kodierung, in der WebAuthn die Challenge
/// in die `clientDataJSON` schreibt.
///
/// Von Hand und ABSICHTLICH nicht aus derselben Quelle wie der Server: ein
/// Zeuge, der den Erwartungswert mit demselben Helfer baut, den er prueft,
/// misst nichts.
fn base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut buffer = [0_u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let value =
            (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
        let digits = [
            (value >> 18) & 0x3f,
            (value >> 12) & 0x3f,
            (value >> 6) & 0x3f,
            value & 0x3f,
        ];
        for digit in digits.iter().take(chunk.len() + 1) {
            out.push(char::from(ALPHABET[*digit as usize]));
        }
    }
    out
}

/// Die `clientDataJSON`, wie ein Browser sie fuer `navigator.credentials.get`
/// serialisiert (WebAuthn Level 2, §5.8.1).
fn client_data_json(challenge: &[u8; 32], origin: &str) -> Vec<u8> {
    format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
        base64url_no_pad(challenge),
        origin
    )
    .into_bytes()
}

/// `authenticatorData`: `rpIdHash` ‖ `flags` ‖ `signCount`.
///
/// `flags` traegt `UP` und `UV` — der Authenticator hat den Menschen gesehen
/// und geprueft.
fn authenticator_data(relying_party_id: &str, signature_counter: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&Sha256::digest(relying_party_id.as_bytes()));
    data.push(0x05);
    data.extend_from_slice(&signature_counter.to_be_bytes());
    data
}

/// Der Bauplan einer Assertion.
struct Assertion {
    /// Der Authenticator, der signiert.
    authenticator_seed: [u8; 32],
    credential_id: [u8; 32],
    /// Der BEHAUPTETE `userHandle`. Er ist absichtlich von der Assertion
    /// getrennt: nur so laesst sich eine Assertion bauen, die eine fremde
    /// `subjectId` behauptet.
    claimed_subject: [u8; 16],
    challenge: [u8; 32],
    signature_counter: u32,
    /// Setzt die Signatur auf Nullbytes — „ohne Assertion" auf dem Draht.
    without_signature: bool,
}

impl Assertion {
    const fn of(authenticator_seed: [u8; 32], credential_id: [u8; 32], subject: [u8; 16]) -> Self {
        Self {
            authenticator_seed,
            credential_id,
            claimed_subject: subject,
            challenge: [0; 32],
            signature_counter: 1,
            without_signature: false,
        }
    }

    const fn with_challenge(mut self, challenge: [u8; 32]) -> Self {
        self.challenge = challenge;
        self
    }

    const fn claiming(mut self, subject: [u8; 16]) -> Self {
        self.claimed_subject = subject;
        self
    }

    const fn at_counter(mut self, signature_counter: u32) -> Self {
        self.signature_counter = signature_counter;
        self
    }

    const fn without_signature(mut self) -> Self {
        self.without_signature = true;
        self
    }

    fn into_request(self, organization_id: OrganizationId) -> VaultBlobRetrievalRequestV1 {
        let client_data = client_data_json(&self.challenge, common::TEST_BUNDLE_ORIGIN);
        let authenticator =
            authenticator_data(common::TEST_RELYING_PARTY_ID, self.signature_counter);
        let mut message = authenticator.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let signature = if self.without_signature {
            [0_u8; 64]
        } else {
            ea_testkit::ed25519_sign_raw(&self.authenticator_seed, &message)
        };
        VaultBlobRetrievalRequestV1::new(
            organization_id,
            subject(self.claimed_subject),
            self.credential_id.to_vec(),
            self.challenge,
            authenticator,
            client_data,
            signature,
        )
        .expect("the retrieval frame must build")
    }
}

/// Die aufgebaute Kulisse: Server, Organisation und ein eingetragenes
/// Credential je Leser.
struct Api {
    database: common::TestDatabase,
    server: common::TestServer,
    organization_id: OrganizationId,
    request_id: std::cell::Cell<u8>,
}

impl Api {
    async fn stand_up() -> Self {
        let database = common::fresh_database().await;
        let fixture = common::seed_trust_fixture(database.pool(), TRUST_CASE, &[]).await;
        let server = common::spawn_server(
            database.pool().clone(),
            UnixMillis::new(SERVER_NOW_MILLIS),
            fixture.organization_id,
            SERVER_SECRET,
            CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
        )
        .await;
        let api = Self {
            database,
            server,
            organization_id: fixture.organization_id,
            request_id: std::cell::Cell::new(0),
        };
        api.register_credential(
            READER_SUBJECT,
            READER_CREDENTIAL_ID,
            READER_AUTHENTICATOR_SEED,
        )
        .await;
        api.register_credential(OTHER_SUBJECT, OTHER_CREDENTIAL_ID, OTHER_AUTHENTICATOR_SEED)
            .await;
        api
    }

    /// Eine je Aufruf frische, nicht kollidierende Request-ID.
    fn next_request_id(&self) -> [u8; 16] {
        let next = self.request_id.get().wrapping_add(1);
        self.request_id.set(next);
        let mut id = [0x40_u8; 16];
        id[15] = next;
        id
    }

    async fn fresh_challenge(&self) -> [u8; 32] {
        let body = ChallengeRequestV1::new(self.organization_id);
        let response = common::https_request(
            self.server.address,
            &self.server.authority,
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

    /// Eine Challenge, die es GAB und die bereits verbraucht ist.
    async fn spent_challenge(&self) -> [u8; 32] {
        let nonce = self.fresh_challenge().await;
        // Verbraucht wird sie auf dem regulaeren Weg: ein signierter Request,
        // der sie mitfuehrt. Ein `UPDATE` daneben pruefte den Verbrauch nicht,
        // sondern behauptete ihn.
        let upload = VaultBlobUploadV1::new(subject(READER_SUBJECT), WRAPPED_BLOB.to_vec())
            .expect("the upload frame must build");
        let response = self.send_signed_upload(&upload, nonce).await;
        assert_eq!(
            response.status,
            201,
            "the fixture upload must succeed; the server answered {:?}",
            common::error_code(&response.body)
        );
        nonce
    }

    async fn register_credential(
        &self,
        subject_bytes: [u8; 16],
        credential_id: [u8; 32],
        authenticator_seed: [u8; 32],
    ) {
        let registration = WebauthnCredentialRegistrationV1::new(
            subject(subject_bytes),
            credential_id.to_vec(),
            credential_public_cose_key(authenticator_seed),
        )
        .expect("the registration frame must build");
        let nonce = self.fresh_challenge().await;
        let headers = common::signed_headers(&common::SignedCall {
            signer: &signer(ADMIN_SEED),
            endpoint: EndpointV1::WebauthnCredentials,
            authority: &self.server.authority,
            target: EndpointV1::WebauthnCredentials.path_template(),
            body: Some(registration.exact_bytes()),
            organization_id: self.organization_id,
            request_id: self.next_request_id(),
            nonce,
            created: 0,
        });
        let response = common::https_request(
            self.server.address,
            &self.server.authority,
            "POST",
            EndpointV1::WebauthnCredentials.path_template(),
            &headers,
            registration.exact_bytes(),
        )
        .await;
        assert_eq!(
            response.status,
            201,
            "the fixture credential must register; the server answered {:?}",
            common::error_code(&response.body)
        );
    }

    async fn send_signed_upload(
        &self,
        upload: &VaultBlobUploadV1,
        nonce: [u8; 32],
    ) -> common::HttpResponse {
        let headers = common::signed_headers(&common::SignedCall {
            signer: &signer(ADMIN_SEED),
            endpoint: EndpointV1::VaultBlobs,
            authority: &self.server.authority,
            target: EndpointV1::VaultBlobs.path_template(),
            body: Some(upload.exact_bytes()),
            organization_id: self.organization_id,
            request_id: self.next_request_id(),
            nonce,
            created: 0,
        });
        common::https_request(
            self.server.address,
            &self.server.authority,
            "PUT",
            EndpointV1::VaultBlobs.path_template(),
            &headers,
            upload.exact_bytes(),
        )
        .await
    }

    async fn put_blob(&self, subject_bytes: [u8; 16], ciphertext: &[u8]) -> common::HttpResponse {
        let upload = VaultBlobUploadV1::new(subject(subject_bytes), ciphertext.to_vec())
            .expect("the upload frame must build");
        let nonce = self.fresh_challenge().await;
        self.send_signed_upload(&upload, nonce).await
    }

    /// Der UNSIGNIERTE Abruf. Keine `signature-input`, keine `signature` —
    /// genau der Browser, dessen Vault noch verschlossen ist.
    async fn retrieve_blobs(&self, assertion: Assertion) -> common::HttpResponse {
        self.retrieve_blobs_from_origin(assertion, None).await
    }

    /// Derselbe Abruf, aber mit gesetztem `Origin` — so, wie ein Browser ihn
    /// absetzt.
    async fn retrieve_blobs_from_origin(
        &self,
        assertion: Assertion,
        origin: Option<&str>,
    ) -> common::HttpResponse {
        let request = assertion.into_request(self.organization_id);
        let request_id = self.next_request_id();
        let mut headers = vec![
            ("content-type", STRUCTURED_MEDIA_TYPE_V1.to_owned()),
            (
                ea_sync_protocol::REQUEST_ID_HEADER_V1,
                hex::encode(request_id),
            ),
        ];
        if let Some(origin) = origin {
            headers.push(("origin", origin.to_owned()));
        }
        common::https_request(
            self.server.address,
            &self.server.authority,
            "POST",
            EndpointV1::VaultBlobRetrievals.path_template(),
            &headers,
            request.exact_bytes(),
        )
        .await
    }

    /// Ein CORS-Vorabflug auf einen Pfad.
    async fn preflight(&self, origin: &str, target: &str) -> common::HttpResponse {
        common::https_request(
            self.server.address,
            &self.server.authority,
            "OPTIONS",
            target,
            &[
                ("origin", origin.to_owned()),
                ("access-control-request-method", "POST".to_owned()),
                ("access-control-request-headers", "content-type".to_owned()),
            ],
            &[],
        )
        .await
    }

    async fn cleanup(self) {
        self.database.cleanup().await;
    }
}

/// Der Fehlerkoerper mit AUSMASKIERTER `request-id`.
///
/// Zwei Antworten auf denselben Befund duerfen sich in genau dieser Position
/// unterscheiden — sie ist global eindeutig —, und in keiner anderen. Ohne die
/// Maske waere ein Bytevergleich zweier Fehlerkoerper nie erfuellbar und der
/// Zeuge damit wertlos.
fn masked_error_body(body: &[u8]) -> Vec<u8> {
    let error = ProtocolErrorV1::decode(body).expect("a refusal carries protocol-error-v1");
    let zero = RequestIdV1::try_from(&[0_u8; 16][..]).expect("16 bytes");
    ProtocolErrorV1::with_code(
        error.error_code(),
        zero,
        error.retryable(),
        error.required_registry_version(),
        error.required_registry_head_hash(),
    )
    .exact_bytes()
    .to_vec()
}

fn released_ciphertexts(body: &[u8]) -> Vec<Vec<u8>> {
    VaultBlobRetrievalResponseV1::decode(body)
        .expect("the retrieval response must decode")
        .ciphertexts()
        .to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn no_ciphertext_leaves_the_server_without_a_valid_assertion() {
    let api = Api::stand_up().await;

    let stored = api.put_blob(READER_SUBJECT, &WRAPPED_BLOB).await;
    assert_eq!(
        stored.status,
        201,
        "the signed upload must answer 201; the server answered {:?}",
        common::error_code(&stored.body)
    );

    // Ohne Assertion.
    let unsigned = api
        .retrieve_blobs(
            Assertion::of(
                READER_AUTHENTICATOR_SEED,
                READER_CREDENTIAL_ID,
                READER_SUBJECT,
            )
            .with_challenge(api.fresh_challenge().await)
            .without_signature(),
        )
        .await;
    assert_eq!(
        (
            common::error_code(&unsigned.body).as_deref(),
            unsigned.status
        ),
        (Some("EA-WEBAUTHN-ASSERTION-INVALID"), 401),
        "an assertion that does not verify releases nothing"
    );

    // Mit einer bereits verbrauchten Challenge: die Assertion selbst traegt,
    // die Bindung an eine offene Challenge fehlt. Ohne sie waere die Assertion
    // eine beliebig oft wiederholbare Capability.
    let spent = api.spent_challenge().await;
    let replayed = api
        .retrieve_blobs(
            Assertion::of(
                READER_AUTHENTICATOR_SEED,
                READER_CREDENTIAL_ID,
                READER_SUBJECT,
            )
            .with_challenge(spent),
        )
        .await;
    assert_eq!(
        (
            common::error_code(&replayed.body).as_deref(),
            replayed.status
        ),
        (Some("EA-WEBAUTHN-ASSERTION-INVALID"), 401),
        "a spent challenge releases nothing"
    );

    // Und mit einer frischen.
    let released = api
        .retrieve_blobs(
            Assertion::of(
                READER_AUTHENTICATOR_SEED,
                READER_CREDENTIAL_ID,
                READER_SUBJECT,
            )
            .with_challenge(api.fresh_challenge().await),
        )
        .await;
    assert_eq!(
        released.status,
        200,
        "a valid, unspent assertion releases the ciphertexts; the server answered {:?}",
        common::error_code(&released.body)
    );
    assert_eq!(
        released_ciphertexts(&released.body),
        vec![WRAPPED_BLOB.to_vec()],
        "exactly the ciphertexts bound to this subjectId, and nothing else"
    );

    api.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_retrieval_endpoint_offers_no_enumeration_surface() {
    let api = Api::stand_up().await;
    api.put_blob(READER_SUBJECT, &WRAPPED_BLOB).await;

    // Ein nie eingetragener Leser mit einer in sich gueltigen Assertion.
    let unknown = api
        .retrieve_blobs(
            Assertion::of(
                NEVER_ENROLLED_AUTHENTICATOR_SEED,
                NEVER_ENROLLED_CREDENTIAL_ID,
                NEVER_ENROLLED_SUBJECT,
            )
            .with_challenge(api.fresh_challenge().await),
        )
        .await;

    // Ein EINGETRAGENER Leser, dessen Assertion eine fremde `subjectId`
    // behauptet.
    let foreign = api
        .retrieve_blobs(
            Assertion::of(OTHER_AUTHENTICATOR_SEED, OTHER_CREDENTIAL_ID, OTHER_SUBJECT)
                .with_challenge(api.fresh_challenge().await)
                .claiming(READER_SUBJECT),
        )
        .await;

    assert_eq!(
        (common::error_code(&unknown.body).as_deref(), unknown.status),
        (Some("EA-WEBAUTHN-ASSERTION-INVALID"), 401),
        "an unknown subject is not a 404 — that would be the enumeration surface"
    );
    assert_eq!(
        (common::error_code(&foreign.body).as_deref(), foreign.status),
        (common::error_code(&unknown.body).as_deref(), unknown.status),
        "both refusals carry the identical code and status"
    );
    assert_eq!(
        masked_error_body(&foreign.body),
        masked_error_body(&unknown.body),
        "both refusals carry identical bytes modulo the globally unique request-id"
    );
    assert_ne!(
        ProtocolErrorV1::decode(&foreign.body)
            .expect("protocol-error-v1")
            .request_id(),
        ProtocolErrorV1::decode(&unknown.body)
            .expect("protocol-error-v1")
            .request_id(),
        "the two calls really did carry different request ids — otherwise the mask proves nothing"
    );

    // Und beide Wege haben dieselbe Arbeit geleistet: die Challenge ist in
    // BEIDEN Faellen verbraucht. Waere sie es nur auf einem, unterschiede ein
    // Angreifer die beiden Faelle daran, ob er seine Nonce wiederverwenden
    // kann.
    let spent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM challenges WHERE challenge_state = 'spent' AND organization_id = $1",
    )
    .bind(&api.organization_id.as_bytes()[..])
    .fetch_one(api.database.pool())
    .await
    .expect("counting spent challenges must succeed");
    assert_eq!(
        spent, 5,
        "two credential registrations, one upload and BOTH refused retrievals spend a challenge"
    );

    api.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signature_counter_that_does_not_increase_is_a_replay() {
    let api = Api::stand_up().await;
    api.put_blob(READER_SUBJECT, &WRAPPED_BLOB).await;

    let first = api
        .retrieve_blobs(
            Assertion::of(
                READER_AUTHENTICATOR_SEED,
                READER_CREDENTIAL_ID,
                READER_SUBJECT,
            )
            .with_challenge(api.fresh_challenge().await)
            .at_counter(7),
        )
        .await;
    assert_eq!(first.status, 200, "the first assertion carries counter 7");

    let regressed = api
        .retrieve_blobs(
            Assertion::of(
                READER_AUTHENTICATOR_SEED,
                READER_CREDENTIAL_ID,
                READER_SUBJECT,
            )
            .with_challenge(api.fresh_challenge().await)
            .at_counter(7),
        )
        .await;
    assert_eq!(
        (
            common::error_code(&regressed.body).as_deref(),
            regressed.status
        ),
        (Some("EA-WEBAUTHN-ASSERTION-INVALID"), 401),
        "a counter that does not strictly increase is a cloned authenticator"
    );

    let advanced = api
        .retrieve_blobs(
            Assertion::of(
                READER_AUTHENTICATOR_SEED,
                READER_CREDENTIAL_ID,
                READER_SUBJECT,
            )
            .with_challenge(api.fresh_challenge().await)
            .at_counter(8),
        )
        .await;
    assert_eq!(advanced.status, 200, "eight is greater than seven");

    api.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unlisted_origin_receives_no_cors_headers() {
    let api = Api::stand_up().await;

    let refused = api
        .preflight(
            "https://not-listed.example",
            EndpointV1::VaultBlobRetrievals.path_template(),
        )
        .await;
    assert!(
        refused.header("access-control-allow-origin").is_none(),
        "an unlisted origin receives NO Access-Control-Allow-Origin at all"
    );

    let allowed = api
        .preflight(
            common::TEST_BUNDLE_ORIGIN,
            EndpointV1::VaultBlobRetrievals.path_template(),
        )
        .await;
    assert_eq!(
        allowed.header("access-control-allow-origin"),
        Some(common::TEST_BUNDLE_ORIGIN),
        "the separate bundle origin is the one delivery-side entry (§4.1, :70-75)"
    );
    assert!(
        allowed.header("access-control-allow-credentials").is_none(),
        "credentials stay off: the endpoint carries its own authority, not an ambient cookie"
    );
    assert!(
        allowed
            .header("access-control-allow-origin")
            .is_some_and(|value| value != "*"),
        "never a wildcard"
    );

    // Auch die ECHTE Antwort traegt den Origin nur fuer einen gelisteten
    // Aufrufer — und fuer den traegt sie ihn wirklich. Ein Vorabflug allein
    // bewiese das nicht: der Browser wirft die eigentliche Antwort weg, wenn
    // ihr die Kopfzeile fehlt.
    let response = api
        .retrieve_blobs(
            Assertion::of(
                READER_AUTHENTICATOR_SEED,
                READER_CREDENTIAL_ID,
                READER_SUBJECT,
            )
            .with_challenge(api.fresh_challenge().await),
        )
        .await;
    assert!(
        response.header("access-control-allow-origin").is_none(),
        "a request without an Origin header receives no CORS header either"
    );

    let from_bundle = api
        .retrieve_blobs_from_origin(
            Assertion::of(
                READER_AUTHENTICATOR_SEED,
                READER_CREDENTIAL_ID,
                READER_SUBJECT,
            )
            .with_challenge(api.fresh_challenge().await),
            Some(common::TEST_BUNDLE_ORIGIN),
        )
        .await;
    assert_eq!(
        from_bundle.header("access-control-allow-origin"),
        Some(common::TEST_BUNDLE_ORIGIN),
        "the real response carries the origin back for a listed caller"
    );
    assert!(
        from_bundle
            .header("access-control-allow-credentials")
            .is_none(),
        "credentials stay off on the real response too"
    );

    let from_stranger = api
        .retrieve_blobs_from_origin(
            Assertion::of(
                READER_AUTHENTICATOR_SEED,
                READER_CREDENTIAL_ID,
                READER_SUBJECT,
            )
            .with_challenge(api.fresh_challenge().await),
            Some("https://not-listed.example"),
        )
        .await;
    assert!(
        from_stranger
            .header("access-control-allow-origin")
            .is_none(),
        "an unlisted origin gets nothing back on the real response either"
    );

    api.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_upload_is_create_if_absent_and_capped_per_subject() {
    let api = Api::stand_up().await;

    // Dieselben Bytes zweimal: create-if-absent, kein Update, kein Konflikt.
    assert_eq!(
        api.put_blob(READER_SUBJECT, &WRAPPED_BLOB).await.status,
        201
    );
    assert_eq!(
        api.put_blob(READER_SUBJECT, &WRAPPED_BLOB).await.status,
        201
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM reader_vault_blobs WHERE subject_id = $1")
            .bind(&READER_SUBJECT[..])
            .fetch_one(api.database.pool())
            .await
            .expect("counting the stored blobs must succeed");
    assert_eq!(rows, 1, "create-if-absent over (subjectId, blob hash)");

    assert_eq!(
        api.put_blob(READER_SUBJECT, &SECOND_WRAPPED_BLOB)
            .await
            .status,
        201,
        "a second authenticator brings a second wrapped blob (§6.3)"
    );

    // Bis an die Decke und einen darueber.
    for filler in 0..(MAX_VAULT_BLOBS_PER_SUBJECT_V1 - 2) {
        let mut blob = WRAPPED_BLOB;
        blob[0] = u8::try_from(filler).expect("the cap is small");
        assert_eq!(api.put_blob(READER_SUBJECT, &blob).await.status, 201);
    }
    let mut over = WRAPPED_BLOB;
    over[1] = 0xff;
    let refused = api.put_blob(READER_SUBJECT, &over).await;
    assert_eq!(
        (common::error_code(&refused.body).as_deref(), refused.status),
        (Some("EA-VAULT-BLOB-LIMIT"), 413),
        "a released device cannot fill the table under a subjectId without bound"
    );

    api.cleanup().await;
}

/// Die Signaturausnahmen bleiben bei GENAU ZWEI, und der Ablageweg gehoert
/// nicht dazu.
#[test]
fn only_the_retrieval_is_a_signature_exception() {
    assert_eq!(
        EndpointV1::VaultBlobs.authentication(),
        EndpointAuthentication::Signed,
        "the reader owns its Ed25519 key while enrolling (web-reader-design.md §6.4)"
    );
    assert_eq!(
        EndpointV1::VaultBlobRetrievals.authentication(),
        EndpointAuthentication::Unsigned,
        "the fresh browser's vault — and with it the signing key — is still locked (:213-216)"
    );
    assert_eq!(EndpointV1::VaultBlobs.success_status(), 201);
    assert_eq!(EndpointV1::VaultBlobRetrievals.success_status(), 200);
}
