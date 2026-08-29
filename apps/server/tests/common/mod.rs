//! Die gemeinsame Klammer der Integrationstestziele dieses Pakets.
//!
//! Ein Verzeichnismodul, KEIN Testziel: Cargo erklaert `tests/*.rs` und
//! `tests/*/main.rs` zu Zielen, `tests/common/mod.rs` gehoert zu keinem von
//! beiden.
//!
//! ## Warum hier ueberhaupt eine eigene Datenbankklammer steht
//!
//! `#[sqlx::test]` ist in diesem Arbeitsbereich NICHT erreichbar, und das ist
//! kein Versaeumnis: `sqlx::test` haengt an `#[cfg(feature = "macros")]`,
//! `sqlx::testing` an `#[cfg(feature = "migrate")]` (`sqlx-0.9.0/src/lib.rs`),
//! und genau diese beiden Fassadenmerkmale verweisen schwach auf
//! `sqlx-sqlite?/...`. Eine schwache Merkmalsreferenz aktiviert die
//! Abhaengigkeit nicht, zwingt Cargo aber trotzdem, sie zu VERSIONIEREN — und
//! `sqlx-sqlite 0.9.0` verlangt `libsqlite3-sys >=0.30.1, <0.38.0`, waehrend
//! `docs/adr/0002-local-database-encryption.md` `=0.38.0` pinnt. Beide tragen
//! `links = "sqlite3"`, also loest der gesamte Arbeitsbereich nicht mehr auf.
//! Die Begruendung steht in
//! `docs/adr/0004-server-runtime-and-dependency-class.md`.
//!
//! Die Klammer leistet deshalb selbst, was `#[sqlx::test]` geleistet haette:
//! je Test eine EIGENE Datenbank, darin die eine Migration, danach fort damit.

#![allow(dead_code)]

pub mod archive_objects;
pub mod trust_closure;

use std::{
    path::Path,
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use rustls::pki_types::pem::PemObject as _;
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};
use sqlx_core::migrate::Migrator;

/// Der Praefix jeder Wegwerfdatenbank. Er ist zugleich das Suchmuster, mit dem
/// eine abgebrochene Voraufnahme wieder aufgeraeumt wird.
const TEST_DATABASE_PREFIX: &str = "ea_test_";

/// Nach dieser Frist gilt eine liegen gebliebene Testdatenbank als verwaist.
///
/// Ein `Drop` kann nicht `await`en, also hinterlaesst ein panischer Test seine
/// Datenbank. Dagegen hilft kein Guard, sondern nur ein Kehraus zu Beginn — und
/// die Frist ist grosszuegig genug, dass er nie eine LAUFENDE Aufnahme trifft.
const STALE_DATABASE_AGE_MILLIS: u64 = 60 * 60 * 1000;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Die Verwaltungsverbindung, wie `xtask integration up` sie druckt.
#[must_use]
pub fn admin_database_url() -> String {
    std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must be set; run `cargo run --locked -p xtask -- integration up` and eval \
         its export lines",
    )
}

/// Der Object-Store-Endpunkt, wie `xtask integration up` ihn druckt.
#[must_use]
pub fn object_store_endpoint() -> String {
    std::env::var("EA_OBJECT_STORE_ENDPOINT").expect(
        "EA_OBJECT_STORE_ENDPOINT must be set; run `cargo run --locked -p xtask -- integration \
         up` and eval its export lines",
    )
}

/// Der Bucket, den `xtask integration up` versioniert anlegt.
pub const INTEGRATION_BUCKET: &str = "einsatzarchiv-objects";

/// Die Wurzeldaten des Integrationsdienstes — ein an `127.0.0.1` gebundener
/// Container ohne einen einzigen fachlichen Inhalt.
pub const INTEGRATION_ACCESS_KEY_ID: &str = "einsatzarchiv";
pub const INTEGRATION_SECRET_ACCESS_KEY: &str = "einsatzarchiv";

/// Ein prozess- UND laufweit eindeutiges Namenssegment.
///
/// Die Testziele laufen als GETRENNTE Prozesse nebeneinander, deshalb reicht
/// ein Zaehler allein nicht: erst Zeit, Prozesskennung und Zaehler zusammen
/// sind ueber Prozessgrenzen hinweg eindeutig.
#[must_use]
pub fn unique_suffix() -> String {
    format!(
        "{}_{}_{}",
        millis_now(),
        process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn millis_now() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the system clock is after the Unix epoch")
            .as_millis(),
    )
    .expect("milliseconds since the Unix epoch fit in u64")
}

/// Eine Wegwerfdatenbank mit angewandter Migration.
pub struct TestDatabase {
    name: String,
    pool: PgPool,
}

impl TestDatabase {
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Schliesst den Pool und wirft die Datenbank fort.
    ///
    /// Der Pool MUSS vorher zu sein: `DROP DATABASE` scheitert an jeder offenen
    /// Verbindung.
    pub async fn cleanup(self) {
        self.pool.close().await;
        let mut admin = connect_admin().await;
        let statement = format!("DROP DATABASE IF EXISTS \"{}\"", self.name);
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut admin)
            .await
            .expect("dropping the disposable test database must succeed");
    }
}

async fn connect_admin() -> PgConnection {
    PgConnection::connect(&admin_database_url())
        .await
        .expect("the integration PostgreSQL must be reachable")
}

/// Legt eine frische Datenbank an, wendet `migrations/0001_initial.sql` an und
/// gibt einen Pool darauf heraus.
pub async fn fresh_database() -> TestDatabase {
    let mut admin = connect_admin().await;
    sweep_stale_databases(&mut admin).await;

    let name = format!("{TEST_DATABASE_PREFIX}{}", unique_suffix());
    let statement = format!("CREATE DATABASE \"{name}\"");
    sqlx::query(sqlx::AssertSqlSafe(statement))
        .execute(&mut admin)
        .await
        .expect("creating the disposable test database must succeed");

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url_for(&name))
        .await
        .expect("connecting to the disposable test database must succeed");

    Migrator::new(Path::new("migrations"))
        .await
        .expect("the migrations directory must resolve")
        .run(&pool)
        .await
        .expect("the single Stage 3 migration must apply");

    TestDatabase { name, pool }
}

fn database_url_for(name: &str) -> String {
    let url = admin_database_url();
    let (prefix, _) = url
        .rsplit_once('/')
        .expect("DATABASE_URL carries a database path segment");
    format!("{prefix}/{name}")
}

/// Raeumt Datenbanken einer abgebrochenen Voraufnahme fort.
///
/// Das Alter steckt im Namen selbst; eine Datenbank, deren Zeitstempel nicht
/// lesbar ist, wird NICHT angefasst.
async fn sweep_stale_databases(admin: &mut PgConnection) {
    let cutoff = millis_now().saturating_sub(STALE_DATABASE_AGE_MILLIS);
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT datname FROM pg_database WHERE datname LIKE 'ea\\_test\\_%' ESCAPE '\\'",
    )
    .fetch_all(&mut *admin)
    .await
    .expect("listing databases must succeed");
    for (name,) in rows {
        let Some(created) = name
            .strip_prefix(TEST_DATABASE_PREFIX)
            .and_then(|rest| rest.split('_').next())
            .and_then(|millis| millis.parse::<u64>().ok())
        else {
            continue;
        };
        if created >= cutoff {
            continue;
        }
        let statement = format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)");
        let _ = sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut *admin)
            .await;
    }
}

/// Wegwerf-Schluesselmaterial AUSSCHLIESSLICH fuer die TLS-Testfaelle dieses
/// Pakets.
///
/// Eine winzige eigene Test-CA und ein davon ausgestelltes Blattzertifikat auf
/// `localhost`, beides Ed25519, ohne jede Beziehung zu einem Betriebsschluessel.
/// Die ZWEI Stufen sind noetig und keine Zierde: `rustls` weist ein
/// selbstsigniertes CA-Zertifikat, das zugleich als Blatt auftritt, mit
/// `CaUsedAsEndEntity` ab. Ohne echte Kette koennte die Positivkontrolle des
/// TLS-1.3-Handschlags nie gruen werden, und die Abweisung des
/// TLS-1.2-Klienten bewiese dann nichts.
///
/// Der private Schluessel steht hier offen, weil er nichts schuetzt.
pub const TEST_TLS_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBVzCCAQmgAwIBAgIUPRGyz4NpHQ81UhurE//42e9Y2uMwBQYDK2VwMCAxHjAc
BgNVBAMMFUVpbnNhdHphcmNoaXYgVGVzdCBDQTAgFw0yNjA4MjkwODMyNTJaGA8y
MTI2MDgwNTA4MzI1MlowIDEeMBwGA1UEAwwVRWluc2F0emFyY2hpdiBUZXN0IENB
MCowBQYDK2VwAyEA9Cgc0LhkYgMvbnSG7O/GKe7xCMdseOFoGXLpWArF6JmjUzBR
MB0GA1UdDgQWBBS8B238LrwhVXCYavBtSObBSqmgJzAfBgNVHSMEGDAWgBS8B238
LrwhVXCYavBtSObBSqmgJzAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBADp8RnkK
heSs0FDadqTxESiJQOywM4eKrCCeDtUqESryjv0S0T+BcTwxbKpJEP7k8Ex9nlEz
sG7e1nb1+TaD3ww=
-----END CERTIFICATE-----
";

pub const TEST_TLS_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBizCCAT2gAwIBAgIUcSaSVCbbAm8fpgoJsR2QuwnBEWMwBQYDK2VwMCAxHjAc
BgNVBAMMFUVpbnNhdHphcmNoaXYgVGVzdCBDQTAgFw0yNjA4MjkwODMyNTJaGA8y
MTI2MDgwNTA4MzI1MlowFDESMBAGA1UEAwwJbG9jYWxob3N0MCowBQYDK2VwAyEA
KsskgIiRqxEZNGR4qRJC49sv25r5n50PTQ4dS2h/tKmjgZIwgY8wGgYDVR0RBBMw
EYIJbG9jYWxob3N0hwR/AAABMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBTm4bIP+MupROBRLDobHSki
s4e0bTAfBgNVHSMEGDAWgBS8B238LrwhVXCYavBtSObBSqmgJzAFBgMrZXADQQBq
KH4j76XC9+yVjDOfjC4JGVsAZGVUZkmeOL7nw7mFgoHC4qFNaQAGqonake0rpk18
5NDMjbdg+Bzoh38/JL0C
-----END CERTIFICATE-----
";

pub const TEST_TLS_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEk97R2RQp7lL3KaxEnR+mL3764JrOXDRMlyu2iPTO8D
-----END PRIVATE KEY-----
";

/// Schreibt Zertifikat und Schluessel in ein temporaeres Verzeichnis und gibt
/// die beiden Pfade heraus.
///
/// `config.rs` liest benannte DATEIEN — der Test darf diese Kante nicht
/// umgehen, sonst prueft er eine andere Konfiguration als die ausgelieferte.
#[must_use]
pub fn write_test_tls_material() -> (std::path::PathBuf, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!("ea-tls-{}", unique_suffix()));
    std::fs::create_dir_all(&directory).expect("the temporary directory must be creatable");
    let certificate = directory.join("certificate.pem");
    let key = directory.join("key.pem");
    std::fs::write(&certificate, TEST_TLS_CERTIFICATE_PEM).expect("writing the certificate");
    std::fs::write(directory.join("ca.pem"), TEST_TLS_CA_PEM).expect("writing the test CA");
    std::fs::write(&key, TEST_TLS_PRIVATE_KEY_PEM).expect("writing the key");
    (certificate, key)
}

/// Ein winziger HTTP/1.1-Klient ueber TLS 1.3.
///
/// Er steht hier, weil dieser Arbeitsbereich KEINEN HTTP-Klienten pinnt und
/// einen dafuer zu pinnen eine Abhaengigkeitsklasse fuer eine Testhilfe
/// oeffnete (ADR 0004). Alles, was er braucht, ist schon da: `rustls` und
/// `tokio-rustls` liegen auf der Serverseite ohnehin, und `TEST_TLS_CA_PEM`
/// oben ist die Wurzel, gegen die das Blattzertifikat prueft.
///
/// ALPN nennt AUSSCHLIESSLICH `http/1.1`. Ohne diese Zeile handelte der
/// Server `h2` aus — `config.rs` bietet es zuerst an —, und ein
/// zeilenweiser Leser sah HTTP/2-Rahmen.
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn client_tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(TEST_TLS_CA_PEM.as_bytes())
    {
        roots
            .add(certificate.expect("the test CA must parse"))
            .expect("the test CA must be addable");
    }
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 is the only version this workspace compiles")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    std::sync::Arc::new(config)
}

/// Sendet genau einen Request und liest genau eine Antwort.
///
/// Keine Wiederverwendung der Verbindung: jeder Testfall soll denselben Weg
/// nehmen wie ein frischer Klient, und `Connection: close` macht das
/// Antwortende eindeutig.
pub async fn https_request(
    address: std::net::SocketAddr,
    authority: &str,
    method: &str,
    target: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> HttpResponse {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("the listener must accept the connection");
    let connector = tokio_rustls::TlsConnector::from(client_tls_config());
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .expect("the leaf certificate is issued for localhost");
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .expect("the TLS 1.3 handshake must succeed");

    let mut request = format!("{method} {target} HTTP/1.1\r\nhost: {authority}\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!("content-length: {}\r\n", body.len()));
    request.push_str("connection: close\r\n\r\n");
    let mut wire = request.into_bytes();
    wire.extend_from_slice(body);
    stream
        .write_all(&wire)
        .await
        .expect("writing the request must succeed");
    stream.flush().await.expect("flushing must succeed");

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .expect("reading the response must succeed");
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("an HTTP response separates head and body by CRLFCRLF");
    let head = std::str::from_utf8(&raw[..split]).expect("the response head is ASCII");
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("a response carries a status line");
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .expect("a status line carries a numeric code");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    HttpResponse {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

/// Der ECHTE Writer-Sync-Transport gegen diesen Lauscher.
///
/// Er baut `hyper` auf `tokio-rustls` genau so, wie ein Geraet es tut, und
/// vertraut GENAU der Test-CA — dieselbe Wurzel, gegen die auch
/// [`https_request`] prueft. Der kleine handgeschriebene Klient daneben bleibt,
/// was er ist: die Testhilfe der uebrigen Ziele. Dieses eine Ziel misst den
/// PRODUKTIONSPFAD, und dafuer muss der Produktionstransport laufen.
///
/// # Panics
///
/// Wenn die Test-CA nicht parst.
#[must_use]
pub fn hyper_transport(server: &TestServer) -> ea_sync_client::HyperTlsTransport {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(TEST_TLS_CA_PEM.as_bytes())
    {
        roots
            .add(certificate.expect("the test CA must parse"))
            .expect("the test CA must be addable");
    }
    ea_sync_client::HyperTlsTransport::new(server.address, "localhost".to_owned(), roots)
        .expect("the production transport must stand up")
}

/// Der Kryptographieanbieter dieses Prozesses, genau einmal gesetzt.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Der getrennte Auslieferungs-Origin der Testkulisse
/// (`web-reader-design.md` §4.1, :70-75).
///
/// Er steht hier und nicht in jedem Testziel: die CORS-Positivliste und die
/// WebAuthn-`rpId` muessen dieselbe Quelle haben, sonst prueft ein Testfall
/// gegen eine andere Gegenstelle als die konfigurierte.
pub const TEST_BUNDLE_ORIGIN: &str = "https://reader.einsatzarchiv.test";

/// Die `rpId`, die der Server aus [`TEST_BUNDLE_ORIGIN`] ableitet: sein
/// Hostname.
pub const TEST_RELYING_PARTY_ID: &str = "reader.einsatzarchiv.test";

/// Ein laufender Server auf einem TLS-Lauscher an `127.0.0.1`.
pub struct TestServer {
    pub address: std::net::SocketAddr,
    pub authority: String,
}

/// Baut den ECHTEN Router mit den ECHTEN Adaptern und bedient ihn auf einem
/// TLS-1.3-Lauscher.
///
/// Kein `oneshot` gegen den Router: der Testfall soll denselben Weg nehmen,
/// den ein Klient nimmt — durch TLS, durch Axum, durch die Adapter, in die
/// echte Datenbank und in den echten Object Store.
pub async fn spawn_server(
    pool: PgPool,
    now: ea_types::UnixMillis,
    organization_id: ea_types::OrganizationId,
    server_secret: [u8; 32],
    server_certificate_hash: ea_types::CertificateHash,
) -> TestServer {
    use std::sync::Arc;

    use einsatzarchiv_server::{
        adapters::{
            clock::FixedClock, postgres::PostgresRepository, s3::S3ObjectStore,
            server_keys::ServerKeyStore, trust_authority::PostgresTrustAuthority,
        },
        config::tls_server_config,
        http::AppState,
        router::{TlsListener, router, serve},
    };

    install_crypto_provider();
    let (certificate, key) = write_test_tls_material();
    let tls = tls_server_config(&certificate, &key).expect("the test TLS material must load");
    let listener = TlsListener::bind("127.0.0.1:0", tls)
        .await
        .expect("binding the loopback listener must succeed");
    let address = listener
        .local_address()
        .expect("the bound address must be readable");
    let authority = format!("localhost:{}", address.port());

    let clock = Arc::new(FixedClock(now));
    let repository = Arc::new(PostgresRepository::new(pool.clone()));
    let signer = Arc::new(
        ServerKeyStore::new(
            ea_crypto::SecretBytes::new(server_secret),
            server_certificate_hash,
            1,
        )
        .expect("the test server key must load"),
    );
    let objects = Arc::new(S3ObjectStore::new(
        object_store_client().await,
        INTEGRATION_BUCKET.to_owned(),
        organization_id,
        repository.clone(),
        repository.clone(),
        clock.clone(),
    ));
    let web_origins = Arc::new(
        einsatzarchiv_server::config::WebOriginPolicy::new(TEST_BUNDLE_ORIGIN.to_owned(), &[])
            .expect("the test bundle origin must be a usable https origin"),
    );
    let state = Arc::new(AppState {
        authority: authority.clone(),
        clock,
        signer,
        objects: objects.clone(),
        repository: repository.clone(),
        trust_authority: Arc::new(PostgresTrustAuthority::new(pool, objects)),
        relying_party: ea_sync_server::vault_blob::WebauthnRelyingPartyV1::new(
            web_origins.bundle_origin().to_owned(),
            web_origins.relying_party_id(),
        ),
    });

    tokio::spawn(async move {
        let _ = serve(listener, router(state, web_origins)).await;
    });
    TestServer { address, authority }
}

/// Der S3-Klient gegen den Integrationsdienst.
pub async fn object_store_client() -> aws_sdk_s3::Client {
    let http_client = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https();
    let configuration = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .http_client(http_client)
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(object_store_endpoint())
        .force_path_style(true)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            INTEGRATION_ACCESS_KEY_ID,
            INTEGRATION_SECRET_ACCESS_KEY,
            None,
            None,
            "einsatzarchiv-integration",
        ))
        .build();
    aws_sdk_s3::Client::from_conf(configuration)
}

/// Der Bauplan eines signierten Testrequests.
///
/// Ein Datensatz statt neun Stellungsargumenten: neun Stellungen in Folge
/// sind eine Verwechslung, die der Compiler nicht sieht — `request_id` und
/// `nonce` waeren beide Bytefolgen.
pub struct SignedCall<'a> {
    pub signer: &'a ea_sync_protocol::RequestSigner,
    pub endpoint: ea_sync_protocol::EndpointV1,
    pub authority: &'a str,
    pub target: &'a str,
    pub body: Option<&'a [u8]>,
    pub organization_id: ea_types::OrganizationId,
    pub request_id: [u8; 16],
    pub nonce: [u8; 32],
    /// `created` der Signaturparameter. Ein negativer Wert legt das Fenster
    /// bewusst in die Vergangenheit.
    pub created: i64,
}

/// Die Kopfzeilen eines RFC-9421-signierten Requests dieses Profils.
///
/// Signiert wird mit dem echten [`ea_sync_protocol::RequestSigner`] — ein
/// zweiter Signierer im Test prueefte den Server gegen eine andere Auslegung
/// desselben Profils.
#[must_use]
pub fn signed_headers(call: &SignedCall<'_>) -> Vec<(&'static str, String)> {
    use ea_sync_protocol::{RequestParts, SignatureParametersV1, body_digest, organization_tag};

    let parts = RequestParts {
        method: call.endpoint.method(),
        authority: call.authority.to_owned(),
        target_uri: format!("https://{}{}", call.authority, call.target),
        content_type: call.endpoint.request_media_type().map(ToOwned::to_owned),
        body_digest: call.body.map(body_digest),
        request_id: ea_sync_protocol::RequestIdV1::try_from(&call.request_id[..])
            .expect("a request id is 16 bytes"),
    };
    let parameters = SignatureParametersV1::new(
        call.created,
        call.created + 300,
        call.nonce,
        organization_tag(call.organization_id),
    );
    let signed = call
        .signer
        .sign(&parts, &parameters)
        .expect("signing the test request must succeed");

    let mut headers = vec![
        (
            ea_sync_protocol::REQUEST_ID_HEADER_V1,
            signed.request_id().to_header_value(),
        ),
        ("signature-input", signed.signature_input_header()),
        ("signature", signed.signature_header()),
    ];
    if let Some(media_type) = call.endpoint.request_media_type() {
        headers.push(("content-type", media_type.to_owned()));
    }
    if let Some(digest) = signed.content_digest_header() {
        headers.push(("content-digest", digest.to_owned()));
    }
    headers
}

/// Ein eingefrorener Trust-Bestand, wie der Server ihn kennt.
pub struct TrustFixture {
    pub organization_id: ea_types::OrganizationId,
    /// Die Objekte, die absichtlich NICHT eingespielt wurden — der Testfall
    /// laedt sie ueber den Endpunkt nach.
    pub withheld: Vec<Vec<u8>>,
}

/// Spielt einen eingefrorenen Trust-Vektor als Serverbestand ein.
///
/// Die Bytes sind die EINGEFRORENEN aus `vectors/trust/v1/`; sie werden nicht
/// nachgebaut. Eingespielt wird auf dem Weg, den der Server spaeter liest:
/// die exakten Bytes in den Object Store unter `etb/<hex objectHash>`, ihre
/// Kennungen in `object_index` und `trust_events`, und ein `registryEvent`
/// zusaetzlich in die Registry-Linie.
pub async fn seed_trust_fixture(pool: &PgPool, case: &str, withhold: &[&str]) -> TrustFixture {
    seed_trust_fixture_named(pool, case, withhold).await.0
}

/// Dieselbe Einspielung, aber sie gibt die zurueckgehaltenen Objekte MIT
/// ihrem Dateinamen heraus.
///
/// Der Bootstrap-Fall reicht sie in Abhaengigkeitsreihenfolge ueber den
/// Endpunkt nach, und die Reihenfolge steht in den Namen.
pub async fn seed_trust_fixture_named(
    pool: &PgPool,
    case: &str,
    withhold: &[&str],
) -> (TrustFixture, Vec<(String, Vec<u8>)>) {
    use ea_format::{DecodedTrustPayloadV1, ObjectTypeV1, ParsedArchiveObject};

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/trust/v1")
        .join(case);
    let anchor_bytes = std::fs::read(root.join("anchor.bin")).expect("the frozen anchor must read");
    let anchor = ea_trust::decode_trust_anchor(&anchor_bytes).expect("the frozen anchor decodes");
    let organization_id = anchor.organization_id();

    sqlx::query(
        "INSERT INTO organizations (organization_id, root_key_thumbprint, trust_anchor_bytes, \
         created_at_millis) VALUES ($1, $2, $3, $4)",
    )
    .bind(&organization_id.as_bytes()[..])
    .bind(&anchor.root_key_thumbprint().as_bytes()[..])
    .bind(&anchor_bytes[..])
    .bind(0_i64)
    .execute(pool)
    .await
    .expect("the organization row is technical and must insert");

    let client = object_store_client().await;
    let mut names: Vec<_> = std::fs::read_dir(&root)
        .expect("the frozen case directory must read")
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
        .filter_map(|name| name.to_str().map(ToOwned::to_owned))
        .filter(|name| name.ends_with(".bin"))
        .collect();
    names.sort();

    let mut withheld = Vec::new();
    for name in names {
        if name == "anchor.bin" || name == "pre-anchor.bin" {
            continue;
        }
        let bytes = std::fs::read(root.join(&name)).expect("a frozen object must read");
        if withhold.contains(&name.as_str()) {
            withheld.push((name.clone(), bytes));
            continue;
        }
        let hash = ea_crypto::object_hash(&bytes);
        client
            .put_object()
            .bucket(INTEGRATION_BUCKET)
            .key(ea_sync_server::object_key(ObjectTypeV1::Trust, hash))
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes.clone()))
            .send()
            .await
            .expect("storing a frozen trust object must succeed");

        sqlx::query(
            "INSERT INTO object_index (object_hash, organization_id, object_type_code, \
             size_bytes, stored_at_millis) VALUES ($1, $2, 5, $3, 0)",
        )
        .bind(&hash.as_bytes()[..])
        .bind(&organization_id.as_bytes()[..])
        .bind(i64::try_from(bytes.len()).expect("a frozen object is small"))
        .execute(pool)
        .await
        .expect("indexing a frozen trust object must succeed");

        let ParsedArchiveObject::Trust(parsed) =
            ea_format::decode_exact_object(&bytes).expect("a frozen trust object parses")
        else {
            panic!("the frozen case must hold trust objects only");
        };
        let subtype = parsed.value().subtype().as_str();
        sqlx::query(
            "INSERT INTO trust_events (organization_id, event_id, object_hash, event_code, \
             received_at_millis) VALUES ($1, $2, $3, $4, 0)",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&hash.as_bytes()[..16])
        .bind(&hash.as_bytes()[..])
        .bind(subtype)
        .execute(pool)
        .await
        .expect("recording a frozen trust object must succeed");

        if let Ok(DecodedTrustPayloadV1::RegistryEvent(core)) = parsed.value().decoded_payload() {
            sqlx::query(
                "INSERT INTO registry_events (organization_id, registry_version, \
                 registry_head_hash, effective_from_millis) VALUES ($1, $2, $3, $4)",
            )
            .bind(&organization_id.as_bytes()[..])
            .bind(
                i64::try_from(core.fields().registry_version.get())
                    .expect("a frozen registry version is small"),
            )
            .bind(&hash.as_bytes()[..])
            .bind(core.fields().issued_at.get())
            .execute(pool)
            .await
            .expect("recording a frozen registry head must succeed");
        }
    }

    (
        TrustFixture {
            organization_id,
            withheld: withheld.iter().map(|(_, bytes)| bytes.clone()).collect(),
        },
        withheld,
    )
}

/// Spielt den FORTGESCHRIEBENEN Vertrauensabschluss ueber den ECHTEN Endpunkt
/// `POST /v1/trust/events` ein.
///
/// Nicht per `INSERT`: der Weg durch den Endpunkt fuehrt jedes Objekt durch die
/// geteilte `ea-trust`-Pruefung, also durch dieselbe Instanz, die auch ein
/// Reader fuehrt. Ein falsch gebautes Objekt der Kulisse faellt damit HIER auf
/// und nicht erst als raetselhafter Commit-Fehler — die Kulisse kann sich
/// nicht selbst fuer gueltig erklaeren.
///
/// Die Reihenfolge ist die ABHAENGIGKEITSREIHENFOLGE aus
/// [`trust_closure::build`]: Autorisierung vor Ziel, Ziel vor Kopf.
///
/// # Panics
///
/// Wenn ein Objekt abgewiesen wird — dann ist die Kulisse defekt.
pub async fn publish_closure(
    server: &TestServer,
    closure: &trust_closure::ExtendedClosure,
    signer: &ea_sync_protocol::RequestSigner,
    created: i64,
) {
    use ea_sync_protocol::{EndpointV1, TrustEventUploadV1};

    for (index, object) in closure.objects.iter().enumerate() {
        let upload =
            TrustEventUploadV1::new(object.bytes.clone()).expect("the upload frame must build");
        let nonce = fresh_challenge(server, closure.organization_id).await;
        let mut request_id = [0xa0_u8; 16];
        request_id[15] = u8::try_from(index).expect("the closure holds fewer than 256 objects");
        let headers = signed_headers(&SignedCall {
            signer,
            endpoint: EndpointV1::TrustEvents,
            authority: &server.authority,
            target: EndpointV1::TrustEvents.path_template(),
            body: Some(upload.exact_bytes()),
            organization_id: closure.organization_id,
            request_id,
            nonce,
            created,
        });
        let response = https_request(
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
            "the closure object {} must be accepted; the server answered {:?}",
            object.name,
            ea_sync_protocol::ProtocolErrorV1::decode(&response.body)
                .ok()
                .map(|error| (
                    error.error_code().to_owned(),
                    error.required_registry_version().map(|v| v.get()),
                    error
                        .required_registry_head_hash()
                        .map(|h| hex::encode(h.as_bytes()))
                ))
        );
    }
}

/// Eine frische Challenge-Nonce.
///
/// Sie steht hier und nicht in jedem Testziel: jeder signierte Request braucht
/// eine, und drei Kopien derselben zehn Zeilen waeren drei Gelegenheiten, sie
/// verschieden zu machen.
///
/// # Panics
///
/// Wenn der Challenge-Endpunkt nicht mit `200` antwortet.
pub async fn fresh_challenge(
    server: &TestServer,
    organization_id: ea_types::OrganizationId,
) -> [u8; 32] {
    use ea_sync_protocol::{
        ChallengeRequestV1, ChallengeResponseV1, EndpointV1, STRUCTURED_MEDIA_TYPE_V1,
    };

    let body = ChallengeRequestV1::new(organization_id);
    let response = https_request(
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

// ---------------------------------------------------------------------------
// Die gemeinsame Kulisse der LESENDEN und VERWALTENDEN Testziele
// ---------------------------------------------------------------------------
//
// `read_apis`, `historical_grant_api`, `destruction_api` und `export_api`
// brauchen alle denselben Aufbau: eine Organisation mit fortgeschriebenem
// Abschluss, eine laufende Kette und mindestens einen ECHT committeten
// Eintrag. Vier Kopien davon waeren vier Gelegenheiten, sie verschieden zu
// machen — und ein Testziel, dessen Kulisse von den anderen abweicht, prueft
// etwas anderes, als es behauptet.

/// Innerhalb des `notBefore`/`notAfter`-Fensters aller Koepfe.
pub const READ_SERVER_NOW_MILLIS: i64 = 1_000;
pub const READ_SERVER_SECRET: [u8; 32] = [0x51; 32];
pub const READ_SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];
/// Der Kopf, auf dem die Kette steht, bevor der erste Eintrag committet wird.
pub const READ_SEEDED_HEAD_ENTRY_HASH: [u8; 32] = [0x77; 32];
const READ_SEEDED_HEAD_ACCEPTED_AT: i64 = 500;

/// Ein aufgebauter Server samt seinem Abschluss.
pub struct ReadyServer {
    pub server: TestServer,
    pub closure: trust_closure::ExtendedClosure,
}

#[must_use]
pub fn request_signer(seed: [u8; 32]) -> ea_sync_protocol::RequestSigner {
    ea_sync_protocol::RequestSigner::from_secret(ea_crypto::SecretBytes::new(seed))
}

/// Der Fehlercode eines `protocol-error-v1`, oder `None`.
#[must_use]
pub fn error_code(body: &[u8]) -> Option<String> {
    ea_sync_protocol::ProtocolErrorV1::decode(body)
        .ok()
        .map(|error| error.error_code().to_owned())
}

/// Eine Organisation mit fortgeschriebenem Abschluss und laufender Kette.
///
/// `with_grant_authorities` schaltet die Historical Grant Authority und die
/// beiden Key Approver dazu; ohne sie sind ein historischer Re-Grant und eine
/// Vernichtung gar nicht baubar.
///
/// # Panics
///
/// Wenn die Kulisse nicht steht — dann ist sie defekt, nicht der Server.
pub async fn stand_up_read_server(
    database: &TestDatabase,
    now_millis: i64,
    with_grant_authorities: bool,
) -> ReadyServer {
    let fixture = seed_trust_fixture(database.pool(), trust_closure::ROTATION_CASE, &[]).await;
    let closure = trust_closure::build_with(false, with_grant_authorities);
    assert!(
        closure.organization_id == fixture.organization_id,
        "the extension binds to the frozen anchor's organization"
    );
    let server = spawn_server(
        database.pool().clone(),
        ea_types::UnixMillis::new(now_millis),
        closure.organization_id,
        READ_SERVER_SECRET,
        ea_types::CertificateHash::try_from(&READ_SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;
    publish_closure(
        &server,
        &closure,
        &request_signer(trust_closure::ADMIN_SEED),
        0,
    )
    .await;
    trust_closure::seed_chain_head(
        database.pool(),
        closure.organization_id,
        closure.chain_id,
        trust_closure::ExtendedClosure::seeded_head_sequence(),
        READ_SEEDED_HEAD_ENTRY_HASH,
        READ_SEEDED_HEAD_ACCEPTED_AT,
    )
    .await;
    ReadyServer { server, closure }
}

/// Ein ECHT committeter Eintrag, samt seinen Adressen.
pub struct CommittedEntry {
    pub sequence: u64,
    pub entry_hash: ea_types::EntryHash,
    pub entry_object_hash: ea_types::ObjectHash,
    pub recovery_grant_object_hash: ea_types::ObjectHash,
    pub reader_grant_object_hash: ea_types::ObjectHash,
}

/// Committet EINEN Eintrag ueber den ECHTEN Endpunkt.
///
/// Nicht per `INSERT`: die Leseflaechen sollen das ausliefern, was der
/// Commit-Pfad abgelegt hat, und nicht das, was ein Test daneben gestellt hat.
///
/// # Panics
///
/// Wenn der Commit nicht mit `200` beantwortet wird.
pub async fn commit_one_entry(
    ready: &ReadyServer,
    sequence: u64,
    previous_entry_hash: Option<ea_types::EntryHash>,
    marker: u8,
) -> CommittedEntry {
    use ea_sync_protocol::EndpointV1;

    let closure = &ready.closure;
    let recipients = [
        archive_objects::Recipient::reader(closure),
        archive_objects::Recipient::recovery(closure),
    ];
    let plan = archive_objects::plan(&recipients);
    let spec = archive_objects::CommitSpec {
        closure,
        sequence,
        previous_entry_hash,
        recipients: &recipients,
        marker,
        writer_override: None,
        registry_override: None,
    };
    let entry_bytes = archive_objects::entry_bytes(&spec, &plan);
    let entry_hash = archive_objects::entry_hash_of(&entry_bytes);
    let request = archive_objects::commit_request(&spec);

    let target = archive_objects::entry_commit_path(closure.chain_id);
    let nonce = fresh_challenge(&ready.server, closure.organization_id).await;
    let mut request_id = [0xc0_u8; 16];
    request_id[15] = marker;
    let headers = signed_headers(&SignedCall {
        signer: &request_signer(trust_closure::WRITER_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &ready.server.authority,
        target: &target,
        body: Some(request.exact_bytes()),
        organization_id: closure.organization_id,
        request_id,
        nonce,
        created: READ_SERVER_NOW_MILLIS.div_euclid(1_000),
    });
    let response = https_request(
        ready.server.address,
        &ready.server.authority,
        "POST",
        &target,
        &headers,
        request.exact_bytes(),
    )
    .await;
    assert_eq!(
        response.status,
        200,
        "the fixture commit must be accepted; the server answered {:?}",
        error_code(&response.body)
    );

    CommittedEntry {
        sequence,
        entry_hash,
        entry_object_hash: ea_crypto::object_hash(&entry_bytes),
        recovery_grant_object_hash: ea_crypto::object_hash(&archive_objects::grant_bytes(
            closure,
            entry_hash,
            archive_objects::Recipient::recovery(closure),
        )),
        reader_grant_object_hash: ea_crypto::object_hash(&archive_objects::grant_bytes(
            closure,
            entry_hash,
            archive_objects::Recipient::reader(closure),
        )),
    }
}

/// Ein signierter Request gegen den echten Server — die gemeinsame Klammer der
/// vier lesenden und verwaltenden Testziele.
pub struct ApiCall<'a> {
    pub ready: &'a ReadyServer,
    pub signer_seed: [u8; 32],
    pub endpoint: ea_sync_protocol::EndpointV1,
    pub target: &'a str,
    pub body: Option<&'a [u8]>,
    pub request_id: [u8; 16],
}

/// Sendet ihn und gibt die Antwort heraus.
///
/// # Panics
///
/// Wenn der Challenge-Endpunkt nicht antwortet.
pub async fn call(request: &ApiCall<'_>) -> HttpResponse {
    let organization_id = request.ready.closure.organization_id;
    let nonce = fresh_challenge(&request.ready.server, organization_id).await;
    let headers = signed_headers(&SignedCall {
        signer: &request_signer(request.signer_seed),
        endpoint: request.endpoint,
        authority: &request.ready.server.authority,
        target: request.target,
        body: request.body,
        organization_id,
        request_id: request.request_id,
        nonce,
        created: READ_SERVER_NOW_MILLIS.div_euclid(1_000),
    });
    let method = match request.endpoint.method() {
        ea_sync_protocol::HttpMethod::Get => "GET",
        ea_sync_protocol::HttpMethod::Put => "PUT",
        ea_sync_protocol::HttpMethod::Post => "POST",
    };
    https_request(
        request.ready.server.address,
        &request.ready.server.authority,
        method,
        request.target,
        &headers,
        request.body.unwrap_or(&[]),
    )
    .await
}

/// Legt exakte `.etb`-Bytes DIREKT in den Object Store.
///
/// Bewusst NICHT ueber `POST /v1/trust/events`: die Aufnahme weist
/// `grantAuthorization` und `destructionAuthorization` fail-closed als
/// `EA-TRUST-EVENT-UNVERIFIABLE` ab, weil `ea-trust` fuer sie im
/// Registrierungsabschluss keine Signiererregel fuehrt. Sie erreichen den
/// Server auf ihrem eigenen Weg — die Vernichtung ueber `POST /v1/destructions`,
/// die Grant-Autorisierung als das Objekt, das ein historisches `.eag` NENNT
/// und das der Server content-addressed aufloest. Fuer das zweite gibt es in
/// dieser Stufe noch keinen Aufnahmeendpunkt; die Kulisse legt es deshalb
/// dorthin, wo Stufe 5 es hinlegen wird.
///
/// # Panics
///
/// Wenn die Ablage scheitert.
pub async fn seed_trust_object_bytes(bytes: &[u8]) -> ea_types::ObjectHash {
    let hash = ea_crypto::object_hash(bytes);
    object_store_client()
        .await
        .put_object()
        .bucket(INTEGRATION_BUCKET)
        .key(ea_sync_server::object_key(
            ea_format::ObjectTypeV1::Trust,
            hash,
        ))
        .body(aws_sdk_s3::primitives::ByteStream::from(bytes.to_vec()))
        .send()
        .await
        .expect("storing a fixture trust object must succeed");
    hash
}

/// Ein ZWEITER Server auf derselben Datenbank, mit einer anderen Uhr.
///
/// Die Uhr eines Servers steht bei seinem Aufbau fest — sie ist ein Port und
/// kein Zustand. Ein Fall, der eine Frist ueberschreiten laesst, braucht
/// deshalb einen zweiten Server und nicht einen zweiten Testfall: derselbe
/// Bestand, dieselbe Kette, eine spaetere Zeit.
///
/// # Panics
///
/// Wenn der Lauscher nicht bindet.
pub async fn respawn_read_server(
    database: &TestDatabase,
    closure: &trust_closure::ExtendedClosure,
    now_millis: i64,
) -> ReadyServer {
    let server = spawn_server(
        database.pool().clone(),
        ea_types::UnixMillis::new(now_millis),
        closure.organization_id,
        READ_SERVER_SECRET,
        ea_types::CertificateHash::try_from(&READ_SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;
    ReadyServer {
        server,
        closure: trust_closure::build_with(false, true),
    }
}

/// Derselbe signierte Request, aber mit ausdruecklich gesetzter Signaturzeit.
///
/// `call` folgt der Standarduhr; ein Fall gegen einen Server mit VERSTELLTER
/// Uhr muss seine Signatur mitverstellen, sonst faellt er am Signaturfenster
/// und nicht an der Sache, die er prueft.
pub async fn call_at(request: &ApiCall<'_>, now_millis: i64) -> HttpResponse {
    let organization_id = request.ready.closure.organization_id;
    let nonce = fresh_challenge(&request.ready.server, organization_id).await;
    let headers = signed_headers(&SignedCall {
        signer: &request_signer(request.signer_seed),
        endpoint: request.endpoint,
        authority: &request.ready.server.authority,
        target: request.target,
        body: request.body,
        organization_id,
        request_id: request.request_id,
        nonce,
        created: now_millis.div_euclid(1_000),
    });
    let method = match request.endpoint.method() {
        ea_sync_protocol::HttpMethod::Get => "GET",
        ea_sync_protocol::HttpMethod::Put => "PUT",
        ea_sync_protocol::HttpMethod::Post => "POST",
    };
    https_request(
        request.ready.server.address,
        &request.ready.server.authority,
        method,
        request.target,
        &headers,
        request.body.unwrap_or(&[]),
    )
    .await
}

/// Ein ECHTER technischer Cursor, ausgestellt mit DEMSELBEN Serverschluessel,
/// den die Testkulisse dem Server gibt.
///
/// Er steht hier, weil eine Blaetterseite in diesen Testfaellen nie voll wird —
/// zwei Eintraege reissen keine Decke von tausend Objekten. Ohne ihn pruefte
/// jeder Cursorfall nur die ABWEISUNG, und ein Cursor, den der Server
/// ausstellt, aber nie wieder oeffnet, kaeme durch alle davon.
///
/// # Panics
///
/// Wenn der Schluessel nicht laedt oder der Cursor nicht entsteht.
#[must_use]
pub fn issue_technical_cursor(fields: &ea_sync_protocol::TechnicalCursorFieldsV1) -> Vec<u8> {
    let signer = einsatzarchiv_server::adapters::server_keys::ServerKeyStore::new(
        ea_crypto::SecretBytes::new(READ_SERVER_SECRET),
        ea_types::CertificateHash::try_from(&READ_SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
        1,
    )
    .expect("the test server key must load");
    ea_sync_protocol::TechnicalCursorV1::issue(fields, &signer)
        .expect("issuing a technical cursor must succeed")
        .token_bytes()
        .to_vec()
}

/// Ein Eintrag an Sequenz NULL — der Genesis-Eintrag.
///
/// # Warum diese Zeile von Hand entsteht
///
/// Der ECHTE Commit-Pfad kann sie in dieser Kulisse nicht erzeugen, und das
/// liegt an der Sequenzleihe und nicht am Commit: die eingefrorenen
/// Registrierungskoepfe leihen sich `0..=100` und `101..=200`, und
/// `select_registry_head` haelt beim ERSTEN Kopf an, dessen Leihe die
/// vorgeschlagene Sequenz deckt. Fuer Sequenz null ist das der erste
/// eingefrorene Kopf — und der traegt kein Writer-Zertifikat. Ein echter
/// Commit an Sequenz null waere deshalb `EA-COMMIT-WRITER-UNAUTHORIZED` und
/// kein Genesis-Eintrag.
///
/// Was dieser Zeuge misst, ist auch nicht der Commit, sondern die
/// BLAETTERGRENZE des Lesestapels: Sequenz null ist eine echte Kettenposition,
/// und eine exklusive Grenze liesse sie unerreichbar. Das `.eip` ist deshalb
/// ECHT und liegt content-addressed im Object Store; Quittung und
/// Registrierungskopf sind die ADRESSEN vorhandener, ebenfalls echter Objekte
/// — der Stapel liefert sie aus und rechnet sie gegen ihre Adresse zurueck,
/// und genau das soll er.
///
/// # Panics
///
/// Wenn das Einfuegen oder die Ablage scheitert.
pub async fn seed_genesis_entry(
    pool: &sqlx::PgPool,
    closure: &trust_closure::ExtendedClosure,
    receipt_object_hash: ea_types::ObjectHash,
) -> (ea_types::EntryHash, ea_types::ObjectHash) {
    let recipients = [
        archive_objects::Recipient::reader(closure),
        archive_objects::Recipient::recovery(closure),
    ];
    let plan = archive_objects::plan(&recipients);
    let spec = archive_objects::CommitSpec {
        closure,
        sequence: 0,
        previous_entry_hash: None,
        recipients: &recipients,
        marker: 0x0e,
        writer_override: None,
        registry_override: None,
    };
    let entry_bytes = archive_objects::entry_bytes(&spec, &plan);
    let entry_hash = archive_objects::entry_hash_of(&entry_bytes);
    let entry_object_hash = ea_crypto::object_hash(&entry_bytes);

    object_store_client()
        .await
        .put_object()
        .bucket(INTEGRATION_BUCKET)
        .key(ea_sync_server::object_key(
            ea_format::ObjectTypeV1::Entry,
            entry_object_hash,
        ))
        .body(aws_sdk_s3::primitives::ByteStream::from(
            entry_bytes.clone(),
        ))
        .send()
        .await
        .expect("storing the genesis entry must succeed");

    sqlx::query(
        "INSERT INTO object_index (object_hash, organization_id, object_type_code, size_bytes, \
         stored_at_millis) VALUES ($1, $2, 1, $3, 0)",
    )
    .bind(&entry_object_hash.as_bytes()[..])
    .bind(&closure.organization_id.as_bytes()[..])
    .bind(i64::try_from(entry_bytes.len()).expect("a fixture entry is small"))
    .execute(pool)
    .await
    .expect("indexing the genesis entry must succeed");

    sqlx::query(
        "INSERT INTO entries (entry_hash, organization_id, chain_id, sequence_number, \
         previous_entry_hash, entry_object_hash, initial_grant_plan_hash, receipt_object_hash, \
         device_id, accepted_at_server_millis, registry_version, registry_head_hash) \
         VALUES ($1, $2, $3, 0, NULL, $4, $5, $6, $7, 0, $8, $9)",
    )
    .bind(&entry_hash.as_bytes()[..])
    .bind(&closure.organization_id.as_bytes()[..])
    .bind(&closure.chain_id.as_bytes()[..])
    .bind(&entry_object_hash.as_bytes()[..])
    .bind(&plan.hash().as_bytes()[..])
    .bind(&receipt_object_hash.as_bytes()[..])
    .bind(&[0xe1_u8; 16][..])
    .bind(i64::try_from(closure.registry_version.get()).expect("a test version is small"))
    .bind(&closure.registry_head_hash.as_bytes()[..])
    .execute(pool)
    .await
    .expect("inserting the genesis entry must succeed");

    (entry_hash, entry_object_hash)
}

/// Die Quittungsadresse eines bereits committeten Eintrags.
///
/// # Panics
///
/// Wenn der Eintrag nicht existiert.
pub async fn receipt_object_hash_of(
    pool: &sqlx::PgPool,
    entry_hash: ea_types::EntryHash,
) -> ea_types::ObjectHash {
    let row: (Vec<u8>,) =
        sqlx::query_as("SELECT receipt_object_hash FROM entries WHERE entry_hash = $1")
            .bind(&entry_hash.as_bytes()[..])
            .fetch_one(pool)
            .await
            .expect("reading the receipt address must succeed");
    ea_types::ObjectHash::try_from(row.0.as_slice()).expect("32 bytes")
}
