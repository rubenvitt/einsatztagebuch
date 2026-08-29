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

use std::{
    path::Path,
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

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
