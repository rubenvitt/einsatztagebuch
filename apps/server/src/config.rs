//! Die Konfiguration des Servers — und darin die TLS-Terminierung.
//!
//! # TLS 1.3, fail-closed, IM PROZESS
//!
//! `design.md`:1497 sagt im ersten Satz von §13.1: „Alle `/v1`-Requests laufen
//! ueber TLS 1.3.“ Diese Terminierung liegt AUSDRUECKLICH NICHT ausserhalb des
//! Prozesses: der Server terminiert selbst, mit `tokio-rustls` vor Axum, und
//! [`router::serve`](crate::router::serve) bindet ausschliesslich den so
//! konfigurierten Lauscher. Es gibt keinen zweiten, unverschluesselten
//! Lauscher, den ein Betriebsfehler versehentlich freigeben koennte.
//!
//! Die Durchsetzung steht auf ZWEI Beinen, und das zweite ist das
//! belastbarere:
//!
//! 1. [`tls_server_config`] baut die `rustls::ServerConfig` ueber
//!    `builder_with_protocol_versions(&[&rustls::version::TLS13])` — TLS 1.3
//!    ist die einzige angebotene Version, nicht die bevorzugte.
//! 2. `rustls` und `tokio-rustls` sind ohne das Merkmal `tls12` gepinnt
//!    (ADR 0004). TLS 1.2 ist in diesem Binaerteil gar nicht einkompiliert.
//!    Eine Fehlkonfiguration kann es nicht zurueckholen; dafuer muesste jemand
//!    den Pin aendern, und der haengt am ADR-Gate.
//!
//! Ein Klient, der nur TLS 1.2 anbietet, bekommt deshalb keinen ServerHello,
//! sondern einen Abbruch. `apps/server/tests/fault_scenarios.rs` haelt genau
//! das fest.
//!
//! # Zertifikat und Schluessel
//!
//! Beides kommt aus BENANNTEN Dateien im PEM-Format, deren Pfade in der
//! Umgebung stehen: `EA_TLS_CERTIFICATE_PEM` und `EA_TLS_PRIVATE_KEY_PEM`.
//! Fehlt eine der beiden, startet der Server NICHT — es gibt keinen
//! selbstsignierten Notbehelf und kein stilles Abschalten von TLS.

use std::{path::PathBuf, sync::Arc};

use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

/// Die Umgebungsnamen, aus denen der Server liest. Sie stehen hier einmal,
/// damit eine Fehlermeldung denselben Namen nennt wie die Dokumentation.
pub const ENV_BIND_ADDRESS: &str = "EA_BIND_ADDRESS";
pub const ENV_TLS_CERTIFICATE: &str = "EA_TLS_CERTIFICATE_PEM";
pub const ENV_TLS_PRIVATE_KEY: &str = "EA_TLS_PRIVATE_KEY_PEM";
pub const ENV_DATABASE_URL: &str = "DATABASE_URL";
pub const ENV_OBJECT_STORE_ENDPOINT: &str = "EA_OBJECT_STORE_ENDPOINT";
pub const ENV_OBJECT_STORE_BUCKET: &str = "EA_OBJECT_STORE_BUCKET";
pub const ENV_OBJECT_STORE_REGION: &str = "EA_OBJECT_STORE_REGION";
pub const ENV_OBJECT_STORE_ACCESS_KEY_ID: &str = "EA_OBJECT_STORE_ACCESS_KEY_ID";
pub const ENV_OBJECT_STORE_SECRET_ACCESS_KEY: &str = "EA_OBJECT_STORE_SECRET_ACCESS_KEY";
pub const ENV_MIGRATIONS_DIRECTORY: &str = "EA_MIGRATIONS_DIRECTORY";
/// Die Autoritaet, gegen die jede RFC-9421-Signatur `@authority` und
/// `@target-uri` stellt. Sie wird KONFIGURIERT und nicht aus dem `Host`-Header
/// abgeleitet: sonst setzte der Aufrufer selbst die Erwartung, gegen die er
/// geprueft wird.
pub const ENV_SYNC_AUTHORITY: &str = "EA_SYNC_AUTHORITY";
/// Die Organisation, die diese Installation bedient. Der Object Store schreibt
/// seine Security Events unter ihr, und die Ratenbegrenzung des
/// Challenge-Endpunkts zaehlt je Organisation.
pub const ENV_ORGANIZATION_ID: &str = "EA_ORGANIZATION_ID";
pub const ENV_SERVER_SIGNING_KEY: &str = "EA_SERVER_SIGNING_KEY_HEX";
pub const ENV_SERVER_CERTIFICATE_HASH: &str = "EA_SERVER_CERTIFICATE_HASH_HEX";
pub const ENV_SERVER_KEY_GENERATION: &str = "EA_SERVER_KEY_GENERATION";

/// Die Befunde beim Hochfahren. Alle fail-closed: der Server startet nicht.
#[derive(Debug)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
    Tls(rustls::Error),
}

impl ConfigError {
    /// Der stabile Code dieses Befundes.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Missing(_) => "EA-CONFIG-MISSING",
            Self::Invalid(_) => "EA-CONFIG-INVALID",
            Self::Tls(_) => "EA-CONFIG-TLS",
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(name) => write!(formatter, "{}: {name}", self.code()),
            Self::Invalid(name) => write!(formatter, "{}: {name}", self.code()),
            Self::Tls(_) => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Der Object-Store-Zugang. Endpunkt, Region, Bucket und Zugangsdaten.
pub struct ObjectStoreConfig {
    pub endpoint_url: String,
    pub region: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

pub struct ServerConfiguration {
    pub bind_address: String,
    pub sync_authority: String,
    pub organization_id: ea_types::OrganizationId,
    /// Der geheime Ed25519-Skalar des Servers. Er kommt aus der Umgebung und
    /// wird von hier an ausschliesslich als [`ea_crypto::SecretBytes`]
    /// weitergereicht — nie als `String`, den ein `Debug` mitdruckte.
    pub server_signing_key: ea_crypto::SecretBytes<32>,
    pub server_certificate_hash: ea_types::CertificateHash,
    pub server_key_generation: u32,
    pub tls_certificate_path: PathBuf,
    pub tls_private_key_path: PathBuf,
    pub database_url: String,
    pub migrations_directory: PathBuf,
    pub object_store: ObjectStoreConfig,
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    std::env::var(name).map_err(|_| ConfigError::Missing(name))
}

fn optional(name: &'static str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

/// Eine Bytefolge FESTER Laenge aus Kleinbuchstaben-Hex.
///
/// Die Laenge ist Teil des Formats und keine Meinung: ein zu kurzer Schluessel
/// ist kein kuerzerer Schluessel, sondern ein Konfigurationsfehler.
fn fixed_hex<const N: usize>(name: &'static str) -> Result<[u8; N], ConfigError> {
    let mut bytes = [0_u8; N];
    hex::decode_to_slice(required(name)?, &mut bytes).map_err(|_| ConfigError::Invalid(name))?;
    Ok(bytes)
}

impl ServerConfiguration {
    /// Liest die Konfiguration aus der Umgebung — vollstaendig oder gar nicht.
    pub fn from_environment() -> Result<Self, ConfigError> {
        Ok(Self {
            bind_address: optional(ENV_BIND_ADDRESS, "127.0.0.1:8443"),
            sync_authority: required(ENV_SYNC_AUTHORITY)?,
            organization_id: ea_types::OrganizationId::try_from(
                &fixed_hex::<16>(ENV_ORGANIZATION_ID)?[..],
            )
            .map_err(|_| ConfigError::Invalid(ENV_ORGANIZATION_ID))?,
            server_signing_key: ea_crypto::SecretBytes::new(fixed_hex::<32>(
                ENV_SERVER_SIGNING_KEY,
            )?),
            server_certificate_hash: ea_types::CertificateHash::try_from(
                &fixed_hex::<32>(ENV_SERVER_CERTIFICATE_HASH)?[..],
            )
            .map_err(|_| ConfigError::Invalid(ENV_SERVER_CERTIFICATE_HASH))?,
            server_key_generation: optional(ENV_SERVER_KEY_GENERATION, "1")
                .parse()
                .map_err(|_| ConfigError::Invalid(ENV_SERVER_KEY_GENERATION))?,
            tls_certificate_path: PathBuf::from(required(ENV_TLS_CERTIFICATE)?),
            tls_private_key_path: PathBuf::from(required(ENV_TLS_PRIVATE_KEY)?),
            database_url: required(ENV_DATABASE_URL)?,
            migrations_directory: PathBuf::from(optional(ENV_MIGRATIONS_DIRECTORY, "migrations")),
            object_store: ObjectStoreConfig {
                endpoint_url: required(ENV_OBJECT_STORE_ENDPOINT)?,
                region: optional(ENV_OBJECT_STORE_REGION, "us-east-1"),
                bucket: optional(ENV_OBJECT_STORE_BUCKET, "einsatzarchiv-objects"),
                access_key_id: required(ENV_OBJECT_STORE_ACCESS_KEY_ID)?,
                secret_access_key: required(ENV_OBJECT_STORE_SECRET_ACCESS_KEY)?,
            },
        })
    }

    /// Die TLS-Konfiguration dieses Servers.
    pub fn tls(&self) -> Result<Arc<ServerConfig>, ConfigError> {
        tls_server_config(&self.tls_certificate_path, &self.tls_private_key_path)
    }
}

/// Baut die EINE TLS-Konfiguration dieses Servers: TLS 1.3 und sonst nichts.
///
/// Ohne Klientenzertifikat: die Aufrufer authentisieren sich nach RFC 9421 auf
/// der Anwendungsschicht (`design.md` §13.1), nicht ueber mTLS.
pub fn tls_server_config(
    certificate_path: &std::path::Path,
    private_key_path: &std::path::Path,
) -> Result<Arc<ServerConfig>, ConfigError> {
    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(certificate_path)
            .map_err(|_| ConfigError::Invalid(ENV_TLS_CERTIFICATE))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConfigError::Invalid(ENV_TLS_CERTIFICATE))?;
    if certificates.is_empty() {
        return Err(ConfigError::Invalid(ENV_TLS_CERTIFICATE));
    }
    let key = PrivateKeyDer::from_pem_file(private_key_path)
        .map_err(|_| ConfigError::Invalid(ENV_TLS_PRIVATE_KEY))?;

    // Die Versionsmenge ist EINELEMENTIG. Sie steht hier ausgeschrieben und
    // nicht als „alles ausser TLS 1.2“: eine Aufzaehlung dessen, was gilt,
    // kann nicht versehentlich um etwas Aelteres wachsen.
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(ConfigError::Tls)?
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .map_err(ConfigError::Tls)?;
    // HTTP/2 zuerst, HTTP/1.1 als Rueckfall — beides sind die Merkmale, die
    // ADR 0004 an Axum freigeschaltet hat.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
