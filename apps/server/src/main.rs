//! Der Einstiegspunkt des Sync-Servers.
//!
//! Er tut vier Dinge und nichts sonst: Konfiguration lesen, die eine Migration
//! anwenden, den TLS-Lauscher binden, bedienen. Jeder Schritt ist fail-closed —
//! faellt einer aus, startet der Server NICHT und laeuft insbesondere nicht
//! ohne TLS weiter.

#![forbid(unsafe_code)]

use std::{path::Path, sync::Arc};

use einsatzarchiv_server::{
    adapters::{
        clock::SystemClock, postgres::PostgresRepository, s3::S3ObjectStore,
        server_keys::ServerKeyStore, trust_authority::PostgresTrustAuthority,
    },
    config::ServerConfiguration,
    http::AppState,
    router::{TlsListener, router, serve},
};
use sqlx::postgres::PgPoolOptions;
use sqlx_core::migrate::Migrator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Der Kryptographieanbieter wird EINMAL und ausdruecklich gesetzt: `ring`,
    // wie ADR 0004 ihn fuer die ganze Klasse ausgewaehlt hat. Ohne diese Zeile
    // entschiede die Verfuegbarkeit von Merkmalen, welcher Anbieter greift.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "the ring crypto provider must install exactly once")?;

    let configuration = ServerConfiguration::from_environment()?;
    let tls = configuration.tls()?;

    let pool = PgPoolOptions::new()
        .connect(&configuration.database_url)
        .await?;
    Migrator::new(Path::new(&configuration.migrations_directory))
        .await?
        .run(&pool)
        .await?;

    // Die Verdrahtung: jeder Port bekommt genau einen Adapter, und der Handler
    // sieht nur den Port. Sie steht HIER und nicht in der Bibliothek, weil sie
    // die einzige Stelle ist, an der eine Betriebsentscheidung — welcher
    // Object Store, welche Uhr, welcher Schluessel — getroffen wird.
    let clock = Arc::new(SystemClock);
    let repository = Arc::new(PostgresRepository::new(pool.clone()));
    let signer = Arc::new(ServerKeyStore::new(
        configuration.server_signing_key,
        configuration.server_certificate_hash,
        configuration.server_key_generation,
    )?);
    let http_client = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https();
    let s3 = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .http_client(http_client)
        .region(aws_sdk_s3::config::Region::new(
            configuration.object_store.region.clone(),
        ))
        .endpoint_url(configuration.object_store.endpoint_url.clone())
        .force_path_style(true)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            configuration.object_store.access_key_id.clone(),
            configuration.object_store.secret_access_key.clone(),
            None,
            None,
            "einsatzarchiv-server",
        ))
        .build();
    let objects = Arc::new(S3ObjectStore::new(
        aws_sdk_s3::Client::from_conf(s3),
        configuration.object_store.bucket.clone(),
        configuration.organization_id,
        repository.clone(),
        repository.clone(),
        clock.clone(),
    ));
    let state = Arc::new(AppState {
        authority: configuration.sync_authority.clone(),
        clock,
        signer,
        objects: objects.clone(),
        repository: repository.clone(),
        trust_authority: Arc::new(PostgresTrustAuthority::new(pool.clone(), objects)),
    });

    let listener = TlsListener::bind(&configuration.bind_address, tls).await?;
    serve(listener, router(state)).await?;
    Ok(())
}
