//! Der Einstiegspunkt des Sync-Servers.
//!
//! Er tut vier Dinge und nichts sonst: Konfiguration lesen, die eine Migration
//! anwenden, den TLS-Lauscher binden, bedienen. Jeder Schritt ist fail-closed —
//! faellt einer aus, startet der Server NICHT und laeuft insbesondere nicht
//! ohne TLS weiter.

#![forbid(unsafe_code)]

use std::path::Path;

use einsatzarchiv_server::{
    config::ServerConfiguration,
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

    let listener = TlsListener::bind(&configuration.bind_address, tls).await?;
    serve(listener, router()).await?;
    Ok(())
}
