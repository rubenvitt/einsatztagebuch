//! Der Lauscher und die Routentafel.
//!
//! Es gibt GENAU EINEN Weg in diesen Server, und er fuehrt durch
//! [`TlsListener`]: einen TCP-Lauscher, hinter dem sofort der
//! `tokio_rustls::TlsAcceptor` mit der Konfiguration aus
//! [`crate::config`] steht. Ein Klartext-Lauscher existiert nicht — auch nicht
//! hinter einem Schalter, weil ein Schalter irgendwann umgelegt wird.
//!
//! Die Routentafel traegt GENAU die siebzehn Endpunkte aus `design.md` §13.2 —
//! seit dieser Aufgabe vollstaendig.
//!
//! # Die eine signaturfreie Routenzeile
//!
//! `POST /v1/vault-blobs/retrievals` steht ausdruecklich SEPARAT
//! (`web-reader-design.md` §6.4.1, :213-216): der Browser, der ihn ruft, hat
//! seinen Vault noch nicht entsperrt und kommt deshalb an seinen
//! Ed25519-Schluessel gar nicht heran. Sein Handler ruft
//! [`ea_sync_server::auth::authenticate`] NICHT — und weil dieser Server
//! innerhalb der Handler authentisiert und nicht in einer vorgelagerten
//! Schicht, IST das bereits der Zweig ohne Pruefer und ohne
//! `AuthenticatedDevice`-Extraktor. Es gibt keine Schicht, an der
//! vorbeigeroutet werden muesste, und deshalb auch keine, die jemand
//! versehentlich fuer diesen Pfad abschalten koennte.
//!
//! Das ist NICHT die anders geroutete Geraeteregistrierung: die ist mit dem
//! BEANTRAGTEN Schluessel signiert und liefert
//! `AuthenticatedDevice::ProofOfPossession`. Hier existiert ueberhaupt keine
//! Geraeteidentitaet.
//!
//! # Die CORS-Schicht
//!
//! Sie liegt ueber dem GESAMTEN Router (`crate::cors`), sieht den Request also
//! vor der Wegwahl und kann den Vorabflug beantworten; eine `OPTIONS`-Route
//! gibt es nicht.

use std::sync::Arc;

use axum::{
    Router,
    extract::connect_info::Connected,
    routing::{get, post, put},
};
use ea_sync_protocol::EndpointV1;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::{
    config::WebOriginPolicy,
    cors::apply_cors,
    http::{
        AppState, challenges, checkpoints, destructions, device_registrations, entries,
        entry_commits, exports, grants, objects, reader_acks, trust, vault_blobs,
        webauthn_credentials,
    },
};

/// Die Routentafel des Servers.
///
/// Kein JSON-Extraktor: das Merkmal `json` ist an Axum ABGESCHALTET
/// (ADR 0004), damit neben dem deterministischen CBOR des Protokolls kein
/// zweiter, ungepruefter Dekodierweg in den Server fuehrt. Die Pfade stehen
/// nicht als Zeichenketten hier, sondern kommen aus
/// [`EndpointV1::path_template`] — eine abweichende Route waere sonst ein
/// Tippfehler, den nur ein Klient bemerkte.
pub fn router(state: Arc<AppState>, web_origins: Arc<WebOriginPolicy>) -> Router {
    Router::new()
        .route(
            EndpointV1::AuthChallenges.path_template(),
            post(challenges::create_challenge),
        )
        .route(
            EndpointV1::DeviceRegistrations.path_template(),
            post(device_registrations::create_device_registration),
        )
        .route(
            EndpointV1::WebauthnCredentials.path_template(),
            post(webauthn_credentials::register_credential),
        )
        .route(
            EndpointV1::VaultBlobs.path_template(),
            put(vault_blobs::put_vault_blob),
        )
        // Die eine signaturfreie Zeile. Ihr Handler ruft `authenticate` nicht.
        .route(
            EndpointV1::VaultBlobRetrievals.path_template(),
            post(vault_blobs::create_vault_blob_retrieval),
        )
        .route(
            EndpointV1::TrustRegistry.path_template(),
            get(trust::list_trust_registry),
        )
        .route(
            EndpointV1::TrustEvents.path_template(),
            post(trust::upload_trust_event),
        )
        .route(
            EndpointV1::EntryCommits.path_template(),
            post(entry_commits::create_entry_commit),
        )
        .route(
            EndpointV1::Checkpoints.path_template(),
            get(checkpoints::list_checkpoints),
        )
        .route(
            EndpointV1::ChainEntries.path_template(),
            get(entries::list_chain_entries),
        )
        .route(
            EndpointV1::Objects.path_template(),
            get(objects::read_object),
        )
        .route(
            EndpointV1::HistoricalGrants.path_template(),
            post(grants::create_historical_grant),
        )
        .route(
            EndpointV1::EntryGrants.path_template(),
            get(grants::list_entry_grants),
        )
        .route(
            EndpointV1::ReaderAcks.path_template(),
            post(reader_acks::create_reader_ack),
        )
        .route(
            EndpointV1::ArchiveExports.path_template(),
            get(exports::read_current_export),
        )
        .route(
            EndpointV1::Destructions.path_template(),
            post(destructions::create_destruction),
        )
        .route(
            EndpointV1::DestructionStatus.path_template(),
            get(destructions::read_destruction),
        )
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            web_origins,
            apply_cors,
        ))
}

/// Ein Lauscher, der ausschliesslich TLS-Verbindungen herausgibt.
///
/// `axum::serve::Listener::accept` darf keinen Fehler zurueckgeben, also wird
/// hier geschleift: ein gescheiterter Handschlag — etwa der eines Klienten, der
/// nur TLS 1.2 anbietet — verwirft die Verbindung und der Lauscher wartet
/// weiter. Genau das ist die fail-closed Antwort: der Klient bekommt keinen
/// ServerHello, und der Server bleibt stehen.
pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    #[must_use]
    pub fn new(listener: TcpListener, tls: Arc<ServerConfig>) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(tls),
        }
    }

    /// Bindet die Adresse und legt den TLS-Abnehmer davor.
    pub async fn bind(address: &str, tls: Arc<ServerConfig>) -> Result<Self, std::io::Error> {
        Ok(Self::new(TcpListener::bind(address).await?, tls))
    }

    /// Die tatsaechlich gebundene Adresse — der Testfall braucht den Port, den
    /// das Betriebssystem vergeben hat.
    pub fn local_address(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((stream, address)) = self.listener.accept().await else {
                continue;
            };
            if let Ok(stream) = self.acceptor.accept(stream).await {
                return (stream, address);
            }
            // Handschlag gescheitert. KEINE Rueckfallebene, kein zweiter
            // Versuch mit einer aelteren Version — die gibt es nicht.
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// Die Gegenstellenadresse einer Verbindung.
///
/// Sie ist die einzige Identitaet, die ein UNSIGNIERTER Request mitbringt, die
/// er nicht selbst behaupten kann: sie entsteht aus dem TCP-Handschlag und
/// nicht aus dem Koerper. Der Challenge-Endpunkt haengt seine Ratenbegrenzung
/// daran (`crates/ea-sync-server/src/auth.rs`).
///
/// Axum liefert `SocketAddr` als `ConnectInfo` nur fuer seinen eigenen
/// `TcpListener`; fuer [`TlsListener`] muss die Bruecke hier stehen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerAddress(pub std::net::SocketAddr);

impl Connected<axum::serve::IncomingStream<'_, TlsListener>> for PeerAddress {
    fn connect_info(stream: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

/// Bedient den Router auf dem TLS-Lauscher, bis das Abschaltsignal kommt.
pub async fn serve(listener: TlsListener, router: Router) -> Result<(), std::io::Error> {
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<PeerAddress>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
}

/// Das geordnete Abschalten: `SIGTERM` im Container, `Ctrl-C` von Hand.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
