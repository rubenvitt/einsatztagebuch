//! Der Lauscher und die Routentafel.
//!
//! Es gibt GENAU EINEN Weg in diesen Server, und er fuehrt durch
//! [`TlsListener`]: einen TCP-Lauscher, hinter dem sofort der
//! `tokio_rustls::TlsAcceptor` mit der Konfiguration aus
//! [`crate::config`] steht. Ein Klartext-Lauscher existiert nicht — auch nicht
//! hinter einem Schalter, weil ein Schalter irgendwann umgelegt wird.
//!
//! Die Routentafel traegt GENAU die fuenf Endpunkte, die es heute gibt. Die
//! uebrigen zwoelf der siebzehn aus `design.md` §13.2 sind NICHT gemountet —
//! ein nicht gemounteter Endpunkt antwortet mit `404` und kann nicht
//! versehentlich halb fertig erreichbar sein.

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use ea_sync_protocol::EndpointV1;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::http::{AppState, challenges, device_registrations, trust, webauthn_credentials};

/// Die Routentafel des Servers.
///
/// Kein JSON-Extraktor: das Merkmal `json` ist an Axum ABGESCHALTET
/// (ADR 0004), damit neben dem deterministischen CBOR des Protokolls kein
/// zweiter, ungepruefter Dekodierweg in den Server fuehrt. Die Pfade stehen
/// nicht als Zeichenketten hier, sondern kommen aus
/// [`EndpointV1::path_template`] — eine abweichende Route waere sonst ein
/// Tippfehler, den nur ein Klient bemerkte.
pub fn router(state: Arc<AppState>) -> Router {
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
            EndpointV1::TrustRegistry.path_template(),
            get(trust::list_trust_registry),
        )
        .route(
            EndpointV1::TrustEvents.path_template(),
            post(trust::upload_trust_event),
        )
        .with_state(state)
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

/// Bedient den Router auf dem TLS-Lauscher, bis das Abschaltsignal kommt.
pub async fn serve(listener: TlsListener, router: Router) -> Result<(), std::io::Error> {
    axum::serve(listener, router)
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
