//! Der Lauscher und die Routentafel.
//!
//! Es gibt GENAU EINEN Weg in diesen Server, und er fuehrt durch
//! [`TlsListener`]: einen TCP-Lauscher, hinter dem sofort der
//! `tokio_rustls::TlsAcceptor` mit der Konfiguration aus
//! [`crate::config`] steht. Ein Klartext-Lauscher existiert nicht — auch nicht
//! hinter einem Schalter, weil ein Schalter irgendwann umgelegt wird.
//!
//! Die Routentafel ist in dieser Stufe noch leer: die siebzehn Endpunkte aus
//! `design.md` §13.2 entstehen in den folgenden Tasks. Was hier steht, ist die
//! Klammer, in die sie kommen.

use std::sync::Arc;

use axum::Router;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

/// Die Routentafel des Servers.
///
/// Noch ohne Endpunkte, aber schon mit der Zusage, die sie tragen: kein
/// JSON-Extraktor. Das Merkmal `json` ist an Axum ABGESCHALTET (ADR 0004),
/// damit neben dem deterministischen CBOR des Protokolls kein zweiter,
/// ungeprueftear Dekodierweg in den Server fuehrt.
pub fn router() -> Router {
    Router::new()
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
