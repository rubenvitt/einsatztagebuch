//! Der HTTPS-Transport haengt nicht.
//!
//! `HyperTlsTransport` hatte keinen Zeitgeber: eine Gegenstelle, die die
//! TCP-Verbindung annimmt und danach schweigt, liess den Push so lange stehen,
//! bis das Betriebssystem von sich aus aufgab — Minuten, in denen der Anwender
//! einen Vorgang sieht, der nichts tut. `TransportErrorV1::Timeout` war
//! dadurch eine Variante, die kein Weg je erreichte.
//!
//! Der Zeuge braucht KEINEN TLS-Server: er braucht genau die Gegenstelle, die
//! das Problem war. Sie nimmt an und schweigt, der TLS-Aufbau kommt nie
//! zustande, und der Deckel entscheidet.
//!
//! Der Fall laeuft in ECHTZEIT und dauert damit
//! [`ea_sync_client::CONNECT_TIMEOUT_MS_V1`]. Eine angehaltene Laufzeituhr
//! (`tokio`s `start_paused`) braeuchte das Merkmal `test-util`, und ein
//! Merkmal an der Laufzeit des ganzen Arbeitsbereichs anzuschalten, damit ein
//! Testfall zehn Sekunden schneller ist, waere der falsche Handel.

use std::time::{Duration, Instant};

use ea_sync_client::{SyncTransportV1 as _, TransportErrorV1, TransportRequestV1};
use ea_sync_protocol::HttpMethod;

/// Eine Gegenstelle, die annimmt und danach schweigt, laeuft in den Deckel.
///
/// Gemessen wird BEIDES: dass der Befund `Timeout` ist, und dass er vom
/// eigenen Deckel kommt und nicht vom Zeitgeber des Betriebssystems — sonst
/// belegte der Fall nur, dass irgendwann irgendetwas aufgibt.
#[tokio::test]
async fn a_silent_peer_ends_in_a_timeout_and_not_in_a_hang() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding a loopback listener must succeed");
    let address = listener
        .local_addr()
        .expect("a bound listener has an address");
    // Angenommen und dann geschwiegen. Die Verbindung wird ABSICHTLICH
    // gehalten: ein sofortiges Schliessen waere ein anderer Befund.
    let silent = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let transport = ea_sync_client::HyperTlsTransport::new(
        address,
        "localhost".to_owned(),
        rustls::RootCertStore::empty(),
    )
    .expect("an empty root store still builds a client config");

    let started = Instant::now();
    let error = transport
        .send(TransportRequestV1 {
            method: HttpMethod::Post,
            target: "/v1/auth/challenges".to_owned(),
            authority: "localhost".to_owned(),
            content_type: None,
            headers: Vec::new(),
            body: Vec::new(),
            nonce: [0; 32],
        })
        .await
        .expect_err("a silent peer never answers");
    let elapsed = started.elapsed();

    assert_eq!(
        error,
        TransportErrorV1::Timeout,
        "the transport must give up on its own instead of hanging"
    );
    assert!(
        elapsed < Duration::from_millis(ea_sync_client::CONNECT_TIMEOUT_MS_V1 * 3),
        "the deadline fired, not the operating system: {elapsed:?}"
    );

    silent.abort();
}

/// Die beiden Deckel stehen als benannte Konstanten und sind es wert, gepinnt
/// zu werden: ein versehentliches Nullsetzen machte jeden Request sofort zum
/// Timeout, ein versehentliches Hochsetzen brachte den Haenger zurueck. Der
/// Aufbau muss dabei frueher aufgeben als der ganze Umlauf — sonst waere der
/// Aufbaudeckel wirkungslos.
#[test]
fn the_transport_deadlines_are_named_and_bounded() {
    assert_eq!(ea_sync_client::CONNECT_TIMEOUT_MS_V1, 10_000);
    assert_eq!(ea_sync_client::REQUEST_TIMEOUT_MS_V1, 60_000);
    assert!(
        std::hint::black_box(ea_sync_client::CONNECT_TIMEOUT_MS_V1)
            < std::hint::black_box(ea_sync_client::REQUEST_TIMEOUT_MS_V1)
    );
}
