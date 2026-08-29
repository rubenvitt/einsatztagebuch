//! Zwei Fehlerpunkte, die fail-closed antworten MUESSEN.
//!
//! Beide Faelle sind spaeter als Szenarien `tls-downgrade` und
//! `cursor-key-rotation` an dieses Ziel gebunden. Sie stehen zusammen, weil sie
//! dieselbe Frage stellen: Was tut der Server, wenn eine Gegenstelle etwas
//! Aelteres oder etwas Abgelaufenes vorlegt? Die Antwort ist beide Male
//! „nichts, und zwar mit einem stabilen Befund“.

mod common;

use std::sync::Arc;

use ea_crypto::SecretBytes;
use ea_sync_protocol::{
    EndpointV1, TechnicalCursorFieldsV1, TechnicalCursorScopeV1, TechnicalCursorV1,
};
use ea_types::{CertificateHash, Id16, ObjectHash, OrganizationId, UnixMillis};
use einsatzarchiv_server::{
    adapters::server_keys::ServerKeyStore,
    config::tls_server_config,
    router::{TlsListener, serve},
};
use rustls::pki_types::pem::PemObject as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Ein handgeschriebener TLS-1.2-ClientHello.
///
/// Er MUSS von Hand kommen: `rustls` ist ohne das Merkmal `tls12` gepinnt
/// (ADR 0004), also kann kein Klient dieses Arbeitsbereichs TLS 1.2 ueberhaupt
/// anbieten — und das Merkmal einzuschalten, nur um es zu pruefen, hoebe genau
/// die Eigenschaft auf, um die es geht.
///
/// Der Rahmen ist ein `handshake`-Record (0x16) mit Record-Version 0x0303 und
/// einer `client_hello`-Nachricht (0x01), deren `client_version` 0x0303 ist —
/// TLS 1.2. Es gibt KEINE `supported_versions`-Erweiterung; ohne sie kann ein
/// TLS-1.3-Server die Aushandlung gar nicht auf 1.3 heben.
fn tls12_client_hello() -> Vec<u8> {
    let mut hello = Vec::new();
    // client_version = TLS 1.2
    hello.extend_from_slice(&[0x03, 0x03]);
    // random (32 Byte, fest — er traegt hier keine Sicherheitslast)
    hello.extend_from_slice(&[0x2a; 32]);
    // legacy_session_id: leer
    hello.push(0x00);
    // cipher_suites: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    hello.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]);
    // compression_methods: nur `null`
    hello.extend_from_slice(&[0x01, 0x00]);

    // Erweiterungen: nur server_name, ausdruecklich OHNE supported_versions.
    let mut extensions = Vec::new();
    let host = b"localhost";
    let mut server_name = Vec::new();
    server_name.extend_from_slice(&u16::try_from(host.len() + 3).unwrap_or(0).to_be_bytes());
    server_name.push(0x00);
    server_name.extend_from_slice(&u16::try_from(host.len()).unwrap_or(0).to_be_bytes());
    server_name.extend_from_slice(host);
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&u16::try_from(server_name.len()).unwrap_or(0).to_be_bytes());
    extensions.extend_from_slice(&server_name);
    hello.extend_from_slice(&u16::try_from(extensions.len()).unwrap_or(0).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = vec![0x01];
    let length = u32::try_from(hello.len()).unwrap_or(0).to_be_bytes();
    handshake.extend_from_slice(&length[1..]);
    handshake.extend_from_slice(&hello);

    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&u16::try_from(handshake.len()).unwrap_or(0).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Szenario `tls-downgrade`.
///
/// Der von `config.rs` konfigurierte Lauscher bekommt einen ClientHello, der
/// ausschliesslich TLS 1.2 anbietet. Erwartet wird: KEIN ServerHello. Entweder
/// schickt der Server einen fatalen Alert-Record (0x15) oder er schliesst die
/// Verbindung. Beides ist fail-closed; was NICHT passieren darf, ist ein
/// Handshake-Record (0x16) mit Nachrichtentyp `server_hello` (0x02).
#[tokio::test(flavor = "multi_thread")]
async fn a_tls12_only_client_handshake_is_rejected() {
    install_crypto_provider();
    let (certificate, key) = common::write_test_tls_material();
    let tls = tls_server_config(&certificate, &key).expect("the test TLS material must load");
    let listener = TlsListener::bind("127.0.0.1:0", tls)
        .await
        .expect("binding the loopback listener must succeed");
    let address = listener
        .local_address()
        .expect("the bound address must be readable");
    let server = tokio::spawn(async move {
        // Eine LEERE Routentafel: dieser Fall entscheidet sich im
        // TLS-Handschlag und erreicht nie eine Route. Der echte Router
        // verlangte einen vollstaendigen `AppState` samt Datenbank und Object
        // Store, und der bewiese hier nichts.
        let _ = serve(listener, axum::Router::new()).await;
    });

    let mut stream = TcpStream::connect(address)
        .await
        .expect("the listener must accept the connection");
    stream
        .write_all(&tls12_client_hello())
        .await
        .expect("writing the ClientHello must succeed");
    stream.flush().await.expect("flushing must succeed");

    let mut response = [0_u8; 16];
    let read = stream.read(&mut response).await.unwrap_or(0);

    // GEMESSEN, nicht erinnert: `rustls` antwortet mit einem Alert-Record
    // (0x15) der Record-Version 0x0303, Laenge 2, Stufe `fatal` (0x02) und
    // Beschreibung 40 (`handshake_failure`). Das ist die stabile Antwort, die
    // das Szenario `tls-downgrade` festhaelt.
    assert_eq!(
        &response[..read],
        &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28],
        "a TLS 1.2 only client must get a fatal handshake_failure alert and never a ServerHello \
         (design.md:1497 makes TLS 1.3 a Global Constraint)"
    );
    assert_ne!(
        response[0], 0x16,
        "the answer must not be a handshake record; there is no ServerHello for TLS 1.2"
    );

    server.abort();
}

/// Positivkontrolle zum Szenario darueber.
///
/// Ohne sie bewiese die Abweisung nichts: ein Lauscher, der ueberhaupt keinen
/// Handschlag fuehren kann, weist einen TLS-1.2-Klienten genauso ab. Hier
/// spricht ein echter `rustls`-Klient — der dieses Arbeitsbereichs, also
/// zwingend TLS 1.3 — und bekommt seinen Handschlag.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_listener_completes_a_tls13_handshake() {
    install_crypto_provider();
    let (certificate, key) = common::write_test_tls_material();
    let tls = tls_server_config(&certificate, &key).expect("the test TLS material must load");
    let listener = TlsListener::bind("127.0.0.1:0", tls)
        .await
        .expect("binding the loopback listener must succeed");
    let address = listener
        .local_address()
        .expect("the bound address must be readable");
    let server = tokio::spawn(async move {
        // Eine LEERE Routentafel: dieser Fall entscheidet sich im
        // TLS-Handschlag und erreicht nie eine Route. Der echte Router
        // verlangte einen vollstaendigen `AppState` samt Datenbank und Object
        // Store, und der bewiese hier nichts.
        let _ = serve(listener, axum::Router::new()).await;
    });

    // Vertraut wird der TEST-CA, nicht dem Blatt: ein selbstsigniertes Blatt
    // im Wurzelspeicher weist `rustls` mit `CaUsedAsEndEntity` ab.
    let mut roots = rustls::RootCertStore::empty();
    for anchor in
        rustls::pki_types::CertificateDer::pem_slice_iter(common::TEST_TLS_CA_PEM.as_bytes())
    {
        roots
            .add(anchor.expect("the test CA must parse"))
            .expect("the test CA must be a valid anchor");
    }
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 must be available")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(address)
        .await
        .expect("the listener must accept the connection");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("a valid server name");
    let connected = connector.connect(name, stream).await;
    assert!(
        connected.is_ok(),
        "a TLS 1.3 client must complete the handshake against the very listener that refuses \
         TLS 1.2; otherwise the refusal above proves nothing: {:?}",
        connected.err()
    );

    server.abort();
}

/// Szenario `cursor-key-rotation`.
///
/// Ein technischer Cursor, der unter der VORIGEN Serverschluesselgeneration
/// ausgestellt wurde, oeffnet nach der Rotation nicht mehr — mit dem stabilen
/// Code `EA-SYNC-CURSOR-INVALID`. Der Code verraet dem Klienten nichts ueber
/// die Rotation; er soll den Cursor ohnehin nicht deuten und blaettert neu an.
#[tokio::test]
async fn a_cursor_signed_under_the_previous_key_generation_fails_to_open() {
    let organization =
        OrganizationId::from(Id16::try_from(&[0x31_u8; 16][..]).expect("sixteen bytes"));
    let certificate =
        CertificateHash::from(ObjectHash::try_from(&[0x42_u8; 32][..]).expect("thirty two bytes"));

    let previous = ServerKeyStore::new(
        SecretBytes::new(std::array::from_fn(|index| {
            u8::try_from(index).unwrap_or(0)
        })),
        certificate,
        1,
    )
    .expect("the previous generation key must build");
    let rotated = ServerKeyStore::new(
        SecretBytes::new(std::array::from_fn(|index| {
            u8::try_from(index).unwrap_or(0).wrapping_add(0x80)
        })),
        certificate,
        2,
    )
    .expect("the rotated key must build");
    assert_eq!(previous.key_generation(), 1);
    assert_eq!(rotated.key_generation(), 2);

    let fields = TechnicalCursorFieldsV1 {
        organization_id: organization,
        endpoint: EndpointV1::Checkpoints,
        chain_id: None,
        start_head_entry_hash: None,
        last_technical_index: 17,
        expires_at: UnixMillis::new(2_000_000_000_000),
        nonce: [0x09; 16],
    };
    let scope = TechnicalCursorScopeV1 {
        organization_id: organization,
        endpoint: EndpointV1::Checkpoints,
        chain_id: None,
        start_head_entry_hash: None,
    };
    let now = UnixMillis::new(1_700_000_000_000);

    let cursor =
        TechnicalCursorV1::issue(&fields, &previous).expect("issuing under generation 1 works");

    // Positivkontrolle: unter DERSELBEN Generation oeffnet er.
    let reopened = TechnicalCursorV1::open(cursor.token_bytes(), &previous, now, &scope)
        .expect("the cursor must open under the generation that issued it");
    assert_eq!(reopened.last_technical_index(), 17);

    // Und nach der Rotation nicht mehr.
    let error = TechnicalCursorV1::open(cursor.token_bytes(), &rotated, now, &scope)
        .expect_err("a cursor of the previous key generation must not open after rotation");
    assert_eq!(error.code(), "EA-SYNC-CURSOR-INVALID");
}

use ea_sync_server::ServerSigner as _;

/// Der Anbieter wird je Testprozess genau einmal gesetzt; ein zweiter Versuch
/// ist kein Fehler.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
