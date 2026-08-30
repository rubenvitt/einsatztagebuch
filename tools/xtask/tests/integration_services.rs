//! Treibt `xtask integration` gegen die echten Integrationsdienste.
//!
//! `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md`:120-121
//! nennt PostgreSQL und einen S3-kompatiblen Object Store als die beiden
//! Serverdienste der Stufe 3. Ohne diesen Gate belegt nichts, dass die
//! beiden Dienste aus `ops/compose/integration.yaml` wirklich antworten;
//! `#[sqlx::test]` liest `DATABASE_URL` erst zur Laufzeit und scheitert sonst
//! im spaeteren Task mit einer Verbindungsmeldung statt hier mit einer
//! Anweisung.
//!
//! Diese Datei traegt bewusst GENAU EINEN Test. `cargo test` faehrt Tests
//! desselben Ziels nebenlaeufig, und zwei Tests, die gleichzeitig
//! `docker compose up` und `down` riefen, wuerden einander die Dienste unter
//! den Fuessen wegziehen.

use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    process::Command,
    time::Duration,
};

/// Kurz genug, dass ein fehlender Dienst schnell auffaellt, und lang genug fuer
/// einen frisch gestarteten Container auf einem belasteten Rechner.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Ruft das gebaute `xtask`-Binaer und trennt Erfolg von Fehlermeldung.
///
/// `main` schreibt jeden Fehler als `xtask: {error}` nach stderr und beendet
/// sich mit 2; das Praefix wird hier abgeschnitten, damit der Test den
/// Wortlaut der Fehlermeldung selbst pruefen kann.
fn run_gate<const N: usize>(args: [&str; N]) -> Result<String, String> {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask must start");
    let stdout = String::from_utf8(output.stdout).expect("xtask stdout must be UTF-8");
    if output.status.success() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8(output.stderr).expect("xtask stderr must be UTF-8");
    Err(stderr
        .lines()
        .find_map(|line| line.strip_prefix("xtask: "))
        .unwrap_or_else(|| panic!("xtask must report its failure on stderr: {stderr}"))
        .to_owned())
}

/// Liest eine der beiden `export`-Zeilen aus der Ausgabe von `integration up`.
///
/// Ein Kindprozess kann die Umgebung seines Aufrufers nicht setzen, deshalb ist
/// die gedruckte, mit `eval` verwendbare Zeile der Vertrag — nicht ein
/// `env::var` im Testprozess, das nur belegte, dass der Test sich selbst
/// gesetzt hat, was er behauptet zu pruefen.
fn exported(output: &str, name: &str) -> String {
    let prefix = format!("export {name}=");
    output
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("integration up must export {name}; output was:\n{output}"))
        .to_owned()
}

/// Loest `host:port` aus einer URL und oeffnet eine TCP-Verbindung mit Frist.
fn connect(authority: &str) -> Option<TcpStream> {
    let address = authority
        .to_socket_addrs()
        .ok()?
        .next()
        .expect("the integration endpoints resolve to at least one address");
    let stream = TcpStream::connect_timeout(&address, PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;
    Some(stream)
}

/// Schneidet `host:port` aus `postgres://user:pass@host:port/db`.
fn authority_of(url: &str) -> String {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let after_credentials = without_scheme
        .rsplit_once('@')
        .map_or(without_scheme, |(_, rest)| rest);
    after_credentials
        .split(['/', '?'])
        .next()
        .expect("split always yields a first element")
        .to_owned()
}

/// Belegt, dass am Ende der Verbindung wirklich PostgreSQL spricht.
///
/// Ein offener Port allein belegt nichts: Docker bindet die Weiterleitung,
/// bevor der Server bereit ist. Der SSLRequest aus dem PostgreSQL-Frontend-
/// Protokoll (Laenge 8, Code 80877103) ist die kuerzeste Anfrage, die ein
/// echter Server beantwortet — mit genau einem Byte, `S` oder `N`.
fn postgres_is_reachable(url: &str) -> bool {
    let Some(mut stream) = connect(&authority_of(url)) else {
        return false;
    };
    let mut request = [0u8; 8];
    request[..4].copy_from_slice(&8u32.to_be_bytes());
    request[4..].copy_from_slice(&80_877_103u32.to_be_bytes());
    if stream.write_all(&request).is_err() {
        return false;
    }
    let mut answer = [0u8; 1];
    stream.read_exact(&mut answer).is_ok() && matches!(answer[0], b'S' | b'N')
}

/// Belegt, dass der Object Store seine Bereitschaft selbst bestaetigt.
///
/// MinIO beantwortet `GET /minio/health/live` ohne Anmeldedaten; die
/// Statuszeile wird gelesen, nicht nur die Verbindung.
fn object_store_is_reachable(endpoint: &str) -> bool {
    let authority = authority_of(endpoint);
    let Some(mut stream) = connect(&authority) else {
        return false;
    };
    let request = format!(
        "GET /minio/health/live HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut answer = Vec::new();
    if stream.read_to_end(&mut answer).is_err() {
        return false;
    }
    String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200")
}

#[test]
fn integration_up_is_idempotent_and_exports_both_endpoints() {
    let first = run_gate(["integration", "up"]).expect("integration up must succeed");
    let second = run_gate(["integration", "up"]).expect("integration up must be idempotent");
    assert_eq!(
        first, second,
        "integration up must export the same endpoints on every run"
    );

    let database_url = exported(&second, "DATABASE_URL");
    let object_store_endpoint = exported(&second, "EA_OBJECT_STORE_ENDPOINT");
    assert!(
        postgres_is_reachable(&database_url),
        "PostgreSQL must answer at {database_url}"
    );
    assert!(
        object_store_is_reachable(&object_store_endpoint),
        "the object store must answer at {object_store_endpoint}"
    );

    // Die Argumentgrammatik des NEUEN Arms, nicht `unknown gate: integration`:
    // sobald der Arm existiert, kann der Verteiler ihn nicht mehr als
    // unbekannt melden. Der Wortlaut folgt dem bestehenden Muster
    // `{gate} does not accept arguments` in `tools/xtask/src/main.rs`.
    assert_eq!(
        run_gate(["integration", "sideways"]).unwrap_err(),
        "integration accepts exactly one of: up, down"
    );
    assert_eq!(
        run_gate(["integration"]).unwrap_err(),
        "integration accepts exactly one of: up, down"
    );
    assert_eq!(
        run_gate(["integration", "up", "down"]).unwrap_err(),
        "integration accepts exactly one of: up, down"
    );
}
