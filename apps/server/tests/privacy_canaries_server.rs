//! Die Kanarienvoegel des SERVERS: kein fachliches Zeichen taucht auf einer
//! serverbeobachtbaren Flaeche auf.
//!
//! # Der schlimmstmoegliche Fall, mit Absicht
//!
//! Der Server ist blind — er bewegt Chiffrat, das er nicht oeffnen kann. Ein
//! Kanarientest, der die Marker nur in den Klartext eines Writers legte, wuerde
//! deshalb NICHTS messen: sie kaemen nie beim Server an, und die Suche waere
//! auch dann gruen, wenn jede Flaeche des Servers leckte.
//!
//! Dieses Ziel dreht die Probe um. Die Marker liegen IM AUSGELIEFERTEN
//! CIPHERTEXT des Eintragspakets — so, als waere die Verschluesselung
//! durchsichtig. Der Server bekommt sie also wirklich geliefert, legt sie
//! wirklich in seinen Object Store, und die Zusage lautet: KEINE seiner
//! beobachtbaren Flaechen gibt sie wieder.
//!
//! # Die fuenf durchsuchten Flaechen
//!
//! 1. Jeder Wert in JEDER Tabelle der Datenbank — die Zeile wird von
//!    PostgreSQL selbst als Text gerendert (`SELECT t::text FROM t`), also
//!    sind Textspalten UND `bytea`-Spalten erfasst. Gesucht wird nach dem
//!    Marker UND nach seiner Hexdarstellung, weil `::text` `bytea` hexadezimal
//!    rendert.
//! 2. Jeder S3-SCHLUESSEL, jedes S3-TAG und jede S3-METADATENzeile.
//! 3. Jeder Fehlerkoerper, den der Server auf eine abgewiesene Anfrage
//!    zurueckgibt.
//! 4. Die Containerausgabe beider Integrationsdienste
//!    (`docker compose logs`).
//! 5. Der normativ festgelegte Labelsatz aus `ops/monitoring/metrics.md`.
//!
//! AUSDRUECKLICH NICHT durchsucht wird der KOERPER der abgelegten Objekte. Er
//! ist das ausgelieferte Archivobjekt, er traegt die Marker per Konstruktion,
//! und er ist fuer den Server undurchsichtig. Genau das macht ihn zur
//! Positivkontrolle dieser Datei.
//!
//! # Die drei Positivkontrollen
//!
//! Ohne sie waere die ganze Datei gruen, wenn die Marker nie in das System
//! gelangt waeren oder die Suche nichts taete:
//!
//! 1. Der Objektkoerper im Store TRAEGT jeden Marker — der Beleg, dass genau
//!    diese Bytes den Server erreicht haben.
//! 2. Ein in eine Textspalte gepflanzter Marker WIRD von der Datenbanksuche
//!    gefunden.
//! 3. Ein an ein Objekt gehaengtes Tag WIRD von der Tagsuche gefunden.

mod common;

use common::{archive_objects, trust_closure};
use ea_crypto::SecretBytes;
use ea_sync_protocol::{EndpointV1, ProtocolErrorV1, RequestSigner};
use ea_types::{CertificateHash, UnixMillis};
use sqlx::Row;

/// Innerhalb des `notBefore`/`notAfter`-Fensters aller Koepfe.
const SERVER_NOW_MILLIS: i64 = 1_000;
const SERVER_SECRET: [u8; 32] = [0x51; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];
const SEEDED_HEAD_ENTRY_HASH: [u8; 32] = [0x77; 32];
const SEEDED_HEAD_ACCEPTED_AT: i64 = 500;

/// Je fachliches Feld GENAU EIN eigener Marker.
///
/// Ein gemeinsamer Marker fuer zwei Felder liesse offen, welches von beiden
/// geleckt hat. Die Felder sind dieselben, die
/// `tests/ea-system-tests/tests/privacy_canaries_writer.rs` auf der
/// Writerseite saet; die Marker stehen hier NOCH EINMAL und werden nicht von
/// dort importiert, weil ein Integrationstestziel das Modul eines anderen
/// Pakets nicht erreichen kann — und weil eine gemeinsame Konstante beide
/// Seiten gleichzeitig blind machen koennte.
const CANARY_MARKERS: [(&str, &str); 9] = [
    ("keyword", "KANARIE-SRV-STICHWORT-7f3a"),
    ("location", "KANARIE-SRV-ORT-1c8d"),
    ("personnel", "KANARIE-SRV-PERSONAL-4b21"),
    ("vehicles", "KANARIE-SRV-FAHRZEUG-9e05"),
    ("external_organizations", "KANARIE-SRV-FREMDORG-2d77"),
    ("human_incident_number", "KANARIE-SRV-NUMMER-2026-000777"),
    ("notes", "KANARIE-SRV-FREITEXT-b512"),
    ("personnel_empty_reason", "KANARIE-SRV-GRUND-PERSONAL-3f60"),
    ("vehicles_empty_reason", "KANARIE-SRV-GRUND-FAHRZEUG-8c1e"),
];

/// Ein Ciphertext, der jeden Marker traegt.
///
/// Die Marker stehen durch `|` getrennt hintereinander; die Trennung haelt
/// zwei Marker davon ab, im Bytestrom zu einem dritten zu verschmelzen.
fn canary_ciphertext() -> Vec<u8> {
    let mut bytes = Vec::new();
    for (_, marker) in CANARY_MARKERS {
        bytes.extend_from_slice(marker.as_bytes());
        bytes.push(b'|');
    }
    bytes
}

/// Der Marker eines Feldes.
fn canary(field: &str) -> &'static str {
    CANARY_MARKERS
        .iter()
        .find(|(name, _)| *name == field)
        .map(|(_, marker)| *marker)
        .unwrap_or_else(|| panic!("{field} traegt keinen Marker"))
}

/// Ein Fund: die Flaeche und der Marker, der dort steht.
type Finding = (String, &'static str);

fn signer(seed: [u8; 32]) -> RequestSigner {
    RequestSigner::from_secret(SecretBytes::new(seed))
}

/// Ein Server auf dem fortgeschriebenen Vertrauensabschluss, wie ihn die
/// uebrigen Serverziele dieses Pakets aufbauen.
async fn stand_up(
    database: &common::TestDatabase,
) -> (common::TestServer, trust_closure::ExtendedClosure) {
    let fixture =
        common::seed_trust_fixture(database.pool(), trust_closure::ROTATION_CASE, &[]).await;
    let closure = trust_closure::build(false);
    assert!(closure.organization_id == fixture.organization_id);
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        closure.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;
    common::publish_closure(&server, &closure, &signer(trust_closure::ADMIN_SEED), 0).await;
    trust_closure::seed_chain_head(
        database.pool(),
        closure.organization_id,
        closure.chain_id,
        trust_closure::ExtendedClosure::seeded_head_sequence(),
        SEEDED_HEAD_ENTRY_HASH,
        SEEDED_HEAD_ACCEPTED_AT,
    )
    .await;
    (server, closure)
}

/// Rendert JEDE Zeile JEDER Basistabelle als Text.
///
/// Die Darstellung kommt von PostgreSQL selbst (`t::text`), nicht von einer
/// Spaltenliste dieses Tests: eine Spaltenliste, die eine spaetere Migration
/// nicht mitnimmt, waere genau die Luecke, durch die ein Wert unbemerkt
/// liefe. `bytea` erscheint darin hexadezimal, deshalb sucht
/// [`database_findings`] auch nach der Hexdarstellung des Markers.
async fn database_dump(pool: &sqlx::PgPool) -> Vec<(String, String)> {
    let tables: Vec<String> = sqlx::query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
    .expect("reading the table list must succeed")
    .iter()
    .map(|row| row.get::<String, _>("table_name"))
    .collect();
    assert!(
        tables.len() > 20,
        "die Tabellenliste MUSS das ganze Schema treffen, gefunden: {}",
        tables.len()
    );

    let mut dump = Vec::new();
    for table in tables {
        let statement = format!("SELECT t::text AS rendered FROM \"{table}\" t");
        let rows = sqlx::query(sqlx::AssertSqlSafe(statement))
            .fetch_all(pool)
            .await
            .unwrap_or_else(|error| panic!("rendering {table} must succeed: {error}"));
        for row in rows {
            if let Ok(rendered) = row.try_get::<String, _>("rendered") {
                dump.push((format!("postgres:{table}"), rendered));
            }
        }
    }
    dump
}

/// Jeder Marker, der in der Datenbank steht — als Klartext ODER hexadezimal.
async fn database_findings(pool: &sqlx::PgPool) -> Vec<Finding> {
    let dump = database_dump(pool).await;
    let mut findings = Vec::new();
    for (place, rendered) in dump {
        for (_, marker) in CANARY_MARKERS {
            if rendered.contains(marker) || rendered.contains(&hex::encode(marker.as_bytes())) {
                findings.push((place.clone(), marker));
            }
        }
    }
    findings
}

/// Schluessel, Tags und Metadaten jedes Objekts im Bucket — NICHT die Koerper.
async fn object_store_surface(bucket: &str) -> Vec<(String, String)> {
    let client = common::object_store_client().await;
    let listing = client
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .expect("listing the bucket must succeed");
    let mut surface = Vec::new();
    for object in listing.contents() {
        let key = object.key().unwrap_or_default().to_owned();
        surface.push((format!("s3-key:{key}"), key.clone()));

        let head = client
            .head_object()
            .bucket(bucket)
            .key(&key)
            .send()
            .await
            .expect("heading a listed object must succeed");
        for (name, value) in head.metadata().into_iter().flatten() {
            surface.push((format!("s3-metadata:{key}:{name}"), value.clone()));
        }

        let tagging = client
            .get_object_tagging()
            .bucket(bucket)
            .key(&key)
            .send()
            .await
            .expect("reading the tags of a listed object must succeed");
        for tag in tagging.tag_set() {
            surface.push((
                format!("s3-tag:{key}:{}", tag.key()),
                tag.value().to_owned(),
            ));
        }
    }
    assert!(
        !surface.is_empty(),
        "der Bucket MUSS Objekte tragen, sonst misst die Suche nichts"
    );
    surface
}

/// Die Wurzel des Arbeitsbereichs, von `apps/server` aus gerechnet.
fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root must be reachable from apps/server")
}

/// Die Ausgabe beider Integrationscontainer.
///
/// Sie steht in der Liste der durchsuchten Flaechen, weil ein fachlicher Wert,
/// der in einer Anfrage steckt, ueber eine Fehlermeldung von PostgreSQL oder
/// MinIO in deren Ausgabe geraten koennte — ein Kanal, den keine Zusicherung
/// des Serverkerns abdeckt.
fn container_output() -> String {
    let output = std::process::Command::new("docker")
        .args([
            "compose",
            "--file",
            "ops/compose/integration.yaml",
            "logs",
            "--no-color",
            "--tail",
            "2000",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("docker compose logs must be invocable; the integration services are running");
    assert!(
        output.status.success(),
        "docker compose logs must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    assert!(
        !text.trim().is_empty(),
        "die Containerausgabe MUSS nichtleer sein, sonst misst die Suche nichts"
    );
    text
}

/// Der normativ festgelegte Labelsatz.
fn metric_label_declaration() -> String {
    std::fs::read_to_string(workspace_root().join("ops/monitoring/metrics.md"))
        .expect("ops/monitoring/metrics.md must be readable")
}

#[tokio::test]
async fn no_fachliche_canary_survives_a_commit_on_any_server_surface() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database).await;

    // Der Commit, dessen Ciphertext JEDEN Marker traegt.
    let ciphertext = canary_ciphertext();
    let request = archive_objects::commit_request_with_ciphertext(
        &archive_objects::CommitSpec {
            closure: &closure,
            sequence: trust_closure::ExtendedClosure::seeded_head_sequence() + 1,
            previous_entry_hash: Some(
                ea_types::EntryHash::try_from(&SEEDED_HEAD_ENTRY_HASH[..]).expect("32 bytes"),
            ),
            recipients: &[
                archive_objects::Recipient::reader(&closure),
                archive_objects::Recipient::recovery(&closure),
            ],
            marker: 0x5a,
            writer_override: None,
            registry_override: None,
        },
        &ciphertext,
    );
    let body = request.exact_bytes().to_vec();
    let target = archive_objects::entry_commit_path(closure.chain_id);
    let nonce = common::fresh_challenge(&server, closure.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(trust_closure::WRITER_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(&body),
        organization_id: closure.organization_id,
        request_id: [0x11; 16],
        nonce,
        created: SERVER_NOW_MILLIS.div_euclid(1_000),
    });
    let accepted = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &target,
        &headers,
        &body,
    )
    .await;
    assert_eq!(
        accepted.status,
        EndpointV1::EntryCommits.success_status(),
        "die Kanarienfixture MUSS wirklich committen, sonst misst die Suche nichts"
    );

    // POSITIVKONTROLLE 1: die Marker haben den Server WIRKLICH erreicht und
    // liegen als Objektkoerper in seinem Store. Ohne sie waere jede
    // Abwesenheitszusage unten auch dann gruen, wenn nie etwas ankam.
    let client = common::object_store_client().await;
    let listing = client
        .list_objects_v2()
        .bucket(common::INTEGRATION_BUCKET)
        .send()
        .await
        .expect("listing the bucket must succeed");
    let mut bodies = Vec::new();
    for object in listing.contents() {
        let key = object.key().unwrap_or_default();
        let body = client
            .get_object()
            .bucket(common::INTEGRATION_BUCKET)
            .key(key)
            .send()
            .await
            .expect("reading a listed object must succeed")
            .body
            .collect()
            .await
            .expect("collecting the object body must succeed")
            .into_bytes();
        bodies.push(body.to_vec());
    }
    for (field, marker) in CANARY_MARKERS {
        assert!(
            bodies
                .iter()
                .any(|body| ea_testkit::contains_canary(body, marker.as_bytes())),
            "{field}: der Marker MUSS als Objektkoerper im Store liegen, sonst misst die Suche \
             nichts"
        );
    }

    // Und ein Fehlerkoerper, ausgeloest von einem Rumpf, der die Marker traegt.
    let nonce = common::fresh_challenge(&server, closure.organization_id).await;
    let malformed = canary_ciphertext();
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(trust_closure::WRITER_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(&malformed),
        organization_id: closure.organization_id,
        request_id: [0x12; 16],
        nonce,
        created: SERVER_NOW_MILLIS.div_euclid(1_000),
    });
    let refused = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &target,
        &headers,
        &malformed,
    )
    .await;
    assert!(
        (400..500).contains(&refused.status),
        "ein Rumpf aus Markerbytes MUSS abgewiesen werden, gemessen: {}",
        refused.status
    );
    assert!(
        ProtocolErrorV1::decode(&refused.body).is_ok(),
        "die Abweisung MUSS ein typisierter Fehlerkoerper sein"
    );

    // DIE SUCHE.
    let mut findings: Vec<Finding> = database_findings(database.pool()).await;
    for (place, value) in object_store_surface(common::INTEGRATION_BUCKET).await {
        for (_, marker) in CANARY_MARKERS {
            if value.contains(marker) {
                findings.push((place.clone(), marker));
            }
        }
    }
    for (place, bytes) in [
        ("error-body", refused.body.clone()),
        ("accepted-body", accepted.body.clone()),
        ("container-output", container_output().into_bytes()),
        ("metric-labels", metric_label_declaration().into_bytes()),
    ] {
        for (_, marker) in CANARY_MARKERS {
            if ea_testkit::contains_canary(&bytes, marker.as_bytes()) {
                findings.push((place.to_owned(), marker));
            }
        }
    }

    assert!(
        findings.is_empty(),
        "kein fachlicher Marker darf auf einer serverbeobachtbaren Flaeche stehen; gefunden: \
         {findings:?}"
    );

    database.cleanup().await;
}

#[tokio::test]
async fn the_search_finds_a_marker_that_really_lies_on_a_searched_surface() {
    // POSITIVKONTROLLE 2 und 3: die GEGENKONTROLLE der ganzen Datei. Liegt ein
    // Marker wirklich in einer Datenbankspalte oder in einem S3-Tag, MUSS die
    // Suche ihn finden. Ohne sie waere jede Abwesenheitszusicherung auch dann
    // gruen, wenn `database_findings` oder `object_store_surface` leer liefen.
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database).await;
    let _ = &server;

    assert!(
        database_findings(database.pool()).await.is_empty(),
        "vor der Probe darf kein Marker in der Datenbank stehen"
    );

    // Die Datenbankseite: ein Marker in einer Textspalte.
    sqlx::query(
        "INSERT INTO security_events (organization_id, event_code, subject_key, \
         observed_at_millis) VALUES ($1, $2, $3, $4)",
    )
    .bind(&closure.organization_id.as_bytes()[..])
    .bind("EA-TEST-PLANTED")
    .bind(canary("notes"))
    .bind(SERVER_NOW_MILLIS)
    .execute(database.pool())
    .await
    .expect("planting a marker must succeed");
    let found = database_findings(database.pool()).await;
    assert!(
        found.iter().any(|(_, marker)| *marker == canary("notes")),
        "die Datenbanksuche MUSS einen wirklich gepflanzten Marker finden; gefunden: {found:?}"
    );

    // Die Objektseite: ein Marker als Tag an einem eigens angelegten Objekt.
    //
    // In einem EIGENEN Bucket. Im gemeinsamen Integrationsbucket faende der
    // nebenlaeufige Abwesenheitstest dieses Ziels das gepflanzte Tag und
    // schluege fehl — gemessen, genau so aufgetreten. Die Gegenkontrolle darf
    // die Zusicherung, die sie absichert, nicht selbst verletzen.
    let bucket = common::unique_bucket_name("canary-probe");
    common::ensure_bucket(&bucket).await;
    let client = common::object_store_client().await;
    let key = format!("canary-probe/{}", common::unique_suffix());
    client
        .put_object()
        .bucket(&bucket)
        .key(&key)
        .body(aws_sdk_s3::primitives::ByteStream::from_static(b"probe"))
        .send()
        .await
        .expect("planting a probe object must succeed");
    client
        .put_object_tagging()
        .bucket(&bucket)
        .key(&key)
        .tagging(
            aws_sdk_s3::types::Tagging::builder()
                .tag_set(
                    aws_sdk_s3::types::Tag::builder()
                        .key("canary")
                        .value(canary("location"))
                        .build()
                        .expect("the probe tag is well formed"),
                )
                .build()
                .expect("the probe tagging is well formed"),
        )
        .send()
        .await
        .expect("planting a probe tag must succeed");

    let surface = object_store_surface(&bucket).await;
    assert!(
        surface
            .iter()
            .any(|(place, value)| place.starts_with("s3-tag:") && value == canary("location")),
        "die Tagsuche MUSS ein wirklich gesetztes Tag finden"
    );

    client
        .delete_object()
        .bucket(&bucket)
        .key(&key)
        .send()
        .await
        .expect("removing the probe object must succeed");

    database.cleanup().await;
}

#[test]
fn every_named_field_carries_its_own_marker() {
    // Die Vollstaendigkeit der Markermenge ist selbst eine Zusage: zwei Felder
    // mit demselben Marker liessen offen, welches geleckt hat, und ein leerer
    // Marker liesse jede Suche immer `false` melden.
    let markers: std::collections::BTreeSet<&str> =
        CANARY_MARKERS.iter().map(|(_, marker)| *marker).collect();
    assert_eq!(markers.len(), CANARY_MARKERS.len());
    let fields: std::collections::BTreeSet<&str> =
        CANARY_MARKERS.iter().map(|(field, _)| *field).collect();
    assert_eq!(fields.len(), CANARY_MARKERS.len());
    for (field, marker) in CANARY_MARKERS {
        assert!(!marker.is_empty(), "{field} traegt einen leeren Marker");
    }
}

/// Der Labelsatz traegt keinen der VERBOTENEN Schluessel als erlaubtes Label.
///
/// Die Kanariensuche oben prueft die DATEI gegen die Marker; diese Zusicherung
/// prueft ihre AUSSAGE. Ohne sie waere `ops/monitoring/metrics.md` eine Datei,
/// die kein Test liest, und ihre Tabelle koennte still jeden Schluessel
/// aufnehmen.
#[test]
fn the_declared_metric_labels_carry_no_unbounded_identity() {
    let declaration = metric_label_declaration();
    // EIN Schnitt an der Grenze, dann der Kopf des vorderen Teils weg: die
    // erlaubte Tabelle steht zwischen den beiden Ueberschriften, die
    // verbotene dahinter.
    let (allowed, forbidden) = declaration
        .split_once("## Verbotene Labels")
        .expect("metrics.md must carry the forbidden label section");
    let (_, allowed) = allowed
        .split_once("## Erlaubte Labels")
        .expect("metrics.md must carry the allowed label section");

    for key in [
        "organizationId",
        "deviceId",
        "subjectId",
        "chainId",
        "recordId",
    ] {
        assert!(
            forbidden.contains(key),
            "{key} muss ausdruecklich als verbotenes Label stehen"
        );
        assert!(
            !allowed.contains(key),
            "{key} darf in der Tabelle der erlaubten Labels nicht stehen"
        );
    }
    for (field, _) in CANARY_MARKERS {
        assert!(
            !allowed.contains(field),
            "{field} darf kein erlaubtes Label sein"
        );
    }
}
