//! Der Rueckspielnachweis: PostgreSQL UND Bucket in einen GETRENNTEN
//! Integrationsnamensraum zurueckgespielt, gemessen gegen einen bekannten
//! Checkpoint.
//!
//! # Warum ein getrennter Namensraum
//!
//! Eine Rueckspielung, die in denselben Bestand zurueckschreibt, aus dem sie
//! stammt, belegt nichts: sie kann nicht von „nichts getan" unterschieden
//! werden. Dieses Ziel legt deshalb BEIDE Haelften neu an — eine eigene
//! Datenbank und einen eigenen Bucket — und stellt danach einen ZWEITEN Server
//! darauf. Geprueft wird gegen den ZWEITEN Server, nicht gegen die Ablage:
//! wiederhergestellt ist ein Bestand erst, wenn ein Server ihn wieder
//! ausliefert.
//!
//! # Der bekannte Checkpoint
//!
//! Ein echter Commit gegen den ersten Server. Was er hinterlaesst, ist der
//! Vergleichsmassstab: der Kettenkopf, die exakte Objektmenge des Buckets und
//! die exakten Bytes jedes Objekts.
//!
//! # Was hier NICHT belegt ist
//!
//! Die produktionsreife Sicherung — Aufbewahrungsfristen, Verschluesselung der
//! Sicherung, Wiederanlaufzeit, Object Lock gegen den Betreiber selbst —
//! bleibt Stufe 7. Diese Stufe belegt die MECHANIK: eine Sicherung beider
//! Haelften spielt in einen leeren Namensraum zurueck, und der Bestand kommt
//! vollstaendig und byteidentisch wieder.

mod common;

use common::{archive_objects, trust_closure};
use ea_crypto::SecretBytes;
use ea_sync_protocol::{EndpointV1, RequestSigner};
use ea_types::{CertificateHash, EntryHash, ObjectHash, UnixMillis};
use sqlx::Row;

const SERVER_NOW_MILLIS: i64 = 1_000;
const SERVER_SECRET: [u8; 32] = [0x51; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];
const SEEDED_HEAD_ENTRY_HASH: [u8; 32] = [0x77; 32];
const SEEDED_HEAD_ACCEPTED_AT: i64 = 500;

fn signer(seed: [u8; 32]) -> RequestSigner {
    RequestSigner::from_secret(SecretBytes::new(seed))
}

/// Die Wurzel des Arbeitsbereichs, von `apps/server` aus gerechnet.
fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root must be reachable from apps/server")
}

/// Ein Server auf dem fortgeschriebenen Abschluss, gegen einen BENANNTEN
/// Bucket.
async fn stand_up(
    database: &common::TestDatabase,
    bucket: &str,
) -> (common::TestServer, trust_closure::ExtendedClosure) {
    let fixture =
        common::seed_trust_fixture(database.pool(), trust_closure::ROTATION_CASE, &[]).await;
    let closure = trust_closure::build(false);
    assert!(closure.organization_id == fixture.organization_id);
    let server = common::spawn_server_in_bucket(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        closure.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
        bucket,
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

/// Die Objekte, die GENAU DIESE Installation angelegt hat.
///
/// Der Quellbucket ist der gemeinsame Integrationsbucket — `seed_trust_fixture`
/// spielt die eingefrorenen Vertrauensobjekte dort ein, und ihn zu
/// parametrisieren hiesse, eine dritte Kulissenkante aufzumachen. Die
/// DATENBANK dagegen ist je Testfall frisch, also nennt ihr `object_index`
/// exakt die Objekte dieser Installation. Der Vergleichsmassstab kommt
/// deshalb von dort und nicht aus einer blanken Bucketauflistung, die auch die
/// Objekte NEBENLAEUFIGER Testfaelle traefe.
async fn known_object_keys(pool: &sqlx::PgPool) -> Vec<String> {
    let hashes: Vec<String> = sqlx::query("SELECT object_hash FROM object_index")
        .fetch_all(pool)
        .await
        .expect("reading the object index must succeed")
        .iter()
        .map(|row| hex::encode(row.get::<Vec<u8>, _>("object_hash")))
        .collect();
    assert!(
        !hashes.is_empty(),
        "die Installation MUSS Objekte gebucht haben, sonst misst die Rueckspielung nichts"
    );

    let client = common::object_store_client().await;
    let mut keys = Vec::new();
    let mut continuation = None;
    loop {
        let mut request = client.list_objects_v2().bucket(common::INTEGRATION_BUCKET);
        if let Some(token) = continuation {
            request = request.continuation_token(token);
        }
        let listing = request
            .send()
            .await
            .expect("listing the source bucket must succeed");
        for object in listing.contents() {
            let key = object.key().unwrap_or_default().to_owned();
            if hashes.iter().any(|hash| key.ends_with(hash)) {
                keys.push(key);
            }
        }
        match listing.next_continuation_token() {
            Some(token) => continuation = Some(token.to_owned()),
            None => break,
        }
    }
    assert_eq!(
        keys.len(),
        hashes.len(),
        "jedes gebuchte Objekt MUSS im Quellbucket liegen"
    );
    keys.sort();
    keys
}

/// Die exakten Bytes hinter einer Schluesselmenge.
async fn objects_at(bucket: &str, keys: &[String]) -> std::collections::BTreeMap<String, Vec<u8>> {
    let client = common::object_store_client().await;
    let mut contents = std::collections::BTreeMap::new();
    for key in keys {
        let body = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .expect("reading a known object must succeed")
            .body
            .collect()
            .await
            .expect("collecting the object body must succeed")
            .into_bytes()
            .to_vec();
        contents.insert(key.clone(), body);
    }
    contents
}

/// Der Zustand des Buckets: Schluessel und die exakten Bytes dahinter.
async fn bucket_contents(bucket: &str) -> std::collections::BTreeMap<String, Vec<u8>> {
    let client = common::object_store_client().await;
    let listing = client
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .expect("listing the bucket must succeed");
    let mut contents = std::collections::BTreeMap::new();
    for object in listing.contents() {
        let key = object.key().unwrap_or_default().to_owned();
        let body = client
            .get_object()
            .bucket(bucket)
            .key(&key)
            .send()
            .await
            .expect("reading a listed object must succeed")
            .body
            .collect()
            .await
            .expect("collecting the object body must succeed")
            .into_bytes()
            .to_vec();
        contents.insert(key, body);
    }
    contents
}

/// Die SICHERUNG und ihre Rueckspielung fuer die Datenbankhaelfte.
///
/// `pg_dump` und `psql` laufen IM Container, mit einer Pipe dazwischen: die
/// Sicherung verlaesst den Dienst nie und beruehrt den Wirt nicht. `--clean
/// --if-exists` raeumt den Zielnamensraum vor dem Einspielen ab, deshalb darf
/// das Ziel eine bereits migrierte Wegwerfdatenbank sein und braucht keinen
/// zweiten Anlegepfad.
fn restore_database(from: &str, into: &str) {
    let script = format!(
        "set -e; PGPASSWORD=einsatzarchiv pg_dump --clean --if-exists \
         --username=einsatzarchiv --host=127.0.0.1 --dbname={from} \
         | PGPASSWORD=einsatzarchiv psql --quiet --set=ON_ERROR_STOP=1 \
         --username=einsatzarchiv --host=127.0.0.1 --dbname={into}"
    );
    let output = std::process::Command::new("docker")
        .args([
            "compose",
            "--file",
            "ops/compose/integration.yaml",
            "exec",
            "-T",
            "postgres",
            "sh",
            "-c",
            &script,
        ])
        .current_dir(workspace_root())
        .output()
        .expect("docker compose exec must be invocable; the integration services are running");
    assert!(
        output.status.success(),
        "the database restore must succeed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Die Rueckspielung der Objekthaelfte: jedes gesicherte Objekt, Schluessel
/// fuer Schluessel, in den Zielbucket.
async fn restore_bucket(from: &str, into: &str, keys: &[String]) {
    let client = common::object_store_client().await;
    for key in keys {
        client
            .copy_object()
            .bucket(into)
            .key(key)
            .copy_source(format!("{from}/{key}"))
            .send()
            .await
            .expect("copying an object into the restore namespace must succeed");
    }
}

/// Der Kettenkopf, wie die Datenbank ihn fuehrt.
async fn chain_head(
    pool: &sqlx::PgPool,
    closure: &trust_closure::ExtendedClosure,
) -> (i64, Vec<u8>) {
    let row = sqlx::query(
        "SELECT head_sequence, head_entry_hash FROM chain_heads \
         WHERE organization_id = $1 AND chain_id = $2",
    )
    .bind(&closure.organization_id.as_bytes()[..])
    .bind(&closure.chain_id.as_bytes()[..])
    .fetch_one(pool)
    .await
    .expect("the chain head must exist");
    (row.get("head_sequence"), row.get("head_entry_hash"))
}

#[tokio::test]
async fn a_restore_into_a_separate_namespace_returns_the_exact_objects_and_head() {
    // ---- Der QUELLbestand und sein bekannter Checkpoint. ----
    let source_database = common::fresh_database().await;
    let (server, closure) = stand_up(&source_database, common::INTEGRATION_BUCKET).await;

    let sequence = trust_closure::ExtendedClosure::seeded_head_sequence() + 1;
    let request = archive_objects::valid_commit(
        &closure,
        sequence,
        Some(EntryHash::try_from(&SEEDED_HEAD_ENTRY_HASH[..]).expect("32 bytes")),
        0x3c,
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
        request_id: [0x21; 16],
        nonce,
        created: SERVER_NOW_MILLIS.div_euclid(1_000),
    });
    let committed = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &target,
        &headers,
        &body,
    )
    .await;
    assert_eq!(
        committed.status,
        EndpointV1::EntryCommits.success_status(),
        "der bekannte Checkpoint MUSS wirklich entstehen, sonst misst die Rueckspielung nichts; \
         Befund: {:?}",
        common::error_code(&committed.body)
    );

    let known_head = chain_head(source_database.pool(), &closure).await;
    let known_keys = known_object_keys(source_database.pool()).await;
    let known_objects = objects_at(common::INTEGRATION_BUCKET, &known_keys).await;
    assert!(
        known_objects.len() >= 4,
        "der Checkpoint MUSS Eintrag, Grants, Quittung und Checkpoint tragen, gefunden: {}",
        known_objects.len()
    );
    assert_eq!(
        i64::try_from(sequence).expect("the fixture sequence fits an i64"),
        known_head.0,
        "der Kopf MUSS auf der committeten Sequenz stehen"
    );

    // ---- Die RUECKSPIELUNG in einen getrennten Namensraum. ----
    let restored_database = common::fresh_database().await;
    let restored_bucket = common::unique_bucket_name("restore-target");
    common::ensure_bucket(&restored_bucket).await;

    // Die Gegenprobe VOR der Rueckspielung: der Zielnamensraum ist wirklich
    // leer. Ohne sie waere jede Gleichheit unten auch dann erreichbar, wenn
    // die Rueckspielung gar nichts getan haette und beide Seiten dasselbe
    // Verzeichnis laesen.
    assert!(
        bucket_contents(&restored_bucket).await.is_empty(),
        "der Zielbucket MUSS vor der Rueckspielung leer sein"
    );
    let empty_head = sqlx::query(
        "SELECT count(*) AS heads FROM chain_heads WHERE organization_id = $1 AND chain_id = $2",
    )
    .bind(&closure.organization_id.as_bytes()[..])
    .bind(&closure.chain_id.as_bytes()[..])
    .fetch_one(restored_database.pool())
    .await
    .expect("counting the heads of the empty namespace must succeed");
    assert_eq!(
        empty_head.get::<i64, _>("heads"),
        0,
        "die Zieldatenbank MUSS vor der Rueckspielung ohne Kettenkopf sein"
    );

    restore_database(source_database.name(), restored_database.name());
    restore_bucket(common::INTEGRATION_BUCKET, &restored_bucket, &known_keys).await;

    // ---- Die MESSUNG gegen den bekannten Checkpoint. ----
    // 1. Die Objektmenge ist EXAKT dieselbe — Schluessel fuer Schluessel und
    //    Byte fuer Byte. `assert_eq!` ueber die ganze Abbildung und nicht ueber
    //    ihre Groesse: zwei gleich grosse, verschiedene Mengen waeren sonst
    //    gleich.
    let restored_objects = bucket_contents(&restored_bucket).await;
    assert_eq!(
        restored_objects.keys().collect::<Vec<_>>(),
        known_objects.keys().collect::<Vec<_>>(),
        "die Rueckspielung MUSS exakt dieselbe Objektmenge tragen"
    );
    assert!(
        restored_objects == known_objects,
        "jedes zurueckgespielte Objekt MUSS byteidentisch sein"
    );

    // 2. Der Kopf ist derselbe.
    assert_eq!(
        chain_head(restored_database.pool(), &closure).await,
        known_head,
        "der zurueckgespielte Kettenkopf MUSS der bekannte sein"
    );

    // 3. Und der entscheidende Schritt: ein ZWEITER Server auf dem
    //    zurueckgespielten Namensraum liefert jedes Objekt des Checkpoints
    //    wieder aus. Eine Ablage, die richtig aussieht, aber nicht mehr
    //    bedient wird, waere keine Wiederherstellung.
    let restored_server = common::spawn_server_in_bucket(
        restored_database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS),
        closure.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
        &restored_bucket,
    )
    .await;
    for (index, bytes) in known_objects.values().enumerate() {
        // Die Request-ID darf mit KEINER kollidieren, die die Sicherung
        // mitgebracht hat: die Rueckspielung bringt `request_ids` mit, und die
        // Kulisse hat ihre eigenen ab null vergeben. Ein `[0x00; 16]` liefe
        // deshalb in `EA-AUTH-REQUEST-ID-REPLAY` — gemessen.
        let mut request_id = [0xbb_u8; 16];
        request_id[0] = u8::try_from(index).unwrap_or(0xff);
        let hash = ea_crypto::object_hash(bytes);
        let target = format!("/v1/objects/{}", hex::encode(ObjectHash::as_bytes(&hash)));
        let nonce = common::fresh_challenge(&restored_server, closure.organization_id).await;
        let headers = common::signed_headers(&common::SignedCall {
            signer: &signer(trust_closure::READER_SIGNING_SEED),
            endpoint: EndpointV1::Objects,
            authority: &restored_server.authority,
            target: &target,
            body: None,
            organization_id: closure.organization_id,
            request_id,
            nonce,
            created: SERVER_NOW_MILLIS.div_euclid(1_000),
        });
        let response = common::https_request(
            restored_server.address,
            &restored_server.authority,
            "GET",
            &target,
            &headers,
            &[],
        )
        .await;
        assert_eq!(
            response.status,
            200,
            "der zurueckgespielte Server MUSS jedes Objekt des Checkpoints ausliefern; Befund: \
             {:?}",
            common::error_code(&response.body)
        );
        assert!(
            &response.body == bytes,
            "die ausgelieferten Bytes MUESSEN die gesicherten sein"
        );
    }

    restored_database.cleanup().await;
    source_database.cleanup().await;
}
