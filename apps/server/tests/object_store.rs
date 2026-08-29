//! Der content-addressed Object Store gegen einen ECHTEN S3-Dienst.
//!
//! Die drei Aussagen dieses Ziels sind die drei Zusagen aus `design.md` §13.3:
//!
//! 1. Gleicher Schluessel, ANDERE Bytes ist ein Security Event und wird als
//!    solches aufgezeichnet — nicht als idempotenter Wiederholungsfall.
//! 2. Der Adapter stromt und hasht, ohne den vollen Koerper zu puffern; die
//!    Groessendecke wirkt, BEVOR der Strom zu Ende gelesen ist.
//! 3. Byteweise gleiche Bytes sind der zulaessige Wiederholungsfall.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_s3::{
    Client,
    config::{Credentials, Region},
    primitives::ByteStream,
};
use ea_crypto::object_hash;
use ea_format::ObjectTypeV1;
use ea_sync_server::{ObjectStore, ObjectTypeDirectory, RepositoryError, ServerClock, object_key};
use ea_types::{Id16, ObjectHash, OrganizationId, UnixMillis};
use einsatzarchiv_server::adapters::{postgres::PostgresRepository, s3::S3ObjectStore};
use sqlx::Row;

/// Eine feste Serverzeit. Der Test stellt keine Uhr des Rechners.
struct FixedClock(UnixMillis);

impl ServerClock for FixedClock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}

/// Ein Objektartverzeichnis, das der Test selbst fuellt.
///
/// Der ECHTE Weg fuehrt ueber `object_index`, und den fuellt erst die
/// Commit-Transaktion. Dieses Ziel prueft den Object Store, nicht den Commit,
/// also stellt es das Verzeichnis.
struct FixedDirectory(ObjectTypeV1);

#[async_trait]
impl ObjectTypeDirectory for FixedDirectory {
    async fn object_type_of(
        &self,
        _hash: ObjectHash,
    ) -> Result<Option<ObjectTypeV1>, RepositoryError> {
        Ok(Some(self.0))
    }
}

async fn object_store_client() -> Client {
    let http_client = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https();
    let configuration = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .http_client(http_client)
        .region(Region::new("us-east-1"))
        .endpoint_url(common::object_store_endpoint())
        .force_path_style(true)
        .credentials_provider(Credentials::new(
            common::INTEGRATION_ACCESS_KEY_ID,
            common::INTEGRATION_SECRET_ACCESS_KEY,
            None,
            None,
            "einsatzarchiv-integration",
        ))
        .build();
    Client::from_conf(configuration)
}

/// Ein gueltiges `.etb`-artiges Objekt: Praefix plus Fuellung.
///
/// Der Object Store prueft die ersten neun Bytes und sonst nichts — die
/// Formatpruefung ist Schritt 2 von §13.3 und gehoert nicht hierher.
fn trust_object(filler: u8, length: usize) -> Vec<u8> {
    let mut bytes = ea_format::ETB_PREFIX_V1.to_vec();
    bytes.resize(bytes.len() + length, filler);
    bytes
}

const ORGANIZATION: [u8; 16] = [0x5a; 16];

async fn insert_organization(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO organizations (organization_id, root_key_thumbprint, created_at_millis) \
         VALUES ($1, $2, $3)",
    )
    .bind(&ORGANIZATION[..])
    .bind(&[9_u8; 32][..])
    .bind(1_700_000_000_000_i64)
    .execute(pool)
    .await
    .expect("the organization row must insert");
}

fn organization_id() -> OrganizationId {
    OrganizationId::from(Id16::try_from(&ORGANIZATION[..]).expect("sixteen bytes"))
}

#[tokio::test(flavor = "multi_thread")]
async fn same_object_key_with_different_bytes_is_security_event() {
    let database = common::fresh_database().await;
    insert_organization(database.pool()).await;
    let repository = Arc::new(PostgresRepository::new(database.pool().clone()));
    let store = S3ObjectStore::new(
        object_store_client().await,
        common::INTEGRATION_BUCKET.to_owned(),
        organization_id(),
        repository.clone(),
        Arc::new(FixedDirectory(ObjectTypeV1::Trust)),
        Arc::new(FixedClock(UnixMillis::new(1_700_000_000_000))),
    );

    // Der Konflikt wird HERGESTELLT, nicht erhofft: zwei ehrliche Koerper
    // haetten verschiedene Hashwerte und damit verschiedene Schluessel, und die
    // Kollision aus §13.3 Schritt 3 traete nie ein. Hier weichen zusaetzlich
    // die LAENGEN ab — das ist der Schnellpfad. Den Bytevergleich selbst faehrt
    // der Zeuge darunter.
    let honest = unique_trust_object(96);
    let hash = object_hash(&honest);
    let target = object_key(ObjectTypeV1::Trust, hash);
    object_store_client()
        .await
        .put_object()
        .bucket(common::INTEGRATION_BUCKET)
        .key(&target)
        .body(ByteStream::from(trust_object(0xb2, 8)))
        .send()
        .await
        .expect("planting the colliding bytes must succeed");

    let staged = store
        .stage_stream(
            ObjectTypeV1::Trust,
            ByteStream::from(honest.clone()),
            1_024 * 1_024,
        )
        .await
        .expect("staging an honest object must succeed");
    assert!(staged.object_hash() == hash);

    let error = store
        .put_if_absent(staged)
        .await
        .expect_err("the same key with different bytes must not pass as an idempotent replay");
    assert_eq!(error.code(), "EA-STORE-HASH-CONFLICT");

    let rows = sqlx::query(
        "SELECT event_code, subject_key FROM security_events WHERE organization_id = $1",
    )
    .bind(&ORGANIZATION[..])
    .fetch_all(database.pool())
    .await
    .expect("reading the security events must succeed");
    assert_eq!(rows.len(), 1, "the finding must be recorded exactly once");
    let code: String = rows[0].get("event_code");
    let subject: String = rows[0].get("subject_key");
    assert_eq!(code, "object-hash-conflict");
    // Gegen ein LITERAL, nicht gegen `object_key()`: sonst verglichen sich hier
    // die Funktion mit sich selbst und die Schluesselform waere ungeprueft.
    assert_eq!(subject, format!("etb/{}", hex::encode(hash.as_bytes())));
    assert_eq!(subject, target);

    cleanup_key(&target).await;
    database.cleanup().await;
}

/// Derselbe Schluessel, GLEICHE LAENGE, andere Bytes.
///
/// Der eigentliche Bytevergleich aus `design.md` §13.3, Schritt 3. Der Zeuge
/// daruber weicht in der Laenge ab und wird deshalb schon vom Schnellpfad
/// entschieden; erst hier laeuft der Hashvergleich wirklich. Genau diesen Weg
/// hatte die fruehere Fassung mit `!same_length || …` uebersprungen: `||` kam
/// nie bis zum Hash, solange die Laengen abwichen, und ein Angreifer mit
/// gleicher Laenge waere als idempotenter Replay durchgegangen.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_key_with_same_length_but_different_bytes_is_a_conflict() {
    let database = common::fresh_database().await;
    insert_organization(database.pool()).await;
    let repository = Arc::new(PostgresRepository::new(database.pool().clone()));
    let client = object_store_client().await;
    let store = S3ObjectStore::new(
        client.clone(),
        common::INTEGRATION_BUCKET.to_owned(),
        organization_id(),
        repository,
        Arc::new(FixedDirectory(ObjectTypeV1::Trust)),
        Arc::new(FixedClock(UnixMillis::new(1_700_000_000_000))),
    );

    let honest = unique_trust_object(96);
    // Gleiche Laenge, ein einziges gekipptes Byte hinter dem Praefix.
    let mut impostor = honest.clone();
    let last = impostor.len() - 1;
    impostor[last] ^= 0xff;
    assert_eq!(impostor.len(), honest.len());
    assert_ne!(impostor, honest);

    let target = object_key(ObjectTypeV1::Trust, object_hash(&honest));
    client
        .put_object()
        .bucket(common::INTEGRATION_BUCKET)
        .key(&target)
        .body(ByteStream::from(impostor.clone()))
        .send()
        .await
        .expect("planting the same length impostor must succeed");

    // Positivkontrolle fuer den WEG: die Laengen sind gleich, also kann der
    // Schnellpfad hier nichts entscheiden — der Befund kommt vom Hash.
    let planted = client
        .head_object()
        .bucket(common::INTEGRATION_BUCKET)
        .key(&target)
        .send()
        .await
        .expect("the planted object must exist");
    assert_eq!(
        planted.content_length().and_then(|l| u64::try_from(l).ok()),
        Some(honest.len() as u64),
        "the impostor must have the same length; otherwise the fast path decides and the byte \
         comparison stays untested"
    );

    let staged = store
        .stage_stream(
            ObjectTypeV1::Trust,
            ByteStream::from(honest.clone()),
            1_024 * 1_024,
        )
        .await
        .expect("staging the honest object must succeed");
    let error = store
        .put_if_absent(staged)
        .await
        .expect_err("same length with different bytes must not pass as an idempotent replay");
    assert_eq!(error.code(), "EA-STORE-HASH-CONFLICT");

    let events: Vec<String> =
        sqlx::query_scalar("SELECT event_code FROM security_events WHERE organization_id = $1")
            .bind(&ORGANIZATION[..])
            .fetch_all(database.pool())
            .await
            .expect("reading the security events must succeed");
    assert_eq!(events, vec!["object-hash-conflict".to_owned()]);

    cleanup_key(&target).await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn identical_bytes_under_the_same_key_are_an_idempotent_replay() {
    let database = common::fresh_database().await;
    insert_organization(database.pool()).await;
    let repository = Arc::new(PostgresRepository::new(database.pool().clone()));
    let store = S3ObjectStore::new(
        object_store_client().await,
        common::INTEGRATION_BUCKET.to_owned(),
        organization_id(),
        repository.clone(),
        Arc::new(FixedDirectory(ObjectTypeV1::Trust)),
        Arc::new(FixedClock(UnixMillis::new(1_700_000_000_000))),
    );

    let body = unique_trust_object(96);
    let target = object_key(ObjectTypeV1::Trust, object_hash(&body));

    for expected_new in [true, false] {
        let staged = store
            .stage_stream(
                ObjectTypeV1::Trust,
                ByteStream::from(body.clone()),
                1_024 * 1_024,
            )
            .await
            .unwrap();
        let stored = store.put_if_absent(staged).await.unwrap();
        assert_eq!(stored.newly_stored(), expected_new);
        assert_eq!(stored.size_bytes(), body.len() as u64);
    }

    // Kein Security Event: derselbe Schluessel mit DENSELBEN Bytes ist der
    // zulaessige Wiederholungsfall.
    let events: (i64,) = sqlx::query_as("SELECT count(*) FROM security_events")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(events.0, 0);

    // Tags und benutzerdefinierte Metadaten tragen INHALTSTYP UND GROESSE und
    // sonst nichts (`design.md` §13.4, „Keine fachlichen Werte ... in Object
    // Keys, Tags oder benutzerdefinierten Metadaten“). Geprueft wird die
    // Schluesselmenge EXAKT: ein spaeter ergaenztes Feld faellt hier auf, statt
    // still mitzureisen.
    let head = object_store_client()
        .await
        .head_object()
        .bucket(common::INTEGRATION_BUCKET)
        .key(&target)
        .send()
        .await
        .expect("the stored object must exist");
    let metadata = head
        .metadata()
        .expect("the stored object must carry metadata");
    let mut keys: Vec<&str> = metadata.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["object-size", "object-type"],
        "the object store must carry exactly the content type and the size"
    );
    assert_eq!(metadata.get("object-type").map(String::as_str), Some("etb"));
    assert_eq!(
        metadata
            .get("object-size")
            .and_then(|value| value.parse::<usize>().ok()),
        Some(body.len())
    );
    assert_eq!(
        head.content_type(),
        Some("application/einsatzarchiv-object")
    );

    // Und die exakten Bytes kommen unveraendert zurueck.
    let mut returned = store.get_exact(object_hash(&body)).await.unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = returned.next().await {
        collected.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(collected, body);

    cleanup_key(&target).await;
    database.cleanup().await;
}

/// Der Streaming-Nachweis, in zwei Haelften.
///
/// **Erste Haelfte — die Decke traegt.** Ein Koerper ueber der Grenze endet mit
/// `EA-STORE-LIMIT`, und der angefangene mehrteilige Upload wird abgebrochen:
/// nach dem Fehlschlag steht kein offener Upload mehr im Bucket. Ohne den
/// Abbruch bliebe ein halbes Objekt liegen, das ein spaeterer Lauf fuer echt
/// halten koennte.
///
/// **Zweite Haelfte — es wird wirklich gestromt.** Ein Koerper von zwoelf MiB
/// laeuft durch, sein Objekthash stimmt mit `ea_crypto::object_hash` ueber die
/// aneinandergehaengten Bytes ueberein, UND das abgelegte Objekt traegt ein
/// mehrteiliges ETag der Form `…-3`. Dieses Suffix entsteht ausschliesslich
/// dann, wenn der Upload tatsaechlich in drei getrennten Teilen lief. Ein
/// Adapter, der den Koerper erst vollstaendig gepuffert und dann in EINEM
/// Stueck hochgeladen haette, truege ein ETag ohne Bindestrich.
///
/// GENAU GESAGT ist die Spitzenlast des Adapters `min(Koerper, 5 MiB)` — fuenf
/// MiB ist die kleinste Teilgroesse, die S3 zulaesst, und darunter geht es
/// nicht. Fuer ein echtes Archivobjekt liegt sie deshalb beim Koerper selbst:
/// `ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1` sind vier MiB, also passt jedes
/// zulaessige Objekt in genau EINEN Teil. Der Speicher ist damit doppelt
/// gedeckelt — durch die Formatgrenze und durch das `limit`-Argument —, und die
/// mehrteilige Strecke ist das, was die Deckelung auch fuer einen kuenftigen
/// Aufrufer haelt, der eine groessere Grenze setzt. Dieser Test faehrt genau
/// diesen Fall, weil nur er die Streckenwahl ueberhaupt sichtbar macht.
#[tokio::test(flavor = "multi_thread")]
async fn the_adapter_streams_and_hashes_without_buffering_a_full_payload() {
    let database = common::fresh_database().await;
    insert_organization(database.pool()).await;
    let repository = Arc::new(PostgresRepository::new(database.pool().clone()));
    let client = object_store_client().await;
    let store = S3ObjectStore::new(
        client.clone(),
        common::INTEGRATION_BUCKET.to_owned(),
        organization_id(),
        repository,
        Arc::new(FixedDirectory(ObjectTypeV1::Trust)),
        Arc::new(FixedClock(UnixMillis::new(1_700_000_000_000))),
    );

    const LIMIT: u64 = 256 * 1024;
    let oversized = trust_object(0xd4, 1_024 * 1_024);
    let error = store
        .stage_stream(ObjectTypeV1::Trust, ByteStream::from(oversized), LIMIT)
        .await
        .expect_err("a body over the limit must be refused");
    assert_eq!(error.code(), "EA-STORE-LIMIT");

    let open_uploads = client
        .list_multipart_uploads()
        .bucket(common::INTEGRATION_BUCKET)
        .prefix("staging/etb/")
        .send()
        .await
        .expect("listing the open multipart uploads must succeed");
    assert!(
        open_uploads.uploads().is_empty(),
        "the refused upload must be aborted; a half written staging object must not survive"
    );

    // Zwoelf MiB bei fuenf MiB Teilgroesse sind drei Teile.
    let large = unique_trust_object(12 * 1_024 * 1_024);
    let staged = store
        .stage_stream(
            ObjectTypeV1::Trust,
            ByteStream::from(large.clone()),
            32 * 1_024 * 1_024,
        )
        .await
        .expect("a body inside the limit must stage");
    assert!(staged.object_hash() == object_hash(&large));
    assert_eq!(staged.size_bytes(), large.len() as u64);

    let head = client
        .head_object()
        .bucket(common::INTEGRATION_BUCKET)
        .key(staged.staging_key())
        .send()
        .await
        .expect("the staged object must exist");
    let etag = head.e_tag().unwrap_or_default().to_owned();
    assert!(
        etag.trim_matches('"').ends_with("-3"),
        "the staged object must carry a three part multipart ETag, proving the adapter never \
         held more than one part; it carries {etag}"
    );

    let target = object_key(ObjectTypeV1::Trust, staged.object_hash());
    let staging_key = staged.staging_key().to_owned();
    store
        .put_if_absent(staged)
        .await
        .expect("the put must succeed");
    cleanup_key(&target).await;
    cleanup_key(&staging_key).await;
    database.cleanup().await;
}

/// Eine Objektart, deren Praefix nicht passt, kommt gar nicht erst in den
/// Namensraum der anderen.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_without_the_declared_prefix_is_refused() {
    let database = common::fresh_database().await;
    insert_organization(database.pool()).await;
    let repository = Arc::new(PostgresRepository::new(database.pool().clone()));
    let store = S3ObjectStore::new(
        object_store_client().await,
        common::INTEGRATION_BUCKET.to_owned(),
        organization_id(),
        repository,
        Arc::new(FixedDirectory(ObjectTypeV1::Trust)),
        Arc::new(FixedClock(UnixMillis::new(1_700_000_000_000))),
    );

    // `.eip`-Bytes, als `.etb` angemeldet.
    let mut body = ea_format::EIP_PREFIX_V1.to_vec();
    body.resize(128, 0xe5);
    let error = store
        .stage_stream(ObjectTypeV1::Trust, ByteStream::from(body), 1_024 * 1_024)
        .await
        .expect_err("an entry package must not be filed under the trust namespace");
    assert_eq!(error.code(), "EA-STORE-OBJECT-TYPE");

    database.cleanup().await;
}

/// Ein Koerper, dessen Bytes ueber LAEUFE hinweg eindeutig sind.
///
/// Nicht nur ueber parallele Ziele: ein Test, der vor seinem `cleanup_key`
/// abbricht, laesst sein Objekt im Bucket liegen. Ein Fuellmuster aus einem
/// kleinen Zahlenraum traefe beim naechsten Lauf denselben content-addressed
/// Schluessel, und `newly_stored()` waere dann schon beim ERSTEN Ablegen
/// `false` — ein Fehlschlag, der nichts mit dem Adapter zu tun haette. Die
/// Marke ist deshalb dieselbe wie bei den Wegwerfdatenbanken: Zeit,
/// Prozesskennung und Zaehler.
fn unique_trust_object(length: usize) -> Vec<u8> {
    let marker = common::unique_suffix();
    let marker = marker.as_bytes();
    let mut bytes = ea_format::ETB_PREFIX_V1.to_vec();
    bytes.extend(
        (0..length)
            .map(|index| marker[index % marker.len()] ^ u8::try_from(index % 251).unwrap_or(0)),
    );
    bytes
}

async fn cleanup_key(key: &str) {
    let _ = object_store_client()
        .await
        .delete_object()
        .bucket(common::INTEGRATION_BUCKET)
        .key(key)
        .send()
        .await;
}
