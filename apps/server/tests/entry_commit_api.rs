//! `POST /v1/chains/{chainId}/entry-commits` gegen ECHTE Dienste.
//!
//! Jeder Fall laeuft den ganzen Weg: TLS 1.3, Axum, RFC-9421-Pruefung, die
//! geteilte `ea-trust`-Pruefung, PostgreSQL und der Object Store. Ein
//! `oneshot` gegen den Router prueefte eine Abkuerzung, die es im Betrieb
//! nicht gibt.
//!
//! Der Vertrauensabschluss mit Writer, Reader und Recovery-Empfaenger kommt aus
//! `common::trust_closure` und wird ueber den ECHTEN Endpunkt
//! `POST /v1/trust/events` eingespielt; die Eintraege und Grants baut
//! `common::archive_objects`. Warum beides noetig ist, steht in den Kopfnoten
//! jener Module.

mod common;

use common::{archive_objects, trust_closure};
use ea_crypto::SecretBytes;
use ea_sync_protocol::{
    EndpointV1, EntryCommitOutcome, EntryCommitResponseV1, ProtocolErrorV1, RequestSigner,
};
use ea_types::{CertificateHash, EntryHash, UnixMillis};
use sqlx::Row;

/// Innerhalb des `notBefore`/`notAfter`-Fensters aller Koepfe.
const SERVER_NOW_MILLIS: i64 = 1_000;
const SERVER_SECRET: [u8; 32] = [0x51; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];

/// Der Kopf, auf dem die Kette bereits steht, bevor der Testfall committet.
const SEEDED_HEAD_ENTRY_HASH: [u8; 32] = [0x77; 32];
/// Die Annahmezeit dieses Kopfes. Sie liegt UNTER der Serverzeit, damit der
/// glueckliche Pfad die Serverzeit nimmt.
const SEEDED_HEAD_ACCEPTED_AT: i64 = 500;

fn signer(seed: [u8; 32]) -> RequestSigner {
    RequestSigner::from_secret(SecretBytes::new(seed))
}

fn error_code(body: &[u8]) -> Option<String> {
    ProtocolErrorV1::decode(body)
        .ok()
        .map(|error| error.error_code().to_owned())
}

fn seeded_head_entry_hash() -> EntryHash {
    EntryHash::try_from(&SEEDED_HEAD_ENTRY_HASH[..]).expect("32 bytes")
}

/// Ein Server, dessen Organisation den fortgeschriebenen Abschluss traegt und
/// dessen Kette bereits innerhalb der Sequenzleihe steht.
async fn stand_up(
    database: &common::TestDatabase,
    now_millis: i64,
    with_second_reader: bool,
) -> (common::TestServer, trust_closure::ExtendedClosure) {
    let fixture =
        common::seed_trust_fixture(database.pool(), trust_closure::ROTATION_CASE, &[]).await;
    let closure = trust_closure::build(with_second_reader);
    assert!(
        closure.organization_id == fixture.organization_id,
        "the extension binds to the frozen anchor's organization"
    );
    let server = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(now_millis),
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

/// Ein signierter Commit-Request gegen den echten Server.
/// `created` folgt der Uhr DIESES Servers: das Signaturfenster wird gegen die
/// Serverzeit gestellt, und ein Fall, der die Uhr bewusst verstellt, muss
/// seine Signatur mitverstellen.
async fn post_commit_at(
    server: &common::TestServer,
    closure: &trust_closure::ExtendedClosure,
    body: &[u8],
    request_id: [u8; 16],
    now_millis: i64,
) -> common::HttpResponse {
    let target = archive_objects::entry_commit_path(closure.chain_id);
    let nonce = common::fresh_challenge(server, closure.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(trust_closure::WRITER_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(body),
        organization_id: closure.organization_id,
        request_id,
        nonce,
        created: now_millis.div_euclid(1_000),
    });
    common::https_request(
        server.address,
        &server.authority,
        "POST",
        &target,
        &headers,
        body,
    )
    .await
}

/// Derselbe Aufruf gegen einen Server mit der Standarduhr.
async fn post_commit(
    server: &common::TestServer,
    closure: &trust_closure::ExtendedClosure,
    body: &[u8],
    request_id: [u8; 16],
) -> common::HttpResponse {
    post_commit_at(server, closure, body, request_id, SERVER_NOW_MILLIS).await
}

/// Der glueckliche Pfad: Eintrag, Grants, Kopf und Quittung werden GEMEINSAM
/// sichtbar, und die ausgelieferte Quittung ist die gespeicherte.
#[tokio::test(flavor = "multi_thread")]
async fn a_complete_commit_is_accepted_and_becomes_visible_together() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS, false).await;

    let request = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xa1,
    );
    let response = post_commit(&server, &closure, request.exact_bytes(), [0x01; 16]).await;
    assert_eq!(
        response.status,
        200,
        "a complete commit must be accepted; the server answered {:?}",
        error_code(&response.body)
    );

    let decoded = EntryCommitResponseV1::decode(&response.body).expect("the response decodes");
    assert_eq!(decoded.outcome(), EntryCommitOutcome::Accepted);
    // `checkpoint-bytes` bleibt in DIESER Stufe `null`; der
    // Standard-Checkpoint fuellt es spaeter und beruehrt dabei kein
    // Receipt-Byte.
    assert_eq!(decoded.checkpoint_bytes(), None);

    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(decoded.receipt_bytes()).expect("the receipt parses")
    else {
        panic!("the response carries a receipt");
    };
    let fields = receipt.value().core().fields();
    assert!(fields.entry_hash == request.identity().entry_hash());
    assert!(fields.entry_object_hash == request.identity().entry_object_hash());
    assert_eq!(
        fields.chain_sequence.get(),
        trust_closure::ExtendedClosure::commit_sequence()
    );
    assert!(fields.registry_version == closure.registry_version);
    // Der gebundene Kopf ist der GEWAEHLTE — nicht irgendeiner aus einer Zeile.
    assert_eq!(
        fields.registry_head_hash.as_bytes(),
        closure.registry_head_hash.as_bytes()
    );
    // Die Grant-Hashes der Quittung sind exakt die des unteilbar angenommenen
    // Satzes, sortiert.
    assert_eq!(
        fields.initial_grant_object_hashes.len(),
        request.identity().sorted_grant_object_hashes().len()
    );
    assert!(
        fields
            .initial_grant_object_hashes
            .iter()
            .zip(request.identity().sorted_grant_object_hashes())
            .all(|(left, right)| left == right)
    );
    // Standardprofil: keine Evidence-Frist.
    assert_eq!(fields.evidence_due_at, None);
    // Die Annahmezeit ist das Maximum aus Serverzeit und Vorgaengerzeit.
    assert_eq!(
        fields.accepted_at_server,
        UnixMillis::new(SERVER_NOW_MILLIS)
    );

    // Schritt 8: alles gemeinsam sichtbar.
    let row = sqlx::query(
        "SELECT (SELECT count(*) FROM entries) AS entries, \
         (SELECT count(*) FROM grants) AS grants, \
         (SELECT count(*) FROM receipts) AS receipts, \
         (SELECT head_sequence FROM chain_heads) AS head",
    )
    .fetch_one(database.pool())
    .await
    .expect("counting must succeed");
    assert_eq!(row.get::<i64, _>("entries"), 1);
    assert_eq!(row.get::<i64, _>("grants"), 2);
    assert_eq!(row.get::<i64, _>("receipts"), 1);
    assert_eq!(
        u64::try_from(row.get::<i64, _>("head")).expect("a sequence is not negative"),
        trust_closure::ExtendedClosure::commit_sequence()
    );
    // Kein Security Event auf dem glueklichen Pfad.
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(database.pool())
        .await
        .expect("counting security events must succeed");
    assert_eq!(events, 0);

    database.cleanup().await;
}

/// Ein identischer zweiter Commit liefert BYTEGLEICH dieselbe Quittung — auch
/// wenn die Serveruhr inzwischen weitergelaufen ist.
///
/// Genau die Zusage aus `design.md` §13.3: „Nach dem Commit kann ein Retry
/// ausschliesslich die gespeicherten Receipt-Bytes wieder ausliefern." Die
/// zweite Anfrage laeuft gegen einen Server mit einer SPAETEREN festen Uhr,
/// also gegen genau den Fall, den ein Neustart nach verlorener Antwort
/// erzeugt.
#[tokio::test(flavor = "multi_thread")]
async fn identical_replay_returns_byte_identical_receipt_bytes() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS, false).await;

    let request = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xa2,
    );
    let first = post_commit(&server, &closure, request.exact_bytes(), [0x02; 16]).await;
    assert_eq!(first.status, 200, "{:?}", error_code(&first.body));
    let first = EntryCommitResponseV1::decode(&first.body).expect("the response decodes");
    assert_eq!(first.outcome(), EntryCommitOutcome::Accepted);

    // Ein zweiter Server auf DERSELBEN Datenbank, mit einer spaeteren Uhr.
    let later = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS + 4_000),
        closure.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;
    let second = post_commit_at(
        &later,
        &closure,
        request.exact_bytes(),
        [0x03; 16],
        SERVER_NOW_MILLIS + 4_000,
    )
    .await;
    assert_eq!(second.status, 200, "{:?}", error_code(&second.body));
    let second = EntryCommitResponseV1::decode(&second.body).expect("the response decodes");

    assert_eq!(second.outcome(), EntryCommitOutcome::IdempotentReplay);
    assert_eq!(
        first.receipt_bytes(),
        second.receipt_bytes(),
        "a replay changes neither the time nor a single byte"
    );

    // Nichts ist doppelt entstanden, und der Kopf steht unveraendert.
    let row = sqlx::query(
        "SELECT (SELECT count(*) FROM entries) AS entries, \
         (SELECT count(*) FROM receipts) AS receipts, \
         (SELECT count(*) FROM security_events) AS events",
    )
    .fetch_one(database.pool())
    .await
    .expect("counting must succeed");
    assert_eq!(row.get::<i64, _>("entries"), 1);
    assert_eq!(row.get::<i64, _>("receipts"), 1);
    assert_eq!(
        row.get::<i64, _>("events"),
        0,
        "a replay is never a security event"
    );

    database.cleanup().await;
}

/// Zwei aufeinanderfolgende Eintraege: die Kette waechst, und die Annahmezeit
/// laeuft nie rueckwaerts.
#[tokio::test(flavor = "multi_thread")]
async fn a_successor_extends_the_chain_and_never_moves_time_backwards() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS, false).await;

    let first = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xa3,
    );
    let response = post_commit(&server, &closure, first.exact_bytes(), [0x04; 16]).await;
    assert_eq!(response.status, 200, "{:?}", error_code(&response.body));

    // Der Nachfolger laeuft gegen einen Server, dessen Uhr ZURUECK steht.
    let earlier = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS - 400),
        closure.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;
    let second = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence() + 1,
        Some(first.identity().entry_hash()),
        0xa4,
    );
    let response = post_commit_at(
        &earlier,
        &closure,
        second.exact_bytes(),
        [0x05; 16],
        SERVER_NOW_MILLIS - 400,
    )
    .await;
    assert_eq!(response.status, 200, "{:?}", error_code(&response.body));
    let decoded = EntryCommitResponseV1::decode(&response.body).expect("the response decodes");
    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(decoded.receipt_bytes()).expect("the receipt parses")
    else {
        panic!("the response carries a receipt");
    };
    assert_eq!(
        receipt.value().core().fields().accepted_at_server,
        UnixMillis::new(SERVER_NOW_MILLIS),
        "the successor never precedes its predecessor"
    );

    let entries: i64 = sqlx::query_scalar("SELECT count(*) FROM entries")
        .fetch_one(database.pool())
        .await
        .expect("counting must succeed");
    assert_eq!(entries, 2);

    database.cleanup().await;
}

/// Die Quittung liegt content-addressed im Object Store und ist von dort
/// BYTEGLEICH abrufbar — Schritt 9 liest genau das zurueck.
#[tokio::test(flavor = "multi_thread")]
async fn the_accepted_receipt_is_stored_content_addressed() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS, false).await;

    let request = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xa5,
    );
    let response = post_commit(&server, &closure, request.exact_bytes(), [0x06; 16]).await;
    assert_eq!(response.status, 200, "{:?}", error_code(&response.body));
    let decoded = EntryCommitResponseV1::decode(&response.body).expect("the response decodes");

    let hash = ea_crypto::object_hash(decoded.receipt_bytes());
    let stored: Vec<u8> = common::object_store_client()
        .await
        .get_object()
        .bucket(common::INTEGRATION_BUCKET)
        .key(ea_sync_server::object_key(
            ea_format::ObjectTypeV1::Receipt,
            hash,
        ))
        .send()
        .await
        .expect("the receipt must be in the object store")
        .body
        .collect()
        .await
        .expect("reading the receipt must succeed")
        .into_bytes()
        .to_vec();
    assert_eq!(stored, decoded.receipt_bytes());

    // Und die Datenbank nennt genau diesen Hash.
    let indexed: Vec<u8> = sqlx::query_scalar("SELECT receipt_object_hash FROM entries")
        .fetch_one(database.pool())
        .await
        .expect("reading the receipt hash must succeed");
    assert_eq!(indexed, hash.as_bytes());

    database.cleanup().await;
}

/// Der bei einem Replay verworfene Receipt bleibt eine UNSICHTBARE Waise —
/// gemessen gegen die ECHTEN Adapter.
///
/// `design.md` §13.3, vorletzter Absatz: eine Reconciliation „darf einen
/// Receipt nicht als angenommen ausgeben, solange keine atomare
/// Commit-Referenz existiert". Ein Replay bildet zuerst eine Quittung — er
/// weiss vorher nicht, dass er einer ist —, legt sie content-addressed ab und
/// liefert dann die GESPEICHERTE aus. Die verworfene liegt danach wirklich im
/// Object Store.
///
/// Der Fall laeuft ueber `reconcile_object` mit dem ECHTEN Object Store und
/// dem ECHTEN Objektindex. Genau darin liegt seine Aussage: eine Attrappe des
/// Index wuerde die Invariante nachbilden, die der Test beweisen soll, statt
/// die zu messen, die die Adapter tatsaechlich halten.
#[tokio::test(flavor = "multi_thread")]
async fn the_receipt_discarded_by_a_replay_stays_an_invisible_orphan() {
    use std::sync::Arc;

    use ea_sync_server::reconcile::{ReconcileOutcomeV1, ReconcilePorts, reconcile_object};
    use einsatzarchiv_server::adapters::{
        clock::FixedClock, postgres::PostgresRepository, s3::S3ObjectStore,
    };

    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS, false).await;

    let request = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xa6,
    );
    let accepted = post_commit(&server, &closure, request.exact_bytes(), [0x07; 16]).await;
    assert_eq!(accepted.status, 200, "{:?}", error_code(&accepted.body));
    let accepted = EntryCommitResponseV1::decode(&accepted.body).expect("the response decodes");
    let accepted_hash = ea_crypto::object_hash(accepted.receipt_bytes());

    // Ein zweiter Server mit SPAETERER Uhr: sein Replay bildet eine andere
    // Quittung, legt sie ab und liefert dennoch die gespeicherte aus.
    let later = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS + 4_000),
        closure.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;
    let replay = post_commit_at(
        &later,
        &closure,
        request.exact_bytes(),
        [0x08; 16],
        SERVER_NOW_MILLIS + 4_000,
    )
    .await;
    assert_eq!(replay.status, 200, "{:?}", error_code(&replay.body));

    // Die verworfene Quittung: dieselben Bindungen, aber die spaetere
    // Annahmezeit. Sie wird hier NACHGEBILDET, um ihre Adresse zu kennen.
    let discarded_hash = {
        let esr_prefix = ea_format::ESR_PREFIX_V1;
        let client = common::object_store_client().await;
        let listed = client
            .list_objects_v2()
            .bucket(common::INTEGRATION_BUCKET)
            .prefix("esr/")
            .send()
            .await
            .expect("listing the receipts must succeed");
        let mut orphan = None;
        for object in listed.contents() {
            let key = object.key().expect("a stored object has a key");
            let bytes = client
                .get_object()
                .bucket(common::INTEGRATION_BUCKET)
                .key(key)
                .send()
                .await
                .expect("reading a stored receipt must succeed")
                .body
                .collect()
                .await
                .expect("collecting must succeed")
                .into_bytes()
                .to_vec();
            assert!(bytes.starts_with(&esr_prefix), "the esr prefix holds");
            let hash = ea_crypto::object_hash(&bytes);
            if hash != accepted_hash {
                orphan = Some(hash);
            }
        }
        orphan.expect("the replay left its discarded receipt behind")
    };

    let repository = Arc::new(PostgresRepository::new(database.pool().clone()));
    let clock = Arc::new(FixedClock(UnixMillis::new(SERVER_NOW_MILLIS)));
    let objects = S3ObjectStore::new(
        common::object_store_client().await,
        common::INTEGRATION_BUCKET.to_owned(),
        closure.organization_id,
        repository.clone(),
        repository.clone(),
        clock.clone(),
    );
    let ports = ReconcilePorts {
        clock: clock.as_ref(),
        objects: &objects,
        object_types: repository.as_ref(),
        security: repository.as_ref(),
    };

    // Die ANGENOMMENE Quittung nennt eine Commit-Referenz.
    assert_eq!(
        reconcile_object(
            accepted_hash,
            ea_format::ObjectTypeV1::Receipt,
            closure.organization_id,
            &ports
        )
        .await
        .expect("the accepted receipt is readable"),
        ReconcileOutcomeV1::Adopted
    );
    // Die VERWORFENE nicht — und sie wird niemals als angenommen ausgegeben.
    assert_eq!(
        reconcile_object(
            discarded_hash,
            ea_format::ObjectTypeV1::Receipt,
            closure.organization_id,
            &ports
        )
        .await
        .expect("the discarded receipt is readable"),
        ReconcileOutcomeV1::InvisibleOrphan
    );
    // Eine Waise ist kein Angriff.
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(database.pool())
        .await
        .expect("counting security events must succeed");
    assert_eq!(events, 0);

    database.cleanup().await;
}
