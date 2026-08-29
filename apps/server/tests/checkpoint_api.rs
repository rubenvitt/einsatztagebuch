//! Der Standard-Checkpoint und `GET /v1/checkpoints?after={cursor}` gegen
//! ECHTE Dienste.
//!
//! Jeder Fall laeuft den ganzen Weg: TLS 1.3, Axum, RFC-9421-Pruefung, die
//! geteilte `ea-trust`-Pruefung, PostgreSQL und der Object Store. Der
//! Vertrauensabschluss und die Archivobjekte kommen aus derselben Kulisse wie
//! im Commit-Test (`common::trust_closure`, `common::archive_objects`); eine
//! zweite Kulisse waere eine zweite Auslegung derselben Regeln.
//!
//! # Warum EIN Fall die Transaktion direkt ruft
//!
//! Der abweichende Vorgaenger ist unter der Kettenkopfsperre nicht ueber HTTP
//! erreichbar: der Checkpoint reist IN der Commit-Transaktion, also bewegt
//! sich der Checkpoint-Kopf nie ohne den Kettenkopf, und ein Nachzuegler
//! scheitert vorher an Sequenz oder Vorgaenger. Geprueft wird der Zwang
//! deshalb dort, wo er wohnt — an der echten Datenbank, wie schon der uebrige
//! Vertrag von `commit_locked_head` in `apps/server/tests/migrations.rs`.

mod common;

use common::{archive_objects, trust_closure};
use ea_crypto::SecretBytes;
use ea_format::ObjectTypeV1;
use ea_sync_protocol::{
    CheckpointListResponseV1, EndpointV1, EntryCommitOutcome, EntryCommitResponseV1,
    ProtocolErrorV1, RequestSigner,
};
use ea_sync_server::{
    CheckpointCommitV1, CommitDbCommand, CommitIdentityV1, CommitRepository, IndexedObjectV1,
    RepositoryError,
};
use ea_types::{CertificateHash, ChainSequence, EntryHash, ObjectHash, UnixMillis};
use sqlx::Row;

/// Innerhalb des `notBefore`/`notAfter`-Fensters aller Koepfe.
const SERVER_NOW_MILLIS: i64 = 1_000;
const SERVER_SECRET: [u8; 32] = [0x51; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];

/// Der Kopf, auf dem die Kette bereits steht, bevor der Testfall committet.
/// Er traegt bewusst KEINEN Checkpoint: der erste Checkpoint dieser Kette hat
/// deshalb keinen Vorgaenger.
const SEEDED_HEAD_ENTRY_HASH: [u8; 32] = [0x77; 32];
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

/// Der Kern eines archivierten Standard-Checkpoints.
fn checkpoint_core(bytes: &[u8]) -> ea_format::CheckpointCoreV1 {
    let ea_format::ParsedArchiveObject::Evidence(parsed) =
        ea_format::decode_exact_object(bytes).expect("the checkpoint parses")
    else {
        panic!("a standard checkpoint is an evidence object");
    };
    assert_eq!(
        parsed.value().kind(),
        ea_format::EvidenceKindV1::StandardCheckpoint
    );
    let ea_format::DecodedEvidencePayloadV1::Standard { core, .. } = parsed
        .value()
        .decoded_payload()
        .expect("the payload decodes")
    else {
        panic!("Stufe 3 stellt keinen zeitgestempelten Checkpoint aus");
    };
    core
}

async fn stand_up(
    database: &common::TestDatabase,
    now_millis: i64,
) -> (common::TestServer, trust_closure::ExtendedClosure) {
    let fixture =
        common::seed_trust_fixture(database.pool(), trust_closure::ROTATION_CASE, &[]).await;
    let closure = trust_closure::build(false);
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

async fn post_commit(
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

/// Eine signierte Leseanfrage auf die Checkpoint-Seite.
async fn get_checkpoints(
    server: &common::TestServer,
    closure: &trust_closure::ExtendedClosure,
    after: Option<&str>,
    request_id: [u8; 16],
) -> common::HttpResponse {
    let target = after.map_or_else(
        || EndpointV1::Checkpoints.path_template().to_owned(),
        |cursor| format!("{}?after={cursor}", EndpointV1::Checkpoints.path_template()),
    );
    let nonce = common::fresh_challenge(server, closure.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(trust_closure::WRITER_SEED),
        endpoint: EndpointV1::Checkpoints,
        authority: &server.authority,
        target: &target,
        body: None,
        organization_id: closure.organization_id,
        request_id,
        nonce,
        created: SERVER_NOW_MILLIS.div_euclid(1_000),
    });
    common::https_request(
        server.address,
        &server.authority,
        "GET",
        &target,
        &headers,
        &[],
    )
    .await
}

/// Der angenommene Commit liefert `checkpoint-bytes`, und der Checkpoint
/// bindet GENAU den Kopf, der gerade sichtbar geworden ist.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_commit_answers_with_a_checkpoint_over_the_committed_head() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS).await;

    let request = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xc1,
    );
    let response = post_commit(
        &server,
        &closure,
        request.exact_bytes(),
        [0x11; 16],
        SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(
        response.status,
        200,
        "a complete commit must be accepted; the server answered {:?}",
        error_code(&response.body)
    );
    let decoded = EntryCommitResponseV1::decode(&response.body).expect("the response decodes");
    assert_eq!(decoded.outcome(), EntryCommitOutcome::Accepted);

    let checkpoint_bytes = decoded
        .checkpoint_bytes()
        .expect("an accepted commit carries its standard checkpoint");
    let core = checkpoint_core(checkpoint_bytes);
    let fields = core.fields();
    assert!(fields.organization_id == closure.organization_id);
    assert!(fields.chain_id == closure.chain_id);
    assert_eq!(
        fields.covered_through_sequence.get(),
        trust_closure::ExtendedClosure::commit_sequence()
    );
    assert_eq!(
        fields.covered_from_sequence.get(),
        fields.covered_through_sequence.get()
    );
    assert!(fields.head_entry_hash == request.identity().entry_hash());
    assert_eq!(
        fields.registry_head_hash.as_bytes(),
        closure.registry_head_hash.as_bytes()
    );
    // Die Ausstellungszeit ist die ANNAHMEZEIT des Commits und keine zweite
    // Uhrablesung: ein Checkpoint darf nicht vor dem Eintrag liegen, den er
    // abdeckt.
    assert_eq!(fields.issued_at_server, UnixMillis::new(SERVER_NOW_MILLIS));
    // Die Kette dieses Servers beginnt hier: kein Vorgaenger.
    assert!(fields.previous_evidence_hash.is_none());

    // Der Checkpoint steht content-addressed im Objektindex UND in der
    // Checkpoint-Tabelle — gemeinsam mit Eintrag, Grants und Quittung.
    let object_hash = ea_crypto::object_hash(checkpoint_bytes);
    let row = sqlx::query(
        "SELECT c.covered_sequence, c.issued_at_millis, c.technical_index, o.object_type_code \
         FROM checkpoints c JOIN object_index o ON o.object_hash = c.object_hash \
         WHERE c.object_hash = $1",
    )
    .bind(&object_hash.as_bytes()[..])
    .fetch_one(database.pool())
    .await
    .expect("the checkpoint row must be visible together with the commit");
    assert_eq!(
        u64::try_from(row.get::<i64, _>("covered_sequence")).expect("a sequence is not negative"),
        trust_closure::ExtendedClosure::commit_sequence()
    );
    assert_eq!(row.get::<i64, _>("issued_at_millis"), SERVER_NOW_MILLIS);
    assert_eq!(
        row.get::<i16, _>("object_type_code"),
        i16::try_from(ObjectTypeV1::Evidence.code()).expect("a code fits")
    );

    // Und die archivierten Bytes sind BYTEGLEICH die ausgelieferten.
    let stored = common::object_store_client()
        .await
        .get_object()
        .bucket(common::INTEGRATION_BUCKET)
        .key(format!("ecp/{}", hex::encode(object_hash.as_bytes())))
        .send()
        .await
        .expect("the checkpoint must lie under its content-addressed key");
    let stored = stored
        .body
        .collect()
        .await
        .expect("the stored body reads")
        .into_bytes()
        .to_vec();
    assert_eq!(stored, checkpoint_bytes);

    // Kein Security Event auf dem glueklichen Pfad.
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(database.pool())
        .await
        .expect("counting security events must succeed");
    assert_eq!(events, 0);

    database.cleanup().await;
}

/// Zwei aufeinanderfolgende Commits: der zweite Checkpoint bindet den ersten
/// ueber `previous-evidence-hash`, und die Kette gabelt sich nicht.
#[tokio::test(flavor = "multi_thread")]
async fn the_checkpoint_chain_binds_its_predecessor_across_two_commits() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS).await;

    let first_request = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xc2,
    );
    let first = post_commit(
        &server,
        &closure,
        first_request.exact_bytes(),
        [0x21; 16],
        SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(first.status, 200, "{:?}", error_code(&first.body));
    let first = EntryCommitResponseV1::decode(&first.body).expect("the response decodes");
    let first_checkpoint = first
        .checkpoint_bytes()
        .expect("the first commit carries a checkpoint")
        .to_vec();

    let second_request = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence() + 1,
        Some(first_request.identity().entry_hash()),
        0xc3,
    );
    let second = post_commit(
        &server,
        &closure,
        second_request.exact_bytes(),
        [0x22; 16],
        SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(second.status, 200, "{:?}", error_code(&second.body));
    let second = EntryCommitResponseV1::decode(&second.body).expect("the response decodes");
    let second_checkpoint = second
        .checkpoint_bytes()
        .expect("the successor carries a checkpoint")
        .to_vec();

    let first_hash = ea_crypto::object_hash(&first_checkpoint);
    let second_core = checkpoint_core(&second_checkpoint);
    assert!(
        second_core.fields().previous_evidence_hash == Some(first_hash),
        "every checkpoint binds its predecessor"
    );
    assert_eq!(
        second_core.fields().covered_through_sequence.get(),
        trust_closure::ExtendedClosure::commit_sequence() + 1
    );

    // Genau zwei Checkpoints, und ihre Blaetterpositionen steigen.
    let rows = sqlx::query(
        "SELECT object_hash, technical_index FROM checkpoints ORDER BY technical_index",
    )
    .fetch_all(database.pool())
    .await
    .expect("reading the checkpoints must succeed");
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].get::<Vec<u8>, _>("object_hash"),
        first_hash.as_bytes().to_vec()
    );
    assert!(
        rows[0].get::<i64, _>("technical_index") < rows[1].get::<i64, _>("technical_index"),
        "the technical index counts forward"
    );

    database.cleanup().await;
}

/// Ein idempotenter Replay liefert den GESPEICHERTEN Checkpoint byteweise
/// zurueck und legt keinen zweiten an.
#[tokio::test(flavor = "multi_thread")]
async fn an_idempotent_replay_returns_the_stored_checkpoint_bytes() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS).await;

    let request = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xc4,
    );
    let first = post_commit(
        &server,
        &closure,
        request.exact_bytes(),
        [0x31; 16],
        SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(first.status, 200, "{:?}", error_code(&first.body));
    let first = EntryCommitResponseV1::decode(&first.body).expect("the response decodes");

    let later = common::spawn_server(
        database.pool().clone(),
        UnixMillis::new(SERVER_NOW_MILLIS + 4_000),
        closure.organization_id,
        SERVER_SECRET,
        CertificateHash::try_from(&SERVER_CERTIFICATE_HASH[..]).expect("32 bytes"),
    )
    .await;
    let second = post_commit(
        &later,
        &closure,
        request.exact_bytes(),
        [0x32; 16],
        SERVER_NOW_MILLIS + 4_000,
    )
    .await;
    assert_eq!(second.status, 200, "{:?}", error_code(&second.body));
    let second = EntryCommitResponseV1::decode(&second.body).expect("the response decodes");
    assert_eq!(second.outcome(), EntryCommitOutcome::IdempotentReplay);
    assert_eq!(
        first.checkpoint_bytes(),
        second.checkpoint_bytes(),
        "a replay changes neither the issuing time nor a single checkpoint byte"
    );

    let checkpoints: i64 = sqlx::query_scalar("SELECT count(*) FROM checkpoints")
        .fetch_one(database.pool())
        .await
        .expect("counting must succeed");
    assert_eq!(checkpoints, 1, "a replay anchors nothing a second time");

    database.cleanup().await;
}

/// `GET /v1/checkpoints` liefert die EXAKTEN archivierten Bytes und keinen
/// Cursor, solange die Seite nicht voll ist.
#[tokio::test(flavor = "multi_thread")]
async fn the_checkpoint_page_delivers_the_exact_archived_bytes() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS).await;

    let request = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xc5,
    );
    let commit = post_commit(
        &server,
        &closure,
        request.exact_bytes(),
        [0x41; 16],
        SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(commit.status, 200, "{:?}", error_code(&commit.body));
    let commit = EntryCommitResponseV1::decode(&commit.body).expect("the response decodes");
    let expected = commit
        .checkpoint_bytes()
        .expect("the commit carries a checkpoint")
        .to_vec();

    let page = get_checkpoints(&server, &closure, None, [0x42; 16]).await;
    assert_eq!(page.status, 200, "{:?}", error_code(&page.body));
    assert_eq!(
        page.header("content-type"),
        Some(ea_sync_protocol::STRUCTURED_MEDIA_TYPE_V1)
    );
    let page = CheckpointListResponseV1::decode(&page.body).expect("the page decodes");
    assert_eq!(page.requested_cursor(), None);
    assert_eq!(page.next_cursor(), None);
    assert_eq!(page.checkpoints().len(), 1);
    assert_eq!(page.checkpoints()[0].exact_object_bytes(), expected);
    assert!(page.checkpoints()[0].object_hash() == ea_crypto::object_hash(&expected));

    database.cleanup().await;
}

/// Eine leere Seite ist ein `200` mit leerer Liste und `next-cursor = null` —
/// ausdruecklich KEIN `204`.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_checkpoint_page_is_an_empty_list_and_not_a_no_content() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS).await;

    let page = get_checkpoints(&server, &closure, None, [0x51; 16]).await;
    assert_eq!(page.status, 200, "{:?}", error_code(&page.body));
    let page = CheckpointListResponseV1::decode(&page.body).expect("the page decodes");
    assert!(page.checkpoints().is_empty());
    assert_eq!(page.next_cursor(), None);

    database.cleanup().await;
}

/// Ein unlesbarer Cursor ist ein `400` — und der Fehlerkoerper verraet nicht,
/// woran die Form brach.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_cursor_is_refused_with_four_hundred() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS).await;

    let page = get_checkpoints(&server, &closure, Some("00ff00ff"), [0x61; 16]).await;
    assert_eq!(page.status, 400);
    assert_eq!(
        error_code(&page.body).as_deref(),
        Some("EA-SYNC-CURSOR-INVALID")
    );

    // Und derselbe Befund fuer eine Zeichenkette, die gar kein Hex ist.
    let page = get_checkpoints(&server, &closure, Some("zzzz"), [0x62; 16]).await;
    assert_eq!(page.status, 400);
    assert_eq!(
        error_code(&page.body).as_deref(),
        Some("EA-SYNC-CURSOR-INVALID")
    );

    database.cleanup().await;
}

/// Der abweichende Vorgaenger wird von der GESPERRTEN Transaktion abgewiesen.
///
/// Der Aufruf geht bewusst direkt an den Adapter: unter der Kettenkopfsperre
/// ist dieser Widerspruch ueber HTTP nicht erreichbar, weil der Checkpoint IN
/// der Commit-Transaktion reist. Genau deshalb muss der Zwang selbst geprueft
/// werden — an der echten Datenbank und nicht an einer Attrappe.
#[tokio::test(flavor = "multi_thread")]
async fn a_divergent_checkpoint_predecessor_is_refused_by_the_locked_transaction() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, SERVER_NOW_MILLIS).await;

    let request = archive_objects::valid_commit(
        &closure,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xc6,
    );
    let commit = post_commit(
        &server,
        &closure,
        request.exact_bytes(),
        [0x71; 16],
        SERVER_NOW_MILLIS,
    )
    .await;
    assert_eq!(commit.status, 200, "{:?}", error_code(&commit.body));

    let repository =
        einsatzarchiv_server::adapters::postgres::PostgresRepository::new(database.pool().clone());
    let head = repository
        .checkpoint_head(closure.organization_id, closure.chain_id)
        .await
        .expect("reading the checkpoint head must succeed")
        .expect("the accepted commit anchored a checkpoint");
    let foreign = ObjectHash::try_from(&[0xee_u8; 32][..]).expect("thirty two bytes");
    assert!(head != foreign);

    let next_sequence = trust_closure::ExtendedClosure::commit_sequence() + 1;
    let command = CommitDbCommand {
        organization_id: closure.organization_id,
        chain_id: closure.chain_id,
        device_id: ea_types::DeviceId::from(
            ea_types::Id16::try_from(&[0x60_u8; 16][..]).expect("sixteen bytes"),
        ),
        sequence: ChainSequence::new(next_sequence),
        previous_entry_hash: Some(request.identity().entry_hash()),
        identity: CommitIdentityV1 {
            entry_hash: EntryHash::try_from(&[0xa0_u8; 32][..]).expect("thirty two bytes"),
            entry_object_hash: ObjectHash::try_from(&[0xa1_u8; 32][..]).expect("thirty two bytes"),
            initial_grant_plan_hash: ea_types::Hash32::try_from(&[0xa2_u8; 32][..])
                .expect("thirty two bytes"),
            initial_grant_object_hashes: vec![
                ObjectHash::try_from(&[0xa3_u8; 32][..]).expect("thirty two bytes"),
            ],
        },
        receipt_object_hash: ObjectHash::try_from(&[0xa4_u8; 32][..]).expect("thirty two bytes"),
        accepted_at_server: UnixMillis::new(SERVER_NOW_MILLIS),
        evidence_due_at: None,
        registry_version: closure.registry_version,
        registry_head_hash: closure.registry_head_hash,
        indexed_objects: vec![
            IndexedObjectV1 {
                kind: ObjectTypeV1::Entry,
                object_hash: ObjectHash::try_from(&[0xa1_u8; 32][..]).expect("thirty two bytes"),
                size_bytes: 512,
            },
            IndexedObjectV1 {
                kind: ObjectTypeV1::Grant,
                object_hash: ObjectHash::try_from(&[0xa3_u8; 32][..]).expect("thirty two bytes"),
                size_bytes: 641,
            },
            IndexedObjectV1 {
                kind: ObjectTypeV1::Receipt,
                object_hash: ObjectHash::try_from(&[0xa4_u8; 32][..]).expect("thirty two bytes"),
                size_bytes: 256,
            },
            IndexedObjectV1 {
                kind: ObjectTypeV1::Evidence,
                object_hash: ObjectHash::try_from(&[0xa5_u8; 32][..]).expect("thirty two bytes"),
                size_bytes: 256,
            },
        ],
        checkpoint: CheckpointCommitV1 {
            object_hash: ObjectHash::try_from(&[0xa5_u8; 32][..]).expect("thirty two bytes"),
            covered_sequence: ChainSequence::new(next_sequence),
            issued_at_server: UnixMillis::new(SERVER_NOW_MILLIS),
            previous_evidence_hash: Some(foreign),
        },
    };
    let error = repository
        .commit_locked_head(command)
        .await
        .expect_err("a checkpoint over a foreign predecessor must not become visible");
    assert_eq!(error, RepositoryError::CheckpointPredecessorConflict);

    // Und es ist NICHTS entstanden: die Transaktion ist ganz zurueckgerollt.
    let row = sqlx::query(
        "SELECT (SELECT count(*) FROM entries) AS entries, \
         (SELECT count(*) FROM checkpoints) AS checkpoints",
    )
    .fetch_one(database.pool())
    .await
    .expect("counting must succeed");
    assert_eq!(row.get::<i64, _>("entries"), 1);
    assert_eq!(row.get::<i64, _>("checkpoints"), 1);

    database.cleanup().await;
}
