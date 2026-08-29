//! Die Abweisungen des Commit-Endpunkts, gegen ECHTE Dienste.
//!
//! Zwei Schichten in einem Ziel, und beide gegen denselben echten Server:
//!
//! 1. die NEUN SCHRITTE selbst — unvollstaendige Empfaengermenge, Fork,
//!    falscher Vorgaenger, unzulaessiger Writer, fremde Kette und ein zu alt
//!    gebundener Registry-Head —, und
//! 2. die KANTE davor: Rahmen, Grenzen, Medientyp, Pfad, Signatur, Capability.
//!
//! Jede Antwort ist ein `protocol-error-v1` mit einem stabilen Code, keine
//! traegt ein Fragment der gelieferten Nutzdaten, und nach jeder Abweisung ist
//! NICHTS sichtbar, was vorher nicht sichtbar war.

mod common;

use common::{archive_objects, trust_closure};
use ea_crypto::SecretBytes;
use ea_sync_protocol::{
    EndpointV1, MAX_ENTRY_COMMIT_BODY_BYTES_V1, ProtocolErrorV1, RequestSigner,
    STRUCTURED_MEDIA_TYPE_V1,
};
use ea_types::{CertificateHash, EntryHash, RegistryVersion, UnixMillis};
use sqlx::Row;

const SERVER_NOW_MILLIS: i64 = 1_000;
const SERVER_SECRET: [u8; 32] = [0x51; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x52; 32];

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

fn commit_sequence() -> u64 {
    trust_closure::ExtendedClosure::commit_sequence()
}

/// Ein Server mit fortgeschriebenem Abschluss und stehender Kette.
async fn stand_up(
    database: &common::TestDatabase,
    with_second_reader: bool,
) -> (common::TestServer, trust_closure::ExtendedClosure) {
    common::seed_trust_fixture(database.pool(), trust_closure::ROTATION_CASE, &[]).await;
    let closure = trust_closure::build(with_second_reader);
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

/// Ein signierter Commit gegen den echten Server, mit waehlbarem Signierer.
async fn post_commit_as(
    server: &common::TestServer,
    closure: &trust_closure::ExtendedClosure,
    caller_seed: [u8; 32],
    body: &[u8],
    request_id: [u8; 16],
) -> common::HttpResponse {
    let target = archive_objects::entry_commit_path(closure.chain_id);
    post_to(server, closure, caller_seed, &target, body, request_id).await
}

/// Derselbe Aufruf gegen ein FREI gewaehltes Ziel.
async fn post_to(
    server: &common::TestServer,
    closure: &trust_closure::ExtendedClosure,
    caller_seed: [u8; 32],
    target: &str,
    body: &[u8],
    request_id: [u8; 16],
) -> common::HttpResponse {
    let nonce = common::fresh_challenge(server, closure.organization_id).await;
    let headers = common::signed_headers(&common::SignedCall {
        signer: &signer(caller_seed),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target,
        body: Some(body),
        organization_id: closure.organization_id,
        request_id,
        nonce,
        created: SERVER_NOW_MILLIS / 1_000,
    });
    common::https_request(
        server.address,
        &server.authority,
        "POST",
        target,
        &headers,
        body,
    )
    .await
}

async fn post_commit(
    server: &common::TestServer,
    closure: &trust_closure::ExtendedClosure,
    body: &[u8],
    request_id: [u8; 16],
) -> common::HttpResponse {
    post_commit_as(
        server,
        closure,
        trust_closure::WRITER_SEED,
        body,
        request_id,
    )
    .await
}

/// Wie viele Eintraege, Quittungen und Security Events sichtbar sind.
async fn visible(pool: &sqlx::PgPool) -> (i64, i64, i64) {
    let row = sqlx::query(
        "SELECT (SELECT count(*) FROM entries) AS entries, \
         (SELECT count(*) FROM receipts) AS receipts, \
         (SELECT count(*) FROM security_events) AS events",
    )
    .fetch_one(pool)
    .await
    .expect("counting must succeed");
    (row.get("entries"), row.get("receipts"), row.get("events"))
}

async fn security_event_codes(pool: &sqlx::PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT event_code FROM security_events ORDER BY security_event_id")
        .fetch_all(pool)
        .await
        .expect("reading security events must succeed")
}

fn standard_recipients(
    closure: &trust_closure::ExtendedClosure,
) -> [archive_objects::Recipient; 2] {
    [
        archive_objects::Recipient::reader(closure),
        archive_objects::Recipient::recovery(closure),
    ]
}

// ---------------------------------------------------------------------------
// Die neun Schritte
// ---------------------------------------------------------------------------

/// Ein fehlender Reader-Grant weist den GANZEN Commit ab — Entry und Grants
/// sind eine unteilbare fachliche Transaktion.
#[tokio::test(flavor = "multi_thread")]
async fn an_incomplete_recipient_set_is_refused_atomically() {
    let database = common::fresh_database().await;
    // Der Kopf traegt ZWEI Reader; der Commit bedient nur einen.
    let (server, closure) = stand_up(&database, true).await;

    let request = archive_objects::commit_request(&archive_objects::CommitSpec {
        closure: &closure,
        sequence: commit_sequence(),
        previous_entry_hash: Some(seeded_head_entry_hash()),
        recipients: &standard_recipients(&closure),
        marker: 0xb1,
        writer_override: None,
        registry_override: None,
    });
    let response = post_commit(&server, &closure, request.exact_bytes(), [0x21; 16]).await;

    assert_eq!(response.status, 422);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-COMMIT-GRANT-SET")
    );
    assert_eq!(visible(database.pool()).await, (0, 0, 0));

    database.cleanup().await;
}

/// Gleiche Sequenz, ANDERER Eintrag: ein Fork, ein Security Event, `409` — und
/// der erste Eintrag bleibt unangetastet.
#[tokio::test(flavor = "multi_thread")]
async fn a_fork_on_the_same_sequence_is_refused_and_recorded() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let first = archive_objects::valid_commit(
        &closure,
        commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xb2,
    );
    let accepted = post_commit(&server, &closure, first.exact_bytes(), [0x22; 16]).await;
    assert_eq!(accepted.status, 200, "{:?}", error_code(&accepted.body));

    let fork = archive_objects::valid_commit(
        &closure,
        commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xb3,
    );
    let response = post_commit(&server, &closure, fork.exact_bytes(), [0x23; 16]).await;

    assert_eq!(response.status, 409);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-COMMIT-SEQUENCE-FORK")
    );
    assert_eq!(
        security_event_codes(database.pool()).await,
        vec!["sequence-fork".to_owned()]
    );
    let (entries, receipts, _) = visible(database.pool()).await;
    assert_eq!((entries, receipts), (1, 1));

    database.cleanup().await;
}

/// Ein falscher Vorgaenger ist ein EIGENER Befund mit eigenem Security Event.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_predecessor_is_refused_and_recorded() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let request = archive_objects::valid_commit(
        &closure,
        commit_sequence(),
        Some(EntryHash::try_from(&[0x99_u8; 32][..]).expect("32 bytes")),
        0xb4,
    );
    let response = post_commit(&server, &closure, request.exact_bytes(), [0x24; 16]).await;

    assert_eq!(response.status, 409);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-COMMIT-PREDECESSOR")
    );
    assert_eq!(
        security_event_codes(database.pool()).await,
        vec!["predecessor-mismatch".to_owned()]
    );
    assert_eq!(visible(database.pool()).await.0, 0);

    database.cleanup().await;
}

/// Ein Aufrufer, der NICHT der im Manifest benannte Writer ist, wird
/// abgewiesen — Security Event, `409`, nichts sichtbar.
///
/// Das Manifest benennt hier den READER als Schreiber und ist von dessen
/// Schluessel signiert; der Request kommt vom echten Writer. Beide Signaturen
/// tragen also, und die Abweisung kommt allein aus der Autoritaet.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_who_is_not_the_named_writer_is_refused() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let request = archive_objects::commit_request(&archive_objects::CommitSpec {
        closure: &closure,
        sequence: commit_sequence(),
        previous_entry_hash: Some(seeded_head_entry_hash()),
        recipients: &standard_recipients(&closure),
        marker: 0xb5,
        writer_override: Some((
            closure.reader_certificate_hash,
            trust_closure::READER_SIGNING_SEED,
        )),
        registry_override: None,
    });
    let response = post_commit(&server, &closure, request.exact_bytes(), [0x25; 16]).await;

    assert_eq!(response.status, 409);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-COMMIT-WRITER-UNAUTHORIZED")
    );
    assert_eq!(
        security_event_codes(database.pool()).await,
        vec!["writer-unauthorized".to_owned()]
    );
    assert_eq!(visible(database.pool()).await.0, 0);

    database.cleanup().await;
}

/// Ein Paket, das einen AELTEREN Registry-Head bindet, wird mit dem
/// erforderlichen Kopf abgewiesen.
///
/// `design.md` §13.3 Schritt 5 verlangt genau das, und `protocol-error-v1`
/// fuehrt Version und Hash an eigenen Pflichtpositionen: ein Aufrufer, der nur
/// den Code bekaeme, wuesste nicht, wohin.
#[tokio::test(flavor = "multi_thread")]
async fn a_package_binding_an_older_head_names_the_required_head() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let older = RegistryVersion::new(closure.registry_version.get() - 1);
    let request = archive_objects::commit_request(&archive_objects::CommitSpec {
        closure: &closure,
        sequence: commit_sequence(),
        previous_entry_hash: Some(seeded_head_entry_hash()),
        recipients: &standard_recipients(&closure),
        marker: 0xb6,
        writer_override: None,
        registry_override: Some((older, [0x5b; 32])),
    });
    let response = post_commit(&server, &closure, request.exact_bytes(), [0x26; 16]).await;

    // `409` und nicht `422`: die 409-Zeile des Nachtrags nennt „erforderlicher
    // neuerer Registry-Head" ausdruecklich, und der Aufrufer soll
    // wiederkommen statt aufzugeben.
    assert_eq!(response.status, 409);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-COMMIT-REGISTRY")
    );
    let error = ProtocolErrorV1::decode(&response.body).expect("the error body decodes");
    assert!(
        error.required_registry_version() == Some(closure.registry_version),
        "the caller is told which head to fetch"
    );
    assert_eq!(
        error
            .required_registry_head_hash()
            .map(|hash| hash.as_bytes().to_vec()),
        Some(closure.registry_head_hash.as_bytes().to_vec())
    );
    assert_eq!(visible(database.pool()).await, (0, 0, 0));

    database.cleanup().await;
}

/// Eine FREMDE Kette im Pfad wird abgewiesen: Manifest, Pfad und Anker muessen
/// dieselbe Kette nennen.
#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_chain_in_the_path_is_refused() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let request = archive_objects::valid_commit(
        &closure,
        commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xb7,
    );
    let foreign =
        ea_types::ChainId::from(ea_types::Id16::try_from(&[0x6f_u8; 16][..]).expect("16 bytes"));
    let response = post_to(
        &server,
        &closure,
        trust_closure::WRITER_SEED,
        &archive_objects::entry_commit_path(foreign),
        request.exact_bytes(),
        [0x27; 16],
    )
    .await;

    assert_eq!(response.status, 422);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-COMMIT-CHAIN")
    );
    assert_eq!(visible(database.pool()).await, (0, 0, 0));

    database.cleanup().await;
}

// ---------------------------------------------------------------------------
// Die Kante
// ---------------------------------------------------------------------------

/// Ohne RFC-9421-Signatur kommt niemand an diesen Endpunkt.
#[tokio::test(flavor = "multi_thread")]
async fn an_unsigned_commit_is_refused() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &archive_objects::entry_commit_path(closure.chain_id),
        &[("content-type", STRUCTURED_MEDIA_TYPE_V1.to_owned())],
        b"\x85\x01\x40\x80\x80",
    )
    .await;

    assert_eq!(response.status, 401, "an unsigned commit is never accepted");
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-HTTP-SIGNATURE-MALFORMED")
    );

    database.cleanup().await;
}

/// Ein Aufrufer OHNE `initialGrant` erreicht die neun Schritte nicht.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_without_the_capability_never_reaches_the_commit() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let request = archive_objects::valid_commit(
        &closure,
        commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xb8,
    );
    // Der Reader ist ein freigegebenes Geraet — er traegt nur keine
    // `initialGrant`-Capability.
    let response = post_commit_as(
        &server,
        &closure,
        trust_closure::READER_SIGNING_SEED,
        request.exact_bytes(),
        [0x28; 16],
    )
    .await;

    assert_eq!(response.status, 403);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-HTTP-CAPABILITY-MISSING")
    );
    assert_eq!(visible(database.pool()).await, (0, 0, 0));

    database.cleanup().await;
}

/// Die Koerperdecke greift VOR der Akkumulation.
#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_body_is_refused_by_the_limit() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let body = vec![0x00_u8; MAX_ENTRY_COMMIT_BODY_BYTES_V1 + 1];
    let response = post_commit(&server, &closure, &body, [0x29; 16]).await;

    assert_eq!(response.status, 413);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-SYNC-BODY-LIMIT")
    );

    database.cleanup().await;
}

/// Ein Koerper, der kein `entry-commit-request-v1` ist, wird als Rahmenfehler
/// abgewiesen — und niemals halb verarbeitet.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_frame_is_refused() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let response = post_commit(&server, &closure, b"\xff\xff\xff\xff", [0x2a; 16]).await;

    assert_eq!(response.status, 400);
    assert!(ProtocolErrorV1::decode(&response.body).is_ok());
    assert_eq!(visible(database.pool()).await, (0, 0, 0));

    database.cleanup().await;
}

/// Eine unlesbare Kettenkennung im Pfad ist eine UNBEKANNTE Kette.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_chain_id_is_an_unknown_chain() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let request = archive_objects::valid_commit(
        &closure,
        commit_sequence(),
        Some(seeded_head_entry_hash()),
        0xb9,
    );
    let response = post_to(
        &server,
        &closure,
        trust_closure::WRITER_SEED,
        "/v1/chains/nichtHex/entry-commits",
        request.exact_bytes(),
        [0x2b; 16],
    )
    .await;

    assert_eq!(response.status, 404);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-SYNC-NOT-FOUND")
    );

    database.cleanup().await;
}

/// Ein falscher Medientyp ist ein RAHMENFEHLER.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_media_type_is_refused() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let body = b"\x85\x01\x40\x80\x80".to_vec();
    let target = archive_objects::entry_commit_path(closure.chain_id);
    let nonce = common::fresh_challenge(&server, closure.organization_id).await;
    let mut headers = common::signed_headers(&common::SignedCall {
        signer: &signer(trust_closure::WRITER_SEED),
        endpoint: EndpointV1::EntryCommits,
        authority: &server.authority,
        target: &target,
        body: Some(&body),
        organization_id: closure.organization_id,
        request_id: [0x2c; 16],
        nonce,
        created: SERVER_NOW_MILLIS / 1_000,
    });
    for header in &mut headers {
        if header.0 == "content-type" {
            header.1 = "application/octet-stream".to_owned();
        }
    }
    let response = common::https_request(
        server.address,
        &server.authority,
        "POST",
        &target,
        &headers,
        &body,
    )
    .await;

    // `400` und nicht `401`: die Abbildung des Nachtrags fuehrt einen
    // fehlerhaften Rahmen — und der Medientyp ist Teil des Rahmens — in der
    // 400-Zeile, waehrend 401 der Signatur selbst gehoert.
    assert_eq!(response.status, 400);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-HTTP-CONTENT-TYPE")
    );

    database.cleanup().await;
}

/// Ein Schluessel, den KEIN Trust-Objekt kennt, loest nicht auf.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_key_never_reaches_the_commit() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let response = post_commit_as(
        &server,
        &closure,
        [0x9c; 32],
        b"\x85\x01\x40\x80\x80",
        [0x2d; 16],
    )
    .await;

    assert_eq!(response.status, 401);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-HTTP-KEY-UNRESOLVED")
    );

    database.cleanup().await;
}

/// Der Fehlerkoerper traegt KEIN Fragment der gelieferten Nutzdaten.
#[tokio::test(flavor = "multi_thread")]
async fn the_error_body_carries_no_fragment_of_the_delivered_payload() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, false).await;

    let request = archive_objects::valid_commit(
        &closure,
        commit_sequence(),
        Some(EntryHash::try_from(&[0x99_u8; 32][..]).expect("32 bytes")),
        0xba,
    );
    let body = request.exact_bytes().to_vec();
    let response = post_commit(&server, &closure, &body, [0x2e; 16]).await;
    assert_eq!(response.status, 409);

    // Zweiunddreissig Byte aus der Mitte des Koerpers sind lang genug, um
    // zufaellige Treffer auszuschliessen.
    let canary = &body[body.len() / 2..body.len() / 2 + 32];
    assert!(
        !ea_testkit::contains_canary(&response.body, canary),
        "the error body must not echo the delivered payload"
    );

    database.cleanup().await;
}

/// Ein UEBERZAEHLIGER Grant wird ebenso abgewiesen wie ein fehlender: der
/// gelieferte Satz muss die aktive Empfaengermenge GENAU treffen.
///
/// Der Commit wird gegen einen Abschluss MIT zweitem Reader gebaut und gegen
/// einen Server OHNE ihn gefuehrt. Der Server kennt dieses Zertifikat also
/// gar nicht — und genau das ist der Punkt: die Menge gehoert dem Kopf, nicht
/// dem Aufrufer.
#[tokio::test(flavor = "multi_thread")]
async fn a_superfluous_grant_is_refused_as_well() {
    let database = common::fresh_database().await;
    let (server, narrow) = stand_up(&database, false).await;
    // Nur fuer das ZERTIFIKAT des zweiten Readers — Eintrag, Grants und
    // gebundener Kopf gehoeren dem schmalen Abschluss, damit die
    // Registry-Pruefung traegt und der Befund wirklich die Empfaengermenge
    // trifft.
    let wide = trust_closure::build(true);

    let request = archive_objects::commit_request(&archive_objects::CommitSpec {
        closure: &narrow,
        sequence: commit_sequence(),
        previous_entry_hash: Some(seeded_head_entry_hash()),
        recipients: &[
            archive_objects::Recipient::reader(&narrow),
            archive_objects::Recipient::second_reader(&wide),
            archive_objects::Recipient::recovery(&narrow),
        ],
        marker: 0xbb,
        writer_override: None,
        registry_override: None,
    });
    let response = post_commit(&server, &narrow, request.exact_bytes(), [0x2f; 16]).await;

    assert_eq!(response.status, 422);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-COMMIT-GRANT-SET")
    );
    assert_eq!(visible(database.pool()).await, (0, 0, 0));

    database.cleanup().await;
}

/// Ein FALSCHER Recovery-Empfaenger wird abgewiesen: die Rolle gehoert dem
/// Zertifikat, das der Kopf als `RecoveryRecipient` fuehrt, und keinem, den
/// der Aufrufer dazu erklaert.
///
/// Der gelieferte Satz nennt hier den zweiten READER unter dem Zweck
/// `Recovery`. Beide Zertifikate sind dem Kopf bekannt und beide Grants sind
/// echt signiert — abgewiesen wird allein die ZUORDNUNG. Zusammen mit dem
/// fehlenden und dem ueberzaehligen Grant ist die Empfaengermenge damit in
/// allen drei Richtungen gemessen.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_recovery_recipient_is_refused() {
    let database = common::fresh_database().await;
    let (server, closure) = stand_up(&database, true).await;

    let miscast = archive_objects::Recipient {
        kem_seed: trust_closure::SECOND_READER_KEM_SEED,
        certificate_hash: closure
            .second_reader_certificate_hash
            .expect("this closure carries a second reader"),
        purpose: ea_format::GrantPurposeV1::Recovery,
    };
    let request = archive_objects::commit_request(&archive_objects::CommitSpec {
        closure: &closure,
        sequence: commit_sequence(),
        previous_entry_hash: Some(seeded_head_entry_hash()),
        recipients: &[archive_objects::Recipient::reader(&closure), miscast],
        marker: 0xbc,
        writer_override: None,
        registry_override: None,
    });
    let response = post_commit(&server, &closure, request.exact_bytes(), [0x30; 16]).await;

    assert_eq!(response.status, 422);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-COMMIT-GRANT-SET")
    );
    assert_eq!(visible(database.pool()).await, (0, 0, 0));

    database.cleanup().await;
}

/// Ein Paket, das einen NEUEREN Kopf bindet als der Server kennt, wird NICHT
/// rueckwaerts geschickt.
///
/// Hier hinkt der SERVER, nicht der Aufrufer. `required-registry-version` nennt
/// deshalb die Version des PAKETS — die, die der Server erst lernen muss —
/// und nicht seine eigene, aeltere. Ihm die eigene zu nennen hiesse, ihn zu
/// einem Kopf zu schicken, den er nachweislich schon ueberholt hat.
#[tokio::test(flavor = "multi_thread")]
async fn a_bound_head_newer_than_the_server_knows_never_points_backwards() {
    let database = common::fresh_database().await;
    // Der Server kennt den SCHMALEN Abschluss; das Paket bindet den Kopf des
    // breiten, den es hier wirklich gibt — er ist nur nicht eingespielt.
    let (server, narrow) = stand_up(&database, false).await;
    let wide = trust_closure::build(true);
    assert!(
        wide.registry_version.get() > narrow.registry_version.get(),
        "the wide closure really is ahead"
    );

    let request = archive_objects::commit_request(&archive_objects::CommitSpec {
        closure: &narrow,
        sequence: commit_sequence(),
        previous_entry_hash: Some(seeded_head_entry_hash()),
        recipients: &standard_recipients(&narrow),
        marker: 0xbd,
        writer_override: None,
        registry_override: Some((wide.registry_version, *wide.registry_head_hash.as_bytes())),
    });
    let response = post_commit(&server, &narrow, request.exact_bytes(), [0x31; 16]).await;

    assert_eq!(response.status, 409);
    assert_eq!(
        error_code(&response.body).as_deref(),
        Some("EA-COMMIT-REGISTRY-HEAD-REQUIRED")
    );
    let error = ProtocolErrorV1::decode(&response.body).expect("the error body decodes");
    assert!(
        error.required_registry_version() == Some(wide.registry_version),
        "the required version is the one the server must learn, never an older one"
    );
    assert_eq!(
        error
            .required_registry_head_hash()
            .map(|hash| hash.as_bytes().to_vec()),
        Some(wide.registry_head_hash.as_bytes().to_vec())
    );
    assert_eq!(visible(database.pool()).await, (0, 0, 0));

    database.cleanup().await;
}
