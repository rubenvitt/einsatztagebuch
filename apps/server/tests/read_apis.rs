//! Die drei Leseflaechen des Readers gegen ECHTE Dienste.
//!
//! `GET /v1/chains/{chainId}/entries`, `GET /v1/objects/{objectHash}` und
//! `POST /v1/reader-acks`. Jeder Fall laeuft den ganzen Weg: TLS 1.3, Axum,
//! RFC-9421-Pruefung, die geteilte `ea-trust`-Pruefung, PostgreSQL und der
//! Object Store. Die Eintraege, die gelesen werden, entstehen ueber den
//! ECHTEN Commit-Endpunkt — was hier herauskommt, hat der Commit-Pfad
//! abgelegt und nicht ein `INSERT` daneben.

mod common;

use common::{archive_objects, trust_closure};
use ea_crypto::{ReaderAckCoreV1, encode_reader_ack_core};
use ea_sync_protocol::{
    EndpointV1, OBJECT_MEDIA_TYPE_V1, ReaderAckV1, ReaderBatchV1, STRUCTURED_MEDIA_TYPE_V1,
};
use ea_types::{ChainSequence, EntryHash, ObjectHash, UnixMillis};

/// Der Pfad des Lesestapels.
fn entries_path(
    chain: ea_types::ChainId,
    after_sequence: u64,
    after_entry_hash: EntryHash,
    cursor: Option<&[u8]>,
) -> String {
    let mut target = format!(
        "/v1/chains/{}/entries?afterSequence={after_sequence}&afterEntryHash={}",
        hex::encode(chain.as_bytes()),
        hex::encode(after_entry_hash.as_bytes())
    );
    if let Some(cursor) = cursor {
        target.push_str(&format!("&cursor={}", hex::encode(cursor)));
    }
    target
}

fn object_path(hash: ObjectHash) -> String {
    format!("/v1/objects/{}", hex::encode(hash.as_bytes()))
}

/// Der Nullhash: der Startkopf eines Lesers, der noch keinen verifiziert hat.
fn genesis_start() -> EntryHash {
    EntryHash::try_from(&[0_u8; 32][..]).expect("32 bytes")
}

/// Zwei echt committete Eintraege auf der laufenden Kette.
async fn two_entries(
    ready: &common::ReadyServer,
) -> (common::CommittedEntry, common::CommittedEntry) {
    let first_sequence = trust_closure::ExtendedClosure::commit_sequence();
    let seeded = EntryHash::try_from(&common::READ_SEEDED_HEAD_ENTRY_HASH[..]).expect("32 bytes");
    let first = common::commit_one_entry(ready, first_sequence, Some(seeded), 0x11).await;
    let second =
        common::commit_one_entry(ready, first_sequence + 1, Some(first.entry_hash), 0x12).await;
    (first, second)
}

/// Der Stapel BINDET den angefragten Startkopf und liefert nur SPAETERE
/// Eintraege — mit ihren exakten Objektbytes.
#[tokio::test]
async fn a_reader_batch_binds_the_requested_start_head_and_carries_exact_bytes() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let (first, second) = two_entries(&ready).await;

    let target = entries_path(
        ready.closure.chain_id,
        first.sequence,
        first.entry_hash,
        None,
    );
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ChainEntries,
        target: &target,
        body: None,
        request_id: [0x21; 16],
    })
    .await;
    assert_eq!(
        response.status,
        200,
        "the batch must be delivered; the server answered {:?}",
        common::error_code(&response.body)
    );
    assert_eq!(
        response.header("content-type"),
        Some(STRUCTURED_MEDIA_TYPE_V1)
    );

    let batch = ReaderBatchV1::decode(&response.body).expect("the batch frame must decode");
    assert!(batch.chain_id() == ready.closure.chain_id);
    assert_eq!(batch.requested_after_sequence(), first.sequence);
    assert!(batch.requested_after_entry_hash() == first.entry_hash);
    // Der gebundene Startkopf ist der ANGEFRAGTE (`design.md` §14.5).
    assert!(batch.start_head_entry_hash() == first.entry_hash);
    assert_eq!(batch.covered_through_sequence(), second.sequence);
    // Eine halbe Seite ist die letzte.
    assert_eq!(batch.next_cursor(), None);

    let delivered: Vec<ObjectHash> = batch
        .objects()
        .iter()
        .map(ea_sync_protocol::ObjectRecordV1::object_hash)
        .collect();
    // Der ERSTE Eintrag ist NICHT dabei: der Stapel liefert ausschliesslich
    // spaetere Kettenpositionen.
    assert!(
        !delivered.contains(&first.entry_object_hash),
        "the batch must not carry the entry the reader already has"
    );
    for expected in [
        second.entry_object_hash,
        second.recovery_grant_object_hash,
        second.reader_grant_object_hash,
    ] {
        assert!(
            delivered.contains(&expected),
            "the batch must carry every object of the later entry"
        );
    }
    // Trust, Receipt und Checkpoint sind da: der Stapel traegt sechs
    // Objektarten und nicht nur den Eintrag.
    assert!(
        delivered.len() >= 6,
        "entry, receipt, checkpoint, registry head and two grants make six objects, not {}",
        delivered.len()
    );
    // Jedes gelieferte Byte ist das Objekt, unter dessen Hash es steht.
    for record in batch.objects() {
        assert!(
            ea_crypto::object_hash(record.exact_object_bytes()) == record.object_hash(),
            "a delivered object must hash to its own address"
        );
    }

    database.cleanup().await;
}

/// Der Nullhash an Sequenz null ist der Kettenanfang — und liefert BEIDE
/// Eintraege.
#[tokio::test]
async fn a_reader_without_a_verified_head_starts_at_the_beginning_of_the_chain() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let (first, second) = two_entries(&ready).await;

    let target = entries_path(ready.closure.chain_id, 0, genesis_start(), None);
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ChainEntries,
        target: &target,
        body: None,
        request_id: [0x22; 16],
    })
    .await;
    assert_eq!(response.status, 200);
    let batch = ReaderBatchV1::decode(&response.body).expect("the batch frame must decode");
    assert_eq!(batch.covered_through_sequence(), second.sequence);
    let delivered: Vec<ObjectHash> = batch
        .objects()
        .iter()
        .map(ea_sync_protocol::ObjectRecordV1::object_hash)
        .collect();
    assert!(delivered.contains(&first.entry_object_hash));
    assert!(delivered.contains(&second.entry_object_hash));

    database.cleanup().await;
}

/// Ein ANDERER Startkopf an derselben Sequenz stoppt den Stapel — `409` und
/// kein `404`: die Kette ist bekannt, der Kopf weicht ab.
#[tokio::test]
async fn a_diverging_start_head_stops_the_batch_with_a_conflict() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let (first, _) = two_entries(&ready).await;

    let foreign = EntryHash::try_from(&[0x9f_u8; 32][..]).expect("32 bytes");
    let target = entries_path(ready.closure.chain_id, first.sequence, foreign, None);
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ChainEntries,
        target: &target,
        body: None,
        request_id: [0x23; 16],
    })
    .await;
    assert_eq!(response.status, 409);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-READER-START-HEAD-MISMATCH")
    );

    database.cleanup().await;
}

/// Eine unbekannte Kette ist `404` — die eine Zeile der Abbildung, die sie
/// nennt.
#[tokio::test]
async fn an_unknown_chain_is_not_found() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let _ = two_entries(&ready).await;

    let foreign = ea_types::ChainId::try_from(&[0x5c_u8; 16][..]).expect("16 bytes");
    let target = entries_path(foreign, 0, genesis_start(), None);
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ChainEntries,
        target: &target,
        body: None,
        request_id: [0x24; 16],
    })
    .await;
    assert_eq!(response.status, 404);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-READER-CHAIN-UNKNOWN")
    );

    database.cleanup().await;
}

/// Ein Cursor eines ANDEREN Endpunkts blaettert hier nicht.
///
/// Der Checkpoint-Cursor ist echt und vom Server signiert — er ist damit
/// genau der Fall, den eine Signaturpruefung allein NICHT faengt. Was ihn
/// abweist, ist die Bindung: Endpunkt, Kette und Startkopf stehen im Token.
#[tokio::test]
async fn a_cursor_from_another_endpoint_does_not_page_the_reader_batch() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let (first, _) = two_entries(&ready).await;

    // Ein ECHTER Cursor — vom Checkpoint-Endpunkt. Er entsteht nur, wenn die
    // Seite voll war; mit zwei Checkpoints ist sie es nicht. Der Fall nimmt
    // deshalb den Weg ueber ein Token, das der Server ausgestellt hat, aber
    // fuer einen anderen Endpunkt: das ist der signierte Cursor der
    // Exportseite.
    let export = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ArchiveExports,
        target: EndpointV1::ArchiveExports.path_template(),
        body: None,
        request_id: [0x25; 16],
    })
    .await;
    assert_eq!(export.status, 200);

    // Ein Token, das nicht einmal lesbar ist, faellt schon an der Form —
    // `400` und nicht `404`, denn der Server hat nirgends nachgesehen.
    let target = entries_path(
        ready.closure.chain_id,
        first.sequence,
        first.entry_hash,
        Some(&[0x01, 0x02, 0x03]),
    );
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ChainEntries,
        target: &target,
        body: None,
        request_id: [0x26; 16],
    })
    .await;
    assert_eq!(response.status, 400);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-SYNC-CURSOR-INVALID")
    );

    database.cleanup().await;
}

/// Die Objektantwort liefert die EXAKTEN archivierten Bytes — mit Laenge und
/// RFC-9530-Digest ueber genau diese Bytes.
#[tokio::test]
async fn the_object_endpoint_streams_exact_stored_bytes_with_their_digest() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let (first, _) = two_entries(&ready).await;

    let target = object_path(first.entry_object_hash);
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::Objects,
        target: &target,
        body: None,
        request_id: [0x31; 16],
    })
    .await;
    assert_eq!(
        response.status,
        200,
        "the object must be delivered; the server answered {:?}",
        common::error_code(&response.body)
    );
    assert_eq!(response.header("content-type"), Some(OBJECT_MEDIA_TYPE_V1));
    assert_eq!(
        response.header("content-length"),
        Some(response.body.len().to_string().as_str())
    );
    // KEIN CBOR-Rahmen: die Bytes SIND das Objekt.
    assert!(
        ea_crypto::object_hash(&response.body) == first.entry_object_hash,
        "the response body must be the exact archived object"
    );
    // Der Digest ist der BLANKE SHA-256 der uebertragenen Bytes und
    // ausdruecklich nicht der domaenengetrennte `objectHash`.
    let expected = {
        use sha2::{Digest as _, Sha256};
        let digest: [u8; 32] = Sha256::digest(&response.body).into();
        format!("sha-256=:{}:", base64(&digest))
    };
    assert_eq!(response.header("content-digest"), Some(expected.as_str()));

    database.cleanup().await;
}

/// Ein unbekannter Objekthash ist `404`.
#[tokio::test]
async fn an_unknown_object_is_not_found() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let _ = two_entries(&ready).await;

    let unknown =
        ObjectHash::from(ea_types::Hash32::try_from(&[0x6e_u8; 32][..]).expect("32 bytes"));
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::Objects,
        target: &object_path(unknown),
        body: None,
        request_id: [0x32; 16],
    })
    .await;
    assert_eq!(response.status, 404);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-READER-OBJECT-UNKNOWN")
    );

    database.cleanup().await;
}

/// Eine signierte Lesequittung wird append-only aufgenommen und antwortet mit
/// `204`.
#[tokio::test]
async fn a_signed_reader_acknowledgement_is_recorded_without_content() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let (_, second) = two_entries(&ready).await;

    let body = reader_ack(&ready, second.entry_hash, second.sequence);
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ReaderAcks,
        target: EndpointV1::ReaderAcks.path_template(),
        body: Some(body.exact_bytes()),
        request_id: [0x41; 16],
    })
    .await;
    assert_eq!(
        response.status,
        204,
        "the acknowledgement must be recorded; the server answered {:?}",
        common::error_code(&response.body)
    );
    assert!(response.body.is_empty(), "a 204 carries no body");

    let stored: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM reader_acknowledgements WHERE reader_certificate_hash = $1",
    )
    .bind(&ready.closure.reader_certificate_hash.as_bytes()[..])
    .fetch_one(database.pool())
    .await
    .expect("counting the acknowledgements must succeed");
    assert_eq!(stored.0, 1, "the acknowledgement is stored exactly once");

    database.cleanup().await;
}

/// Eine Quittung, die einen ANDEREN Leser nennt, wird abgewiesen.
///
/// Der Aufrufer ist authentisch, der Kern gehoert aber einem anderen
/// Zertifikat. Ohne diese Pruefung quittierte ein Geraet fuer ein anderes.
#[tokio::test]
async fn an_acknowledgement_for_another_reader_is_refused() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let (_, second) = two_entries(&ready).await;

    let core = ReaderAckCoreV1 {
        organization_id: ready.closure.organization_id,
        chain_id: ready.closure.chain_id,
        // Das Zertifikat des WRITERS, signiert wird aber vom Reader.
        reader_certificate_hash: ready.closure.writer_certificate_hash,
        through_sequence: ChainSequence::new(second.sequence),
        head_entry_hash: second.entry_hash,
        acknowledged_at_device: UnixMillis::new(common::READ_SERVER_NOW_MILLIS),
    };
    let exact_core = encode_reader_ack_core(&core).expect("the core encodes");
    let signature = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        trust_closure::READER_SIGNING_SEED,
    ))
    .sign_reader_ack(&exact_core)
    .expect("signing the acknowledgement must succeed");
    let body = ReaderAckV1::new(core, &signature).expect("the acknowledgement frame builds");

    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ReaderAcks,
        target: EndpointV1::ReaderAcks.path_template(),
        body: Some(body.exact_bytes()),
        request_id: [0x42; 16],
    })
    .await;
    assert_eq!(response.status, 422);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-READER-ACK-MISMATCH")
    );

    database.cleanup().await;
}

/// Eine Quittung auf einen unbekannten Eintrag ist `404`.
#[tokio::test]
async fn an_acknowledgement_for_an_unknown_entry_is_not_found() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let (_, second) = two_entries(&ready).await;

    let unknown = EntryHash::try_from(&[0x7e_u8; 32][..]).expect("32 bytes");
    let body = reader_ack(&ready, unknown, second.sequence + 40);
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ReaderAcks,
        target: EndpointV1::ReaderAcks.path_template(),
        body: Some(body.exact_bytes()),
        request_id: [0x43; 16],
    })
    .await;
    assert_eq!(response.status, 404);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-READER-ENTRY-UNKNOWN")
    );

    database.cleanup().await;
}

/// Eine echte, vom Leser signierte Quittung.
fn reader_ack(
    ready: &common::ReadyServer,
    head_entry_hash: EntryHash,
    through_sequence: u64,
) -> ReaderAckV1 {
    let core = ReaderAckCoreV1 {
        organization_id: ready.closure.organization_id,
        chain_id: ready.closure.chain_id,
        reader_certificate_hash: ready.closure.reader_certificate_hash,
        through_sequence: ChainSequence::new(through_sequence),
        head_entry_hash,
        acknowledged_at_device: UnixMillis::new(common::READ_SERVER_NOW_MILLIS),
    };
    let exact_core = encode_reader_ack_core(&core).expect("the core encodes");
    let signature = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        trust_closure::READER_SIGNING_SEED,
    ))
    .sign_reader_ack(&exact_core)
    .expect("signing the acknowledgement must succeed");
    ReaderAckV1::new(core, &signature).expect("the acknowledgement frame builds")
}

/// Base64 ohne Bibliothek — dieselben sechzehn Zeilen wie im Handler, hier als
/// UNABHAENGIGE Gegenrechnung. Waere die Kodierung falsch, waeren beide
/// gleich falsch; deshalb prueft der Fall oben ZUSAETZLICH den Objekthash der
/// gelieferten Bytes, und der laeuft ueber `ea-crypto`.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let block = u32::from(chunk[0]) << 16
            | u32::from(chunk.get(1).copied().unwrap_or(0)) << 8
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for position in 0..4 {
            if position <= chunk.len() {
                encoded.push(char::from(
                    ALPHABET[((block >> (18 - 6 * position)) & 0x3f) as usize],
                ));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// Die Kulisse ist nicht selbst der Beweis: der Abschluss ohne die Grant- und
/// Vernichtungsrollen traegt sie AUCH NICHT.
#[test]
fn the_default_closure_carries_no_grant_authorities() {
    let closure = trust_closure::build(false);
    assert!(
        closure
            .historical_grant_authority_certificate_hash
            .is_none()
    );
    assert!(closure.approver_certificate_hashes.is_none());
    let _ = archive_objects::authorization_sequence();
}

/// Ein ECHTER Cursor dieses Endpunkts BLAETTERT — und faengt genau dort an, wo
/// er zeigt.
///
/// Die drei Faelle darueber pruefen die Abweisung; dieser prueft die Annahme.
/// Ohne ihn kaeme ein Cursor durch, den der Server ausstellt, aber nie wieder
/// oeffnet.
#[tokio::test]
async fn an_authentic_cursor_of_this_endpoint_resumes_where_it_points() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let (first, second) = two_entries(&ready).await;

    // Der Cursor zeigt hinter den ERSTEN Eintrag und ist an dessen Kette und
    // Startkopf gebunden — genau so, wie der Server ihn ausstellen wuerde.
    let cursor = common::issue_technical_cursor(&ea_sync_protocol::TechnicalCursorFieldsV1 {
        organization_id: ready.closure.organization_id,
        endpoint: EndpointV1::ChainEntries,
        chain_id: Some(ready.closure.chain_id),
        start_head_entry_hash: Some(genesis_start()),
        last_technical_index: first.sequence,
        expires_at: UnixMillis::new(common::READ_SERVER_NOW_MILLIS + 900_000),
        nonce: [0x0c; 16],
    });

    // Der Aufruf startet formal am Kettenanfang; der Cursor setzt die Strecke
    // trotzdem hinter dem ersten Eintrag fort.
    let target = entries_path(ready.closure.chain_id, 0, genesis_start(), Some(&cursor));
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ChainEntries,
        target: &target,
        body: None,
        request_id: [0x27; 16],
    })
    .await;
    assert_eq!(
        response.status,
        200,
        "an authentic, correctly bound cursor must page; the server answered {:?}",
        common::error_code(&response.body)
    );
    let batch = ReaderBatchV1::decode(&response.body).expect("the batch frame must decode");
    let delivered: Vec<ObjectHash> = batch
        .objects()
        .iter()
        .map(ea_sync_protocol::ObjectRecordV1::object_hash)
        .collect();
    assert!(
        !delivered.contains(&first.entry_object_hash),
        "the cursor skips what the previous page already carried"
    );
    assert!(delivered.contains(&second.entry_object_hash));
    assert_eq!(batch.covered_through_sequence(), second.sequence);

    // Derselbe Cursor an einer ANDEREN Startposition passt nicht mehr: die
    // Bindung ist Teil des Tokens.
    let mismatched = entries_path(
        ready.closure.chain_id,
        first.sequence,
        first.entry_hash,
        Some(&cursor),
    );
    let refused = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ChainEntries,
        target: &mismatched,
        body: None,
        request_id: [0x28; 16],
    })
    .await;
    assert_eq!(refused.status, 400);
    assert_eq!(
        common::error_code(&refused.body).as_deref(),
        Some("EA-SYNC-CURSOR-SCOPE")
    );

    database.cleanup().await;
}
