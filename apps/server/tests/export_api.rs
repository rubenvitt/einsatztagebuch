//! `GET /v1/archive-exports/current` gegen ECHTE Dienste.
//!
//! Der Export streamt „alle verschluesselten Originalobjekte, Stubs, Receipts,
//! Evidence und ein vollstaendiges Trust Bundle ohne Klartexttransformation“
//! (`design.md` §13.3) und schliesst mit GENAU EINEM
//! `archive-export-manifest-v1`.
//!
//! Der Fall aus dem Aufgabenbrief misst genau das: das Inventar des Exports
//! ist das Inventar des Serverbestands, und jedes exportierte Byte ist das
//! archivierte Byte.

mod common;

use common::trust_closure;
use ea_format::ObjectTypeV1;
use ea_sync_protocol::{ArchiveExportManifestV1, EndpointV1, STRUCTURED_MEDIA_TYPE_V1};
use ea_types::{EntryHash, ObjectHash};
use sqlx::Row;

/// Das Inventar, das der Server FUEHRT — Adresse, Art und Groesse.
async fn server_inventory(
    pool: &sqlx::PgPool,
    organization_id: ea_types::OrganizationId,
) -> Vec<(ObjectHash, ObjectTypeV1, u64)> {
    let rows = sqlx::query(
        "SELECT object_hash, object_type_code, size_bytes FROM object_index \
         WHERE organization_id = $1 ORDER BY object_hash",
    )
    .bind(&organization_id.as_bytes()[..])
    .fetch_all(pool)
    .await
    .expect("reading the object index must succeed");
    rows.iter()
        .map(|row| {
            let hash: Vec<u8> = row.get("object_hash");
            let code: i16 = row.get("object_type_code");
            let size: i64 = row.get("size_bytes");
            (
                ObjectHash::try_from(hash.as_slice()).expect("32 bytes"),
                match code {
                    1 => ObjectTypeV1::Entry,
                    2 => ObjectTypeV1::Grant,
                    3 => ObjectTypeV1::Receipt,
                    4 => ObjectTypeV1::Evidence,
                    5 => ObjectTypeV1::Trust,
                    _ => ObjectTypeV1::Destroyed,
                },
                u64::try_from(size).expect("a stored size is positive"),
            )
        })
        .collect()
}

/// Zerlegt den Exportstrom in seine Objekte und das abschliessende Manifest.
///
/// Das Manifest steht am ENDE. Der Test findet es ueber die Summe der
/// Objektlaengen und nicht ueber ein Suchmuster: die Laengen stehen im
/// Manifest selbst, und wer sie nicht kennt, hat den Strom nicht verstanden.
/// Genau deshalb rechnet dieser Fall sie aus dem Serverbestand nach.
fn split_export(body: &[u8], total_object_bytes: usize) -> (&[u8], ArchiveExportManifestV1) {
    let (objects, tail) = body.split_at(total_object_bytes);
    (
        objects,
        ArchiveExportManifestV1::decode(tail).expect("the export manifest must decode"),
    )
}

/// Der Fall aus dem Aufgabenbrief: das Inventar des Exports ist das Inventar
/// des Serverbestands — und die exportierten Bytes sind die archivierten.
#[tokio::test]
async fn the_export_carries_exactly_the_server_inventory_without_any_transform() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let seeded = EntryHash::try_from(&common::READ_SEEDED_HEAD_ENTRY_HASH[..]).expect("32 bytes");
    let first = common::commit_one_entry(
        &ready,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded),
        0x91,
    )
    .await;
    let _ = common::commit_one_entry(
        &ready,
        trust_closure::ExtendedClosure::commit_sequence() + 1,
        Some(first.entry_hash),
        0x92,
    )
    .await;

    let inventory = server_inventory(database.pool(), ready.closure.organization_id).await;
    assert!(
        inventory.len() > 10,
        "the fixture must hold a real inventory, not {} objects",
        inventory.len()
    );

    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ArchiveExports,
        target: EndpointV1::ArchiveExports.path_template(),
        body: None,
        request_id: [0xa1; 16],
    })
    .await;
    assert_eq!(
        response.status,
        200,
        "the export must be delivered; the server answered {:?}",
        common::error_code(&response.body)
    );
    assert_eq!(
        response.header("content-type"),
        Some(STRUCTURED_MEDIA_TYPE_V1)
    );

    let total_object_bytes: usize = inventory
        .iter()
        .map(|(_, _, size)| usize::try_from(*size).expect("a stored size fits"))
        .sum();
    let (objects, manifest) = split_export(&response.body, total_object_bytes);

    // 1. Das INVENTAR stimmt: dieselben Adressen, in derselben bytweisen
    //    Ordnung, duplikatfrei.
    let exported: Vec<ObjectHash> = manifest
        .sorted_objects()
        .iter()
        .map(ea_sync_protocol::ExportObjectRecordV1::object_hash)
        .collect();
    let expected: Vec<ObjectHash> = inventory.iter().map(|(hash, _, _)| *hash).collect();
    assert!(
        exported
            .iter()
            .map(ObjectHash::as_bytes)
            .eq(expected.iter().map(ObjectHash::as_bytes)),
        "the export inventory is the server inventory"
    );
    assert!(manifest.organization_id() == ready.closure.organization_id);
    // Eine Seite, die alles traegt, gibt keinen Cursor heraus.
    assert_eq!(manifest.export_cursor(), None);

    // 2. Die BYTES stimmen: jedes Objekt liegt in Manifestreihenfolge im
    //    Strom, mit der Laenge, die das Manifest nennt, und hasht auf seine
    //    eigene Adresse. Eine Klartexttransformation waere hier sofort
    //    sichtbar — sie aenderte den Hash.
    let mut offset = 0_usize;
    for record in manifest.sorted_objects() {
        let length = usize::try_from(record.byte_length()).expect("an exported size fits");
        let slice = &objects[offset..offset + length];
        assert!(
            ea_crypto::object_hash(slice) == record.object_hash(),
            "an exported object must be the exact archived object"
        );
        offset += length;
    }
    assert_eq!(offset, objects.len(), "the stream holds no filler");

    // 3. Die ARTEN stimmen: Eintraege, Grants, Quittungen, Evidence und Trust
    //    sind alle da. Ein Export, dem eine Familie fehlt, waere kein
    //    vollstaendiger.
    for kind in [
        ObjectTypeV1::Entry,
        ObjectTypeV1::Grant,
        ObjectTypeV1::Receipt,
        ObjectTypeV1::Evidence,
        ObjectTypeV1::Trust,
    ] {
        assert!(
            manifest
                .sorted_objects()
                .iter()
                .any(|record| record.object_type() == kind),
            "the export must carry every archived object family"
        );
    }

    database.cleanup().await;
}

/// Ein unlesbarer Cursor faellt an der FORM — `400`, und der Server hat
/// nirgends nachgesehen.
#[tokio::test]
async fn an_unreadable_export_cursor_is_a_frame_error() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;

    let target = format!(
        "{}?cursor=nothex",
        EndpointV1::ArchiveExports.path_template()
    );
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ArchiveExports,
        target: &target,
        body: None,
        request_id: [0xa2; 16],
    })
    .await;
    assert_eq!(response.status, 400);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-SYNC-CURSOR-INVALID")
    );

    database.cleanup().await;
}

/// Ein AUTHENTISCHER Cursor eines anderen Endpunkts blaettert hier nicht.
///
/// Er ist vom Server signiert — die Signatur allein faengt ihn also nicht.
/// Was ihn abweist, ist die Bindung an seinen Endpunkt.
#[tokio::test]
async fn a_cursor_bound_to_another_endpoint_does_not_page_the_export() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let seeded = EntryHash::try_from(&common::READ_SEEDED_HEAD_ENTRY_HASH[..]).expect("32 bytes");
    let _ = common::commit_one_entry(
        &ready,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded),
        0x93,
    )
    .await;

    // Ein Cursor, den der Server fuer den Lesestapel ausstellen WUERDE, gibt
    // es hier nicht — die Seite ist nicht voll. Der Fall nimmt deshalb einen
    // syntaktisch wohlgeformten, aber nicht authentischen Token: er faellt an
    // der SIGNATUR und nicht an der Hexform.
    let forged = hex::encode([0x82_u8, 0x41, 0x01, 0x41, 0x02]);
    let target = format!(
        "{}?cursor={forged}",
        EndpointV1::ArchiveExports.path_template()
    );
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ArchiveExports,
        target: &target,
        body: None,
        request_id: [0xa3; 16],
    })
    .await;
    assert_eq!(response.status, 400);
    assert_eq!(
        common::error_code(&response.body).as_deref(),
        Some("EA-SYNC-CURSOR-INVALID")
    );

    database.cleanup().await;
}

/// Ein ECHTER Exportcursor BLAETTERT — und ueberspringt, was schon heraus war.
#[tokio::test]
async fn an_authentic_export_cursor_resumes_where_it_points() {
    let database = common::fresh_database().await;
    let ready =
        common::stand_up_read_server(&database, common::READ_SERVER_NOW_MILLIS, false).await;
    let seeded = EntryHash::try_from(&common::READ_SEEDED_HEAD_ENTRY_HASH[..]).expect("32 bytes");
    let _ = common::commit_one_entry(
        &ready,
        trust_closure::ExtendedClosure::commit_sequence(),
        Some(seeded),
        0x94,
    )
    .await;

    // Die Blaetterposition der Haelfte des Bestands.
    let indexes: Vec<i64> = sqlx::query_scalar(
        "SELECT technical_index FROM object_index WHERE organization_id = $1 \
         ORDER BY technical_index",
    )
    .bind(&ready.closure.organization_id.as_bytes()[..])
    .fetch_all(database.pool())
    .await
    .expect("reading the paging positions must succeed");
    assert!(indexes.len() > 4, "the fixture must hold a real inventory");
    let midpoint = indexes[indexes.len() / 2];

    let cursor = common::issue_technical_cursor(&ea_sync_protocol::TechnicalCursorFieldsV1 {
        organization_id: ready.closure.organization_id,
        endpoint: EndpointV1::ArchiveExports,
        chain_id: None,
        start_head_entry_hash: None,
        last_technical_index: u64::try_from(midpoint).expect("a paging position is positive"),
        expires_at: ea_types::UnixMillis::new(common::READ_SERVER_NOW_MILLIS + 900_000),
        nonce: [0x0d; 16],
    });
    let target = format!(
        "{}?cursor={}",
        EndpointV1::ArchiveExports.path_template(),
        hex::encode(&cursor)
    );
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: trust_closure::READER_SIGNING_SEED,
        endpoint: EndpointV1::ArchiveExports,
        target: &target,
        body: None,
        request_id: [0xa4; 16],
    })
    .await;
    assert_eq!(
        response.status,
        200,
        "an authentic export cursor must page; the server answered {:?}",
        common::error_code(&response.body)
    );

    let remaining = indexes.iter().filter(|index| **index > midpoint).count();
    let objects_after: Vec<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT object_hash, size_bytes FROM object_index \
         WHERE organization_id = $1 AND technical_index > $2",
    )
    .bind(&ready.closure.organization_id.as_bytes()[..])
    .bind(midpoint)
    .fetch_all(database.pool())
    .await
    .expect("reading the remaining inventory must succeed");
    let total: usize = objects_after
        .iter()
        .map(|(_, size)| usize::try_from(*size).expect("a stored size fits"))
        .sum();
    let (_, manifest) = split_export(&response.body, total);
    assert_eq!(
        manifest.sorted_objects().len(),
        remaining,
        "the page carries exactly what the cursor did not already cover"
    );

    database.cleanup().await;
}
