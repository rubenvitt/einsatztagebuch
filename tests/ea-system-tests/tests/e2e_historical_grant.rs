//! Real issuance -> server admission/storage -> delivery -> Reader opening.
//! PostgreSQL/S3 are real adapters; separate historical_grant_api tests cover HTTP.
#[allow(dead_code)]
#[path = "../../../crates/ea-recovery/tests/historical_grant/support.rs"]
mod issuance;
#[path = "../../../crates/ea-reader/tests/verify_fixtures/mod.rs"]
mod reader_support;
#[path = "../../../crates/ea-recovery/tests/support/mod.rs"]
mod support;
use ea_crypto::{SecretBytes, object_hash};
use ea_format::ObjectTypeV1;
use ea_sync_server::*;
use ea_types::*;
use einsatzarchiv_server::adapters::{
    postgres::PostgresRepository, s3::S3ObjectStore, server_keys::ServerKeyStore,
    trust_authority::PostgresTrustAuthority,
};
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};
use support::verify_support as fixture;

struct Clock(AtomicI64);
impl ServerClock for Clock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0.load(Ordering::SeqCst))
    }
}

#[tokio::test]
async fn create_upload_deliver_open_and_replay_after_expiry() {
    let mut plaintext = Vec::new();
    let f = fixture::historical::fixture_with_expired_original_head(|version, binding| {
        plaintext = reader_support::operator::bound_plaintext(
            reader_support::fixtures::genesis_plaintext(),
            binding,
            version.get(),
            reader_support::operator::Defect::None,
        );
        plaintext.clone()
    });
    let harness = issuance::Harness::new(f);
    let f = &harness.fixture;
    let authorization =
        ea_trust::verify_grant_authorization(&f.authorization(800), &f.selected(1, 800, 800))
            .unwrap();
    let issued = harness
        .create(&authorization)
        .expect("real Recovery-KEM/HGA/approver/native proof/audit issuance");
    let issued_hash = object_hash(issued.as_bytes());
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let database_name = format!("ea_test_t8_{suffix}");
    let database_url =
        std::env::var("DATABASE_URL").expect("controller-owned integration environment");
    let admin = sqlx::PgPool::connect(&database_url).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE \"{database_name}\""
    )))
    .execute(&admin)
    .await
    .unwrap();
    let (prefix, _) = database_url.rsplit_once('/').unwrap();
    let pool = sqlx::PgPool::connect(&format!("{prefix}/{database_name}"))
        .await
        .unwrap();
    sqlx_core::migrate::Migrator::new(std::path::Path::new("../../apps/server/migrations"))
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();
    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https();
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .http_client(http)
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(std::env::var("EA_OBJECT_STORE_ENDPOINT").unwrap())
        .force_path_style(true)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            "einsatzarchiv",
            "einsatzarchiv",
            None,
            None,
            "t8-fixture",
        ))
        .build();
    let client = aws_sdk_s3::Client::from_conf(config);
    let bucket = format!("ea-t8-{suffix}");
    client.create_bucket().bucket(&bucket).send().await.unwrap();
    let repo = Arc::new(PostgresRepository::new(pool.clone()));
    let clock = Arc::new(Clock(AtomicI64::new(800)));
    let objects = Arc::new(S3ObjectStore::new(
        client.clone(),
        bucket.clone(),
        f.anchor.organization_id(),
        repo.clone(),
        repo.clone(),
        clock.clone(),
    ));
    sqlx::query("INSERT INTO organizations(organization_id,root_key_thumbprint,trust_anchor_bytes,created_at_millis) VALUES($1,$2,$3,0)").bind(f.anchor.organization_id().as_bytes().as_slice()).bind(f.anchor.root_key_thumbprint().as_bytes().as_slice()).bind(f.line.exact_anchor_bytes()).execute(&pool).await.unwrap();
    // Install the verified historical archive and its initial grant plan, as the
    // preexisting committed state. The new historical grant is never seeded.
    let inventory = ea_archive::ArchiveInventory::build(&f.fixture).unwrap();
    for p in inventory.trust() {
        store_object(
            &objects,
            &pool,
            f.anchor.organization_id(),
            ObjectTypeV1::Trust,
            p.exact_bytes().as_bytes(),
        )
        .await;
        sqlx::query("INSERT INTO trust_events(organization_id,event_id,object_hash,event_code,received_at_millis) VALUES($1,$2,$3,$4,0)").bind(f.anchor.organization_id().as_bytes().as_slice()).bind(&p.object_hash().as_bytes()[..16]).bind(p.object_hash().as_bytes().as_slice()).bind(p.value().subtype().as_str()).execute(&pool).await.unwrap();
    }
    store_object(
        &objects,
        &pool,
        f.anchor.organization_id(),
        ObjectTypeV1::Entry,
        &f.entry_bytes,
    )
    .await;
    store_object(
        &objects,
        &pool,
        f.anchor.organization_id(),
        ObjectTypeV1::Grant,
        &f.original_bytes,
    )
    .await;
    store_object(
        &objects,
        &pool,
        f.anchor.organization_id(),
        ObjectTypeV1::Trust,
        authorization.exact_bytes(),
    )
    .await;
    let entry = &inventory.entries()[0];
    let manifest = entry.value().manifest().fields();
    sqlx::query("INSERT INTO entries(entry_hash,organization_id,chain_id,sequence_number,entry_object_hash,initial_grant_plan_hash,receipt_object_hash,device_id,accepted_at_server_millis,registry_version,registry_head_hash) VALUES($1,$2,$3,0,$4,$5,$6,$7,100,$8,$9)")
        .bind(f.entry_hash.as_bytes().as_slice()).bind(f.anchor.organization_id().as_bytes().as_slice()).bind(f.anchor.chain_id().as_bytes().as_slice()).bind(entry.object_hash().as_bytes().as_slice()).bind(manifest.initial_grant_plan_hash.as_slice()).bind(&[0u8;32][..]).bind(&[0x55u8;16][..]).bind(manifest.registry_version.get() as i64).bind(manifest.registry_head_hash.as_slice()).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO grants(object_hash,organization_id,entry_hash,recipient_key_thumbprint,grant_kind_code) VALUES($1,$2,$3,$4,'initial')").bind(object_hash(&f.original_bytes).as_bytes().as_slice()).bind(f.anchor.organization_id().as_bytes().as_slice()).bind(f.entry_hash.as_bytes().as_slice()).bind(fixture::complete_recipient_key_thumbprint().as_bytes().as_slice()).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO chain_heads(organization_id,chain_id,head_sequence,head_entry_hash,head_accepted_at_server_millis) VALUES($1,$2,0,$3,100)").bind(f.anchor.organization_id().as_bytes().as_slice()).bind(f.anchor.chain_id().as_bytes().as_slice()).bind(f.entry_hash.as_bytes().as_slice()).execute(&pool).await.unwrap();
    let heads = PostgresTrustAuthority::new(pool.clone(), objects.clone());
    let ports = historical_grant::HistoricalGrantPorts {
        clock: clock.as_ref(),
        objects: objects.as_ref(),
        entries: repo.as_ref(),
        grants: repo.as_ref(),
        heads: &heads,
        destructions: repo.as_ref(),
    };
    historical_grant::accept_historical_grant(
        f.anchor.organization_id(),
        f.hga_certificate,
        f.entry_hash,
        issued.as_bytes(),
        &ports,
    )
    .await
    .expect("new Reader enrolled at sequence1 can receive Entry0");
    let signer = ServerKeyStore::new(SecretBytes::new([0x91; 32]), f.hga_certificate, 0).unwrap();
    let reader_ports = reader_sync::ReaderPorts {
        clock: clock.as_ref(),
        signer: &signer,
        objects: objects.as_ref(),
        object_types: repo.as_ref(),
        entries: repo.as_ref(),
        acks: repo.as_ref(),
        destructions: repo.as_ref(),
        heads: &heads,
    };
    let page = reader_sync::grant_list(f.anchor.organization_id(), f.entry_hash, &reader_ports)
        .await
        .unwrap();
    let delivered = page
        .grants()
        .iter()
        .find(|record| record.object_hash() == issued_hash)
        .expect("exact expiry is deliverable")
        .exact_object_bytes()
        .to_vec();
    assert_eq!(delivered, issued.as_bytes());
    let mut received = fixture::archive_support::ArchiveFixture::new();
    for (name, bytes) in f.fixture.blobs() {
        received.push_exact_bytes(name, bytes.clone());
    }
    received.push_exact_bytes(
        "trust/authorization.etb",
        authorization.exact_bytes().to_vec(),
    );
    received.push_exact_bytes("grants/historical.eag", delivered.clone());
    let contents = ea_reader::VaultContentsV1::new(
        SecretBytes::new(fixture::other_recipient_secret_bytes()),
        SecretBytes::new([0x52; 32]),
        f.line.exact_anchor_bytes().to_vec(),
        None,
    );
    let sealed =
        ea_reader::ReaderVault::seal(contents, &[reader_support::fixtures::authenticator()])
            .unwrap();
    let vault = ea_reader::ReaderVault::unlock(&sealed, &reader_support::fixtures::authenticator())
        .unwrap();
    let mut reader_time = ea_reader::InMemoryReaderBlobStore::new();
    let verified =
        ea_reader::ReaderVerifier::new(ea_reader::ReaderMode::Server, UnixMillis::new(800))
            .classify_with_time_store(
                &received,
                &vault,
                &mut reader_time,
                &mut ea_reader::SilentObserver,
            )
            .unwrap();
    let entry = verified.verified_entry(f.entry_hash).unwrap();
    let grant = verified.verified_grant(f.entry_hash).unwrap();
    let opened = ea_reader::decrypt_verified(
        entry,
        grant,
        &vault,
        &ea_reader::SchemaRegistry::v1(),
        UnixMillis::new(800),
        &mut ea_reader::SilentObserver,
    )
    .unwrap();
    assert!(opened.with_plaintext(|bytes| bytes == plaintext));
    clock.0.store(801, Ordering::SeqCst);
    let error = historical_grant::accept_historical_grant(
        f.anchor.organization_id(),
        f.hga_certificate,
        f.entry_hash,
        &delivered,
        &ports,
    )
    .await
    .unwrap_err();
    assert_eq!(error.error.code(), "EA-GRANT-EXPIRED");
    let after = reader_sync::grant_list(f.anchor.organization_id(), f.entry_hash, &reader_ports)
        .await
        .unwrap();
    assert!(
        after
            .grants()
            .iter()
            .all(|g| g.object_hash() != issued_hash)
    );
    assert_eq!(
        ea_reader::decrypt_verified(
            entry,
            grant,
            &vault,
            &ea_reader::SchemaRegistry::v1(),
            UnixMillis::new(801),
            &mut ea_reader::SilentObserver
        )
        .unwrap_err()
        .code(),
        "EA-GRANT-EXPIRED"
    );
    let reopened =
        ea_reader::ReaderVerifier::new(ea_reader::ReaderMode::Server, UnixMillis::new(801))
            .classify_with_time_store(
                &received,
                &vault,
                &mut reader_time,
                &mut ea_reader::SilentObserver,
            )
            .unwrap();
    assert!(reopened.verified_grant(f.entry_hash).is_none());
    let stored = objects
        .get_exact_in(ObjectTypeV1::Entry, object_hash(&f.entry_bytes))
        .await
        .unwrap()
        .collect()
        .await
        .unwrap()
        .into_bytes();
    assert_eq!(stored.as_ref(), f.entry_bytes);
    drop(reader_ports);
    drop(ports);
    drop(heads);
    drop(objects);
    drop(repo);
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE \"{database_name}\""
    )))
    .execute(&admin)
    .await
    .unwrap();
    admin.close().await;
    let listed = client
        .list_objects_v2()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
    for object in listed.contents() {
        client
            .delete_object()
            .bucket(&bucket)
            .key(object.key().unwrap())
            .send()
            .await
            .unwrap();
    }
    client.delete_bucket().bucket(&bucket).send().await.unwrap();
}
async fn store_object(
    objects: &S3ObjectStore,
    pool: &sqlx::PgPool,
    org: OrganizationId,
    kind: ObjectTypeV1,
    bytes: &[u8],
) {
    let staged = objects
        .stage_stream(
            kind,
            aws_sdk_s3::primitives::ByteStream::from(bytes.to_vec()),
            1_048_576,
        )
        .await
        .unwrap();
    let stored = objects.put_if_absent(staged).await.unwrap();
    sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,$3,$4,0)").bind(stored.object_hash().as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(match kind {ObjectTypeV1::Entry=>1i16,ObjectTypeV1::Grant=>2,ObjectTypeV1::Trust=>5,_=>panic!()}).bind(bytes.len() as i64).execute(pool).await.unwrap();
}
