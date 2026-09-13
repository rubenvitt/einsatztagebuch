//! T11 direct admission through real PostgreSQL/S3/Root trust adapters.
//! Fixtures seed prior server progress; this test performs no physical removal.
#[path = "../../../crates/ea-destruction/tests/support/mod.rs"]
mod support;
use ea_format::{ObjectTypeV1, ParsedArchiveObject, decode_exact_object};
use ea_sync_server::*;
use ea_trust::TrustObjectSource;
use ea_types::*;
use einsatzarchiv_server::adapters::{
    postgres::PostgresRepository, s3::S3ObjectStore, trust_authority::PostgresTrustAuthority,
};
use std::sync::Arc;

struct Clock;
impl ServerClock for Clock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(support::NOW)
    }
}

#[tokio::test]
async fn policy_publication_without_chain_progress_refuses_stale_admission() {
    let mut f = support::Fixture::new(true, true, false);
    let original = f.authorization();
    let anchor = ea_trust::decode_trust_anchor(f.line.exact_anchor_bytes()).unwrap();
    let org = anchor.organization_id();
    let chain = anchor.chain_id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let suffix = format!("{}-{nanos}", std::process::id());
    let database_name = format!("ea_test_t11_catalog_{}", suffix.replace('-', "_"));
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
            "t11-fixture",
        ))
        .build();
    let client = aws_sdk_s3::Client::from_conf(config);
    let bucket = format!("ea-t11-catalog-{suffix}");
    client.create_bucket().bucket(&bucket).send().await.unwrap();
    let repository = Arc::new(PostgresRepository::new(pool.clone()));
    let clock = Arc::new(Clock);
    let objects = Arc::new(S3ObjectStore::new(
        client.clone(),
        bucket.clone(),
        org,
        repository.clone(),
        repository.clone(),
        clock.clone(),
    ));
    sqlx::query("INSERT INTO organizations(organization_id,root_key_thumbprint,trust_anchor_bytes,created_at_millis) VALUES($1,$2,$3,0)").bind(org.as_bytes().as_slice()).bind(anchor.root_key_thumbprint().as_bytes().as_slice()).bind(f.line.exact_anchor_bytes()).execute(&pool).await.unwrap();
    let source = f.line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .unwrap();
    for hash in hashes {
        let exact = source.read_exact_trust_object(hash).unwrap().unwrap();
        let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&exact).unwrap() else {
            panic!()
        };
        let staged = objects
            .stage_stream(
                ObjectTypeV1::Trust,
                aws_sdk_s3::primitives::ByteStream::from(exact.to_vec()),
                1_048_576,
            )
            .await
            .unwrap();
        let stored = objects.put_if_absent(staged).await.unwrap();
        sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,5,$3,0)").bind(stored.object_hash().as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(exact.len() as i64).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO trust_events(organization_id,event_id,object_hash,event_code,received_at_millis) VALUES($1,$2,$3,$4,0)").bind(org.as_bytes().as_slice()).bind(&hash.as_bytes()[..16]).bind(hash.as_bytes().as_slice()).bind(parsed.value().subtype().as_str()).execute(&pool).await.unwrap();
    }
    drop(source);
    let committed = ChainHeadStateV1 {
        sequence: ChainSequence::new(350),
        entry_hash: EntryHash::try_from(&[0x84; 32][..]).unwrap(),
        accepted_at_server: UnixMillis::new(support::NOW),
    };
    sqlx::query("INSERT INTO chain_heads(organization_id,chain_id,head_sequence,head_entry_hash,head_accepted_at_server_millis) VALUES($1,$2,350,$3,$4)").bind(org.as_bytes().as_slice()).bind(chain.as_bytes().as_slice()).bind(committed.entry_hash.as_bytes().as_slice()).bind(committed.accepted_at_server.get()).execute(&pool).await.unwrap();
    let heads = PostgresTrustAuthority::new(pool.clone(), objects.clone());

    assert!(selected_policy(&heads, org, 351).await);
    let authority_fence = heads
        .select_current_admission(org, ChainSequence::new(351), clock.now())
        .await
        .unwrap()
        .unwrap()
        .fence;
    let staged = objects
        .stage_stream(
            ObjectTypeV1::Trust,
            aws_sdk_s3::primitives::ByteStream::from(original.clone()),
            1_048_576,
        )
        .await
        .unwrap();
    let stored = objects.put_if_absent(staged).await.unwrap();
    // Authorized admission was calculated above at next sequence351.
    let command = DestructionRequestCommandV1 {
        organization_id: org,
        chain_id: chain,
        expected_chain_head: committed,
        authority_fence,
        destruction_id: f.fields().destruction_id,
        authorization: IndexedObjectV1 {
            kind: ObjectTypeV1::Trust,
            object_hash: stored.object_hash(),
            size_bytes: stored.size_bytes(),
        },
        targets: vec![
            (EntryHash::try_from(&[1; 32][..]).unwrap(), 1),
            (EntryHash::try_from(&[2; 32][..]).unwrap(), 1),
        ],
        requested_at: clock.now(),
    };
    f.line.push(
        support::trust::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: Some(351),
        },
        support::trust::HeadOptions {
            effective_from: Some(351),
            policy_destruction_enabled_override: Some(false),
            policy_eds_privacy_decision_document_hash_override: Some(None),
            ..support::options()
        },
    );
    let source = f.line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .unwrap();
    for hash in hashes {
        let exact = source.read_exact_trust_object(hash).unwrap().unwrap();
        let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&exact).unwrap() else {
            panic!()
        };
        let staged = objects
            .stage_stream(
                ObjectTypeV1::Trust,
                aws_sdk_s3::primitives::ByteStream::from(exact.to_vec()),
                1_048_576,
            )
            .await
            .unwrap();
        let stored = objects.put_if_absent(staged).await.unwrap();
        sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,5,$3,0) ON CONFLICT DO NOTHING").bind(stored.object_hash().as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(exact.len() as i64).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO trust_events(organization_id,event_id,object_hash,event_code,received_at_millis) VALUES($1,$2,$3,$4,0) ON CONFLICT DO NOTHING").bind(org.as_bytes().as_slice()).bind(&hash.as_bytes()[..16]).bind(hash.as_bytes().as_slice()).bind(parsed.value().subtype().as_str()).execute(&pool).await.unwrap();
    }

    assert!(
        selected_policy(&heads, org, 301).await,
        "original authorization remains valid history"
    );
    assert!(
        !selected_policy(&heads, org, 351).await,
        "published policy is effective NOW at unchanged next351"
    );
    let actual = repository
        .committed_chain_head(org, chain)
        .await
        .unwrap()
        .unwrap();
    assert!(actual == committed);
    let outcome = repository
        .record_destruction_request(command, clock.as_ref())
        .await;
    let reservations: i64 = sqlx::query_scalar("SELECT count(*) FROM destructions")
        .fetch_one(&pool)
        .await
        .unwrap();

    println!(
        "unchanged chain350 / next351: stale admission result={outcome:?}; reservations={reservations}"
    );
    drop(heads);
    drop(objects);
    drop(repository);
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
    assert_eq!(outcome, Err(RepositoryError::HeadConflict));
    assert_eq!(reservations, 0);
}

async fn selected_policy(
    heads: &PostgresTrustAuthority,
    org: OrganizationId,
    sequence: u64,
) -> bool {
    let RegistryHeadSelectionV1::Selected(head) = heads
        .select_head_for_sequence(
            org,
            ChainSequence::new(sequence),
            UnixMillis::new(support::NOW),
        )
        .await
        .unwrap()
    else {
        panic!("real adapter must select the applicable head")
    };
    head.policy_fields().retention_policy.destruction_enabled
}
