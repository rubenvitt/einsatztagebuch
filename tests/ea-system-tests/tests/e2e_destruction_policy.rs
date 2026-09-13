//! T11 direct admission through real PostgreSQL/S3/Root trust adapters.
//! Fixtures seed prior server progress; this test performs no physical removal.
#[path = "../../../crates/ea-destruction/tests/support/mod.rs"]
mod support;
use ea_crypto::object_hash;
use ea_format::{ObjectTypeV1, ParsedArchiveObject, decode_exact_object};
use ea_sync_server::{
    destruction::{DestructionPorts, accept_destruction_request, destruction_status},
    *,
};
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
async fn real_current_progress_privacy_gate_exact_replay_and_transaction_fence() {
    let mut f = support::Fixture::new(true, true, false);
    let original = f.authorization();
    let mut fields = f.fields();
    fields.destruction_id = DestructionId::try_from(&[0x82; 16][..]).unwrap();
    let never_submitted = f.sign(fields.clone(), f.approvers.to_vec());
    fields.destruction_id = f.fields().destruction_id;
    fields.legal_reason_code = 1;
    let conflicting = f.sign(fields, f.approvers.to_vec());
    f.line.push(
        support::trust::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        support::trust::HeadOptions {
            policy_destruction_enabled_override: Some(false),
            policy_eds_privacy_decision_document_hash_override: Some(None),
            ..support::options()
        },
    );
    let anchor = ea_trust::decode_trust_anchor(f.line.exact_anchor_bytes()).unwrap();
    let org = anchor.organization_id();
    let chain = anchor.chain_id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let suffix = format!("{}-{nanos}", std::process::id());
    let database_name = format!("ea_test_t11_policy_{}", suffix.replace('-', "_"));
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
    let bucket = format!("ea-t11-policy-{suffix}");
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
    let committed = ChainHeadStateV1 {
        sequence: ChainSequence::new(300),
        entry_hash: EntryHash::try_from(&[0x84; 32][..]).unwrap(),
        accepted_at_server: UnixMillis::new(support::NOW),
    };
    sqlx::query("INSERT INTO chain_heads(organization_id,chain_id,head_sequence,head_entry_hash,head_accepted_at_server_millis) VALUES($1,$2,300,$3,$4)").bind(org.as_bytes().as_slice()).bind(chain.as_bytes().as_slice()).bind(committed.entry_hash.as_bytes().as_slice()).bind(committed.accepted_at_server.get()).execute(&pool).await.unwrap();
    let heads = PostgresTrustAuthority::new(pool.clone(), objects.clone());
    let ports = DestructionPorts {
        clock: clock.as_ref(),
        objects: objects.as_ref(),
        destructions: repository.as_ref(),
        heads: &heads,
        chain_heads: repository.as_ref(),
    };
    assert!(selected_policy(&heads, org, 301).await);
    let authority_fence = heads
        .select_current_admission(org, ChainSequence::new(301), clock.now())
        .await
        .unwrap()
        .unwrap()
        .fence;
    let accepted = accept_destruction_request(org, &original, &ports)
        .await
        .expect("future disabling successor cannot deny next sequence301");
    let stored = objects
        .get_exact_in(ObjectTypeV1::Trust, object_hash(&original))
        .await
        .unwrap()
        .collect()
        .await
        .unwrap()
        .into_bytes();
    assert_eq!(stored.as_ref(), original);
    assert_eq!(accepted.state(), 0);
    sqlx::query("UPDATE chain_heads SET head_sequence=400,revision=revision+1 WHERE organization_id=$1 AND chain_id=$2").bind(org.as_bytes().as_slice()).bind(chain.as_bytes().as_slice()).execute(&pool).await.unwrap();
    assert!(
        selected_policy(&heads, org, 301).await,
        "historical context still enabled"
    );
    assert!(
        !selected_policy(&heads, org, 401).await,
        "actual next sequence sees effective signed disablement"
    );
    assert_eq!(
        accept_destruction_request(org, &never_submitted, &ports)
            .await
            .unwrap_err()
            .code(),
        "EA-DESTRUCTION-PRIVACY-GATE"
    );
    let replay = accept_destruction_request(org, &original, &ports)
        .await
        .expect("exact recorded reservation remains readable");
    assert!(replay.authorization_object_hash() == accepted.authorization_object_hash());
    assert_eq!(
        accept_destruction_request(org, &conflicting, &ports)
            .await
            .unwrap_err()
            .code(),
        "EA-DESTRUCTION-CONFLICT"
    );
    // An admission decision made at300 cannot commit after the chain reaches400.
    let command = DestructionRequestCommandV1 {
        organization_id: org,
        chain_id: chain,
        expected_chain_head: committed,
        authority_fence,
        destruction_id: DestructionId::try_from(&[0x83; 16][..]).unwrap(),
        authorization: IndexedObjectV1 {
            kind: ObjectTypeV1::Trust,
            object_hash: object_hash(&never_submitted),
            size_bytes: never_submitted.len() as u64,
        },
        targets: vec![(EntryHash::try_from(&[1; 32][..]).unwrap(), 1)],
        requested_at: clock.now(),
    };
    assert_eq!(
        repository
            .record_destruction_request(command, clock.as_ref())
            .await
            .unwrap_err(),
        RepositoryError::HeadConflict
    );
    let reservations: i64 = sqlx::query_scalar("SELECT count(*) FROM destructions")
        .fetch_one(&pool)
        .await
        .unwrap();
    let rejected_objects: i64 =
        sqlx::query_scalar("SELECT count(*) FROM object_index WHERE object_hash=$1")
            .bind(object_hash(&never_submitted).as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reservations, 1);
    assert_eq!(rejected_objects, 0);
    let id = DestructionId::try_from(&[0x81; 16][..]).unwrap();
    let intact = destruction_status(org, id, &ports).await.unwrap();
    assert!(intact.authorization_object_hash() == object_hash(&original));
    let targets: i64 =
        sqlx::query_scalar("SELECT count(*) FROM destruction_targets WHERE destruction_id=$1")
            .bind(id.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        targets, 2,
        "all signed targets are blocked before confirmation"
    );
    sqlx::query("DELETE FROM destruction_targets WHERE organization_id=$1 AND destruction_id=$2 AND entry_hash=$3")
        .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(&[2u8;32][..]).execute(&pool).await.unwrap();
    assert!(
        destruction_status(org, id, &ports).await.is_err(),
        "one missing real target must prevent a successful barrier status"
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
