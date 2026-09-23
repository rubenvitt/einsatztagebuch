//! Deterministic concurrent publisher around real PostgreSQL/S3 selection.
#[path = "../../../crates/ea-destruction/tests/support/mod.rs"]
mod support;
use async_trait::async_trait;
use ea_format::{DecodedTrustPayloadV1, ObjectTypeV1, ParsedArchiveObject, decode_exact_object};
use ea_sync_server::{
    destruction::{DestructionPorts, accept_destruction_request},
    *,
};
use ea_trust::TrustObjectSource;
use ea_types::*;
use einsatzarchiv_server::adapters::{
    postgres::PostgresRepository, s3::S3ObjectStore, trust_authority::PostgresTrustAuthority,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI64, Ordering},
};
struct Clock(AtomicI64);
impl ServerClock for Clock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0.load(Ordering::SeqCst))
    }
}
struct Live {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    database_name: String,
    client: aws_sdk_s3::Client,
    bucket: String,
    repository: Arc<PostgresRepository>,
    objects: Arc<S3ObjectStore>,
    heads: PostgresTrustAuthority,
    clock: Arc<Clock>,
    org: OrganizationId,
    chain: ChainId,
    committed: ChainHeadStateV1,
}
impl Live {
    async fn new(f: &support::Fixture) -> Self {
        let anchor = ea_trust::decode_trust_anchor(f.line.exact_anchor_bytes()).unwrap();
        let org = anchor.organization_id();
        let chain = anchor.chain_id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let suffix = format!(
            "{}-{}-{nanos}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let database_name = format!("ea_test_t11_admission_{}", suffix.replace('-', "_"));
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
        let bucket = format!("ea-t11-admission-{suffix}");
        client.create_bucket().bucket(&bucket).send().await.unwrap();
        let repository = Arc::new(PostgresRepository::new(pool.clone()));
        let clock = Arc::new(Clock(AtomicI64::new(support::NOW)));
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

        Self {
            admin,
            pool,
            database_name,
            client,
            bucket,
            repository,
            objects,
            heads,
            clock,
            org,
            chain,
            committed,
        }
    }
    fn ports<'a>(&'a self, heads: &'a dyn RegistryHeadDirectory) -> DestructionPorts<'a> {
        DestructionPorts {
            clock: self.clock.as_ref(),
            objects: self.objects.as_ref(),
            destructions: self.repository.as_ref(),
            heads,
            chain_heads: self.repository.as_ref(),
        }
    }
    async fn rows(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM destructions")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn close(self) {
        let Self {
            admin,
            pool,
            database_name,
            client,
            bucket,
            repository,
            objects,
            heads,
            ..
        } = self;
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
}
async fn publish_catalog(live: &Live, line: &support::trust::RegistryLineBuilder) {
    publish_catalog_ports(
        &live.objects,
        &live.repository,
        live.org,
        line,
        live.clock.now(),
    )
    .await;
}
async fn publish_catalog_ports(
    objects: &S3ObjectStore,
    repository: &PostgresRepository,
    org: OrganizationId,
    line: &support::trust::RegistryLineBuilder,
    now: UnixMillis,
) {
    let source = line.source();
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
        let (registry_version, effective_from) = match parsed.value().decoded_payload().unwrap() {
            DecodedTrustPayloadV1::RegistryEvent(core) => (
                Some(core.fields().registry_version),
                core.fields().not_before,
            ),
            _ => (None, UnixMillis::new(0)),
        };
        let result = repository
            .index_event(TrustEventCommandV1 {
                organization_id: org,
                object_hash: stored.object_hash(),
                size_bytes: stored.size_bytes(),
                subtype_code: parsed.value().subtype().as_str().into(),
                registry_version,
                effective_from,
                received_at: now,
                catalog_fence: None,
                reader_key_escrow: None,
            })
            .await
            .unwrap();
        assert!(matches!(
            result,
            TrustIndexOutcome::Indexed | TrustIndexOutcome::AlreadyIndexed
        ));
    }
}
fn disable(f: &mut support::Fixture, from: u64, issued: i64) {
    f.line.push(
        support::trust::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: Some(from),
        },
        support::trust::HeadOptions {
            effective_from: Some(from),
            issued_at: UnixMillis::new(issued),
            not_before: UnixMillis::new(issued),
            policy_destruction_enabled_override: Some(false),
            policy_eds_privacy_decision_document_hash_override: Some(None),
            ..support::options()
        },
    );
}
enum AfterSelection<'a> {
    Publish(&'a support::trust::RegistryLineBuilder),
    Clock(i64),
}
struct PublishDuringRead {
    objects: Arc<S3ObjectStore>,
    repository: Arc<PostgresRepository>,
    org: OrganizationId,
    line: support::trust::RegistryLineBuilder,
    fired: AtomicBool,
}
#[async_trait]
impl ObjectStore for PublishDuringRead {
    async fn stage_stream(
        &self,
        kind: ObjectTypeV1,
        bytes: aws_sdk_s3::primitives::ByteStream,
        limit: u64,
    ) -> Result<StagedObject, StoreError> {
        self.objects.stage_stream(kind, bytes, limit).await
    }
    async fn put_if_absent(&self, staged: StagedObject) -> Result<StoredObject, StoreError> {
        self.objects.put_if_absent(staged).await
    }
    async fn get_exact(
        &self,
        hash: ObjectHash,
    ) -> Result<aws_sdk_s3::primitives::ByteStream, StoreError> {
        if !self.fired.swap(true, Ordering::SeqCst) {
            publish_catalog_ports(
                &self.objects,
                &self.repository,
                self.org,
                &self.line,
                UnixMillis::new(support::NOW),
            )
            .await;
        }
        self.objects.get_exact(hash).await
    }
    async fn get_exact_in(
        &self,
        kind: ObjectTypeV1,
        hash: ObjectHash,
    ) -> Result<aws_sdk_s3::primitives::ByteStream, StoreError> {
        self.objects.get_exact_in(kind, hash).await
    }
}

#[tokio::test]
async fn catalog_changed_during_signature_walk_cannot_receive_a_new_revision_fence() {
    let mut f = support::Fixture::new(true, true, false);
    let live = Live::new(&f).await;
    disable(&mut f, 351, 100);
    let objects = Arc::new(PublishDuringRead {
        objects: live.objects.clone(),
        repository: live.repository.clone(),
        org: live.org,
        line: f.line,
        fired: AtomicBool::new(false),
    });
    let authority = PostgresTrustAuthority::new(live.pool.clone(), objects);
    let result = authority
        .select_current_admission(live.org, ChainSequence::new(351), live.clock.now())
        .await;
    assert_eq!(result.err(), Some(AuthorityError::StateConflict));
    assert_eq!(live.rows().await, 0);
    drop(authority);
    live.close().await;
}

#[tokio::test]
async fn same_object_indexing_and_reservation_serialize_without_reverse_lock_deadlock() {
    let f = support::Fixture::new(true, true, false);
    let exact = f.authorization();
    let live = Live::new(&f).await;
    let selected = live
        .heads
        .select_current_admission(live.org, ChainSequence::new(351), live.clock.now())
        .await
        .unwrap()
        .unwrap();
    let staged = live
        .objects
        .stage_stream(
            ObjectTypeV1::Trust,
            aws_sdk_s3::primitives::ByteStream::from(exact.clone()),
            1_048_576,
        )
        .await
        .unwrap();
    let stored = live.objects.put_if_absent(staged).await.unwrap();
    let command = DestructionRequestCommandV1 {
        organization_id: live.org,
        chain_id: live.chain,
        expected_chain_head: live.committed,
        authority_fence: selected.fence,
        destruction_id: f.fields().destruction_id,
        authorization: IndexedObjectV1 {
            kind: ObjectTypeV1::Trust,
            object_hash: stored.object_hash(),
            size_bytes: stored.size_bytes(),
        },
        targets: vec![(EntryHash::try_from(&[1; 32][..]).unwrap(), 1)],
        requested_at: live.clock.now(),
    };
    // Pause reservation after its organization lock but before the index write.
    let mut blocker = live.pool.begin().await.unwrap();
    sqlx::query(
        "SELECT head_sequence FROM chain_heads WHERE organization_id=$1 AND chain_id=$2 FOR UPDATE",
    )
    .bind(live.org.as_bytes().as_slice())
    .bind(live.chain.as_bytes().as_slice())
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
    let repository = live.repository.clone();
    let clock = live.clock.clone();
    let reservation = tokio::spawn(async move {
        repository
            .record_destruction_request(command, clock.as_ref())
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10),async {
  loop {
   let probe=sqlx::query("SELECT organization_id FROM organizations WHERE organization_id=$1 FOR NO KEY UPDATE NOWAIT").bind(live.org.as_bytes().as_slice()).fetch_one(&live.pool).await;
   match probe {Err(sqlx::Error::Database(error)) if error.code().as_deref()==Some("55P03")=>break,Ok(_)=>tokio::task::yield_now().await,Err(error)=>panic!("organization lock probe failed: {error}")}
  }
 }).await.expect("reservation must reach the held chain lock");
    let event = TrustEventCommandV1 {
        organization_id: live.org,
        object_hash: stored.object_hash(),
        size_bytes: stored.size_bytes(),
        subtype_code: "destructionAuthorization".into(),
        registry_version: None,
        effective_from: UnixMillis::new(0),
        received_at: live.clock.now(),
        catalog_fence: None,
        reader_key_escrow: None,
    };
    let repository = live.repository.clone();
    let indexing = tokio::spawn(async move { repository.index_event(event).await });
    tokio::time::timeout(std::time::Duration::from_secs(10),async {
  loop {
   let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND (query LIKE '%SELECT organization_id FROM organizations%' OR query LIKE '%INSERT INTO trust_events%'))").fetch_one(&live.pool).await.unwrap();
   if waiting {break}tokio::task::yield_now().await;
  }
 }).await.expect("concurrent indexing must wait behind reservation");
    blocker.commit().await.unwrap();
    let (reserved, indexed) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(reservation, indexing)
    })
    .await
    .expect("org-first order must not deadlock");
    assert_eq!(reserved.unwrap().unwrap(), AppendOutcome::Recorded);
    assert_eq!(indexed.unwrap().unwrap(), TrustIndexOutcome::Indexed);
    assert_eq!(live.rows().await, 1);
    live.close().await;
}
/// Real selection completes, then another real index transaction commits
/// before the admission service receives its snapshot. Chain stays at350.
struct InterleavingDirectory<'a> {
    live: &'a Live,
    after: AfterSelection<'a>,
    fired: AtomicBool,
}
#[async_trait]
impl RegistryHeadDirectory for InterleavingDirectory<'_> {
    async fn select_head_for_sequence(
        &self,
        org: OrganizationId,
        seq: ChainSequence,
        now: UnixMillis,
    ) -> Result<RegistryHeadSelectionV1, AuthorityError> {
        self.live
            .heads
            .select_head_for_sequence(org, seq, now)
            .await
    }
    async fn select_current_admission(
        &self,
        org: OrganizationId,
        seq: ChainSequence,
        now: UnixMillis,
    ) -> Result<Option<RegistryAdmissionV1>, AuthorityError> {
        let result = self
            .live
            .heads
            .select_current_admission(org, seq, now)
            .await?;
        if !self.fired.swap(true, Ordering::SeqCst) {
            match &self.after {
                AfterSelection::Publish(line) => publish_catalog(self.live, line).await,
                AfterSelection::Clock(time) => self.live.clock.0.store(*time, Ordering::SeqCst),
            }
        }
        Ok(result)
    }
}
#[tokio::test]
async fn service_fences_concurrent_catalog_publication_and_future_policy_retry_is_allowed() {
    for effective in [351, 401] {
        let mut f = support::Fixture::new(true, true, false);
        let exact = f.authorization();
        let live = Live::new(&f).await;
        disable(&mut f, effective, 100);
        let directory = InterleavingDirectory {
            live: &live,
            after: AfterSelection::Publish(&f.line),
            fired: AtomicBool::new(false),
        };
        let result = accept_destruction_request(live.org, &exact, &live.ports(&directory)).await;
        assert_eq!(
            result.unwrap_err().code(),
            "EA-DESTRUCTION-DEPENDENCY-UNAVAILABLE"
        );
        assert_eq!(live.rows().await, 0);
        assert!(
            live.repository
                .committed_chain_head(live.org, live.chain)
                .await
                .unwrap()
                == Some(live.committed)
        );
        let retry = accept_destruction_request(live.org, &exact, &live.ports(&live.heads)).await;
        if effective == 351 {
            assert_eq!(retry.unwrap_err().code(), "EA-DESTRUCTION-PRIVACY-GATE");
            assert_eq!(live.rows().await, 0)
        } else {
            assert_eq!(retry.unwrap().state(), 0);
            assert_eq!(live.rows().await, 1)
        }
        live.close().await;
    }
}
#[tokio::test]
async fn time_is_rechecked_under_locks_and_signed_future_successor_has_no_fallback_authority() {
    for at_commit in [10_000_000, 10_000_001] {
        let f = support::Fixture::new(true, true, false);
        let exact = f.authorization();
        let live = Live::new(&f).await;
        let directory = InterleavingDirectory {
            live: &live,
            after: AfterSelection::Clock(at_commit),
            fired: AtomicBool::new(false),
        };
        let result = accept_destruction_request(live.org, &exact, &live.ports(&directory)).await;
        if at_commit == 10_000_000 {
            assert_eq!(result.unwrap().state(), 0)
        } else {
            assert_eq!(
                result.unwrap_err().code(),
                "EA-DESTRUCTION-DEPENDENCY-UNAVAILABLE"
            );
            assert_eq!(live.rows().await, 0)
        }
        live.close().await;
    }
    let mut f = support::Fixture::new(true, true, false);
    let exact = f.authorization();
    disable(&mut f, 351, support::NOW + 100);
    let live = Live::new(&f).await;
    assert!(
        live.heads
            .select_current_admission(live.org, ChainSequence::new(351), live.clock.now())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        accept_destruction_request(live.org, &exact, &live.ports(&live.heads))
            .await
            .unwrap_err()
            .code(),
        "EA-DESTRUCTION-AUTHORIZATION-UNVERIFIABLE"
    );
    live.clock.0.store(support::NOW + 100, Ordering::SeqCst);
    assert_eq!(
        accept_destruction_request(live.org, &exact, &live.ports(&live.heads))
            .await
            .unwrap_err()
            .code(),
        "EA-DESTRUCTION-PRIVACY-GATE"
    );
    assert_eq!(live.rows().await, 0);
    live.close().await;
}
