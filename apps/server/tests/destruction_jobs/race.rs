//! The decorator controls scheduling only; every byte/list/delete and every
//! mutation lock goes to the actual S3/PostgreSQL adapters.
use super::*;
use aws_sdk_s3::primitives::ByteStream;
use ea_sync_server::managed_destruction::{ObservedObjectVersions, StoredObjectVersion};
use ea_sync_server::{ObjectStore, StagedObject, StoreError, StoredObject};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
struct PausedStore {
    real: Arc<dyn ObjectStore>,
    pause: AtomicBool,
    pause_entry: AtomicBool,
    expire: Option<Arc<TestClock>>,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl ObjectStore for PausedStore {
    async fn verify_destruction_scope(
        &self,
        t: &[EntryHash],
        k: &[ea_sync_server::IndexedObjectV1],
    ) -> Result<(), StoreError> {
        self.real.verify_destruction_scope(t, k).await
    }
    async fn remaining_destruction_versions(
        &self,
        k: ObjectTypeV1,
        h: ObjectHash,
    ) -> Result<Vec<StoredObjectVersion>, StoreError> {
        if self.pause.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        self.real.remaining_destruction_versions(k, h).await
    }
    async fn destruction_versions(
        &self,
        k: ObjectTypeV1,
        h: ObjectHash,
    ) -> Result<ObservedObjectVersions, StoreError> {
        self.real.destruction_versions(k, h).await
    }
    async fn remove_destruction_version(
        &self,
        k: ObjectTypeV1,
        h: ObjectHash,
        v: &StoredObjectVersion,
        window: &ea_sync_server::managed_destruction::ServerRemovalWindow,
    ) -> Result<(), StoreError> {
        if let Some(clock) = &self.expire {
            clock.0.store(2_000_000, Ordering::SeqCst);
        }
        self.real.remove_destruction_version(k, h, v, window).await
    }
    async fn stage_stream(
        &self,
        k: ObjectTypeV1,
        b: ByteStream,
        l: u64,
    ) -> Result<StagedObject, StoreError> {
        if k == ObjectTypeV1::Entry && self.pause_entry.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        self.real.stage_stream(k, b, l).await
    }
    async fn put_if_absent(&self, s: StagedObject) -> Result<StoredObject, StoreError> {
        self.real.put_if_absent(s).await
    }
    async fn get_exact(&self, h: ObjectHash) -> Result<ByteStream, StoreError> {
        self.real.get_exact(h).await
    }
    async fn get_exact_in(&self, k: ObjectTypeV1, h: ObjectHash) -> Result<ByteStream, StoreError> {
        self.real.get_exact_in(k, h).await
    }
}
#[tokio::test]
async fn already_started_put_cannot_resurrect_a_generation_after_measured_removal() {
    use einsatzarchiv_server::adapters::{
        clock::FixedClock, postgres::PostgresRepository, s3::S3ObjectStore,
    };
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-put-race");
    common::ensure_bucket(&bucket).await;
    let prior = fixture.seed(&database, &bucket).await;
    let org = fixture.original.anchor.organization_id();
    let repo = Arc::new(PostgresRepository::new(database.pool().clone()));
    let client = common::object_store_client().await;
    let real = Arc::new(S3ObjectStore::new(
        client.clone(),
        bucket.clone(),
        org,
        repo.clone(),
        repo,
        Arc::new(FixedClock(UnixMillis::new(NOW))),
    ));
    // Exact persisted staging belongs to an already prepared older upload.
    let staging = "staging/eip/preexisting-put";
    client
        .put_object()
        .bucket(&bucket)
        .key(staging)
        .body(ByteStream::from(fixture.original.original_bytes.clone()))
        .send()
        .await
        .unwrap();
    let paused = Arc::new(PausedStore {
        real: real.clone(),
        pause: AtomicBool::new(true),
        pause_entry: AtomicBool::new(false),
        expire: None,
        entered: Default::default(),
        resume: Default::default(),
    });
    let host = common::spawn_server_with_object_store(
        database.pool().clone(),
        UnixMillis::new(NOW),
        org,
        SERVER_SEED,
        fixture.server,
        &bucket,
        common::TestExecutionPorts {
            deletion: Some((COMPONENT_SEED, fixture.component)),
            objects_override: Some(paused.clone()),
            clock_override: None,
        },
    )
    .await;
    let ready = Arc::new(common::ReadyServer {
        server: host,
        closure: prior.closure,
    });
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionJobs,
            target: &jobs,
            body: Some(&fixture.body),
            request_id: [0xf1; 16]
        })
        .await
        .status,
        202
    );
    let request = transition(&fixture, None, 0, None, 0xf1);
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&request),
            request_id: [0xf2; 16]
        })
        .await
        .status,
        202
    );
    let start = transition(&fixture, Some(0), 1, Some(object_hash(&request)), 0xf2);
    let action_ready = ready.clone();
    let action = tokio::spawn(async move {
        common::call(&common::ApiCall {
            ready: &action_ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&start),
            request_id: [0xf3; 16],
        })
        .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        paused.entered.notified(),
    )
    .await
    .unwrap();
    let hash = object_hash(&fixture.original.original_bytes);
    let size = fixture.original.original_bytes.len() as u64;
    let old_put = tokio::spawn(async move {
        real.put_if_absent(StagedObject::new(
            ObjectTypeV1::Entry,
            hash,
            size,
            staging.to_owned(),
        ))
        .await
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FOR SHARE%')")
            .fetch_one(database.pool()).await.unwrap();
        if blocked {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the real older Put must wait on the execution transaction lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(!old_put.is_finished());
    paused.resume.notify_one();
    let completed = tokio::time::timeout(std::time::Duration::from_secs(60), action)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        completed.status, 202,
        "actual signed start/execution must finish"
    );
    assert!(
        old_put.await.unwrap().is_err(),
        "released older Put must recheck the persisted reservation before provider write"
    );
    let list = client
        .list_object_versions()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
    for key in [
        ea_sync_server::object_key(ObjectTypeV1::Entry, hash),
        staging.to_owned(),
    ] {
        assert!(
            !list
                .versions()
                .iter()
                .any(|v| v.key() == Some(key.as_str()))
        );
        assert!(
            !list
                .delete_markers()
                .iter()
                .any(|v| v.key() == Some(key.as_str()))
        );
    }
    cleanup_fixture(database, &bucket).await;
}

struct TestClock(std::sync::atomic::AtomicI64);
impl ea_sync_server::ServerClock for TestClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0.load(Ordering::SeqCst))
    }
}
#[tokio::test]
async fn time_expiring_before_provider_delete_preserves_every_target_generation() {
    use einsatzarchiv_server::adapters::{postgres::PostgresRepository, s3::S3ObjectStore};
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-expiry");
    common::ensure_bucket(&bucket).await;
    let prior = fixture.seed(&database, &bucket).await;
    let org = fixture.original.anchor.organization_id();
    let clock = Arc::new(TestClock(std::sync::atomic::AtomicI64::new(NOW)));
    let repo = Arc::new(PostgresRepository::new(database.pool().clone()));
    let client = common::object_store_client().await;
    let real = Arc::new(S3ObjectStore::new(
        client.clone(),
        bucket.clone(),
        org,
        repo.clone(),
        repo,
        clock.clone(),
    ));
    let expiring = Arc::new(PausedStore {
        real,
        pause: AtomicBool::new(false),
        pause_entry: AtomicBool::new(false),
        expire: Some(clock.clone()),
        entered: Default::default(),
        resume: Default::default(),
    });
    let host = common::spawn_server_with_object_store(
        database.pool().clone(),
        UnixMillis::new(NOW),
        org,
        SERVER_SEED,
        fixture.server,
        &bucket,
        common::TestExecutionPorts {
            deletion: Some((COMPONENT_SEED, fixture.component)),
            objects_override: Some(expiring),
            clock_override: Some(clock),
        },
    )
    .await;
    let ready = common::ReadyServer {
        server: host,
        closure: prior.closure,
    };
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionJobs,
            target: &jobs,
            body: Some(&fixture.body),
            request_id: [0x45; 16]
        })
        .await
        .status,
        202
    );
    let request = transition(&fixture, None, 0, None, 0x45);
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&request),
            request_id: [0x46; 16]
        })
        .await
        .status,
        202
    );
    let start = transition(&fixture, Some(0), 1, Some(object_hash(&request)), 0x46);
    let failed = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&start),
        request_id: [0x47; 16],
    })
    .await;
    assert!(
        failed.status >= 400,
        "expired current authority cannot issue measurement success"
    );
    for (kind, hash) in [
        (
            ObjectTypeV1::Entry,
            object_hash(&fixture.original.original_bytes),
        ),
        (
            ObjectTypeV1::Grant,
            object_hash(&fixture.original.initial_grant_bytes),
        ),
    ] {
        let list = client
            .list_object_versions()
            .bucket(&bucket)
            .prefix(ea_sync_server::object_key(kind, hash))
            .send()
            .await
            .unwrap();
        assert_eq!(
            list.versions().len(),
            1,
            "not even the first provider generation may be deleted after the action authority expired"
        );
    }
    cleanup_fixture(database, &bucket).await;
}

#[tokio::test]
async fn authenticated_http_commit_started_before_execution_cannot_recreate_removed_ciphertext() {
    use einsatzarchiv_server::adapters::{
        clock::FixedClock, postgres::PostgresRepository, s3::S3ObjectStore,
    };
    let fixture = JobFixture::with_options(NOW, false, true);
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-http-commit-race");
    common::ensure_bucket(&bucket).await;
    let prior = fixture.seed(&database, &bucket).await;
    let org = fixture.original.anchor.organization_id();
    let repo = Arc::new(PostgresRepository::new(database.pool().clone()));
    let s3 = common::object_store_client().await;
    let paused = Arc::new(PausedStore {
        real: Arc::new(S3ObjectStore::new(
            s3.clone(),
            bucket.clone(),
            org,
            repo.clone(),
            repo,
            Arc::new(FixedClock(UnixMillis::new(NOW))),
        )),
        pause: AtomicBool::new(false),
        pause_entry: AtomicBool::new(true),
        expire: None,
        entered: Default::default(),
        resume: Default::default(),
    });
    let host = common::spawn_server_with_object_store(
        database.pool().clone(),
        UnixMillis::new(NOW),
        org,
        SERVER_SEED,
        fixture.server,
        &bucket,
        common::TestExecutionPorts {
            deletion: Some((COMPONENT_SEED, fixture.component)),
            objects_override: Some(paused.clone()),
            clock_override: None,
        },
    )
    .await;
    let ready = Arc::new(common::ReadyServer {
        server: host,
        closure: prior.closure,
    });
    let ParsedArchiveObject::Grant(g) =
        decode_exact_object(&fixture.original.initial_grant_bytes).unwrap()
    else {
        panic!()
    };
    let f = g.value().grant_body().fields();
    let plan = ea_format::GrantPlanV1::new(vec![ea_format::GrantPlanItemV1::new(
        f.recipient_key_thumbprint,
        f.recipient_certificate_hash,
        ea_format::GrantPurposeV1::Recovery,
    )])
    .unwrap();
    let commit = ea_sync_protocol::EntryCommitRequestV1::new(
        fixture.original.original_bytes.clone(),
        plan,
        vec![fixture.original.initial_grant_bytes.clone()],
    )
    .unwrap();
    let request_ready = ready.clone();
    let mut pending = tokio::spawn(async move {
        let target = format!(
            "/v1/chains/{}/entry-commits",
            hex::encode(request_ready.closure.chain_id.as_bytes())
        );
        let nonce = common::fresh_challenge(&request_ready.server, org).await;
        let signer = ea_sync_protocol::RequestSigner::from_secret(SecretBytes::new([0xe3; 32]));
        let headers = common::signed_headers(&common::SignedCall {
            signer: &signer,
            endpoint: EndpointV1::EntryCommits,
            authority: &request_ready.server.authority,
            target: &target,
            body: Some(commit.exact_bytes()),
            organization_id: org,
            request_id: [0xb1; 16],
            nonce,
            created: NOW.div_euclid(1000),
        });
        common::https_request(
            request_ready.server.address,
            &request_ready.server.authority,
            "POST",
            &target,
            &headers,
            commit.exact_bytes(),
        )
        .await
    });
    tokio::select! {
        response = &mut pending => {
            let response=response.unwrap();
            panic!("fixture HTTP Commit refused before provider boundary: {} {:?}",response.status,common::error_code(&response.body));
        },
        entered = tokio::time::timeout(std::time::Duration::from_secs(20),paused.entered.notified()) => {
            entered.expect("real HTTP authentication must reach production Commit service");
        }
    }
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionJobs,
            target: &jobs,
            body: Some(&fixture.body),
            request_id: [0xb2; 16]
        })
        .await
        .status,
        202
    );
    let requested = transition(&fixture, None, 0, None, 0xb1);
    let started = transition(&fixture, Some(0), 1, Some(object_hash(&requested)), 0xb2);
    for (marker, body) in [(0xb3, &requested), (0xb4, &started)] {
        assert_eq!(
            common::call(&common::ApiCall {
                ready: &ready,
                signer_seed: COMPONENT_SEED,
                endpoint: EndpointV1::DestructionEvents,
                target: &events,
                body: Some(body),
                request_id: [marker; 16]
            })
            .await
            .status,
            202
        );
    }
    paused.resume.notify_one();
    assert_eq!(
        pending.await.unwrap().status,
        503,
        "the authenticated older Commit must stop before its real S3 stage"
    );
    let versions = s3
        .list_object_versions()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
    for (kind, bytes) in [
        (ObjectTypeV1::Entry, &fixture.original.original_bytes),
        (ObjectTypeV1::Grant, &fixture.original.initial_grant_bytes),
    ] {
        let key = ea_sync_server::object_key(kind, object_hash(bytes));
        assert!(
            !versions
                .versions()
                .iter()
                .any(|v| v.key() == Some(key.as_str()))
        );
        assert!(
            !versions
                .delete_markers()
                .iter()
                .any(|v| v.key() == Some(key.as_str()))
        );
    }
    assert!(!versions.versions().iter().any(|v| {
        v.key()
            .is_some_and(|k| k.starts_with("staging/eip/") || k.starts_with("staging/eag/"))
    }));
    cleanup_fixture(database, &bucket).await;
}
