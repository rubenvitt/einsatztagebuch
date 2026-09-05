//! Cache witnesses against PostgreSQL, the real S3 adapter and frozen signed
//! trust objects. The wrapper observes object reads and can pause one read;
//! it neither supplies trust bytes nor decides authority.

mod common;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use ea_crypto::{SecretBytes, object_hash};
use ea_format::{DecodedTrustPayloadV1, ObjectTypeV1, ParsedArchiveObject};
use ea_sync_protocol::RequestSigner;
use ea_sync_server::trust::TrustEventValidator;
use ea_sync_server::{
    AuthorityError, DeviceAuthorityDirectory, ObjectStore, StagedObject, StoreError, StoredObject,
    TrustEventCommandV1, TrustEventStore, TrustIndexOutcome,
};
use ea_types::{KeyThumbprint, ObjectHash, OrganizationId, UnixMillis};
use einsatzarchiv_server::adapters::{
    clock::FixedClock, postgres::PostgresRepository, s3::S3ObjectStore,
    trust_authority::PostgresTrustAuthority,
};
use sqlx::PgPool;
use tokio::sync::oneshot;

const CASE: &str = "registry/accepted-admin-rotation";
const SECOND_HEAD: &str = "second-head-event.bin";
const NOW: UnixMillis = UnixMillis::new(1_000);

fn admin_key() -> KeyThumbprint {
    RequestSigner::from_secret(SecretBytes::new(
        ea_testkit::TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
    ))
    .public_key()
    .thumbprint()
}

fn rotated_key() -> KeyThumbprint {
    RequestSigner::from_secret(SecretBytes::new(
        ea_testkit::TEST_ENTROPY_ROTATED_ORGANIZATION_ADMIN_ED25519_SEED,
    ))
    .public_key()
    .thumbprint()
}

struct ReadGate {
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

struct ObservedObjects {
    inner: S3ObjectStore,
    reads: AtomicUsize,
    gate: Mutex<Option<ReadGate>>,
}

impl ObservedObjects {
    async fn new(pool: &PgPool, organization_id: OrganizationId) -> Arc<Self> {
        let repository = Arc::new(PostgresRepository::new(pool.clone()));
        Arc::new(Self {
            inner: S3ObjectStore::new(
                common::object_store_client().await,
                common::INTEGRATION_BUCKET.to_owned(),
                organization_id,
                repository.clone(),
                repository,
                Arc::new(FixedClock(NOW)),
            ),
            reads: AtomicUsize::new(0),
            gate: Mutex::new(None),
        })
    }

    fn pause_next_read(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered, observed) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        *self.gate.lock().expect("test gate mutex must be healthy") = Some(ReadGate {
            entered,
            release: resume,
        });
        (observed, release)
    }
}

#[async_trait]
impl ObjectStore for ObservedObjects {
    async fn stage_stream(
        &self,
        kind: ObjectTypeV1,
        body: ByteStream,
        limit: u64,
    ) -> Result<StagedObject, StoreError> {
        self.inner.stage_stream(kind, body, limit).await
    }

    async fn put_if_absent(&self, staged: StagedObject) -> Result<StoredObject, StoreError> {
        self.inner.put_if_absent(staged).await
    }

    async fn get_exact(&self, hash: ObjectHash) -> Result<ByteStream, StoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let gate = self
            .gate
            .lock()
            .expect("test gate mutex must be healthy")
            .take();
        if let Some(gate) = gate {
            gate.entered
                .send(())
                .expect("the test must observe the read");
            gate.release.await.expect("the test must release the read");
        }
        self.inner.get_exact(hash).await
    }

    async fn get_exact_in(
        &self,
        kind: ObjectTypeV1,
        hash: ObjectHash,
    ) -> Result<ByteStream, StoreError> {
        self.inner.get_exact_in(kind, hash).await
    }
}

async fn catalog_size(pool: &PgPool) -> usize {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM trust_events")
        .fetch_one(pool)
        .await
        .expect("the trust catalog must be countable");
    usize::try_from(count).expect("the fixture catalog is small")
}

async fn index_trust_object(pool: &PgPool, organization_id: OrganizationId, bytes: Vec<u8>) {
    let hash = object_hash(&bytes);
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&bytes).expect("the frozen head decodes")
    else {
        panic!("the fixture must be a trust object");
    };
    let registry = match parsed
        .value()
        .decoded_payload()
        .expect("the signed payload decodes")
    {
        DecodedTrustPayloadV1::RegistryEvent(core) => Some(core),
        _ => None,
    };
    common::object_store_client()
        .await
        .put_object()
        .bucket(common::INTEGRATION_BUCKET)
        .key(ea_sync_server::object_key(ObjectTypeV1::Trust, hash))
        .body(ByteStream::from(bytes.clone()))
        .send()
        .await
        .expect("the signed head must reach the real object store");
    let result = PostgresRepository::new(pool.clone())
        .index_event(TrustEventCommandV1 {
            organization_id,
            object_hash: hash,
            size_bytes: u64::try_from(bytes.len()).expect("the fixture is small"),
            subtype_code: parsed.value().subtype().as_str().to_owned(),
            registry_version: registry.as_ref().map(|core| core.fields().registry_version),
            effective_from: registry
                .as_ref()
                .map_or(NOW, |core| core.fields().issued_at),
            received_at: NOW,
        })
        .await
        .expect("the real trust index must accept the frozen successor");
    assert_eq!(result, TrustIndexOutcome::Indexed);
}

#[tokio::test(flavor = "multi_thread")]
async fn steady_state_authority_lookup_does_not_reread_the_catalog() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), CASE, &[]).await;
    let objects = ObservedObjects::new(database.pool(), fixture.organization_id).await;
    let authority = PostgresTrustAuthority::new(database.pool().clone(), objects.clone());
    let first = authority
        .resolve(fixture.organization_id, admin_key(), NOW)
        .await
        .unwrap();
    assert!(first.is_some(), "the signed baseline must carry authority");
    let cold_reads = objects.reads.load(Ordering::SeqCst);
    assert_eq!(cold_reads, catalog_size(database.pool()).await);

    let second = authority
        .resolve(fixture.organization_id, admin_key(), UnixMillis::new(1_001))
        .await
        .unwrap();
    assert_eq!(first, second);
    assert!(
        authority
            .resolve(fixture.organization_id, rotated_key(), NOW)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        objects.reads.load(Ordering::SeqCst),
        cold_reads,
        "changing the caller or advancing within validity must reuse verified authority"
    );
    let writes: i64 = sqlx::query_scalar("SELECT count(*) FROM trust_state")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(writes, 0, "cache fills and hits are read-only");
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_cold_requests_share_one_catalog_read() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), CASE, &[]).await;
    let objects = ObservedObjects::new(database.pool(), fixture.organization_id).await;
    let authority = PostgresTrustAuthority::new(database.pool().clone(), objects.clone());
    let (first, second) = tokio::join!(
        authority.resolve(fixture.organization_id, admin_key(), NOW),
        authority.resolve(fixture.organization_id, rotated_key(), NOW),
    );
    assert!(first.unwrap().is_some());
    assert!(second.unwrap().is_some());
    assert_eq!(
        objects.reads.load(Ordering::SeqCst),
        catalog_size(database.pool()).await
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn indexing_a_successor_invalidates_every_authority_instance() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), CASE, &[SECOND_HEAD]).await;
    let objects = ObservedObjects::new(database.pool(), fixture.organization_id).await;
    let first = PostgresTrustAuthority::new(database.pool().clone(), objects.clone());
    let second = PostgresTrustAuthority::new(database.pool().clone(), objects);
    for authority in [&first, &second] {
        assert!(
            authority
                .resolve(fixture.organization_id, rotated_key(), NOW)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            authority
                .resolve(fixture.organization_id, admin_key(), NOW)
                .await
                .unwrap()
                .is_some()
        );
    }
    index_trust_object(
        database.pool(),
        fixture.organization_id,
        fixture.withheld.into_iter().next().unwrap(),
    )
    .await;
    for authority in [&first, &second] {
        assert!(
            authority
                .resolve(fixture.organization_id, rotated_key(), NOW)
                .await
                .unwrap()
                .is_some(),
            "the signed successor activates the rotated certificate on each instance"
        );
    }
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn indexing_during_a_cold_build_cannot_return_the_old_authority() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), CASE, &[SECOND_HEAD]).await;
    let objects = ObservedObjects::new(database.pool(), fixture.organization_id).await;
    let (entered, release) = objects.pause_next_read();
    let authority = Arc::new(PostgresTrustAuthority::new(
        database.pool().clone(),
        objects,
    ));
    let reader = authority.clone();
    let organization_id = fixture.organization_id;
    let pending =
        tokio::spawn(async move { reader.resolve(organization_id, admin_key(), NOW).await });
    tokio::time::timeout(std::time::Duration::from_secs(10), entered)
        .await
        .expect("the cold reader must reach object storage")
        .unwrap();
    index_trust_object(
        database.pool(),
        fixture.organization_id,
        fixture.withheld.into_iter().next().unwrap(),
    )
    .await;
    release
        .send(())
        .expect("the cold reader must still be waiting");
    assert_eq!(pending.await.unwrap(), Err(AuthorityError::StateConflict));
    assert!(
        authority
            .resolve(organization_id, rotated_key(), NOW)
            .await
            .unwrap()
            .is_some()
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_warm_head_expires_and_a_backward_clock_rechecks_selection() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), CASE, &[]).await;
    let objects = ObservedObjects::new(database.pool(), fixture.organization_id).await;
    let authority = PostgresTrustAuthority::new(database.pool().clone(), objects.clone());
    assert!(
        authority
            .resolve(fixture.organization_id, rotated_key(), NOW)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        authority
            .resolve(
                fixture.organization_id,
                rotated_key(),
                UnixMillis::new(10_000)
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        authority
            .resolve(
                fixture.organization_id,
                rotated_key(),
                UnixMillis::new(10_001)
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        authority
            .resolve(fixture.organization_id, rotated_key(), UnixMillis::new(99))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        authority
            .resolve(fixture.organization_id, rotated_key(), NOW)
            .await
            .unwrap()
            .is_some()
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn replacing_the_anchor_does_not_reuse_old_authority() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), CASE, &[]).await;
    let objects = ObservedObjects::new(database.pool(), fixture.organization_id).await;
    let authority = PostgresTrustAuthority::new(database.pool().clone(), objects);
    assert!(
        authority
            .resolve(fixture.organization_id, admin_key(), NOW)
            .await
            .unwrap()
            .is_some()
    );
    sqlx::query("UPDATE organizations SET trust_anchor_bytes = $1")
        .bind(&[0xff_u8][..])
        .execute(database.pool())
        .await
        .unwrap();
    assert!(
        authority
            .resolve(fixture.organization_id, admin_key(), NOW)
            .await
            .unwrap()
            .is_none()
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn truncating_the_catalog_invalidates_a_warm_authority() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), CASE, &[]).await;
    let objects = ObservedObjects::new(database.pool(), fixture.organization_id).await;
    let authority = PostgresTrustAuthority::new(database.pool().clone(), objects);
    assert!(
        authority
            .resolve(fixture.organization_id, admin_key(), NOW)
            .await
            .unwrap()
            .is_some()
    );
    sqlx::query("TRUNCATE trust_events")
        .execute(database.pool())
        .await
        .unwrap();
    assert!(
        authority
            .resolve(fixture.organization_id, admin_key(), NOW)
            .await
            .unwrap()
            .is_none()
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pending_future_head_is_reselected_when_its_signed_time_arrives() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), CASE, &[]).await;
    for bytes in common::trust_closure::future_admin_revocation() {
        index_trust_object(database.pool(), fixture.organization_id, bytes).await;
    }
    let objects = ObservedObjects::new(database.pool(), fixture.organization_id).await;
    let authority = PostgresTrustAuthority::new(database.pool().clone(), objects);
    // The old heads expired at 10_000, the successor starts at 20_000, and
    // its overlapping lease leaves the shared selection PendingFuture.
    assert!(
        authority
            .resolve(
                fixture.organization_id,
                admin_key(),
                UnixMillis::new(15_000)
            )
            .await
            .unwrap()
            .is_some(),
        "the baseline must exercise the headless authority branch"
    );
    assert!(
        authority
            .resolve(
                fixture.organization_id,
                admin_key(),
                UnixMillis::new(20_000)
            )
            .await
            .unwrap()
            .is_none(),
        "the now-applicable signed head revokes this administrator"
    );
    assert!(
        authority
            .resolve(
                fixture.organization_id,
                rotated_key(),
                UnixMillis::new(20_000)
            )
            .await
            .unwrap()
            .is_some(),
        "the selected successor still authorizes its active admin"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_pinned_head_is_an_authorization_refusal() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), CASE, &[]).await;
    let objects = ObservedObjects::new(database.pool(), fixture.organization_id).await;
    let authority = PostgresTrustAuthority::new(database.pool().clone(), objects);
    authority
        .advance_pinned_head(fixture.organization_id, NOW)
        .await
        .unwrap();
    assert!(
        authority
            .resolve(fixture.organization_id, admin_key(), NOW)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        authority
            .resolve(
                fixture.organization_id,
                admin_key(),
                UnixMillis::new(10_001)
            )
            .await,
        Ok(None),
        "expiry is no active authority, not a catalog rollback"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invalid_anchor_with_a_pin_is_an_authorization_refusal() {
    let database = common::fresh_database().await;
    let fixture = common::seed_trust_fixture(database.pool(), CASE, &[]).await;
    let objects = ObservedObjects::new(database.pool(), fixture.organization_id).await;
    let authority = PostgresTrustAuthority::new(database.pool().clone(), objects);
    authority
        .advance_pinned_head(fixture.organization_id, NOW)
        .await
        .unwrap();
    assert!(
        authority
            .resolve(fixture.organization_id, admin_key(), NOW)
            .await
            .unwrap()
            .is_some()
    );
    sqlx::query("UPDATE organizations SET trust_anchor_bytes = $1")
        .bind(&[0xff_u8][..])
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        authority
            .resolve(fixture.organization_id, admin_key(), NOW)
            .await,
        Ok(None)
    );
    database.cleanup().await;
}
