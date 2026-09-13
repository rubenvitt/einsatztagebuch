//! Routing and marker bytes must come from one committed SQLCipher state.
//! The synthetic job rows exercise local routing only, never signature authority.

use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ea_crypto::object_hash;
use ea_draft::{AutosaveDraftRepository, DraftRepository as _, EvidenceDraftSource};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider as _, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreError, StoreValue as V};
use ea_types::{DestructionId, ObjectHash, OrganizationId};

const ORDINARY_MARKER: &[u8] = b"ordinary prepared bytes";
const EVIDENCE_MARKER: &[u8] = b"evidence prepared bytes";
const JOB_CORE: &[u8] = b"synthetic local routing core";

struct Fixture {
    root: PathBuf,
    database: Arc<EncryptedDatabase>,
    repo: AutosaveDraftRepository,
    source: EvidenceDraftSource,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ea-marker-snapshot-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let provider = Arc::new(InMemoryKeyProvider::new_for_test([0x73; 32]));
        let key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let database = Arc::new(
            EncryptedDatabase::open(&root.join("writer.sqlite3"), provider.as_ref(), &key).unwrap(),
        );
        let repo = AutosaveDraftRepository::new(Arc::clone(&database), provider);
        repo.load_or_create().unwrap();
        // Keep all schema checks, foreign keys and immutable-row triggers active.
        database.transaction::<_, StoreError>(|tx| {
            tx.execute("INSERT INTO local_audit_event(event_id,exact_bytes,object_hash) VALUES(zeroblob(16),X'01',zeroblob(32))", &[])?;
            tx.execute("INSERT INTO destruction_request(organization_id,destruction_id,event_id,event_hash,exact_authorization,exact_event,audit_event_id) VALUES(zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(32),X'01',X'02',zeroblob(16))", &[])?;
            tx.execute("INSERT INTO destruction_inventory(organization_id,destruction_id,authorization_hash,exact_bytes) VALUES(zeroblob(16),zeroblob(16),zeroblob(32),X'03')", &[])?;
            tx.execute("INSERT INTO destruction_job(organization_id,destruction_id,authorization_hash,signer_certificate_hash,exact_inventory,exact_core,exact_signature) VALUES(zeroblob(16),zeroblob(16),zeroblob(32),zeroblob(32),X'03',?1,X'04')", &[V::Blob(JOB_CORE.to_vec())])?;
            Ok(())
        }).unwrap();
        let source = EvidenceDraftSource::new(
            OrganizationId::try_from([0; 16].as_slice()).unwrap(),
            DestructionId::try_from([0; 16].as_slice()).unwrap(),
            ObjectHash::try_from([0; 32].as_slice()).unwrap(),
            object_hash(JOB_CORE),
        );
        Self {
            root,
            database,
            repo,
            source,
        }
    }

    fn set_state(&self, evidence: bool) {
        set_state(&self.database, evidence);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn set_state(database: &EncryptedDatabase, evidence: bool) {
    database.transaction::<_, StoreError>(|tx| {
        tx.execute("DELETE FROM writer_evidence_draft WHERE singleton=0", &[])?;
        if evidence {
            tx.execute("INSERT INTO writer_evidence_draft(singleton,draft_id,organization_id,destruction_id,authorization_hash,preflight_hash) SELECT singleton,draft_id,zeroblob(16),zeroblob(16),zeroblob(32),?1 FROM draft WHERE singleton=0", &[V::Blob(object_hash(JOB_CORE).as_bytes().to_vec())])?;
        }
        let marker = if evidence { EVIDENCE_MARKER } else { ORDINARY_MARKER };
        tx.execute("INSERT INTO draft_transition(singleton,kind,draft_id,save_revision,marker,recorded_at_ms) SELECT singleton,1,draft_id,save_revision,?1,0 FROM draft WHERE singleton=0 ON CONFLICT(singleton) DO UPDATE SET marker=excluded.marker", &[V::Blob(marker.to_vec())])?;
        Ok(())
    }).unwrap();
}

#[test]
fn marker_absence_and_routing_errors_keep_their_precedence() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .repo
            .prepared_finalization_marker()
            .unwrap()
            .is_none()
    );
    let binding = fixture.repo.reserve_evidence_draft(fixture.source).unwrap();
    let scoped = fixture.repo.for_evidence_draft(binding).unwrap();
    fixture.set_state(true);
    assert_eq!(
        scoped
            .prepared_finalization_marker()
            .unwrap()
            .unwrap()
            .as_bytes(),
        EVIDENCE_MARKER
    );
    assert_eq!(
        fixture
            .repo
            .prepared_finalization_marker()
            .unwrap_err()
            .code(),
        "EA-DRAFT-EVIDENCE-RESERVED"
    );

    fixture
        .database
        .execute("DELETE FROM schema_migration WHERE version=2", &[])
        .unwrap();
    // Routing refusal precedes even the legacy migration-absent result.
    assert_eq!(
        fixture
            .repo
            .prepared_finalization_marker()
            .unwrap_err()
            .code(),
        "EA-DRAFT-EVIDENCE-RESERVED"
    );
    assert!(scoped.prepared_finalization_marker().unwrap().is_none());
    fixture.set_state(false);
    assert_eq!(
        scoped.prepared_finalization_marker().unwrap_err().code(),
        "EA-DRAFT-EVIDENCE-BINDING"
    );
    assert!(
        fixture
            .repo
            .prepared_finalization_marker()
            .unwrap()
            .is_none()
    );
}

#[test]
fn ordinary_marker_read_never_crosses_into_a_committed_evidence_route() {
    let fixture = Fixture::new();
    // Prove that both states are valid before introducing competition.
    fixture.set_state(true);
    assert_eq!(
        fixture
            .repo
            .prepared_finalization_marker()
            .unwrap_err()
            .code(),
        "EA-DRAFT-EVIDENCE-RESERVED"
    );
    fixture.set_state(false);
    assert_eq!(
        fixture
            .repo
            .prepared_finalization_marker()
            .unwrap()
            .unwrap()
            .as_bytes(),
        ORDINARY_MARKER
    );

    let start = Barrier::new(2);
    let stop = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(10);
    let (crossed, reads, writes) = thread::scope(|scope| {
        let writer = scope.spawn(|| {
            start.wait();
            let mut writes = 0;
            while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                fixture.set_state(writes % 2 == 0);
                writes += 1;
                thread::yield_now();
            }
            writes
        });
        start.wait();
        let mut crossed = false;
        let mut reads = 0;
        while reads < 5_000 && Instant::now() < deadline {
            match fixture.repo.prepared_finalization_marker() {
                Ok(Some(marker)) if marker.as_bytes() == ORDINARY_MARKER => {}
                Ok(Some(marker)) if marker.as_bytes() == EVIDENCE_MARKER => {
                    crossed = true;
                    break;
                }
                result => assert_eq!(result.unwrap_err().code(), "EA-DRAFT-EVIDENCE-RESERVED"),
            }
            reads += 1;
            thread::yield_now();
        }
        stop.store(true, Ordering::Release);
        (crossed, reads, writer.join().unwrap())
    });
    eprintln!(
        "snapshot probe: {reads} reads, {writes} committed state switches, crossed={crossed}"
    );
    assert!(
        reads > 0 && writes > 1,
        "both readers and writers must make progress"
    );
    assert!(
        !crossed,
        "ordinary facade returned the committed Evidence marker"
    );
}
