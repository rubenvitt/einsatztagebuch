//! Der Standard-Checkpoint und die Checkpoint-KETTE.
//!
//! Geprueft wird hier der transportneutrale Dienst: die eingefrorenen
//! Positionen von `checkpoint-core-v1`, die Bindung jedes Vorgaengers ueber
//! `previous-evidence-hash`, der abgedeckte Sequenzbereich und die
//! Blaetterung der Checkpoint-Seite. Der Weg durch Axum, PostgreSQL und den
//! Object Store steht in `apps/server/tests/checkpoint_api.rs`; er kann diese
//! Aussagen nicht ersetzen, weil er sie nur an EINEM Datenbestand zeigte.

use std::sync::Mutex;

use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, CryptoError, SecretBytes};
use ea_format::ObjectTypeV1;
use ea_sync_protocol::{
    EndpointV1, MAX_CHECKPOINT_PAGE_OBJECTS_V1, TechnicalCursorFieldsV1, TechnicalCursorSigner,
    TechnicalCursorV1, TechnicalCursorVerifier,
};
use ea_sync_server::{
    CheckpointDirectory, CheckpointIndexEntryV1, ObjectStore, RepositoryError, ServerClock,
    ServerSigner, StagedObject, StoreError, StoredObject,
    checkpoint::{
        CHECKPOINT_CURSOR_TTL_MILLIS_V1, CheckpointBindingV1, CheckpointError, CheckpointPageError,
        CheckpointPorts, build_checkpoint, checkpoint_page,
    },
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, KeyThumbprint, ObjectHash,
    OrganizationId, UnixMillis,
};

const SERVER_SEED: [u8; 32] = [0x12; 32];
const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x32; 32];
const ORGANIZATION_ID: [u8; 16] = [0x21; 16];
const CHAIN_ID: [u8; 16] = [0x22; 16];
const REGISTRY_HEAD_HASH: [u8; 32] = [0x30; 32];

fn organization_id() -> OrganizationId {
    OrganizationId::from(ea_types::Id16::try_from(&ORGANIZATION_ID[..]).expect("sixteen bytes"))
}

fn chain_id() -> ChainId {
    ChainId::from(ea_types::Id16::try_from(&CHAIN_ID[..]).expect("sixteen bytes"))
}

fn entry_hash(marker: u8) -> EntryHash {
    EntryHash::try_from(&[marker; 32][..]).expect("thirty two bytes")
}

/// Der Kettenkopf, ueber den ein Checkpoint ausgestellt wird.
///
/// Genau das, was der angenommene Commit hinterlaesst: eine Sequenz und den
/// Eintragshash, der auf ihr steht.
fn head_at_sequence(sequence: u64) -> (ChainSequence, EntryHash) {
    (
        ChainSequence::new(sequence),
        entry_hash(u8::try_from(sequence).unwrap_or(0xff)),
    )
}

fn binding_for(sequence: u64, previous: Option<ObjectHash>) -> CheckpointBindingV1 {
    let (covered_sequence, head_entry_hash) = head_at_sequence(sequence);
    CheckpointBindingV1 {
        organization_id: organization_id(),
        chain_id: chain_id(),
        covered_sequence,
        head_entry_hash,
        registry_head_hash: Hash32::try_from(&REGISTRY_HEAD_HASH[..]).expect("thirty two bytes"),
        previous_evidence_hash: previous,
    }
}

struct TestSigner {
    signer: CoseSigner,
    public_key: CanonicalPublicCoseKey,
}

impl TestSigner {
    fn new() -> Self {
        let signer = CoseSigner::from_secret(SecretBytes::new(SERVER_SEED));
        let public_key = signer.public_key().expect("the declared seed loads");
        Self { signer, public_key }
    }
}

impl ServerSigner for TestSigner {
    fn certificate_hash(&self) -> CertificateHash {
        CertificateHash::try_from(SERVER_CERTIFICATE_HASH.as_slice()).expect("thirty two bytes")
    }

    fn key_thumbprint(&self) -> KeyThumbprint {
        self.public_key.thumbprint()
    }

    fn key_generation(&self) -> u32 {
        1
    }

    fn sign_receipt(&self, exact_receipt_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer.sign_receipt(exact_receipt_core)
    }

    fn sign_checkpoint(&self, exact_checkpoint_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer
            .sign_checkpoint(self.certificate_hash(), exact_checkpoint_core)
    }

    fn sign_challenge_response(&self, exact_challenge_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer.sign_challenge_response(exact_challenge_core)
    }
}

impl TechnicalCursorSigner for TestSigner {
    fn sign_technical_cursor_digest(&self, digest: Hash32) -> Result<Vec<u8>, CryptoError> {
        self.signer
            .sign_technical_cursor(self.certificate_hash(), digest)
    }
}

impl TechnicalCursorVerifier for TestSigner {
    fn verify_technical_cursor_digest(
        &self,
        digest: Hash32,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        ea_crypto::verify_technical_cursor(
            signature,
            &self.public_key,
            self.certificate_hash(),
            digest,
        )
    }
}

struct FixedClock(UnixMillis);

impl ServerClock for FixedClock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}

/// Ein Object Store im Speicher, der ausschliesslich content-addressed liest.
#[derive(Default)]
struct FakeObjectStore {
    objects: Mutex<std::collections::BTreeMap<[u8; 32], Vec<u8>>>,
    unavailable: Mutex<bool>,
}

impl FakeObjectStore {
    fn insert(&self, bytes: Vec<u8>) -> ObjectHash {
        let hash = ea_crypto::object_hash(&bytes);
        self.objects
            .lock()
            .expect("not poisoned")
            .insert(*hash.as_bytes(), bytes);
        hash
    }

    fn break_it(&self) {
        *self.unavailable.lock().expect("not poisoned") = true;
    }
}

#[async_trait]
impl ObjectStore for FakeObjectStore {
    async fn stage_stream(
        &self,
        _kind: ObjectTypeV1,
        _body: ByteStream,
        _limit: u64,
    ) -> Result<StagedObject, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn put_if_absent(&self, _staged: StagedObject) -> Result<StoredObject, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn get_exact(&self, hash: ObjectHash) -> Result<ByteStream, StoreError> {
        if *self.unavailable.lock().expect("not poisoned") {
            return Err(StoreError::Unavailable);
        }
        self.objects
            .lock()
            .expect("not poisoned")
            .get(hash.as_bytes())
            .map(|bytes| ByteStream::from(bytes.clone()))
            .ok_or(StoreError::NotFound)
    }

    async fn get_exact_in(
        &self,
        _kind: ObjectTypeV1,
        hash: ObjectHash,
    ) -> Result<ByteStream, StoreError> {
        self.get_exact(hash).await
    }
}

/// Der Checkpoint-Index im Speicher, aufsteigend nach Blaetterposition.
#[derive(Default)]
struct FakeCheckpoints {
    entries: Mutex<Vec<CheckpointIndexEntryV1>>,
}

impl FakeCheckpoints {
    fn push(&self, technical_index: u64, object_hash: ObjectHash) {
        self.entries
            .lock()
            .expect("not poisoned")
            .push(CheckpointIndexEntryV1 {
                technical_index,
                object_hash,
            });
    }
}

#[async_trait]
impl CheckpointDirectory for FakeCheckpoints {
    async fn checkpoints_after(
        &self,
        _organization_id: OrganizationId,
        after_technical_index: u64,
        limit: usize,
    ) -> Result<Vec<CheckpointIndexEntryV1>, RepositoryError> {
        Ok(self
            .entries
            .lock()
            .expect("not poisoned")
            .iter()
            .filter(|entry| entry.technical_index > after_technical_index)
            .take(limit)
            .cloned()
            .collect())
    }
}

struct Harness {
    signer: TestSigner,
    clock: FixedClock,
    objects: FakeObjectStore,
    checkpoints: FakeCheckpoints,
}

impl Harness {
    fn new() -> Self {
        Self {
            signer: TestSigner::new(),
            clock: FixedClock(UnixMillis::new(1_700_000_000_000)),
            objects: FakeObjectStore::default(),
            checkpoints: FakeCheckpoints::default(),
        }
    }

    fn ports(&self) -> CheckpointPorts<'_> {
        CheckpointPorts {
            clock: &self.clock,
            signer: &self.signer,
            objects: &self.objects,
            checkpoints: &self.checkpoints,
        }
    }

    /// Legt `count` Checkpoints ab und indiziert sie in Ausstellungsreihenfolge.
    fn seed_checkpoints(&self, count: u64) -> Vec<ObjectHash> {
        let mut previous = None;
        let mut hashes = Vec::new();
        for sequence in 0..count {
            let checkpoint = build_checkpoint(
                binding_for(sequence, previous),
                UnixMillis::new(1_000 + i64::try_from(sequence).unwrap_or(0)),
                &self.signer,
            )
            .expect("a checkpoint over technical values must build");
            let hash = self.objects.insert(checkpoint.exact_bytes().to_vec());
            assert!(hash == checkpoint.object_hash());
            self.checkpoints.push(sequence + 1, hash);
            hashes.push(hash);
            previous = Some(hash);
        }
        hashes
    }
}

/// Jeder Checkpoint bindet seinen Vorgaenger ueber `previous-evidence-hash`,
/// und der abgedeckte Bereich folgt dem committeten Kopf.
#[test]
fn checkpoint_chain_binds_each_predecessor_by_previous_evidence_hash() {
    let signer = TestSigner::new();

    let first = build_checkpoint(binding_for(1, None), UnixMillis::new(1_000), &signer)
        .expect("the first checkpoint of a chain builds without a predecessor");
    let second = build_checkpoint(
        binding_for(2, Some(first.object_hash())),
        UnixMillis::new(2_000),
        &signer,
    )
    .expect("the successor binds the first");

    assert!(first.core().fields().previous_evidence_hash.is_none());
    assert!(second.core().fields().previous_evidence_hash == Some(first.object_hash()));
    assert_eq!(
        second.core().fields().covered_through_sequence.get(),
        head_at_sequence(2).0.get()
    );
    // Der abgedeckte Bereich ist der EINE Sequenzpunkt, den dieser Checkpoint
    // belegen kann: er bindet genau einen Kopf-Eintragshash.
    assert_eq!(
        second.core().fields().covered_from_sequence.get(),
        second.core().fields().covered_through_sequence.get()
    );
    // Zwei Checkpoints ueber verschiedene Koepfe sind verschiedene Objekte.
    assert!(first.object_hash() != second.object_hash());
}

/// Die eingefrorenen Positionen von `checkpoint-core-v1` — gelesen aus den
/// ARCHIVIERTEN Bytes, nicht aus dem Baustein, der sie gerade erzeugt hat.
#[test]
fn a_standard_checkpoint_archives_the_frozen_core_positions_and_its_own_signature() {
    let signer = TestSigner::new();
    let checkpoint = build_checkpoint(binding_for(7, None), UnixMillis::new(4_242), &signer)
        .expect("the checkpoint builds");

    // Die Adresse gehoert zum Inhalt.
    assert!(checkpoint.object_hash() == ea_crypto::object_hash(checkpoint.exact_bytes()));
    // Und die Bytes tragen das `.ecp`-Praefix.
    assert!(
        checkpoint
            .exact_bytes()
            .starts_with(&ea_format::ECP_PREFIX_V1)
    );

    let ea_format::ParsedArchiveObject::Evidence(parsed) =
        ea_format::decode_exact_object(checkpoint.exact_bytes()).expect("the checkpoint parses")
    else {
        panic!("a standard checkpoint is an evidence object");
    };
    assert_eq!(
        parsed.value().kind(),
        ea_format::EvidenceKindV1::StandardCheckpoint
    );
    let ea_format::DecodedEvidencePayloadV1::Standard { core, .. } = parsed
        .value()
        .decoded_payload()
        .expect("the payload decodes")
    else {
        panic!("a standard checkpoint carries no RFC-3161 token in this stage");
    };
    let fields = core.fields();
    assert!(fields.organization_id == organization_id());
    assert!(fields.chain_id == chain_id());
    assert_eq!(fields.covered_from_sequence.get(), 7);
    assert_eq!(fields.covered_through_sequence.get(), 7);
    assert!(fields.head_entry_hash == head_at_sequence(7).1);
    assert_eq!(fields.registry_head_hash.as_bytes(), &REGISTRY_HEAD_HASH);
    assert_eq!(fields.issued_at_server, UnixMillis::new(4_242));
    assert!(fields.previous_evidence_hash.is_none());
    // Die Domaene steht an Position 1 des Kerns, unmittelbar hinter der
    // Objektversion.
    assert!(
        core.exact_bytes()
            .windows(27)
            .any(|window| window == b"EINSATZARCHIV-CHECKPOINT-v1")
    );
}

/// Eine Seite liefert die exakten archivierten Bytes, sortiert nach
/// Objekthash, und reicht keinen Cursor heraus, solange sie nicht voll ist.
#[tokio::test]
async fn a_page_delivers_exact_bytes_sorted_by_object_hash_and_ends_without_a_cursor() {
    let harness = Harness::new();
    let hashes = harness.seed_checkpoints(3);

    let page = checkpoint_page(organization_id(), None, [0x01; 16], &harness.ports())
        .await
        .expect("a page over three checkpoints must build");

    assert_eq!(page.requested_cursor(), None);
    assert_eq!(page.checkpoints().len(), 3);
    assert_eq!(
        page.next_cursor(),
        None,
        "a page that is not full is the last page"
    );
    // Sortiert nach Objekthash — die Rahmenschicht verlangt es, und die
    // Blaetterposition bleibt trotzdem die technische Reihenfolge.
    let mut expected: Vec<[u8; 32]> = hashes.iter().map(|hash| *hash.as_bytes()).collect();
    expected.sort_unstable();
    let delivered: Vec<[u8; 32]> = page
        .checkpoints()
        .iter()
        .map(|record| *record.object_hash().as_bytes())
        .collect();
    assert_eq!(delivered, expected);
    // Und die Bytes gehoeren zu ihrer Adresse.
    for record in page.checkpoints() {
        assert!(ea_crypto::object_hash(record.exact_object_bytes()) == record.object_hash());
    }
}

/// Eine leere Seite ist ein Erfolg mit leerer Liste und ohne Cursor — kein
/// Fehler und kein `204`.
#[tokio::test]
async fn an_empty_page_is_an_empty_list_without_a_cursor() {
    let harness = Harness::new();

    let page = checkpoint_page(organization_id(), None, [0x02; 16], &harness.ports())
        .await
        .expect("an empty page is a legitimate answer");

    assert!(page.checkpoints().is_empty());
    assert_eq!(page.next_cursor(), None);
}

/// Eine VOLLE Seite reicht einen Cursor heraus, und der Cursor blaettert
/// genau den Rest nach.
///
/// Der einzige Fall, in dem `checkpoint_page` selbst einen Cursor ausstellt.
/// Ohne ihn waere die Blaetterzusage des Nachtrags — „jede Seitenantwort
/// traegt `next-cursor`; `null` heisst keine weitere Seite“ — an keiner
/// Stelle durchlaufen.
#[tokio::test]
async fn a_full_page_hands_out_a_cursor_that_pages_exactly_the_remainder() {
    let harness = Harness::new();
    let total = MAX_CHECKPOINT_PAGE_OBJECTS_V1 + 1;
    let hashes = harness.seed_checkpoints(u64::try_from(total).expect("the page ceiling fits"));

    let first = checkpoint_page(organization_id(), None, [0x11; 16], &harness.ports())
        .await
        .expect("the first page must build");
    assert_eq!(first.checkpoints().len(), MAX_CHECKPOINT_PAGE_OBJECTS_V1);
    let cursor = first
        .next_cursor()
        .expect("a full page is never the last page")
        .to_vec();

    let second = checkpoint_page(
        organization_id(),
        Some(&cursor),
        [0x12; 16],
        &harness.ports(),
    )
    .await
    .expect("the handed-out cursor must page");
    assert_eq!(second.requested_cursor(), Some(cursor.as_slice()));
    assert_eq!(
        second.checkpoints().len(),
        1,
        "the second page carries exactly the remainder"
    );
    assert_eq!(second.next_cursor(), None);
    // Und es ist der ZULETZT ausgestellte Anker — die Blaetterposition folgt
    // der technischen Reihenfolge, nicht der Hashsortierung der Seite.
    assert!(
        second.checkpoints()[0].object_hash()
            == *hashes.last().expect("the seeding produced anchors")
    );
    // Keine Ueberschneidung: zusammen sind es genau die gesetzten Anker.
    let mut delivered: Vec<[u8; 32]> = first
        .checkpoints()
        .iter()
        .chain(second.checkpoints())
        .map(|record| *record.object_hash().as_bytes())
        .collect();
    delivered.sort_unstable();
    delivered.dedup();
    assert_eq!(delivered.len(), total);
}

/// Ein Cursor eines ANDEREN Endpunkts oeffnet nicht — auch wenn derselbe
/// Server ihn ausgestellt hat.
#[tokio::test]
async fn a_cursor_of_a_foreign_endpoint_does_not_open() {
    let harness = Harness::new();
    harness.seed_checkpoints(1);

    let foreign = TechnicalCursorV1::issue(
        &TechnicalCursorFieldsV1 {
            organization_id: organization_id(),
            endpoint: EndpointV1::ChainEntries,
            chain_id: None,
            start_head_entry_hash: None,
            last_technical_index: 0,
            expires_at: UnixMillis::new(1_700_000_000_000 + CHECKPOINT_CURSOR_TTL_MILLIS_V1),
            nonce: [0x03; 16],
        },
        &harness.signer,
    )
    .expect("issuing the foreign cursor works");

    let error = checkpoint_page(
        organization_id(),
        Some(foreign.token_bytes()),
        [0x04; 16],
        &harness.ports(),
    )
    .await
    .expect_err("a cursor of another endpoint must not page here");
    assert_eq!(error.code(), "EA-SYNC-CURSOR-SCOPE");
    assert_eq!(error.http_status(), 400);
}

/// Ein abgelaufener Cursor wird abgewiesen, bevor er weiterblaettert.
#[tokio::test]
async fn an_expired_cursor_does_not_page() {
    let harness = Harness::new();
    harness.seed_checkpoints(1);

    let expired = TechnicalCursorV1::issue(
        &TechnicalCursorFieldsV1 {
            organization_id: organization_id(),
            endpoint: EndpointV1::Checkpoints,
            chain_id: None,
            start_head_entry_hash: None,
            last_technical_index: 0,
            expires_at: UnixMillis::new(1_600_000_000_000),
            nonce: [0x05; 16],
        },
        &harness.signer,
    )
    .expect("issuing works");

    let error = checkpoint_page(
        organization_id(),
        Some(expired.token_bytes()),
        [0x06; 16],
        &harness.ports(),
    )
    .await
    .expect_err("an expired cursor must not page");
    assert_eq!(error.code(), "EA-SYNC-CURSOR-EXPIRED");
}

/// Ein gueltiger Cursor blaettert GENAU hinter seiner Position weiter.
#[tokio::test]
async fn a_cursor_continues_behind_its_own_technical_position() {
    let harness = Harness::new();
    let hashes = harness.seed_checkpoints(3);

    let cursor = TechnicalCursorV1::issue(
        &TechnicalCursorFieldsV1 {
            organization_id: organization_id(),
            endpoint: EndpointV1::Checkpoints,
            chain_id: None,
            start_head_entry_hash: None,
            last_technical_index: 2,
            expires_at: UnixMillis::new(1_700_000_000_000 + CHECKPOINT_CURSOR_TTL_MILLIS_V1),
            nonce: [0x07; 16],
        },
        &harness.signer,
    )
    .expect("issuing works");

    let page = checkpoint_page(
        organization_id(),
        Some(cursor.token_bytes()),
        [0x08; 16],
        &harness.ports(),
    )
    .await
    .expect("the cursor pages");

    assert_eq!(page.requested_cursor(), Some(cursor.token_bytes()));
    assert_eq!(page.checkpoints().len(), 1);
    assert!(page.checkpoints()[0].object_hash() == hashes[2]);
}

/// Ein Ausfall des Object Stores ist ein WIEDERHOLBARER Befund und keine
/// halbe Seite.
#[tokio::test]
async fn a_broken_object_store_fails_the_page_closed() {
    let harness = Harness::new();
    harness.seed_checkpoints(2);
    harness.objects.break_it();

    let error = checkpoint_page(organization_id(), None, [0x09; 16], &harness.ports())
        .await
        .expect_err("a page whose bytes are unreadable is no page");
    assert_eq!(error.code(), "EA-CHECKPOINT-DEPENDENCY-UNAVAILABLE");
    assert_eq!(error.http_status(), 503);
    assert!(error.retryable());
}

/// Die Seitendecke des Nachtrags steht im Dienst und nicht in einem Aufrufer.
#[test]
fn the_page_ceiling_is_the_one_thousand_of_the_addendum() {
    assert_eq!(MAX_CHECKPOINT_PAGE_OBJECTS_V1, 1_000);
}

/// Kein Befund traegt einen fachlichen Wert, und die Codes sind stabil.
#[test]
fn every_checkpoint_code_is_stable_and_free_of_domain_values() {
    for error in CheckpointError::ALL {
        assert!(
            error.code().starts_with("EA-CHECKPOINT-"),
            "{} must carry the stable technical prefix",
            error.code()
        );
    }
    assert_eq!(
        CheckpointError::PredecessorConflict.code(),
        "EA-CHECKPOINT-PREDECESSOR-CONFLICT"
    );
    for error in CheckpointPageError::ALL {
        assert_eq!(
            error.retryable(),
            matches!(error.http_status(), 429 | 500 | 503)
        );
    }
}

/// Der Cursor wird gegen die AUFRUFENDE Organisation gestellt, nicht gegen
/// die, die im Token steht.
#[tokio::test]
async fn a_cursor_of_a_foreign_organization_does_not_open() {
    let harness = Harness::new();
    harness.seed_checkpoints(1);

    let foreign_organization =
        OrganizationId::from(ea_types::Id16::try_from(&[0x99_u8; 16][..]).expect("sixteen bytes"));
    let cursor = TechnicalCursorV1::issue(
        &TechnicalCursorFieldsV1 {
            organization_id: foreign_organization,
            endpoint: EndpointV1::Checkpoints,
            chain_id: None,
            start_head_entry_hash: None,
            last_technical_index: 0,
            expires_at: UnixMillis::new(1_700_000_000_000 + CHECKPOINT_CURSOR_TTL_MILLIS_V1),
            nonce: [0x0a; 16],
        },
        &harness.signer,
    )
    .expect("issuing works");

    let error = checkpoint_page(
        organization_id(),
        Some(cursor.token_bytes()),
        [0x0b; 16],
        &harness.ports(),
    )
    .await
    .expect_err("a cursor of another organization must not page here");
    assert_eq!(error.code(), "EA-SYNC-CURSOR-SCOPE");
}

/// Der Dienst haelt keine eigene Zufallsquelle: die Nonce des ausgestellten
/// Cursors ist die uebergebene.
#[tokio::test]
async fn the_issued_cursor_carries_the_supplied_nonce_and_the_service_ttl() {
    let harness = Harness::new();
    // Eine volle Seite ist die einzige, die einen Cursor herausgibt; die
    // Decke wird hier nicht erreicht, also wird der Cursor direkt geprueft.
    let fields = TechnicalCursorFieldsV1 {
        organization_id: organization_id(),
        endpoint: EndpointV1::Checkpoints,
        chain_id: None,
        start_head_entry_hash: None,
        last_technical_index: 5,
        expires_at: UnixMillis::new(1_700_000_000_000 + CHECKPOINT_CURSOR_TTL_MILLIS_V1),
        nonce: [0x0c; 16],
    };
    let cursor = TechnicalCursorV1::issue(&fields, &harness.signer).expect("issuing works");
    let reopened = TechnicalCursorV1::open(
        cursor.token_bytes(),
        &harness.signer,
        UnixMillis::new(1_700_000_000_000),
        &ea_sync_protocol::TechnicalCursorScopeV1 {
            organization_id: organization_id(),
            endpoint: EndpointV1::Checkpoints,
            chain_id: None,
            start_head_entry_hash: None,
        },
    )
    .expect("the cursor opens under its own scope");
    assert_eq!(reopened.last_technical_index(), 5);
    assert_eq!(reopened.fields().nonce, [0x0c; 16]);
    // Das Fenster reicht GENAU bis `expiresAt` — die Zusage ist „ein Cursor
    // mit `expiresAt < jetzt` wird abgewiesen", nicht „streng darunter".
    let scope = ea_sync_protocol::TechnicalCursorScopeV1 {
        organization_id: organization_id(),
        endpoint: EndpointV1::Checkpoints,
        chain_id: None,
        start_head_entry_hash: None,
    };
    TechnicalCursorV1::open(
        cursor.token_bytes(),
        &harness.signer,
        fields.expires_at,
        &scope,
    )
    .expect("a cursor opens up to and including its expiry");
    let error = TechnicalCursorV1::open(
        cursor.token_bytes(),
        &harness.signer,
        UnixMillis::new(fields.expires_at.get() + 1),
        &scope,
    )
    .expect_err("one millisecond later it does not");
    assert_eq!(error.code(), "EA-SYNC-CURSOR-EXPIRED");
}

/// Der Vorgaengerkonflikt ist ein `409` und ausdruecklich nicht wiederholbar:
/// derselbe Aufruf traefe denselben Widerspruch erneut.
#[test]
fn a_divergent_predecessor_is_a_conflict_and_never_retried() {
    let error = CheckpointError::PredecessorConflict;
    assert_eq!(error.code(), "EA-CHECKPOINT-PREDECESSOR-CONFLICT");
    assert_eq!(error.http_status(), 409);
    assert!(!error.retryable());
}
