//! Zeremonie A nativ hinter der Sperre (Profil §5, DRK-458).
//!
//! Der produktive Cutover-Port scheitert vor jeder Nebenwirkung. Hinter dem
//! Fixture-Port (nur `test-support`) laufen Freigabe, Root-Signatur und der
//! atomare Commit gegen echtes SQLCipher und eine echte Trust-Linie; die
//! publizierten Bytes bestehen danach den Trust-Kern und öffnen Ende zu Ende
//! über Zeremonie B.
#[path = "../../ea-audit/tests/support/mod.rs"]
mod audit_support;
#[path = "../../ea-trust/tests/escrow_support/mod.rs"]
mod escrow_support;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;
// Die Audit-Fixture nennt die Trust-Fixture `trust_support`; es ist dieselbe.
use support as trust_support;

use std::{
    cell::Cell,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use ea_admin::{
    reader_key_escrow_opening::ReaderKeyEscrowLedger,
    reader_key_escrow_publication::{
        CutoverPending, FixtureBundleRelease, PublishedReaderKeyEscrow,
        ReaderKeyEscrowPublicationContext, publish_reader_key_escrow_in_context,
    },
};
use ea_audit::{LocalAuditRepository, SignedLocalAuditService, SqliteLocalAuditRepository};
use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, HpkeRecipientPrivateKey, HpkeSealed, ProtectedHeader,
    SecretBytes, hpke_aad, hpke_info, hpke_open,
};
use ea_format::{
    KeyProtectionProfileV1, LocalAuditActionV1, LocalAuditOutcomeV1, ReaderKeyEscrowCoreV1,
    decode_local_audit_event, encode_reader_key_escrow_package,
};
use ea_key_provider::{InMemoryKeyProvider, KeyHandle, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_operator::OperatorSessionProof;
use ea_recovery::{ReaderKeyEscrowError, ReaderKeyEscrowOpeningService};
use ea_trust::{
    ReaderKeyEscrowHead, ReaderKeyEscrowStanding, SelectedRegistryHead, TrustError, VerifiedTrust,
    verify_reader_key_escrow_recovery_authorization, verify_reader_key_escrows,
};
use ea_types::{CertificateHash, Hash32, ObjectHash, UnixMillis};
use ed25519_dalek::{Signer as _, SigningKey};
use escrow_support::{
    Basis, EscrowLine, EscrowLineOptions, READER_KEM_SEED, RECOVERY_KEM_SEED,
    SECOND_READER_KEM_SEED, TRANSPORT_KEM_SEED, certificate_of, escrow_core, escrow_line,
    push_reader, push_revocation, recovery_core, select, signed_recovery, subject, tip_sequence,
    x25519_public,
};

/// Das wurzelsignierte `issued-at` jedes Pakets dieser Zeugen.
const ISSUED: u64 = 1_000;
const NOW: i64 = 1_100;
const WINDOW: i64 = 300_000;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// Eine COSE_Sign1 im Normalprofil über einen Trust-Digest — derselbe Aufbau,
/// den `KeyProvider::sign` des Autoritätswirts liefert.
fn trust_digest_cose(seed: [u8; 32], certificate: CertificateHash, digest: Hash32) -> Vec<u8> {
    let key = SigningKey::from_bytes(&seed);
    let public = CanonicalPublicCoseKey::ed25519(key.verifying_key().to_bytes()).unwrap();
    let protected =
        ProtectedHeader::normal(ContentType::TrustDigest, public.thumbprint(), certificate);
    let signature = key.sign(&protected.sig_structure_bytes(digest.as_bytes()));
    let mut bytes = vec![0xd2, 0x84];
    let mut encoder = minicbor::Encoder::new(&mut bytes);
    encoder.bytes(&protected.to_deterministic_cbor()).unwrap();
    encoder.map(0).unwrap();
    encoder.bytes(digest.as_bytes()).unwrap();
    encoder.bytes(&signature.to_bytes()).unwrap();
    bytes
}

struct Store {
    root: PathBuf,
    provider: Arc<InMemoryKeyProvider>,
    database_key: KeyHandle,
    signing: KeyHandle,
    proof: OperatorSessionProof,
}

impl Store {
    fn new(name: &str) -> Self {
        let proof = audit_support::AuditHarness::new().operator_session();
        let root = std::env::temp_dir().join(format!(
            "ea-escrow-publication-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let provider = Arc::new(InMemoryKeyProvider::new_for_test([0x4d; 32]));
        let database_key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let signing = provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        Self {
            root,
            provider,
            database_key,
            signing,
            proof,
        }
    }

    fn open(&self) -> Arc<EncryptedDatabase> {
        Arc::new(
            EncryptedDatabase::open(
                &self.root.join("operator.sqlite"),
                self.provider.as_ref(),
                &self.database_key,
            )
            .unwrap(),
        )
    }

    fn audit(&self, database: &Arc<EncryptedDatabase>) -> SignedLocalAuditService {
        SignedLocalAuditService::new(
            Arc::new(SqliteLocalAuditRepository::new(Arc::clone(database)))
                as Arc<dyn LocalAuditRepository>,
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            self.signing,
            ObjectHash::try_from([0x33; 32].as_slice()).unwrap(),
            UnixMillis::new(NOW),
        )
    }
}

/// Der Zeremonienkontext, einmal je Lauf: Admin- und Root-Signierer zählen
/// ihre Aufrufe, `authorization-id` und `nonce` sind fest oder frisch.
struct Ceremony<'a> {
    database: &'a EncryptedDatabase,
    audit: &'a SignedLocalAuditService,
    proof: &'a OperatorSessionProof,
    trust: VerifiedTrust,
    head: SelectedRegistryHead,
    admin_certificate: CertificateHash,
    admin_binding: ObjectHash,
    signatures: AtomicUsize,
    now: i64,
    ids: Option<([u8; 16], [u8; 32])>,
    /// Läuft einmal in der Sitzungsprüfung vor dem Commit — also zwischen
    /// Vorprüfung und Transaktion: der Platz eines nebenläufigen Prozesses.
    interleave: Cell<Option<Box<dyn FnOnce() + 'a>>>,
}

impl<'a> Ceremony<'a> {
    fn new(
        line: &EscrowLine,
        database: &'a EncryptedDatabase,
        audit: &'a SignedLocalAuditService,
        proof: &'a OperatorSessionProof,
    ) -> Self {
        let (trust, head) = select(&line.line, tip_sequence(&line.line));
        Self {
            database,
            audit,
            proof,
            trust,
            head,
            admin_certificate: certificate_of(line.line.second_bootstrap_admin_hash()),
            admin_binding: line.line.second_bootstrap_admin_binding_hash(),
            signatures: AtomicUsize::new(0),
            now: NOW,
            ids: None,
            interleave: Cell::new(None),
        }
    }

    fn publish(
        &self,
        cutover: &dyn ea_admin::reader_key_escrow_publication::ReaderKeyEscrowCutover,
        exact_package: &[u8],
    ) -> Result<PublishedReaderKeyEscrow, ReaderKeyEscrowError> {
        let admin_sign = |certificate, digest| {
            self.signatures.fetch_add(1, Ordering::SeqCst);
            Ok(trust_digest_cose(
                support::second_admin_signing_secret(),
                certificate,
                digest,
            ))
        };
        let root_sign = |certificate, digest| {
            self.signatures.fetch_add(1, Ordering::SeqCst);
            Ok(trust_digest_cose(
                support::root_signing_secret(),
                certificate,
                digest,
            ))
        };
        let session = || {
            if let Some(racing) = self.interleave.take() {
                racing();
            }
            Ok(())
        };
        // Ohne feste Werte: eindeutig je Paket, abgeleitet aus seinem Hash.
        let ids = || {
            Ok(self.ids.unwrap_or_else(|| {
                let hash = *ea_crypto::object_hash(exact_package).as_bytes();
                let mut id = [0; 16];
                id.copy_from_slice(&hash[..16]);
                (id, hash)
            }))
        };
        publish_reader_key_escrow_in_context(
            cutover,
            &ReaderKeyEscrowPublicationContext {
                database: self.database,
                trust: &self.trust,
                head: &self.head,
                audit: self.audit,
                proof: self.proof,
                admin_certificate: self.admin_certificate,
                admin_binding: self.admin_binding,
                admin_sign: &admin_sign,
                root_sign: &root_sign,
                now: UnixMillis::new(self.now),
                session_current: &session,
                fresh_approval_ids: &ids,
            },
            exact_package,
        )
    }
}

fn bundle_release() -> ObjectHash {
    ObjectHash::try_from([0x7b; 32].as_slice()).unwrap()
}

fn package(
    line: &EscrowLine,
    enrollment: &escrow_support::Enrollment,
    seed: [u8; 32],
    person: u8,
    issued: u64,
) -> (ReaderKeyEscrowCoreV1, Vec<u8>) {
    let core = escrow_core(line, enrollment, seed, subject(person), issued);
    let bytes = encode_reader_key_escrow_package(&core).unwrap();
    (core, bytes)
}

fn count(database: &EncryptedDatabase, table: &str) -> i64 {
    database
        .query_row(&format!("SELECT count(*) FROM {table}"), &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}

/// Die Publikationszeilen des Audits (Aktion 13) als (Escrow, Freigabe,
/// Bundle-Release, Ausgang).
fn publication_rows(
    database: &EncryptedDatabase,
) -> Vec<(
    ObjectHash,
    ObjectHash,
    Option<ObjectHash>,
    LocalAuditOutcomeV1,
)> {
    let mut rows = Vec::new();
    let mut after = 0_i64;
    while let Some(row) = database
        .query_row(
            "SELECT insertion_sequence,exact_bytes FROM local_audit_event WHERE insertion_sequence>?1 ORDER BY insertion_sequence LIMIT 1",
            &[StoreValue::Integer(after)],
        )
        .unwrap()
    {
        after = row.integer(0).unwrap();
        let event = decode_local_audit_event(row.blob(1).unwrap()).unwrap();
        if let LocalAuditActionV1::ReaderKeyEscrowPublication(context) = event.action() {
            assert!(context.target_transport_key_thumbprint().is_none());
            rows.push((
                context.escrow_object_hash(),
                context.authorization_object_hash(),
                context.bundle_release_object_hash(),
                event.outcome(),
            ));
        }
    }
    rows
}

// ---------------------------------------------------------------------------
// Die Sperre
// ---------------------------------------------------------------------------

/// Pflicht bis (f): der produktive Port scheitert als ERSTER Schritt — kein
/// Signierer, keine Sperrzeile, keine Publikationszeile, keine Auditzeile.
#[test]
fn the_productive_cutover_port_refuses_before_any_side_effect() {
    let line = escrow_line(EscrowLineOptions::default());
    let store = Store::new("locked");
    let database = store.open();
    let audit = store.audit(&database);
    let ceremony = Ceremony::new(&line, &database, &audit, &store.proof);
    let (_, bytes) = package(&line, &line.reader, READER_KEM_SEED, 0xc1, ISSUED);
    let error = ceremony.publish(&CutoverPending, &bytes).err().unwrap();
    assert_eq!(error, ReaderKeyEscrowError::CutoverNotReady);
    assert_eq!(error.code(), "EA-ESCROW-CUTOVER-NOT-READY");
    assert_eq!(error.exit_code(), ea_recovery::ExitCode::Unsupported);
    assert_eq!(error.exit_code().as_i32(), 21);
    // Selbst ein unlesbares Paket kommt nicht bis zur Prüfung.
    assert_eq!(
        ceremony.publish(&CutoverPending, b"not a package").err(),
        Some(ReaderKeyEscrowError::CutoverNotReady)
    );
    assert_eq!(ceremony.signatures.load(Ordering::SeqCst), 0);
    for table in [
        "operator_admin_replay",
        "reader_key_escrow_publication",
        "local_audit_event",
    ] {
        assert_eq!(count(&database, table), 0, "{table}");
    }
}

// ---------------------------------------------------------------------------
// Hinter dem Fixture-Port
// ---------------------------------------------------------------------------

/// Die publizierten Bytes bestehen den Trust-Kern, das Audit trägt den
/// Bundle-Release-Hash und keinen Abdruck, und das Escrow öffnet Ende zu Ende
/// über Zeremonie B zum Reader-KEM.
#[test]
fn a_published_escrow_passes_the_trust_core_and_opens_end_to_end() {
    let mut line = escrow_line(EscrowLineOptions::default());
    let store = Store::new("publish");
    let database = store.open();
    let audit = store.audit(&database);
    let (core, bytes) = package(&line, &line.reader, READER_KEM_SEED, 0xc1, ISSUED);
    let published = {
        let ceremony = Ceremony::new(&line, &database, &audit, &store.proof);
        let published = ceremony
            .publish(&FixtureBundleRelease(bundle_release()), &bytes)
            .unwrap();
        assert_eq!(ceremony.signatures.load(Ordering::SeqCst), 2);
        published
    };
    assert!(!published.replayed);
    assert!(published.escrow_object_hash == ea_crypto::object_hash(&published.exact_escrow));
    assert!(published.approval_object_hash == ea_crypto::object_hash(&published.exact_approval));
    assert_eq!(
        publication_rows(&database)
            .into_iter()
            .map(|(escrow, approval, bundle, outcome)| (
                escrow == published.escrow_object_hash,
                approval == published.approval_object_hash,
                bundle == Some(bundle_release()),
                outcome
            ))
            .collect::<Vec<_>>(),
        [(true, true, true, LocalAuditOutcomeV1::Completed)]
    );
    assert_eq!(count(&database, "operator_admin_replay"), 2);
    assert_eq!(count(&database, "reader_key_escrow_publication"), 1);

    // Der Test legt die Bytes in den Katalog; der Trust-Kern nimmt sie an.
    line.line.add_object(published.exact_approval.clone());
    line.line.add_object(published.exact_escrow.clone());
    let (trust, head) = select(&line.line, tip_sequence(&line.line));
    let escrows = verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::Selected(&head)).unwrap();
    let verified = escrows.get(published.escrow_object_hash).unwrap();
    assert_eq!(verified.standing(), ReaderKeyEscrowStanding::Valid);
    assert!(*verified.core() == core);

    // Zeremonie B über dieselbe Linie.
    let fields = recovery_core(
        published.escrow_object_hash,
        &core,
        Basis::of_selected(&head),
        (2_000, 2_900),
        0xf1,
    );
    let authorization = verify_reader_key_escrow_recovery_authorization(
        &trust,
        &head,
        &signed_recovery(&fields, &line.approvers),
        UnixMillis::new(2_100),
    )
    .unwrap();
    let transport = authorization
        .require_target_transport_key(x25519_public(TRANSPORT_KEM_SEED))
        .unwrap();
    let ledger = ReaderKeyEscrowLedger::new(&database, &audit, &store.proof);
    let recovery =
        HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(RECOVERY_KEM_SEED)).unwrap();
    let session = || Ok(());
    let envelope = ReaderKeyEscrowOpeningService::new(&recovery, &ledger, &session)
        .open(&authorization, &transport)
        .unwrap();
    let context = envelope.restore_context.encode();
    let restored = hpke_open(
        &HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(TRANSPORT_KEM_SEED)).unwrap(),
        &HpkeSealed::from_parts(envelope.encapsulated_key, envelope.sealed_reader_kem_key).unwrap(),
        &hpke_info(&context),
        &hpke_aad(&context),
    )
    .unwrap();
    assert!(restored.matches(&READER_KEM_SEED));
}

/// Profil §5: ein exakter Wiedereinspielversuch liefert dieselben Bytes,
/// ohne Verbrauch und ohne zweite Auditzeile.
#[test]
fn replaying_the_same_package_returns_the_same_bytes_once_audited() {
    let line = escrow_line(EscrowLineOptions::default());
    let store = Store::new("replay");
    let database = store.open();
    let audit = store.audit(&database);
    let ceremony = Ceremony::new(&line, &database, &audit, &store.proof);
    let (_, bytes) = package(&line, &line.reader, READER_KEM_SEED, 0xc1, ISSUED);
    let first = ceremony
        .publish(&FixtureBundleRelease(bundle_release()), &bytes)
        .unwrap();
    let again = ceremony
        .publish(&FixtureBundleRelease(bundle_release()), &bytes)
        .unwrap();
    assert!(again.replayed);
    assert_eq!(again.exact_approval, first.exact_approval);
    assert_eq!(again.exact_escrow, first.exact_escrow);
    assert_eq!(ceremony.signatures.load(Ordering::SeqCst), 2);
    assert_eq!(publication_rows(&database).len(), 1);
    assert_eq!(count(&database, "operator_admin_replay"), 2);
}

/// Lokale Eindeutigkeit vor (f): dasselbe Reader-Zertifikat mit einem anderen
/// Core scheitert, ebenso dieselbe Person unter einem zweiten, noch aktiven
/// Zertifikat — nach dem Widerruf des alten gelingt der Ersatz.
#[test]
fn a_second_escrow_for_the_same_certificate_or_person_conflicts_until_revocation() {
    let mut line = escrow_line(EscrowLineOptions::default());
    let store = Store::new("conflict");
    let database = store.open();
    let audit = store.audit(&database);
    let (_, first) = package(&line, &line.reader, READER_KEM_SEED, 0xc1, ISSUED);
    Ceremony::new(&line, &database, &audit, &store.proof)
        .publish(&FixtureBundleRelease(bundle_release()), &first)
        .unwrap();

    // Gleiches Zertifikat, anderer Core.
    let (_, other_core) = package(&line, &line.reader, READER_KEM_SEED, 0xc1, ISSUED + 1);
    let error = Ceremony::new(&line, &database, &audit, &store.proof)
        .publish(&FixtureBundleRelease(bundle_release()), &other_core)
        .err()
        .unwrap();
    assert_eq!(error, ReaderKeyEscrowError::PublicationConflict);
    assert_eq!(error.code(), "EA-ESCROW-PUBLICATION-CONFLICT");

    // Dieselbe Person unter einem zweiten, AKTIVEN Zertifikat.
    let second = push_reader(&mut line.line, 0x82, SECOND_READER_KEM_SEED);
    let (_, same_person) = package(&line, &second, SECOND_READER_KEM_SEED, 0xc1, ISSUED);
    assert_eq!(
        Ceremony::new(&line, &database, &audit, &store.proof)
            .publish(&FixtureBundleRelease(bundle_release()), &same_person)
            .err(),
        Some(ReaderKeyEscrowError::PublicationConflict)
    );

    // Nach dem Widerruf des alten Zertifikats gelingt der Ersatz.
    push_revocation(&mut line.line, line.reader.certificate);
    let replacement = Ceremony::new(&line, &database, &audit, &store.proof)
        .publish(&FixtureBundleRelease(bundle_release()), &same_person)
        .unwrap();
    assert!(!replacement.replayed);
    assert_eq!(count(&database, "reader_key_escrow_publication"), 2);
    assert_eq!(publication_rows(&database).len(), 2);
}

/// Ruling Q2: das Paket muss innerhalb von 300 s verarbeitet werden; ein
/// `issued-at` in der Zukunft ist ebenso veraltet.
#[test]
fn a_package_is_fresh_for_exactly_three_hundred_seconds() {
    let line = escrow_line(EscrowLineOptions::default());
    let (_, bytes) = package(&line, &line.reader, READER_KEM_SEED, 0xc1, ISSUED);
    for (offset, accepted) in [(WINDOW + 1, false), (-1, false), (WINDOW, true)] {
        let store = Store::new("fresh");
        let database = store.open();
        let audit = store.audit(&database);
        let mut ceremony = Ceremony::new(&line, &database, &audit, &store.proof);
        ceremony.now = i64::try_from(ISSUED).unwrap() + offset;
        let result = ceremony.publish(&FixtureBundleRelease(bundle_release()), &bytes);
        if accepted {
            assert!(result.is_ok(), "{offset}");
        } else {
            let error = result.err().unwrap();
            assert_eq!(error, ReaderKeyEscrowError::PackageStale, "{offset}");
            assert_eq!(error.code(), "EA-ESCROW-PACKAGE-STALE");
            assert_eq!(ceremony.signatures.load(Ordering::SeqCst), 0);
            assert_eq!(count(&database, "local_audit_event"), 0);
        }
    }
}

/// Die Freigabe teilt den Namensraum der Sperrzeilen: ein zweiter Commit mit
/// derselben `authorization-id` und `nonce` scheitert am Wiedereinspiel und
/// hinterlässt nichts.
#[test]
fn a_second_commit_with_the_same_approval_identity_is_a_replay() {
    let mut line = escrow_line(EscrowLineOptions::default());
    let second = push_reader(&mut line.line, 0x82, SECOND_READER_KEM_SEED);
    let store = Store::new("approval-replay");
    let database = store.open();
    let audit = store.audit(&database);
    let mut ceremony = Ceremony::new(&line, &database, &audit, &store.proof);
    ceremony.ids = Some(([0x5a; 16], [0x5b; 32]));
    let (_, first) = package(&line, &line.reader, READER_KEM_SEED, 0xc1, ISSUED);
    ceremony
        .publish(&FixtureBundleRelease(bundle_release()), &first)
        .unwrap();
    let (_, other) = package(&line, &second, SECOND_READER_KEM_SEED, 0xc2, ISSUED);
    assert_eq!(
        ceremony
            .publish(&FixtureBundleRelease(bundle_release()), &other)
            .err(),
        Some(ReaderKeyEscrowError::Trust(TrustError::AuthReplay))
    );
    assert_eq!(count(&database, "reader_key_escrow_publication"), 1);
    assert_eq!(publication_rows(&database).len(), 1);
    assert_eq!(count(&database, "operator_admin_replay"), 2);
}

/// Nebenläufige Publikation (review-c P3-2): zwei Pakete zum selben
/// Reader-Zertifikat bestehen beide die Vorprüfung; der zweite Prozess
/// committet zwischen Vorprüfung und Transaktion des ersten. Genau eine
/// Publikation entsteht, die andere scheitert mit `PUBLICATION-CONFLICT` und
/// hinterlässt keine Sperr-, Publikations- oder Auditzeile.
#[test]
fn concurrent_publications_for_one_certificate_commit_exactly_once() {
    let line = escrow_line(EscrowLineOptions::default());
    let store = Store::new("concurrent-certificate");
    let database = store.open();
    let other = store.open();
    let audit = store.audit(&database);
    let other_audit = store.audit(&other);
    let (_, first) = package(&line, &line.reader, READER_KEM_SEED, 0xc1, ISSUED);
    let (_, second) = package(&line, &line.reader, READER_KEM_SEED, 0xc1, ISSUED + 1);
    assert_ne!(first, second);
    let racing = Ceremony::new(&line, &other, &other_audit, &store.proof);
    let raced = Cell::new(None);
    let ceremony = Ceremony::new(&line, &database, &audit, &store.proof);
    ceremony.interleave.set(Some(Box::new(|| {
        raced.set(Some(
            racing
                .publish(&FixtureBundleRelease(bundle_release()), &second)
                .map(|published| published.replayed),
        ));
    })));
    let error = ceremony
        .publish(&FixtureBundleRelease(bundle_release()), &first)
        .err()
        .expect("the slower publication must conflict");
    assert_eq!(error, ReaderKeyEscrowError::PublicationConflict);
    assert_eq!(error.code(), "EA-ESCROW-PUBLICATION-CONFLICT");
    assert_eq!(raced.take(), Some(Ok(false)));
    assert_eq!(count(&database, "reader_key_escrow_publication"), 1);
    assert_eq!(publication_rows(&database).len(), 1);
    assert_eq!(count(&database, "operator_admin_replay"), 2);
}

/// Nebenläufige Publikation zur selben Person unter zwei aktiven
/// Zertifikaten: genau eine; die Personenprüfung läuft in der Transaktion
/// des Commits noch einmal.
#[test]
fn concurrent_publications_for_one_person_commit_exactly_once() {
    let mut line = escrow_line(EscrowLineOptions::default());
    let second_reader = push_reader(&mut line.line, 0x82, SECOND_READER_KEM_SEED);
    let store = Store::new("concurrent-person");
    let database = store.open();
    let other = store.open();
    let audit = store.audit(&database);
    let other_audit = store.audit(&other);
    let (_, first) = package(&line, &line.reader, READER_KEM_SEED, 0xc1, ISSUED);
    let (_, second) = package(&line, &second_reader, SECOND_READER_KEM_SEED, 0xc1, ISSUED);
    let racing = Ceremony::new(&line, &other, &other_audit, &store.proof);
    let raced = Cell::new(None);
    let ceremony = Ceremony::new(&line, &database, &audit, &store.proof);
    ceremony.interleave.set(Some(Box::new(|| {
        raced.set(Some(
            racing
                .publish(&FixtureBundleRelease(bundle_release()), &second)
                .map(|published| published.replayed),
        ));
    })));
    let error = ceremony
        .publish(&FixtureBundleRelease(bundle_release()), &first)
        .err()
        .expect("the slower publication must conflict");
    assert_eq!(error, ReaderKeyEscrowError::PublicationConflict);
    assert_eq!(raced.take(), Some(Ok(false)));
    assert_eq!(count(&database, "reader_key_escrow_publication"), 1);
    assert_eq!(publication_rows(&database).len(), 1);
    assert_eq!(count(&database, "operator_admin_replay"), 2);
}
