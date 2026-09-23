//! Zeremonie B nativ gegen echtes SQLCipher (Profil §6 und §8, DRK-458).
//!
//! Die Zeugen laufen gegen das Ledger der nativen Administration, eine echte
//! verschlüsselte Datenbank, den signierenden Auditdienst und eine voll
//! geprüfte Öffnungsautorisierung aus der Trust-Linie. Die Laufzeitkomposition
//! (Reauthentifizierung, abgelaufene Sitzung VOR dem Verbrauch, PKCS#11) liegt
//! bei den CLI-Zeugen.
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
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use ea_admin::{
    reader_key_escrow_inbox::{read_escrow_inbox, read_transport_key, write_escrow_outbox},
    reader_key_escrow_opening::{READER_KEY_ESCROW_RESULT_RETENTION_MS, ReaderKeyEscrowLedger},
};
use ea_audit::{LocalAuditRepository, SignedLocalAuditService, SqliteLocalAuditRepository};
use ea_crypto::{CryptoError, HpkeRecipientPrivateKey, SecretBytes};
use ea_format::{
    KeyProtectionProfileV1, LocalAuditActionV1, LocalAuditOutcomeV1, ReaderKeyEscrowTransferKindV1,
    ReaderKeyEscrowTransportRequestV1, decode_local_audit_event,
    encode_reader_key_escrow_transport_request, reader_key_escrow_transfer_file_name,
};
use ea_key_provider::{InMemoryKeyProvider, KeyHandle, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_operator::OperatorSessionProof;
use ea_recovery::{
    ConsumedEscrowOpening, EscrowOpeningLedger, ReaderKeyEscrowError, ReaderKeyEscrowKem,
    ReaderKeyEscrowOpeningService,
};
use ea_trust::{
    AuthorizedEscrowTransportKey, TrustError, VerifiedReaderKeyEscrowRecoveryAuthorization,
    verify_reader_key_escrow_recovery_authorization,
};
use ea_types::{KeyThumbprint, ObjectHash, UnixMillis};
use escrow_support::{
    Basis, EscrowLineOptions, READER_KEM_SEED, RECOVERY_KEM_SEED, TRANSPORT_KEM_SEED,
    approval_core, escrow_core, escrow_line, publish_escrow, recovery_core, select,
    signed_recovery, subject, tip_sequence, x25519_public,
};

const NOW: i64 = 2_100;
const STORED_AT: i64 = 1_700_000_000_000;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// Eine Linie mit gültigem Escrow und die Bausteine frischer
/// Öffnungsautorisierungen dagegen.
struct Line {
    escrow: escrow_support::EscrowLine,
    core: ea_format::ReaderKeyEscrowCoreV1,
    escrow_hash: ObjectHash,
}

fn line() -> Line {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = escrow_core(
        &escrow,
        &escrow.reader,
        READER_KEM_SEED,
        subject(0xc1),
        1_200,
    );
    let tip = *escrow.line.heads().last().unwrap();
    let approval = approval_core(
        &escrow.line,
        Basis::of(&tip, tip.effective_from.get()),
        (1_000, 1_300),
        0xe1,
    );
    let (_, escrow_hash) = publish_escrow(&mut escrow, &core, &approval);
    Line {
        escrow,
        core,
        escrow_hash,
    }
}

struct Opening {
    authorization: VerifiedReaderKeyEscrowRecoveryAuthorization,
    transport: AuthorizedEscrowTransportKey,
}

impl Line {
    /// Eine voll geprüfte Autorisierung; `change` darf die Felder vor der
    /// Signatur ändern (etwa dieselbe Nonce unter anderer ID).
    fn opening(
        &self,
        id: u8,
        change: impl FnOnce(&mut ea_format::ReaderKeyEscrowRecoveryAuthorizationCoreV1),
    ) -> Opening {
        let (trust, head) = select(&self.escrow.line, tip_sequence(&self.escrow.line));
        let mut fields = recovery_core(
            self.escrow_hash,
            &self.core,
            Basis::of_selected(&head),
            (2_000, 2_900),
            id,
        );
        change(&mut fields);
        let bytes = signed_recovery(&fields, &self.escrow.approvers);
        let authorization =
            verify_reader_key_escrow_recovery_authorization(&trust, &head, &bytes, millis(NOW))
                .unwrap();
        let transport = authorization
            .require_target_transport_key(x25519_public(TRANSPORT_KEM_SEED))
            .unwrap();
        Opening {
            authorization,
            transport,
        }
    }
}

fn millis(value: i64) -> UnixMillis {
    UnixMillis::new(value)
}

/// Eine echte verschlüsselte Datenbank, die sich beliebig oft neu öffnen
/// lässt, ein signierender Auditdienst je Griff und ein echter
/// Präsenznachweis.
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
            "ea-escrow-opening-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let provider = Arc::new(InMemoryKeyProvider::new_for_test([0x3c; 32]));
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

    /// Ein NEUER Griff auf dieselbe Datei — ein Neustart oder eine zweite
    /// Laufzeit.
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
            millis(NOW),
        )
    }

    fn directory(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::create_dir_all(&path).unwrap();
        path
    }
}

fn count(database: &EncryptedDatabase, table: &str) -> i64 {
    database
        .query_row(&format!("SELECT count(*) FROM {table}"), &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}

/// Die Escrow-Auditzeilen (Aktion 14) mit ihrem Ausgang, in Buchungsfolge.
fn opening_rows(database: &EncryptedDatabase) -> Vec<LocalAuditOutcomeV1> {
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
        if let LocalAuditActionV1::ReaderKeyEscrowOpening(context) = event.action() {
            // Nur Hashes: der Abdruck steht, der Bundle-Hash nie.
            assert!(context.target_transport_key_thumbprint().is_some());
            assert!(context.bundle_release_object_hash().is_none());
            rows.push(event.outcome());
        }
    }
    rows
}

fn stored_envelope(database: &EncryptedDatabase) -> Option<Vec<u8>> {
    database
        .query_row("SELECT exact_envelope FROM reader_key_escrow_result", &[])
        .unwrap()
        .map(|row| row.blob(0).unwrap().to_vec())
}

fn recovery_key() -> HpkeRecipientPrivateKey {
    HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(RECOVERY_KEM_SEED)).unwrap()
}

/// Ein Recovery-Schlüssel, der seine privaten Operationen zählt und auf
/// Wunsch mitten in der Zeremonie „abstürzt".
struct CountingKem<'a> {
    calls: &'a AtomicUsize,
    crash: bool,
}
impl ReaderKeyEscrowKem for CountingKem<'_> {
    fn key_thumbprint(&self) -> Result<KeyThumbprint, CryptoError> {
        recovery_key().key_thumbprint()
    }
    fn open_reader_key_escrow(
        &self,
        opening: &ConsumedEscrowOpening<'_>,
    ) -> Result<SecretBytes<32>, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.crash,
            "simulated crash after the committed consumption"
        );
        recovery_key().open_reader_key_escrow(opening)
    }
}

fn open_with(
    ledger: &dyn EscrowOpeningLedger,
    kem: &dyn ReaderKeyEscrowKem,
    opening: &Opening,
) -> Result<ea_format::ReaderKeyEscrowEnvelopeV1, ReaderKeyEscrowError> {
    let session = || Ok(());
    ReaderKeyEscrowOpeningService::new(kem, ledger, &session)
        .open(&opening.authorization, &opening.transport)
}

// ---------------------------------------------------------------------------
// Pflichtzeuge: Absturz nach dem Verbrauch, vor dem Ergebnis
// ---------------------------------------------------------------------------

#[test]
fn a_crash_after_consumption_before_the_result_burns_the_authorization() {
    let line = line();
    let store = Store::new("crash");
    let database = store.open();
    let audit = store.audit(&database);
    let ledger = ReaderKeyEscrowLedger::new(&database, &audit, &store.proof);
    let calls = AtomicUsize::new(0);
    let opening = line.opening(0xf1, |_| {});

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        open_with(
            &ledger,
            &CountingKem {
                calls: &calls,
                crash: true,
            },
            &opening,
        )
    }));
    assert!(crashed.is_err(), "the provider crashed");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Verbrauch, Sperrzeilen und 14/accepted stehen; ein Ergebnis gibt es nicht.
    assert_eq!(count(&database, "reader_key_escrow_opening"), 1);
    assert_eq!(count(&database, "operator_admin_replay"), 2);
    assert_eq!(opening_rows(&database), [LocalAuditOutcomeV1::Accepted]);
    assert_eq!(count(&database, "reader_key_escrow_result"), 0);

    // Nach einem Neustart läuft dieselbe Autorisierung nie wieder, und der
    // Provider wird nicht mehr angesprochen.
    let database = store.open();
    let audit = store.audit(&database);
    let ledger = ReaderKeyEscrowLedger::new(&database, &audit, &store.proof);
    let error = open_with(
        &ledger,
        &CountingKem {
            calls: &calls,
            crash: false,
        },
        &opening,
    )
    .unwrap_err();
    assert_eq!(error.code(), "EA-TRUST-AUTH-REPLAY");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        ledger
            .stored_result(opening.authorization.object_hash())
            .err(),
        Some(ReaderKeyEscrowError::ResultMissing)
    );
    assert_eq!(
        ReaderKeyEscrowError::ResultMissing.code(),
        "EA-ESCROW-RESULT-MISSING"
    );

    // Eine frische Zwei-Approver-Autorisierung (neue ID, neue Nonce) gelingt.
    let fresh = line.opening(0xf2, |_| {});
    let envelope = open_with(
        &ledger,
        &CountingKem {
            calls: &calls,
            crash: false,
        },
        &fresh,
    )
    .unwrap();
    assert!(envelope.restore_context == fresh.authorization.restore_context());
    assert_eq!(
        opening_rows(&database),
        [LocalAuditOutcomeV1::Accepted, LocalAuditOutcomeV1::Accepted]
    );
    assert_eq!(count(&database, "reader_key_escrow_result"), 1);
}

// ---------------------------------------------------------------------------
// Pflichtzeuge: doppelter Verbrauch
// ---------------------------------------------------------------------------

#[test]
fn a_consumed_authorization_is_refused_sequentially_and_through_either_dimension() {
    let line = line();
    let store = Store::new("double");
    let database = store.open();
    let audit = store.audit(&database);
    let ledger = ReaderKeyEscrowLedger::new(&database, &audit, &store.proof);
    let kem = recovery_key();
    let first = line.opening(0xf1, |_| {});
    open_with(&ledger, &kem, &first).unwrap();

    // Sequenziell dieselbe Autorisierung.
    assert_eq!(
        open_with(&ledger, &kem, &first).unwrap_err(),
        ReaderKeyEscrowError::Trust(TrustError::AuthReplay)
    );
    // Dieselbe Nonce unter anderer ID: Dimension 1.
    let same_nonce = line.opening(0xf3, |fields| {
        fields.nonce = first.authorization.fields().nonce
    });
    assert_eq!(
        open_with(&ledger, &kem, &same_nonce).unwrap_err(),
        ReaderKeyEscrowError::Trust(TrustError::AuthReplay)
    );
    // Die ID einer bereits verbrauchten Freigabe oder
    // Administrationsautorisierung (geteilter Namensraum, F8): Dimension 0.
    let foreign = line.opening(0xf4, |_| {});
    database
        .execute(
            "INSERT INTO operator_admin_replay(organization_id,dimension,replay_value) VALUES(?1,0,?2)",
            &[
                StoreValue::Blob(store.proof.organization_id().as_bytes().to_vec()),
                StoreValue::Blob(foreign.authorization.fields().authorization_id.as_bytes().to_vec()),
            ],
        )
        .unwrap();
    assert_eq!(
        open_with(&ledger, &kem, &foreign).unwrap_err(),
        ReaderKeyEscrowError::Trust(TrustError::AuthReplay)
    );
    // Keiner der Versuche hat eine Verbrauchs- oder Auditzeile hinterlassen.
    assert_eq!(count(&database, "reader_key_escrow_opening"), 1);
    assert_eq!(opening_rows(&database), [LocalAuditOutcomeV1::Accepted]);
}

/// Zwei Laufzeiten auf derselben Datei, nebenläufig: genau ein Verbrauch,
/// genau ein Providerzugriff, genau eine `accepted`-Zeile. Der Verlierer
/// scheitert am Wiedereinspiel oder — wenn SQLite die Sperre nicht rechtzeitig
/// freigibt — an der Ablage; beides ohne Providerzugriff.
#[test]
fn concurrent_openings_of_one_authorization_consume_it_exactly_once() {
    let line = line();
    let store = Store::new("concurrent");
    let opening = line.opening(0xf1, |_| {});
    let calls = AtomicUsize::new(0);
    // Die Datei existiert und ist migriert, bevor zwei Laufzeiten sie öffnen.
    drop(store.open());
    let results: Vec<_> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let store = &store;
                let opening = &opening;
                let calls = &calls;
                scope.spawn(move || {
                    let database = store.open();
                    let audit = store.audit(&database);
                    let ledger = ReaderKeyEscrowLedger::new(&database, &audit, &store.proof);
                    open_with(
                        &ledger,
                        &CountingKem {
                            calls,
                            crash: false,
                        },
                        opening,
                    )
                    .map(|_| ())
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let loser = results.iter().find_map(|result| result.err()).unwrap();
    assert!(
        matches!(
            loser,
            ReaderKeyEscrowError::Trust(TrustError::AuthReplay) | ReaderKeyEscrowError::Store
        ),
        "{loser:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let database = store.open();
    assert_eq!(count(&database, "reader_key_escrow_opening"), 1);
    assert_eq!(opening_rows(&database), [LocalAuditOutcomeV1::Accepted]);
    assert_eq!(count(&database, "reader_key_escrow_result"), 1);
}

// ---------------------------------------------------------------------------
// Pflichtzeuge: Abholung an einen abweichenden Schlüssel
// ---------------------------------------------------------------------------

#[test]
fn a_pickup_for_another_transport_key_changes_nothing() {
    let line = line();
    let store = Store::new("pickup-other");
    let database = store.open();
    let audit = store.audit(&database);
    let ledger = ReaderKeyEscrowLedger::new(&database, &audit, &store.proof);
    let opening = line.opening(0xf1, |_| {});
    open_with(&ledger, &recovery_key(), &opening).unwrap();
    let before = stored_envelope(&database).unwrap();

    let stored = ledger
        .stored_result(opening.authorization.object_hash())
        .unwrap();
    let other = x25519_public([0x5e; 32]);
    assert_eq!(
        stored.require_transport_key(other).unwrap_err(),
        ReaderKeyEscrowError::TransportMismatch
    );
    assert_eq!(
        ReaderKeyEscrowError::TransportMismatch.code(),
        "EA-ESCROW-TRANSPORT-MISMATCH"
    );
    assert_eq!(
        stored.require_transport_key([0; 32]).unwrap_err(),
        ReaderKeyEscrowError::TransportMismatch,
        "a non-canonical key is refused as well"
    );
    // Bytegleich, keine Abschlusszeile, keine `completed`-Zeile.
    assert_eq!(stored_envelope(&database).unwrap(), before);
    assert_eq!(opening_rows(&database), [LocalAuditOutcomeV1::Accepted]);
    // Ein zweites Ergebnis — etwa an den anderen Schlüssel neu versiegelt —
    // scheitert schon am Schema.
    assert!(
        database
            .execute(
                "INSERT INTO reader_key_escrow_result(authorization_object_hash,target_transport_key_thumbprint,exact_envelope,stored_at_ms,expires_at_ms) VALUES(?1,?2,x'01',0,86400000)",
                &[
                    StoreValue::Blob(opening.authorization.object_hash().as_bytes().to_vec()),
                    StoreValue::Blob(
                        ea_crypto::CanonicalPublicCoseKey::x25519(other)
                            .unwrap()
                            .thumbprint()
                            .as_bytes()
                            .to_vec()
                    ),
                ],
            )
            .is_err()
    );

    // Mit dem richtigen Schlüssel gelingt die Abholung danach.
    stored
        .require_transport_key(x25519_public(TRANSPORT_KEM_SEED))
        .unwrap();
    ledger.complete_delivery(&stored).unwrap();
    assert_eq!(
        opening_rows(&database),
        [
            LocalAuditOutcomeV1::Accepted,
            LocalAuditOutcomeV1::Completed
        ]
    );
    assert!(stored_envelope(&database).is_none());
}

// ---------------------------------------------------------------------------
// Pflichtzeuge: abgelaufene Sitzung NACH dem Verbrauch
// ---------------------------------------------------------------------------

#[test]
fn a_session_expiring_after_consumption_burns_the_authorization_and_books_it() {
    let line = line();
    let store = Store::new("expired-after");
    let database = store.open();
    let audit = store.audit(&database);
    let ledger = ReaderKeyEscrowLedger::new(&database, &audit, &store.proof);
    let opening = line.opening(0xf1, |_| {});
    let calls = AtomicUsize::new(0);
    let checks = Cell::new(0);
    let session = || {
        checks.set(checks.get() + 1);
        if checks.get() == 1 {
            Ok(())
        } else {
            Err(ReaderKeyEscrowError::Operator)
        }
    };
    let kem = CountingKem {
        calls: &calls,
        crash: false,
    };
    let error = ReaderKeyEscrowOpeningService::new(&kem, &ledger, &session)
        .open(&opening.authorization, &opening.transport)
        .unwrap_err();
    assert_eq!(error.code(), "EA-ESCROW-OPERATOR-UNAUTHORIZED");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        opening_rows(&database),
        [LocalAuditOutcomeV1::Accepted, LocalAuditOutcomeV1::Failed]
    );
    assert_eq!(count(&database, "reader_key_escrow_result"), 0);
    // Verbrannt: dieselbe Autorisierung läuft nie wieder.
    assert_eq!(
        open_with(&ledger, &recovery_key(), &opening).unwrap_err(),
        ReaderKeyEscrowError::Trust(TrustError::AuthReplay)
    );
}

// ---------------------------------------------------------------------------
// Neustart, Abholung, einmalige Auslieferung
// ---------------------------------------------------------------------------

#[test]
fn an_interrupted_delivery_resumes_after_a_restart_exactly_once() {
    let line = line();
    let store = Store::new("restart");
    let opening = line.opening(0xf1, |_| {});
    {
        let database = store.open();
        let audit = store.audit(&database);
        let ledger = ReaderKeyEscrowLedger::new(&database, &audit, &store.proof);
        open_with(&ledger, &recovery_key(), &opening).unwrap();
        // Die Auslieferung bricht hier ab: keine Datei, kein Abschluss.
    }
    let database = store.open();
    let audit = store.audit(&database);
    let ledger = ReaderKeyEscrowLedger::new(&database, &audit, &store.proof);
    let stored = ledger
        .stored_result(opening.authorization.object_hash())
        .unwrap();
    stored
        .require_transport_key(x25519_public(TRANSPORT_KEM_SEED))
        .unwrap();
    let outbox = store.directory("outbox");
    let file = write_escrow_outbox(
        &outbox,
        ReaderKeyEscrowTransferKindV1::Envelope,
        stored.exact_envelope(),
    )
    .unwrap();
    ledger.complete_delivery(&stored).unwrap();
    assert!(file == ea_crypto::object_hash(stored.exact_envelope()));
    assert_eq!(
        database
            .query_row("SELECT reason FROM reader_key_escrow_result_closure", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    assert_eq!(
        opening_rows(&database),
        [
            LocalAuditOutcomeV1::Accepted,
            LocalAuditOutcomeV1::Completed
        ]
    );
    // Die ausgelieferte Datei öffnet zum Reader-KEM.
    let name = reader_key_escrow_transfer_file_name(
        ReaderKeyEscrowTransferKindV1::Envelope,
        stored.exact_envelope(),
    );
    let envelope =
        ea_format::decode_reader_key_escrow_envelope(&std::fs::read(outbox.join(name)).unwrap())
            .unwrap();
    let context = envelope.restore_context.encode();
    let restored = ea_crypto::hpke_open(
        &HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(TRANSPORT_KEM_SEED)).unwrap(),
        &ea_crypto::HpkeSealed::from_parts(
            envelope.encapsulated_key,
            envelope.sealed_reader_kem_key,
        )
        .unwrap(),
        &ea_crypto::hpke_info(&context),
        &ea_crypto::hpke_aad(&context),
    )
    .unwrap();
    assert!(restored.matches(&READER_KEM_SEED));

    // Ein zweites Abholen findet nichts mehr.
    let error = ledger
        .stored_result(opening.authorization.object_hash())
        .err()
        .unwrap();
    assert_eq!(error, ReaderKeyEscrowError::ResultDelivered);
    assert_eq!(error.code(), "EA-ESCROW-RESULT-DELIVERED");
    assert_eq!(
        ledger.complete_delivery(&stored).unwrap_err(),
        ReaderKeyEscrowError::ResultDelivered
    );
}

// ---------------------------------------------------------------------------
// Verfall nach 86 400 000 ms
// ---------------------------------------------------------------------------

#[test]
fn a_result_expires_exactly_at_the_retention_boundary() {
    let line = line();
    let store = Store::new("expiry");
    let database = store.open();
    let audit = store.audit(&database);
    let now = Cell::new(STORED_AT);
    let clock = || Ok(millis(now.get()));
    let ledger = ReaderKeyEscrowLedger::with_clock(&database, &audit, &store.proof, &clock);
    let opening = line.opening(0xf1, |_| {});
    open_with(&ledger, &recovery_key(), &opening).unwrap();
    assert_eq!(
        database
            .query_row(
                "SELECT stored_at_ms,expires_at_ms FROM reader_key_escrow_result",
                &[]
            )
            .unwrap()
            .map(|row| (row.integer(0).unwrap(), row.integer(1).unwrap())),
        Some((STORED_AT, STORED_AT + READER_KEY_ESCROW_RESULT_RETENTION_MS))
    );

    now.set(STORED_AT + READER_KEY_ESCROW_RESULT_RETENTION_MS - 1);
    assert_eq!(ledger.purge_expired().unwrap(), 0);
    assert!(
        ledger
            .stored_result(opening.authorization.object_hash())
            .is_ok()
    );

    now.set(STORED_AT + READER_KEY_ESCROW_RESULT_RETENTION_MS);
    assert_eq!(ledger.purge_expired().unwrap(), 1);
    assert_eq!(count(&database, "reader_key_escrow_result"), 0);
    assert_eq!(
        database
            .query_row(
                "SELECT reason,closed_at_ms FROM reader_key_escrow_result_closure",
                &[]
            )
            .unwrap()
            .map(|row| (row.integer(0).unwrap(), row.integer(1).unwrap())),
        Some((1, STORED_AT + READER_KEY_ESCROW_RESULT_RETENTION_MS))
    );
    assert_eq!(
        opening_rows(&database),
        [LocalAuditOutcomeV1::Accepted, LocalAuditOutcomeV1::Failed]
    );
    let error = ledger
        .stored_result(opening.authorization.object_hash())
        .err()
        .unwrap();
    assert_eq!(error, ReaderKeyEscrowError::ResultExpired);
    assert_eq!(error.code(), "EA-ESCROW-RESULT-EXPIRED");
    // Die Verbrauchszeile steht weiter.
    assert_eq!(count(&database, "reader_key_escrow_opening"), 1);
}

/// Wird ein Ergebnis beim Abholen verfallen gefunden, räumt schon das Abholen
/// auf — ohne dass vorher jemand `purge_expired` rief.
#[test]
fn a_pickup_after_the_boundary_deletes_and_reports_expiry() {
    let line = line();
    let store = Store::new("expiry-pickup");
    let database = store.open();
    let audit = store.audit(&database);
    let now = Cell::new(STORED_AT);
    let clock = || Ok(millis(now.get()));
    let ledger = ReaderKeyEscrowLedger::with_clock(&database, &audit, &store.proof, &clock);
    let opening = line.opening(0xf1, |_| {});
    open_with(&ledger, &recovery_key(), &opening).unwrap();
    now.set(STORED_AT + READER_KEY_ESCROW_RESULT_RETENTION_MS);
    assert_eq!(
        ledger
            .stored_result(opening.authorization.object_hash())
            .err(),
        Some(ReaderKeyEscrowError::ResultExpired)
    );
    assert_eq!(count(&database, "reader_key_escrow_result"), 0);
    assert_eq!(count(&database, "reader_key_escrow_result_closure"), 1);
}

// ---------------------------------------------------------------------------
// Die Transportdatei und die Escrow-Inbox
// ---------------------------------------------------------------------------

fn write_transport(inbox: &Path, request: &ReaderKeyEscrowTransportRequestV1) -> PathBuf {
    let bytes = encode_reader_key_escrow_transport_request(request).unwrap();
    let path = inbox.join(reader_key_escrow_transfer_file_name(
        ReaderKeyEscrowTransferKindV1::TransportRequest,
        &bytes,
    ));
    std::fs::write(&path, bytes).unwrap();
    path
}

fn transport_request(line: &Line, key: [u8; 32]) -> ReaderKeyEscrowTransportRequestV1 {
    ReaderKeyEscrowTransportRequestV1 {
        organization_id: line.core.organization_id,
        escrow_object_hash: line.escrow_hash,
        target_transport_public_key: key,
    }
}

/// Eine Transportdatei mit einem nicht kanonischen oder einem abweichenden
/// Schlüssel wird abgewiesen, BEVOR irgendetwas verbraucht ist.
#[test]
fn a_foreign_or_non_canonical_transport_key_is_refused_before_consumption() {
    let line = line();
    let store = Store::new("transport");
    let (trust, head) = select(&line.escrow.line, tip_sequence(&line.escrow.line));
    let fields = recovery_core(
        line.escrow_hash,
        &line.core,
        Basis::of_selected(&head),
        (2_000, 2_900),
        0xf1,
    );
    let authorization = verify_reader_key_escrow_recovery_authorization(
        &trust,
        &head,
        &signed_recovery(&fields, &line.escrow.approvers),
        millis(NOW),
    )
    .unwrap();
    for key in [[0; 32], x25519_public([0x5e; 32])] {
        let inbox = store.directory(&format!("inbox-{}", hex::encode(&key[..4])));
        write_transport(&inbox, &transport_request(&line, key));
        let read = read_transport_key(&inbox, line.core.organization_id, line.escrow_hash).unwrap();
        assert_eq!(
            authorization
                .require_target_transport_key(read)
                .err()
                .map(TrustError::code),
            Some("EA-TRUST-ACTION-MISMATCH")
        );
    }
    let database = store.open();
    assert_eq!(count(&database, "reader_key_escrow_opening"), 0);
    assert_eq!(count(&database, "operator_admin_replay"), 0);
}

#[test]
fn the_escrow_inbox_reads_strictly() {
    let line = line();
    let store = Store::new("inbox");
    let key = x25519_public(TRANSPORT_KEM_SEED);

    // Genau eine passende Transportdatei: ihr Schlüssel.
    let inbox = store.directory("single");
    write_transport(&inbox, &transport_request(&line, key));
    assert_eq!(
        read_transport_key(&inbox, line.core.organization_id, line.escrow_hash).unwrap(),
        key
    );
    assert_eq!(read_escrow_inbox(&inbox).unwrap().len(), 1);

    // Keine passende und zwei passende Dateien sind mehrdeutig.
    let empty = store.directory("empty");
    assert_eq!(
        read_transport_key(&empty, line.core.organization_id, line.escrow_hash).unwrap_err(),
        ReaderKeyEscrowError::TransferFile
    );
    let twice = store.directory("twice");
    write_transport(&twice, &transport_request(&line, key));
    write_transport(&twice, &transport_request(&line, x25519_public([0x5e; 32])));
    assert_eq!(
        read_transport_key(&twice, line.core.organization_id, line.escrow_hash).unwrap_err(),
        ReaderKeyEscrowError::TransferFile
    );

    // Ein Stamm, der nicht der Hash der Bytes ist, und ein fremder Name.
    let renamed = store.directory("renamed");
    let path = write_transport(&renamed, &transport_request(&line, key));
    std::fs::rename(
        &path,
        renamed.join(format!(
            "{}.reader-key-escrow-transport.cbor",
            "ab".repeat(32)
        )),
    )
    .unwrap();
    assert_eq!(
        read_escrow_inbox(&renamed).err(),
        Some(ReaderKeyEscrowError::TransferFile)
    );
    let foreign = store.directory("foreign");
    write_transport(&foreign, &transport_request(&line, key));
    std::fs::write(foreign.join("notes.txt"), b"x").unwrap();
    assert_eq!(
        read_escrow_inbox(&foreign).err(),
        Some(ReaderKeyEscrowError::TransferFile)
    );

    // Ein Symlink statt der Datei.
    #[cfg(unix)]
    {
        let linked = store.directory("linked");
        let target = write_transport(&store.directory("target"), &transport_request(&line, key));
        std::os::unix::fs::symlink(&target, linked.join(target.file_name().unwrap())).unwrap();
        assert_eq!(
            read_escrow_inbox(&linked).err(),
            Some(ReaderKeyEscrowError::TransferFile)
        );
        assert_eq!(
            ReaderKeyEscrowError::TransferFile.code(),
            "EA-ESCROW-TRANSFER-FILE"
        );
    }
}

/// Der Ausgang schreibt idempotent: dieselben Bytes unter demselben Namen
/// gelingen erneut, fremde Bytes unter dem Namen nicht.
#[test]
fn the_escrow_outbox_writes_idempotently_and_never_overwrites() {
    let store = Store::new("outbox");
    let outbox = store.directory("outbox");
    let bytes = b"sealed-envelope-bytes";
    let first =
        write_escrow_outbox(&outbox, ReaderKeyEscrowTransferKindV1::Envelope, bytes).unwrap();
    let again =
        write_escrow_outbox(&outbox, ReaderKeyEscrowTransferKindV1::Envelope, bytes).unwrap();
    assert!(first == again);
    let name = reader_key_escrow_transfer_file_name(ReaderKeyEscrowTransferKindV1::Envelope, bytes);
    std::fs::write(outbox.join(&name), b"other").unwrap();
    assert_eq!(
        write_escrow_outbox(&outbox, ReaderKeyEscrowTransferKindV1::Envelope, bytes).err(),
        Some(ReaderKeyEscrowError::Output)
    );
    // Kein Zwischenname bleibt liegen.
    assert_eq!(std::fs::read_dir(&outbox).unwrap().count(), 1);
}
