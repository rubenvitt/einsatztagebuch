//! Die zweite getypte Operation des Recovery-Ports: die Öffnung eines
//! verbrauchten, geprüften Reader-Key-Escrows (Profil §6, DRK-458).
//!
//! Die Reihenfolge ist Vertrag: Abdruckvergleich, Sitzung, Verbrauch, Sitzung,
//! private Operation, Gegenprobe, Versiegelung an den Ziel-Transport-Schlüssel,
//! dauerhaftes Ergebnis. Die Zeugen laufen gegen eine echte, voll geprüfte
//! Öffnungsautorisierung aus der Trust-Linie und einen Spion-Ledger.
#[path = "../../ea-trust/tests/escrow_support/mod.rs"]
mod escrow_support;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;

use std::cell::{Cell, RefCell};

use ea_crypto::{
    CanonicalPublicCoseKey, CryptoError, HpkeRecipientPrivateKey, HpkeSealed, SecretBytes,
    hpke_aad, hpke_info, hpke_open,
};
use ea_format::ReaderKeyEscrowEnvelopeV1;
use ea_recovery::{
    ConsumedEscrowOpening, ConsumptionReceipt, EscrowOpeningLedger, ReaderKeyEscrowError,
    ReaderKeyEscrowKem, ReaderKeyEscrowOpeningService,
};
use ea_trust::{
    AuthorizedEscrowTransportKey, TrustError, VerifiedReaderKeyEscrowRecoveryAuthorization,
    verify_reader_key_escrow_recovery_authorization,
};
use ea_types::UnixMillis;
use escrow_support::{
    Basis, EscrowLineOptions, READER_KEM_SEED, RECOVERY_KEM_SEED, SECOND_READER_KEM_SEED,
    TRANSPORT_KEM_SEED, approval_core, escrow_core, escrow_line, publish_escrow, recovery_core,
    select, signed_recovery, subject, tip_sequence, x25519_key, x25519_public,
};

const NOW: i64 = 2_100;

/// Eine voll geprüfte Öffnungsautorisierung und ihr Ziel-Transport-Schlüssel.
struct Opening {
    authorization: VerifiedReaderKeyEscrowRecoveryAuthorization,
    transport: AuthorizedEscrowTransportKey,
}

/// `reader_kem_seed` ist das, was im Escrow VERSIEGELT steht; das
/// Reader-Zertifikat trägt immer den KEM aus `READER_KEM_SEED`. Ein anderes
/// Geheimnis mit korrektem Kontext ist genau der Fall der Gegenprobe.
fn opening_sealing(reader_kem_seed: [u8; 32]) -> Opening {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = escrow_core(
        &escrow,
        &escrow.reader,
        reader_kem_seed,
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
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let fields = recovery_core(
        escrow_hash,
        &core,
        Basis::of_selected(&head),
        (2_000, 2_900),
        0xf1,
    );
    let bytes = signed_recovery(&fields, &escrow.approvers);
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

fn opening() -> Opening {
    opening_sealing(READER_KEM_SEED)
}

fn millis(value: i64) -> UnixMillis {
    UnixMillis::new(value)
}

fn recovery_key() -> HpkeRecipientPrivateKey {
    HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(RECOVERY_KEM_SEED)).unwrap()
}

/// Was in welcher Reihenfolge geschah.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Session,
    Consume,
    Open,
    Store,
    Failure,
}

#[derive(Default)]
struct Journal(RefCell<Vec<Step>>);
impl Journal {
    fn push(&self, step: Step) {
        self.0.borrow_mut().push(step);
    }
    fn steps(&self) -> Vec<Step> {
        self.0.borrow().clone()
    }
}

/// Ein Ledger, der jeden Aufruf protokolliert und auf Wunsch scheitert.
struct SpyLedger<'a> {
    journal: &'a Journal,
    refuse_consume: bool,
    stored: RefCell<Option<ReaderKeyEscrowEnvelopeV1>>,
}
impl<'a> SpyLedger<'a> {
    fn new(journal: &'a Journal) -> Self {
        Self {
            journal,
            refuse_consume: false,
            stored: RefCell::new(None),
        }
    }
}
impl EscrowOpeningLedger for SpyLedger<'_> {
    fn consume(
        &self,
        authorization: &VerifiedReaderKeyEscrowRecoveryAuthorization,
        transport: &AuthorizedEscrowTransportKey,
    ) -> Result<ConsumptionReceipt, ReaderKeyEscrowError> {
        self.journal.push(Step::Consume);
        if self.refuse_consume {
            return Err(ReaderKeyEscrowError::Trust(TrustError::AuthReplay));
        }
        Ok(ConsumptionReceipt::new(
            authorization,
            transport,
            millis(NOW),
        ))
    }
    fn store_result(
        &self,
        receipt: &ConsumptionReceipt,
        envelope: &ReaderKeyEscrowEnvelopeV1,
    ) -> Result<(), ReaderKeyEscrowError> {
        assert!(receipt.consumed_at() == millis(NOW));
        self.journal.push(Step::Store);
        *self.stored.borrow_mut() = Some(envelope.clone());
        Ok(())
    }
    fn book_failure(&self, _receipt: &ConsumptionReceipt) {
        self.journal.push(Step::Failure);
    }
}

/// Ein KEM, der seine private Operation protokolliert und an einen echten
/// Schlüssel weiterreicht.
struct SpyKem<'a, K> {
    journal: &'a Journal,
    inner: K,
    calls: Cell<usize>,
}
impl<K: ReaderKeyEscrowKem> ReaderKeyEscrowKem for SpyKem<'_, K> {
    fn key_thumbprint(&self) -> Result<ea_types::KeyThumbprint, CryptoError> {
        self.inner.key_thumbprint()
    }
    fn open_reader_key_escrow(
        &self,
        opening: &ConsumedEscrowOpening<'_>,
    ) -> Result<SecretBytes<32>, CryptoError> {
        self.journal.push(Step::Open);
        self.calls.set(self.calls.get() + 1);
        self.inner.open_reader_key_escrow(opening)
    }
}

fn service<'a>(
    kem: &'a dyn ReaderKeyEscrowKem,
    ledger: &'a dyn EscrowOpeningLedger,
    session: &'a dyn Fn() -> Result<(), ReaderKeyEscrowError>,
) -> ReaderKeyEscrowOpeningService<'a> {
    ReaderKeyEscrowOpeningService::new(kem, ledger, session)
}

/// Öffnet den Umschlag so, wie der Browser es tut: mit dem lebenden privaten
/// Transport-Schlüssel und der öffentlichen Bindung als Quelle von info/AAD.
fn open_as_browser(envelope: &ReaderKeyEscrowEnvelopeV1) -> SecretBytes<32> {
    let transport =
        HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(TRANSPORT_KEM_SEED)).unwrap();
    let context = envelope.restore_context.encode();
    hpke_open(
        &transport,
        &HpkeSealed::from_parts(envelope.encapsulated_key, envelope.sealed_reader_kem_key).unwrap(),
        &hpke_info(&context),
        &hpke_aad(&context),
    )
    .unwrap()
}

#[test]
fn the_envelope_opens_with_the_transport_key_to_the_reader_kem() {
    let opening = opening();
    let journal = Journal::default();
    let ledger = SpyLedger::new(&journal);
    let kem = SpyKem {
        journal: &journal,
        inner: recovery_key(),
        calls: Cell::new(0),
    };
    let session = || {
        journal.push(Step::Session);
        Ok(())
    };
    let envelope = service(&kem, &ledger, &session)
        .open(&opening.authorization, &opening.transport)
        .unwrap();
    assert_eq!(
        journal.steps(),
        [
            Step::Session,
            Step::Consume,
            Step::Session,
            Step::Open,
            Step::Store
        ],
        "consumption comes strictly before the private operation"
    );
    assert!(ledger.stored.borrow().as_ref() == Some(&envelope));
    assert!(envelope.restore_context == opening.authorization.restore_context());
    let restored = open_as_browser(&envelope);
    assert!(restored.matches(&READER_KEM_SEED));
    let derived = restored.with_exposed(|bytes| {
        *HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(*bytes))
            .unwrap()
            .public_key()
            .as_bytes()
    });
    assert!(CanonicalPublicCoseKey::x25519(derived).unwrap() == x25519_key(READER_KEM_SEED));
}

/// Ein fremder Recovery-Schlüssel bricht ab, BEVOR etwas verbraucht ist.
#[test]
fn a_foreign_recovery_key_consumes_nothing() {
    let opening = opening();
    let journal = Journal::default();
    let ledger = SpyLedger::new(&journal);
    let foreign = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x5a; 32])).unwrap();
    let kem = SpyKem {
        journal: &journal,
        inner: foreign,
        calls: Cell::new(0),
    };
    let session = || {
        journal.push(Step::Session);
        Ok(())
    };
    let error = service(&kem, &ledger, &session)
        .open(&opening.authorization, &opening.transport)
        .unwrap_err();
    assert_eq!(error, ReaderKeyEscrowError::RecoveryKey);
    assert_eq!(error.code(), "EA-ESCROW-RECOVERY-KEY");
    assert!(journal.steps().is_empty(), "{:?}", journal.steps());
}

/// Scheitert der Verbrauch, wird der Provider nie gerufen.
#[test]
fn a_refused_consumption_never_reaches_the_provider() {
    let opening = opening();
    let journal = Journal::default();
    let mut ledger = SpyLedger::new(&journal);
    ledger.refuse_consume = true;
    let kem = SpyKem {
        journal: &journal,
        inner: recovery_key(),
        calls: Cell::new(0),
    };
    let session = || {
        journal.push(Step::Session);
        Ok(())
    };
    let error = service(&kem, &ledger, &session)
        .open(&opening.authorization, &opening.transport)
        .unwrap_err();
    assert_eq!(error, ReaderKeyEscrowError::Trust(TrustError::AuthReplay));
    assert_eq!(error.code(), "EA-TRUST-AUTH-REPLAY");
    assert_eq!(kem.calls.get(), 0);
    assert_eq!(journal.steps(), [Step::Session, Step::Consume]);
}

/// Eine vor dem Verbrauch abgelaufene Sitzung verbraucht nichts.
#[test]
fn an_expired_session_before_consumption_consumes_nothing() {
    let opening = opening();
    let journal = Journal::default();
    let ledger = SpyLedger::new(&journal);
    let kem = SpyKem {
        journal: &journal,
        inner: recovery_key(),
        calls: Cell::new(0),
    };
    let session = || {
        journal.push(Step::Session);
        Err(ReaderKeyEscrowError::Operator)
    };
    let error = service(&kem, &ledger, &session)
        .open(&opening.authorization, &opening.transport)
        .unwrap_err();
    assert_eq!(error, ReaderKeyEscrowError::Operator);
    assert_eq!(error.code(), "EA-ESCROW-OPERATOR-UNAUTHORIZED");
    assert_eq!(journal.steps(), [Step::Session]);
}

/// Läuft die Sitzung NACH dem Verbrauch ab, ist die Autorisierung verbrannt:
/// gebucht wird das Scheitern, der Provider wird nie gerufen, ein Ergebnis gibt
/// es nicht (Profil §8: eine Verbrauchszeile wird nie zurückgesetzt).
#[test]
fn an_expired_session_after_consumption_burns_the_authorization() {
    let opening = opening();
    let journal = Journal::default();
    let ledger = SpyLedger::new(&journal);
    let kem = SpyKem {
        journal: &journal,
        inner: recovery_key(),
        calls: Cell::new(0),
    };
    let checks = Cell::new(0);
    let session = || {
        journal.push(Step::Session);
        checks.set(checks.get() + 1);
        if checks.get() == 1 {
            Ok(())
        } else {
            Err(ReaderKeyEscrowError::Operator)
        }
    };
    let error = service(&kem, &ledger, &session)
        .open(&opening.authorization, &opening.transport)
        .unwrap_err();
    assert_eq!(error, ReaderKeyEscrowError::Operator);
    assert_eq!(
        journal.steps(),
        [Step::Session, Step::Consume, Step::Session, Step::Failure]
    );
    assert_eq!(kem.calls.get(), 0);
    assert!(ledger.stored.borrow().is_none());
}

/// Die Gegenprobe: ein Chiffrat mit richtigem Kontext, aber einem ANDEREN
/// Reader-KEM, gibt nichts heraus und bucht das Scheitern.
#[test]
fn a_decrypted_key_that_is_not_the_reader_kem_is_refused_and_booked() {
    let opening = opening_sealing(SECOND_READER_KEM_SEED);
    let journal = Journal::default();
    let ledger = SpyLedger::new(&journal);
    let kem = SpyKem {
        journal: &journal,
        inner: recovery_key(),
        calls: Cell::new(0),
    };
    let session = || {
        journal.push(Step::Session);
        Ok(())
    };
    let error = service(&kem, &ledger, &session)
        .open(&opening.authorization, &opening.transport)
        .unwrap_err();
    assert_eq!(error, ReaderKeyEscrowError::KemMismatch);
    assert_eq!(error.code(), "EA-ESCROW-KEM-MISMATCH");
    assert_eq!(
        journal.steps(),
        [
            Step::Session,
            Step::Consume,
            Step::Session,
            Step::Open,
            Step::Failure
        ]
    );
    assert!(ledger.stored.borrow().is_none());
}

/// Scheitert die private Operation, ist das Scheitern gebucht und nichts
/// gespeichert.
#[test]
fn a_failing_private_operation_is_booked() {
    struct Failing;
    impl ReaderKeyEscrowKem for Failing {
        fn key_thumbprint(&self) -> Result<ea_types::KeyThumbprint, CryptoError> {
            Ok(x25519_key(RECOVERY_KEM_SEED).thumbprint())
        }
        fn open_reader_key_escrow(
            &self,
            _opening: &ConsumedEscrowOpening<'_>,
        ) -> Result<SecretBytes<32>, CryptoError> {
            Err(CryptoError::HpkeOpen)
        }
    }
    let opening = opening();
    let journal = Journal::default();
    let ledger = SpyLedger::new(&journal);
    let session = || Ok(());
    let error = service(&Failing, &ledger, &session)
        .open(&opening.authorization, &opening.transport)
        .unwrap_err();
    assert_eq!(error, ReaderKeyEscrowError::Crypto);
    assert_eq!(error.code(), "EA-ESCROW-CRYPTO-FAILED");
    assert_eq!(journal.steps(), [Step::Consume, Step::Failure]);
}

/// Die Quittung gehört zu genau einer Autorisierung: eine Quittung, die ein
/// Ledger für eine andere ausstellt, führt nicht zur privaten Operation.
#[test]
fn a_receipt_for_another_authorization_is_refused() {
    struct Foreign<'a> {
        other: &'a Opening,
    }
    impl EscrowOpeningLedger for Foreign<'_> {
        fn consume(
            &self,
            _authorization: &VerifiedReaderKeyEscrowRecoveryAuthorization,
            _transport: &AuthorizedEscrowTransportKey,
        ) -> Result<ConsumptionReceipt, ReaderKeyEscrowError> {
            Ok(ConsumptionReceipt::new(
                &self.other.authorization,
                &self.other.transport,
                millis(NOW),
            ))
        }
        fn store_result(
            &self,
            _receipt: &ConsumptionReceipt,
            _envelope: &ReaderKeyEscrowEnvelopeV1,
        ) -> Result<(), ReaderKeyEscrowError> {
            panic!("nothing is stored for a foreign receipt");
        }
        fn book_failure(&self, _receipt: &ConsumptionReceipt) {}
    }
    let opening = opening();
    let other = opening_sealing(SECOND_READER_KEM_SEED);
    let journal = Journal::default();
    let kem = SpyKem {
        journal: &journal,
        inner: recovery_key(),
        calls: Cell::new(0),
    };
    let session = || Ok(());
    let error = service(&kem, &Foreign { other: &other }, &session)
        .open(&opening.authorization, &opening.transport)
        .unwrap_err();
    assert_eq!(error, ReaderKeyEscrowError::Store);
    assert_eq!(kem.calls.get(), 0);
}

/// Der PKCS#11-fähige Wegweiser: `ResolvedRecipientKey` öffnet über denselben
/// Kontext wie der Softwareschlüssel.
#[test]
fn the_resolved_recipient_key_routes_the_escrow_operation() {
    let opening = opening();
    let journal = Journal::default();
    let ledger = SpyLedger::new(&journal);
    let resolved = ea_recovery::ResolvedRecipientKey::Software(recovery_key());
    let session = || Ok(());
    let envelope = service(&resolved, &ledger, &session)
        .open(&opening.authorization, &opening.transport)
        .unwrap();
    assert!(open_as_browser(&envelope).matches(&READER_KEM_SEED));
}
