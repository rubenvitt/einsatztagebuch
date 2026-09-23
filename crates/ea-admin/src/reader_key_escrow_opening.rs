//! Zeremonie B nativ: die Öffnung eines Reader-Key-Escrows und die einmalige
//! Auslieferung des versiegelten Umschlags (Profil §6 und §8, DRK-458).
//!
//! Drei Teile:
//!
//! - [`ReaderKeyEscrowLedger`] ist der dauerhafte Zustand in SQLCipher und
//!   implementiert [`EscrowOpeningLedger`]: Verbrauch von `authorization-id`
//!   und `nonce` im geteilten Namensraum `operator_admin_replay` (F8) atomar
//!   mit der Verbrauchszeile und der signierten Auditzeile 14/`accepted`,
//!   bevor der private Provider angesprochen wird; das verschlüsselte
//!   Ergebnis; Abschluss durch Abholung (14/`completed`) oder Verfall
//!   (14/`failed`) atomar mit der Löschung. Eine Verbrauchszeile wird nie
//!   zurückgesetzt.
//! - [`open_reader_key_escrow`] ordnet die Zeremonie in der Laufzeit an:
//!   Prüfung über `ea-trust`, Transportdatei, frische Reauthentifizierung mit
//!   dem eigenen Zweck und dem Restore-Kontext, Öffnung über
//!   [`ReaderKeyEscrowOpeningService`], Auslieferung.
//! - [`pickup_reader_key_escrow`] setzt eine abgebrochene Auslieferung fort:
//!   nur mit der exakten Autorisierung, frischer Reauthentifizierung und einer
//!   Transportdatei mit GLEICHEM Abdruck. Es wird nie neu versiegelt
//!   (Entscheidung D6: die Frist der verbrauchten Autorisierung zählt hier
//!   nicht mehr, nur ihre Identität).
//!
//! Verfall (Entscheidung D5): gültig bei `now < stored + 86 400 000`, verfallen
//! ab `>=`. Jedes Escrow-Kommando löscht verfallene Ergebnisse gleich beim
//! Start, VOR Prüfung und Reauthentifizierung
//! ([`purge_expired_reader_key_escrow_results`]): unter dem geprüften Gerät
//! ohne Bedienerbindung, je Ergebnis atomar mit Abschlusszeile und Audit
//! 14/`failed`. Benannte Grenzen: ein Ergebnis, nach dem nie wieder ein
//! Escrow-Kommando läuft, bleibt verschlüsselt liegen; die ausgelieferte
//! Umschlagdatei im Ausgang (`--escrow-outbox`) ist eine Kopie außerhalb der
//! Datenbank und fällt nicht unter diesen Verfall.

use std::path::Path;

use ea_audit::{
    AuditActorProof, LocalAuditService, PreparedLocalAuditEvent, SignedLocalAuditService,
    SqliteLocalAuditRepository, TypedLocalAuditEvent,
};
use ea_crypto::{CanonicalPublicCoseKey, HpkeRecipientPublicKey, object_hash};
use ea_format::{
    OperatorRoleV1, ReaderKeyEscrowEnvelopeV1, ReaderKeyEscrowRestoreContextV1,
    ReaderKeyEscrowTransferKindV1, decode_reader_key_escrow_envelope,
    encode_reader_key_escrow_envelope,
};
use ea_local_store::{EncryptedDatabase, StoreError, StoreValue};
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_recovery::{
    ConsumptionReceipt, EscrowOpeningLedger, ReaderKeyEscrowError, ReaderKeyEscrowKem,
    ReaderKeyEscrowOpeningService,
};
use ea_trust::{
    AdminAuthorizationReplayDimension, AuthorizedEscrowTransportKey, TrustError,
    VerifiedReaderKeyEscrowRecoveryAuthorization, verify_reader_key_escrow_recovery_authorization,
};
use ea_types::{Hash32, KeyThumbprint, ObjectHash, OrganizationId, UnixMillis};

use crate::{
    operator_runtime::{OperatorRuntime, fresh_wall_clock},
    reader_key_escrow_inbox::{read_transport_key, write_escrow_outbox},
};

/// Die Höchsthaltedauer des verschlüsselten Ergebnisses (Entscheidung 6).
pub const READER_KEY_ESCROW_RESULT_RETENTION_MS: i64 = 86_400_000;

/// Der Abschlussgrund einer Abholung.
const CLOSED_DELIVERED: i64 = 0;
/// Der Abschlussgrund eines Verfalls.
const CLOSED_EXPIRED: i64 = 1;
/// Mehr verfallene Ergebnisse als diese räumt ein Lauf nicht auf einmal.
const MAX_PURGE: usize = 4096;

type Clock<'a> = &'a dyn Fn() -> Result<UnixMillis, ReaderKeyEscrowError>;

fn wall_clock() -> Result<UnixMillis, ReaderKeyEscrowError> {
    fresh_wall_clock().map_err(|_| ReaderKeyEscrowError::Operator)
}

fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}

/// Der Fehler innerhalb einer Transaktion: jeder Ablagebefund wird `Store`.
struct Tx(ReaderKeyEscrowError);
impl From<StoreError> for Tx {
    fn from(_: StoreError) -> Self {
        Self(ReaderKeyEscrowError::Store)
    }
}
impl From<ReaderKeyEscrowError> for Tx {
    fn from(error: ReaderKeyEscrowError) -> Self {
        Self(error)
    }
}

/// Ein gespeichertes, noch nicht abgeschlossenes Ergebnis.
pub struct StoredReaderKeyEscrowResult {
    authorization_object_hash: ObjectHash,
    escrow_object_hash: ObjectHash,
    target_transport_key_thumbprint: KeyThumbprint,
    exact_envelope: Vec<u8>,
    envelope: ReaderKeyEscrowEnvelopeV1,
}

impl StoredReaderKeyEscrowResult {
    #[must_use]
    pub const fn authorization_object_hash(&self) -> ObjectHash {
        self.authorization_object_hash
    }
    #[must_use]
    pub const fn target_transport_key_thumbprint(&self) -> KeyThumbprint {
        self.target_transport_key_thumbprint
    }
    /// Die exakten Bytes der Umschlagdatei.
    #[must_use]
    pub fn exact_envelope(&self) -> &[u8] {
        &self.exact_envelope
    }
    /// Die öffentliche Bindung des Umschlags.
    #[must_use]
    pub const fn restore_context(&self) -> &ReaderKeyEscrowRestoreContextV1 {
        &self.envelope.restore_context
    }

    /// Eine Abholung nennt GENAU den Schlüssel ihres Verbrauchs: kanonisches
    /// X25519 mit demselben Abdruck. Eine Umverschlüsselung an einen anderen
    /// Schlüssel gibt es nicht; das Ergebnis bleibt unverändert.
    ///
    /// # Errors
    ///
    /// [`ReaderKeyEscrowError::TransportMismatch`].
    pub fn require_transport_key(
        &self,
        x25519_public: [u8; 32],
    ) -> Result<(), ReaderKeyEscrowError> {
        HpkeRecipientPublicKey::from_bytes(x25519_public)
            .map_err(|_| ReaderKeyEscrowError::TransportMismatch)?;
        if CanonicalPublicCoseKey::x25519(x25519_public)
            .map_err(|_| ReaderKeyEscrowError::TransportMismatch)?
            .thumbprint()
            != self.target_transport_key_thumbprint
        {
            return Err(ReaderKeyEscrowError::TransportMismatch);
        }
        Ok(())
    }
}

/// Der dauerhafte Zustand der Zeremonie B in SQLCipher.
///
/// Jede Auditzeile trägt den Präsenznachweis der laufenden Zeremonie.
pub struct ReaderKeyEscrowLedger<'a> {
    database: &'a EncryptedDatabase,
    audit: &'a SignedLocalAuditService,
    proof: &'a OperatorSessionProof,
    clock: Clock<'a>,
}

impl<'a> ReaderKeyEscrowLedger<'a> {
    /// Das Ledger über der Wanduhr.
    #[must_use]
    pub fn new(
        database: &'a EncryptedDatabase,
        audit: &'a SignedLocalAuditService,
        proof: &'a OperatorSessionProof,
    ) -> Self {
        Self {
            database,
            audit,
            proof,
            clock: &wall_clock,
        }
    }

    /// Fixture-Eingang mit eingespielter Uhr, für die Verfallszeugen. Kein
    /// Produktivpfad erreicht ihn.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn with_clock(
        database: &'a EncryptedDatabase,
        audit: &'a SignedLocalAuditService,
        proof: &'a OperatorSessionProof,
        clock: Clock<'a>,
    ) -> Self {
        Self {
            database,
            audit,
            proof,
            clock,
        }
    }

    fn prepare(
        &self,
        event: TypedLocalAuditEvent,
    ) -> Result<PreparedLocalAuditEvent, ReaderKeyEscrowError> {
        self.audit
            .prepare_signed(AuditActorProof::OperatorSession(self.proof), event)
            .map_err(|_| ReaderKeyEscrowError::Audit)
    }

    fn organization_id(&self) -> OrganizationId {
        self.proof.organization_id()
    }

    /// Löscht jedes Ergebnis mit `now >= expires_at` — je Ergebnis atomar mit
    /// seiner Abschlusszeile (Grund 1) und der Auditzeile 14/`failed`.
    ///
    /// # Errors
    ///
    /// `Store` oder `Audit`; der Zustand bleibt dann unverändert.
    pub fn purge_expired(&self) -> Result<usize, ReaderKeyEscrowError> {
        purge_expired_results(self.database, (self.clock)()?, &|event| self.prepare(event))
    }

    /// Das gespeicherte Ergebnis zu einer Autorisierung — oder der Grund,
    /// warum es keines (mehr) gibt.
    ///
    /// # Errors
    ///
    /// `ResultMissing` ohne Verbrauch oder ohne Ergebnis, `ResultDelivered`
    /// nach der Abholung, `ResultExpired` nach dem Verfall, `Store` für einen
    /// widersprüchlichen Zustand.
    pub fn stored_result(
        &self,
        authorization_object_hash: ObjectHash,
    ) -> Result<StoredReaderKeyEscrowResult, ReaderKeyEscrowError> {
        let now = (self.clock)()?;
        let stored = read_stored_result(self.database, authorization_object_hash)?;
        if now.get() >= stored.1 {
            self.purge_expired()?;
            return Err(ReaderKeyEscrowError::ResultExpired);
        }
        Ok(stored.0)
    }

    /// Schließt eine erfolgreiche Abholung ab: Abschlusszeile (Grund 0),
    /// Löschung des Ergebnisses und Auditzeile 14/`completed` in EINER
    /// Transaktion. Danach gibt es dieses Ergebnis nie wieder.
    ///
    /// # Errors
    ///
    /// `Store`, `Audit`, oder `ResultDelivered`/`ResultExpired`, wenn ein
    /// nebenläufiger Lauf schneller war.
    pub fn complete_delivery(
        &self,
        stored: &StoredReaderKeyEscrowResult,
    ) -> Result<(), ReaderKeyEscrowError> {
        let now = (self.clock)()?;
        let prepared = self.prepare(TypedLocalAuditEvent::reader_key_escrow_delivered(
            stored.escrow_object_hash,
            stored.authorization_object_hash,
            stored.target_transport_key_thumbprint,
        ))?;
        close_in_transaction(
            self.database,
            stored.authorization_object_hash,
            CLOSED_DELIVERED,
            now,
            &prepared,
            Some(&stored.exact_envelope),
        )
    }
}

/// Löscht jedes Ergebnis mit `now >= expires_at` — je Ergebnis atomar mit
/// seiner Abschlusszeile (Grund 1) und der Auditzeile 14/`failed`, die
/// `prepare` unter dem Akteur des Aufrufers signiert.
fn purge_expired_results(
    database: &EncryptedDatabase,
    now: UnixMillis,
    prepare: &dyn Fn(TypedLocalAuditEvent) -> Result<PreparedLocalAuditEvent, ReaderKeyEscrowError>,
) -> Result<usize, ReaderKeyEscrowError> {
    let mut purged = 0;
    while purged < MAX_PURGE {
        let row = database
            .query_row(
                "SELECT r.authorization_object_hash,o.escrow_object_hash,o.target_transport_key_thumbprint \
                 FROM reader_key_escrow_result r JOIN reader_key_escrow_opening o \
                 ON o.authorization_object_hash=r.authorization_object_hash \
                 WHERE r.expires_at_ms<=?1 ORDER BY r.authorization_object_hash LIMIT 1",
                &[StoreValue::Integer(now.get())],
            )
            .map_err(|_| ReaderKeyEscrowError::Store)?;
        let Some(row) = row else {
            return Ok(purged);
        };
        let hashes = (|| -> Result<_, StoreError> {
            Ok((
                ObjectHash::try_from(row.blob(0)?).map_err(|_| StoreError::Shape)?,
                ObjectHash::try_from(row.blob(1)?).map_err(|_| StoreError::Shape)?,
                KeyThumbprint::try_from(row.blob(2)?).map_err(|_| StoreError::Shape)?,
            ))
        })()
        .map_err(|_| ReaderKeyEscrowError::Store)?;
        let (authorization, escrow, thumbprint) = hashes;
        let prepared = prepare(TypedLocalAuditEvent::reader_key_escrow_failed(
            escrow,
            authorization,
            thumbprint,
        ))?;
        close_in_transaction(
            database,
            authorization,
            CLOSED_EXPIRED,
            now,
            &prepared,
            None,
        )?;
        purged += 1;
    }
    Ok(purged)
}

fn close_in_transaction(
    database: &EncryptedDatabase,
    authorization: ObjectHash,
    reason: i64,
    now: UnixMillis,
    prepared: &PreparedLocalAuditEvent,
    exact_envelope: Option<&[u8]>,
) -> Result<(), ReaderKeyEscrowError> {
    database
            .transaction(|tx| {
                let closed = tx.query_row(
                    "SELECT reason FROM reader_key_escrow_result_closure WHERE authorization_object_hash=?1",
                    &[blob(authorization.as_bytes())],
                )?;
                if let Some(closed) = closed {
                    return Err(Tx(closure_error(closed.integer(0)?)));
                }
                let current = tx
                    .query_row(
                        "SELECT exact_envelope FROM reader_key_escrow_result WHERE authorization_object_hash=?1",
                        &[blob(authorization.as_bytes())],
                    )?
                    .ok_or(Tx(ReaderKeyEscrowError::ResultMissing))?;
                if exact_envelope.is_some_and(|expected| current.blob(0).ok() != Some(expected)) {
                    return Err(Tx(ReaderKeyEscrowError::Store));
                }
                SqliteLocalAuditRepository::append_prepared_in(tx, prepared)
                    .map_err(|_| Tx(ReaderKeyEscrowError::Audit))?;
                tx.execute(
                    "INSERT INTO reader_key_escrow_result_closure(authorization_object_hash,reason,closed_at_ms,audit_event_id) VALUES(?1,?2,?3,?4)",
                    &[
                        blob(authorization.as_bytes()),
                        StoreValue::Integer(reason),
                        StoreValue::Integer(now.get()),
                        blob(prepared.id().as_bytes()),
                    ],
                )?;
                if tx.execute(
                    "DELETE FROM reader_key_escrow_result WHERE authorization_object_hash=?1",
                    &[blob(authorization.as_bytes())],
                )? != 1
                {
                    return Err(Tx(ReaderKeyEscrowError::Store));
                }
                Ok(())
            })
            .map_err(|Tx(error)| error)
}

const fn closure_error(reason: i64) -> ReaderKeyEscrowError {
    if reason == CLOSED_DELIVERED {
        ReaderKeyEscrowError::ResultDelivered
    } else if reason == CLOSED_EXPIRED {
        ReaderKeyEscrowError::ResultExpired
    } else {
        ReaderKeyEscrowError::Store
    }
}

/// Liest ohne Nebenwirkung: das Ergebnis und seinen Ablauf, oder den Grund,
/// warum es keines gibt.
fn read_stored_result(
    database: &EncryptedDatabase,
    authorization: ObjectHash,
) -> Result<(StoredReaderKeyEscrowResult, i64), ReaderKeyEscrowError> {
    let store = |_| ReaderKeyEscrowError::Store;
    let opening = database
        .query_row(
            "SELECT escrow_object_hash,target_transport_key_thumbprint FROM reader_key_escrow_opening WHERE authorization_object_hash=?1",
            &[blob(authorization.as_bytes())],
        )
        .map_err(store)?
        .ok_or(ReaderKeyEscrowError::ResultMissing)?;
    if let Some(closed) = database
        .query_row(
            "SELECT reason FROM reader_key_escrow_result_closure WHERE authorization_object_hash=?1",
            &[blob(authorization.as_bytes())],
        )
        .map_err(store)?
    {
        return Err(closure_error(closed.integer(0).map_err(store)?));
    }
    let result = database
        .query_row(
            "SELECT target_transport_key_thumbprint,exact_envelope,expires_at_ms FROM reader_key_escrow_result WHERE authorization_object_hash=?1",
            &[blob(authorization.as_bytes())],
        )
        .map_err(store)?
        .ok_or(ReaderKeyEscrowError::ResultMissing)?;
    let escrow = ObjectHash::try_from(opening.blob(0).map_err(store)?)
        .map_err(|_| ReaderKeyEscrowError::Store)?;
    let thumbprint = KeyThumbprint::try_from(opening.blob(1).map_err(store)?)
        .map_err(|_| ReaderKeyEscrowError::Store)?;
    let exact_envelope = result.blob(1).map_err(store)?.to_vec();
    let envelope = decode_reader_key_escrow_envelope(&exact_envelope)
        .map_err(|_| ReaderKeyEscrowError::Store)?;
    if result.blob(0).map_err(store)? != thumbprint.as_bytes()
        || envelope.restore_context.authorization_object_hash != authorization
        || envelope.restore_context.escrow_object_hash != escrow
        || envelope.restore_context.target_transport_key_thumbprint != thumbprint
    {
        // Ein zerrissener Zustand bleibt ein ausdrücklicher Fehlschlag.
        return Err(ReaderKeyEscrowError::Store);
    }
    Ok((
        StoredReaderKeyEscrowResult {
            authorization_object_hash: authorization,
            escrow_object_hash: escrow,
            target_transport_key_thumbprint: thumbprint,
            exact_envelope,
            envelope,
        },
        result.integer(2).map_err(store)?,
    ))
}

impl EscrowOpeningLedger for ReaderKeyEscrowLedger<'_> {
    fn consume(
        &self,
        authorization: &VerifiedReaderKeyEscrowRecoveryAuthorization,
        transport: &AuthorizedEscrowTransportKey,
    ) -> Result<ConsumptionReceipt, ReaderKeyEscrowError> {
        let now = (self.clock)()?;
        let receipt = ConsumptionReceipt::new(authorization, transport, now);
        let prepared = self.prepare(TypedLocalAuditEvent::reader_key_escrow_consumed(
            receipt.escrow_object_hash(),
            receipt.authorization_object_hash(),
            receipt.target_transport_key_thumbprint(),
        ))?;
        self.database
            .transaction(|tx| {
                for key in authorization.replay_keys() {
                    if key.organization_id() != self.organization_id() {
                        return Err(Tx(ReaderKeyEscrowError::Trust(TrustError::ActionMismatch)));
                    }
                    let (dimension, value) = match key.dimension() {
                        AdminAuthorizationReplayDimension::AuthorizationId(id) => {
                            (0, blob(id.as_bytes()))
                        }
                        AdminAuthorizationReplayDimension::Nonce(nonce) => (1, blob(&nonce)),
                    };
                    let inserted = tx.execute(
                        "INSERT INTO operator_admin_replay(organization_id,dimension,replay_value) VALUES(?1,?2,?3) ON CONFLICT(organization_id,dimension,replay_value) DO NOTHING",
                        &[blob(key.organization_id().as_bytes()), StoreValue::Integer(dimension), value],
                    )?;
                    if inserted != 1 {
                        return Err(Tx(ReaderKeyEscrowError::Trust(TrustError::AuthReplay)));
                    }
                }
                SqliteLocalAuditRepository::append_prepared_in(tx, &prepared)
                    .map_err(|_| Tx(ReaderKeyEscrowError::Audit))?;
                tx.execute(
                    "INSERT INTO reader_key_escrow_opening(authorization_object_hash,organization_id,escrow_object_hash,target_transport_key_thumbprint,consumed_at_ms,consume_audit_event_id) VALUES(?1,?2,?3,?4,?5,?6)",
                    &[
                        blob(receipt.authorization_object_hash().as_bytes()),
                        blob(self.organization_id().as_bytes()),
                        blob(receipt.escrow_object_hash().as_bytes()),
                        blob(receipt.target_transport_key_thumbprint().as_bytes()),
                        StoreValue::Integer(now.get()),
                        blob(prepared.id().as_bytes()),
                    ],
                )?;
                Ok(())
            })
            .map_err(|Tx(error)| error)?;
        Ok(receipt)
    }

    fn store_result(
        &self,
        receipt: &ConsumptionReceipt,
        envelope: &ReaderKeyEscrowEnvelopeV1,
    ) -> Result<(), ReaderKeyEscrowError> {
        let exact =
            encode_reader_key_escrow_envelope(envelope).map_err(|_| ReaderKeyEscrowError::Store)?;
        let now = (self.clock)()?;
        self.database
            .execute(
                "INSERT INTO reader_key_escrow_result(authorization_object_hash,target_transport_key_thumbprint,exact_envelope,stored_at_ms,expires_at_ms) VALUES(?1,?2,?3,?4,?5)",
                &[
                    blob(receipt.authorization_object_hash().as_bytes()),
                    blob(receipt.target_transport_key_thumbprint().as_bytes()),
                    blob(&exact),
                    StoreValue::Integer(now.get()),
                    StoreValue::Integer(
                        now.get()
                            .checked_add(READER_KEY_ESCROW_RESULT_RETENTION_MS)
                            .ok_or(ReaderKeyEscrowError::Store)?,
                    ),
                ],
            )
            .map_err(|_| ReaderKeyEscrowError::Store)?;
        Ok(())
    }

    fn book_failure(&self, receipt: &ConsumptionReceipt) {
        // Bestmöglich: der ursprüngliche Fehler geht nie verloren, und die
        // Verbrauchszeile steht ohnehin.
        let _ = self.audit.record_signed(
            AuditActorProof::OperatorSession(self.proof),
            TypedLocalAuditEvent::reader_key_escrow_failed(
                receipt.escrow_object_hash(),
                receipt.authorization_object_hash(),
                receipt.target_transport_key_thumbprint(),
            ),
        );
    }
}

/// Was eine Öffnung oder Abholung berichtet — nur Hashes.
#[derive(Clone, Copy)]
pub struct DeliveredReaderKeyEscrow {
    pub authorization_object_hash: ObjectHash,
    pub envelope_file_hash: ObjectHash,
}

fn require_recovery_operator(runtime: &OperatorRuntime) -> Result<(), ReaderKeyEscrowError> {
    if runtime.config().role != OperatorRoleV1::OrganizationAdmin
        || runtime.config().purpose != ReauthPurpose::ReaderKeyEscrowRecovery
    {
        return Err(ReaderKeyEscrowError::Operator);
    }
    Ok(())
}

/// Der Verfall beim Start jedes Escrow-Kommandos (Entscheidung D5, Profil §8):
/// löscht jedes verfallene Ergebnis, BEVOR geprüft oder reauthentifiziert
/// wird — auch wenn beides danach scheitert.
///
/// Es gibt dafür keinen frischen Bedienernachweis. Gebucht wird deshalb unter
/// dem geprüften Gerät dieser Laufzeit (am gewählten Kopf nachgeprüft) und
/// ohne Bedienerbindung, mit der Gerätesignatur — wie die Gerätezeilen des
/// Bindungslebenszyklus (`operator_host`). Aktion und Ausgang sind die des
/// Verfalls: 14/`failed`.
///
/// # Errors
///
/// `Operator`, wenn das Gerät am gewählten Kopf nicht mehr trägt; `Store`
/// oder `Audit`, dann bleibt der Zustand des betroffenen Ergebnisses
/// unverändert.
pub fn purge_expired_reader_key_escrow_results(
    runtime: &OperatorRuntime,
) -> Result<usize, ReaderKeyEscrowError> {
    let device = runtime
        .local_device()
        .unbound_audit_actor(runtime.head())
        .map_err(|_| ReaderKeyEscrowError::Operator)?;
    let audit = runtime.audit_service();
    purge_expired_results(runtime.database(), wall_clock()?, &|event| {
        audit
            .prepare_signed(AuditActorProof::AuthenticatedDevice(&device), event)
            .map_err(|_| ReaderKeyEscrowError::Audit)
    })
}

/// Der Reauthentifizierungskontext: der Objekthash der Restore-Bindung, die
/// Autorisierungs-Objekthash und Transport-Abdruck trägt (Profil §6
/// Schritt 3). Die Domänentrennung kommt aus dem Suite-Literal im CBOR.
fn restore_context_hash(context: &ReaderKeyEscrowRestoreContextV1) -> Hash32 {
    Hash32::try_from(object_hash(&context.encode()).as_bytes().as_slice())
        .expect("an object hash is 32 bytes")
}

fn session_current(
    runtime: &OperatorRuntime,
    proof: &OperatorSessionProof,
) -> Result<(), ReaderKeyEscrowError> {
    runtime
        .ensure_current()
        .map_err(|_| ReaderKeyEscrowError::Operator)?;
    if !proof.is_valid_at(ReauthPurpose::ReaderKeyEscrowRecovery, wall_clock()?) {
        return Err(ReaderKeyEscrowError::Operator);
    }
    Ok(())
}

fn reauthenticate(
    runtime: &OperatorRuntime,
    context: Hash32,
) -> Result<crate::VerifiedOperatorSession, ReaderKeyEscrowError> {
    let session = runtime
        .reauthenticate_for_context(ReauthPurpose::ReaderKeyEscrowRecovery, context)
        .map_err(|_| ReaderKeyEscrowError::Operator)?;
    if session.proof().context_hash() != Some(context) {
        return Err(ReaderKeyEscrowError::Operator);
    }
    Ok(session)
}

fn deliver(
    ledger: &ReaderKeyEscrowLedger<'_>,
    authorization: ObjectHash,
    outbox: &Path,
) -> Result<DeliveredReaderKeyEscrow, ReaderKeyEscrowError> {
    let stored = ledger.stored_result(authorization)?;
    let envelope_file_hash = write_escrow_outbox(
        outbox,
        ReaderKeyEscrowTransferKindV1::Envelope,
        stored.exact_envelope(),
    )?;
    ledger.complete_delivery(&stored)?;
    Ok(DeliveredReaderKeyEscrow {
        authorization_object_hash: authorization,
        envelope_file_hash,
    })
}

/// Zeremonie B: öffnet das Escrow der Autorisierung mit dem Recovery-Schlüssel
/// und liefert den versiegelten Umschlag in den Ausgang.
///
/// Reihenfolge: Rolle und Zweck; Verfall; Prüfung der Autorisierung über
/// `ea-trust` gegen den gewählten Kopf und seine exakte Sequenz; genau eine
/// passende Transportdatei, geprüft über `require_target_transport_key`;
/// frische Reauthentifizierung mit dem Restore-Kontext; Öffnung (Verbrauch
/// vor Provider); Auslieferung.
///
/// # Errors
///
/// Jeder [`ReaderKeyEscrowError`]; vor dem Verbrauch ist nichts verbraucht.
pub fn open_reader_key_escrow(
    runtime: &OperatorRuntime,
    recovery_key: &dyn ReaderKeyEscrowKem,
    exact_authorization: &[u8],
    inbox: &Path,
    outbox: &Path,
) -> Result<DeliveredReaderKeyEscrow, ReaderKeyEscrowError> {
    require_recovery_operator(runtime)?;
    purge_expired_reader_key_escrow_results(runtime)?;
    let authorization = verify_reader_key_escrow_recovery_authorization(
        runtime.trust(),
        runtime.head(),
        exact_authorization,
        wall_clock()?,
    )?;
    let transport = authorization
        .require_target_transport_key(read_transport_key(
            inbox,
            runtime.anchor().organization_id(),
            authorization.escrow().object_hash(),
        )?)
        .map_err(|_| ReaderKeyEscrowError::TransportMismatch)?;
    let session = reauthenticate(
        runtime,
        restore_context_hash(&authorization.restore_context()),
    )?;
    let audit = runtime.audit_service();
    let ledger = ReaderKeyEscrowLedger::new(runtime.database(), &audit, session.proof());
    let current = || session_current(runtime, session.proof());
    ReaderKeyEscrowOpeningService::new(recovery_key, &ledger, &current)
        .open(&authorization, &transport)?;
    deliver(&ledger, authorization.object_hash(), outbox)
}

/// Setzt eine abgebrochene Auslieferung fort: dieselbe exakte Autorisierung,
/// frische Reauthentifizierung und eine Transportdatei mit GLEICHEM Abdruck.
/// Das gespeicherte Ergebnis wird nie neu versiegelt. Verfallene Ergebnisse
/// löscht sie wie die Öffnung gleich beim Start.
///
/// # Errors
///
/// `ResultMissing`, `ResultDelivered`, `ResultExpired`,
/// `TransportMismatch` (das Ergebnis bleibt dann unverändert) und jeder
/// weitere [`ReaderKeyEscrowError`].
pub fn pickup_reader_key_escrow(
    runtime: &OperatorRuntime,
    exact_authorization: &[u8],
    inbox: &Path,
    outbox: &Path,
) -> Result<DeliveredReaderKeyEscrow, ReaderKeyEscrowError> {
    require_recovery_operator(runtime)?;
    purge_expired_reader_key_escrow_results(runtime)?;
    let authorization = object_hash(exact_authorization);
    let (stored, _) = read_stored_result(runtime.database(), authorization)?;
    stored.require_transport_key(read_transport_key(
        inbox,
        runtime.anchor().organization_id(),
        stored.restore_context().escrow_object_hash,
    )?)?;
    let session = reauthenticate(runtime, restore_context_hash(stored.restore_context()))?;
    let audit = runtime.audit_service();
    let ledger = ReaderKeyEscrowLedger::new(runtime.database(), &audit, session.proof());
    session_current(runtime, session.proof())?;
    deliver(&ledger, authorization, outbox)
}
