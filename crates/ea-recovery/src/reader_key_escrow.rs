//! Die zweite getypte Operation des Recovery-Ports: die Öffnung eines
//! Reader-Key-Escrows (Profil §6, DRK-458).
//!
//! [`crate::RecoveryKem`] ist auf `GrantV1` typisiert; ein Escrow ist kein
//! Grant. [`ReaderKeyEscrowKem`] ist deshalb eine EIGENE Operation, und sie
//! öffnet ausschließlich ein [`ConsumedEscrowOpening`] — einen Wert, den nur
//! [`ReaderKeyEscrowOpeningService`] baut, und zwar erst NACHDEM der
//! [`EscrowOpeningLedger`] den Verbrauch bestätigt hat. Die Typordnung ist
//! damit „Verbrauch vor Provider" (Profil §6 Schritt 4).
//!
//! Die Reihenfolge in [`ReaderKeyEscrowOpeningService::open`] ist Vertrag:
//!
//! 1. Abdruck des Recovery-Schlüssels gegen den geprüften Core — ein falsch
//!    gesteckter Token verbrennt keine Zwei-Approver-Autorisierung. Das
//!    Öffnen des Tokens und das Lesen seines öffentlichen Schlüssels liegen
//!    davor; als Providerzugriff im Sinne von §6 gilt die PRIVATE Operation
//!    (Entscheidung D2).
//! 2. Sitzung aktuell.
//! 3. Verbrauch (atomar mit dem signierten Audit, im Ledger).
//! 4. Sitzung aktuell — sonst ist die Autorisierung verbrannt.
//! 5. Private Operation.
//! 6. Gegenprobe gegen den KEM des Reader-Zertifikats.
//! 7. Versiegelung an den geprüften Ziel-Transport-Schlüssel; der Klartext
//!    fällt danach.
//! 8. Dauerhaftes verschlüsseltes Ergebnis.
//!
//! Jede Prüfung des Trust-Materials läuft über die geprüften Typen aus
//! `ea-trust`; dieses Modul vergleicht selbst keine Trust-Felder.

use core::fmt;

use ea_crypto::{
    CanonicalPublicCoseKey, CryptoError, HpkeRecipientPrivateKey, HpkeRecipientPublicKey,
    HpkeSealed, SecretBytes, hpke_aad, hpke_info, hpke_open, hpke_seal,
};
use ea_format::ReaderKeyEscrowEnvelopeV1;
use ea_trust::{
    AuthorizedEscrowTransportKey, TrustError, VerifiedReaderKeyEscrow,
    VerifiedReaderKeyEscrowRecoveryAuthorization,
};
use ea_types::{KeyThumbprint, ObjectHash, UnixMillis};

/// Der EINE Fehlerbegriff der Escrow-Zeremonien. ea-admin und die CLI reichen
/// seine Codes durch.
///
/// Die Formatierung nennt ausschließlich den stabilen Code — kein Hash, kein
/// Pfad, kein Schlüsselmaterial.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ReaderKeyEscrowError {
    /// Ein Befund des Trust-Kerns, unverändert durchgereicht.
    Trust(TrustError),
    /// Rolle, Zweck, Wiederanmeldungskontext oder Sitzung passen nicht.
    Operator,
    /// Eine Übergabedatei ist nicht lesbar, nicht eindeutig oder falsch
    /// benannt.
    TransferFile,
    /// Die Transportdatei passt nicht zur Autorisierung, oder eine Abholung
    /// nennt einen anderen Schlüssel.
    TransportMismatch,
    /// Der Recovery-Schlüssel ist nicht der, an den das Escrow gekapselt ist.
    RecoveryKey,
    /// Der entschlüsselte Schlüssel ist nicht der KEM des Reader-Zertifikats.
    KemMismatch,
    /// Die private Operation oder die Versiegelung ist gescheitert.
    Crypto,
    /// Die signierte Auditzeile ließ sich nicht schreiben.
    Audit,
    /// Der dauerhafte Zustand ist unlesbar, zerrissen oder widersprüchlich.
    Store,
    /// Die Ausgabedatei ließ sich nicht schreiben.
    Output,
    /// Verbraucht, aber ohne dauerhaftes Ergebnis: nur eine frische
    /// Autorisierung hilft.
    ResultMissing,
    /// Das Ergebnis wurde schon abgeholt und ist gelöscht.
    ResultDelivered,
    /// Das Ergebnis ist nach 86 400 000 ms verfallen und gelöscht.
    ResultExpired,
    /// Das Paket der Zeremonie A liegt außerhalb seines 300-s-Fensters.
    PackageStale,
    /// Zu Reader-Zertifikat oder Person liegt schon ein anderes Escrow vor.
    PublicationConflict,
    /// Die Cutover-Vorbedingung (aktive v1.1-`webBundleRelease`) ist nicht
    /// erfüllt.
    CutoverNotReady,
}

impl ReaderKeyEscrowError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Trust(error) => error.code(),
            Self::Operator => "EA-ESCROW-OPERATOR-UNAUTHORIZED",
            Self::TransferFile => "EA-ESCROW-TRANSFER-FILE",
            Self::TransportMismatch => "EA-ESCROW-TRANSPORT-MISMATCH",
            Self::RecoveryKey => "EA-ESCROW-RECOVERY-KEY",
            Self::KemMismatch => "EA-ESCROW-KEM-MISMATCH",
            Self::Crypto => "EA-ESCROW-CRYPTO-FAILED",
            Self::Audit => "EA-ESCROW-AUDIT-FAILED",
            Self::Store => "EA-ESCROW-STORE-FAILED",
            Self::Output => "EA-ESCROW-OUTPUT-IO",
            Self::ResultMissing => "EA-ESCROW-RESULT-MISSING",
            Self::ResultDelivered => "EA-ESCROW-RESULT-DELIVERED",
            Self::ResultExpired => "EA-ESCROW-RESULT-EXPIRED",
            Self::PackageStale => "EA-ESCROW-PACKAGE-STALE",
            Self::PublicationConflict => "EA-ESCROW-PUBLICATION-CONFLICT",
            Self::CutoverNotReady => "EA-ESCROW-CUTOVER-NOT-READY",
        }
    }

    /// Der Prozess-Exitcode der CLI (Bauplan §3.5).
    #[must_use]
    pub const fn exit_code(self) -> crate::ExitCode {
        use crate::ExitCode;
        match self {
            Self::TransferFile => ExitCode::Integrity,
            Self::RecoveryKey | Self::KemMismatch | Self::Crypto => ExitCode::Key,
            Self::Audit | Self::Store | Self::Output => ExitCode::Io,
            Self::CutoverNotReady => ExitCode::Unsupported,
            Self::Trust(_)
            | Self::Operator
            | Self::TransportMismatch
            | Self::ResultMissing
            | Self::ResultDelivered
            | Self::ResultExpired
            | Self::PackageStale
            | Self::PublicationConflict => ExitCode::Trust,
        }
    }
}

impl fmt::Display for ReaderKeyEscrowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReaderKeyEscrowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ReaderKeyEscrowError {}

impl From<TrustError> for ReaderKeyEscrowError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

/// Die Bestätigung des Ledgers, dass eine Öffnungsautorisierung dauerhaft
/// verbraucht ist — atomar mit ihrem signierten Audit.
///
/// Sie entsteht nur aus den GEPRÜFTEN Typen und trägt deshalb genau deren
/// Hashes: Escrow, Autorisierung und Transport-Abdruck.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ConsumptionReceipt {
    escrow_object_hash: ObjectHash,
    authorization_object_hash: ObjectHash,
    target_transport_key_thumbprint: KeyThumbprint,
    consumed_at: UnixMillis,
}

impl ConsumptionReceipt {
    /// Die Quittung eines Ledgers für genau diese Autorisierung und diesen
    /// Transport-Schlüssel.
    #[must_use]
    pub fn new(
        authorization: &VerifiedReaderKeyEscrowRecoveryAuthorization,
        transport: &AuthorizedEscrowTransportKey,
        consumed_at: UnixMillis,
    ) -> Self {
        Self {
            escrow_object_hash: authorization.escrow().object_hash(),
            authorization_object_hash: authorization.object_hash(),
            target_transport_key_thumbprint: transport.public_key().thumbprint(),
            consumed_at,
        }
    }

    #[must_use]
    pub const fn escrow_object_hash(&self) -> ObjectHash {
        self.escrow_object_hash
    }

    #[must_use]
    pub const fn authorization_object_hash(&self) -> ObjectHash {
        self.authorization_object_hash
    }

    #[must_use]
    pub const fn target_transport_key_thumbprint(&self) -> KeyThumbprint {
        self.target_transport_key_thumbprint
    }

    #[must_use]
    pub const fn consumed_at(&self) -> UnixMillis {
        self.consumed_at
    }
}

impl fmt::Debug for ConsumptionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsumptionReceipt(<consumed>)")
    }
}

/// Eine verbrauchte, geprüfte Öffnung — der EINZIGE Eingang der privaten
/// Operation.
///
/// Nur [`ReaderKeyEscrowOpeningService`] baut diesen Wert, und erst nachdem
/// der Ledger den Verbrauch bestätigt hat:
///
/// ```compile_fail
/// fn forge<'a>(
///     authorization: &'a ea_trust::VerifiedReaderKeyEscrowRecoveryAuthorization,
///     receipt: &'a ea_recovery::ConsumptionReceipt,
/// ) -> ea_recovery::ConsumedEscrowOpening<'a> {
///     ea_recovery::ConsumedEscrowOpening { authorization, receipt }
/// }
/// ```
pub struct ConsumedEscrowOpening<'a> {
    authorization: &'a VerifiedReaderKeyEscrowRecoveryAuthorization,
    receipt: &'a ConsumptionReceipt,
}

impl ConsumedEscrowOpening<'_> {
    /// Das voll geprüfte Escrow, das geöffnet werden darf.
    #[must_use]
    pub const fn escrow(&self) -> &VerifiedReaderKeyEscrow {
        self.authorization.escrow()
    }

    /// Die Quittung des Verbrauchs.
    #[must_use]
    pub const fn receipt(&self) -> &ConsumptionReceipt {
        self.receipt
    }
}

/// Die zweite getypte Recovery-Operation: öffnet NUR ein verbrauchtes,
/// geprüftes Escrow. Kein Digest, kein freies Chiffrat.
pub trait ReaderKeyEscrowKem {
    /// Der Abdruck des öffentlichen Recovery-Schlüssels — ohne private
    /// Operation.
    ///
    /// # Errors
    ///
    /// Jeder Befund des Providers.
    fn key_thumbprint(&self) -> Result<KeyThumbprint, CryptoError>;

    /// Entkapselt den Reader-KEM aus dem Escrow.
    ///
    /// # Errors
    ///
    /// Jeder Befund der Entkapselung.
    fn open_reader_key_escrow(
        &self,
        opening: &ConsumedEscrowOpening<'_>,
    ) -> Result<SecretBytes<32>, CryptoError>;
}

/// Die EINE Kontextbildung für jede Implementierung: das Chiffrat aus dem
/// geprüften Core, `info` und AAD in der Hausform über dem abgeleiteten
/// Escrow-Kontext (Profil §4).
///
/// # Errors
///
/// [`CryptoError`], wenn der Kapselungswert kein Punkt der Kurve ist.
pub fn reader_key_escrow_envelope(
    escrow: &VerifiedReaderKeyEscrow,
) -> Result<(HpkeSealed, Vec<u8>, Vec<u8>), CryptoError> {
    let context = escrow.hpke_context().encode();
    let core = escrow.core();
    Ok((
        HpkeSealed::from_parts(core.encapsulated_key, core.encrypted_reader_kem_key)?,
        hpke_info(&context),
        hpke_aad(&context),
    ))
}

impl ReaderKeyEscrowKem for HpkeRecipientPrivateKey {
    fn key_thumbprint(&self) -> Result<KeyThumbprint, CryptoError> {
        Ok(CanonicalPublicCoseKey::x25519(*self.public_key().as_bytes())?.thumbprint())
    }

    fn open_reader_key_escrow(
        &self,
        opening: &ConsumedEscrowOpening<'_>,
    ) -> Result<SecretBytes<32>, CryptoError> {
        let (sealed, info, aad) = reader_key_escrow_envelope(opening.escrow())?;
        hpke_open(self, &sealed, &info, &aad)
    }
}

/// Der dauerhafte Zustand der Öffnung — in der nativen Administration das
/// SQLCipher-Ledger (ea-admin).
pub trait EscrowOpeningLedger {
    /// Verbraucht `authorization-id` und `nonce` atomar mit dem signierten
    /// Audit (14/`accepted`) und der Verbrauchszeile.
    ///
    /// # Errors
    ///
    /// `Trust(AuthReplay)` für eine schon verbrauchte Autorisierung, sonst
    /// jeden Befund der Ablage oder des Audits.
    fn consume(
        &self,
        authorization: &VerifiedReaderKeyEscrowRecoveryAuthorization,
        transport: &AuthorizedEscrowTransportKey,
    ) -> Result<ConsumptionReceipt, ReaderKeyEscrowError>;

    /// Legt den versiegelten Umschlag als dauerhaftes Ergebnis ab.
    ///
    /// # Errors
    ///
    /// Jeder Befund der Ablage.
    fn store_result(
        &self,
        receipt: &ConsumptionReceipt,
        envelope: &ReaderKeyEscrowEnvelopeV1,
    ) -> Result<(), ReaderKeyEscrowError>;

    /// Bucht das Scheitern NACH dem Verbrauch (14/`failed`), bestmöglich:
    /// der ursprüngliche Fehler geht nie verloren.
    fn book_failure(&self, receipt: &ConsumptionReceipt);
}

/// Die Öffnung selbst: Verbrauch vor Provider, Gegenprobe, Versiegelung.
pub struct ReaderKeyEscrowOpeningService<'a> {
    kem: &'a dyn ReaderKeyEscrowKem,
    ledger: &'a dyn EscrowOpeningLedger,
    session_current: &'a dyn Fn() -> Result<(), ReaderKeyEscrowError>,
}

impl<'a> ReaderKeyEscrowOpeningService<'a> {
    #[must_use]
    pub fn new(
        kem: &'a dyn ReaderKeyEscrowKem,
        ledger: &'a dyn EscrowOpeningLedger,
        session_current: &'a dyn Fn() -> Result<(), ReaderKeyEscrowError>,
    ) -> Self {
        Self {
            kem,
            ledger,
            session_current,
        }
    }

    /// Öffnet das Escrow der Autorisierung und gibt allein den versiegelten
    /// Umschlag zurück.
    ///
    /// # Errors
    ///
    /// [`ReaderKeyEscrowError::RecoveryKey`] vor jedem Verbrauch; nach dem
    /// Verbrauch `Operator`, `Crypto`, `KemMismatch` oder `Store` — jeweils
    /// mit gebuchtem Scheitern und verbrannter Autorisierung.
    pub fn open(
        &self,
        authorization: &VerifiedReaderKeyEscrowRecoveryAuthorization,
        transport: &AuthorizedEscrowTransportKey,
    ) -> Result<ReaderKeyEscrowEnvelopeV1, ReaderKeyEscrowError> {
        let escrow = authorization.escrow();
        if self
            .kem
            .key_thumbprint()
            .map_err(|_| ReaderKeyEscrowError::RecoveryKey)?
            != escrow.core().recovery_kem_key_thumbprint
        {
            return Err(ReaderKeyEscrowError::RecoveryKey);
        }
        let CanonicalPublicCoseKey::X25519(transport_public) = *transport.public_key() else {
            return Err(ReaderKeyEscrowError::TransportMismatch);
        };
        (self.session_current)()?;
        let receipt = self.ledger.consume(authorization, transport)?;
        if receipt != ConsumptionReceipt::new(authorization, transport, receipt.consumed_at()) {
            // Eine Quittung über eine andere Autorisierung ist kein Verbrauch
            // DIESER; der Provider wird nicht angesprochen.
            return Err(ReaderKeyEscrowError::Store);
        }
        let failed = |error: ReaderKeyEscrowError| {
            self.ledger.book_failure(&receipt);
            error
        };
        (self.session_current)().map_err(|_| failed(ReaderKeyEscrowError::Operator))?;
        let opening = ConsumedEscrowOpening {
            authorization,
            receipt: &receipt,
        };
        let secret = self
            .kem
            .open_reader_key_escrow(&opening)
            .map_err(|_| failed(ReaderKeyEscrowError::Crypto))?;
        let derived = secret
            .with_exposed(|bytes| HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(*bytes)))
            .and_then(|key| CanonicalPublicCoseKey::x25519(*key.public_key().as_bytes()))
            .map_err(|_| failed(ReaderKeyEscrowError::KemMismatch))?;
        escrow
            .require_reader_kem_public_key(&derived)
            .map_err(|_| failed(ReaderKeyEscrowError::KemMismatch))?;
        let restore_context = authorization.restore_context();
        let context = restore_context.encode();
        let sealed = HpkeRecipientPublicKey::from_bytes(transport_public)
            .and_then(|recipient| {
                hpke_seal(
                    &recipient,
                    &secret,
                    &hpke_info(&context),
                    &hpke_aad(&context),
                )
            })
            .map_err(|_| failed(ReaderKeyEscrowError::Crypto))?;
        drop(secret);
        let envelope = ReaderKeyEscrowEnvelopeV1 {
            restore_context,
            encapsulated_key: *sealed.encapsulated_key(),
            sealed_reader_kem_key: *sealed.wrapped_cek(),
        };
        self.ledger
            .store_result(&receipt, &envelope)
            .map_err(failed)?;
        Ok(envelope)
    }
}
