//! Der getypte Ereignisbegriff und der Nachweis, unter dem er entsteht.

use core::fmt;

use ea_crypto::CryptoError;
use ea_format::{
    FormatError, GenericAuditContextV1, LocalAuditActionV1, LocalAuditOutcomeV1,
    ReaderKeyEscrowContextV1,
};
use ea_key_provider::KeyError;
use ea_local_store::StoreError;
use ea_operator::OperatorSessionProof;
use ea_types::{DeviceId, EventId, KeyThumbprint, ObjectHash, OrganizationId};

/// Ein Fehlschlag an der Auditgrenze.
///
/// Die Formatierung nennt AUSSCHLIESSLICH den stabilen Code. Sie traegt keinen
/// Ereignisinhalt, keinen Bezeichner und keinen Hash — eine Auditzeile, die
/// ueber ihre eigene Fehlermeldung in eine Protokolldatei sickert, waere
/// derselbe Austritt durch eine bequemere Tuer.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuditError {
    /// Der Praesenznachweis ist abgelaufen oder durch eine Sperre entwertet.
    SessionExpired,
    /// Es gibt unter dieser Kennung keine Auditzeile.
    NotFound,
    /// Die lokale Zufallsquelle hat kein Material geliefert.
    LocalRng,
    /// Die Kodierung oder die COSE-Pruefung des Ereignisses ist gescheitert.
    Encoding,
    /// Ein Vorgang der Kryptografieschicht ist gescheitert.
    Crypto(CryptoError),
    /// Der Schluesselport hat abgelehnt.
    Key(KeyError),
    /// Die Ablage hat abgelehnt.
    Store(StoreError),
}

impl AuditError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SessionExpired => "EA-AUDIT-SESSION-EXPIRED",
            Self::NotFound => "EA-AUDIT-NOT-FOUND",
            Self::LocalRng => "EA-AUDIT-LOCAL-RNG",
            Self::Encoding => "EA-AUDIT-ENCODING",
            Self::Crypto(error) => error.code(),
            Self::Key(error) => error.code(),
            Self::Store(error) => error.code(),
        }
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for AuditError {}

impl From<FormatError> for AuditError {
    fn from(_: FormatError) -> Self {
        Self::Encoding
    }
}

impl From<KeyError> for AuditError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<StoreError> for AuditError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<CryptoError> for AuditError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

/// Ein geprueftes Geraet ohne frischen Bedienernachweis.
///
/// Der Arm existiert ausschliesslich, damit die Anmeldung und die
/// GESCHEITERTE Wiederanmeldung ueberhaupt festgehalten werden koennen — in
/// beiden Faellen wird kein neuer Bedienernachweis ausgestellt. Er traegt den
/// geprueften Geraetesigner und einen bereits BEKANNTEN Bindungshash, niemals
/// einen ungeprueften Kontowert: es gibt keinen Konstruktor, der einen
/// Kontobezeichner oder einen Benutzernamen annimmt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthenticatedDevice {
    organization_id: OrganizationId,
    device_id: DeviceId,
    signer_certificate_object_hash: ObjectHash,
    known_binding_object_hash: Option<ObjectHash>,
}

impl AuthenticatedDevice {
    #[must_use]
    pub const fn new(
        organization_id: OrganizationId,
        device_id: DeviceId,
        signer_certificate_object_hash: ObjectHash,
        known_binding_object_hash: Option<ObjectHash>,
    ) -> Self {
        Self {
            organization_id,
            device_id,
            signer_certificate_object_hash,
            known_binding_object_hash,
        }
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    #[must_use]
    pub const fn signer_certificate_object_hash(&self) -> ObjectHash {
        self.signer_certificate_object_hash
    }

    #[must_use]
    pub const fn known_binding_object_hash(&self) -> Option<ObjectHash> {
        self.known_binding_object_hash
    }
}

impl fmt::Debug for AuthenticatedDevice {
    /// Undurchsichtig: die Bezeichner dieses Bauwerks tragen keine
    /// Formatierung, und ein Geraetebezeichner gehoert nicht in eine
    /// Protokollzeile.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedDevice(<verified>)")
    }
}

/// Der Nachweis, unter dem eine Auditzeile entsteht — GESCHLOSSEN.
///
/// Drei Arme, mehr gibt es nicht. Ein vierter, der „irgendein Aufrufer" hiesse,
/// wuerde die Zurechenbarkeit der ganzen Familie aufloesen.
pub enum AuditActorProof<'a> {
    /// Ein frischer Bedienernachweis. Fuer jede erfolgreiche privilegierte
    /// Handlung erforderlich.
    OperatorSession(&'a OperatorSessionProof),
    /// Ein geprueftes Geraet ohne frischen Bedienernachweis.
    AuthenticatedDevice(&'a AuthenticatedDevice),
    /// Der Zustand, in den ein abgelaufener oder durch die Sperre entwerteter
    /// Nachweis zusammenfaellt.
    Expired,
}

/// Das getypte Ereignis: eine Aktion und ein Ausgang.
///
/// Der Kontext REIST IN DER AKTION — `ea_format::LocalAuditActionV1` bindet ihn
/// variantenweise, und diese Crate deklariert keinen zweiten Kontexttyp.
pub struct TypedLocalAuditEvent {
    pub action: LocalAuditActionV1,
    pub outcome: LocalAuditOutcomeV1,
}

impl TypedLocalAuditEvent {
    /// Die gescheiterte Anmeldung, ohne jeden Bezug auf ein Subjekt.
    ///
    /// Der Konstruktor des Pfades, auf dem [`AuditActorProof::Expired`]
    /// abgewiesen wird: er nennt kein Subjekt, weil an dieser Stelle keines
    /// geprueft ist.
    #[must_use]
    pub const fn login_failed() -> Self {
        Self {
            action: LocalAuditActionV1::Login(GenericAuditContextV1::new(None)),
            outcome: LocalAuditOutcomeV1::Failed,
        }
    }

    /// Die Abweisung einer abgelaufenen Bedienersitzung (DRK-282, AK 53).
    ///
    /// Eine eigene Aktion (`sessionExpired`, Code 12) statt einer
    /// `reauthFailure`: nur so ist der Ablauf im Audit als Ablauf erkennbar.
    /// Der Kontext nennt höchstens den Hash einer bereits BEKANNTEN Bindung —
    /// nie Konto, Anzeigename, Funktion oder Salt. Der Ausgang ist immer
    /// `failed`, weil die Sitzung abgewiesen wurde.
    #[must_use]
    pub const fn session_expired(known_binding_object_hash: Option<ObjectHash>) -> Self {
        Self {
            action: LocalAuditActionV1::SessionExpired(GenericAuditContextV1::new(
                known_binding_object_hash,
            )),
            outcome: LocalAuditOutcomeV1::Failed,
        }
    }

    /// Die Publikation eines Reader-Key-Escrows (DRK-458, Aktion 13).
    ///
    /// Immer `completed`: die Zeile entsteht atomar mit dem Verbrauch der
    /// Freigabe und der Publikationszeile, eine gescheiterte Publikation
    /// hinterlässt keinen Verbrauch. Der Kontext trägt den Objekthash der
    /// `webBundleRelease`, die die Cutover-Vorbedingung erfüllt, und keinen
    /// Transport-Abdruck.
    #[must_use]
    pub const fn reader_key_escrow_published(
        escrow_object_hash: ObjectHash,
        approval_object_hash: ObjectHash,
        bundle_release_object_hash: ObjectHash,
    ) -> Self {
        Self {
            action: LocalAuditActionV1::ReaderKeyEscrowPublication(
                ReaderKeyEscrowContextV1::publication(
                    escrow_object_hash,
                    approval_object_hash,
                    bundle_release_object_hash,
                ),
            ),
            outcome: LocalAuditOutcomeV1::Completed,
        }
    }

    /// Der Verbrauch einer Öffnungsautorisierung (Aktion 14, `accepted`) —
    /// gebucht VOR jedem Zugriff auf den privaten Recovery-Schlüssel.
    #[must_use]
    pub const fn reader_key_escrow_consumed(
        escrow_object_hash: ObjectHash,
        authorization_object_hash: ObjectHash,
        target_transport_key_thumbprint: KeyThumbprint,
    ) -> Self {
        Self::reader_key_escrow_opening(
            escrow_object_hash,
            authorization_object_hash,
            target_transport_key_thumbprint,
            LocalAuditOutcomeV1::Accepted,
        )
    }

    /// Die erste erfolgreiche Abholung des versiegelten Umschlags (Aktion 14,
    /// `completed`); das dauerhafte Ergebnis ist damit gelöscht.
    #[must_use]
    pub const fn reader_key_escrow_delivered(
        escrow_object_hash: ObjectHash,
        authorization_object_hash: ObjectHash,
        target_transport_key_thumbprint: KeyThumbprint,
    ) -> Self {
        Self::reader_key_escrow_opening(
            escrow_object_hash,
            authorization_object_hash,
            target_transport_key_thumbprint,
            LocalAuditOutcomeV1::Completed,
        )
    }

    /// Eine Öffnung, die nach dem Verbrauch scheiterte oder deren Ergebnis
    /// verfiel (Aktion 14, `failed`). Die Autorisierung ist verbrannt.
    #[must_use]
    pub const fn reader_key_escrow_failed(
        escrow_object_hash: ObjectHash,
        authorization_object_hash: ObjectHash,
        target_transport_key_thumbprint: KeyThumbprint,
    ) -> Self {
        Self::reader_key_escrow_opening(
            escrow_object_hash,
            authorization_object_hash,
            target_transport_key_thumbprint,
            LocalAuditOutcomeV1::Failed,
        )
    }

    const fn reader_key_escrow_opening(
        escrow_object_hash: ObjectHash,
        authorization_object_hash: ObjectHash,
        target_transport_key_thumbprint: KeyThumbprint,
        outcome: LocalAuditOutcomeV1,
    ) -> Self {
        Self {
            action: LocalAuditActionV1::ReaderKeyEscrowOpening(ReaderKeyEscrowContextV1::opening(
                escrow_object_hash,
                authorization_object_hash,
                target_transport_key_thumbprint,
            )),
            outcome,
        }
    }
}

/// Eine geschriebene, signierte Auditzeile.
///
/// Der Konstruktor bleibt PRIVAT — nach dem Stufe-1-Muster fuer nachweisende
/// Typen. Ein frei gebautes `SignedLocalAuditEvent` waere eine Auditzeile, die
/// nie signiert und nie gebucht wurde.
pub struct SignedLocalAuditEvent {
    id: EventId,
    exact_bytes: Vec<u8>,
}

impl SignedLocalAuditEvent {
    pub(crate) const fn sealed(id: EventId, exact_bytes: Vec<u8>) -> Self {
        Self { id, exact_bytes }
    }

    /// Die exakten `local-audit-event-v1`-Bytes.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }
}

impl fmt::Debug for SignedLocalAuditEvent {
    /// Undurchsichtig wie `LocalAuditEventV1`: eine Auditzeile gehoert nicht in
    /// eine Protokollzeile. Der Rumpf existiert, damit `Result::unwrap_err` an
    /// diesem Typ ueberhaupt aufrufbar ist.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedLocalAuditEvent(<signed>)")
    }
}

/// Der Dienst, der eine getypte Zeile signiert und bucht.
pub trait LocalAuditService: Send + Sync {
    /// Signiert und bucht das Ereignis.
    ///
    /// # Errors
    ///
    /// [`AuditError::SessionExpired`] fuer [`AuditActorProof::Expired`] — mit
    /// einer Meldung, die kein Ereignisinhalt nennt; sonst der Fehler der
    /// Kodierung, der Signatur oder der Ablage.
    fn record_signed(
        &self,
        actor: AuditActorProof<'_>,
        event: TypedLocalAuditEvent,
    ) -> Result<SignedLocalAuditEvent, AuditError>;
}
