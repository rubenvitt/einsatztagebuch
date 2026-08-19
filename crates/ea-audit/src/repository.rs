//! Die anhaengende Ablage und der Dienst, der in sie hineinschreibt.

use std::sync::Arc;

use ea_crypto::{ContentType, object_hash};
use ea_format::{LocalAuditEventCoreFieldsV1, encode_local_audit_core, encode_local_audit_event};
use ea_key_provider::{KeyHandle, KeyProvider};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_types::{CertificateHash, DeviceId, EventId, ObjectHash, OrganizationId, UnixMillis};

use crate::event::{
    AuditActorProof, AuditError, LocalAuditService, SignedLocalAuditEvent, TypedLocalAuditEvent,
};

/// Die ANHAENGENDE Ablage der lokalen Auditzeilen.
///
/// Kein Aenderungs- und kein Loeschpfad: der Vertrag nennt keinen, und
/// `0001_writer.sql` haengt zwei Trigger an die Tabelle, die auch eine fremde
/// SQL-Zeile abbrechen lassen.
pub trait LocalAuditRepository: Send + Sync {
    /// Haengt die Zeile an.
    ///
    /// # Errors
    ///
    /// [`AuditError::Store`], wenn die Ablage ablehnt.
    fn append(&self, event: &SignedLocalAuditEvent) -> Result<(), AuditError>;

    /// Liest die Zeile unter dieser Kennung.
    ///
    /// # Errors
    ///
    /// [`AuditError::NotFound`], wenn es keine gibt.
    fn event(&self, id: EventId) -> Result<SignedLocalAuditEvent, AuditError>;
}

/// Die Ablage in der verschluesselten lokalen Datenbank.
pub struct SqliteLocalAuditRepository {
    database: Arc<EncryptedDatabase>,
}

impl SqliteLocalAuditRepository {
    #[must_use]
    pub const fn new(database: Arc<EncryptedDatabase>) -> Self {
        Self { database }
    }
}

impl LocalAuditRepository for SqliteLocalAuditRepository {
    fn append(&self, event: &SignedLocalAuditEvent) -> Result<(), AuditError> {
        // EINE Transaktion, und sie wird gebucht, bevor diese Methode
        // zurueckkehrt: eine Auditzeile, die der Aufrufer als geschrieben
        // ansieht, waehrend sie noch in einer offenen Transaktion haengt, waere
        // eine Zeile, die ein Absturz verschwinden laesst.
        self.database.transaction(|transaction| {
            transaction.execute(
                "INSERT INTO local_audit_event (event_id, exact_bytes, object_hash) \
                 VALUES (?1, ?2, ?3)",
                &[
                    StoreValue::Blob(event.id().as_bytes().to_vec()),
                    StoreValue::Blob(event.exact_bytes().to_vec()),
                    StoreValue::Blob(object_hash(event.exact_bytes()).as_bytes().to_vec()),
                ],
            )?;
            Ok::<(), AuditError>(())
        })
    }

    fn event(&self, id: EventId) -> Result<SignedLocalAuditEvent, AuditError> {
        let row = self
            .database
            .query_row(
                "SELECT exact_bytes FROM local_audit_event WHERE event_id = ?1",
                &[StoreValue::Blob(id.as_bytes().to_vec())],
            )?
            .ok_or(AuditError::NotFound)?;
        Ok(SignedLocalAuditEvent::sealed(id, row.blob(0)?.to_vec()))
    }
}

/// Der Dienst, der eine getypte Zeile signiert und bucht.
///
/// Er haelt den Signaturgriff und den Objekthash des Signierzertifikats, weil
/// beide zum SCHLUESSEL gehoeren und nicht zum einzelnen Ereignis: der
/// Zertifikatshash, den der geschuetzte COSE-Kopf nennt, MUSS derselbe sein,
/// den der Kern nennt (`crates/ea-format/src/local_audit.rs`, Pruefung von
/// `encode_local_audit_event`). Zwei Quellen desselben Wertes koennten
/// auseinanderlaufen; hier gibt es nur eine.
///
/// Die Zeit kommt als [`UnixMillis`] aus dem GEWAEHLTEN Registry-Head
/// (`SelectedRegistryHead::preexisting_effective_now`). Der Dienst nimmt sie
/// beim Bauen entgegen und nicht je Aufruf, damit sie nicht Ereignis fuer
/// Ereignis frei gesetzt werden kann; eine `ea-trust`-Kante traegt diese Crate
/// ausdruecklich nicht.
pub struct SignedLocalAuditService {
    repository: Arc<dyn LocalAuditRepository>,
    provider: Arc<dyn KeyProvider>,
    signing_handle: KeyHandle,
    signer_certificate_object_hash: ObjectHash,
    effective_now: UnixMillis,
}

impl SignedLocalAuditService {
    #[must_use]
    pub const fn new(
        repository: Arc<dyn LocalAuditRepository>,
        provider: Arc<dyn KeyProvider>,
        signing_handle: KeyHandle,
        signer_certificate_object_hash: ObjectHash,
        effective_now: UnixMillis,
    ) -> Self {
        Self {
            repository,
            provider,
            signing_handle,
            signer_certificate_object_hash,
            effective_now,
        }
    }
}

/// Wer handelt, unter welcher Bindung und unter welchem Signierzertifikat.
struct ResolvedActor {
    organization_id: OrganizationId,
    device_id: DeviceId,
    operator_binding_object_hash: Option<ObjectHash>,
    signer_certificate_object_hash: ObjectHash,
}

impl LocalAuditService for SignedLocalAuditService {
    fn record_signed(
        &self,
        actor: AuditActorProof<'_>,
        event: TypedLocalAuditEvent,
    ) -> Result<SignedLocalAuditEvent, AuditError> {
        let actor = match actor {
            AuditActorProof::OperatorSession(session) => ResolvedActor {
                organization_id: session.organization_id(),
                device_id: session.device_id(),
                operator_binding_object_hash: Some(session.binding_object_hash()),
                signer_certificate_object_hash: self.signer_certificate_object_hash,
            },
            AuditActorProof::AuthenticatedDevice(device) => ResolvedActor {
                organization_id: device.organization_id(),
                device_id: device.device_id(),
                operator_binding_object_hash: device.known_binding_object_hash(),
                signer_certificate_object_hash: device.signer_certificate_object_hash(),
            },
            // Fail-closed und OHNE Ereignisbezug: die Meldung nennt nur ihren
            // Code, also kann aus ihr nichts ueber das abgewiesene Ereignis
            // herausgelesen werden.
            AuditActorProof::Expired => return Err(AuditError::SessionExpired),
        };

        let event_id =
            EventId::try_from(fresh::<16>()?.as_slice()).map_err(|_| AuditError::Encoding)?;
        let fields = LocalAuditEventCoreFieldsV1 {
            event_id,
            organization_id: actor.organization_id,
            device_id: actor.device_id,
            operator_binding_object_hash: actor.operator_binding_object_hash,
            signer_certificate_object_hash: actor.signer_certificate_object_hash,
            action: event.action,
            outcome: event.outcome,
            effective_now: self.effective_now,
            nonce: fresh::<32>()?,
        };
        let core = encode_local_audit_core(&fields)?;
        let cose = self.provider.sign(
            &self.signing_handle,
            ContentType::LocalAuditCbor,
            CertificateHash::from(actor.signer_certificate_object_hash),
            &core,
        )?;
        // `encode_local_audit_event` liest den Kern zurueck UND prueft die
        // fertige COSE gegen ihn — Inhaltstyp, Nutzlastgleichheit und
        // Zertifikatshash. Die Pruefung liegt damit VOR dem Buchen, und eine
        // Zeile, die ihre eigene Signatur nicht traegt, erreicht die Datenbank
        // nicht.
        let exact_bytes = encode_local_audit_event(&core, cose.as_bytes())?;
        let signed = SignedLocalAuditEvent::sealed(event_id, exact_bytes);
        self.repository.append(&signed)?;
        Ok(signed)
    }
}

fn fresh<const N: usize>() -> Result<[u8; N], AuditError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| AuditError::LocalRng)?;
    Ok(bytes)
}
