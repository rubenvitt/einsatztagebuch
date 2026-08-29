//! Der transportneutrale Trust-Dienst: Annahme und Verteilung exakter `.etb`.
//!
//! # Was hier NICHT passiert
//!
//! Es gibt keine zweite Trust-Pruefung. Ein `.etb` wird von
//! [`ea_format::decode_exact_object`] in seine Familie und seinen Subtyp
//! zerlegt und danach von der GETEILTEN Pruefung `ea_trust::verify_trust`
//! gegen den Anker der Organisation gefuehrt — genau der Pruefung, die auch
//! der Reader fuehrt. Der Server bildet sich kein eigenes Urteil, und er
//! setzt kein Urteil aus Datenbankzeilen zusammen: `GET /v1/trust/registry`
//! liefert die EXAKTEN archivierten Objektbytes aus dem Object Store, und der
//! Index sagt nur, welche und in welcher Reihenfolge (`design.md` §13.2,
//! „Technische Listen sind nicht autoritativ“).
//!
//! # Die Subtypmenge
//!
//! Angenommen wird, was [`ea_format::TrustSubtypeV1`] zum Zeitpunkt des Laufs
//! traegt — heute elf Arme. Diese Datei zaehlt sie NICHT ab: sie ruft den
//! Dekodierer, und ein zwoelfter Arm wandert dadurch ohne eine Zeile
//! Aenderung hier hinein.
//!
//! # Die Registry-Linie
//!
//! `trust-registry-response-v1` verlangt streng aufsteigende, duplikatfreie
//! `registry-version`-Werte (`crates/ea-sync-protocol/src/reader.rs`). Unter
//! einer Version kann also genau EIN Objekt stehen, und das ist das
//! `registryEvent` selbst: nur diese Objektart traegt eine Registry-Version.
//! Jedes andere `.etb` wird indiziert und ueber `GET /v1/objects/{objectHash}`
//! ausgeliefert, steht aber nicht auf dieser Linie.

use core::fmt;

use ea_format::{DecodedTrustPayloadV1, ObjectTypeV1, ParsedArchiveObject};
use ea_sync_protocol::{
    MAX_TRUST_PAGE_EVENTS_V1, SyncProtocolError, TrustEventRecordV1, TrustRegistryResponseV1,
};
use ea_types::{ObjectHash, OrganizationId, RegistryVersion, UnixMillis};

use crate::{
    RepositoryError, ServerClock, StoreError,
    models::{TrustEventCommandV1, TrustIndexOutcome},
    ports::{ObjectStore, TrustEventStore},
};

/// Jeder Befund des Trust-Dienstes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TrustServiceError {
    /// Das gelieferte Objekt ist kein `.etb`.
    ObjectFamily,
    /// Das `.etb` ist formal oder in seiner Trust-Kette ungueltig.
    EventInvalid,
    /// Das Objekt gehoert einer anderen Organisation.
    OrganizationMismatch,
    /// Dieselbe Registry-Version traegt bereits ein ANDERES Objekt.
    Conflict,
    /// Die Organisation hat keinen hinterlegten Trust Anchor; ohne ihn gibt es
    /// keine Wurzel, gegen die geprueft werden koennte.
    AnchorMissing,
    /// Datenbank oder Object Store antworten nicht.
    DependencyUnavailable,
    /// Interner Fehler ohne fachliche Ursache.
    Internal,
    /// Ein durchgereichter Rahmenbefund.
    Protocol(SyncProtocolError),
}

impl TrustServiceError {
    pub const ALL: [Self; 7] = [
        Self::ObjectFamily,
        Self::EventInvalid,
        Self::OrganizationMismatch,
        Self::Conflict,
        Self::AnchorMissing,
        Self::DependencyUnavailable,
        Self::Internal,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ObjectFamily => "EA-TRUST-EVENT-OBJECT-FAMILY",
            Self::EventInvalid => "EA-TRUST-EVENT-INVALID",
            Self::OrganizationMismatch => "EA-TRUST-EVENT-ORGANIZATION",
            Self::Conflict => "EA-TRUST-EVENT-CONFLICT",
            Self::AnchorMissing => "EA-TRUST-EVENT-ANCHOR-MISSING",
            Self::DependencyUnavailable => "EA-TRUST-EVENT-DEPENDENCY-UNAVAILABLE",
            Self::Internal => "EA-TRUST-EVENT-INTERNAL",
            Self::Protocol(error) => error.code(),
        }
    }

    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            // Wohlgeformt, aber ungueltig in Trust oder Format.
            Self::ObjectFamily | Self::EventInvalid | Self::AnchorMissing => 422,
            Self::OrganizationMismatch => 403,
            Self::Conflict => 409,
            Self::Internal => 500,
            Self::DependencyUnavailable => 503,
            Self::Protocol(error) => error.http_status(),
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

impl From<SyncProtocolError> for TrustServiceError {
    fn from(value: SyncProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<RepositoryError> for TrustServiceError {
    fn from(value: RepositoryError) -> Self {
        match value {
            RepositoryError::Unavailable => Self::DependencyUnavailable,
            _ => Self::Conflict,
        }
    }
}

impl From<StoreError> for TrustServiceError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::HashConflict => Self::Conflict,
            StoreError::ObjectTypeMismatch => Self::ObjectFamily,
            StoreError::LimitExceeded => Self::Protocol(SyncProtocolError::BodyLimit),
            StoreError::NotFound => Self::Protocol(SyncProtocolError::NotFound),
            StoreError::Unavailable => Self::DependencyUnavailable,
        }
    }
}

impl fmt::Display for TrustServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for TrustServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for TrustServiceError {}

/// Die geteilte Trust-Pruefung, wie der Serverpfad sie ruft.
///
/// Ein Port und keine Funktion, weil die Pruefung Anker, Objektkatalog und
/// persistenten Vertrauenszustand braucht — alles drei liegt hinter der
/// Laufzeit von `apps/server`. Der Port beschreibt nur, WAS gefragt wird:
/// „Ist dieses `.etb` unter dem Anker dieser Organisation gueltig?“ Er
/// beantwortet die Frage nicht selbst und darf sie nicht selbst beantworten.
#[async_trait::async_trait]
pub trait TrustEventValidator: Send + Sync {
    /// Prueft die exakten `.etb`-Bytes gegen den Anker der Organisation.
    ///
    /// Die Bytes kommen als PARAMETER und nicht ueber ihren Hash aus dem
    /// Object Store: sie sind zum Zeitpunkt der Pruefung noch nicht abgelegt,
    /// und sie sollen es auch nicht sein — ein ungeprueftes Objekt hat im
    /// Bestand nichts verloren. Die Pruefung sieht damit genau die Objektmenge,
    /// die der Reader spaeter sieht: den bestehenden Katalog PLUS dieses eine
    /// Objekt.
    async fn validate_exact_etb(
        &self,
        organization_id: OrganizationId,
        object_hash: ObjectHash,
        exact_etb_bytes: &[u8],
        now: UnixMillis,
    ) -> Result<(), TrustServiceError>;
}

/// Was der Annahmepfad an Ports braucht.
pub struct TrustPorts<'a> {
    pub clock: &'a dyn ServerClock,
    pub objects: &'a dyn ObjectStore,
    pub events: &'a dyn TrustEventStore,
    pub validator: &'a dyn TrustEventValidator,
}

/// `POST /v1/trust/events` — genau ein exaktes `.etb`.
///
/// Die Reihenfolge ist fail-closed und nicht verhandelbar:
///
/// 1. Objektfamilie und Subtyp aus den EXAKTEN Bytes lesen — `ea-format`,
/// 2. Organisationsbindung des Objekts gegen die des Aufrufers stellen,
/// 3. die GETEILTE Trust-Pruefung fuehren,
/// 4. die Bytes content-addressed ablegen,
/// 5. erst danach transaktional indizieren.
///
/// Ein ungeprueftes Objekt wird nie abgelegt. Faellt Schritt 5, bleibt
/// hoechstens ein content-addressed Orphan zurueck — genau das, was
/// `design.md` §13.3 als zulaessig benennt, und weniger gefaehrlich als ein
/// Index, der auf ein ungeprueftes Objekt zeigt.
pub async fn publish_trust_event(
    exact_etb_bytes: &[u8],
    organization_id: OrganizationId,
    ports: &TrustPorts<'_>,
) -> Result<TrustIndexOutcome, TrustServiceError> {
    let ParsedArchiveObject::Trust(parsed) = ea_format::decode_exact_object(exact_etb_bytes)
        .map_err(|_| TrustServiceError::EventInvalid)?
    else {
        return Err(TrustServiceError::ObjectFamily);
    };
    let subtype = parsed.value().subtype();
    let payload = parsed
        .value()
        .decoded_payload()
        .map_err(|_| TrustServiceError::EventInvalid)?;
    let registry_version = registry_version_of(&payload);
    if let Some(embedded) = organization_of(&payload)
        && embedded != organization_id
    {
        return Err(TrustServiceError::OrganizationMismatch);
    }

    let now = ports.clock.now();
    ports
        .validator
        .validate_exact_etb(
            organization_id,
            ea_crypto::object_hash(exact_etb_bytes),
            exact_etb_bytes,
            now,
        )
        .await?;

    let staged = ports
        .objects
        .stage_stream(
            ObjectTypeV1::Trust,
            aws_sdk_s3::primitives::ByteStream::from(exact_etb_bytes.to_vec()),
            u64::try_from(ea_format::ETB_MAX_RAW_BYTES_V1).unwrap_or(u64::MAX),
        )
        .await?;
    let stored = ports.objects.put_if_absent(staged).await?;

    let outcome = ports
        .events
        .index_event(TrustEventCommandV1 {
            organization_id,
            object_hash: stored.object_hash(),
            size_bytes: stored.size_bytes(),
            subtype_code: subtype.as_str().to_owned(),
            registry_version,
            effective_from: effective_from(&payload).unwrap_or(now),
            received_at: now,
        })
        .await?;
    match outcome {
        TrustIndexOutcome::Conflict => Err(TrustServiceError::Conflict),
        accepted => Ok(accepted),
    }
}

/// `GET /v1/trust/registry?afterVersion={n}` — exakte Objekte, nichts sonst.
pub async fn registry_page(
    organization_id: OrganizationId,
    after_version: RegistryVersion,
    ports: &TrustPorts<'_>,
) -> Result<TrustRegistryResponseV1, TrustServiceError> {
    let line = ports
        .events
        .registry_line_after(organization_id, after_version, MAX_TRUST_PAGE_EVENTS_V1)
        .await?;
    let mut events = Vec::with_capacity(line.len());
    for entry in line {
        let stream = ports.objects.get_exact(entry.object_hash).await?;
        let exact = stream
            .collect()
            .await
            .map_err(|_| TrustServiceError::DependencyUnavailable)?
            .into_bytes()
            .to_vec();
        events.push(TrustEventRecordV1::new(
            entry.registry_version,
            entry.object_hash,
            exact,
        ));
    }
    TrustRegistryResponseV1::new(after_version, events).map_err(TrustServiceError::from)
}

/// Die Registry-Version eines `.etb` — `Some` genau fuer ein `registryEvent`.
fn registry_version_of(payload: &DecodedTrustPayloadV1) -> Option<RegistryVersion> {
    match payload {
        DecodedTrustPayloadV1::RegistryEvent(core) => Some(core.fields().registry_version),
        _ => None,
    }
}

/// Der technische Zeitpunkt, ab dem ein `registryEvent` wirkt.
fn effective_from(payload: &DecodedTrustPayloadV1) -> Option<UnixMillis> {
    match payload {
        DecodedTrustPayloadV1::RegistryEvent(core) => Some(core.fields().issued_at),
        _ => None,
    }
}

/// Die Organisation, an die ein `.etb` sich bindet, sofern sein Subtyp eine
/// nennt.
///
/// Die Aufzaehlung ist ABSICHTLICH nicht vollstaendig: sie prueft, wo eine
/// Bindung im Feld steht, und laesst die Subtypen ohne eigenes
/// `organizationId`-Feld der geteilten Trust-Pruefung. Dort ist die Bindung
/// ueber die Kette ohnehin enger.
fn organization_of(payload: &DecodedTrustPayloadV1) -> Option<OrganizationId> {
    match payload {
        DecodedTrustPayloadV1::InitialRoot(fields) => Some(fields.organization_id),
        DecodedTrustPayloadV1::AuthorizedRoot(core) => Some(core.fields().organization_id),
        DecodedTrustPayloadV1::InitialAdminDevice(fields) => Some(fields.organization_id),
        DecodedTrustPayloadV1::AuthorizedDevice(core) => Some(core.fields().organization_id),
        DecodedTrustPayloadV1::InitialAdminOperatorBinding(fields) => Some(fields.organization_id),
        DecodedTrustPayloadV1::AuthorizedOperatorBinding(core) => {
            Some(core.fields().organization_id)
        }
        DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) => {
            Some(fields.organization_id)
        }
        DecodedTrustPayloadV1::RegistryEvent(core) => Some(core.fields().organization_id),
        _ => None,
    }
}
