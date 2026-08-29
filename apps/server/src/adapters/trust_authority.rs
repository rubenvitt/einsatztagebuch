//! Die Autoritaetsaufloesung des Servers — ueber die GETEILTE Trust-Pruefung.
//!
//! # Warum das hier so aufwendig aussieht
//!
//! Der Server darf nicht wissen, welche Capability ein Zertifikat traegt; er
//! darf es nur FESTSTELLEN, und zwar auf demselben Weg wie jeder Reader:
//! `verify_trust` gegen den Anker der Organisation, dann
//! `verify_registry_candidate`, `prepare_local_time` und
//! `select_registry_head`. Erst der gewaehlte Head sagt, welche Zertifikate
//! zur vorgeschlagenen Sequenz aktiv sind und welche Capabilities sie tragen.
//!
//! Die Abkuerzung waere, `role_intervals` zu lesen. Sie ist verboten: eine
//! Zeile ist keine Signatur, und `design.md` §12 laesst Rollen und
//! Capabilities ausschliesslich aus Root-signierten Trust-Objekten entstehen.
//!
//! # Lesen schreibt nicht
//!
//! `select_registry_head` ist in `ea-trust` ein SCHREIBENDER Weg: auch der
//! Zweig, der den bereits gepinnten Kopf nur bestaetigt, committet
//! (`crates/ea-trust/src/registry.rs`, `compare_and_affirm`). Liefe die
//! Authentisierung darueber gegen den persistenten Speicher, dann
//!
//! * schriebe JEDER `/v1`-Request eine Zeile,
//! * waere diese eine Zeile — `(organizationId, [0x5e; 16])` — der
//!   Serialisierungspunkt der ganzen Organisation, und
//! * bekaeme der Verlierer eines Rennens ein endgueltiges `401`, obwohl er
//!   nichts falsch gemacht hat.
//!
//! Deshalb laeuft die Authentisierung ueber
//! [`ea_verify::EphemeralTrustStateStore`] — denselben Speicher, mit dem der
//! Reader ein Archiv verifiziert. Er startet leer, die Kopfkette wird aus dem
//! Anker heraus nachgelaufen, und nach der Antwort ist er fort. Es gibt keinen
//! Schreibzugriff, kein Rennen und keine Serialisierung.
//!
//! Gepinnt wird ausschliesslich dort, wo der Kopf WIRKLICH vorrueckt: beim
//! Indizieren eines Trust-Ereignisses ([`TrustEventValidator`]). Verliert
//! dort jemand das Rennen, ist die Antwort `EA-TRUST-STATE-CONFLICT` mit
//! `503` und `retryable = true` — nie ein `401`.
//!
//! # Die vorgeschlagene Sequenz
//!
//! `verify_registry_candidate` fragt nach einer Kettensequenz, zu der die
//! Autoritaet gelten soll. Die Trust-Endpunkte schreiben in keine Kette, also
//! gibt es keine natuerliche. Genommen wird die groesste
//! `effective-from-sequence` der bekannten Registry-Ereignisse: die Sequenz,
//! ab der der juengste Kopf gilt, gelesen aus dem signierten Ereignis selbst
//! und nicht aus einer Zeile.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use ea_crypto::{CanonicalPublicCoseKey, CertificateCapability};
use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject, TrustSubtypeV1};
use ea_sync_protocol::RegisteredDevice;
use ea_sync_server::{
    AuthorityError, ObjectStore, RepositoryError,
    trust::{TrustEventValidator, TrustServiceError},
};
use ea_trust::{
    RegistryError, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError, TrustAnchorV1,
    TrustError, TrustObjectSource, TrustSourceError, TrustStateKey, TrustStateStore,
    decode_trust_anchor, load_trust_state, prepare_local_time, select_registry_head,
    verify_registry_candidate, verify_trust,
};
use ea_types::{ChainSequence, DeviceId, KeyThumbprint, ObjectHash, OrganizationId, UnixMillis};
use ea_verify::{EphemeralTrustStateStore, verification_state_key};
use sqlx::{PgPool, Row};

/// Die technische Geraetekennung, unter der der SERVER seinen PERSISTENTEN
/// Vertrauenszustand fuehrt.
///
/// Sie gilt nur noch fuer den einen schreibenden Weg — das Indizieren eines
/// Trust-Ereignisses. Der Wert ist eine Konstante ohne fachlichen Sinn; er
/// muss nur ueber Laeufe hinweg derselbe bleiben, damit der gepinnte Kopf
/// nicht bei jedem Start verloren geht.
pub const SERVER_TRUST_DEVICE_ID_V1: [u8; 16] = [0x5e; 16];

/// Der Zeitboden, mit dem eine noch leere Vertrauenszeile beginnt.
///
/// Null und nicht „jetzt“: der Boden ist streng monoton, und ein zu hoch
/// gesetzter Startwert liesse sich nie mehr senken.
const INITIAL_TRUSTED_FLOOR_MILLIS: i64 = 0;

/// Warum ein Kopflauf nicht bei einem gewaehlten Kopf endete.
///
/// VIER Ausgaenge und kein `Option`: ein Ausfall, ein verlorenes Rennen, ein
/// noch nicht anwendbarer Kopf und eine gebrochene Kette sind vier
/// verschiedene Antworten, und genau ihre Vermischung war der Befund.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeadWalkError {
    /// Datenbank oder Object Store antworten nicht.
    Unavailable,
    /// Der persistente Zustand hat sich unter dem Lauf bewegt.
    StateConflict,
    /// Der Kopf ist (noch) nicht anwendbar: veraltet, in der Zukunft, oder
    /// ausserhalb seiner Sequenzleihe.
    NotApplicable,
    /// Anker, Kette oder Signatur tragen nicht.
    Invalid,
}

impl From<StateStoreError> for HeadWalkError {
    fn from(value: StateStoreError) -> Self {
        match value {
            StateStoreError::Conflict => Self::StateConflict,
            StateStoreError::Unavailable => Self::Unavailable,
            _ => Self::Invalid,
        }
    }
}

impl From<TrustError> for HeadWalkError {
    fn from(value: TrustError) -> Self {
        match value {
            TrustError::StateConflict => Self::StateConflict,
            TrustError::StateUnavailable => Self::Unavailable,
            // Zeitfenster einer Autorisierung: das Objekt traegt, es gilt nur
            // jetzt nicht.
            TrustError::AuthNotYetValid | TrustError::AuthExpired => Self::NotApplicable,
            _ => Self::Invalid,
        }
    }
}

impl From<RegistryError> for HeadWalkError {
    fn from(value: RegistryError) -> Self {
        match value {
            // Zeit und Sequenzleihe: das Objekt traegt, es gilt nur jetzt
            // nicht.
            RegistryError::Stale
            | RegistryError::FutureSkew
            | RegistryError::PendingFuture
            | RegistryError::SequenceLease => Self::NotApplicable,
            _ => Self::Invalid,
        }
    }
}

/// Die Aufloesung eines `keyid` auf ein freigegebenes Geraet und die Pruefung
/// eines gelieferten `.etb` — beides ueber denselben Trust-Abschluss.
pub struct PostgresTrustAuthority {
    pool: PgPool,
    objects: Arc<dyn ObjectStore>,
}

impl PostgresTrustAuthority {
    #[must_use]
    pub const fn new(pool: PgPool, objects: Arc<dyn ObjectStore>) -> Self {
        Self { pool, objects }
    }

    async fn anchor_bytes(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Option<Vec<u8>>, RepositoryError> {
        let row =
            sqlx::query("SELECT trust_anchor_bytes FROM organizations WHERE organization_id = $1")
                .bind(&organization_id.as_bytes()[..])
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
        Ok(row.and_then(|row| row.get::<Option<Vec<u8>>, _>("trust_anchor_bytes")))
    }

    /// Alle indizierten `.etb` dieser Organisation, mit ihren EXAKTEN Bytes.
    ///
    /// Vorher geholt und nicht waehrend der Pruefung: `TrustObjectSource` ist
    /// synchron, der Object Store ist es nicht.
    async fn trust_catalog(
        &self,
        organization_id: OrganizationId,
    ) -> Result<BTreeMap<ObjectHash, Arc<[u8]>>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT object_hash FROM trust_events WHERE organization_id = $1 ORDER BY object_hash",
        )
        .bind(&organization_id.as_bytes()[..])
        .fetch_all(&self.pool)
        .await
        .map_err(|_| RepositoryError::Unavailable)?;

        let mut catalog = BTreeMap::new();
        for row in &rows {
            let raw: Vec<u8> = row.get("object_hash");
            let object_hash =
                ObjectHash::try_from(raw.as_slice()).map_err(|_| RepositoryError::Unavailable)?;
            let stream = self
                .objects
                .get_exact(object_hash)
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
            let bytes = stream
                .collect()
                .await
                .map_err(|_| RepositoryError::Unavailable)?
                .into_bytes()
                .to_vec();
            catalog.insert(object_hash, Arc::<[u8]>::from(bytes));
        }
        Ok(catalog)
    }
}

/// Laeuft die Kopfkette vom Anker aus bis zum juengsten anwendbaren Kopf.
///
/// Der Lauf ist noetig, weil `select_registry_head` GENAU EINEN Uebergang
/// entscheidet: aus einem leeren Stand heraus erreicht man den dritten Kopf
/// nur ueber den ersten und den zweiten. `Advanced` heisst „ein Uebergang
/// geschafft, es gibt noch mehr“, `Selected` heisst „das ist der aktuelle“.
/// Die Schleifenschranke ist die Zahl der bekannten Registry-Ereignisse plus
/// eins; sie kann nicht laenger laufen, als es Koepfe gibt.
fn walk_to_selected_head(
    anchor: &TrustAnchorV1,
    source: &dyn TrustObjectSource,
    store: &mut dyn TrustStateStore,
    key: TrustStateKey,
    proposed_sequence: ChainSequence,
    now: UnixMillis,
    head_count: usize,
) -> Result<Option<SelectedRegistryHead>, HeadWalkError> {
    for _ in 0..head_count.saturating_add(1) {
        let snapshot = load_trust_state(store, key).map_err(HeadWalkError::from)?;
        let trust = verify_trust(anchor, source, snapshot).map_err(HeadWalkError::from)?;
        let candidate =
            verify_registry_candidate(&trust, proposed_sequence).map_err(HeadWalkError::from)?;
        let local_time =
            prepare_local_time(store, &candidate, now, &[]).map_err(HeadWalkError::from)?;
        match select_registry_head(candidate, local_time, None).map_err(HeadWalkError::from)? {
            RegistrySelectionOutcome::Selected(selected) => return Ok(Some(selected)),
            // Ein Uebergang ist geschafft; der naechste Durchlauf liest den
            // fortgeschriebenen Stand.
            RegistrySelectionOutcome::Advanced(_) => {}
            // Der naechste Kopf gilt erst spaeter. Das ist eine Antwort, kein
            // Fehler — und sie traegt keine Autoritaet.
            RegistrySelectionOutcome::PendingFuture(_) => return Ok(None),
        }
    }
    Ok(None)
}

#[async_trait]
impl ea_sync_server::DeviceAuthorityDirectory for PostgresTrustAuthority {
    async fn resolve(
        &self,
        organization_id: OrganizationId,
        key_thumbprint: KeyThumbprint,
        now: UnixMillis,
    ) -> Result<Option<RegisteredDevice>, AuthorityError> {
        let Some(anchor_bytes) = self
            .anchor_bytes(organization_id)
            .await
            .map_err(|_| AuthorityError::Unavailable)?
        else {
            // Ohne Anker gibt es keine Wurzel und damit keine Autoritaet. Das
            // ist eine Antwort, kein Ausfall.
            return Ok(None);
        };
        let Ok(anchor) = decode_trust_anchor(&anchor_bytes) else {
            return Ok(None);
        };
        let catalog = self
            .trust_catalog(organization_id)
            .await
            .map_err(|_| AuthorityError::Unavailable)?;
        let proposed_sequence = highest_effective_from_sequence(&catalog);
        let head_count = registry_event_count(&catalog);
        let source = CatalogSource(catalog);

        // LESEND: der Stand dieses Laufs lebt im Speicher und ist nach der
        // Antwort fort. Keine Zeile, kein Rennen, kein Serialisierungspunkt.
        let key = verification_state_key(organization_id);
        let mut store =
            EphemeralTrustStateStore::new(key, UnixMillis::new(INITIAL_TRUSTED_FLOOR_MILLIS));
        let head = match walk_to_selected_head(
            &anchor,
            &source,
            &mut store,
            key,
            proposed_sequence,
            now,
            head_count,
        ) {
            Ok(Some(head)) => head,
            Ok(None) => return Ok(None),
            Err(HeadWalkError::Unavailable) => return Err(AuthorityError::Unavailable),
            Err(HeadWalkError::StateConflict) => return Err(AuthorityError::StateConflict),
            // Kein anwendbarer Kopf heisst: keine Autoritaet. Das ist eine
            // Antwort und kein Ausfall.
            Err(HeadWalkError::NotApplicable | HeadWalkError::Invalid) => return Ok(None),
        };

        for (certificate_hash, fields) in head.active_certificates() {
            if fields.signing_key_thumbprint != Some(key_thumbprint) {
                continue;
            }
            let Some(exact_key) = fields.signing_public_cose_key.as_ref() else {
                continue;
            };
            let Ok(public_key) = CanonicalPublicCoseKey::from_deterministic_cbor(exact_key) else {
                continue;
            };
            // Ein unbekanntes Capability-Literal ist ein Zertifikatsbefund und
            // KEIN ignorierbarer Zusatz: das ganze Zertifikat faellt aus.
            let mut capabilities = Vec::with_capacity(fields.capabilities.len());
            for literal in &fields.capabilities {
                let Ok(capability) = CertificateCapability::try_from(literal.as_str()) else {
                    return Ok(None);
                };
                capabilities.push(capability);
            }
            return Ok(Some(RegisteredDevice::new(
                organization_id,
                certificate_hash,
                public_key,
                capabilities,
            )));
        }
        Ok(None)
    }
}

#[async_trait]
impl TrustEventValidator for PostgresTrustAuthority {
    /// Prueft das GELIEFERTE OBJEKT, nicht nur die Organisation.
    ///
    /// Die geteilte Pruefung beweist heute genau zwei Dinge ueber ein einzelnes
    /// `.etb`:
    ///
    /// 1. `verify_trust` beweist die Bootstrap-Menge, die der Anker NAMENTLICH
    ///    nennt — `require_exact_anchor_sets` laesst ein zusaetzliches
    ///    Root-Zertifikat, Admin-Zertifikat oder Operator-Binding scheitern.
    /// 2. `verify_registry_candidate` plus `select_registry_head` beweisen
    ///    GENAU EINEN Registry-Uebergang: Signatur, Autorisierung, Policy,
    ///    Kettenposition und — ueber `prepare_local_time` — das
    ///    `notBefore`/`notAfter`-Fenster.
    ///
    /// Alles andere kann diese Stufe nicht beweisen, und was sie nicht
    /// beweisen kann, nimmt sie nicht an: `EA-TRUST-EVENT-UNVERIFIABLE`. Das
    /// ist die fail-closed Antwort und ausdruecklich KEINE zweite
    /// Trust-Umsetzung — die Menge waechst von selbst mit, sobald die geteilte
    /// Pruefung mehr beweist.
    async fn validate_exact_etb(
        &self,
        organization_id: OrganizationId,
        object_hash: ObjectHash,
        exact_etb_bytes: &[u8],
        now: UnixMillis,
    ) -> Result<(), TrustServiceError> {
        let anchor_bytes = self
            .anchor_bytes(organization_id)
            .await
            .map_err(|_| TrustServiceError::DependencyUnavailable)?
            .ok_or(TrustServiceError::AnchorMissing)?;
        let anchor =
            decode_trust_anchor(&anchor_bytes).map_err(|_| TrustServiceError::AnchorMissing)?;

        let mut catalog = self
            .trust_catalog(organization_id)
            .await
            .map_err(|_| TrustServiceError::DependencyUnavailable)?;
        catalog.insert(object_hash, Arc::<[u8]>::from(exact_etb_bytes.to_vec()));
        let proposed_sequence = highest_effective_from_sequence(&catalog);
        let head_count = registry_event_count(&catalog);
        let is_registry_event = subtype_of(exact_etb_bytes) == Some(TrustSubtypeV1::RegistryEvent);
        let source = CatalogSource(catalog);

        // Fall 1: der Anker NENNT dieses Objekt. Dann beweist `verify_trust`
        // es — `require_exact_anchor_sets` laesst jede Abweichung von der
        // benannten Menge scheitern. Ein Kopf wird dafuer nicht gebraucht, und
        // es wird deshalb auch nichts gepinnt.
        if anchor_names(&anchor, object_hash) {
            let key = verification_state_key(organization_id);
            let mut store =
                EphemeralTrustStateStore::new(key, UnixMillis::new(INITIAL_TRUSTED_FLOOR_MILLIS));
            let snapshot = load_trust_state(&mut store, key)
                .map_err(|error| map_walk_error(HeadWalkError::from(error)))?;
            verify_trust(&anchor, &source, snapshot)
                .map_err(|error| map_walk_error(HeadWalkError::from(error)))?;
            return Ok(());
        }

        // Fall 2: das Objekt IST der neue Kopf. Nur hier rueckt die
        // Registry-Linie wirklich vor, also ist DIES der eine schreibende Weg
        // und der persistente Speicher gehoert hierhin.
        if is_registry_event {
            let key = TrustStateKey {
                organization_id,
                device_id: DeviceId::try_from(&SERVER_TRUST_DEVICE_ID_V1[..])
                    .map_err(|_| TrustServiceError::Internal)?,
            };
            let mut store = super::trust_state::PostgresTrustStateStore::new(
                self.pool.clone(),
                UnixMillis::new(INITIAL_TRUSTED_FLOOR_MILLIS),
            );
            let head = walk_to_selected_head(
                &anchor,
                &source,
                &mut store,
                key,
                proposed_sequence,
                now,
                head_count,
            )
            .map_err(map_walk_error)?;
            return match head {
                Some(head) if head.registry_head_hash() == object_hash => Ok(()),
                Some(_) | None => Err(TrustServiceError::EventNotApplicable),
            };
        }

        // Fall 3: die geteilte Pruefung kann ueber dieses Objekt heute nichts
        // beweisen. Fail-closed.
        Err(TrustServiceError::EventUnverifiable)
    }
}

/// Nennt der Anker dieses Objekt namentlich?
fn anchor_names(anchor: &TrustAnchorV1, object_hash: ObjectHash) -> bool {
    anchor.root_certificate_object_hash() == object_hash
        || anchor
            .initial_admin_certificate_object_hashes()
            .contains(&object_hash)
        || anchor
            .initial_admin_operator_binding_object_hashes()
            .contains(&object_hash)
}

const fn map_walk_error(error: HeadWalkError) -> TrustServiceError {
    match error {
        HeadWalkError::Unavailable => TrustServiceError::DependencyUnavailable,
        HeadWalkError::StateConflict => TrustServiceError::StateConflict,
        HeadWalkError::NotApplicable => TrustServiceError::EventNotApplicable,
        HeadWalkError::Invalid => TrustServiceError::EventInvalid,
    }
}

/// Der Subtyp eines `.etb`, sofern es eines ist.
fn subtype_of(exact_etb_bytes: &[u8]) -> Option<TrustSubtypeV1> {
    match ea_format::decode_exact_object(exact_etb_bytes) {
        Ok(ParsedArchiveObject::Trust(parsed)) => Some(parsed.value().subtype()),
        _ => None,
    }
}

/// Die groesste `effective-from-sequence` der Registry-Ereignisse im Katalog.
fn highest_effective_from_sequence(catalog: &BTreeMap<ObjectHash, Arc<[u8]>>) -> ChainSequence {
    let mut highest = 0_u64;
    for core in registry_events(catalog) {
        highest = highest.max(core);
    }
    ChainSequence::new(highest)
}

/// Wie viele Registry-Ereignisse der Katalog traegt — die Schranke des Laufs.
fn registry_event_count(catalog: &BTreeMap<ObjectHash, Arc<[u8]>>) -> usize {
    registry_events(catalog).count()
}

/// Die `effective-from-sequence` jedes Registry-Ereignisses im Katalog.
fn registry_events(catalog: &BTreeMap<ObjectHash, Arc<[u8]>>) -> impl Iterator<Item = u64> + '_ {
    catalog.values().filter_map(|bytes| {
        let Ok(ParsedArchiveObject::Trust(parsed)) = ea_format::decode_exact_object(bytes) else {
            return None;
        };
        let Ok(DecodedTrustPayloadV1::RegistryEvent(core)) = parsed.value().decoded_payload()
        else {
            return None;
        };
        Some(core.fields().effective_from_sequence.get())
    })
}

/// Ein Objektkatalog, den die geteilte Pruefung synchron lesen kann.
struct CatalogSource(BTreeMap<ObjectHash, Arc<[u8]>>);

impl TrustObjectSource for CatalogSource {
    fn visit_trust_object_hashes(
        &self,
        visitor: &mut dyn FnMut(ObjectHash) -> Result<(), TrustSourceError>,
    ) -> Result<(), TrustSourceError> {
        for object_hash in self.0.keys() {
            visitor(*object_hash)?;
        }
        Ok(())
    }

    fn read_exact_trust_object(
        &self,
        object_hash: ObjectHash,
    ) -> Result<Option<Arc<[u8]>>, TrustSourceError> {
        Ok(self.0.get(&object_hash).map(Arc::clone))
    }
}
