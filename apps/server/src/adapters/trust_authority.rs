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
//! Anker heraus nachgelaufen. Der bewiesene Abschluss wird je Kopf gecacht;
//! weitere Aufrufe pruefen nur Katalogstand, Anker, Pin und Zeitfenster und
//! schlagen den Schluessel in der daraus abgeleiteten Autoritaetsmenge nach.
//! Weder Cache-Aufbau noch Cache-Treffer schreiben den persistenten Zustand.
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

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use async_trait::async_trait;
use ea_crypto::{CanonicalPublicCoseKey, CertificateCapability};
use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject, TrustSubtypeV1};
use ea_sync_protocol::RegisteredDevice;
use ea_sync_server::{
    AuthorityError, ObjectStore, RegistryHeadSelectionV1, RepositoryError,
    trust::{TrustEventValidator, TrustPublishError, TrustServiceError},
};
use ea_trust::{
    RegistryError, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError, TrustAnchorV1,
    TrustError, TrustObjectSource, TrustSourceError, TrustStateKey, TrustStateStore, VerifiedTrust,
    bootstrap_active_certificates, decode_trust_anchor, load_trust_state, prepare_local_time,
    select_registry_head, verify_catalogue_admission, verify_registry_candidate, verify_trust,
};
use ea_types::{
    ChainSequence, DeviceId, KeyThumbprint, ObjectHash, OrganizationId, RegistryVersion, UnixMillis,
};
use ea_verify::{EphemeralTrustStateStore, verification_state_key};
use sqlx::{PgPool, Row};
use tokio::sync::Mutex;

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

/// Nur fertige oder gerade aufgebaute Organisationsabschluesse, keine
/// Eintraege je angefragtem Schluessel. Verdraengung aendert keine Autoritaet.
const AUTHORITY_CACHE_CAPACITY: usize = 128;

type AuthorityCacheSlot = Arc<Mutex<Option<CachedAuthority>>>;

#[derive(Eq, PartialEq)]
struct CatalogIdentity {
    anchor_bytes: Option<Vec<u8>>,
    revision: i64,
}

struct AuthoritySnapshot {
    catalog: CatalogIdentity,
    pinned_head: Option<(RegistryVersion, ObjectHash)>,
}

struct CachedAuthority {
    catalog: CatalogIdentity,
    /// Identitaet des SIGNIERT und GETEILT gewaehlten Kopfes. Die Datenbank
    /// liefert nur Invalidierung und Rueckfallboden, nie diese Autoritaet.
    head: Option<(RegistryVersion, ObjectHash)>,
    verified_at: UnixMillis,
    not_after: Option<UnixMillis>,
    /// Ein nicht anwendbarer Kopf ist kein zeitloser Bootstrap-Stand.
    cacheable: bool,
    devices: HashMap<KeyThumbprint, Option<RegisteredDevice>>,
}

impl CachedAuthority {
    fn reusable(&self, catalog: &CatalogIdentity, now: UnixMillis) -> bool {
        self.catalog == *catalog
            && now >= self.verified_at
            && self.not_after.is_none_or(|not_after| now <= not_after)
    }

    fn resolve(&self, key: KeyThumbprint) -> Option<RegisteredDevice> {
        self.devices.get(&key).cloned().flatten()
    }
}

fn require_pin_floor(
    selected: Option<(RegistryVersion, ObjectHash)>,
    pinned: Option<(RegistryVersion, ObjectHash)>,
) -> Result<(), AuthorityError> {
    if let Some((pinned_version, pinned_hash)) = pinned
        && selected.is_none_or(|(version, hash)| {
            version < pinned_version || (version == pinned_version && hash != pinned_hash)
        })
    {
        return Err(AuthorityError::StateConflict);
    }
    Ok(())
}

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
    cache: Mutex<HashMap<OrganizationId, AuthorityCacheSlot>>,
}

impl PostgresTrustAuthority {
    #[must_use]
    pub fn new(pool: PgPool, objects: Arc<dyn ObjectStore>) -> Self {
        Self {
            pool,
            objects,
            cache: Mutex::new(HashMap::new()),
        }
    }

    async fn cache_slot(&self, organization_id: OrganizationId) -> AuthorityCacheSlot {
        let mut cache = self.cache.lock().await;
        if let Some(slot) = cache.get(&organization_id) {
            return Arc::clone(slot);
        }
        let slot = Arc::new(Mutex::new(None));
        if cache.len() == AUTHORITY_CACHE_CAPACITY {
            // Einen laufenden Aufbau nicht verdraengen: seine Mitleser
            // sollen weiter denselben Slot finden. Sind alle belegt, laeuft
            // dieser Aufruf ungecacht; die Map bleibt trotzdem begrenzt.
            let idle = cache
                .iter()
                .find(|(_, slot)| Arc::strong_count(slot) == 1)
                .map(|(organization, _)| *organization);
            let Some(idle) = idle else {
                return slot;
            };
            cache.remove(&idle);
        }
        cache.insert(organization_id, Arc::clone(&slot));
        slot
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

    /// Ein indizierter Punktzugriff: Anker, technischer Katalogstand und
    /// persistenter Rueckfallboden im selben Datenbanksnapshot. Die Revision
    /// aendert sich atomar beim Indizieren, auch auf ANDEREN Serverinstanzen.
    async fn authority_snapshot(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Option<AuthoritySnapshot>, AuthorityError> {
        let row = sqlx::query(
            "SELECT o.trust_anchor_bytes, o.trust_catalog_revision, \
             t.pinned_registry_version, t.pinned_registry_head_hash \
             FROM organizations o LEFT JOIN trust_state t \
             ON t.organization_id = o.organization_id AND t.device_id = $2 \
             WHERE o.organization_id = $1",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&SERVER_TRUST_DEVICE_ID_V1[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthorityError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let pinned_head = match (
            row.get::<Option<i64>, _>("pinned_registry_version"),
            row.get::<Option<Vec<u8>>, _>("pinned_registry_head_hash"),
        ) {
            (None, None) => None,
            (Some(version), Some(hash)) => Some((
                RegistryVersion::new(
                    u64::try_from(version).map_err(|_| AuthorityError::Unavailable)?,
                ),
                ObjectHash::try_from(hash.as_slice()).map_err(|_| AuthorityError::Unavailable)?,
            )),
            _ => return Err(AuthorityError::Unavailable),
        };
        Ok(Some(AuthoritySnapshot {
            catalog: CatalogIdentity {
                anchor_bytes: row.get("trust_anchor_bytes"),
                revision: row.get("trust_catalog_revision"),
            },
            pinned_head,
        }))
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
///
/// Zurueck kommt AUCH die geprüfte Vertrauenslage, nicht nur der Kopf: die
/// Aufnahme eines einzelnen Objekts braucht sie, und vor dem ersten Kopf ist
/// sie das Einzige, was es gibt.
///
/// `Rollback` in der ERSTEN Runde heisst „diese Organisation hat noch keinen
/// Kopf“ — kein Angriff, sondern der Bootstrap-Stand. Ab der zweiten Runde
/// gibt es einen Pin, und dann ist derselbe Befund genau das, wonach er
/// aussieht.
fn walk_to_selected_head(
    anchor: &TrustAnchorV1,
    source: &dyn TrustObjectSource,
    store: &mut dyn TrustStateStore,
    key: TrustStateKey,
    proposed_sequence: ChainSequence,
    now: UnixMillis,
    head_count: usize,
) -> Result<(VerifiedTrust, Option<SelectedRegistryHead>), HeadWalkError> {
    let mut carried = None;
    for round in 0..head_count.saturating_add(1) {
        let snapshot = load_trust_state(store, key).map_err(HeadWalkError::from)?;
        let trust = verify_trust(anchor, source, snapshot).map_err(HeadWalkError::from)?;
        let candidate = match verify_registry_candidate(&trust, proposed_sequence) {
            Ok(candidate) => candidate,
            Err(RegistryError::Rollback) if round == 0 => return Ok((trust, None)),
            Err(error) => return Err(HeadWalkError::from(error)),
        };
        let local_time =
            prepare_local_time(store, &candidate, now, &[]).map_err(HeadWalkError::from)?;
        match select_registry_head(candidate, local_time, None).map_err(HeadWalkError::from)? {
            RegistrySelectionOutcome::Selected(selected) => return Ok((trust, Some(selected))),
            // Ein Uebergang ist geschafft; der naechste Durchlauf liest den
            // fortgeschriebenen Stand.
            RegistrySelectionOutcome::Advanced(_) => carried = Some(trust),
            // Der naechste Kopf gilt erst spaeter. Das ist eine Antwort, kein
            // Fehler — und sie traegt keine Autoritaet.
            RegistrySelectionOutcome::PendingFuture(_) => return Ok((trust, None)),
        }
    }
    carried.map_or(Err(HeadWalkError::Invalid), |trust| Ok((trust, None)))
}

#[async_trait]
impl ea_sync_server::DeviceAuthorityDirectory for PostgresTrustAuthority {
    async fn resolve(
        &self,
        organization_id: OrganizationId,
        key_thumbprint: KeyThumbprint,
        now: UnixMillis,
    ) -> Result<Option<RegisteredDevice>, AuthorityError> {
        let slot = self.cache_slot(organization_id).await;
        let mut cached = slot.lock().await;
        // NACH dem Warten lesen: ein anderer Aufruf kann unterdessen einen
        // Abschluss aufgebaut haben, waehrend die Indexierung den Pin hebt.
        let Some(snapshot) = self.authority_snapshot(organization_id).await? else {
            *cached = None;
            return Ok(None);
        };
        if let Some(authority) = cached.as_ref()
            && authority.reusable(&snapshot.catalog, now)
        {
            require_pin_floor(authority.head, snapshot.pinned_head)?;
            return Ok(authority.resolve(key_thumbprint));
        }
        *cached = None;
        let built = self
            .build_authority(organization_id, &snapshot.catalog, now)
            .await?;
        // Der Object Store liegt ausserhalb des DB-Snapshots. Ein waehrend
        // des Aufbaus geaenderter Katalog darf weder antworten noch cachen.
        let current = self
            .authority_snapshot(organization_id)
            .await?
            .ok_or(AuthorityError::StateConflict)?;
        if current.catalog != snapshot.catalog {
            return Err(AuthorityError::StateConflict);
        }
        if let Some(authority) = built.as_ref() {
            require_pin_floor(authority.head, current.pinned_head)?;
        }
        let result = built
            .as_ref()
            .and_then(|value| value.resolve(key_thumbprint));
        if let Some(authority) = built
            && authority.cacheable
        {
            *cached = Some(authority);
        }
        Ok(result)
    }
}

impl PostgresTrustAuthority {
    async fn build_authority(
        &self,
        organization_id: OrganizationId,
        identity: &CatalogIdentity,
        now: UnixMillis,
    ) -> Result<Option<CachedAuthority>, AuthorityError> {
        let Some(anchor_bytes) = identity.anchor_bytes.as_ref() else {
            return Ok(None);
        };
        let Ok(anchor) = decode_trust_anchor(anchor_bytes) else {
            return Ok(None);
        };
        let catalog = self
            .trust_catalog(organization_id)
            .await
            .map_err(|_| AuthorityError::Unavailable)?;
        let proposed_sequence = highest_effective_from_sequence(&catalog);
        let head_count = registry_event_count(&catalog);
        let source = CatalogSource(catalog);
        let key = verification_state_key(organization_id);
        let mut store =
            EphemeralTrustStateStore::new(key, UnixMillis::new(INITIAL_TRUSTED_FLOOR_MILLIS));
        let (trust, head) = match walk_to_selected_head(
            &anchor,
            &source,
            &mut store,
            key,
            proposed_sequence,
            now,
            head_count,
        ) {
            Ok(pair) => pair,
            Err(HeadWalkError::Unavailable) => return Err(AuthorityError::Unavailable),
            Err(HeadWalkError::StateConflict) => return Err(AuthorityError::StateConflict),
            Err(HeadWalkError::NotApplicable | HeadWalkError::Invalid) => return Ok(None),
        };
        let devices = verified_devices(organization_id, &trust, head.as_ref(), proposed_sequence);
        Ok(Some(CachedAuthority {
            catalog: CatalogIdentity {
                anchor_bytes: identity.anchor_bytes.clone(),
                revision: identity.revision,
            },
            head: head
                .as_ref()
                .map(|head| (head.registry_version(), head.registry_head_hash())),
            // Die Auswahl benutzt KEINE unabhaengigen Zeitquellen. Nach
            // einem erfolgreichen Lauf bleiben seine Uebergaenge bis zum
            // notAfter des gewaehlten Kopfes anwendbar; Autorisierungen
            // pruefen gegen das SIGNIERTE issuedAt ihres Ereignisses.
            // Ein Ruecksprung vor die verifizierte Zeit laeuft erneut durch
            // die geteilte Auswahl, ebenso ein Zeitpunkt nach dem Ablaufende.
            verified_at: now,
            not_after: head.as_ref().map(SelectedRegistryHead::not_after),
            // None kann auch PendingFuture bedeuten. Ohne gewaehlten Kopf
            // wird nur ein Katalog OHNE Registry-Ereignisse gecacht.
            cacheable: head.is_some() || head_count == 0,
            devices,
        }))
    }
}

fn verified_devices(
    organization_id: OrganizationId,
    trust: &VerifiedTrust,
    head: Option<&SelectedRegistryHead>,
    proposed_sequence: ChainSequence,
) -> HashMap<KeyThumbprint, Option<RegisteredDevice>> {
    // Ohne Kopf gelten die vom ANKER benannten Administratorzertifikate.
    // Erst der Aufrufer stellt sicher, dass kein persistenter Pin diesen
    // Bootstrap-Stand verbietet. Die Reihenfolge bleibt CertificateHash-
    // aufsteigend: mehrere Zertifikate fuer denselben Schluessel behalten
    // exakt die bisherige erste anwendbare Antwort.
    let active: Vec<_> = head.map_or_else(
        || {
            bootstrap_active_certificates(trust, proposed_sequence)
                .map(|(hash, fields)| (hash, fields.clone()))
                .collect()
        },
        |head| {
            head.active_certificates()
                .map(|(hash, fields)| (hash, fields.clone()))
                .collect()
        },
    );
    let mut devices = HashMap::new();
    for (certificate_hash, fields) in active {
        let Some(thumbprint) = fields.signing_key_thumbprint else {
            continue;
        };
        let Some(exact_key) = fields.signing_public_cose_key.as_ref() else {
            continue;
        };
        let Ok(public_key) = CanonicalPublicCoseKey::from_deterministic_cbor(exact_key) else {
            continue;
        };
        // Ein unbekanntes Literal verweigert diesen Schluessel. Auch diese
        // erste Antwort bleibt stehen, statt ein spaeteres Zertifikat unter
        // demselben Schluessel unbemerkt vorzuziehen.
        devices.entry(thumbprint).or_insert_with(|| {
            let capabilities = fields
                .capabilities
                .iter()
                .map(|literal| CertificateCapability::try_from(literal.as_str()))
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            Some(RegisteredDevice::new(
                organization_id,
                certificate_hash,
                public_key,
                capabilities,
            ))
        });
    }
    devices
}

#[async_trait]
impl TrustEventValidator for PostgresTrustAuthority {
    /// Prueft das GELIEFERTE OBJEKT, nicht nur die Organisation.
    ///
    /// Zwei Wege, und beide gehoeren der geteilten Pruefung:
    ///
    /// 1. Ein `registryEvent` ist gueltig, wenn es der NAECHSTE Kopf wird —
    ///    `verify_registry_candidate` plus `select_registry_head` pruefen
    ///    dafuer Signatur, Autorisierung, Policy, Kettenposition und, ueber
    ///    `prepare_local_time`, das `notBefore`/`notAfter`-Fenster. Wird ein
    ///    anderer Kopf gewaehlt, braucht der Aufrufer erst den — und der
    ///    Fehlerkoerper nennt ihn.
    /// 2. Jedes andere `.etb` laeuft durch
    ///    [`ea_trust::verify_catalogue_admission`]: Organisationsbindung,
    ///    die Signiererregel SEINER Objektart im aktuellen Abschluss, und sein
    ///    Zeitfenster. Aufnahme ist keine Autoritaet — sie legt das Objekt in
    ///    den Katalog, damit der Kopf, der es spaeter nennt, es ueberhaupt
    ///    finden kann.
    ///
    /// LESEND: der Lauf laeuft auf einem Speicher, der nach der Antwort fort
    /// ist. Der persistente Pin rueckt erst in [`Self::advance_pinned_head`]
    /// nach, also nachdem das Objekt liegt und indiziert ist.
    async fn validate_exact_etb(
        &self,
        organization_id: OrganizationId,
        object_hash: ObjectHash,
        exact_etb_bytes: &[u8],
        now: UnixMillis,
    ) -> Result<(), TrustPublishError> {
        let prepared = self
            .prepare(organization_id, Some(exact_etb_bytes))
            .await?
            .ok_or(TrustServiceError::AnchorMissing)?;
        let key = verification_state_key(organization_id);
        let mut store =
            EphemeralTrustStateStore::new(key, UnixMillis::new(INITIAL_TRUSTED_FLOOR_MILLIS));
        let (trust, head) = walk_to_selected_head(
            &prepared.anchor,
            &prepared.source,
            &mut store,
            key,
            prepared.proposed_sequence,
            now,
            prepared.head_count,
        )
        .map_err(|error| TrustPublishError::from(map_walk_error(error)))?;

        if subtype_of(exact_etb_bytes) == Some(TrustSubtypeV1::RegistryEvent) {
            return match head {
                Some(head) if head.registry_head_hash() == object_hash => Ok(()),
                // „erforderlicher neuerer Registry-Head“ — 409 mit genau der
                // Version und dem Hash, die der Aufrufer zuerst holen muss.
                Some(head) => Err(TrustPublishError::requiring_head(
                    head.registry_version(),
                    head.registry_head_hash(),
                )),
                None => Err(TrustServiceError::EventNotApplicable.into()),
            };
        }

        verify_catalogue_admission(
            &trust,
            head.as_ref(),
            exact_etb_bytes,
            now,
            prepared.proposed_sequence,
        )
        .map(|_| ())
        .map_err(|error| TrustPublishError::from(map_admission_error(error)))
    }

    /// Rueckt den persistenten Kopf nach — der EINE schreibende Weg.
    async fn advance_pinned_head(
        &self,
        organization_id: OrganizationId,
        now: UnixMillis,
    ) -> Result<(), TrustPublishError> {
        let Some(prepared) = self.prepare(organization_id, None).await? else {
            return Ok(());
        };
        let key = TrustStateKey {
            organization_id,
            device_id: DeviceId::try_from(&SERVER_TRUST_DEVICE_ID_V1[..])
                .map_err(|_| TrustServiceError::Internal)?,
        };
        let mut store = super::trust_state::PostgresTrustStateStore::new(
            self.pool.clone(),
            UnixMillis::new(INITIAL_TRUSTED_FLOOR_MILLIS),
        );
        walk_to_selected_head(
            &prepared.anchor,
            &prepared.source,
            &mut store,
            key,
            prepared.proposed_sequence,
            now,
            prepared.head_count,
        )
        .map(|_| ())
        .map_err(|error| TrustPublishError::from(map_walk_error(error)))
    }
}

/// Die Kopfauswahl fuer GENAU EINE Eintragssequenz (`design.md` §13.3,
/// Schritt 5).
///
/// Sie laeuft ueber denselben `walk_to_selected_head` wie die
/// Autoritaetsaufloesung und ueber denselben fluechtigen Speicher — LESEND,
/// ohne Zeile, ohne Rennen. Der Unterschied ist die VORGESCHLAGENE SEQUENZ:
/// die Autoritaetsaufloesung nimmt die groesste bekannte
/// `effective-from-sequence`, weil die Trust-Endpunkte in keine Kette
/// schreiben; der Commit nimmt die Sequenz SEINES Eintrags, weil
/// [`SelectedRegistryHead::active_certificates`] genau ueber sie antwortet.
/// Denselben Kopf fuer beides zu nehmen ergaebe die falsche Empfaengermenge.
#[async_trait]
impl ea_sync_server::RegistryHeadDirectory for PostgresTrustAuthority {
    async fn select_head_for_sequence(
        &self,
        organization_id: OrganizationId,
        proposed_sequence: ChainSequence,
        now: UnixMillis,
    ) -> Result<RegistryHeadSelectionV1, AuthorityError> {
        let Some(prepared) = self
            .prepare(organization_id, None)
            .await
            .map_err(|_| AuthorityError::Unavailable)?
        else {
            // Ohne Anker gibt es keine Wurzel und damit keinen Kopf. Eine
            // Antwort, kein Ausfall.
            return Ok(RegistryHeadSelectionV1::NoApplicableHead);
        };
        let key = verification_state_key(organization_id);
        let mut store =
            EphemeralTrustStateStore::new(key, UnixMillis::new(INITIAL_TRUSTED_FLOOR_MILLIS));
        match walk_to_selected_head(
            &prepared.anchor,
            &prepared.source,
            &mut store,
            key,
            proposed_sequence,
            now,
            prepared.head_count,
        ) {
            Ok((_, Some(head))) => Ok(RegistryHeadSelectionV1::Selected(Arc::new(head))),
            // Kein gewaehlter Kopf. WELCHE der beiden Antworten es ist, sagt
            // der Bestand: gibt es ueberhaupt einen Registry-Kopf, dann ist
            // dieser Lauf an seinem Zeitfenster oder seiner Sequenzleihe
            // stehen geblieben, und der Aufrufer braucht den naechsten.
            //
            // Die geforderte Version wird aus dem KATALOG gelesen und nicht
            // aus `PendingFutureSuccessor`: `ea-trust` gibt aus diesem Beweis
            // nichts heraus (`crates/ea-trust/src/registry.rs`), und die Crate
            // wird dafuer nicht aufgebohrt — dieselbe Zurueckhaltung, die
            // `crates/ea-verify/src/entry.rs` beim Schreiberwechsel begruendet.
            Ok((_, None)) => Ok(highest_known_head(&prepared.source).map_or(
                RegistryHeadSelectionV1::NoApplicableHead,
                |(version, head_hash)| RegistryHeadSelectionV1::PendingFuture {
                    required_registry_version: version,
                    required_registry_head_hash: head_hash,
                },
            )),
            Err(HeadWalkError::Unavailable) => Err(AuthorityError::Unavailable),
            Err(HeadWalkError::StateConflict) => Err(AuthorityError::StateConflict),
            Err(HeadWalkError::NotApplicable | HeadWalkError::Invalid) => {
                Ok(RegistryHeadSelectionV1::NoApplicableHead)
            }
        }
    }
}

/// Die hoechste bekannte Registry-Version dieser Organisation und ihr
/// Objekthash.
///
/// Gelesen aus den SIGNIERTEN Ereignissen des Katalogs und nicht aus
/// `registry_events`: eine Zeile ist keine Signatur, und diese Antwort steht
/// in einem Fehlerkoerper, den ein Aufrufer als Anweisung liest.
fn highest_known_head(source: &CatalogSource) -> Option<(RegistryVersion, ObjectHash)> {
    let mut highest: Option<(RegistryVersion, ObjectHash)> = None;
    for (object_hash, bytes) in &source.0 {
        let Ok(ParsedArchiveObject::Trust(parsed)) = ea_format::decode_exact_object(bytes) else {
            continue;
        };
        let Ok(DecodedTrustPayloadV1::RegistryEvent(core)) = parsed.value().decoded_payload()
        else {
            continue;
        };
        let version = core.fields().registry_version;
        if highest.is_none_or(|(known, _)| version.get() > known.get()) {
            highest = Some((version, *object_hash));
        }
    }
    highest
}

/// Was ein Lauf braucht: Anker, Katalog und die daraus gelesenen Kennzahlen.
struct PreparedClosure {
    anchor: TrustAnchorV1,
    source: CatalogSource,
    proposed_sequence: ChainSequence,
    head_count: usize,
}

impl PostgresTrustAuthority {
    /// Sammelt Anker und Katalog — wahlweise samt einem noch nicht abgelegten
    /// Objekt, damit die Pruefung genau die Menge sieht, die ein Reader spaeter
    /// saehe.
    async fn prepare(
        &self,
        organization_id: OrganizationId,
        additional: Option<&[u8]>,
    ) -> Result<Option<PreparedClosure>, TrustServiceError> {
        let Some(anchor_bytes) = self
            .anchor_bytes(organization_id)
            .await
            .map_err(|_| TrustServiceError::DependencyUnavailable)?
        else {
            return Ok(None);
        };
        let anchor =
            decode_trust_anchor(&anchor_bytes).map_err(|_| TrustServiceError::AnchorMissing)?;
        let mut catalog = self
            .trust_catalog(organization_id)
            .await
            .map_err(|_| TrustServiceError::DependencyUnavailable)?;
        if let Some(bytes) = additional {
            catalog.insert(
                ea_crypto::object_hash(bytes),
                Arc::<[u8]>::from(bytes.to_vec()),
            );
        }
        let proposed_sequence = highest_effective_from_sequence(&catalog);
        let head_count = registry_event_count(&catalog);
        Ok(Some(PreparedClosure {
            anchor,
            source: CatalogSource(catalog),
            proposed_sequence,
            head_count,
        }))
    }
}

/// Die Befunde der Einzelobjektaufnahme in der Sprache des Protokolls.
const fn map_admission_error(error: TrustError) -> TrustServiceError {
    match error {
        // „Ueber diese Objektart kann die geteilte Pruefung heute nichts
        // sagen“ — und was sie nicht beweisen kann, nimmt der Server nicht an.
        TrustError::ActionMismatch => TrustServiceError::EventUnverifiable,
        TrustError::AuthNotYetValid | TrustError::AuthExpired => {
            TrustServiceError::EventNotYetOrNoLongerValid
        }
        TrustError::StateConflict => TrustServiceError::StateConflict,
        TrustError::StateUnavailable => TrustServiceError::DependencyUnavailable,
        _ => TrustServiceError::EventInvalid,
    }
}

const fn map_walk_error(error: HeadWalkError) -> TrustServiceError {
    match error {
        HeadWalkError::Unavailable => TrustServiceError::DependencyUnavailable,
        HeadWalkError::StateConflict => TrustServiceError::StateConflict,
        HeadWalkError::NotApplicable => TrustServiceError::EventNotYetOrNoLongerValid,
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
