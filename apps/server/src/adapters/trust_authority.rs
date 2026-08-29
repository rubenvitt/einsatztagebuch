//! Die Autoritaetsaufloesung des Servers — ueber die GETEILTE Trust-Pruefung.
//!
//! # Warum das hier so aufwendig aussieht
//!
//! Der Server darf nicht wissen, welche Capability ein Zertifikat traegt; er
//! darf es nur FESTSTELLEN, und zwar auf demselben Weg wie jeder Reader:
//! `verify_trust` gegen den Anker der Organisation, dann
//! `verify_registry_candidate`, `prepare_local_time` und
//! `select_registry_head`. Erst der gewaehlte Head sagt, welche Zertifikate
//! zur vorgeschlagenen Sequenz aktiv sind und welche Capabilities sie tragen
//! (`crates/ea-trust/src/registry.rs`).
//!
//! Die Abkuerzung waere, `role_intervals` zu lesen. Sie ist verboten: eine
//! Zeile ist keine Signatur, und `design.md` §12 laesst Rollen und
//! Capabilities ausschliesslich aus Root-signierten Trust-Objekten entstehen.
//! Ein aus Zeilen zusammengesetztes Urteil waere eine ZWEITE Trust-Umsetzung
//! neben der geprueften.
//!
//! # Die vorgeschlagene Sequenz
//!
//! `verify_registry_candidate` fragt nach einer Kettensequenz, zu der die
//! Autoritaet gelten soll. Die Trust-Endpunkte schreiben in keine Kette, also
//! gibt es keine natuerliche. Genommen wird deshalb die groesste
//! `effective-from-sequence` der bekannten Registry-Ereignisse: das ist die
//! Sequenz, ab der der juengste Head ueberhaupt gilt, und sie stammt aus dem
//! signierten Ereignis selbst und nicht aus einer Zeile.
//!
//! # Nebenwirkung
//!
//! `select_registry_head` SCHREIBT: es pinnt den gewaehlten Head im
//! Vertrauenszustand. Das ist der Vertrag von `ea-trust` und keine
//! Bequemlichkeit dieses Adapters — die Kopfauswahl ist dort ausdruecklich ein
//! schreibender Weg (`apps/server/src/adapters/trust_state.rs`). Ein
//! verlorenes Rennen antwortet mit `EA-TRUST-STATE-CONFLICT`, und der Aufrufer
//! bekommt fail-closed „nicht autorisiert“ statt einer geratenen Antwort.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use ea_crypto::{CanonicalPublicCoseKey, CertificateCapability};
use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject};
use ea_sync_protocol::RegisteredDevice;
use ea_sync_server::{
    DeviceAuthorityDirectory, ObjectStore, RepositoryError,
    trust::{TrustEventValidator, TrustServiceError},
};
use ea_trust::{
    RegistrySelectionOutcome, SelectedRegistryHead, TrustObjectSource, TrustSourceError,
    TrustStateKey, decode_trust_anchor, load_trust_state, prepare_local_time, select_registry_head,
    verify_registry_candidate, verify_trust,
};
use ea_types::{ChainSequence, DeviceId, KeyThumbprint, ObjectHash, OrganizationId, UnixMillis};
use sqlx::{PgPool, Row};

/// Die technische Geraetekennung, unter der der SERVER seinen eigenen
/// Vertrauenszustand fuehrt.
///
/// `TrustStateKey` ist auf (Organisation, Geraet) geschluesselt, und der
/// Server ist aus Sicht dieser Tabelle ein Geraet wie jedes andere — eines
/// ohne Zertifikat. Der Wert ist eine Konstante und traegt keinen fachlichen
/// Sinn; er muss nur ueber Laeufe hinweg derselbe bleiben, damit der gepinnte
/// Head nicht bei jedem Start verloren geht.
pub const SERVER_TRUST_DEVICE_ID_V1: [u8; 16] = [0x5e; 16];

/// Der Zeitboden, mit dem eine noch leere Vertrauenszeile beginnt.
///
/// Null und nicht „jetzt“: der Boden ist streng monoton, und ein zu hoch
/// gesetzter Startwert liesse sich nie mehr senken. Ein Boden von null ist der
/// ehrliche leere Stand.
const INITIAL_TRUSTED_FLOOR_MILLIS: i64 = 0;

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

    /// Der gewaehlte Registry-Head dieser Organisation, oder `None`, wenn es
    /// keinen gibt, den die geteilte Pruefung traegt.
    async fn selected_head(
        &self,
        organization_id: OrganizationId,
        now: UnixMillis,
    ) -> Result<Option<SelectedRegistryHead>, RepositoryError> {
        let Some(anchor_bytes) = self.anchor_bytes(organization_id).await? else {
            return Ok(None);
        };
        let Ok(anchor) = decode_trust_anchor(&anchor_bytes) else {
            return Ok(None);
        };
        let catalog = self.trust_catalog(organization_id).await?;
        let proposed_sequence = highest_effective_from_sequence(&catalog);
        let source = CatalogSource(catalog);

        let key = TrustStateKey {
            organization_id,
            device_id: DeviceId::try_from(&SERVER_TRUST_DEVICE_ID_V1[..])
                .map_err(|_| RepositoryError::Unavailable)?,
        };
        let mut store = super::trust_state::PostgresTrustStateStore::new(
            self.pool.clone(),
            UnixMillis::new(INITIAL_TRUSTED_FLOOR_MILLIS),
        );
        let Ok(snapshot) = load_trust_state(&mut store, key) else {
            return Ok(None);
        };
        let Ok(trust) = verify_trust(&anchor, &source, snapshot) else {
            return Ok(None);
        };
        let Ok(candidate) = verify_registry_candidate(&trust, proposed_sequence) else {
            return Ok(None);
        };
        let Ok(local_time) = prepare_local_time(&mut store, &candidate, now, &[]) else {
            return Ok(None);
        };
        match select_registry_head(candidate, local_time, None) {
            Ok(RegistrySelectionOutcome::Selected(selected)) => Ok(Some(selected)),
            // Advanced, PendingFuture und jeder Fehler sind fail-closed
            // „keine Autoritaet“: keiner von beiden ist eine Kopfauswahl, an
            // der eine Capability haenge.
            _ => Ok(None),
        }
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

#[async_trait]
impl DeviceAuthorityDirectory for PostgresTrustAuthority {
    async fn resolve(
        &self,
        organization_id: OrganizationId,
        key_thumbprint: KeyThumbprint,
        now: UnixMillis,
    ) -> Result<Option<RegisteredDevice>, RepositoryError> {
        let Some(head) = self.selected_head(organization_id, now).await? else {
            return Ok(None);
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
    /// Die geteilte Pruefung, gegen den Katalog EINSCHLIESSLICH des soeben
    /// abgelegten Objekts.
    ///
    /// Der Katalog wird um genau dieses eine Objekt erweitert und der ganze
    /// Abschluss noch einmal gefuehrt. Traegt er, ist das `.etb` gueltig —
    /// nach derselben Regel, nach der ein Reader es spaeter prueft.
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
        let source = CatalogSource(catalog);

        let key = TrustStateKey {
            organization_id,
            device_id: DeviceId::try_from(&SERVER_TRUST_DEVICE_ID_V1[..])
                .map_err(|_| TrustServiceError::Internal)?,
        };
        let mut store = super::trust_state::PostgresTrustStateStore::new(
            self.pool.clone(),
            UnixMillis::new(INITIAL_TRUSTED_FLOOR_MILLIS),
        );
        let snapshot =
            load_trust_state(&mut store, key).map_err(|_| TrustServiceError::EventInvalid)?;
        let trust = verify_trust(&anchor, &source, snapshot)
            .map_err(|_| TrustServiceError::EventInvalid)?;
        verify_registry_candidate(&trust, proposed_sequence)
            .map_err(|_| TrustServiceError::EventInvalid)?;
        let _ = now;
        Ok(())
    }
}

/// Die groesste `effective-from-sequence` der Registry-Ereignisse im Katalog.
fn highest_effective_from_sequence(catalog: &BTreeMap<ObjectHash, Arc<[u8]>>) -> ChainSequence {
    let mut highest = 0_u64;
    for bytes in catalog.values() {
        let Ok(ParsedArchiveObject::Trust(parsed)) = ea_format::decode_exact_object(bytes) else {
            continue;
        };
        let Ok(DecodedTrustPayloadV1::RegistryEvent(core)) = parsed.value().decoded_payload()
        else {
            continue;
        };
        highest = highest.max(core.fields().effective_from_sequence.get());
    }
    ChainSequence::new(highest)
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
