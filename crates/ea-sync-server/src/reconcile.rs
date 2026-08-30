//! Der vorletzte Absatz von `design.md` §13.3: die unsichtbaren Waisen.
//!
//! „Ein Absturz vor dem Datenbank-Commit hinterlaesst hoechstens
//! content-addressed, nicht sichtbare Entry-, Grant- oder Receipt-Orphans.
//! Eine Reconciliation darf sie nur nach erneuter vollstaendiger Pruefung
//! uebernehmen oder quarantaenisieren; sie darf einen Receipt nicht als
//! angenommen ausgeben, solange keine atomare Commit-Referenz existiert."
//!
//! # Was „atomare Commit-Referenz" hier konkret ist
//!
//! Die Zeile im technischen Objektindex. Fuer die Objektarten dieses Pfades —
//! Entry, Grant und Receipt — entsteht sie AUSSCHLIESSLICH in der Transaktion
//! von Schritt 8, gemeinsam mit Entry, Grants, Receipt und Kopf
//! (`apps/server/src/adapters/postgres.rs`). Ein Objekt, das im Object Store
//! liegt und im Index fehlt, ist deshalb genau das, was §13.3 als zulaessige
//! Waise benennt — und es ist nicht angenommen.
//!
//! NACHGESEHEN und nicht angenommen: `INSERT INTO object_index` steht im
//! ganzen Baum an genau ZWEI Stellen. Die eine ist jene Commit-Transaktion;
//! die andere ist `apps/server/src/adapters/trust_index.rs`, und sie schreibt
//! ausschliesslich `ObjectTypeV1::Trust` in derselben Transaktion, die auch
//! `trust_events` fuellt — fuer ein `.etb` ist also auch dort die Zeile die
//! atomare Referenz. Der Object-Store-Adapter schreibt den Index NICHT: er
//! bekommt das Verzeichnis nur lesend, um zu einem Hash die Objektart
//! aufzuloesen (`apps/server/src/adapters/s3.rs`). Ein content-addressed
//! abgelegtes Objekt wird durch die Ablage allein deshalb nie sichtbar.
//!
//! Der Index ist damit NICHT die Quelle der Gueltigkeit, sondern der Beleg der
//! SICHTBARKEIT. Die Gueltigkeit stellt weiterhin die erneute Pruefung der
//! Bytes fest, und die laeuft hier vor jedem Urteil.
//!
//! # Warum die Antwort dreiwertig ist
//!
//! „Uebernehmen oder quarantaenisieren" sind zwei Ausgaenge, und „liegt da,
//! gehoert niemandem, schadet nicht" ist ein dritter. Ihn mit der Quarantaene
//! zusammenzuwerfen hiesse, jeden abgebrochenen Commit als Angriff zu fuehren;
//! ihn mit der Uebernahme zusammenzuwerfen hiesse, einen Receipt als
//! angenommen auszugeben, den keine Transaktion je genannt hat. Genau das
//! verbietet der Absatz.

use core::fmt;

use ea_format::ObjectTypeV1;
use ea_types::{ObjectHash, OrganizationId, UnixMillis};

use crate::{
    models::{SecurityEventKindV1, SecurityEventV1, StoreError, object_key},
    ports::{ObjectStore, ObjectTypeDirectory, SecurityEventSink, ServerClock},
};

/// Was der Bestand ueber ein content-addressed abgelegtes Objekt sagt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileOutcomeV1 {
    /// Die Bytes tragen, und eine atomare Commit-Referenz nennt sie. Das
    /// Objekt ist sichtbar und angenommen.
    Adopted,
    /// Die Bytes tragen, aber KEINE Commit-Referenz nennt sie. Es bleibt
    /// unsichtbar und wird ausdruecklich NICHT als angenommen ausgegeben.
    InvisibleOrphan,
    /// Die Bytes tragen NICHT: der Inhalt passt nicht zu seiner Adresse, oder
    /// er ist nicht die Objektart, unter deren Namensraum er liegt. Ein
    /// Security Event, und das Objekt wird nie uebernommen.
    Quarantined,
}

/// Warum ein Objekt nicht beurteilt werden konnte.
///
/// „Es traegt nicht" steht bewusst NICHT darin: das ist ein URTEIL und
/// [`ReconcileOutcomeV1::Quarantined`].
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ReconcileError {
    /// Unter diesem Hash liegt nichts.
    NotFound,
    /// Datenbank oder Object Store antworten nicht.
    DependencyUnavailable,
}

impl ReconcileError {
    pub const ALL: [Self; 2] = [Self::NotFound, Self::DependencyUnavailable];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "EA-RECONCILE-NOT-FOUND",
            Self::DependencyUnavailable => "EA-RECONCILE-DEPENDENCY-UNAVAILABLE",
        }
    }
}

impl fmt::Display for ReconcileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReconcileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReconcileError {}

/// Was die Beurteilung an Ports braucht.
pub struct ReconcilePorts<'a> {
    pub clock: &'a dyn ServerClock,
    pub objects: &'a dyn ObjectStore,
    pub object_types: &'a dyn ObjectTypeDirectory,
    pub security: &'a dyn SecurityEventSink,
}

/// Beurteilt EIN content-addressed abgelegtes Objekt.
///
/// Die Reihenfolge ist fail-closed und nicht verhandelbar:
///
/// 1. die exakten Bytes aus dem BENANNTEN Namensraum holen — nicht ueber den
///    Index, denn genau der fehlt einer Waise,
/// 2. sie ERNEUT gegen ihre Adresse hashen — der Inhalt muss seine Adresse
///    tragen, sonst ist er quarantaenepflichtig,
/// 3. sie ERNEUT parsen und ihre Objektart gegen die erwartete stellen,
/// 4. und erst dann fragen, ob eine atomare Commit-Referenz sie nennt.
///
/// Schritt 4 ist ausdruecklich der LETZTE. Stuende er vorn, waere die Antwort
/// „im Index, also gut" — und der Index sagt nichts ueber Bytes.
///
/// # Errors
///
/// [`ReconcileError::NotFound`], wenn unter dem Hash nichts liegt, und
/// [`ReconcileError::DependencyUnavailable`], wenn Object Store oder Datenbank
/// nicht antworten. Beides ist KEIN Urteil ueber das Objekt.
pub async fn reconcile_object(
    object_hash: ObjectHash,
    expected_kind: ObjectTypeV1,
    organization_id: OrganizationId,
    ports: &ReconcilePorts<'_>,
) -> Result<ReconcileOutcomeV1, ReconcileError> {
    let stream = ports
        .objects
        .get_exact_in(expected_kind, object_hash)
        .await
        .map_err(|error| match error {
            StoreError::NotFound => ReconcileError::NotFound,
            _ => ReconcileError::DependencyUnavailable,
        })?;
    let bytes = stream
        .collect()
        .await
        .map_err(|_| ReconcileError::DependencyUnavailable)?
        .into_bytes()
        .to_vec();

    if ea_crypto::object_hash(&bytes) != object_hash {
        return quarantine(object_hash, expected_kind, organization_id, ports).await;
    }
    let parsed_kind = match ea_format::decode_exact_object(&bytes) {
        Ok(object) => object_type_of(&object),
        Err(_) => return quarantine(object_hash, expected_kind, organization_id, ports).await,
    };
    if parsed_kind != expected_kind {
        return quarantine(object_hash, expected_kind, organization_id, ports).await;
    }

    // Erst JETZT die Sichtbarkeitsfrage. `Some` heisst: die Transaktion von
    // Schritt 8 hat dieses Objekt genannt.
    let referenced = ports
        .object_types
        .object_type_of(object_hash)
        .await
        .map_err(|_| ReconcileError::DependencyUnavailable)?;
    Ok(match referenced {
        Some(kind) if kind == expected_kind => ReconcileOutcomeV1::Adopted,
        // Der Index nennt eine ANDERE Art unter demselben Hash. Das ist kein
        // Waisenfall, sondern ein Widerspruch im Bestand.
        Some(_) => quarantine(object_hash, expected_kind, organization_id, ports).await?,
        None => ReconcileOutcomeV1::InvisibleOrphan,
    })
}

/// Der Quarantaenefall samt Security Event.
///
/// `subject` traegt den OBJEKTSCHLUESSEL und sonst nichts — dieselbe
/// technische Kennung, die auch Schritt 3 protokolliert.
async fn quarantine(
    object_hash: ObjectHash,
    expected_kind: ObjectTypeV1,
    organization_id: OrganizationId,
    ports: &ReconcilePorts<'_>,
) -> Result<ReconcileOutcomeV1, ReconcileError> {
    // Der Ausgang wird verworfen: das Urteil steht fest, auch wenn es sich
    // nicht protokollieren liess.
    let _ = ports
        .security
        .record(SecurityEventV1 {
            organization_id,
            kind: SecurityEventKindV1::ObjectHashConflict,
            subject: object_key(expected_kind, object_hash),
            observed_at: observed_at(ports),
        })
        .await;
    Ok(ReconcileOutcomeV1::Quarantined)
}

fn observed_at(ports: &ReconcilePorts<'_>) -> UnixMillis {
    ports.clock.now()
}

/// Die Objektart eines geparsten Objekts.
///
/// Ueber die geschlossene Menge von `ea-format` und ohne Auffangzweig: eine
/// siebte Objektart faellt hier auf, statt still als „passt nicht" zu enden.
const fn object_type_of(object: &ea_format::ParsedArchiveObject) -> ObjectTypeV1 {
    match object {
        ea_format::ParsedArchiveObject::Entry(_) => ObjectTypeV1::Entry,
        ea_format::ParsedArchiveObject::Grant(_) => ObjectTypeV1::Grant,
        ea_format::ParsedArchiveObject::Receipt(_) => ObjectTypeV1::Receipt,
        ea_format::ParsedArchiveObject::Evidence(_) => ObjectTypeV1::Evidence,
        ea_format::ParsedArchiveObject::Trust(_) => ObjectTypeV1::Trust,
        ea_format::ParsedArchiveObject::Destroyed(_) => ObjectTypeV1::Destroyed,
    }
}
