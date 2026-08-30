//! Der technische Index der Trust-Objekte hinter PostgreSQL.
//!
//! Er INDIZIERT und BLAETTERT. Er entscheidet nichts: welche Bytes gueltig
//! sind, sagt ausschliesslich die geteilte Pruefung aus `ea-trust`, und was
//! ausgeliefert wird, holt der Dienst als exakte Bytes aus dem Object Store.
//!
//! Die Aufnahme laeuft in EINER Transaktion ueber drei Tabellen —
//! `object_index`, `trust_events` und, fuer ein `registryEvent`,
//! `registry_events`. Bricht eine der drei, bricht die ganze Aufnahme: ein
//! halb indiziertes Trust-Ereignis waere eine Registry-Linie mit einem Loch,
//! und ein Reader liefe darueber in eine falsche Kopfauswahl.

use async_trait::async_trait;
use ea_format::ObjectTypeV1;
use ea_sync_server::{
    RegistryLineEntryV1, RepositoryError, TrustEventCommandV1, TrustEventStore, TrustIndexOutcome,
};
use ea_types::{ObjectHash, OrganizationId, RegistryVersion};
use sqlx::Row;

use crate::adapters::postgres::PostgresRepository;

const fn unavailable(_error: &sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable
}

/// Die `eventId` eines Trust-Ereignisses.
///
/// Die ersten 16 Byte seines Objekthashes. Sie ist rein TECHNISCH: sie
/// benennt dieselbe Bytefolge wie `object_hash` und traegt keinen eigenen
/// Wert. Eine laufende Nummer waere nicht content-addressed und machte
/// dieselbe Aufnahme zweimal zu zwei verschiedenen Ereignissen.
fn event_id(object_hash: ObjectHash) -> [u8; 16] {
    let mut id = [0_u8; 16];
    id.copy_from_slice(&object_hash.as_bytes()[..16]);
    id
}

#[async_trait]
impl TrustEventStore for PostgresRepository {
    async fn index_event(
        &self,
        event: TrustEventCommandV1,
    ) -> Result<TrustIndexOutcome, RepositoryError> {
        let mut transaction = self.pool().begin().await.map_err(|e| unavailable(&e))?;

        let existing = sqlx::query(
            "SELECT event_code FROM trust_events WHERE organization_id = $1 AND object_hash = $2",
        )
        .bind(&event.organization_id.as_bytes()[..])
        .bind(&event.object_hash.as_bytes()[..])
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?;
        if let Some(row) = existing {
            let code: String = row.get("event_code");
            transaction.rollback().await.map_err(|e| unavailable(&e))?;
            return Ok(if code == event.subtype_code {
                TrustIndexOutcome::AlreadyIndexed
            } else {
                TrustIndexOutcome::Conflict
            });
        }

        sqlx::query(
            "INSERT INTO object_index (object_hash, organization_id, object_type_code, \
             size_bytes, stored_at_millis) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (object_hash) DO NOTHING",
        )
        .bind(&event.object_hash.as_bytes()[..])
        .bind(&event.organization_id.as_bytes()[..])
        .bind(i16::try_from(ObjectTypeV1::Trust.code()).map_err(|_| RepositoryError::Unavailable)?)
        .bind(i64::try_from(event.size_bytes).map_err(|_| RepositoryError::Unavailable)?)
        .bind(event.received_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?;

        sqlx::query(
            "INSERT INTO trust_events (organization_id, event_id, object_hash, event_code, \
             received_at_millis) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&event.organization_id.as_bytes()[..])
        .bind(&event_id(event.object_hash)[..])
        .bind(&event.object_hash.as_bytes()[..])
        .bind(&event.subtype_code)
        .bind(event.received_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?;

        if let Some(version) = event.registry_version {
            let inserted = sqlx::query(
                "INSERT INTO registry_events (organization_id, registry_version, \
                 registry_head_hash, effective_from_millis) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (organization_id, registry_version) DO NOTHING",
            )
            .bind(&event.organization_id.as_bytes()[..])
            .bind(i64::try_from(version.get()).map_err(|_| RepositoryError::Unavailable)?)
            .bind(&event.object_hash.as_bytes()[..])
            .bind(event.effective_from.get())
            .execute(&mut *transaction)
            .await
            .map_err(|e| unavailable(&e))?;
            if inserted.rows_affected() != 1 {
                // Diese Version traegt bereits ein ANDERES Objekt. Alles
                // zurueck — auch der Objektindex und `trust_events`.
                transaction.rollback().await.map_err(|e| unavailable(&e))?;
                return Ok(TrustIndexOutcome::Conflict);
            }
        }

        transaction.commit().await.map_err(|e| unavailable(&e))?;
        Ok(TrustIndexOutcome::Indexed)
    }

    async fn registry_line_after(
        &self,
        organization_id: OrganizationId,
        after_version: RegistryVersion,
        limit: usize,
    ) -> Result<Vec<RegistryLineEntryV1>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT registry_version, registry_head_hash FROM registry_events \
             WHERE organization_id = $1 AND registry_version > $2 \
             ORDER BY registry_version LIMIT $3",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(i64::try_from(after_version.get()).map_err(|_| RepositoryError::Unavailable)?)
        .bind(i64::try_from(limit).map_err(|_| RepositoryError::Unavailable)?)
        .fetch_all(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;

        let mut line = Vec::with_capacity(rows.len());
        for row in &rows {
            let version: i64 = row.get("registry_version");
            let head: Vec<u8> = row.get("registry_head_hash");
            line.push(RegistryLineEntryV1 {
                registry_version: RegistryVersion::new(
                    u64::try_from(version).map_err(|_| RepositoryError::Unavailable)?,
                ),
                object_hash: ObjectHash::try_from(head.as_slice())
                    .map_err(|_| RepositoryError::Unavailable)?,
            });
        }
        Ok(line)
    }
}
