//! Die Einmalwert- und Aufnahmetabellen hinter PostgreSQL.
//!
//! Vier Ports auf einem Adapter, weil sie EINE Verantwortung teilen: die
//! technische Aufnahme eines Aufrufers, der noch keine Autoritaet hat. Keine
//! Anweisung dieser Datei schreibt eine Rolle, eine Capability oder ein
//! Trust-Objekt; die Freigabe entsteht ausschliesslich aus Root-signierten
//! Trust-Objekten (`design.md` §12).
//!
//! Jede Einmaligkeit steht als CONSTRAINT und nicht als vorheriges `SELECT`:
//! ein `SELECT` gefolgt von einem `INSERT` verlaeuft zwischen zwei
//! Verbindungen im Rennen, ein Primaerschluessel nicht.

use async_trait::async_trait;
use ea_sync_server::{
    ChallengeSpendOutcome, ChallengeStore, CredentialRegistrationOutcome, DeviceRegistrationStore,
    PENDING_REGISTRATION_STATE_V1, PendingDeviceRequestV1, PendingRegistrationOutcome,
    RepositoryError, RequestIdStore, WebauthnCredentialStore, WebauthnCredentialV1,
};
use ea_types::{Hash32, OrganizationId, UnixMillis};
use sqlx::Row;

use crate::adapters::postgres::PostgresRepository;

/// Jeder unerkannte Datenbankfehler ist ein Ausfall. Der Datenbanktext wird
/// NICHT weitergereicht: er truege Spaltenwerte.
const fn unavailable(_error: &sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable
}

#[async_trait]
impl ChallengeStore for PostgresRepository {
    async fn issue(
        &self,
        organization_id: OrganizationId,
        nonce_digest: Hash32,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<(), RepositoryError> {
        // Ohne `ON CONFLICT`: derselbe Digest zweimal auszugeben hiesse, dass
        // die Zufallsquelle dieselbe Nonce zweimal geliefert hat. Das ist kein
        // Wiederholungsfall, sondern ein Befund.
        sqlx::query(
            "INSERT INTO challenges (organization_id, nonce_digest, challenge_state, \
             issued_at_millis, expires_at_millis) VALUES ($1, $2, 'issued', $3, $4)",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&nonce_digest.as_bytes()[..])
        .bind(issued_at.get())
        .bind(expires_at.get())
        .execute(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(())
    }

    async fn count_issued_since(
        &self,
        organization_id: OrganizationId,
        since: UnixMillis,
    ) -> Result<u64, RepositoryError> {
        let row = sqlx::query(
            "SELECT count(*) AS issued FROM challenges \
             WHERE organization_id = $1 AND issued_at_millis >= $2",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(since.get())
        .fetch_one(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        let issued: i64 = row.get("issued");
        u64::try_from(issued).map_err(|_| RepositoryError::Unavailable)
    }

    async fn spend(
        &self,
        organization_id: OrganizationId,
        nonce_digest: Hash32,
        now: UnixMillis,
    ) -> Result<ChallengeSpendOutcome, RepositoryError> {
        // EIN Statement: das bedingte `UPDATE` ist zugleich die Sperre. Ein
        // zweiter Aufrufer trifft null Zeilen und bekommt danach ueber den
        // Zustandsblick den GRUND — abgelaufen oder bereits verbraucht.
        let updated = sqlx::query(
            "UPDATE challenges SET challenge_state = 'spent', spent_at_millis = $3 \
             WHERE organization_id = $1 AND nonce_digest = $2 \
             AND challenge_state = 'issued' AND expires_at_millis >= $3",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&nonce_digest.as_bytes()[..])
        .bind(now.get())
        .execute(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        if updated.rows_affected() == 1 {
            return Ok(ChallengeSpendOutcome::Spent);
        }

        let row = sqlx::query(
            "SELECT challenge_state, expires_at_millis FROM challenges \
             WHERE organization_id = $1 AND nonce_digest = $2",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&nonce_digest.as_bytes()[..])
        .fetch_optional(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(ChallengeSpendOutcome::Unknown);
        };
        let state: String = row.get("challenge_state");
        let expires_at: i64 = row.get("expires_at_millis");
        if state == "spent" {
            Ok(ChallengeSpendOutcome::AlreadySpent)
        } else if expires_at < now.get() {
            Ok(ChallengeSpendOutcome::Expired)
        } else {
            // Offen und nicht abgelaufen, aber das `UPDATE` hat sie nicht
            // getroffen: ein anderer Aufrufer war in derselben Millisekunde
            // schneller. Fail-closed derselbe Befund wie ein Replay.
            Ok(ChallengeSpendOutcome::AlreadySpent)
        }
    }
}

#[async_trait]
impl RequestIdStore for PostgresRepository {
    async fn claim(
        &self,
        organization_id: OrganizationId,
        request_id: [u8; 16],
        seen_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<bool, RepositoryError> {
        let inserted = sqlx::query(
            "INSERT INTO request_ids (organization_id, request_id, seen_at_millis, \
             expires_at_millis) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&request_id[..])
        .bind(seen_at.get())
        .bind(expires_at.get())
        .execute(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(inserted.rows_affected() == 1)
    }
}

#[async_trait]
impl DeviceRegistrationStore for PostgresRepository {
    async fn record_pending(
        &self,
        request: PendingDeviceRequestV1,
    ) -> Result<PendingRegistrationOutcome, RepositoryError> {
        let inserted = sqlx::query(
            "INSERT INTO pending_device_requests (organization_id, device_id, \
             requested_key_thumbprint, request_object_hash, request_state, received_at_millis) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        )
        .bind(&request.organization_id.as_bytes()[..])
        .bind(&request.device_id.as_bytes()[..])
        .bind(&request.requested_key_thumbprint.as_bytes()[..])
        .bind(&request.request_object_hash.as_bytes()[..])
        .bind(PENDING_REGISTRATION_STATE_V1)
        .bind(request.received_at.get())
        .execute(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        if inserted.rows_affected() == 1 {
            return Ok(PendingRegistrationOutcome::Recorded);
        }

        // Es liegt schon ein Antrag fuer dieses Geraet. Nur ein byteweise
        // gleicher ist der zulaessige Wiederholungsfall.
        let row = sqlx::query(
            "SELECT requested_key_thumbprint, request_object_hash FROM pending_device_requests \
             WHERE organization_id = $1 AND device_id = $2",
        )
        .bind(&request.organization_id.as_bytes()[..])
        .bind(&request.device_id.as_bytes()[..])
        .fetch_optional(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(PendingRegistrationOutcome::Conflict);
        };
        let thumbprint: Vec<u8> = row.get("requested_key_thumbprint");
        let object_hash: Vec<u8> = row.get("request_object_hash");
        if thumbprint == request.requested_key_thumbprint.as_bytes()
            && object_hash == request.request_object_hash.as_bytes()
        {
            Ok(PendingRegistrationOutcome::AlreadyPending)
        } else {
            Ok(PendingRegistrationOutcome::Conflict)
        }
    }
}

#[async_trait]
impl WebauthnCredentialStore for PostgresRepository {
    async fn register(
        &self,
        credential: WebauthnCredentialV1,
    ) -> Result<CredentialRegistrationOutcome, RepositoryError> {
        let inserted = sqlx::query(
            "INSERT INTO webauthn_credentials (organization_id, subject_id, credential_id, \
             public_key, signature_counter, registered_at_millis) \
             VALUES ($1, $2, $3, $4, 0, $5) ON CONFLICT DO NOTHING",
        )
        .bind(&credential.organization_id.as_bytes()[..])
        .bind(&credential.subject_id.as_bytes()[..])
        .bind(&credential.credential_id[..])
        .bind(&credential.credential_public_cose_key[..])
        .bind(credential.registered_at.get())
        .execute(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        if inserted.rows_affected() == 1 {
            return Ok(CredentialRegistrationOutcome::Registered);
        }

        let row = sqlx::query(
            "SELECT subject_id, public_key FROM webauthn_credentials \
             WHERE organization_id = $1 AND credential_id = $2",
        )
        .bind(&credential.organization_id.as_bytes()[..])
        .bind(&credential.credential_id[..])
        .fetch_optional(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(CredentialRegistrationOutcome::Conflict);
        };
        let subject: Vec<u8> = row.get("subject_id");
        let public_key: Vec<u8> = row.get("public_key");
        if subject == credential.subject_id.as_bytes()
            && public_key == credential.credential_public_cose_key
        {
            Ok(CredentialRegistrationOutcome::AlreadyRegistered)
        } else {
            Ok(CredentialRegistrationOutcome::Conflict)
        }
    }
}
