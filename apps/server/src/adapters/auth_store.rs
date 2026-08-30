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
    ReaderVaultBlobV1, RepositoryError, RequestIdStore, StoredWebauthnCredentialV1,
    VaultBlobOutcome, VaultBlobStore, WebauthnCredentialStore, WebauthnCredentialV1,
};
use ea_types::{Hash32, OrganizationId, SubjectId, UnixMillis};
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
        rate_key_digest: Hash32,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<(), RepositoryError> {
        // Ohne `ON CONFLICT`: derselbe Digest zweimal auszugeben hiesse, dass
        // die Zufallsquelle dieselbe Nonce zweimal geliefert hat. Das ist kein
        // Wiederholungsfall, sondern ein Befund.
        sqlx::query(
            "INSERT INTO challenges (organization_id, nonce_digest, rate_key_digest, \
             challenge_state, issued_at_millis, expires_at_millis) \
             VALUES ($1, $2, $3, 'issued', $4, $5)",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&nonce_digest.as_bytes()[..])
        .bind(&rate_key_digest.as_bytes()[..])
        .bind(issued_at.get())
        .bind(expires_at.get())
        .execute(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(())
    }

    async fn count_issued_since(
        &self,
        rate_key_digest: Hash32,
        since: UnixMillis,
    ) -> Result<u64, RepositoryError> {
        let row = sqlx::query(
            "SELECT count(*) AS issued FROM challenges \
             WHERE rate_key_digest = $1 AND issued_at_millis >= $2",
        )
        .bind(&rate_key_digest.as_bytes()[..])
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

    async fn resolve(
        &self,
        organization_id: OrganizationId,
        credential_id: &[u8],
    ) -> Result<Option<StoredWebauthnCredentialV1>, RepositoryError> {
        let row = sqlx::query(
            "SELECT subject_id, public_key, signature_counter FROM webauthn_credentials \
             WHERE organization_id = $1 AND credential_id = $2",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(credential_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let subject: Vec<u8> = row.get("subject_id");
        let counter: i64 = row.get("signature_counter");
        Ok(Some(StoredWebauthnCredentialV1 {
            subject_id: SubjectId::try_from(subject.as_slice())
                .map_err(|_| RepositoryError::Unavailable)?,
            credential_public_cose_key: row.get("public_key"),
            signature_counter: u32::try_from(counter).map_err(|_| RepositoryError::Unavailable)?,
        }))
    }

    async fn advance_counter(
        &self,
        organization_id: OrganizationId,
        credential_id: &[u8],
        from: u32,
        to: u32,
    ) -> Result<bool, RepositoryError> {
        // Compare-and-Set in EINER Anweisung: das `WHERE` auf den gelesenen
        // Zaehler ist zugleich die Sperre. Zwei Abrufe mit derselben Assertion
        // treffen nie beide eine Zeile.
        let updated = sqlx::query(
            "UPDATE webauthn_credentials SET signature_counter = $4 \
             WHERE organization_id = $1 AND credential_id = $2 AND signature_counter = $3",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(credential_id)
        .bind(i64::from(from))
        .bind(i64::from(to))
        .execute(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(updated.rows_affected() == 1)
    }
}

/// Der Klassenteil des Advisory Locks der Blobtabelle.
///
/// PostgreSQL fuehrt die Zwei-Integer-Form von `pg_advisory_xact_lock` in
/// einem ANDEREN Schluesselraum als die Bigint-Form; der Migrator von `sqlx`
/// nimmt die Bigint-Form, eine Kollision ist damit ausgeschlossen. Der Wert
/// ist ASCII `EAVB` und traegt keine fachliche Bedeutung.
const VAULT_BLOB_LOCK_CLASS_V1: i32 = 0x4541_5642;

/// Der Objektteil des Advisory Locks: die ersten vier Bytes des SHA-256 ueber
/// Organisation und `subjectId`.
///
/// Ein Digest und nicht die Kennungen selbst — der Schluessel ist vier Byte
/// breit, also muss er ohnehin verdichtet werden, und ein Digest verteilt
/// gleichmaessiger als ein Praefix. Eine Kollision zweier `subjectId` kostet
/// nur wechselseitiges Warten und niemals Korrektheit: die Zaehlung hinter der
/// Sperre ist je Organisation und `subjectId` gefiltert.
fn vault_blob_lock_key(organization_id: OrganizationId, subject_id: SubjectId) -> i32 {
    let mut material = [0_u8; 32];
    material[..16].copy_from_slice(organization_id.as_bytes());
    material[16..].copy_from_slice(subject_id.as_bytes());
    let digest = ea_sync_protocol::body_digest(&material);
    i32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

#[async_trait]
impl VaultBlobStore for PostgresRepository {
    async fn store(
        &self,
        blob: ReaderVaultBlobV1,
        max_per_subject: u64,
    ) -> Result<VaultBlobOutcome, RepositoryError> {
        let capacity = i64::try_from(max_per_subject).map_err(|_| RepositoryError::Unavailable)?;
        let mut transaction = self.pool().begin().await.map_err(|e| unavailable(&e))?;

        // Die Decke braucht GEGENSEITIGEN AUSSCHLUSS und nicht bloss eine
        // Anweisung. Eine Zaehlung als Unterabfrage der Einfuegung liest unter
        // `READ COMMITTED` einen Schnappschuss und nimmt KEINE Sperre auf die
        // gezaehlten Zeilen: zwei gleichzeitige Ablagen saehen beide sieben,
        // beide kaemen an `7 < 8` vorbei, und weil ihre Blobhashes verschieden
        // sind, greift auch `ON CONFLICT` nicht — der Bestand landete bei neun.
        // Diese Stufe hat keinen Loeschpfad, der Bestand waere also dauerhaft
        // ueber der Decke.
        //
        // Das Advisory Lock haengt an (`organizationId`, `subjectId`) und
        // nicht an der Tabelle: zwei verschiedene Leser blockieren einander
        // nicht. Es ist ein `xact`-Lock, faellt also mit der Transaktion — auch
        // mit einer abgebrochenen.
        sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
            .bind(VAULT_BLOB_LOCK_CLASS_V1)
            .bind(vault_blob_lock_key(blob.organization_id, blob.subject_id))
            .execute(&mut *transaction)
            .await
            .map_err(|e| unavailable(&e))?;

        // Hinter der Sperre. Jede Anweisung einer `READ COMMITTED`-Transaktion
        // nimmt ihren eigenen Schnappschuss, also sieht diese Zaehlung, was der
        // Vorgaenger committet hat, bevor er die Sperre freigab.
        let existing = sqlx::query(
            "SELECT count(*) FILTER (WHERE blob_hash = $3) AS same, count(*) AS held \
             FROM reader_vault_blobs WHERE organization_id = $1 AND subject_id = $2",
        )
        .bind(&blob.organization_id.as_bytes()[..])
        .bind(&blob.subject_id.as_bytes()[..])
        .bind(&blob.blob_hash.as_bytes()[..])
        .fetch_one(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?;
        let same: i64 = existing.get("same");
        let held: i64 = existing.get("held");

        // Der idempotente Wiederholer zuerst: er darf auch AN der Decke noch
        // durch, sonst spiegelte eine volle `subjectId` eine Ablehnung fuer
        // Bytes vor, die laengst liegen. Der Blobhash ist SHA-256 ueber die
        // Bytes, also traegt dieselbe Adresse immer dieselben Bytes.
        if same > 0 {
            transaction.commit().await.map_err(|e| unavailable(&e))?;
            return Ok(VaultBlobOutcome::AlreadyStored);
        }
        if held >= capacity {
            transaction.commit().await.map_err(|e| unavailable(&e))?;
            return Ok(VaultBlobOutcome::LimitReached);
        }

        sqlx::query(
            "INSERT INTO reader_vault_blobs (organization_id, subject_id, blob_hash, ciphertext, \
             stored_at_millis) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&blob.organization_id.as_bytes()[..])
        .bind(&blob.subject_id.as_bytes()[..])
        .bind(&blob.blob_hash.as_bytes()[..])
        .bind(&blob.ciphertext[..])
        .bind(blob.stored_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?;
        transaction.commit().await.map_err(|e| unavailable(&e))?;
        Ok(VaultBlobOutcome::Stored)
    }

    async fn list_for_subject(
        &self,
        organization_id: OrganizationId,
        subject_id: SubjectId,
        limit: u64,
    ) -> Result<Vec<Vec<u8>>, RepositoryError> {
        // Nach dem Blobhash geordnet: die Antwort soll fuer denselben Bestand
        // dieselbe sein, und eine Einfuegereihenfolge ist keine Ordnung.
        //
        // Das `LIMIT` ist Tiefenverteidigung hinter der Decke aus `store`.
        // Ohne es koennte ein Bestand ueber der Decke gar nicht mehr gerahmt
        // werden, und diese `subjectId` waere dauerhaft ausgesperrt — es gibt
        // keinen Loeschpfad, der das wieder aufloeste.
        let rows = sqlx::query(
            "SELECT ciphertext FROM reader_vault_blobs \
             WHERE organization_id = $1 AND subject_id = $2 ORDER BY blob_hash LIMIT $3",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&subject_id.as_bytes()[..])
        .bind(i64::try_from(limit).map_err(|_| RepositoryError::Unavailable)?)
        .fetch_all(self.pool())
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(rows.iter().map(|row| row.get("ciphertext")).collect())
    }
}
