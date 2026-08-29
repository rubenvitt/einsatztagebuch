//! Die technische Serverpersistenz hinter PostgreSQL.
//!
//! Der Adapter fuehrt die Schritte 4 bis 8 von `design.md` §13.3 in EINER
//! Transaktion aus: Kettenkopf sperren, Sequenz und Vorgaenger pruefen, Entry,
//! initiale Grants, Objektindex, Receipt und neuen Kopf gemeinsam sichtbar
//! schalten. Ein Abbruch dazwischen hinterlaesst nichts Halbes — hoechstens
//! content-addressed Orphans im Object Store, die §13.3 ausdruecklich als
//! zulaessig benennt.
//!
//! Es wird nichts Fachliches geschrieben. Jede Spalte, die dieser Adapter
//! fuellt, ist ein Hash, eine Kennung, eine Groesse oder ein technischer
//! Zeitpunkt.

use async_trait::async_trait;
use ea_format::ObjectTypeV1;
use ea_sync_server::{
    ChainHeadStateV1, CommitDbCommand, CommitRepository, CommittedDbState, ObjectTypeDirectory,
    RepositoryError, SecurityEventSink, SecurityEventV1,
};
use ea_types::{ChainSequence, EntryHash, ObjectHash, UnixMillis};
use sqlx::{PgPool, Row};

pub struct PostgresRepository {
    pool: PgPool,
}

impl PostgresRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Jeder Datenbankfehler, der KEIN erkannter Fachbefund ist, ist
/// [`RepositoryError::Unavailable`].
///
/// Der Fehlertext der Datenbank wird dabei NICHT weitergereicht: er truege
/// Spaltenwerte, und ein Spaltenwert in einer Fehlermeldung ist genau der
/// Kanal, ueber den der blinde Server doch noch etwas ausspraeche.
const fn unavailable(_error: &sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable
}

#[async_trait]
impl CommitRepository for PostgresRepository {
    /// Der Kopf MIT seiner Annahmezeit, OHNE Sperre.
    ///
    /// Er wird gelesen, damit Schritt 5 `acceptedAtServer` als Maximum aus
    /// Serverzeit und Vorgaengerzeit bilden kann — die Quittung entsteht aus
    /// dieser Zahl und muss fertig sein, bevor die Transaktion sie nennt.
    /// Bewegt sich der Kopf danach, weist [`Self::commit_locked_head`] unter
    /// `FOR UPDATE` ab; dieser Lesezugriff entscheidet nichts.
    async fn head_state(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
    ) -> Result<Option<ChainHeadStateV1>, RepositoryError> {
        let row = sqlx::query(
            "SELECT head_sequence, head_entry_hash, head_accepted_at_server_millis \
             FROM chain_heads WHERE organization_id = $1 AND chain_id = $2",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&chain_id.as_bytes()[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let sequence: i64 = row.get("head_sequence");
        let entry_hash: Vec<u8> = row.get("head_entry_hash");
        let accepted: i64 = row.get("head_accepted_at_server_millis");
        Ok(Some(ChainHeadStateV1 {
            sequence: ChainSequence::new(
                u64::try_from(sequence).map_err(|_| RepositoryError::Unavailable)?,
            ),
            entry_hash: EntryHash::try_from(entry_hash.as_slice())
                .map_err(|_| RepositoryError::Unavailable)?,
            accepted_at_server: UnixMillis::new(accepted),
        }))
    }

    async fn commit_locked_head(
        &self,
        command: CommitDbCommand,
    ) -> Result<CommittedDbState, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(|e| unavailable(&e))?;

        // Schritt 4: den Kopf SPERREN, nicht nur lesen. `FOR UPDATE` haelt jede
        // zweite Transaktion auf derselben Kette auf, bis diese hier entschieden
        // hat.
        //
        // NEBENLAEUFIGKEIT, ERSTER COMMIT EINER KETTE: `FOR UPDATE` sperrt eine
        // Zeile, die es noch nicht gibt, ausdruecklich NICHT. Zwei gleichzeitige
        // erste Commits lesen deshalb beide `None` und laufen beide weiter. Der
        // Verlierer bricht dann am Eindeutigkeitszwang `(chain_id,
        // sequence_number)` von `entries` — nicht am Kettenkopf, der also nie
        // ueberschrieben wird — und bekommt `EA-DB-HEAD-CONFLICT`, weil das
        // Rennen um den Kopf und nicht um die Commit-Identitaet verloren ging.
        // Die Zuordnung leistet `map_commit_error` ueber den Constraintnamen.
        let head = sqlx::query(
            "SELECT head_sequence, head_entry_hash, head_accepted_at_server_millis, revision \
             FROM chain_heads WHERE organization_id = $1 AND chain_id = $2 FOR UPDATE",
        )
        .bind(&command.organization_id.as_bytes()[..])
        .bind(&command.chain_id.as_bytes()[..])
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?;

        // Der idempotente Wiederholungsfall aus §13.3: dieselbe
        // Commit-Identitaet liefert denselben gespeicherten Receipt. Geprueft
        // wird die VOLLE Identitaet, nicht nur der `entryHash`.
        if let Some(existing) = sqlx::query(
            "SELECT sequence_number, entry_object_hash, initial_grant_plan_hash, \
             receipt_object_hash, accepted_at_server_millis FROM entries WHERE entry_hash = $1",
        )
        .bind(&command.identity.entry_hash.as_bytes()[..])
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?
        {
            let same_object: Vec<u8> = existing.get("entry_object_hash");
            let same_plan: Vec<u8> = existing.get("initial_grant_plan_hash");
            let sequence: i64 = existing.get("sequence_number");
            if same_object != command.identity.entry_object_hash.as_bytes()
                || same_plan != command.identity.initial_grant_plan_hash.as_bytes()
                || u64::try_from(sequence) != Ok(command.sequence.get())
                || !stored_grants_match(&mut transaction, &command).await?
            {
                return Err(RepositoryError::CommitIdentityConflict);
            }
            let receipt: Vec<u8> = existing.get("receipt_object_hash");
            let accepted: i64 = existing.get("accepted_at_server_millis");
            return Ok(CommittedDbState {
                sequence: ChainSequence::new(command.sequence.get()),
                entry_hash: command.identity.entry_hash,
                receipt_object_hash: ObjectHash::try_from(receipt.as_slice())
                    .map_err(|_| RepositoryError::Unavailable)?,
                accepted_at_server: UnixMillis::new(accepted),
                newly_committed: false,
            });
        }

        // Schritt 6: ausschliesslich `currentSequence + 1` und der aktuelle
        // Kopf als Vorgaenger.
        let expected_sequence = match &head {
            Some(row) => {
                let current: i64 = row.get("head_sequence");
                u64::try_from(current)
                    .map_err(|_| RepositoryError::Unavailable)?
                    .checked_add(1)
                    .ok_or(RepositoryError::Unavailable)?
            }
            None => 0,
        };
        if command.sequence.get() != expected_sequence {
            return Err(RepositoryError::HeadConflict);
        }
        let expected_previous = head
            .as_ref()
            .map(|row| -> Vec<u8> { row.get("head_entry_hash") });
        let actual_previous = command
            .previous_entry_hash
            .map(|hash| hash.as_bytes().to_vec());
        if expected_previous != actual_previous {
            return Err(RepositoryError::HeadConflict);
        }

        // Die MONOTONIE der Annahmezeit, unter der Sperre.
        //
        // `design.md`:929: „`accepted-at-server` … darf je Kette nicht unter
        // der des vorherigen Receipts liegen." Der Dienst bildet die Zahl aus
        // einem Kopf, den er OHNE Sperre gelesen hat; zieht ein anderer Commit
        // dazwischen den Kopf mit einer SPAETEREN Annahmezeit vor, traegt die
        // schon gerechnete Zahl eine Zeit, die unter der des neuen Vorgaengers
        // liegt. Sequenz und Vorgaengerhash faengen das NICHT: der Nachzuegler
        // sitzt korrekt hinter dem neuen Kopf.
        //
        // Und danach ist es unheilbar — die Zeit ist dann signiert. Also wird
        // sie hier geprueft, wo der Kopf gesperrt ist, und der Verlierer
        // bekommt `HeadConflict`: er hat ein RENNEN verloren, und sein
        // naechster Versuch liest den neuen Kopf und rechnet richtig.
        if head
            .as_ref()
            .map(|row| -> i64 { row.get("head_accepted_at_server_millis") })
            .is_some_and(|previous| command.accepted_at_server.get() < previous)
        {
            return Err(RepositoryError::HeadConflict);
        }

        // Schritt 8: Objektindex, Entry, Receipt und Kopf gemeinsam.
        for object in &command.indexed_objects {
            sqlx::query(
                "INSERT INTO object_index (object_hash, organization_id, object_type_code, \
                 size_bytes, stored_at_millis) VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (object_hash) DO NOTHING",
            )
            .bind(&object.object_hash.as_bytes()[..])
            .bind(&command.organization_id.as_bytes()[..])
            .bind(i16::try_from(object.kind.code()).map_err(|_| RepositoryError::Unavailable)?)
            .bind(i64::try_from(object.size_bytes).map_err(|_| RepositoryError::Unavailable)?)
            .bind(command.accepted_at_server.get())
            .execute(&mut *transaction)
            .await
            .map_err(|e| unavailable(&e))?;
        }

        sqlx::query(
            "INSERT INTO entries (entry_hash, organization_id, chain_id, sequence_number, \
             previous_entry_hash, entry_object_hash, initial_grant_plan_hash, \
             receipt_object_hash, device_id, accepted_at_server_millis, evidence_due_at_millis, \
             registry_version, registry_head_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(&command.identity.entry_hash.as_bytes()[..])
        .bind(&command.organization_id.as_bytes()[..])
        .bind(&command.chain_id.as_bytes()[..])
        .bind(i64::try_from(command.sequence.get()).map_err(|_| RepositoryError::Unavailable)?)
        .bind(
            command
                .previous_entry_hash
                .map(|hash| hash.as_bytes().to_vec()),
        )
        .bind(&command.identity.entry_object_hash.as_bytes()[..])
        .bind(&command.identity.initial_grant_plan_hash.as_bytes()[..])
        .bind(&command.receipt_object_hash.as_bytes()[..])
        .bind(&command.device_id.as_bytes()[..])
        .bind(command.accepted_at_server.get())
        .bind(command.evidence_due_at.map(UnixMillis::get))
        .bind(
            i64::try_from(command.registry_version.get())
                .map_err(|_| RepositoryError::Unavailable)?,
        )
        .bind(&command.registry_head_hash.as_bytes()[..])
        .execute(&mut *transaction)
        .await
        .map_err(map_commit_error)?;

        for grant in &command.identity.initial_grant_object_hashes {
            sqlx::query(
                "INSERT INTO grants (object_hash, organization_id, entry_hash, \
                 recipient_key_thumbprint, grant_kind_code, expires_at_millis) \
                 VALUES ($1, $2, $3, $4, 'initial', NULL) ON CONFLICT (object_hash) DO NOTHING",
            )
            .bind(&grant.as_bytes()[..])
            .bind(&command.organization_id.as_bytes()[..])
            .bind(&command.identity.entry_hash.as_bytes()[..])
            // Der Empfaengerabdruck steht im Grant selbst; der Datenbanksatz
            // fuehrt ihn erst, wenn die Grant-Pruefung ihn liefert. Bis dahin
            // traegt die Zeile den Nullabdruck und KEINE Behauptung.
            .bind(&[0_u8; 32][..])
            .execute(&mut *transaction)
            .await
            .map_err(map_commit_error)?;
        }

        sqlx::query(
            "INSERT INTO receipts (object_hash, organization_id, entry_hash, \
             accepted_at_server_millis, evidence_due_at_millis) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&command.receipt_object_hash.as_bytes()[..])
        .bind(&command.organization_id.as_bytes()[..])
        .bind(&command.identity.entry_hash.as_bytes()[..])
        .bind(command.accepted_at_server.get())
        .bind(command.evidence_due_at.map(UnixMillis::get))
        .execute(&mut *transaction)
        .await
        .map_err(map_commit_error)?;

        let head_rows = sqlx::query(
            "INSERT INTO chain_heads (organization_id, chain_id, head_sequence, \
             head_entry_hash, head_accepted_at_server_millis, revision) \
             VALUES ($1, $2, $3, $4, $5, 0) \
             ON CONFLICT (organization_id, chain_id) DO UPDATE \
             SET head_sequence = EXCLUDED.head_sequence, \
                 head_entry_hash = EXCLUDED.head_entry_hash, \
                 head_accepted_at_server_millis = EXCLUDED.head_accepted_at_server_millis, \
                 revision = chain_heads.revision + 1 \
             WHERE chain_heads.revision = $6",
        )
        .bind(&command.organization_id.as_bytes()[..])
        .bind(&command.chain_id.as_bytes()[..])
        .bind(i64::try_from(command.sequence.get()).map_err(|_| RepositoryError::Unavailable)?)
        .bind(&command.identity.entry_hash.as_bytes()[..])
        .bind(command.accepted_at_server.get())
        .bind(head.as_ref().map_or(0_i64, |row| row.get("revision")))
        .execute(&mut *transaction)
        .await
        .map_err(map_commit_error)?
        .rows_affected();
        if head_rows != 1 {
            return Err(RepositoryError::HeadConflict);
        }

        transaction.commit().await.map_err(|e| unavailable(&e))?;
        Ok(CommittedDbState {
            sequence: command.sequence,
            entry_hash: command.identity.entry_hash,
            receipt_object_hash: command.receipt_object_hash,
            accepted_at_server: command.accepted_at_server,
            newly_committed: true,
        })
    }
}

/// Die Grants eines bereits gespeicherten Commits, sortiert, gegen die
/// erwartete Liste.
async fn stored_grants_match(
    transaction: &mut sqlx::PgTransaction<'_>,
    command: &CommitDbCommand,
) -> Result<bool, RepositoryError> {
    let rows = sqlx::query(
        "SELECT object_hash FROM grants WHERE entry_hash = $1 AND grant_kind_code = 'initial' \
         ORDER BY object_hash",
    )
    .bind(&command.identity.entry_hash.as_bytes()[..])
    .fetch_all(&mut **transaction)
    .await
    .map_err(|e| unavailable(&e))?;
    let stored: Vec<Vec<u8>> = rows.iter().map(|row| row.get("object_hash")).collect();
    let expected: Vec<Vec<u8>> = command
        .identity
        .initial_grant_object_hashes
        .iter()
        .map(|hash| hash.as_bytes().to_vec())
        .collect();
    Ok(stored == expected)
}

/// Ein Eindeutigkeitsbruch beim Commit ist ein FACHBEFUND, kein Ausfall.
///
/// WELCHER Befund, entscheidet der Constraint und nicht der Zufall: ein Bruch an
/// `(chain_id, sequence_number)` oder am Kettenkopf ist ein verlorenes Rennen um
/// den KOPF (`EA-DB-HEAD-CONFLICT`), jeder andere Eindeutigkeitsbruch ein
/// Widerspruch in der COMMIT-IDENTITAET. Ohne diese Unterscheidung meldete der
/// erste Commit einer Kette, der ein Rennen verliert, „derselbe entryHash mit
/// anderer Identitaet“ — und das waere schlicht falsch.
fn map_commit_error(error: sqlx::Error) -> RepositoryError {
    if let sqlx::Error::Database(database) = &error {
        // 23505 = unique_violation.
        if database.code().as_deref() == Some("23505") {
            return match database.constraint() {
                Some("entries_chain_id_sequence_number_key" | "chain_heads_pkey") => {
                    RepositoryError::HeadConflict
                }
                _ => RepositoryError::CommitIdentityConflict,
            };
        }
    }
    unavailable(&error)
}

#[async_trait]
impl SecurityEventSink for PostgresRepository {
    async fn record(&self, event: SecurityEventV1) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO security_events (organization_id, event_code, subject_key, \
             observed_at_millis) VALUES ($1, $2, $3, $4)",
        )
        .bind(&event.organization_id.as_bytes()[..])
        .bind(event.kind.code())
        .bind(&event.subject)
        .bind(event.observed_at.get())
        .execute(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(())
    }
}

#[async_trait]
impl ObjectTypeDirectory for PostgresRepository {
    async fn object_type_of(
        &self,
        hash: ObjectHash,
    ) -> Result<Option<ObjectTypeV1>, RepositoryError> {
        let row = sqlx::query("SELECT object_type_code FROM object_index WHERE object_hash = $1")
            .bind(&hash.as_bytes()[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let code: i16 = row.get("object_type_code");
        // Die Zuordnung laeuft ueber die geschlossene Menge von `ea-format`;
        // ein Wert ausserhalb 1..6 kann die Spaltenpruefung gar nicht passiert
        // haben und ist deshalb ein Ausfall, keine Objektart.
        Ok(Some(match code {
            1 => ObjectTypeV1::Entry,
            2 => ObjectTypeV1::Grant,
            3 => ObjectTypeV1::Receipt,
            4 => ObjectTypeV1::Evidence,
            5 => ObjectTypeV1::Trust,
            6 => ObjectTypeV1::Destroyed,
            _ => return Err(RepositoryError::Unavailable),
        }))
    }
}

/// Die Request-ID-Sperre aus `design.md` §13.1.
///
/// Sie steht hier neben dem Commit, weil beide dieselbe Tabelle und dieselbe
/// Eindeutigkeit betreffen; ein zweiter Aufruf mit derselben ID ist
/// [`RepositoryError::RequestIdReplay`].
impl PostgresRepository {
    pub async fn consume_request_id(
        &self,
        organization_id: ea_types::OrganizationId,
        request_id: &[u8; 16],
        seen_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<(), RepositoryError> {
        let affected = sqlx::query(
            "INSERT INTO request_ids (organization_id, request_id, seen_at_millis, \
             expires_at_millis) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&request_id[..])
        .bind(seen_at.get())
        .bind(expires_at.get())
        .execute(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?
        .rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(RepositoryError::RequestIdReplay)
        }
    }

    /// Der aktuelle Kettenkopf, ohne Sperre — fuer Leseantworten.
    pub async fn chain_head(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
    ) -> Result<Option<(ChainSequence, EntryHash)>, RepositoryError> {
        let row = sqlx::query(
            "SELECT head_sequence, head_entry_hash FROM chain_heads \
             WHERE organization_id = $1 AND chain_id = $2",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&chain_id.as_bytes()[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let sequence: i64 = row.get("head_sequence");
        let hash: Vec<u8> = row.get("head_entry_hash");
        Ok(Some((
            ChainSequence::new(u64::try_from(sequence).map_err(|_| RepositoryError::Unavailable)?),
            EntryHash::try_from(hash.as_slice()).map_err(|_| RepositoryError::Unavailable)?,
        )))
    }
}
