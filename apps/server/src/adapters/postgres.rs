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
    AppendOutcome, ArchiveExportDirectory, ChainHeadStateV1, CheckpointDirectory,
    CheckpointIndexEntryV1, CommitDbCommand, CommitRepository, CommittedDbState,
    DestructionRequestCommandV1, DestructionStateV1, DestructionStore, EntryDirectory,
    EntryIndexEntryV1, ExportIndexEntryV1, GrantDeliveryV1, GrantIndexEntryV1,
    HistoricalGrantCommandV1, HistoricalGrantStore, IndexedObjectV1, ObjectTypeDirectory,
    ReaderAckCommandV1, ReaderAckStore, RepositoryError, SecurityEventSink, SecurityEventV1,
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

    /// Der Kopf der CHECKPOINT-Kette, OHNE Sperre.
    ///
    /// Er ist der Anker mit der hoechsten abgedeckten Sequenz dieser Kette —
    /// und weil jede Sequenz genau einen Anker traegt (Eindeutigkeitszwang in
    /// `0001_initial.sql`), ist das genau einer. Der Lesezugriff entscheidet
    /// nichts: [`Self::commit_locked_head`] stellt den genannten Vorgaenger
    /// unter der Sperre erneut gegen diesen Kopf.
    async fn checkpoint_head(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
    ) -> Result<Option<ObjectHash>, RepositoryError> {
        let row = sqlx::query(
            "SELECT object_hash FROM checkpoints WHERE organization_id = $1 AND chain_id = $2 \
             ORDER BY covered_sequence DESC LIMIT 1",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&chain_id.as_bytes()[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        row.map(|row| {
            let hash: Vec<u8> = row.get("object_hash");
            ObjectHash::try_from(hash.as_slice()).map_err(|_| RepositoryError::Unavailable)
        })
        .transpose()
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
            // Der GESPEICHERTE Anker dieses Commits, nicht der eben
            // gebildete. Er ist in derselben Transaktion entstanden wie der
            // Eintrag, also traegt jede Sequenz mit einem Eintrag auch ihren
            // Checkpoint; ein fehlender waere ein Widerspruch im Bestand und
            // wird fail-closed gemeldet statt erfunden.
            let checkpoint = stored_checkpoint(&mut transaction, &command).await?;
            return Ok(CommittedDbState {
                sequence: ChainSequence::new(command.sequence.get()),
                entry_hash: command.identity.entry_hash,
                receipt_object_hash: ObjectHash::try_from(receipt.as_slice())
                    .map_err(|_| RepositoryError::Unavailable)?,
                checkpoint_object_hash: checkpoint,
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

        // Der Vorgaenger der CHECKPOINT-Kette, unter derselben Sperre.
        //
        // `design.md` §15.2 gibt jedem Anker seinen Vorgaenger; zwei Anker
        // ueber demselben Vorgaenger waeren zwei einander widersprechende
        // Ketten. Der Dienst hat den Kopf sperrfrei gelesen und in den
        // signierten Checkpoint gebunden — hier wird er ERNEUT gestellt, denn
        // erst unter der Sperre ist die Aussage unter Nebenlaeufigkeit wahr.
        //
        // Die Pruefung steht NACH Sequenz und Vorgaenger: ein schlicht
        // verlorenes Rennen bleibt ein Kopfkonflikt und wird nicht zu einem
        // Gabelungsvorwurf umgedeutet.
        let checkpoint_head: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT object_hash FROM checkpoints WHERE organization_id = $1 AND chain_id = $2 \
             ORDER BY covered_sequence DESC LIMIT 1",
        )
        .bind(&command.organization_id.as_bytes()[..])
        .bind(&command.chain_id.as_bytes()[..])
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?;
        let claimed_predecessor = command
            .checkpoint
            .previous_evidence_hash
            .map(|hash| hash.as_bytes().to_vec());
        if checkpoint_head != claimed_predecessor {
            return Err(RepositoryError::CheckpointPredecessorConflict);
        }

        // Schritt 8: Objektindex, Entry, Receipt, Checkpoint und Kopf
        // gemeinsam.
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

        sqlx::query(
            "INSERT INTO checkpoints (object_hash, organization_id, chain_id, covered_sequence, \
             issued_at_millis) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&command.checkpoint.object_hash.as_bytes()[..])
        .bind(&command.organization_id.as_bytes()[..])
        .bind(&command.chain_id.as_bytes()[..])
        .bind(
            i64::try_from(command.checkpoint.covered_sequence.get())
                .map_err(|_| RepositoryError::Unavailable)?,
        )
        .bind(command.checkpoint.issued_at_server.get())
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
            checkpoint_object_hash: command.checkpoint.object_hash,
            accepted_at_server: command.accepted_at_server,
            newly_committed: true,
        })
    }
}

/// Der Checkpoint-Index einer Organisation, aufsteigend nach Blaetterposition.
///
/// Er BLAETTERT und entscheidet nichts: die gelieferten Adressen loest der
/// Dienst gegen den Object Store auf, und die exakten Bytes prueft der
/// Empfaenger selbst.
#[async_trait]
impl CheckpointDirectory for PostgresRepository {
    async fn checkpoints_after(
        &self,
        organization_id: ea_types::OrganizationId,
        after_technical_index: u64,
        limit: usize,
    ) -> Result<Vec<CheckpointIndexEntryV1>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT object_hash, technical_index FROM checkpoints \
             WHERE organization_id = $1 AND technical_index > $2 \
             ORDER BY technical_index LIMIT $3",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(i64::try_from(after_technical_index).map_err(|_| RepositoryError::Unavailable)?)
        .bind(i64::try_from(limit).map_err(|_| RepositoryError::Unavailable)?)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.into_iter()
            .map(|row| {
                let hash: Vec<u8> = row.get("object_hash");
                let index: i64 = row.get("technical_index");
                Ok(CheckpointIndexEntryV1 {
                    technical_index: u64::try_from(index)
                        .map_err(|_| RepositoryError::Unavailable)?,
                    object_hash: ObjectHash::try_from(hash.as_slice())
                        .map_err(|_| RepositoryError::Unavailable)?,
                })
            })
            .collect()
    }
}

/// Der Anker, der zu einem bereits gespeicherten Commit gehoert.
async fn stored_checkpoint(
    transaction: &mut sqlx::PgTransaction<'_>,
    command: &CommitDbCommand,
) -> Result<ObjectHash, RepositoryError> {
    let hash: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT object_hash FROM checkpoints \
         WHERE organization_id = $1 AND chain_id = $2 AND covered_sequence = $3",
    )
    .bind(&command.organization_id.as_bytes()[..])
    .bind(&command.chain_id.as_bytes()[..])
    .bind(i64::try_from(command.sequence.get()).map_err(|_| RepositoryError::Unavailable)?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|e| unavailable(&e))?;
    hash.ok_or(RepositoryError::Unavailable).and_then(|hash| {
        ObjectHash::try_from(hash.as_slice()).map_err(|_| RepositoryError::Unavailable)
    })
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
                // Eine Sequenz traegt genau EINEN Anker. Reisst dieser Zwang,
                // haette sich die Checkpoint-Kette gegabelt — und das ist
                // weder ein Kopfkonflikt noch ein Widerspruch in der
                // Commit-Identitaet.
                Some("checkpoints_organization_id_chain_id_covered_sequence_key") => {
                    RepositoryError::CheckpointPredecessorConflict
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
        object_type_of_code(row.get("object_type_code")).map(Some)
    }

    async fn indexed_object(
        &self,
        organization_id: ea_types::OrganizationId,
        hash: ObjectHash,
    ) -> Result<Option<IndexedObjectV1>, RepositoryError> {
        self.indexed_object_row(organization_id, hash).await
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
}

/// Die Aufloesung eines Hashes INNERHALB einer Organisation.
///
/// Sie steht neben [`ObjectTypeDirectory::object_type_of`] und nicht an deren
/// Stelle: jene geht den eigenen Bestand durch und darf deshalb
/// organisationsfrei fragen, diese beantwortet eine LESEANFRAGE und darf es
/// nicht.
impl PostgresRepository {
    async fn indexed_object_row(
        &self,
        organization_id: ea_types::OrganizationId,
        hash: ObjectHash,
    ) -> Result<Option<IndexedObjectV1>, RepositoryError> {
        let row = sqlx::query(
            "SELECT object_type_code, size_bytes FROM object_index \
             WHERE object_hash = $1 AND organization_id = $2",
        )
        .bind(&hash.as_bytes()[..])
        .bind(&organization_id.as_bytes()[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let size: i64 = row.get("size_bytes");
        Ok(Some(IndexedObjectV1 {
            kind: object_type_of_code(row.get("object_type_code"))?,
            object_hash: hash,
            size_bytes: u64::try_from(size).map_err(|_| RepositoryError::Unavailable)?,
        }))
    }
}

/// Die Zuordnung Code zu Objektart, EINMAL.
///
/// Sie laeuft ueber die geschlossene Menge von `ea-format`; ein Wert
/// ausserhalb 1..6 kann die Spaltenpruefung gar nicht passiert haben und ist
/// deshalb ein Ausfall, keine Objektart.
const fn object_type_of_code(code: i16) -> Result<ObjectTypeV1, RepositoryError> {
    Ok(match code {
        1 => ObjectTypeV1::Entry,
        2 => ObjectTypeV1::Grant,
        3 => ObjectTypeV1::Receipt,
        4 => ObjectTypeV1::Evidence,
        5 => ObjectTypeV1::Trust,
        6 => ObjectTypeV1::Destroyed,
        _ => return Err(RepositoryError::Unavailable),
    })
}

fn object_hash_of(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<ObjectHash, RepositoryError> {
    let bytes: Vec<u8> = row.get(column);
    ObjectHash::try_from(bytes.as_slice()).map_err(|_| RepositoryError::Unavailable)
}

fn entry_index_entry(row: &sqlx::postgres::PgRow) -> Result<EntryIndexEntryV1, RepositoryError> {
    let sequence: i64 = row.get("sequence_number");
    let entry_hash: Vec<u8> = row.get("entry_hash");
    Ok(EntryIndexEntryV1 {
        sequence: ChainSequence::new(
            u64::try_from(sequence).map_err(|_| RepositoryError::Unavailable)?,
        ),
        entry_hash: EntryHash::try_from(entry_hash.as_slice())
            .map_err(|_| RepositoryError::Unavailable)?,
        entry_object_hash: object_hash_of(row, "entry_object_hash")?,
        receipt_object_hash: object_hash_of(row, "receipt_object_hash")?,
        registry_head_hash: object_hash_of(row, "registry_head_hash")?,
    })
}

/// Die Spalten, die ein Satz des Eintragsindex braucht — EINMAL geschrieben,
/// damit die vier Abfragen darunter nicht auseinanderlaufen.
const ENTRY_INDEX_COLUMNS: &str = "sequence_number, entry_hash, entry_object_hash, \
                                   receipt_object_hash, registry_head_hash";

#[async_trait]
impl EntryDirectory for PostgresRepository {
    async fn entry_at(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
        sequence: ChainSequence,
    ) -> Result<Option<EntryIndexEntryV1>, RepositoryError> {
        let statement = format!(
            "SELECT {ENTRY_INDEX_COLUMNS} FROM entries \
             WHERE organization_id = $1 AND chain_id = $2 AND sequence_number = $3"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(&organization_id.as_bytes()[..])
            .bind(&chain_id.as_bytes()[..])
            .bind(i64::try_from(sequence.get()).map_err(|_| RepositoryError::Unavailable)?)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| unavailable(&e))?;
        row.as_ref().map(entry_index_entry).transpose()
    }

    async fn entry_of(
        &self,
        organization_id: ea_types::OrganizationId,
        entry_hash: EntryHash,
    ) -> Result<Option<EntryIndexEntryV1>, RepositoryError> {
        let statement = format!(
            "SELECT {ENTRY_INDEX_COLUMNS} FROM entries \
             WHERE organization_id = $1 AND entry_hash = $2"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(&organization_id.as_bytes()[..])
            .bind(&entry_hash.as_bytes()[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| unavailable(&e))?;
        row.as_ref().map(entry_index_entry).transpose()
    }

    /// `>=` und nicht `>`: die Grenze ist EINSCHLIESSLICH, weil Sequenz null
    /// der Genesis-Eintrag ist und ein Leser ohne verifizierten Kopf genau ab
    /// dort fragt. Der Aufrufer, der nach einer bekannten Position
    /// weiterliest, uebergibt `position + 1`.
    async fn entries_from(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
        from_sequence: ChainSequence,
        limit: usize,
    ) -> Result<Vec<EntryIndexEntryV1>, RepositoryError> {
        let statement = format!(
            "SELECT {ENTRY_INDEX_COLUMNS} FROM entries \
             WHERE organization_id = $1 AND chain_id = $2 AND sequence_number >= $3 \
             ORDER BY sequence_number LIMIT $4"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(&organization_id.as_bytes()[..])
            .bind(&chain_id.as_bytes()[..])
            .bind(i64::try_from(from_sequence.get()).map_err(|_| RepositoryError::Unavailable)?)
            .bind(i64::try_from(limit).map_err(|_| RepositoryError::Unavailable)?)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| unavailable(&e))?;
        rows.iter().map(entry_index_entry).collect()
    }

    async fn grant_delivery(
        &self,
        organization_id: ea_types::OrganizationId,
        object_hash: ObjectHash,
    ) -> Result<Option<GrantDeliveryV1>, RepositoryError> {
        let row = sqlx::query(
            "SELECT entry_hash, expires_at_millis FROM grants \
             WHERE organization_id = $1 AND object_hash = $2",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&object_hash.as_bytes()[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let entry: Vec<u8> = row.get("entry_hash");
        let expires: Option<i64> = row.get("expires_at_millis");
        Ok(Some(GrantDeliveryV1 {
            entry_hash: EntryHash::try_from(entry.as_slice())
                .map_err(|_| RepositoryError::Unavailable)?,
            expires_at: expires.map(UnixMillis::new),
        }))
    }

    async fn chain_head(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
    ) -> Result<Option<ChainHeadStateV1>, RepositoryError> {
        CommitRepository::head_state(self, organization_id, chain_id).await
    }

    async fn grants_of(
        &self,
        organization_id: ea_types::OrganizationId,
        entry_hash: EntryHash,
    ) -> Result<Vec<GrantIndexEntryV1>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT object_hash, expires_at_millis FROM grants \
             WHERE organization_id = $1 AND entry_hash = $2 ORDER BY object_hash",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&entry_hash.as_bytes()[..])
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter()
            .map(|row| {
                let expires: Option<i64> = row.get("expires_at_millis");
                Ok(GrantIndexEntryV1 {
                    object_hash: object_hash_of(row, "object_hash")?,
                    expires_at: expires.map(UnixMillis::new),
                })
            })
            .collect()
    }

    async fn checkpoint_covering(
        &self,
        organization_id: ea_types::OrganizationId,
        chain_id: ea_types::ChainId,
        covered_sequence: ChainSequence,
    ) -> Result<Option<ObjectHash>, RepositoryError> {
        let row = sqlx::query(
            "SELECT object_hash FROM checkpoints \
             WHERE organization_id = $1 AND chain_id = $2 AND covered_sequence = $3",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&chain_id.as_bytes()[..])
        .bind(i64::try_from(covered_sequence.get()).map_err(|_| RepositoryError::Unavailable)?)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        row.as_ref()
            .map(|row| object_hash_of(row, "object_hash"))
            .transpose()
    }
}

#[async_trait]
impl ArchiveExportDirectory for PostgresRepository {
    async fn objects_after(
        &self,
        organization_id: ea_types::OrganizationId,
        after_technical_index: u64,
        limit: usize,
    ) -> Result<Vec<ExportIndexEntryV1>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT object_hash, object_type_code, size_bytes, technical_index FROM object_index \
             WHERE organization_id = $1 AND technical_index > $2 \
             ORDER BY technical_index LIMIT $3",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(i64::try_from(after_technical_index).map_err(|_| RepositoryError::Unavailable)?)
        .bind(i64::try_from(limit).map_err(|_| RepositoryError::Unavailable)?)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter()
            .map(|row| {
                let index: i64 = row.get("technical_index");
                let size: i64 = row.get("size_bytes");
                Ok(ExportIndexEntryV1 {
                    technical_index: u64::try_from(index)
                        .map_err(|_| RepositoryError::Unavailable)?,
                    object: IndexedObjectV1 {
                        kind: object_type_of_code(row.get("object_type_code"))?,
                        object_hash: object_hash_of(row, "object_hash")?,
                        size_bytes: u64::try_from(size)
                            .map_err(|_| RepositoryError::Unavailable)?,
                    },
                })
            })
            .collect()
    }
}

/// Der historische Grant. Er beruehrt AUSSCHLIESSLICH `object_index` und
/// `grants` — kein `entries`, kein `chain_heads`, kein `receipts`.
///
/// `ON CONFLICT DO NOTHING` plus Rueckvergleich statt `DO UPDATE`: derselbe
/// Grant zweimal ist der zulaessige idempotente Fall, derselbe `objectHash`
/// mit anderer Zuordnung ein Widerspruch — und ein Widerspruch wird nicht
/// repariert.
#[async_trait]
impl HistoricalGrantStore for PostgresRepository {
    async fn record_historical_grant(
        &self,
        command: HistoricalGrantCommandV1,
    ) -> Result<AppendOutcome, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(|e| unavailable(&e))?;
        sqlx::query(
            "INSERT INTO object_index (object_hash, organization_id, object_type_code, \
             size_bytes, stored_at_millis) VALUES ($1, $2, 2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(&command.object.object_hash.as_bytes()[..])
        .bind(&command.organization_id.as_bytes()[..])
        .bind(i64::try_from(command.object.size_bytes).map_err(|_| RepositoryError::Unavailable)?)
        .bind(command.stored_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?;

        let inserted = sqlx::query(
            "INSERT INTO grants (object_hash, organization_id, entry_hash, \
             recipient_key_thumbprint, grant_kind_code, expires_at_millis) \
             VALUES ($1, $2, $3, $4, 'historical', $5) ON CONFLICT DO NOTHING",
        )
        .bind(&command.object.object_hash.as_bytes()[..])
        .bind(&command.organization_id.as_bytes()[..])
        .bind(&command.entry_hash.as_bytes()[..])
        .bind(&command.recipient_key_thumbprint.as_bytes()[..])
        .bind(command.expires_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?
        .rows_affected();

        let outcome = if inserted == 1 {
            AppendOutcome::Recorded
        } else {
            // Es lag schon eine Zeile da. Ob sie DIESELBE ist, entscheidet der
            // Rueckvergleich und nicht die Annahme des Aufrufers.
            let row = sqlx::query(
                "SELECT entry_hash, expires_at_millis FROM grants WHERE object_hash = $1",
            )
            .bind(&command.object.object_hash.as_bytes()[..])
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|e| unavailable(&e))?;
            match row {
                Some(row) => {
                    let entry: Vec<u8> = row.get("entry_hash");
                    let expires: Option<i64> = row.get("expires_at_millis");
                    if entry == command.entry_hash.as_bytes()
                        && expires == Some(command.expires_at.get())
                    {
                        AppendOutcome::AlreadyRecorded
                    } else {
                        AppendOutcome::Conflict
                    }
                }
                None => AppendOutcome::Conflict,
            }
        };
        transaction.commit().await.map_err(|e| unavailable(&e))?;
        Ok(outcome)
    }
}

/// Die Lesequittung, APPEND-ONLY.
///
/// Der Primaerschluessel schliesst `ack_object_hash` ein: zwei Quittungen
/// desselben Lesers zu verschiedenen Kettenstaenden sind zwei Saetze und kein
/// Ueberschreiben. Der eindeutige Zwang auf `ack_object_hash` faengt dieselbe
/// Quittung zweimal ab.
#[async_trait]
impl ReaderAckStore for PostgresRepository {
    async fn record_reader_ack(
        &self,
        command: ReaderAckCommandV1,
    ) -> Result<AppendOutcome, RepositoryError> {
        let inserted = sqlx::query(
            "INSERT INTO reader_acknowledgements (organization_id, reader_certificate_hash, \
             entry_hash, ack_object_hash, acknowledged_at_millis) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&command.organization_id.as_bytes()[..])
        .bind(&command.reader_certificate_hash.as_bytes()[..])
        .bind(&command.entry_hash.as_bytes()[..])
        .bind(&command.ack_object_hash.as_bytes()[..])
        .bind(command.acknowledged_at.get())
        .execute(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?
        .rows_affected();
        if inserted == 1 {
            return Ok(AppendOutcome::Recorded);
        }
        let row = sqlx::query(
            "SELECT organization_id, reader_certificate_hash, entry_hash \
             FROM reader_acknowledgements WHERE ack_object_hash = $1",
        )
        .bind(&command.ack_object_hash.as_bytes()[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(AppendOutcome::Conflict);
        };
        let organization: Vec<u8> = row.get("organization_id");
        let certificate: Vec<u8> = row.get("reader_certificate_hash");
        let entry: Vec<u8> = row.get("entry_hash");
        if organization == command.organization_id.as_bytes()
            && certificate == command.reader_certificate_hash.as_bytes()
            && entry == command.entry_hash.as_bytes()
        {
            Ok(AppendOutcome::AlreadyRecorded)
        } else {
            Ok(AppendOutcome::Conflict)
        }
    }
}

/// Der Vernichtungsvorgang, APPEND-ONLY.
#[async_trait]
impl DestructionStore for PostgresRepository {
    async fn record_destruction_request(
        &self,
        command: DestructionRequestCommandV1,
    ) -> Result<AppendOutcome, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(|e| unavailable(&e))?;
        sqlx::query(
            "INSERT INTO object_index (object_hash, organization_id, object_type_code, \
             size_bytes, stored_at_millis) VALUES ($1, $2, 5, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(&command.authorization.object_hash.as_bytes()[..])
        .bind(&command.organization_id.as_bytes()[..])
        .bind(
            i64::try_from(command.authorization.size_bytes)
                .map_err(|_| RepositoryError::Unavailable)?,
        )
        .bind(command.requested_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?;

        let inserted = sqlx::query(
            "INSERT INTO destructions (organization_id, destruction_id, \
             authorization_object_hash, state_code, requested_at_millis) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(&command.organization_id.as_bytes()[..])
        .bind(&command.destruction_id.as_bytes()[..])
        .bind(&command.authorization.object_hash.as_bytes()[..])
        .bind(i16::from(
            ea_sync_server::destruction::DESTRUCTION_STATE_REQUESTED_V1,
        ))
        .bind(command.requested_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(|e| unavailable(&e))?
        .rows_affected();

        if inserted == 0 {
            // Derselbe Vorgang noch einmal ist idempotent; eine ANDERE
            // Autorisierung unter derselben Kennung ist ein Widerspruch.
            let row = sqlx::query(
                "SELECT authorization_object_hash FROM destructions \
                 WHERE organization_id = $1 AND destruction_id = $2",
            )
            .bind(&command.organization_id.as_bytes()[..])
            .bind(&command.destruction_id.as_bytes()[..])
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|e| unavailable(&e))?;
            let same = row.is_some_and(|row| {
                let stored: Vec<u8> = row.get("authorization_object_hash");
                stored == command.authorization.object_hash.as_bytes()
            });
            transaction.commit().await.map_err(|e| unavailable(&e))?;
            return Ok(if same {
                AppendOutcome::AlreadyRecorded
            } else {
                AppendOutcome::Conflict
            });
        }

        for (entry_hash, chain_sequence) in &command.targets {
            sqlx::query(
                "INSERT INTO destruction_targets (organization_id, destruction_id, entry_hash, \
                 chain_sequence) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            )
            .bind(&command.organization_id.as_bytes()[..])
            .bind(&command.destruction_id.as_bytes()[..])
            .bind(&entry_hash.as_bytes()[..])
            .bind(i64::try_from(*chain_sequence).map_err(|_| RepositoryError::Unavailable)?)
            .execute(&mut *transaction)
            .await
            .map_err(|e| unavailable(&e))?;
        }
        transaction.commit().await.map_err(|e| unavailable(&e))?;
        Ok(AppendOutcome::Recorded)
    }

    async fn destruction_state(
        &self,
        organization_id: ea_types::OrganizationId,
        destruction_id: ea_types::DestructionId,
    ) -> Result<Option<DestructionStateV1>, RepositoryError> {
        let row = sqlx::query(
            "SELECT authorization_object_hash, state_code FROM destructions \
             WHERE organization_id = $1 AND destruction_id = $2",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&destruction_id.as_bytes()[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let state: i16 = row.get("state_code");
        Ok(Some(DestructionStateV1 {
            authorization_object_hash: object_hash_of(&row, "authorization_object_hash")?,
            state: u8::try_from(state).map_err(|_| RepositoryError::Unavailable)?,
            transition_object_hashes: self
                .destruction_objects("destruction_transitions", organization_id, destruction_id)
                .await?,
            attestation_object_hashes: self
                .destruction_objects("destruction_attestations", organization_id, destruction_id)
                .await?,
        }))
    }

    async fn is_destruction_target(
        &self,
        organization_id: ea_types::OrganizationId,
        entry_hash: EntryHash,
    ) -> Result<bool, RepositoryError> {
        let row = sqlx::query(
            "SELECT 1 AS present FROM destruction_targets \
             WHERE organization_id = $1 AND entry_hash = $2 LIMIT 1",
        )
        .bind(&organization_id.as_bytes()[..])
        .bind(&entry_hash.as_bytes()[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(row.is_some())
    }
}

impl PostgresRepository {
    /// Die Objektadressen einer append-only Vernichtungstabelle, in
    /// Blaetterreihenfolge.
    ///
    /// Der Tabellenname ist eine KONSTANTE dieser Datei und kommt niemals aus
    /// einem Request; die beiden Aufrufer oben sind die einzigen.
    async fn destruction_objects(
        &self,
        table: &'static str,
        organization_id: ea_types::OrganizationId,
        destruction_id: ea_types::DestructionId,
    ) -> Result<Vec<ObjectHash>, RepositoryError> {
        let statement = format!(
            "SELECT object_hash FROM {table} \
             WHERE organization_id = $1 AND destruction_id = $2 ORDER BY technical_index"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(&organization_id.as_bytes()[..])
            .bind(&destruction_id.as_bytes()[..])
            .fetch_all(&self.pool)
            .await
            .map_err(|e| unavailable(&e))?;
        rows.iter()
            .map(|row| object_hash_of(row, "object_hash"))
            .collect()
    }
}
