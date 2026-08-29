//! Die BEGRENZTE Wiederaufnahme — abzaehlbar ueber einen Neustart hinweg.
//!
//! # Was hier NICHT entsteht
//!
//! Kein zweiter Backoff. Die Regel — exponentiell, gedeckelt, gejittert,
//! abzaehlbar — steht in [`ea_types::RetryPolicy`] und ist dort schon
//! gemessen. Diese Datei fuegt genau das hinzu, was jene nicht haben kann,
//! weil sie keine Ablage kennt: die DAUERHAFTIGKEIT des Zaehlers und des
//! naechsten Versuchszeitpunkts.
//!
//! # Warum das dauerhaft sein MUSS
//!
//! `design.md`:1584 verlangt einen BEGRENZTEN Backoff. Eine Grenze, die jeder
//! Neustart zuruecksetzt, ist keine: ein Geraet, das bei jedem Versuch
//! abstuerzt, laege ewig auf derselben Leitung. Erst der dauerhafte Zaehler
//! macht [`DetailCause::ResumeAttemptsExhausted`] erreichbar — die Ursache
//! trug bis zu diesem Task ihren Namen, aber weder einen Zaehler noch einen
//! Backoff noch einen gespeicherten naechsten Versuch.
//!
//! # Woher die Schranke kommt
//!
//! Aus dem PROFIL und nicht aus einer Konstante dieser Crate:
//! `ControlledNetworkProfileV1` fuehrt `resume_backoff_initial_ms`,
//! `resume_backoff_max_ms` und `resume_max_attempts`, und die Beschriftung der
//! Ursache sagt woertlich „die Wiederaufnahmeversuche DES PROFILS".

use ea_local_store::{EncryptedDatabase, StoreError, StoreValue, unix_millis_now};
use ea_types::{JitterSource, ObjectHash, RetryConfig, RetryDecision, RetryPolicy, UnixMillis};

use crate::SyncClientError;

/// Der Name der Tabelle aus `0004_sync_retry.sql`.
///
/// Als Konstante, damit die Abfragen dieser Datei und die Migration denselben
/// Namen nennen und ein Tippfehler nicht erst zur Laufzeit auffaellt.
pub const SYNC_RETRY_TABLE_V1: &str = "sync_retry";

/// Der dauerhafte Wiederaufnahmezustand EINES Eintrags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryScheduleV1 {
    /// Die Zahl der bisher VERGEBLICHEN Versuche.
    pub failed_attempts: u16,
    /// Der fruehestens zulaessige naechste Versuch.
    pub next_attempt_at: UnixMillis,
    /// Der zuletzt BESTAETIGTE technische Cursor, undurchsichtig.
    pub cursor: Option<Vec<u8>>,
}

impl RetryScheduleV1 {
    /// Ein Eintrag, der noch nie vergeblich versucht wurde.
    #[must_use]
    pub const fn fresh() -> Self {
        Self {
            failed_attempts: 0,
            next_attempt_at: UnixMillis::new(0),
            cursor: None,
        }
    }

    /// Darf jetzt versucht werden?
    #[must_use]
    pub const fn is_due(&self, now: UnixMillis) -> bool {
        now.get() >= self.next_attempt_at.get()
    }
}

/// Der Jitter aus dem Betriebssystem-CSPRNG.
///
/// Er zieht GLEICHVERTEILT aus `[0, ceiling_ms]` — „full jitter", die Variante,
/// die zwei Geraete, die im selben Moment die Verbindung verlieren, auch
/// wirklich auseinanderzieht. Ein Jitter, der nur die letzten Prozent
/// verwackelt, laesst genau den Gleichlauf stehen, wegen dem er da ist.
pub struct OsJitter;

impl JitterSource for OsJitter {
    fn jitter_ms(&mut self, ceiling_ms: u64) -> u64 {
        if ceiling_ms == 0 {
            return 0;
        }
        let mut raw = [0_u8; 8];
        // Ein Fehlschlag des CSPRNG ist KEIN Grund, ungejittert
        // weiterzulaufen: das Volle Warteintervall ist die konservative
        // Antwort, und sie ist es in beide Richtungen — sie wartet laenger und
        // erfindet keine Zufallszahl.
        if getrandom::fill(&mut raw).is_err() {
            return ceiling_ms;
        }
        u64::from_be_bytes(raw) % (ceiling_ms + 1)
    }
}

/// Die dauerhafte Ablage des Wiederaufnahmezustands.
pub struct RetryStore {
    database: std::sync::Arc<EncryptedDatabase>,
    config: RetryConfig,
    max_attempts: u16,
}

impl RetryStore {
    /// Baut die Ablage aus den Schranken des Profils.
    ///
    /// # Errors
    ///
    /// [`SyncClientError::RetryStateUnreadable`], wenn die Registratur der
    /// Migrationen nicht antwortet oder `0004_sync_retry.sql` noch nicht
    /// angewandt ist. Die Abfrage ist POSITIV und fail-closed: eine fehlende
    /// Tabelle ist eine andere Aussage als eine beschaedigte Datenbank, und
    /// aus keiner von beiden darf ein Zaehler bei null entstehen.
    pub fn open(
        database: std::sync::Arc<EncryptedDatabase>,
        config: RetryConfig,
        max_attempts: u16,
    ) -> Result<Self, SyncClientError> {
        if !database.has_migration(ea_local_store::migrations::SYNC_RETRY_MIGRATION_VERSION)? {
            return Err(SyncClientError::RetryStateUnreadable);
        }
        Ok(Self {
            database,
            config,
            max_attempts,
        })
    }

    /// Der gespeicherte Zustand eines Eintrags, oder ein frischer.
    ///
    /// # Errors
    ///
    /// [`SyncClientError::RetryStateUnreadable`].
    pub fn load(&self, entry: ObjectHash) -> Result<RetryScheduleV1, SyncClientError> {
        let row = self.database.query_row(
            "SELECT failed_attempts, next_attempt_at_ms, cursor FROM sync_retry \
             WHERE entry_object_hash = ?1",
            &[StoreValue::Blob(entry.as_bytes().to_vec())],
        )?;
        let Some(row) = row else {
            return Ok(RetryScheduleV1::fresh());
        };
        let failed_attempts = u16::try_from(row.integer(0)?.max(0))
            .map_err(|_| SyncClientError::RetryStateUnreadable)?;
        Ok(RetryScheduleV1 {
            failed_attempts,
            next_attempt_at: UnixMillis::new(row.integer(1)?),
            cursor: row.blob(2).ok().map(<[u8]>::to_vec),
        })
    }

    /// Bucht einen VERGEBLICHEN Versuch und errechnet den naechsten Zeitpunkt.
    ///
    /// Liefert [`None`], wenn die Schranke des Profils erschoepft ist — der
    /// EINE Ort, an dem [`crate::DetailCause::ResumeAttemptsExhausted`]
    /// entsteht.
    ///
    /// # Errors
    ///
    /// [`SyncClientError::RetryStateUnreadable`].
    pub fn record_failure(
        &self,
        entry: ObjectHash,
        now: UnixMillis,
        jitter: &mut impl JitterSource,
    ) -> Result<Option<RetryScheduleV1>, SyncClientError> {
        let previous = self.load(entry)?;
        let failed_attempts = previous.failed_attempts.saturating_add(1);

        // Die Politik wird VORGESPULT und nicht nachgebaut: `RetryPolicy`
        // haelt ihren Zaehler privat, und ein zweiter Rechenweg fuer denselben
        // Backoff waere genau die zweite Wahrheit, die diese Datei vermeidet.
        // Die Schleife laeuft hoechstens `u8::MAX` Mal — die Schranke von
        // `RetryConfig` ist ein `u8`.
        let mut policy =
            ea_types::TechnicalError::new(ea_types::TechnicalErrorCode::TemporaryTransport)
                .into_retry_policy(self.config)
                .unwrap_or_else(|_| {
                    unreachable!("TemporaryTransport ist die begrenzt wiederholbare Klasse")
                });
        let decision = advance(&mut policy, failed_attempts, jitter);

        let RetryDecision::RetryAfter { delay_ms } = decision else {
            self.write(
                entry,
                failed_attempts,
                previous.next_attempt_at,
                &previous.cursor,
                now,
            )?;
            return Ok(None);
        };
        if failed_attempts >= self.max_attempts {
            self.write(
                entry,
                failed_attempts,
                previous.next_attempt_at,
                &previous.cursor,
                now,
            )?;
            return Ok(None);
        }

        let next_attempt_at = UnixMillis::new(
            now.get()
                .saturating_add(i64::try_from(delay_ms).unwrap_or(i64::MAX)),
        );
        self.write(
            entry,
            failed_attempts,
            next_attempt_at,
            &previous.cursor,
            now,
        )?;
        Ok(Some(RetryScheduleV1 {
            failed_attempts,
            next_attempt_at,
            cursor: previous.cursor,
        }))
    }

    /// Haelt den zuletzt BESTAETIGTEN Cursor fest, ohne den Zaehler anzufassen.
    ///
    /// # Errors
    ///
    /// [`SyncClientError::RetryStateUnreadable`].
    pub fn record_cursor(
        &self,
        entry: ObjectHash,
        cursor: &[u8],
        now: UnixMillis,
    ) -> Result<(), SyncClientError> {
        let previous = self.load(entry)?;
        self.write(
            entry,
            previous.failed_attempts,
            previous.next_attempt_at,
            &Some(cursor.to_vec()),
            now,
        )
    }

    /// Loescht den Zustand eines Eintrags — der Lauf ist bestaetigt.
    ///
    /// # Errors
    ///
    /// [`SyncClientError::RetryStateUnreadable`].
    pub fn clear(&self, entry: ObjectHash) -> Result<(), SyncClientError> {
        self.database.execute(
            "DELETE FROM sync_retry WHERE entry_object_hash = ?1",
            &[StoreValue::Blob(entry.as_bytes().to_vec())],
        )?;
        Ok(())
    }

    fn write(
        &self,
        entry: ObjectHash,
        failed_attempts: u16,
        next_attempt_at: UnixMillis,
        cursor: &Option<Vec<u8>>,
        now: UnixMillis,
    ) -> Result<(), SyncClientError> {
        let _ = now;
        self.database.execute(
            "INSERT INTO sync_retry \
             (entry_object_hash, failed_attempts, next_attempt_at_ms, cursor, recorded_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(entry_object_hash) DO UPDATE SET \
             failed_attempts = excluded.failed_attempts, \
             next_attempt_at_ms = excluded.next_attempt_at_ms, \
             cursor = excluded.cursor, \
             recorded_at_ms = excluded.recorded_at_ms",
            &[
                StoreValue::Blob(entry.as_bytes().to_vec()),
                StoreValue::Integer(i64::from(failed_attempts)),
                StoreValue::Integer(next_attempt_at.get()),
                cursor
                    .as_ref()
                    .map_or(StoreValue::Null, |bytes| StoreValue::Blob(bytes.clone())),
                StoreValue::Integer(unix_millis_now()),
            ],
        )?;
        Ok(())
    }
}

/// Spult die Politik auf `failed_attempts` vor und liefert die letzte
/// Entscheidung.
fn advance(
    policy: &mut RetryPolicy,
    failed_attempts: u16,
    jitter: &mut impl JitterSource,
) -> RetryDecision {
    let mut decision = policy.next(jitter);
    for _ in 1..failed_attempts {
        decision = policy.next(jitter);
    }
    decision
}

impl From<StoreError> for SyncClientError {
    fn from(_: StoreError) -> Self {
        Self::RetryStateUnreadable
    }
}
