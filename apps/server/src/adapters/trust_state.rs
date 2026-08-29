//! Der persistente `ea_trust::TrustStateStore` hinter PostgreSQL.
//!
//! # Nebenlaeufigkeitsaussage
//!
//! Der einzige oeffentliche Weg zur Kopfauswahl ist ein SCHREIBENDER:
//! `prepare_local_time` (`crates/ea-trust/src/time.rs`) nimmt
//! `&mut dyn TrustStateStore` und ruft `commit_independent_time`;
//! `select_registry_head` (`crates/ea-trust/src/registry.rs`) antwortet danach
//! mit Selected, Advanced oder PendingFuture. Dieser Adapter muss deshalb
//! sagen, welche Revision er erwartet und wie ein verlorenes Rennen beantwortet
//! wird — und er sagt es hier:
//!
//! * **Erwartete Revision.** Jeder Commit traegt die Revision, die der Aufrufer
//!   bei seinem `load` gelesen hat. Geschrieben wird mit
//!   `UPDATE … WHERE organization_id = $1 AND device_id = $2 AND revision = $expected`,
//!   und die neue Revision ist genau `expected + 1`. Es gibt keinen anderen
//!   Weg, eine Zeile dieser Tabelle zu veraendern.
//! * **Verlorenes Rennen.** Ein Commit, dessen `UPDATE` NULL Zeilen trifft, hat
//!   verloren: eine andere Transaktion hat dieselbe Zeile inzwischen
//!   fortgeschrieben. Die Antwort ist [`StateStoreError::Conflict`]
//!   (`EA-TRUST-STATE-CONFLICT`). Der Adapter WIEDERHOLT NICHT von sich aus —
//!   ein stiller Retry rechnete die Auswahl auf einem Zustand nach, den der
//!   Aufrufer nie gesehen hat. Der Aufrufer liest neu und entscheidet neu.
//! * **Monotonie.** Ein Zeitboden, der sinken wuerde, wird VOR dem Schreiben
//!   abgewiesen: [`StateStoreError::MonotonicityViolation`]. Ein rueckwaerts
//!   laufender Boden ist genau der Angriff, gegen den `ea-time` ihn fuehrt.
//! * **Wiedereinspielung.** Ein Freigabenachweis wird in derselben Transaktion
//!   in `clock_release_replays` eingetragen; der Primaerschluessel IST die
//!   Sperre, ein zweites Einspielen ist
//!   [`StateStoreError::ReplayAlreadyConsumed`].
//! * **Ausfall.** Jeder Datenbankfehler, der keiner der drei Befunde ist, ist
//!   [`StateStoreError::Unavailable`]. Der Datenbanktext wird nie
//!   weitergereicht.
//!
//! # Warum der Adapter blockierend bruecken darf
//!
//! `TrustStateStore` ist SYNCHRON und nimmt `&mut self` — die Kernbibliotheken
//! unter `crates/` halten keine Laufzeit, und das bleibt so. Die Bruecke
//! liegt deshalb hier, in `apps/server`, wo die Tokio-Laufzeit lebt:
//! [`PostgresTrustStateStore`] fuehrt jede Anweisung ueber
//! `block_in_place` plus `Handle::block_on`.
//!
//! DAS SETZT DIE MEHRFADEN-LAUFZEIT VORAUS. `block_in_place` bricht auf einer
//! Ein-Faden-Laufzeit mit Panik ab, und das ist der Vorgabewert von
//! `#[tokio::test]`. Jeder Test, der diesen Adapter fuehrt, laeuft deshalb als
//! `#[tokio::test(flavor = "multi_thread")]`; der Serverbinaerteil laeuft
//! ohnehin auf `rt-multi-thread` (ADR 0004).

use ea_time::{IndependentTimeInput, IndependentTimeKind, TrustedTimeState};
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, StateStoreError, TrustStateKey, TrustStateStore,
};
use ea_types::{ObjectHash, RegistryVersion, UnixMillis};
use sqlx::{PgPool, Row, postgres::PgRow};
use tokio::{runtime::Handle, task};

pub struct PostgresTrustStateStore {
    pool: PgPool,
    /// Der Zeitboden, mit dem eine noch unbekannte Zeile angelegt wird.
    ///
    /// Er ist PFLICHT und kein `Option`: ein leerer Stand braucht einen
    /// ehrlichen Boden, und den kann diese Struktur nicht erfinden — sie
    /// bekommt ihn vom Aufrufer, so wie `EphemeralTrustStateStore` ihn
    /// bekommt.
    initial_floor: UnixMillis,
}

impl PostgresTrustStateStore {
    #[must_use]
    pub const fn new(pool: PgPool, initial_floor: UnixMillis) -> Self {
        Self {
            pool,
            initial_floor,
        }
    }

    /// Fuehrt eine asynchrone Anweisung aus einem synchronen Vertrag heraus.
    fn block_on<F: Future>(future: F) -> F::Output {
        task::block_in_place(|| Handle::current().block_on(future))
    }

    fn read(&self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        let row = Self::block_on(
            sqlx::query(
                "SELECT revision, trusted_floor_millis, independent_kind_code, \
                 independent_object_hash, independent_verified_at_millis, \
                 pinned_registry_version, pinned_registry_head_hash FROM trust_state \
                 WHERE organization_id = $1 AND device_id = $2",
            )
            .bind(&key.organization_id.as_bytes()[..])
            .bind(&key.device_id.as_bytes()[..])
            .fetch_optional(&self.pool),
        )
        .map_err(|_| StateStoreError::Unavailable)?;
        match row {
            Some(row) => decode_record(&row),
            // Ein unbekannter Schluessel ist KEIN Fehler: er ist der leere
            // Stand, aus dem jede Vertrauenslinie beginnt.
            None => Ok(PersistedTrustRecord::new(
                0,
                TrustedTimeState::initial(self.initial_floor),
                None,
            )),
        }
    }

    /// Der eine Schreibweg: Compare-and-Set ueber die Revision.
    fn write(
        &self,
        key: TrustStateKey,
        expected_revision: u64,
        next_trusted_time: &TrustedTimeState,
        next_head: Option<RegistryHeadPin>,
        replay_key: Option<&ClockReleaseReplayKey>,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        let current = self.read(key)?;
        if current.revision() != expected_revision {
            return Err(StateStoreError::Conflict);
        }
        if next_trusted_time.floor() < current.trusted_time().floor() {
            return Err(StateStoreError::MonotonicityViolation);
        }
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(StateStoreError::Unavailable)?;

        Self::block_on(async {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| StateStoreError::Unavailable)?;

            if let Some(replay) = replay_key {
                let inserted = sqlx::query(
                    "INSERT INTO clock_release_replays (organization_id, target_device_id, \
                     nonce, consumed_at_millis) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                )
                .bind(&replay.organization_id().as_bytes()[..])
                .bind(&replay.target_device_id().as_bytes()[..])
                .bind(&replay.nonce()[..])
                .bind(next_trusted_time.floor().get())
                .execute(&mut *transaction)
                .await
                .map_err(|_| StateStoreError::Unavailable)?
                .rows_affected();
                if inserted != 1 {
                    return Err(StateStoreError::ReplayAlreadyConsumed);
                }
            }

            let reference = next_trusted_time.independent_reference();
            let affected = sqlx::query(
                "INSERT INTO trust_state (organization_id, device_id, revision, \
                 trusted_floor_millis, independent_kind_code, independent_object_hash, \
                 independent_verified_at_millis, pinned_registry_version, \
                 pinned_registry_head_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (organization_id, device_id) DO UPDATE SET \
                 revision = EXCLUDED.revision, \
                 trusted_floor_millis = EXCLUDED.trusted_floor_millis, \
                 independent_kind_code = EXCLUDED.independent_kind_code, \
                 independent_object_hash = EXCLUDED.independent_object_hash, \
                 independent_verified_at_millis = EXCLUDED.independent_verified_at_millis, \
                 pinned_registry_version = EXCLUDED.pinned_registry_version, \
                 pinned_registry_head_hash = EXCLUDED.pinned_registry_head_hash \
                 WHERE trust_state.revision = $10",
            )
            .bind(&key.organization_id.as_bytes()[..])
            .bind(&key.device_id.as_bytes()[..])
            .bind(i64::try_from(next_revision).map_err(|_| StateStoreError::Unavailable)?)
            .bind(next_trusted_time.floor().get())
            .bind(reference.map(|value| i16::from(kind_code(value.kind()))))
            .bind(reference.map(|value| value.object_hash().as_bytes().to_vec()))
            .bind(reference.map(|value| value.verified_time().get()))
            .bind(
                next_head
                    .map(|head| i64::try_from(head.registry_version().get()))
                    .transpose()
                    .map_err(|_| StateStoreError::Unavailable)?,
            )
            .bind(next_head.map(|head| head.registry_head_hash().as_bytes().to_vec()))
            .bind(i64::try_from(expected_revision).map_err(|_| StateStoreError::Unavailable)?)
            .execute(&mut *transaction)
            .await
            .map_err(|_| StateStoreError::Unavailable)?
            .rows_affected();

            // NULL Zeilen heisst: verlorenes Rennen. Kein Retry.
            if affected != 1 {
                return Err(StateStoreError::Conflict);
            }
            transaction
                .commit()
                .await
                .map_err(|_| StateStoreError::Unavailable)?;
            Ok(())
        })?;

        Ok(PersistedTrustRecord::new(
            next_revision,
            next_trusted_time.clone(),
            next_head,
        ))
    }
}

impl TrustStateStore for PostgresTrustStateStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        self.read(key)
    }

    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        let pinned = self.read(key)?.pinned_head().copied();
        self.write(
            key,
            expected_revision,
            commit.next_trusted_time(),
            pinned,
            None,
        )
    }

    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        let row = Self::block_on(
            sqlx::query(
                "SELECT 1 AS present FROM clock_release_replays WHERE organization_id = $1 \
                 AND target_device_id = $2 AND nonce = $3",
            )
            .bind(&key.organization_id().as_bytes()[..])
            .bind(&key.target_device_id().as_bytes()[..])
            .bind(&key.nonce()[..])
            .fetch_optional(&self.pool),
        )
        .map_err(|_| StateStoreError::Unavailable)?;
        Ok(row.is_some())
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        // Dieselbe Regel wie im lesenden Modell: die Kopfauswahl darf den Boden
        // heben, aber niemals die unabhaengige Referenz austauschen — die
        // entsteht ausschliesslich aus signierten Zeitquellen ueber
        // `commit_independent_time`.
        let current = self.read(key)?;
        if commit.next_trusted_time().independent_reference()
            != current.trusted_time().independent_reference()
        {
            return Err(StateStoreError::MonotonicityViolation);
        }
        self.write(
            key,
            expected_revision,
            commit.next_trusted_time(),
            Some(*commit.next_head()),
            commit.replay_key(),
        )
    }
}

const fn kind_code(kind: IndependentTimeKind) -> u8 {
    match kind {
        IndependentTimeKind::Receipt => 0,
        IndependentTimeKind::Checkpoint => 1,
        IndependentTimeKind::Tsa => 2,
    }
}

const fn kind_of(code: i16) -> Option<IndependentTimeKind> {
    match code {
        0 => Some(IndependentTimeKind::Receipt),
        1 => Some(IndependentTimeKind::Checkpoint),
        2 => Some(IndependentTimeKind::Tsa),
        _ => None,
    }
}

fn decode_record(row: &PgRow) -> Result<PersistedTrustRecord, StateStoreError> {
    let revision: i64 = row.get("revision");
    let floor: i64 = row.get("trusted_floor_millis");
    let kind: Option<i16> = row.get("independent_kind_code");
    let object_hash: Option<Vec<u8>> = row.get("independent_object_hash");
    let verified: Option<i64> = row.get("independent_verified_at_millis");
    let version: Option<i64> = row.get("pinned_registry_version");
    let head_hash: Option<Vec<u8>> = row.get("pinned_registry_head_hash");

    let reference = match (kind, object_hash, verified) {
        (Some(kind), Some(hash), Some(verified)) => Some(IndependentTimeInput::new(
            kind_of(kind).ok_or(StateStoreError::Unavailable)?,
            ObjectHash::try_from(hash.as_slice()).map_err(|_| StateStoreError::Unavailable)?,
            UnixMillis::new(verified),
        )),
        (None, None, None) => None,
        // Die Spaltenpruefung der Migration schliesst jede halbe Referenz aus;
        // trifft sie hier doch ein, ist der Stand unbrauchbar und nicht halb
        // gueltig.
        _ => return Err(StateStoreError::Unavailable),
    };
    let trusted_time = TrustedTimeState::from_persisted(UnixMillis::new(floor), reference)
        .map_err(|_| StateStoreError::MonotonicityViolation)?;

    let pinned = match (version, head_hash) {
        (Some(version), Some(hash)) => Some(RegistryHeadPin::new(
            RegistryVersion::new(u64::try_from(version).map_err(|_| StateStoreError::Unavailable)?),
            ObjectHash::try_from(hash.as_slice()).map_err(|_| StateStoreError::Unavailable)?,
        )),
        (None, None) => None,
        _ => return Err(StateStoreError::Unavailable),
    };

    Ok(PersistedTrustRecord::new(
        u64::try_from(revision).map_err(|_| StateStoreError::Unavailable)?,
        trusted_time,
        pinned,
    ))
}
