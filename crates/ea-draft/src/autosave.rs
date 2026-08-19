//! Die Autospeicherung des EINEN aktiven Entwurfs.
//!
//! Zwei Verschluesselungen liegen uebereinander. Die Nutzlast wird mit
//! `ea_crypto::aead_seal` unter einem eigenen `draftDEK` und einer FRISCHEN
//! Nonce je Speicherung verschlossen, BEVOR die Zeile SQLCipher erreicht: eine
//! Nonce wird nie ueber zwei Fassungen desselben Schluessels wiederverwendet,
//! und alte Datenbankseiten bleiben unlesbar, sobald der Schluessel fort ist.
//!
//! Der `draftDEK` selbst liegt im Schluesselspeicher des Betriebssystems —
//! geraetegebunden, nicht roamend, nicht cloud-synchronisierend und aus der
//! gewoehnlichen Anwendungs- und Systemsicherung ausgenommen
//! (`design.md`:428, :1491). Die Zeile traegt nur den Verweis auf seinen Griff.

use std::sync::Arc;

use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes, SecretVec, aead_open, aead_seal};
use ea_key_provider::{KeyHandle, KeyProvider, KeystoreProvider, SecretPurpose};
use ea_local_store::{
    EncryptedDatabase, StoreTransaction, StoreValue, migrations::DISCARD_MIGRATION_VERSION,
    unix_millis_now,
};
use ea_types::{Hash32, Id16};

use crate::{
    DraftLock,
    model::{
        DiscardIntent, DiscardOutcome, Draft, DraftError, PreparedFinalizationMarker, SavedDraft,
    },
    repository::DraftRepository,
};

/// Die Marke des Verwerfenszustands in `draft_transition`.
const TRANSITION_DISCARD: i64 = 0;
/// Die Marke des vorbereiteten Abschlusses in `draft_transition`.
const TRANSITION_FINALIZATION: i64 = 1;

const SELECT_DRAFT: &str = "SELECT draft_id, payload_ciphertext, payload_nonce, \
     dek_keystore_provider, dek_account_instance, save_revision FROM draft WHERE singleton = 0";

/// Die Ablage, die genau einen aktiven Entwurf zulaesst.
pub struct AutosaveDraftRepository {
    database: Arc<EncryptedDatabase>,
    provider: Arc<dyn KeyProvider>,
}

impl AutosaveDraftRepository {
    #[must_use]
    pub fn new(database: Arc<EncryptedDatabase>, provider: Arc<dyn KeyProvider>) -> Self {
        Self { database, provider }
    }

    /// Legt den einen leeren Entwurf an, den es geben darf.
    ///
    /// Der frische `draftDEK` wird eingepackt und danach WIEDER AUSGEPACKT,
    /// statt die Rohbytes daneben zu behalten: `wrap_secret` verbraucht das
    /// Geheimnis, und ein zweites, ungeschuetztes Abbild davon waere genau der
    /// Prozessspeicher-Rest, den `SecretBytes` verhindern soll. Der Umweg
    /// belegt in derselben Bewegung, dass der Eintrag wirklich liegt.
    fn create_blank(&self, transaction: &StoreTransaction<'_>) -> Result<SavedDraft, DraftError> {
        let draft_id =
            Id16::try_from(fresh::<16>()?.as_slice()).map_err(|_| DraftError::Payload)?;
        let handle = self.provider.wrap_secret(
            SecretPurpose::DraftDek,
            SecretBytes::new(fresh::<CEK_SIZE>()?),
        )?;
        let dek = self.provider.unwrap_secret(&handle)?;
        let nonce = SecretBytes::<AEAD_NONCE_SIZE>::new(fresh::<AEAD_NONCE_SIZE>()?);
        let ciphertext = aead_seal(
            &dek,
            &nonce,
            SecretVec::new(Vec::new()),
            &associated_data(draft_id, 0),
        )?;
        let now = unix_millis_now();
        transaction.execute(
            "INSERT INTO draft (singleton, draft_id, payload_ciphertext, payload_nonce, \
             dek_keystore_provider, dek_account_instance, save_revision, created_at_ms, \
             updated_at_ms) VALUES (0, ?1, ?2, ?3, ?4, ?5, 0, ?6, ?6)",
            &[
                StoreValue::Blob(draft_id.as_bytes().to_vec()),
                StoreValue::Blob(ciphertext),
                StoreValue::Blob(nonce.with_exposed(|bytes| bytes.to_vec())),
                StoreValue::Integer(provider_code(handle.keystore_provider())),
                StoreValue::Blob(handle.account_instance().as_bytes().to_vec()),
                StoreValue::Integer(now),
            ],
        )?;
        Ok(SavedDraft::new(draft_id, 0))
    }

    fn read_row(
        &self,
        transaction: &StoreTransaction<'_>,
    ) -> Result<Option<StoredDraftRow>, DraftError> {
        let Some(row) = transaction.query_row(SELECT_DRAFT, &[])? else {
            return Ok(None);
        };
        let draft_id = Id16::try_from(row.blob(0)?).map_err(|_| DraftError::Payload)?;
        let ciphertext = row.blob(1)?.to_vec();
        let nonce: [u8; AEAD_NONCE_SIZE] =
            row.blob(2)?.try_into().map_err(|_| DraftError::Payload)?;
        let provider = provider_from_code(row.integer(3)?)?;
        let account = Hash32::try_from(row.blob(4)?).map_err(|_| DraftError::Payload)?;
        let revision = u64::try_from(row.integer(5)?).map_err(|_| DraftError::Payload)?;
        Ok(Some(StoredDraftRow {
            draft_id,
            ciphertext,
            nonce,
            handle: KeyHandle::new(provider, account, SecretPurpose::DraftDek),
            revision,
        }))
    }

    /// Meldet, ob die Uebergangstabelle bereits existiert.
    ///
    /// Eine POSITIVE Abfrage der Registratur und kein verschluckter SQL-Fehler:
    /// „`0002_discard.sql` ist nicht registriert" ist eine wahre Aussage
    /// darueber, dass der Zustand noch gar nicht entstehen KANN, und nicht das
    /// Wegdruecken eines Fehlschlags.
    fn transition_table_exists(&self) -> Result<bool, DraftError> {
        Ok(self.database.has_migration(DISCARD_MIGRATION_VERSION)?)
    }
}

struct StoredDraftRow {
    draft_id: Id16,
    ciphertext: Vec<u8>,
    nonce: [u8; AEAD_NONCE_SIZE],
    handle: KeyHandle,
    revision: u64,
}

impl DraftRepository for AutosaveDraftRepository {
    fn load_or_create(&self) -> Result<Draft, DraftError> {
        self.database.transaction(|transaction| {
            if let Some(row) = self.read_row(transaction)? {
                let dek = self.provider.unwrap_secret(&row.handle)?;
                let plaintext = aead_open(
                    &dek,
                    &SecretBytes::new(row.nonce),
                    &row.ciphertext,
                    &associated_data(row.draft_id, row.revision),
                )?;
                let notes = plaintext
                    .with_exposed(|bytes| core::str::from_utf8(bytes).map(str::to_owned))
                    .map_err(|_| DraftError::Payload)?;
                return Ok(Draft::restored(row.draft_id, row.revision, notes));
            }
            let created = self.create_blank(transaction)?;
            Ok(Draft::restored(
                created.draft_id(),
                created.revision(),
                String::new(),
            ))
        })
    }

    fn save(&self, draft: Draft) -> Result<SavedDraft, DraftError> {
        self.database.transaction(|transaction| {
            let row = self.read_row(transaction)?.ok_or(DraftError::NoDraft)?;
            if row.draft_id != draft.draft_id() || row.revision != draft.revision() {
                return Err(DraftError::RevisionConflict);
            }
            let target = row
                .revision
                .checked_add(1)
                .ok_or(DraftError::RevisionConflict)?;
            let dek = self.provider.unwrap_secret(&row.handle)?;
            let nonce = SecretBytes::<AEAD_NONCE_SIZE>::new(fresh::<AEAD_NONCE_SIZE>()?);
            let ciphertext = aead_seal(
                &dek,
                &nonce,
                SecretVec::new(draft.notes().as_bytes().to_vec()),
                &associated_data(row.draft_id, target),
            )?;
            // Die Bedingung `save_revision = ?5` wiederholt den Vergleich IN
            // der Anweisung. Das Lesen oben liefert den Fehlercode, diese Zeile
            // die Atomizitaet: zwischen Lesen und Schreiben kann keine zweite
            // Sitzung dazwischentreten, weil die Transaktion unmittelbar
            // exklusiv ist UND die Anweisung ihre eigene Vorbedingung traegt.
            let changed = transaction.execute(
                "UPDATE draft SET payload_ciphertext = ?1, payload_nonce = ?2, \
                 save_revision = ?3, updated_at_ms = ?4 WHERE singleton = 0 AND save_revision = ?5",
                &[
                    StoreValue::Blob(ciphertext),
                    StoreValue::Blob(nonce.with_exposed(|bytes| bytes.to_vec())),
                    StoreValue::Integer(i64::try_from(target).map_err(|_| DraftError::Payload)?),
                    StoreValue::Integer(unix_millis_now()),
                    StoreValue::Integer(
                        i64::try_from(row.revision).map_err(|_| DraftError::Payload)?,
                    ),
                ],
            )?;
            if changed != 1 {
                return Err(DraftError::RevisionConflict);
            }
            Ok(SavedDraft::new(row.draft_id, target))
        })
    }

    fn draft_dek_handle(&self, draft: &SavedDraft) -> Result<KeyHandle, DraftError> {
        self.database.transaction(|transaction| {
            let row = self.read_row(transaction)?.ok_or(DraftError::NoDraft)?;
            if row.draft_id != draft.draft_id() {
                return Err(DraftError::NoDraft);
            }
            Ok(row.handle)
        })
    }

    fn commit_discard_intent(&self, draft: &SavedDraft) -> Result<DiscardIntent, DraftError> {
        if !self.transition_table_exists()? {
            return Err(DraftError::TransitionUnavailable);
        }
        self.database.transaction(|transaction| {
            let row = self.read_row(transaction)?.ok_or(DraftError::NoDraft)?;
            if row.draft_id != draft.draft_id() || row.revision != draft.revision() {
                return Err(DraftError::RevisionConflict);
            }
            transaction.execute(
                UPSERT_TRANSITION,
                &[
                    StoreValue::Integer(TRANSITION_DISCARD),
                    StoreValue::Blob(row.draft_id.as_bytes().to_vec()),
                    StoreValue::Integer(
                        i64::try_from(row.revision).map_err(|_| DraftError::Payload)?,
                    ),
                    StoreValue::Null,
                    StoreValue::Integer(unix_millis_now()),
                ],
            )?;
            Ok(DiscardIntent::new(row.draft_id, row.revision))
        })
    }

    fn pending_discard(&self) -> Result<Option<DiscardIntent>, DraftError> {
        if !self.transition_table_exists()? {
            return Ok(None);
        }
        let row = self.database.query_row(
            "SELECT draft_id, save_revision FROM draft_transition WHERE singleton = 0 AND kind = ?1",
            &[StoreValue::Integer(TRANSITION_DISCARD)],
        )?;
        let Some(row) = row else { return Ok(None) };
        let draft_id = Id16::try_from(row.blob(0)?).map_err(|_| DraftError::Payload)?;
        let revision = u64::try_from(row.integer(1)?).map_err(|_| DraftError::Payload)?;
        Ok(Some(DiscardIntent::new(draft_id, revision)))
    }

    fn replace_with_blank(&self) -> Result<SavedDraft, DraftError> {
        self.database.transaction(|transaction| {
            transaction.execute("DELETE FROM draft WHERE singleton = 0", &[])?;
            self.create_blank(transaction)
        })
    }

    fn remove_ciphertext_and_intent_create_blank(
        &self,
        intent: &DiscardIntent,
    ) -> Result<DiscardOutcome, DraftError> {
        if !self.transition_table_exists()? {
            return Err(DraftError::TransitionUnavailable);
        }
        self.database.transaction(|transaction| {
            let row = self.read_row(transaction)?.ok_or(DraftError::NoDraft)?;
            if row.draft_id != intent.draft_id() {
                return Err(DraftError::NoDraft);
            }
            transaction.execute("DELETE FROM draft WHERE singleton = 0", &[])?;
            transaction.execute(
                "DELETE FROM draft_transition WHERE singleton = 0 AND kind = ?1",
                &[StoreValue::Integer(TRANSITION_DISCARD)],
            )?;
            let blank = self.create_blank(transaction)?;
            Ok(DiscardOutcome::new(row.draft_id, blank))
        })
    }

    fn prepared_finalization_marker(
        &self,
    ) -> Result<Option<PreparedFinalizationMarker>, DraftError> {
        if !self.transition_table_exists()? {
            return Ok(None);
        }
        let row = self.database.query_row(
            "SELECT marker FROM draft_transition WHERE singleton = 0 AND kind = ?1",
            &[StoreValue::Integer(TRANSITION_FINALIZATION)],
        )?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(PreparedFinalizationMarker::new(row.blob(0)?.to_vec())))
    }

    fn replace_prepared_finalization_marker(
        &self,
        marker: Option<PreparedFinalizationMarker>,
    ) -> Result<(), DraftError> {
        if !self.transition_table_exists()? {
            return Err(DraftError::TransitionUnavailable);
        }
        self.database.transaction(|transaction| {
            // EIN Schreibvorgang, in beide Richtungen. `draft_transition` ist
            // ein einziger Platz: eine gesetzte Abschlussmarke verdraengt eine
            // gebuchte Verwerfensabsicht und umgekehrt. Genau deshalb kann die
            // gegenseitige Ausschliessung der zwei Zustaende nicht auf zwei
            // Schreibvorgaenge zerfallen.
            match marker {
                Some(marker) => {
                    transaction.execute(
                        UPSERT_TRANSITION,
                        &[
                            StoreValue::Integer(TRANSITION_FINALIZATION),
                            StoreValue::Blob(Id16::ZERO.as_bytes().to_vec()),
                            StoreValue::Integer(0),
                            StoreValue::Blob(marker.as_bytes().to_vec()),
                            StoreValue::Integer(unix_millis_now()),
                        ],
                    )?;
                }
                None => {
                    transaction.execute(
                        "DELETE FROM draft_transition WHERE singleton = 0 AND kind = ?1",
                        &[StoreValue::Integer(TRANSITION_FINALIZATION)],
                    )?;
                }
            }
            Ok(())
        })
    }

    fn acquire_draft_lock(&self) -> Result<DraftLock, DraftError> {
        DraftLock::acquire(self.database.path())
    }
}

/// Der eine Platz von `draft_transition`, in beide Richtungen beschrieben.
const UPSERT_TRANSITION: &str = "INSERT INTO draft_transition \
     (singleton, kind, draft_id, save_revision, marker, recorded_at_ms) \
     VALUES (0, ?1, ?2, ?3, ?4, ?5) \
     ON CONFLICT(singleton) DO UPDATE SET kind = excluded.kind, \
     draft_id = excluded.draft_id, save_revision = excluded.save_revision, \
     marker = excluded.marker, recorded_at_ms = excluded.recorded_at_ms";

/// Die zusaetzlichen Daten der AEAD: Zeilenidentitaet und ZIELFASSUNG.
///
/// Sie sind lokal, werden nie archiviert und von keiner zweiten Implementierung
/// nachgeprueft; sie bekommen deshalb kein eingefrorenes Format und fuehren
/// keine neue Domainkonstante ein. Die Zielfassung steht darin, damit ein
/// Chiffrat einer Fassung nicht als Chiffrat einer anderen durchgeht.
fn associated_data(draft_id: Id16, revision: u64) -> Vec<u8> {
    let mut associated = Vec::with_capacity(24);
    associated.extend_from_slice(draft_id.as_bytes());
    associated.extend_from_slice(&revision.to_be_bytes());
    associated
}

fn fresh<const N: usize>() -> Result<[u8; N], DraftError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| DraftError::LocalRng)?;
    Ok(bytes)
}

const fn provider_code(provider: KeystoreProvider) -> i64 {
    match provider {
        KeystoreProvider::OperatingSystem => 0,
        KeystoreProvider::InMemory => 1,
    }
}

const fn provider_from_code(code: i64) -> Result<KeystoreProvider, DraftError> {
    match code {
        0 => Ok(KeystoreProvider::OperatingSystem),
        1 => Ok(KeystoreProvider::InMemory),
        _ => Err(DraftError::Payload),
    }
}
