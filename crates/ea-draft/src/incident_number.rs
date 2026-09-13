//! Das Register verbrauchter Einsatznummern.
//!
//! Der Schluessel ist genau der von `design.md`:361-373: Organisation,
//! oertliches Kalenderjahr und die NFC-normalisierten UTF-8-Bytes der
//! menschenlesbaren Nummer.
//!
//! Das Register ist eine ERFASSUNGSQUELLE und kein abgeleiteter Zustand. Die
//! Rekonstruktionspflicht aus `design.md` §19.3 gilt ihm deshalb nicht, und
//! eine gesalzene Zusage braucht es nicht.
//!
//! Das Ableiten des oertlichen Kalenderjahres aus `incidentOccurredAt.start` in
//! `timezone` gegen die gepinnte tzdb und das Erzwingen des Anspruchs unter der
//! ausschliesslichen Writer-Sperre vor Validieren-und-Serialisieren gehoeren
//! Task 11 — hier steht die Tabelle und ihr Anspruch.

use std::sync::Arc;

use ea_local_store::{
    EncryptedDatabase, StoreError, StoreTransaction, StoreValue, unix_millis_now,
};
use ea_types::OrganizationId;
use hmac::{Hmac, KeyInit, Mac};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::model::DraftError;

/// Das Register.
pub struct IncidentNumberRegister {
    database: Arc<EncryptedDatabase>,
}

impl IncidentNumberRegister {
    /// The register's one NFC equality definition, also used to identify
    /// historical raw claim spellings during exact authorized source cleanup.
    pub fn same_number(left: &str, right: &str) -> bool {
        Zeroizing::new(register_key(left)) == Zeroizing::new(register_key(right))
    }
    /// Retain only a minimal equality token before an independently authorized
    /// target purge. This method removes no source row and grants no authority
    /// to call `release_in` after publication. Caller holds the exact purge
    /// job's SQLCipher transaction and native/Writer locks.
    pub fn retain_for_destruction_in(
        tx: &StoreTransaction<'_>,
        organization_id: OrganizationId,
        local_civil_year: i32,
        human_incident_number: &str,
    ) -> Result<(), DraftError> {
        let sync = tx
            .query_row("PRAGMA synchronous", &[])?
            .ok_or(StoreError::Database)?
            .integer(0)?;
        if !matches!(sync, 2 | 3) {
            return Err(DraftError::Store(StoreError::Database));
        }
        let token = retained_token(
            tx,
            organization_id,
            local_civil_year,
            human_incident_number,
            true,
        )?
        .ok_or(StoreError::Database)?;
        tx.execute("INSERT INTO incident_number_retained_token(token) VALUES(?1) ON CONFLICT(token) DO NOTHING",&[StoreValue::Blob(token.to_vec())])?;
        Ok(())
    }

    #[must_use]
    pub const fn new(database: Arc<EncryptedDatabase>) -> Self {
        Self { database }
    }

    /// Beansprucht eine Nummer fuer Organisation und oertliches Kalenderjahr.
    ///
    /// Die Normalisierung findet HIER statt und nicht beim Aufrufer: sonst
    /// koennte ein Aufrufer den Schluessel mit einer zerlegten Form aufweichen
    /// und dieselbe Nummer zweimal beanspruchen. Gespeichert werden genau die
    /// normalisierten Bytes.
    ///
    /// # Errors
    ///
    /// [`DraftError::IncidentNumberTaken`], wenn der Schluessel bereits
    /// verbraucht ist — die Ablehnung kommt aus der `UNIQUE`-Bedingung des
    /// Schemas und nicht aus einer vorgelagerten Abfrage, damit die Bedingung
    /// tragend ist und nicht dekorativ.
    pub fn claim(
        &self,
        organization_id: OrganizationId,
        local_civil_year: i32,
        human_incident_number: &str,
    ) -> Result<(), DraftError> {
        self.database.transaction(|tx| {
            Self::claim_in(tx, organization_id, local_civil_year, human_incident_number)
        })
    }

    /// Whether an atomic recovery journal uses this register's exact store.
    #[must_use]
    pub fn uses_database(&self, database: &Arc<EncryptedDatabase>) -> bool {
        Arc::ptr_eq(&self.database, database)
    }

    /// The exact encrypted acquisition-source store, for a Writer journal
    /// that must commit atomically with the normal number claim.
    #[must_use]
    pub fn database_handle(&self) -> Arc<EncryptedDatabase> {
        Arc::clone(&self.database)
    }

    /// Claim with the normal UNIQUE/NFC rules in the caller's atomic journal
    /// transaction. The caller must hold the Writer and draft locks.
    pub fn claim_in(
        tx: &StoreTransaction<'_>,
        organization_id: OrganizationId,
        local_civil_year: i32,
        human_incident_number: &str,
    ) -> Result<(), DraftError> {
        if retained_contains(tx, organization_id, local_civil_year, human_incident_number)? {
            return Err(DraftError::IncidentNumberTaken);
        }
        let outcome = tx.execute(
            "INSERT INTO incident_number_register \
             (organization_id, local_civil_year, human_incident_number, claimed_at_ms) \
             VALUES (?1, ?2, ?3, ?4)",
            &[
                StoreValue::Blob(organization_id.as_bytes().to_vec()),
                StoreValue::Integer(i64::from(local_civil_year)),
                StoreValue::Blob(register_key(human_incident_number)),
                StoreValue::Integer(unix_millis_now()),
            ],
        );
        match outcome {
            Ok(_) => Ok(()),
            Err(StoreError::Constraint) => Err(DraftError::IncidentNumberTaken),
            Err(error) => Err(DraftError::Store(error)),
        }
    }

    /// Gibt eine Nummer wieder FREI.
    ///
    /// # Wer sie aufrufen darf
    ///
    /// AUSSCHLIESSLICH eine Finalisierung, die nach ihrem Anspruch und VOR der
    /// unwiderruflichen Grenze gescheitert ist (`design.md` §9.4: „vor der
    /// dauerhaften Loeschung des `draftDEK` darf der Entwurf wiederhergestellt
    /// werden"). Fuer sie gehoert die Nummer weiterhin demselben realen Einsatz,
    /// und ohne die Freigabe muesste der Bediener sich fuer ihn eine andere
    /// ausdenken.
    ///
    /// Hinter der Grenze ist der Aufruf VERBOTEN: dort traegt ein
    /// veroeffentlichter Eintrag die Nummer in seiner Nutzlast, und eine
    /// Freigabe liesse einen zweiten Einsatz dieselbe beanspruchen — zwei
    /// committed Eintraege, die sich nicht mehr zuruecknehmen lassen.
    ///
    /// Normalisiert dieselbe Zeichenkette wie [`Self::claim`]; eine zerlegte
    /// Form gaebe sonst einen anderen Schluessel frei als den beanspruchten.
    ///
    /// # Errors
    ///
    /// [`DraftError::Store`], wenn die Ablage ablehnt. Dass KEINE Zeile
    /// getroffen wurde, ist KEIN Fehler: die Freigabe ist idempotent, und ein
    /// zweiter Aufruf ueber denselben Schluessel soll nichts anderes bedeuten
    /// als der erste.
    pub fn release(
        &self,
        organization_id: OrganizationId,
        local_civil_year: i32,
        human_incident_number: &str,
    ) -> Result<(), DraftError> {
        self.database.transaction(|tx| {
            Self::release_in(tx, organization_id, local_civil_year, human_incident_number)
        })
    }

    /// Release the exact normalized claim in the same transaction as its
    /// durable recovery resolution. The reversible-boundary rule of `release`
    /// still applies; this operation grants no independent recovery authority.
    pub fn release_in(
        tx: &StoreTransaction<'_>,
        organization_id: OrganizationId,
        local_civil_year: i32,
        human_incident_number: &str,
    ) -> Result<(), DraftError> {
        let mut parameters = [
            StoreValue::Blob(organization_id.as_bytes().to_vec()),
            StoreValue::Integer(i64::from(local_civil_year)),
            StoreValue::Blob(register_key(human_incident_number)),
        ];
        let removed = tx.execute(
            "DELETE FROM incident_number_register WHERE organization_id = ?1 \
             AND local_civil_year = ?2 AND human_incident_number = ?3",
            &parameters,
        );
        if let StoreValue::Blob(number) = &mut parameters[2] {
            number.zeroize();
        }
        removed?;
        Ok(())
    }

    /// Meldet, ob der Schluessel bereits verbraucht ist.
    ///
    /// Normalisiert dieselbe Zeichenkette wie [`Self::claim`]: eine zerlegte
    /// Anfrage darf nicht „nicht enthalten" melden, wo die zusammengesetzte
    /// Form liegt.
    ///
    /// # Errors
    ///
    /// [`DraftError::Store`], wenn die Ablage ablehnt.
    pub fn contains(
        &self,
        organization_id: OrganizationId,
        local_civil_year: i32,
        human_incident_number: &str,
    ) -> Result<bool, DraftError> {
        self.database.transaction(|tx| {
            if retained_contains(tx, organization_id, local_civil_year, human_incident_number)? {
                return Ok(true);
            }
            let row = tx.query_row(
                "SELECT count(*) FROM incident_number_register WHERE organization_id = ?1 \
             AND local_civil_year = ?2 AND human_incident_number = ?3",
                &[
                    StoreValue::Blob(organization_id.as_bytes().to_vec()),
                    StoreValue::Integer(i64::from(local_civil_year)),
                    StoreValue::Blob(register_key(human_incident_number)),
                ],
            )?;
            match row {
                Some(row) => Ok(row.integer(0)? > 0),
                None => Ok(false),
            }
        })
    }
}

fn retained_contains(
    tx: &StoreTransaction<'_>,
    organization: OrganizationId,
    year: i32,
    number: &str,
) -> Result<bool, DraftError> {
    let Some(token) = retained_token(tx, organization, year, number, false)? else {
        return Ok(false);
    };
    Ok(tx
        .query_row(
            "SELECT token FROM incident_number_retained_token WHERE token=?1",
            &[StoreValue::Blob(token.to_vec())],
        )?
        .is_some())
}
fn retained_token(
    tx: &StoreTransaction<'_>,
    organization: OrganizationId,
    year: i32,
    number: &str,
    create: bool,
) -> Result<Option<[u8; 32]>, DraftError> {
    let row = tx.query_row(
        "SELECT key_bytes FROM incident_number_retained_key WHERE singleton=0",
        &[],
    )?;
    let key = match row {
        Some(row) => row.into_secret_blob()?,
        None => {
            // Losing/restoring only the key cannot reset equality constraints.
            if tx
                .query_row(
                    "SELECT token FROM incident_number_retained_token LIMIT 1",
                    &[],
                )?
                .is_some()
            {
                return Err(DraftError::Store(StoreError::Database));
            }
            if !create {
                return Ok(None);
            }
            let mut raw = Zeroizing::new([0u8; 32]);
            getrandom::fill(raw.as_mut()).map_err(|_| DraftError::LocalRng)?;
            let mut params = [StoreValue::Blob(raw.to_vec())];
            let result = tx.execute(
                "INSERT INTO incident_number_retained_key(singleton,key_bytes) VALUES(0,?1)",
                &params,
            );
            if let StoreValue::Blob(bytes) = &mut params[0] {
                bytes.zeroize();
            }
            result?;
            tx.query_row(
                "SELECT key_bytes FROM incident_number_retained_key WHERE singleton=0",
                &[],
            )?
            .ok_or(StoreError::Database)?
            .into_secret_blob()?
        }
    };
    if key.len() != 32 {
        return Err(DraftError::Store(StoreError::Shape));
    }
    let normalized = Zeroizing::new(register_key(number));
    let token = key.with_exposed(|bytes| {
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(bytes)
            .map_err(|_| DraftError::Store(StoreError::Shape))?;
        mac.update(b"EINSATZARCHIV-INCIDENT-NUMBER-RETAINED-v1\0");
        mac.update(organization.as_bytes());
        mac.update(&year.to_be_bytes());
        mac.update(&(normalized.len() as u64).to_be_bytes());
        mac.update(&normalized);
        Ok::<[u8; 32], DraftError>(mac.finalize().into_bytes().into())
    })?;
    Ok(Some(token))
}

/// Die exakten NFC-normalisierten UTF-8-Bytes der Nummer.
fn register_key(human_incident_number: &str) -> Vec<u8> {
    human_incident_number.nfc().collect::<String>().into_bytes()
}
