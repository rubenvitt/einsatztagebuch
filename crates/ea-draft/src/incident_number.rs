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

use ea_local_store::{EncryptedDatabase, StoreError, StoreValue, unix_millis_now};
use ea_types::OrganizationId;
use unicode_normalization::UnicodeNormalization;

use crate::model::DraftError;

/// Das Register.
pub struct IncidentNumberRegister {
    database: Arc<EncryptedDatabase>,
}

impl IncidentNumberRegister {
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
        let outcome = self.database.execute(
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
        let row = self.database.query_row(
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
    }
}

/// Die exakten NFC-normalisierten UTF-8-Bytes der Nummer.
fn register_key(human_incident_number: &str) -> Vec<u8> {
    human_incident_number.nfc().collect::<String>().into_bytes()
}
