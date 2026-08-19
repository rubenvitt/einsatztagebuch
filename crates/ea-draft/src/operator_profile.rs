//! Die Einzelzeile des Bedienerprofils — NUR LESEND.
//!
//! Stufe 2 KONSUMIERT Bedieneridentitaet und stellt sie nie aus: das Ausgeben
//! des Profils und der Root-signierten Bindung ist Stufe-5-Arbeit. Es gibt hier
//! deshalb keinen Schreib- und keinen Bereitstellungsarm, und es entsteht kein
//! neues Byte-Urbild — Urbild, Domaintrennung, Kanonisierung und
//! Feldreihenfolge sind eingefroren.
//!
//! Task 11 rechnet `operatorProfileCommitment` aus genau dieser Zeile nach und
//! stellt es der gebundenen Bindung gegenueber.

use core::fmt;
use std::sync::Arc;

use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_types::{ObjectHash, OperatorSubjectId, OrganizationId};

use crate::model::DraftError;

/// Die fuenf Zusageeingaben plus der Bindungshash, in der eingefrorenen
/// Reihenfolge.
#[derive(Clone, Eq, PartialEq)]
pub struct OperatorProfile {
    organization_id: OrganizationId,
    operator_subject_id: OperatorSubjectId,
    display_name: String,
    function_label: String,
    profile_commitment_salt: [u8; 32],
    operator_binding_object_hash: ObjectHash,
}

impl OperatorProfile {
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn operator_subject_id(&self) -> OperatorSubjectId {
        self.operator_subject_id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn function_label(&self) -> &str {
        &self.function_label
    }

    /// Das Salz der Profilzusage.
    ///
    /// Kein Geheimnis im Sinne von `SecretBytes`: es steht als Feld im
    /// signierten Kopf eines Eintrags (`crates/ea-schema/src/encode.rs`:443)
    /// und ist damit ohnehin oeffentlich.
    #[must_use]
    pub const fn profile_commitment_salt(&self) -> &[u8; 32] {
        &self.profile_commitment_salt
    }

    #[must_use]
    pub const fn operator_binding_object_hash(&self) -> ObjectHash {
        self.operator_binding_object_hash
    }
}

impl fmt::Debug for OperatorProfile {
    /// Undurchsichtig: ein Anzeigename ist eine personenbezogene Angabe und
    /// gehoert nicht in eine Protokollzeile. Der Rumpf existiert, damit
    /// `Option::unwrap` an diesem Typ ueberhaupt aufrufbar ist.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorProfile(<bound>)")
    }
}

/// Die NUR LESENDE Ablage der Profilzeile.
///
/// Sie hat genau einen fachlichen Arm. Ein Schreib- oder Bereitstellungsarm,
/// spaeter hinzugefuegt, machte die Zusage „Stufe 2 konsumiert
/// Bedieneridentitaet, sie stellt sie nicht aus" unwahr.
pub struct OperatorProfileRepository {
    database: Arc<EncryptedDatabase>,
}

impl OperatorProfileRepository {
    #[must_use]
    pub const fn new(database: Arc<EncryptedDatabase>) -> Self {
        Self { database }
    }

    /// Liest die Profilzeile, falls eine liegt.
    ///
    /// # Errors
    ///
    /// [`DraftError::Payload`], wenn die Zeile nicht die eingefrorene Gestalt
    /// hat, sonst [`DraftError::Store`].
    pub fn load(&self) -> Result<Option<OperatorProfile>, DraftError> {
        let row = self.database.query_row(
            "SELECT organization_id, operator_subject_id, display_name, function_label, \
             profile_commitment_salt, operator_binding_object_hash FROM operator_profile \
             WHERE singleton = 0",
            &[] as &[StoreValue],
        )?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(OperatorProfile {
            organization_id: OrganizationId::try_from(row.blob(0)?)
                .map_err(|_| DraftError::Payload)?,
            operator_subject_id: OperatorSubjectId::try_from(row.blob(1)?)
                .map_err(|_| DraftError::Payload)?,
            display_name: row.text(2)?.to_owned(),
            function_label: row.text(3)?.to_owned(),
            profile_commitment_salt: row.blob(4)?.try_into().map_err(|_| DraftError::Payload)?,
            operator_binding_object_hash: ObjectHash::try_from(row.blob(5)?)
                .map_err(|_| DraftError::Payload)?,
        }))
    }
}
