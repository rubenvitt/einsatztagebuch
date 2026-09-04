//! Die Beschriftung einer Indexzeile mit Quell- UND Zielschema.
//!
//! Diese Ansicht LIEST die vier Beschriftungsspalten, die `crates/ea-reader`
//! innerhalb seiner Klartextausleihe aus `SchemaRegistry::derive_view` und
//! dessen `DerivedView` eingetragen hat. Sie leitet keine ab: die Ableitung
//! braucht die exakten Nutzlastbytes, und die betreten diese Crate nicht. Was
//! sie tut, ist ein Zielschema ABWEISEN, das diese Fassung nicht projizieren
//! kann.

use core::fmt;

use ea_schema::{SCHEMA_VERSION_V1, SchemaError, SchemaRegistry};

use crate::{IndexError, inverted::IndexableRecordV1, inverted::normalize_display};

/// Das EINE Zielschema, das diese Stufe projiziert.
///
/// Die fachliche Indexzeile ist der Einsatz. Nachtragsreferenzen und die
/// Original/Nachtrag-Projektion sind die naechste Aufgabe dieser Stufe und
/// nicht diese; bis dahin wird ein Nachtrag ISOLIERT statt halb projiziert.
const PROJECTED_TARGET_SCHEMA_ID_V1: &str = "ea.incident";

/// Die geprueften Beschriftungen EINER Zeile.
///
/// Sie traegt die BESCHRIFTUNG und die abgeleiteten Werte, nie die exakten
/// Nutzlastbytes.
pub struct SchemaViewV1 {
    source_schema_id: &'static str,
    source_schema_version: u64,
    target_schema_id: &'static str,
    target_schema_version: u64,
    human_incident_number: String,
}

impl SchemaViewV1 {
    /// Prueft beide Beschriftungen eines Datensatzes.
    ///
    /// Das QUELLSCHEMA muss eine der Kennungen sein, die
    /// `SchemaRegistry::v1().schemas()` fuehrt — die Registrierung ist die
    /// einzige Quelle dieser Menge, und eine zweite Liste hier waere eine
    /// zweite Wahrheit ueber dieselben fuenf Kennungen. Das ZIELSCHEMA muss
    /// zusaetzlich projizierbar sein.
    ///
    /// Die zurueckgegebenen Kennungen sind die STATISCHEN der Registrierung und
    /// nicht die uebergebenen Zeichenketten: damit traegt jede Indexzeile eine
    /// Kennung aus der Registrierung, und der versiegelte Koerper kann keine
    /// Kennung tragen, die es nicht gibt.
    ///
    /// # Errors
    /// `EA-SCHEMA-UNSUPPORTED` fuer eine unbekannte Quelle und fuer ein
    /// Zielschema, das diese Fassung nicht projiziert. Beide Male nennt der
    /// Fehler die ABGEWIESENE Kennung samt Fassung.
    pub fn derive(record: &IndexableRecordV1) -> Result<Self, IndexError> {
        let source_schema_id =
            registered_schema_id(&record.source_schema_id, record.source_schema_version)?;
        let target_schema_id =
            registered_schema_id(&record.target_schema_id, record.target_schema_version)?;
        if target_schema_id != PROJECTED_TARGET_SCHEMA_ID_V1 {
            return Err(IndexError::Schema(SchemaError::Unsupported {
                schema_id: target_schema_id.to_owned(),
                schema_version: record.target_schema_version,
            }));
        }
        Ok(Self {
            source_schema_id,
            source_schema_version: record.source_schema_version,
            target_schema_id,
            target_schema_version: record.target_schema_version,
            human_incident_number: normalize_display(&record.human_incident_number),
        })
    }

    /// Quellschema und -fassung.
    #[must_use]
    pub const fn source_schema(&self) -> (&'static str, u64) {
        (self.source_schema_id, self.source_schema_version)
    }

    /// Zielschema und -fassung.
    #[must_use]
    pub const fn target_schema(&self) -> (&'static str, u64) {
        (self.target_schema_id, self.target_schema_version)
    }

    /// Die menschliche Einsatznummer, in ihrer Anzeigeform.
    #[must_use]
    pub fn human_incident_number(&self) -> &str {
        &self.human_incident_number
    }
}

/// Kein abgeleitetes `Debug`: die Einsatznummer ist ein aus entschluesseltem
/// Inhalt abgeleiteter Wert. Ausgewiesen werden die beiden BESCHRIFTUNGEN, die
/// aus der Registrierung stammen und nichts ueber den Einsatz sagen.
impl fmt::Debug for SchemaViewV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SchemaViewV1 {{ source: {}/{}, target: {}/{}, human_incident_number: <redacted> }}",
            self.source_schema_id,
            self.source_schema_version,
            self.target_schema_id,
            self.target_schema_version
        )
    }
}

/// Die statische Kennung der Registrierung, oder die Weigerung.
fn registered_schema_id(schema_id: &str, schema_version: u64) -> Result<&'static str, IndexError> {
    SchemaRegistry::v1()
        .schemas()
        .iter()
        .find(|descriptor| {
            descriptor.schema_id() == schema_id && schema_version == SCHEMA_VERSION_V1
        })
        .map(|descriptor| descriptor.schema_id())
        .ok_or_else(|| {
            IndexError::Schema(SchemaError::Unsupported {
                schema_id: schema_id.to_owned(),
                schema_version,
            })
        })
}
