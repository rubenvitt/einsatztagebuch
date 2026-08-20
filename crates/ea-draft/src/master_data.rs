//! Die Stammdaten des Writers und die AUFBEWAHRUNG des Protokollurbilds.
//!
//! Drei Zusagen tragen dieses Modul:
//!
//! 1. **Eine erfasste Momentaufnahme ist ein eigener Wert.** [`PersonnelSnapshotV1`]
//!    und [`VehicleSnapshotV1`] besitzen ihre Zeichenketten; eine spaetere
//!    Stammdatenaenderung kann eine schon erfasste Momentaufnahme nicht mehr
//!    beruehren, weil es keinen Weg von der Momentaufnahme zurueck zur Zeile
//!    gibt.
//! 2. **Die Revision kommt aus der Tabelle und nie aus der Datei.** Die beiden
//!    eingefrorenen Kopfzeilen tragen keine Revisionsspalte
//!    (`schemas/reports/v1/import-report.cddl`), also KANN der Wert nicht aus
//!    dem CSV kommen. Ein gebuchter Import setzt `1`, jede Aenderung erhoeht um
//!    genau eins, und der Wire-Arm ist stets `[0, revisionNumber]`
//!    (`schemas/payload/v1/payload.cddl`:121-123) — also
//!    [`MasterDataRevisionV1::RevisionNumber`]. [`MasterDataRevisionV1::ChangedAt`]
//!    erscheint in einer Writer-Momentaufnahme nie.
//! 3. **Ein Hash ohne Urbild entsteht nicht.** Die exakten
//!    `import-report-v1`-Bytes liegen in der verschluesselten Datenbank, und
//!    der Fremdschluessel von `master_person` und `master_vehicle` auf
//!    `import_report` macht daraus eine SCHEMAZUSAGE: eine Stammdatenzeile
//!    kann keinen Protokollhash nennen, dessen Urbild nicht aufbewahrt ist.
//!
//! Ad-hoc-Eintraege legen KEINE Zeile an. Sie sind strukturell erkennbar und
//! nicht durch ein Kennzeichen: [`PersonnelSnapshotV1::revision`] und
//! [`PersonnelSnapshotV1::imported_provenance`] melden fuer sie beide `None`
//! (`crates/ea-schema/src/model.rs`:924-928, :931-937).

use core::fmt;
use std::sync::Arc;

use ea_format::ImportReportV1;
use ea_local_store::{EncryptedDatabase, StoreError, StoreValue, unix_millis_now};
use ea_schema::{
    ImportedProvenanceV1, MasterDataRevisionV1, PersonnelSnapshotV1, VehicleSnapshotV1,
};
use ea_types::ObjectHash;

/// Ein Fehlschlag an der Stammdatengrenze.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum MasterDataError {
    /// Diese Stammdatenkennung gibt es nicht.
    ///
    /// Eine BENANNTE Abwesenheit und keine leere Momentaufnahme: „diese Person
    /// ist nicht erfasst" ist eine andere Aussage als „diese Person hat keinen
    /// Namen".
    UnknownMasterId,
    /// Die Zeile hat die geschlossene Stufe-1-Vereinigung nicht erfuellt.
    ///
    /// Sie kommt aus [`ea_schema::SchemaError`] und wird ABGEFLACHT: die
    /// Stufe-1-Fehlermenge ist nicht `Copy`, und eine Stammdatenzeile, die die
    /// eingefrorene Gestalt verletzt, hat genau einen Grund — sie ist
    /// unbrauchbar.
    Snapshot,
    /// Die Revisionsspalte laesst sich nicht mehr erhoehen.
    RevisionOverflow,
    /// Die Ablage hat abgelehnt.
    Store(StoreError),
}

impl MasterDataError {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn und nie gegen eine
    /// Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownMasterId => "EA-MASTER-UNKNOWN-ID",
            Self::Snapshot => "EA-MASTER-SNAPSHOT",
            Self::RevisionOverflow => "EA-MASTER-REVISION-OVERFLOW",
            Self::Store(error) => error.code(),
        }
    }
}

impl fmt::Display for MasterDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for MasterDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for MasterDataError {}

impl From<StoreError> for MasterDataError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// Eine Personenzeile, wie ein gebuchter Import sie anlegt.
///
/// `pub(crate)` und nicht oeffentlich: sie ist die Naht zwischen Importeur und
/// Ablage innerhalb dieser Crate und keine Flaeche, an der ein Aufrufer eine
/// Stammdatenzeile ohne Import anlegen koennte.
pub(crate) struct ImportedPersonRowV1 {
    pub master_personnel_id: String,
    pub display_name: String,
    pub role_or_function: Option<String>,
    pub active: bool,
}

/// Eine Fahrzeugzeile, wie ein gebuchter Import sie anlegt.
pub(crate) struct ImportedVehicleRowV1 {
    pub master_vehicle_id: String,
    pub display_name: String,
    pub radio_call_sign: Option<String>,
    pub license_plate: Option<String>,
    pub active: bool,
}

/// Die angenommenen Zeilen EINES Imports — beide Arme der geschlossenen
/// Quellart.
pub(crate) enum ImportedRowsV1 {
    Persons(Vec<ImportedPersonRowV1>),
    Vehicles(Vec<ImportedVehicleRowV1>),
}

/// Die Stammdatenablage.
pub struct MasterDataRepository {
    database: Arc<EncryptedDatabase>,
}

impl MasterDataRepository {
    #[must_use]
    pub const fn new(database: Arc<EncryptedDatabase>) -> Self {
        Self { database }
    }

    /// Die Zahl der Personenstammdatenzeilen.
    ///
    /// # Errors
    ///
    /// [`MasterDataError::Store`], wenn die Ablage ablehnt.
    pub fn person_count(&self) -> Result<u64, MasterDataError> {
        self.count("SELECT count(*) FROM master_person")
    }

    /// Die Zahl der Fahrzeugstammdatenzeilen.
    ///
    /// # Errors
    ///
    /// [`MasterDataError::Store`], wenn die Ablage ablehnt.
    pub fn vehicle_count(&self) -> Result<u64, MasterDataError> {
        self.count("SELECT count(*) FROM master_vehicle")
    }

    fn count(&self, sql: &str) -> Result<u64, MasterDataError> {
        let row = self
            .database
            .query_row(sql, &[] as &[StoreValue])?
            .ok_or(MasterDataError::Store(StoreError::Shape))?;
        u64::try_from(row.integer(0)?).map_err(|_| MasterDataError::Store(StoreError::Shape))
    }

    /// Erfasst die Momentaufnahme EINER Person.
    ///
    /// Der zurueckgegebene Wert besitzt seine Zeichenketten. Eine spaetere
    /// Aenderung an der Stammdatenzeile beruehrt ihn nicht mehr — genau das ist
    /// die Zusage, die ein Eintrag im Einsatztagebuch braucht.
    ///
    /// # Errors
    ///
    /// [`MasterDataError::UnknownMasterId`], wenn es die Zeile nicht gibt;
    /// [`MasterDataError::Snapshot`], wenn die Zeile die eingefrorene Gestalt
    /// verletzt; sonst [`MasterDataError::Store`].
    pub fn snapshot_person(
        &self,
        master_personnel_id: &str,
    ) -> Result<PersonnelSnapshotV1, MasterDataError> {
        let row = self
            .database
            .query_row(
                "SELECT display_name, role_or_function, revision, source_id, \
                 source_format_version, import_protocol_hash FROM master_person \
                 WHERE master_personnel_id = ?1",
                &[StoreValue::Text(master_personnel_id.to_owned())],
            )?
            .ok_or(MasterDataError::UnknownMasterId)?;
        let display_name = row.text(0)?.to_owned();
        let role_or_function = optional_text(&row, 1)?;
        let revision = revision_of(&row, 2)?;
        let provenance = provenance_of(&row, 3, 4, 5)?;
        PersonnelSnapshotV1::master(
            master_personnel_id,
            display_name,
            role_or_function,
            revision,
            Some(provenance),
        )
        .map_err(|_| MasterDataError::Snapshot)
    }

    /// Erfasst die Momentaufnahme EINES Fahrzeugs.
    ///
    /// # Errors
    ///
    /// Wie [`Self::snapshot_person`].
    pub fn snapshot_vehicle(
        &self,
        master_vehicle_id: &str,
    ) -> Result<VehicleSnapshotV1, MasterDataError> {
        let row = self
            .database
            .query_row(
                "SELECT display_name, radio_call_sign, license_plate, revision, source_id, \
                 source_format_version, import_protocol_hash FROM master_vehicle \
                 WHERE master_vehicle_id = ?1",
                &[StoreValue::Text(master_vehicle_id.to_owned())],
            )?
            .ok_or(MasterDataError::UnknownMasterId)?;
        let display_name = row.text(0)?.to_owned();
        let radio_call_sign = optional_text(&row, 1)?;
        let license_plate = optional_text(&row, 2)?;
        let revision = revision_of(&row, 3)?;
        let provenance = provenance_of(&row, 4, 5, 6)?;
        VehicleSnapshotV1::master(
            master_vehicle_id,
            display_name,
            radio_call_sign,
            license_plate,
            revision,
            Some(provenance),
        )
        .map_err(|_| MasterDataError::Snapshot)
    }

    /// Ein Ad-hoc-Eintrag: KEINE Stammdatenzeile, keine Revision, keine
    /// Provenienz.
    ///
    /// # Errors
    ///
    /// [`MasterDataError::Snapshot`], wenn die Gestalt verletzt ist.
    pub fn ad_hoc_person(
        &self,
        display_name: &str,
        role_or_function: Option<&str>,
    ) -> Result<PersonnelSnapshotV1, MasterDataError> {
        PersonnelSnapshotV1::ad_hoc(display_name, role_or_function.map(str::to_owned))
            .map_err(|_| MasterDataError::Snapshot)
    }

    /// Ein Ad-hoc-Fahrzeug: KEINE Stammdatenzeile.
    ///
    /// # Errors
    ///
    /// [`MasterDataError::Snapshot`], wenn die Gestalt verletzt ist.
    pub fn ad_hoc_vehicle(
        &self,
        display_name: &str,
        radio_call_sign: Option<&str>,
        license_plate: Option<&str>,
    ) -> Result<VehicleSnapshotV1, MasterDataError> {
        VehicleSnapshotV1::ad_hoc(
            display_name,
            radio_call_sign.map(str::to_owned),
            license_plate.map(str::to_owned),
        )
        .map_err(|_| MasterDataError::Snapshot)
    }

    /// Aendert den Anzeigenamen einer Person und ERHOEHT die Revision um eins.
    ///
    /// Gibt die neue Revision zurueck. Aenderung und Erhoehung liegen in EINER
    /// Anweisung: eine getrennte Erhoehung koennte ausbleiben und liesse zwei
    /// verschiedene Namen unter derselben Revision zurueck.
    ///
    /// # Errors
    ///
    /// [`MasterDataError::UnknownMasterId`], wenn es die Zeile nicht gibt;
    /// sonst [`MasterDataError::Store`].
    pub fn rename_person(
        &self,
        master_personnel_id: &str,
        display_name: &str,
    ) -> Result<u64, MasterDataError> {
        self.rename(
            "UPDATE master_person SET display_name = ?1, revision = revision + 1, \
             updated_at_ms = ?2 WHERE master_personnel_id = ?3",
            "SELECT revision FROM master_person WHERE master_personnel_id = ?1",
            master_personnel_id,
            display_name,
        )
    }

    /// Aendert den Anzeigenamen eines Fahrzeugs und ERHOEHT die Revision.
    ///
    /// # Errors
    ///
    /// Wie [`Self::rename_person`].
    pub fn rename_vehicle(
        &self,
        master_vehicle_id: &str,
        display_name: &str,
    ) -> Result<u64, MasterDataError> {
        self.rename(
            "UPDATE master_vehicle SET display_name = ?1, revision = revision + 1, \
             updated_at_ms = ?2 WHERE master_vehicle_id = ?3",
            "SELECT revision FROM master_vehicle WHERE master_vehicle_id = ?1",
            master_vehicle_id,
            display_name,
        )
    }

    fn rename(
        &self,
        update: &str,
        select: &str,
        master_id: &str,
        display_name: &str,
    ) -> Result<u64, MasterDataError> {
        self.database.transaction(|transaction| {
            let changed = transaction.execute(
                update,
                &[
                    StoreValue::Text(display_name.to_owned()),
                    StoreValue::Integer(unix_millis_now()),
                    StoreValue::Text(master_id.to_owned()),
                ],
            )?;
            if changed == 0 {
                return Err(MasterDataError::UnknownMasterId);
            }
            let row = transaction
                .query_row(select, &[StoreValue::Text(master_id.to_owned())])?
                .ok_or(MasterDataError::UnknownMasterId)?;
            u64::try_from(row.integer(0)?).map_err(|_| MasterDataError::RevisionOverflow)
        })
    }

    /// Bucht EINEN Import: das Urbild und alle angenommenen Zeilen in EINER
    /// Transaktion.
    ///
    /// Die exakten Bytes werden AUFBEWAHRT und nie neu kodiert. Genau daran
    /// haengt die Provenienzzusage: eine zweite Kodierung traege eine andere
    /// `imported-at`-Zeit, und der in der Momentaufnahme versiegelte Hash haette
    /// dann kein Urbild mehr.
    ///
    /// Das Urbild wird ZUERST eingefuegt, weil die Stammdatentabellen einen
    /// Fremdschluessel darauf tragen. Scheitert irgendeine Zeile — etwa an einer
    /// schon vergebenen Stammdatenkennung —, rollt die ganze Transaktion
    /// zurueck und es steht keine einzige neue Zeile.
    ///
    /// # Errors
    ///
    /// [`MasterDataError::Store`] bei jeder Ablehnung der Ablage, darunter
    /// [`StoreError::Constraint`] fuer eine schon vergebene Kennung oder ein
    /// schon gebuchtes Urbild.
    pub(crate) fn commit_import(
        &self,
        report: &ImportReportV1,
        rows: &ImportedRowsV1,
    ) -> Result<(), MasterDataError> {
        let hash = report.import_protocol_hash().as_bytes().to_vec();
        let now = unix_millis_now();
        self.database.transaction(|transaction| {
            transaction.execute(
                "INSERT INTO import_report \
                 (import_protocol_hash, exact_bytes, source_kind, imported_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    StoreValue::Blob(hash.clone()),
                    StoreValue::Blob(report.exact_bytes().to_vec()),
                    StoreValue::Integer(i64::from(report.source_kind().code())),
                    StoreValue::Integer(report.imported_at()),
                ],
            )?;
            match rows {
                ImportedRowsV1::Persons(persons) => {
                    for person in persons {
                        transaction.execute(
                            "INSERT INTO master_person \
                             (master_personnel_id, display_name, role_or_function, revision, \
                              active, source_id, source_format_version, import_protocol_hash, \
                              updated_at_ms) \
                             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8)",
                            &[
                                StoreValue::Text(person.master_personnel_id.clone()),
                                StoreValue::Text(person.display_name.clone()),
                                optional_value(person.role_or_function.as_deref()),
                                StoreValue::Integer(i64::from(person.active)),
                                StoreValue::Text(report.source_id().to_owned()),
                                integer_or_shape(report.source_format_version())?,
                                StoreValue::Blob(hash.clone()),
                                StoreValue::Integer(now),
                            ],
                        )?;
                    }
                }
                ImportedRowsV1::Vehicles(vehicles) => {
                    for vehicle in vehicles {
                        transaction.execute(
                            "INSERT INTO master_vehicle \
                             (master_vehicle_id, display_name, radio_call_sign, license_plate, \
                              revision, active, source_id, source_format_version, \
                              import_protocol_hash, updated_at_ms) \
                             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9)",
                            &[
                                StoreValue::Text(vehicle.master_vehicle_id.clone()),
                                StoreValue::Text(vehicle.display_name.clone()),
                                optional_value(vehicle.radio_call_sign.as_deref()),
                                optional_value(vehicle.license_plate.as_deref()),
                                StoreValue::Integer(i64::from(vehicle.active)),
                                StoreValue::Text(report.source_id().to_owned()),
                                integer_or_shape(report.source_format_version())?,
                                StoreValue::Blob(hash.clone()),
                                StoreValue::Integer(now),
                            ],
                        )?;
                    }
                }
            }
            Ok(())
        })
    }

    /// Die AUFBEWAHRTEN exakten `import-report-v1`-Bytes zu einem Hash.
    ///
    /// Der EINZIGE Lesepfad auf das Urbild. `Ok(None)` heisst „zu diesem Hash
    /// ist nichts aufbewahrt" und ist eine Aussage, kein Fehlschlag.
    ///
    /// # Errors
    ///
    /// [`MasterDataError::Store`], wenn die Ablage ablehnt.
    pub fn import_report_bytes(
        &self,
        import_protocol_hash: &ObjectHash,
    ) -> Result<Option<Vec<u8>>, MasterDataError> {
        let row = self.database.query_row(
            "SELECT exact_bytes FROM import_report WHERE import_protocol_hash = ?1",
            &[StoreValue::Blob(import_protocol_hash.as_bytes().to_vec())],
        )?;
        match row {
            Some(row) => Ok(Some(row.blob(0)?.to_vec())),
            None => Ok(None),
        }
    }
}

fn optional_text(
    row: &ea_local_store::StoreRow,
    index: usize,
) -> Result<Option<String>, StoreError> {
    match row.text(index) {
        Ok(value) => Ok(Some(value.to_owned())),
        Err(StoreError::Shape) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Der Revisionsarm der Momentaufnahme.
///
/// AUSSCHLIESSLICH [`MasterDataRevisionV1::RevisionNumber`]: der Wire-Arm ist
/// `[0, revisionNumber]` (`schemas/payload/v1/payload.cddl`:121-123), und
/// `ChangedAt` waere dieselbe Position mit anderem Sinn.
fn revision_of(
    row: &ea_local_store::StoreRow,
    index: usize,
) -> Result<MasterDataRevisionV1, MasterDataError> {
    let value = u64::try_from(row.integer(index)?)
        .map_err(|_| MasterDataError::Store(StoreError::Shape))?;
    Ok(MasterDataRevisionV1::RevisionNumber(value))
}

fn provenance_of(
    row: &ea_local_store::StoreRow,
    source_id: usize,
    source_format_version: usize,
    import_protocol_hash: usize,
) -> Result<ImportedProvenanceV1, MasterDataError> {
    let hash = ObjectHash::try_from(row.blob(import_protocol_hash)?)
        .map_err(|_| MasterDataError::Store(StoreError::Shape))?;
    let version = u64::try_from(row.integer(source_format_version)?)
        .map_err(|_| MasterDataError::Store(StoreError::Shape))?;
    ImportedProvenanceV1::new(row.text(source_id)?, version, hash)
        .map_err(|_| MasterDataError::Snapshot)
}

fn optional_value(value: Option<&str>) -> StoreValue {
    match value {
        Some(value) => StoreValue::Text(value.to_owned()),
        None => StoreValue::Null,
    }
}

fn integer_or_shape(value: u64) -> Result<StoreValue, MasterDataError> {
    i64::try_from(value)
        .map(StoreValue::Integer)
        .map_err(|_| MasterDataError::Store(StoreError::Shape))
}
