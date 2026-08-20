//! Die Eingabe der Finalisierung: der fachliche Entwurfsinhalt.
//!
//! Sie kommt vom AUFRUFER und nicht aus [`ea_draft::DraftRepository`]:
//! [`ea_draft::Draft`] haelt die Autospeicherung der Oberflaeche und nicht die
//! vollstaendige Nutzlast, und die geschlossenen Momentaufnahmetypen liegen in
//! `ea-schema`. Der Writer KONSUMIERT sie und deklariert keinen zweiten
//! Nutzlasttyp.
//!
//! Was hier NICHT steht, ist der Kopf. `recordId`, `finalizedAtDevice`, der
//! `operator`-Snapshot und die `registryVersion` entstehen in Schritt 4 aus der
//! verifizierten Sitzung, der NUR LESEND geoeffneten Profilzeile und dem
//! gebundenen Head — nie aus einer Eingabe. Waeren sie hier, koennte ein
//! Aufrufer einen fremden Bediener in den signierten Kopf schreiben.

use ea_schema::{
    ExternalOrganizationV1, KeywordV1, LocationV1, NativeSourceV1, OccurredAtV1, PatientCount,
    PersonnelSnapshotV1, VehicleSnapshotV1,
};

/// Der fachliche Inhalt eines abzuschliessenden Einsatzes.
pub struct FinalizationInputV1 {
    /// Die Geraetezeitzone, kanonisiert gegen die gepinnte tzdb. `ea-schema`
    /// prueft sie in `CommonHeaderV1::new`, und daraus leitet
    /// `IncidentV1::incident_uniqueness_key` das oertliche Kalenderjahr ab —
    /// diese Crate rechnet keine Zeitzone selbst und traegt deshalb keine
    /// `jiff`-Kante.
    pub timezone: String,
    pub source: NativeSourceV1,
    pub human_incident_number: String,
    pub occurred_at: OccurredAtV1,
    pub keyword: KeywordV1,
    pub location: LocationV1,
    pub personnel: Vec<PersonnelSnapshotV1>,
    pub personnel_empty_reason: Option<String>,
    pub vehicles: Vec<VehicleSnapshotV1>,
    pub vehicles_empty_reason: Option<String>,
    pub patient_count: PatientCount,
    pub notes: Option<String>,
    pub external_organizations: Vec<ExternalOrganizationV1>,
}
