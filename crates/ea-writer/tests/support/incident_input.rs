//! Pure Incident input shared without importing a Writer/Trust harness.
use ea_schema::{
    KeywordV1, LocationV1, NativeSourceV1, OccurredAtV1, PatientCount, StructuredAddressV1,
};
use ea_types::UnixMillis;
use ea_writer::FinalizationInputV1;

/// The unchanged incident number used by the Writer fixture.
pub const FIXTURE_INCIDENT_NUMBER: &str = "2026-000042";

/// Build the existing valid Incident with explicit number and occurrence time.
#[must_use]
pub fn incident_numbered_at(number: &str, occurred_at: UnixMillis) -> FinalizationInputV1 {
    FinalizationInputV1 {
        timezone: "Europe/Berlin".to_owned(),
        source: NativeSourceV1::new("ea.writer.fixture", 1)
            .expect("die Quelle der Fixture ist gueltig"),
        human_incident_number: number.to_owned(),
        occurred_at: OccurredAtV1::new(occurred_at, None)
            .expect("das Intervall der Fixture ist gueltig"),
        keyword: KeywordV1::free_text("Verkehrsunfall")
            .expect("das Stichwort der Fixture ist gueltig"),
        location: LocationV1::structured(
            StructuredAddressV1::new(
                Some("Hauptstrasse".to_owned()),
                Some("1".to_owned()),
                Some("12345".to_owned()),
                Some("Musterstadt".to_owned()),
                None,
                Some("DE".to_owned()),
            )
            .expect("die Adresse der Fixture ist gueltig"),
            None,
        )
        .expect("der Ort der Fixture ist gueltig"),
        personnel: Vec::new(),
        personnel_empty_reason: Some("keine Personalzuordnung erfasst".to_owned()),
        vehicles: Vec::new(),
        vehicles_empty_reason: Some("keine Fahrzeugzuordnung erfasst".to_owned()),
        patient_count: PatientCount::Known(0),
        notes: None,
        external_organizations: Vec::new(),
    }
}
