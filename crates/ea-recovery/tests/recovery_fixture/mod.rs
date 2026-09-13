use crate::support;

pub fn recovery_payload(
    version: ea_types::RegistryVersion,
    binding: ea_types::ObjectHash,
) -> Vec<u8> {
    use ea_schema::*;
    use ea_types::*;
    let mut id = [1; 16];
    id[6] = 0x70;
    id[8] = 0x80;
    let header = CommonHeaderV1::new(
        RecordId::try_from(id.as_slice()).unwrap(),
        UnixMillis::new(0),
        "Europe/Berlin",
        OperatorSnapshotV1::new(
            support::verify_support::archive_support::trust_support::organization(),
            OperatorSubjectId::try_from(&[0x20; 16][..]).unwrap(),
            "Erika Beispiel",
            "Einsatzleitung",
            [0x30; 32],
            binding,
        )
        .unwrap(),
        NativeSourceV1::new("recovery-fixture", 1).unwrap(),
        version,
    )
    .unwrap();
    encode_payload(&PayloadV1::Incident(
        IncidentV1::new(
            header,
            "1970-0001",
            OccurredAtV1::new(UnixMillis::new(0), None).unwrap(),
            KeywordV1::free_text("T9 secret sample").unwrap(),
            LocationV1::free_text("T9 private location", None).unwrap(),
            vec![],
            Some("Keine Kräfte".into()),
            vec![],
            Some("Keine Fahrzeuge".into()),
            PatientCount::Unknown,
            None,
            vec![],
        )
        .unwrap(),
    ))
    .unwrap()
}
