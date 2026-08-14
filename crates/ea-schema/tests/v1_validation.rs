use ea_schema::{
    AmendmentChangeV1, AmendmentV1, CommonHeaderV1, CoordinatesV1, DestructionEvidenceV1,
    DestructionExecutionResultV1, DestructionStubBindingV1, DestructionTargetV1,
    ExternalOrganizationV1, GenesisV1, IANA_TZDB_VERSION_V1, ImportedProvenanceV1, IncidentV1,
    KeyTransitionV1, KeywordV1, LocationV1, MasterDataRevisionV1, NativeSourceV1, OccurredAtV1,
    OperatorSnapshotV1, PAYLOAD_PLAINTEXT_MAX_BYTES_V1, PatientCount, PayloadV1,
    PersonnelSnapshotV1, ReplicaResultV1, SCHEMA_VERSION_V1, SUITE_ID_V1, SchemaError,
    SchemaRegistry, StructuredAddressV1, VehicleSnapshotV1, encode_payload,
};
use ea_types::{
    ChainId, ChainSequence, DestructionId, EntryHash, Id16, ObjectHash, OperatorSubjectId,
    OrganizationId, RecordId, RegistryVersion, UnixMillis,
};

#[test]
fn public_v1_contract_is_available() {
    let _registry = SchemaRegistry::v1();
    let _encoder: fn(&PayloadV1) -> _ = encode_payload;
    assert_eq!(PAYLOAD_PLAINTEXT_MAX_BYTES_V1, 1_048_576);
    assert_eq!(SCHEMA_VERSION_V1, 1);
    assert_eq!(SUITE_ID_V1, "EINSATZARCHIV-SUITE-1");
    assert_eq!(IANA_TZDB_VERSION_V1, "2026c");
}

#[test]
fn unsupported_and_oversized_inputs_fail_before_payload_parsing() {
    let registry = SchemaRegistry::v1();
    assert!(matches!(
        registry.validate("ea.incident", 99, b"not cbor"),
        Err(SchemaError::Unsupported { .. })
    ));
    let oversized = vec![0xff; PAYLOAD_PLAINTEXT_MAX_BYTES_V1 + 1];
    for (schema_id, schema_version) in [("ea.unknown", 1), ("ea.incident", 99)] {
        assert!(matches!(
            registry.validate(schema_id, schema_version, &oversized),
            Err(SchemaError::Unsupported { .. })
        ));
    }
    let error = registry.validate("ea.incident", 1, &oversized).unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-PLAINTEXT-LIMIT");
}

#[test]
fn common_header_and_exact_one_item_contract_fail_closed() {
    let registry = SchemaRegistry::v1();
    let exact =
        hex::decode(include_str!("../../../vectors/format/payload-v1/genesis.hex").trim_end())
            .unwrap();

    let mut trailing = exact.clone();
    trailing.push(0xf6);
    assert_eq!(
        registry
            .validate("ea.genesis", 1, &trailing)
            .unwrap_err()
            .code(),
        "EA-CBOR-TRAILING"
    );

    let mut wrong_uuid_version = exact.clone();
    wrong_uuid_version[16] = 0x60;
    let error = registry
        .validate("ea.genesis", 1, &wrong_uuid_version)
        .unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-UUID-V7");
    assert_eq!(error.field(), Some("recordId"));

    let mut wrong_family = exact.clone();
    let record_type = wrong_family
        .windows(b"genesis".len())
        .position(|window| window == b"genesis")
        .unwrap();
    wrong_family[record_type..record_type + 7].copy_from_slice(b"inciden");
    let error = registry
        .validate("ea.genesis", 1, &wrong_family)
        .unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-RECORD-TYPE");

    let schema_id = exact
        .windows(b"ea.genesis".len())
        .position(|window| window == b"ea.genesis")
        .unwrap();
    let mut wrong_schema_id = exact.clone();
    wrong_schema_id[schema_id + b"ea.genesis".len() - 1] = b'x';
    let error = registry
        .validate("ea.genesis", 1, &wrong_schema_id)
        .unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-SCHEMA-ID");

    let mut wrong_internal_version = exact.clone();
    wrong_internal_version[schema_id + b"ea.genesis".len()] = 2;
    let error = registry
        .validate("ea.genesis", 1, &wrong_internal_version)
        .unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-SCHEMA-VERSION");

    let mut timezone_case_variant = exact.clone();
    let timezone = timezone_case_variant
        .windows(b"Europe/Berlin".len())
        .position(|window| window == b"Europe/Berlin")
        .unwrap();
    timezone_case_variant[timezone] = b'e';
    let error = registry
        .validate("ea.genesis", 1, &timezone_case_variant)
        .unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-TIMEZONE-CANONICAL");
    assert_eq!(error.field(), Some("timezone"));

    let mut alternate_source_tag = exact.clone();
    let source = alternate_source_tag
        .windows(b"writer-native".len())
        .position(|window| window == b"writer-native")
        .unwrap();
    alternate_source_tag[source - 2] = 1;
    let error = registry
        .validate("ea.genesis", 1, &alternate_source_tag)
        .unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-SOURCE-TAG");

    let mut unknown_extension = exact.clone();
    let extension = unknown_extension
        .windows(3)
        .position(|window| window == [0x07, 0x80, 0x86])
        .unwrap()
        + 1;
    unknown_extension.splice(extension..=extension, [0x81, 0x00]);
    let error = registry
        .validate("ea.genesis", 1, &unknown_extension)
        .unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-UNKNOWN-CRITICAL-EXTENSION");
}

#[test]
fn textual_legacy_source_kinds_have_the_stable_legacy_error() {
    let registry = SchemaRegistry::v1();
    for kind in ["legacyImport", "legacy-access-import"] {
        let exact = genesis_wire_with_text_source_kind(kind);
        let error = registry.validate("ea.genesis", 1, &exact).unwrap_err();
        assert_eq!(error.code(), "EA-SCHEMA-LEGACY-SOURCE", "kind {kind}");
        assert_eq!(error.field(), Some("source.kind"), "kind {kind}");
    }
}

#[test]
fn every_other_non_native_source_kind_has_the_stable_source_tag_error() {
    let registry = SchemaRegistry::v1();
    let mut numeric = genesis_vector();
    let source_id = numeric
        .windows(b"writer-native".len())
        .position(|window| window == b"writer-native")
        .unwrap();
    numeric[source_id - 2] = 1;
    let mut negative = genesis_vector();
    negative[source_id - 2] = 0x20;
    for exact in [
        numeric,
        negative,
        genesis_wire_with_text_source_kind("alternate"),
    ] {
        let error = registry.validate("ea.genesis", 1, &exact).unwrap_err();
        assert_eq!(error.code(), "EA-SCHEMA-SOURCE-TAG");
        assert_eq!(error.field(), Some("source.kind"));
    }
}

#[test]
fn native_source_id_does_not_reserve_legacy_kind_spellings() {
    let exact = genesis_wire_with_source_id("legacyImport");
    let validated = SchemaRegistry::v1()
        .validate("ea.genesis", 1, &exact)
        .unwrap();
    let PayloadV1::Genesis(genesis) = validated.payload() else {
        panic!("expected Genesis")
    };
    assert_eq!(genesis.header().source().source_id(), "legacyImport");
    assert_eq!(validated.exact_bytes(), exact);
}

#[test]
fn native_empty_source_id_constructor_is_valid() {
    let source = NativeSourceV1::new("", 1).unwrap();
    assert_eq!(source.source_id(), "");
    assert_eq!(source.source_format_version(), 1);
}

#[test]
fn canonical_native_empty_source_id_decodes_and_reencodes() {
    let exact = genesis_wire_with_source_id("");
    let validated = SchemaRegistry::v1()
        .validate("ea.genesis", 1, &exact)
        .unwrap();
    let PayloadV1::Genesis(genesis) = validated.payload() else {
        panic!("expected Genesis")
    };
    assert_eq!(genesis.header().source().source_id(), "");
    assert_eq!(validated.exact_bytes(), exact);
    assert_eq!(encode_payload(validated.payload()).unwrap(), exact);
}

#[test]
fn all_five_literal_vectors_decode_and_reencode_byte_identically() {
    let registry = SchemaRegistry::v1();
    let cases = [
        (
            "ea.genesis",
            "genesis",
            include_str!("../../../vectors/format/payload-v1/genesis.hex"),
        ),
        (
            "ea.incident",
            "incident",
            include_str!("../../../vectors/format/payload-v1/incident.hex"),
        ),
        (
            "ea.amendment",
            "amendment",
            include_str!("../../../vectors/format/payload-v1/amendment.hex"),
        ),
        (
            "ea.key-transition",
            "keyTransition",
            include_str!("../../../vectors/format/payload-v1/key-transition.hex"),
        ),
        (
            "ea.destruction-evidence",
            "destructionEvidence",
            include_str!("../../../vectors/format/payload-v1/destruction-evidence.hex"),
        ),
    ];

    for (schema_id, record_type, source) in cases {
        let exact = hex::decode(source.trim_end()).unwrap();
        let validated = registry.validate(schema_id, 1, &exact).unwrap();
        assert_eq!(validated.payload().schema_id(), schema_id);
        assert_eq!(validated.payload().record_type(), record_type);
        assert_eq!(validated.exact_bytes(), exact);
        assert_eq!(encode_payload(validated.payload()).unwrap(), exact);

        match (schema_id, validated.payload()) {
            ("ea.genesis", PayloadV1::Genesis(_))
            | ("ea.incident", PayloadV1::Incident(_))
            | ("ea.amendment", PayloadV1::Amendment(_))
            | ("ea.key-transition", PayloadV1::KeyTransition(_))
            | ("ea.destruction-evidence", PayloadV1::DestructionEvidence(_)) => {}
            _ => panic!("schema ID decoded to the wrong typed family"),
        }
    }
}

fn genesis_vector() -> Vec<u8> {
    hex::decode(include_str!("../../../vectors/format/payload-v1/genesis.hex").trim_end()).unwrap()
}

fn genesis_wire_with_text_source_kind(kind: &str) -> Vec<u8> {
    assert!(kind.len() < 24);
    let mut exact = genesis_vector();
    let source_id = exact
        .windows(b"writer-native".len())
        .position(|window| window == b"writer-native")
        .unwrap();
    let kind_offset = source_id - 2;
    assert_eq!(exact[kind_offset], 0);
    let mut encoded_kind = vec![0x60 + u8::try_from(kind.len()).unwrap()];
    encoded_kind.extend_from_slice(kind.as_bytes());
    exact.splice(kind_offset..kind_offset + 1, encoded_kind);
    exact
}

fn genesis_wire_with_source_id(source_id: &str) -> Vec<u8> {
    assert!(source_id.len() < 24);
    let mut exact = genesis_vector();
    let original = b"writer-native";
    let value_offset = exact
        .windows(original.len())
        .position(|window| window == original)
        .unwrap();
    let header_offset = value_offset - 1;
    let mut encoded_source_id = vec![0x60 + u8::try_from(source_id.len()).unwrap()];
    encoded_source_id.extend_from_slice(source_id.as_bytes());
    exact.splice(
        header_offset..value_offset + original.len(),
        encoded_source_id,
    );
    exact
}

#[test]
fn freshly_constructed_typed_variants_roundtrip_without_raw_cbor() {
    let organization_id = organization_id(0x10);
    let entry_hash = entry_hash(0x90);
    let payloads = vec![
        PayloadV1::Genesis(
            GenesisV1::new(
                header("Europe/Berlin", 1_700_000_000_000),
                organization_id,
                ChainId::try_from(&[0x11; 16][..]).unwrap(),
                object_hash(0x12),
                1,
                object_hash(0x13),
            )
            .unwrap(),
        ),
        PayloadV1::Incident(
            minimal_incident(
                header("America/New_York", 1_700_000_000_001),
                "2026-0001",
                1_798_763_400_000,
                PatientCount::Known(0),
            )
            .unwrap(),
        ),
        PayloadV1::Amendment(
            AmendmentV1::new(
                header("Europe/Berlin", 1_700_000_000_002),
                "2026-0001",
                record_id(0x21),
                entry_hash,
                ChainSequence::new(7),
                "Lage präzisiert",
                vec![AmendmentChangeV1::new("location", "Hausnummer ergänzt").unwrap()],
            )
            .unwrap(),
        ),
        PayloadV1::KeyTransition(
            KeyTransitionV1::new(
                header("Europe/Berlin", 1_700_000_000_003),
                object_hash(0xa0),
                "Geplanter Writer-Wechsel",
            )
            .unwrap(),
        ),
        PayloadV1::DestructionEvidence(
            DestructionEvidenceV1::new(
                header("Europe/Berlin", 1_700_000_000_004),
                DestructionId::try_from(&[0xb0; 16][..]).unwrap(),
                object_hash(0xb1),
                1,
                vec![DestructionTargetV1::new(entry_hash, ChainSequence::new(7))],
                vec![DestructionExecutionResultV1::new(entry_hash, true, 0)],
                vec![],
                vec![ReplicaResultV1::successful(
                    Id16::try_from(&[1; 16][..]).unwrap(),
                    object_hash(0xd1),
                )],
            )
            .unwrap(),
        ),
    ];

    let registry = SchemaRegistry::v1();
    for payload in payloads {
        let exact = encode_payload(&payload).unwrap();
        let validated = registry
            .validate(payload.schema_id(), SCHEMA_VERSION_V1, &exact)
            .unwrap();
        assert_eq!(validated.exact_bytes(), exact);
        assert_eq!(validated.payload().schema_id(), payload.schema_id());
    }
}

#[test]
fn all_incident_union_constructors_roundtrip_in_authoring_order() {
    let provenance = ImportedProvenanceV1::new("csv-personnel", 1, object_hash(0x81)).unwrap();
    let personnel = vec![
        PersonnelSnapshotV1::master(
            "person-42",
            "Zulu Zugführer",
            Some("Zugführer".to_owned()),
            MasterDataRevisionV1::RevisionNumber(3),
            Some(provenance),
        )
        .unwrap(),
        PersonnelSnapshotV1::ad_hoc("Alpha Unterstützung", None).unwrap(),
    ];
    let vehicles = vec![
        VehicleSnapshotV1::master(
            "vehicle-7",
            "Zulu",
            Some("Florian 1/46-1".to_owned()),
            Some("B-DR 112".to_owned()),
            MasterDataRevisionV1::ChangedAt(UnixMillis::new(1_700_000_000_000)),
            None,
        )
        .unwrap(),
        VehicleSnapshotV1::ad_hoc("Alpha", None, None).unwrap(),
    ];
    let address = StructuredAddressV1::new(
        Some("Hauptstraße".to_owned()),
        Some("7a".to_owned()),
        Some("10115".to_owned()),
        Some("Berlin".to_owned()),
        Some("BE".to_owned()),
        Some("DE".to_owned()),
    )
    .unwrap();
    let incident = IncidentV1::new(
        header("Europe/Berlin", 1_700_000_000_000),
        "2027-42",
        OccurredAtV1::new(UnixMillis::new(1_798_759_800_000), None).unwrap(),
        KeywordV1::reference("brand", "Brand groß").unwrap(),
        LocationV1::structured(
            address,
            Some(CoordinatesV1::new(525_200_000, 134_050_000).unwrap()),
        )
        .unwrap(),
        personnel,
        None,
        vehicles,
        None,
        PatientCount::Known(3),
        Some("Keine Patientendaten.".to_owned()),
        vec![
            ExternalOrganizationV1::new(Some("z-org"), "Zulu Klinik").unwrap(),
            ExternalOrganizationV1::new(None, "Alpha Behörde").unwrap(),
        ],
    )
    .unwrap();
    let payload = PayloadV1::Incident(incident);
    let exact = encode_payload(&payload).unwrap();
    let validated = SchemaRegistry::v1()
        .validate("ea.incident", 1, &exact)
        .unwrap();
    let PayloadV1::Incident(decoded) = validated.payload() else {
        panic!("expected Incident")
    };
    assert_eq!(
        decoded
            .personnel()
            .iter()
            .map(PersonnelSnapshotV1::display_name)
            .collect::<Vec<_>>(),
        ["Zulu Zugführer", "Alpha Unterstützung"]
    );
    assert_eq!(
        decoded
            .vehicles()
            .iter()
            .map(VehicleSnapshotV1::display_name)
            .collect::<Vec<_>>(),
        ["Zulu", "Alpha"]
    );
    assert_eq!(
        decoded
            .external_organizations()
            .iter()
            .map(ExternalOrganizationV1::display_name)
            .collect::<Vec<_>>(),
        ["Zulu Klinik", "Alpha Behörde"]
    );
    assert_eq!(encode_payload(validated.payload()).unwrap(), exact);
}

#[test]
fn incident_semantics_distinguish_counts_and_enforce_local_correlations() {
    for patient_count in [
        PatientCount::Known(0),
        PatientCount::Known(3),
        PatientCount::Unknown,
    ] {
        let incident = minimal_incident(
            header("Europe/Berlin", 1_700_000_000_000),
            "2027-17",
            1_798_759_800_000,
            patient_count,
        )
        .unwrap();
        encode_payload(&PayloadV1::Incident(incident)).unwrap();
    }

    let error = OccurredAtV1::new(UnixMillis::new(10), Some(UnixMillis::new(9))).unwrap_err();
    assert_eq!(error.field(), Some("occurredAt"));

    let error = IncidentV1::new(
        header("Europe/Berlin", 0),
        "17",
        OccurredAtV1::new(UnixMillis::new(10), None).unwrap(),
        KeywordV1::free_text("Brand").unwrap(),
        LocationV1::free_text("Hauptstraße", None).unwrap(),
        vec![],
        None,
        vec![],
        Some("keine".to_owned()),
        PatientCount::Unknown,
        None,
        vec![],
    )
    .err()
    .unwrap();
    assert_eq!(error.field(), Some("personnelEmptyReason"));
}

#[test]
fn incident_uniqueness_key_uses_pinned_timezone_start_and_exact_number_bytes() {
    let new_york = minimal_incident(
        header("America/New_York", 1_900_000_000_000),
        "2027-AbC",
        1_798_763_400_000,
        PatientCount::Unknown,
    )
    .unwrap();
    let berlin = minimal_incident(
        header("Europe/Berlin", 1_600_000_000_000),
        "2027-AbC",
        1_798_759_800_000,
        PatientCount::Unknown,
    )
    .unwrap();
    let new_york_key = new_york.incident_uniqueness_key().unwrap();
    let berlin_key = berlin.incident_uniqueness_key().unwrap();
    assert_eq!(new_york_key.local_civil_year(), 2026);
    assert_eq!(berlin_key.local_civil_year(), 2027);
    assert_eq!(new_york_key.incident_number_nfc_bytes(), b"2027-AbC");
    assert_eq!(berlin_key.incident_number_nfc_bytes(), b"2027-AbC");
    assert_eq!(
        new_york_key.organization_id().as_bytes(),
        organization_id(0x10).as_bytes()
    );

    let changed_finalized_at = minimal_incident(
        header("America/New_York", -9_000_000_000_000),
        "2027-AbC",
        1_798_763_400_000,
        PatientCount::Unknown,
    )
    .unwrap()
    .incident_uniqueness_key()
    .unwrap();
    assert_eq!(changed_finalized_at.local_civil_year(), 2026);
    assert_eq!(
        changed_finalized_at.incident_number_nfc_bytes(),
        new_york_key.incident_number_nfc_bytes()
    );

    let changed_prefix = minimal_incident(
        header("America/New_York", 1_900_000_000_000),
        "1999-AbC",
        1_798_763_400_000,
        PatientCount::Unknown,
    )
    .unwrap()
    .incident_uniqueness_key()
    .unwrap();
    assert_eq!(changed_prefix.local_civil_year(), 2026);
    assert_eq!(changed_prefix.incident_number_nfc_bytes(), b"1999-AbC");
    assert_ne!(
        changed_prefix.incident_number_nfc_bytes(),
        new_york_key.incident_number_nfc_bytes()
    );
}

#[test]
fn incident_constructor_rejects_start_outside_bundled_timezone_range() {
    let error = minimal_incident(
        header("Europe/Berlin", 0),
        "17",
        i64::MAX,
        PatientCount::Unknown,
    )
    .expect_err("an accepted Incident must have a representable local civil year");
    assert_eq!(error.code(), "EA-SCHEMA-TIMESTAMP-RANGE");
    assert_eq!(error.field(), Some("occurredAt.start"));
}

#[test]
fn registry_acceptance_implies_a_total_incident_uniqueness_key() {
    let registry = SchemaRegistry::v1();
    let exact =
        hex::decode(include_str!("../../../vectors/format/payload-v1/incident.hex").trim_end())
            .unwrap();
    let original_start = 1_798_763_400_000_i64.to_be_bytes();
    let positions = exact
        .windows(original_start.len())
        .enumerate()
        .filter_map(|(index, window)| (window == original_start).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(
        positions.len(),
        2,
        "fixture pins finalizedAt and occurredAt.start"
    );

    let accepted = registry.validate("ea.incident", 1, &exact).unwrap();
    let PayloadV1::Incident(accepted) = accepted.payload() else {
        panic!("expected Incident")
    };
    accepted.incident_uniqueness_key().unwrap();

    let mut out_of_range = exact;
    out_of_range[positions[1]..positions[1] + 8].copy_from_slice(&i64::MAX.to_be_bytes());
    let error = registry
        .validate("ea.incident", 1, &out_of_range)
        .unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-TIMESTAMP-RANGE");
    assert_eq!(error.field(), Some("occurredAt.start"));
}

#[test]
fn incident_constructor_boundaries_fail_closed() {
    let error = minimal_incident(
        header("Europe/Berlin", 0),
        &"x".repeat(65),
        1_798_759_800_000,
        PatientCount::Unknown,
    )
    .err()
    .unwrap();
    assert_eq!(error.field(), Some("humanIncidentNumber"));

    assert!(CoordinatesV1::new(900_000_001, 0).is_err());
    assert!(CoordinatesV1::new(0, -1_800_000_001).is_err());
    assert!(StructuredAddressV1::new(None, None, None, None, None, None).is_err());

    let personnel = (0..201)
        .map(|index| PersonnelSnapshotV1::ad_hoc(format!("Kraft {index}"), None).unwrap())
        .collect();
    let error = IncidentV1::new(
        header("Europe/Berlin", 0),
        "17",
        OccurredAtV1::new(UnixMillis::new(10), None).unwrap(),
        KeywordV1::free_text("Brand").unwrap(),
        LocationV1::free_text("Hauptstraße", None).unwrap(),
        personnel,
        None,
        vec![],
        Some("Keine Fahrzeuge".to_owned()),
        PatientCount::Unknown,
        None,
        vec![],
    )
    .err()
    .unwrap();
    assert_eq!(error.field(), Some("personnel"));

    let error = IncidentV1::new(
        header("Europe/Berlin", 0),
        "17",
        OccurredAtV1::new(UnixMillis::new(10), None).unwrap(),
        KeywordV1::free_text("Brand").unwrap(),
        LocationV1::free_text("Hauptstraße", None).unwrap(),
        vec![PersonnelSnapshotV1::ad_hoc("Kraft", None).unwrap()],
        Some("unzulässig".to_owned()),
        vec![],
        Some("Keine Fahrzeuge".to_owned()),
        PatientCount::Unknown,
        None,
        vec![],
    )
    .err()
    .unwrap();
    assert_eq!(error.field(), Some("personnelEmptyReason"));

    let error = IncidentV1::new(
        header("Europe/Berlin", 0),
        "17",
        OccurredAtV1::new(UnixMillis::new(10), None).unwrap(),
        KeywordV1::free_text("Brand").unwrap(),
        LocationV1::free_text("Hauptstraße", None).unwrap(),
        vec![],
        Some("Keine Kräfte".to_owned()),
        vec![],
        Some("Keine Fahrzeuge".to_owned()),
        PatientCount::Unknown,
        Some("x".repeat(20_001)),
        vec![],
    )
    .unwrap_err();
    assert_eq!(error.field(), Some("notes"));

    let external_organizations = (0..101)
        .map(|index| ExternalOrganizationV1::new(None, format!("Organisation {index}")).unwrap())
        .collect();
    let error = IncidentV1::new(
        header("Europe/Berlin", 0),
        "17",
        OccurredAtV1::new(UnixMillis::new(10), None).unwrap(),
        KeywordV1::free_text("Brand").unwrap(),
        LocationV1::free_text("Hauptstraße", None).unwrap(),
        vec![],
        Some("Keine Kräfte".to_owned()),
        vec![],
        Some("Keine Fahrzeuge".to_owned()),
        PatientCount::Unknown,
        None,
        external_organizations,
    )
    .unwrap_err();
    assert_eq!(error.field(), Some("externalOrganizations"));
}

#[test]
fn plaintext_limit_accepts_exact_maximum_and_rejects_one_more() {
    const KEY_TRANSITION_VECTOR_BYTES: usize = 288;
    const ORIGINAL_REASON_WIRE_BYTES: usize = 2 + 24;
    const LARGE_TEXT_HEADER_BYTES: usize = 5;
    const EXACT_REASON_LEN: usize = PAYLOAD_PLAINTEXT_MAX_BYTES_V1 - KEY_TRANSITION_VECTOR_BYTES
        + ORIGINAL_REASON_WIRE_BYTES
        - LARGE_TEXT_HEADER_BYTES;

    let exact_payload = PayloadV1::KeyTransition(
        KeyTransitionV1::new(
            header("Europe/Berlin", 1_700_000_000_000),
            object_hash(0xa0),
            "x".repeat(EXACT_REASON_LEN),
        )
        .unwrap(),
    );
    let exact = encode_payload(&exact_payload).unwrap();
    assert_eq!(exact.len(), PAYLOAD_PLAINTEXT_MAX_BYTES_V1);
    SchemaRegistry::v1()
        .validate("ea.key-transition", 1, &exact)
        .unwrap();

    let over_payload = PayloadV1::KeyTransition(
        KeyTransitionV1::new(
            header("Europe/Berlin", 1_700_000_000_000),
            object_hash(0xa0),
            "x".repeat(EXACT_REASON_LEN + 1),
        )
        .unwrap(),
    );
    let error = encode_payload(&over_payload).unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-PLAINTEXT-LIMIT");
}

#[test]
fn wire_mutations_reject_float_non_nfc_legacy_and_patient_mismatch() {
    let registry = SchemaRegistry::v1();
    let exact =
        hex::decode(include_str!("../../../vectors/format/payload-v1/incident.hex").trim_end())
            .unwrap();

    let mut float_coordinate = exact.clone();
    let coordinate = float_coordinate
        .windows(5)
        .position(|window| window == [0x1a, 0x1f, 0x4d, 0xea, 0x80])
        .unwrap();
    float_coordinate[coordinate] = 0xfa;
    assert_eq!(
        registry
            .validate("ea.incident", 1, &float_coordinate)
            .unwrap_err()
            .code(),
        "EA-CBOR-FLOAT"
    );

    let mut non_nfc = exact.clone();
    let composed = "Zugführer".as_bytes();
    let decomposed = "Zugfu\u{308}hrer".as_bytes();
    let text_start = non_nfc
        .windows(composed.len())
        .enumerate()
        .find(|(index, window)| {
            *window == composed && non_nfc[index.saturating_sub(1)] & 0xe0 == 0x60
        })
        .map(|(index, _)| index)
        .unwrap();
    non_nfc[text_start - 1] += 1;
    non_nfc.splice(
        text_start..text_start + composed.len(),
        decomposed.iter().copied(),
    );
    assert_eq!(
        registry
            .validate("ea.incident", 1, &non_nfc)
            .unwrap_err()
            .code(),
        "EA-CBOR-NON-NFC"
    );

    let mut legacy = exact.clone();
    let native = b"writer-native";
    let source_start = legacy
        .windows(native.len())
        .position(|window| window == native)
        .unwrap();
    let kind_offset = source_start - 2;
    legacy.splice(
        kind_offset..kind_offset + 1,
        [0x6c].into_iter().chain(b"legacyImport".iter().copied()),
    );
    assert_eq!(
        registry
            .validate("ea.incident", 1, &legacy)
            .unwrap_err()
            .code(),
        "EA-SCHEMA-LEGACY-SOURCE"
    );

    let mut patient_mismatch = exact;
    let status = patient_mismatch
        .windows(4)
        .position(|window| window == [0xf6, 0x01, 0x00, 0x75])
        .unwrap()
        + 1;
    patient_mismatch[status] = 0;
    let error = registry
        .validate("ea.incident", 1, &patient_mismatch)
        .unwrap_err();
    assert_eq!(error.field(), Some("patientCount"));
}

#[test]
fn other_variant_local_rules_and_destruction_order_fail_closed() {
    let genesis_error = GenesisV1::new(
        header("Europe/Berlin", 0),
        organization_id(0x99),
        ChainId::try_from(&[0x11; 16][..]).unwrap(),
        object_hash(0x12),
        1,
        object_hash(0x13),
    )
    .err()
    .unwrap();
    assert_eq!(genesis_error.field(), Some("genesis.organizationId"));

    let amendment_error = AmendmentV1::new(
        header("Europe/Berlin", 0),
        "2026-1",
        record_id(1),
        entry_hash(1),
        ChainSequence::new(1),
        "Grund",
        vec![],
    )
    .err()
    .unwrap();
    assert_eq!(amendment_error.field(), Some("amendment.changes"));

    let transition_error = KeyTransitionV1::new(header("Europe/Berlin", 0), object_hash(1), "")
        .err()
        .unwrap();
    assert_eq!(
        transition_error.field(),
        Some("keyTransition.organizationalReason")
    );

    let high = entry_hash(2);
    let low = entry_hash(1);
    let destruction_error = DestructionEvidenceV1::new(
        header("Europe/Berlin", 0),
        DestructionId::try_from(&[0xb0; 16][..]).unwrap(),
        object_hash(0xb1),
        1,
        vec![
            DestructionTargetV1::new(high, ChainSequence::new(1)),
            DestructionTargetV1::new(low, ChainSequence::new(2)),
        ],
        vec![DestructionExecutionResultV1::new(low, true, 0)],
        vec![],
        vec![ReplicaResultV1::pending(
            Id16::try_from(&[1; 16][..]).unwrap(),
        )],
    )
    .err()
    .unwrap();
    assert_eq!(destruction_error.code(), "EA-SCHEMA-SORT-UNIQUE");
    assert_eq!(
        destruction_error.field(),
        Some("destructionEvidence.targets")
    );

    let duplicate_target_error = DestructionEvidenceV1::new(
        header("Europe/Berlin", 0),
        DestructionId::try_from(&[0xb0; 16][..]).unwrap(),
        object_hash(0xb1),
        1,
        vec![
            DestructionTargetV1::new(low, ChainSequence::new(1)),
            DestructionTargetV1::new(low, ChainSequence::new(2)),
        ],
        vec![DestructionExecutionResultV1::new(low, true, 0)],
        vec![],
        vec![ReplicaResultV1::pending(
            Id16::try_from(&[1; 16][..]).unwrap(),
        )],
    )
    .err()
    .unwrap();
    assert_eq!(duplicate_target_error.code(), "EA-SCHEMA-SORT-UNIQUE");

    let duplicate_result_error = DestructionEvidenceV1::new(
        header("Europe/Berlin", 0),
        DestructionId::try_from(&[0xb0; 16][..]).unwrap(),
        object_hash(0xb1),
        1,
        vec![DestructionTargetV1::new(low, ChainSequence::new(1))],
        vec![
            DestructionExecutionResultV1::new(low, true, 0),
            DestructionExecutionResultV1::new(low, false, 1),
        ],
        vec![],
        vec![ReplicaResultV1::pending(
            Id16::try_from(&[1; 16][..]).unwrap(),
        )],
    )
    .err()
    .unwrap();
    assert_eq!(duplicate_result_error.code(), "EA-SCHEMA-SORT-UNIQUE");

    let duplicate_stub_error = DestructionEvidenceV1::new(
        header("Europe/Berlin", 0),
        DestructionId::try_from(&[0xb0; 16][..]).unwrap(),
        object_hash(0xb1),
        1,
        vec![DestructionTargetV1::new(low, ChainSequence::new(1))],
        vec![DestructionExecutionResultV1::new(low, true, 0)],
        vec![
            DestructionStubBindingV1::new(low, object_hash(0xc1)),
            DestructionStubBindingV1::new(low, object_hash(0xc2)),
        ],
        vec![ReplicaResultV1::pending(
            Id16::try_from(&[1; 16][..]).unwrap(),
        )],
    )
    .err()
    .unwrap();
    assert_eq!(duplicate_stub_error.code(), "EA-SCHEMA-SORT-UNIQUE");

    let duplicate_replica_id = Id16::try_from(&[1; 16][..]).unwrap();
    let duplicate_replica_error = DestructionEvidenceV1::new(
        header("Europe/Berlin", 0),
        DestructionId::try_from(&[0xb0; 16][..]).unwrap(),
        object_hash(0xb1),
        1,
        vec![DestructionTargetV1::new(low, ChainSequence::new(1))],
        vec![DestructionExecutionResultV1::new(low, true, 0)],
        vec![],
        vec![
            ReplicaResultV1::pending(duplicate_replica_id),
            ReplicaResultV1::unreachable(duplicate_replica_id),
        ],
    )
    .err()
    .unwrap();
    assert_eq!(duplicate_replica_error.code(), "EA-SCHEMA-SORT-UNIQUE");
}

#[test]
fn destruction_replica_state_requires_the_exact_attestation_shape() {
    let registry = SchemaRegistry::v1();
    let mut exact = hex::decode(
        include_str!("../../../vectors/format/payload-v1/destruction-evidence.hex").trim_end(),
    )
    .unwrap();
    let mut pending = vec![0x83, 0x50];
    pending.extend([0x02; 16]);
    pending.extend([0x01, 0xf6]);
    let position = exact
        .windows(pending.len())
        .position(|window| window == pending)
        .unwrap();
    exact[position + pending.len() - 2] = 0;

    let error = registry
        .validate("ea.destruction-evidence", 1, &exact)
        .unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-SHAPE");
    assert_eq!(
        error.field(),
        Some("destructionEvidence.replicaResults[].deletionAttestationObjectHash")
    );
}

#[test]
fn schema_errors_never_render_identifiers_or_payload_text() {
    let error = SchemaError::Unsupported {
        schema_id: "PATIENT-SECRET-SCHEMA".to_owned(),
        schema_version: 99,
    };
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(rendered.contains("EA-SCHEMA-UNSUPPORTED"));
        assert!(!rendered.contains("PATIENT"));
        assert!(!rendered.contains("99"));
    }
}

fn minimal_incident(
    header: CommonHeaderV1,
    number: &str,
    start: i64,
    patient_count: PatientCount,
) -> Result<IncidentV1, SchemaError> {
    IncidentV1::new(
        header,
        number,
        OccurredAtV1::new(UnixMillis::new(start), None)?,
        KeywordV1::free_text("Brand")?,
        LocationV1::free_text("Hauptstraße", None)?,
        vec![],
        Some("Keine Kräfte".to_owned()),
        vec![],
        Some("Keine Fahrzeuge".to_owned()),
        patient_count,
        None,
        vec![],
    )
}

fn header(timezone: &str, finalized_at: i64) -> CommonHeaderV1 {
    CommonHeaderV1::new(
        record_id(0x01),
        UnixMillis::new(finalized_at),
        timezone,
        OperatorSnapshotV1::new(
            organization_id(0x10),
            OperatorSubjectId::try_from(&[0x20; 16][..]).unwrap(),
            "Erika Beispiel",
            "Einsatzleitung",
            [0x30; 32],
            object_hash(0x40),
        )
        .unwrap(),
        NativeSourceV1::new("writer-native", 1).unwrap(),
        RegistryVersion::new(7),
    )
    .unwrap()
}

fn record_id(seed: u8) -> RecordId {
    let mut bytes = [seed; 16];
    bytes[6] = 0x70 | (seed & 0x0f);
    bytes[8] = 0x80 | (seed & 0x3f);
    RecordId::try_from(bytes.as_slice()).unwrap()
}

fn organization_id(seed: u8) -> OrganizationId {
    OrganizationId::try_from(&[seed; 16][..]).unwrap()
}

fn object_hash(seed: u8) -> ObjectHash {
    ObjectHash::try_from(&[seed; 32][..]).unwrap()
}

fn entry_hash(seed: u8) -> EntryHash {
    EntryHash::try_from(&[seed; 32][..]).unwrap()
}
