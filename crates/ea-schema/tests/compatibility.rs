use ea_schema::{
    IANA_TZDB_VERSION_V1, SCHEMA_VERSION_V1, SUITE_ID_V1, SchemaError, SchemaRegistry,
    UnsupportedSchema,
};

#[test]
fn registry_has_exactly_five_v1_identity_descriptors() {
    let registry = SchemaRegistry::v1();
    let schemas = registry.schemas();
    assert_eq!(schemas.len(), 5);
    assert_eq!(
        schemas
            .iter()
            .map(|schema| (
                schema.schema_id(),
                schema.record_type(),
                schema.schema_version()
            ))
            .collect::<Vec<_>>(),
        vec![
            ("ea.genesis", "genesis", 1),
            ("ea.incident", "incident", 1),
            ("ea.amendment", "amendment", 1),
            ("ea.key-transition", "keyTransition", 1),
            ("ea.destruction-evidence", "destructionEvidence", 1,),
        ]
    );
    assert!(schemas.iter().all(|schema| schema.identity_view_only()));
    assert!(
        schemas
            .iter()
            .all(|schema| schema.suite_id() == SUITE_ID_V1)
    );
    assert!(
        schemas
            .iter()
            .all(|schema| schema.tzdb_version() == IANA_TZDB_VERSION_V1)
    );
}

#[test]
fn unknown_schema_is_decided_before_parse_and_suite_failure_is_distinct() {
    let registry = SchemaRegistry::v1();
    assert!(matches!(
        registry.derive_view("ea.incident", 99, b"not cbor"),
        Err(SchemaError::Unsupported { .. })
    ));
    assert!(matches!(
        registry.derive_view("ea.unknown", 1, b"not cbor"),
        Err(SchemaError::Unsupported { .. })
    ));
    registry.require_suite(SUITE_ID_V1).unwrap();
    let error = registry
        .require_suite("EINSATZARCHIV-SUITE-SECRET")
        .unwrap_err();
    assert_eq!(error.code(), "EA-SCHEMA-UNSUPPORTED-SUITE");
    assert!(!format!("{error:?}").contains("SECRET"));
}

#[test]
fn unsupported_schema_maps_to_the_single_public_error_path() {
    let error = SchemaError::from(UnsupportedSchema {
        schema_id: "ea.future".to_owned(),
        schema_version: 2,
    });
    assert!(matches!(
        error,
        SchemaError::Unsupported {
            schema_id,
            schema_version: 2
        } if schema_id == "ea.future"
    ));
}

#[test]
fn all_identity_views_preserve_verified_source_bytes() {
    let registry = SchemaRegistry::v1();
    let cases = [
        (
            "ea.genesis",
            include_str!("../../../vectors/format/payload-v1/genesis.hex"),
        ),
        (
            "ea.incident",
            include_str!("../../../vectors/format/payload-v1/incident.hex"),
        ),
        (
            "ea.amendment",
            include_str!("../../../vectors/format/payload-v1/amendment.hex"),
        ),
        (
            "ea.key-transition",
            include_str!("../../../vectors/format/payload-v1/key-transition.hex"),
        ),
        (
            "ea.destruction-evidence",
            include_str!("../../../vectors/format/payload-v1/destruction-evidence.hex"),
        ),
    ];

    for (schema_id, source) in cases {
        let exact = hex::decode(source.trim_end()).unwrap();
        let view = registry
            .derive_view(schema_id, SCHEMA_VERSION_V1, &exact)
            .unwrap();
        assert_eq!(view.source_schema_id(), schema_id);
        assert_eq!(view.source_schema_version(), 1);
        assert_eq!(view.target_schema_id(), schema_id);
        assert_eq!(view.target_schema_version(), 1);
        assert_eq!(view.exact_source_bytes(), exact);
    }
}

#[test]
fn checked_in_compatibility_matrix_is_generated_from_registry() {
    let expected = SchemaRegistry::v1().compatibility_matrix_json();
    assert_eq!(
        include_str!("../../../schemas/compatibility-matrix.json"),
        expected
    );
}
