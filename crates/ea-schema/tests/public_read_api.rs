use ea_schema::{CommonHeaderV1, PayloadV1, SchemaRegistry};

#[test]
fn decoded_payloads_expose_complete_read_only_typed_views() {
    let registry = SchemaRegistry::v1();

    let genesis_exact = decode(include_str!(
        "../../../vectors/format/payload-v1/genesis.hex"
    ));
    let genesis = registry.validate("ea.genesis", 1, &genesis_exact).unwrap();
    let PayloadV1::Genesis(genesis) = genesis.payload() else {
        panic!("expected Genesis")
    };
    assert_common_header(genesis.header(), "Europe/Berlin", 1_700_000_000_000);
    assert_eq!(genesis.organization_id().as_bytes(), &[0x10; 16]);
    assert_eq!(genesis.chain_id().as_bytes(), &[0x50; 16]);
    assert_eq!(
        genesis.initial_writer_certificate_object_hash().as_bytes(),
        &[0x60; 32]
    );
    assert_eq!(genesis.format_version(), 1);
    assert_eq!(genesis.initial_policy_object_hash().as_bytes(), &[0x70; 32]);

    let incident_exact = decode(include_str!(
        "../../../vectors/format/payload-v1/incident.hex"
    ));
    let incident = registry
        .validate("ea.incident", 1, &incident_exact)
        .unwrap();
    let PayloadV1::Incident(incident) = incident.payload() else {
        panic!("expected Incident")
    };
    assert_common_header(incident.header(), "America/New_York", 1_798_763_400_000);
    assert_eq!(incident.human_incident_number(), "2026-0001");
    assert_eq!(incident.occurred_at().start().get(), 1_798_763_400_000);
    assert_eq!(
        incident.occurred_at().end().map(|value| value.get()),
        Some(1_798_767_000_000)
    );
    assert_eq!(
        incident.keyword().as_reference(),
        Some(("brand", "Brand groß"))
    );
    let (address, coordinates) = incident.location().as_structured().unwrap();
    assert_eq!(address.street(), Some("Hauptstraße"));
    assert_eq!(address.house_number(), Some("7a"));
    assert_eq!(address.postal_code(), Some("10115"));
    assert_eq!(address.locality(), Some("Berlin"));
    assert_eq!(address.admin_area(), Some("BE"));
    assert_eq!(address.country_code(), Some("DE"));
    let coordinates = coordinates.unwrap();
    assert_eq!(coordinates.lat_e7(), 525_200_000);
    assert_eq!(coordinates.lon_e7(), 134_050_000);

    assert_eq!(incident.personnel().len(), 2);
    let master_personnel = &incident.personnel()[0];
    assert!(master_personnel.is_master());
    assert_eq!(master_personnel.master_personnel_id(), Some("person-42"));
    assert_eq!(master_personnel.display_name(), "Zulu Zugführer");
    assert_eq!(master_personnel.role_or_function(), Some("Zugführer"));
    assert_eq!(
        master_personnel
            .revision()
            .and_then(|revision| revision.revision_number()),
        Some(3)
    );
    assert!(master_personnel.imported_provenance().is_none());
    let ad_hoc_personnel = &incident.personnel()[1];
    assert!(!ad_hoc_personnel.is_master());
    assert_eq!(ad_hoc_personnel.master_personnel_id(), None);
    assert_eq!(ad_hoc_personnel.display_name(), "Alpha Unterstützung");
    assert_eq!(incident.personnel_empty_reason(), None);

    assert_eq!(incident.vehicles().len(), 1);
    let vehicle = &incident.vehicles()[0];
    assert!(vehicle.is_master());
    assert_eq!(vehicle.master_vehicle_id(), Some("vehicle-7"));
    assert_eq!(vehicle.display_name(), "LF 20");
    assert_eq!(vehicle.radio_call_sign(), Some("Florian 1/46-1"));
    assert_eq!(vehicle.license_plate(), Some("B-DR 112"));
    assert_eq!(
        vehicle
            .revision()
            .and_then(|revision| revision.changed_at())
            .map(|value| value.get()),
        Some(1_700_000_000_000)
    );
    let provenance = vehicle.imported_provenance().unwrap();
    assert_eq!(provenance.source_id(), "csv-vehicles");
    assert_eq!(provenance.source_format_version(), 1);
    assert_eq!(provenance.import_protocol_hash().as_bytes(), &[0x81; 32]);
    assert_eq!(incident.vehicles_empty_reason(), None);
    assert_eq!(incident.patient_count().known(), Some(0));
    assert!(!incident.patient_count().is_unknown());
    assert_eq!(incident.notes(), Some("Keine Patientendaten."));
    assert_eq!(incident.external_organizations().len(), 2);
    assert_eq!(incident.external_organizations()[0].id(), Some("z-org"));
    assert_eq!(
        incident.external_organizations()[0].display_name(),
        "Zulu Klinik"
    );
    assert_eq!(incident.external_organizations()[1].id(), None);

    let amendment_exact = decode(include_str!(
        "../../../vectors/format/payload-v1/amendment.hex"
    ));
    let amendment = registry
        .validate("ea.amendment", 1, &amendment_exact)
        .unwrap();
    let PayloadV1::Amendment(amendment) = amendment.payload() else {
        panic!("expected Amendment")
    };
    assert_common_header(amendment.header(), "Europe/Berlin", 1_798_768_000_000);
    assert_eq!(amendment.original_incident_number(), "2026-0001");
    assert_eq!(amendment.original_record_id().as_bytes()[0], 0x11);
    assert_eq!(amendment.original_entry_hash().as_bytes(), &[0x90; 32]);
    assert_eq!(amendment.original_sequence().get(), 42);
    assert_eq!(amendment.reason(), "Lage präzisiert");
    assert_eq!(amendment.changes().len(), 2);
    assert_eq!(amendment.changes()[0].field_path(), "location");
    assert_eq!(
        amendment.changes()[0].change_text(),
        "Hausnummer 7a ergänzt"
    );

    let transition_exact = decode(include_str!(
        "../../../vectors/format/payload-v1/key-transition.hex"
    ));
    let transition = registry
        .validate("ea.key-transition", 1, &transition_exact)
        .unwrap();
    let PayloadV1::KeyTransition(transition) = transition.payload() else {
        panic!("expected KeyTransition")
    };
    assert_common_header(transition.header(), "Europe/Berlin", 1_798_769_000_000);
    assert_eq!(
        transition.writer_transition_event_object_hash().as_bytes(),
        &[0xa0; 32]
    );
    assert_eq!(
        transition.organizational_reason(),
        "Geplanter Writer-Wechsel"
    );

    let destruction_exact = decode(include_str!(
        "../../../vectors/format/payload-v1/destruction-evidence.hex"
    ));
    let destruction = registry
        .validate("ea.destruction-evidence", 1, &destruction_exact)
        .unwrap();
    let PayloadV1::DestructionEvidence(destruction) = destruction.payload() else {
        panic!("expected DestructionEvidence")
    };
    assert_common_header(destruction.header(), "Europe/Berlin", 1_798_770_000_000);
    assert_eq!(destruction.destruction_id().as_bytes(), &[0xb0; 16]);
    assert_eq!(
        destruction.authorization_object_hash().as_bytes(),
        &[0xb1; 32]
    );
    assert_eq!(destruction.scope_code(), 1);
    assert_eq!(destruction.targets().len(), 2);
    assert_eq!(
        destruction.targets()[0].entry_hash().as_bytes(),
        &[0x01; 32]
    );
    assert_eq!(destruction.targets()[0].chain_sequence().get(), 7);
    assert_eq!(destruction.execution_results().len(), 2);
    assert!(destruction.execution_results()[0].confirmed());
    assert_eq!(destruction.execution_results()[0].result_code(), 0);
    assert_eq!(destruction.stub_bindings().len(), 2);
    assert_eq!(
        destruction.stub_bindings()[0].stub_object_hash().as_bytes(),
        &[0xc1; 32]
    );
    assert_eq!(destruction.replica_results().len(), 3);
    assert_eq!(
        destruction.replica_results()[0].replica_id().as_bytes(),
        &[0x01; 16]
    );
    assert_eq!(
        destruction.replica_results()[0]
            .state()
            .deletion_attestation_object_hash()
            .unwrap()
            .as_bytes(),
        &[0xd1; 32]
    );
    assert!(destruction.replica_results()[1].state().is_pending());
    assert!(destruction.replica_results()[2].state().is_unreachable());

    let view = registry
        .derive_view("ea.incident", 1, &incident_exact)
        .unwrap();
    assert_eq!(view.exact_source_bytes(), incident_exact);
    assert_eq!(view.validated_payload().exact_bytes(), incident_exact);
    let PayloadV1::Incident(view_incident) = view.payload() else {
        panic!("identity view must expose its typed Incident")
    };
    assert_eq!(view_incident.human_incident_number(), "2026-0001");
}

fn assert_common_header(header: &CommonHeaderV1, timezone: &str, finalized_at: i64) {
    assert_eq!(header.finalized_at_device().get(), finalized_at);
    assert_eq!(header.timezone(), timezone);
    assert_eq!(header.operator().organization_id().as_bytes(), &[0x10; 16]);
    assert_eq!(
        header.operator().operator_subject_id().as_bytes(),
        &[0x20; 16]
    );
    assert_eq!(header.operator().display_name(), "Erika Beispiel");
    assert_eq!(header.operator().function_label(), "Einsatzleitung");
    assert_eq!(header.operator().salt(), &[0x30; 32]);
    assert_eq!(
        header.operator().operator_binding_object_hash().as_bytes(),
        &[0x40; 32]
    );
    assert_eq!(header.source().source_id(), "writer-native");
    assert_eq!(header.source().source_format_version(), 1);
    assert_eq!(header.registry_version().get(), 7);
    assert_eq!(header.record_id().as_bytes()[6] >> 4, 7);
}

fn decode(source: &str) -> Vec<u8> {
    hex::decode(source.trim_end()).unwrap()
}
