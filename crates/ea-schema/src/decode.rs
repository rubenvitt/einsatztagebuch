use ea_types::{
    ChainId, ChainSequence, DestructionId, EntryHash, Id16, ObjectHash, OperatorSubjectId,
    OrganizationId, RecordId, RegistryVersion, UnixMillis,
};
use jiff::tz::TimeZoneDatabase;
use minicbor::{Decoder, data::Type};

use crate::{
    AmendmentChangeV1, AmendmentV1, CommonHeaderV1, CoordinatesV1, DestructionEvidenceV1,
    DestructionExecutionResultV1, DestructionStubBindingV1, DestructionTargetV1,
    ExternalOrganizationV1, GenesisV1, IANA_TZDB_VERSION_V1, ImportedProvenanceV1, IncidentV1,
    KeyTransitionV1, KeywordV1, LocationV1, MasterDataRevisionV1, NativeSourceV1, OccurredAtV1,
    OperatorSnapshotV1, PatientCount, PayloadV1, PersonnelSnapshotV1, ReplicaResultV1,
    ReplicaStateV1, SCHEMA_VERSION_V1, SUITE_ID_V1, SchemaError, StructuredAddressV1,
    VehicleSnapshotV1,
};

pub(crate) fn decode_payload(
    expected_schema_id: &str,
    exact_bytes: &[u8],
) -> Result<PayloadV1, SchemaError> {
    let (header, mut decoder) = decode_common_header(expected_schema_id, exact_bytes)?;
    let payload = match expected_schema_id {
        "ea.genesis" => PayloadV1::Genesis(decode_genesis(header, &mut decoder)?),
        "ea.incident" => PayloadV1::Incident(decode_incident(header, &mut decoder)?),
        "ea.amendment" => PayloadV1::Amendment(decode_amendment(header, &mut decoder)?),
        "ea.key-transition" => {
            PayloadV1::KeyTransition(decode_key_transition(header, &mut decoder)?)
        }
        "ea.destruction-evidence" => {
            PayloadV1::DestructionEvidence(decode_destruction_evidence(header, &mut decoder)?)
        }
        _ => {
            return Err(SchemaError::invalid("EA-SCHEMA-BODY-NOT-IMPLEMENTED", None));
        }
    };
    if decoder.position() != exact_bytes.len() {
        return Err(shape("payload"));
    }
    Ok(payload)
}

fn decode_destruction_evidence(
    header: CommonHeaderV1,
    decoder: &mut Decoder<'_>,
) -> Result<DestructionEvidenceV1, SchemaError> {
    expect_array(decoder, 7, "destructionEvidence")?;
    let destruction_id = typed_id::<DestructionId>(decoder, "destructionEvidence.destructionId")?;
    let authorization_object_hash =
        typed_hash::<ObjectHash>(decoder, "destructionEvidence.authorizationObjectHash")?;
    let scope_code = uint(decoder, "destructionEvidence.scopeCode")?;

    let target_count = nonempty_array_len(decoder, "destructionEvidence.targets")?;
    let mut targets = Vec::with_capacity(target_count);
    for _ in 0..target_count {
        expect_array(decoder, 2, "destructionEvidence.targets[]")?;
        targets.push(DestructionTargetV1 {
            entry_hash: typed_hash::<EntryHash>(
                decoder,
                "destructionEvidence.targets[].entryHash",
            )?,
            chain_sequence: ChainSequence::new(uint(
                decoder,
                "destructionEvidence.targets[].chainSequence",
            )?),
        });
    }

    let execution_count = nonempty_array_len(decoder, "destructionEvidence.executionResults")?;
    let mut execution_results = Vec::with_capacity(execution_count);
    for _ in 0..execution_count {
        expect_array(decoder, 3, "destructionEvidence.executionResults[]")?;
        execution_results.push(DestructionExecutionResultV1 {
            entry_hash: typed_hash::<EntryHash>(
                decoder,
                "destructionEvidence.executionResults[].entryHash",
            )?,
            confirmed: decoder
                .bool()
                .map_err(|_| shape("destructionEvidence.executionResults[].confirmed"))?,
            result_code: uint(decoder, "destructionEvidence.executionResults[].resultCode")?,
        });
    }

    let stub_count = array_len(decoder, "destructionEvidence.stubBindings")?;
    let mut stub_bindings = Vec::with_capacity(stub_count);
    for _ in 0..stub_count {
        expect_array(decoder, 2, "destructionEvidence.stubBindings[]")?;
        stub_bindings.push(DestructionStubBindingV1 {
            entry_hash: typed_hash::<EntryHash>(
                decoder,
                "destructionEvidence.stubBindings[].entryHash",
            )?,
            stub_object_hash: typed_hash::<ObjectHash>(
                decoder,
                "destructionEvidence.stubBindings[].stubObjectHash",
            )?,
        });
    }

    let replica_count = nonempty_array_len(decoder, "destructionEvidence.replicaResults")?;
    let mut replica_results = Vec::with_capacity(replica_count);
    for _ in 0..replica_count {
        expect_array(decoder, 3, "destructionEvidence.replicaResults[]")?;
        let replica_id =
            typed_id::<Id16>(decoder, "destructionEvidence.replicaResults[].replicaId")?;
        let state = match uint(decoder, "destructionEvidence.replicaResults[].state")? {
            0 => ReplicaStateV1::Successful {
                deletion_attestation_object_hash: typed_hash::<ObjectHash>(
                    decoder,
                    "destructionEvidence.replicaResults[].deletionAttestationObjectHash",
                )?,
            },
            1 => {
                decoder
                    .null()
                    .map_err(|_| shape("destructionEvidence.replicaResults[].attestation"))?;
                ReplicaStateV1::Pending
            }
            2 => {
                decoder
                    .null()
                    .map_err(|_| shape("destructionEvidence.replicaResults[].attestation"))?;
                ReplicaStateV1::Unreachable
            }
            _ => return Err(shape("destructionEvidence.replicaResults[].state")),
        };
        replica_results.push(ReplicaResultV1 { replica_id, state });
    }

    Ok(DestructionEvidenceV1 {
        header,
        destruction_id,
        authorization_object_hash,
        scope_code,
        targets,
        execution_results,
        stub_bindings,
        replica_results,
    })
}

fn decode_key_transition(
    header: CommonHeaderV1,
    decoder: &mut Decoder<'_>,
) -> Result<KeyTransitionV1, SchemaError> {
    expect_array(decoder, 2, "keyTransition")?;
    Ok(KeyTransitionV1 {
        header,
        writer_transition_event_object_hash: typed_hash::<ObjectHash>(
            decoder,
            "keyTransition.writerTransitionEventObjectHash",
        )?,
        organizational_reason: text(decoder, "keyTransition.organizationalReason")?,
    })
}

fn decode_amendment(
    header: CommonHeaderV1,
    decoder: &mut Decoder<'_>,
) -> Result<AmendmentV1, SchemaError> {
    expect_array(decoder, 6, "amendment")?;
    let original_incident_number = text(decoder, "amendment.originalIncidentNumber")?;
    let original_record_id_bytes = bytes::<16>(decoder, "amendment.originalRecordId")?;
    if original_record_id_bytes[6] >> 4 != 7 || original_record_id_bytes[8] & 0xc0 != 0x80 {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-UUID-V7",
            Some("amendment.originalRecordId"),
        ));
    }
    let original_record_id = RecordId::try_from(original_record_id_bytes.as_slice())
        .map_err(|_| shape("amendment.originalRecordId"))?;
    let original_entry_hash = typed_hash::<EntryHash>(decoder, "amendment.originalEntryHash")?;
    let original_sequence = ChainSequence::new(uint(decoder, "amendment.originalSequence")?);
    let reason = text(decoder, "amendment.reason")?;
    let change_count = array_len(decoder, "amendment.changes")?;
    if change_count == 0 {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-NONEMPTY",
            Some("amendment.changes"),
        ));
    }
    let mut changes = Vec::with_capacity(change_count);
    for _ in 0..change_count {
        expect_array(decoder, 2, "amendment.changes[]")?;
        changes.push(AmendmentChangeV1 {
            field_path: text(decoder, "amendment.changes[].fieldPath")?,
            change_text: text(decoder, "amendment.changes[].changeText")?,
        });
    }
    Ok(AmendmentV1 {
        header,
        original_incident_number,
        original_record_id,
        original_entry_hash,
        original_sequence,
        reason,
        changes,
    })
}

fn decode_incident(
    header: CommonHeaderV1,
    decoder: &mut Decoder<'_>,
) -> Result<IncidentV1, SchemaError> {
    expect_array(decoder, 12, "incident")?;
    let human_incident_number = text(decoder, "incident.humanIncidentNumber")?;
    expect_array(decoder, 2, "incident.occurredAt")?;
    let start = integer(decoder, "incident.occurredAt.start")?;
    let end = optional_integer(decoder, "incident.occurredAt.end")?;
    let keyword = decode_keyword(decoder)?;
    let location = decode_location(decoder)?;
    let personnel = decode_personnel(decoder)?;
    let personnel_empty_reason = optional_text(decoder, "incident.personnelEmptyReason")?;
    let vehicles = decode_vehicles(decoder)?;
    let vehicles_empty_reason = optional_text(decoder, "incident.vehiclesEmptyReason")?;
    let patient_count =
        match uint(decoder, "incident.patientCountStatus")? {
            0 => {
                decoder.null().map_err(|_| {
                    SchemaError::invalid("EA-SCHEMA-PATIENT-COUNT", Some("patientCount"))
                })?;
                PatientCount::Unknown
            }
            1 => PatientCount::Known(decoder.u32().map_err(|_| {
                SchemaError::invalid("EA-SCHEMA-PATIENT-COUNT", Some("patientCount"))
            })?),
            _ => {
                return Err(SchemaError::invalid(
                    "EA-SCHEMA-PATIENT-COUNT",
                    Some("patientCount"),
                ));
            }
        };
    let notes = optional_text(decoder, "incident.notes")?;
    let external_organizations = decode_external_organizations(decoder)?;
    Ok(IncidentV1 {
        header,
        body: Box::new(crate::model::IncidentBodyV1 {
            human_incident_number,
            occurred_at: OccurredAtV1 {
                start: UnixMillis::new(start),
                end: end.map(UnixMillis::new),
            },
            keyword,
            location,
            personnel,
            personnel_empty_reason,
            vehicles,
            vehicles_empty_reason,
            patient_count,
            notes,
            external_organizations,
        }),
    })
}

fn decode_keyword(decoder: &mut Decoder<'_>) -> Result<KeywordV1, SchemaError> {
    let length = array_len(decoder, "incident.keyword")?;
    match uint(decoder, "incident.keyword.kind")? {
        0 if length == 2 => Ok(KeywordV1::FreeText(text(decoder, "incident.keyword.text")?)),
        1 if length == 3 => Ok(KeywordV1::Reference {
            reference_id: text(decoder, "incident.keyword.referenceId")?,
            display_text: text(decoder, "incident.keyword.displayText")?,
        }),
        _ => Err(shape("incident.keyword")),
    }
}

fn decode_location(decoder: &mut Decoder<'_>) -> Result<LocationV1, SchemaError> {
    expect_array(decoder, 3, "incident.location")?;
    match uint(decoder, "incident.location.kind")? {
        0 => Ok(LocationV1::FreeText {
            free_text: text(decoder, "incident.location.freeText")?,
            coordinates: optional_coordinates(decoder)?,
        }),
        1 => {
            expect_array(decoder, 6, "incident.location.structuredAddress")?;
            let address = StructuredAddressV1 {
                street: optional_text(decoder, "incident.location.street")?,
                house_number: optional_text(decoder, "incident.location.houseNumber")?,
                postal_code: optional_text(decoder, "incident.location.postalCode")?,
                locality: optional_text(decoder, "incident.location.locality")?,
                admin_area: optional_text(decoder, "incident.location.adminArea")?,
                country_code: optional_text(decoder, "incident.location.countryCode")?,
            };
            Ok(LocationV1::Structured {
                address,
                coordinates: optional_coordinates(decoder)?,
            })
        }
        _ => Err(shape("incident.location")),
    }
}

fn optional_coordinates(decoder: &mut Decoder<'_>) -> Result<Option<CoordinatesV1>, SchemaError> {
    if decoder
        .datatype()
        .map_err(|_| shape("incident.location.coordinates"))?
        == Type::Null
    {
        decoder
            .null()
            .map_err(|_| shape("incident.location.coordinates"))?;
        return Ok(None);
    }
    expect_array(decoder, 2, "incident.location.coordinates")?;
    let lat = integer(decoder, "incident.location.coordinates.latE7")?;
    let lon = integer(decoder, "incident.location.coordinates.lonE7")?;
    if !(-900_000_000..=900_000_000).contains(&lat)
        || !(-1_800_000_000..=1_800_000_000).contains(&lon)
    {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-COORDINATES",
            Some("location.coordinates"),
        ));
    }
    Ok(Some(CoordinatesV1 {
        lat_e7: i32::try_from(lat).map_err(|_| shape("incident.location.coordinates.latE7"))?,
        lon_e7: i32::try_from(lon).map_err(|_| shape("incident.location.coordinates.lonE7"))?,
    }))
}

fn decode_personnel(decoder: &mut Decoder<'_>) -> Result<Vec<PersonnelSnapshotV1>, SchemaError> {
    let length = bounded_array_len(decoder, "incident.personnel", 200)?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        let item_length = array_len(decoder, "incident.personnel[]")?;
        let value = match uint(decoder, "incident.personnel[].kind")? {
            0 if item_length == 6 => PersonnelSnapshotV1::Master {
                master_personnel_id: text(decoder, "incident.personnel[].masterPersonnelId")?,
                display_name: text(decoder, "incident.personnel[].displayName")?,
                role_or_function: optional_text(decoder, "incident.personnel[].roleOrFunction")?,
                revision: decode_revision(decoder, "incident.personnel[].revision")?,
                imported_provenance: optional_provenance(decoder)?,
            },
            1 if item_length == 3 => PersonnelSnapshotV1::AdHoc {
                display_name: text(decoder, "incident.personnel[].displayName")?,
                role_or_function: optional_text(decoder, "incident.personnel[].roleOrFunction")?,
            },
            _ => return Err(shape("incident.personnel[]")),
        };
        values.push(value);
    }
    Ok(values)
}

fn decode_vehicles(decoder: &mut Decoder<'_>) -> Result<Vec<VehicleSnapshotV1>, SchemaError> {
    let length = bounded_array_len(decoder, "incident.vehicles", 100)?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        let item_length = array_len(decoder, "incident.vehicles[]")?;
        let value = match uint(decoder, "incident.vehicles[].kind")? {
            0 if item_length == 7 => VehicleSnapshotV1::Master {
                master_vehicle_id: text(decoder, "incident.vehicles[].masterVehicleId")?,
                display_name: text(decoder, "incident.vehicles[].displayName")?,
                radio_call_sign: optional_text(decoder, "incident.vehicles[].radioCallSign")?,
                license_plate: optional_text(decoder, "incident.vehicles[].licensePlate")?,
                revision: decode_revision(decoder, "incident.vehicles[].revision")?,
                imported_provenance: optional_provenance(decoder)?,
            },
            1 if item_length == 4 => VehicleSnapshotV1::AdHoc {
                display_name: text(decoder, "incident.vehicles[].displayName")?,
                radio_call_sign: optional_text(decoder, "incident.vehicles[].radioCallSign")?,
                license_plate: optional_text(decoder, "incident.vehicles[].licensePlate")?,
            },
            _ => return Err(shape("incident.vehicles[]")),
        };
        values.push(value);
    }
    Ok(values)
}

fn decode_revision(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<MasterDataRevisionV1, SchemaError> {
    expect_array(decoder, 2, field)?;
    match uint(decoder, field)? {
        0 => Ok(MasterDataRevisionV1::RevisionNumber(uint(decoder, field)?)),
        1 => Ok(MasterDataRevisionV1::ChangedAt(UnixMillis::new(integer(
            decoder, field,
        )?))),
        _ => Err(shape(field)),
    }
}

fn optional_provenance(
    decoder: &mut Decoder<'_>,
) -> Result<Option<ImportedProvenanceV1>, SchemaError> {
    if decoder
        .datatype()
        .map_err(|_| shape("incident.importedProvenance"))?
        == Type::Null
    {
        decoder
            .null()
            .map_err(|_| shape("incident.importedProvenance"))?;
        return Ok(None);
    }
    expect_array(decoder, 3, "incident.importedProvenance")?;
    Ok(Some(ImportedProvenanceV1 {
        source_id: text(decoder, "incident.importedProvenance.sourceId")?,
        source_format_version: uint(decoder, "incident.importedProvenance.sourceFormatVersion")?,
        import_protocol_hash: typed_hash::<ObjectHash>(
            decoder,
            "incident.importedProvenance.importProtocolHash",
        )?,
    }))
}

fn decode_external_organizations(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<ExternalOrganizationV1>, SchemaError> {
    let length = bounded_array_len(decoder, "incident.externalOrganizations", 100)?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        expect_array(decoder, 2, "incident.externalOrganizations[]")?;
        values.push(ExternalOrganizationV1 {
            id: optional_text(decoder, "incident.externalOrganizations[].id")?,
            display_name: text(decoder, "incident.externalOrganizations[].displayName")?,
        });
    }
    Ok(values)
}

fn decode_genesis(
    header: CommonHeaderV1,
    decoder: &mut Decoder<'_>,
) -> Result<GenesisV1, SchemaError> {
    expect_array(decoder, 6, "genesis")?;
    let organization_id = typed_id::<OrganizationId>(decoder, "genesis.organizationId")?;
    let chain_id = typed_id::<ChainId>(decoder, "genesis.chainId")?;
    let initial_writer_certificate_object_hash =
        typed_hash::<ObjectHash>(decoder, "genesis.initialWriterCertificateObjectHash")?;
    let format_version = uint(decoder, "genesis.formatVersion")?;
    let suite_id = text(decoder, "genesis.suiteId")?;
    if suite_id != SUITE_ID_V1 {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-UNSUPPORTED-SUITE",
            Some("genesis.suiteId"),
        ));
    }
    let initial_policy_object_hash =
        typed_hash::<ObjectHash>(decoder, "genesis.initialPolicyObjectHash")?;
    if organization_id != header.operator.organization_id {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-ORGANIZATION-MISMATCH",
            Some("genesis.organizationId"),
        ));
    }
    Ok(GenesisV1 {
        header,
        organization_id,
        chain_id,
        initial_writer_certificate_object_hash,
        format_version,
        initial_policy_object_hash,
    })
}

pub(crate) fn decode_common_header<'a>(
    expected_schema_id: &str,
    exact_bytes: &'a [u8],
) -> Result<(CommonHeaderV1, Decoder<'a>), SchemaError> {
    let mut decoder = Decoder::new(exact_bytes);
    expect_array(&mut decoder, 11, "payload")?;

    let record_type = text(&mut decoder, "recordType")?;
    let record_id_bytes = bytes::<16>(&mut decoder, "recordId")?;
    let schema_id = text(&mut decoder, "schemaId")?;
    let schema_version = uint(&mut decoder, "schemaVersion")?;
    let finalized_at_device = integer(&mut decoder, "finalizedAtDevice")?;
    let timezone = text(&mut decoder, "timezone")?;

    let expected_record_type = record_type_for_schema(expected_schema_id);
    if matches!(
        record_type.as_str(),
        "legacyImport" | "legacy-access-import"
    ) {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-LEGACY-SOURCE",
            Some("recordType"),
        ));
    }
    if record_type != expected_record_type {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-RECORD-TYPE",
            Some("recordType"),
        ));
    }
    if schema_id != expected_schema_id {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-SCHEMA-ID",
            Some("schemaId"),
        ));
    }
    if schema_version != SCHEMA_VERSION_V1 {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-SCHEMA-VERSION",
            Some("schemaVersion"),
        ));
    }
    if record_id_bytes[6] >> 4 != 7 || record_id_bytes[8] & 0xc0 != 0x80 {
        return Err(SchemaError::invalid("EA-SCHEMA-UUID-V7", Some("recordId")));
    }
    validate_timezone(&timezone)?;

    expect_array(&mut decoder, 6, "operator")?;
    let organization_id = typed_id::<OrganizationId>(&mut decoder, "operator.organizationId")?;
    let operator_subject_id =
        typed_id::<OperatorSubjectId>(&mut decoder, "operator.operatorSubjectId")?;
    let display_name = text(&mut decoder, "operator.displayName")?;
    let function_label = text(&mut decoder, "operator.functionLabel")?;
    let salt = bytes::<32>(&mut decoder, "operator.salt")?;
    let operator_binding_object_hash =
        typed_hash::<ObjectHash>(&mut decoder, "operator.operatorBindingObjectHash")?;

    expect_array(&mut decoder, 4, "source")?;
    decode_source_kind(&mut decoder)?;
    let source_id = text(&mut decoder, "source.sourceId")?;
    let source_format_version = uint(&mut decoder, "source.sourceFormatVersion")?;
    decoder.null().map_err(|_| shape("source.reserved"))?;

    let registry_version = uint(&mut decoder, "registryVersion")?;
    let extension_count = decoder
        .array()
        .map_err(|_| shape("extensionData"))?
        .ok_or_else(|| shape("extensionData"))?;
    if extension_count != 0 {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-UNKNOWN-CRITICAL-EXTENSION",
            Some("extensionData"),
        ));
    }

    Ok((
        CommonHeaderV1 {
            record_id: RecordId::try_from(record_id_bytes.as_slice())
                .map_err(|_| shape("recordId"))?,
            finalized_at_device: UnixMillis::new(finalized_at_device),
            timezone,
            operator: OperatorSnapshotV1 {
                organization_id,
                operator_subject_id,
                display_name,
                function_label,
                salt,
                operator_binding_object_hash,
            },
            source: NativeSourceV1 {
                source_id,
                source_format_version,
            },
            registry_version: RegistryVersion::new(registry_version),
        },
        decoder,
    ))
}

fn decode_source_kind(decoder: &mut Decoder<'_>) -> Result<(), SchemaError> {
    match decoder.datatype().map_err(|_| shape("source.kind"))? {
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            if uint(decoder, "source.kind")? == 0 {
                Ok(())
            } else {
                Err(SchemaError::invalid(
                    "EA-SCHEMA-SOURCE-TAG",
                    Some("source.kind"),
                ))
            }
        }
        Type::String => {
            let source_kind = text(decoder, "source.kind")?;
            if matches!(
                source_kind.as_str(),
                "legacyImport" | "legacy-access-import"
            ) {
                Err(SchemaError::invalid(
                    "EA-SCHEMA-LEGACY-SOURCE",
                    Some("source.kind"),
                ))
            } else {
                Err(SchemaError::invalid(
                    "EA-SCHEMA-SOURCE-TAG",
                    Some("source.kind"),
                ))
            }
        }
        Type::I8 | Type::I16 | Type::I32 | Type::I64 | Type::Int => Err(SchemaError::invalid(
            "EA-SCHEMA-SOURCE-TAG",
            Some("source.kind"),
        )),
        _ => Err(shape("source.kind")),
    }
}

fn record_type_for_schema(schema_id: &str) -> &'static str {
    match schema_id {
        "ea.genesis" => "genesis",
        "ea.incident" => "incident",
        "ea.amendment" => "amendment",
        "ea.key-transition" => "keyTransition",
        "ea.destruction-evidence" => "destructionEvidence",
        _ => unreachable!("registry precheck owns unsupported schema IDs"),
    }
}

pub(crate) fn validate_timezone(name: &str) -> Result<(), SchemaError> {
    if jiff_tzdb::VERSION != Some(IANA_TZDB_VERSION_V1) {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-TZDB-VERSION",
            Some("timezone"),
        ));
    }
    if name == "Etc/Unknown" {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-TIMEZONE-UNKNOWN",
            Some("timezone"),
        ));
    }
    let (canonical_name, _) = jiff_tzdb::get(name)
        .ok_or_else(|| SchemaError::invalid("EA-SCHEMA-TIMEZONE-UNKNOWN", Some("timezone")))?;
    if canonical_name.as_bytes() != name.as_bytes() {
        return Err(SchemaError::invalid(
            "EA-SCHEMA-TIMEZONE-CANONICAL",
            Some("timezone"),
        ));
    }
    TimeZoneDatabase::bundled()
        .get(name)
        .map_err(|_| SchemaError::invalid("EA-SCHEMA-TIMEZONE-UNKNOWN", Some("timezone")))?;
    Ok(())
}

pub(crate) fn expect_array(
    decoder: &mut Decoder<'_>,
    expected: u64,
    field: &'static str,
) -> Result<(), SchemaError> {
    if decoder.array().map_err(|_| shape(field))? != Some(expected) {
        return Err(shape(field));
    }
    Ok(())
}

fn array_len(decoder: &mut Decoder<'_>, field: &'static str) -> Result<usize, SchemaError> {
    let length = decoder
        .array()
        .map_err(|_| shape(field))?
        .ok_or_else(|| shape(field))?;
    usize::try_from(length).map_err(|_| shape(field))
}

fn bounded_array_len(
    decoder: &mut Decoder<'_>,
    field: &'static str,
    maximum: usize,
) -> Result<usize, SchemaError> {
    let length = array_len(decoder, field)?;
    if length > maximum {
        return Err(SchemaError::invalid("EA-SCHEMA-COUNT", Some(field)));
    }
    Ok(length)
}

fn nonempty_array_len(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<usize, SchemaError> {
    let length = array_len(decoder, field)?;
    if length == 0 {
        return Err(SchemaError::invalid("EA-SCHEMA-NONEMPTY", Some(field)));
    }
    Ok(length)
}

pub(crate) fn text(decoder: &mut Decoder<'_>, field: &'static str) -> Result<String, SchemaError> {
    decoder.str().map(str::to_owned).map_err(|_| shape(field))
}

pub(crate) fn uint(decoder: &mut Decoder<'_>, field: &'static str) -> Result<u64, SchemaError> {
    decoder.u64().map_err(|_| shape(field))
}

pub(crate) fn integer(decoder: &mut Decoder<'_>, field: &'static str) -> Result<i64, SchemaError> {
    decoder.i64().map_err(|_| shape(field))
}

fn optional_integer(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<Option<i64>, SchemaError> {
    if decoder.datatype().map_err(|_| shape(field))? == Type::Null {
        decoder.null().map_err(|_| shape(field))?;
        Ok(None)
    } else {
        integer(decoder, field).map(Some)
    }
}

fn optional_text(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<Option<String>, SchemaError> {
    if decoder.datatype().map_err(|_| shape(field))? == Type::Null {
        decoder.null().map_err(|_| shape(field))?;
        Ok(None)
    } else {
        text(decoder, field).map(Some)
    }
}

pub(crate) fn bytes<const N: usize>(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<[u8; N], SchemaError> {
    decoder
        .bytes()
        .map_err(|_| shape(field))?
        .try_into()
        .map_err(|_| shape(field))
}

pub(crate) fn typed_id<T>(decoder: &mut Decoder<'_>, field: &'static str) -> Result<T, SchemaError>
where
    for<'a> T: TryFrom<&'a [u8]>,
{
    let raw = bytes::<16>(decoder, field)?;
    T::try_from(raw.as_slice()).map_err(|_| shape(field))
}

pub(crate) fn typed_hash<T>(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<T, SchemaError>
where
    for<'a> T: TryFrom<&'a [u8]>,
{
    let raw = bytes::<32>(decoder, field)?;
    T::try_from(raw.as_slice()).map_err(|_| shape(field))
}

pub(crate) const fn shape(field: &'static str) -> SchemaError {
    SchemaError::invalid("EA-SCHEMA-SHAPE", Some(field))
}
