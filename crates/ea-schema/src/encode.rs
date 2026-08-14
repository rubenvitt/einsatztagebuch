use minicbor::Encoder;

use crate::{
    AmendmentV1, CommonHeaderV1, CoordinatesV1, DestructionEvidenceV1, GenesisV1,
    ImportedProvenanceV1, IncidentV1, KeyTransitionV1, KeywordV1, LocationV1, MasterDataRevisionV1,
    PAYLOAD_PLAINTEXT_MAX_BYTES_V1, PatientCount, PayloadV1, PersonnelSnapshotV1, ReplicaStateV1,
    SCHEMA_VERSION_V1, SUITE_ID_V1, SchemaError, VehicleSnapshotV1,
};

pub(crate) fn encode_payload(payload: &PayloadV1) -> Result<Vec<u8>, SchemaError> {
    payload.validate()?;
    let encoded = encode_payload_unchecked(payload)?;
    if encoded.len() > PAYLOAD_PLAINTEXT_MAX_BYTES_V1 {
        return Err(SchemaError::invalid("EA-SCHEMA-PLAINTEXT-LIMIT", None));
    }
    ea_cbor::validate(&encoded, ea_cbor::ParserLimits::V1)?;
    Ok(encoded)
}

pub(crate) fn encode_payload_unchecked(payload: &PayloadV1) -> Result<Vec<u8>, SchemaError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(11).map_err(encode_error)?;
    encoder.str(payload.record_type()).map_err(encode_error)?;
    let header = match payload {
        PayloadV1::Genesis(value) => &value.header,
        PayloadV1::Incident(value) => &value.header,
        PayloadV1::Amendment(value) => &value.header,
        PayloadV1::KeyTransition(value) => &value.header,
        PayloadV1::DestructionEvidence(value) => &value.header,
    };
    encode_common_tail(&mut encoder, header, payload.schema_id())?;
    match payload {
        PayloadV1::Genesis(value) => encode_genesis(&mut encoder, value)?,
        PayloadV1::Incident(value) => encode_incident(&mut encoder, value)?,
        PayloadV1::Amendment(value) => encode_amendment(&mut encoder, value)?,
        PayloadV1::KeyTransition(value) => encode_key_transition(&mut encoder, value)?,
        PayloadV1::DestructionEvidence(value) => encode_destruction_evidence(&mut encoder, value)?,
    }
    Ok(encoder.into_writer())
}

fn encode_destruction_evidence(
    encoder: &mut Encoder<Vec<u8>>,
    value: &DestructionEvidenceV1,
) -> Result<(), SchemaError> {
    encoder.array(7).map_err(encode_error)?;
    encoder
        .bytes(value.destruction_id.as_bytes())
        .map_err(encode_error)?;
    encoder
        .bytes(value.authorization_object_hash.as_bytes())
        .map_err(encode_error)?;
    encoder.u64(value.scope_code).map_err(encode_error)?;
    encoder
        .array(value.targets.len() as u64)
        .map_err(encode_error)?;
    for target in &value.targets {
        encoder.array(2).map_err(encode_error)?;
        encoder
            .bytes(target.entry_hash.as_bytes())
            .map_err(encode_error)?;
        encoder
            .u64(target.chain_sequence.get())
            .map_err(encode_error)?;
    }
    encoder
        .array(value.execution_results.len() as u64)
        .map_err(encode_error)?;
    for result in &value.execution_results {
        encoder.array(3).map_err(encode_error)?;
        encoder
            .bytes(result.entry_hash.as_bytes())
            .map_err(encode_error)?;
        encoder.bool(result.confirmed).map_err(encode_error)?;
        encoder.u64(result.result_code).map_err(encode_error)?;
    }
    encoder
        .array(value.stub_bindings.len() as u64)
        .map_err(encode_error)?;
    for binding in &value.stub_bindings {
        encoder.array(2).map_err(encode_error)?;
        encoder
            .bytes(binding.entry_hash.as_bytes())
            .map_err(encode_error)?;
        encoder
            .bytes(binding.stub_object_hash.as_bytes())
            .map_err(encode_error)?;
    }
    encoder
        .array(value.replica_results.len() as u64)
        .map_err(encode_error)?;
    for result in &value.replica_results {
        encoder.array(3).map_err(encode_error)?;
        encoder
            .bytes(result.replica_id.as_bytes())
            .map_err(encode_error)?;
        match &result.state {
            ReplicaStateV1::Successful {
                deletion_attestation_object_hash,
            } => {
                encoder.u8(0).map_err(encode_error)?;
                encoder
                    .bytes(deletion_attestation_object_hash.as_bytes())
                    .map_err(encode_error)?;
            }
            ReplicaStateV1::Pending => {
                encoder.u8(1).map_err(encode_error)?;
                encoder.null().map_err(encode_error)?;
            }
            ReplicaStateV1::Unreachable => {
                encoder.u8(2).map_err(encode_error)?;
                encoder.null().map_err(encode_error)?;
            }
        }
    }
    Ok(())
}

fn encode_key_transition(
    encoder: &mut Encoder<Vec<u8>>,
    value: &KeyTransitionV1,
) -> Result<(), SchemaError> {
    encoder.array(2).map_err(encode_error)?;
    encoder
        .bytes(value.writer_transition_event_object_hash.as_bytes())
        .map_err(encode_error)?;
    encoder
        .str(&value.organizational_reason)
        .map_err(encode_error)?;
    Ok(())
}

fn encode_amendment(
    encoder: &mut Encoder<Vec<u8>>,
    value: &AmendmentV1,
) -> Result<(), SchemaError> {
    encoder.array(6).map_err(encode_error)?;
    encoder
        .str(&value.original_incident_number)
        .map_err(encode_error)?;
    encoder
        .bytes(value.original_record_id.as_bytes())
        .map_err(encode_error)?;
    encoder
        .bytes(value.original_entry_hash.as_bytes())
        .map_err(encode_error)?;
    encoder
        .u64(value.original_sequence.get())
        .map_err(encode_error)?;
    encoder.str(&value.reason).map_err(encode_error)?;
    encoder
        .array(value.changes.len() as u64)
        .map_err(encode_error)?;
    for change in &value.changes {
        encoder.array(2).map_err(encode_error)?;
        encoder.str(&change.field_path).map_err(encode_error)?;
        encoder.str(&change.change_text).map_err(encode_error)?;
    }
    Ok(())
}

fn encode_incident(encoder: &mut Encoder<Vec<u8>>, value: &IncidentV1) -> Result<(), SchemaError> {
    encoder.array(12).map_err(encode_error)?;
    encoder
        .str(&value.body.human_incident_number)
        .map_err(encode_error)?;
    encoder.array(2).map_err(encode_error)?;
    encoder
        .i64(value.body.occurred_at.start.get())
        .map_err(encode_error)?;
    encode_optional_integer(encoder, value.body.occurred_at.end.map(|value| value.get()))?;
    encode_keyword(encoder, &value.body.keyword)?;
    encode_location(encoder, &value.body.location)?;
    encoder
        .array(value.body.personnel.len() as u64)
        .map_err(encode_error)?;
    for snapshot in &value.body.personnel {
        encode_personnel(encoder, snapshot)?;
    }
    encode_optional_text(encoder, value.body.personnel_empty_reason.as_deref())?;
    encoder
        .array(value.body.vehicles.len() as u64)
        .map_err(encode_error)?;
    for snapshot in &value.body.vehicles {
        encode_vehicle(encoder, snapshot)?;
    }
    encode_optional_text(encoder, value.body.vehicles_empty_reason.as_deref())?;
    match value.body.patient_count {
        PatientCount::Unknown => {
            encoder.u8(0).map_err(encode_error)?;
            encoder.null().map_err(encode_error)?;
        }
        PatientCount::Known(count) => {
            encoder.u8(1).map_err(encode_error)?;
            encoder.u32(count).map_err(encode_error)?;
        }
    }
    encode_optional_text(encoder, value.body.notes.as_deref())?;
    encoder
        .array(value.body.external_organizations.len() as u64)
        .map_err(encode_error)?;
    for organization in &value.body.external_organizations {
        encoder.array(2).map_err(encode_error)?;
        encode_optional_text(encoder, organization.id.as_deref())?;
        encoder
            .str(&organization.display_name)
            .map_err(encode_error)?;
    }
    Ok(())
}

fn encode_keyword(encoder: &mut Encoder<Vec<u8>>, keyword: &KeywordV1) -> Result<(), SchemaError> {
    match keyword {
        KeywordV1::FreeText(text) => {
            encoder.array(2).map_err(encode_error)?;
            encoder.u8(0).map_err(encode_error)?;
            encoder.str(text).map_err(encode_error)?;
        }
        KeywordV1::Reference {
            reference_id,
            display_text,
        } => {
            encoder.array(3).map_err(encode_error)?;
            encoder.u8(1).map_err(encode_error)?;
            encoder.str(reference_id).map_err(encode_error)?;
            encoder.str(display_text).map_err(encode_error)?;
        }
    }
    Ok(())
}

fn encode_location(
    encoder: &mut Encoder<Vec<u8>>,
    location: &LocationV1,
) -> Result<(), SchemaError> {
    encoder.array(3).map_err(encode_error)?;
    match location {
        LocationV1::FreeText {
            free_text,
            coordinates,
        } => {
            encoder.u8(0).map_err(encode_error)?;
            encoder.str(free_text).map_err(encode_error)?;
            encode_coordinates(encoder, coordinates.as_ref())?;
        }
        LocationV1::Structured {
            address,
            coordinates,
        } => {
            encoder.u8(1).map_err(encode_error)?;
            encoder.array(6).map_err(encode_error)?;
            encode_optional_text(encoder, address.street.as_deref())?;
            encode_optional_text(encoder, address.house_number.as_deref())?;
            encode_optional_text(encoder, address.postal_code.as_deref())?;
            encode_optional_text(encoder, address.locality.as_deref())?;
            encode_optional_text(encoder, address.admin_area.as_deref())?;
            encode_optional_text(encoder, address.country_code.as_deref())?;
            encode_coordinates(encoder, coordinates.as_ref())?;
        }
    }
    Ok(())
}

fn encode_coordinates(
    encoder: &mut Encoder<Vec<u8>>,
    coordinates: Option<&CoordinatesV1>,
) -> Result<(), SchemaError> {
    let Some(coordinates) = coordinates else {
        encoder.null().map_err(encode_error)?;
        return Ok(());
    };
    encoder.array(2).map_err(encode_error)?;
    encoder.i32(coordinates.lat_e7).map_err(encode_error)?;
    encoder.i32(coordinates.lon_e7).map_err(encode_error)?;
    Ok(())
}

fn encode_personnel(
    encoder: &mut Encoder<Vec<u8>>,
    snapshot: &PersonnelSnapshotV1,
) -> Result<(), SchemaError> {
    match snapshot {
        PersonnelSnapshotV1::Master {
            master_personnel_id,
            display_name,
            role_or_function,
            revision,
            imported_provenance,
        } => {
            encoder.array(6).map_err(encode_error)?;
            encoder.u8(0).map_err(encode_error)?;
            encoder.str(master_personnel_id).map_err(encode_error)?;
            encoder.str(display_name).map_err(encode_error)?;
            encode_optional_text(encoder, role_or_function.as_deref())?;
            encode_revision(encoder, revision)?;
            encode_provenance(encoder, imported_provenance.as_ref())?;
        }
        PersonnelSnapshotV1::AdHoc {
            display_name,
            role_or_function,
        } => {
            encoder.array(3).map_err(encode_error)?;
            encoder.u8(1).map_err(encode_error)?;
            encoder.str(display_name).map_err(encode_error)?;
            encode_optional_text(encoder, role_or_function.as_deref())?;
        }
    }
    Ok(())
}

fn encode_vehicle(
    encoder: &mut Encoder<Vec<u8>>,
    snapshot: &VehicleSnapshotV1,
) -> Result<(), SchemaError> {
    match snapshot {
        VehicleSnapshotV1::Master {
            master_vehicle_id,
            display_name,
            radio_call_sign,
            license_plate,
            revision,
            imported_provenance,
        } => {
            encoder.array(7).map_err(encode_error)?;
            encoder.u8(0).map_err(encode_error)?;
            encoder.str(master_vehicle_id).map_err(encode_error)?;
            encoder.str(display_name).map_err(encode_error)?;
            encode_optional_text(encoder, radio_call_sign.as_deref())?;
            encode_optional_text(encoder, license_plate.as_deref())?;
            encode_revision(encoder, revision)?;
            encode_provenance(encoder, imported_provenance.as_ref())?;
        }
        VehicleSnapshotV1::AdHoc {
            display_name,
            radio_call_sign,
            license_plate,
        } => {
            encoder.array(4).map_err(encode_error)?;
            encoder.u8(1).map_err(encode_error)?;
            encoder.str(display_name).map_err(encode_error)?;
            encode_optional_text(encoder, radio_call_sign.as_deref())?;
            encode_optional_text(encoder, license_plate.as_deref())?;
        }
    }
    Ok(())
}

fn encode_revision(
    encoder: &mut Encoder<Vec<u8>>,
    revision: &MasterDataRevisionV1,
) -> Result<(), SchemaError> {
    encoder.array(2).map_err(encode_error)?;
    match revision {
        MasterDataRevisionV1::RevisionNumber(number) => {
            encoder.u8(0).map_err(encode_error)?;
            encoder.u64(*number).map_err(encode_error)?;
        }
        MasterDataRevisionV1::ChangedAt(changed_at) => {
            encoder.u8(1).map_err(encode_error)?;
            encoder.i64(changed_at.get()).map_err(encode_error)?;
        }
    }
    Ok(())
}

fn encode_provenance(
    encoder: &mut Encoder<Vec<u8>>,
    provenance: Option<&ImportedProvenanceV1>,
) -> Result<(), SchemaError> {
    let Some(provenance) = provenance else {
        encoder.null().map_err(encode_error)?;
        return Ok(());
    };
    encoder.array(3).map_err(encode_error)?;
    encoder.str(&provenance.source_id).map_err(encode_error)?;
    encoder
        .u64(provenance.source_format_version)
        .map_err(encode_error)?;
    encoder
        .bytes(provenance.import_protocol_hash.as_bytes())
        .map_err(encode_error)?;
    Ok(())
}

fn encode_optional_text(
    encoder: &mut Encoder<Vec<u8>>,
    value: Option<&str>,
) -> Result<(), SchemaError> {
    match value {
        Some(value) => {
            encoder.str(value).map_err(encode_error)?;
        }
        None => {
            encoder.null().map_err(encode_error)?;
        }
    }
    Ok(())
}

fn encode_optional_integer(
    encoder: &mut Encoder<Vec<u8>>,
    value: Option<i64>,
) -> Result<(), SchemaError> {
    match value {
        Some(value) => {
            encoder.i64(value).map_err(encode_error)?;
        }
        None => {
            encoder.null().map_err(encode_error)?;
        }
    }
    Ok(())
}

fn encode_common_tail(
    encoder: &mut Encoder<Vec<u8>>,
    header: &CommonHeaderV1,
    schema_id: &str,
) -> Result<(), SchemaError> {
    encoder
        .bytes(header.record_id.as_bytes())
        .map_err(encode_error)?;
    encoder.str(schema_id).map_err(encode_error)?;
    encoder.u64(SCHEMA_VERSION_V1).map_err(encode_error)?;
    encoder
        .i64(header.finalized_at_device.get())
        .map_err(encode_error)?;
    encoder.str(&header.timezone).map_err(encode_error)?;
    encoder.array(6).map_err(encode_error)?;
    encoder
        .bytes(header.operator.organization_id.as_bytes())
        .map_err(encode_error)?;
    encoder
        .bytes(header.operator.operator_subject_id.as_bytes())
        .map_err(encode_error)?;
    encoder
        .str(&header.operator.display_name)
        .map_err(encode_error)?;
    encoder
        .str(&header.operator.function_label)
        .map_err(encode_error)?;
    encoder.bytes(&header.operator.salt).map_err(encode_error)?;
    encoder
        .bytes(header.operator.operator_binding_object_hash.as_bytes())
        .map_err(encode_error)?;
    encoder.array(4).map_err(encode_error)?;
    encoder.u8(0).map_err(encode_error)?;
    encoder
        .str(&header.source.source_id)
        .map_err(encode_error)?;
    encoder
        .u64(header.source.source_format_version)
        .map_err(encode_error)?;
    encoder.null().map_err(encode_error)?;
    encoder
        .u64(header.registry_version.get())
        .map_err(encode_error)?;
    encoder.array(0).map_err(encode_error)?;
    Ok(())
}

fn encode_genesis(encoder: &mut Encoder<Vec<u8>>, value: &GenesisV1) -> Result<(), SchemaError> {
    encoder.array(6).map_err(encode_error)?;
    encoder
        .bytes(value.organization_id.as_bytes())
        .map_err(encode_error)?;
    encoder
        .bytes(value.chain_id.as_bytes())
        .map_err(encode_error)?;
    encoder
        .bytes(value.initial_writer_certificate_object_hash.as_bytes())
        .map_err(encode_error)?;
    encoder.u64(value.format_version).map_err(encode_error)?;
    encoder.str(SUITE_ID_V1).map_err(encode_error)?;
    encoder
        .bytes(value.initial_policy_object_hash.as_bytes())
        .map_err(encode_error)?;
    Ok(())
}

fn encode_error<E>(_error: E) -> SchemaError {
    SchemaError::invalid("EA-SCHEMA-ENCODE", None)
}
