use ea_types::{
    ObjectHash, OperatorSubjectId, OrganizationId, RecordId, RegistryVersion, UnixMillis,
};
use jiff::{Timestamp, tz::TimeZoneDatabase};
use unicode_normalization::UnicodeNormalization;

use crate::SchemaError;

pub struct CommonHeaderV1 {
    pub(crate) record_id: RecordId,
    pub(crate) finalized_at_device: UnixMillis,
    pub(crate) timezone: String,
    pub(crate) operator: OperatorSnapshotV1,
    pub(crate) source: NativeSourceV1,
    pub(crate) registry_version: RegistryVersion,
}

impl CommonHeaderV1 {
    pub fn new(
        record_id: RecordId,
        finalized_at_device: UnixMillis,
        timezone: impl Into<String>,
        operator: OperatorSnapshotV1,
        source: NativeSourceV1,
        registry_version: RegistryVersion,
    ) -> Result<Self, SchemaError> {
        validate_uuid_v7(record_id, "recordId")?;
        let timezone = normalize_text(timezone);
        crate::decode::validate_timezone(&timezone)?;
        Ok(Self {
            record_id,
            finalized_at_device,
            timezone,
            operator,
            source,
            registry_version,
        })
    }

    #[must_use]
    pub const fn operator(&self) -> &OperatorSnapshotV1 {
        &self.operator
    }

    #[must_use]
    pub const fn record_id(&self) -> RecordId {
        self.record_id
    }

    #[must_use]
    pub const fn finalized_at_device(&self) -> UnixMillis {
        self.finalized_at_device
    }

    #[must_use]
    pub fn timezone(&self) -> &str {
        &self.timezone
    }

    #[must_use]
    pub const fn source(&self) -> &NativeSourceV1 {
        &self.source
    }

    #[must_use]
    pub const fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }

    fn validate(&self) -> Result<(), SchemaError> {
        validate_uuid_v7(self.record_id, "recordId")?;
        crate::decode::validate_timezone(&self.timezone)?;
        for (value, field) in [
            (&self.operator.display_name, "operator.displayName"),
            (&self.operator.function_label, "operator.functionLabel"),
            (&self.source.source_id, "source.sourceId"),
        ] {
            if !value.nfc().eq(value.chars()) {
                return Err(SchemaError::invalid("EA-SCHEMA-NON-NFC", Some(field)));
            }
        }
        Ok(())
    }
}

pub struct OperatorSnapshotV1 {
    pub(crate) organization_id: OrganizationId,
    pub(crate) operator_subject_id: OperatorSubjectId,
    pub(crate) display_name: String,
    pub(crate) function_label: String,
    pub(crate) salt: [u8; 32],
    pub(crate) operator_binding_object_hash: ObjectHash,
}

impl OperatorSnapshotV1 {
    pub fn new(
        organization_id: OrganizationId,
        operator_subject_id: OperatorSubjectId,
        display_name: impl Into<String>,
        function_label: impl Into<String>,
        salt: [u8; 32],
        operator_binding_object_hash: ObjectHash,
    ) -> Result<Self, SchemaError> {
        Ok(Self {
            organization_id,
            operator_subject_id,
            display_name: normalize_text(display_name),
            function_label: normalize_text(function_label),
            salt,
            operator_binding_object_hash,
        })
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn operator_subject_id(&self) -> OperatorSubjectId {
        self.operator_subject_id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn function_label(&self) -> &str {
        &self.function_label
    }

    #[must_use]
    pub const fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    #[must_use]
    pub const fn operator_binding_object_hash(&self) -> ObjectHash {
        self.operator_binding_object_hash
    }
}

pub struct NativeSourceV1 {
    pub(crate) source_id: String,
    pub(crate) source_format_version: u64,
}

impl NativeSourceV1 {
    pub fn new(
        source_id: impl Into<String>,
        source_format_version: u64,
    ) -> Result<Self, SchemaError> {
        let source_id = normalize_text(source_id);
        Ok(Self {
            source_id,
            source_format_version,
        })
    }

    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    #[must_use]
    pub const fn source_format_version(&self) -> u64 {
        self.source_format_version
    }
}

pub struct ValidatedPayload {
    pub(crate) payload: PayloadV1,
    pub(crate) exact_bytes: Vec<u8>,
}

impl ValidatedPayload {
    #[must_use]
    pub const fn payload(&self) -> &PayloadV1 {
        &self.payload
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

impl core::fmt::Debug for ValidatedPayload {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ValidatedPayload")
    }
}

pub enum PayloadV1 {
    Genesis(GenesisV1),
    Incident(IncidentV1),
    Amendment(AmendmentV1),
    KeyTransition(KeyTransitionV1),
    DestructionEvidence(DestructionEvidenceV1),
}

impl PayloadV1 {
    #[must_use]
    pub const fn schema_id(&self) -> &'static str {
        match self {
            Self::Genesis(_) => "ea.genesis",
            Self::Incident(_) => "ea.incident",
            Self::Amendment(_) => "ea.amendment",
            Self::KeyTransition(_) => "ea.key-transition",
            Self::DestructionEvidence(_) => "ea.destruction-evidence",
        }
    }

    #[must_use]
    pub const fn record_type(&self) -> &'static str {
        match self {
            Self::Genesis(_) => "genesis",
            Self::Incident(_) => "incident",
            Self::Amendment(_) => "amendment",
            Self::KeyTransition(_) => "keyTransition",
            Self::DestructionEvidence(_) => "destructionEvidence",
        }
    }

    pub fn validate(&self) -> Result<(), SchemaError> {
        match self {
            Self::Genesis(value) => value.validate(),
            Self::Incident(value) => value.validate(),
            Self::Amendment(value) => value.validate(),
            Self::KeyTransition(value) => value.validate(),
            Self::DestructionEvidence(value) => value.validate(),
        }
    }
}

pub enum PatientCount {
    Known(u32),
    Unknown,
}

impl PatientCount {
    #[must_use]
    pub const fn known(&self) -> Option<u32> {
        match self {
            Self::Known(value) => Some(*value),
            Self::Unknown => None,
        }
    }

    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

pub struct GenesisV1 {
    pub(crate) header: CommonHeaderV1,
    pub(crate) organization_id: OrganizationId,
    pub(crate) chain_id: ea_types::ChainId,
    pub(crate) initial_writer_certificate_object_hash: ObjectHash,
    pub(crate) format_version: u64,
    pub(crate) initial_policy_object_hash: ObjectHash,
}

impl GenesisV1 {
    pub fn new(
        header: CommonHeaderV1,
        organization_id: OrganizationId,
        chain_id: ea_types::ChainId,
        initial_writer_certificate_object_hash: ObjectHash,
        format_version: u64,
        initial_policy_object_hash: ObjectHash,
    ) -> Result<Self, SchemaError> {
        let value = Self {
            header,
            organization_id,
            chain_id,
            initial_writer_certificate_object_hash,
            format_version,
            initial_policy_object_hash,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn header(&self) -> &CommonHeaderV1 {
        &self.header
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn chain_id(&self) -> ea_types::ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn initial_writer_certificate_object_hash(&self) -> ObjectHash {
        self.initial_writer_certificate_object_hash
    }

    #[must_use]
    pub const fn format_version(&self) -> u64 {
        self.format_version
    }

    #[must_use]
    pub const fn initial_policy_object_hash(&self) -> ObjectHash {
        self.initial_policy_object_hash
    }

    fn validate(&self) -> Result<(), SchemaError> {
        self.header.validate()?;
        if self.organization_id != self.header.operator.organization_id {
            return Err(SchemaError::invalid(
                "EA-SCHEMA-ORGANIZATION-MISMATCH",
                Some("genesis.organizationId"),
            ));
        }
        if self.format_version != 1 {
            return Err(SchemaError::invalid(
                "EA-SCHEMA-FORMAT-VERSION",
                Some("genesis.formatVersion"),
            ));
        }
        Ok(())
    }
}

pub struct IncidentV1 {
    pub(crate) header: CommonHeaderV1,
    pub(crate) body: Box<IncidentBodyV1>,
}

pub(crate) struct IncidentBodyV1 {
    pub(crate) human_incident_number: String,
    pub(crate) occurred_at: OccurredAtV1,
    pub(crate) keyword: KeywordV1,
    pub(crate) location: LocationV1,
    pub(crate) personnel: Vec<PersonnelSnapshotV1>,
    pub(crate) personnel_empty_reason: Option<String>,
    pub(crate) vehicles: Vec<VehicleSnapshotV1>,
    pub(crate) vehicles_empty_reason: Option<String>,
    pub(crate) patient_count: PatientCount,
    pub(crate) notes: Option<String>,
    pub(crate) external_organizations: Vec<ExternalOrganizationV1>,
}

impl IncidentV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        header: CommonHeaderV1,
        human_incident_number: impl Into<String>,
        occurred_at: OccurredAtV1,
        keyword: KeywordV1,
        location: LocationV1,
        personnel: Vec<PersonnelSnapshotV1>,
        personnel_empty_reason: Option<String>,
        vehicles: Vec<VehicleSnapshotV1>,
        vehicles_empty_reason: Option<String>,
        patient_count: PatientCount,
        notes: Option<String>,
        external_organizations: Vec<ExternalOrganizationV1>,
    ) -> Result<Self, SchemaError> {
        let value = Self {
            header,
            body: Box::new(IncidentBodyV1 {
                human_incident_number: normalize_text(human_incident_number),
                occurred_at,
                keyword,
                location,
                personnel,
                personnel_empty_reason: personnel_empty_reason.map(normalize_text),
                vehicles,
                vehicles_empty_reason: vehicles_empty_reason.map(normalize_text),
                patient_count,
                notes: notes.map(normalize_text),
                external_organizations,
            }),
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn header(&self) -> &CommonHeaderV1 {
        &self.header
    }

    #[must_use]
    pub fn human_incident_number(&self) -> &str {
        &self.body.human_incident_number
    }

    #[must_use]
    pub const fn occurred_at(&self) -> &OccurredAtV1 {
        &self.body.occurred_at
    }

    #[must_use]
    pub const fn keyword(&self) -> &KeywordV1 {
        &self.body.keyword
    }

    #[must_use]
    pub const fn location(&self) -> &LocationV1 {
        &self.body.location
    }

    #[must_use]
    pub fn personnel(&self) -> &[PersonnelSnapshotV1] {
        &self.body.personnel
    }

    #[must_use]
    pub fn personnel_empty_reason(&self) -> Option<&str> {
        self.body.personnel_empty_reason.as_deref()
    }

    #[must_use]
    pub fn vehicles(&self) -> &[VehicleSnapshotV1] {
        &self.body.vehicles
    }

    #[must_use]
    pub fn vehicles_empty_reason(&self) -> Option<&str> {
        self.body.vehicles_empty_reason.as_deref()
    }

    #[must_use]
    pub const fn patient_count(&self) -> &PatientCount {
        &self.body.patient_count
    }

    #[must_use]
    pub fn notes(&self) -> Option<&str> {
        self.body.notes.as_deref()
    }

    #[must_use]
    pub fn external_organizations(&self) -> &[ExternalOrganizationV1] {
        &self.body.external_organizations
    }

    pub fn incident_uniqueness_key(&self) -> Result<IncidentUniquenessKey, SchemaError> {
        self.validate()?;
        Ok(IncidentUniquenessKey {
            organization_id: self.header.operator.organization_id,
            local_civil_year: local_civil_year(&self.header.timezone, self.body.occurred_at.start)?,
            incident_number_nfc_bytes: self.body.human_incident_number.as_bytes().to_vec(),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), SchemaError> {
        self.header.validate()?;
        local_civil_year(&self.header.timezone, self.body.occurred_at.start)?;
        validate_char_count(
            &self.body.human_incident_number,
            1,
            64,
            "humanIncidentNumber",
        )?;
        if self
            .body
            .occurred_at
            .end
            .is_some_and(|end| end < self.body.occurred_at.start)
        {
            return Err(SchemaError::invalid(
                "EA-SCHEMA-INTERVAL",
                Some("occurredAt"),
            ));
        }
        validate_keyword(&self.body.keyword)?;
        validate_location(&self.body.location)?;
        if self.body.personnel.len() > 200 {
            return Err(SchemaError::invalid("EA-SCHEMA-COUNT", Some("personnel")));
        }
        for snapshot in &self.body.personnel {
            snapshot.validate()?;
        }
        validate_empty_reason(
            self.body.personnel.is_empty(),
            self.body.personnel_empty_reason.as_deref(),
            "personnelEmptyReason",
        )?;
        if self.body.vehicles.len() > 100 {
            return Err(SchemaError::invalid("EA-SCHEMA-COUNT", Some("vehicles")));
        }
        for snapshot in &self.body.vehicles {
            snapshot.validate()?;
        }
        validate_empty_reason(
            self.body.vehicles.is_empty(),
            self.body.vehicles_empty_reason.as_deref(),
            "vehiclesEmptyReason",
        )?;
        if let Some(notes) = &self.body.notes {
            validate_char_count(notes, 0, 20_000, "notes")?;
        }
        if self.body.external_organizations.len() > 100 {
            return Err(SchemaError::invalid(
                "EA-SCHEMA-COUNT",
                Some("externalOrganizations"),
            ));
        }
        for organization in &self.body.external_organizations {
            organization.validate()?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for IncidentV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("IncidentV1")
    }
}

pub struct IncidentUniquenessKey {
    organization_id: OrganizationId,
    local_civil_year: i16,
    incident_number_nfc_bytes: Vec<u8>,
}

impl IncidentUniquenessKey {
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn local_civil_year(&self) -> i16 {
        self.local_civil_year
    }

    #[must_use]
    pub fn incident_number_nfc_bytes(&self) -> &[u8] {
        &self.incident_number_nfc_bytes
    }
}

pub struct OccurredAtV1 {
    pub(crate) start: UnixMillis,
    pub(crate) end: Option<UnixMillis>,
}

impl OccurredAtV1 {
    pub fn new(start: UnixMillis, end: Option<UnixMillis>) -> Result<Self, SchemaError> {
        if end.is_some_and(|end| end < start) {
            return Err(SchemaError::invalid(
                "EA-SCHEMA-INTERVAL",
                Some("occurredAt"),
            ));
        }
        Ok(Self { start, end })
    }

    #[must_use]
    pub const fn start(&self) -> UnixMillis {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> Option<UnixMillis> {
        self.end
    }
}

impl core::fmt::Debug for OccurredAtV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OccurredAtV1")
    }
}

pub enum KeywordV1 {
    FreeText(String),
    Reference {
        reference_id: String,
        display_text: String,
    },
}

impl KeywordV1 {
    pub fn free_text(value: impl Into<String>) -> Result<Self, SchemaError> {
        let value = normalize_text(value);
        validate_char_count(&value, 1, 128, "keyword")?;
        Ok(Self::FreeText(value))
    }

    pub fn reference(
        reference_id: impl Into<String>,
        display_text: impl Into<String>,
    ) -> Result<Self, SchemaError> {
        let reference_id = normalize_text(reference_id);
        let display_text = normalize_text(display_text);
        validate_char_count(&reference_id, 1, 128, "keyword.referenceId")?;
        validate_char_count(&display_text, 1, 128, "keyword.displayText")?;
        Ok(Self::Reference {
            reference_id,
            display_text,
        })
    }

    #[must_use]
    pub fn as_free_text(&self) -> Option<&str> {
        match self {
            Self::FreeText(value) => Some(value),
            Self::Reference { .. } => None,
        }
    }

    #[must_use]
    pub fn as_reference(&self) -> Option<(&str, &str)> {
        match self {
            Self::Reference {
                reference_id,
                display_text,
            } => Some((reference_id, display_text)),
            Self::FreeText(_) => None,
        }
    }
}

pub enum LocationV1 {
    FreeText {
        free_text: String,
        coordinates: Option<CoordinatesV1>,
    },
    Structured {
        address: StructuredAddressV1,
        coordinates: Option<CoordinatesV1>,
    },
}

impl LocationV1 {
    pub fn free_text(
        free_text: impl Into<String>,
        coordinates: Option<CoordinatesV1>,
    ) -> Result<Self, SchemaError> {
        Ok(Self::FreeText {
            free_text: normalize_text(free_text),
            coordinates,
        })
    }

    pub fn structured(
        address: StructuredAddressV1,
        coordinates: Option<CoordinatesV1>,
    ) -> Result<Self, SchemaError> {
        address.validate()?;
        Ok(Self::Structured {
            address,
            coordinates,
        })
    }

    #[must_use]
    pub fn as_free_text(&self) -> Option<(&str, Option<&CoordinatesV1>)> {
        match self {
            Self::FreeText {
                free_text,
                coordinates,
            } => Some((free_text, coordinates.as_ref())),
            Self::Structured { .. } => None,
        }
    }

    #[must_use]
    pub fn as_structured(&self) -> Option<(&StructuredAddressV1, Option<&CoordinatesV1>)> {
        match self {
            Self::Structured {
                address,
                coordinates,
            } => Some((address, coordinates.as_ref())),
            Self::FreeText { .. } => None,
        }
    }
}

pub struct CoordinatesV1 {
    pub(crate) lat_e7: i32,
    pub(crate) lon_e7: i32,
}

impl CoordinatesV1 {
    pub fn new(lat_e7: i32, lon_e7: i32) -> Result<Self, SchemaError> {
        if !(-900_000_000..=900_000_000).contains(&lat_e7)
            || !(-1_800_000_000..=1_800_000_000).contains(&lon_e7)
        {
            return Err(SchemaError::invalid(
                "EA-SCHEMA-COORDINATES",
                Some("location.coordinates"),
            ));
        }
        Ok(Self { lat_e7, lon_e7 })
    }

    #[must_use]
    pub const fn lat_e7(&self) -> i32 {
        self.lat_e7
    }

    #[must_use]
    pub const fn lon_e7(&self) -> i32 {
        self.lon_e7
    }
}

pub struct StructuredAddressV1 {
    pub(crate) street: Option<String>,
    pub(crate) house_number: Option<String>,
    pub(crate) postal_code: Option<String>,
    pub(crate) locality: Option<String>,
    pub(crate) admin_area: Option<String>,
    pub(crate) country_code: Option<String>,
}

impl StructuredAddressV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        street: Option<String>,
        house_number: Option<String>,
        postal_code: Option<String>,
        locality: Option<String>,
        admin_area: Option<String>,
        country_code: Option<String>,
    ) -> Result<Self, SchemaError> {
        let value = Self {
            street: street.map(normalize_text),
            house_number: house_number.map(normalize_text),
            postal_code: postal_code.map(normalize_text),
            locality: locality.map(normalize_text),
            admin_area: admin_area.map(normalize_text),
            country_code: country_code.map(normalize_text),
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub fn street(&self) -> Option<&str> {
        self.street.as_deref()
    }

    #[must_use]
    pub fn house_number(&self) -> Option<&str> {
        self.house_number.as_deref()
    }

    #[must_use]
    pub fn postal_code(&self) -> Option<&str> {
        self.postal_code.as_deref()
    }

    #[must_use]
    pub fn locality(&self) -> Option<&str> {
        self.locality.as_deref()
    }

    #[must_use]
    pub fn admin_area(&self) -> Option<&str> {
        self.admin_area.as_deref()
    }

    #[must_use]
    pub fn country_code(&self) -> Option<&str> {
        self.country_code.as_deref()
    }

    fn validate(&self) -> Result<(), SchemaError> {
        if [
            &self.street,
            &self.house_number,
            &self.postal_code,
            &self.locality,
            &self.admin_area,
            &self.country_code,
        ]
        .iter()
        .all(|value| value.is_none())
        {
            return Err(SchemaError::invalid(
                "EA-SCHEMA-STRUCTURED-ADDRESS",
                Some("location.structuredAddress"),
            ));
        }
        Ok(())
    }
}

pub enum MasterDataRevisionV1 {
    RevisionNumber(u64),
    ChangedAt(UnixMillis),
}

impl MasterDataRevisionV1 {
    #[must_use]
    pub const fn revision_number(&self) -> Option<u64> {
        match self {
            Self::RevisionNumber(value) => Some(*value),
            Self::ChangedAt(_) => None,
        }
    }

    #[must_use]
    pub const fn changed_at(&self) -> Option<UnixMillis> {
        match self {
            Self::ChangedAt(value) => Some(*value),
            Self::RevisionNumber(_) => None,
        }
    }
}

pub struct ImportedProvenanceV1 {
    pub(crate) source_id: String,
    pub(crate) source_format_version: u64,
    pub(crate) import_protocol_hash: ObjectHash,
}

impl ImportedProvenanceV1 {
    pub fn new(
        source_id: impl Into<String>,
        source_format_version: u64,
        import_protocol_hash: ObjectHash,
    ) -> Result<Self, SchemaError> {
        let value = Self {
            source_id: normalize_text(source_id),
            source_format_version,
            import_protocol_hash,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), SchemaError> {
        validate_snapshot_text(&self.source_id, "importedProvenance.sourceId")
    }

    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    #[must_use]
    pub const fn source_format_version(&self) -> u64 {
        self.source_format_version
    }

    #[must_use]
    pub const fn import_protocol_hash(&self) -> ObjectHash {
        self.import_protocol_hash
    }
}

pub enum PersonnelSnapshotV1 {
    Master {
        master_personnel_id: String,
        display_name: String,
        role_or_function: Option<String>,
        revision: MasterDataRevisionV1,
        imported_provenance: Option<ImportedProvenanceV1>,
    },
    AdHoc {
        display_name: String,
        role_or_function: Option<String>,
    },
}

impl PersonnelSnapshotV1 {
    pub fn master(
        master_personnel_id: impl Into<String>,
        display_name: impl Into<String>,
        role_or_function: Option<String>,
        revision: MasterDataRevisionV1,
        imported_provenance: Option<ImportedProvenanceV1>,
    ) -> Result<Self, SchemaError> {
        let value = Self::Master {
            master_personnel_id: normalize_text(master_personnel_id),
            display_name: normalize_text(display_name),
            role_or_function: role_or_function.map(normalize_text),
            revision,
            imported_provenance,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn ad_hoc(
        display_name: impl Into<String>,
        role_or_function: Option<String>,
    ) -> Result<Self, SchemaError> {
        let value = Self::AdHoc {
            display_name: normalize_text(display_name),
            role_or_function: role_or_function.map(normalize_text),
        };
        value.validate()?;
        Ok(value)
    }

    /// Die Textregel der Momentaufnahme: Kennung und Anzeigename 1..200
    /// NFC-Zeichen, die optionale Funktion, WENN vorhanden, ebenso.
    ///
    /// Der Dekodierpfad baut die Varianten direkt und ruft dieselbe Regel
    /// ueber [`IncidentV1::validate`]; beide Wege nehmen dieselbe Menge an.
    pub(crate) fn validate(&self) -> Result<(), SchemaError> {
        match self {
            Self::Master {
                master_personnel_id,
                display_name,
                role_or_function,
                imported_provenance,
                ..
            } => {
                validate_snapshot_text(master_personnel_id, "personnel.masterPersonnelId")?;
                validate_snapshot_text(display_name, "personnel.displayName")?;
                validate_optional_snapshot_text(
                    role_or_function.as_deref(),
                    "personnel.roleOrFunction",
                )?;
                if let Some(provenance) = imported_provenance {
                    provenance.validate()?;
                }
                Ok(())
            }
            Self::AdHoc {
                display_name,
                role_or_function,
            } => {
                validate_snapshot_text(display_name, "personnel.displayName")?;
                validate_optional_snapshot_text(
                    role_or_function.as_deref(),
                    "personnel.roleOrFunction",
                )
            }
        }
    }

    #[must_use]
    pub const fn is_master(&self) -> bool {
        matches!(self, Self::Master { .. })
    }

    #[must_use]
    pub fn master_personnel_id(&self) -> Option<&str> {
        match self {
            Self::Master {
                master_personnel_id,
                ..
            } => Some(master_personnel_id),
            Self::AdHoc { .. } => None,
        }
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        match self {
            Self::Master { display_name, .. } | Self::AdHoc { display_name, .. } => display_name,
        }
    }

    #[must_use]
    pub fn role_or_function(&self) -> Option<&str> {
        match self {
            Self::Master {
                role_or_function, ..
            }
            | Self::AdHoc {
                role_or_function, ..
            } => role_or_function.as_deref(),
        }
    }

    #[must_use]
    pub const fn revision(&self) -> Option<&MasterDataRevisionV1> {
        match self {
            Self::Master { revision, .. } => Some(revision),
            Self::AdHoc { .. } => None,
        }
    }

    #[must_use]
    pub const fn imported_provenance(&self) -> Option<&ImportedProvenanceV1> {
        match self {
            Self::Master {
                imported_provenance,
                ..
            } => imported_provenance.as_ref(),
            Self::AdHoc { .. } => None,
        }
    }
}

pub enum VehicleSnapshotV1 {
    Master {
        master_vehicle_id: String,
        display_name: String,
        radio_call_sign: Option<String>,
        license_plate: Option<String>,
        revision: MasterDataRevisionV1,
        imported_provenance: Option<ImportedProvenanceV1>,
    },
    AdHoc {
        display_name: String,
        radio_call_sign: Option<String>,
        license_plate: Option<String>,
    },
}

impl VehicleSnapshotV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn master(
        master_vehicle_id: impl Into<String>,
        display_name: impl Into<String>,
        radio_call_sign: Option<String>,
        license_plate: Option<String>,
        revision: MasterDataRevisionV1,
        imported_provenance: Option<ImportedProvenanceV1>,
    ) -> Result<Self, SchemaError> {
        let value = Self::Master {
            master_vehicle_id: normalize_text(master_vehicle_id),
            display_name: normalize_text(display_name),
            radio_call_sign: radio_call_sign.map(normalize_text),
            license_plate: license_plate.map(normalize_text),
            revision,
            imported_provenance,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn ad_hoc(
        display_name: impl Into<String>,
        radio_call_sign: Option<String>,
        license_plate: Option<String>,
    ) -> Result<Self, SchemaError> {
        let value = Self::AdHoc {
            display_name: normalize_text(display_name),
            radio_call_sign: radio_call_sign.map(normalize_text),
            license_plate: license_plate.map(normalize_text),
        };
        value.validate()?;
        Ok(value)
    }

    /// Wie [`PersonnelSnapshotV1::validate`]: Kennung und Bezeichnung 1..200
    /// NFC-Zeichen, Funkrufname und Kennzeichen, WENN vorhanden, ebenso.
    pub(crate) fn validate(&self) -> Result<(), SchemaError> {
        match self {
            Self::Master {
                master_vehicle_id,
                display_name,
                radio_call_sign,
                license_plate,
                imported_provenance,
                ..
            } => {
                validate_snapshot_text(master_vehicle_id, "vehicles.masterVehicleId")?;
                validate_snapshot_text(display_name, "vehicles.displayName")?;
                validate_optional_snapshot_text(
                    radio_call_sign.as_deref(),
                    "vehicles.radioCallSign",
                )?;
                validate_optional_snapshot_text(license_plate.as_deref(), "vehicles.licensePlate")?;
                if let Some(provenance) = imported_provenance {
                    provenance.validate()?;
                }
                Ok(())
            }
            Self::AdHoc {
                display_name,
                radio_call_sign,
                license_plate,
            } => {
                validate_snapshot_text(display_name, "vehicles.displayName")?;
                validate_optional_snapshot_text(
                    radio_call_sign.as_deref(),
                    "vehicles.radioCallSign",
                )?;
                validate_optional_snapshot_text(license_plate.as_deref(), "vehicles.licensePlate")
            }
        }
    }

    #[must_use]
    pub const fn is_master(&self) -> bool {
        matches!(self, Self::Master { .. })
    }

    #[must_use]
    pub fn master_vehicle_id(&self) -> Option<&str> {
        match self {
            Self::Master {
                master_vehicle_id, ..
            } => Some(master_vehicle_id),
            Self::AdHoc { .. } => None,
        }
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        match self {
            Self::Master { display_name, .. } | Self::AdHoc { display_name, .. } => display_name,
        }
    }

    #[must_use]
    pub fn radio_call_sign(&self) -> Option<&str> {
        match self {
            Self::Master {
                radio_call_sign, ..
            }
            | Self::AdHoc {
                radio_call_sign, ..
            } => radio_call_sign.as_deref(),
        }
    }

    #[must_use]
    pub fn license_plate(&self) -> Option<&str> {
        match self {
            Self::Master { license_plate, .. } | Self::AdHoc { license_plate, .. } => {
                license_plate.as_deref()
            }
        }
    }

    #[must_use]
    pub const fn revision(&self) -> Option<&MasterDataRevisionV1> {
        match self {
            Self::Master { revision, .. } => Some(revision),
            Self::AdHoc { .. } => None,
        }
    }

    #[must_use]
    pub const fn imported_provenance(&self) -> Option<&ImportedProvenanceV1> {
        match self {
            Self::Master {
                imported_provenance,
                ..
            } => imported_provenance.as_ref(),
            Self::AdHoc { .. } => None,
        }
    }
}

pub struct ExternalOrganizationV1 {
    pub(crate) id: Option<String>,
    pub(crate) display_name: String,
}

impl ExternalOrganizationV1 {
    pub fn new(id: Option<&str>, display_name: impl Into<String>) -> Result<Self, SchemaError> {
        let value = Self {
            id: id.map(normalize_text),
            display_name: normalize_text(display_name),
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), SchemaError> {
        validate_optional_snapshot_text(self.id.as_deref(), "externalOrganizations.id")?;
        validate_snapshot_text(&self.display_name, "externalOrganizations.displayName")
    }

    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}
pub struct AmendmentV1 {
    pub(crate) header: CommonHeaderV1,
    pub(crate) original_incident_number: String,
    pub(crate) original_record_id: RecordId,
    pub(crate) original_entry_hash: ea_types::EntryHash,
    pub(crate) original_sequence: ea_types::ChainSequence,
    pub(crate) reason: String,
    pub(crate) changes: Vec<AmendmentChangeV1>,
}

impl AmendmentV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        header: CommonHeaderV1,
        original_incident_number: impl Into<String>,
        original_record_id: RecordId,
        original_entry_hash: ea_types::EntryHash,
        original_sequence: ea_types::ChainSequence,
        reason: impl Into<String>,
        changes: Vec<AmendmentChangeV1>,
    ) -> Result<Self, SchemaError> {
        let value = Self {
            header,
            original_incident_number: normalize_text(original_incident_number),
            original_record_id,
            original_entry_hash,
            original_sequence,
            reason: normalize_text(reason),
            changes,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn header(&self) -> &CommonHeaderV1 {
        &self.header
    }

    #[must_use]
    pub fn original_incident_number(&self) -> &str {
        &self.original_incident_number
    }

    #[must_use]
    pub const fn original_record_id(&self) -> RecordId {
        self.original_record_id
    }

    #[must_use]
    pub const fn original_entry_hash(&self) -> ea_types::EntryHash {
        self.original_entry_hash
    }

    #[must_use]
    pub const fn original_sequence(&self) -> ea_types::ChainSequence {
        self.original_sequence
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub fn changes(&self) -> &[AmendmentChangeV1] {
        &self.changes
    }

    fn validate(&self) -> Result<(), SchemaError> {
        self.header.validate()?;
        validate_char_count(
            &self.original_incident_number,
            1,
            64,
            "amendment.originalIncidentNumber",
        )?;
        validate_uuid_v7(self.original_record_id, "amendment.originalRecordId")?;
        validate_char_count(&self.reason, 1, usize::MAX, "amendment.reason")?;
        if self.changes.is_empty() {
            return Err(SchemaError::invalid(
                "EA-SCHEMA-NONEMPTY",
                Some("amendment.changes"),
            ));
        }
        for change in &self.changes {
            change.validate()?;
        }
        Ok(())
    }
}

pub struct AmendmentChangeV1 {
    pub(crate) field_path: String,
    pub(crate) change_text: String,
}

impl AmendmentChangeV1 {
    pub fn new(
        field_path: impl Into<String>,
        change_text: impl Into<String>,
    ) -> Result<Self, SchemaError> {
        let value = Self {
            field_path: normalize_text(field_path),
            change_text: normalize_text(change_text),
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub fn field_path(&self) -> &str {
        &self.field_path
    }

    #[must_use]
    pub fn change_text(&self) -> &str {
        &self.change_text
    }

    fn validate(&self) -> Result<(), SchemaError> {
        validate_char_count(
            &self.field_path,
            1,
            usize::MAX,
            "amendment.changes.fieldPath",
        )?;
        validate_char_count(
            &self.change_text,
            1,
            usize::MAX,
            "amendment.changes.changeText",
        )
    }
}
pub struct KeyTransitionV1 {
    pub(crate) header: CommonHeaderV1,
    pub(crate) writer_transition_event_object_hash: ObjectHash,
    pub(crate) organizational_reason: String,
}

impl KeyTransitionV1 {
    pub fn new(
        header: CommonHeaderV1,
        writer_transition_event_object_hash: ObjectHash,
        organizational_reason: impl Into<String>,
    ) -> Result<Self, SchemaError> {
        let value = Self {
            header,
            writer_transition_event_object_hash,
            organizational_reason: normalize_text(organizational_reason),
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn header(&self) -> &CommonHeaderV1 {
        &self.header
    }

    #[must_use]
    pub const fn writer_transition_event_object_hash(&self) -> ObjectHash {
        self.writer_transition_event_object_hash
    }

    #[must_use]
    pub fn organizational_reason(&self) -> &str {
        &self.organizational_reason
    }

    fn validate(&self) -> Result<(), SchemaError> {
        self.header.validate()?;
        validate_char_count(
            &self.organizational_reason,
            1,
            usize::MAX,
            "keyTransition.organizationalReason",
        )
    }
}
pub struct DestructionEvidenceV1 {
    pub(crate) header: CommonHeaderV1,
    pub(crate) destruction_id: ea_types::DestructionId,
    pub(crate) authorization_object_hash: ObjectHash,
    pub(crate) scope_code: u64,
    pub(crate) targets: Vec<DestructionTargetV1>,
    pub(crate) execution_results: Vec<DestructionExecutionResultV1>,
    pub(crate) stub_bindings: Vec<DestructionStubBindingV1>,
    pub(crate) replica_results: Vec<ReplicaResultV1>,
}

impl DestructionEvidenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        header: CommonHeaderV1,
        destruction_id: ea_types::DestructionId,
        authorization_object_hash: ObjectHash,
        scope_code: u64,
        targets: Vec<DestructionTargetV1>,
        execution_results: Vec<DestructionExecutionResultV1>,
        stub_bindings: Vec<DestructionStubBindingV1>,
        replica_results: Vec<ReplicaResultV1>,
    ) -> Result<Self, SchemaError> {
        let value = Self {
            header,
            destruction_id,
            authorization_object_hash,
            scope_code,
            targets,
            execution_results,
            stub_bindings,
            replica_results,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn header(&self) -> &CommonHeaderV1 {
        &self.header
    }

    #[must_use]
    pub const fn destruction_id(&self) -> ea_types::DestructionId {
        self.destruction_id
    }

    #[must_use]
    pub const fn authorization_object_hash(&self) -> ObjectHash {
        self.authorization_object_hash
    }

    #[must_use]
    pub const fn scope_code(&self) -> u64 {
        self.scope_code
    }

    #[must_use]
    pub fn targets(&self) -> &[DestructionTargetV1] {
        &self.targets
    }

    #[must_use]
    pub fn execution_results(&self) -> &[DestructionExecutionResultV1] {
        &self.execution_results
    }

    #[must_use]
    pub fn stub_bindings(&self) -> &[DestructionStubBindingV1] {
        &self.stub_bindings
    }

    #[must_use]
    pub fn replica_results(&self) -> &[ReplicaResultV1] {
        &self.replica_results
    }

    fn validate(&self) -> Result<(), SchemaError> {
        self.header.validate()?;
        require_nonempty(&self.targets, "destructionEvidence.targets")?;
        require_strictly_sorted(
            &self.targets,
            |value| *value.entry_hash.as_bytes(),
            "destructionEvidence.targets",
        )?;
        require_nonempty(
            &self.execution_results,
            "destructionEvidence.executionResults",
        )?;
        require_strictly_sorted(
            &self.execution_results,
            |value| *value.entry_hash.as_bytes(),
            "destructionEvidence.executionResults",
        )?;
        require_strictly_sorted(
            &self.stub_bindings,
            |value| *value.entry_hash.as_bytes(),
            "destructionEvidence.stubBindings",
        )?;
        require_nonempty(&self.replica_results, "destructionEvidence.replicaResults")?;
        require_strictly_sorted(
            &self.replica_results,
            |value| *value.replica_id.as_bytes(),
            "destructionEvidence.replicaResults",
        )
    }
}

pub struct DestructionTargetV1 {
    pub(crate) entry_hash: ea_types::EntryHash,
    pub(crate) chain_sequence: ea_types::ChainSequence,
}

impl DestructionTargetV1 {
    #[must_use]
    pub const fn new(
        entry_hash: ea_types::EntryHash,
        chain_sequence: ea_types::ChainSequence,
    ) -> Self {
        Self {
            entry_hash,
            chain_sequence,
        }
    }

    #[must_use]
    pub const fn entry_hash(&self) -> ea_types::EntryHash {
        self.entry_hash
    }

    #[must_use]
    pub const fn chain_sequence(&self) -> ea_types::ChainSequence {
        self.chain_sequence
    }
}

pub struct DestructionExecutionResultV1 {
    pub(crate) entry_hash: ea_types::EntryHash,
    pub(crate) confirmed: bool,
    pub(crate) result_code: u64,
}

impl DestructionExecutionResultV1 {
    #[must_use]
    pub const fn new(entry_hash: ea_types::EntryHash, confirmed: bool, result_code: u64) -> Self {
        Self {
            entry_hash,
            confirmed,
            result_code,
        }
    }

    #[must_use]
    pub const fn entry_hash(&self) -> ea_types::EntryHash {
        self.entry_hash
    }

    #[must_use]
    pub const fn confirmed(&self) -> bool {
        self.confirmed
    }

    #[must_use]
    pub const fn result_code(&self) -> u64 {
        self.result_code
    }
}

pub struct DestructionStubBindingV1 {
    pub(crate) entry_hash: ea_types::EntryHash,
    pub(crate) stub_object_hash: ObjectHash,
}

impl DestructionStubBindingV1 {
    #[must_use]
    pub const fn new(entry_hash: ea_types::EntryHash, stub_object_hash: ObjectHash) -> Self {
        Self {
            entry_hash,
            stub_object_hash,
        }
    }

    #[must_use]
    pub const fn entry_hash(&self) -> ea_types::EntryHash {
        self.entry_hash
    }

    #[must_use]
    pub const fn stub_object_hash(&self) -> ObjectHash {
        self.stub_object_hash
    }
}

pub struct ReplicaResultV1 {
    pub(crate) replica_id: ea_types::Id16,
    pub(crate) state: ReplicaStateV1,
}

impl ReplicaResultV1 {
    #[must_use]
    pub const fn successful(replica_id: ea_types::Id16, attestation: ObjectHash) -> Self {
        Self {
            replica_id,
            state: ReplicaStateV1::Successful {
                deletion_attestation_object_hash: attestation,
            },
        }
    }

    #[must_use]
    pub const fn pending(replica_id: ea_types::Id16) -> Self {
        Self {
            replica_id,
            state: ReplicaStateV1::Pending,
        }
    }

    #[must_use]
    pub const fn unreachable(replica_id: ea_types::Id16) -> Self {
        Self {
            replica_id,
            state: ReplicaStateV1::Unreachable,
        }
    }

    #[must_use]
    pub const fn replica_id(&self) -> ea_types::Id16 {
        self.replica_id
    }

    #[must_use]
    pub const fn state(&self) -> &ReplicaStateV1 {
        &self.state
    }
}

pub enum ReplicaStateV1 {
    Successful {
        deletion_attestation_object_hash: ObjectHash,
    },
    Pending,
    Unreachable,
}

impl ReplicaStateV1 {
    #[must_use]
    pub const fn deletion_attestation_object_hash(&self) -> Option<ObjectHash> {
        match self {
            Self::Successful {
                deletion_attestation_object_hash,
            } => Some(*deletion_attestation_object_hash),
            Self::Pending | Self::Unreachable => None,
        }
    }

    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    #[must_use]
    pub const fn is_unreachable(&self) -> bool {
        matches!(self, Self::Unreachable)
    }
}

fn normalize_text(value: impl Into<String>) -> String {
    value.into().nfc().collect()
}

fn require_nonempty<T>(values: &[T], field: &'static str) -> Result<(), SchemaError> {
    if values.is_empty() {
        return Err(SchemaError::invalid("EA-SCHEMA-NONEMPTY", Some(field)));
    }
    Ok(())
}

fn require_strictly_sorted<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    field: &'static str,
) -> Result<(), SchemaError> {
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(SchemaError::invalid("EA-SCHEMA-SORT-UNIQUE", Some(field)));
    }
    Ok(())
}

fn validate_char_count(
    value: &str,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), SchemaError> {
    if !value.nfc().eq(value.chars()) {
        return Err(SchemaError::invalid("EA-SCHEMA-NON-NFC", Some(field)));
    }
    let count = value.chars().count();
    if !(minimum..=maximum).contains(&count) {
        return Err(SchemaError::invalid("EA-SCHEMA-LENGTH", Some(field)));
    }
    Ok(())
}

/// Obergrenze fuer JEDEN Text einer Stammdaten- oder Organisationsmomentaufnahme.
///
/// Deckungsgleich mit `MAX_FIELD_CHARS` des CSV-Imports in `ea-draft`: eine
/// angenommene Importzeile ergibt damit immer eine gueltige Momentaufnahme,
/// und die Grenze ist an EINER Stelle der Stufe 1 festgelegt.
pub const SNAPSHOT_TEXT_MAX_CHARS_V1: usize = 200;

fn validate_snapshot_text(value: &str, field: &'static str) -> Result<(), SchemaError> {
    validate_char_count(value, 1, SNAPSHOT_TEXT_MAX_CHARS_V1, field)
}

/// `None` ist die Abwesenheit; `Some("")` ist KEINE zweite Schreibweise dafuer
/// und wird abgelehnt, damit ein Wert genau eine Darstellung hat.
fn validate_optional_snapshot_text(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), SchemaError> {
    value.map_or(Ok(()), |value| validate_snapshot_text(value, field))
}

fn validate_uuid_v7(record_id: RecordId, field: &'static str) -> Result<(), SchemaError> {
    let bytes = record_id.as_bytes();
    if bytes[6] >> 4 != 7 || bytes[8] & 0xc0 != 0x80 {
        return Err(SchemaError::invalid("EA-SCHEMA-UUID-V7", Some(field)));
    }
    Ok(())
}

fn validate_keyword(keyword: &KeywordV1) -> Result<(), SchemaError> {
    match keyword {
        KeywordV1::FreeText(value) => validate_char_count(value, 1, 128, "keyword"),
        KeywordV1::Reference {
            reference_id,
            display_text,
        } => {
            validate_char_count(reference_id, 1, 128, "keyword.referenceId")?;
            validate_char_count(display_text, 1, 128, "keyword.displayText")
        }
    }
}

fn validate_location(location: &LocationV1) -> Result<(), SchemaError> {
    match location {
        LocationV1::FreeText {
            free_text,
            coordinates,
        } => {
            if !free_text.nfc().eq(free_text.chars()) {
                return Err(SchemaError::invalid(
                    "EA-SCHEMA-NON-NFC",
                    Some("location.freeText"),
                ));
            }
            if let Some(coordinates) = coordinates {
                CoordinatesV1::new(coordinates.lat_e7, coordinates.lon_e7)?;
            }
        }
        LocationV1::Structured {
            address,
            coordinates,
        } => {
            address.validate()?;
            if let Some(coordinates) = coordinates {
                CoordinatesV1::new(coordinates.lat_e7, coordinates.lon_e7)?;
            }
        }
    }
    Ok(())
}

fn validate_empty_reason(
    list_is_empty: bool,
    reason: Option<&str>,
    field: &'static str,
) -> Result<(), SchemaError> {
    match (list_is_empty, reason) {
        (true, Some(reason)) if !reason.is_empty() && reason.nfc().eq(reason.chars()) => Ok(()),
        (false, None) => Ok(()),
        _ => Err(SchemaError::invalid("EA-SCHEMA-LIST-REASON", Some(field))),
    }
}

fn local_civil_year(timezone_name: &str, start: UnixMillis) -> Result<i16, SchemaError> {
    let timestamp = Timestamp::from_millisecond(start.get())
        .map_err(|_| SchemaError::invalid("EA-SCHEMA-TIMESTAMP-RANGE", Some("occurredAt.start")))?;
    let timezone = TimeZoneDatabase::bundled()
        .get(timezone_name)
        .map_err(|_| SchemaError::invalid("EA-SCHEMA-TIMEZONE-UNKNOWN", Some("timezone")))?;
    Ok(timestamp.to_zoned(timezone).year())
}
