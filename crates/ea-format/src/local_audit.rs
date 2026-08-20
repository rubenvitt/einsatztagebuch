use core::fmt;

use ea_cbor::{ParserLimits, validate};
use ea_crypto::{ContentType, parse_cose_sign1, validate_unsigned_protocol_core};
use ea_types::{
    ChainSequence, DeviceId, EntryHash, EventId, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};
use minicbor::{Decoder, Encoder};

use crate::object::{
    FormatError, bytes_exact, exact_item, expect_array_length, expect_empty_array, finish,
    optional_bytes_exact,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IndependentTimeKindV1 {
    Receipt = 0,
    Checkpoint = 1,
    Tsa = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ClockReleaseJustificationV1 {
    OperatorVerifiedWallClock = 0,
    PlatformTimeSourceRecovery = 1,
    HardwareClockMaintenance = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LocalAuditOutcomeV1 {
    Failed = 0,
    Accepted = 1,
    Completed = 2,
}

pub struct IndependentTimeReferenceV1 {
    kind: IndependentTimeKindV1,
    object_hash: ObjectHash,
    verified_time: UnixMillis,
}

impl IndependentTimeReferenceV1 {
    #[must_use]
    pub const fn kind(&self) -> IndependentTimeKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn verified_time(&self) -> UnixMillis {
        self.verified_time
    }
}

pub struct ClockReleaseContextV1 {
    trusted_time_floor: UnixMillis,
    observed_os_wall_clock: UnixMillis,
    max_future_clock_skew_ms: u64,
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    guard_policy_object_hash: ObjectHash,
    independent_reference: IndependentTimeReferenceV1,
    justification: ClockReleaseJustificationV1,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClockReleaseContextV1 {
    #[must_use]
    pub const fn trusted_time_floor(&self) -> UnixMillis {
        self.trusted_time_floor
    }

    #[must_use]
    pub const fn observed_os_wall_clock(&self) -> UnixMillis {
        self.observed_os_wall_clock
    }

    #[must_use]
    pub const fn max_future_clock_skew_ms(&self) -> u64 {
        self.max_future_clock_skew_ms
    }

    #[must_use]
    pub const fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }

    #[must_use]
    pub const fn registry_head_hash(&self) -> ObjectHash {
        self.registry_head_hash
    }

    #[must_use]
    pub const fn guard_policy_object_hash(&self) -> ObjectHash {
        self.guard_policy_object_hash
    }

    #[must_use]
    pub const fn independent_reference(&self) -> &IndependentTimeReferenceV1 {
        &self.independent_reference
    }

    #[must_use]
    pub const fn justification(&self) -> ClockReleaseJustificationV1 {
        self.justification
    }

    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

pub struct ClockReleaseAuditV1 {
    event_id: EventId,
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    admin_operator_binding_object_hash: ObjectHash,
    signer_certificate_object_hash: ObjectHash,
    outcome: LocalAuditOutcomeV1,
    effective_now: UnixMillis,
    context: ClockReleaseContextV1,
    nonce: [u8; 32],
    exact_core: Vec<u8>,
    exact_cose: Vec<u8>,
    signature: Vec<u8>,
}

impl ClockReleaseAuditV1 {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    #[must_use]
    pub const fn admin_operator_binding_object_hash(&self) -> ObjectHash {
        self.admin_operator_binding_object_hash
    }

    #[must_use]
    pub const fn signer_certificate_object_hash(&self) -> ObjectHash {
        self.signer_certificate_object_hash
    }

    #[must_use]
    pub const fn outcome(&self) -> LocalAuditOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub const fn effective_now(&self) -> UnixMillis {
        self.effective_now
    }

    #[must_use]
    pub const fn context(&self) -> &ClockReleaseContextV1 {
        &self.context
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    #[must_use]
    pub fn exact_core(&self) -> &[u8] {
        &self.exact_core
    }

    #[must_use]
    pub fn exact_cose(&self) -> &[u8] {
        &self.exact_cose
    }

    #[must_use]
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }
}

pub fn decode_clock_release_audit(exact_bytes: &[u8]) -> Result<ClockReleaseAuditV1, FormatError> {
    validate(exact_bytes, ParserLimits::V1)?;
    let mut decoder = Decoder::new(exact_bytes);
    expect_array_length(&mut decoder, 2)?;
    let exact_core = exact_item(exact_bytes, &mut decoder)?;
    let core = decode_clock_release_core(exact_core)?;
    let exact_cose = exact_item(exact_bytes, &mut decoder)?;
    finish(&decoder, exact_bytes)?;

    let parsed = parse_cose_sign1(exact_cose, &[]).map_err(|_| FormatError::Cose)?;
    if parsed.content_type() != ContentType::LocalAuditCbor
        || parsed.payload() != exact_core
        || parsed
            .certificate_hash()
            .is_none_or(|hash| hash.as_bytes() != core.signer_certificate_object_hash.as_bytes())
    {
        return Err(FormatError::Cose);
    }

    Ok(ClockReleaseAuditV1 {
        event_id: core.event_id,
        organization_id: core.organization_id,
        target_device_id: core.target_device_id,
        admin_operator_binding_object_hash: core.admin_operator_binding_object_hash,
        signer_certificate_object_hash: core.signer_certificate_object_hash,
        outcome: core.outcome,
        effective_now: core.effective_now,
        context: core.context,
        nonce: core.nonce,
        exact_core: exact_core.to_vec(),
        exact_cose: exact_cose.to_vec(),
        signature: parsed.signature_bytes().to_vec(),
    })
}

struct DecodedClockReleaseCore {
    event_id: EventId,
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    admin_operator_binding_object_hash: ObjectHash,
    signer_certificate_object_hash: ObjectHash,
    outcome: LocalAuditOutcomeV1,
    effective_now: UnixMillis,
    context: ClockReleaseContextV1,
    nonce: [u8; 32],
}

fn decode_clock_release_core(input: &[u8]) -> Result<DecodedClockReleaseCore, FormatError> {
    validate_unsigned_protocol_core(ContentType::LocalAuditCbor, input)
        .map_err(|_| FormatError::Shape)?;
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 12)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
        return Err(FormatError::UnknownVersion);
    }
    let event_id = typed_bytes(&mut decoder, 16)?;
    let organization_id = typed_bytes(&mut decoder, 16)?;
    let target_device_id = typed_bytes(&mut decoder, 16)?;
    let admin_operator_binding_object_hash = typed_bytes(&mut decoder, 32)?;
    let signer_certificate_object_hash = typed_bytes(&mut decoder, 32)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 6 {
        return Err(FormatError::TagMismatch);
    }
    let outcome = decode_outcome(decoder.u64().map_err(|_| FormatError::Shape)?)?;
    let effective_now = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    expect_array_length(&mut decoder, 2)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 2 {
        return Err(FormatError::TagMismatch);
    }
    let context = decode_clock_release_context(&mut decoder, effective_now)?;
    let nonce = bytes_exact(&mut decoder, 32)?
        .try_into()
        .map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)?;
    Ok(DecodedClockReleaseCore {
        event_id,
        organization_id,
        target_device_id,
        admin_operator_binding_object_hash,
        signer_certificate_object_hash,
        outcome,
        effective_now,
        context,
        nonce,
    })
}

fn decode_clock_release_context(
    decoder: &mut Decoder<'_>,
    effective_now: UnixMillis,
) -> Result<ClockReleaseContextV1, FormatError> {
    expect_array_length(decoder, 10)?;
    let trusted_time_floor = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    let observed_os_wall_clock = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    let max_future_clock_skew_ms = decoder.u64().map_err(|_| FormatError::Shape)?;
    let registry_version = RegistryVersion::new(decoder.u64().map_err(|_| FormatError::Shape)?);
    let registry_head_hash = typed_bytes(decoder, 32)?;
    let guard_policy_object_hash = typed_bytes(decoder, 32)?;
    expect_array_length(decoder, 3)?;
    let independent_reference = IndependentTimeReferenceV1 {
        kind: decode_independent_time_kind(decoder.u64().map_err(|_| FormatError::Shape)?)?,
        object_hash: typed_bytes(decoder, 32)?,
        verified_time: UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?),
    };
    let justification = decode_justification(decoder.u64().map_err(|_| FormatError::Shape)?)?;
    let issued_at = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    let expires_at = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    if issued_at.get() >= expires_at.get()
        || effective_now.get() != trusted_time_floor.get().max(observed_os_wall_clock.get())
    {
        return Err(FormatError::Shape);
    }
    Ok(ClockReleaseContextV1 {
        trusted_time_floor,
        observed_os_wall_clock,
        max_future_clock_skew_ms,
        registry_version,
        registry_head_hash,
        guard_policy_object_hash,
        independent_reference,
        justification,
        issued_at,
        expires_at,
    })
}

fn decode_independent_time_kind(value: u64) -> Result<IndependentTimeKindV1, FormatError> {
    match value {
        0 => Ok(IndependentTimeKindV1::Receipt),
        1 => Ok(IndependentTimeKindV1::Checkpoint),
        2 => Ok(IndependentTimeKindV1::Tsa),
        _ => Err(FormatError::TagMismatch),
    }
}

fn decode_justification(value: u64) -> Result<ClockReleaseJustificationV1, FormatError> {
    match value {
        0 => Ok(ClockReleaseJustificationV1::OperatorVerifiedWallClock),
        1 => Ok(ClockReleaseJustificationV1::PlatformTimeSourceRecovery),
        2 => Ok(ClockReleaseJustificationV1::HardwareClockMaintenance),
        _ => Err(FormatError::TagMismatch),
    }
}

fn decode_outcome(value: u64) -> Result<LocalAuditOutcomeV1, FormatError> {
    match value {
        0 => Ok(LocalAuditOutcomeV1::Failed),
        1 => Ok(LocalAuditOutcomeV1::Accepted),
        2 => Ok(LocalAuditOutcomeV1::Completed),
        _ => Err(FormatError::TagMismatch),
    }
}

fn typed_bytes<'a, T>(decoder: &mut Decoder<'a>, length: usize) -> Result<T, FormatError>
where
    T: TryFrom<&'a [u8]>,
{
    T::try_from(bytes_exact(decoder, length)?).map_err(|_| FormatError::Shape)
}

// ---------------------------------------------------------------------------
// Der allgemeine Kodierer der zwoelf Ereignisse
//
// Die Aktion und ihr Kontext sind EIN Wert. `schemas/reports/v1/local-audit.cddl`
// bindet in seinen zwoelf Zweigen jede Aktion an genau einen Kontextarm, und
// `ea_crypto::validate_unsigned_protocol_core` weist ein falsches Paar an der
// Signaturgrenze ab. Ein Typ mit unabhaengigem Aktionsfeld und unabhaengigem
// Kontextfeld boete das freie Produkt aus zwoelf Aktionen und neun Kontexten,
// dessen Mehrheit unbaubare Bytes sind. Hier ist ein falsches Paar deshalb
// nicht ablehnbar, sondern nicht konstruierbar.
// ---------------------------------------------------------------------------

/// Der entartete Kontext aus `schemas/reports/v1/local-audit.cddl:47`.
///
/// Eine Position, nullbar. Der Konstruktor ist deshalb infallibel: es gibt
/// nichts abzulehnen.
pub struct GenericAuditContextV1 {
    subject_object_hash: Option<ObjectHash>,
}

impl GenericAuditContextV1 {
    #[must_use]
    pub const fn new(subject_object_hash: Option<ObjectHash>) -> Self {
        Self {
            subject_object_hash,
        }
    }

    #[must_use]
    pub const fn subject_object_hash(&self) -> Option<ObjectHash> {
        self.subject_object_hash
    }
}

/// Die sechs Positionen von `schemas/reports/v1/local-audit.cddl:6-10`.
///
/// `preview_hash` ist einer der vier D-B02-Slots: diese Crate SPEICHERT ihn und
/// berechnet ihn nicht. Sein Urbild und die dazugehoerige Domain-Zeichenkette
/// entstehen in Task 11, zusammen mit ihrem eigenen Vektor.
pub struct StaleRegistryContextV1 {
    registry_head_hash: ObjectHash,
    policy_object_hash: ObjectHash,
    proposed_sequence: ChainSequence,
    registry_not_after: UnixMillis,
    acknowledged_at: UnixMillis,
    preview_hash: Hash32,
}

impl StaleRegistryContextV1 {
    #[must_use]
    pub const fn new(
        registry_head_hash: ObjectHash,
        policy_object_hash: ObjectHash,
        proposed_sequence: ChainSequence,
        registry_not_after: UnixMillis,
        acknowledged_at: UnixMillis,
        preview_hash: Hash32,
    ) -> Self {
        Self {
            registry_head_hash,
            policy_object_hash,
            proposed_sequence,
            registry_not_after,
            acknowledged_at,
            preview_hash,
        }
    }

    #[must_use]
    pub const fn registry_head_hash(&self) -> ObjectHash {
        self.registry_head_hash
    }

    #[must_use]
    pub const fn policy_object_hash(&self) -> ObjectHash {
        self.policy_object_hash
    }

    #[must_use]
    pub const fn proposed_sequence(&self) -> ChainSequence {
        self.proposed_sequence
    }

    #[must_use]
    pub const fn registry_not_after(&self) -> UnixMillis {
        self.registry_not_after
    }

    #[must_use]
    pub const fn acknowledged_at(&self) -> UnixMillis {
        self.acknowledged_at
    }

    #[must_use]
    pub const fn preview_hash(&self) -> Hash32 {
        self.preview_hash
    }
}

/// Die zwei Positionen von `schemas/reports/v1/local-audit.cddl:23`.
///
/// `target_kind` bleibt eine `uint` und wird NICHT zu einer geschlossenen
/// Aufzaehlung verengt: die Grammatik laesst jede vorzeichenlose Ganzzahl zu,
/// und ein Kodierer, der weniger annimmt als die Norm, koennte ein gueltiges
/// Ziel nicht schreiben.
pub struct ExportContextV1 {
    entry_hash: EntryHash,
    target_kind: u64,
}

impl ExportContextV1 {
    #[must_use]
    pub const fn new(entry_hash: EntryHash, target_kind: u64) -> Self {
        Self {
            entry_hash,
            target_kind,
        }
    }

    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    #[must_use]
    pub const fn target_kind(&self) -> u64 {
        self.target_kind
    }
}

/// Die drei Positionen von `schemas/reports/v1/local-audit.cddl:24-28`, zwei
/// davon nullbar: eine erste Bindung hat keinen Vorgaenger, ein Widerruf keinen
/// Nachfolger.
pub struct BindingLifecycleContextV1 {
    old_binding_object_hash: Option<ObjectHash>,
    new_binding_object_hash: Option<ObjectHash>,
    effective_from_sequence: ChainSequence,
}

impl BindingLifecycleContextV1 {
    #[must_use]
    pub const fn new(
        old_binding_object_hash: Option<ObjectHash>,
        new_binding_object_hash: Option<ObjectHash>,
        effective_from_sequence: ChainSequence,
    ) -> Self {
        Self {
            old_binding_object_hash,
            new_binding_object_hash,
            effective_from_sequence,
        }
    }

    #[must_use]
    pub const fn old_binding_object_hash(&self) -> Option<ObjectHash> {
        self.old_binding_object_hash
    }

    #[must_use]
    pub const fn new_binding_object_hash(&self) -> Option<ObjectHash> {
        self.new_binding_object_hash
    }

    #[must_use]
    pub const fn effective_from_sequence(&self) -> ChainSequence {
        self.effective_from_sequence
    }
}

/// Die drei Positionen von `schemas/reports/v1/local-audit.cddl:29-32`.
pub struct AdminRootContextV1 {
    authorization_object_hash: ObjectHash,
    target_object_hash: ObjectHash,
    action_code: u64,
}

impl AdminRootContextV1 {
    #[must_use]
    pub const fn new(
        authorization_object_hash: ObjectHash,
        target_object_hash: ObjectHash,
        action_code: u64,
    ) -> Self {
        Self {
            authorization_object_hash,
            target_object_hash,
            action_code,
        }
    }

    #[must_use]
    pub const fn authorization_object_hash(&self) -> ObjectHash {
        self.authorization_object_hash
    }

    #[must_use]
    pub const fn target_object_hash(&self) -> ObjectHash {
        self.target_object_hash
    }

    #[must_use]
    pub const fn action_code(&self) -> u64 {
        self.action_code
    }
}

/// Die fuenf Positionen von `schemas/reports/v1/local-audit.cddl:33-38`.
pub struct HistoricalRegrantContextV1 {
    authorization_object_hash: ObjectHash,
    entry_hash: EntryHash,
    original_recovery_grant_object_hash: ObjectHash,
    recipient_certificate_object_hash: ObjectHash,
    new_grant_object_hash: ObjectHash,
}

impl HistoricalRegrantContextV1 {
    #[must_use]
    pub const fn new(
        authorization_object_hash: ObjectHash,
        entry_hash: EntryHash,
        original_recovery_grant_object_hash: ObjectHash,
        recipient_certificate_object_hash: ObjectHash,
        new_grant_object_hash: ObjectHash,
    ) -> Self {
        Self {
            authorization_object_hash,
            entry_hash,
            original_recovery_grant_object_hash,
            recipient_certificate_object_hash,
            new_grant_object_hash,
        }
    }

    #[must_use]
    pub const fn authorization_object_hash(&self) -> ObjectHash {
        self.authorization_object_hash
    }

    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    #[must_use]
    pub const fn original_recovery_grant_object_hash(&self) -> ObjectHash {
        self.original_recovery_grant_object_hash
    }

    #[must_use]
    pub const fn recipient_certificate_object_hash(&self) -> ObjectHash {
        self.recipient_certificate_object_hash
    }

    #[must_use]
    pub const fn new_grant_object_hash(&self) -> ObjectHash {
        self.new_grant_object_hash
    }
}

/// Die zwei Positionen von `schemas/reports/v1/local-audit.cddl:39-42`.
pub struct DestructionContextV1 {
    destruction_authorization_object_hash: ObjectHash,
    state_event_object_hash: ObjectHash,
}

impl DestructionContextV1 {
    #[must_use]
    pub const fn new(
        destruction_authorization_object_hash: ObjectHash,
        state_event_object_hash: ObjectHash,
    ) -> Self {
        Self {
            destruction_authorization_object_hash,
            state_event_object_hash,
        }
    }

    #[must_use]
    pub const fn destruction_authorization_object_hash(&self) -> ObjectHash {
        self.destruction_authorization_object_hash
    }

    #[must_use]
    pub const fn state_event_object_hash(&self) -> ObjectHash {
        self.state_event_object_hash
    }
}

/// Die vier Positionen von `schemas/reports/v1/local-audit.cddl:43-46`.
///
/// Alle vier sind D-B02-Slots: diese Crate SPEICHERT sie und berechnet keine
/// davon. Die drei Archivhashes und ihre Domain-Zeichenketten entstehen in
/// Task 9, jeder mit seinem eigenen Vektor.
pub struct ArchiveProfileMigrationContextV1 {
    source_profile_hash: Hash32,
    target_profile_hash: Hash32,
    inventory_hash: Hash32,
    active_pointer_hash: Hash32,
}

impl ArchiveProfileMigrationContextV1 {
    #[must_use]
    pub const fn new(
        source_profile_hash: Hash32,
        target_profile_hash: Hash32,
        inventory_hash: Hash32,
        active_pointer_hash: Hash32,
    ) -> Self {
        Self {
            source_profile_hash,
            target_profile_hash,
            inventory_hash,
            active_pointer_hash,
        }
    }

    #[must_use]
    pub const fn source_profile_hash(&self) -> Hash32 {
        self.source_profile_hash
    }

    #[must_use]
    pub const fn target_profile_hash(&self) -> Hash32 {
        self.target_profile_hash
    }

    #[must_use]
    pub const fn inventory_hash(&self) -> Hash32 {
        self.inventory_hash
    }

    #[must_use]
    pub const fn active_pointer_hash(&self) -> Hash32 {
        self.active_pointer_hash
    }
}

impl IndependentTimeReferenceV1 {
    /// Der Konstruktor der eingefrorenen Zeitreferenz.
    ///
    /// ADDITIV: Felder, Dekodierpfad und Zugriffe des Stufe-1-Typs sind
    /// unveraendert. Ohne diesen Konstruktor koennte KEIN Aufrufer ausserhalb
    /// dieses Moduls den Taktfreigabearm der Aktion bauen.
    #[must_use]
    pub const fn new(
        kind: IndependentTimeKindV1,
        object_hash: ObjectHash,
        verified_time: UnixMillis,
    ) -> Self {
        Self {
            kind,
            object_hash,
            verified_time,
        }
    }
}

impl ClockReleaseContextV1 {
    /// Der Konstruktor des eingefrorenen Taktfreigabekontexts.
    ///
    /// ADDITIV, aus demselben Grund wie
    /// [`IndependentTimeReferenceV1::new`]. Er prueft NICHTS: das Fenster
    /// (`issued_at < expires_at`) und die Zeitgleichheit
    /// (`effective_now == max(floor, wall)`) haengen an Feldern des Kerns und
    /// werden von `encode_local_audit_core` an der Signaturgrenze gemessen —
    /// derselben, die auch die Bytes des Dekodierers annimmt oder abweist.
    #[allow(
        clippy::too_many_arguments,
        reason = "die zehn Positionen von local-audit.cddl:15-22; eine \
                  Parallelstruktur nur fuer den Aufruf waere eine zweite Quelle \
                  derselben Feldliste"
    )]
    #[must_use]
    pub const fn new(
        trusted_time_floor: UnixMillis,
        observed_os_wall_clock: UnixMillis,
        max_future_clock_skew_ms: u64,
        registry_version: RegistryVersion,
        registry_head_hash: ObjectHash,
        guard_policy_object_hash: ObjectHash,
        independent_reference: IndependentTimeReferenceV1,
        justification: ClockReleaseJustificationV1,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Self {
        Self {
            trusted_time_floor,
            observed_os_wall_clock,
            max_future_clock_skew_ms,
            registry_version,
            registry_head_hash,
            guard_policy_object_hash,
            independent_reference,
            justification,
            issued_at,
            expires_at,
        }
    }
}

/// Die zwoelf Aktionen von `schemas/reports/v1/local-audit.cddl:63-75`, jede
/// mit dem Kontext, an den die Grammatik sie bindet.
pub enum LocalAuditActionV1 {
    Login(GenericAuditContextV1),
    ReauthFailure(GenericAuditContextV1),
    BindingChange(BindingLifecycleContextV1),
    Revocation(BindingLifecycleContextV1),
    RegistryStaleWarnAcceptance(StaleRegistryContextV1),
    PlaintextExport(ExportContextV1),
    ClockSkewRelease(ClockReleaseContextV1),
    AdminRootCeremony(AdminRootContextV1),
    RecoveryTest(GenericAuditContextV1),
    HistoricalRegrant(HistoricalRegrantContextV1),
    Destruction(DestructionContextV1),
    ArchiveProfileMigration(ArchiveProfileMigrationContextV1),
}

impl LocalAuditActionV1 {
    /// Der eingefrorene Aktionscode, `0..11` in der Reihenfolge von
    /// `schemas/reports/v1/local-audit.cddl:63-75`.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Self::Login(_) => 0,
            Self::ReauthFailure(_) => 1,
            Self::BindingChange(_) => 2,
            Self::Revocation(_) => 3,
            Self::RegistryStaleWarnAcceptance(_) => 4,
            Self::PlaintextExport(_) => 5,
            Self::ClockSkewRelease(_) => 6,
            Self::AdminRootCeremony(_) => 7,
            Self::RecoveryTest(_) => 8,
            Self::HistoricalRegrant(_) => 9,
            Self::Destruction(_) => 10,
            Self::ArchiveProfileMigration(_) => 11,
        }
    }

    /// Die eingefrorene Kontextmarke, dieselbe Zuordnung, die
    /// `crates/ea-crypto/src/cose.rs` an der Signaturgrenze erzwingt.
    ///
    /// Sie folgt aus der Variante und nicht aus einem zweiten Feld — deshalb
    /// koennen Aktionscode und Kontextmarke nicht auseinanderlaufen.
    #[must_use]
    pub const fn context_tag(&self) -> u8 {
        match self {
            Self::Login(_) | Self::ReauthFailure(_) | Self::RecoveryTest(_) => 0,
            Self::RegistryStaleWarnAcceptance(_) => 1,
            Self::ClockSkewRelease(_) => 2,
            Self::PlaintextExport(_) => 3,
            Self::BindingChange(_) | Self::Revocation(_) => 4,
            Self::AdminRootCeremony(_) => 5,
            Self::HistoricalRegrant(_) => 6,
            Self::Destruction(_) => 7,
            Self::ArchiveProfileMigration(_) => 8,
        }
    }
}

/// Die zwoelf Positionen von `schemas/reports/v1/local-audit.cddl:77-85`, ohne
/// das Versionsliteral und ohne die leere Erweiterungsliste: beide schreibt der
/// Kodierer selbst.
pub struct LocalAuditEventCoreFieldsV1 {
    pub event_id: EventId,
    pub organization_id: OrganizationId,
    pub device_id: DeviceId,
    pub operator_binding_object_hash: Option<ObjectHash>,
    pub signer_certificate_object_hash: ObjectHash,
    pub action: LocalAuditActionV1,
    pub outcome: LocalAuditOutcomeV1,
    pub effective_now: UnixMillis,
    pub nonce: [u8; 32],
}

/// Ein dekodiertes, signiertes Ereignis.
///
/// Es ist KEIN Archivobjekt: eine lokale Auditzeile traegt keines der sechs
/// Objektpraefixe (`crates/ea-format/src/parser.rs`), also gibt es hier kein
/// `ExactObjectBytes`, kein siebtes Praefix und keine siebte Rohgroesse.
pub struct LocalAuditEventV1 {
    event_id: EventId,
    organization_id: OrganizationId,
    device_id: DeviceId,
    operator_binding_object_hash: Option<ObjectHash>,
    signer_certificate_object_hash: ObjectHash,
    action: LocalAuditActionV1,
    outcome: LocalAuditOutcomeV1,
    effective_now: UnixMillis,
    nonce: [u8; 32],
    exact_core: Vec<u8>,
    exact_bytes: Vec<u8>,
}

impl LocalAuditEventV1 {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    #[must_use]
    pub const fn operator_binding_object_hash(&self) -> Option<ObjectHash> {
        self.operator_binding_object_hash
    }

    #[must_use]
    pub const fn signer_certificate_object_hash(&self) -> ObjectHash {
        self.signer_certificate_object_hash
    }

    #[must_use]
    pub const fn action(&self) -> &LocalAuditActionV1 {
        &self.action
    }

    #[must_use]
    pub const fn outcome(&self) -> LocalAuditOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub const fn effective_now(&self) -> UnixMillis {
        self.effective_now
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Die exakten Bytes des Kerns, die die Signatur deckt.
    #[must_use]
    pub fn exact_core(&self) -> &[u8] {
        &self.exact_core
    }

    /// Die exakten Bytes des Paares aus Kern und Signatur.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

impl fmt::Debug for LocalAuditEventV1 {
    /// Undurchsichtig, wie `ParsedArchiveObject`: die Bezeichner dieses
    /// Bauwerks tragen keine Formatierung, und eine Auditzeile gehoert nicht in
    /// eine Protokollzeile. Der Rumpf existiert, damit `Result::unwrap_err` an
    /// diesem Typ ueberhaupt aufrufbar ist.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalAuditEventV1(<bound>)")
    }
}

/// Kodiert die zwoelf Positionen des Kerns in einem Durchgang.
///
/// Eine definite `array(12)`, das Versionsliteral `1` zuerst, jede optionale
/// Position als ausdrueckliches `null`, der Kontext als `array(2)` aus Marke und
/// getypter Nutzlast, dann die 32-Byte-Nonce und die schliessende leere Liste.
/// Keine Map, keine unbestimmte Laenge, keine Umsortierung — die Positionen sind
/// der Vertrag.
///
/// Die letzte Handlung ist `validate_unsigned_protocol_core`: der Kodierer wird
/// an genau der Grenze gemessen, die die Signatur spaeter annimmt oder abweist,
/// und eine Abweichung faellt beim Kodieren auf statt in dauerhaften
/// Auditzeilen.
///
/// # Errors
///
/// [`FormatError::Shape`], wenn die Signaturgrenze den Kern nicht annimmt —
/// etwa ein rueckwaerts laufendes Freigabefenster oder eine `effective-now`, die
/// nicht das Maximum der beiden Taktangaben ist.
pub fn encode_local_audit_core(
    fields: &LocalAuditEventCoreFieldsV1,
) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(512);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(12)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.event_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.device_id.as_bytes()))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_hash(&mut encoder, fields.operator_binding_object_hash)?;
    encoder
        .bytes(fields.signer_certificate_object_hash.as_bytes())
        .and_then(|encoder| encoder.u8(fields.action.code()))
        .and_then(|encoder| encoder.u8(fields.outcome as u8))
        .and_then(|encoder| encoder.i64(fields.effective_now.get()))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.u8(fields.action.context_tag()))
        .map_err(|_| FormatError::Shape)?;
    encode_local_audit_context(&mut encoder, &fields.action)?;
    encoder
        .bytes(&fields.nonce)
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    validate_unsigned_protocol_core(ContentType::LocalAuditCbor, &exact)
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

/// Umschliesst Kern und COSE-Signatur zum eingefrorenen Paar.
///
/// Der Rueckgabewert ist `Vec<u8>` und kein `ExactObjectBytes`: eine lokale
/// Auditzeile ist kein Archivobjekt.
///
/// # Errors
///
/// [`FormatError::Cose`], wenn die Signatur nicht `local-audit+cbor` ist, nicht
/// genau diesen Kern als Nutzlast traegt oder einen anderen Zertifikatshash
/// nennt als der Kern; [`FormatError::Shape`] und
/// [`FormatError::TagMismatch`], wenn `core` kein gueltiger Kern ist — der
/// Umschlag wird nur um einen Kern gelegt, den auch der Dekodierer annimmt.
pub fn encode_local_audit_event(core: &[u8], cose_sign1: &[u8]) -> Result<Vec<u8>, FormatError> {
    let decoded = decode_local_audit_core(core)?;
    check_local_audit_cose(cose_sign1, core, decoded.signer_certificate_object_hash)?;
    let mut exact = Vec::with_capacity(
        core.len()
            .saturating_add(cose_sign1.len())
            .saturating_add(8),
    );
    Encoder::new(&mut exact)
        .array(2)
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(core);
    exact.extend_from_slice(cose_sign1);
    Ok(exact)
}

/// Dekodiert ein signiertes Ereignis jeder der zwoelf Aktionen.
///
/// Das allgemeine Gegenstueck zu [`decode_clock_release_audit`], das unberuehrt
/// daneben stehen bleibt. Beide lesen denselben Kern und pruefen dieselben drei
/// COSE-Bedingungen; dieser hier nimmt die nullbare Bindungsposition auch als
/// `null` an, waehrend der Taktfreigabepfad dort eine Adminbindung verlangt.
///
/// # Errors
///
/// [`FormatError::Shape`] bei jeder Gestaltabweichung des Kerns — die
/// Signaturgrenze prueft Aktionsbereich, Ausgangsbereich, das Paar aus Aktion
/// und Kontextmarke und die Feldgestalt jedes Kontexts, bevor dieser Dekodierer
/// ein Byte liest, und ihre Ablehnung ist `Shape`. [`FormatError::TagMismatch`]
/// bleibt dem Abgleich der Tabelle DIESER Crate gegen die Bytes vorbehalten:
/// er faellt nur, wenn die beiden Tabellen auseinanderlaufen.
/// [`FormatError::Cose`] bei einer Signatur, die nicht genau diesen Kern deckt.
pub fn decode_local_audit_event(exact_bytes: &[u8]) -> Result<LocalAuditEventV1, FormatError> {
    validate(exact_bytes, ParserLimits::V1)?;
    let mut decoder = Decoder::new(exact_bytes);
    expect_array_length(&mut decoder, 2)?;
    let exact_core = exact_item(exact_bytes, &mut decoder)?;
    let core = decode_local_audit_core(exact_core)?;
    let exact_cose = exact_item(exact_bytes, &mut decoder)?;
    finish(&decoder, exact_bytes)?;
    check_local_audit_cose(exact_cose, exact_core, core.signer_certificate_object_hash)?;
    Ok(LocalAuditEventV1 {
        event_id: core.event_id,
        organization_id: core.organization_id,
        device_id: core.device_id,
        operator_binding_object_hash: core.operator_binding_object_hash,
        signer_certificate_object_hash: core.signer_certificate_object_hash,
        action: core.action,
        outcome: core.outcome,
        effective_now: core.effective_now,
        nonce: core.nonce,
        exact_core: exact_core.to_vec(),
        exact_bytes: exact_bytes.to_vec(),
    })
}

/// Die drei Bedingungen, die schon der Taktfreigabepfad anwendet: Inhaltstyp,
/// Nutzlastgleichheit und Zertifikatshash.
fn check_local_audit_cose(
    exact_cose: &[u8],
    exact_core: &[u8],
    signer_certificate_object_hash: ObjectHash,
) -> Result<(), FormatError> {
    let parsed = parse_cose_sign1(exact_cose, &[]).map_err(|_| FormatError::Cose)?;
    if parsed.content_type() != ContentType::LocalAuditCbor
        || parsed.payload() != exact_core
        || parsed
            .certificate_hash()
            .is_none_or(|hash| hash.as_bytes() != signer_certificate_object_hash.as_bytes())
    {
        return Err(FormatError::Cose);
    }
    Ok(())
}

fn encode_optional_hash(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<ObjectHash>,
) -> Result<(), FormatError> {
    if let Some(value) = value {
        encoder
            .bytes(value.as_bytes())
            .map_err(|_| FormatError::Shape)?;
    } else {
        encoder.null().map_err(|_| FormatError::Shape)?;
    }
    Ok(())
}

/// Die getypte Nutzlast hinter der Kontextmarke.
fn encode_local_audit_context(
    encoder: &mut Encoder<&mut Vec<u8>>,
    action: &LocalAuditActionV1,
) -> Result<(), FormatError> {
    match action {
        LocalAuditActionV1::Login(context)
        | LocalAuditActionV1::ReauthFailure(context)
        | LocalAuditActionV1::RecoveryTest(context) => {
            encode_optional_hash(encoder, context.subject_object_hash)?;
        }
        LocalAuditActionV1::BindingChange(context) | LocalAuditActionV1::Revocation(context) => {
            encoder.array(3).map_err(|_| FormatError::Shape)?;
            encode_optional_hash(encoder, context.old_binding_object_hash)?;
            encode_optional_hash(encoder, context.new_binding_object_hash)?;
            encoder
                .u64(context.effective_from_sequence.get())
                .map_err(|_| FormatError::Shape)?;
        }
        LocalAuditActionV1::RegistryStaleWarnAcceptance(context) => {
            encoder
                .array(6)
                .and_then(|encoder| encoder.bytes(context.registry_head_hash.as_bytes()))
                .and_then(|encoder| encoder.bytes(context.policy_object_hash.as_bytes()))
                .and_then(|encoder| encoder.u64(context.proposed_sequence.get()))
                .and_then(|encoder| encoder.i64(context.registry_not_after.get()))
                .and_then(|encoder| encoder.i64(context.acknowledged_at.get()))
                .and_then(|encoder| encoder.bytes(context.preview_hash.as_bytes()))
                .map_err(|_| FormatError::Shape)?;
        }
        LocalAuditActionV1::PlaintextExport(context) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.bytes(context.entry_hash.as_bytes()))
                .and_then(|encoder| encoder.u64(context.target_kind))
                .map_err(|_| FormatError::Shape)?;
        }
        LocalAuditActionV1::ClockSkewRelease(context) => {
            encoder
                .array(10)
                .and_then(|encoder| encoder.i64(context.trusted_time_floor.get()))
                .and_then(|encoder| encoder.i64(context.observed_os_wall_clock.get()))
                .and_then(|encoder| encoder.u64(context.max_future_clock_skew_ms))
                .and_then(|encoder| encoder.u64(context.registry_version.get()))
                .and_then(|encoder| encoder.bytes(context.registry_head_hash.as_bytes()))
                .and_then(|encoder| encoder.bytes(context.guard_policy_object_hash.as_bytes()))
                .and_then(|encoder| encoder.array(3))
                .and_then(|encoder| encoder.u8(context.independent_reference.kind as u8))
                .and_then(|encoder| {
                    encoder.bytes(context.independent_reference.object_hash.as_bytes())
                })
                .and_then(|encoder| encoder.i64(context.independent_reference.verified_time.get()))
                .and_then(|encoder| encoder.u8(context.justification as u8))
                .and_then(|encoder| encoder.i64(context.issued_at.get()))
                .and_then(|encoder| encoder.i64(context.expires_at.get()))
                .map_err(|_| FormatError::Shape)?;
        }
        LocalAuditActionV1::AdminRootCeremony(context) => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.bytes(context.authorization_object_hash.as_bytes()))
                .and_then(|encoder| encoder.bytes(context.target_object_hash.as_bytes()))
                .and_then(|encoder| encoder.u64(context.action_code))
                .map_err(|_| FormatError::Shape)?;
        }
        LocalAuditActionV1::HistoricalRegrant(context) => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.bytes(context.authorization_object_hash.as_bytes()))
                .and_then(|encoder| encoder.bytes(context.entry_hash.as_bytes()))
                .and_then(|encoder| {
                    encoder.bytes(context.original_recovery_grant_object_hash.as_bytes())
                })
                .and_then(|encoder| {
                    encoder.bytes(context.recipient_certificate_object_hash.as_bytes())
                })
                .and_then(|encoder| encoder.bytes(context.new_grant_object_hash.as_bytes()))
                .map_err(|_| FormatError::Shape)?;
        }
        LocalAuditActionV1::Destruction(context) => {
            encoder
                .array(2)
                .and_then(|encoder| {
                    encoder.bytes(context.destruction_authorization_object_hash.as_bytes())
                })
                .and_then(|encoder| encoder.bytes(context.state_event_object_hash.as_bytes()))
                .map_err(|_| FormatError::Shape)?;
        }
        LocalAuditActionV1::ArchiveProfileMigration(context) => {
            // DIESELBE Funktion, die auch der eigenstaendige Kodierer ruft.
            // Zwei Koerper koennten auseinanderlaufen; einer kann es nicht.
            write_archive_profile_migration_context(encoder, context)?;
        }
    }
    Ok(())
}

fn write_archive_profile_migration_context(
    encoder: &mut Encoder<&mut Vec<u8>>,
    context: &ArchiveProfileMigrationContextV1,
) -> Result<(), FormatError> {
    encoder
        .array(4)
        .and_then(|encoder| encoder.bytes(context.source_profile_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(context.target_profile_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(context.inventory_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(context.active_pointer_hash.as_bytes()))
        .map_err(|_| FormatError::Shape)?;
    Ok(())
}

/// Die deterministischen `archive-profile-migration-context-v1`-Bytes, ALLEIN.
///
/// Dieselben vier mal zweiunddreissig Bytes, die
/// [`encode_local_audit_core`] in die Auditzeile schreibt — physisch dieselbe
/// Funktion, damit der eigenstaendige und der eingebettete Kodierer nicht
/// auseinanderlaufen koennen. Der Kontext traegt AUSSCHLIESSLICH Digests: kein
/// Pfad, kein Hostname, kein fachlicher Name.
///
/// # Errors
///
/// [`FormatError::Shape`], wenn das Kodieren nicht gelingt.
pub fn encode_archive_profile_migration_context(
    context: &ArchiveProfileMigrationContextV1,
) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::with_capacity(140);
    let mut encoder = Encoder::new(&mut bytes);
    write_archive_profile_migration_context(&mut encoder, context)?;
    Ok(bytes)
}

/// Der dekodierte Kern jeder Aktion.
struct DecodedLocalAuditCore {
    event_id: EventId,
    organization_id: OrganizationId,
    device_id: DeviceId,
    operator_binding_object_hash: Option<ObjectHash>,
    signer_certificate_object_hash: ObjectHash,
    action: LocalAuditActionV1,
    outcome: LocalAuditOutcomeV1,
    effective_now: UnixMillis,
    nonce: [u8; 32],
}

fn decode_local_audit_core(input: &[u8]) -> Result<DecodedLocalAuditCore, FormatError> {
    validate_unsigned_protocol_core(ContentType::LocalAuditCbor, input)
        .map_err(|_| FormatError::Shape)?;
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 12)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
        return Err(FormatError::UnknownVersion);
    }
    let event_id = typed_bytes(&mut decoder, 16)?;
    let organization_id = typed_bytes(&mut decoder, 16)?;
    let device_id = typed_bytes(&mut decoder, 16)?;
    let operator_binding_object_hash = optional_typed_bytes(&mut decoder, 32)?;
    let signer_certificate_object_hash = typed_bytes(&mut decoder, 32)?;
    let action_code = u8::try_from(decoder.u64().map_err(|_| FormatError::Shape)?)
        .map_err(|_| FormatError::TagMismatch)?;
    let outcome = decode_outcome(decoder.u64().map_err(|_| FormatError::Shape)?)?;
    let effective_now = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    expect_array_length(&mut decoder, 2)?;
    let context_tag = decoder.u64().map_err(|_| FormatError::Shape)?;
    let action = decode_local_audit_action(&mut decoder, action_code, context_tag, effective_now)?;
    let nonce = bytes_exact(&mut decoder, 32)?
        .try_into()
        .map_err(|_| FormatError::Shape)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, input)?;
    Ok(DecodedLocalAuditCore {
        event_id,
        organization_id,
        device_id,
        operator_binding_object_hash,
        signer_certificate_object_hash,
        action,
        outcome,
        effective_now,
        nonce,
    })
}

/// Die Aktion samt ihrem Kontext, aus dem Aktionscode heraus gelesen.
///
/// Der Schlussabgleich stellt die Tabelle DIESER Crate gegen die Bytes und
/// damit gegen die Tabelle von `ea-crypto`, die die Bytes bereits passiert
/// haben: laufen die beiden je auseinander, faellt es hier auf statt in einer
/// dauerhaften Auditzeile.
fn decode_local_audit_action(
    decoder: &mut Decoder<'_>,
    action_code: u8,
    context_tag: u64,
    effective_now: UnixMillis,
) -> Result<LocalAuditActionV1, FormatError> {
    let action = match action_code {
        0 => LocalAuditActionV1::Login(decode_generic_context(decoder)?),
        1 => LocalAuditActionV1::ReauthFailure(decode_generic_context(decoder)?),
        2 => LocalAuditActionV1::BindingChange(decode_binding_lifecycle_context(decoder)?),
        3 => LocalAuditActionV1::Revocation(decode_binding_lifecycle_context(decoder)?),
        4 => {
            LocalAuditActionV1::RegistryStaleWarnAcceptance(decode_stale_registry_context(decoder)?)
        }
        5 => LocalAuditActionV1::PlaintextExport(decode_export_context(decoder)?),
        6 => LocalAuditActionV1::ClockSkewRelease(decode_clock_release_context(
            decoder,
            effective_now,
        )?),
        7 => LocalAuditActionV1::AdminRootCeremony(decode_admin_root_context(decoder)?),
        8 => LocalAuditActionV1::RecoveryTest(decode_generic_context(decoder)?),
        9 => LocalAuditActionV1::HistoricalRegrant(decode_historical_regrant_context(decoder)?),
        10 => LocalAuditActionV1::Destruction(decode_destruction_context(decoder)?),
        11 => LocalAuditActionV1::ArchiveProfileMigration(
            decode_archive_profile_migration_context(decoder)?,
        ),
        _ => return Err(FormatError::TagMismatch),
    };
    if action.code() != action_code || u64::from(action.context_tag()) != context_tag {
        return Err(FormatError::TagMismatch);
    }
    Ok(action)
}

fn decode_generic_context(decoder: &mut Decoder<'_>) -> Result<GenericAuditContextV1, FormatError> {
    Ok(GenericAuditContextV1::new(optional_typed_bytes(
        decoder, 32,
    )?))
}

fn decode_binding_lifecycle_context(
    decoder: &mut Decoder<'_>,
) -> Result<BindingLifecycleContextV1, FormatError> {
    expect_array_length(decoder, 3)?;
    Ok(BindingLifecycleContextV1::new(
        optional_typed_bytes(decoder, 32)?,
        optional_typed_bytes(decoder, 32)?,
        ChainSequence::new(decoder.u64().map_err(|_| FormatError::Shape)?),
    ))
}

fn decode_stale_registry_context(
    decoder: &mut Decoder<'_>,
) -> Result<StaleRegistryContextV1, FormatError> {
    expect_array_length(decoder, 6)?;
    Ok(StaleRegistryContextV1::new(
        typed_bytes(decoder, 32)?,
        typed_bytes(decoder, 32)?,
        ChainSequence::new(decoder.u64().map_err(|_| FormatError::Shape)?),
        UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?),
        UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?),
        typed_bytes(decoder, 32)?,
    ))
}

fn decode_export_context(decoder: &mut Decoder<'_>) -> Result<ExportContextV1, FormatError> {
    expect_array_length(decoder, 2)?;
    Ok(ExportContextV1::new(
        typed_bytes(decoder, 32)?,
        decoder.u64().map_err(|_| FormatError::Shape)?,
    ))
}

fn decode_admin_root_context(decoder: &mut Decoder<'_>) -> Result<AdminRootContextV1, FormatError> {
    expect_array_length(decoder, 3)?;
    Ok(AdminRootContextV1::new(
        typed_bytes(decoder, 32)?,
        typed_bytes(decoder, 32)?,
        decoder.u64().map_err(|_| FormatError::Shape)?,
    ))
}

fn decode_historical_regrant_context(
    decoder: &mut Decoder<'_>,
) -> Result<HistoricalRegrantContextV1, FormatError> {
    expect_array_length(decoder, 5)?;
    Ok(HistoricalRegrantContextV1::new(
        typed_bytes(decoder, 32)?,
        typed_bytes(decoder, 32)?,
        typed_bytes(decoder, 32)?,
        typed_bytes(decoder, 32)?,
        typed_bytes(decoder, 32)?,
    ))
}

fn decode_destruction_context(
    decoder: &mut Decoder<'_>,
) -> Result<DestructionContextV1, FormatError> {
    expect_array_length(decoder, 2)?;
    Ok(DestructionContextV1::new(
        typed_bytes(decoder, 32)?,
        typed_bytes(decoder, 32)?,
    ))
}

fn decode_archive_profile_migration_context(
    decoder: &mut Decoder<'_>,
) -> Result<ArchiveProfileMigrationContextV1, FormatError> {
    expect_array_length(decoder, 4)?;
    Ok(ArchiveProfileMigrationContextV1::new(
        typed_bytes(decoder, 32)?,
        typed_bytes(decoder, 32)?,
        typed_bytes(decoder, 32)?,
        typed_bytes(decoder, 32)?,
    ))
}

fn optional_typed_bytes<'a, T>(
    decoder: &mut Decoder<'a>,
    length: usize,
) -> Result<Option<T>, FormatError>
where
    T: TryFrom<&'a [u8]>,
{
    match optional_bytes_exact(decoder, length)? {
        None => Ok(None),
        Some(value) => T::try_from(value).map(Some).map_err(|_| FormatError::Shape),
    }
}
