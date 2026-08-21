//! Die Kommandoflaeche der Erfassung: Entwurf, Stammdaten, Vorschau,
//! Abschluss, Gesundheit, Haltung und der Ein-Datei-Buendelexport.
//!
//! # Was hier WIRKLICH laeuft — und was benannt fehlt
//!
//! Diese Datei ist die Grenze, nicht die Fachlogik. Drei Gruppen:
//!
//! 1. **Vollstaendig ausgefuehrt.** [`device_posture_report`] liest die Haltung
//!    des Hosts ueber `ea-key-provider` und meldet sie fail-closed;
//!    [`writer_recover_pending`] loest eine liegende Abschlussmarke ueber den
//!    Startpfad auf und unterscheidet die Fortsetzung von der Blockade;
//!    [`archive_health_report`], [`draft_load_active`], [`draft_save`] und
//!    [`master_data_search`] rufen ihre Ports beziehungsweise Ablagen direkt.
//!    [`draft_save`] schreibt die EINGABE — nicht den gelesenen Entwurf — und
//!    meldet `lokal gesichert` erst hinter dem `?` der Ablage;
//!    [`draft_load_active`] liest sie zurueck.
//! 2. **Eingabevertrag ausgefuehrt, Naht gebaut, Wirt nicht verdrahtet.**
//!    [`writer_preview`] und [`writer_finalize`] wandeln den Einsatzrumpf mit
//!    den Stufe-1-Konstruktoren von `ea-schema`, lehnen eine verletzte Eingabe
//!    mit DEREN Code ab und rufen dann den Schreibport
//!    (`crate::state::WriterPreviewPort`, `WriterFinalizePort`). Solange dieses
//!    Geraet keine aufgeloeste Bedienerbindung hat, ist KEIN Port verdrahtet,
//!    und die Abwesenheit sitzt genau dort — am fehlenden Port und nicht an
//!    einer fehlenden Zeile.
//! 3. **Benannte Abwesenheit.** [`session_reauthenticate`],
//!    [`writer_acknowledge_stale_registry`], [`draft_discard_begin`],
//!    [`draft_discard_resume`] und [`archive_export_bundle_file`] antworten mit
//!    einem stabilen Code. Jeder dieser Codes benennt eine Voraussetzung, die
//!    in diesem Bauzustand nicht aufgeloest ist — und keiner von ihnen ist ein
//!    Vorgabewert, der etwas Gutes behauptet.
//!
//! Fail-closed ist die durchgaengige Richtung: eine unbekannte Voraussetzung
//! ist keine erfuellte.

use ea_archive_fs::ArchiveHealthReport;
use ea_key_provider::{DevicePostureReport, PostureRequirement, SupportMatrixRow};
use ea_schema::SchemaError;
use ea_ui_contracts::{
    ArchiveHealthSummaryView, DevicePostureSummaryView, FinalizationPreviewView,
    FinalizeOutcomeView, IncidentInputView, PatientCountView, PendingFinalizationResumeView,
    PendingResumeOutcomeView, PostureRequirementView,
};
use ea_writer::{RecoveryOutcome, WriterError};
use serde::{Deserialize, Serialize};

use super::{
    ARCHIVE_HEALTH_UNAVAILABLE, BUNDLE_EXPORT_UNAVAILABLE, CommandError, DISCARD_UNAVAILABLE,
    DRAFT_PAYLOAD_UNREADABLE, DRAFTS_UNAVAILABLE, MASTER_DATA_UNAVAILABLE, MASTER_DATA_UNREADABLE,
    NO_VERIFIED_SESSION, REAUTH_UNAVAILABLE, SESSION_STATE_UNREADABLE, STALE_ACK_UNAVAILABLE,
    STARTUP_RECOVERY_UNAVAILABLE, WRITER_UNAVAILABLE, run_blocking,
};
use crate::state::{DesktopState, DraftPayloadPort};

// ---------------------------------------------------------------------------
// Drahtformen. Jede traegt `rename_all = "camelCase"` und ist die EINE
// Serialisierung ihres Ansichtsmodells aus `ea-ui-contracts`.
// ---------------------------------------------------------------------------

/// Ein Koordinatenpaar als ganzzahliges E7-Paar.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoordinatesDto {
    pub lat_e7: i32,
    pub lon_e7: i32,
}

/// Der Zeitraum eines Einsatzes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OccurredAtDto {
    pub start: i64,
    pub end: Option<i64>,
}

/// Das Einsatzstichwort.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeywordDto {
    pub reference_id: Option<String>,
    pub display_text: String,
}

/// Die strukturierte Adresse, Position fuer Position.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredAddressDto {
    pub street: Option<String>,
    pub house_number: Option<String>,
    pub postal_code: Option<String>,
    pub locality: Option<String>,
    pub admin_area: Option<String>,
    pub country_code: Option<String>,
}

/// Der Einsatzort.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationDto {
    pub free_text: Option<String>,
    pub address: Option<StructuredAddressDto>,
    pub coordinates: Option<CoordinatesDto>,
}

/// Eine Personalauswahl — Stammdatenkennung ODER Ad-hoc-Eintrag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonnelSelectionDto {
    pub master_personnel_id: Option<String>,
    pub display_name: String,
    pub role_label: Option<String>,
}

/// Eine Fahrzeugauswahl.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VehicleSelectionDto {
    pub master_vehicle_id: Option<String>,
    pub display_name: String,
    pub radio_call_name: Option<String>,
    pub license_plate: Option<String>,
}

/// Eine beteiligte externe Organisation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalOrganizationDto {
    pub id: Option<String>,
    pub display_name: String,
}

/// Der Einsatzrumpf, wie die Oberflaeche ihn schickt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentInputDto {
    pub human_incident_number: String,
    pub occurred_at: OccurredAtDto,
    pub keyword: KeywordDto,
    pub location: LocationDto,
    pub personnel: Vec<PersonnelSelectionDto>,
    pub personnel_empty_reason: Option<String>,
    pub vehicles: Vec<VehicleSelectionDto>,
    pub vehicles_empty_reason: Option<String>,
    pub patient_count_status: String,
    pub patient_count: Option<u32>,
    pub notes: Option<String>,
    pub external_organizations: Vec<ExternalOrganizationDto>,
}

/// Der Eingabevertrag ist verletzt — mit dem Code der Stufe 1.
pub const INCIDENT_INPUT_REJECTED: &str = "EA-DESKTOP-INCIDENT-INPUT-REJECTED";

impl IncidentInputDto {
    /// Die Drahtform als Ansichtsmodell — mit GEPRUEFTEM Patientenzustand.
    ///
    /// # Errors
    ///
    /// [`INCIDENT_INPUT_REJECTED`], wenn das PAAR aus Zustand und Zahl keine
    /// Eingabe ist: ein Wort, das nicht in der emittierten Vereinigung steht,
    /// ein `known` OHNE Zahl oder ein `unknown` MIT Zahl. Alle drei sind hier
    /// eine Ablehnung und kein Vorgabewert — ein `known` ohne Zahl waere sonst
    /// die bekannte Null unter einer Anzeige, die „unbekannt" sagt.
    pub fn to_view(&self) -> Result<IncidentInputView, CommandError> {
        let patient_count =
            PatientCountView::from_wire(&self.patient_count_status, self.patient_count)
                .ok_or_else(|| CommandError::new(INCIDENT_INPUT_REJECTED))?;
        Ok(IncidentInputView {
            human_incident_number: self.human_incident_number.clone(),
            occurred_at: ea_ui_contracts::OccurredAtView {
                start: ea_types::UnixMillis::new(self.occurred_at.start),
                end: self.occurred_at.end.map(ea_types::UnixMillis::new),
            },
            keyword: ea_ui_contracts::KeywordView {
                reference_id: self.keyword.reference_id.clone(),
                display_text: self.keyword.display_text.clone(),
            },
            location: ea_ui_contracts::LocationView {
                free_text: self.location.free_text.clone(),
                address: self.location.address.as_ref().map(|address| {
                    ea_ui_contracts::StructuredAddressView {
                        street: address.street.clone(),
                        house_number: address.house_number.clone(),
                        postal_code: address.postal_code.clone(),
                        locality: address.locality.clone(),
                        admin_area: address.admin_area.clone(),
                        country_code: address.country_code.clone(),
                    }
                }),
                coordinates: self.location.coordinates.map(|pair| {
                    ea_ui_contracts::CoordinatesView {
                        lat_e7: pair.lat_e7,
                        lon_e7: pair.lon_e7,
                    }
                }),
            },
            personnel: self
                .personnel
                .iter()
                .map(|person| ea_ui_contracts::PersonnelSelectionView {
                    master_personnel_id: person.master_personnel_id.clone(),
                    display_name: person.display_name.clone(),
                    role_label: person.role_label.clone(),
                })
                .collect(),
            personnel_empty_reason: self.personnel_empty_reason.clone(),
            vehicles: self
                .vehicles
                .iter()
                .map(|vehicle| ea_ui_contracts::VehicleSelectionView {
                    master_vehicle_id: vehicle.master_vehicle_id.clone(),
                    display_name: vehicle.display_name.clone(),
                    radio_call_name: vehicle.radio_call_name.clone(),
                    license_plate: vehicle.license_plate.clone(),
                })
                .collect(),
            vehicles_empty_reason: self.vehicles_empty_reason.clone(),
            patient_count,
            notes: self.notes.clone(),
            external_organizations: self
                .external_organizations
                .iter()
                .map(|organization| ea_ui_contracts::ExternalOrganizationView {
                    id: organization.id.clone(),
                    display_name: organization.display_name.clone(),
                })
                .collect(),
        })
    }
}

/// Der Sync-Zustand in seiner Drahtform.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStateDto {
    pub status: &'static str,
    pub detail_cause: Option<&'static str>,
}

impl From<&ea_ui_contracts::SyncStateView> for SyncStateDto {
    fn from(view: &ea_ui_contracts::SyncStateView) -> Self {
        Self {
            status: view.status.label(),
            detail_cause: view.detail_cause.map(|cause| cause.label()),
        }
    }
}

/// Der aktive Entwurf samt Speicherzustand.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftStateDto {
    pub incident: IncidentInputDto,
    pub sync: SyncStateDto,
}

/// Das Ergebnis einer Stammdatensuche.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterDataResultDto {
    pub personnel: Vec<PersonnelSelectionDto>,
    pub vehicles: Vec<VehicleSelectionDto>,
    pub personnel_total: u64,
    pub vehicle_total: u64,
}

/// Die Abschlussvorschau in ihrer Drahtform.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizationPreviewDto {
    pub proposed_sequence: u64,
    pub binds_predecessor: bool,
    pub effective_now: i64,
    pub trust_age_ms: u64,
    pub reader_trust_refresh_ms: u64,
    pub trust_refresh_overdue: bool,
    pub stale_decision: String,
}

impl From<FinalizationPreviewView> for FinalizationPreviewDto {
    fn from(view: FinalizationPreviewView) -> Self {
        Self {
            proposed_sequence: view.proposed_sequence.get(),
            binds_predecessor: view.binds_predecessor,
            effective_now: view.effective_now.get(),
            trust_age_ms: view.trust_age_ms,
            reader_trust_refresh_ms: view.reader_trust_refresh_ms,
            trust_refresh_overdue: view.trust_refresh_overdue,
            stale_decision: ea_ui_contracts::stale_decision_literal(view.stale_decision).to_owned(),
        }
    }
}

/// Die BESTAETIGTE Vorschau ist eine Drahtform und wird geprueft.
pub const PREVIEW_REJECTED: &str = "EA-DESKTOP-PREVIEW-REJECTED";

impl FinalizationPreviewDto {
    /// Die bestaetigte Vorschau als Ansichtsmodell — mit GEPRUEFTEM Zeitstatus.
    ///
    /// # Errors
    ///
    /// [`PREVIEW_REJECTED`], wenn der Zeitstatus nicht in der emittierten
    /// Vereinigung steht. Ein unbekanntes Wort waere sonst ein `Fresh`, und
    /// damit faellt genau die Bestaetigungspflicht des mittleren Arms.
    pub fn to_view(&self) -> Result<FinalizationPreviewView, CommandError> {
        Ok(FinalizationPreviewView {
            proposed_sequence: ea_types::ChainSequence::new(self.proposed_sequence),
            binds_predecessor: self.binds_predecessor,
            effective_now: ea_types::UnixMillis::new(self.effective_now),
            trust_age_ms: self.trust_age_ms,
            reader_trust_refresh_ms: self.reader_trust_refresh_ms,
            trust_refresh_overdue: self.trust_refresh_overdue,
            stale_decision: ea_ui_contracts::stale_decision_from_wire(&self.stale_decision)
                .ok_or_else(|| CommandError::new(PREVIEW_REJECTED))?,
        })
    }
}

/// Das Ergebnis eines abgeschlossenen Eintrags — OHNE jede Nutzlast.
///
/// Die zwei HASHES und die Sequenz: das ist alles, was der Writer nach dem
/// Commit ueber den Eintrag erfaehrt, und ein Fingerabdruck ohne Hash ist
/// keiner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeOutcomeDto {
    pub sequence: u64,
    pub entry_hash: String,
    pub object_hash: String,
    pub sync: SyncStateDto,
}

impl From<FinalizeOutcomeView> for FinalizeOutcomeDto {
    fn from(view: FinalizeOutcomeView) -> Self {
        Self {
            sequence: view.sequence.get(),
            entry_hash: view.entry_hash,
            object_hash: view.object_hash,
            sync: SyncStateDto::from(&view.sync),
        }
    }
}

/// Die Bestaetigung eines veralteten Registry-Head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleAcknowledgementDto {
    pub captured: bool,
    pub proof_code: String,
}

/// Das Ergebnis einer nativen erneuten Authentisierung.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReauthResultDto {
    pub fresh: bool,
    pub purpose_code: String,
}

/// Der Stand eines Verwerfens.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscardStateDto {
    pub phase_code: String,
    pub complete: bool,
}

/// Das Ergebnis des Ein-Datei-Buendelexports.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleExportDto {
    pub path: String,
    pub object_count: u64,
    pub byte_count: u64,
}

/// Der Gesundheitsbefund in seiner Drahtform.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveHealthDto {
    pub healthy: bool,
    pub finding_codes: Vec<&'static str>,
    pub quarantine_reasons: Vec<&'static str>,
}

impl From<&ArchiveHealthSummaryView> for ArchiveHealthDto {
    fn from(view: &ArchiveHealthSummaryView) -> Self {
        Self {
            healthy: view.healthy,
            finding_codes: view.finding_codes.iter().map(|code| code.code()).collect(),
            quarantine_reasons: view
                .quarantine_reasons
                .iter()
                .map(|reason| reason.as_str())
                .collect(),
        }
    }
}

/// EIN Haltungssignal in seiner Drahtform.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureRequirementDto {
    pub requirement_code: String,
    pub satisfied: Option<bool>,
    pub evidence_code: String,
}

/// Die Haltung des Geraets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePostureDto {
    pub requirements: Vec<PostureRequirementDto>,
    pub production_ready: bool,
}

impl From<&DevicePostureSummaryView> for DevicePostureDto {
    fn from(view: &DevicePostureSummaryView) -> Self {
        Self {
            requirements: view
                .requirements
                .iter()
                .map(|requirement| PostureRequirementDto {
                    requirement_code: requirement.requirement_code.clone(),
                    satisfied: requirement.satisfied,
                    evidence_code: requirement.evidence_code.clone(),
                })
                .collect(),
            production_ready: view.production_ready,
        }
    }
}

/// Die Fortsetzungsansicht MIT Blockadecode und Veroeffentlichungszustand.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingResumeOutcomeDto {
    pub resume: super::session::ResumeDto,
    pub blocked_code: Option<String>,
    pub sync: Option<SyncStateDto>,
}

impl From<&PendingResumeOutcomeView> for PendingResumeOutcomeDto {
    fn from(view: &PendingResumeOutcomeView) -> Self {
        Self {
            resume: super::session::ResumeDto::from(&view.resume),
            blocked_code: view.blocked_code.clone(),
            sync: view.sync.as_ref().map(SyncStateDto::from),
        }
    }
}

// ---------------------------------------------------------------------------
// Die synchronen Kerne. Jeder ist ohne Wirt aufrufbar und damit messbar.
// ---------------------------------------------------------------------------

/// Der stabile Code EINER Haltungsanforderung.
///
/// Ein `match` ohne Sammelarm: eine fuenfte Anforderung in `ea-key-provider`
/// bricht die Uebersetzung, statt still zu verschwinden.
const fn requirement_code(requirement: PostureRequirement) -> &'static str {
    match requirement {
        PostureRequirement::FullDiskEncryption => "EA-POSTURE-FULL-DISK-ENCRYPTION",
        PostureRequirement::LockedNonSharedAccount => "EA-POSTURE-ACCOUNT-EXCLUSIVE",
        PostureRequirement::AutomaticScreenLock => "EA-POSTURE-SCREEN-LOCK",
        PostureRequirement::SupportedOsPatchLevel => "EA-POSTURE-OS-PATCH-LEVEL",
    }
}

/// Die Haltung des Geraets, aus dem Bericht des Hosts.
///
/// `satisfied` ist DREIWERTIG: `None` heisst „auf dieser Plattform nicht
/// belegbar" und ist ausdruecklich kein automatisches Ja.
/// `DevicePostureSummaryView::new` leitet `production_ready` fail-closed ab.
#[must_use]
pub fn posture_view(report: &DevicePostureReport) -> DevicePostureSummaryView {
    DevicePostureSummaryView::new(
        PostureRequirement::ALL
            .into_iter()
            .map(|requirement| {
                let check = report.check(requirement);
                PostureRequirementView {
                    requirement_code: requirement_code(requirement).to_owned(),
                    satisfied: if check.is_unknown() {
                        None
                    } else {
                        Some(check.is_pass())
                    },
                    evidence_code: check.evidence_code().to_owned(),
                }
            })
            .collect(),
    )
}

/// Der Kern von [`device_posture_report`].
///
/// Kein Port und keine Attrappe: die Support-Matrix nennt die Zeile des Hosts,
/// und deren Adapter liest, was er lesen kann. Ein Ziel, das v0.1 nicht als
/// Produktivziel fuehrt, ist KEIN Fehler, sondern ein Bericht, in dem keine
/// Anforderung belegt ist — und damit fail-closed nicht produktionsbereit.
fn device_posture_core() -> Result<DevicePostureDto, CommandError> {
    let report = match SupportMatrixRow::current_host() {
        None => DevicePostureReport::unresolved(),
        Some(row) => row
            .posture_provider()
            .report()
            .unwrap_or_else(|_| DevicePostureReport::unresolved()),
    };
    Ok(DevicePostureDto::from(&posture_view(&report)))
}

/// Der Kern von [`archive_health_report`].
fn archive_health_core(state: &DesktopState) -> Result<ArchiveHealthDto, CommandError> {
    let port = state
        .health()
        .ok_or_else(|| CommandError::new(ARCHIVE_HEALTH_UNAVAILABLE))?;
    let report = port
        .health()
        .map_err(|_| CommandError::new(ARCHIVE_HEALTH_UNAVAILABLE))?;
    Ok(ArchiveHealthDto::from(&health_view(&report)))
}

/// Die Zusammenfassung EINES Gesundheitsberichts.
///
/// Die Isolationsliste ist leer, weil der Schreibport dieser Ausbaustufe keine
/// Leseprimitive fuer isolierte Objekte fuehrt; `healthy` bleibt damit die
/// UND-Verknuepfung ueber eine leere zweite Menge und wird dadurch nie
/// freundlicher, sondern nur unvollstaendiger — und das steht hier.
#[must_use]
pub fn health_view(report: &ArchiveHealthReport) -> ArchiveHealthSummaryView {
    ArchiveHealthSummaryView::new(report, &[])
}

/// Der Kern von [`writer_recover_pending`].
///
/// Er unterscheidet GENAU zwei Ausgaenge, und beide kommen aus dem Kern:
/// die Fortsetzung (der Startpfad hat aufgeloest) und die Blockade (der
/// Startpfad hat abgelehnt, und sein Code sagt, warum). Der
/// Veroeffentlichungszustand bleibt `None`, solange keine
/// Publikationswarteschlange verdrahtet ist — eine erfundene Zeile waere hier
/// eine Aussage ueber einen Upload, den niemand versucht hat.
fn recover_pending_core(state: &DesktopState) -> Result<PendingResumeOutcomeDto, CommandError> {
    let startup = state
        .startup()
        .ok_or_else(|| CommandError::new(STARTUP_RECOVERY_UNAVAILABLE))?;
    match startup.resolve_pending_finalization() {
        Ok(outcome) => Ok(PendingResumeOutcomeDto::from(&resume_view(&outcome, None))),
        Err(error) => Ok(PendingResumeOutcomeDto::from(&blocked_view(error))),
    }
}

/// Die Fortsetzungsansicht eines aufgeloesten Startpfads.
#[must_use]
pub fn resume_view(
    outcome: &RecoveryOutcome,
    sync: Option<ea_ui_contracts::SyncStateView>,
) -> PendingResumeOutcomeView {
    PendingResumeOutcomeView {
        resume: PendingFinalizationResumeView::new(
            super::session::phase_of(outcome),
            Some(outcome),
        ),
        blocked_code: None,
        sync,
    }
}

/// Die Blockade — mit dem Code des Kerns und ohne jede Abschlusshandhabe.
#[must_use]
pub fn blocked_view(error: WriterError) -> PendingResumeOutcomeView {
    PendingResumeOutcomeView {
        resume: PendingFinalizationResumeView::new(
            ea_writer::FinalizationPhase::PreparedAndFlushed,
            None,
        ),
        blocked_code: Some(error.code().to_owned()),
        sync: None,
    }
}

/// Der Kern von [`master_data_search`].
///
/// Was er kann und was er nicht kann, und beides steht hier: die Ablage der
/// Stufe 2 fuehrt Zaehlungen und die Momentaufnahme EINER Kennung
/// (`MasterDataRepository::snapshot_person`, `snapshot_vehicle`), aber keine
/// Freitextsuche. Deshalb loest dieser Kern die Anfrage als KENNUNG auf und
/// meldet daneben die Gesamtzahlen; eine Freitextsuche ueber Stammdaten
/// existiert in `ea-draft` nicht und wird hier nicht erfunden.
fn master_data_search_core(
    state: &DesktopState,
    query: &str,
) -> Result<MasterDataResultDto, CommandError> {
    let repository = state
        .master_data()
        .ok_or_else(|| CommandError::new(MASTER_DATA_UNAVAILABLE))?;
    let personnel_total = repository
        .person_count()
        .map_err(|_| CommandError::new(MASTER_DATA_UNREADABLE))?;
    let vehicle_total = repository
        .vehicle_count()
        .map_err(|_| CommandError::new(MASTER_DATA_UNREADABLE))?;
    let personnel = repository
        .snapshot_person(query)
        .map(|snapshot| {
            vec![PersonnelSelectionDto {
                master_personnel_id: Some(query.to_owned()),
                display_name: snapshot.display_name().to_owned(),
                role_label: None,
            }]
        })
        .unwrap_or_default();
    let vehicles = repository
        .snapshot_vehicle(query)
        .map(|snapshot| {
            vec![VehicleSelectionDto {
                master_vehicle_id: Some(query.to_owned()),
                display_name: snapshot.display_name().to_owned(),
                radio_call_name: None,
                license_plate: None,
            }]
        })
        .unwrap_or_default();
    Ok(MasterDataResultDto {
        personnel,
        vehicles,
        personnel_total,
        vehicle_total,
    })
}

/// Der Kern von [`draft_load_active`].
///
/// Der ENTWURFSKLARTEXT verlaesst diese Grenze ausschliesslich mit einem
/// `ea_operator::OperatorSessionProof`, und die Pruefung steht VOR dem Port:
/// eine Ablehnung liest die Nutzlast nicht, also kann der Klartext auch nicht
/// im Fehlerfall entstehen. `SessionState::role` ist die Klammer um den
/// Nachweis — sie liefert `None`, solange keiner vorliegt (siehe
/// `crate::state::SessionState::role`) —, und dieser Kern liest genau sie und
/// baut keine zweite Bedingung daneben.
///
/// Der Grund, warum das nicht schon in Task 16 stand: die zwei UNWIDERRUFLICHEN
/// Handlungen pruefen die Frische im Kern (`ea_draft::DiscardService` und
/// `ea_writer::WriterService::finalize` gegen `OperatorSessionProof::is_valid_for`),
/// das HERAUSGEBEN des laufenden Entwurfs war dagegen an nichts gebunden. Ein
/// Geraet, das gesperrt und wieder entsperrt wurde, zeigte den Einsatzrumpf
/// ohne Wiederanmeldung.
///
/// Messbar ist hier nur die ABLEHNUNG, und das ist keine Luecke des Zeugen:
/// [`ea_operator::OperatorSessionProof`] hat ausserhalb von `ea-operator`
/// keinen Konstruktor, und `OperatorAuthenticator::reauthenticate` verlangt eine
/// aufgeloeste Root-signierte Bindung samt `PreexistingEffectiveNow`. Dieselbe
/// Lage und dieselbe Begruendung wie bei `commands::session::verified_session_core`.
/// Die ABBILDUNG Nutzlast → Drahtform ist deshalb in
/// [`draft_state_of`] herausgezogen und dort vollstaendig bezeugt.
fn draft_load_core(state: &DesktopState) -> Result<DraftStateDto, CommandError> {
    state
        .session()
        .lock()
        .map_err(|_| CommandError::new(SESSION_STATE_UNREADABLE))?
        .role()
        .ok_or_else(|| CommandError::new(NO_VERIFIED_SESSION))?;
    let repository = state
        .drafts()
        .ok_or_else(|| CommandError::new(DRAFTS_UNAVAILABLE))?;
    draft_state_of(repository)
}

/// Die Nutzlast EINES Entwurfsports als Drahtform.
///
/// Sie nimmt den Port und nicht den Zustand: so kann dieser Halbschritt nicht
/// versehentlich der Kern eines Kommandos werden, denn von `&DesktopState` zur
/// Drahtform fuehrt nur [`draft_load_core`] — und der traegt das Sitzungstor.
///
/// Die Nutzlast kommt aus derselben Ablage, in die [`draft_save_core`] sie
/// geschrieben hat: entsiegelt unter dem `draftDEK` durch `ea-draft` und hier
/// nur noch entschluesselt IM SINNE der Drahtform. Eine leere Nutzlast ist der
/// frisch angelegte Entwurf und damit ein leerer Rumpf; eine nicht lesbare
/// Nutzlast ist eine BENANNTE Abwesenheit und nicht der leere Rumpf, weil das
/// die stille Loeschung einer Erfassung waere.
fn draft_state_of(
    repository: &(dyn DraftPayloadPort + Send + Sync),
) -> Result<DraftStateDto, CommandError> {
    let payload = repository
        .load_payload()
        .map_err(|_| CommandError::new(DRAFTS_UNAVAILABLE))?;
    Ok(DraftStateDto {
        incident: decode_draft_payload(&payload)?,
        sync: SyncStateDto {
            status: ea_archive_fs::SyncStatus::LocallySaved.label(),
            detail_cause: None,
        },
    })
}

/// Die Nutzlast eines Entwurfs als Einsatzrumpf.
///
/// # Errors
///
/// [`DRAFT_PAYLOAD_UNREADABLE`], wenn die entsiegelte Nutzlast keine Drahtform
/// dieser Anwendung ist. Fail-closed: der leere Rumpf ist die Antwort fuer den
/// LEEREN Entwurf und niemals die fuer einen unlesbaren.
fn decode_draft_payload(payload: &str) -> Result<IncidentInputDto, CommandError> {
    if payload.is_empty() {
        return Ok(blank_incident_dto());
    }
    serde_json::from_str(payload).map_err(|_| CommandError::new(DRAFT_PAYLOAD_UNREADABLE))
}

/// Der Einsatzrumpf als Nutzlast eines Entwurfs.
fn encode_draft_payload(incident: &IncidentInputDto) -> Result<String, CommandError> {
    serde_json::to_string(incident).map_err(|_| CommandError::new(DRAFT_PAYLOAD_UNREADABLE))
}

/// Ein leerer Einsatzrumpf in seiner Drahtform.
#[must_use]
pub fn blank_incident_dto() -> IncidentInputDto {
    IncidentInputDto {
        human_incident_number: String::new(),
        occurred_at: OccurredAtDto {
            start: 0,
            end: None,
        },
        keyword: KeywordDto {
            reference_id: None,
            display_text: String::new(),
        },
        location: LocationDto {
            free_text: Some(String::new()),
            address: None,
            coordinates: None,
        },
        personnel: Vec::new(),
        personnel_empty_reason: None,
        vehicles: Vec::new(),
        vehicles_empty_reason: None,
        // AUS der emittierten Vereinigung und nicht als Literal hier: die
        // Wire-Reihenfolge ist `unknown`, `known`, und ein leerer Rumpf traegt
        // keine Zahl.
        patient_count_status: ea_ui_contracts::PATIENT_COUNT_STATUS_LITERALS[0].to_owned(),
        patient_count: None,
        notes: None,
        external_organizations: Vec::new(),
    }
}

/// Der Kern von [`draft_save`].
///
/// Der Eingabevertrag wird ZUERST geprueft: eine Autospeicherung, die einen
/// unzulaessigen Rumpf annimmt, macht die Ablehnung erst beim Abschluss
/// sichtbar.
///
/// Danach wird die EINGABE geschrieben und nicht der gelesene Entwurf. Der
/// gemeldete Zustand `lokal gesichert` ist eine Aussage ueber genau diesen
/// Schreibvorgang: er steht hinter dem `?` der Ablage, und ein Fehlschlag
/// erreicht ihn nicht.
fn draft_save_core(
    state: &DesktopState,
    incident: &IncidentInputDto,
) -> Result<SyncStateDto, CommandError> {
    let view = incident.to_view()?;
    view.try_into_scalars()
        .map_err(|error| CommandError::new(schema_code(&error)))?;
    let repository = state
        .drafts()
        .ok_or_else(|| CommandError::new(DRAFTS_UNAVAILABLE))?;
    repository
        .save_payload(encode_draft_payload(incident)?)
        .map_err(|_| CommandError::new(DRAFTS_UNAVAILABLE))?;
    Ok(SyncStateDto {
        status: ea_archive_fs::SyncStatus::LocallySaved.label(),
        detail_cause: None,
    })
}

/// Der stabile Code eines Stufe-1-Schemafehlers.
///
/// Er kommt AUS dem Fehler und wird hier nicht nachgebaut: die biconditionale
/// Regel `EA-SCHEMA-LIST-REASON`, die Intervallregel, der Koordinatenbereich
/// und die Zeichenlaengen leben in `ea-schema`, und diese Grenze wiederholt
/// keine davon.
fn schema_code(error: &SchemaError) -> &'static str {
    error.code()
}

/// Der gepruefte Einsatzrumpf als Ansichtsmodell.
///
/// Er tut, was an dieser Grenze getan werden KANN — die SKALAREN Positionen des
/// Einsatzrumpfes gegen die Stufe-1-Konstruktoren pruefen — und gibt die
/// Ansicht heraus, mit der der Schreibport gerufen wird.
///
/// Was er ausdruecklich nicht prueft: die biconditionale Listenregel
/// `EA-SCHEMA-LIST-REASON`. Sie lebt in `IncidentV1::new`, und dieser
/// Konstruktor verlangt Momentaufnahmen mit Revision und Provenienz aus der
/// Stammdatenablage. Sie wird also im Schreibdienst erzwungen und nicht hier
/// nachgebaut; die Oberflaeche fuehrt sie zusaetzlich als Gestalt.
fn writer_input_core(incident: &IncidentInputDto) -> Result<IncidentInputView, CommandError> {
    let view = incident.to_view()?;
    view.try_into_scalars()
        .map_err(|error| CommandError::new(schema_code(&error)))?;
    Ok(view)
}

/// Der Kern von [`writer_preview`].
///
/// Die Reihenfolge ist die Aussage: erst der Eingabevertrag, dann der PORT. Die
/// Abwesenheit sitzt damit an der fehlenden Naht — kein aufgeloester
/// `WriterService` auf diesem Geraet — und nicht an einer fehlenden Zeile.
fn preview_core(
    state: &DesktopState,
    incident: &IncidentInputDto,
) -> Result<FinalizationPreviewDto, CommandError> {
    let view = writer_input_core(incident)?;
    let port = state
        .writer()
        .ok_or_else(|| CommandError::new(WRITER_UNAVAILABLE))?;
    port.preview(&view).map(FinalizationPreviewDto::from)
}

/// Der Kern von [`writer_finalize`].
fn finalize_core(
    state: &DesktopState,
    incident: &IncidentInputDto,
    confirmed: &FinalizationPreviewDto,
) -> Result<FinalizeOutcomeDto, CommandError> {
    let view = writer_input_core(incident)?;
    let port = state
        .writer()
        .ok_or_else(|| CommandError::new(WRITER_UNAVAILABLE))?;
    port.finalize(&view, &confirmed.to_view()?)
        .map(FinalizeOutcomeDto::from)
}

// ---------------------------------------------------------------------------
// Die Kommandos. Jeder Rumpf ist `pub async fn` und schickt seinen synchronen
// Kern ueber `run_blocking`.
// ---------------------------------------------------------------------------

/// Eine erneute native Authentisierung fuer GENAU einen Zweck.
///
/// # Errors
///
/// [`REAUTH_UNAVAILABLE`]: eine Wiederanmeldung verlangt einen `BoundOperator`
/// aus einer aufgeloesten Root-signierten Bindung und einen Anbieter nativer
/// Praesenz. Beides ist auf diesem Geraet nicht aufgeloest, und ein
/// Vorgabewert waere hier ein erfundener Nachweis.
#[tauri::command]
pub async fn session_reauthenticate(purpose: String) -> Result<ReauthResultDto, CommandError> {
    run_blocking(move || {
        let _ = purpose;
        Err(CommandError::new(REAUTH_UNAVAILABLE))
    })
    .await
}

/// Die Stammdatensuche.
///
/// # Errors
///
/// [`MASTER_DATA_UNAVAILABLE`] ohne geoeffnete Ablage,
/// [`MASTER_DATA_UNREADABLE`], wenn sie ablehnt.
#[tauri::command]
pub async fn master_data_search(
    state: tauri::State<'_, DesktopState>,
    query: String,
) -> Result<MasterDataResultDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || master_data_search_core(&state, &query)).await
}

/// Der EINE aktive Entwurf.
///
/// # Errors
///
/// [`NO_VERIFIED_SESSION`] ohne `ea_operator::OperatorSessionProof` — der
/// Entwurfsklartext wird ohne Nachweis nicht herausgegeben und dafuer auch nicht
/// gelesen; [`SESSION_STATE_UNREADABLE`] bei vergiftetem Sitzungsschloss;
/// [`DRAFTS_UNAVAILABLE`] ohne geoeffnete Entwurfsablage;
/// [`DRAFT_PAYLOAD_UNREADABLE`], wenn die entsiegelte Nutzlast keine Drahtform
/// dieser Anwendung ist.
#[tauri::command]
pub async fn draft_load_active(
    state: tauri::State<'_, DesktopState>,
) -> Result<DraftStateDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || draft_load_core(&state)).await
}

/// Das GEWOEHNLICHE Speichern — ohne Wiederanmeldung und ohne Bestaetigung.
///
/// # Errors
///
/// Der Code der Stufe 1 bei verletztem Eingabevertrag, sonst
/// [`DRAFTS_UNAVAILABLE`].
#[tauri::command]
pub async fn draft_save(
    state: tauri::State<'_, DesktopState>,
    incident: IncidentInputDto,
) -> Result<SyncStateDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || draft_save_core(&state, &incident)).await
}

/// Bucht die Verwerfensabsicht dauerhaft.
///
/// # Errors
///
/// [`DISCARD_UNAVAILABLE`]: `DiscardService` verlangt einen
/// `OperatorSessionProof` und eine beobachtete Zeit, und ein Nachweis ist auf
/// diesem Geraet nicht aufgeloest.
#[tauri::command]
pub async fn draft_discard_begin() -> Result<DiscardStateDto, CommandError> {
    run_blocking(|| Err(CommandError::new(DISCARD_UNAVAILABLE))).await
}

/// Setzt ein unterbrochenes Verwerfen fort.
///
/// # Errors
///
/// Wie [`draft_discard_begin`].
#[tauri::command]
pub async fn draft_discard_resume() -> Result<DiscardStateDto, CommandError> {
    run_blocking(|| Err(CommandError::new(DISCARD_UNAVAILABLE))).await
}

/// Loest eine liegende Abschlussmarke auf und meldet, wo sie steht.
///
/// # Errors
///
/// [`STARTUP_RECOVERY_UNAVAILABLE`] ohne verdrahteten Startpfad. Eine
/// ABLEHNUNG des Startpfads ist dagegen KEIN Fehler dieses Kommandos: sie ist
/// die Blockade, und sie reist als Code in der Antwort mit.
#[tauri::command]
pub async fn writer_recover_pending(
    state: tauri::State<'_, DesktopState>,
) -> Result<PendingResumeOutcomeDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || recover_pending_core(&state)).await
}

/// Die Abschlussvorschau.
///
/// # Errors
///
/// Der Code der Stufe 1 bei verletztem Eingabevertrag, [`WRITER_UNAVAILABLE`]
/// ohne verdrahteten Schreibport, sonst der stabile Code des Kerns.
#[tauri::command]
pub async fn writer_preview(
    state: tauri::State<'_, DesktopState>,
    incident: IncidentInputDto,
) -> Result<FinalizationPreviewDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || preview_core(&state, &incident)).await
}

/// Die Bestaetigung eines veralteten Registry-Head.
///
/// # Errors
///
/// [`STALE_ACK_UNAVAILABLE`]: der Bestaetigungspfad ist im Kern eine benannte
/// Auslassung (`ea-writer/src/lib.rs`), und der Ausgang ist dort fail-closed.
/// Diese Grenze erfindet ihn nicht — sie sagt, dass es ihn nicht gibt, und die
/// Oberflaeche zeigt daraufhin „keine Bestaetigung erfasst".
#[tauri::command]
pub async fn writer_acknowledge_stale_registry() -> Result<StaleAcknowledgementDto, CommandError> {
    run_blocking(|| Err(CommandError::new(STALE_ACK_UNAVAILABLE))).await
}

/// Der unwiderrufliche Abschluss.
///
/// # Errors
///
/// Wie [`writer_preview`], zusaetzlich [`PREVIEW_REJECTED`], wenn die
/// BESTAETIGTE Vorschau keinen Zeitstatus des Kontrakts nennt.
#[tauri::command]
pub async fn writer_finalize(
    state: tauri::State<'_, DesktopState>,
    incident: IncidentInputDto,
    confirmed: FinalizationPreviewDto,
) -> Result<FinalizeOutcomeDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || finalize_core(&state, &incident, &confirmed)).await
}

/// Der Gesundheitsbefund des Bestands.
///
/// # Errors
///
/// [`ARCHIVE_HEALTH_UNAVAILABLE`] ohne geoeffneten Bestand.
#[tauri::command]
pub async fn archive_health_report(
    state: tauri::State<'_, DesktopState>,
) -> Result<ArchiveHealthDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || archive_health_core(&state)).await
}

/// Die Haltung dieses Geraets.
///
/// # Errors
///
/// Keiner: ein unlesbares Signal ist ein `Unknown` und kein Fehlschlag.
#[tauri::command]
pub async fn device_posture_report() -> Result<DevicePostureDto, CommandError> {
    run_blocking(device_posture_core).await
}

/// Der Ein-Datei-Buendelexport.
///
/// # Errors
///
/// [`BUNDLE_EXPORT_UNAVAILABLE`]: `ea_archive_fs::write_archive_bundle`
/// verlangt einen aufgeloesten `TrustAnchorV1`, und `ea-trust` steht nicht in
/// der Abhaengigkeitsmenge dieses Pakets. Der Export ist deshalb PERMANENT
/// angeboten und heute benannt unverfuegbar — nicht bedingt versteckt.
///
/// OHNE Argument: das Ziel gehoert dem WIRT. Eine Oberflaeche, die einen
/// Dateipfad einreicht, waehlte einen Ort im Dateisystem — und die
/// Freies-Ziel-Regel samt `O_CREAT|O_EXCL` liegt im Kern.
#[tauri::command]
pub async fn archive_export_bundle_file() -> Result<BundleExportDto, CommandError> {
    run_blocking(|| Err(CommandError::new(BUNDLE_EXPORT_UNAVAILABLE))).await
}

#[cfg(test)]
mod tests {
    use ea_key_provider::{DevicePostureReport, PostureRequirement};
    use ea_types::ChainSequence;
    use ea_writer::{RecoveryOutcome, WriterError};

    use super::{
        ARCHIVE_HEALTH_UNAVAILABLE, ArchiveHealthReport, CommandError, DesktopState,
        FinalizationPreviewView, FinalizeOutcomeView, INCIDENT_INPUT_REJECTED, IncidentInputDto,
        IncidentInputView, WRITER_UNAVAILABLE, archive_health_core, blank_incident_dto,
        blocked_view, device_posture_core, draft_load_core, draft_save_core, draft_state_of,
        finalize_core, master_data_search_core, posture_view, preview_core, recover_pending_core,
        resume_view,
    };
    use crate::commands::NO_VERIFIED_SESSION;
    use crate::state::{ArchiveHealthPort, SessionState, StartupRecoveryPort};

    fn bare_state() -> DesktopState {
        DesktopState::new(SessionState::new(None, None), None, None, None, None, None)
    }

    struct FixedStartup(Result<RecoveryOutcome, WriterError>);

    impl StartupRecoveryPort for FixedStartup {
        fn resolve_pending_finalization(&self) -> Result<RecoveryOutcome, WriterError> {
            match &self.0 {
                Ok(RecoveryOutcome::NothingPending) => Ok(RecoveryOutcome::NothingPending),
                Ok(RecoveryOutcome::DraftRestored { unused_sequence }) => {
                    Ok(RecoveryOutcome::DraftRestored {
                        unused_sequence: *unused_sequence,
                    })
                }
                Ok(RecoveryOutcome::CommittedFromPreparedBytes { sequence }) => {
                    Ok(RecoveryOutcome::CommittedFromPreparedBytes {
                        sequence: *sequence,
                    })
                }
                Err(error) => Err(*error),
            }
        }
    }

    struct FixedHealth(ArchiveHealthReport);

    impl ArchiveHealthPort for FixedHealth {
        fn health(&self) -> Result<ArchiveHealthReport, ea_archive::ArchiveBackendError> {
            Ok(self.0.clone())
        }
    }

    fn state_with_startup(outcome: Result<RecoveryOutcome, WriterError>) -> DesktopState {
        DesktopState::new(
            SessionState::new(None, None),
            Some(std::sync::Arc::new(FixedStartup(outcome))),
            None,
            None,
            None,
            None,
        )
    }

    /// Eine Entwurfsablage, die AUFSCHREIBT, was sie bekommt.
    ///
    /// Sie ist der Grund, warum der Port ueber Zeichenketten geht: ein Doppel
    /// eines `DraftRepository` kann es ausserhalb von `ea-draft` nicht geben
    /// (`Draft` und `SavedDraft` haben nur `pub(crate)`-Konstruktoren), und ohne
    /// Doppel bliebe „das Speichern schreibt die EINGABE" eine Behauptung.
    struct RecordingDrafts {
        payload: std::sync::Mutex<String>,
        refuse: bool,
        /// Wie oft die Nutzlast GELESEN wurde.
        ///
        /// Ohne diesen Zaehler waere „ohne Nachweis kein Klartext" nur am
        /// Fehlercode messbar — und der stuende auch dann da, wenn die Grenze
        /// die entsiegelte Nutzlast erst holt und danach ablehnt.
        reads: std::sync::atomic::AtomicUsize,
    }

    impl RecordingDrafts {
        fn accepting(payload: &str) -> Self {
            Self {
                payload: std::sync::Mutex::new(payload.to_owned()),
                refuse: false,
                reads: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn refusing() -> Self {
            Self {
                payload: std::sync::Mutex::new(String::new()),
                refuse: true,
                reads: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn written(&self) -> String {
            self.payload
                .lock()
                .expect("kein vergiftetes Schloss")
                .clone()
        }

        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl crate::state::DraftPayloadPort for RecordingDrafts {
        fn load_payload(&self) -> Result<String, ea_draft::DraftError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.refuse {
                return Err(ea_draft::DraftError::NoDraft);
            }
            Ok(self.written())
        }

        fn save_payload(&self, payload: String) -> Result<(), ea_draft::DraftError> {
            if self.refuse {
                return Err(ea_draft::DraftError::RevisionConflict);
            }
            *self.payload.lock().expect("kein vergiftetes Schloss") = payload;
            Ok(())
        }
    }

    fn state_with_drafts(drafts: std::sync::Arc<RecordingDrafts>) -> DesktopState {
        state_with_drafts_and_session(drafts, SessionState::new(None, None))
    }

    fn state_with_drafts_and_session(
        drafts: std::sync::Arc<RecordingDrafts>,
        session: SessionState,
    ) -> DesktopState {
        DesktopState::new(session, None, None, Some(drafts), None, None)
    }

    /// Ein Schreibport, der die Vorschau und den Abschluss ZURUECKGIBT.
    ///
    /// Er haelt fest, mit welchem Rumpf er gerufen wurde: ohne dieses Argument
    /// koennte die Grenze eine andere Erfassung weiterreichen als die gepruefte,
    /// und der Zeuge bliebe gruen.
    struct FixedWriter {
        preview: FinalizationPreviewView,
        outcome: FinalizeOutcomeView,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl crate::state::WriterPreviewPort for FixedWriter {
        fn preview(
            &self,
            incident: &IncidentInputView,
        ) -> Result<FinalizationPreviewView, CommandError> {
            self.seen
                .lock()
                .expect("kein vergiftetes Schloss")
                .push(incident.human_incident_number.clone());
            Ok(self.preview)
        }
    }

    impl crate::state::WriterFinalizePort for FixedWriter {
        fn finalize(
            &self,
            incident: &IncidentInputView,
            confirmed: &FinalizationPreviewView,
        ) -> Result<FinalizeOutcomeView, CommandError> {
            assert_eq!(
                *confirmed, self.preview,
                "die bestaetigte Vorschau reist mit"
            );
            self.seen
                .lock()
                .expect("kein vergiftetes Schloss")
                .push(incident.human_incident_number.clone());
            Ok(self.outcome.clone())
        }
    }

    fn fixed_writer() -> std::sync::Arc<FixedWriter> {
        std::sync::Arc::new(FixedWriter {
            preview: FinalizationPreviewView {
                proposed_sequence: ChainSequence::new(7),
                binds_predecessor: true,
                effective_now: ea_types::UnixMillis::new(1_771_000_100_000),
                trust_age_ms: 3_600_000,
                reader_trust_refresh_ms: 604_800_000,
                trust_refresh_overdue: false,
                stale_decision: ea_ui_contracts::StaleDecision::Fresh,
            },
            seen: std::sync::Mutex::new(Vec::new()),
            outcome: FinalizeOutcomeView {
                sequence: ChainSequence::new(7),
                entry_hash: "aa".repeat(32),
                object_hash: "bb".repeat(32),
                sync: ea_ui_contracts::SyncStateView {
                    status: ea_archive_fs::SyncStatus::LocallySaved,
                    detail_cause: None,
                },
            },
        })
    }

    fn state_with_writer(writer: std::sync::Arc<FixedWriter>) -> DesktopState {
        DesktopState::new(
            SessionState::new(None, None),
            None,
            None,
            None,
            None,
            Some(writer),
        )
    }

    /// Vier `Unknown` sind die WAHRE Aussage ueber ein Geraet, dessen Haltung
    /// niemand gelesen hat — und `production_ready` ist dann `false`.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: ein Adapter oder eine Abbildung,
    /// die ein unlesbares Signal in ein `Some(true)` druecken — dann waere die
    /// Sperre der produktiven Rolle still gefallen.
    #[test]
    fn the_host_posture_reports_four_unresolved_requirements_and_is_not_production_ready() {
        let dto = device_posture_core().expect("die Haltung ist kein Fehlschlag");
        assert_eq!(dto.requirements.len(), PostureRequirement::ALL.len());
        assert!(!dto.production_ready);
        for requirement in &dto.requirements {
            assert_eq!(requirement.satisfied, None);
            assert!(requirement.evidence_code.ends_with("-UNREPORTABLE"));
            assert!(requirement.requirement_code.starts_with("EA-POSTURE-"));
        }
    }

    /// Die Abbildung selbst, an allen drei Ergebnissen — der Bericht des Hosts
    /// traegt heute nur eines davon.
    #[test]
    fn the_posture_mapping_keeps_pass_fail_and_unknown_apart() {
        let mut report = DevicePostureReport::unresolved();
        report.full_disk_encryption = PostureRequirement::FullDiskEncryption.pass();
        report.automatic_screen_lock = PostureRequirement::AutomaticScreenLock.fail();
        let view = posture_view(&report);
        assert_eq!(view.requirements[0].satisfied, Some(true));
        assert_eq!(view.requirements[1].satisfied, None);
        assert_eq!(view.requirements[2].satisfied, Some(false));
        assert!(!view.production_ready);
    }

    /// Der Startpfad hat aufgeloest: die Fortsetzung traegt Phase, Ausgang und
    /// Sequenz — und KEINEN Blockadecode.
    #[test]
    fn a_resolved_startup_path_carries_no_blocked_code() {
        let state = state_with_startup(Ok(RecoveryOutcome::CommittedFromPreparedBytes {
            sequence: ChainSequence::new(0),
        }));
        let dto = recover_pending_core(&state).expect("der Startpfad hat aufgeloest");
        assert_eq!(dto.blocked_code, None);
        assert_eq!(dto.resume.outcome_sequence, Some(0));
        assert_eq!(
            dto.resume.outcome_code.as_deref(),
            Some("CommittedFromPreparedBytes")
        );
        assert!(dto.resume.irreversible);
    }

    /// Nichts lag an: derselbe Weg, andere Phase, keine Sequenz.
    #[test]
    fn nothing_pending_is_a_reversible_draft_without_a_sequence() {
        let state = state_with_startup(Ok(RecoveryOutcome::NothingPending));
        let dto = recover_pending_core(&state).expect("der Startpfad hat aufgeloest");
        assert_eq!(dto.blocked_code, None);
        assert_eq!(dto.resume.outcome_sequence, None);
        assert!(!dto.resume.irreversible);
    }

    /// Der Startpfad hat ABGELEHNT: das ist kein Fehler des Kommandos, sondern
    /// die Blockade — mit dem Code des Kerns.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: eine Grenze, die die Ablehnung
    /// in einen `Err` verwandelt. Dann saehe die Oberflaeche „Wiederaufnahme
    /// nicht abgeschlossen" statt „externe Head-Reconciliation ausstehend" —
    /// und der Bediener wuesste nicht, dass er ein Backup zurueckgespielt hat.
    #[test]
    fn a_refused_startup_path_becomes_a_blocked_outcome_with_its_code() {
        let state = state_with_startup(Err(WriterError::HeadReconciliationRequired));
        let dto = recover_pending_core(&state).expect("die Ablehnung ist die Antwort");
        assert_eq!(
            dto.blocked_code.as_deref(),
            Some("EA-WRITER-HEAD-RECONCILIATION-REQUIRED")
        );
        assert_eq!(dto.sync, None);
    }

    /// Der Blockadecode kommt AUS dem Fehler und nicht aus einer Liste hier.
    #[test]
    fn the_blocked_code_is_the_code_of_the_core_error() {
        for error in [
            WriterError::HeadReconciliationRequired,
            WriterError::SequenceLeaseExhausted,
            WriterError::RegistryStaleBlocked,
        ] {
            assert_eq!(
                blocked_view(error).blocked_code.as_deref(),
                Some(error.code())
            );
        }
    }

    /// Ohne verdrahteten Startpfad: eine BENANNTE Abwesenheit.
    #[test]
    fn without_a_startup_path_the_recovery_names_its_absence() {
        let error = recover_pending_core(&bare_state()).expect_err("kein Startpfad");
        assert_eq!(error.code, super::STARTUP_RECOVERY_UNAVAILABLE);
    }

    /// Ein leerer Bericht heisst „alle zehn Erkenner haben nichts gefunden".
    #[test]
    fn an_empty_health_report_is_a_healthy_archive() {
        let state = DesktopState::new(
            SessionState::new(None, None),
            None,
            None,
            None,
            Some(std::sync::Arc::new(FixedHealth(
                ArchiveHealthReport::default(),
            ))),
            None,
        );
        let dto = archive_health_core(&state).expect("der Bericht liegt");
        assert!(dto.healthy);
        assert!(dto.finding_codes.is_empty());
    }

    /// Ohne geoeffneten Bestand: BENANNTE Abwesenheit und nicht „gesund".
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: ein Vorgabewert `healthy: true`
    /// fuer ein Archiv, das niemand gelesen hat.
    #[test]
    fn without_an_archive_the_health_names_its_absence() {
        let error = archive_health_core(&bare_state()).expect_err("kein Bestand");
        assert_eq!(error.code, ARCHIVE_HEALTH_UNAVAILABLE);
    }

    /// Ohne geoeffnete Stammdatenablage: BENANNTE Abwesenheit und nicht die
    /// leere Trefferliste.
    #[test]
    fn without_master_data_the_search_names_its_absence() {
        let error = master_data_search_core(&bare_state(), "P-1").expect_err("keine Ablage");
        assert_eq!(error.code, super::MASTER_DATA_UNAVAILABLE);
    }

    /// Der Eingabevertrag wird VOR der Abwesenheitsmeldung geprueft.
    ///
    /// Beide Haelften sind der Zeuge: ein gueltiger Rumpf kommt bis zur
    /// benannten Abwesenheit des Schreibdienstes, ein unbekannter
    /// Patientenzustand nicht. Ohne die zweite Haelfte koennte die Pruefung
    /// ganz fehlen und der Test bliebe gruen.
    #[test]
    fn the_incident_input_is_checked_before_the_writer_absence_is_reported() {
        let mut incident = valid_incident();
        assert_eq!(
            preview_core(&bare_state(), &incident)
                .expect_err("kein Schreibdienst")
                .code,
            WRITER_UNAVAILABLE
        );

        incident.patient_count_status = "Vielleicht".to_owned();
        assert_eq!(
            preview_core(&bare_state(), &incident)
                .expect_err("ein unbekannter Zustand ist keine Eingabe")
                .code,
            INCIDENT_INPUT_REJECTED
        );
    }

    /// Die SKALAREN Positionen werden an dieser Grenze von der Stufe 1
    /// zurueckgewiesen — mit DEREN Code und nicht mit einem eigenen.
    ///
    /// Gemessen an der Intervallregel: ein Ende vor dem Beginn ist
    /// `EA-SCHEMA-INTERVAL` aus `ea-schema` und keine Meldung dieser Datei.
    ///
    /// Was dieser Zeuge ausdruecklich NICHT behauptet: dass die biconditionale
    /// Listenregel `EA-SCHEMA-LIST-REASON` hier schon greift. Sie wird von
    /// `IncidentV1::new` erzwungen, und dieser Konstruktor verlangt die zwei
    /// Momentaufnahmelisten samt Revision und Provenienz — die entstehen
    /// ausschliesslich in der Stammdatenablage. Die Regel greift damit im
    /// Schreibdienst, und die Oberflaeche fuehrt sie zusaetzlich als Gestalt
    /// (das Begruendungsfeld existiert nur bei leerer Liste). Diese Grenze baut
    /// sie NICHT nach: eine zweite Fassung derselben eingefrorenen Regel waere
    /// eine zweite Quelle.
    #[test]
    fn the_scalar_positions_are_rejected_with_the_stage_one_code() {
        let mut incident = valid_incident();
        incident.occurred_at.end = Some(incident.occurred_at.start - 1);
        let error = preview_core(&bare_state(), &incident).expect_err("ein Ende vor dem Beginn");
        assert_eq!(error.code, "EA-SCHEMA-INTERVAL");

        incident.occurred_at.end = None;
        assert_eq!(
            preview_core(&bare_state(), &incident)
                .expect_err("jetzt faellt nur der Dienst")
                .code,
            WRITER_UNAVAILABLE
        );
    }

    /// Der Koordinatenbereich, an derselben Grenze und aus derselben Quelle.
    #[test]
    fn a_coordinate_outside_the_frozen_range_is_rejected() {
        let mut incident = valid_incident();
        incident.location.coordinates = Some(super::CoordinatesDto {
            lat_e7: 900_000_001,
            lon_e7: 0,
        });
        assert_eq!(
            preview_core(&bare_state(), &incident)
                .expect_err("Breite jenseits des Bereichs")
                .code,
            "EA-SCHEMA-COORDINATES"
        );
    }

    /// Der leere Rumpf ist eine gueltige DRAHTFORM und wird von der Stufe 1
    /// dennoch abgelehnt — ein leerer Entwurf ist kein abschliessbarer Einsatz.
    #[test]
    fn the_blank_incident_is_wire_valid_and_stage_one_invalid() {
        let blank = blank_incident_dto();
        assert!(blank.to_view().is_ok());
        assert!(preview_core(&bare_state(), &blank).is_err());
    }

    /// Die Fortsetzungsansicht traegt den Veroeffentlichungszustand, wenn einer
    /// gemeldet ist — und `None`, wenn keiner gemeldet ist.
    #[test]
    fn the_resume_view_reports_a_sync_state_only_when_one_is_given() {
        let outcome = RecoveryOutcome::NothingPending;
        assert_eq!(resume_view(&outcome, None).sync, None);
        let sync = ea_ui_contracts::SyncStateView {
            status: ea_archive_fs::SyncStatus::UploadPending,
            detail_cause: Some(ea_archive_fs::DetailCause::NetworkArchiveWaiting),
        };
        let view = resume_view(&outcome, Some(sync));
        assert_eq!(view.sync, Some(sync));
    }

    /// Das Speichern schreibt die EINGABE — und meldet erst danach `lokal
    /// gesichert`.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: eine Grenze, die die Eingabe
    /// prueft und dann den GELADENEN Entwurf zurueckspeichert. Sie meldete den
    /// bestaetigenden Zustand, der Bediener startete neu, und die Erfassung waere
    /// fort — ohne dass irgendein Pfad eine Abwesenheit benannt haette.
    #[test]
    fn saving_a_draft_writes_the_typed_incident_and_reads_it_back() {
        let drafts = std::sync::Arc::new(RecordingDrafts::accepting(""));
        let state = state_with_drafts(std::sync::Arc::clone(&drafts));

        // Der leere Entwurf ist ein leerer Rumpf und kein erfundener Inhalt.
        //
        // Gelesen wird ueber `draft_state_of` und nicht ueber `draft_load_core`:
        // der Kern traegt seit VM-15 das Sitzungstor, und ein
        // `OperatorSessionProof` ist ausserhalb von `ea-operator` nicht baubar.
        // Die ABBILDUNG Nutzlast → Drahtform, um die es diesem Zeugen geht,
        // liegt vollstaendig in `draft_state_of`; das Tor selbst hat seinen
        // eigenen Zeugen.
        let loaded = draft_state_of(drafts.as_ref()).expect("der Entwurf liegt");
        assert_eq!(loaded.incident, blank_incident_dto());

        let incident = valid_incident();
        let sync = draft_save_core(&state, &incident).expect("die Ablage nimmt an");
        assert_eq!(sync.status, ea_archive_fs::SyncStatus::LocallySaved.label());
        assert!(!drafts.written().is_empty(), "die Nutzlast ist geschrieben");

        let reloaded = draft_state_of(drafts.as_ref()).expect("der Entwurf liegt");
        assert_eq!(
            reloaded.incident, incident,
            "jede Position der Erfassung kommt zurueck"
        );
        assert_ne!(reloaded.incident, blank_incident_dto());
    }

    /// Eine abgelehnte Speicherung meldet KEINEN bestaetigten Zustand.
    #[test]
    fn a_refused_draft_write_reports_no_confirmed_sync_state() {
        let refusing = state_with_drafts(std::sync::Arc::new(RecordingDrafts::refusing()));
        assert_eq!(
            draft_save_core(&refusing, &valid_incident())
                .expect_err("die Ablage lehnt ab")
                .code,
            super::DRAFTS_UNAVAILABLE
        );
        assert_eq!(
            draft_save_core(&bare_state(), &valid_incident())
                .expect_err("keine Ablage")
                .code,
            super::DRAFTS_UNAVAILABLE
        );
    }

    /// Eine unlesbare Nutzlast ist eine BENANNTE Abwesenheit und nicht der leere
    /// Rumpf.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: ein `unwrap_or_default` beim
    /// Lesen. Es zeigte dem Bediener eine leere Maske ueber einer Erfassung, die
    /// noch da ist — und das naechste Speichern ueberschriebe sie.
    #[test]
    fn an_unreadable_draft_payload_is_a_named_absence() {
        let drafts = std::sync::Arc::new(RecordingDrafts::accepting("kein Einsatzrumpf"));
        assert_eq!(
            draft_state_of(drafts.as_ref())
                .expect_err("das ist keine Drahtform")
                .code,
            super::DRAFT_PAYLOAD_UNREADABLE
        );
    }

    /// Der Entwurfsklartext verlaesst die Grenze NUR mit Sitzungsnachweis — und
    /// wird ohne ihn nicht einmal gelesen.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: `draft_load_core` holt den
    /// Entwurfsport und ruft `load_payload()` — die unter dem `draftDEK`
    /// ENTSIEGELTE Nutzlast — ohne einen `OperatorSessionProof` zu konsultieren.
    /// Ein Geraet, das gesperrt und wieder entsperrt wird, zeigte den
    /// Einsatzrumpf dann ohne Wiederanmeldung, obwohl die Sperre den Nachweis
    /// entwertet hat (`crate::honor_session_lock`).
    ///
    /// Die Rolle ist hier GESETZT und der Nachweis fehlt: das ist der Zustand,
    /// in dem eine Grenze ohne die Klammer von `SessionState::role` eine
    /// Sitzung zu sehen glaubt. Der Zaehler ist die zweite Haelfte — er
    /// unterscheidet „abgelehnt, bevor gelesen wurde" von „gelesen und danach
    /// abgelehnt".
    #[test]
    fn loading_the_active_draft_without_a_session_proof_never_reads_the_payload() {
        let drafts = std::sync::Arc::new(RecordingDrafts::accepting(""));
        let state = state_with_drafts_and_session(
            std::sync::Arc::clone(&drafts),
            SessionState::new(Some(ea_format::OperatorRoleV1::Writer), None),
        );
        let incident = valid_incident();
        draft_save_core(&state, &incident).expect("das Speichern verlangt keinen Nachweis");
        assert!(!drafts.written().is_empty(), "die Nutzlast liegt jetzt da");

        assert_eq!(
            draft_load_core(&state)
                .expect_err("ohne Nachweis gibt diese Grenze keinen Klartext heraus")
                .code,
            NO_VERIFIED_SESSION
        );
        assert_eq!(
            drafts.reads(),
            0,
            "die entsiegelte Nutzlast wird ohne Nachweis nicht einmal geholt"
        );

        // Positivkontrolle: derselbe Port gibt genau diesen Rumpf heraus, wenn
        // er gefragt wird. Ohne sie koennte die Ablehnung oben auch an einem
        // leeren Port liegen.
        assert_eq!(
            draft_state_of(drafts.as_ref())
                .expect("der Entwurf liegt")
                .incident,
            incident
        );
        assert_eq!(drafts.reads(), 1);
    }

    /// Die Vorschau des Kerns kommt durch die GRENZE — als Drahtform.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: eine Grenze, die den Port nicht
    /// ruft (oder eine andere Erfassung weiterreicht als die gepruefte). Dann
    /// stuende der Aufruf von `WriterService::preview` nirgends, und die
    /// Bestaetigungsflaeche zeigte eine Vorschau, die niemand gerechnet hat.
    #[test]
    fn the_preview_comes_through_the_writer_port_as_the_wire_form() {
        let writer = fixed_writer();
        let state = state_with_writer(std::sync::Arc::clone(&writer));
        let dto = preview_core(&state, &valid_incident()).expect("der Port antwortet");
        assert_eq!(dto.proposed_sequence, 7);
        assert!(dto.binds_predecessor);
        assert_eq!(dto.effective_now, 1_771_000_100_000);
        // Die zwei Zahlen der Vertrauensfrist stehen NEBENEINANDER und sind
        // verschieden: vertauscht saehe der Bediener ein Alter von sieben Tagen
        // gegen eine Frist von einer Stunde.
        assert_eq!(dto.trust_age_ms, 3_600_000);
        assert_eq!(dto.reader_trust_refresh_ms, 604_800_000);
        assert!(!dto.trust_refresh_overdue);
        assert_eq!(dto.stale_decision, "Fresh");
        assert_eq!(
            writer
                .seen
                .lock()
                .expect("kein vergiftetes Schloss")
                .as_slice(),
            ["2026-0001"],
            "der GEPRUEFTE Rumpf erreicht den Port"
        );
    }

    /// Der Abschluss traegt die zwei HASHES und die Sequenz.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: eine Drahtform, die die Hashes
    /// fallen laesst. Dann zeigte der `FingerprintBlock` nach dem
    /// unwiderruflichen Schritt nur eine Zahl, und der Bediener haette keinen
    /// Fingerabdruck des Eintrags.
    #[test]
    fn the_finalize_outcome_carries_both_hashes_and_the_sequence() {
        let state = state_with_writer(fixed_writer());
        let confirmed = preview_core(&state, &valid_incident()).expect("der Port antwortet");
        let dto =
            finalize_core(&state, &valid_incident(), &confirmed).expect("der Port schliesst ab");
        assert_eq!(dto.sequence, 7);
        // JEDES Feld an SEINER Position: eine Laengenpruefung liesse die zwei
        // Hashes vertauschen, und ein vertauschter Fingerabdruck ist einer.
        assert_eq!(dto.entry_hash, "aa".repeat(32));
        assert_eq!(dto.object_hash, "bb".repeat(32));
        assert_eq!(
            dto.sync.status,
            ea_archive_fs::SyncStatus::LocallySaved.label()
        );
    }

    /// Ohne verdrahteten Schreibport: die Abwesenheit sitzt am PORT.
    #[test]
    fn without_a_writer_port_preview_and_finalize_name_the_absence() {
        let state = state_with_writer(fixed_writer());
        let confirmed = preview_core(&state, &valid_incident()).expect("der Port antwortet");
        assert_eq!(
            preview_core(&bare_state(), &valid_incident())
                .expect_err("kein Port")
                .code,
            WRITER_UNAVAILABLE
        );
        assert_eq!(
            finalize_core(&bare_state(), &valid_incident(), &confirmed)
                .expect_err("kein Port")
                .code,
            WRITER_UNAVAILABLE
        );
    }

    /// Eine bestaetigte Vorschau mit unbekanntem Zeitstatus ist keine.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: ein ungeprueftes Wort, das zu
    /// `Fresh` wird. Dann faellt die Bestaetigungspflicht des mittleren Arms
    /// `StaleAcknowledgeable` still weg.
    #[test]
    fn a_confirmed_preview_with_an_unknown_time_status_is_rejected() {
        let state = state_with_writer(fixed_writer());
        let mut confirmed = preview_core(&state, &valid_incident()).expect("der Port antwortet");
        confirmed.stale_decision = "Egal".to_owned();
        assert_eq!(
            finalize_core(&state, &valid_incident(), &confirmed)
                .expect_err("das ist kein Zeitstatus")
                .code,
            super::PREVIEW_REJECTED
        );
    }

    /// Ein Zustand `known` OHNE Zahl ist keine Eingabe — und ein `unknown` MIT
    /// Zahl auch nicht.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: die Grenze fuellt die fehlende
    /// Zahl mit einem Vorgabewert auf. Die Bestaetigungsansicht sagte dann
    /// „Patientenzahl unbekannt", und der Draht truege `known, 0` — zwei
    /// verschiedene Aussagen ueber dieselbe Zahl.
    #[test]
    fn a_divergent_patient_count_pair_is_rejected_at_the_boundary() {
        let mut incident = valid_incident();
        incident.patient_count = None;
        assert_eq!(
            incident
                .to_view()
                .expect_err("bekannt ohne Zahl ist keine Eingabe")
                .code,
            INCIDENT_INPUT_REJECTED
        );

        incident.patient_count_status = super::blank_incident_dto().patient_count_status;
        incident.patient_count = Some(3);
        assert_eq!(
            incident
                .to_view()
                .expect_err("unbekannt mit Zahl ist keine Eingabe")
                .code,
            INCIDENT_INPUT_REJECTED
        );

        incident.patient_count = None;
        assert!(
            incident.to_view().is_ok(),
            "unbekannt ohne Zahl ist gueltig"
        );
    }

    fn valid_incident() -> IncidentInputDto {
        IncidentInputDto {
            human_incident_number: "2026-0001".to_owned(),
            occurred_at: super::OccurredAtDto {
                start: 1_771_000_000_000,
                end: None,
            },
            keyword: super::KeywordDto {
                reference_id: None,
                display_text: "Verkehrsunfall".to_owned(),
            },
            location: super::LocationDto {
                free_text: Some("Bahnhofstrasse 1".to_owned()),
                address: None,
                coordinates: None,
            },
            personnel: vec![super::PersonnelSelectionDto {
                master_personnel_id: None,
                display_name: "A. Beispiel".to_owned(),
                role_label: None,
            }],
            personnel_empty_reason: None,
            vehicles: vec![super::VehicleSelectionDto {
                master_vehicle_id: None,
                display_name: "RTW 1".to_owned(),
                radio_call_name: None,
                license_plate: None,
            }],
            vehicles_empty_reason: None,
            patient_count_status: "Known".to_owned(),
            patient_count: Some(2),
            notes: None,
            external_organizations: Vec::new(),
        }
    }
}
