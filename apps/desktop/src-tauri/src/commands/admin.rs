//! Die Kommandoflaeche der VERWALTUNG (Stufe 5, Task 6, DRK-274).
//!
//! # Was hier WIRKLICH laeuft — und was benannt fehlt
//!
//! Diese Datei ist die Grenze, nicht die Fachlogik. Drei Zusagen liegen HIER
//! und nirgends sonst, und jede ist mit Doppeln bezeugt:
//!
//! 1. **Das Rollentor.** Jeder Kern verlangt die Rolle
//!    [`OperatorRoleV1::OrganizationAdmin`] ([`require_administrator`]) — ein
//!    Writer wird auch an einem verdrahteten Port abgewiesen, und der Port
//!    wird dann nicht einmal gerufen.
//! 2. **Die Schrittfolge.** Eine Trust-Zeremonie geht GENAU einen Schritt je
//!    Kommando ([`Administration::advance`]): die Grenze liest den erreichten
//!    Stand, verlangt mit `ea_admin::ceremony_steps::next_step`, dass das
//!    Kommando der eine Nachfolger ist, und prueft danach, dass der Port genau
//!    diesen erreicht hat. Ein Sprung — von der Schale verlangt oder vom Port
//!    behauptet — ist [`CEREMONY_STEP_OUT_OF_ORDER`].
//! 3. **Die Frischepflicht.** Schritte mit
//!    `ea_admin::ceremony_steps::requires_fresh_reauth`, die Aktivierung des
//!    Writer-Uebergangs und die Uhrenfreigabe VERBRAUCHEN eine unverbrauchte
//!    Marke aus [`SessionState::take_fresh_reauth`] fuer genau ihren Zweck —
//!    sonst [`REAUTH_REQUIRED`]. Der Nachweis selbst liegt beim Implementierer
//!    des Ports (siehe `crate::state::ReauthPort`); dort prueft der Kern ihn
//!    autoritativ.
//!
//! Was benannt FEHLT: der Port. Solange dieses Geraet keine aufgeloeste
//! Administratorbindung, keinen gewaehlten Head und keinen Trust-Speicher hat,
//! ist [`crate::state::AdministrationPort`] nicht verdrahtet, und jedes
//! Kommando antwortet mit [`ADMINISTRATION_UNAVAILABLE`]. Kein Kern liest
//! Freitext in einen Dienst: der Fingerprint wird HIER geparst
//! (`ea_admin::fingerprint`), die Art und die Begruendung HIER aus der
//! emittierten Vereinigung geholt; der Port sieht nur Werte. Die EINE
//! Ausnahme ist `admin_writer_transition_prepare(requestJson)`: das JSON der
//! Uebergangsanfrage geht als Text an den Port, weil der Kern es selbst
//! fail-closed liest — `LoadedWriterTransitionRequest::from_json` mit seinem
//! `REQUEST_LIMIT` — und ein zweiter Parser an dieser Grenze eine zweite
//! Wahrheit ueber dasselbe Dokument waere.
//!
//! Fail-closed ist die durchgaengige Richtung: eine unbekannte Voraussetzung
//! ist keine erfuellte, ein fremdes Drahtwort keine Wahl.

use std::sync::{Arc, Mutex};

use ea_admin::{
    GoLiveRequirementStatus, TrustCeremonyKind, TrustCeremonyStep,
    administration_runtime::{FingerprintSubjectV1, TrustCeremonyRoundV1},
    ceremony_steps::next_step_for_round,
    parse_human_readable_fingerprint, reauth_purpose, requires_fresh_reauth,
};
use ea_format::{ClockReleaseJustificationV1, OperatorRoleV1};
use ea_operator::ReauthPurpose;
use ea_ui_contracts::{
    ClockReleaseAvailability, ClockReleaseOfferView, ClockReleaseOutcomeView, GoLiveChecklistView,
    PendingDeviceRequestView, PolicyProfileView, RegistryHealthView, RevocationEffectView,
    RevocationTargetClass, TrustCeremonyView, WriterTransitionPhase, WriterTransitionView,
    clock_release_justification_from_wire, stale_decision_literal, trust_ceremony_kind_from_wire,
};
use serde::Serialize;

use super::{
    ADMINISTRATION_FORBIDDEN, ADMINISTRATION_UNAVAILABLE, ADMINISTRATION_WIRE_VALUE,
    CEREMONY_STEP_OUT_OF_ORDER, CommandError, REAUTH_REQUIRED, SESSION_STATE_UNREADABLE,
    TRANSITION_NOT_PREPARED, run_blocking,
};
use crate::state::{AdministrationPort, DesktopState, SessionState};

// ---------------------------------------------------------------------------
// Drahtliterale. Jeder `match` ohne Sammelarm; der Zeuge
// `every_admin_literal_is_the_emitted_one` misst sie gegen `ADMIN_ENUMS_V1`.
// Sie stehen hier und nicht in `ea-ui-contracts`, weil die dortigen Abbildungen
// privat sind — die EINE benannte Quelle bleibt die emittierte Tabelle.
// ---------------------------------------------------------------------------

pub(crate) const fn trust_ceremony_kind_literal(value: TrustCeremonyKind) -> &'static str {
    match value {
        TrustCeremonyKind::DeviceApprove => "DeviceApprove",
        TrustCeremonyKind::DeviceRevoke => "DeviceRevoke",
        TrustCeremonyKind::PolicyChange => "PolicyChange",
        TrustCeremonyKind::WriterTransition => "WriterTransition",
    }
}

pub(crate) const fn trust_ceremony_step_literal(value: TrustCeremonyStep) -> &'static str {
    match value {
        TrustCeremonyStep::PendingRequest => "PendingRequest",
        TrustCeremonyStep::FingerprintConfirmed => "FingerprintConfirmed",
        TrustCeremonyStep::AdminAuthorized => "AdminAuthorized",
        TrustCeremonyStep::RootRequestExported => "RootRequestExported",
        TrustCeremonyStep::RootReplyImported => "RootReplyImported",
        TrustCeremonyStep::RegistryPublished => "RegistryPublished",
        TrustCeremonyStep::TargetPublished => "TargetPublished",
    }
}

const fn fingerprint_subject_literal(value: FingerprintSubjectV1) -> &'static str {
    match value {
        FingerprintSubjectV1::RegistrationRequest => "RegistrationRequest",
        FingerprintSubjectV1::IssuedCertificate => "IssuedCertificate",
    }
}
const fn trust_ceremony_round_literal(value: TrustCeremonyRoundV1) -> &'static str {
    match value {
        TrustCeremonyRoundV1::IssueTarget => "IssueTarget",
        TrustCeremonyRoundV1::ActivateRegistry => "ActivateRegistry",
    }
}

pub(crate) const fn writer_transition_phase_literal(value: WriterTransitionPhase) -> &'static str {
    match value {
        WriterTransitionPhase::NoTransition => "NoTransition",
        WriterTransitionPhase::Prepared => "Prepared",
        WriterTransitionPhase::Activated => "Activated",
    }
}

pub(crate) const fn go_live_requirement_status_literal(
    value: GoLiveRequirementStatus,
) -> &'static str {
    match value {
        GoLiveRequirementStatus::Confirmed => "Confirmed",
        GoLiveRequirementStatus::NotMet => "NotMet",
        GoLiveRequirementStatus::NotAutomaticallyVerifiable => "NotAutomaticallyVerifiable",
    }
}

pub(crate) const fn clock_release_availability_literal(
    value: ClockReleaseAvailability,
) -> &'static str {
    match value {
        ClockReleaseAvailability::Offered => "Offered",
        ClockReleaseAvailability::IndependentTimeUnavailable => "IndependentTimeUnavailable",
        ClockReleaseAvailability::NotBlocked => "NotBlocked",
    }
}

pub(crate) const fn revocation_target_class_literal(value: RevocationTargetClass) -> &'static str {
    match value {
        RevocationTargetClass::NonAdminDevice => "NonAdminDevice",
        RevocationTargetClass::OperatorBinding => "OperatorBinding",
        RevocationTargetClass::Component => "Component",
    }
}

pub(crate) const fn clock_release_justification_literal(
    value: ClockReleaseJustificationV1,
) -> &'static str {
    match value {
        ClockReleaseJustificationV1::OperatorVerifiedWallClock => "OperatorVerifiedWallClock",
        ClockReleaseJustificationV1::PlatformTimeSourceRecovery => "PlatformTimeSourceRecovery",
        ClockReleaseJustificationV1::HardwareClockMaintenance => "HardwareClockMaintenance",
    }
}

// ---------------------------------------------------------------------------
// Drahtformen. Jede traegt `rename_all = "camelCase"` und ist die EINE
// Serialisierung ihres Ansichtsmodells aus `ea-ui-contracts` — dieselbe Bauart
// wie in `commands::writer`. Zeitpunkte sind `i64`-Millisekunden, Sequenzen und
// Versionen `u64`, Aufzaehlungen das emittierte Literal.
// ---------------------------------------------------------------------------

/// EINE ausstehende Geraeteanfrage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingDeviceRequestDto {
    pub request_id: String,
    pub certificate_kind_code: String,
    pub fingerprint: String,
    pub received_at_ms: i64,
    pub fingerprint_subject: &'static str,
}

impl From<&PendingDeviceRequestView> for PendingDeviceRequestDto {
    fn from(view: &PendingDeviceRequestView) -> Self {
        Self {
            request_id: view.request_id.clone(),
            certificate_kind_code: view.certificate_kind_code.clone(),
            fingerprint: view.fingerprint.clone(),
            received_at_ms: view.received_at_ms.get(),
            fingerprint_subject: fingerprint_subject_literal(view.fingerprint_subject),
        }
    }
}

/// Der Stand EINER Trust-Zeremonie.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustCeremonyDto {
    pub ceremony_id: String,
    pub kind: &'static str,
    pub step: &'static str,
    pub target_fingerprint: Option<String>,
    pub exchange_file_name: Option<String>,
    pub round: &'static str,
    pub linked_ceremony_id: Option<String>,
    pub fingerprint_subject: Option<&'static str>,
}

impl TryFrom<&TrustCeremonyView> for TrustCeremonyDto {
    type Error = CommandError;

    /// `TryFrom` und nicht `From`, weil die Ansicht einen Wert traegt, den die
    /// Grenze pruefen MUSS ([`checked_exchange_file_name`]) — ein `From`
    /// haette ihn still durchgereicht, und jeder Zeremoniekern geht hier
    /// durch.
    fn try_from(view: &TrustCeremonyView) -> Result<Self, CommandError> {
        if view.target_fingerprint.is_some() != view.fingerprint_subject.is_some()
            || (view.step == TrustCeremonyStep::RegistryPublished
                && view.round != TrustCeremonyRoundV1::ActivateRegistry)
            || (view.step == TrustCeremonyStep::TargetPublished
                && view.round != TrustCeremonyRoundV1::IssueTarget)
        {
            return Err(CommandError::new(ADMINISTRATION_WIRE_VALUE));
        }
        let ceremony_id = checked_ceremony_identifier(&view.ceremony_id)?;
        let linked_ceremony_id = view
            .linked_ceremony_id
            .as_deref()
            .map(checked_ceremony_identifier)
            .transpose()?;
        if linked_ceremony_id.as_ref() == Some(&ceremony_id) {
            return Err(CommandError::new(ADMINISTRATION_WIRE_VALUE));
        }
        if let Some(fingerprint) = &view.target_fingerprint {
            parse_human_readable_fingerprint(fingerprint)
                .map_err(|_| CommandError::new(ADMINISTRATION_WIRE_VALUE))?;
        }
        Ok(Self {
            ceremony_id,
            kind: trust_ceremony_kind_literal(view.kind),
            step: trust_ceremony_step_literal(view.step),
            target_fingerprint: view.target_fingerprint.clone(),
            exchange_file_name: checked_exchange_file_name(view.exchange_file_name.as_deref())?,
            round: trust_ceremony_round_literal(view.round),
            linked_ceremony_id,
            fingerprint_subject: view.fingerprint_subject.map(fingerprint_subject_literal),
        })
    }
}

fn checked_ceremony_identifier(value: &str) -> Result<String, CommandError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(CommandError::new(ADMINISTRATION_WIRE_VALUE));
    }
    Ok(value.to_owned())
}

/// `exchangeFileName` ist ein NAME und nie ein Pfad.
///
/// Die Global Constraints verbieten einen Pfad auf der Oberflaeche, und ein
/// Port, der einen Pfad haendigt, legte ihn genau dort ab — der Emitter
/// verspricht der Schale einen Dateinamen, und die Schale zeigt, was sie
/// bekommt. Ein Trenner (`/`, `\`), ein Elternverweis (`..`) oder ein leerer
/// Name ist deshalb [`ADMINISTRATION_WIRE_VALUE`]: der Wert des Ports ist
/// keiner der vereinbarten, so wie ein fremdes Drahtwort der Schale keine
/// Wahl ist. `None` bleibt `None` — vor dem Export gibt es keine Datei.
fn checked_exchange_file_name(name: Option<&str>) -> Result<Option<String>, CommandError> {
    match name {
        None => Ok(None),
        Some(name) if name.is_empty() || name.contains(['/', '\\']) || name.contains("..") => {
            Err(CommandError::new(ADMINISTRATION_WIRE_VALUE))
        }
        Some(name) => Ok(Some(name.to_owned())),
    }
}

/// Das Policy-Profil des gewaehlten Kopfes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyProfileDto {
    pub operating_profile: u8,
    pub max_registry_age_ms: u64,
    pub max_future_clock_skew_ms: u64,
    pub registry_expiry_behavior: u8,
    pub evidence_max_delay_ms: u64,
    pub reader_inactivity_ms: u64,
    pub reader_trust_refresh_ms: u64,
    pub reader_history_access_allowed: bool,
    pub backup_frequency_ms: u64,
    pub restore_test_interval_ms: u64,
    pub minimum_retention_ms: Option<u64>,
    pub destruction_enabled: bool,
    pub effective_from_sequence: u64,
    pub lease_valid_through_sequence: u64,
    pub not_after_ms: i64,
}

impl From<&PolicyProfileView> for PolicyProfileDto {
    fn from(view: &PolicyProfileView) -> Self {
        Self {
            operating_profile: view.operating_profile,
            max_registry_age_ms: view.max_registry_age_ms,
            max_future_clock_skew_ms: view.max_future_clock_skew_ms,
            registry_expiry_behavior: view.registry_expiry_behavior,
            evidence_max_delay_ms: view.evidence_max_delay_ms,
            reader_inactivity_ms: view.reader_inactivity_ms,
            reader_trust_refresh_ms: view.reader_trust_refresh_ms,
            reader_history_access_allowed: view.reader_history_access_allowed,
            backup_frequency_ms: view.backup_frequency_ms,
            restore_test_interval_ms: view.restore_test_interval_ms,
            minimum_retention_ms: view.minimum_retention_ms,
            destruction_enabled: view.destruction_enabled,
            effective_from_sequence: view.effective_from_sequence.get(),
            lease_valid_through_sequence: view.lease_valid_through_sequence.get(),
            not_after_ms: view.not_after_ms.get(),
        }
    }
}

/// Alter, Lease und Zeitstatus des gewaehlten Kopfes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryHealthDto {
    pub registry_version: u64,
    pub head_hash: String,
    pub registry_age_ms: u64,
    pub max_registry_age_ms: u64,
    pub lease_valid_through_sequence: u64,
    pub next_sequence: u64,
    pub not_after_ms: i64,
    pub stale_decision: &'static str,
}

impl From<&RegistryHealthView> for RegistryHealthDto {
    fn from(view: &RegistryHealthView) -> Self {
        Self {
            registry_version: view.registry_version.get(),
            head_hash: view.head_hash.clone(),
            registry_age_ms: view.registry_age_ms,
            max_registry_age_ms: view.max_registry_age_ms,
            lease_valid_through_sequence: view.lease_valid_through_sequence.get(),
            next_sequence: view.next_sequence.get(),
            not_after_ms: view.not_after_ms.get(),
            stale_decision: stale_decision_literal(view.stale_decision),
        }
    }
}

/// EINE Go-live-Anforderung.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoLiveRequirementDto {
    pub requirement_code: String,
    pub status: &'static str,
    pub evidence_code: String,
    pub decision_document_hash: Option<String>,
}

/// Die Go-live-Liste; `production_ready` kommt aus dem Aggregat und wird hier
/// nicht nachgerechnet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoLiveChecklistDto {
    pub requirements: Vec<GoLiveRequirementDto>,
    pub production_ready: bool,
}

impl From<&GoLiveChecklistView> for GoLiveChecklistDto {
    fn from(view: &GoLiveChecklistView) -> Self {
        Self {
            requirements: view
                .requirements
                .iter()
                .map(|requirement| GoLiveRequirementDto {
                    requirement_code: requirement.requirement_code.clone(),
                    status: go_live_requirement_status_literal(requirement.status),
                    evidence_code: requirement.evidence_code.clone(),
                    decision_document_hash: requirement.decision_document_hash.clone(),
                })
                .collect(),
            production_ready: view.production_ready,
        }
    }
}

/// Was der Uhrenfreigabe-Assistent zeigen darf.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClockReleaseOfferDto {
    pub availability: &'static str,
    pub floor_ms: Option<i64>,
    pub observed_wall_clock_ms: Option<i64>,
    pub max_future_clock_skew_ms: Option<u64>,
    pub expires_at_ms: Option<i64>,
    pub justifications: Vec<&'static str>,
}

impl From<&ClockReleaseOfferView> for ClockReleaseOfferDto {
    fn from(view: &ClockReleaseOfferView) -> Self {
        Self {
            availability: clock_release_availability_literal(view.availability),
            floor_ms: view.floor_ms.map(ea_types::UnixMillis::get),
            observed_wall_clock_ms: view.observed_wall_clock_ms.map(ea_types::UnixMillis::get),
            max_future_clock_skew_ms: view.max_future_clock_skew_ms,
            expires_at_ms: view.expires_at_ms.map(ea_types::UnixMillis::get),
            justifications: view
                .justifications
                .iter()
                .copied()
                .map(clock_release_justification_literal)
                .collect(),
        }
    }
}

/// Das Ergebnis einer ausgestellten Uhrenfreigabe — die drei `changes_*` sind
/// Felder des Kerns und keine Prosa dieser Grenze.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClockReleaseOutcomeDto {
    pub release_id: String,
    pub expires_at_ms: i64,
    pub changes_time_floor: bool,
    pub changes_registry_expiry: bool,
    pub changes_lease: bool,
}

impl From<&ClockReleaseOutcomeView> for ClockReleaseOutcomeDto {
    fn from(view: &ClockReleaseOutcomeView) -> Self {
        Self {
            release_id: view.release_id.clone(),
            expires_at_ms: view.expires_at_ms.get(),
            changes_time_floor: view.changes_time_floor,
            changes_registry_expiry: view.changes_registry_expiry,
            changes_lease: view.changes_lease,
        }
    }
}

/// Der Stand des Writer-Uebergangs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriterTransitionDto {
    pub phase: &'static str,
    pub ceremony_id: Option<String>,
    pub current_writer_hash: String,
    pub new_writer_hash: Option<String>,
    pub effective_from_sequence: Option<u64>,
}

impl From<&WriterTransitionView> for WriterTransitionDto {
    fn from(view: &WriterTransitionView) -> Self {
        Self {
            phase: writer_transition_phase_literal(view.phase),
            ceremony_id: view.ceremony_id.clone(),
            current_writer_hash: view.current_writer_hash.clone(),
            new_writer_hash: view.new_writer_hash.clone(),
            effective_from_sequence: view
                .effective_from_sequence
                .map(ea_types::ChainSequence::get),
        }
    }
}

/// Was ein Widerruf tut — und was er ausdruecklich NICHT tut.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationEffectDto {
    pub target_class: &'static str,
    pub target_hash: String,
    pub stops_new_grants_from_sequence: u64,
    pub recalls_issued_grants: bool,
    pub recalls_decrypted_plaintext: bool,
}

impl From<&RevocationEffectView> for RevocationEffectDto {
    fn from(view: &RevocationEffectView) -> Self {
        Self {
            target_class: revocation_target_class_literal(view.target_class),
            target_hash: view.target_hash.clone(),
            stops_new_grants_from_sequence: view.stops_new_grants_from_sequence.get(),
            recalls_issued_grants: view.recalls_issued_grants,
            recalls_decrypted_plaintext: view.recalls_decrypted_plaintext,
        }
    }
}

// ---------------------------------------------------------------------------
// Das Tor und die Grenze.
// ---------------------------------------------------------------------------

/// Das Rollentor: nur [`OperatorRoleV1::OrganizationAdmin`] kommt durch.
///
/// Ein `match` ohne Sammelarm ueber die Rolle, damit eine vierte Rolle hier
/// ausdruecklich entscheidet. `None` — keine Rolle mit Nachweis — ist kein
/// Administrator und bekommt denselben Code: die Schale erfaehrt die fehlende
/// Sitzung aus `verified_session`, nicht aus einem Verwaltungskommando.
pub(crate) const fn require_administrator(
    role: Option<OperatorRoleV1>,
) -> Result<(), CommandError> {
    match role {
        Some(OperatorRoleV1::OrganizationAdmin) => Ok(()),
        Some(OperatorRoleV1::Writer | OperatorRoleV1::Reader) | None => {
            Err(CommandError::new(ADMINISTRATION_FORBIDDEN))
        }
    }
}

/// Die Verwaltungsgrenze HINTER dem Tor: der Port und die Sitzung, an der die
/// Frischemarke haengt.
///
/// Getrennt von [`administration`], damit die Abbildung Port → Drahtform samt
/// Schrittfolge und Frischepflicht mit Doppeln messbar ist: der Weg durch das
/// Tor ist hier nur fail-closed messbar, weil `SessionState::role` einen
/// [`ea_operator::OperatorSessionProof`] verlangt und den ausserhalb von
/// `ea-operator` niemand bauen kann.
pub(crate) struct Administration<'a> {
    pub(crate) port: Arc<dyn AdministrationPort + Send + Sync>,
    pub(crate) session: &'a Mutex<SessionState>,
}

/// Das Tor: erst der Port, dann die Rolle.
///
/// Der Port zuerst, wie bei `commands::writer::discard_port`: die Abwesenheit
/// sitzt an der fehlenden Naht und ist ohne Nachweis messbar. Ein Nichtadmin
/// erfaehrt so hoechstens, dass die Verwaltung nicht verdrahtet ist — und
/// nichts ueber ihren Stand.
fn administration(state: &DesktopState) -> Result<Administration<'_>, CommandError> {
    let port = state
        .administration_port()
        .ok_or_else(|| CommandError::new(ADMINISTRATION_UNAVAILABLE))?;
    let role = state.verified_role()?;
    require_administrator(role)?;
    Ok(Administration {
        port,
        session: state.session(),
    })
}

impl Administration<'_> {
    /// Verbraucht die Frischemarke fuer `purpose` — oder verweigert den
    /// Schritt.
    fn take_fresh_reauth(&self, purpose: ReauthPurpose) -> Result<(), CommandError> {
        let taken = self
            .session
            .lock()
            .map_err(|_| CommandError::new(SESSION_STATE_UNREADABLE))?
            .take_fresh_reauth(purpose);
        if taken {
            Ok(())
        } else {
            Err(CommandError::new(REAUTH_REQUIRED))
        }
    }

    /// GENAU ein Schritt einer Zeremonie: `target` muss der eine Nachfolger
    /// des erreichten Schritts sein, die Frischepflicht wird VOR dem Port
    /// erfuellt, und der Port muss danach genau `target` erreicht haben.
    ///
    /// Die Reihenfolge ist die Aussage: Reihenfolge vor Praesenz, damit ein
    /// Schritt ausser der Reihe keine Marke verbraucht; Praesenz vor dem Port,
    /// damit der Kern nie ohne sie gerufen wird.
    fn advance(
        &self,
        ceremony_id: &str,
        target: TrustCeremonyStep,
        step: impl FnOnce(&dyn AdministrationPort) -> Result<TrustCeremonyView, CommandError>,
    ) -> Result<TrustCeremonyDto, CommandError> {
        self.advance_with_target(ceremony_id, |_| target, step)
    }

    fn advance_with_target(
        &self,
        ceremony_id: &str,
        target: impl FnOnce(&TrustCeremonyView) -> TrustCeremonyStep,
        step: impl FnOnce(&dyn AdministrationPort) -> Result<TrustCeremonyView, CommandError>,
    ) -> Result<TrustCeremonyDto, CommandError> {
        let current = self.port.ceremony(ceremony_id)?;
        let target = target(&current);
        if current.ceremony_id != ceremony_id
            || next_step_for_round(current.kind, current.round, current.step) != Some(target)
        {
            return Err(CommandError::new(CEREMONY_STEP_OUT_OF_ORDER));
        }
        if requires_fresh_reauth(target) {
            self.take_fresh_reauth(reauth_purpose(current.kind))?;
        }
        let reached = step(self.port.as_ref())?;
        if reached.ceremony_id != current.ceremony_id
            || reached.kind != current.kind
            || reached.round != current.round
            || reached.step != target
        {
            return Err(CommandError::new(CEREMONY_STEP_OUT_OF_ORDER));
        }
        TrustCeremonyDto::try_from(&reached)
    }

    pub(crate) fn pending_device_requests(
        &self,
    ) -> Result<Vec<PendingDeviceRequestDto>, CommandError> {
        Ok(self
            .port
            .pending_device_requests()?
            .iter()
            .map(PendingDeviceRequestDto::from)
            .collect())
    }

    pub(crate) fn open_ceremonies(&self) -> Result<Vec<TrustCeremonyDto>, CommandError> {
        let rounds = self.port.open_ceremonies()?;
        if rounds.len() > 4096 {
            return Err(CommandError::new(ADMINISTRATION_WIRE_VALUE));
        }
        let mut ids = std::collections::BTreeSet::new();
        rounds
            .iter()
            .map(|round| {
                checked_ceremony_identifier(&round.ceremony_id)?;
                if !ids.insert(&round.ceremony_id)
                    || matches!(
                        round.step,
                        TrustCeremonyStep::TargetPublished | TrustCeremonyStep::RegistryPublished
                    )
                {
                    return Err(CommandError::new(ADMINISTRATION_WIRE_VALUE));
                }
                TrustCeremonyDto::try_from(round)
            })
            .collect()
    }

    /// Beginnt eine Zeremonie; der Beginn steht auf `PendingRequest`, alles
    /// andere ist ein Sprung.
    pub(crate) fn ceremony_begin(
        &self,
        request_id: &str,
        kind: &str,
    ) -> Result<TrustCeremonyDto, CommandError> {
        let kind = trust_ceremony_kind_from_wire(kind)
            .ok_or_else(|| CommandError::new(ADMINISTRATION_WIRE_VALUE))?;
        let begun = self.port.begin_ceremony(request_id, kind)?;
        if begun.kind != kind || begun.step != TrustCeremonyStep::PendingRequest {
            return Err(CommandError::new(CEREMONY_STEP_OUT_OF_ORDER));
        }
        TrustCeremonyDto::try_from(&begun)
    }

    pub(crate) fn ceremony_read(
        &self,
        ceremony_id: &str,
    ) -> Result<TrustCeremonyDto, CommandError> {
        checked_ceremony_identifier(ceremony_id)?;
        let value = self.port.ceremony(ceremony_id)?;
        if value.ceremony_id != ceremony_id {
            return Err(CommandError::new(ADMINISTRATION_WIRE_VALUE));
        }
        TrustCeremonyDto::try_from(&value)
    }

    /// Der Freitext des Bedieners wird HIER gelesen; der Port sieht den Hash.
    pub(crate) fn confirm_fingerprint(
        &self,
        ceremony_id: &str,
        reported_fingerprint: &str,
    ) -> Result<TrustCeremonyDto, CommandError> {
        let reported = parse_human_readable_fingerprint(reported_fingerprint)
            .map_err(|error| CommandError::new(error.code()))?;
        self.advance(
            ceremony_id,
            TrustCeremonyStep::FingerprintConfirmed,
            |port| port.confirm_fingerprint(ceremony_id, &reported),
        )
    }

    pub(crate) fn authorize(&self, ceremony_id: &str) -> Result<TrustCeremonyDto, CommandError> {
        self.advance(ceremony_id, TrustCeremonyStep::AdminAuthorized, |port| {
            port.authorize(ceremony_id)
        })
    }

    pub(crate) fn export_request(
        &self,
        ceremony_id: &str,
    ) -> Result<TrustCeremonyDto, CommandError> {
        self.advance(
            ceremony_id,
            TrustCeremonyStep::RootRequestExported,
            |port| port.export_request(ceremony_id),
        )
    }

    pub(crate) fn import_reply(&self, ceremony_id: &str) -> Result<TrustCeremonyDto, CommandError> {
        self.advance(ceremony_id, TrustCeremonyStep::RootReplyImported, |port| {
            port.import_reply(ceremony_id)
        })
    }

    pub(crate) fn publish(&self, ceremony_id: &str) -> Result<TrustCeremonyDto, CommandError> {
        self.advance_with_target(
            ceremony_id,
            |current| match current.round {
                TrustCeremonyRoundV1::IssueTarget => TrustCeremonyStep::TargetPublished,
                TrustCeremonyRoundV1::ActivateRegistry => TrustCeremonyStep::RegistryPublished,
            },
            |port| port.publish(ceremony_id),
        )
    }

    pub(crate) fn policy_profile(&self) -> Result<PolicyProfileDto, CommandError> {
        self.port
            .policy_profile()
            .map(|view| PolicyProfileDto::from(&view))
    }

    pub(crate) fn registry_health(&self) -> Result<RegistryHealthDto, CommandError> {
        self.port
            .registry_health()
            .map(|view| RegistryHealthDto::from(&view))
    }

    pub(crate) fn go_live_checklist(&self) -> Result<GoLiveChecklistDto, CommandError> {
        self.port
            .go_live_checklist()
            .map(|checklist| GoLiveChecklistDto::from(&GoLiveChecklistView::from(&checklist)))
    }

    /// Die Evidenzliste `ea.go-live-checklist/v1` — Text, den die Schale
    /// unveraendert weiterreicht.
    pub(crate) fn go_live_export_unresolved(&self) -> Result<String, CommandError> {
        self.port
            .go_live_checklist()
            .map(|checklist| checklist.unresolved_report_json())
    }

    pub(crate) fn clock_release_offer(&self) -> Result<ClockReleaseOfferDto, CommandError> {
        self.port
            .clock_release_offer()
            .map(|view| ClockReleaseOfferDto::from(&view))
    }

    /// Erst das Drahtwort, dann die Praesenz, dann der Port: ein Drahtfehler
    /// verbraucht keine Marke.
    pub(crate) fn clock_release_issue(
        &self,
        justification: &str,
    ) -> Result<ClockReleaseOutcomeDto, CommandError> {
        let justification = clock_release_justification_from_wire(justification)
            .ok_or_else(|| CommandError::new(ADMINISTRATION_WIRE_VALUE))?;
        self.take_fresh_reauth(ReauthPurpose::ClockSkewRelease)?;
        self.port
            .clock_release_issue(justification)
            .map(|view| ClockReleaseOutcomeDto::from(&view))
    }

    pub(crate) fn writer_transition_state(&self) -> Result<WriterTransitionDto, CommandError> {
        self.port
            .writer_transition_state()
            .map(|view| WriterTransitionDto::from(&view))
    }

    pub(crate) fn writer_transition_prepare(
        &self,
        request_json: &str,
    ) -> Result<WriterTransitionDto, CommandError> {
        self.port
            .writer_transition_prepare(request_json)
            .map(|view| WriterTransitionDto::from(&view))
    }

    /// Die Aktivierung ist eine Root-Wirkung und verlangt denselben Zweck wie
    /// die Zeremonieart `WriterTransition` — aber erst der Stand, dann die
    /// Praesenz, dann der Port: ein Uebergang, der nicht `Prepared` ist, wird
    /// mit [`TRANSITION_NOT_PREPARED`] abgewiesen, OHNE die Marke zu
    /// verbrauchen (wie [`Administration::advance`]: Reihenfolge vor
    /// Praesenz).
    pub(crate) fn writer_transition_activate(&self) -> Result<WriterTransitionDto, CommandError> {
        let current = self.port.writer_transition_state()?;
        if current.phase != WriterTransitionPhase::Prepared {
            return Err(CommandError::new(TRANSITION_NOT_PREPARED));
        }
        self.take_fresh_reauth(reauth_purpose(TrustCeremonyKind::WriterTransition))?;
        self.port
            .writer_transition_activate()
            .map(|view| WriterTransitionDto::from(&view))
    }

    /// Der Zielhash kommt als Text der Ansicht zurueck — mit oder ohne
    /// Doppelpunkte — und wird HIER zum Hash; ein unlesbarer ist ein
    /// Drahtfehler und kein Fingerprintfehler des Bedieners.
    pub(crate) fn revocation_effect(
        &self,
        target_hash: &str,
    ) -> Result<RevocationEffectDto, CommandError> {
        let target = parse_human_readable_fingerprint(target_hash)
            .map_err(|_| CommandError::new(ADMINISTRATION_WIRE_VALUE))?;
        self.port
            .revocation_effect(&target)
            .map(|view| RevocationEffectDto::from(&view))
    }
}

// ---------------------------------------------------------------------------
// Die Kerne: Tor, dann Grenze. Einer je Kommando, damit jede Abwesenheit und
// jedes Verbot am Kern messbar ist.
// ---------------------------------------------------------------------------

pub(crate) fn pending_device_requests_core(
    state: &DesktopState,
) -> Result<Vec<PendingDeviceRequestDto>, CommandError> {
    administration(state)?.pending_device_requests()
}

pub(crate) fn open_ceremonies_core(
    state: &DesktopState,
) -> Result<Vec<TrustCeremonyDto>, CommandError> {
    administration(state)?.open_ceremonies()
}

pub(crate) fn ceremony_begin_core(
    state: &DesktopState,
    request_id: &str,
    kind: &str,
) -> Result<TrustCeremonyDto, CommandError> {
    administration(state)?.ceremony_begin(request_id, kind)
}

pub(crate) fn ceremony_read_core(
    state: &DesktopState,
    ceremony_id: &str,
) -> Result<TrustCeremonyDto, CommandError> {
    administration(state)?.ceremony_read(ceremony_id)
}

pub(crate) fn ceremony_confirm_fingerprint_core(
    state: &DesktopState,
    ceremony_id: &str,
    reported_fingerprint: &str,
) -> Result<TrustCeremonyDto, CommandError> {
    administration(state)?.confirm_fingerprint(ceremony_id, reported_fingerprint)
}

pub(crate) fn ceremony_authorize_core(
    state: &DesktopState,
    ceremony_id: &str,
) -> Result<TrustCeremonyDto, CommandError> {
    administration(state)?.authorize(ceremony_id)
}

pub(crate) fn ceremony_export_request_core(
    state: &DesktopState,
    ceremony_id: &str,
) -> Result<TrustCeremonyDto, CommandError> {
    administration(state)?.export_request(ceremony_id)
}

pub(crate) fn ceremony_import_reply_core(
    state: &DesktopState,
    ceremony_id: &str,
) -> Result<TrustCeremonyDto, CommandError> {
    administration(state)?.import_reply(ceremony_id)
}

pub(crate) fn ceremony_publish_core(
    state: &DesktopState,
    ceremony_id: &str,
) -> Result<TrustCeremonyDto, CommandError> {
    administration(state)?.publish(ceremony_id)
}

pub(crate) fn policy_profile_core(state: &DesktopState) -> Result<PolicyProfileDto, CommandError> {
    administration(state)?.policy_profile()
}

pub(crate) fn writer_lock_diagnosis_core(
    state: &DesktopState,
) -> Result<&'static str, CommandError> {
    administration(state)?
        .port
        .diagnose_writer_lock()
        .map(ea_ui_contracts::local_writer_lock_diagnosis_literal)
}

pub(crate) fn registry_health_core(
    state: &DesktopState,
) -> Result<RegistryHealthDto, CommandError> {
    administration(state)?.registry_health()
}

pub(crate) fn go_live_checklist_core(
    state: &DesktopState,
) -> Result<GoLiveChecklistDto, CommandError> {
    administration(state)?.go_live_checklist()
}

pub(crate) fn go_live_export_unresolved_core(state: &DesktopState) -> Result<String, CommandError> {
    administration(state)?.go_live_export_unresolved()
}

pub(crate) fn clock_release_offer_core(
    state: &DesktopState,
) -> Result<ClockReleaseOfferDto, CommandError> {
    administration(state)?.clock_release_offer()
}

pub(crate) fn clock_release_issue_core(
    state: &DesktopState,
    justification: &str,
) -> Result<ClockReleaseOutcomeDto, CommandError> {
    administration(state)?.clock_release_issue(justification)
}

pub(crate) fn writer_transition_state_core(
    state: &DesktopState,
) -> Result<WriterTransitionDto, CommandError> {
    administration(state)?.writer_transition_state()
}

pub(crate) fn writer_transition_prepare_core(
    state: &DesktopState,
    request_json: &str,
) -> Result<WriterTransitionDto, CommandError> {
    administration(state)?.writer_transition_prepare(request_json)
}

pub(crate) fn writer_transition_activate_core(
    state: &DesktopState,
) -> Result<WriterTransitionDto, CommandError> {
    administration(state)?.writer_transition_activate()
}

pub(crate) fn revocation_effect_core(
    state: &DesktopState,
    target_hash: &str,
) -> Result<RevocationEffectDto, CommandError> {
    administration(state)?.revocation_effect(target_hash)
}

// ---------------------------------------------------------------------------
// Die Kommandos. Jeder Rumpf ist `pub async fn` und schickt seinen synchronen
// Kern ueber `run_blocking`. Die Argumentnamen sind am Draht camelCase
// (`requestId`, `ceremonyId`, `reportedFingerprint`, `requestJson`,
// `targetHash`) — Tauris Vorgabe fuer `snake_case`-Parameter.
// ---------------------------------------------------------------------------

/// Die ausstehenden Geraeteanfragen.
///
/// # Errors
///
/// [`ADMINISTRATION_UNAVAILABLE`], [`ADMINISTRATION_FORBIDDEN`], oder der Code
/// des Kerns.
#[tauri::command]
pub async fn admin_pending_device_requests(
    state: tauri::State<'_, DesktopState>,
) -> Result<Vec<PendingDeviceRequestDto>, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || pending_device_requests_core(&state)).await
}

/// Lists existing verified unfinished rounds without creating new authority.
#[tauri::command]
pub async fn admin_open_ceremonies(
    state: tauri::State<'_, DesktopState>,
) -> Result<Vec<TrustCeremonyDto>, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || open_ceremonies_core(&state)).await
}

/// Reopens one persisted ceremony, including its separately authorized round.
#[tauri::command]
pub async fn admin_ceremony_read(
    state: tauri::State<'_, DesktopState>,
    ceremony_id: String,
) -> Result<TrustCeremonyDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || ceremony_read_core(&state, &ceremony_id)).await
}

/// Beginnt eine Trust-Zeremonie fuer eine Anfrage.
///
/// # Errors
///
/// [`ADMINISTRATION_WIRE_VALUE`] fuer eine fremde Art;
/// [`CEREMONY_STEP_OUT_OF_ORDER`], wenn der Beginn nicht auf `PendingRequest`
/// steht; sonst wie [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_ceremony_begin(
    state: tauri::State<'_, DesktopState>,
    request_id: String,
    kind: String,
) -> Result<TrustCeremonyDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || ceremony_begin_core(&state, &request_id, &kind)).await
}

/// Bestaetigt den ueber den zweiten Kanal gemeldeten Fingerprint.
///
/// # Errors
///
/// `EA-WORKFLOW-FINGERPRINT-UNREADABLE` fuer einen unlesbaren Text (der Port
/// wird dann nicht gerufen); `EA-WORKFLOW-FINGERPRINT-MISMATCH` aus dem Kern;
/// [`CEREMONY_STEP_OUT_OF_ORDER`] ausser der Reihe; sonst wie
/// [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_ceremony_confirm_fingerprint(
    state: tauri::State<'_, DesktopState>,
    ceremony_id: String,
    reported_fingerprint: String,
) -> Result<TrustCeremonyDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || {
        ceremony_confirm_fingerprint_core(&state, &ceremony_id, &reported_fingerprint)
    })
    .await
}

/// Erteilt die Administrationsautorisierung — verlangt einen frischen
/// Nachweis `AdminRootCeremony`.
///
/// # Errors
///
/// [`REAUTH_REQUIRED`] ohne unverbrauchte Marke; [`CEREMONY_STEP_OUT_OF_ORDER`]
/// ausser der Reihe; sonst wie [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_ceremony_authorize(
    state: tauri::State<'_, DesktopState>,
    ceremony_id: String,
) -> Result<TrustCeremonyDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || ceremony_authorize_core(&state, &ceremony_id)).await
}

/// Exportiert die Root-Anfrage als Offline-Austauschdatei.
///
/// # Errors
///
/// [`CEREMONY_STEP_OUT_OF_ORDER`] ausser der Reihe; sonst wie
/// [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_ceremony_export_request(
    state: tauri::State<'_, DesktopState>,
    ceremony_id: String,
) -> Result<TrustCeremonyDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || ceremony_export_request_core(&state, &ceremony_id)).await
}

/// Importiert die Root-Antwort aus der Offline-Austauschdatei.
///
/// # Errors
///
/// [`CEREMONY_STEP_OUT_OF_ORDER`] ausser der Reihe; sonst wie
/// [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_ceremony_import_reply(
    state: tauri::State<'_, DesktopState>,
    ceremony_id: String,
) -> Result<TrustCeremonyDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || ceremony_import_reply_core(&state, &ceremony_id)).await
}

/// Veroeffentlicht das Registry-Ereignis — verlangt einen frischen Nachweis
/// `AdminRootCeremony`.
///
/// # Errors
///
/// Wie [`admin_ceremony_authorize`].
#[tauri::command]
pub async fn admin_ceremony_publish(
    state: tauri::State<'_, DesktopState>,
    ceremony_id: String,
) -> Result<TrustCeremonyDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || ceremony_publish_core(&state, &ceremony_id)).await
}

/// Das Policy-Profil des gewaehlten Kopfes.
///
/// # Errors
///
/// Wie [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_policy_profile(
    state: tauri::State<'_, DesktopState>,
) -> Result<PolicyProfileDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || policy_profile_core(&state)).await
}

/// Alter, Lease und Zeitstatus des gewaehlten Kopfes.
///
/// # Errors
///
/// Wie [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_registry_health(
    state: tauri::State<'_, DesktopState>,
) -> Result<RegistryHealthDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || registry_health_core(&state)).await
}

/// Read-only diagnosis of the configured local archive lock, without arguments.
///
/// # Errors
/// Requires the same admitted administrator and live native session as other views.
#[tauri::command]
pub async fn admin_writer_lock_diagnosis(
    state: tauri::State<'_, DesktopState>,
) -> Result<&'static str, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || writer_lock_diagnosis_core(&state)).await
}

/// Die Go-live-Liste — sechzehn Anforderungen, `productionReady` nur, wenn
/// jede bestaetigt ist.
///
/// # Errors
///
/// Wie [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_go_live_checklist(
    state: tauri::State<'_, DesktopState>,
) -> Result<GoLiveChecklistDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || go_live_checklist_core(&state)).await
}

/// Die Evidenzliste `ea.go-live-checklist/v1` als JSON-Text — nur Codes.
///
/// # Errors
///
/// Wie [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_go_live_export_unresolved(
    state: tauri::State<'_, DesktopState>,
) -> Result<String, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || go_live_export_unresolved_core(&state)).await
}

/// Was der Uhrenfreigabe-Assistent zeigen darf.
///
/// # Errors
///
/// `EA-SKEW-*` aus dem Kern; sonst wie [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_clock_release_offer(
    state: tauri::State<'_, DesktopState>,
) -> Result<ClockReleaseOfferDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || clock_release_offer_core(&state)).await
}

/// Stellt eine Uhrenfreigabe aus — verlangt einen frischen Nachweis
/// `ClockSkewRelease`.
///
/// # Errors
///
/// [`ADMINISTRATION_WIRE_VALUE`] fuer eine fremde Begruendung;
/// [`REAUTH_REQUIRED`] ohne unverbrauchte Marke; `EA-SKEW-*` aus dem Kern;
/// sonst wie [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_clock_release_issue(
    state: tauri::State<'_, DesktopState>,
    justification: String,
) -> Result<ClockReleaseOutcomeDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || clock_release_issue_core(&state, &justification)).await
}

/// Der Stand des Writer-Uebergangs.
///
/// # Errors
///
/// Wie [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_writer_transition_state(
    state: tauri::State<'_, DesktopState>,
) -> Result<WriterTransitionDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || writer_transition_state_core(&state)).await
}

/// Bereitet den Writer-Uebergang aus dem JSON der Anfrage vor.
///
/// # Errors
///
/// `EA-TRANSITION-*` aus dem Kern; sonst wie [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_writer_transition_prepare(
    state: tauri::State<'_, DesktopState>,
    request_json: String,
) -> Result<WriterTransitionDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || writer_transition_prepare_core(&state, &request_json)).await
}

/// Aktiviert den vorbereiteten Writer-Uebergang — verlangt einen frischen
/// Nachweis `AdminRootCeremony`.
///
/// # Errors
///
/// [`TRANSITION_NOT_PREPARED`], wenn der Stand nicht `Prepared` ist (die
/// Marke bleibt dann stehen); [`REAUTH_REQUIRED`] ohne unverbrauchte Marke;
/// `EA-TRANSITION-*` aus dem Kern; sonst wie
/// [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_writer_transition_activate(
    state: tauri::State<'_, DesktopState>,
) -> Result<WriterTransitionDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || writer_transition_activate_core(&state)).await
}

/// Was ein Widerruf dieses Ziels tut — und was nicht.
///
/// # Errors
///
/// [`ADMINISTRATION_WIRE_VALUE`] fuer einen unlesbaren Zielhash;
/// `EA-WORKFLOW-TARGET-NOT-ACTIVE` aus dem Kern; sonst wie
/// [`admin_pending_device_requests`].
#[tauri::command]
pub async fn admin_revocation_effect(
    state: tauri::State<'_, DesktopState>,
    target_hash: String,
) -> Result<RevocationEffectDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || revocation_effect_core(&state, &target_hash)).await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use ea_admin::{
        GoLiveChecklist, GoLiveEvidence, TrustCeremonyKind, TrustCeremonyStep,
        administration_runtime::{FingerprintSubjectV1, TrustCeremonyRoundV1},
        ceremony_steps::next_step_for_round,
        evaluate_go_live, requires_fresh_reauth,
    };
    use ea_format::{ClockReleaseJustificationV1, OperatorRoleV1};
    use ea_operator::ReauthPurpose;
    use ea_types::{ChainSequence, ObjectHash, UnixMillis};
    use ea_ui_contracts::{
        ADMIN_ENUMS_V1, ADMIN_VIEW_MODELS_V1, ClockReleaseAvailability, ClockReleaseOfferView,
        ClockReleaseOutcomeView, PendingDeviceRequestView, PolicyProfileView, RegistryHealthView,
        RevocationEffectView, RevocationTargetClass, TrustCeremonyView, WriterTransitionPhase,
        WriterTransitionView, admin_view_model_fields,
    };

    use super::{
        Administration, ceremony_authorize_core, ceremony_begin_core,
        ceremony_confirm_fingerprint_core, ceremony_export_request_core,
        ceremony_import_reply_core, ceremony_publish_core, ceremony_read_core,
        clock_release_availability_literal, clock_release_issue_core,
        clock_release_justification_literal, clock_release_offer_core, fingerprint_subject_literal,
        go_live_checklist_core, go_live_export_unresolved_core, go_live_requirement_status_literal,
        pending_device_requests_core, policy_profile_core, registry_health_core,
        require_administrator, revocation_effect_core, revocation_target_class_literal,
        trust_ceremony_kind_literal, trust_ceremony_round_literal, trust_ceremony_step_literal,
        writer_transition_activate_core, writer_transition_phase_literal,
        writer_transition_prepare_core, writer_transition_state_core,
    };
    use crate::commands::{
        ADMINISTRATION_FORBIDDEN, ADMINISTRATION_UNAVAILABLE, ADMINISTRATION_WIRE_VALUE,
        CEREMONY_STEP_OUT_OF_ORDER, CommandError, REAUTH_REQUIRED, TRANSITION_NOT_PREPARED,
    };
    use crate::state::{AdministrationPort, DesktopState, SessionState};

    // -----------------------------------------------------------------------
    // Ein Doppel des Verwaltungsports, das AUFSCHREIBT, was es gefragt wird,
    // und eine Zeremonie regelkonform genau einen Schritt weitergehen laesst —
    // oder, mit `jumps`, von `PendingRequest` direkt auf `RegistryPublished`.
    // -----------------------------------------------------------------------

    struct FakeAdministration {
        ceremonies: Mutex<BTreeMap<String, TrustCeremonyView>>,
        calls: Mutex<Vec<&'static str>>,
        jumps: bool,
        /// Was der Port beim Export als `exchange_file_name` behauptet — im
        /// Regelfall ein Name; ein Doppel kann hier einen PFAD behaupten.
        exchange_file_name: String,
        /// Der Stand des Writer-Uebergangs, damit `writer_transition_state`
        /// sagt, was `prepare` und `activate` bewirkt haben.
        transition_phase: Mutex<WriterTransitionPhase>,
    }

    impl FakeAdministration {
        fn build(jumps: bool, exchange_file_name: &str) -> Arc<Self> {
            Arc::new(Self {
                ceremonies: Mutex::new(BTreeMap::new()),
                calls: Mutex::new(Vec::new()),
                jumps,
                exchange_file_name: exchange_file_name.to_owned(),
                transition_phase: Mutex::new(WriterTransitionPhase::NoTransition),
            })
        }

        fn compliant() -> Arc<Self> {
            Self::build(false, "root-request.eax")
        }

        fn jumping() -> Arc<Self> {
            Self::build(true, "root-request.eax")
        }

        fn exporting(exchange_file_name: &str) -> Arc<Self> {
            Self::build(false, exchange_file_name)
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }

        fn note(&self, call: &'static str) {
            self.calls.lock().unwrap().push(call);
        }

        fn advance(
            &self,
            ceremony_id: &str,
            call: &'static str,
        ) -> Result<TrustCeremonyView, CommandError> {
            self.note(call);
            let mut ceremonies = self.ceremonies.lock().unwrap();
            let view = ceremonies
                .get_mut(ceremony_id)
                .ok_or_else(|| CommandError::new("EA-TEST-UNKNOWN-CEREMONY"))?;
            view.step = if self.jumps {
                TrustCeremonyStep::RegistryPublished
            } else {
                next_step_for_round(view.kind, view.round, view.step)
                    .ok_or_else(|| CommandError::new("EA-TEST-AT-END"))?
            };
            if view.step == TrustCeremonyStep::RootRequestExported {
                view.exchange_file_name = Some(self.exchange_file_name.clone());
            }
            Ok(view.clone())
        }

        /// Der Stand des Uebergangs aus der gemerkten Phase: `NoTransition`
        /// traegt keinen neuen Writer, die zwei anderen Phasen denselben.
        fn transition_view(&self) -> WriterTransitionView {
            let phase = *self.transition_phase.lock().unwrap();
            let prepared = phase != WriterTransitionPhase::NoTransition;
            WriterTransitionView {
                phase,
                ceremony_id: None,
                current_writer_hash: "cd".repeat(32),
                new_writer_hash: prepared.then(|| "ef".repeat(32)),
                effective_from_sequence: prepared.then(|| ChainSequence::new(9)),
            }
        }
    }

    fn hash(byte: u8) -> ObjectHash {
        ObjectHash::try_from([byte; 32].as_slice()).unwrap()
    }

    impl AdministrationPort for FakeAdministration {
        fn open_ceremonies(&self) -> Result<Vec<TrustCeremonyView>, CommandError> {
            self.note("open_ceremonies");
            Ok(self.ceremonies.lock().unwrap().values().cloned().collect())
        }
        fn pending_device_requests(&self) -> Result<Vec<PendingDeviceRequestView>, CommandError> {
            self.note("pending_device_requests");
            Ok(vec![PendingDeviceRequestView {
                request_id: "req-1".to_owned(),
                certificate_kind_code: "Writer".to_owned(),
                fingerprint: ea_admin::human_readable_fingerprint(&hash(0xAB)),
                received_at_ms: UnixMillis::new(1_771_000_000_000),
                fingerprint_subject: FingerprintSubjectV1::IssuedCertificate,
            }])
        }

        fn ceremony(&self, ceremony_id: &str) -> Result<TrustCeremonyView, CommandError> {
            self.note("ceremony");
            self.ceremonies
                .lock()
                .unwrap()
                .get(ceremony_id)
                .cloned()
                .ok_or_else(|| CommandError::new("EA-TEST-UNKNOWN-CEREMONY"))
        }

        fn begin_ceremony(
            &self,
            request_id: &str,
            kind: TrustCeremonyKind,
        ) -> Result<TrustCeremonyView, CommandError> {
            self.note("begin_ceremony");
            let view = TrustCeremonyView {
                ceremony_id: format!("cer-{request_id}"),
                kind,
                step: if self.jumps {
                    TrustCeremonyStep::AdminAuthorized
                } else {
                    TrustCeremonyStep::PendingRequest
                },
                target_fingerprint: (kind == TrustCeremonyKind::DeviceApprove)
                    .then(|| ea_admin::human_readable_fingerprint(&hash(0xAB))),
                exchange_file_name: None,
                round: TrustCeremonyRoundV1::ActivateRegistry,
                linked_ceremony_id: None,
                fingerprint_subject: (kind == TrustCeremonyKind::DeviceApprove)
                    .then_some(FingerprintSubjectV1::IssuedCertificate),
            };
            self.ceremonies
                .lock()
                .unwrap()
                .insert(view.ceremony_id.clone(), view.clone());
            Ok(view)
        }

        fn confirm_fingerprint(
            &self,
            ceremony_id: &str,
            reported: &ObjectHash,
        ) -> Result<TrustCeremonyView, CommandError> {
            if *reported != hash(0xAB) {
                self.note("confirm_fingerprint");
                return Err(CommandError::new("EA-WORKFLOW-FINGERPRINT-MISMATCH"));
            }
            self.advance(ceremony_id, "confirm_fingerprint")
        }

        fn authorize(&self, ceremony_id: &str) -> Result<TrustCeremonyView, CommandError> {
            self.advance(ceremony_id, "authorize")
        }

        fn export_request(&self, ceremony_id: &str) -> Result<TrustCeremonyView, CommandError> {
            self.advance(ceremony_id, "export_request")
        }

        fn import_reply(&self, ceremony_id: &str) -> Result<TrustCeremonyView, CommandError> {
            self.advance(ceremony_id, "import_reply")
        }

        fn publish(&self, ceremony_id: &str) -> Result<TrustCeremonyView, CommandError> {
            self.advance(ceremony_id, "publish")
        }

        fn policy_profile(&self) -> Result<PolicyProfileView, CommandError> {
            self.note("policy_profile");
            Ok(PolicyProfileView {
                operating_profile: 1,
                max_registry_age_ms: 86_400_000,
                max_future_clock_skew_ms: 300_000,
                registry_expiry_behavior: 0,
                evidence_max_delay_ms: 3_600_000,
                reader_inactivity_ms: 300_000,
                reader_trust_refresh_ms: 3_600_000,
                reader_history_access_allowed: false,
                backup_frequency_ms: 604_800_000,
                restore_test_interval_ms: 7_776_000_000,
                minimum_retention_ms: Some(315_360_000_000),
                destruction_enabled: false,
                effective_from_sequence: ChainSequence::new(0),
                lease_valid_through_sequence: ChainSequence::new(1_000),
                not_after_ms: UnixMillis::new(1_800_000_000_000),
            })
        }

        fn registry_health(&self) -> Result<RegistryHealthView, CommandError> {
            self.note("registry_health");
            Ok(RegistryHealthView {
                registry_version: ea_types::RegistryVersion::new(3),
                head_hash: "ab".repeat(32),
                registry_age_ms: 1_000,
                max_registry_age_ms: 86_400_000,
                lease_valid_through_sequence: ChainSequence::new(1_000),
                next_sequence: ChainSequence::new(7),
                not_after_ms: UnixMillis::new(1_800_000_000_000),
                stale_decision: ea_ui_contracts::StaleDecision::Fresh,
            })
        }

        fn go_live_checklist(&self) -> Result<GoLiveChecklist, CommandError> {
            self.note("go_live_checklist");
            Ok(evaluate_go_live(&GoLiveEvidence {
                active_admin_count: None,
                key_backups: None,
                registry: None,
                policy_present: None,
                evidence_policy_present: None,
                last_recovery_test: None,
                writer_transition: None,
                device_posture: None,
                eds_privacy_decision: None,
            }))
        }

        fn clock_release_offer(&self) -> Result<ClockReleaseOfferView, CommandError> {
            self.note("clock_release_offer");
            Ok(ClockReleaseOfferView {
                availability: ClockReleaseAvailability::Offered,
                floor_ms: Some(UnixMillis::new(1_771_000_000_000)),
                observed_wall_clock_ms: Some(UnixMillis::new(1_771_000_100_000)),
                max_future_clock_skew_ms: Some(300_000),
                expires_at_ms: Some(UnixMillis::new(1_771_000_300_000)),
                justifications: vec![
                    ClockReleaseJustificationV1::OperatorVerifiedWallClock,
                    ClockReleaseJustificationV1::PlatformTimeSourceRecovery,
                    ClockReleaseJustificationV1::HardwareClockMaintenance,
                ],
            })
        }

        fn clock_release_issue(
            &self,
            justification: ClockReleaseJustificationV1,
        ) -> Result<ClockReleaseOutcomeView, CommandError> {
            self.note("clock_release_issue");
            assert_eq!(
                justification,
                ClockReleaseJustificationV1::HardwareClockMaintenance
            );
            Ok(ClockReleaseOutcomeView {
                release_id: "rel-1".to_owned(),
                expires_at_ms: UnixMillis::new(1_771_000_300_000),
                changes_time_floor: false,
                changes_registry_expiry: false,
                changes_lease: false,
            })
        }

        fn writer_transition_state(&self) -> Result<WriterTransitionView, CommandError> {
            self.note("writer_transition_state");
            Ok(self.transition_view())
        }

        fn writer_transition_prepare(
            &self,
            request_json: &str,
        ) -> Result<WriterTransitionView, CommandError> {
            self.note("writer_transition_prepare");
            if request_json.is_empty() {
                return Err(CommandError::new("EA-TRANSITION-REQUEST-UNREADABLE"));
            }
            *self.transition_phase.lock().unwrap() = WriterTransitionPhase::Prepared;
            Ok(self.transition_view())
        }

        fn writer_transition_activate(&self) -> Result<WriterTransitionView, CommandError> {
            self.note("writer_transition_activate");
            *self.transition_phase.lock().unwrap() = WriterTransitionPhase::Activated;
            Ok(self.transition_view())
        }

        fn revocation_effect(
            &self,
            target: &ObjectHash,
        ) -> Result<RevocationEffectView, CommandError> {
            self.note("revocation_effect");
            Ok(RevocationEffectView {
                target_class: RevocationTargetClass::NonAdminDevice,
                target_hash: ea_admin::human_readable_fingerprint(target),
                stops_new_grants_from_sequence: ChainSequence::new(12),
                recalls_issued_grants: false,
                recalls_decrypted_plaintext: false,
            })
        }
    }

    fn bare_state() -> DesktopState {
        DesktopState::new(SessionState::new(None, None), None, None, None, None, None)
    }

    fn state_with(port: Arc<FakeAdministration>, session: SessionState) -> DesktopState {
        DesktopState::new(session, None, None, None, None, None).with_administration(port)
    }

    /// Die Grenze OHNE das Tor: Port und Sitzung direkt, wie `administration()`
    /// sie nach bestandenem Tor zusammenstellt. Der Weg durch das Tor ist hier
    /// nur fail-closed messbar, weil `OperatorSessionProof` ausserhalb von
    /// `ea-operator` nicht baubar ist (`SessionState::role` verlangt ihn).
    fn admin<'a>(
        port: &Arc<FakeAdministration>,
        session: &'a Mutex<SessionState>,
    ) -> Administration<'a> {
        Administration {
            port: Arc::clone(port) as Arc<dyn AdministrationPort + Send + Sync>,
            session,
        }
    }

    fn fresh(purpose: ReauthPurpose) -> Mutex<SessionState> {
        let mut session = SessionState::new(None, None);
        session.record_fresh_reauth(purpose);
        Mutex::new(session)
    }

    fn stale() -> Mutex<SessionState> {
        Mutex::new(SessionState::new(None, None))
    }

    const GOOD_FINGERPRINT: &str = "AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB";

    // -----------------------------------------------------------------------
    // Das Tor.
    // -----------------------------------------------------------------------

    /// Fail-closed: ohne Port gibt es keine Verwaltung — fuer JEDES der
    /// achtzehn Kommandos denselben Code, und keiner davon ist ein leerer
    /// Bericht.
    #[test]
    fn a_shell_without_an_administration_port_gets_a_named_absence() {
        let state = bare_state();
        let codes = [
            pending_device_requests_core(&state).unwrap_err().code,
            ceremony_read_core(&state, "cer-req-1").unwrap_err().code,
            ceremony_begin_core(&state, "req-1", "DeviceApprove")
                .unwrap_err()
                .code,
            ceremony_confirm_fingerprint_core(&state, "cer-req-1", GOOD_FINGERPRINT)
                .unwrap_err()
                .code,
            ceremony_authorize_core(&state, "cer-req-1")
                .unwrap_err()
                .code,
            ceremony_export_request_core(&state, "cer-req-1")
                .unwrap_err()
                .code,
            ceremony_import_reply_core(&state, "cer-req-1")
                .unwrap_err()
                .code,
            ceremony_publish_core(&state, "cer-req-1").unwrap_err().code,
            policy_profile_core(&state).unwrap_err().code,
            registry_health_core(&state).unwrap_err().code,
            go_live_checklist_core(&state).unwrap_err().code,
            go_live_export_unresolved_core(&state).unwrap_err().code,
            clock_release_offer_core(&state).unwrap_err().code,
            clock_release_issue_core(&state, "HardwareClockMaintenance")
                .unwrap_err()
                .code,
            writer_transition_state_core(&state).unwrap_err().code,
            writer_transition_prepare_core(&state, "{}")
                .unwrap_err()
                .code,
            writer_transition_activate_core(&state).unwrap_err().code,
            revocation_effect_core(&state, GOOD_FINGERPRINT)
                .unwrap_err()
                .code,
        ];
        assert_eq!(codes.len(), 18);
        for code in codes {
            assert_eq!(code, ADMINISTRATION_UNAVAILABLE);
        }
    }

    /// Das Rollentor, Arm fuer Arm: nur der Organisationsadministrator kommt
    /// durch. Ein Writer wird abgewiesen, ein Reader auch — und eine fehlende
    /// Sitzung ist ebenfalls kein Administrator.
    #[test]
    fn only_an_organization_admin_passes_the_role_gate() {
        assert!(require_administrator(Some(OperatorRoleV1::OrganizationAdmin)).is_ok());
        for refused in [
            Some(OperatorRoleV1::Writer),
            Some(OperatorRoleV1::Reader),
            None,
        ] {
            assert_eq!(
                require_administrator(refused).unwrap_err().code,
                ADMINISTRATION_FORBIDDEN
            );
        }
    }

    /// Eine Sitzung OHNE nachgewiesenen Administrator an einem VERDRAHTETEN
    /// Port: FORBIDDEN fuer JEDES der achtzehn Kommandos, und der Port wird
    /// nicht einmal gerufen. Das Tor haengt an der Rolle und nicht an der
    /// Anwesenheit des Ports — und es steht in jedem Kern, nicht nur in dreien.
    ///
    /// Ehrlich benannt: `SessionState::new(Some(Writer), None)` traegt zwar die
    /// Writer-Rolle, aber KEINEN Nachweis, und `SessionState::role` liefert
    /// dann `None`. Gemessen wird hier also der `None`-Arm von
    /// [`require_administrator`] am Tor, nicht der Writer-Arm. Den Writer-Arm
    /// AM TOR zu messen verlangte einen `OperatorSessionProof`, und den baut
    /// ausserhalb von `ea-operator` niemand: es gibt keinen Konstruktor, auch
    /// keinen unter `cfg(test)`; `verify_current_session` nimmt einen an,
    /// stellt aber keinen aus. Der Writer- und der Reader-Arm sind deshalb in
    /// `only_an_organization_admin_passes_the_role_gate` direkt am Tor
    /// bezeugt, und dieser Zeuge misst, dass jeder Kern durch das Tor geht.
    #[test]
    fn a_session_without_a_verified_admin_is_forbidden_on_every_core() {
        let port = FakeAdministration::compliant();
        let state = state_with(
            Arc::clone(&port),
            SessionState::new(Some(OperatorRoleV1::Writer), None),
        );
        let codes = [
            pending_device_requests_core(&state).unwrap_err().code,
            ceremony_read_core(&state, "cer-req-1").unwrap_err().code,
            ceremony_begin_core(&state, "req-1", "DeviceApprove")
                .unwrap_err()
                .code,
            ceremony_confirm_fingerprint_core(&state, "cer-req-1", GOOD_FINGERPRINT)
                .unwrap_err()
                .code,
            ceremony_authorize_core(&state, "cer-req-1")
                .unwrap_err()
                .code,
            ceremony_export_request_core(&state, "cer-req-1")
                .unwrap_err()
                .code,
            ceremony_import_reply_core(&state, "cer-req-1")
                .unwrap_err()
                .code,
            ceremony_publish_core(&state, "cer-req-1").unwrap_err().code,
            policy_profile_core(&state).unwrap_err().code,
            registry_health_core(&state).unwrap_err().code,
            go_live_checklist_core(&state).unwrap_err().code,
            go_live_export_unresolved_core(&state).unwrap_err().code,
            clock_release_offer_core(&state).unwrap_err().code,
            clock_release_issue_core(&state, "HardwareClockMaintenance")
                .unwrap_err()
                .code,
            writer_transition_state_core(&state).unwrap_err().code,
            writer_transition_prepare_core(&state, "{}")
                .unwrap_err()
                .code,
            writer_transition_activate_core(&state).unwrap_err().code,
            revocation_effect_core(&state, GOOD_FINGERPRINT)
                .unwrap_err()
                .code,
        ];
        assert_eq!(codes.len(), 18);
        for code in codes {
            assert_eq!(code, ADMINISTRATION_FORBIDDEN);
        }
        assert!(
            port.calls().is_empty(),
            "der Port wird ohne Administratorrolle nicht gerufen"
        );
    }

    // -----------------------------------------------------------------------
    // Die Zeremonie, Schritt fuer Schritt.
    // -----------------------------------------------------------------------

    /// Die Geraetefreigabe geht alle sechs Schritte, GENAU einen je Kommando,
    /// und verlangt an `AdminAuthorized` und `RegistryPublished` je eine
    /// frische Wiederanmeldung mit dem Zweck `AdminRootCeremony`.
    #[test]
    fn the_device_approval_walks_one_step_per_command_and_needs_fresh_reauth_twice() {
        let port = FakeAdministration::compliant();
        let session = stale();
        let admin = admin(&port, &session);

        let begun = admin.ceremony_begin("req-1", "DeviceApprove").unwrap();
        assert_eq!(begun.kind, "DeviceApprove");
        assert_eq!(begun.step, "PendingRequest");
        assert_eq!(begun.target_fingerprint.as_deref(), Some(GOOD_FINGERPRINT));
        let id = begun.ceremony_id.clone();

        let confirmed = admin.confirm_fingerprint(&id, "ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab").unwrap();
        assert_eq!(confirmed.step, "FingerprintConfirmed");

        // Ohne frische Praesenz keine Autorisierung — und der Port bleibt ungerufen.
        let calls_before = port.calls().len();
        assert_eq!(admin.authorize(&id).unwrap_err().code, REAUTH_REQUIRED);
        assert_eq!(
            port.calls().len(),
            calls_before + 1,
            "nur die Lesung des Stands"
        );
        assert_eq!(port.calls().last(), Some(&"ceremony"));

        session
            .lock()
            .unwrap()
            .record_fresh_reauth(ReauthPurpose::AdminRootCeremony);
        let authorized = admin.authorize(&id).unwrap();
        assert_eq!(authorized.step, "AdminAuthorized");
        assert_eq!(
            session.lock().unwrap().fresh_reauth(),
            None,
            "die Marke ist verbraucht"
        );

        let exported = admin.export_request(&id).unwrap();
        assert_eq!(exported.step, "RootRequestExported");
        assert_eq!(
            exported.exchange_file_name.as_deref(),
            Some("root-request.eax")
        );

        let imported = admin.import_reply(&id).unwrap();
        assert_eq!(imported.step, "RootReplyImported");

        // Die zweite Root-Wirkung verlangt die ZWEITE Praesenz.
        assert_eq!(admin.publish(&id).unwrap_err().code, REAUTH_REQUIRED);
        session
            .lock()
            .unwrap()
            .record_fresh_reauth(ReauthPurpose::AdminRootCeremony);
        let published = admin.publish(&id).unwrap();
        assert_eq!(published.step, "RegistryPublished");

        // Nach dem letzten Schritt gibt es keinen weiteren.
        session
            .lock()
            .unwrap()
            .record_fresh_reauth(ReauthPurpose::AdminRootCeremony);
        assert_eq!(
            admin.publish(&id).unwrap_err().code,
            CEREMONY_STEP_OUT_OF_ORDER
        );

        let advancing: Vec<&str> = port
            .calls()
            .into_iter()
            .filter(|call| *call != "ceremony")
            .collect();
        assert_eq!(
            advancing,
            [
                "begin_ceremony",
                "confirm_fingerprint",
                "authorize",
                "export_request",
                "import_reply",
                "publish",
            ]
        );
        // Diese Registry-Runde hat zwei Praesenzschritte. TargetPublished
        // gehoert ausschliesslich zur getrennten IssueTarget-Runde.
        assert_eq!(
            TrustCeremonyStep::ALL
                .into_iter()
                .filter(|step| *step != TrustCeremonyStep::TargetPublished)
                .filter(|step| requires_fresh_reauth(*step))
                .count(),
            2
        );
    }

    /// Die drei anderen Arten ueberspringen GENAU `FingerprintConfirmed`: der
    /// Fingerprint-Vergleich ist bei ihnen ein Schritt ausser der Reihe.
    #[test]
    fn the_other_kinds_skip_the_fingerprint_step() {
        for kind in ["DeviceRevoke", "PolicyChange", "WriterTransition"] {
            let port = FakeAdministration::compliant();
            let session = stale();
            let admin = admin(&port, &session);
            let begun = admin.ceremony_begin("req-2", kind).unwrap();
            assert_eq!(begun.kind, kind);
            assert_eq!(begun.target_fingerprint, None);
            let id = begun.ceremony_id.clone();

            assert_eq!(
                admin
                    .confirm_fingerprint(&id, GOOD_FINGERPRINT)
                    .unwrap_err()
                    .code,
                CEREMONY_STEP_OUT_OF_ORDER,
                "{kind}: der Fingerprint-Schritt gehoert nicht in diese Folge"
            );
            assert!(!port.calls().contains(&"confirm_fingerprint"));

            session
                .lock()
                .unwrap()
                .record_fresh_reauth(ReauthPurpose::AdminRootCeremony);
            assert_eq!(admin.authorize(&id).unwrap().step, "AdminAuthorized");
            assert_eq!(
                admin.export_request(&id).unwrap().step,
                "RootRequestExported"
            );
            assert_eq!(admin.import_reply(&id).unwrap().step, "RootReplyImported");
            session
                .lock()
                .unwrap()
                .record_fresh_reauth(ReauthPurpose::AdminRootCeremony);
            assert_eq!(admin.publish(&id).unwrap().step, "RegistryPublished");
        }
    }

    /// Ein Schritt AUSSER DER REIHE wird abgewiesen, bevor der Port gerufen
    /// wird: `authorize` auf einer Geraetefreigabe, deren Fingerprint noch nicht
    /// bestaetigt ist.
    #[test]
    fn a_step_out_of_order_never_reaches_the_port() {
        let port = FakeAdministration::compliant();
        let session = fresh(ReauthPurpose::AdminRootCeremony);
        let admin = admin(&port, &session);
        let id = admin
            .ceremony_begin("req-3", "DeviceApprove")
            .unwrap()
            .ceremony_id;
        for (name, result) in [
            ("authorize", admin.authorize(&id)),
            ("export_request", admin.export_request(&id)),
            ("import_reply", admin.import_reply(&id)),
            ("publish", admin.publish(&id)),
        ] {
            assert_eq!(
                result.unwrap_err().code,
                CEREMONY_STEP_OUT_OF_ORDER,
                "{name}"
            );
            assert!(
                !port.calls().contains(&name),
                "{name} wurde trotzdem gerufen"
            );
        }
        // Die Frischemarke ist NICHT verbraucht: die Reihenfolge wird vor der
        // Praesenz geprueft.
        assert_eq!(
            session.lock().unwrap().fresh_reauth(),
            Some(ReauthPurpose::AdminRootCeremony)
        );
    }

    /// Ein Port, der SPRINGT — von `PendingRequest` direkt auf
    /// `RegistryPublished` —, wird abgewiesen: die Grenze prueft den erreichten
    /// Schritt gegen `next_step` und nimmt nicht hin, was der Port behauptet.
    #[test]
    fn a_port_that_jumps_steps_is_refused() {
        let port = FakeAdministration::jumping();
        let session = fresh(ReauthPurpose::AdminRootCeremony);
        let admin = admin(&port, &session);
        // Schon der Beginn muss auf `PendingRequest` stehen.
        assert_eq!(
            admin
                .ceremony_begin("req-4", "DeviceApprove")
                .unwrap_err()
                .code,
            CEREMONY_STEP_OUT_OF_ORDER
        );
        // Und ein Fortschritt um mehr als einen Schritt ebenso.
        {
            let mut ceremonies = port.ceremonies.lock().unwrap();
            let view = ceremonies.get_mut("cer-req-4").unwrap();
            view.step = TrustCeremonyStep::PendingRequest;
        }
        assert_eq!(
            admin
                .confirm_fingerprint("cer-req-4", GOOD_FINGERPRINT)
                .unwrap_err()
                .code,
            CEREMONY_STEP_OUT_OF_ORDER
        );
    }

    /// Ein unlesbarer Fingerprint traegt den Code aus `ea_admin::fingerprint`
    /// und erreicht den Port nie — nicht einmal die Lesung des Stands.
    #[test]
    fn an_unreadable_fingerprint_carries_the_fingerprint_code_and_never_reaches_the_port() {
        let port = FakeAdministration::compliant();
        let session = stale();
        let admin = admin(&port, &session);
        let id = admin
            .ceremony_begin("req-5", "DeviceApprove")
            .unwrap()
            .ceremony_id;
        let calls_before = port.calls().len();
        for text in ["", "AB:CD", "nicht hex", &"ZZ:".repeat(32)[..95]] {
            assert_eq!(
                admin.confirm_fingerprint(&id, text).unwrap_err().code,
                ea_admin::FINGERPRINT_PARSE_ERROR,
                "{text:?}"
            );
        }
        assert_eq!(port.calls().len(), calls_before);
        // Ein LESBARER, aber falscher Fingerprint kommt dagegen mit dem Code des
        // Kerns zurueck.
        assert_eq!(
            admin
                .confirm_fingerprint(&id, &"CD:".repeat(32)[..95])
                .unwrap_err()
                .code,
            "EA-WORKFLOW-FINGERPRINT-MISMATCH"
        );
    }

    /// Ein fremdes Wort fuer die Art oder die Begruendung ist ein Drahtfehler —
    /// und kein Vorgabewert.
    #[test]
    fn an_unknown_wire_value_is_refused_before_the_port() {
        let port = FakeAdministration::compliant();
        let session = fresh(ReauthPurpose::ClockSkewRelease);
        let admin = admin(&port, &session);
        for kind in ["deviceApprove", "DeviceApprove ", "", "RootRotation"] {
            assert_eq!(
                admin.ceremony_begin("req-6", kind).unwrap_err().code,
                ADMINISTRATION_WIRE_VALUE,
                "{kind:?}"
            );
        }
        for justification in ["hardwareClockMaintenance", "", "BecauseISaidSo"] {
            assert_eq!(
                admin.clock_release_issue(justification).unwrap_err().code,
                ADMINISTRATION_WIRE_VALUE,
                "{justification:?}"
            );
        }
        assert_eq!(
            admin.revocation_effect("kein hash").unwrap_err().code,
            ADMINISTRATION_WIRE_VALUE
        );
        assert!(port.calls().is_empty());
        // Ein Drahtfehler verbraucht keine Praesenz.
        assert_eq!(
            session.lock().unwrap().fresh_reauth(),
            Some(ReauthPurpose::ClockSkewRelease)
        );
    }

    #[test]
    fn open_ceremonies_is_read_only_and_refuses_terminal_or_malformed_views() {
        let port = FakeAdministration::compliant();
        let session = stale();
        let admin = admin(&port, &session);
        let pending = admin
            .ceremony_begin("open-existing", "DeviceRevoke")
            .unwrap();
        let calls_before = port.calls().len();
        let rows = admin.open_ceremonies().unwrap();
        assert_eq!(rows, vec![pending.clone()]);
        assert_eq!(&port.calls()[calls_before..], &["open_ceremonies"]);
        assert!(session.lock().unwrap().fresh_reauth().is_none());
        {
            let mut rows = port.ceremonies.lock().unwrap();
            rows.get_mut(&pending.ceremony_id).unwrap().step = TrustCeremonyStep::RegistryPublished;
        }
        assert_eq!(
            admin.open_ceremonies().unwrap_err().code,
            ADMINISTRATION_WIRE_VALUE
        );
        {
            let mut rows = port.ceremonies.lock().unwrap();
            let row = rows.get_mut(&pending.ceremony_id).unwrap();
            row.step = TrustCeremonyStep::PendingRequest;
            row.ceremony_id = "../private".into();
        }
        assert_eq!(
            admin.open_ceremonies().unwrap_err().code,
            ADMINISTRATION_WIRE_VALUE
        );
    }

    #[test]
    fn open_ceremonies_keeps_the_host_role_and_missing_port_gate() {
        assert_eq!(
            super::open_ceremonies_core(&bare_state()).unwrap_err().code,
            ADMINISTRATION_UNAVAILABLE
        );
        let port = FakeAdministration::compliant();
        let state = state_with(port.clone(), SessionState::new(None, None));
        assert_eq!(
            super::open_ceremonies_core(&state).unwrap_err().code,
            ADMINISTRATION_FORBIDDEN
        );
        assert!(port.calls().is_empty());
    }

    #[test]
    fn target_publication_requires_fresh_presence_and_never_claims_registry_activation() {
        let port = FakeAdministration::compliant();
        let session = stale();
        let admin = admin(&port, &session);
        let id = admin
            .ceremony_begin("issue", "DeviceApprove")
            .unwrap()
            .ceremony_id;
        {
            let mut views = port.ceremonies.lock().unwrap();
            let view = views.get_mut(&id).unwrap();
            view.round = TrustCeremonyRoundV1::IssueTarget;
            view.step = TrustCeremonyStep::RootReplyImported;
            view.fingerprint_subject = Some(FingerprintSubjectV1::RegistrationRequest);
            view.linked_ceremony_id = Some("activate-exact".to_owned());
        }
        assert_eq!(admin.publish(&id).unwrap_err().code, REAUTH_REQUIRED);
        assert!(!port.calls().contains(&"publish"));
        session
            .lock()
            .unwrap()
            .record_fresh_reauth(ReauthPurpose::AdminRootCeremony);
        let reached = admin.publish(&id).unwrap();
        assert_eq!(reached.step, "TargetPublished");
        assert_eq!(reached.round, "IssueTarget");
        assert_eq!(reached.fingerprint_subject, Some("RegistrationRequest"));
        assert_eq!(
            reached.linked_ceremony_id.as_deref(),
            Some("activate-exact")
        );
        assert_eq!(admin.ceremony_read(&id).unwrap(), reached);
        assert!(session.lock().unwrap().fresh_reauth().is_none());
    }

    #[test]
    fn ceremony_read_refuses_paths_other_ids_and_inconsistent_round_claims() {
        let port = FakeAdministration::compliant();
        let session = stale();
        let admin = admin(&port, &session);
        assert_eq!(
            admin.ceremony_read("../private").unwrap_err().code,
            ADMINISTRATION_WIRE_VALUE
        );
        assert!(port.calls().is_empty());
        let id = admin
            .ceremony_begin("read", "DeviceApprove")
            .unwrap()
            .ceremony_id;
        {
            let mut views = port.ceremonies.lock().unwrap();
            views.get_mut(&id).unwrap().ceremony_id = "different".to_owned();
        }
        assert_eq!(
            admin.ceremony_read(&id).unwrap_err().code,
            ADMINISTRATION_WIRE_VALUE
        );
        {
            let mut views = port.ceremonies.lock().unwrap();
            let view = views.get_mut(&id).unwrap();
            view.ceremony_id = id.clone();
            view.round = TrustCeremonyRoundV1::IssueTarget;
            view.step = TrustCeremonyStep::RegistryPublished;
        }
        assert_eq!(
            admin.ceremony_read(&id).unwrap_err().code,
            ADMINISTRATION_WIRE_VALUE
        );
    }

    /// `exchangeFileName` ist ein NAME und nie ein Pfad: ein Port, der beim
    /// Export einen Pfad, einen Elternverweis oder einen leeren Namen
    /// behauptet, wird mit WIRE-VALUE abgewiesen — sonst laege ein Pfad auf
    /// der Oberflaeche. Ein schlichter Name kommt durch. Der Port ist zu diesem
    /// Zeitpunkt schon gelaufen; gemessen wird der Code, nicht die Marke.
    #[test]
    fn an_exchange_file_path_from_the_port_is_a_wire_error() {
        let cases: [(&str, Result<&str, &str>); 6] = [
            ("/tmp/x.eaex", Err(ADMINISTRATION_WIRE_VALUE)),
            ("C:\\exchange\\x.eaex", Err(ADMINISTRATION_WIRE_VALUE)),
            ("../x.eaex", Err(ADMINISTRATION_WIRE_VALUE)),
            ("x/../y.eaex", Err(ADMINISTRATION_WIRE_VALUE)),
            ("", Err(ADMINISTRATION_WIRE_VALUE)),
            ("root-request-1.eaex", Ok("root-request-1.eaex")),
        ];
        for (claimed, expected) in cases {
            let port = FakeAdministration::exporting(claimed);
            let session = fresh(ReauthPurpose::AdminRootCeremony);
            let admin = admin(&port, &session);
            let id = admin
                .ceremony_begin("req-8", "DeviceRevoke")
                .unwrap()
                .ceremony_id;
            assert_eq!(admin.authorize(&id).unwrap().step, "AdminAuthorized");
            let exported = admin.export_request(&id);
            match expected {
                Err(code) => assert_eq!(exported.unwrap_err().code, code, "{claimed:?}"),
                Ok(name) => assert_eq!(
                    exported.unwrap().exchange_file_name.as_deref(),
                    Some(name),
                    "{claimed:?}"
                ),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Uhrenfreigabe, Writer-Uebergang, Widerruf.
    // -----------------------------------------------------------------------

    /// Die Uhrenfreigabe verlangt den Zweck `ClockSkewRelease`; ein Nachweis
    /// fuer eine Root-Zeremonie ist keiner fuer eine Freigabe.
    #[test]
    fn the_clock_release_requires_the_clock_skew_purpose() {
        let port = FakeAdministration::compliant();
        let session = fresh(ReauthPurpose::AdminRootCeremony);
        let admin = admin(&port, &session);
        assert_eq!(
            admin
                .clock_release_issue("HardwareClockMaintenance")
                .unwrap_err()
                .code,
            REAUTH_REQUIRED
        );
        assert!(port.calls().is_empty());
        // Die fremde Marke bleibt stehen.
        assert_eq!(
            session.lock().unwrap().fresh_reauth(),
            Some(ReauthPurpose::AdminRootCeremony)
        );

        session
            .lock()
            .unwrap()
            .record_fresh_reauth(ReauthPurpose::ClockSkewRelease);
        let outcome = admin
            .clock_release_issue("HardwareClockMaintenance")
            .unwrap();
        assert_eq!(outcome.release_id, "rel-1");
        assert_eq!(outcome.expires_at_ms, 1_771_000_300_000);
        assert!(!outcome.changes_time_floor);
        assert!(!outcome.changes_registry_expiry);
        assert!(!outcome.changes_lease);
        assert_eq!(port.calls(), ["clock_release_issue"]);
        assert_eq!(session.lock().unwrap().fresh_reauth(), None);

        let offer = admin.clock_release_offer().unwrap();
        assert_eq!(offer.availability, "Offered");
        assert_eq!(offer.floor_ms, Some(1_771_000_000_000));
        assert_eq!(
            offer.justifications,
            [
                "OperatorVerifiedWallClock",
                "PlatformTimeSourceRecovery",
                "HardwareClockMaintenance",
            ]
        );
    }

    /// Der Writer-Uebergang: Stand und Vorbereitung ohne Praesenz, die
    /// Aktivierung mit dem Zweck `AdminRootCeremony`.
    #[test]
    fn the_writer_transition_activation_requires_the_ceremony_purpose() {
        let port = FakeAdministration::compliant();
        let session = stale();
        let admin = admin(&port, &session);
        let state = admin.writer_transition_state().unwrap();
        assert_eq!(state.phase, "NoTransition");
        assert_eq!(state.new_writer_hash, None);
        assert_eq!(state.effective_from_sequence, None);

        assert_eq!(
            admin.writer_transition_prepare("").unwrap_err().code,
            "EA-TRANSITION-REQUEST-UNREADABLE"
        );
        let prepared = admin
            .writer_transition_prepare("{\"schema\":\"x\"}")
            .unwrap();
        assert_eq!(prepared.phase, "Prepared");
        assert_eq!(prepared.effective_from_sequence, Some(9));

        assert_eq!(
            admin.writer_transition_activate().unwrap_err().code,
            REAUTH_REQUIRED
        );
        session
            .lock()
            .unwrap()
            .record_fresh_reauth(ReauthPurpose::ClockSkewRelease);
        assert_eq!(
            admin.writer_transition_activate().unwrap_err().code,
            REAUTH_REQUIRED
        );
        session
            .lock()
            .unwrap()
            .record_fresh_reauth(ReauthPurpose::AdminRootCeremony);
        assert_eq!(
            admin.writer_transition_activate().unwrap().phase,
            "Activated"
        );
        // Jede Aktivierung liest ZUERST den Stand — auch die zwei, die dann an
        // der Praesenz scheitern; erst die dritte erreicht `activate`.
        assert_eq!(
            port.calls(),
            [
                "writer_transition_state",
                "writer_transition_prepare",
                "writer_transition_prepare",
                "writer_transition_state",
                "writer_transition_state",
                "writer_transition_state",
                "writer_transition_activate",
            ]
        );
    }

    /// Die Aktivierung eines NICHT vorbereiteten Uebergangs — `NoTransition`
    /// oder schon `Activated` — ist TRANSITION-NOT-PREPARED und verbraucht
    /// die Frischemarke NICHT: der Stand wird vor der Praesenz gelesen, wie
    /// die Reihenfolge einer Zeremonie vor ihrer Praesenz geprueft wird. Sonst
    /// muesste der Administrator sich fuer einen Schritt neu anmelden, den es
    /// gar nicht gibt. Der Port sieht nur die Lesung, nie `activate`.
    #[test]
    fn activating_an_unprepared_transition_keeps_the_marker() {
        for phase in [
            WriterTransitionPhase::NoTransition,
            WriterTransitionPhase::Activated,
        ] {
            let port = FakeAdministration::compliant();
            *port.transition_phase.lock().unwrap() = phase;
            let session = fresh(ReauthPurpose::AdminRootCeremony);
            let admin = admin(&port, &session);
            assert_eq!(
                admin.writer_transition_activate().unwrap_err().code,
                TRANSITION_NOT_PREPARED,
                "{phase:?}"
            );
            assert_eq!(
                session.lock().unwrap().fresh_reauth(),
                Some(ReauthPurpose::AdminRootCeremony),
                "{phase:?}: die Marke bleibt stehen"
            );
            assert_eq!(port.calls(), ["writer_transition_state"], "{phase:?}");
        }
    }

    /// Der Widerruf nimmt den Hash in beiden Schreibweisen und liefert die zwei
    /// „nie"-Felder als Felder.
    #[test]
    fn the_revocation_effect_parses_the_target_and_renders_the_never_fields() {
        let port = FakeAdministration::compliant();
        let session = stale();
        let admin = admin(&port, &session);
        let effect = admin.revocation_effect(&"ab".repeat(32)).unwrap();
        assert_eq!(effect.target_class, "NonAdminDevice");
        assert_eq!(effect.target_hash, GOOD_FINGERPRINT);
        assert_eq!(effect.stops_new_grants_from_sequence, 12);
        assert!(!effect.recalls_issued_grants);
        assert!(!effect.recalls_decrypted_plaintext);
        assert_eq!(
            admin
                .revocation_effect(GOOD_FINGERPRINT)
                .unwrap()
                .target_hash,
            GOOD_FINGERPRINT
        );
    }

    // -----------------------------------------------------------------------
    // Lesende Flaechen.
    // -----------------------------------------------------------------------

    /// Ohne einen einzigen Beleg ist NICHTS grün: sechzehn Anforderungen,
    /// jede `NotAutomaticallyVerifiable`, `productionReady == false`.
    #[test]
    fn a_checklist_without_evidence_is_not_production_ready() {
        let port = FakeAdministration::compliant();
        let session = stale();
        let admin = admin(&port, &session);
        let checklist = admin.go_live_checklist().unwrap();
        assert_eq!(checklist.requirements.len(), 16);
        assert!(!checklist.production_ready);
        for requirement in &checklist.requirements {
            assert_eq!(requirement.status, "NotAutomaticallyVerifiable");
            assert_eq!(requirement.evidence_code, "EA-GOLIVE-EVIDENCE-UNAVAILABLE");
            assert_eq!(requirement.decision_document_hash, None);
            assert!(requirement.requirement_code.starts_with("EA-"));
        }
        let codes: Vec<&str> = checklist
            .requirements
            .iter()
            .map(|requirement| requirement.requirement_code.as_str())
            .collect();
        assert_eq!(codes, ea_admin::GO_LIVE_REQUIREMENT_CODES);
    }

    /// Die Evidenzliste ist das Schema `ea.go-live-checklist/v1` — nur Codes.
    #[test]
    fn the_unresolved_export_carries_the_schema_and_only_codes() {
        let port = FakeAdministration::compliant();
        let session = stale();
        let admin = admin(&port, &session);
        let json = admin.go_live_export_unresolved().unwrap();
        assert!(
            json.contains("\"schema\":\"ea.go-live-checklist/v1\""),
            "{json}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["unresolved"].as_array().unwrap().len(), 16);
        // `serde_json::Value` sortiert Schluessel; gemessen wird die MENGE der
        // Felder — genau die drei Codes und nichts daneben.
        for row in parsed["unresolved"].as_array().unwrap() {
            let mut keys: Vec<&str> = row
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(keys, ["evidenceCode", "requirementCode", "status"]);
        }
    }

    /// Die lesenden Ansichten kommen Feld fuer Feld als nackte Zahlen und
    /// camelCase-Namen ueber den Draht.
    #[test]
    fn the_reading_views_carry_bare_numbers_and_camel_case_names() {
        let port = FakeAdministration::compliant();
        let session = stale();
        let admin = admin(&port, &session);

        let pending = admin.pending_device_requests().unwrap();
        let json = serde_json::to_string(&pending).unwrap();
        assert!(json.contains("\"requestId\":\"req-1\""), "{json}");
        assert!(json.contains("\"receivedAtMs\":1771000000000"), "{json}");
        assert!(
            json.contains(&format!("\"fingerprint\":\"{GOOD_FINGERPRINT}\"")),
            "{json}"
        );
        assert!(!json.contains("$serde_json"), "{json}");

        let policy = serde_json::to_string(&admin.policy_profile().unwrap()).unwrap();
        assert!(policy.contains("\"operatingProfile\":1"), "{policy}");
        assert!(
            policy.contains("\"leaseValidThroughSequence\":1000"),
            "{policy}"
        );
        assert!(policy.contains("\"notAfterMs\":1800000000000"), "{policy}");
        assert!(
            policy.contains("\"readerHistoryAccessAllowed\":false"),
            "{policy}"
        );

        let health = serde_json::to_string(&admin.registry_health().unwrap()).unwrap();
        assert!(health.contains("\"registryVersion\":3"), "{health}");
        assert!(health.contains("\"staleDecision\":\"Fresh\""), "{health}");
        assert!(health.contains("\"nextSequence\":7"), "{health}");

        let ceremony =
            serde_json::to_string(&admin.ceremony_begin("req-7", "PolicyChange").unwrap()).unwrap();
        assert!(ceremony.contains("\"kind\":\"PolicyChange\""), "{ceremony}");
        assert!(
            ceremony.contains("\"step\":\"PendingRequest\""),
            "{ceremony}"
        );
        assert!(
            ceremony.contains("\"targetFingerprint\":null"),
            "{ceremony}"
        );
        assert!(ceremony.contains("\"exchangeFileName\":null"), "{ceremony}");
    }

    /// Jedes Drahtliteral der Verwaltung ist das EMITTIERTE — gemessen gegen
    /// `ADMIN_ENUMS_V1` und nicht gegen eine zweite Liste hier.
    #[test]
    fn every_admin_literal_is_the_emitted_one() {
        fn literals(name: &str) -> &'static [&'static str] {
            ADMIN_ENUMS_V1
                .iter()
                .find_map(|(candidate, values)| (*candidate == name).then_some(*values))
                .unwrap_or_else(|| panic!("die emittierte Aufzaehlung {name} fehlt"))
        }
        let kinds: Vec<&str> = TrustCeremonyKind::ALL
            .iter()
            .copied()
            .map(trust_ceremony_kind_literal)
            .collect();
        assert_eq!(kinds, literals("TrustCeremonyKind"));
        let steps: Vec<&str> = TrustCeremonyStep::ALL
            .iter()
            .copied()
            .map(trust_ceremony_step_literal)
            .collect();
        assert_eq!(steps, literals("TrustCeremonyStep"));
        let phases: Vec<&str> = WriterTransitionPhase::ALL
            .iter()
            .copied()
            .map(writer_transition_phase_literal)
            .collect();
        assert_eq!(phases, literals("WriterTransitionPhase"));
        let statuses: Vec<&str> = ea_admin::GoLiveRequirementStatus::ALL
            .iter()
            .copied()
            .map(go_live_requirement_status_literal)
            .collect();
        assert_eq!(statuses, literals("GoLiveRequirementStatus"));
        assert_eq!(
            [
                ClockReleaseAvailability::Offered,
                ClockReleaseAvailability::IndependentTimeUnavailable,
                ClockReleaseAvailability::NotBlocked,
            ]
            .map(clock_release_availability_literal),
            literals("ClockReleaseAvailability")
        );
        assert_eq!(
            [
                RevocationTargetClass::NonAdminDevice,
                RevocationTargetClass::OperatorBinding,
                RevocationTargetClass::Component,
            ]
            .map(revocation_target_class_literal),
            literals("RevocationTargetClass")
        );
        assert_eq!(
            [
                ClockReleaseJustificationV1::OperatorVerifiedWallClock,
                ClockReleaseJustificationV1::PlatformTimeSourceRecovery,
                ClockReleaseJustificationV1::HardwareClockMaintenance,
            ]
            .map(clock_release_justification_literal),
            literals("ClockReleaseJustificationV1")
        );
        use ea_ui_contracts::DestructionStateV1;
        assert_eq!(
            [
                DestructionStateV1::Requested,
                DestructionStateV1::InProgress,
                DestructionStateV1::PendingBackupExpiry,
                DestructionStateV1::CompleteManagedScope,
                DestructionStateV1::IncompleteUnreachableReplica,
            ]
            .map(crate::commands::destruction::destruction_state_literal),
            literals("DestructionStateV1")
        );
        assert_eq!(
            [
                FingerprintSubjectV1::RegistrationRequest,
                FingerprintSubjectV1::IssuedCertificate,
            ]
            .map(fingerprint_subject_literal),
            literals("FingerprintSubjectV1")
        );
        assert_eq!(
            [
                TrustCeremonyRoundV1::IssueTarget,
                TrustCeremonyRoundV1::ActivateRegistry,
            ]
            .map(trust_ceremony_round_literal),
            literals("TrustCeremonyRoundV1")
        );
        assert_eq!(ADMIN_ENUMS_V1.len(), 11);
    }

    /// Die Schluessel EINES JSON-Objekts in DOKUMENTREIHENFOLGE.
    ///
    /// `serde_json::Value` sortiert seine Schluessel, sofern nicht irgendeine
    /// Crate im Graphen `preserve_order` einschaltet — und eine Aussage ueber
    /// die Reihenfolge darf nicht an einer transitiv aktivierten Funktion
    /// haengen. Der Besucher liest den Text, den `Serialize` geschrieben hat,
    /// und nimmt die Schluessel, wie sie kommen.
    struct KeysInOrder(Vec<String>);

    impl<'de> serde::Deserialize<'de> for KeysInOrder {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;

            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = KeysInOrder;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("ein JSON-Objekt")
                }

                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut keys = Vec::new();
                    while let Some(key) = map.next_key::<String>()? {
                        map.next_value::<serde::de::IgnoredAny>()?;
                        keys.push(key);
                    }
                    Ok(KeysInOrder(keys))
                }
            }

            deserializer.deserialize_map(Visitor)
        }
    }

    fn wire_keys<T: serde::Serialize>(value: &T) -> Vec<String> {
        serde_json::from_str::<KeysInOrder>(&serde_json::to_string(value).unwrap())
            .unwrap()
            .0
    }

    /// Jede Drahtform serialisiert GENAU die emittierten Felder — Name fuer
    /// Name, in Reihenfolge —, gemessen gegen `ADMIN_VIEW_MODELS_V1` ueber
    /// `admin_view_model_fields` und nicht gegen eine zweite Liste hier. Jedes
    /// Ansichtsmodell der Tabelle, je eine Drahtform, in ihrer Reihenfolge;
    /// `GoLiveRequirementView` ist ein eigener Eintrag und keine Beigabe der
    /// Liste. Ein umbenanntes oder verschobenes DTO-Feld faellt hier.
    #[test]
    fn every_admin_dto_serialises_exactly_the_emitted_fields() {
        fn emitted(name: &str) -> Vec<String> {
            admin_view_model_fields(name)
                .unwrap_or_else(|| panic!("das emittierte Ansichtsmodell {name} fehlt"))
                .iter()
                .map(|(field, _)| (*field).to_owned())
                .collect()
        }
        let port = FakeAdministration::compliant();
        let session = fresh(ReauthPurpose::ClockSkewRelease);
        let admin = admin(&port, &session);
        let checklist = admin.go_live_checklist().unwrap();
        use crate::commands::destruction::{
            DestructionAdministrationWire, DestructionPreflightWire, DestructionProcessWire,
            DestructionReplicaWire, DestructionTargetWire,
        };
        let target = ea_ui_contracts::DestructionTargetView {
            entry_hash: "ab".repeat(32),
            chain_sequence: ea_types::ChainSequence::new(7),
            stub_object_hash: None,
        };
        let preflight = ea_ui_contracts::DestructionPreflightView {
            job_hash: "cd".repeat(32),
            exact_canonical_report_json: "{}".to_owned(),
            known_replica_count: 3,
        };
        let replica = ea_ui_contracts::DestructionReplicaView {
            device_id: "08".repeat(16),
            kind_code: 0,
            attestation_hash: None,
            result_code: None,
            backup_expiry_at: None,
        };
        let process = ea_ui_contracts::DestructionProcessView {
            destruction_id: "01".repeat(16),
            authorization_object_hash: "02".repeat(32),
            state: ea_ui_contracts::DestructionStateV1::Requested,
            scope_code: 1,
            legal_reason_code: 2,
            controller_device_id: "03".repeat(16),
            custodian_device_id: "04".repeat(16),
            approver_certificate_hashes: vec!["05".repeat(32), "06".repeat(32)],
            targets: vec![target.clone()],
            preflight: Some(preflight.clone()),
            replicas: vec![replica.clone()],
            evidence_entry_hash: None,
        };
        let destruction = ea_ui_contracts::DestructionAdministrationView {
            privacy_decision_enabled: true,
            policy_hash: "07".repeat(32),
            known_destruction_ids: vec![process.destruction_id.clone()],
            process: Some(process.clone()),
        };
        // Die Drahtform der Reader-Zustellung hat private Felder und keine
        // Umwandlung; gemessen wird sie deshalb dort, wo sie entsteht — am
        // Kern des Kommandos hinter einem Administratorport, der genau die
        // drei Originale liefert.
        let reader_delivery = {
            use crate::state::{DestructionAdministrationPort, RuntimeSessionPort};
            use ea_ui_contracts::{DestructionAdministrationView, DestructionReaderDeliveryView};
            struct Admin;
            impl RuntimeSessionPort for Admin {
                fn verified_role(&self) -> Result<Option<OperatorRoleV1>, CommandError> {
                    Ok(Some(OperatorRoleV1::OrganizationAdmin))
                }
                fn invalidate(&self) {}
            }
            struct Delivery;
            fn unused() -> Result<DestructionAdministrationView, CommandError> {
                Err(CommandError::new("EA-TEST-UNUSED"))
            }
            impl DestructionAdministrationPort for Delivery {
                fn export_reader_delivery(
                    &self,
                    _: ea_types::DestructionId,
                    _: ObjectHash,
                    _: ea_types::DeviceId,
                ) -> Result<DestructionReaderDeliveryView, CommandError> {
                    Ok(DestructionReaderDeliveryView {
                        destruction_id: "11".repeat(16),
                        job_hash: "22".repeat(32),
                        reader_id: "33".repeat(16),
                        exact_authorization: vec![1],
                        exact_initiating_event: vec![2],
                        exact_job_upload: vec![3],
                    })
                }
                fn authenticate_custodian(
                    &self,
                    _: ea_types::DestructionId,
                    _: ObjectHash,
                ) -> Result<DestructionAdministrationView, CommandError> {
                    unused()
                }
                fn synchronize(
                    &self,
                    _: ea_types::DestructionId,
                    _: ObjectHash,
                ) -> Result<DestructionAdministrationView, CommandError> {
                    unused()
                }
                fn read(
                    &self,
                    _: Option<ea_types::DestructionId>,
                ) -> Result<DestructionAdministrationView, CommandError> {
                    unused()
                }
                fn prepare(&self, _: &[u8]) -> Result<DestructionAdministrationView, CommandError> {
                    unused()
                }
                fn start(
                    &self,
                    _: ea_types::DestructionId,
                    _: ObjectHash,
                ) -> Result<DestructionAdministrationView, CommandError> {
                    unused()
                }
                fn resume(
                    &self,
                    _: ea_types::DestructionId,
                ) -> Result<DestructionAdministrationView, CommandError> {
                    unused()
                }
                fn import_progress(
                    &self,
                    _: ea_types::DestructionId,
                    _: ObjectHash,
                    _: &[Vec<u8>],
                ) -> Result<DestructionAdministrationView, CommandError> {
                    unused()
                }
            }
            let state =
                DesktopState::new(SessionState::new(None, None), None, None, None, None, None)
                    .with_runtime_session(Arc::new(Admin))
                    .with_destruction(Arc::new(Delivery));
            crate::commands::destruction::destruction_export_reader_delivery_core(
                &state,
                &"11".repeat(16),
                &"22".repeat(32),
                &"33".repeat(16),
            )
            .unwrap()
        };
        let evidence_review =
            crate::commands::destruction_evidence::DestructionEvidenceReviewWire::try_from(
                ea_ui_contracts::DestructionEvidenceReviewView {
                    writer_device_id: process.custodian_device_id.clone(),
                    process: process.clone(),
                    preview: ea_ui_contracts::FinalizationPreviewView {
                        proposed_sequence: ea_types::ChainSequence::new(8),
                        binds_predecessor: true,
                        effective_now: ea_types::UnixMillis::new(1000),
                        trust_age_ms: 100,
                        reader_trust_refresh_ms: 1000,
                        trust_refresh_overdue: false,
                        stale_decision: ea_ui_contracts::StaleDecision::Fresh,
                    },
                },
            )
            .unwrap();
        let recovery_request = ea_ui_contracts::RecoveryMediumRequestView {
            run_id: "01".repeat(16),
            request_id: "02".repeat(32),
            medium_id_hash: "03".repeat(32),
            index: 1,
            total: 1,
            role_code: "root".into(),
            certificate_hash: "04".repeat(32),
            expected_thumbprint: "05".repeat(32),
            protection_code: 2,
            test_kind_code: "signatureChallenge".into(),
        };
        let recovery_report = ea_ui_contracts::RecoveryReportView {
            completed: true,
            exact_public_report_json: serde_json::json!({"schemaId":"ea.recovery-test/v1",
                "testId":"01".repeat(16),"result":"complete","sourceEnvelopeHash":"06".repeat(32)})
            .to_string(),
            envelope_hash: "07".repeat(32),
            source_envelope_hash: "06".repeat(32),
            audit_id: "08".repeat(16),
            finished_at_ms: 1000,
            next_due_at_ms: Some(2000),
        };
        let recovery =
            crate::commands::recovery::recovery_wire(ea_ui_contracts::RecoveryAdministrationView {
                last_success: Some(recovery_report.clone()),
                last_failure: None,
                run: Some(ea_ui_contracts::RecoveryRunView {
                    operation_id: "09".repeat(16),
                    phase_code: 3,
                    request: None,
                    observations: vec![ea_ui_contracts::RecoveryMediumObservationView {
                        request: recovery_request,
                        result_code: 0,
                        observed_thumbprint: Some("05".repeat(32)),
                        error_code: None,
                    }],
                    report: Some(recovery_report),
                    error_code: None,
                }),
            })
            .unwrap();
        let checked: [(&str, Vec<String>); 22] = [
            (
                "RecoveryMediumRequestView",
                wire_keys(&recovery["run"]["observations"][0]["request"]),
            ),
            (
                "RecoveryMediumObservationView",
                wire_keys(&recovery["run"]["observations"][0]),
            ),
            ("RecoveryReportView", wire_keys(&recovery["lastSuccess"])),
            ("RecoveryRunView", wire_keys(&recovery["run"])),
            ("RecoveryAdministrationView", wire_keys(&recovery)),
            (
                "DestructionTargetView",
                wire_keys(&DestructionTargetWire::try_from(target).unwrap()),
            ),
            (
                "DestructionPreflightView",
                wire_keys(&DestructionPreflightWire::from(preflight)),
            ),
            (
                "DestructionReplicaView",
                wire_keys(&DestructionReplicaWire::try_from(replica).unwrap()),
            ),
            (
                "DestructionProcessView",
                wire_keys(&DestructionProcessWire::try_from(process).unwrap()),
            ),
            (
                "DestructionAdministrationView",
                wire_keys(&DestructionAdministrationWire::try_from(destruction).unwrap()),
            ),
            ("DestructionReaderDeliveryView", wire_keys(&reader_delivery)),
            ("DestructionEvidenceReviewView", wire_keys(&evidence_review)),
            (
                "PendingDeviceRequestView",
                wire_keys(&admin.pending_device_requests().unwrap()[0]),
            ),
            (
                "TrustCeremonyView",
                wire_keys(&admin.ceremony_begin("req-9", "DeviceApprove").unwrap()),
            ),
            (
                "PolicyProfileView",
                wire_keys(&admin.policy_profile().unwrap()),
            ),
            (
                "RegistryHealthView",
                wire_keys(&admin.registry_health().unwrap()),
            ),
            (
                "GoLiveRequirementView",
                wire_keys(&checklist.requirements[0]),
            ),
            ("GoLiveChecklistView", wire_keys(&checklist)),
            (
                "ClockReleaseOfferView",
                wire_keys(&admin.clock_release_offer().unwrap()),
            ),
            (
                "ClockReleaseOutcomeView",
                wire_keys(
                    &admin
                        .clock_release_issue("HardwareClockMaintenance")
                        .unwrap(),
                ),
            ),
            (
                "WriterTransitionView",
                wire_keys(&admin.writer_transition_state().unwrap()),
            ),
            (
                "RevocationEffectView",
                wire_keys(&admin.revocation_effect(GOOD_FINGERPRINT).unwrap()),
            ),
        ];
        assert_eq!(checked.len(), 22);
        for (name, keys) in &checked {
            if name.starts_with("Recovery") {
                // Recovery IPC uses serde_json::Value, whose object key order
                // is unspecified. Check the exact emitted field set instead.
                let mut keys = keys.clone();
                keys.sort_unstable();
                let mut fields = emitted(name);
                fields.sort_unstable();
                assert_eq!(keys, fields, "{name}");
            } else {
                assert_eq!(*keys, emitted(name), "{name}");
            }
        }
        // Und die Tabelle hat KEINEN Eintrag, der hier ungemessen bliebe.
        let table_names: Vec<&str> = ADMIN_VIEW_MODELS_V1.iter().map(|(name, _)| *name).collect();
        let checked_names: Vec<&str> = checked.iter().map(|(name, _)| *name).collect();
        assert_eq!(checked_names, table_names);
        assert!(admin_view_model_fields("NoSuchView").is_none());
    }
    #[test]
    fn lock_diagnosis_requires_admin_and_emits_only_the_closed_result() {
        use ea_ui_contracts::LocalWriterLockDiagnosis;
        assert_eq!(
            super::writer_lock_diagnosis_core(&bare_state())
                .unwrap_err()
                .code,
            ADMINISTRATION_UNAVAILABLE
        );
        let port = FakeAdministration::compliant();
        let state = state_with(
            Arc::clone(&port),
            SessionState::new(Some(OperatorRoleV1::Writer), None),
        );
        assert_eq!(
            super::writer_lock_diagnosis_core(&state).unwrap_err().code,
            ADMINISTRATION_FORBIDDEN
        );
        assert!(port.calls.lock().unwrap().is_empty());
        for (value, literal) in [
            (LocalWriterLockDiagnosis::Missing, "Missing"),
            (LocalWriterLockDiagnosis::AbandonedInert, "AbandonedInert"),
            (LocalWriterLockDiagnosis::LiveOwner, "LiveOwner"),
            (LocalWriterLockDiagnosis::Unreadable, "Unreadable"),
        ] {
            assert_eq!(
                ea_ui_contracts::local_writer_lock_diagnosis_literal(value),
                literal
            );
            assert_eq!(
                serde_json::to_value(ea_ui_contracts::local_writer_lock_diagnosis_literal(value))
                    .unwrap(),
                literal
            );
        }
    }
}
