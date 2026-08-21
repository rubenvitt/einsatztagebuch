//! Die geprueften Sitzungsangaben, die Sperrpflicht und der automatische
//! Startpfad.

use ea_format::OperatorRoleV1;
use ea_ui_contracts::PendingFinalizationResumeView;
use ea_writer::{FinalizationPhase, RecoveryOutcome};
use serde::Serialize;

use super::{
    CommandError, NO_VERIFIED_SESSION, SESSION_STATE_UNREADABLE, STARTUP_RECOVERY_FAILED,
    STARTUP_RECOVERY_UNAVAILABLE, run_blocking,
};
use crate::state::DesktopState;

/// Die Faehigkeit, die die Erfassung freischaltet.
pub const CAPTURE_CAPABILITY: &str = "capture";

/// Die geprueften Sitzungsangaben in ihrer Drahtform.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionDto {
    pub role: &'static str,
    pub capabilities: Vec<&'static str>,
}

/// Die Rollenkennung der Drahtform: die KLEINSCHREIBUNG des Kontraktliterals.
///
/// Kein Sammelarm, also nimmt eine vierte Rolle diesen `match` mit. Der Zeuge
/// unten vergleicht jeden Wert gegen das emittierte Literal aus
/// `ea-ui-contracts` und nicht gegen eine zweite Liste.
pub(crate) const fn role_slug(role: OperatorRoleV1) -> &'static str {
    match role {
        OperatorRoleV1::Writer => "writer",
        OperatorRoleV1::Reader => "reader",
        OperatorRoleV1::OrganizationAdmin => "organizationadmin",
    }
}

/// Was diese Rolle auf DIESEM Geraet darf.
///
/// Der Desktop schaltet ausschliesslich den Writer frei: der Reader ist eine
/// Browser-PWA, und die Verwaltung ist Stufe 5. Deshalb tragen beide anderen
/// Rollen hier die leere Liste, und es gibt keinen Weg, aus ihnen lokal eine
/// Faehigkeit zu machen.
pub(crate) const fn capabilities_of(role: OperatorRoleV1) -> &'static [&'static str] {
    match role {
        OperatorRoleV1::Writer => &[CAPTURE_CAPABILITY],
        OperatorRoleV1::Reader | OperatorRoleV1::OrganizationAdmin => &[],
    }
}

/// Die Phase, die eine Wiederherstellung ERREICHT hat.
///
/// Abgeleitet und nicht geraten. `recover_pending` kehrt vor jedem
/// Phasenfortschritt zurueck, wenn nichts anlag oder der Entwurf
/// wiederhergestellt wurde (`ea-writer/src/recover.rs`), also ist die Phase
/// dort [`FinalizationPhase::ReversibleDraft`]. Nach der Grenze veroeffentlicht
/// derselbe Aufruf mit `Stop::After(ReconcileAndOpenBlankDraft)`, und genau
/// dieser Schritt setzt [`FinalizationPhase::Reconciled`]
/// (`ea-writer/src/finalize.rs`) — ein Erfolg kann also keine andere Phase
/// erreicht haben.
const fn phase_of(outcome: &RecoveryOutcome) -> FinalizationPhase {
    match outcome {
        RecoveryOutcome::NothingPending | RecoveryOutcome::DraftRestored { .. } => {
            FinalizationPhase::ReversibleDraft
        }
        RecoveryOutcome::CommittedFromPreparedBytes { .. } => FinalizationPhase::Reconciled,
    }
}

/// Das Literal der Phase — dasselbe, das `ea-ui-contracts` emittiert.
pub(crate) const fn phase_literal(phase: FinalizationPhase) -> &'static str {
    match phase {
        FinalizationPhase::ReversibleDraft => "ReversibleDraft",
        FinalizationPhase::PreparedAndFlushed => "PreparedAndFlushed",
        FinalizationPhase::DraftKeyAbsent => "DraftKeyAbsent",
        FinalizationPhase::GrantsPublished => "GrantsPublished",
        FinalizationPhase::EntryCommitted => "EntryCommitted",
        FinalizationPhase::NetworkArchivePublished => "NetworkArchivePublished",
        FinalizationPhase::Reconciled => "Reconciled",
    }
}

/// Die Fortsetzungsansicht in ihrer Drahtform.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumeDto {
    pub phase: &'static str,
    pub irreversible: bool,
    pub outcome_code: Option<String>,
    pub outcome_sequence: Option<u64>,
}

impl From<&PendingFinalizationResumeView> for ResumeDto {
    fn from(view: &PendingFinalizationResumeView) -> Self {
        Self {
            phase: phase_literal(view.phase),
            irreversible: view.irreversible,
            outcome_code: view.outcome_code.clone(),
            outcome_sequence: view.outcome_sequence.map(ea_types::ChainSequence::get),
        }
    }
}

/// Die Drahtform EINER geprueften Rolle.
///
/// Getrennt von [`verified_session_core`], damit die Abbildung Rolle → Drahtform
/// messbar bleibt: `SessionState::role` liefert seit der Klammer um den Nachweis
/// nur MIT [`ea_operator::OperatorSessionProof`] eine Rolle, und ein Nachweis ist
/// ausserhalb von `ea-operator` nicht baubar (kein Konstruktor, und
/// `OperatorAuthenticator::reauthenticate` verlangt eine aufgeloeste
/// Root-signierte Bindung samt `PreexistingEffectiveNow`). Der Weg durch das
/// Kommando ist damit hier nur fail-closed messbar — die Abbildung selbst
/// vollstaendig.
fn session_dto(role: OperatorRoleV1) -> SessionDto {
    SessionDto {
        role: role_slug(role),
        capabilities: capabilities_of(role).to_vec(),
    }
}

pub(crate) fn verified_session_core(state: &DesktopState) -> Result<SessionDto, CommandError> {
    let role = state
        .session()
        .lock()
        .map_err(|_| CommandError::new(SESSION_STATE_UNREADABLE))?
        .role()
        .ok_or_else(|| CommandError::new(NO_VERIFIED_SESSION))?;
    Ok(session_dto(role))
}

pub(crate) fn startup_recovery_core(state: &DesktopState) -> Result<ResumeDto, CommandError> {
    let port = state
        .startup()
        .ok_or_else(|| CommandError::new(STARTUP_RECOVERY_UNAVAILABLE))?;
    let outcome = port
        .resolve_pending_finalization()
        .map_err(|_| CommandError::new(STARTUP_RECOVERY_FAILED))?;
    let view = PendingFinalizationResumeView::new(phase_of(&outcome), Some(&outcome));
    Ok(ResumeDto::from(&view))
}

/// Die geprueften Rolle und Faehigkeiten dieses Geraets.
///
/// # Errors
///
/// [`NO_VERIFIED_SESSION`], solange keine Bindung gilt.
#[tauri::command]
pub async fn verified_session(
    state: tauri::State<'_, DesktopState>,
) -> Result<SessionDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || verified_session_core(&state)).await
}

/// Entwertet den `OperatorSessionProof` wegen einer Sperre.
///
/// # Errors
///
/// [`super::BLOCKING_WORK_LOST`], wenn der Blockierthread verlorengeht. Das
/// Entwerten selbst kann nicht scheitern.
#[tauri::command]
pub async fn invalidate_session_on_lock(
    state: tauri::State<'_, DesktopState>,
) -> Result<(), CommandError> {
    let state = state.inner().clone();
    run_blocking(move || {
        state.invalidate_session_on_lock();
        Ok(())
    })
    .await
}

/// Der automatische Startpfad: `WriterService::recover_pending`.
///
/// # Errors
///
/// [`STARTUP_RECOVERY_UNAVAILABLE`], solange kein Startpfad verdrahtet ist;
/// [`STARTUP_RECOVERY_FAILED`], wenn der Schreibport ablehnt.
#[tauri::command]
pub async fn startup_recovery(
    state: tauri::State<'_, DesktopState>,
) -> Result<ResumeDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || startup_recovery_core(&state)).await
}

#[cfg(test)]
mod tests {
    use ea_format::OperatorRoleV1;
    use ea_types::ChainSequence;
    use ea_ui_contracts::{PendingFinalizationResumeView, SECURITY_ENUMS_V1, WRITER_ENUMS_V1};
    use ea_writer::{FinalizationPhase, RecoveryOutcome, WriterError};

    use super::{
        CAPTURE_CAPABILITY, ResumeDto, capabilities_of, phase_literal, phase_of, role_slug,
        session_dto, startup_recovery_core, verified_session_core,
    };
    use crate::commands::{NO_VERIFIED_SESSION, STARTUP_RECOVERY_UNAVAILABLE};
    use crate::state::{DesktopState, SessionState, StartupRecoveryPort};

    fn literals(name: &str) -> &'static [&'static str] {
        for (candidate, values) in SECURITY_ENUMS_V1.iter().chain(WRITER_ENUMS_V1) {
            if *candidate == name {
                return values;
            }
        }
        panic!("die emittierte Aufzaehlung {name} fehlt");
    }

    /// Die Drahtkennung der Rolle ist die Kleinschreibung des EMITTIERTEN
    /// Literals — gemessen gegen `ea-ui-contracts` und nicht gegen eine zweite
    /// Liste hier. Eine umbenannte oder hinzugefuegte Rolle faellt damit auf.
    #[test]
    fn every_role_slug_is_the_lowercase_contract_literal() {
        let roles = [
            OperatorRoleV1::Writer,
            OperatorRoleV1::Reader,
            OperatorRoleV1::OrganizationAdmin,
        ];
        let emitted = literals("OperatorRoleV1");
        assert_eq!(emitted.len(), roles.len());
        for (role, literal) in roles.into_iter().zip(emitted) {
            assert_eq!(role_slug(role), literal.to_lowercase());
        }
    }

    /// Der Desktop schaltet ausschliesslich den Writer frei.
    #[test]
    fn only_the_writer_carries_a_capability() {
        assert_eq!(
            capabilities_of(OperatorRoleV1::Writer),
            [CAPTURE_CAPABILITY]
        );
        assert!(capabilities_of(OperatorRoleV1::Reader).is_empty());
        assert!(capabilities_of(OperatorRoleV1::OrganizationAdmin).is_empty());
    }

    #[test]
    fn every_phase_literal_is_the_emitted_one() {
        let emitted = literals("FinalizationPhase");
        assert_eq!(emitted.len(), FinalizationPhase::ALL.len());
        for (phase, literal) in FinalizationPhase::ALL.into_iter().zip(emitted) {
            assert_eq!(phase_literal(phase), *literal);
        }
    }

    /// Die Phasenabbildung, Arm fuer Arm. Sequenz 0 ist der GUELTIGE erste
    /// Eintrag und kein Sentinel.
    #[test]
    fn the_reached_phase_follows_the_outcome() {
        assert_eq!(
            phase_of(&RecoveryOutcome::NothingPending),
            FinalizationPhase::ReversibleDraft
        );
        assert_eq!(
            phase_of(&RecoveryOutcome::DraftRestored {
                unused_sequence: ChainSequence::new(0)
            }),
            FinalizationPhase::ReversibleDraft
        );
        assert_eq!(
            phase_of(&RecoveryOutcome::CommittedFromPreparedBytes {
                sequence: ChainSequence::new(0)
            }),
            FinalizationPhase::Reconciled
        );
        assert!(!FinalizationPhase::ReversibleDraft.is_irreversible());
        assert!(FinalizationPhase::Reconciled.is_irreversible());
    }

    struct Recovered(RecoveryOutcome);

    impl StartupRecoveryPort for Recovered {
        fn resolve_pending_finalization(&self) -> Result<RecoveryOutcome, WriterError> {
            Ok(self.0.clone())
        }
    }

    struct Refusing;

    impl StartupRecoveryPort for Refusing {
        fn resolve_pending_finalization(&self) -> Result<RecoveryOutcome, WriterError> {
            Err(WriterError::PreparedFinalizationUnreadable)
        }
    }

    fn state_with(
        role: Option<OperatorRoleV1>,
        startup: Option<std::sync::Arc<dyn StartupRecoveryPort + Send + Sync>>,
    ) -> DesktopState {
        DesktopState::new(SessionState::new(role, None), startup, None)
    }

    #[test]
    fn a_device_without_a_binding_has_no_session() {
        let state = state_with(None, None);
        assert_eq!(
            verified_session_core(&state).unwrap_err().code,
            NO_VERIFIED_SESSION
        );
    }

    /// Eine Rolle OHNE Nachweis ist keine Sitzung.
    ///
    /// Die Klammer aus `SessionState::role`, an der Kommandogrenze gemessen:
    /// dieses Geraet TRAEGT eine Writer-Rolle im Feld, und `verified_session`
    /// gibt sie trotzdem nicht heraus. Ohne die Klammer waere dieser Zeuge gruen
    /// mit einer Sitzung, die niemand nachgewiesen hat — genau die Naht, die
    /// Task 16 sonst erbt.
    #[test]
    fn a_role_without_a_proof_is_no_verified_session() {
        let state = state_with(Some(OperatorRoleV1::Writer), None);
        assert_eq!(
            verified_session_core(&state).unwrap_err().code,
            NO_VERIFIED_SESSION
        );
    }

    /// Die Abbildung Rolle → Drahtform, vollstaendig und ohne Nachweis
    /// messbar.
    #[test]
    fn the_writer_dto_names_its_role_and_its_capability() {
        let session = session_dto(OperatorRoleV1::Writer);
        assert_eq!(session.role, "writer");
        assert_eq!(session.capabilities, ["capture"]);
        assert!(session_dto(OperatorRoleV1::Reader).capabilities.is_empty());
        assert!(
            session_dto(OperatorRoleV1::OrganizationAdmin)
                .capabilities
                .is_empty()
        );
    }

    #[test]
    fn a_shell_without_a_startup_path_gets_a_named_absence() {
        let state = state_with(Some(OperatorRoleV1::Writer), None);
        assert_eq!(
            startup_recovery_core(&state).unwrap_err().code,
            STARTUP_RECOVERY_UNAVAILABLE
        );
    }

    #[test]
    fn a_resumed_genesis_entry_keeps_its_sequence_and_its_phase() {
        let state = state_with(
            Some(OperatorRoleV1::Writer),
            Some(std::sync::Arc::new(Recovered(
                RecoveryOutcome::CommittedFromPreparedBytes {
                    sequence: ChainSequence::new(0),
                },
            ))),
        );
        let resume = startup_recovery_core(&state).unwrap();
        assert_eq!(
            resume,
            ResumeDto {
                phase: "Reconciled",
                irreversible: true,
                outcome_code: Some("CommittedFromPreparedBytes".to_owned()),
                outcome_sequence: Some(0),
            }
        );
    }

    #[test]
    fn nothing_pending_stays_reversible() {
        let state = state_with(
            Some(OperatorRoleV1::Writer),
            Some(std::sync::Arc::new(Recovered(
                RecoveryOutcome::NothingPending,
            ))),
        );
        let resume = startup_recovery_core(&state).unwrap();
        assert_eq!(resume.phase, "ReversibleDraft");
        assert!(!resume.irreversible);
        assert_eq!(resume.outcome_sequence, None);
    }

    /// Ein ablehnender Startpfad ist KEINE leere Fortsetzung.
    #[test]
    fn a_refusing_startup_path_fails_closed() {
        let state = state_with(
            Some(OperatorRoleV1::Writer),
            Some(std::sync::Arc::new(Refusing)),
        );
        assert!(startup_recovery_core(&state).is_err());
    }

    /// `serde_json` traegt in der Wurzeltabelle `arbitrary_precision`. Dieser
    /// Zeuge misst die DIREKTE Drahtform: nackte Ziffern und keine
    /// Ersatzabbildung `$serde_json::private::Number`. Der `Value`-vermittelte
    /// Weg innerhalb der Tauri-IPC bleibt davon unberuehrt und ungemessen.
    #[test]
    fn the_wire_form_carries_bare_numbers_and_camel_case_names() {
        let view = PendingFinalizationResumeView::new(
            FinalizationPhase::EntryCommitted,
            Some(&RecoveryOutcome::CommittedFromPreparedBytes {
                sequence: ChainSequence::new(7),
            }),
        );
        let json = serde_json::to_string(&ResumeDto::from(&view)).unwrap();
        assert!(!json.contains("$serde_json"), "{json}");
        assert!(json.contains("\"outcomeSequence\":7"), "{json}");
        assert!(json.contains("\"irreversible\":true"), "{json}");
        let session = serde_json::to_string(&session_dto(OperatorRoleV1::Writer)).unwrap();
        assert_eq!(
            session,
            "{\"role\":\"writer\",\"capabilities\":[\"capture\"]}"
        );
    }
}
