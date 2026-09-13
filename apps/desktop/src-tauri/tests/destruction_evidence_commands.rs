//! The Evidence commands keep Admin admission and the separate native Writer port.
use ea_desktop::{
    commands::{CommandError, destruction_evidence::*, writer::FinalizationPreviewDto},
    state::{DesktopState, DestructionEvidencePort, RuntimeSessionPort, SessionState},
};
use ea_format::OperatorRoleV1;
use ea_types::{DestructionId, ObjectHash};
use ea_ui_contracts::{
    DestructionEvidenceReviewView, DiscardStateView, FinalizationPreviewView, FinalizeOutcomeView,
    PendingResumeOutcomeView,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Role(Option<OperatorRoleV1>);
impl RuntimeSessionPort for Role {
    fn verified_role(&self) -> Result<Option<OperatorRoleV1>, CommandError> {
        Ok(self.0)
    }
    fn invalidate(&self) {}
}
struct Port(AtomicUsize);
impl Port {
    fn check<T>(
        &self,
        id: DestructionId,
        hash: ObjectHash,
        code: &'static str,
    ) -> Result<T, CommandError> {
        assert_eq!(id.as_bytes(), &[0x11; 16]);
        assert_eq!(hash.as_bytes(), &[0x22; 32]);
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CommandError::new(code))
    }
}
impl DestructionEvidencePort for Port {
    fn preview(
        &self,
        id: DestructionId,
        hash: ObjectHash,
    ) -> Result<DestructionEvidenceReviewView, CommandError> {
        self.check(id, hash, "NATIVE-EVIDENCE-PREVIEW-REFUSED")
    }
    fn finalize(
        &self,
        id: DestructionId,
        hash: ObjectHash,
        confirmed: &FinalizationPreviewView,
    ) -> Result<FinalizeOutcomeView, CommandError> {
        assert_eq!(confirmed, &preview().to_view().unwrap());
        self.check(id, hash, "NATIVE-EVIDENCE-FINALIZE-REFUSED")
    }
    fn recover(
        &self,
        id: DestructionId,
        hash: ObjectHash,
    ) -> Result<PendingResumeOutcomeView, CommandError> {
        self.check(id, hash, "NATIVE-EVIDENCE-RECOVER-REFUSED")
    }
    fn discard(
        &self,
        id: DestructionId,
        hash: ObjectHash,
    ) -> Result<DiscardStateView, CommandError> {
        self.check(id, hash, "NATIVE-EVIDENCE-DISCARD-REFUSED")
    }
}
fn host(role: Option<OperatorRoleV1>) -> (DesktopState, Arc<Port>) {
    let port = Arc::new(Port(AtomicUsize::new(0)));
    let state = DesktopState::new(SessionState::new(None, None), None, None, None, None, None)
        .with_runtime_session(Arc::new(Role(role)))
        .with_destruction_evidence(port.clone());
    (state, port)
}
fn preview() -> FinalizationPreviewDto {
    FinalizationPreviewDto {
        proposed_sequence: 2,
        binds_predecessor: true,
        effective_now: 10,
        trust_age_ms: 1,
        reader_trust_refresh_ms: 100,
        trust_refresh_overdue: false,
        stale_decision: ea_ui_contracts::stale_decision_literal(
            ea_ui_contracts::StaleDecision::Fresh,
        )
        .into(),
    }
}
#[test]
fn evidence_commands_refuse_every_non_admin_before_parsing_or_entering_the_port() {
    for role in [
        None,
        Some(OperatorRoleV1::Writer),
        Some(OperatorRoleV1::Reader),
    ] {
        let (state, port) = host(role);
        let results = [
            destruction_evidence_preview_core(&state, "bad", "bad").err(),
            destruction_evidence_finalize_core(&state, "bad", "bad", &preview()).err(),
            destruction_evidence_recover_core(&state, "bad", "bad").err(),
            destruction_evidence_discard_core(&state, "bad", "bad").err(),
        ];
        assert!(
            results
                .into_iter()
                .all(|error| error.unwrap().code == "EA-DESKTOP-ADMINISTRATION-FORBIDDEN")
        );
        assert_eq!(port.0.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn each_explicit_evidence_action_uses_its_own_port_and_preserves_native_refusal() {
    let (state, port) = host(Some(OperatorRoleV1::OrganizationAdmin));
    let id = "11".repeat(16);
    let hash = "22".repeat(32);
    assert_eq!(
        destruction_evidence_preview_core(&state, &id, &hash)
            .err()
            .unwrap()
            .code,
        "NATIVE-EVIDENCE-PREVIEW-REFUSED"
    );
    assert_eq!(
        destruction_evidence_finalize_core(&state, &id, &hash, &preview())
            .err()
            .unwrap()
            .code,
        "NATIVE-EVIDENCE-FINALIZE-REFUSED"
    );
    assert_eq!(
        destruction_evidence_recover_core(&state, &id, &hash)
            .err()
            .unwrap()
            .code,
        "NATIVE-EVIDENCE-RECOVER-REFUSED"
    );
    assert_eq!(
        destruction_evidence_discard_core(&state, &id, &hash)
            .err()
            .unwrap()
            .code,
        "NATIVE-EVIDENCE-DISCARD-REFUSED"
    );
    assert_eq!(port.0.load(Ordering::SeqCst), 4);
}
#[test]
fn malformed_identifiers_and_preview_never_reach_the_evidence_writer() {
    let (state, port) = host(Some(OperatorRoleV1::OrganizationAdmin));
    let id = "11".repeat(16);
    let hash = "22".repeat(32);
    assert!(destruction_evidence_preview_core(&state, "../job", &hash).is_err());
    assert!(destruction_evidence_recover_core(&state, &id, &"AA".repeat(32)).is_err());
    assert!(destruction_evidence_discard_core(&state, &id, "").is_err());
    let mut wrong = preview();
    wrong.stale_decision = "arbitrary".into();
    assert!(destruction_evidence_finalize_core(&state, &id, &hash, &wrong).is_err());
    wrong = preview();
    wrong.proposed_sequence = u64::MAX;
    assert!(destruction_evidence_finalize_core(&state, &id, &hash, &wrong).is_err());
    assert_eq!(port.0.load(Ordering::SeqCst), 0);
}
