//! Command authorization and exact input correlation. Native recovery outcome
//! verification is exercised by the separate actual recovery process fixtures.
use ea_desktop::{
    commands::{CommandError, recovery::*},
    state::{
        DesktopState, RecoveryAdministrationPort, RecoveryMediumChoice, RuntimeSessionPort,
        SessionState,
    },
};
use ea_format::OperatorRoleV1;
use ea_ui_contracts::RecoveryAdministrationView;
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
struct Native(AtomicUsize);
impl Native {
    fn called(&self) -> Result<RecoveryAdministrationView, CommandError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CommandError::new("ACTUAL-PORT-REFUSAL"))
    }
}
impl RecoveryAdministrationPort for Native {
    fn read(&self) -> Result<RecoveryAdministrationView, CommandError> {
        self.called()
    }
    fn start(&self) -> Result<RecoveryAdministrationView, CommandError> {
        self.called()
    }
    fn submit(
        &self,
        op: &str,
        run: &str,
        request: &str,
        choice: RecoveryMediumChoice,
    ) -> Result<RecoveryAdministrationView, CommandError> {
        assert_eq!(op, "11".repeat(16));
        assert_eq!(run, "22".repeat(16));
        assert_eq!(request, "33".repeat(32));
        assert_eq!(choice, RecoveryMediumChoice::UseConfiguredSource);
        self.called()
    }
    fn cancel(&self, op: &str) -> Result<RecoveryAdministrationView, CommandError> {
        assert_eq!(op, "11".repeat(16));
        self.called()
    }
}
fn host(role: Option<OperatorRoleV1>) -> (DesktopState, Arc<Native>) {
    let native = Arc::new(Native(AtomicUsize::new(0)));
    let state = DesktopState::new(SessionState::new(None, None), None, None, None, None, None)
        .with_runtime_session(Arc::new(Role(role)))
        .with_recovery(native.clone());
    (state, native)
}
#[test]
fn recovery_commands_reject_non_admin_before_parsing_input_or_touching_native_resources() {
    for role in [
        None,
        Some(OperatorRoleV1::Reader),
        Some(OperatorRoleV1::Writer),
    ] {
        let (state, native) = host(role);
        for result in [
            recovery_read_core(&state),
            recovery_start_core(&state),
            recovery_submit_core(&state, "invalid", "invalid", "invalid", 255),
            recovery_cancel_core(&state, "invalid"),
        ] {
            assert_eq!(
                result.err().unwrap().code,
                "EA-DESKTOP-ADMINISTRATION-FORBIDDEN"
            );
        }
        assert_eq!(native.0.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn exact_choice_and_identifiers_reach_the_native_port_and_preserve_its_refusal() {
    let (state, native) = host(Some(OperatorRoleV1::OrganizationAdmin));
    for result in [
        recovery_read_core(&state),
        recovery_start_core(&state),
        recovery_submit_core(
            &state,
            &"11".repeat(16),
            &"22".repeat(16),
            &"33".repeat(32),
            0,
        ),
        recovery_cancel_core(&state, &"11".repeat(16)),
    ] {
        assert_eq!(result.err().unwrap().code, "ACTUAL-PORT-REFUSAL");
    }
    assert_eq!(native.0.load(Ordering::SeqCst), 4);
}
#[test]
fn malformed_or_unbounded_inputs_never_enter_the_native_port() {
    let (state, native) = host(Some(OperatorRoleV1::OrganizationAdmin));
    for result in [
        recovery_submit_core(&state, "/tmp/path", &"22".repeat(16), &"33".repeat(32), 0),
        recovery_submit_core(
            &state,
            &"11".repeat(16),
            &"A".repeat(32),
            &"33".repeat(32),
            0,
        ),
        recovery_submit_core(
            &state,
            &"11".repeat(16),
            &"22".repeat(16),
            &"33".repeat(33),
            0,
        ),
        recovery_submit_core(
            &state,
            &"11".repeat(16),
            &"22".repeat(16),
            &"33".repeat(32),
            2,
        ),
        recovery_cancel_core(&state, ""),
    ] {
        assert_eq!(result.err().unwrap().code, "EA-DESKTOP-RECOVERY-WIRE-VALUE");
    }
    assert_eq!(native.0.load(Ordering::SeqCst), 0);
}
