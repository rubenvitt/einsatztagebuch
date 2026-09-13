//! IPC/role boundary witnesses. Native signature, presence and persistence are
//! exercised separately by the actual operator destruction process fixtures.
use ea_desktop::{
    commands::{CommandError, destruction::*},
    state::{DesktopState, DestructionAdministrationPort, RuntimeSessionPort, SessionState},
};
use ea_format::OperatorRoleV1;
use ea_types::{DestructionId, ObjectHash};
use ea_ui_contracts::DestructionAdministrationView;
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
struct Observe(AtomicUsize);
impl Observe {
    fn called(&self) -> Result<DestructionAdministrationView, CommandError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CommandError::new("NATIVE-PORT-REFUSED"))
    }
}
impl DestructionAdministrationPort for Observe {
    fn authenticate_custodian(
        &self,
        id: DestructionId,
        hash: ObjectHash,
    ) -> Result<DestructionAdministrationView, CommandError> {
        assert_eq!(id.as_bytes(), &[0x11; 16]);
        assert_eq!(hash.as_bytes(), &[0x22; 32]);
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CommandError::new("NATIVE-CUSTODIAN-LOGIN-REFUSED"))
    }
    fn synchronize(
        &self,
        id: DestructionId,
        hash: ObjectHash,
    ) -> Result<DestructionAdministrationView, CommandError> {
        assert_eq!(id.as_bytes(), &[0x11; 16]);
        assert_eq!(hash.as_bytes(), &[0x22; 32]);
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CommandError::new("NATIVE-SYNCHRONIZE-REFUSED"))
    }
    fn read(
        &self,
        _: Option<DestructionId>,
    ) -> Result<DestructionAdministrationView, CommandError> {
        self.called()
    }
    fn prepare(&self, _: &[u8]) -> Result<DestructionAdministrationView, CommandError> {
        self.called()
    }
    fn start(
        &self,
        id: DestructionId,
        hash: ObjectHash,
    ) -> Result<DestructionAdministrationView, CommandError> {
        assert_eq!(id.as_bytes(), &[0x11; 16]);
        assert_eq!(hash.as_bytes(), &[0x22; 32]);
        self.called()
    }
    fn import_progress(
        &self,
        id: DestructionId,
        hash: ObjectHash,
        exact: &[Vec<u8>],
    ) -> Result<DestructionAdministrationView, CommandError> {
        assert_eq!(id.as_bytes(), &[0x11; 16]);
        assert_eq!(hash.as_bytes(), &[0x22; 32]);
        assert_eq!(exact, &[vec![0xff, 0x00, 0x81], vec![0x00, 0x7f]]);
        self.called()
    }
    fn resume(&self, _: DestructionId) -> Result<DestructionAdministrationView, CommandError> {
        self.called()
    }
}
fn host(role: Option<OperatorRoleV1>) -> (DesktopState, Arc<Observe>) {
    let port = Arc::new(Observe(AtomicUsize::new(0)));
    let state = DesktopState::new(SessionState::new(None, None), None, None, None, None, None)
        .with_runtime_session(Arc::new(Role(role)))
        .with_destruction(port.clone());
    (state, port)
}

#[test]
fn every_destruction_action_refuses_non_admin_before_touching_the_port() {
    for role in [
        None,
        Some(OperatorRoleV1::Writer),
        Some(OperatorRoleV1::Reader),
    ] {
        let (state, port) = host(role);
        let id = "11".repeat(16);
        let hash = "22".repeat(32);
        for result in [
            destruction_read_core(&state, None),
            destruction_prepare_core(&state, &[1]),
            destruction_start_core(&state, &id, &hash),
            destruction_resume_core(&state, &id),
            destruction_synchronize_core(&state, &id, &hash),
            destruction_authenticate_custodian_core(&state, &id, &hash),
            destruction_import_progress_core(&state, &id, &hash, &[vec![1]]),
        ] {
            assert_eq!(
                result.err().unwrap().code,
                "EA-DESKTOP-ADMINISTRATION-FORBIDDEN"
            );
        }
        assert_eq!(port.0.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn exact_start_identifiers_reach_the_native_port_and_its_refusal_is_preserved() {
    let (state, port) = host(Some(OperatorRoleV1::OrganizationAdmin));
    let result = destruction_start_core(&state, &"11".repeat(16), &"22".repeat(32));
    assert_eq!(result.err().unwrap().code, "NATIVE-PORT-REFUSED");
    assert_eq!(port.0.load(Ordering::SeqCst), 1);
}

#[test]
fn exact_synchronize_identifiers_reach_only_the_native_synchronize_port() {
    let (state, port) = host(Some(OperatorRoleV1::OrganizationAdmin));
    let result = destruction_synchronize_core(&state, &"11".repeat(16), &"22".repeat(32));
    assert_eq!(result.err().unwrap().code, "NATIVE-SYNCHRONIZE-REFUSED");
    assert_eq!(port.0.load(Ordering::SeqCst), 1);
}

#[test]
fn custodian_login_has_its_own_port_and_preserves_its_native_refusal() {
    let (state, port) = host(Some(OperatorRoleV1::OrganizationAdmin));
    let result =
        destruction_authenticate_custodian_core(&state, &"11".repeat(16), &"22".repeat(32));
    assert_eq!(result.err().unwrap().code, "NATIVE-CUSTODIAN-LOGIN-REFUSED");
    assert_eq!(port.0.load(Ordering::SeqCst), 1);
}

#[test]
fn malformed_identifiers_and_unbounded_authorization_never_enter_the_native_port() {
    let (state, port) = host(Some(OperatorRoleV1::OrganizationAdmin));
    let id = "11".repeat(16);
    for result in [
        destruction_read_core(&state, Some("/tmp/job")),
        destruction_start_core(&state, &id, &"A".repeat(64)),
        destruction_resume_core(&state, ""),
        destruction_synchronize_core(&state, "../job", &"22".repeat(32)),
        destruction_synchronize_core(&state, &id, &"A".repeat(64)),
        destruction_authenticate_custodian_core(&state, "../job", &"22".repeat(32)),
        destruction_authenticate_custodian_core(&state, &id, &"A".repeat(64)),
        destruction_prepare_core(&state, &[]),
        destruction_prepare_core(&state, &vec![0; ea_format::ETB_MAX_RAW_BYTES_V1 + 1]),
    ] {
        assert_eq!(
            result.err().unwrap().code,
            "EA-DESKTOP-DESTRUCTION-WIRE-VALUE"
        );
    }
    assert_eq!(port.0.load(Ordering::SeqCst), 0);
}

#[test]
fn exact_signed_progress_bytes_reach_the_native_port_unchanged() {
    let (state, port) = host(Some(OperatorRoleV1::OrganizationAdmin));
    let result = destruction_import_progress_core(
        &state,
        &"11".repeat(16),
        &"22".repeat(32),
        &[vec![0xff, 0x00, 0x81], vec![0x00, 0x7f]],
    );
    assert_eq!(result.err().unwrap().code, "NATIVE-PORT-REFUSED");
    assert_eq!(port.0.load(Ordering::SeqCst), 1);
}

#[test]
fn progress_import_refuses_bad_ids_empty_and_over_limit_batches_before_native_work() {
    let (state, port) = host(Some(OperatorRoleV1::OrganizationAdmin));
    let id = "11".repeat(16);
    let hash = "22".repeat(32);
    let max = ea_format::ETB_MAX_RAW_BYTES_V1;
    let cases = [
        ("../job", hash.as_str(), vec![vec![1]]),
        (id.as_str(), "AB", vec![vec![1]]),
        (id.as_str(), hash.as_str(), vec![]),
        (id.as_str(), hash.as_str(), vec![vec![]]),
        (id.as_str(), hash.as_str(), vec![vec![1]; 257]),
        (id.as_str(), hash.as_str(), vec![vec![1; max + 1]]),
        // Duplicate bytes still count against the incoming aggregate limit.
        (id.as_str(), hash.as_str(), vec![vec![1; max]; 5]),
    ];
    for (id, hash, exact) in cases {
        assert_eq!(
            destruction_import_progress_core(&state, id, hash, &exact)
                .err()
                .unwrap()
                .code,
            "EA-DESKTOP-DESTRUCTION-WIRE-VALUE"
        );
    }
    assert_eq!(port.0.load(Ordering::SeqCst), 0);
}
