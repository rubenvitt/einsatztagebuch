//! IPC routing and bounds only. Real native authority is tested in the CLI host fixture.
use ea_desktop::{
    commands::{CommandError, destruction::destruction_export_reader_delivery_core},
    state::{DesktopState, DestructionAdministrationPort, RuntimeSessionPort, SessionState},
};
use ea_format::OperatorRoleV1;
use ea_types::{DestructionId, DeviceId, ObjectHash};
use ea_ui_contracts::{DestructionAdministrationView, DestructionReaderDeliveryView};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct Role(Option<OperatorRoleV1>);
impl RuntimeSessionPort for Role {
    fn verified_role(&self) -> Result<Option<OperatorRoleV1>, CommandError> {
        Ok(self.0)
    }
    fn invalidate(&self) {}
}
fn denied() -> CommandError {
    CommandError::new("UNEXPECTED-OTHER-PORT")
}
macro_rules! old_port_methods {
    () => {
        fn authenticate_custodian(
            &self,
            _: DestructionId,
            _: ObjectHash,
        ) -> Result<DestructionAdministrationView, CommandError> {
            Err(denied())
        }
        fn synchronize(
            &self,
            _: DestructionId,
            _: ObjectHash,
        ) -> Result<DestructionAdministrationView, CommandError> {
            Err(denied())
        }
        fn read(
            &self,
            _: Option<DestructionId>,
        ) -> Result<DestructionAdministrationView, CommandError> {
            Err(denied())
        }
        fn prepare(&self, _: &[u8]) -> Result<DestructionAdministrationView, CommandError> {
            Err(denied())
        }
        fn start(
            &self,
            _: DestructionId,
            _: ObjectHash,
        ) -> Result<DestructionAdministrationView, CommandError> {
            Err(denied())
        }
        fn resume(&self, _: DestructionId) -> Result<DestructionAdministrationView, CommandError> {
            Err(denied())
        }
        fn import_progress(
            &self,
            _: DestructionId,
            _: ObjectHash,
            _: &[Vec<u8>],
        ) -> Result<DestructionAdministrationView, CommandError> {
            Err(denied())
        }
    };
}
struct Legacy;
impl DestructionAdministrationPort for Legacy {
    old_port_methods!();
}
struct Export {
    calls: AtomicUsize,
    reply: Mutex<Option<Result<DestructionReaderDeliveryView, CommandError>>>,
}
impl DestructionAdministrationPort for Export {
    old_port_methods!();
    fn export_reader_delivery(
        &self,
        id: DestructionId,
        job: ObjectHash,
        reader: DeviceId,
    ) -> Result<DestructionReaderDeliveryView, CommandError> {
        assert_eq!(id.as_bytes(), &[0x11; 16]);
        assert_eq!(job.as_bytes(), &[0x22; 32]);
        assert_eq!(reader.as_bytes(), &[0x33; 16]);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.reply.lock().unwrap().take().unwrap()
    }
}
fn view() -> DestructionReaderDeliveryView {
    DestructionReaderDeliveryView {
        destruction_id: "11".repeat(16),
        job_hash: "22".repeat(32),
        reader_id: "33".repeat(16),
        exact_authorization: vec![0, 255, 129],
        exact_initiating_event: vec![255, 0, 128],
        exact_job_upload: vec![132, 1, 0, 255],
    }
}
fn state(
    role: Option<OperatorRoleV1>,
    port: Arc<dyn DestructionAdministrationPort>,
) -> DesktopState {
    DesktopState::new(SessionState::new(None, None), None, None, None, None, None)
        .with_runtime_session(Arc::new(Role(role)))
        .with_destruction(port)
}
fn export(reply: Result<DestructionReaderDeliveryView, CommandError>) -> Arc<Export> {
    Arc::new(Export {
        calls: AtomicUsize::new(0),
        reply: Mutex::new(Some(reply)),
    })
}
#[test]
fn reader_export_refuses_non_admin_and_malformed_selectors_before_port_work() {
    for role in [
        None,
        Some(OperatorRoleV1::Writer),
        Some(OperatorRoleV1::Reader),
    ] {
        let port = export(Ok(view()));
        let state = state(role, port.clone());
        assert_eq!(
            destruction_export_reader_delivery_core(
                &state,
                &"11".repeat(16),
                &"22".repeat(32),
                &"33".repeat(16)
            )
            .err()
            .unwrap()
            .code,
            "EA-DESKTOP-ADMINISTRATION-FORBIDDEN"
        );
        assert_eq!(port.calls.load(Ordering::SeqCst), 0);
    }
    let port = export(Ok(view()));
    let state = state(Some(OperatorRoleV1::OrganizationAdmin), port.clone());
    for (id, job, reader) in [
        ("../job".into(), "22".repeat(32), "33".repeat(16)),
        ("11".repeat(16), "AA".repeat(32), "33".repeat(16)),
        ("11".repeat(16), "22".repeat(32), "33".repeat(15)),
        ("11".repeat(16), "22".repeat(32), "CC".repeat(16)),
    ] {
        assert_eq!(
            destruction_export_reader_delivery_core(&state, &id, &job, &reader)
                .err()
                .unwrap()
                .code,
            "EA-DESKTOP-DESTRUCTION-WIRE-VALUE"
        );
    }
    assert_eq!(port.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn reader_export_preserves_exact_payloads_selectors_native_refusal_and_default_deny() {
    let port = export(Ok(view()));
    let state = state(Some(OperatorRoleV1::OrganizationAdmin), port.clone());
    let wire = destruction_export_reader_delivery_core(
        &state,
        &"11".repeat(16),
        &"22".repeat(32),
        &"33".repeat(16),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(wire).unwrap(),
        serde_json::json!({
            "destructionId":"11".repeat(16),"jobHash":"22".repeat(32),"readerId":"33".repeat(16),
            "exactAuthorization":[0,255,129],"exactInitiatingEvent":[255,0,128],"exactJobUpload":[132,1,0,255]
        })
    );
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    let port = export(Err(CommandError::new("NATIVE-EXPORT-REFUSED")));
    let host = super_state(port);
    assert_eq!(
        destruction_export_reader_delivery_core(
            &host,
            &"11".repeat(16),
            &"22".repeat(32),
            &"33".repeat(16)
        )
        .err()
        .unwrap()
        .code,
        "NATIVE-EXPORT-REFUSED"
    );
    let host = super_state(Arc::new(Legacy));
    assert_eq!(
        destruction_export_reader_delivery_core(
            &host,
            &"11".repeat(16),
            &"22".repeat(32),
            &"33".repeat(16)
        )
        .err()
        .unwrap()
        .code,
        "EA-DESKTOP-READER-DELIVERY-UNAVAILABLE"
    );
}
fn super_state(port: Arc<dyn DestructionAdministrationPort>) -> DesktopState {
    state(Some(OperatorRoleV1::OrganizationAdmin), port)
}
#[test]
fn reader_export_refuses_changed_output_selection_empty_and_oversize_originals() {
    for case in [
        "id",
        "job",
        "reader",
        "authorization-empty",
        "event-empty",
        "upload-empty",
        "authorization-limit",
        "event-limit",
        "upload-limit",
    ] {
        let mut reply = view();
        match case {
            "id" => reply.destruction_id = "44".repeat(16),
            "job" => reply.job_hash = "55".repeat(32),
            "reader" => reply.reader_id = "66".repeat(16),
            "authorization-empty" => reply.exact_authorization.clear(),
            "event-empty" => reply.exact_initiating_event.clear(),
            "upload-empty" => reply.exact_job_upload.clear(),
            "authorization-limit" => {
                reply.exact_authorization = vec![0; ea_format::ETB_MAX_RAW_BYTES_V1 + 1]
            }
            "event-limit" => {
                reply.exact_initiating_event = vec![0; ea_format::ETB_MAX_RAW_BYTES_V1 + 1]
            }
            "upload-limit" => {
                reply.exact_job_upload = vec![0; ea_sync_protocol::MAX_READER_PAGE_BYTES_V1 + 1]
            }
            _ => unreachable!(),
        }
        let host = super_state(export(Ok(reply)));
        assert_eq!(
            destruction_export_reader_delivery_core(
                &host,
                &"11".repeat(16),
                &"22".repeat(32),
                &"33".repeat(16)
            )
            .err()
            .unwrap()
            .code,
            "EA-DESKTOP-DESTRUCTION-WIRE-VALUE",
            "{case}"
        );
    }
}
