use super::*;
use ea_admin::{
    native_provider::NativeOperatorProvider,
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig},
};
use ea_key_provider::{
    DevicePostureProvider, DevicePostureProviderFake, DevicePostureReport, KeyError,
    PostureRequirement,
};
use std::sync::{Mutex, atomic::Ordering};

struct MutablePosture {
    report: Mutex<DevicePostureReport>,
    fail_after_presence: Option<std::path::PathBuf>,
    io_failure: std::sync::atomic::AtomicBool,
}

impl MutablePosture {
    fn passing() -> Self {
        Self {
            report: Mutex::new(DevicePostureProviderFake::all_passing().report().unwrap()),
            fail_after_presence: None,
            io_failure: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl DevicePostureProvider for MutablePosture {
    fn report(&self) -> Result<DevicePostureReport, KeyError> {
        if self.io_failure.load(Ordering::SeqCst) {
            return Err(KeyError::NotFound);
        }
        if self.fail_after_presence.as_ref().is_some_and(|path| {
            fs::read_to_string(path).is_ok_and(|calls| calls.contains("sign operator-instance"))
        }) {
            return Ok(DevicePostureProviderFake::failing_screen_lock()
                .report()
                .unwrap());
        }
        Ok(*self.report.lock().unwrap())
    }
}

fn runtime(installation: &Installation, posture: Arc<MutablePosture>) -> OperatorRuntime {
    let native = NativeOperatorProvider::open_test_fixture(
        installation.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    OperatorRuntime::open_with_test_native_and_posture(
        OperatorRuntimeConfig::load(&installation.config).unwrap(),
        &installation.anchor,
        support::live_clock(),
        false,
        native,
        posture,
    )
    .unwrap()
}

#[test]
fn each_failed_or_unresolved_posture_denies_a_real_native_session() {
    let installation = Installation::new();
    let posture = Arc::new(MutablePosture::passing());
    let runtime = runtime(&installation, Arc::clone(&posture));
    assert!(
        runtime.reauthenticate().is_ok(),
        "control: actual native proof and persisted audit"
    );
    for requirement in PostureRequirement::ALL {
        for report in [
            DevicePostureProviderFake::failing(requirement)
                .report()
                .unwrap(),
            DevicePostureProviderFake::unknown(requirement)
                .report()
                .unwrap(),
        ] {
            *posture.report.lock().unwrap() = report;
            let error = runtime
                .reauthenticate()
                .err()
                .expect("posture must deny actual session issuance");
            assert_eq!(error.code(), "EA-OPERATOR-POSTURE");
            let measured = runtime.device_posture_report().unwrap();
            assert_eq!(measured, report);
            assert_eq!(measured.go_live_follow_up(), report.go_live_follow_up());
            let go_live = runtime.go_live_report().unwrap();
            assert!(!go_live.session_admitted);
            assert!(
                go_live
                    .device_posture_evidence
                    .contains(&report.check(requirement).evidence_code())
            );
        }
    }
    posture.io_failure.store(true, Ordering::SeqCst);
    assert_eq!(
        runtime.reauthenticate().err().unwrap().code(),
        "EA-OPERATOR-POSTURE"
    );
    assert!(runtime.go_live_report().is_err());
}

#[test]
fn posture_is_rechecked_after_native_presence_before_a_session_is_returned() {
    let installation = Installation::new();
    // Change the measured posture only after the actual native signature
    // operation. Additional pre-dialog checks must not move this event earlier.
    let posture = Arc::new(MutablePosture {
        fail_after_presence: Some(installation.directory.path().join("helper-calls")),
        ..MutablePosture::passing()
    });
    let runtime = runtime(&installation, Arc::clone(&posture));
    let error = runtime
        .reauthenticate()
        .err()
        .expect("changed posture must deny the result");
    assert_eq!(error.code(), "EA-OPERATOR-PROOF-MISMATCH");
    let calls = fs::read_to_string(installation.directory.path().join("helper-calls")).unwrap();
    assert!(
        calls.contains("sign operator-instance"),
        "actual native presence occurred before posture changed"
    );
    installation.latest_audit(LocalAuditOutcomeV1::Failed);
}
