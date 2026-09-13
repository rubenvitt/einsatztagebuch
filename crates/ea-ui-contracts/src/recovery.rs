//! Public observations of a native recovery test. No provider location or key
//! material crosses this boundary; progress never replaces a signed report.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryMediumRequestView {
    pub run_id: String,
    pub request_id: String,
    pub medium_id_hash: String,
    pub index: u32,
    pub total: u32,
    pub role_code: String,
    pub certificate_hash: String,
    pub expected_thumbprint: String,
    pub protection_code: u64,
    pub test_kind_code: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryMediumObservationView {
    pub request: RecoveryMediumRequestView,
    /// 0 passed, 1 missing, 2 failed, from the native kernel observation.
    pub result_code: u8,
    pub observed_thumbprint: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReportView {
    pub completed: bool,
    pub exact_public_report_json: String,
    pub envelope_hash: String,
    pub source_envelope_hash: String,
    pub audit_id: String,
    pub finished_at_ms: i64,
    pub next_due_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRunView {
    pub operation_id: String,
    /// 0 preparing, 1 awaiting medium, 2 checking medium, 3 completed,
    /// 4 failed with signed report, 5 cancelled, 6 refused without report.
    /// 7 cancellation requested; native worker has not returned its outcome.
    pub phase_code: u8,
    pub request: Option<RecoveryMediumRequestView>,
    pub observations: Vec<RecoveryMediumObservationView>,
    pub report: Option<RecoveryReportView>,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAdministrationView {
    pub last_success: Option<RecoveryReportView>,
    pub last_failure: Option<RecoveryReportView>,
    pub run: Option<RecoveryRunView>,
}
