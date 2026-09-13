use super::{CommandError, identifier};
use ea_ui_contracts::{
    RecoveryAdministrationView, RecoveryMediumObservationView, RecoveryMediumRequestView,
    RecoveryReportView, RecoveryRunView,
};
use serde_json::{Value, json};

fn invalid() -> CommandError {
    CommandError::new("EA-DESKTOP-RECOVERY-WIRE-VALUE")
}
fn request(value: RecoveryMediumRequestView) -> Result<Value, CommandError> {
    let RecoveryMediumRequestView {
        run_id,
        request_id,
        medium_id_hash,
        index,
        total,
        role_code,
        certificate_hash,
        expected_thumbprint,
        protection_code,
        test_kind_code,
    } = value;
    identifier(&run_id, 16)?;
    identifier(&request_id, 32)?;
    identifier(&medium_id_hash, 32)?;
    identifier(&certificate_hash, 32)?;
    identifier(&expected_thumbprint, 32)?;
    if total == 0 || total > 1024 || index == 0 || index > total || protection_code > 4 {
        return Err(invalid());
    }
    Ok(
        json!({"runId":run_id,"requestId":request_id,"mediumIdHash":medium_id_hash,
        "index":index,"total":total,"roleCode":role_code,"certificateHash":certificate_hash,
        "expectedThumbprint":expected_thumbprint,"protectionCode":protection_code,"testKindCode":test_kind_code}),
    )
}
fn observation(value: RecoveryMediumObservationView) -> Result<Value, CommandError> {
    let RecoveryMediumObservationView {
        request: pending,
        result_code,
        observed_thumbprint,
        error_code,
    } = value;
    if result_code > 2 {
        return Err(invalid());
    }
    if let Some(hash) = &observed_thumbprint {
        identifier(hash, 32)?;
    }
    Ok(json!({"request":request(pending)?,"resultCode":result_code,
        "observedThumbprint":observed_thumbprint,"errorCode":error_code}))
}
fn report(value: Option<RecoveryReportView>) -> Result<Value, CommandError> {
    let Some(RecoveryReportView {
        completed,
        exact_public_report_json,
        envelope_hash,
        source_envelope_hash,
        audit_id,
        finished_at_ms,
        next_due_at_ms,
    }) = value
    else {
        return Ok(Value::Null);
    };
    identifier(&envelope_hash, 32)?;
    identifier(&source_envelope_hash, 32)?;
    identifier(&audit_id, 16)?;
    if !(0..=8_640_000_000_000_000).contains(&finished_at_ms)
        || completed != next_due_at_ms.is_some()
        || next_due_at_ms.is_some_and(|due| due < finished_at_ms || due > 8_640_000_000_000_000)
        || exact_public_report_json.is_empty()
        || exact_public_report_json.len() > 4 * 1024 * 1024
    {
        return Err(invalid());
    }
    let body: Value = serde_json::from_str(&exact_public_report_json).map_err(|_| invalid())?;
    if body["schemaId"] != "ea.recovery-test/v1"
        || body["sourceEnvelopeHash"] != source_envelope_hash
        || body["result"] != if completed { "complete" } else { "failed" }
    {
        return Err(invalid());
    }
    Ok(
        json!({"completed":completed,"exactPublicReportJson":exact_public_report_json,
        "envelopeHash":envelope_hash,"sourceEnvelopeHash":source_envelope_hash,"auditId":audit_id,
        "finishedAtMs":finished_at_ms,"nextDueAtMs":next_due_at_ms}),
    )
}
fn run(value: Option<RecoveryRunView>) -> Result<Value, CommandError> {
    let Some(RecoveryRunView {
        operation_id,
        phase_code,
        request: pending,
        observations,
        report: outcome,
        error_code,
    }) = value
    else {
        return Ok(Value::Null);
    };
    identifier(&operation_id, 16)?;
    if phase_code > 6 || observations.len() > 1024 {
        return Err(invalid());
    }
    let pending = pending.map(request).transpose()?.unwrap_or(Value::Null);
    let observations = observations
        .into_iter()
        .map(observation)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(
        json!({"operationId":operation_id,"phaseCode":phase_code,"request":pending,
        "observations":observations,"report":report(outcome)?,"errorCode":error_code}),
    )
}
/// One exact JSON representation for IPC and native wire witness artifacts.
pub fn recovery_wire(value: RecoveryAdministrationView) -> Result<Value, CommandError> {
    let RecoveryAdministrationView {
        last_success,
        last_failure,
        run: operation,
    } = value;
    if last_success.as_ref().is_some_and(|value| !value.completed)
        || last_failure.as_ref().is_some_and(|value| value.completed)
    {
        return Err(invalid());
    }
    Ok(
        json!({"lastSuccess":report(last_success)?,"lastFailure":report(last_failure)?,"run":run(operation)?}),
    )
}
