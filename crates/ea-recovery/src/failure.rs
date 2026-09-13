//! A signed failed attempt is durable diagnosis and cannot produce readiness.
use crate::completion::decode_hash;
use crate::test_run::TestReport;
use crate::{
    FailedRecoveryRun, FsArchiveSource, KeyInventory, RecoveryTestError, VerifiedRecoverySource,
};
use ea_trust::TrustAnchorV1;
use ea_types::{ChainSequence, EventId, Hash32, ObjectHash, RegistryVersion, UnixMillis};

const DOMAIN: &str = "EINSATZARCHIV-RECOVERY-FAILURE-v1";
pub struct RecoveryFailureCore {
    exact: Vec<u8>,
    report: Vec<u8>,
    restored: [u8; 32],
    failed: UnixMillis,
}
impl RecoveryFailureCore {
    pub fn new(
        run: &FailedRecoveryRun,
        restored: [u8; 32],
        failed: UnixMillis,
    ) -> Result<Self, RecoveryTestError> {
        Self::encode(run.exact_report().to_vec(), restored, failed)
    }
    fn encode(
        report: Vec<u8>,
        restored: [u8; 32],
        failed: UnixMillis,
    ) -> Result<Self, RecoveryTestError> {
        if report.is_empty() || report.len() > 768 * 1024 || restored == [0; 32] || failed.get() < 0
        {
            return Err(RecoveryTestError::Source);
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(5)
            .and_then(|e| e.str(DOMAIN))
            .and_then(|e| e.u8(1))
            .and_then(|e| e.bytes(&report))
            .and_then(|e| e.bytes(&restored))
            .and_then(|e| e.i64(failed.get()))
            .map_err(|_| RecoveryTestError::Source)?;
        Ok(Self {
            exact: e.into_writer(),
            report,
            restored,
            failed,
        })
    }
    fn parse(exact: &[u8]) -> Result<Self, RecoveryTestError> {
        if exact.len() > 1024 * 1024 {
            return Err(RecoveryTestError::Source);
        }
        let mut d = minicbor::Decoder::new(exact);
        if d.array().map_err(|_| RecoveryTestError::Source)? != Some(5)
            || d.str().map_err(|_| RecoveryTestError::Source)? != DOMAIN
            || d.u8().map_err(|_| RecoveryTestError::Source)? != 1
        {
            return Err(RecoveryTestError::Source);
        }
        let report = d.bytes().map_err(|_| RecoveryTestError::Source)?.to_vec();
        let restored = d
            .bytes()
            .map_err(|_| RecoveryTestError::Source)?
            .try_into()
            .map_err(|_| RecoveryTestError::Source)?;
        let failed = UnixMillis::new(d.i64().map_err(|_| RecoveryTestError::Source)?);
        let value = Self::encode(report, restored, failed)?;
        if d.position() != exact.len() || value.exact != exact {
            return Err(RecoveryTestError::Source);
        }
        Ok(value)
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub fn context_hash(&self) -> Hash32 {
        let mut h = ea_crypto::StreamingObjectHasher::new();
        h.update(b"EINSATZARCHIV-RECOVERY-FAILURE-CONTEXT-v1");
        h.update(&self.exact);
        Hash32::try_from(h.finish().as_bytes().as_slice()).expect("hash width")
    }
}
pub fn recovery_failure_envelope(
    core: &RecoveryFailureCore,
    audit: &[u8],
) -> Result<Vec<u8>, RecoveryTestError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .and_then(|e| e.bytes(&core.exact))
        .and_then(|e| e.bytes(audit))
        .map_err(|_| RecoveryTestError::Source)?;
    Ok(e.into_writer())
}
pub struct VerifiedFailedRecoveryReport {
    exact: Vec<u8>,
    core: RecoveryFailureCore,
    report: TestReport,
    audit_id: EventId,
}
impl VerifiedFailedRecoveryReport {
    pub fn exact_envelope(&self) -> &[u8] {
        &self.exact
    }
    pub fn public_report(&self) -> &[u8] {
        &self.core.report
    }
    pub fn envelope_hash(&self) -> ObjectHash {
        ea_crypto::object_hash(&self.exact)
    }
    pub fn context_hash(&self) -> Hash32 {
        self.core.context_hash()
    }
    pub fn failed_at(&self) -> UnixMillis {
        self.core.failed
    }
    pub fn audit_id(&self) -> EventId {
        self.audit_id
    }
    pub fn restored_content_hash(&self) -> &[u8; 32] {
        &self.core.restored
    }
    pub fn source_envelope_hash(&self) -> ObjectHash {
        ObjectHash::try_from(
            decode_hash(&self.report.source_envelope_hash)
                .expect("verified hash")
                .as_slice(),
        )
        .expect("hash width")
    }
    pub fn target_machine(&self) -> Hash32 {
        Hash32::try_from(
            decode_hash(&self.report.target_machine)
                .expect("verified hash")
                .as_slice(),
        )
        .expect("hash width")
    }
    pub fn target_installation(&self) -> Hash32 {
        Hash32::try_from(
            decode_hash(&self.report.target_installation)
                .expect("verified hash")
                .as_slice(),
        )
        .expect("hash width")
    }
}
pub fn verify_failed_recovery_report(
    exact: &[u8],
    scope: &VerifiedRecoverySource,
    source: &FsArchiveSource,
    anchor: &TrustAnchorV1,
    keys: &KeyInventory,
    now: UnixMillis,
) -> Result<VerifiedFailedRecoveryReport, RecoveryTestError> {
    if exact.len() > 1024 * 1024 {
        return Err(RecoveryTestError::Source);
    }
    let mut d = minicbor::Decoder::new(exact);
    if d.array().map_err(|_| RecoveryTestError::Source)? != Some(2) {
        return Err(RecoveryTestError::Source);
    }
    let core = RecoveryFailureCore::parse(d.bytes().map_err(|_| RecoveryTestError::Source)?)?;
    let audit = d.bytes().map_err(|_| RecoveryTestError::Source)?;
    if d.position() != exact.len() || recovery_failure_envelope(&core, audit)? != exact {
        return Err(RecoveryTestError::Source);
    }
    let report: TestReport =
        serde_json::from_slice(&core.report).map_err(|_| RecoveryTestError::Source)?;
    if serde_json::to_vec(&report).map_err(|_| RecoveryTestError::Source)? != core.report {
        return Err(RecoveryTestError::Source);
    }
    let f = scope.core().fields();
    if report.schema_id != "ea.recovery-test/v1"
        || report.result != "failed"
        || report.test_id.len() != 32
        || !report
            .test_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || decode_hash(&report.source_envelope_hash)? != *scope.envelope_hash().as_bytes()
        || decode_hash(&report.source_machine)? != f.source_machine
        || decode_hash(&report.target_machine)? == f.source_machine
        || decode_hash(&report.target_machine)? == [0; 32]
        || decode_hash(&report.target_installation)? == f.source_installation
        || decode_hash(&report.target_installation)? == [0; 32]
        || decode_hash(&report.anchor_hash)? != *anchor.trust_anchor_hash().as_bytes()
        || f.inventory_hash != *keys.exact_hash().as_bytes()
        || decode_hash(&report.archive_inventory_hash)? != f.archive_inventory_hash
        || f.archive_inventory_hash != crate::recovery_archive_inventory_hash(source)?
        || report.tip_sequence != f.tip_sequence
        || decode_hash(&report.tip_entry_hash)? != f.tip_entry_hash
        || report.effective_now < f.effective_now
        || report.effective_now > core.failed.get()
        || core.failed > now
        || report.registry_version < f.registry_version
        || report.proposed_sequence != f.proposed_sequence
        || report.error_code.as_deref() != Some(RecoveryTestError::Incomplete.code())
        || report.release_version.is_empty()
        || report.release_version.len() > 128
        || !report.samples.is_empty()
    {
        return Err(RecoveryTestError::Source);
    }
    let probe = crate::RecoveryArchiveProbe::verify(source, anchor, now)?;
    let head = ea_verify::historical_registry_head(
        probe.inventory(),
        anchor,
        RegistryVersion::new(report.registry_version),
        ObjectHash::try_from(decode_hash(&report.registry_head_hash)?.as_slice())
            .map_err(|_| RecoveryTestError::Source)?,
        ChainSequence::new(report.proposed_sequence),
        now,
    )
    .ok_or(RecoveryTestError::Source)?;
    crate::source_verification::verify_recovery_audit_context(
        audit,
        &head,
        core.context_hash(),
        core.failed,
        ea_format::LocalAuditOutcomeV1::Failed,
    )?;
    let event = ea_format::decode_local_audit_event(audit).map_err(|_| RecoveryTestError::Audit)?;
    let schemas = ea_schema::SchemaRegistry::v1();
    let expected = schemas
        .schemas()
        .iter()
        .map(|s| format!("{}/v{}", s.schema_id(), s.schema_version()))
        .collect::<Vec<_>>();
    if report.schema_versions != expected
        || report.suite_versions != [ea_schema::SUITE_ID_V1]
        || report.media.len() != keys.media().len()
    {
        return Err(RecoveryTestError::Incomplete);
    }
    let mut media = keys.media().iter().collect::<Vec<_>>();
    media.sort_by_key(|m| m.pseudonymous_id_hash());

    for (actual, medium) in report.media.iter().zip(media) {
        let kind = match medium.test_kind() {
            crate::RecoveryTestKind::SignatureChallenge => "signatureChallenge",
            crate::RecoveryTestKind::RecoveryDecrypt => "recoveryDecrypt",
            crate::RecoveryTestKind::ProviderPresence => "providerPresence",
        };
        if decode_hash(&actual.medium_id_hash)? != *medium.pseudonymous_id_hash().as_bytes()
            || actual.role != medium.role().label()
            || decode_hash(&actual.certificate_hash)? != *medium.certificate().as_bytes()
            || decode_hash(&actual.expected_thumbprint)? != *medium.expected_thumbprint().as_bytes()
            || actual.test_kind != kind
        {
            return Err(RecoveryTestError::Incomplete);
        }
        match actual.result.as_str() {
            "passed"
                if actual.observed_thumbprint == actual.expected_thumbprint
                    && actual.error_code.is_none() => {}
            "missing"
                if actual.observed_thumbprint.is_empty()
                    && actual.error_code.as_deref()
                        == Some(RecoveryTestError::Incomplete.code()) => {}
            "failed"
                if actual.error_code.as_deref().is_some_and(valid_failure_code)
                    && (actual.observed_thumbprint.is_empty()
                        || decode_hash(&actual.observed_thumbprint).is_ok()) => {}
            _ => return Err(RecoveryTestError::Incomplete),
        }
    }
    // Every probe may pass while aggregate archive coverage remains incomplete.
    // The signed overall code preserves this separate failure.
    Ok(VerifiedFailedRecoveryReport {
        exact: exact.to_vec(),
        core,
        report,
        audit_id: event.event_id(),
    })
}
fn valid_failure_code(code: &str) -> bool {
    use RecoveryTestError::*;
    [
        Archive, Inventory, Key, Protection, Role, Entropy, Payload, Incomplete, Operator, Audit,
        Source, Machine, Store,
    ]
    .into_iter()
    .any(|error| error.code() == code)
}
