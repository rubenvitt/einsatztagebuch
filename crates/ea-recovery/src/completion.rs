//! Signed completion of a full native recovery run. This document is evidence
//! of tested recovery, never a Writer authorization or a replacement registry.
use crate::test_run::TestReport;
use crate::{
    CompletedRecoveryRun, FsArchiveSource, KeyInventory, RecoveryTestError, VerifiedRecoverySource,
};
use ea_trust::TrustAnchorV1;
use ea_types::{ChainSequence, Hash32, ObjectHash, RegistryVersion, UnixMillis};
use std::collections::BTreeSet;
const DOMAIN: &str = "EINSATZARCHIV-RECOVERY-COMPLETION-v1";

pub struct RecoveryCompletionCore {
    exact: Vec<u8>,
    report: Vec<u8>,
    restored: [u8; 32],
    completed: UnixMillis,
    next_due: UnixMillis,
}
impl RecoveryCompletionCore {
    pub fn new(
        run: &CompletedRecoveryRun,
        restored: [u8; 32],
        completed: UnixMillis,
        next_due: UnixMillis,
    ) -> Result<Self, RecoveryTestError> {
        Self::encode(run.exact_report().to_vec(), restored, completed, next_due)
    }
    fn encode(
        report: Vec<u8>,
        restored: [u8; 32],
        completed: UnixMillis,
        next_due: UnixMillis,
    ) -> Result<Self, RecoveryTestError> {
        if report.is_empty()
            || report.len() > 768 * 1024
            || restored == [0; 32]
            || completed.get() < 0
            || next_due <= completed
        {
            return Err(RecoveryTestError::Source);
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(6)
            .and_then(|e| e.str(DOMAIN))
            .and_then(|e| e.u64(1))
            .and_then(|e| e.bytes(&report))
            .and_then(|e| e.bytes(&restored))
            .and_then(|e| e.i64(completed.get()))
            .and_then(|e| e.i64(next_due.get()))
            .map_err(|_| RecoveryTestError::Source)?;
        Ok(Self {
            exact: e.into_writer(),
            report,
            restored,
            completed,
            next_due,
        })
    }
    fn parse(exact: &[u8]) -> Result<Self, RecoveryTestError> {
        if exact.len() > 1024 * 1024 {
            return Err(RecoveryTestError::Source);
        }
        let mut d = minicbor::Decoder::new(exact);
        if d.array().map_err(|_| RecoveryTestError::Source)? != Some(6)
            || d.str().map_err(|_| RecoveryTestError::Source)? != DOMAIN
            || d.u64().map_err(|_| RecoveryTestError::Source)? != 1
        {
            return Err(RecoveryTestError::Source);
        }
        let report = d.bytes().map_err(|_| RecoveryTestError::Source)?.to_vec();
        let restored = d
            .bytes()
            .map_err(|_| RecoveryTestError::Source)?
            .try_into()
            .map_err(|_| RecoveryTestError::Source)?;
        let completed = UnixMillis::new(d.i64().map_err(|_| RecoveryTestError::Source)?);
        let next_due = UnixMillis::new(d.i64().map_err(|_| RecoveryTestError::Source)?);
        let core = Self::encode(report, restored, completed, next_due)?;
        if d.position() != exact.len() || core.exact != exact {
            return Err(RecoveryTestError::Source);
        }
        Ok(core)
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub fn context_hash(&self) -> Hash32 {
        let mut hash = ea_crypto::StreamingObjectHasher::new();
        hash.update(b"EINSATZARCHIV-RECOVERY-COMPLETION-CONTEXT-v1");
        hash.update(&self.exact);
        Hash32::try_from(hash.finish().as_bytes().as_slice()).expect("hash width")
    }
}
pub fn recovery_completion_envelope(
    core: &RecoveryCompletionCore,
    audit: &[u8],
) -> Result<Vec<u8>, RecoveryTestError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .and_then(|e| e.bytes(&core.exact))
        .and_then(|e| e.bytes(audit))
        .map_err(|_| RecoveryTestError::Source)?;
    Ok(e.into_writer())
}
pub struct VerifiedCompletedRecoveryReport {
    exact: Vec<u8>,
    core: RecoveryCompletionCore,
    report: TestReport,
    audit_id: ea_types::EventId,
}
impl VerifiedCompletedRecoveryReport {
    pub fn exact_envelope(&self) -> &[u8] {
        &self.exact
    }
    pub fn envelope_hash(&self) -> ObjectHash {
        ea_crypto::object_hash(&self.exact)
    }
    pub fn restored_content_hash(&self) -> &[u8; 32] {
        &self.core.restored
    }
    pub fn completed_at(&self) -> UnixMillis {
        self.core.completed
    }
    pub fn next_due_at(&self) -> UnixMillis {
        self.core.next_due
    }
    pub fn audit_id(&self) -> ea_types::EventId {
        self.audit_id
    }
    pub fn source_envelope_hash(&self) -> ObjectHash {
        ObjectHash::try_from(
            decode_hash(&self.report.source_envelope_hash)
                .expect("verified field")
                .as_slice(),
        )
        .expect("hash width")
    }
    pub fn target_machine(&self) -> Hash32 {
        Hash32::try_from(
            decode_hash(&self.report.target_machine)
                .expect("verified field")
                .as_slice(),
        )
        .expect("hash width")
    }
    pub fn anchor_hash(&self) -> Hash32 {
        Hash32::try_from(
            decode_hash(&self.report.anchor_hash)
                .expect("verified field")
                .as_slice(),
        )
        .expect("hash width")
    }
    pub fn target_installation(&self) -> Hash32 {
        Hash32::try_from(
            decode_hash(&self.report.target_installation)
                .expect("verified field")
                .as_slice(),
        )
        .expect("hash width")
    }
    pub fn tested_media_count(&self) -> usize {
        self.report.media.len()
    }
    pub fn public_report(&self) -> &[u8] {
        &self.core.report
    }
}
pub(crate) fn decode_hash(value: &str) -> Result<[u8; 32], RecoveryTestError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(RecoveryTestError::Source);
    }
    hex::decode(value)
        .map_err(|_| RecoveryTestError::Source)?
        .try_into()
        .map_err(|_| RecoveryTestError::Source)
}
pub fn verify_completed_recovery_report(
    exact: &[u8],
    scope: &VerifiedRecoverySource,
    source: &FsArchiveSource,
    anchor: &TrustAnchorV1,
    keys: &KeyInventory,
    now: UnixMillis,
) -> Result<VerifiedCompletedRecoveryReport, RecoveryTestError> {
    if exact.len() > 1024 * 1024 {
        return Err(RecoveryTestError::Source);
    }
    let mut d = minicbor::Decoder::new(exact);
    if d.array().map_err(|_| RecoveryTestError::Source)? != Some(2) {
        return Err(RecoveryTestError::Source);
    }
    let core = RecoveryCompletionCore::parse(d.bytes().map_err(|_| RecoveryTestError::Source)?)?;
    let audit = d.bytes().map_err(|_| RecoveryTestError::Source)?;
    if d.position() != exact.len() || recovery_completion_envelope(&core, audit)? != exact {
        return Err(RecoveryTestError::Source);
    }
    let report: TestReport =
        serde_json::from_slice(&core.report).map_err(|_| RecoveryTestError::Source)?;
    if serde_json::to_vec(&report).map_err(|_| RecoveryTestError::Source)? != core.report {
        return Err(RecoveryTestError::Source);
    }
    let f = scope.core().fields();
    if report.schema_id != "ea.recovery-test/v1"
        || report.result != "complete"
        || report.error_code.is_some()
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
        || decode_hash(&report.archive_inventory_hash)?
            != crate::recovery_archive_inventory_hash(source)?
        || decode_hash(&report.archive_inventory_hash)? != f.archive_inventory_hash
        || report.tip_sequence != f.tip_sequence
        || decode_hash(&report.tip_entry_hash)? != f.tip_entry_hash
        || report.effective_now < f.effective_now
        || report.effective_now > core.completed.get()
        || core.completed > now
        || report.release_version.is_empty()
        || report.release_version.len() > 128
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
    if report.registry_version < f.registry_version
        || report.proposed_sequence != f.proposed_sequence
        || u64::try_from(core.next_due.get().saturating_sub(core.completed.get())).ok()
            != Some(head.policy_fields().restore_test_interval_ms)
    {
        return Err(RecoveryTestError::Source);
    }
    crate::source_verification::verify_recovery_audit_context(
        audit,
        &head,
        core.context_hash(),
        core.completed,
        ea_format::LocalAuditOutcomeV1::Completed,
    )?;
    let event = ea_format::decode_local_audit_event(audit).map_err(|_| RecoveryTestError::Audit)?;
    if report.media.len() != keys.media().len() {
        return Err(RecoveryTestError::Incomplete);
    }
    let mut expected = keys.media().iter().collect::<Vec<_>>();
    expected.sort_by_key(|m| m.pseudonymous_id_hash());
    for (actual, medium) in report.media.iter().zip(expected) {
        let kind = match medium.test_kind() {
            crate::RecoveryTestKind::SignatureChallenge => "signatureChallenge",
            crate::RecoveryTestKind::RecoveryDecrypt => "recoveryDecrypt",
            crate::RecoveryTestKind::ProviderPresence => "providerPresence",
        };
        if decode_hash(&actual.medium_id_hash)? != *medium.pseudonymous_id_hash().as_bytes()
            || actual.role != medium.role().label()
            || decode_hash(&actual.certificate_hash)? != *medium.certificate().as_bytes()
            || decode_hash(&actual.expected_thumbprint)? != *medium.expected_thumbprint().as_bytes()
            || actual.observed_thumbprint != actual.expected_thumbprint
            || actual.test_kind != kind
            || actual.result != "passed"
            || actual.error_code.is_some()
        {
            return Err(RecoveryTestError::Incomplete);
        }
    }
    let schemas = ea_schema::SchemaRegistry::v1();
    let expected_schemas = schemas
        .schemas()
        .iter()
        .map(|s| format!("{}/v{}", s.schema_id(), s.schema_version()))
        .collect::<Vec<_>>();
    if report.schema_versions != expected_schemas
        || report.suite_versions != [ea_schema::SUITE_ID_V1]
        || report.samples.is_empty()
    {
        return Err(RecoveryTestError::Incomplete);
    }
    let mut buckets = BTreeSet::new();
    let mut writers = BTreeSet::new();
    for sample in &report.samples {
        let entry = probe
            .inventory()
            .entries()
            .iter()
            .find(|e| hex::encode(e.value().entry_hash().as_bytes()) == sample.entry_hash)
            .ok_or(RecoveryTestError::Incomplete)?;
        let fields = entry.value().manifest().fields();
        if decode_hash(&sample.object_hash)? != *entry.object_hash().as_bytes()
            || sample.sequence != fields.chain_sequence.get()
            || decode_hash(&sample.writer_certificate_hash)?
                != *fields.writer_certificate_hash.as_bytes()
            || sample.suite_id != ea_schema::SUITE_ID_V1
            || !schemas.schemas().iter().any(|s| {
                s.schema_id() == sample.schema_id && s.schema_version() == sample.schema_version
            })
            || !probe.inventory().grants().iter().any(|g| {
                hex::encode(g.object_hash().as_bytes()) == sample.grant_hash
                    && g.value().grant_body().fields().entry_hash == entry.value().entry_hash()
                    && g.value().grant_body().fields().purpose
                        == ea_format::GrantPurposeV1::Recovery
            })
            || !buckets.insert((
                &sample.schema_id,
                sample.schema_version,
                &sample.suite_id,
                &sample.writer_certificate_hash,
            ))
        {
            return Err(RecoveryTestError::Incomplete);
        }
        writers.insert(fields.writer_certificate_hash);
    }
    if probe
        .inventory()
        .entries()
        .iter()
        .any(|e| !writers.contains(&e.value().manifest().fields().writer_certificate_hash))
    {
        return Err(RecoveryTestError::Incomplete);
    }
    Ok(VerifiedCompletedRecoveryReport {
        exact: exact.to_vec(),
        core,
        report,
        audit_id: event.event_id(),
    })
}
