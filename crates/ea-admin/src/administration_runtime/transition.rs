//! Native transition diagnostics reconstructed from exact current/journal evidence.
use crate::{
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
    writer_transition::WriterTransitionPhase,
};
use ea_types::{CertificateHash, ChainSequence, ObjectHash};
pub struct AdministrationWriterTransition {
    phase: WriterTransitionPhase,
    current_writer: CertificateHash,
    new_writer: Option<CertificateHash>,
    effective_from: Option<ChainSequence>,
    ceremony_id: Option<ObjectHash>,
}
impl AdministrationWriterTransition {
    pub fn phase(&self) -> WriterTransitionPhase {
        self.phase
    }
    pub fn current_writer(&self) -> CertificateHash {
        self.current_writer
    }
    pub fn new_writer(&self) -> Option<CertificateHash> {
        self.new_writer
    }
    pub fn effective_from(&self) -> Option<ChainSequence> {
        self.effective_from
    }
    pub fn ceremony_id(&self) -> Option<ObjectHash> {
        self.ceremony_id
    }
}
pub fn current_transition(
    runtime: &mut OperatorRuntime,
) -> Result<AdministrationWriterTransition, OperatorRuntimeError> {
    super::views::current_view(runtime)?;
    let result = observe_transition(runtime)?;
    runtime.ensure_same_action_authority()?;
    Ok(result)
}
/// Read-only projection for a caller, such as the GoLive callback, that has
/// already reopened its actual source. This value never grants action authority.
pub fn observe_transition(
    runtime: &OperatorRuntime,
) -> Result<AdministrationWriterTransition, OperatorRuntimeError> {
    use crate::{OperatorLifecycleError, TrustCeremonyStep};
    use ea_format::{DecodedTrustPayloadV1, TrustPayloadV1};
    use ea_local_store::StoreValue;
    let error = || OperatorRuntimeError::from(OperatorLifecycleError::JournalConflict);
    if runtime.config().role != ea_format::OperatorRoleV1::OrganizationAdmin
        || runtime.config().authority
    {
        return Err(OperatorRuntimeError::Config);
    }
    runtime.go_live_report()?;
    let current_writer = runtime
        .head()
        .current_writer_certificate_hash()
        .ok_or_else(error)?;
    let effective = runtime.head().effective_writer_transition();
    let mut result = AdministrationWriterTransition {
        phase: if effective.is_some() {
            WriterTransitionPhase::Activated
        } else {
            WriterTransitionPhase::NoTransition
        },
        current_writer,
        new_writer: effective.map(|t| t.new_writer_certificate_hash()),
        effective_from: effective.map(|t| t.effective_from_sequence()),
        ceremony_id: None,
    };
    let count=runtime.database().query_row(
        "SELECT COUNT(*) FROM administration_ceremony_intent WHERE source_kind=0 AND ceremony_round=0",&[])?
        .ok_or_else(error)?.integer(0)?;
    if !(0..=4096).contains(&count) {
        return Err(error());
    }
    for offset in 0..count {
        let row=runtime.database().query_row(
            "SELECT intent_hash,target_payload FROM administration_ceremony_intent WHERE source_kind=0 AND ceremony_round=0 ORDER BY intent_hash LIMIT 1 OFFSET ?1",
            &[StoreValue::Integer(offset)])?.ok_or_else(error)?;
        let payload = TrustPayloadV1::from_exact_digest_input(row.blob(1)?).map_err(|_| error())?;
        let DecodedTrustPayloadV1::WriterTransition(core) =
            payload.decoded_payload().map_err(|_| error())?
        else {
            continue;
        };
        let id = ObjectHash::try_from(row.blob(0)?).map_err(|_| error())?;
        let parent = super::ceremony::load_admitted(runtime, id)?;
        let active = if parent.step() == TrustCeremonyStep::TargetPublished {
            let child = parent.linked_ceremony_id().ok_or_else(error)?;
            let next = super::ceremony::load_admitted(runtime, child)?;
            if next.step() == TrustCeremonyStep::RegistryPublished {
                continue;
            }
            child
        } else {
            id
        };
        if result.ceremony_id.is_some() {
            return Err(error());
        }
        super::direct_intent::validate_transition(runtime, core.fields())?;
        result.phase = WriterTransitionPhase::Prepared;
        result.new_writer = Some(core.fields().new_writer_certificate_hash);
        result.effective_from = Some(core.fields().effective_from_sequence);
        result.ceremony_id = Some(active);
    }
    runtime.go_live_report()?;
    Ok(result)
}
