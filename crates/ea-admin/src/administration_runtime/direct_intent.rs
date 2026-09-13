//! Current explicit policy intentions use the same exact two-round journal.
use super::{
    TrustCeremonyRoundV1,
    ceremony::{self, AdministrationCeremony},
    views::current_view,
};
use crate::{
    OperatorLifecycleError, TrustCeremonyKind, TrustCeremonyStep,
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
};
use ea_crypto::object_hash;
use ea_format::{DecodedTrustPayloadV1, TrustPayloadV1};
use ea_local_store::{StoreRow, StoreValue};
use ea_types::{Hash32, ObjectHash};
fn error() -> OperatorRuntimeError {
    OperatorLifecycleError::JournalConflict.into()
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
fn integer(n: u64) -> Result<StoreValue, OperatorRuntimeError> {
    Ok(StoreValue::Integer(i64::try_from(n).map_err(|_| error())?))
}
fn validate(
    runtime: &OperatorRuntime,
    exact: &[u8],
) -> Result<TrustCeremonyKind, OperatorRuntimeError> {
    let payload = TrustPayloadV1::from_exact_digest_input(exact).map_err(|_| error())?;
    let kind = match payload.decoded_payload().map_err(|_| error())? {
        DecodedTrustPayloadV1::Policy(core) => {
            if core.authorization_object_hash() != ObjectHash::from(Hash32::ZERO)
                || core.fields().organization_id != runtime.anchor().organization_id()
                || core.fields().effective_from_sequence != runtime.next_sequence()
                || Some(core.fields().policy_version)
                    != runtime.head().policy_fields().policy_version.checked_add(1)
                || core.fields().previous_policy_object_hash
                    != Some(runtime.head().policy_object_hash())
            {
                return Err(error());
            }
            TrustCeremonyKind::PolicyChange
        }
        DecodedTrustPayloadV1::WriterTransition(core) => {
            if core.authorization_object_hash() != ObjectHash::from(Hash32::ZERO) {
                return Err(error());
            }
            validate_transition(runtime, core.fields())?;
            TrustCeremonyKind::WriterTransition
        }
        _ => return Err(error()),
    };
    ea_trust::describe_intended_trust_target(
        runtime.trust(),
        Some(runtime.head()),
        &payload,
        runtime.next_sequence(),
    )?;
    Ok(kind)
}
pub(super) fn begin(
    runtime: &mut OperatorRuntime,
    exact: &[u8],
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    current_view(runtime)?;
    validate(runtime, exact)?;
    let id = object_hash(exact);
    runtime.ensure_same_action_authority()?;
    runtime.database().transaction(|tx|{
        ceremony::affirm_persisted(runtime,tx)?;
        tx.execute("INSERT INTO administration_ceremony_intent(intent_hash,organization_id,chain_id,trust_anchor_hash,admin_certificate_hash,admin_binding_hash,registry_version,registry_head_hash,proposed_sequence,target_payload,source_kind,source_bytes,ceremony_round,parent_intent_hash,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,NULL,0,NULL,?11) ON CONFLICT(intent_hash) DO NOTHING",&[
            blob(id.as_bytes()),blob(runtime.anchor().organization_id().as_bytes()),
            blob(runtime.head().chain_id().as_bytes()),blob(runtime.anchor().trust_anchor_hash().as_bytes()),
            blob(runtime.config().device_certificate_hash.as_bytes()),blob(runtime.config().binding_object_hash.as_bytes()),
            integer(runtime.head().registry_version().get())?,blob(runtime.head().registry_head_hash().as_bytes()),
            integer(runtime.next_sequence().get())?,blob(exact),
            StoreValue::Integer(runtime.head().preexisting_effective_now().value().get()),
        ])?;
        Ok::<(),OperatorRuntimeError>(())
    })?;
    runtime.ensure_same_action_authority()?;
    ceremony::load(runtime, id)
}
pub(super) fn load(
    runtime: &OperatorRuntime,
    id: ObjectHash,
    row: &StoreRow,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    if row.integer(9)? != 0
        || row.integer(10)? != 0
        || row.integer(11)? != 1
        || object_hash(row.blob(8)?) != id
    {
        return Err(error());
    }
    let exact = row.blob(8)?;
    let kind = validate(runtime, exact)?;
    if runtime
        .database()
        .query_row(
            "SELECT stage FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=0",
            &[blob(id.as_bytes())],
        )?
        .is_some()
    {
        return Err(error());
    }
    let authorized = super::authorization::restore(runtime, id, exact)?;
    let transport = authorized
        .as_deref()
        .map(|target| super::exchange::restore(runtime, id, target))
        .transpose()?
        .flatten();
    Ok(AdministrationCeremony {
        id,
        kind,
        round: TrustCeremonyRoundV1::IssueTarget,
        step: if let Some((step, _)) = &transport {
            *step
        } else if authorized.is_some() {
            TrustCeremonyStep::AdminAuthorized
        } else {
            TrustCeremonyStep::PendingRequest
        },
        target_payload: authorized.unwrap_or_else(|| exact.to_vec()),
        exchange_file_name: transport.map(|(_, name)| name),
        linked: None,
        fingerprint: None,
    })
}

/// Independently verifies the actual public chain instead of accepting caller
/// progress or deriving it from the Registry lease.
fn actual_tip(
    runtime: &OperatorRuntime,
) -> Result<crate::writer_transition::TrustedChainHead, OperatorRuntimeError> {
    let source = ea_recovery::FsArchiveSource::open_committed(&runtime.config().archive_directory)?;
    let report = ea_verify::verify_archive(
        &source,
        runtime.anchor(),
        ea_verify::VerifyOptions::new(runtime.head().preexisting_effective_now().value()),
    )
    .map_err(|_| error())?;
    let tip = report.verified_public_chain_head().ok_or_else(error)?;
    if tip.sequence().get().checked_add(1) != Some(runtime.next_sequence().get()) {
        return Err(error());
    }
    Ok(crate::writer_transition::TrustedChainHead {
        chain_sequence: tip.sequence(),
        entry_hash: tip.entry_hash(),
    })
}
pub(super) fn validate_transition(
    runtime: &OperatorRuntime,
    fields: &ea_format::WriterTransitionFieldsV1,
) -> Result<(), OperatorRuntimeError> {
    let tip = actual_tip(runtime)?;
    if fields.organization_id != runtime.anchor().organization_id()
        || fields.chain_id != runtime.head().chain_id()
        || fields.effective_from_sequence != runtime.next_sequence()
        || fields.previous_entry_hash != tip.entry_hash
    {
        return Err(error());
    }
    let prepared = crate::writer_transition::WriterTransitionService::new(runtime.head())
        .prepare(
            &crate::writer_transition::WriterTransitionRequest {
                old_writer_certificate_hash: fields.old_writer_certificate_hash,
                new_writer_certificate_hash: fields.new_writer_certificate_hash,
                trusted_head: tip,
                reason_code: fields.reason_code,
            },
            ObjectHash::from(Hash32::ZERO),
        )
        .map_err(|_| error())?;
    if prepared.fields() != fields {
        return Err(error());
    }
    Ok(())
}
pub(super) fn begin_transition(
    runtime: &mut OperatorRuntime,
    request_json: &[u8],
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    current_view(runtime)?;
    let input = crate::writer_transition::WriterTransitionRequest::from_json(request_json)
        .map_err(|_| error())?;
    let actual = actual_tip(runtime)?;
    if input.admin_authorization_object_hash.is_some()
        || input.request.trusted_head.chain_sequence != actual.chain_sequence
        || input.request.trusted_head.entry_hash != actual.entry_hash
    {
        return Err(error());
    }
    let prepared = crate::writer_transition::WriterTransitionService::new(runtime.head())
        .prepare(&input.request, ObjectHash::from(Hash32::ZERO))
        .map_err(|_| error())?;
    begin(runtime, prepared.payload().exact_digest_input())
}
