//! Durable administration intents; unsigned journal metadata never authorizes publication.
use super::{FingerprintSubjectV1, TrustCeremonyRoundV1, views::current_view};
use crate::{
    OperatorLifecycleError, RegistryWindow, TrustCeremonyKind, TrustCeremonyStep,
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
    registry::RegistryEventFactory,
    revocation::plan_revocation,
};
use ea_crypto::object_hash;
use ea_format::{DecodedTrustPayloadV1, RegistryChangeV1, TrustPayloadV1};
use ea_local_store::{StoreRow, StoreValue};
use ea_types::{Hash32, ObjectHash};

pub struct AdministrationCeremony {
    pub(crate) id: ObjectHash,
    pub(crate) kind: TrustCeremonyKind,
    pub(crate) round: TrustCeremonyRoundV1,
    pub(crate) step: TrustCeremonyStep,
    pub(crate) target_payload: Vec<u8>,
    pub(crate) exchange_file_name: Option<String>,
    pub(crate) linked: Option<ObjectHash>,
    pub(crate) fingerprint: Option<(FingerprintSubjectV1, ObjectHash)>,
}
impl AdministrationCeremony {
    pub fn id(&self) -> ObjectHash {
        self.id
    }
    pub fn kind(&self) -> TrustCeremonyKind {
        self.kind
    }
    pub fn round(&self) -> TrustCeremonyRoundV1 {
        self.round
    }
    pub fn step(&self) -> TrustCeremonyStep {
        self.step
    }
    pub fn linked_ceremony_id(&self) -> Option<ObjectHash> {
        self.linked
    }
    pub fn fingerprint_subject(&self) -> Option<FingerprintSubjectV1> {
        self.fingerprint.map(|(subject, _)| subject)
    }
    pub fn target_fingerprint(&self) -> Option<ObjectHash> {
        self.fingerprint.map(|(_, hash)| hash)
    }
    pub fn exact_target_payload(&self) -> &[u8] {
        &self.target_payload
    }
    pub fn exchange_file_name(&self) -> Option<&str> {
        self.exchange_file_name.as_deref()
    }
}
fn conflict() -> OperatorRuntimeError {
    OperatorLifecycleError::JournalConflict.into()
}
fn format_error(_: ea_format::FormatError) -> OperatorRuntimeError {
    conflict()
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
fn integer(value: u64) -> Result<StoreValue, OperatorRuntimeError> {
    Ok(StoreValue::Integer(
        i64::try_from(value).map_err(|_| conflict())?,
    ))
}
fn planned_revoke(
    runtime: &OperatorRuntime,
    target: ObjectHash,
) -> Result<ea_format::RegistryEventFieldsV1, OperatorRuntimeError> {
    let audit = runtime.audit_service();
    let factory = RegistryEventFactory::new(runtime.head(), &audit, runtime.local_device());
    let (event, _) = plan_revocation(
        &factory,
        RegistryWindow {
            effective_from_sequence: runtime.next_sequence(),
            valid_through_sequence: runtime.head().valid_through_sequence(),
            not_after: runtime.head().not_after(),
        },
        target,
    )
    .map_err(|_| OperatorRuntimeError::Config)?;
    Ok(event)
}
pub fn begin_registration(
    runtime: &mut OperatorRuntime,
    exact_request: &[u8],
    exact_target: &[u8],
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    super::registration::begin(runtime, exact_request, exact_target)
}
pub fn confirm_registration_fingerprint(
    runtime: &mut OperatorRuntime,
    id: ObjectHash,
    reported: ObjectHash,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    super::registration::confirm(runtime, id, reported)
}
pub fn begin_policy(
    runtime: &mut OperatorRuntime,
    exact_target: &[u8],
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    let target =
        super::target::UntrustedAdministrationTarget::parse(exact_target).map_err(format_error)?;
    if target.kind() != TrustCeremonyKind::PolicyChange {
        return Err(conflict());
    }
    super::direct_intent::begin(runtime, exact_target)
}
pub fn begin_writer_transition(
    runtime: &mut OperatorRuntime,
    request_json: &[u8],
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    super::direct_intent::begin_transition(runtime, request_json)
}
pub fn begin_revoke(
    runtime: &mut OperatorRuntime,
    target: ObjectHash,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    current_view(runtime)?;
    let event = planned_revoke(runtime, target)?;
    let payload = TrustPayloadV1::registry_event(event, ObjectHash::from(Hash32::ZERO))
        .map_err(format_error)?;
    let id = object_hash(payload.exact_digest_input());
    runtime.ensure_same_action_authority()?;
    runtime.database().transaction(|tx| {
        affirm_persisted(runtime,tx)?;
        tx.execute("INSERT INTO administration_ceremony_intent(intent_hash,organization_id,chain_id,trust_anchor_hash,admin_certificate_hash,admin_binding_hash,registry_version,registry_head_hash,proposed_sequence,target_payload,source_kind,source_bytes,ceremony_round,parent_intent_hash,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,NULL,1,NULL,?11) ON CONFLICT(intent_hash) DO NOTHING",&[
            blob(id.as_bytes()),blob(runtime.anchor().organization_id().as_bytes()),
            blob(runtime.head().chain_id().as_bytes()),blob(runtime.anchor().trust_anchor_hash().as_bytes()),
            blob(runtime.config().device_certificate_hash.as_bytes()),blob(runtime.config().binding_object_hash.as_bytes()),
            integer(runtime.head().registry_version().get())?,blob(runtime.head().registry_head_hash().as_bytes()),
            integer(runtime.next_sequence().get())?,blob(payload.exact_digest_input()),
            StoreValue::Integer(runtime.head().preexisting_effective_now().value().get()),
        ])?;
        Ok::<(),OperatorRuntimeError>(())
    })?;
    runtime.ensure_same_action_authority()?;
    load(runtime, id)
}
pub fn load(
    runtime: &mut OperatorRuntime,
    id: ObjectHash,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    current_view(runtime)?;
    load_admitted(runtime, id)
}
pub(super) fn load_admitted(
    runtime: &OperatorRuntime,
    id: ObjectHash,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    let mut ceremony = load_inner(runtime, id)?;
    // A navigation link is local workflow metadata, not another action proof.
    // Opening that linked ceremony independently verifies all of its bindings.
    ceremony.linked = super::activation::link(runtime, id)?;
    Ok(ceremony)
}
fn load_inner(
    runtime: &OperatorRuntime,
    id: ObjectHash,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    let row=runtime.database().query_row("SELECT organization_id,chain_id,trust_anchor_hash,admin_certificate_hash,admin_binding_hash,registry_version,registry_head_hash,proposed_sequence,target_payload,source_kind,ceremony_round,parent_intent_hash IS NULL,source_bytes,parent_intent_hash FROM administration_ceremony_intent WHERE intent_hash=?1",&[blob(id.as_bytes())])?.ok_or_else(conflict)?;
    if let Some(published) = super::publication::restore(runtime, id, &row)? {
        return Ok(published);
    }
    validate_scope(runtime, &row)?;
    if row.integer(9)? == 1 {
        return super::registration::load(runtime, id, &row);
    }
    if row.integer(9)? == 2 {
        return super::activation::load(runtime, id, &row);
    }
    if row.integer(9)? == 0 && row.integer(10)? == 0 {
        return super::direct_intent::load(runtime, id, &row);
    }
    if runtime
        .database()
        .query_row(
            "SELECT stage FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=0",
            &[blob(id.as_bytes())],
        )?
        .is_some()
    {
        return Err(conflict());
    }
    let exact = row.blob(8)?;
    if object_hash(exact) != id
        || row.integer(9)? != 0
        || row.integer(10)? != 1
        || row.integer(11)? != 1
    {
        return Err(conflict());
    }
    let payload = TrustPayloadV1::from_exact_digest_input(exact).map_err(format_error)?;
    let DecodedTrustPayloadV1::RegistryEvent(core) =
        payload.decoded_payload().map_err(format_error)?
    else {
        return Err(conflict());
    };
    if core.authorization_object_hash() != ObjectHash::from(Hash32::ZERO) {
        return Err(conflict());
    }
    let RegistryChangeV1::Target {
        object_hash: target,
        ..
    } = core.fields().change
    else {
        return Err(conflict());
    };
    let mut expected = planned_revoke(runtime, target)?;
    // A resumed intent preserves its original exact timestamps. The fresh
    // factory still validates all present context/window/target constraints.
    if core.fields().issued_at > expected.issued_at
        || core.fields().not_before != core.fields().issued_at
    {
        return Err(conflict());
    }
    expected.issued_at = core.fields().issued_at;
    expected.not_before = core.fields().not_before;
    if *core.fields() != expected {
        return Err(conflict());
    }
    let authorized = super::authorization::restore(runtime, id, exact)?;
    let transport = authorized
        .as_deref()
        .map(|target| super::exchange::restore(runtime, id, target))
        .transpose()?
        .flatten();
    Ok(AdministrationCeremony {
        id,
        kind: TrustCeremonyKind::DeviceRevoke,
        round: TrustCeremonyRoundV1::ActivateRegistry,
        step: if let Some((step, _)) = &transport {
            *step
        } else if authorized.is_some() {
            TrustCeremonyStep::AdminAuthorized
        } else {
            TrustCeremonyStep::PendingRequest
        },
        target_payload: authorized.unwrap_or_else(|| exact.to_vec()),
        exchange_file_name: transport.map(|(_, name)| name),
        fingerprint: None,
        linked: None,
    })
}
fn validate_scope(runtime: &OperatorRuntime, row: &StoreRow) -> Result<(), OperatorRuntimeError> {
    if row.blob(0)? != runtime.anchor().organization_id().as_bytes()
        || row.blob(1)? != runtime.head().chain_id().as_bytes()
        || row.blob(2)? != runtime.anchor().trust_anchor_hash().as_bytes()
        || row.blob(3)? != runtime.config().device_certificate_hash.as_bytes()
        || row.blob(4)? != runtime.config().binding_object_hash.as_bytes()
        || row.integer(5)?
            != i64::try_from(runtime.head().registry_version().get()).map_err(|_| conflict())?
        || row.blob(6)? != runtime.head().registry_head_hash().as_bytes()
        || row.integer(7)?
            != i64::try_from(runtime.next_sequence().get()).map_err(|_| conflict())?
    {
        return Err(conflict());
    }
    Ok(())
}
pub(crate) fn affirm_persisted(
    runtime: &OperatorRuntime,
    tx: &ea_local_store::StoreTransaction<'_>,
) -> Result<(), OperatorRuntimeError> {
    let key = runtime.trust().state_key();
    let row=tx.query_row("SELECT chain_id,trust_anchor_hash,pin_hash,floor_ms,independent_time_ms,independent_time_ms IS NULL FROM operator_trust_state WHERE organization_id=?1 AND device_id=?2",&[blob(key.organization_id.as_bytes()),blob(key.device_id.as_bytes())])?.ok_or_else(conflict)?;
    let ceiling = if row.integer(5)? != 0 {
        None
    } else {
        let maximum = i128::from(row.integer(4)?)
            + i128::from(runtime.head().policy_fields().max_future_clock_skew_ms);
        Some(ea_types::UnixMillis::new(
            i64::try_from(maximum).unwrap_or(i64::MAX),
        ))
    };
    if row.blob(0)? != runtime.head().chain_id().as_bytes()
        || row.blob(1)? != runtime.anchor().trust_anchor_hash().as_bytes()
        || row.blob(2)? != runtime.head().registry_head_hash().as_bytes()
        || ceiling
            != runtime
                .head()
                .preexisting_effective_now()
                .wall_clock_ceiling()
        || row.integer(3)?
            != runtime
                .head()
                .preexisting_effective_now()
                .persisted_floor()
                .get()
    {
        return Err(conflict());
    }
    Ok(())
}

/// Reconstructs all unfinished rounds from the actual durable journal.
/// Reading never renews an authorization or invents a replacement attempt.
pub fn open_ceremonies(
    runtime: &mut OperatorRuntime,
) -> Result<Vec<AdministrationCeremony>, OperatorRuntimeError> {
    let conflict = || OperatorRuntimeError::from(crate::OperatorLifecycleError::JournalConflict);
    current_view(runtime)?;
    // Capture a bounded identity set under one database snapshot. An insertion
    // before an OFFSET cannot hide a previously captured row.
    let ids=runtime.database().transaction(|tx| {
        let count=tx.query_row("SELECT COUNT(*) FROM administration_ceremony_intent",&[])?
            .ok_or_else(conflict)?.integer(0)?;
        if !(0..=4096).contains(&count) { return Err(conflict()); }
        let mut ids=Vec::new();
        for offset in 0..count {
            let row=tx.query_row("SELECT intent_hash FROM administration_ceremony_intent ORDER BY intent_hash LIMIT 1 OFFSET ?1",
                &[ea_local_store::StoreValue::Integer(offset)])?.ok_or_else(conflict)?;
            ids.push(ObjectHash::try_from(row.blob(0)?).map_err(|_| conflict())?);
        }
        Ok::<_,OperatorRuntimeError>(ids)
    })?;
    let rounds = ids
        .into_iter()
        .map(|id| load_admitted(runtime, id))
        .collect::<Result<Vec<_>, _>>()?;
    for round in &rounds {
        match (round.round(), round.step(), round.linked_ceremony_id()) {
            (
                TrustCeremonyRoundV1::IssueTarget,
                TrustCeremonyStep::TargetPublished,
                Some(child),
            ) => {
                let child = rounds
                    .iter()
                    .find(|value| value.id() == child)
                    .ok_or_else(conflict)?;
                if child.round() != TrustCeremonyRoundV1::ActivateRegistry
                    || child.kind() != round.kind()
                    || child.linked_ceremony_id() != Some(round.id())
                {
                    return Err(conflict());
                }
            }
            (TrustCeremonyRoundV1::IssueTarget, TrustCeremonyStep::TargetPublished, None)
            | (TrustCeremonyRoundV1::IssueTarget, _, Some(_)) => return Err(conflict()),
            (TrustCeremonyRoundV1::ActivateRegistry, _, Some(parent)) => {
                let parent = rounds
                    .iter()
                    .find(|value| value.id() == parent)
                    .ok_or_else(conflict)?;
                if parent.round() != TrustCeremonyRoundV1::IssueTarget
                    || parent.step() != TrustCeremonyStep::TargetPublished
                    || parent.kind() != round.kind()
                    || parent.linked_ceremony_id() != Some(round.id())
                {
                    return Err(conflict());
                }
            }
            (TrustCeremonyRoundV1::ActivateRegistry, _, None)
                if round.kind() != TrustCeremonyKind::DeviceRevoke =>
            {
                return Err(conflict());
            }
            _ => {}
        }
    }
    runtime.ensure_same_action_authority()?;
    Ok(rounds
        .into_iter()
        .filter(|round| {
            !matches!(
                round.step(),
                TrustCeremonyStep::TargetPublished | TrustCeremonyStep::RegistryPublished
            )
        })
        .collect())
}
