//! Durable exact offline request and Root reply transport.
use super::ceremony::{self, AdministrationCeremony, affirm_persisted};
use crate::{
    OperatorLifecycleError, TrustCeremonyStep,
    operator_exchange::{
        NativeExchangeSigner, PendingExchange, read_exchange_file, write_exchange_file,
    },
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
};
use ea_crypto::{CanonicalPublicCoseKey, VerificationContext};
use ea_format::{OperatorRoleV1, ParsedArchiveObject, TrustPayloadV1};
use ea_local_store::StoreValue;
use ea_trust::TrustObjectSource;
use ea_types::{CertificateHash, ObjectHash};
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;
fn conflict() -> OperatorRuntimeError {
    OperatorLifecycleError::JournalConflict.into()
}
fn blob(exact: &[u8]) -> StoreValue {
    StoreValue::Blob(exact.to_vec())
}
struct Plan {
    pending: PendingExchange,
    public: CanonicalPublicCoseKey,
    directory: PathBuf,
    authorization: Vec<u8>,
}
fn plan(
    runtime: &OperatorRuntime,
    id: ObjectHash,
    target: &[u8],
) -> Result<Plan, OperatorRuntimeError> {
    let row=runtime.database().query_row("SELECT exact_record FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=1",&[blob(id.as_bytes())])?.ok_or_else(conflict)?;
    let mut d = minicbor::Decoder::new(row.blob(0)?);
    if d.array().map_err(|_| conflict())? != Some(2) {
        return Err(conflict());
    }
    let authorization = d.bytes().map_err(|_| conflict())?.to_vec();
    if d.bytes().map_err(|_| conflict())? != target || d.position() != row.blob(0)?.len() {
        return Err(conflict());
    }
    let config = runtime.config();
    let certificate = config
        .admin_certificate_hash
        .ok_or(OperatorRuntimeError::Config)?;
    let binding = config
        .admin_binding_object_hash
        .ok_or(OperatorRuntimeError::Config)?;
    if certificate == config.device_certificate_hash {
        return Err(OperatorRuntimeError::Config);
    }
    let fields = runtime
        .head()
        .active_certificate_fields(certificate)
        .ok_or_else(conflict)?;
    let operator = runtime
        .head()
        .active_operator_binding_fields(binding)
        .ok_or_else(conflict)?;
    if fields.certificate_kind != ea_format::CertificateKindV1::OrganizationAdmin
        || operator.operator_role != OperatorRoleV1::OrganizationAdmin
        || operator.device_certificate_hash != certificate
    {
        return Err(conflict());
    }
    let public = CanonicalPublicCoseKey::from_deterministic_cbor(
        fields
            .signing_public_cose_key
            .as_deref()
            .ok_or_else(conflict)?,
    )
    .map_err(|_| conflict())?;
    let source = runtime
        .head()
        .active_certificate_fields(config.device_certificate_hash)
        .ok_or_else(conflict)?;
    let source_public = CanonicalPublicCoseKey::from_deterministic_cbor(
        source
            .signing_public_cose_key
            .as_deref()
            .ok_or_else(conflict)?,
    )
    .map_err(|_| conflict())?;
    let payload = json!({
        "context":{"organization_id":hex::encode(runtime.anchor().organization_id().as_bytes()),"chain_id":hex::encode(runtime.head().chain_id().as_bytes()),
        "registry_head_hash":hex::encode(runtime.head().registry_head_hash().as_bytes()),"registry_version":runtime.head().registry_version().get(),
        "sequence":runtime.next_sequence().get(),"device_certificate_hash":hex::encode(config.device_certificate_hash.as_bytes()),
        "admin_certificate_hash":hex::encode(certificate.as_bytes()),"admin_binding_object_hash":hex::encode(binding.as_bytes())},
        "op":"admin-trust-target","args":{"target_payload":hex::encode(target),"authorization":hex::encode(&authorization),"relevant_objects":relevant_objects(runtime,target)?}
    });
    let pending = PendingExchange::load_or_create(
        runtime.database(),
        payload,
        &NativeExchangeSigner::administrator(runtime.native()),
        &source_public,
    )?;
    runtime.ensure_same_action_authority()?;
    Ok(Plan {
        pending,
        public,
        directory: config
            .ceremony_exchange_directory
            .clone()
            .ok_or(OperatorRuntimeError::Config)?,
        authorization,
    })
}
fn row(
    runtime: &OperatorRuntime,
    id: ObjectHash,
    stage: i64,
) -> Result<Option<Vec<u8>>, OperatorRuntimeError> {
    let Some(row)=runtime.database().query_row("SELECT exact_record,audit_event_id IS NULL FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=?2",&[blob(id.as_bytes()),StoreValue::Integer(stage)])?else{return Ok(None)};
    if row.integer(1)? != 1 {
        return Err(conflict());
    }
    Ok(Some(row.blob(0)?.to_vec()))
}
fn insert(
    runtime: &OperatorRuntime,
    id: ObjectHash,
    stage: i64,
    exact: &[u8],
) -> Result<(), OperatorRuntimeError> {
    runtime.ensure_same_action_authority()?;
    runtime.database().transaction(|tx|{
        affirm_persisted(runtime,tx)?;
        tx.execute("INSERT INTO administration_ceremony_record(intent_hash,stage,exact_record,audit_event_id) VALUES(?1,?2,?3,NULL) ON CONFLICT(intent_hash,stage) DO NOTHING",&[blob(id.as_bytes()),StoreValue::Integer(stage),blob(exact)])?;
        let record=tx.query_row("SELECT exact_record FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=?2",&[blob(id.as_bytes()),StoreValue::Integer(stage)])?.ok_or_else(conflict)?;
        if record.blob(0)?!=exact{return Err(conflict())}
        Ok::<(),OperatorRuntimeError>(())
    })?;
    runtime.ensure_same_action_authority()
}
pub fn export_request(
    runtime: &mut OperatorRuntime,
    id: ObjectHash,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    let ceremony = ceremony::load(runtime, id)?;
    if !matches!(
        ceremony.step(),
        TrustCeremonyStep::AdminAuthorized | TrustCeremonyStep::RootRequestExported
    ) {
        return Err(conflict());
    }
    let plan = plan(runtime, id, ceremony.exact_target_payload())?;
    // PendingExchange has already persisted exact request and wrapped key.
    // Only a completed, flushed file publication advances the visible step.
    write_exchange_file(
        &plan
            .directory
            .join(format!("request-{}.json", plan.pending.request_id())),
        plan.pending.request_bytes(),
    )?;
    runtime.ensure_same_action_authority()?;
    insert(runtime, id, 2, plan.pending.request_bytes())?;
    ceremony::load(runtime, id)
}
pub fn import_reply(
    runtime: &mut OperatorRuntime,
    id: ObjectHash,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    let ceremony = ceremony::load(runtime, id)?;
    if !matches!(
        ceremony.step(),
        TrustCeremonyStep::RootRequestExported | TrustCeremonyStep::RootReplyImported
    ) {
        return Err(conflict());
    }
    let plan = plan(runtime, id, ceremony.exact_target_payload())?;
    let reply = read_exchange_file(
        &plan
            .directory
            .join(format!("reply-{}.json", plan.pending.request_id())),
    )?;
    verify_reply(runtime, &plan, &reply, ceremony.exact_target_payload())?;
    runtime.ensure_same_action_authority()?;
    insert(runtime, id, 3, &reply)?;
    ceremony::load(runtime, id)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    target: String,
}
fn verify_reply(
    runtime: &OperatorRuntime,
    plan: &Plan,
    exact: &[u8],
    target: &[u8],
) -> Result<Vec<u8>, OperatorRuntimeError> {
    let reply: Reply = serde_json::from_value(plan.pending.open_reply(exact, &plan.public)?)
        .map_err(|_| conflict())?;
    if reply.target.len() > 98_304 {
        return Err(conflict());
    }
    let bytes = hex::decode(reply.target).map_err(|_| conflict())?;
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&bytes).map_err(|_| conflict())?
    else {
        return Err(conflict());
    };
    if parsed.value().exact_digest_input() != target {
        return Err(conflict());
    }
    let payload = TrustPayloadV1::from_exact_digest_input(target).map_err(|_| conflict())?;
    let context = VerificationContext::root_trust_digest(
        payload.exact_digest_input(),
        CertificateHash::from(runtime.head().root_certificate_object_hash()),
        Some(&plan.authorization),
    )
    .map_err(|_| conflict())?;
    if parsed.value().signatures().is_empty() {
        return Err(conflict());
    }
    for signature in parsed.value().signatures() {
        ea_crypto::verify_cose_sign1(signature, runtime.head(), &context)
            .map_err(|_| conflict())?;
    }
    Ok(bytes)
}
pub(crate) fn restore(
    runtime: &OperatorRuntime,
    id: ObjectHash,
    target: &[u8],
) -> Result<Option<(TrustCeremonyStep, String)>, OperatorRuntimeError> {
    let exported = row(runtime, id, 2)?;
    let imported = row(runtime, id, 3)?;
    let Some(exact) = exported else {
        if imported.is_some() {
            return Err(conflict());
        }
        return Ok(None);
    };
    if runtime
        .database()
        .query_row(
            "SELECT request_bytes FROM operator_pending_exchange WHERE request_bytes=?1",
            &[blob(&exact)],
        )?
        .is_none()
    {
        return Err(conflict());
    }
    let plan = plan(runtime, id, target)?;
    if plan.pending.request_bytes() != exact {
        return Err(conflict());
    }
    let (step, name) = if let Some(reply) = imported {
        verify_reply(runtime, &plan, &reply, target)?;
        (
            TrustCeremonyStep::RootReplyImported,
            format!("reply-{}.json", plan.pending.request_id()),
        )
    } else {
        (
            TrustCeremonyStep::RootRequestExported,
            format!("request-{}.json", plan.pending.request_id()),
        )
    };
    Ok(Some((step, name)))
}

pub(crate) fn imported_objects(
    runtime: &OperatorRuntime,
    id: ObjectHash,
    target: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), OperatorRuntimeError> {
    let plan = plan(runtime, id, target)?;
    let reply = row(runtime, id, 3)?.ok_or_else(conflict)?;
    let exact = verify_reply(runtime, &plan, &reply, target)?;
    Ok((plan.authorization, exact))
}

/// Only a Registry round's exact direct target and its exact authorization.
/// No unrelated catalog object or authority family crosses this input.
fn relevant_objects(
    runtime: &OperatorRuntime,
    target: &[u8],
) -> Result<Vec<String>, OperatorRuntimeError> {
    let payload = TrustPayloadV1::from_exact_digest_input(target).map_err(|_| conflict())?;
    let ea_format::DecodedTrustPayloadV1::RegistryEvent(core) =
        payload.decoded_payload().map_err(|_| conflict())?
    else {
        return Ok(vec![]);
    };
    let hash = match core.fields().change {
        ea_format::RegistryChangeV1::Certificate { object_hash }
        | ea_format::RegistryChangeV1::Policy { object_hash }
        | ea_format::RegistryChangeV1::WriterTransition { object_hash } => object_hash,
        ea_format::RegistryChangeV1::Target { .. } => return Ok(vec![]),
        _ => return Err(conflict()),
    };
    let exact = runtime
        .inventory()
        .read_exact_trust_object(hash)
        .map_err(|_| conflict())?
        .ok_or_else(conflict)?;
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact.as_ref()).map_err(|_| conflict())?
    else {
        return Err(conflict());
    };
    let authorization = match parsed.value().decoded_payload().map_err(|_| conflict())? {
        ea_format::DecodedTrustPayloadV1::AuthorizedDevice(core) => {
            core.authorization_object_hash()
        }
        ea_format::DecodedTrustPayloadV1::Policy(core) => core.authorization_object_hash(),
        ea_format::DecodedTrustPayloadV1::WriterTransition(core) => {
            core.authorization_object_hash()
        }
        _ => return Err(conflict()),
    };
    let auth = runtime
        .inventory()
        .read_exact_trust_object(authorization)
        .map_err(|_| conflict())?
        .ok_or_else(conflict)?;
    Ok(vec![
        hex::encode(exact.as_ref()),
        hex::encode(auth.as_ref()),
    ])
}
