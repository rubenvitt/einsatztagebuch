//! Exact request/certificate-intent binding and durable human fingerprint comparison.
use super::{
    FingerprintSubjectV1, TrustCeremonyRoundV1,
    ceremony::{self, AdministrationCeremony, affirm_persisted},
    inbox,
    views::current_view,
};
use crate::{
    OperatorLifecycleError, TrustCeremonyKind, TrustCeremonyStep,
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
};
use ea_crypto::object_hash;
use ea_format::{CertificateKindV1, DecodedTrustPayloadV1, KeyProtectionProfileV1, TrustPayloadV1};
use ea_local_store::{StoreRow, StoreValue};
use ea_types::{Hash32, ObjectHash};
fn failure() -> OperatorRuntimeError {
    OperatorLifecycleError::JournalConflict.into()
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
fn integer(value: u64) -> Result<StoreValue, OperatorRuntimeError> {
    Ok(StoreValue::Integer(
        i64::try_from(value).map_err(|_| failure())?,
    ))
}
pub(super) fn validate(
    runtime: &OperatorRuntime,
    request: &[u8],
    target: &[u8],
) -> Result<inbox::VerifiedRegistrationRequest, OperatorRuntimeError> {
    let verified = verify_material(runtime.anchor().organization_id(), request, target)?;
    let payload = TrustPayloadV1::from_exact_digest_input(target).map_err(|_| failure())?;
    let DecodedTrustPayloadV1::AuthorizedDevice(core) =
        payload.decoded_payload().map_err(|_| failure())?
    else {
        return Err(failure());
    };
    if core.fields().effective_from_sequence != runtime.next_sequence()
        || runtime
            .head()
            .active_certificates()
            .any(|(_, c)| c.signing_key_thumbprint == core.fields().signing_key_thumbprint)
    {
        return Err(failure());
    }
    ea_trust::describe_intended_trust_target(
        runtime.trust(),
        Some(runtime.head()),
        &payload,
        runtime.next_sequence(),
    )?;
    Ok(verified)
}
pub(super) fn verify_material(
    organization: ea_types::OrganizationId,
    request: &[u8],
    target: &[u8],
) -> Result<inbox::VerifiedRegistrationRequest, OperatorRuntimeError> {
    let request = inbox::verify_registration(request, organization)?;
    let payload = TrustPayloadV1::from_exact_digest_input(target).map_err(|_| failure())?;
    let DecodedTrustPayloadV1::AuthorizedDevice(core) =
        payload.decoded_payload().map_err(|_| failure())?
    else {
        return Err(failure());
    };
    let fields = core.fields();
    let requested = request.core();
    let kind = if requested.requested_role == 0 {
        CertificateKindV1::Writer
    } else {
        CertificateKindV1::Reader
    };
    let capabilities = if kind == CertificateKindV1::Writer {
        vec!["initialGrant".to_owned()]
    } else {
        vec![]
    };
    if core.authorization_object_hash() != ObjectHash::from(Hash32::ZERO)
        || fields.organization_id != requested.organization_id
        || fields.device_id != requested.device_id
        || fields.certificate_kind != kind
        || fields.authority_subject_id.is_some()
        || fields.signing_public_cose_key.as_deref()
            != Some(
                requested
                    .signing_public_cose_key
                    .to_deterministic_cbor()
                    .as_slice(),
            )
        || fields.signing_key_thumbprint != Some(requested.signing_public_cose_key.thumbprint())
        || fields.kem_public_cose_key
            != requested
                .kem_public_cose_key
                .as_ref()
                .map(|key| key.to_deterministic_cbor())
        || fields.kem_key_thumbprint
            != requested
                .kem_public_cose_key
                .as_ref()
                .map(|key| key.thumbprint())
        || fields.capabilities != capabilities
        || fields.revoked_from_sequence.is_some()
        || !requested.supported_format_versions.contains(&1)
        || !requested
            .supported_suite_ids
            .iter()
            .any(|suite| suite == ea_crypto::SUITE_ID)
    {
        return Err(failure());
    }
    // Enrollment proves key possession only. Stronger provider profiles cannot
    // be selected through this portable intake; no hardware claim is inferred.
    if fields.key_protection_profile != KeyProtectionProfileV1::OsWrapped {
        return Err(OperatorRuntimeError::Config);
    }
    Ok(request)
}
pub(super) fn begin(
    runtime: &mut OperatorRuntime,
    request: &[u8],
    target: &[u8],
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    current_view(runtime)?;
    validate(runtime, request, target)?;
    let id = object_hash(target);
    runtime.ensure_same_action_authority()?;
    runtime.database().transaction(|tx| {
        affirm_persisted(runtime, tx)?;
        insert_in(runtime, tx, request, target)?;
        Ok::<(), OperatorRuntimeError>(())
    })?;
    runtime.ensure_same_action_authority()?;
    ceremony::load(runtime, id)
}
pub(super) fn insert_in(
    runtime: &OperatorRuntime,
    tx: &ea_local_store::StoreTransaction,
    request: &[u8],
    target: &[u8],
) -> Result<(), OperatorRuntimeError> {
    let id = object_hash(target);
    tx.execute("INSERT INTO administration_ceremony_intent(intent_hash,organization_id,chain_id,trust_anchor_hash,admin_certificate_hash,admin_binding_hash,registry_version,registry_head_hash,proposed_sequence,target_payload,source_kind,source_bytes,ceremony_round,parent_intent_hash,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,0,NULL,?12) ON CONFLICT(intent_hash) DO NOTHING",&[
            blob(id.as_bytes()),blob(runtime.anchor().organization_id().as_bytes()),
            blob(runtime.head().chain_id().as_bytes()),blob(runtime.anchor().trust_anchor_hash().as_bytes()),
            blob(runtime.config().device_certificate_hash.as_bytes()),blob(runtime.config().binding_object_hash.as_bytes()),
            integer(runtime.head().registry_version().get())?,blob(runtime.head().registry_head_hash().as_bytes()),
            integer(runtime.next_sequence().get())?,blob(target),blob(request),
            StoreValue::Integer(runtime.head().preexisting_effective_now().value().get()),
        ])?;
    let actual=tx.query_row("SELECT source_bytes,target_payload FROM administration_ceremony_intent WHERE intent_hash=?1",&[blob(id.as_bytes())])?.ok_or_else(failure)?;
    if actual.blob(0)? != request || actual.blob(1)? != target {
        return Err(failure());
    }
    Ok(())
}
fn confirmation(id: ObjectHash, request: ObjectHash) -> Result<Vec<u8>, OperatorRuntimeError> {
    let mut encoded = minicbor::Encoder::new(Vec::new());
    encoded
        .array(2)
        .and_then(|e| e.bytes(id.as_bytes()))
        .and_then(|e| e.bytes(request.as_bytes()))
        .map_err(|_| failure())?;
    Ok(encoded.into_writer())
}
pub(super) fn confirmed(
    runtime: &OperatorRuntime,
    id: ObjectHash,
    request: ObjectHash,
) -> Result<bool, OperatorRuntimeError> {
    let row=runtime.database().query_row("SELECT exact_record,audit_event_id IS NULL FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=0",&[blob(id.as_bytes())])?;
    let Some(row) = row else { return Ok(false) };
    if row.blob(0)? != confirmation(id, request)? || row.integer(1)? != 1 {
        return Err(failure());
    }
    Ok(true)
}
pub(super) fn confirm(
    runtime: &mut OperatorRuntime,
    id: ObjectHash,
    reported: ObjectHash,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    let pending = ceremony::load(runtime, id)?;
    if pending.fingerprint_subject().is_none() || pending.target_fingerprint() != Some(reported) {
        return Err(OperatorLifecycleError::TargetMismatch.into());
    }
    if pending.step() == TrustCeremonyStep::FingerprintConfirmed {
        return Ok(pending);
    }
    if pending.step() != TrustCeremonyStep::PendingRequest {
        return Err(failure());
    }
    let record = confirmation(id, reported)?;
    runtime.ensure_same_action_authority()?;
    runtime.database().transaction(|tx|{
        affirm_persisted(runtime,tx)?;
        tx.execute("INSERT INTO administration_ceremony_record(intent_hash,stage,exact_record,audit_event_id) VALUES(?1,0,?2,NULL)",&[blob(id.as_bytes()),blob(&record)])?;
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
    if row.integer(9)? != 1
        || row.integer(10)? != 0
        || row.integer(11)? != 1
        || object_hash(row.blob(8)?) != id
    {
        return Err(failure());
    }
    let request = validate(runtime, row.blob(12)?, row.blob(8)?)?;
    let confirmed = confirmed(runtime, id, request.request_hash())?;
    let authorized = super::authorization::restore(runtime, id, row.blob(8)?)?;
    if authorized.is_some() && !confirmed {
        return Err(failure());
    }
    let transport = authorized
        .as_deref()
        .map(|target| super::exchange::restore(runtime, id, target))
        .transpose()?
        .flatten();
    Ok(AdministrationCeremony {
        id,
        kind: TrustCeremonyKind::DeviceApprove,
        round: TrustCeremonyRoundV1::IssueTarget,
        step: if let Some((step, _)) = &transport {
            *step
        } else if authorized.is_some() {
            TrustCeremonyStep::AdminAuthorized
        } else if confirmed {
            TrustCeremonyStep::FingerprintConfirmed
        } else {
            TrustCeremonyStep::PendingRequest
        },
        target_payload: authorized
            .unwrap_or_else(|| row.blob(8).expect("validated target").to_vec()),
        exchange_file_name: transport.map(|(_, name)| name),
        linked: None,
        fingerprint: Some((
            FingerprintSubjectV1::RegistrationRequest,
            request.request_hash(),
        )),
    })
}
