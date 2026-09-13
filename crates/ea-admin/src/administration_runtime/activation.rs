//! A dependent Registry intent, bound to an already exact Root-signed target.
use super::{FingerprintSubjectV1, TrustCeremonyRoundV1, ceremony::AdministrationCeremony};
use crate::{
    OperatorLifecycleError, RegistryWindow, TrustCeremonyStep,
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
    registry::{RegistryActionV1, RegistryEventFactory},
};
use ea_crypto::object_hash;
use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject, RegistryChangeV1, TrustPayloadV1};
use ea_local_store::{StoreRow, StoreTransaction, StoreValue};
use ea_types::{Hash32, ObjectHash};
fn error() -> OperatorRuntimeError {
    OperatorLifecycleError::JournalConflict.into()
}
fn blob(b: &[u8]) -> StoreValue {
    StoreValue::Blob(b.to_vec())
}
fn integer(n: u64) -> Result<StoreValue, OperatorRuntimeError> {
    Ok(StoreValue::Integer(i64::try_from(n).map_err(|_| error())?))
}
pub(super) fn plan(
    runtime: &OperatorRuntime,
    target: &[u8],
) -> Result<TrustPayloadV1, OperatorRuntimeError> {
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(target).map_err(|_| error())?
    else {
        return Err(error());
    };
    ea_trust::verify_authorized_trust_target(
        runtime.trust(),
        Some(runtime.head()),
        target,
        runtime.head().preexisting_effective_now().value(),
        runtime.next_sequence(),
    )?;
    let action = match parsed.value().decoded_payload().map_err(|_| error())? {
        DecodedTrustPayloadV1::AuthorizedDevice(core)
            if matches!(
                core.fields().certificate_kind,
                ea_format::CertificateKindV1::Writer | ea_format::CertificateKindV1::Reader
            ) =>
        {
            RegistryActionV1::DeviceApprove {
                certificate_object_hash: object_hash(target),
            }
        }
        DecodedTrustPayloadV1::Policy(_) => RegistryActionV1::PolicyChange {
            policy_object_hash: object_hash(target),
        },
        DecodedTrustPayloadV1::WriterTransition(core) => {
            super::direct_intent::validate_transition(runtime, core.fields())?;
            RegistryActionV1::WriterTransition {
                transition_object_hash: object_hash(target),
            }
        }
        _ => return Err(error()),
    };
    let audit = runtime.audit_service();
    let factory = RegistryEventFactory::new(runtime.head(), &audit, runtime.local_device());
    let fields = factory
        .plan(
            RegistryWindow {
                effective_from_sequence: runtime.next_sequence(),
                valid_through_sequence: runtime.head().valid_through_sequence(),
                not_after: runtime.head().not_after(),
            },
            &action,
        )
        .map_err(|_| error())?;
    TrustPayloadV1::registry_event(fields, ObjectHash::from(Hash32::ZERO)).map_err(|_| error())
}
pub(super) fn insert_in(
    runtime: &OperatorRuntime,
    tx: &StoreTransaction<'_>,
    parent: ObjectHash,
    payload: &TrustPayloadV1,
    target: &[u8],
) -> Result<(), OperatorRuntimeError> {
    let id = object_hash(payload.exact_digest_input());
    if tx
        .query_row(
            "SELECT intent_hash FROM administration_ceremony_intent WHERE parent_intent_hash=?1",
            &[blob(parent.as_bytes())],
        )?
        .is_some()
    {
        return Err(error());
    }
    tx.execute("INSERT INTO administration_ceremony_intent(intent_hash,organization_id,chain_id,trust_anchor_hash,admin_certificate_hash,admin_binding_hash,registry_version,registry_head_hash,proposed_sequence,target_payload,source_kind,source_bytes,ceremony_round,parent_intent_hash,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,2,?11,1,?12,?13)",&[
        blob(id.as_bytes()),blob(runtime.anchor().organization_id().as_bytes()),blob(runtime.head().chain_id().as_bytes()),blob(runtime.anchor().trust_anchor_hash().as_bytes()),
        blob(runtime.config().device_certificate_hash.as_bytes()),blob(runtime.config().binding_object_hash.as_bytes()),
        integer(runtime.head().registry_version().get())?,blob(runtime.head().registry_head_hash().as_bytes()),integer(runtime.next_sequence().get())?,
        blob(payload.exact_digest_input()),blob(target),blob(parent.as_bytes()),StoreValue::Integer(runtime.head().preexisting_effective_now().value().get()),
    ])?;
    Ok(())
}
pub(super) fn link(
    runtime: &OperatorRuntime,
    id: ObjectHash,
) -> Result<Option<ObjectHash>, OperatorRuntimeError> {
    let row=runtime.database().query_row("SELECT parent_intent_hash,parent_intent_hash IS NULL FROM administration_ceremony_intent WHERE intent_hash=?1",&[blob(id.as_bytes())])?.ok_or_else(error)?;
    if row.integer(1)? == 0 {
        return Ok(Some(
            ObjectHash::try_from(row.blob(0)?).map_err(|_| error())?,
        ));
    }
    let count = runtime
        .database()
        .query_row(
            "SELECT count(*) FROM administration_ceremony_intent WHERE parent_intent_hash=?1",
            &[blob(id.as_bytes())],
        )?
        .ok_or_else(error)?
        .integer(0)?;
    if count == 0 {
        return Ok(None);
    }
    if count != 1 {
        return Err(error());
    }
    let row = runtime
        .database()
        .query_row(
            "SELECT intent_hash FROM administration_ceremony_intent WHERE parent_intent_hash=?1",
            &[blob(id.as_bytes())],
        )?
        .ok_or_else(error)?;
    Ok(Some(
        ObjectHash::try_from(row.blob(0)?).map_err(|_| error())?,
    ))
}
pub(super) fn validate_parent(
    runtime: &OperatorRuntime,
    row: &StoreRow,
) -> Result<ObjectHash, OperatorRuntimeError> {
    if row.integer(9)? != 2 || row.integer(10)? != 1 || row.integer(11)? != 0 {
        return Err(error());
    }
    let parent = ObjectHash::try_from(row.blob(13)?).map_err(|_| error())?;
    let exact = super::publication::issued_target(runtime, parent)?;
    if exact != row.blob(12)? {
        return Err(error());
    }
    Ok(parent)
}
pub(super) fn load(
    runtime: &OperatorRuntime,
    id: ObjectHash,
    row: &StoreRow,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    validate_parent(runtime, row)?;
    let exact = row.blob(8)?;
    if object_hash(exact) != id {
        return Err(error());
    }
    let provisional = TrustPayloadV1::from_exact_digest_input(exact).map_err(|_| error())?;
    let DecodedTrustPayloadV1::RegistryEvent(core) =
        provisional.decoded_payload().map_err(|_| error())?
    else {
        return Err(error());
    };
    let expected = plan(runtime, row.blob(12)?)?;
    let DecodedTrustPayloadV1::RegistryEvent(expected) =
        expected.decoded_payload().map_err(|_| error())?
    else {
        return Err(error());
    };
    let mut expected = expected.fields().clone();
    if core.authorization_object_hash() != ObjectHash::from(Hash32::ZERO)
        || core.fields().issued_at > expected.issued_at
        || core.fields().not_before != core.fields().issued_at
    {
        return Err(error());
    }
    expected.issued_at = core.fields().issued_at;
    expected.not_before = core.fields().not_before;
    if *core.fields() != expected {
        return Err(error());
    }
    let target = super::target::UntrustedAdministrationTarget::parse(exact).map_err(|_| error())?;
    let fingerprint = if matches!(core.fields().change, RegistryChangeV1::Certificate { .. }) {
        Some((
            FingerprintSubjectV1::IssuedCertificate,
            object_hash(row.blob(12)?),
        ))
    } else {
        None
    };
    let confirmed = match fingerprint {
        Some((_, hash)) => super::registration::confirmed(runtime, id, hash)?,
        None => false,
    };
    let authorized = super::authorization::restore(runtime, id, exact)?;
    if fingerprint.is_some() && authorized.is_some() && !confirmed {
        return Err(error());
    }
    let transport = authorized
        .as_deref()
        .map(|target| super::exchange::restore(runtime, id, target))
        .transpose()?
        .flatten();
    Ok(AdministrationCeremony {
        id,
        kind: target.kind(),
        round: TrustCeremonyRoundV1::ActivateRegistry,
        step: transport
            .as_ref()
            .map(|t| t.0)
            .unwrap_or(if authorized.is_some() {
                TrustCeremonyStep::AdminAuthorized
            } else if confirmed {
                TrustCeremonyStep::FingerprintConfirmed
            } else {
                TrustCeremonyStep::PendingRequest
            }),
        target_payload: authorized.unwrap_or_else(|| exact.to_vec()),
        exchange_file_name: transport.map(|t| t.1),
        fingerprint,
        linked: None,
    })
}
