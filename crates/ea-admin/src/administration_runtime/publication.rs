//! Exact, resumable publication of already Root-signed administration targets.
use super::{
    authorization::{action_now, verify_authorization},
    ceremony::{self, AdministrationCeremony, affirm_persisted},
    exchange,
};
use crate::{
    OperatorLifecycleError, TrustCeremonyStep, VerifiedOperatorSession,
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
};
use ea_archive::{
    ArchiveBackend, ArchiveBackendProfileV1, ArchivePath, BoundArchiveProfilePolicyV1,
};
use ea_audit::{
    AuditActorProof, SignedLocalAuditService, SqliteLocalAuditRepository, TypedLocalAuditEvent,
};
use ea_crypto::{SignerRole, VerificationContext, object_hash};
use ea_format::{
    AdminRootContextV1, DecodedTrustPayloadV1, LocalAuditActionV1, LocalAuditOutcomeV1,
    OrganizationAdminAuthorizationFieldsV1, ParsedArchiveObject, RegistryEventFieldsV1,
    TrustPayloadV1,
};
use ea_key_provider::SecretPurpose;
use ea_local_store::StoreValue;
use ea_trust::TrustObjectSource;
use ea_types::{ChainSequence, ObjectHash};
use std::sync::Arc;
fn error() -> OperatorRuntimeError {
    OperatorLifecycleError::JournalConflict.into()
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
pub fn publish(
    runtime: &mut OperatorRuntime,
    id: ObjectHash,
    profile: &ArchiveBackendProfileV1,
    session: &VerifiedOperatorSession,
) -> Result<AdministrationCeremony, OperatorRuntimeError> {
    let ceremony = ceremony::load(runtime, id)?;
    if ceremony.step() != TrustCeremonyStep::RootReplyImported {
        return Err(error());
    }
    action_now(runtime, session)?;
    let backend = ea_archive_fs::LocalPathBackend::open(
        runtime.config().archive_directory.clone(),
        profile.clone(),
        &BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields()),
    )
    .map_err(|_| error())?;
    let _lock = backend.acquire_writer_lock().map_err(|_| error())?;
    let existing = read_prepared(runtime, id)?;
    let (authorization, target, record) = if let Some(prepared) = existing {
        (prepared.authorization, prepared.target, prepared.record)
    } else {
        let now = action_now(runtime, session)?;
        let (authorization, target) =
            exchange::imported_objects(runtime, id, ceremony.exact_target_payload())?;
        let payload = TrustPayloadV1::from_exact_digest_input(ceremony.exact_target_payload())
            .map_err(|_| error())?;
        let intent = verify_authorization(runtime, &payload, &authorization, now)?;
        let description = ea_trust::describe_intended_trust_target(
            runtime.trust(),
            Some(runtime.head()),
            &payload,
            runtime.next_sequence(),
        )?;
        let provider = runtime.signing_provider();
        let audit = SignedLocalAuditService::new(
            Arc::new(SqliteLocalAuditRepository::new(runtime.database().clone())),
            provider.clone(),
            provider.handle(SecretPurpose::WriterSigningKey),
            ObjectHash::try_from(
                runtime
                    .config()
                    .device_certificate_hash
                    .as_bytes()
                    .as_slice(),
            )
            .map_err(|_| error())?,
            action_now(runtime, session)?,
        )
        .prepare_signed(
            AuditActorProof::OperatorSession(session.proof()),
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::AdminRootCeremony(AdminRootContextV1::new(
                    object_hash(&authorization),
                    object_hash(&target),
                    u64::from(description.action_code()),
                )),
                outcome: LocalAuditOutcomeV1::Completed,
            },
        )
        .map_err(|_| error())?;
        let parsed =
            ea_format::decode_local_audit_event(audit.exact_bytes()).map_err(|_| error())?;
        let context = VerificationContext::local_audit(
            parsed.exact_core(),
            runtime.next_sequence(),
            SignerRole::OrganizationAdmin,
            runtime.head().registry_version(),
        )
        .map_err(|_| error())?;
        let mut d = minicbor::Decoder::new(audit.exact_bytes());
        d.array().map_err(|_| error())?;
        d.skip().map_err(|_| error())?;
        let start = d.position();
        d.skip().map_err(|_| error())?;
        ea_crypto::verify_cose_sign1(
            &audit.exact_bytes()[start..d.position()],
            runtime.head(),
            &context,
        )
        .map_err(|_| error())?;
        action_now(runtime, session)?;
        let mut encoded = minicbor::Encoder::new(Vec::new());
        encoded
            .array(2)
            .and_then(|e| e.bytes(&authorization))
            .and_then(|e| e.bytes(&target))
            .map_err(|_| error())?;
        let record = encoded.into_writer();
        let trust = publication_trust(runtime, &authorization, &target)?;
        publication_proof(&trust, &authorization, &target, audit.exact_bytes())?;
        let candidate = ea_trust::verify_registry_candidate(&trust, runtime.next_sequence())?;
        let expected_head = if ceremony.round() == super::TrustCeremonyRoundV1::ActivateRegistry {
            object_hash(&target)
        } else {
            runtime.head().registry_head_hash()
        };
        if candidate.registry_head_hash() != expected_head {
            return Err(error());
        }
        runtime.database().transaction(|tx|{
        affirm_persisted(runtime,tx)?;
        for key in intent.replay_keys() {
            if key.organization_id()!=runtime.anchor().organization_id(){return Err(error())}
            let (dimension,value)=match key.dimension(){
                ea_trust::AdminAuthorizationReplayDimension::AuthorizationId(id)=>(0,blob(id.as_bytes())),
                ea_trust::AdminAuthorizationReplayDimension::Nonce(nonce)=>(1,blob(&nonce)),
            };
            if tx.execute("INSERT INTO operator_admin_replay(organization_id,dimension,replay_value) VALUES(?1,?2,?3) ON CONFLICT(organization_id,dimension,replay_value) DO NOTHING",&[blob(key.organization_id().as_bytes()),StoreValue::Integer(dimension),value])?!=1{return Err(error())}
        }
        SqliteLocalAuditRepository::append_prepared_in(tx,&audit).map_err(|_|error())?;
        tx.execute("INSERT INTO administration_ceremony_record(intent_hash,stage,exact_record,audit_event_id) VALUES(?1,4,?2,?3)",&[blob(id.as_bytes()),blob(&record),blob(audit.id().as_bytes())])?;
        Ok::<(),OperatorRuntimeError>(())
    })?;

        (authorization, target, record)
    };
    for exact in [&authorization, &target] {
        action_now(runtime, session)?;
        let ParsedArchiveObject::Trust(parsed) =
            ea_format::decode_exact_object(exact).map_err(|_| error())?
        else {
            return Err(error());
        };
        let bytes = ea_format::encode_trust(parsed.value()).map_err(|_| error())?;
        if bytes.as_bytes() != exact {
            return Err(error());
        }
        let path = ArchivePath::in_dir(
            ea_archive::TRUST_DIR_V1,
            &format!("{}.etb", hex::encode(object_hash(exact).as_bytes())),
        )
        .map_err(|_| error())?;
        backend
            .create_if_absent(&path, &bytes)
            .map_err(|_| error())?;
        backend.sync_file(&path).map_err(|_| error())?;
        backend.sync_directory(&path).map_err(|_| error())?;
    }
    let expected_head = if ceremony.round() == super::TrustCeremonyRoundV1::ActivateRegistry {
        object_hash(&target)
    } else {
        runtime.head().registry_head_hash()
    };
    runtime.refresh_for_action()?;
    if runtime.head().registry_head_hash() != expected_head {
        return Err(error());
    }
    action_now(runtime, session)?;
    let activation = if ceremony.round() == super::TrustCeremonyRoundV1::IssueTarget {
        Some(super::activation::plan(runtime, &target)?)
    } else {
        None
    };
    runtime.database().transaction(|tx| {
        affirm_persisted(runtime,tx)?;
        if let Some(payload)=&activation {super::activation::insert_in(runtime,tx,id,payload,&target)?;}
        tx.execute("INSERT INTO administration_ceremony_record(intent_hash,stage,exact_record,audit_event_id) VALUES(?1,5,?2,NULL) ON CONFLICT(intent_hash,stage) DO NOTHING",
            &[blob(id.as_bytes()),blob(&record)])?;
        Ok::<(),OperatorRuntimeError>(())
    })?;
    action_now(runtime, session)?;
    ceremony::load(runtime, id)
}

struct PreparedPublication {
    authorization: Vec<u8>,
    target: Vec<u8>,
    record: Vec<u8>,
    proof: PublicationProof,
    complete: bool,
}
fn publication_trust(
    runtime: &OperatorRuntime,
    authorization: &[u8],
    target: &[u8],
) -> Result<ea_trust::VerifiedTrust, OperatorRuntimeError> {
    let objects = vec![authorization.to_vec(), target.to_vec()];
    let source = crate::operator_remote::ObjectOverlay::new(runtime.inventory(), &objects);
    let mut store = runtime.trust_store().clone();
    Ok(ea_trust::verify_trust(
        runtime.anchor(),
        &source,
        ea_trust::load_trust_state(&mut store, runtime.trust().state_key())?,
    )?)
}
fn pair(exact: &[u8]) -> Result<(Vec<u8>, Vec<u8>), OperatorRuntimeError> {
    let mut d = minicbor::Decoder::new(exact);
    if d.array().map_err(|_| error())? != Some(2) {
        return Err(error());
    }
    let first = d.bytes().map_err(|_| error())?.to_vec();
    let second = d.bytes().map_err(|_| error())?.to_vec();
    let mut encoded = minicbor::Encoder::new(Vec::new());
    encoded
        .array(2)
        .and_then(|e| e.bytes(&first))
        .and_then(|e| e.bytes(&second))
        .map_err(|_| error())?;
    if d.position() != exact.len() || encoded.into_writer() != exact {
        return Err(error());
    }
    Ok((first, second))
}
fn read_prepared(
    runtime: &OperatorRuntime,
    id: ObjectHash,
) -> Result<Option<PreparedPublication>, OperatorRuntimeError> {
    let Some(row)=runtime.database().query_row(
        "SELECT r.exact_record,a.exact_bytes FROM administration_ceremony_record r JOIN local_audit_event a ON a.event_id=r.audit_event_id WHERE r.intent_hash=?1 AND r.stage=4",
        &[blob(id.as_bytes())])?else{
            if runtime.database().query_row("SELECT stage FROM administration_ceremony_record WHERE intent_hash=?1 AND stage>=4",&[blob(id.as_bytes())])?.is_some(){return Err(error())}
            return Ok(None)
        };
    let (authorization, target) = pair(row.blob(0)?)?;
    let trust = publication_trust(runtime, &authorization, &target)?;
    let proof = publication_proof(&trust, &authorization, &target, row.blob(1)?)?;
    let target_present = runtime
        .inventory()
        .read_exact_trust_object(object_hash(&target))
        .map_err(|_| error())?
        .is_some_and(|exact| exact.as_ref() == target);
    let authorization_present = runtime
        .inventory()
        .read_exact_trust_object(object_hash(&authorization))
        .map_err(|_| error())?
        .is_some_and(|exact| exact.as_ref() == authorization);
    if !target_present
        && (runtime.head().registry_version() != proof.authorization.registry_version
            || runtime.head().registry_head_hash().as_bytes()
                != proof.authorization.registry_head_hash.as_bytes()
            || runtime.next_sequence() != proof.sequence)
    {
        return Err(error());
    }
    if target_present
        && runtime.head().registry_version()
            < proof
                .registry
                .as_ref()
                .map_or(proof.authorization.registry_version, |r| r.registry_version)
    {
        return Err(error());
    }
    let completion=runtime.database().query_row(
        "SELECT exact_record,audit_event_id IS NULL FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=5",&[blob(id.as_bytes())])?;
    let complete = if let Some(completion) = completion {
        if completion.blob(0)? != row.blob(0)?
            || completion.integer(1)? != 1
            || !target_present
            || !authorization_present
        {
            return Err(error());
        }
        true
    } else {
        false
    };
    Ok(Some(PreparedPublication {
        authorization,
        target,
        record: row.blob(0)?.to_vec(),
        proof,
        complete,
    }))
}
pub(crate) fn restore(
    runtime: &OperatorRuntime,
    id: ObjectHash,
    row: &ea_local_store::StoreRow,
) -> Result<Option<AdministrationCeremony>, OperatorRuntimeError> {
    let Some(prepared) = read_prepared(runtime, id)? else {
        return Ok(None);
    };
    let auth = &prepared.proof.authorization;
    if row.blob(0)? != runtime.anchor().organization_id().as_bytes()
        || row.blob(1)? != runtime.head().chain_id().as_bytes()
        || row.blob(2)? != runtime.anchor().trust_anchor_hash().as_bytes()
        || row.blob(3)? != runtime.config().device_certificate_hash.as_bytes()
        || row.blob(4)? != runtime.config().binding_object_hash.as_bytes()
        || row.blob(3)? != auth.admin_certificate_hash.as_bytes()
        || row.blob(4)? != auth.admin_operator_binding_object_hash.as_bytes()
        || row.integer(5)? != i64::try_from(auth.registry_version.get()).map_err(|_| error())?
        || row.blob(6)? != auth.registry_head_hash.as_bytes()
        || row.integer(7)? != i64::try_from(prepared.proof.sequence.get()).map_err(|_| error())?
        || object_hash(row.blob(8)?) != id
    {
        return Err(error());
    }
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&prepared.target).map_err(|_| error())?
    else {
        return Err(error());
    };
    let target_payload = parsed.value().exact_digest_input().to_vec();
    let provisional = TrustPayloadV1::from_exact_digest_input(row.blob(8)?).map_err(|_| error())?;
    let (kind, round, fingerprint) = if let Some(registry) = &prepared.proof.registry {
        let DecodedTrustPayloadV1::RegistryEvent(core) =
            provisional.decoded_payload().map_err(|_| error())?
        else {
            return Err(error());
        };
        let mut expected = registry.clone();
        if !matches!(row.integer(9)?, 0 | 2)
            || row.integer(10)? != 1
            || core.authorization_object_hash() != ObjectHash::from(ea_types::Hash32::ZERO)
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
        if row.integer(9)? == 0 {
            if row.integer(11)? != 1
                || !matches!(expected.change, ea_format::RegistryChangeV1::Target { .. })
            {
                return Err(error());
            }
            (
                crate::TrustCeremonyKind::DeviceRevoke,
                super::TrustCeremonyRoundV1::ActivateRegistry,
                None,
            )
        } else {
            super::activation::validate_parent(runtime, row)?;
            let target_hash = object_hash(row.blob(12)?);
            let (kind, fingerprint) = match expected.change {
                ea_format::RegistryChangeV1::Certificate { object_hash }
                    if object_hash == target_hash =>
                {
                    if !super::registration::confirmed(runtime, id, target_hash)? {
                        return Err(error());
                    }
                    (
                        crate::TrustCeremonyKind::DeviceApprove,
                        Some((super::FingerprintSubjectV1::IssuedCertificate, target_hash)),
                    )
                }
                ea_format::RegistryChangeV1::Policy { object_hash }
                    if object_hash == target_hash =>
                {
                    (crate::TrustCeremonyKind::PolicyChange, None)
                }
                ea_format::RegistryChangeV1::WriterTransition { object_hash }
                    if object_hash == target_hash =>
                {
                    (crate::TrustCeremonyKind::WriterTransition, None)
                }
                _ => return Err(error()),
            };
            (
                kind,
                super::TrustCeremonyRoundV1::ActivateRegistry,
                fingerprint,
            )
        }
    } else {
        if row.integer(10)? != 0 || row.integer(11)? != 1 {
            return Err(error());
        }
        let normalized = super::target::UntrustedAdministrationTarget::parse(&target_payload)
            .map_err(|_| error())?
            .payload(ObjectHash::from(ea_types::Hash32::ZERO))
            .map_err(|_| error())?;
        if normalized.exact_digest_input() != provisional.exact_digest_input() {
            return Err(error());
        }
        let (kind, fingerprint) = match row.integer(9)? {
            1 => {
                let request = super::registration::verify_material(
                    runtime.anchor().organization_id(),
                    row.blob(12)?,
                    row.blob(8)?,
                )?;
                if !super::registration::confirmed(runtime, id, request.request_hash())? {
                    return Err(error());
                }
                (
                    crate::TrustCeremonyKind::DeviceApprove,
                    Some((
                        super::FingerprintSubjectV1::RegistrationRequest,
                        request.request_hash(),
                    )),
                )
            }
            0 => {
                let kind = match normalized.decoded_payload().map_err(|_| error())? {
                    DecodedTrustPayloadV1::Policy(_) => crate::TrustCeremonyKind::PolicyChange,
                    DecodedTrustPayloadV1::WriterTransition(_) => {
                        crate::TrustCeremonyKind::WriterTransition
                    }
                    _ => return Err(error()),
                };
                if runtime.database().query_row("SELECT stage FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=0",&[blob(id.as_bytes())])?.is_some() {
                    return Err(error());
                }
                (kind, None)
            }
            _ => return Err(error()),
        };
        (kind, super::TrustCeremonyRoundV1::IssueTarget, fingerprint)
    };
    let original=runtime.database().query_row("SELECT exact_record FROM administration_ceremony_record WHERE intent_hash=?1 AND stage=1",&[blob(id.as_bytes())])?.ok_or_else(error)?;
    let (original_auth, original_target) = pair(original.blob(0)?)?;
    if original_auth != prepared.authorization || original_target != target_payload {
        return Err(error());
    }
    Ok(Some(AdministrationCeremony {
        id,
        kind,
        round,
        step: if prepared.complete {
            if round == super::TrustCeremonyRoundV1::IssueTarget {
                TrustCeremonyStep::TargetPublished
            } else {
                TrustCeremonyStep::RegistryPublished
            }
        } else {
            TrustCeremonyStep::RootReplyImported
        },
        target_payload,
        exchange_file_name: None,
        fingerprint,
        linked: None,
    }))
}

struct PublicationProof {
    authorization: OrganizationAdminAuthorizationFieldsV1,
    sequence: ChainSequence,
    registry: Option<RegistryEventFieldsV1>,
}
fn publication_proof(
    trust: &ea_trust::VerifiedTrust,
    authorization: &[u8],
    target: &[u8],
    exact_audit: &[u8],
) -> Result<PublicationProof, OperatorRuntimeError> {
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(target).map_err(|_| error())?
    else {
        return Err(error());
    };
    let target_payload =
        TrustPayloadV1::from_exact_digest_input(parsed.value().exact_digest_input())
            .map_err(|_| error())?;
    if matches!(
        target_payload.decoded_payload().map_err(|_| error())?,
        DecodedTrustPayloadV1::RegistryEvent(_)
    ) {
        let proof =
            ea_trust::verify_registry_publication_audit(trust, object_hash(target), exact_audit)?;
        if proof.authorization_hash() != object_hash(authorization) {
            return Err(error());
        }
        return Ok(PublicationProof {
            authorization: proof.authorization_fields().clone(),
            sequence: proof.original_sequence(),
            registry: Some(proof.target_fields().clone()),
        });
    }
    let proof =
        ea_trust::verify_direct_target_publication_audit(trust, object_hash(target), exact_audit)?;
    if proof.authorization_hash() != object_hash(authorization) {
        return Err(error());
    }
    Ok(PublicationProof {
        authorization: proof.authorization_fields().clone(),
        sequence: proof.original_sequence(),
        registry: None,
    })
}

pub(super) fn issued_target(
    runtime: &OperatorRuntime,
    id: ObjectHash,
) -> Result<Vec<u8>, OperatorRuntimeError> {
    let row=runtime.database().query_row("SELECT organization_id,chain_id,trust_anchor_hash,admin_certificate_hash,admin_binding_hash,registry_version,registry_head_hash,proposed_sequence,target_payload,source_kind,ceremony_round,parent_intent_hash IS NULL,source_bytes,parent_intent_hash FROM administration_ceremony_intent WHERE intent_hash=?1",&[blob(id.as_bytes())])?.ok_or_else(error)?;
    if restore(runtime, id, &row)?
        .is_none_or(|ceremony| ceremony.step() != TrustCeremonyStep::TargetPublished)
    {
        return Err(error());
    }
    let prepared = read_prepared(runtime, id)?.ok_or_else(error)?;
    if !prepared.complete || prepared.proof.registry.is_some() {
        return Err(error());
    }
    Ok(prepared.target)
}
