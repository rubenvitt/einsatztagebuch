//! Offline Root station for an already signed, exact Admin target authorization.
use super::{
    authorization::action_now, ceremony::affirm_persisted, target::UntrustedAdministrationTarget,
};
use crate::{
    AdminError, VerifiedOperatorSession,
    operator_authority::AuthorityError,
    operator_exchange::{NativeExchangeSigner, VerifiedExchangeRequest},
    operator_runtime::OperatorRuntime,
};
use ea_audit::{AuditActorProof, SignedLocalAuditService, SqliteLocalAuditRepository};
use ea_crypto::{SignerRole, VerificationContext, object_hash};
use ea_format::{
    DecodedTrustPayloadV1, OperatorRoleV1, ParsedArchiveObject, RegistryChangeV1, TrustPayloadV1,
};
use ea_key_provider::SecretPurpose;
use ea_local_store::StoreValue;
use ea_trust::{
    RegistrySelectionOutcome, SelectedRegistryHead, TrustObjectSource, load_trust_state,
    prepare_local_time, select_registry_head, verify_registry_candidate, verify_trust,
};
use ea_types::{CertificateHash, ObjectHash, UnixMillis};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    target_payload: String,
    authorization: String,
    relevant_objects: Vec<String>,
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
fn decode(value: &str) -> Result<Vec<u8>, AuthorityError> {
    if value.len() > 98_304 {
        return Err(AuthorityError::Invalid);
    }
    hex::decode(value).map_err(|_| AuthorityError::Invalid)
}
fn failure(_: impl std::fmt::Display) -> AdminError {
    AdminError::AuditFailed
}
pub(crate) fn authorize(
    runtime: &OperatorRuntime,
    source: CertificateHash,
    request: &VerifiedExchangeRequest,
    value: &Value,
    session: &VerifiedOperatorSession,
) -> Result<Vec<u8>, AuthorityError> {
    if !runtime.config().authority
        || runtime.config().role != OperatorRoleV1::OrganizationAdmin
        || source == runtime.config().device_certificate_hash
    {
        return Err(AuthorityError::Context);
    }
    let input: Input =
        serde_json::from_value(value.clone()).map_err(|_| AuthorityError::Invalid)?;
    if input.relevant_objects.len() > 32 {
        return Err(AuthorityError::Invalid);
    }
    let target_bytes = decode(&input.target_payload)?;
    let authorization = decode(&input.authorization)?;
    let description =
        UntrustedAdministrationTarget::parse(&target_bytes).map_err(|_| AuthorityError::Invalid)?;
    let target = description
        .payload(object_hash(&authorization))
        .map_err(|_| AuthorityError::Invalid)?;
    if target.exact_digest_input() != target_bytes {
        return Err(AuthorityError::Context);
    }
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&authorization).map_err(|_| AuthorityError::Invalid)?
    else {
        return Err(AuthorityError::Invalid);
    };
    let DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) = parsed
        .value()
        .decoded_payload()
        .map_err(|_| AuthorityError::Invalid)?
    else {
        return Err(AuthorityError::Invalid);
    };
    if fields.admin_certificate_hash != source
        || fields.organization_id != runtime.anchor().organization_id()
        || fields.registry_version != runtime.head().registry_version()
        || fields.registry_head_hash.as_bytes() != runtime.head().registry_head_hash().as_bytes()
    {
        return Err(AuthorityError::Context);
    }
    let binding = runtime
        .head()
        .active_operator_binding_fields(fields.admin_operator_binding_object_hash)
        .ok_or(AuthorityError::Context)?;
    if binding.device_certificate_hash != source
        || binding.operator_role != OperatorRoleV1::OrganizationAdmin
    {
        return Err(AuthorityError::Context);
    }
    let current = || -> Result<UnixMillis, AuthorityError> {
        let now = action_now(runtime, session)?;
        if now < fields.issued_at || now > fields.expires_at {
            return Err(AuthorityError::Context);
        }
        Ok(now)
    };
    let now = current()?;
    let mut objects = required_objects(runtime, &target, &input.relevant_objects)?;
    objects.push(authorization.clone());
    let (trust, head) = overlay(runtime, &objects, now)?;
    let use_time = match target
        .decoded_payload()
        .map_err(|_| AuthorityError::Invalid)?
    {
        DecodedTrustPayloadV1::RegistryEvent(core) => core.fields().issued_at,
        _ => now,
    };
    let intent = ea_trust::verify_intended_trust_target(
        &trust,
        Some(&head),
        &target,
        use_time,
        runtime.next_sequence(),
    )?;
    for exact in objects.iter().take(objects.len() - 1) {
        ea_trust::verify_catalogue_admission(
            &trust,
            Some(&head),
            exact,
            now,
            runtime.next_sequence(),
        )?;
    }
    current()?;
    let request_hash: [u8; 32] = hex::decode(request.request_id())
        .map_err(|_| AuthorityError::Invalid)?
        .try_into()
        .map_err(|_| AuthorityError::Invalid)?;
    let mut record = minicbor::Encoder::new(Vec::new());
    record
        .array(2)
        .and_then(|e| e.bytes(&authorization))
        .and_then(|e| e.bytes(target.exact_digest_input()))
        .map_err(|_| AuthorityError::Invalid)?;
    let exact_record = record.into_writer();
    runtime.database().transaction(|tx|{
        affirm_persisted(runtime,tx)?;
        tx.execute("INSERT INTO administration_root_artifact(request_hash,artifact_kind,exact_bytes) VALUES(?1,0,?2) ON CONFLICT(request_hash,artifact_kind) DO NOTHING",&[blob(&request_hash),blob(&exact_record)])?;
        let row=tx.query_row("SELECT exact_bytes FROM administration_root_artifact WHERE request_hash=?1 AND artifact_kind=0",&[blob(&request_hash)])?.ok_or(AuthorityError::Uncertain)?;
        if row.blob(0)?!=exact_record {return Err(AuthorityError::Context)}
        Ok::<(),AuthorityError>(())
    })?;
    let admin = runtime.signing_provider();
    let root = runtime
        .native()
        .signing_provider(crate::native_provider::NativeSigningSlot::Root);
    let audit = SignedLocalAuditService::new(
        Arc::new(SqliteLocalAuditRepository::new(runtime.database().clone())),
        admin.clone(),
        admin.handle(SecretPurpose::WriterSigningKey),
        ObjectHash::try_from(
            runtime
                .config()
                .device_certificate_hash
                .as_bytes()
                .as_slice(),
        )
        .map_err(|_| AuthorityError::Context)?,
        current()?,
    );
    let ceremony = crate::RootCeremonyService::new(
        &head,
        &root,
        root.handle(SecretPurpose::WriterSigningKey),
        CertificateHash::from(head.root_certificate_object_hash()),
        &audit,
        runtime.config().binding_object_hash,
    );
    let publication = Publication {
        runtime,
        head: &head,
        request,
        request_hash,
        session,
        current: &current,
    };
    ceremony.publish_durably(
        &intent,
        target,
        &authorization,
        session.proof(),
        &publication,
    )?;
    current()?;
    runtime
        .database()
        .query_row(
            "SELECT reply_bytes FROM operator_authority_request WHERE request_hash=?1 AND state=1",
            &[blob(&request_hash)],
        )?
        .ok_or(AuthorityError::Uncertain)?
        .blob(0)
        .map(<[u8]>::to_vec)
        .map_err(Into::into)
}
fn required_objects(
    runtime: &OperatorRuntime,
    target: &TrustPayloadV1,
    inputs: &[String],
) -> Result<Vec<Vec<u8>>, AuthorityError> {
    let mut supplied = BTreeMap::new();
    for input in inputs {
        let exact = decode(input)?;
        if supplied.insert(object_hash(&exact), exact).is_some() {
            return Err(AuthorityError::Invalid);
        }
    }
    let mut needed = BTreeSet::new();
    match target
        .decoded_payload()
        .map_err(|_| AuthorityError::Invalid)?
    {
        DecodedTrustPayloadV1::RegistryEvent(core) => {
            match core.fields().change {
                RegistryChangeV1::Certificate { object_hash, .. }
                | RegistryChangeV1::Policy { object_hash }
                | RegistryChangeV1::WriterTransition { object_hash } => {
                    needed.insert(object_hash);
                }
                RegistryChangeV1::Target { .. } => {}
                _ => return Err(AuthorityError::Invalid),
            };
        }
        DecodedTrustPayloadV1::AuthorizedDevice(_)
        | DecodedTrustPayloadV1::Policy(_)
        | DecodedTrustPayloadV1::WriterTransition(_) => {}
        _ => return Err(AuthorityError::Invalid),
    }
    let mut result = Vec::new();
    let mut visited = BTreeSet::new();
    while let Some(hash) = needed.pop_first() {
        if !visited.insert(hash) {
            return Err(AuthorityError::Invalid);
        }
        let present = runtime
            .inventory()
            .read_exact_trust_object(hash)
            .map_err(|_| AuthorityError::Context)?;
        let supplied_exact = supplied.remove(&hash);
        let exact = match (present, supplied_exact) {
            (Some(existing), Some(input)) if existing.as_ref() == input => input,
            (Some(_), Some(_)) => return Err(AuthorityError::Context),
            (Some(existing), None) => existing.as_ref().to_vec(),
            (None, Some(input)) => input,
            (None, None) => return Err(AuthorityError::Context),
        };
        let ParsedArchiveObject::Trust(parsed) =
            ea_format::decode_exact_object(&exact).map_err(|_| AuthorityError::Invalid)?
        else {
            return Err(AuthorityError::Invalid);
        };
        let authorization = match parsed
            .value()
            .decoded_payload()
            .map_err(|_| AuthorityError::Invalid)?
        {
            DecodedTrustPayloadV1::AuthorizedDevice(core)
                if core.fields().certificate_kind
                    != ea_format::CertificateKindV1::OrganizationAdmin =>
            {
                Some(core.authorization_object_hash())
            }
            DecodedTrustPayloadV1::Policy(core) => Some(core.authorization_object_hash()),
            DecodedTrustPayloadV1::WriterTransition(core) => Some(core.authorization_object_hash()),
            DecodedTrustPayloadV1::OrganizationAdminAuthorization(_) => None,
            _ => return Err(AuthorityError::Invalid),
        };
        if let Some(hash) = authorization {
            needed.insert(hash);
        }
        result.push(exact);
    }
    if !supplied.is_empty() {
        return Err(AuthorityError::Invalid);
    }
    Ok(result)
}
fn overlay(
    runtime: &OperatorRuntime,
    objects: &[Vec<u8>],
    now: UnixMillis,
) -> Result<(ea_trust::VerifiedTrust, SelectedRegistryHead), AuthorityError> {
    let source = crate::operator_remote::ObjectOverlay::new(runtime.inventory(), objects);
    let mut store = runtime.trust_store().clone();
    let trust = verify_trust(
        runtime.anchor(),
        &source,
        load_trust_state(&mut store, runtime.trust().state_key())?,
    )?;
    let candidate = verify_registry_candidate(&trust, runtime.next_sequence())?;
    let time = prepare_local_time(&mut store, &candidate, now, &[])?;
    let RegistrySelectionOutcome::Selected(head) = select_registry_head(candidate, time, None)?
    else {
        return Err(AuthorityError::Context);
    };
    if head.registry_head_hash() != runtime.head().registry_head_hash()
        || !head
            .preexisting_effective_now()
            .has_same_persisted_bounds(runtime.head().preexisting_effective_now())
    {
        return Err(AuthorityError::Context);
    }
    Ok((trust, head))
}
struct Publication<'a> {
    runtime: &'a OperatorRuntime,
    head: &'a SelectedRegistryHead,
    request: &'a VerifiedExchangeRequest,
    request_hash: [u8; 32],
    session: &'a VerifiedOperatorSession,
    current: &'a dyn Fn() -> Result<UnixMillis, AuthorityError>,
}
impl crate::root_ceremony::DurableRootPublication for Publication<'_> {
    fn retained_signature(&self) -> Result<Option<Vec<u8>>, AdminError> {
        self.runtime.database().query_row("SELECT exact_bytes FROM administration_root_artifact WHERE request_hash=?1 AND artifact_kind=1",&[blob(&self.request_hash)]).map_err(failure)?.map(|r|r.blob(0).map(<[u8]>::to_vec).map_err(failure)).transpose()
    }
    fn stage_signature(&self, signature: &[u8]) -> Result<(), AdminError> {
        (self.current)().map_err(failure)?;
        self.runtime.database().transaction(|tx|{
            affirm_persisted(self.runtime,tx).map_err(failure)?;
            tx.execute("INSERT INTO administration_root_artifact(request_hash,artifact_kind,exact_bytes) VALUES(?1,1,?2) ON CONFLICT(request_hash,artifact_kind) DO NOTHING",&[blob(&self.request_hash),blob(signature)]).map_err(failure)?;
            Ok::<(),AuthorityError>(())
        }).map_err(failure)?;
        if self.retained_signature()?.as_deref() != Some(signature) {
            return Err(AdminError::RootSignatureMismatch);
        }
        Ok(())
    }
    fn commit(
        &self,
        target: &ea_format::ExactObjectBytes,
        replay: &[ea_trust::AdminAuthorizationReplayKey; 2],
        event: ea_audit::TypedLocalAuditEvent,
    ) -> Result<(), AdminError> {
        let now = (self.current)().map_err(failure)?;
        let provider = self.runtime.signing_provider();
        let audit = SignedLocalAuditService::new(
            Arc::new(SqliteLocalAuditRepository::new(
                self.runtime.database().clone(),
            )),
            provider.clone(),
            provider.handle(SecretPurpose::WriterSigningKey),
            ObjectHash::try_from(
                self.runtime
                    .config()
                    .device_certificate_hash
                    .as_bytes()
                    .as_slice(),
            )
            .map_err(failure)?,
            now,
        )
        .prepare_signed(
            AuditActorProof::OperatorSession(self.session.proof()),
            event,
        )
        .map_err(failure)?;
        let parsed = ea_format::decode_local_audit_event(audit.exact_bytes()).map_err(failure)?;
        let context = VerificationContext::local_audit(
            parsed.exact_core(),
            self.runtime.next_sequence(),
            SignerRole::OrganizationAdmin,
            self.head.registry_version(),
        )
        .map_err(failure)?;
        let mut decoder = minicbor::Decoder::new(audit.exact_bytes());
        decoder.array().map_err(failure)?;
        decoder.skip().map_err(failure)?;
        let start = decoder.position();
        decoder.skip().map_err(failure)?;
        ea_crypto::verify_cose_sign1(
            &audit.exact_bytes()[start..decoder.position()],
            self.head,
            &context,
        )
        .map_err(failure)?;
        (self.current)().map_err(failure)?;
        let reply = self
            .request
            .reply(
                json!({"target":hex::encode(target.as_bytes())}),
                &NativeExchangeSigner::administrator(self.runtime.native()),
            )
            .map_err(failure)?;
        (self.current)().map_err(failure)?;
        self.runtime.database().transaction(|tx|{
            affirm_persisted(self.runtime,tx).map_err(failure)?;
            for key in replay {
                if key.organization_id()!=self.runtime.anchor().organization_id(){return Err(AuthorityError::Admin(AdminError::AuthorizationMismatch))}
                let (dimension,value)=match key.dimension(){
                    ea_trust::AdminAuthorizationReplayDimension::AuthorizationId(id)=>(0,blob(id.as_bytes())),
                    ea_trust::AdminAuthorizationReplayDimension::Nonce(nonce)=>(1,blob(&nonce)),
                };
                if tx.execute("INSERT INTO operator_admin_replay(organization_id,dimension,replay_value) VALUES(?1,?2,?3) ON CONFLICT(organization_id,dimension,replay_value) DO NOTHING",&[blob(key.organization_id().as_bytes()),StoreValue::Integer(dimension),value]).map_err(failure)?!=1{return Err(AuthorityError::Admin(AdminError::Trust(ea_trust::TrustError::AuthReplay)))}
            }
            SqliteLocalAuditRepository::append_prepared_in(tx,&audit).map_err(failure)?;
            tx.execute("INSERT INTO administration_root_artifact(request_hash,artifact_kind,exact_bytes) VALUES(?1,2,?2)",&[blob(&self.request_hash),blob(target.as_bytes())]).map_err(failure)?;
            if tx.execute("UPDATE operator_authority_request SET state=1,reply_bytes=?1 WHERE request_hash=?2 AND state=0",&[blob(&reply),blob(&self.request_hash)]).map_err(failure)?!=1{return Err(AuthorityError::Admin(AdminError::AuditFailed))}
            Ok::<(),AuthorityError>(())
        }).map_err(failure)
    }
}
