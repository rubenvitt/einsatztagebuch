//! Exact v1 destruction history; current action admission is separate from
//! historical signature attribution. No database state number authorizes removal.
use crate::{
    AppendOutcome, ChainHeadStateV1, IndexedObjectV1, RegistryAdmissionFenceV1,
    destruction::{DestructionError as Error, DestructionPorts, destruction_status},
};
use ea_crypto::{object_hash, parse_cose_sign1};
use ea_destruction::{
    DestructionStateMachine, VerifiedDestructionEvent, verify_authorization_historical,
    verify_event_historical,
};
use ea_format::{DecodedTrustPayloadV1, ObjectTypeV1, ParsedArchiveObject, decode_exact_object};
use ea_sync_protocol::DestructionStatusResponseV1;
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DestructionId, ObjectHash, OrganizationId,
};

/// Only the service constructs this value after signature/history verification.
#[non_exhaustive]
pub struct DestructionEventCommand {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub expected_chain_head: ChainHeadStateV1,
    pub authority_fence: RegistryAdmissionFenceV1,
    pub authorization_hash: ObjectHash,
    pub expected_history: Vec<ObjectHash>,
    pub expected_attestations: Vec<ObjectHash>,
    pub event: VerifiedDestructionEvent,
    pub indexed: IndexedObjectV1,
}

pub async fn accept_event(
    organization_id: OrganizationId,
    principal: CertificateHash,
    destruction_id: DestructionId,
    exact: &[u8],
    ports: &DestructionPorts<'_>,
) -> Result<DestructionStatusResponseV1, Error> {
    // Status rereads exact auth and every barrier target before any mutation.
    let status = destruction_status(organization_id, destruction_id, ports).await?;
    let saved = ports
        .destructions
        .destruction_state(organization_id, destruction_id)
        .await?
        .ok_or(Error::Unknown)?;
    let auth_bytes = read(ports, saved.authorization_object_hash).await?;
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&auth_bytes)? else {
        return Err(Error::AuthorizationInvalid);
    };
    let DecodedTrustPayloadV1::DestructionAuthorization(fields) =
        parsed.value().decoded_payload()?
    else {
        return Err(Error::AuthorizationInvalid);
    };
    let now = ports.clock.now();
    let historical = ports
        .heads
        .historical_registry_authority(
            organization_id,
            fields.registry_version,
            ObjectHash::from(fields.registry_head_hash),
            ChainSequence::new(fields.authorization_sequence),
        )
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    let auth = verify_authorization_historical(&auth_bytes, &historical)
        .map_err(|_| Error::AuthorizationUnverifiable)?;
    let event = verify_event_historical(exact, &auth, &historical, now)
        .map_err(|_| Error::AuthorizationUnverifiable)?;
    let mut machine = DestructionStateMachine::new(&auth);
    let mut replay = false;
    for hash in &saved.transition_object_hashes {
        let bytes = read(ports, *hash).await?;
        let old = verify_event_historical(&bytes, &auth, &historical, now)
            .map_err(|_| Error::AuthorizationUnverifiable)?;
        machine.apply(&old).map_err(|_| Error::Conflict)?;
        if old.object_hash() == event.object_hash() {
            if old.exact_bytes() != exact {
                return Err(Error::Conflict);
            }
            replay = true;
        }
    }
    if !replay {
        machine.apply(&event).map_err(|_| Error::Conflict)?;
    }
    if !replay && event.fields().to_state != 0 {
        let job = load_job(organization_id, destruction_id, ports).await?;
        let mut events = Vec::new();
        let mut attestations = Vec::new();
        for hash in &saved.transition_object_hashes {
            events.push(
                verify_event_historical(&read(ports, *hash).await?, &auth, &historical, now)
                    .map_err(|_| Error::AuthorizationUnverifiable)?,
            );
        }
        events.push(event.clone());
        for hash in &saved.attestation_object_hashes {
            attestations.push(
                ea_destruction::verify_attestation_historical(
                    &read(ports, *hash).await?,
                    &auth,
                    &historical,
                    now,
                )
                .map_err(|_| Error::AuthorizationUnverifiable)?,
            );
        }
        ea_destruction::reconstruct_imported_history(&job, &events, &attestations)
            .map_err(|_| Error::Conflict)?;
    }

    let current_progress = ports
        .chain_heads
        .committed_chain_head(organization_id, historical.chain_id())
        .await?
        .ok_or(Error::Conflict)?;
    let next = current_progress
        .sequence
        .get()
        .checked_add(1)
        .ok_or(Error::Conflict)?;
    let admission = ports
        .heads
        .select_current_admission(organization_id, ChainSequence::new(next), now)
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    let policy = &admission.head.policy_fields().retention_policy;
    if !policy.destruction_enabled || policy.eds_privacy_decision_document_hash.is_none() {
        return Err(Error::PrivacyGate);
    }
    let original = historical
        .active_certificate_fields(principal)
        .ok_or(Error::AuthorizationUnverifiable)?;
    let current = admission
        .head
        .active_certificates()
        .into_iter()
        .find(|(hash, _)| *hash == principal)
        .map(|(_, fields)| fields)
        .ok_or(Error::AuthorizationUnverifiable)?;
    if current != original
        || current.certificate_kind != ea_format::CertificateKindV1::DeletionAttest
        || !current.capabilities.iter().any(|c| c == "deletionAttest")
    {
        return Err(Error::AuthorizationUnverifiable);
    }
    let ParsedArchiveObject::Trust(parsed_event) = decode_exact_object(exact)? else {
        return Err(Error::AuthorizationInvalid);
    };
    let [signature] = parsed_event.value().signatures() else {
        return Err(Error::AuthorizationInvalid);
    };
    if parse_cose_sign1(signature, &[])?.certificate_hash() != Some(principal) {
        return Err(Error::AuthorizationUnverifiable);
    }

    if replay {
        return Ok(status);
    }
    if event.fields().to_state == 3 {
        if !ports
            .destructions
            .server_removal_measured(organization_id, destruction_id, event.fields().executed_at)
            .await?
        {
            return Err(Error::Conflict);
        }
        let job = load_job(organization_id, destruction_id, ports).await?;
        let targets = job
            .targets()
            .iter()
            .map(|t| (t.entry_hash(), t.sequence().get(), t.original_object_hash()))
            .collect::<Vec<_>>();
        let known = ports
            .destructions
            .managed_target_objects(organization_id, destruction_id, &targets)
            .await?;
        ports
            .objects
            .verify_destruction_scope(&targets.iter().map(|t| t.0).collect::<Vec<_>>(), &known)
            .await?;
        for object in known {
            if !ports
                .objects
                .remaining_destruction_versions(object.kind, object.object_hash)
                .await?
                .is_empty()
            {
                return Err(Error::Conflict);
            }
        }
    }
    let staged = ports
        .objects
        .stage_stream(
            ObjectTypeV1::Trust,
            aws_sdk_s3::primitives::ByteStream::from(exact.to_vec()),
            ea_format::ETB_MAX_RAW_BYTES_V1 as u64,
        )
        .await?;
    let stored = ports.objects.put_if_absent(staged).await?;
    if stored.object_hash() != event.object_hash() {
        return Err(Error::Conflict);
    }
    let command = DestructionEventCommand {
        organization_id,
        chain_id: historical.chain_id(),
        expected_chain_head: current_progress,
        authority_fence: admission.fence,
        authorization_hash: auth.object_hash(),
        expected_history: saved.transition_object_hashes,
        expected_attestations: saved.attestation_object_hashes,
        event,
        indexed: IndexedObjectV1 {
            object_hash: stored.object_hash(),
            kind: ObjectTypeV1::Trust,
            size_bytes: stored.size_bytes(),
        },
    };
    match ports
        .destructions
        .record_destruction_event(command, ports.clock)
        .await?
    {
        AppendOutcome::Recorded | AppendOutcome::AlreadyRecorded => {}
        AppendOutcome::Conflict => return Err(Error::Conflict),
    }
    destruction_status(organization_id, destruction_id, ports).await
}

async fn read(ports: &DestructionPorts<'_>, hash: ObjectHash) -> Result<Vec<u8>, Error> {
    let bytes = ports
        .objects
        .get_exact_in(ObjectTypeV1::Trust, hash)
        .await?
        .collect()
        .await
        .map_err(|_| Error::DependencyUnavailable)?
        .into_bytes()
        .to_vec();
    if object_hash(&bytes) != hash {
        return Err(Error::Conflict);
    }
    Ok(bytes)
}

// Provider-observed technical obligations, not authority supplied by a caller.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredObjectVersion {
    pub storage_key: String,
    pub version_id: String,
    pub delete_marker: bool,
    pub retained_until: Option<ea_types::UnixMillis>,
    pub legal_hold: bool,
}
pub struct ObservedObjectVersions {
    pub versions: Vec<StoredObjectVersion>,
    pub exact_bytes: Vec<u8>,
}
pub struct FrozenDestructionObject {
    pub object: IndexedObjectV1,
    pub versions: Vec<StoredObjectVersion>,
}
pub struct StoredDestructionJob {
    pub exact_upload: Vec<u8>,
}
#[non_exhaustive]
pub struct DestructionJobCommand {
    pub principal_certificate: CertificateHash,
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub expected_chain_head: ChainHeadStateV1,
    pub authority_fence: RegistryAdmissionFenceV1,
    pub preflight: ea_destruction::VerifiedImportedPreflight,
    pub objects: Vec<FrozenDestructionObject>,
}

pub async fn accept_job(
    organization_id: OrganizationId,
    principal: CertificateHash,
    id: DestructionId,
    upload: &ea_sync_protocol::DestructionJobUploadV1,
    ports: &DestructionPorts<'_>,
) -> Result<DestructionStatusResponseV1, Error> {
    let status = destruction_status(organization_id, id, ports).await?;
    let core = ea_crypto::decode_destruction_preflight_core(upload.core_bytes())?;
    if core.organization_id != *organization_id.as_bytes()
        || core.destruction_id != *id.as_bytes()
        || core.authorization_hash != *status.authorization_object_hash().as_bytes()
    {
        return Err(Error::Conflict);
    }
    let (proof, original) = verify_job(organization_id, upload, ports).await?;
    let now = ports.clock.now();
    let progress = ports
        .chain_heads
        .committed_chain_head(organization_id, proof.chain_id())
        .await?
        .ok_or(Error::Conflict)?;
    let next = progress
        .sequence
        .get()
        .checked_add(1)
        .ok_or(Error::Conflict)?;
    let current = ports
        .heads
        .select_current_admission(organization_id, ChainSequence::new(next), now)
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    if core.observed_effective_now > now.get()
        || core.execution_sequence > next
        || core.execution_registry > current.head.registry_version().get()
    {
        return Err(Error::AuthorizationUnverifiable);
    }
    let policy = &current.head.policy_fields().retention_policy;
    if !policy.destruction_enabled || policy.eds_privacy_decision_document_hash.is_none() {
        return Err(Error::PrivacyGate);
    }
    let cert = original
        .active_certificate_fields(principal)
        .ok_or(Error::AuthorizationUnverifiable)?;
    let active = current.head.active_certificates();
    if cert.certificate_kind != ea_format::CertificateKindV1::DeletionAttest
        || !cert.capabilities.iter().any(|c| c == "deletionAttest")
        || !active
            .iter()
            .any(|(hash, c)| *hash == principal && *c == cert)
    {
        return Err(Error::AuthorizationUnverifiable);
    }
    let known = current
        .head
        .known_certificate_fields()
        .ok_or(Error::AuthorizationUnverifiable)?;
    let expected: std::collections::BTreeSet<_> = known
        .into_iter()
        .filter(|(_, c)| {
            matches!(
                c.certificate_kind,
                ea_format::CertificateKindV1::Writer
                    | ea_format::CertificateKindV1::Reader
                    | ea_format::CertificateKindV1::ServerReceipt
            )
        })
        .map(|(h, c)| (h, c.device_id, c.certificate_kind as u8))
        .collect();
    if proof
        .replicas()
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        return Err(Error::Conflict);
    }
    if let Some(saved) = ports
        .destructions
        .destruction_job(organization_id, id)
        .await?
    {
        if saved.exact_upload != upload.exact_bytes() {
            return Err(Error::Conflict);
        }
        return Ok(status);
    }
    let targets = proof
        .targets()
        .iter()
        .map(|t| (t.entry_hash(), t.sequence().get(), t.original_object_hash()))
        .collect::<Vec<_>>();
    let indexed = ports
        .destructions
        .managed_target_objects(organization_id, id, &targets)
        .await?;
    let mut frozen = Vec::new();
    let mut originals = std::collections::BTreeMap::new();
    let mut recoveries = std::collections::BTreeMap::new();
    let mut historical_references = Vec::new();
    let mut grant_items: std::collections::BTreeMap<
        ea_types::EntryHash,
        Vec<ea_format::GrantPlanItemV1>,
    > = std::collections::BTreeMap::new();
    for object in indexed {
        let observed = ports
            .objects
            .destruction_versions(object.kind, object.object_hash)
            .await?;
        if observed.versions.is_empty() || object_hash(&observed.exact_bytes) != object.object_hash
        {
            return Err(Error::Conflict);
        }
        match decode_exact_object(&observed.exact_bytes)? {
            ParsedArchiveObject::Entry(entry) if object.kind == ObjectTypeV1::Entry => {
                let target = proof
                    .targets()
                    .iter()
                    .find(|t| t.original_object_hash() == object.object_hash)
                    .ok_or(Error::Conflict)?;
                let ParsedArchiveObject::Destroyed(stub) =
                    decode_exact_object(target.exact_stub_bytes())?
                else {
                    return Err(Error::Conflict);
                };
                if entry.value().entry_hash() != target.entry_hash()
                    || entry.value().signed_manifest().exact_bytes()
                        != stub.value().signed_manifest().exact_bytes()
                    || entry.value().writer_signature() != stub.value().writer_signature()
                {
                    return Err(Error::Conflict);
                }
                originals.insert(
                    target.entry_hash(),
                    entry.value().manifest().fields().initial_grant_plan_hash,
                );
            }
            ParsedArchiveObject::Grant(grant) if object.kind == ObjectTypeV1::Grant => {
                let fields = grant.value().grant_body().fields();
                crate::managed_grant_membership::verify(grant.value(), &proof, ports).await?;
                if fields.kind == ea_format::GrantKindV1::Historical {
                    historical_references.push((
                        fields.entry_hash,
                        fields
                            .original_recovery_grant_object_hash
                            .ok_or(Error::AuthorizationUnverifiable)?,
                    ));
                } else if fields.purpose == ea_format::GrantPurposeV1::Recovery
                    && recoveries
                        .insert(fields.entry_hash, object.object_hash)
                        .is_some()
                {
                    return Err(Error::Conflict);
                }

                if !targets.iter().any(|(e, _, _)| *e == fields.entry_hash) {
                    return Err(Error::Conflict);
                }
                if fields.kind == ea_format::GrantKindV1::Initial {
                    grant_items.entry(fields.entry_hash).or_default().push(
                        ea_format::GrantPlanItemV1::new(
                            fields.recipient_key_thumbprint,
                            fields.recipient_certificate_hash,
                            fields.purpose,
                        ),
                    );
                }
            }
            _ => return Err(Error::Conflict),
        }
        frozen.push(FrozenDestructionObject {
            object,
            versions: observed.versions,
        });
    }
    if historical_references
        .iter()
        .any(|(entry, hash)| recoveries.get(entry) != Some(hash))
    {
        return Err(Error::AuthorizationUnverifiable);
    }
    if originals.len() != targets.len() {
        return Err(Error::Conflict);
    }
    for (entry, hash) in originals {
        let plan = ea_format::GrantPlanV1::new(grant_items.remove(&entry).ok_or(Error::Conflict)?)
            .map_err(|_| Error::Conflict)?;
        if plan.hash().as_bytes() != &hash {
            return Err(Error::Conflict);
        }
    }
    ports
        .objects
        .verify_destruction_scope(
            &targets.iter().map(|t| t.0).collect::<Vec<_>>(),
            &frozen.iter().map(|o| o.object).collect::<Vec<_>>(),
        )
        .await?;
    let command = DestructionJobCommand {
        principal_certificate: principal,
        organization_id,
        chain_id: proof.chain_id(),
        expected_chain_head: progress,
        authority_fence: current.fence,
        preflight: proof,
        objects: frozen,
    };
    match ports
        .destructions
        .record_destruction_job(command, ports.clock)
        .await?
    {
        AppendOutcome::Recorded | AppendOutcome::AlreadyRecorded => {}
        AppendOutcome::Conflict => return Err(Error::Conflict),
    }
    destruction_status(organization_id, id, ports).await
}

/// Dedicated server service credential. No Reader, Recovery or Writer
/// operation is exposed, and a request can only be minted by measured execution.
pub trait ServerDeletionComponent: Send + Sync {
    fn certificate_hash(&self) -> CertificateHash;
    fn public_key(&self) -> &ea_crypto::CanonicalPublicCoseKey;
    fn sign_attestation(
        &self,
        request: &ServerAttestationRequest,
    ) -> Result<Vec<u8>, ea_crypto::CryptoError>;
}
pub struct ServerAttestationRequest {
    pub(crate) authorization: ea_destruction::VerifiedDestructionAuthorization,
    pub(crate) payload: ea_format::TrustPayloadV1,
}
impl ServerAttestationRequest {
    pub fn exact_authorization_bytes(&self) -> &[u8] {
        self.authorization.exact_bytes()
    }
    pub fn exact_payload_digest_input(&self) -> &[u8] {
        self.payload.exact_digest_input()
    }
}

pub(crate) async fn verify_job(
    org: OrganizationId,
    upload: &ea_sync_protocol::DestructionJobUploadV1,
    ports: &DestructionPorts<'_>,
) -> Result<
    (
        ea_destruction::VerifiedImportedPreflight,
        ea_trust::HistoricalRegistryAuthority,
    ),
    Error,
> {
    let organization_id = org;
    let core = ea_crypto::decode_destruction_preflight_core(upload.core_bytes())?;
    let auth_bytes = read(
        ports,
        ObjectHash::try_from(core.authorization_hash.as_slice())
            .map_err(|_| Error::AuthorizationInvalid)?,
    )
    .await?;
    let original = ports
        .heads
        .historical_registry_authority(
            organization_id,
            ea_types::RegistryVersion::new(core.authorization_registry),
            ObjectHash::try_from(core.authorization_head.as_slice())
                .map_err(|_| Error::AuthorizationInvalid)?,
            ChainSequence::new(core.authorization_sequence),
        )
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    let auth = verify_authorization_historical(&auth_bytes, &original)
        .map_err(|_| Error::AuthorizationUnverifiable)?;
    let execution = ports
        .heads
        .historical_registry_authority(
            organization_id,
            ea_types::RegistryVersion::new(core.execution_registry),
            ObjectHash::try_from(core.execution_head.as_slice())
                .map_err(|_| Error::AuthorizationInvalid)?,
            ChainSequence::new(core.execution_sequence),
        )
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    let mut target_authorities = Vec::new();
    for context in ea_destruction::preflight_target_contexts(upload)
        .map_err(|_| Error::AuthorizationInvalid)?
    {
        target_authorities.push(
            ports
                .heads
                .historical_registry_authority(
                    organization_id,
                    context.registry,
                    context.head,
                    context.sequence,
                )
                .await?
                .ok_or(Error::AuthorizationUnverifiable)?,
        );
    }
    let proof = ea_destruction::VerifiedImportedPreflight::verify(
        upload,
        &auth,
        &original,
        &execution,
        &target_authorities,
    )
    .map_err(|_| Error::AuthorizationUnverifiable)?;

    Ok((proof, original))
}
pub(crate) async fn load_job(
    org: OrganizationId,
    id: DestructionId,
    ports: &DestructionPorts<'_>,
) -> Result<ea_destruction::VerifiedImportedPreflight, Error> {
    let saved = ports
        .destructions
        .destruction_job(org, id)
        .await?
        .ok_or(Error::Conflict)?;
    let upload = ea_sync_protocol::DestructionJobUploadV1::decode(&saved.exact_upload)
        .map_err(|_| Error::AuthorizationInvalid)?;
    let (proof, _) = verify_job(org, &upload, ports).await?;
    if proof.authorization().fields().destruction_id != id {
        return Err(Error::Conflict);
    }
    Ok(proof)
}

/// An acquired transaction holds catalog, chain and process locks until the
/// measured result is durably committed. Dropping it cannot claim completion.
#[async_trait::async_trait]
pub trait ServerExecutionGuard: Send {
    fn objects(&self) -> &[FrozenDestructionObject];
    async fn finish(
        self: Box<Self>,
        measurement: ServerRemovalMeasurement,
        clock: &dyn crate::ServerClock,
    ) -> Result<(), crate::RepositoryError>;
}
/// Current admission interval minted by the verified execution service. The
/// provider checks its own clock after inspection, immediately before deletion.
pub struct ServerRemovalWindow {
    pub(crate) selected_at: ea_types::UnixMillis,
    pub(crate) not_after: ea_types::UnixMillis,
}
impl ServerRemovalWindow {
    pub fn is_current(&self, now: ea_types::UnixMillis) -> bool {
        self.selected_at <= now && now <= self.not_after
    }
}

#[non_exhaustive]
pub struct ServerExecutionCommand {
    pub controller_certificate: CertificateHash,
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub destruction_id: DestructionId,
    pub expected_chain_head: ChainHeadStateV1,
    pub authority_fence: RegistryAdmissionFenceV1,
    pub job_hash: ObjectHash,
    pub exact_job: Vec<u8>,
    pub event_hash: ObjectHash,
    pub targets: Vec<(ea_types::EntryHash, u64, ObjectHash)>,
    pub component_certificate: CertificateHash,
}
#[non_exhaustive]
pub struct ServerRemovalMeasurement {
    pub attestation: ea_destruction::VerifiedDeletionAttestation,
    pub stubs: Vec<IndexedObjectV1>,
    pub measured_at: ea_types::UnixMillis,
}

/// Lifetime of a storage mutation fence; the backing transaction rolls back on Drop.
pub trait ObjectWriteGuard: Send + Sync {}

#[non_exhaustive]
pub struct DestructionAttestationCommand {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub destruction_id: DestructionId,
    pub expected_chain_head: ChainHeadStateV1,
    pub authority_fence: RegistryAdmissionFenceV1,
    pub job_hash: ObjectHash,
    pub principal: CertificateHash,
    pub expected_events: Vec<ObjectHash>,
    pub expected_attestations: Vec<ObjectHash>,
    pub attestation: ea_destruction::VerifiedDeletionAttestation,
}
/// Pure evidence intake. The COSE signer is checked in the immutable original
/// authorization context; only the HTTP controller needs current authority.
pub async fn accept_attestation(
    org: OrganizationId,
    principal: CertificateHash,
    id: DestructionId,
    exact: &[u8],
    ports: &DestructionPorts<'_>,
) -> Result<DestructionStatusResponseV1, Error> {
    let status = destruction_status(org, id, ports).await?;
    let job = load_job(org, id, ports).await?;
    let auth = job.authorization();
    let original = ports
        .heads
        .historical_registry_authority(
            org,
            auth.fields().registry_version,
            ObjectHash::from(auth.fields().registry_head_hash),
            ChainSequence::new(auth.fields().authorization_sequence),
        )
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    let now = ports.clock.now();
    let incoming = ea_destruction::verify_attestation_historical(exact, auth, &original, now)
        .map_err(|_| Error::AuthorizationUnverifiable)?;

    let core = ea_crypto::decode_destruction_preflight_core(job.core_bytes())?;
    let frozen = ports
        .destructions
        .frozen_destruction_object_hashes(org, id)
        .await?;
    if incoming.fields().executed_at.get() < core.observed_effective_now
        || incoming
            .fields()
            .removed_object_hashes
            .iter()
            .any(|hash| !job.removal_object_hashes().contains(hash) && !frozen.contains(hash))
    {
        return Err(Error::Conflict);
    }
    let mut all = Vec::new();
    for record in status.attestations() {
        all.push(
            ea_destruction::verify_attestation_historical(
                record.exact_object_bytes(),
                auth,
                &original,
                now,
            )
            .map_err(|_| Error::AuthorizationUnverifiable)?,
        );
    }
    all.push(incoming.clone());
    ea_destruction::project_imported_evidence(&job, &all).map_err(|_| Error::Conflict)?;
    let progress = ports
        .chain_heads
        .committed_chain_head(org, job.chain_id())
        .await?
        .ok_or(Error::Conflict)?;
    let next = ChainSequence::new(
        progress
            .sequence
            .get()
            .checked_add(1)
            .ok_or(Error::Conflict)?,
    );
    let current = ports
        .heads
        .select_current_admission(org, next, now)
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    let controller = original
        .active_certificate_fields(principal)
        .ok_or(Error::AuthorizationUnverifiable)?;
    if controller.certificate_kind != ea_format::CertificateKindV1::DeletionAttest
        || !controller
            .capabilities
            .iter()
            .any(|c| c == "deletionAttest")
        || !current
            .head
            .active_certificates()
            .iter()
            .any(|(h, c)| *h == principal && *c == controller)
    {
        return Err(Error::AuthorizationUnverifiable);
    }
    // Historical evidence may still be preserved while new destruction is
    // disabled; no new physical operation or transition is authorized here.
    if status
        .attestations()
        .iter()
        .any(|r| r.object_hash() == incoming.object_hash() && r.exact_object_bytes() == exact)
    {
        return Ok(status);
    }
    let staged = ports
        .objects
        .stage_stream(
            ObjectTypeV1::Trust,
            aws_sdk_s3::primitives::ByteStream::from(exact.to_vec()),
            ea_format::ETB_MAX_RAW_BYTES_V1 as u64,
        )
        .await?;
    let stored = ports.objects.put_if_absent(staged).await?;
    let reread = read(ports, stored.object_hash()).await?;
    if stored.object_hash() != incoming.object_hash() || reread != exact {
        return Err(Error::Conflict);
    }
    let command = DestructionAttestationCommand {
        organization_id: org,
        chain_id: job.chain_id(),
        destruction_id: id,
        expected_chain_head: progress,
        authority_fence: current.fence,
        job_hash: job.job_hash(),
        principal,
        expected_events: status
            .transitions()
            .iter()
            .map(|r| r.object_hash())
            .collect(),
        expected_attestations: status
            .attestations()
            .iter()
            .map(|r| r.object_hash())
            .collect(),
        attestation: incoming,
    };
    match ports
        .destructions
        .record_replica_attestation(command, ports.clock)
        .await?
    {
        AppendOutcome::Recorded | AppendOutcome::AlreadyRecorded => {}
        AppendOutcome::Conflict => return Err(Error::Conflict),
    }
    destruction_status(org, id, ports).await
}

/// Reconstruct the technical state hint from exact signatures before exposing
/// it. An initial reservation is not itself an executing state.
pub(crate) async fn verify_stored_history(
    org: OrganizationId,
    id: DestructionId,
    saved: &crate::DestructionStateV1,
    transitions: &[ea_sync_protocol::ObjectRecordV1],
    attestations: &[ea_sync_protocol::ObjectRecordV1],
    ports: &DestructionPorts<'_>,
) -> Result<(), Error> {
    if transitions.is_empty() && attestations.is_empty() {
        return if saved.state == 0 {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    let bytes = read(ports, saved.authorization_object_hash).await?;
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&bytes)? else {
        return Err(Error::AuthorizationInvalid);
    };
    let DecodedTrustPayloadV1::DestructionAuthorization(fields) =
        parsed.value().decoded_payload()?
    else {
        return Err(Error::AuthorizationInvalid);
    };
    let historical = ports
        .heads
        .historical_registry_authority(
            org,
            fields.registry_version,
            ObjectHash::from(fields.registry_head_hash),
            ChainSequence::new(fields.authorization_sequence),
        )
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    let auth = verify_authorization_historical(&bytes, &historical)
        .map_err(|_| Error::AuthorizationUnverifiable)?;
    let now = ports.clock.now();
    let events = transitions
        .iter()
        .map(|r| {
            verify_event_historical(r.exact_object_bytes(), &auth, &historical, now)
                .map_err(|_| Error::AuthorizationUnverifiable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let claims = attestations
        .iter()
        .map(|r| {
            ea_destruction::verify_attestation_historical(
                r.exact_object_bytes(),
                &auth,
                &historical,
                now,
            )
            .map_err(|_| Error::AuthorizationUnverifiable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(stored) = ports.destructions.destruction_job(org, id).await? {
        let upload = ea_sync_protocol::DestructionJobUploadV1::decode(&stored.exact_upload)
            .map_err(|_| Error::Conflict)?;
        let (job, _) = verify_job(org, &upload, ports).await?;
        // Claims may arrive before the first requested event; they confer no
        // permission to execute and do not create a transition.
        if events.is_empty() {
            ea_destruction::project_imported_evidence(&job, &claims)
                .map_err(|_| Error::Conflict)?;
            if saved.state != 0 {
                return Err(Error::Conflict);
            }
        } else {
            let rebuilt = ea_destruction::reconstruct_imported_history(&job, &events, &claims)
                .map_err(|_| Error::Conflict)?;
            if rebuilt.state().code() != saved.state {
                return Err(Error::Conflict);
            }
            if saved.state == 3 {
                let complete = events
                    .iter()
                    .find(|e| e.fields().to_state == 3)
                    .ok_or(Error::Conflict)?;
                if !ports
                    .destructions
                    .server_removal_measured(org, id, complete.fields().executed_at)
                    .await?
                {
                    return Err(Error::Conflict);
                }
            }
        }
    } else {
        if !claims.is_empty()
            || saved.state != 0
            || events.len() != 1
            || events[0].fields().to_state != 0
        {
            return Err(Error::Conflict);
        }
        let mut machine = DestructionStateMachine::new(&auth);
        machine.apply(&events[0]).map_err(|_| Error::Conflict)?;
    }
    Ok(())
}
