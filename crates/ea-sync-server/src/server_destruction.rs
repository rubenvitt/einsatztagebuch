//! Current server execution; the signed immutable job remains resume authority.
use crate::{
    ServerSigner,
    destruction::{DestructionError as Error, DestructionPorts, destruction_status},
    managed_destruction::*,
};
use ea_crypto::object_hash;
use ea_format::{CertificateKindV1, DeletionAttestationFieldsV1, ObjectTypeV1, TrustPayloadV1};
use ea_types::{CertificateHash, ChainSequence, DestructionId, OrganizationId};
pub async fn execute_server(
    org: OrganizationId,
    id: DestructionId,
    principal: CertificateHash,
    component: &dyn ServerDeletionComponent,
    receipt: &dyn ServerSigner,
    ports: &DestructionPorts<'_>,
) -> Result<ea_sync_protocol::DestructionStatusResponseV1, Error> {
    let job = load_job(org, id, ports).await?;
    let core = ea_crypto::decode_destruction_preflight_core(job.core_bytes())?;
    let auth = job.authorization();
    let historical = ports
        .heads
        .historical_registry_authority(
            org,
            auth.fields().registry_version,
            ea_types::ObjectHash::from(auth.fields().registry_head_hash),
            ChainSequence::new(auth.fields().authorization_sequence),
        )
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    let status = destruction_status(org, id, ports).await?;
    let mut events = Vec::new();
    let mut attestations = Vec::new();
    for record in status.transitions() {
        events.push(
            ea_destruction::verify_event_historical(
                record.exact_object_bytes(),
                auth,
                &historical,
                ports.clock.now(),
            )
            .map_err(|_| Error::AuthorizationUnverifiable)?,
        );
    }
    for record in status.attestations() {
        attestations.push(
            ea_destruction::verify_attestation_historical(
                record.exact_object_bytes(),
                auth,
                &historical,
                ports.clock.now(),
            )
            .map_err(|_| Error::AuthorizationUnverifiable)?,
        );
    }
    let reconstructed = ea_destruction::reconstruct_imported_history(&job, &events, &attestations)
        .map_err(|_| Error::Conflict)?;
    if !matches!(reconstructed.state().code(), 1 | 2 | 4)
        || !events.iter().any(|e| e.fields().to_state == 1)
    {
        return Err(Error::Conflict);
    }
    // design.md §16.3: "Kein Schritt darf fuer ein blosz erneut gesendetes
    // Ereignis zweimal ausgefuehrt ... werden." Derselbe Vorgang kommt bei
    // jedem Fortsetzen erneut an — als exakter Job-POST oder als erneut
    // gesendetes Ereignis. Sobald die eigene dauerhafte Messung dieses
    // Servers Ergebnis 0 ueber den vollstaendig entfernten eingefrorenen
    // Bestand meldet, traegt eine weitere Ausfuehrung keine neue Information:
    // sie liefe ueber denselben Bestand, faende dasselbe Nichts und
    // unterschriebe eine zweite Attestierung derselben Tatsache.
    // Der eingefrorene Bestand ist unveraenderlich, deshalb ist das eine
    // Eigenschaft des Vorgangs, nicht nur des einzelnen `event_hash`, den die
    // Messzeile mitfuehrt. Gemessen wird weiterhin neu, solange keine Messung
    // vorliegt, die letzte gescheitert ist oder ihr Ergebnis 1/2 einen Rest
    // ausweist — genau die gewollten Neumessungen in Zustand 2 und 4.
    // :1557 (append-only) bleibt unberuehrt: nichts wird umgeschrieben,
    // es wird nur nichts Neues geschrieben. Geprueft wird genau das
    // Praedikat, das `accept_event` schon heute fuer `completeManagedScope`
    // verlangt: der Server misst, solange und nur solange seine eigene
    // physische Pflicht nicht nachweislich erfuellt ist.
    if ports
        .destructions
        .server_removal_measured(org, id, ports.clock.now())
        .await?
    {
        return destruction_status(org, id, ports).await;
    }
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
    let now = ports.clock.now();
    let current = ports
        .heads
        .select_current_admission(org, next, now)
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    let fields = historical
        .active_certificate_fields(component.certificate_hash())
        .ok_or(Error::AuthorizationUnverifiable)?;
    let active = current.head.active_certificates();
    let receipt_fields = active
        .iter()
        .find(|(h, _)| *h == receipt.certificate_hash())
        .map(|(_, f)| *f)
        .ok_or(Error::AuthorizationUnverifiable)?;
    let controller = historical
        .active_certificate_fields(principal)
        .ok_or(Error::AuthorizationUnverifiable)?;
    if fields.certificate_kind != CertificateKindV1::DeletionAttest
        || !fields.capabilities.iter().any(|c| c == "deletionAttest")
        || fields.organization_id != org
        || fields.signing_key_thumbprint != Some(component.public_key().thumbprint())
        || fields.signing_public_cose_key.as_deref()
            != Some(component.public_key().to_deterministic_cbor().as_slice())
        || !active
            .iter()
            .any(|(h, f)| *h == component.certificate_hash() && *f == fields)
        || !active.iter().any(|(h, f)| {
            *h == principal
                && *f == controller
                && f.certificate_kind == CertificateKindV1::DeletionAttest
        })
        || receipt_fields.certificate_kind != CertificateKindV1::ServerReceipt
        || receipt_fields.signing_key_thumbprint != Some(receipt.key_thumbprint())
        || receipt_fields.device_id != fields.device_id
        || receipt.certificate_hash() == component.certificate_hash()
        || receipt.key_thumbprint() == component.public_key().thumbprint()
        || !job
            .replicas()
            .iter()
            .any(|(_, d, k)| *d == fields.device_id && *k == 6)
        || core.observed_effective_now > now.get()
    {
        return Err(Error::AuthorizationUnverifiable);
    }
    let policy = &current.head.policy_fields().retention_policy;
    if !policy.destruction_enabled || policy.eds_privacy_decision_document_hash.is_none() {
        return Err(Error::PrivacyGate);
    }
    let fence = current.fence.clone();
    let command = ServerExecutionCommand {
        controller_certificate: principal,
        organization_id: org,
        chain_id: job.chain_id(),
        destruction_id: id,
        expected_chain_head: progress,
        authority_fence: current.fence,
        job_hash: job.job_hash(),
        exact_job: job.exact_upload().to_vec(),
        event_hash: reconstructed.last_event_hash(),
        targets: job
            .targets()
            .iter()
            .map(|t| (t.entry_hash(), t.sequence().get(), t.original_object_hash()))
            .collect(),
        component_certificate: component.certificate_hash(),
    };
    let guard = ports.destructions.begin_managed_execution(command).await?;
    let removal_window = ServerRemovalWindow {
        selected_at: fence.selected_at,
        not_after: fence.not_after,
    };
    let check_time = || {
        let time = ports.clock.now();
        if time < fence.selected_at || time > fence.not_after {
            Err(Error::AuthorizationUnverifiable)
        } else {
            Ok(time)
        }
    };
    check_time()?;
    let target_hashes = job
        .targets()
        .iter()
        .map(|t| t.entry_hash())
        .collect::<Vec<_>>();
    let known = guard.objects().iter().map(|o| o.object).collect::<Vec<_>>();
    ports
        .objects
        .verify_destruction_scope(&target_hashes, &known)
        .await?;
    // Save and independently reread each exact stub before removing ciphertext.
    let mut stubs = Vec::new();
    for target in job.targets() {
        let exact = target.exact_stub_bytes();
        let staged = ports
            .objects
            .stage_stream(
                ObjectTypeV1::Destroyed,
                aws_sdk_s3::primitives::ByteStream::from(exact.to_vec()),
                ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1 as u64,
            )
            .await?;
        check_time()?;
        let stored = ports.objects.put_if_absent(staged).await?;
        let reread = ports
            .objects
            .get_exact_in(ObjectTypeV1::Destroyed, stored.object_hash())
            .await?
            .collect()
            .await
            .map_err(|_| Error::DependencyUnavailable)?
            .into_bytes();
        if stored.object_hash() != object_hash(exact) || reread.as_ref() != exact {
            return Err(Error::Conflict);
        }
        check_time()?;
        stubs.push(crate::IndexedObjectV1 {
            kind: ObjectTypeV1::Destroyed,
            object_hash: stored.object_hash(),
            size_bytes: stored.size_bytes(),
        });
    }
    let mut removed = Vec::new();
    let mut pending_deadline = None;
    let mut unresolved = false;
    for object in guard.objects() {
        check_time()?;
        let mut current = ports
            .objects
            .remaining_destruction_versions(object.object.kind, object.object.object_hash)
            .await?;
        let same_generation = |v: &StoredObjectVersion, old: &StoredObjectVersion| {
            v.storage_key == old.storage_key
                && v.version_id == old.version_id
                && v.delete_marker == old.delete_marker
        };
        if current
            .iter()
            .any(|v| !object.versions.iter().any(|old| same_generation(v, old)))
        {
            return Err(Error::Conflict);
        }
        current.sort_by_key(|v| !v.delete_marker);
        for version in current {
            let now = check_time()?;
            let original = object
                .versions
                .iter()
                .find(|old| same_generation(&version, old))
                .ok_or(Error::Conflict)?;
            let deadline = std::cmp::max(version.retained_until, original.retained_until);
            if version.legal_hold {
                unresolved = true;
                continue;
            }
            if let Some(deadline) = deadline.filter(|time| *time > now) {
                pending_deadline = std::cmp::max(pending_deadline, Some(deadline));
                continue;
            }
            ports
                .objects
                .remove_destruction_version(
                    object.object.kind,
                    object.object.object_hash,
                    &version,
                    &removal_window,
                )
                .await?;
        }
        let remaining = ports
            .objects
            .remaining_destruction_versions(object.object.kind, object.object.object_hash)
            .await?;
        if remaining.is_empty() {
            removed.push(object.object.object_hash);
        } else {
            // Re-observe every remaining generation; no unmeasured remainder
            // can be represented merely by the passage of a deadline.
            for version in remaining {
                let original = object
                    .versions
                    .iter()
                    .find(|old| same_generation(&version, old))
                    .ok_or(Error::Conflict)?;
                if version.legal_hold {
                    unresolved = true;
                } else if let Some(deadline) =
                    std::cmp::max(version.retained_until, original.retained_until)
                        .filter(|t| *t > ports.clock.now())
                {
                    pending_deadline = std::cmp::max(pending_deadline, Some(deadline));
                } else {
                    return Err(Error::Conflict);
                }
            }
        }
    }
    ports
        .objects
        .verify_destruction_scope(&target_hashes, &known)
        .await?;
    // A stub becomes discoverable only after its exact original EIP was
    // actually removed; the provider copy was safely written beforehand.
    stubs.retain(|stub| {
        job.targets().iter().any(|target| {
            object_hash(target.exact_stub_bytes()) == stub.object_hash
                && removed.contains(&target.original_object_hash())
        })
    });
    let result = if unresolved {
        2
    } else if pending_deadline.is_some() {
        1
    } else {
        0
    };
    let backup_expiry_at = if result == 1 { pending_deadline } else { None };
    removed.sort();
    removed.dedup();
    let measured_at = check_time()?;
    // Locks still protect the catalog/progress. Re-select with the actual clock
    // to detect a known time-triggered successor before signing any new claim.
    let after = ports
        .heads
        .select_current_admission(org, next, measured_at)
        .await?
        .ok_or(Error::AuthorizationUnverifiable)?;
    if after.head.registry_head_hash() != current.head.registry_head_hash()
        || after.fence.catalog_revision != fence.catalog_revision
        || !after
            .head
            .active_certificates()
            .iter()
            .any(|(h, f)| *h == component.certificate_hash() && *f == fields)
    {
        return Err(Error::AuthorizationUnverifiable);
    }
    let payload = TrustPayloadV1::deletion_attestation(DeletionAttestationFieldsV1 {
        destruction_id: id,
        destruction_authorization_object_hash: auth.object_hash(),
        replica_id: *fields.device_id.as_bytes(),
        replica_kind: 2,
        removed_object_hashes: removed,
        result,
        backup_expiry_at,
        executed_at: measured_at,
    })?;
    let request = ServerAttestationRequest {
        authorization: auth.clone(),
        payload,
    };
    let signature = component.sign_attestation(&request)?;
    let exact = ea_format::encode_trust(&ea_format::TrustObjectV1::new(
        request.payload,
        vec![signature],
    )?)?
    .into_vec();
    let attestation =
        ea_destruction::verify_attestation_historical(&exact, auth, &historical, check_time()?)
            .map_err(|_| Error::AuthorizationUnverifiable)?;
    attestations.push(attestation.clone());
    ea_destruction::project_imported_evidence(&job, &attestations).map_err(|_| Error::Conflict)?;
    let staged = ports
        .objects
        .stage_stream(
            ObjectTypeV1::Trust,
            aws_sdk_s3::primitives::ByteStream::from(exact.clone()),
            ea_format::ETB_MAX_RAW_BYTES_V1 as u64,
        )
        .await?;
    let stored = ports.objects.put_if_absent(staged).await?;
    let read = ports
        .objects
        .get_exact_in(ObjectTypeV1::Trust, stored.object_hash())
        .await?
        .collect()
        .await
        .map_err(|_| Error::DependencyUnavailable)?
        .into_bytes();
    if read.as_ref() != exact || stored.object_hash() != attestation.object_hash() {
        return Err(Error::Conflict);
    }
    check_time()?;
    guard
        .finish(
            ServerRemovalMeasurement {
                attestation,
                stubs,
                measured_at,
            },
            ports.clock,
        )
        .await?;
    destruction_status(org, id, ports).await
}
