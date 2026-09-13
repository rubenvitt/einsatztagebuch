//! Read-only projection from authenticated job scope and exact signed claims.
mod publication;
use crate::{
    DestructionError as Error, DestructionExecutionContext, DurableDestructionStart,
    SqliteDestructionJobs, VerifiedDeletionAttestation, VerifiedImportedPreflight,
};
use crate::{ManagedReplicaKind, VerifiedDestructionAuthorization};
use ea_crypto::object_hash;
use ea_types::{
    ChainId, ChainSequence, DestructionId, DeviceId, EntryHash, ObjectHash, OrganizationId,
    UnixMillis,
};
use minicbor::Decoder;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum EvidenceReplicaStatus {
    Successful(ObjectHash),
    PendingBackup,
    Unreachable,
}
pub struct ReconstructedDestruction {
    state: crate::DestructionState,
    last: ObjectHash,
    evidence: VerifiedDestructionEvidence,
}
impl ReconstructedDestruction {
    pub const fn state(&self) -> crate::DestructionState {
        self.state
    }
    pub const fn last_event_hash(&self) -> ObjectHash {
        self.last
    }
    pub fn evidence(&self) -> &VerifiedDestructionEvidence {
        &self.evidence
    }
}
pub fn reconstruct_imported_history(
    job: &VerifiedImportedPreflight,
    events: &[crate::VerifiedDestructionEvent],
    attestations: &[VerifiedDeletionAttestation],
) -> Result<ReconstructedDestruction, Error> {
    let preflight_time =
        ea_crypto::decode_destruction_preflight_core(job.core_bytes())?.observed_effective_now;
    let mut unique = BTreeMap::new();
    let mut following = BTreeMap::new();
    for event in events {
        if let Some(old) = unique.insert(event.object_hash(), event) {
            if old.exact_bytes() != event.exact_bytes() {
                return Err(Error::SecurityConflict);
            }
            continue;
        }
        if following
            .insert(
                event.fields().previous_event_object_hash,
                event.object_hash(),
            )
            .is_some()
        {
            return Err(Error::SecurityConflict);
        }
    }
    let at = |time: UnixMillis| {
        let available = attestations
            .iter()
            .filter(|a| a.fields().executed_at <= time)
            .cloned()
            .collect::<Vec<_>>();
        project_imported_evidence(job, &available)
    };
    let mut machine = crate::DestructionStateMachine::new(job.authorization());
    let mut previous = None;
    let mut seen = 0;
    while let Some(hash) = following.get(&previous) {
        let event = unique.get(hash).ok_or(Error::Event)?;
        let fields = event.fields();
        let evidence = at(fields.executed_at)?;
        match fields.to_state {
            1 => {
                if fields.executed_at.get() < preflight_time {
                    return Err(Error::Event);
                }
                // A verified historical retry attests its trigger. Claim
                // execution times cannot reconstruct when originals arrived;
                // actual resumption still needs fresh executor-side evidence.
            }
            2 => {
                // A retained Pending result does not prove that its immutable
                // deadline still runs at this event. Preserve every previously
                // attested maximum; later-executed claims cannot justify it.
                let mut deadlines = BTreeMap::new();
                for attestation in attestations {
                    let claim = attestation.fields();
                    if claim.executed_at <= fields.executed_at
                        && let Some(expiry) = claim.backup_expiry_at
                    {
                        deadlines
                            .entry(claim.replica_id)
                            .and_modify(|old: &mut UnixMillis| *old = (*old).max(expiry))
                            .or_insert(expiry);
                    }
                }
                if !evidence
                    .replicas
                    .iter()
                    .any(|(_, s)| *s == EvidenceReplicaStatus::PendingBackup)
                    || evidence
                        .replicas
                        .iter()
                        .any(|(_, s)| *s == EvidenceReplicaStatus::Unreachable)
                    || evidence.replicas.iter().any(|(device, status)| {
                        *status == EvidenceReplicaStatus::PendingBackup
                            && deadlines
                                .get(device.as_bytes())
                                .is_none_or(|expiry| *expiry <= fields.executed_at)
                    })
                {
                    return Err(Error::Event);
                }
            }
            3 => {
                if !evidence.complete {
                    return Err(Error::Event);
                }
            }
            // Later delivery may add an older successful claim. It cannot
            // erase an authentic conservative failure in the signed history.
            // This grants no execution capability or missing removal evidence.
            4 => {}
            0 => {}
            _ => return Err(Error::Event),
        }
        machine.apply(event)?;
        seen += 1;
        previous = Some(*hash);
    }
    if seen != unique.len() || seen == 0 {
        return Err(Error::SecurityConflict);
    }
    Ok(ReconstructedDestruction {
        state: machine.state().ok_or(Error::Event)?,
        last: machine.last_event_hash().ok_or(Error::Event)?,
        evidence: project_imported_evidence(job, attestations)?,
    })
}
#[derive(Clone)]
pub struct VerifiedDestructionEvidence {
    organization: OrganizationId,
    chain: ChainId,
    destruction: DestructionId,
    confirmed: Vec<EntryHash>,
    replicas: Vec<(DeviceId, EvidenceReplicaStatus)>,
    complete: bool,
    authorization: ObjectHash,
    scope: u64,
    targets: Vec<(EntryHash, ChainSequence, ObjectHash)>,
    observed: UnixMillis,
    job: Option<ObjectHash>,
    fence: Option<(
        Arc<ea_local_store::EncryptedDatabase>,
        crate::DurableManagedInventory,
    )>,
}
impl VerifiedDestructionEvidence {
    /// Pseudonymous local routing to the already authenticated immutable job.
    /// This reference cannot sign, authorize or replace the native proof.
    pub fn draft_source(&self) -> Result<ea_draft::EvidenceDraftSource, Error> {
        Ok(ea_draft::EvidenceDraftSource::new(
            self.organization,
            self.destruction,
            self.authorization,
            self.job.ok_or(Error::Storage)?,
        ))
    }

    pub const fn organization_id(&self) -> OrganizationId {
        self.organization
    }
    pub const fn chain_id(&self) -> ChainId {
        self.chain
    }
    pub const fn destruction_id(&self) -> DestructionId {
        self.destruction
    }
    pub fn confirmed_entries(&self) -> &[EntryHash] {
        &self.confirmed
    }
    pub fn replicas(&self) -> &[(DeviceId, EvidenceReplicaStatus)] {
        &self.replicas
    }
    pub const fn all_managed_replicas_confirmed(&self) -> bool {
        self.complete
    }
    pub fn validate_archive(&self, source: &dyn ea_archive::ArchiveSource) -> Result<(), Error> {
        let inventory = ea_archive::ArchiveInventory::build(source).map_err(|_| Error::Storage)?;
        if !inventory.format_errors().is_empty() {
            return Err(Error::Format);
        }
        for (entry, _, stub) in &self.targets {
            if !inventory.destroyed().iter().any(|object| {
                object.value().entry_hash() == *entry && object.object_hash() == *stub
            }) || inventory
                .entries()
                .iter()
                .any(|object| object.value().entry_hash() == *entry)
                || inventory
                    .grants()
                    .iter()
                    .any(|object| object.value().grant_body().fields().entry_hash == *entry)
            {
                return Err(Error::Target);
            }
        }
        Ok(())
    }
    /// Actual holdings, including bytes omitted by the committed chain source.
    /// Writer holds its backend lock and checks this before any publication.
    pub fn validate_managed_archive(
        &self,
        backend: &dyn ea_archive::ArchiveBackend,
    ) -> Result<(), Error> {
        require_no_managed_target_bytes(
            backend,
            &self.targets.iter().map(|(entry, _, _)| *entry).collect(),
        )
    }
    pub fn validate_for_writer(
        &self,
        organization: OrganizationId,
        chain: ChainId,
        sequence: ChainSequence,
        now: UnixMillis,
    ) -> Result<(), Error> {
        if self.organization != organization
            || self.chain != chain
            || self.observed > now
            || self
                .targets
                .iter()
                .any(|(_, target, _)| *target >= sequence)
        {
            return Err(Error::Target);
        }
        let (database, custody) = self.fence.as_ref().ok_or(Error::Storage)?;
        database.transaction(|tx| crate::inventory::require_unchanged_in(tx, custody))
    }
    /// Only existing schema fields are produced; the normal Writer supplies
    /// its verified current header and publication pipeline.
    pub fn into_payload(
        self,
        header: ea_schema::CommonHeaderV1,
    ) -> Result<ea_schema::DestructionEvidenceV1, Error> {
        if header.operator().organization_id() != self.organization
            || header.finalized_at_device() < self.observed
        {
            return Err(Error::Target);
        }
        ea_schema::DestructionEvidenceV1::new(
            header,
            self.destruction,
            self.authorization,
            self.scope,
            self.targets
                .iter()
                .map(|(entry, seq, _)| ea_schema::DestructionTargetV1::new(*entry, *seq))
                .collect(),
            self.targets
                .iter()
                .map(|(entry, _, _)| {
                    let confirmed = self.confirmed.contains(entry);
                    ea_schema::DestructionExecutionResultV1::new(
                        *entry,
                        confirmed,
                        if confirmed { 0 } else { 2 },
                    )
                })
                .collect(),
            self.targets
                .iter()
                .map(|(entry, _, stub)| ea_schema::DestructionStubBindingV1::new(*entry, *stub))
                .collect(),
            self.replicas
                .iter()
                .map(|(device, state)| {
                    let id = ea_types::Id16::try_from(device.as_bytes().as_slice())
                        .expect("fixed DeviceId width");
                    match state {
                        EvidenceReplicaStatus::Successful(hash) => {
                            ea_schema::ReplicaResultV1::successful(id, *hash)
                        }
                        EvidenceReplicaStatus::PendingBackup => {
                            ea_schema::ReplicaResultV1::pending(id)
                        }
                        EvidenceReplicaStatus::Unreachable => {
                            ea_schema::ReplicaResultV1::unreachable(id)
                        }
                    }
                })
                .collect(),
        )
        .map_err(|_| Error::Format)
    }
}

fn require_no_managed_target_bytes(
    backend: &dyn ea_archive::ArchiveBackend,
    targets: &BTreeSet<EntryHash>,
) -> Result<(), Error> {
    let mut target_found = false;
    backend
        .visit_managed_blobs(&mut |blob| {
            let target = match ea_format::decode_exact_object(blob.bytes()) {
                Ok(ea_format::ParsedArchiveObject::Entry(entry)) => {
                    Some(entry.value().entry_hash())
                }
                Ok(ea_format::ParsedArchiveObject::Grant(grant)) => {
                    Some(grant.value().grant_body().fields().entry_hash)
                }
                Ok(_) | Err(ea_format::FormatError::Prefix) => None,
                // A malformed actual archive object is unresolved custody,
                // never affirmative proof that no target bytes remain.
                Err(_) => return Err(ea_archive::ArchiveError::Unavailable),
            };
            if target.is_some_and(|entry| targets.contains(&entry)) {
                target_found = true;
                return Err(ea_archive::ArchiveError::Unavailable);
            }
            Ok(())
        })
        .map_err(|_| {
            if target_found {
                Error::Target
            } else {
                Error::Storage
            }
        })
}
pub fn project_imported_evidence(
    job: &VerifiedImportedPreflight,
    attestations: &[VerifiedDeletionAttestation],
) -> Result<VerifiedDestructionEvidence, Error> {
    let targets = job
        .targets()
        .iter()
        .map(|t| {
            (
                t.entry_hash(),
                t.sequence(),
                t.original_object_hash(),
                object_hash(t.exact_stub_bytes()),
            )
        })
        .collect::<Vec<_>>();
    project(
        job.authorization(),
        job.chain_id(),
        job.custody_bytes(),
        &targets,
        attestations,
    )
}
impl SqliteDestructionJobs {
    pub fn project_evidence(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        start: &DurableDestructionStart,
        attestations: &[VerifiedDeletionAttestation],
    ) -> Result<VerifiedDestructionEvidence, Error> {
        let loaded = self
            .load(context.resumed, context.custody, context.trust)?
            .ok_or(Error::Storage)?;
        let auth = context.resumed.request().authorization();
        if start.job_hash() != object_hash(loaded.preflight().exact_core_bytes())
            || start.event().fields().destruction_authorization_object_hash != auth.object_hash()
        {
            return Err(Error::SecurityConflict);
        }
        let targets = loaded
            .preflight()
            .targets
            .iter()
            .map(|target| {
                let seq = auth
                    .fields()
                    .targets
                    .iter()
                    .find(|t| t.entry_hash() == target.entry.as_bytes())
                    .ok_or(Error::Target)?
                    .chain_sequence();
                Ok((
                    target.entry,
                    ChainSequence::new(seq),
                    target.original,
                    object_hash(target.stub.as_bytes()),
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut result = project(
            auth,
            context.resumed.current_head().chain_id(),
            context.custody.exact_bytes(),
            &targets,
            attestations,
        )?;
        if result.observed
            > context
                .resumed
                .current_head()
                .preexisting_effective_now()
                .value()
        {
            return Err(Error::Event);
        }
        result.observed = std::cmp::max(result.observed, start.event().fields().executed_at);
        result.fence = Some((self.database.clone(), context.custody.clone()));
        result.job = Some(start.job_hash());
        self.database
            .transaction(|tx| crate::inventory::require_unchanged_in(tx, context.custody))?;
        Ok(result)
    }
}

struct ReplicaObligation {
    kind: ManagedReplicaKind,
    hashes: BTreeSet<ObjectHash>,
}
fn obligations(exact: &[u8]) -> Result<BTreeMap<DeviceId, ReplicaObligation>, Error> {
    let mut d = Decoder::new(exact);
    d.array().map_err(|_| Error::Format)?;
    for _ in 0..5 {
        d.skip().map_err(|_| Error::Format)?;
    }
    let mut replicas: BTreeMap<DeviceId, ReplicaObligation> = BTreeMap::new();
    for _ in 0..d.array().map_err(|_| Error::Format)?.ok_or(Error::Format)? {
        let mut r = Decoder::new(d.bytes().map_err(|_| Error::Format)?);
        r.array().map_err(|_| Error::Format)?;
        let code = r.u8().map_err(|_| Error::Format)?;
        r.skip().map_err(|_| Error::Format)?;
        let device =
            DeviceId::try_from(r.bytes().map_err(|_| Error::Format)?).map_err(|_| Error::Format)?;
        let kind = match r.u8().map_err(|_| Error::Format)? {
            0 => ManagedReplicaKind::Writer,
            1 => ManagedReplicaKind::Reader,
            6 => ManagedReplicaKind::SyncServer,
            _ => return Err(Error::Format),
        };
        let obligation = replicas.entry(device).or_insert_with(|| ReplicaObligation {
            kind,
            hashes: BTreeSet::new(),
        });
        if obligation.kind != kind {
            return Err(Error::SecurityConflict);
        }
        if code == 2 {
            r.skip().map_err(|_| Error::Format)?;
            r.skip().map_err(|_| Error::Format)?;
            obligation.hashes.insert(
                ObjectHash::try_from(r.bytes().map_err(|_| Error::Format)?)
                    .map_err(|_| Error::Format)?,
            );
        }
    }
    if replicas.is_empty() {
        return Err(Error::Target);
    }
    Ok(replicas)
}
fn project(
    auth: &VerifiedDestructionAuthorization,
    chain: ChainId,
    custody: &[u8],
    targets: &[(EntryHash, ChainSequence, ObjectHash, ObjectHash)],
    attestations: &[VerifiedDeletionAttestation],
) -> Result<VerifiedDestructionEvidence, Error> {
    let expected = obligations(custody)?;
    let mut latest: BTreeMap<DeviceId, &VerifiedDeletionAttestation> = BTreeMap::new();
    // Later claims cannot erase or shorten an already attested retention bound.
    // Expiry alone is insufficient: removal must itself be attested at/after it.
    let mut backup_deadlines: BTreeMap<DeviceId, UnixMillis> = BTreeMap::new();
    let mut seen: BTreeMap<(DeviceId, UnixMillis), &[u8]> = BTreeMap::new();
    for attestation in attestations {
        let f = attestation.fields();
        if f.destruction_id != auth.fields().destruction_id
            || f.destruction_authorization_object_hash != auth.object_hash()
        {
            return Err(Error::SecurityConflict);
        }
        let device = DeviceId::try_from(f.replica_id.as_slice()).map_err(|_| Error::Format)?;
        let obligation = expected.get(&device).ok_or(Error::SecurityConflict)?;
        if f.replica_kind != obligation.kind.code()
            || f.result == 0
                && !obligation
                    .hashes
                    .is_subset(&f.removed_object_hashes.iter().copied().collect())
        {
            return Err(Error::SecurityConflict);
        }
        if let Some(expiry) = f.backup_expiry_at {
            backup_deadlines
                .entry(device)
                .and_modify(|old| *old = (*old).max(expiry))
                .or_insert(expiry);
        }
        // A newer first claim must not hide conflicting older originals.
        if seen
            .insert((device, f.executed_at), attestation.exact_bytes())
            .is_some_and(|old| old != attestation.exact_bytes())
        {
            return Err(Error::SecurityConflict);
        }
        if latest
            .get(&device)
            .is_some_and(|old| old.fields().executed_at > f.executed_at)
        {
            continue;
        }
        latest.insert(device, attestation);
    }
    let mut confirmed = BTreeSet::new();
    let mut replicas = Vec::new();
    let mut observed = UnixMillis::new(0);
    for device in expected.keys() {
        let state = if let Some(attestation) = latest.get(device) {
            let f = attestation.fields();
            observed = std::cmp::max(observed, f.executed_at);
            match f.result {
                0 if backup_deadlines
                    .get(device)
                    .is_some_and(|expiry| f.executed_at < *expiry) =>
                {
                    EvidenceReplicaStatus::PendingBackup
                }
                0 => {
                    for (entry, _, original, _) in targets {
                        if f.removed_object_hashes.contains(original) {
                            confirmed.insert(*entry);
                        }
                    }
                    EvidenceReplicaStatus::Successful(attestation.object_hash())
                }
                1 => EvidenceReplicaStatus::PendingBackup,
                2 => EvidenceReplicaStatus::Unreachable,
                _ => return Err(Error::Event),
            }
        } else {
            EvidenceReplicaStatus::Unreachable
        };
        replicas.push((*device, state));
    }
    let complete = confirmed.len() == targets.len()
        && replicas
            .iter()
            .all(|(_, s)| matches!(s, EvidenceReplicaStatus::Successful(_)));
    Ok(VerifiedDestructionEvidence {
        organization: auth.fields().organization_id,
        chain,
        destruction: auth.fields().destruction_id,
        authorization: auth.object_hash(),
        scope: auth.fields().scope_code,
        confirmed: confirmed.into_iter().collect(),
        replicas,
        complete,
        targets: targets
            .iter()
            .map(|(e, s, _, stub)| (*e, *s, *stub))
            .collect(),
        observed,
        fence: None,
        job: None,
    })
}
