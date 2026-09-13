//! Device-wide local measured attestation, separate from global completion.
use crate::{
    DestructionError as Error, DestructionExecutionContext, DestructionRequestService,
    DurableDestructionStart, LocalDestructionExecution, SqliteDestructionJobs,
    VerifiedDeletionAttestation,
};
use ea_archive::ArchiveBackend;
use ea_crypto::object_hash;
use ea_format::{
    CertificateKindV1, DeletionAttestationFieldsV1, TrustObjectV1, TrustPayloadV1, encode_trust,
};
use ea_local_store::StoreValue;
use ea_operator::OperatorSessionProof;
use ea_types::{DeviceId, ObjectHash};
use minicbor::Decoder;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAttestationCheckpoint {
    LocationsMeasured,
    AcquisitionCompacted,
    Signed,
    BeforeStore,
    Stored,
}
impl SqliteDestructionJobs {
    pub fn attest_local_replica(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        start: &DurableDestructionStart,
        native: &DestructionRequestService<'_>,
        proof: &OperatorSessionProof,
        locations: &[LocalDestructionExecution<'_>],
    ) -> Result<VerifiedDeletionAttestation, Error> {
        self.attest_local_replica_with_progress(
            context,
            start,
            native,
            proof,
            locations,
            &mut |_| Ok(()),
        )
    }
    /// Cancellation/fault observation only. It never establishes authority.
    pub fn attest_local_replica_with_progress(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        start: &DurableDestructionStart,
        native: &DestructionRequestService<'_>,
        proof: &OperatorSessionProof,
        locations: &[LocalDestructionExecution<'_>],
        progress: &mut dyn FnMut(LocalAttestationCheckpoint) -> Result<(), Error>,
    ) -> Result<VerifiedDeletionAttestation, Error> {
        self.attest_local_replica_guarded(
            context,
            start,
            native,
            proof,
            locations,
            progress,
            &mut crate::local::NoAdditionalAuthorityGuard,
        )
    }
    // Preserve the existing typed action arguments; the additional guard only refuses.
    #[allow(clippy::too_many_arguments)]
    pub fn attest_local_replica_guarded(
        &self,
        context: &DestructionExecutionContext<'_, '_>,
        start: &DurableDestructionStart,
        native: &DestructionRequestService<'_>,
        proof: &OperatorSessionProof,
        locations: &[LocalDestructionExecution<'_>],
        progress: &mut dyn FnMut(LocalAttestationCheckpoint) -> Result<(), Error>,
        guard: &mut dyn crate::LocalActionAuthorityGuard,
    ) -> Result<VerifiedDeletionAttestation, Error> {
        let first = locations.first().ok_or(Error::Target)?;
        let resumed = native.resume_original(
            context.resumed.request().authorization(),
            context.resumed.authorization_head(),
            proof,
        )?;
        let device = resumed
            .current_head()
            .active_certificate_fields(first.component_certificate)
            .ok_or(Error::Signature)?
            .device_id;
        let expected_locations = registered_locations(context.custody.exact_bytes(), device)?;
        let mut ordered = BTreeMap::new();
        for local in locations {
            if resumed
                .current_head()
                .active_certificate_fields(local.component_certificate)
                .ok_or(Error::Signature)?
                .device_id
                != device
            {
                return Err(Error::Signature);
            }
            let location = crate::local::location_id(local.backend)?;
            let profile = local.backend.profile_hash().map_err(|_| Error::Storage)?;
            if ordered.insert((profile, location), local).is_some() {
                return Err(Error::SecurityConflict);
            }
        }
        if ordered.keys().copied().collect::<BTreeSet<_>>() != expected_locations {
            return Err(Error::SecurityConflict);
        }
        let mut removed = BTreeSet::new();
        for local in ordered.values() {
            let measurement = self.execute_local_guarded(
                context,
                start,
                native,
                proof,
                local,
                &mut |_| Ok(()),
                guard,
            )?;
            removed.extend(measurement.removed_object_hashes().iter().copied());
        }
        progress(LocalAttestationCheckpoint::LocationsMeasured)?;
        // The acquisition ledger is per native database/job. Preserve the
        // original measurement's chosen local location on exact retries.
        let purge_location = if let Some(row) = self.database.query_row(
            "SELECT exact_measurement FROM destruction_acquisition_purge WHERE job_hash=?1",
            &[blob(start.job_hash().as_bytes())],
        )? {
            let mut d = Decoder::new(row.blob(0)?);
            d.array().map_err(|_| Error::Format)?;
            d.skip().map_err(|_| Error::Format)?;
            d.skip().map_err(|_| Error::Format)?;
            let location = ObjectHash::try_from(d.bytes().map_err(|_| Error::Format)?)
                .map_err(|_| Error::Format)?;
            *ordered
                .iter()
                .find(|((_, id), _)| *id == location)
                .ok_or(Error::SecurityConflict)?
                .1
        } else {
            first
        };
        let purge = self.purge_local_acquisition_guarded(
            context,
            start,
            native,
            proof,
            purge_location,
            &mut |_| Ok(()),
            guard,
        )?;
        progress(LocalAttestationCheckpoint::AcquisitionCompacted)?;
        guard.check_before_effect()?;
        let auth = resumed.request().authorization();
        let historical = ea_trust::verify_historical_registry_authority(
            context.trust,
            auth.fields().registry_version,
            ObjectHash::try_from(auth.fields().registry_head_hash.as_bytes().as_slice())
                .map_err(|_| Error::Registry)?,
            ea_types::ChainSequence::new(auth.fields().authorization_sequence),
        )
        .map_err(|_| Error::Registry)?;
        let key = [blob(start.job_hash().as_bytes()), blob(device.as_bytes())];
        let existing=self.database.query_row("SELECT exact_attestation FROM destruction_local_attestation WHERE job_hash=?1 AND replica_id=?2",&key)?;
        let exact = if let Some(row) = existing {
            row.blob(0)?.to_vec()
        } else {
            let payload = TrustPayloadV1::deletion_attestation(DeletionAttestationFieldsV1 {
                destruction_id: auth.fields().destruction_id,
                destruction_authorization_object_hash: auth.object_hash(),
                replica_id: *device.as_bytes(),
                replica_kind: crate::ManagedReplicaKind::Writer.code(),
                removed_object_hashes: removed.iter().copied().collect(),
                result: 0,
                backup_expiry_at: None,
                executed_at: resumed.current_head().preexisting_effective_now().value(),
            })?;
            let signature = first.signer.sign_deletion_attestation_digest(
                first.component_certificate,
                payload.exact_digest_input(),
                auth.exact_bytes(),
            )?;
            encode_trust(&TrustObjectV1::new(payload, vec![signature])?)?
                .as_bytes()
                .to_vec()
        };
        progress(LocalAttestationCheckpoint::Signed)?;
        guard.check_before_effect()?;
        // An external signing operation cannot bypass the current-action gate.
        let resumed = native.resume_original(auth, context.resumed.authorization_head(), proof)?;
        crate::preflight::check_authority(&resumed, context.custody, first.component_certificate)?;
        let attestation = crate::verify_attestation_historical(
            &exact,
            auth,
            &historical,
            resumed.current_head().preexisting_effective_now().value(),
        )?;
        if attestation.fields().replica_id != *device.as_bytes()
            || attestation.fields().replica_kind != crate::ManagedReplicaKind::Writer.code()
            || attestation.fields().result != 0
            || attestation.fields().backup_expiry_at.is_some()
            || attestation.fields().executed_at < start.event().fields().executed_at
            || attestation
                .fields()
                .removed_object_hashes
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                != removed
        {
            return Err(Error::SecurityConflict);
        }
        // Every location lock remains held through the SQL custody fence,
        // physical remeasurement, signed append and committed re-read.
        let _locks = ordered
            .values()
            .map(|local| {
                local
                    .backend
                    .acquire_writer_lock()
                    .map_err(|_| Error::Storage)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let targets = context
            .job
            .preflight()
            .targets
            .iter()
            .map(|t| t.entry)
            .collect();
        self.database.transaction(|tx| {
            crate::inventory::require_durable(tx)?;
            crate::inventory::require_unchanged_in(tx,context.custody)?;
            guard.check_in(tx)?;
            let row=tx.query_row("SELECT exact_measurement FROM destruction_acquisition_purge WHERE job_hash=?1",&[key[0].clone()])?.ok_or(Error::Storage)?;
            if row.blob(0)?!=purge.exact_bytes() {return Err(Error::SecurityConflict)}
            for target in &context.job.preflight().targets {
                if tx.query_row("SELECT 1 FROM writer_original_identity WHERE entry_hash=?1",&[blob(target.entry.as_bytes())])?.is_some() {return Err(Error::Storage)}
            }
            for ((_,location),local) in &ordered {
                let expected=crate::local::registered_holdings(context.custody.exact_bytes(),local,*location,device)?;
                crate::local::verify_all_stubs(local.backend,context.job.preflight())?;
                if !crate::local::scan(local.backend,&targets,&expected,context.job.preflight())?.is_empty() {return Err(Error::Storage)}
                let measurement=crate::local::encode_measurement(start.job_hash(),*location,device,&expected.iter().copied().collect::<Vec<_>>())?;
                let row=tx.query_row("SELECT exact_measurement FROM destruction_local_measurement WHERE job_hash=?1 AND location_id=?2",&[key[0].clone(),blob(location.as_bytes())])?.ok_or(Error::Storage)?;
                if row.blob(0)?!=measurement {return Err(Error::SecurityConflict)}
            }
            for local in ordered.values() {crate::local::publish_exact_trust(local.backend,&exact)?;}
            progress(LocalAttestationCheckpoint::BeforeStore)?;
            if let Some(row)=tx.query_row("SELECT exact_attestation FROM destruction_local_attestation WHERE job_hash=?1 AND replica_id=?2",&key)? {
                if row.blob(0)?!=exact {return Err(Error::SecurityConflict)}
            } else {
                let head=resumed.current_head();
                tx.execute("INSERT INTO destruction_local_attestation(job_hash,replica_id,organization_id,destruction_id,object_hash,exact_attestation,execution_registry_version,execution_registry_head_hash,execution_sequence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",&[key[0].clone(),key[1].clone(),blob(auth.fields().organization_id.as_bytes()),blob(auth.fields().destruction_id.as_bytes()),blob(object_hash(&exact).as_bytes()),blob(&exact),integer(head.registry_version().get())?,blob(head.registry_head_hash().as_bytes()),integer(head.proposed_sequence().get())?])?;
            }
            Ok::<_,Error>(())
        })?;
        progress(LocalAttestationCheckpoint::Stored)?;
        let row=self.database.query_row("SELECT exact_attestation FROM destruction_local_attestation WHERE job_hash=?1 AND replica_id=?2",&key)?.ok_or(Error::Storage)?;
        if row.blob(0)? != exact {
            return Err(Error::SecurityConflict);
        }
        crate::verify_attestation_historical(
            row.blob(0)?,
            auth,
            &historical,
            resumed.current_head().preexisting_effective_now().value(),
        )
    }
}

fn registered_locations(
    exact: &[u8],
    device: DeviceId,
) -> Result<BTreeSet<(ea_types::Hash32, ObjectHash)>, Error> {
    let mut d = Decoder::new(exact);
    d.array().map_err(|_| Error::Format)?;
    for _ in 0..5 {
        d.skip().map_err(|_| Error::Format)?;
    }
    let mut result = BTreeSet::new();
    for _ in 0..d.array().map_err(|_| Error::Format)?.ok_or(Error::Format)? {
        let mut r = Decoder::new(d.bytes().map_err(|_| Error::Format)?);
        r.array().map_err(|_| Error::Format)?;
        let code = r.u8().map_err(|_| Error::Format)?;
        r.skip().map_err(|_| Error::Format)?;
        let matched = r.bytes().map_err(|_| Error::Format)? == device.as_bytes();
        let kind = r.u8().map_err(|_| Error::Format)?;
        if !matched {
            continue;
        }
        if kind != CertificateKindV1::Writer as u8 {
            return Err(Error::Registry);
        }
        if code > 0 {
            result.insert((
                ea_types::Hash32::try_from(r.bytes().map_err(|_| Error::Format)?)
                    .map_err(|_| Error::Format)?,
                ObjectHash::try_from(r.bytes().map_err(|_| Error::Format)?)
                    .map_err(|_| Error::Format)?,
            ));
        }
    }
    if result.is_empty() {
        return Err(Error::Target);
    }
    Ok(result)
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
fn integer(value: u64) -> Result<StoreValue, Error> {
    Ok(StoreValue::Integer(
        i64::try_from(value).map_err(|_| Error::Format)?,
    ))
}
