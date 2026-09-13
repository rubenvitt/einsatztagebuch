//! Public originals for one existing Reader obligation, never transferred authority.
use super::*;

/// Only the runtime can select these verified public originals. Copies remain
/// untrusted input: the receiving Reader must independently verify its actual
/// session, source, identity, complete job and current component authority.
/// No native session, private proof, signer or key leaves the runtime.
pub struct NativeReaderDestructionDelivery {
    authorization: Vec<u8>,
    initiating_event: Vec<u8>,
    job_upload: Vec<u8>,
    reader: DeviceId,
    job_hash: ObjectHash,
}

impl NativeReaderDestructionDelivery {
    pub fn exact_authorization(&self) -> &[u8] {
        &self.authorization
    }
    pub fn exact_initiating_event(&self) -> &[u8] {
        &self.initiating_event
    }
    pub fn exact_job_upload(&self) -> &[u8] {
        &self.job_upload
    }
    pub fn reader_id(&self) -> DeviceId {
        self.reader
    }
    pub fn job_hash(&self) -> ObjectHash {
        self.job_hash
    }
}

impl DestructionRuntime {
    /// Export the unchanged Authorization ETB, actual Started-transition ETB
    /// and existing DestructionJobUploadV1 for a required Reader. The existing
    /// native session must already be open; this does not request presence,
    /// prepare/start a job, execute removal or issue a claim.
    ///
    /// Existing guards still refresh time, repair audit mirrors and preserve
    /// newly observed custody knowledge, including before a scope refusal.
    /// Thus this is not a promise that every database byte remains unchanged.
    pub fn export_reader_delivery(
        &mut self,
        id: DestructionId,
        expected_job: ObjectHash,
        reader: DeviceId,
    ) -> Result<NativeReaderDestructionDelivery, Error> {
        self.refresh()?;
        self.require_session()?;
        let before = self.import_snapshot()?;
        let saved = self.read_saved(id)?;
        let job = saved.job.as_ref().ok_or(DestructionError::Storage)?;
        if job.job_hash() != expected_job {
            return Err(DestructionError::SecurityConflict.into());
        }
        let mut starts = saved
            .events
            .iter()
            .filter(|event| event.fields().from_state == Some(0) && event.fields().to_state == 1);
        let start = starts.next().ok_or(DestructionError::Event)?;
        if starts.next().is_some() {
            return Err(DestructionError::Event.into());
        }
        self.validate_import_scope(&saved)?;
        let status = self.project_status(&saved)?;
        if !status.replicas.iter().any(|replica| {
            replica.device_id == reader
                && replica.kind == ea_destruction::ManagedReplicaKind::Reader
        }) {
            return Err(DestructionError::Target.into());
        }
        self.require_same_fresh_action()?;
        let delivery = NativeReaderDestructionDelivery {
            authorization: saved.auth.exact_bytes().to_vec(),
            initiating_event: start.exact_bytes().to_vec(),
            job_upload: job.exact_upload().to_vec(),
            reader,
            job_hash: job.job_hash(),
        };
        // Reconstruct and re-observe after the copies. Any changed saved job,
        // history or custody invalidates this selection rather than replacing it.
        let after = self.read_saved(id)?;
        self.validate_import_scope(&after)?;
        self.project_status(&after)?;
        if self.import_snapshot()? != before {
            return Err(DestructionError::SecurityConflict.into());
        }
        self.require_same_fresh_action()?;
        // Presence must survive the actual elapsed export time, not merely be
        // valid at the frozen pre-export selected head time.
        let fresh = self
            .controller
            .reopened_for_action()
            .map_err(|_| Error::Session)?;
        fresh.ensure_current().map_err(|_| Error::Session)?;
        self.controller
            .ensure_same_authority_as(&fresh)
            .map_err(|_| Error::Session)?;
        ea_operator::verify_current_session(
            fresh.head(),
            fresh.config().device_certificate_hash,
            OperatorRoleV1::OrganizationAdmin,
            self.require_session()?.proof(),
            ReauthPurpose::Destruction,
            fresh.native().as_ref(),
        )
        .map_err(|_| Error::Session)?;
        self.check_host()?;
        Ok(delivery)
    }
}
