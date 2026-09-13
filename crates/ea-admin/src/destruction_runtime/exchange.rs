//! Exact durable public exchange with private, continuously rechecked native gates.
use super::*;
use ea_crypto::{CanonicalPublicCoseKey, VerificationContext, parse_cose_sign1, verify_cose_sign1};
use ea_destruction::{
    VerifiedDeletionAttestation, VerifiedDestructionEvent, VerifiedImportedPreflight,
};
use ea_sync_protocol::{ChallengeResponseV1, DestructionStatusResponseV1};
use ea_trust::HistoricalRegistryAuthority;
use ea_types::{OrganizationId, UnixMillis};
use std::collections::BTreeMap;

/// Exact public event bytes with their verified object and signer identity.
pub type NativeDestructionEventBytes<'a> = (ObjectHash, CertificateHash, &'a [u8]);

/// Cannot be constructed, cloned, or converted into native/Registry authority.
/// Its private presence is consumed from the creating runtime, never copied.
pub struct NativeDestructionExchange {
    controller: OperatorRuntime,
    custodian: OperatorRuntime,
    session: VerifiedOperatorSession,
    host: Option<Arc<dyn DestructionHostGuard>>,
    component: CertificateHash,
    original: HistoricalRegistryAuthority,
    job: VerifiedImportedPreflight,
    events: Vec<VerifiedDestructionEvent>,
    attestations: Vec<VerifiedDeletionAttestation>,
    servers: Vec<DeviceId>,
}
impl DestructionRuntime {
    /// Reauthenticate and consume that exact presence into a bounded public
    /// exchange. Subsequent native execution must obtain its own fresh proof.
    pub fn prepare_server_exchange(
        &mut self,
        id: DestructionId,
        expected_preflight_hash: ObjectHash,
    ) -> Result<NativeDestructionExchange, Error> {
        self.unlock()?;
        let mut saved = self.read_saved(id)?;
        self.validate_import_scope(&saved)?;
        self.project_status(&saved)?;
        let job = saved.job.take().ok_or(DestructionError::Storage)?;
        if job.job_hash() != expected_preflight_hash {
            return Err(DestructionError::SecurityConflict.into());
        }
        let catalog = ea_trust::verify_catalog_custody_authority(self.controller.trust())
            .map_err(|_| DestructionError::Registry)?;
        let mut servers = BTreeSet::new();
        for (hash, fields) in catalog.known_certificate_fields() {
            if fields.certificate_kind == CertificateKindV1::ServerReceipt {
                if !job.replicas().contains(&(
                    hash,
                    fields.device_id,
                    CertificateKindV1::ServerReceipt as u8,
                )) {
                    return Err(DestructionError::Target.into());
                }
                servers.insert(fields.device_id);
            }
        }
        for (_, device, kind) in job.replicas() {
            if *kind == CertificateKindV1::ServerReceipt as u8 && !servers.contains(device) {
                return Err(DestructionError::Target.into());
            }
        }
        if servers.is_empty() {
            return Err(DestructionError::Target.into());
        }
        self.require_same_fresh_action()?;
        let controller = self
            .controller
            .reopened_for_action()
            .map_err(|_| Error::Session)?;
        let custodian = self
            .custodian
            .reopened_for_action()
            .map_err(|_| Error::Session)?;
        self.require_same_fresh_action()?;
        let result = NativeDestructionExchange {
            controller,
            custodian,
            session: self.session.take().ok_or(Error::Session)?,
            host: self.host_guard.clone(),
            component: self.component,
            original: saved.original,
            job,
            events: saved.events,
            attestations: saved.attestations,
            servers: servers.into_iter().collect(),
        };
        result.require_current()?;
        Ok(result)
    }
}
impl NativeDestructionExchange {
    pub fn destruction_id(&self) -> DestructionId {
        self.job.authorization().fields().destruction_id
    }
    pub fn organization_id(&self) -> OrganizationId {
        self.job.authorization().fields().organization_id
    }
    pub fn authorization_hash(&self) -> ObjectHash {
        self.job.authorization().object_hash()
    }
    pub fn job_hash(&self) -> ObjectHash {
        self.job.job_hash()
    }
    pub fn exact_authorization(&self) -> &[u8] {
        self.job.authorization().exact_bytes()
    }
    pub fn exact_job(&self) -> &[u8] {
        self.job.exact_upload()
    }
    pub fn component_certificate(&self) -> CertificateHash {
        self.component
    }
    pub fn required_servers(&self) -> &[DeviceId] {
        &self.servers
    }
    pub fn events(&self) -> Result<Vec<NativeDestructionEventBytes<'_>>, Error> {
        ordered_events(&self.events)?
            .into_iter()
            .map(|event| {
                let ea_format::ParsedArchiveObject::Trust(parsed) =
                    ea_format::decode_exact_object(event.exact_bytes())?
                else {
                    return Err(DestructionError::Format.into());
                };
                let [sig] = parsed.value().signatures() else {
                    return Err(DestructionError::Signature.into());
                };
                let certificate = parse_cose_sign1(sig, &[])?
                    .certificate_hash()
                    .ok_or(DestructionError::Signature)?;
                Ok((event.object_hash(), certificate, event.exact_bytes()))
            })
            .collect()
    }
    pub fn attestations(&self) -> impl Iterator<Item = (ObjectHash, &[u8])> {
        self.attestations
            .iter()
            .map(|claim| (claim.object_hash(), claim.exact_bytes()))
    }
    fn fresh(&self) -> Result<OperatorRuntime, Error> {
        if let Some(host) = &self.host {
            host.require_open()?;
        }
        self.controller
            .ensure_current()
            .map_err(|_| Error::Session)?;
        self.custodian
            .ensure_same_action_authority()
            .map_err(|_| Error::Session)?;
        let fresh = self
            .controller
            .reopened_for_action()
            .map_err(|_| Error::Session)?;
        fresh.ensure_current().map_err(|_| Error::Session)?;
        self.controller
            .ensure_same_authority_as(&fresh)
            .map_err(|_| Error::Session)?;
        if ea_trust::verify_catalog_custody_authority(self.controller.trust())
            .map_err(|_| DestructionError::Registry)?
            .registry_head_hash()
            != ea_trust::verify_catalog_custody_authority(fresh.trust())
                .map_err(|_| DestructionError::Registry)?
                .registry_head_hash()
        {
            return Err(Error::Session);
        }
        ea_operator::verify_current_session(
            fresh.head(),
            fresh.config().device_certificate_hash,
            OperatorRoleV1::OrganizationAdmin,
            self.session.proof(),
            ReauthPurpose::Destruction,
            fresh.native().as_ref(),
        )
        .map_err(|_| Error::Session)?;
        let original = self
            .original
            .active_certificate_fields(self.component)
            .ok_or(DestructionError::Signature)?;
        let current = fresh
            .head()
            .active_certificate_fields(self.component)
            .ok_or(DestructionError::Signature)?;
        let writer = fresh
            .head()
            .active_certificate_fields(self.custodian.config().device_certificate_hash)
            .ok_or(Error::Configuration)?;
        let retention = &fresh.head().policy_fields().retention_policy;
        if original != current
            || current.certificate_kind != CertificateKindV1::DeletionAttest
            || current.device_id != writer.device_id
            || !current.capabilities.iter().any(|c| c == "deletionAttest")
            || !retention.destruction_enabled
            || retention.eds_privacy_decision_document_hash.is_none()
        {
            return Err(DestructionError::PrivacyGate.into());
        }
        if let Some(host) = &self.host {
            host.require_open()?;
        }
        Ok(fresh)
    }
    pub fn require_current(&self) -> Result<(), Error> {
        self.fresh().map(|_| ())
    }
    pub fn verify_component_key(&self, public: &CanonicalPublicCoseKey) -> Result<(), Error> {
        let fresh = self.fresh()?;
        let fields = fresh
            .head()
            .active_certificate_fields(self.component)
            .ok_or(DestructionError::Signature)?;
        if fields.signing_key_thumbprint != Some(public.thumbprint())
            || fields.signing_public_cose_key.as_deref()
                != Some(public.to_deterministic_cbor().as_slice())
        {
            return Err(DestructionError::Signature.into());
        }
        Ok(())
    }
    pub fn verify_server(
        &self,
        device: DeviceId,
        certificate: CertificateHash,
    ) -> Result<(), Error> {
        let fresh = self.fresh()?;
        self.verify_server_at(&fresh, device, certificate)
    }
    fn verify_server_at(
        &self,
        fresh: &OperatorRuntime,
        device: DeviceId,
        certificate: CertificateHash,
    ) -> Result<(), Error> {
        let fields = fresh
            .head()
            .active_certificate_fields(certificate)
            .ok_or(DestructionError::Signature)?;
        if !self.servers.contains(&device)
            || fields.device_id != device
            || fields.organization_id != self.organization_id()
            || fields.certificate_kind != CertificateKindV1::ServerReceipt
            || !fields.capabilities.iter().any(|c| c == "serverReceipt")
        {
            return Err(DestructionError::Signature.into());
        }
        Ok(())
    }
    /// Existing RFC9421 seconds, bounded by the actual private presence deadline.
    pub fn http_window(&self) -> Result<(i64, i64), Error> {
        let fresh = self.fresh()?;
        http_window(
            fresh.head().preexisting_effective_now().value(),
            self.session.proof().expires_at(),
        )
    }
    pub fn verify_challenge(
        &self,
        device: DeviceId,
        certificate: CertificateHash,
        exact: &[u8],
    ) -> Result<[u8; 32], Error> {
        self.verify_challenge_window(device, certificate, exact)
            .map(|value| value.0)
    }
    /// Validated nonce and request window from the same fresh native selection.
    pub fn verify_challenge_window(
        &self,
        device: DeviceId,
        certificate: CertificateHash,
        exact: &[u8],
    ) -> Result<([u8; 32], i64, i64), Error> {
        let fresh = self.fresh()?;
        self.verify_server_at(&fresh, device, certificate)?;
        let response = ChallengeResponseV1::decode(exact).map_err(|_| DestructionError::Format)?;
        let core = response.core();
        let now = fresh.head().preexisting_effective_now().value();
        if core.organization_id != self.organization_id()
            || core.server_certificate_hash != certificate
            || core.issued_at_server.get() < 0
            || core.issued_at_server.get() > now.get().saturating_add(60_000)
            || core.expires_at <= now
        {
            return Err(DestructionError::Signature.into());
        }
        let payload = ea_crypto::encode_challenge_response_core(core)?;
        let mut d = minicbor::Decoder::new(exact);
        d.array().map_err(|_| DestructionError::Format)?;
        d.skip().map_err(|_| DestructionError::Format)?;
        let offset = d.position();
        let context = VerificationContext::challenge_response(
            &payload,
            fresh.head().proposed_sequence(),
            fresh.head().registry_version(),
        )?;
        verify_cose_sign1(&exact[offset..], fresh.head(), &context)?;
        let (created, expires) = http_window(now, self.session.proof().expires_at())?;
        Ok((core.nonce, created, expires))
    }
    /// Verify the whole union before splitting, then preserve native import
    /// bounds and causal order. No unsigned response state enters this path.
    pub fn progress_batches(
        &self,
        status: &DestructionStatusResponseV1,
    ) -> Result<Vec<Vec<Vec<u8>>>, Error> {
        let fresh = self.fresh()?;
        if status.destruction_id() != self.destruction_id()
            || status.authorization_object_hash() != self.authorization_hash()
        {
            return Err(DestructionError::SecurityConflict.into());
        }
        let now = fresh.head().preexisting_effective_now().value();
        let mut events = self.events.clone();
        let mut attestations = self.attestations.clone();
        let known: BTreeSet<_> = self
            .events
            .iter()
            .map(|e| e.object_hash())
            .chain(self.attestations.iter().map(|a| a.object_hash()))
            .collect();
        let mut incoming_attestations = BTreeMap::new();
        for record in status.attestations() {
            if object_hash(record.exact_object_bytes()) != record.object_hash() {
                return Err(DestructionError::SecurityConflict.into());
            }
            let claim = ea_destruction::verify_attestation_historical(
                record.exact_object_bytes(),
                self.job.authorization(),
                &self.original,
                now,
            )?;
            if !known.contains(&claim.object_hash()) {
                incoming_attestations.insert(claim.object_hash(), claim.exact_bytes().to_vec());
            }
            if !attestations
                .iter()
                .any(|a| a.object_hash() == claim.object_hash())
            {
                attestations.push(claim);
            }
        }
        for record in status.transitions() {
            if object_hash(record.exact_object_bytes()) != record.object_hash() {
                return Err(DestructionError::SecurityConflict.into());
            }
            let event = ea_destruction::verify_event_historical(
                record.exact_object_bytes(),
                self.job.authorization(),
                &self.original,
                now,
            )?;
            if !events
                .iter()
                .any(|e| e.object_hash() == event.object_hash())
            {
                events.push(event);
            }
        }
        let rebuilt =
            ea_destruction::reconstruct_imported_history(&self.job, &events, &attestations)?;
        if rebuilt.state() == DestructionState::CompleteManagedScope
            && !rebuilt.evidence().all_managed_replicas_confirmed()
        {
            return Err(DestructionError::Event.into());
        }
        let mut objects = incoming_attestations.into_values().collect::<Vec<_>>();
        for event in ordered_events(&events)? {
            if !known.contains(&event.object_hash()) {
                objects.push(event.exact_bytes().to_vec())
            }
        }
        let mut batches = Vec::new();
        let mut batch = Vec::new();
        let mut length = 0usize;
        for exact in objects {
            if exact.len() > ea_format::ETB_MAX_RAW_BYTES_V1 {
                return Err(DestructionError::Format.into());
            }
            if batch.len() == MAX_NATIVE_DESTRUCTION_IMPORT_OBJECTS
                || length + exact.len() > MAX_NATIVE_DESTRUCTION_IMPORT_TOTAL_BYTES
            {
                batches.push(std::mem::take(&mut batch));
                length = 0;
            }
            length += exact.len();
            batch.push(exact);
        }
        if !batch.is_empty() {
            batches.push(batch)
        }
        self.require_current()?;
        Ok(batches)
    }
}
fn ordered_events(
    events: &[VerifiedDestructionEvent],
) -> Result<Vec<&VerifiedDestructionEvent>, Error> {
    let mut following = BTreeMap::new();
    for event in events {
        if following
            .insert(event.fields().previous_event_object_hash, event)
            .is_some()
        {
            return Err(DestructionError::Event.into());
        }
    }
    let mut result = Vec::new();
    let mut previous = None;
    while let Some(event) = following.remove(&previous) {
        previous = Some(event.object_hash());
        result.push(event);
    }
    if !following.is_empty() {
        return Err(DestructionError::Event.into());
    }
    Ok(result)
}
fn http_window(now: UnixMillis, deadline: UnixMillis) -> Result<(i64, i64), Error> {
    let created = now.get().div_euclid(1_000);
    let expires = deadline
        .get()
        .div_euclid(1_000)
        .min(created.saturating_add(300));
    let usable_millis = expires
        .checked_mul(1_000)
        .and_then(|rounded_deadline| rounded_deadline.checked_sub(now.get()))
        .ok_or(Error::Session)?;
    if created < 0 || expires <= created || usable_millis < 1_000 {
        return Err(Error::Session);
    }
    Ok((created, expires))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_http_window_never_outlives_actual_presence() {
        assert_eq!(
            http_window(UnixMillis::new(2_100), UnixMillis::new(10_999)).unwrap(),
            (2, 10)
        );
    }
    #[test]
    fn native_http_window_refuses_expired_or_subsecond_remaining_authority() {
        assert!(http_window(UnixMillis::new(1_000), UnixMillis::new(999)).is_err());
        assert!(http_window(UnixMillis::new(1_000), UnixMillis::new(1_999)).is_err());
    }
    #[test]
    fn native_http_window_refuses_fractional_crossing_with_less_than_one_second_left() {
        assert!(http_window(UnixMillis::new(1_999), UnixMillis::new(2_001)).is_err());
        assert!(http_window(UnixMillis::new(2_001), UnixMillis::new(3_000)).is_err());
        assert_eq!(
            http_window(UnixMillis::new(2_000), UnixMillis::new(3_000)).unwrap(),
            (2, 3)
        );
    }
    #[test]
    fn native_http_window_keeps_the_existing_protocol_maximum() {
        assert_eq!(
            http_window(UnixMillis::new(2_100), UnixMillis::new(999_999)).unwrap(),
            (2, 302)
        );
    }
}
