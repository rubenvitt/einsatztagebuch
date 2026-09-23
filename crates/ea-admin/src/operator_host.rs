//! SQLCipher journal and the only public binding-export boundary.
use super::*;
use ea_crypto::{
    CryptoError, ResolvedSigner, SignerCertificateResolver, SignerRole, VerificationContext,
    verify_cose_sign1,
};
use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject, TrustObjectV1, decode_exact_object};
use ea_local_store::{StoreRow, StoreTransaction, StoreValue};

/// Resolve this from trusted local device configuration, independently of a login request.
#[derive(Clone, Copy)]
pub struct VerifiedLocalDeviceIdentity {
    pub(super) certificate: CertificateHash,
    pub(super) organization: OrganizationId,
    pub(super) device: DeviceId,
    chain: ChainId,
    head: ObjectHash,
    role: SignerRole,
}
impl VerifiedLocalDeviceIdentity {
    pub fn verify(
        head: &SelectedRegistryHead,
        certificate: CertificateHash,
        expected_local_device_id: DeviceId,
    ) -> Result<Self, OperatorLifecycleError> {
        Self::verify_view(head.into(), certificate, expected_local_device_id)
    }
    pub fn verify_writer(
        head: ea_trust::WriterRegistryHeadRef<'_>,
        certificate: CertificateHash,
        expected_local_device_id: DeviceId,
    ) -> Result<Self, OperatorLifecycleError> {
        if head.current_writer_certificate_hash() != Some(certificate) {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        let identity = Self::verify_view(head, certificate, expected_local_device_id)?;
        if identity.role != SignerRole::Writer {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        Ok(identity)
    }
    fn verify_view(
        head: ea_trust::WriterRegistryHeadRef<'_>,
        certificate: CertificateHash,
        expected_local_device_id: DeviceId,
    ) -> Result<Self, OperatorLifecycleError> {
        let fields = head
            .active_certificate_fields(certificate)
            .ok_or(OperatorError::DeviceCertificateNotActive)?;
        let role = match fields.certificate_kind {
            CertificateKindV1::Writer => SignerRole::Writer,
            CertificateKindV1::Reader => SignerRole::Reader,
            CertificateKindV1::OrganizationAdmin => SignerRole::OrganizationAdmin,
            _ => return Err(OperatorLifecycleError::TargetMismatch),
        };
        if fields.device_id != expected_local_device_id || fields.signing_key_thumbprint.is_none() {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        Ok(Self {
            certificate,
            organization: fields.organization_id,
            device: fields.device_id,
            chain: head.chain_id(),
            head: head.registry_head_hash(),
            role,
        })
    }
    pub(super) fn check_writer(
        &self,
        head: ea_trust::WriterRegistryHeadRef<'_>,
    ) -> Result<(), OperatorLifecycleError> {
        if self.chain != head.chain_id() || self.head != head.registry_head_hash() {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        Self::verify_writer(head, self.certificate, self.device).map(|_| ())
    }
    pub(super) fn check(&self, head: &SelectedRegistryHead) -> Result<(), OperatorLifecycleError> {
        if self.chain != head.chain_id() || self.head != head.registry_head_hash() {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        Self::verify(head, self.certificate, self.device).map(|_| ())
    }
    /// Dieses Gerät als Auditakteur OHNE Bedienerbindung, zuvor am gewählten
    /// Kopf nachgeprüft — für Gerätezeilen, zu denen es keinen frischen
    /// Bedienernachweis gibt (Bindungslebenszyklus, Escrow-Verfall).
    pub(crate) fn unbound_audit_actor(
        &self,
        head: &SelectedRegistryHead,
    ) -> Result<AuthenticatedDevice, OperatorLifecycleError> {
        self.check(head)?;
        Ok(AuthenticatedDevice::new(
            self.organization,
            self.device,
            ObjectHash::try_from(self.certificate.as_bytes().as_slice())
                .map_err(|_| OperatorLifecycleError::TargetMismatch)?,
            None,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum PreparedBindingState {
    BindingPrepared = 0,
    ActivationRequested = 1,
    Ready = 2,
    PublicationUncertain = 3,
    Published = 4,
    Active = 5,
    Abandoned = 6,
}
impl PreparedBindingState {
    fn decode(value: i64) -> Result<Self, OperatorLifecycleError> {
        match value {
            0 => Ok(Self::BindingPrepared),
            1 => Ok(Self::ActivationRequested),
            2 => Ok(Self::Ready),
            3 => Ok(Self::PublicationUncertain),
            4 => Ok(Self::Published),
            5 => Ok(Self::Active),
            6 => Ok(Self::Abandoned),
            _ => Err(OperatorLifecycleError::JournalConflict),
        }
    }
}

/// A journal reference, never a capability to obtain or publish signed bytes.
pub struct PreparedOperatorBinding {
    binding: ObjectHash,
    previous: Option<ObjectHash>,
    state: PreparedBindingState,
}
impl PreparedOperatorBinding {
    pub fn binding_object_hash(&self) -> ObjectHash {
        self.binding
    }
    pub fn previous_binding_object_hash(&self) -> Option<ObjectHash> {
        self.previous
    }
    /// Snapshot only; every operation reloads the durable state.
    pub fn state(&self) -> PreparedBindingState {
        self.state
    }
}

/// Borrowed only during the publisher callback after durable readiness checks.
pub struct ReadyOperatorBinding {
    objects: [Vec<u8>; 4],
}
impl ReadyOperatorBinding {
    pub fn binding_authorization_bytes(&self) -> &[u8] {
        &self.objects[0]
    }
    pub fn binding_bytes(&self) -> &[u8] {
        &self.objects[1]
    }
    pub fn activation_authorization_bytes(&self) -> &[u8] {
        &self.objects[2]
    }
    pub fn activation_bytes(&self) -> &[u8] {
        &self.objects[3]
    }
    pub fn binding_object_hash(&self) -> ObjectHash {
        object_hash(self.binding_bytes())
    }
}
pub trait OperatorBindingPublisher {
    /// Implement idempotent delivery of these exact objects. An error is treated
    /// as uncertain delivery; restart must retry the same objects.
    fn publish(&mut self, ready: &ReadyOperatorBinding) -> Result<(), OperatorLifecycleError>;
}

struct Journal {
    binding_hash: ObjectHash,
    chain: ChainId,
    previous: Option<ObjectHash>,
    binding_authorization: Vec<u8>,
    binding: Vec<u8>,
    activation_authorization: Vec<u8>,
    activation: Vec<u8>,
    state: PreparedBindingState,
    valid_through: ChainSequence,
    not_after: UnixMillis,
    issued_at: UnixMillis,
    prepared_at: UnixMillis,
}
const SELECT: &str = "SELECT binding_hash,chain_id,COALESCE(previous_binding_hash,X''),binding_authorization,binding,COALESCE(activation_authorization,X''),COALESCE(activation,X''),state,valid_through,not_after,COALESCE(activation_issued_at,0),prepared_at FROM operator_binding_journal WHERE singleton=0";
fn decode(row: StoreRow) -> Result<Journal, OperatorLifecycleError> {
    let shape = |_| OperatorLifecycleError::JournalConflict;
    let previous = row.blob(2)?;
    Ok(Journal {
        binding_hash: ObjectHash::try_from(row.blob(0)?).map_err(shape)?,
        chain: ChainId::try_from(row.blob(1)?).map_err(shape)?,
        previous: if previous.is_empty() {
            None
        } else {
            Some(ObjectHash::try_from(previous).map_err(shape)?)
        },
        binding_authorization: row.blob(3)?.to_vec(),
        binding: row.blob(4)?.to_vec(),
        activation_authorization: row.blob(5)?.to_vec(),
        activation: row.blob(6)?.to_vec(),
        state: PreparedBindingState::decode(row.integer(7)?)?,
        valid_through: ChainSequence::new(u64::from_be_bytes(
            row.blob(8)?
                .try_into()
                .map_err(|_| OperatorLifecycleError::JournalConflict)?,
        )),
        not_after: UnixMillis::new(row.integer(9)?),
        issued_at: UnixMillis::new(row.integer(10)?),
        prepared_at: UnixMillis::new(row.integer(11)?),
    })
}
fn load(database: &EncryptedDatabase) -> Result<Option<Journal>, OperatorLifecycleError> {
    database.query_row(SELECT, &[])?.map(decode).transpose()
}
fn load_in(tx: &StoreTransaction<'_>) -> Result<Journal, OperatorLifecycleError> {
    decode(
        tx.query_row(SELECT, &[])?
            .ok_or(OperatorLifecycleError::JournalConflict)?,
    )
}
fn exact(bytes: &[u8]) -> Result<TrustObjectV1, OperatorLifecycleError> {
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(bytes)? else {
        return Err(OperatorLifecycleError::TargetMismatch);
    };
    Ok(parsed.value().clone())
}
impl Journal {
    fn handle(&self) -> PreparedOperatorBinding {
        PreparedOperatorBinding {
            binding: self.binding_hash,
            previous: self.previous,
            state: self.state,
        }
    }
    fn fields(&self) -> Result<OperatorBindingFieldsV1, OperatorLifecycleError> {
        if object_hash(&self.binding) != self.binding_hash {
            return Err(OperatorLifecycleError::JournalConflict);
        }
        let DecodedTrustPayloadV1::AuthorizedOperatorBinding(value) =
            exact(&self.binding)?.decoded_payload()?
        else {
            return Err(OperatorLifecycleError::TargetMismatch);
        };
        if value.authorization_object_hash() != object_hash(&self.binding_authorization) {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        Ok(value.fields().clone())
    }
    fn match_handle(&self, handle: &PreparedOperatorBinding) -> Result<(), OperatorLifecycleError> {
        if self.binding_hash != handle.binding || self.previous != handle.previous {
            return Err(OperatorLifecycleError::JournalConflict);
        }
        Ok(())
    }
    fn same(&self, other: &Self) -> bool {
        self.binding_hash == other.binding_hash
            && self.chain == other.chain
            && self.previous == other.previous
            && self.binding_authorization == other.binding_authorization
            && self.binding == other.binding
            && self.activation_authorization == other.activation_authorization
            && self.activation == other.activation
            && self.state == other.state
            && self.valid_through == other.valid_through
            && self.not_after == other.not_after
            && self.issued_at == other.issued_at
            && self.prepared_at == other.prepared_at
    }
    fn previous_head(&self, head: &SelectedRegistryHead) -> Result<(), OperatorLifecycleError> {
        let DecodedTrustPayloadV1::OrganizationAdminAuthorization(auth) =
            exact(&self.binding_authorization)?.decoded_payload()?
        else {
            return Err(OperatorLifecycleError::TargetMismatch);
        };
        if self.chain != head.chain_id()
            || auth.organization_id != head.root_certificate_fields().organization_id
            || auth.registry_version != head.registry_version()
            || auth.registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
        {
            return Err(OperatorLifecycleError::Readiness);
        }
        Ok(())
    }
}

pub(super) fn ensure_preparable(
    database: &EncryptedDatabase,
    head: &SelectedRegistryHead,
    replacement: Option<ObjectHash>,
) -> Result<(), OperatorLifecycleError> {
    let journal = load(database)?;
    if journal.as_ref().is_some_and(|j| {
        j.state == PreparedBindingState::Abandoned
            && j.previous.is_some()
            && (j.chain != head.chain_id() || j.previous != replacement)
    }) {
        return Err(OperatorLifecycleError::ReplacementRequiresRevocation);
    }
    if journal.is_some_and(|j| {
        !(matches!(
            j.state,
            PreparedBindingState::Active | PreparedBindingState::Abandoned
        ) || (j.chain == head.chain_id()
            && head
                .revoked_operator_binding_fields(j.binding_hash)
                .is_some()))
    }) {
        return Err(OperatorLifecycleError::JournalConflict);
    }
    Ok(())
}
pub(super) fn persist_prepared(
    database: &EncryptedDatabase,
    head: &SelectedRegistryHead,
    pending: &PendingProfile,
    old: Option<&OperatorProfile>,
    previous: Option<ObjectHash>,
    signed: SignedOperatorBinding,
    window: RegistryWindow,
) -> Result<PreparedOperatorBinding, OperatorLifecycleError> {
    let hash = signed.binding_object_hash();
    database.transaction(|tx| {
        pending.persist_in(tx, hash, old)?;
        let changed = tx.execute("INSERT INTO operator_binding_journal(singleton,binding_hash,chain_id,previous_binding_hash,binding_authorization,binding,state,valid_through,not_after,prepared_at) VALUES (0,?1,?2,?3,?4,?5,0,?6,?7,?8) ON CONFLICT(singleton) DO UPDATE SET binding_hash=excluded.binding_hash,chain_id=excluded.chain_id,previous_binding_hash=excluded.previous_binding_hash,binding_authorization=excluded.binding_authorization,binding=excluded.binding,activation_authorization=NULL,activation=NULL,activation_issued_at=NULL,state=0,valid_through=excluded.valid_through,not_after=excluded.not_after,prepared_at=excluded.prepared_at WHERE operator_binding_journal.state IN (5,6) OR (operator_binding_journal.chain_id=excluded.chain_id AND operator_binding_journal.binding_hash=excluded.previous_binding_hash)", &[
            blob(hash.as_bytes()), blob(head.chain_id().as_bytes()), previous.map_or(StoreValue::Null, |h| blob(h.as_bytes())), blob(&signed.binding_authorization), blob(signed.binding.as_bytes()), blob(&window.valid_through_sequence.get().to_be_bytes()), StoreValue::Integer(window.not_after.get()), StoreValue::Integer(signed.authorization_use_time.get())
        ])?;
        if changed != 1 { return Err(OperatorLifecycleError::JournalConflict); }
        Ok(PreparedOperatorBinding { binding: hash, previous, state: PreparedBindingState::BindingPrepared })
    })
}
fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}

impl OperatorBindingService<'_> {
    /// Persist readiness and the exact activation authorization before Root signing.
    /// An interrupted request is reconciled through the authority's durable response,
    /// never by issuing another authorization.
    pub fn authorize_prepared(
        &self,
        database: &Arc<EncryptedDatabase>,
        prepared: &PreparedOperatorBinding,
        native: &dyn NativeOperatorProvisioning,
        ports: &mut OperatorMutationPorts<'_>,
        reauth: VerifySessionRequest<'_>,
    ) -> Result<PreparedOperatorBinding, OperatorLifecycleError> {
        if reauth.purpose != ReauthPurpose::AdminRootCeremony {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        let actor = self.verify_session(reauth)?;
        let mut journal = self.checked_journal(database, prepared)?;
        if !matches!(
            journal.state,
            PreparedBindingState::BindingPrepared | PreparedBindingState::ActivationRequested
        ) {
            return Err(OperatorLifecycleError::Readiness);
        }
        let result = (|| {
            let fields = self.native_ready(database, &journal, native)?;
            self.host_audit(&journal, LocalAuditOutcomeV1::Accepted)?;
            ports
                .authorization
                .include_prepared_objects(&[&journal.binding_authorization, &journal.binding])?;
            if journal.state == PreparedBindingState::ActivationRequested
                && !journal.activation_authorization.is_empty()
            {
                let target =
                    OperatorTrustTarget::Registry(self.activation_fields(&journal, &fields)?);
                let bytes = ports.authorization.recover_activation(
                    self.head,
                    &target,
                    &journal.activation_authorization,
                )?;
                return self.reconcile_activation(database, prepared, native, &bytes);
            }
            let event = self.activation_fields(&journal, &fields)?;
            let target = OperatorTrustTarget::Registry(event.clone());
            let auth = if journal.state == PreparedBindingState::BindingPrepared {
                database.transaction(|tx| {
                    if !journal.same(&load_in(tx)?) { return Err(OperatorLifecycleError::JournalConflict); }
                    operator_profile::verify_in(tx, journal.binding_hash, &fields)?;
                    tx.execute("UPDATE operator_binding_journal SET activation_issued_at=?1,state=1 WHERE singleton=0", &[StoreValue::Integer(event.issued_at.get())])?;
                    Ok::<_, OperatorLifecycleError>(())
                })?;
                journal = self.checked_journal(database, prepared)?;
                ports.authorization.authorize(self.head, &target)?
            } else {
                ports
                    .authorization
                    .recover_authorization(self.head, &target)?
            };
            require_distinct_authorizations(
                &journal.binding_authorization,
                &auth.exact_authorization,
            )?;
            // The sealed intent and exact bytes must describe the very request
            // recorded for restart; RootCeremonyService checks them again.
            let payload = target.payload(object_hash(&auth.exact_authorization))?;
            VerificationContext::root_trust_digest(
                payload.exact_digest_input(),
                CertificateHash::from(self.head.root_certificate_object_hash()),
                Some(&auth.exact_authorization),
            )
            .map_err(|_| OperatorLifecycleError::TargetMismatch)?;
            if auth.intent.authorization_object_hash() != object_hash(&auth.exact_authorization)
                || auth.intent.previous_registry_version() != self.head.registry_version()
                || auth.intent.previous_registry_head_hash().as_bytes()
                    != self.head.registry_head_hash().as_bytes()
                || auth.intent.target_trust_subtype() != payload.subtype()
            {
                return Err(OperatorLifecycleError::TargetMismatch);
            }
            self.native_ready(database, &journal, native)?;
            database.transaction(|tx| {
                if !journal.same(&load_in(tx)?) { return Err(OperatorLifecycleError::JournalConflict); }
                operator_profile::verify_in(tx, journal.binding_hash, &fields)?;
                tx.execute("UPDATE operator_binding_journal SET activation_authorization=?1 WHERE singleton=0", &[blob(&auth.exact_authorization)])?;
                Ok::<_, OperatorLifecycleError>(())
            })?;
            let bytes = ports
                .ceremony
                .publish_authorized_target(
                    &auth.intent,
                    payload,
                    &auth.exact_authorization,
                    ports.store,
                    actor.proof(),
                )
                .map_err(OperatorLifecycleError::Ceremony)?;
            self.reconcile_activation(database, prepared, native, bytes.as_bytes())
        })();
        if result.is_err() {
            self.host_audit(&journal, LocalAuditOutcomeV1::Failed)?;
        }
        result
    }

    /// Accept only the exact Root response for a previously journaled request.
    /// A remote authority can call this after recovering its consumed response.
    pub fn reconcile_activation(
        &self,
        database: &Arc<EncryptedDatabase>,
        prepared: &PreparedOperatorBinding,
        native: &dyn NativeOperatorProvisioning,
        exact_activation: &[u8],
    ) -> Result<PreparedOperatorBinding, OperatorLifecycleError> {
        let mut journal = self.checked_journal(database, prepared)?;
        if journal.state != PreparedBindingState::ActivationRequested {
            return Err(OperatorLifecycleError::JournalConflict);
        }
        let fields = self.native_ready(database, &journal, native)?;
        journal.activation = exact_activation.to_vec();
        self.verify_activation(&journal, &fields)?;
        self.host_audit(&journal, LocalAuditOutcomeV1::Accepted)?;
        journal.activation.clear();
        database.transaction(|tx| {
            if !journal.same(&load_in(tx)?) {
                return Err(OperatorLifecycleError::JournalConflict);
            }
            operator_profile::verify_in(tx, journal.binding_hash, &fields)?;
            tx.execute(
                "UPDATE operator_binding_journal SET activation=?1,state=2 WHERE singleton=0",
                &[blob(exact_activation)],
            )?;
            Ok::<_, OperatorLifecycleError>(())
        })?;
        journal.state = PreparedBindingState::Ready;
        Ok(journal.handle())
    }

    fn activation_fields(
        &self,
        journal: &Journal,
        fields: &OperatorBindingFieldsV1,
    ) -> Result<RegistryEventFieldsV1, OperatorLifecycleError> {
        let mut event = self.registry_event(
            RegistryWindow {
                effective_from_sequence: fields.effective_from_sequence,
                valid_through_sequence: journal.valid_through,
                not_after: journal.not_after,
            },
            RegistryChangeV1::OperatorBinding {
                object_hash: journal.binding_hash,
            },
        )?;
        let issued_at = if journal.state == PreparedBindingState::BindingPrepared {
            event.issued_at.max(journal.prepared_at)
        } else {
            journal.issued_at
        };
        if issued_at >= event.not_after {
            return Err(OperatorLifecycleError::RegistryWindow);
        }
        event.issued_at = issued_at;
        event.not_before = issued_at;
        // Head selection checks the binding's authorization at this exact event time.
        verify_signed_pair(
            self.head,
            &journal.binding,
            &journal.binding_authorization,
            fields.effective_from_sequence,
            issued_at,
        )?;
        Ok(event)
    }
    pub(super) fn record_local_audit(
        &self,
        device: &AuthenticatedDevice,
        event: TypedLocalAuditEvent,
    ) -> Result<(), OperatorLifecycleError> {
        record_local_audit_for(
            self.head.into(),
            self.audit,
            self.local_device,
            device,
            event,
        )
    }

    pub fn resume_prepared(
        &self,
        database: &Arc<EncryptedDatabase>,
    ) -> Result<Option<PreparedOperatorBinding>, OperatorLifecycleError> {
        let Some(journal) = load(database)? else {
            return Ok(None);
        };
        if journal.chain != self.head.chain_id() {
            return Err(OperatorLifecycleError::Readiness);
        }
        journal.fields()?;
        Ok((journal.state != PreparedBindingState::Abandoned).then(|| journal.handle()))
    }

    fn native_ready(
        &self,
        database: &Arc<EncryptedDatabase>,
        journal: &Journal,
        native: &dyn NativeOperatorProvisioning,
    ) -> Result<OperatorBindingFieldsV1, OperatorLifecycleError> {
        journal.previous_head(self.head)?;
        let fields = journal.fields()?;
        verify_signed_pair(
            self.head,
            &journal.binding,
            &journal.binding_authorization,
            fields.effective_from_sequence,
            journal.prepared_at,
        )?;
        database
            .transaction(|tx| operator_profile::verify_in(tx, journal.binding_hash, &fields))?;
        let certificate = self
            .head
            .active_certificate_fields(fields.device_certificate_hash)
            .ok_or(OperatorError::DeviceCertificateNotActive)?;
        self.check_native(native, &fields, certificate.device_id)?;
        let key = native
            .operator_instance_public_key()?
            .ok_or(OperatorError::InstanceKeyMissing)?;
        let mut challenge = b"EINSATZARCHIV-OPERATOR-PROVISION-v1".to_vec();
        challenge.extend_from_slice(fields.organization_id.as_bytes());
        challenge.extend_from_slice(certificate.device_id.as_bytes());
        challenge.extend_from_slice(&fresh()?);
        challenge.extend_from_slice(journal.binding_hash.as_bytes());
        key.verify_ed25519_strict(&challenge, &native.prove_presence_and_sign(&challenge)?)
            .map_err(|_| OperatorError::PresenceProofInvalid)?;
        self.check_native(native, &fields, certificate.device_id)?;
        Ok(fields)
    }
    fn check_native(
        &self,
        native: &dyn NativeOperatorProvisioning,
        fields: &OperatorBindingFieldsV1,
        device: DeviceId,
    ) -> Result<(), OperatorLifecycleError> {
        if native.os_account_binding_hash(fields.organization_id, device)?
            != fields.os_account_binding_hash
        {
            return Err(OperatorError::AccountMismatch.into());
        }
        let key = native
            .operator_instance_public_key()?
            .ok_or(OperatorError::InstanceKeyMissing)?;
        if key.thumbprint() != fields.operator_instance_key_thumbprint {
            return Err(OperatorError::InstanceKeyMismatch.into());
        }
        Ok(())
    }
    fn checked_journal(
        &self,
        database: &Arc<EncryptedDatabase>,
        prepared: &PreparedOperatorBinding,
    ) -> Result<Journal, OperatorLifecycleError> {
        let j = load(database)?.ok_or(OperatorLifecycleError::JournalConflict)?;
        j.match_handle(prepared)?;
        Ok(j)
    }
    fn update_state(
        &self,
        database: &Arc<EncryptedDatabase>,
        journal: &Journal,
        fields: &OperatorBindingFieldsV1,
        next: PreparedBindingState,
    ) -> Result<(), OperatorLifecycleError> {
        database.transaction(|tx| {
            if !journal.same(&load_in(tx)?) {
                return Err(OperatorLifecycleError::JournalConflict);
            }
            operator_profile::verify_in(tx, journal.binding_hash, fields)?;
            tx.execute(
                "UPDATE operator_binding_journal SET state=?1 WHERE singleton=0",
                &[StoreValue::Integer(next as i64)],
            )?;
            Ok(())
        })
    }
    pub fn publish_prepared(
        &self,
        database: &Arc<EncryptedDatabase>,
        prepared: &PreparedOperatorBinding,
        native: &dyn NativeOperatorProvisioning,
        publisher: &mut dyn OperatorBindingPublisher,
    ) -> Result<(), OperatorLifecycleError> {
        let journal = self.checked_journal(database, prepared)?;
        if !matches!(
            journal.state,
            PreparedBindingState::Ready
                | PreparedBindingState::PublicationUncertain
                | PreparedBindingState::Published
        ) {
            return Err(OperatorLifecycleError::Readiness);
        }
        let fields = self.native_ready(database, &journal, native)?;
        self.verify_activation(&journal, &fields)?;
        self.host_audit(&journal, LocalAuditOutcomeV1::Accepted)?;
        self.update_state(
            database,
            &journal,
            &fields,
            PreparedBindingState::PublicationUncertain,
        )?;
        let current = self.checked_journal(database, prepared)?;
        self.native_ready(database, &current, native)?;
        let ready = ReadyOperatorBinding {
            objects: [
                journal.binding_authorization.clone(),
                journal.binding.clone(),
                journal.activation_authorization.clone(),
                journal.activation.clone(),
            ],
        };
        if let Err(error) = publisher.publish(&ready) {
            self.host_audit(&current, LocalAuditOutcomeV1::Failed)?;
            return Err(error);
        }
        self.update_state(database, &current, &fields, PreparedBindingState::Published)
    }
    pub fn complete_prepared(
        &self,
        prepared: &PreparedOperatorBinding,
        request: VerifySessionRequest<'_>,
    ) -> Result<VerifiedOperatorSession, OperatorLifecycleError> {
        let database = request.database.clone();
        let requested_binding = request.binding_object_hash;
        let verified = self.verify_session(request)?;
        let journal = self.checked_journal(&database, prepared)?;
        if !matches!(
            journal.state,
            PreparedBindingState::PublicationUncertain
                | PreparedBindingState::Published
                | PreparedBindingState::Active
        ) || journal.chain != self.head.chain_id()
            || requested_binding != journal.binding_hash
            || self
                .head
                .active_operator_binding_fields(journal.binding_hash)
                != Some(&journal.fields()?)
        {
            return Err(OperatorLifecycleError::Readiness);
        }
        self.update_state(
            &database,
            &journal,
            &journal.fields()?,
            PreparedBindingState::Active,
        )?;
        Ok(verified)
    }
    pub fn abandon_prepared(
        &self,
        database: &Arc<EncryptedDatabase>,
        prepared: &PreparedOperatorBinding,
        identity: &dyn ExternalOperatorIdentityVerifier,
    ) -> Result<(), OperatorLifecycleError> {
        let journal = self.checked_journal(database, prepared)?;
        let result = (|| {
            if journal.state != PreparedBindingState::BindingPrepared {
                return Err(OperatorLifecycleError::JournalConflict);
            }
            let DecodedTrustPayloadV1::OrganizationAdminAuthorization(origin) =
                exact(&journal.binding_authorization)?.decoded_payload()?
            else {
                return Err(OperatorLifecycleError::TargetMismatch);
            };
            // State 0 has never requested activation. Cancellation at a later head
            // is safe only while this exact binding has no activated history there.
            if journal.chain != self.head.chain_id()
                || origin.organization_id != self.head.root_certificate_fields().organization_id
                || origin.registry_version > self.head.registry_version()
                || (origin.registry_version == self.head.registry_version()
                    && origin.registry_head_hash.as_bytes()
                        != self.head.registry_head_hash().as_bytes())
                || self
                    .head
                    .active_operator_binding_fields(journal.binding_hash)
                    .is_some()
                || self
                    .head
                    .revoked_operator_binding_fields(journal.binding_hash)
                    .is_some()
            {
                return Err(OperatorLifecycleError::Readiness);
            }
            let fields = journal.fields()?;
            if let Some(previous) = journal.previous {
                let old = self
                    .head
                    .revoked_operator_binding_fields(previous)
                    .ok_or(OperatorLifecycleError::ReplacementRequiresRevocation)?;
                if old.organization_id != fields.organization_id
                    || old.operator_subject_id != fields.operator_subject_id
                {
                    return Err(OperatorLifecycleError::ReplacementRequiresRevocation);
                }
            }
            let certificate = self
                .head
                .active_certificate_fields(fields.device_certificate_hash)
                .ok_or(OperatorError::DeviceCertificateNotActive)?;
            let request = ExternalIdentityRequest {
                organization_id: fields.organization_id,
                device_id: certificate.device_id,
                role: fields.operator_role,
                previous_subject_id: Some(fields.operator_subject_id),
                previous_binding_object_hash: Some(journal.binding_hash),
                challenge: fresh()?,
            };
            let verified = identity.verify_identity(&request)?;
            if verified.organization_id != request.organization_id
                || verified.operator_subject_id != fields.operator_subject_id
                || verified.challenge != request.challenge
                || verified.previous_binding_object_hash != Some(journal.binding_hash)
            {
                return Err(OperatorLifecycleError::IdentityVerification);
            }
            self.host_audit(&journal, LocalAuditOutcomeV1::Accepted)?;
            database.transaction(|tx| {
                if !journal.same(&load_in(tx)?) {
                    return Err(OperatorLifecycleError::JournalConflict);
                }
                operator_profile::verify_in(tx, journal.binding_hash, &fields)?;
                tx.execute("DELETE FROM operator_profile WHERE singleton=0", &[])?;
                tx.execute(
                    "UPDATE operator_binding_journal SET state=6 WHERE singleton=0",
                    &[],
                )?;
                Ok(())
            })
        })();
        if result.is_err() {
            self.host_audit(&journal, LocalAuditOutcomeV1::Failed)?;
        }
        result
    }

    fn host_audit(
        &self,
        journal: &Journal,
        outcome: LocalAuditOutcomeV1,
    ) -> Result<(), OperatorLifecycleError> {
        let actor = self.local_device.unbound_audit_actor(self.head)?;
        self.record_local_audit(
            &actor,
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::BindingChange(BindingLifecycleContextV1::new(
                    journal.previous,
                    Some(journal.binding_hash),
                    journal.fields()?.effective_from_sequence,
                )),
                outcome,
            },
        )
    }
    fn verify_activation(
        &self,
        journal: &Journal,
        fields: &OperatorBindingFieldsV1,
    ) -> Result<(), OperatorLifecycleError> {
        let DecodedTrustPayloadV1::RegistryEvent(event) =
            exact(&journal.activation)?.decoded_payload()?
        else {
            return Err(OperatorLifecycleError::TargetMismatch);
        };
        let expected = self.activation_fields(journal, fields)?;
        if event.fields() != &expected
            || event.authorization_object_hash() != object_hash(&journal.activation_authorization)
        {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        require_distinct_authorizations(
            &journal.binding_authorization,
            &journal.activation_authorization,
        )?;
        verify_signed_pair(
            self.head,
            &journal.activation,
            &journal.activation_authorization,
            fields.effective_from_sequence,
            journal.issued_at,
        )
    }
}

pub(crate) fn verify_signed_pair(
    head: &SelectedRegistryHead,
    target: &[u8],
    authorization: &[u8],
    effective: ChainSequence,
    use_time: UnixMillis,
) -> Result<(), OperatorLifecycleError> {
    let target = exact(target)?;
    let payload = target.decoded_payload()?;
    let expected_action = match &payload {
        DecodedTrustPayloadV1::AuthorizedOperatorBinding(_) => 4,
        DecodedTrustPayloadV1::RegistryEvent(event) => match event.fields().change {
            RegistryChangeV1::OperatorBinding { .. } => 4,
            RegistryChangeV1::Target { target_kind: 1, .. } => 1,
            _ => return Err(OperatorLifecycleError::TargetMismatch),
        },
        _ => return Err(OperatorLifecycleError::TargetMismatch),
    };
    let auth_object = exact(authorization)?;
    let DecodedTrustPayloadV1::OrganizationAdminAuthorization(auth) =
        auth_object.decoded_payload()?
    else {
        return Err(OperatorLifecycleError::TargetMismatch);
    };
    let at = effective.min(head.valid_through_sequence());
    let bound = head
        .active_operator_binding_fields(auth.admin_operator_binding_object_hash)
        .ok_or(OperatorLifecycleError::Readiness)?;
    let cert = head
        .active_certificate_fields(auth.admin_certificate_hash)
        .ok_or(OperatorLifecycleError::Readiness)?;
    if auth.issued_at > use_time
        || auth.expires_at < use_time
        || cert.organization_id != auth.organization_id
        || cert.certificate_kind != CertificateKindV1::OrganizationAdmin
        || cert.signing_key_thumbprint != Some(auth.admin_key_thumbprint)
        || !cert
            .capabilities
            .iter()
            .any(|c| c == "organizationAdminApprove")
        || auth.action_code != expected_action
        || auth.registry_version != head.registry_version()
        || auth.registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
        || auth.organization_id != bound.organization_id
        || bound.device_certificate_hash != auth.admin_certificate_hash
        || bound.operator_role != OperatorRoleV1::OrganizationAdmin
        || bound.effective_from_sequence > at
        || bound.revoked_from_sequence.is_some_and(|s| s <= at)
        || cert.effective_from_sequence > at
        || cert.revoked_from_sequence.is_some_and(|s| s <= at)
        || cert
            .authority_subject_id
            .is_none_or(|s| s.as_bytes() != bound.operator_subject_id.as_bytes())
        || target.signatures().len() != 1
        || auth_object.signatures().len() != 1
    {
        return Err(OperatorLifecycleError::Readiness);
    }
    if let DecodedTrustPayloadV1::AuthorizedOperatorBinding(binding) = payload
        && binding.fields().operator_role == OperatorRoleV1::OrganizationAdmin
        && binding.fields().operator_subject_id == bound.operator_subject_id
    {
        return Err(OperatorLifecycleError::Readiness);
    }
    let context =
        VerificationContext::organization_admin_trust_digest(auth_object.exact_digest_input())
            .map_err(|_| OperatorLifecycleError::Readiness)?;
    verify_cose_sign1(&auth_object.signatures()[0], head, &context)
        .map_err(|_| OperatorLifecycleError::Readiness)?;
    let context = VerificationContext::root_trust_digest(
        target.exact_digest_input(),
        CertificateHash::from(head.root_certificate_object_hash()),
        Some(authorization),
    )
    .map_err(|_| OperatorLifecycleError::Readiness)?;
    verify_cose_sign1(
        &target.signatures()[0],
        &PreparedRootResolver(head),
        &context,
    )
    .map_err(|_| OperatorLifecycleError::Readiness)?;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/support/operator_signed_pair.rs"]
mod signed_pair_tests;

// Like ea-trust's PreviousHeadResolver, the verified Root authorizes future
// changes. The selected-head resolver otherwise limits every signer to today's
// proposal. Only the already verified Root gets this preparation-time scope.
struct PreparedRootResolver<'a>(&'a SelectedRegistryHead);
impl SignerCertificateResolver for PreparedRootResolver<'_> {
    fn resolve(
        &self,
        certificate: CertificateHash,
        registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        if certificate != CertificateHash::from(self.0.root_certificate_object_hash()) {
            return Err(CryptoError::SignerUnresolved);
        }
        let mut signer = self.0.resolve(certificate, registry)?;
        signer.registry_effective_from_sequence = ChainSequence::new(0);
        signer.registry_revoked_from_sequence = None;
        Ok(signer)
    }
}

#[derive(PartialEq)]
enum AuditContext {
    Generic(u8, Option<ObjectHash>),
    Binding(u8, Option<ObjectHash>, Option<ObjectHash>, ChainSequence),
}
fn audit_context(action: &LocalAuditActionV1) -> Result<AuditContext, OperatorLifecycleError> {
    match action {
        LocalAuditActionV1::Login(c)
        | LocalAuditActionV1::ReauthFailure(c)
        | LocalAuditActionV1::SessionExpired(c) => Ok(AuditContext::Generic(
            action.code(),
            c.subject_object_hash(),
        )),
        LocalAuditActionV1::BindingChange(c) | LocalAuditActionV1::Revocation(c) => {
            Ok(AuditContext::Binding(
                action.code(),
                c.old_binding_object_hash(),
                c.new_binding_object_hash(),
                c.effective_from_sequence(),
            ))
        }
        _ => Err(OperatorLifecycleError::AuditFailed),
    }
}

pub(super) fn record_local_audit_for(
    head: ea_trust::WriterRegistryHeadRef<'_>,
    audit: &dyn LocalAuditService,
    local_device: VerifiedLocalDeviceIdentity,
    device: &AuthenticatedDevice,
    event: TypedLocalAuditEvent,
) -> Result<(), OperatorLifecycleError> {
    let action = audit_context(&event.action)?;
    let outcome = event.outcome;
    let signed = audit
        .record_signed(AuditActorProof::AuthenticatedDevice(device), event)
        .map_err(|_| OperatorLifecycleError::AuditFailed)?;
    let checked = (|| {
        let row = ea_format::decode_local_audit_event(signed.exact_bytes()).map_err(|_| ())?;
        if row.signer_certificate_object_hash().as_bytes() != local_device.certificate.as_bytes()
            || row.organization_id() != local_device.organization
            || row.device_id() != local_device.device
            || row.operator_binding_object_hash() != device.known_binding_object_hash()
            || audit_context(row.action()).map_err(|_| ())? != action
            || row.outcome() != outcome
            || row.effective_now() != head.preexisting_effective_now().value()
        {
            return Err(());
        }
        let mut decoder = minicbor::Decoder::new(signed.exact_bytes());
        decoder.array().map_err(|_| ())?;
        decoder.skip().map_err(|_| ())?;
        let start = decoder.position();
        decoder.skip().map_err(|_| ())?;
        let context = VerificationContext::local_audit(
            row.exact_core(),
            head.proposed_sequence(),
            local_device.role,
            head.registry_version(),
        )
        .map_err(|_| ())?;
        verify_cose_sign1(
            &signed.exact_bytes()[start..decoder.position()],
            &head,
            &context,
        )
        .map_err(|_| ())?;
        Ok(())
    })();
    checked.map_err(|_| OperatorLifecycleError::AuditFailed)
}
