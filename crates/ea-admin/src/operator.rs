//! Operator lifecycle orchestration. Prepared objects acquire authority only through Registry selection.
use crate::operator_profile::{self, PendingProfile, verify_operator_snapshot};
use crate::{AdminError, RootCeremonyService};
use ea_audit::{AuditActorProof, AuthenticatedDevice, LocalAuditService, TypedLocalAuditEvent};
use ea_crypto::{CanonicalPublicCoseKey, object_hash};
use ea_draft::OperatorProfile;
use ea_format::{
    BindingLifecycleContextV1, CertificateKindV1, ExactObjectBytes, GenericAuditContextV1,
    LocalAuditActionV1, LocalAuditOutcomeV1, OperatorBindingFieldsV1, OperatorRoleV1,
    RegistryChangeV1, RegistryEventFieldsV1, TrustPayloadV1,
};
use ea_local_store::{EncryptedDatabase, StoreError};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OperatorSessionProof, OsAccountProvider,
    ReauthPurpose, verify_current_session,
};
use ea_trust::{
    SelectedRegistryHead, TrustError, TrustStateStore, VerifiedAdminAuthorizationIntent,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, Hash32, ObjectHash, OperatorSubjectId,
    OrganizationId, RegistryVersion, UnixMillis,
};
use std::{fmt, sync::Arc};

#[path = "operator_host.rs"]
pub(crate) mod operator_host;
pub use operator_host::*;

#[path = "operator_revocation.rs"]
pub(crate) mod operator_revocation;

#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum OperatorLifecycleError {
    Unsupported,
    IdentityVerification,
    ProfileCommitment,
    ProfileMissing,
    ProfileConflict,
    ReplacementRequiresRevocation,
    FreshInstanceRequired,
    RegistryWindow,
    TargetMismatch,
    AuditFailed,
    JournalConflict,
    Readiness,
    Operator(OperatorError),
    Trust(TrustError),
    Ceremony(AdminError),
    Store(StoreError),
    Format(ea_format::FormatError),
}
impl OperatorLifecycleError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unsupported => "EA-OPERATOR-UNSUPPORTED",
            Self::IdentityVerification => "EA-OPERATOR-IDENTITY-VERIFICATION",
            Self::ProfileCommitment => "EA-OPERATOR-PROFILE-COMMITMENT",
            Self::ProfileMissing => "EA-OPERATOR-PROFILE-MISSING",
            Self::ProfileConflict => "EA-OPERATOR-PROFILE-CONFLICT",
            Self::ReplacementRequiresRevocation => "EA-OPERATOR-REPLACEMENT-REQUIRES-REVOCATION",
            Self::FreshInstanceRequired => "EA-OPERATOR-FRESH-INSTANCE-REQUIRED",
            Self::RegistryWindow => "EA-OPERATOR-REGISTRY-WINDOW",
            Self::TargetMismatch => "EA-OPERATOR-TARGET-MISMATCH",
            Self::AuditFailed => "EA-OPERATOR-AUDIT-FAILED",
            Self::JournalConflict => "EA-OPERATOR-JOURNAL-CONFLICT",
            Self::Readiness => "EA-OPERATOR-NOT-READY",
            Self::Operator(e) => e.code(),
            Self::Trust(e) => e.code(),
            Self::Ceremony(e) => e.code(),
            Self::Store(e) => e.code(),
            Self::Format(e) => e.code(),
        }
    }
}
impl fmt::Debug for OperatorLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl fmt::Display for OperatorLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for OperatorLifecycleError {}
impl From<StoreError> for OperatorLifecycleError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<OperatorError> for OperatorLifecycleError {
    fn from(e: OperatorError) -> Self {
        Self::Operator(e)
    }
}
impl From<ea_format::FormatError> for OperatorLifecycleError {
    fn from(e: ea_format::FormatError) -> Self {
        Self::Format(e)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceKeyPolicy {
    InstallationBoundNonRoamingBackupExcluded,
}

/// Trusted native boundary: atomically read this account and create a NEW Ed25519 key.
/// Private keys must never roam, sync, or enter backups; Linux requires a fresh
/// account instance in a PAM-unlocked Secret Service collection. No file adapter.
pub trait NativeOperatorProvisioning: OsAccountProvider {
    fn create_fresh_instance(
        &self,
        policy: InstanceKeyPolicy,
    ) -> Result<CanonicalPublicCoseKey, OperatorLifecycleError>;
    fn prove_presence_and_sign(&self, challenge: &[u8])
    -> Result<[u8; 64], OperatorLifecycleError>;
}

pub struct ExternalIdentityRequest {
    pub organization_id: OrganizationId,
    pub device_id: DeviceId,
    pub role: OperatorRoleV1,
    pub previous_subject_id: Option<OperatorSubjectId>,
    pub previous_binding_object_hash: Option<ObjectHash>,
    pub challenge: [u8; 32],
}
/// Returned exclusively by the trusted external identity-verification adapter.
/// The adapter assigns stable person IDs; a caller-entered name is no evidence.
/// It must independently identify any previous binding, even after local profile
/// loss. `None` attests first enrollment, not merely an empty local database.
pub struct ExternalOperatorIdentity {
    pub organization_id: OrganizationId,
    pub operator_subject_id: OperatorSubjectId,
    pub display_name: String,
    pub function_label: String,
    /// Fresh CSPRNG salt issued by the identifying organizational Admin. Deliver
    /// only in the encrypted attestation response; never in public exchange data.
    pub profile_commitment_salt: [u8; 32],
    pub previous_binding_object_hash: Option<ObjectHash>,
    pub challenge: [u8; 32],
}
pub trait ExternalOperatorIdentityVerifier {
    fn verify_identity(
        &self,
        request: &ExternalIdentityRequest,
    ) -> Result<ExternalOperatorIdentity, OperatorLifecycleError>;
}

pub enum OperatorTrustTarget {
    Binding(OperatorBindingFieldsV1),
    Registry(RegistryEventFieldsV1),
}
impl OperatorTrustTarget {
    pub fn payload(
        &self,
        authorization: ObjectHash,
    ) -> Result<TrustPayloadV1, OperatorLifecycleError> {
        Ok(match self {
            Self::Binding(f) => {
                TrustPayloadV1::authorized_operator_binding(f.clone(), authorization)?
            }
            Self::Registry(f) => TrustPayloadV1::registry_event(f.clone(), authorization)?,
        })
    }
}
pub struct AuthorizedOperatorIntent {
    pub intent: VerifiedAdminAuthorizationIntent,
    pub exact_authorization: Vec<u8>,
}
/// Offline authorization adapter. It obtains fresh Admin authorization and calls
/// `ea_trust::verify_intended_trust_target` against this unchanged selected head.
pub trait OperatorAuthorizationPort {
    /// Add the exact prepared binding pair to a private authority catalog. This
    /// is called after local readiness; it never includes activation objects.
    fn include_prepared_objects(
        &mut self,
        _objects: &[&[u8]],
    ) -> Result<(), OperatorLifecycleError> {
        Ok(())
    }
    /// Reconcile an uncertain Root response for this exact recorded authorization.
    /// The authority must retain its consumed authorization and audited response
    /// durably. Never substitute a newly authorized target or a new nonce.
    fn recover_activation(
        &mut self,
        _head: &SelectedRegistryHead,
        _target: &OperatorTrustTarget,
        _exact_authorization: &[u8],
    ) -> Result<Vec<u8>, OperatorLifecycleError> {
        Err(OperatorLifecycleError::Unsupported)
    }
    /// Recover the retained reply for an exact activation target whose remote
    /// authorization call was interrupted. Must never issue a new authorization.
    fn recover_authorization(
        &mut self,
        _head: &SelectedRegistryHead,
        _target: &OperatorTrustTarget,
    ) -> Result<AuthorizedOperatorIntent, OperatorLifecycleError> {
        Err(OperatorLifecycleError::Unsupported)
    }
    fn authorize(
        &mut self,
        head: &SelectedRegistryHead,
        target: &OperatorTrustTarget,
    ) -> Result<AuthorizedOperatorIntent, OperatorLifecycleError>;
    /// Durably stage the exact public objects for restart/transport, without
    /// selecting a Registry head. Called only after successful audit persistence.
    /// Used for revocation. Binding publication uses `OperatorBindingPublisher`.
    fn stage_signed_objects(&mut self, objects: &[&[u8]]) -> Result<(), OperatorLifecycleError>;
}
pub struct OperatorMutationPorts<'a> {
    pub authorization: &'a mut dyn OperatorAuthorizationPort,
    pub ceremony: &'a RootCeremonyService<'a>,
    pub store: &'a mut dyn TrustStateStore,
}
/// Presence signing without pre-resolving a requested operator binding.
pub trait OperatorPresence {
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError>;
}
impl<T: OperatorAuthenticator + ?Sized> OperatorPresence for T {
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        OperatorAuthenticator::prove_presence_and_sign(self, challenge)
    }
}
pub struct VerifySessionRequest<'a> {
    pub database: &'a Arc<EncryptedDatabase>,
    pub binding_object_hash: ObjectHash,
    pub device_certificate_hash: CertificateHash,
    pub role: OperatorRoleV1,
    pub purpose: ReauthPurpose,
    pub account: Arc<dyn OsAccountProvider>,
    pub authenticator: &'a dyn OperatorPresence,
}
pub struct VerifiedOperatorSession {
    profile: OperatorProfile,
    proof: OperatorSessionProof,
}
impl VerifiedOperatorSession {
    pub fn profile(&self) -> &OperatorProfile {
        &self.profile
    }
    pub fn proof(&self) -> &OperatorSessionProof {
        &self.proof
    }
    pub fn into_parts(self) -> (OperatorProfile, OperatorSessionProof) {
        (self.profile, self.proof)
    }
}
#[derive(Clone, Copy)]
pub struct RegistryWindow {
    /// At or after the selected proposal, within its lease or at the next boundary.
    pub effective_from_sequence: ChainSequence,
    pub valid_through_sequence: ChainSequence,
    pub not_after: UnixMillis,
}
pub struct ProvisionOperatorRequest<'a> {
    pub database: &'a Arc<EncryptedDatabase>,
    pub device_certificate_hash: CertificateHash,
    pub role: OperatorRoleV1,
    pub window: RegistryWindow,
    pub replacement: Option<&'a RevokedOperatorBinding>,
}
pub struct RevokedOperatorBinding {
    old_hash: ObjectHash,
    old_fields: OperatorBindingFieldsV1,
    chain_id: ChainId,
}
impl RevokedOperatorBinding {
    /// Recover evidence from an activated-and-revoked binding in verified current
    /// state. Replacement rechecks this state, including its chain and revocation.
    pub fn resolve(
        current: &SelectedRegistryHead,
        old_hash: ObjectHash,
    ) -> Result<Self, OperatorLifecycleError> {
        let old_fields = current
            .revoked_operator_binding_fields(old_hash)
            .filter(|fields| {
                fields.organization_id == current.root_certificate_fields().organization_id
            })
            .ok_or(OperatorLifecycleError::ReplacementRequiresRevocation)?;
        Ok(Self {
            old_hash,
            old_fields: old_fields.clone(),
            chain_id: current.chain_id(),
        })
    }

    /// Also verifies the exact transition from an active binding to its revocation.
    pub fn verify(
        previous: &SelectedRegistryHead,
        current: &SelectedRegistryHead,
        exact_registry_event: &[u8],
        old_hash: ObjectHash,
    ) -> Result<Self, OperatorLifecycleError> {
        use ea_format::{DecodedTrustPayloadV1, decode_exact_object};
        let old_fields = previous
            .active_operator_binding_fields(old_hash)
            .ok_or(OperatorLifecycleError::ReplacementRequiresRevocation)?;
        let ea_format::ParsedArchiveObject::Trust(parsed) =
            decode_exact_object(exact_registry_event)?
        else {
            return Err(OperatorLifecycleError::ReplacementRequiresRevocation);
        };
        let DecodedTrustPayloadV1::RegistryEvent(event) = parsed.value().decoded_payload()? else {
            return Err(OperatorLifecycleError::ReplacementRequiresRevocation);
        };
        let fields = event.fields();
        if object_hash(exact_registry_event) != current.registry_head_hash()
            || previous.chain_id() != current.chain_id()
            || fields.organization_id != old_fields.organization_id
            || fields
                .previous_registry_hash
                .is_none_or(|h| h.as_bytes() != previous.registry_head_hash().as_bytes())
            || previous.registry_version().get().checked_add(1)
                != Some(current.registry_version().get())
            || current.proposed_sequence() < fields.effective_from_sequence
            || current.active_operator_binding_fields(old_hash).is_some()
            || !matches!(fields.change,RegistryChangeV1::Target{target_kind:1,object_hash} if object_hash==old_hash)
        {
            return Err(OperatorLifecycleError::ReplacementRequiresRevocation);
        }
        let evidence = Self::resolve(current, old_hash)?;
        let mut expected = old_fields.clone();
        expected.revoked_from_sequence = Some(fields.effective_from_sequence);
        if evidence.old_fields != expected {
            return Err(OperatorLifecycleError::ReplacementRequiresRevocation);
        }
        Ok(evidence)
    }
}
pub struct RevokeOperatorRequest<'a> {
    /// Durable target database, reused unchanged after interruption.
    pub database: &'a EncryptedDatabase,
    pub binding_object_hash: ObjectHash,
    pub window: RegistryWindow,
}
pub struct PreparedOperatorRevocation {
    registry: ExactObjectBytes,
    authorization: Vec<u8>,
}
impl PreparedOperatorRevocation {
    pub fn registry_bytes(&self) -> &[u8] {
        self.registry.as_bytes()
    }
    pub fn authorization_bytes(&self) -> &[u8] {
        &self.authorization
    }
}
pub(crate) struct SignedOperatorBinding {
    binding: ExactObjectBytes,
    binding_authorization: Vec<u8>,
    authorization_use_time: UnixMillis,
}
impl SignedOperatorBinding {
    pub fn binding_object_hash(&self) -> ObjectHash {
        ea_crypto::object_hash(self.binding.as_bytes())
    }
}
pub struct OperatorBindingService<'a> {
    head: &'a SelectedRegistryHead,
    audit: &'a dyn LocalAuditService,
    local_device: VerifiedLocalDeviceIdentity,
}
impl<'a> OperatorBindingService<'a> {
    pub const fn new(
        head: &'a SelectedRegistryHead,
        audit: &'a dyn LocalAuditService,
        local_device: VerifiedLocalDeviceIdentity,
    ) -> Self {
        Self {
            head,
            audit,
            local_device,
        }
    }
    /// Revokes a binding using wire target-kind 1/action 1. Admin certificate
    /// revocation (action 5) belongs to the separate certificate lifecycle.
    pub fn revoke(
        &self,
        request: RevokeOperatorRequest<'_>,
        ports: &mut OperatorMutationPorts<'_>,
        reauth: VerifySessionRequest<'_>,
    ) -> Result<PreparedOperatorRevocation, OperatorLifecycleError> {
        if reauth.purpose != ReauthPurpose::AdminRootCeremony {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        let actor = self.verify_session(reauth)?;
        let event = self.revocation_target(&request, actor.proof())?;
        let signed = (|| {
            self.head
                .active_operator_binding_fields(request.binding_object_hash)
                .ok_or(OperatorError::BindingNotActive)?;
            self.sign(
                &OperatorTrustTarget::Registry(event.clone()),
                ports,
                actor.proof(),
                None,
            )
        })();
        let outcome = if signed.is_ok() {
            LocalAuditOutcomeV1::Accepted
        } else {
            LocalAuditOutcomeV1::Failed
        };
        self.audit
            .record_signed(
                AuditActorProof::OperatorSession(actor.proof()),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::Revocation(BindingLifecycleContextV1::new(
                        Some(request.binding_object_hash),
                        None,
                        event.effective_from_sequence,
                    )),
                    outcome,
                },
            )
            .map_err(|_| OperatorLifecycleError::AuditFailed)?;
        let (registry, authorized) = signed?;
        let authorization = authorized.exact_authorization;
        if let Err(error) = ports
            .authorization
            .stage_signed_objects(&[&authorization, registry.as_bytes()])
        {
            self.audit
                .record_signed(
                    AuditActorProof::OperatorSession(actor.proof()),
                    TypedLocalAuditEvent {
                        action: LocalAuditActionV1::Revocation(BindingLifecycleContextV1::new(
                            Some(request.binding_object_hash),
                            None,
                            event.effective_from_sequence,
                        )),
                        outcome: LocalAuditOutcomeV1::Failed,
                    },
                )
                .map_err(|_| OperatorLifecycleError::AuditFailed)?;
            return Err(error);
        }
        Ok(PreparedOperatorRevocation {
            registry,
            authorization,
        })
    }
    /// Performs fresh native presence, current-head verification, and exact decrypted
    /// profile comparison. Neither profile nor proof escapes before the Login audit.
    pub fn verify_session(
        &self,
        request: VerifySessionRequest<'_>,
    ) -> Result<VerifiedOperatorSession, OperatorLifecycleError> {
        self.verify_session_inner(request, None)
    }

    pub fn verify_session_for_context(
        &self,
        request: VerifySessionRequest<'_>,
        context_hash: Hash32,
    ) -> Result<VerifiedOperatorSession, OperatorLifecycleError> {
        self.verify_session_inner(request, Some(context_hash))
    }

    /// Bucht die Abweisung einer abgelaufenen Sitzung (DRK-282, AK 53).
    ///
    /// Der Aufrufer weist die Sitzung ohnehin ab; diese Zeile hält nur fest,
    /// DASS abgewiesen wurde, und zwar als Ablauf (`sessionExpired`) mit dem
    /// Ausgang `failed`. Gebucht wird unter dem geprüften Gerät, wie bei der
    /// gescheiterten Anmeldung: die Bindung erscheint nur als Hash und nur,
    /// wenn sie am gewählten Kopf für genau dieses Gerät aktiv ist — sonst
    /// wird die Zeile niemandem zugerechnet. Kein Konto, kein Name, kein Salt.
    ///
    /// # Errors
    ///
    /// Der Fehler der Gerätprüfung oder [`OperatorLifecycleError::AuditFailed`],
    /// wenn die Zeile nicht signiert, nicht dauerhaft geschrieben oder nicht
    /// zurückgelesen werden konnte. Der Aufrufer bleibt dann bei seiner
    /// Abweisung.
    pub fn record_session_expired(
        &self,
        binding_object_hash: ObjectHash,
        device_certificate_hash: CertificateHash,
    ) -> Result<(), OperatorLifecycleError> {
        let authority = SessionAuthority::Current(self.head);
        authority.check(self.local_device)?;
        let head = authority.view();
        let (device, known) = audit_device(
            head,
            self.local_device,
            binding_object_hash,
            device_certificate_hash,
        )?;
        operator_host::record_local_audit_for(
            head,
            self.audit,
            self.local_device,
            &device,
            TypedLocalAuditEvent::session_expired(known),
        )
    }

    fn verify_session_inner(
        &self,
        request: VerifySessionRequest<'_>,
        context_hash: Option<Hash32>,
    ) -> Result<VerifiedOperatorSession, OperatorLifecycleError> {
        verify_session_with_authority(
            SessionAuthority::Current(self.head),
            self.audit,
            self.local_device,
            request,
            context_hash,
        )
    }

    /// Signs only the binding, then atomically persists its encrypted profile and
    /// journal. Activation authorization starts separately in `authorize_prepared`.
    pub fn provision(
        &self,
        request: ProvisionOperatorRequest<'_>,
        native: &dyn NativeOperatorProvisioning,
        identity: &dyn ExternalOperatorIdentityVerifier,
        ports: &mut OperatorMutationPorts<'_>,
        reauth: VerifySessionRequest<'_>,
    ) -> Result<PreparedOperatorBinding, OperatorLifecycleError> {
        if reauth.purpose != ReauthPurpose::AdminRootCeremony {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        let actor = self.verify_session(reauth)?;
        let mut event = self.registry_event(
            request.window,
            RegistryChangeV1::OperatorBinding {
                object_hash: ObjectHash::from(Hash32::ZERO),
            },
        )?;
        let old_hash = request.replacement.map(|r| r.old_hash);
        let mut attempted_new = None;
        let preparation = (|| {
            let certificate = self
                .head
                .active_certificate_fields(request.device_certificate_hash)
                .ok_or(OperatorError::DeviceCertificateNotActive)?;
            if !matches!(
                (certificate.certificate_kind, request.role),
                (CertificateKindV1::Writer, OperatorRoleV1::Writer)
                    | (CertificateKindV1::Reader, OperatorRoleV1::Reader)
                    | (
                        CertificateKindV1::OrganizationAdmin,
                        OperatorRoleV1::OrganizationAdmin
                    )
            ) || certificate
                .revoked_from_sequence
                .is_some_and(|s| s <= event.effective_from_sequence)
            {
                return Err(OperatorLifecycleError::TargetMismatch);
            }
            let old = operator_profile::load(request.database)?;
            if let Some(replacement) = request.replacement {
                if replacement.chain_id != self.head.chain_id()
                    || replacement.old_fields.organization_id != certificate.organization_id
                    || self
                        .head
                        .revoked_operator_binding_fields(replacement.old_hash)
                        != Some(&replacement.old_fields)
                {
                    return Err(OperatorLifecycleError::ReplacementRequiresRevocation);
                }
                if let Some(old) = old.as_ref() {
                    if old.operator_binding_object_hash() != replacement.old_hash {
                        return Err(OperatorLifecycleError::ProfileConflict);
                    }
                    verify_operator_snapshot(old, &replacement.old_fields)?;
                }
            } else if old.is_some() {
                return Err(OperatorLifecycleError::ReplacementRequiresRevocation);
            }
            operator_host::ensure_preparable(request.database, self.head, old_hash)?;
            let identity_request = ExternalIdentityRequest {
                organization_id: certificate.organization_id,
                device_id: certificate.device_id,
                role: request.role,
                previous_subject_id: request
                    .replacement
                    .map(|r| r.old_fields.operator_subject_id),
                previous_binding_object_hash: old_hash,
                challenge: fresh()?,
            };
            let verified = identity.verify_identity(&identity_request)?;
            if verified.previous_binding_object_hash != old_hash {
                return Err(OperatorLifecycleError::ReplacementRequiresRevocation);
            }
            if verified.organization_id != identity_request.organization_id
                || verified.challenge != identity_request.challenge
                || identity_request
                    .previous_subject_id
                    .is_some_and(|s| s != verified.operator_subject_id)
            {
                return Err(OperatorLifecycleError::IdentityVerification);
            }
            if request.role == OperatorRoleV1::OrganizationAdmin
                && certificate
                    .authority_subject_id
                    .is_none_or(|s| s.as_bytes() != verified.operator_subject_id.as_bytes())
            {
                return Err(OperatorLifecycleError::IdentityVerification);
            }
            if old.as_ref().is_some_and(|profile| {
                profile.profile_commitment_salt() == &verified.profile_commitment_salt
            }) {
                return Err(OperatorLifecycleError::ProfileCommitment);
            }
            let normalized = ea_schema::OperatorSnapshotV1::new(
                verified.organization_id,
                verified.operator_subject_id,
                verified.display_name,
                verified.function_label,
                verified.profile_commitment_salt,
                ObjectHash::from(Hash32::ZERO),
            )
            .map_err(|_| OperatorLifecycleError::ProfileCommitment)?;
            let pending = PendingProfile {
                organization: normalized.organization_id(),
                subject: normalized.operator_subject_id(),
                name: normalized.display_name().to_owned(),
                function: normalized.function_label().to_owned(),
                salt: *normalized.salt(),
            };
            let before = native.operator_instance_public_key()?;
            let account_hash = native
                .os_account_binding_hash(certificate.organization_id, certificate.device_id)?;
            let instance = native.create_fresh_instance(
                InstanceKeyPolicy::InstallationBoundNonRoamingBackupExcluded,
            )?;
            if !matches!(instance, CanonicalPublicCoseKey::Ed25519(_))
                || before.is_some_and(|k| k.thumbprint() == instance.thumbprint())
                || certificate.signing_key_thumbprint == Some(instance.thumbprint())
                || request.replacement.is_some_and(|r| {
                    r.old_fields.operator_instance_key_thumbprint == instance.thumbprint()
                })
            {
                return Err(OperatorLifecycleError::FreshInstanceRequired);
            }
            let mut challenge = b"EINSATZARCHIV-OPERATOR-PROVISION-v1".to_vec();
            challenge.extend_from_slice(certificate.organization_id.as_bytes());
            challenge.extend_from_slice(certificate.device_id.as_bytes());
            challenge.extend_from_slice(&identity_request.challenge);
            instance
                .verify_ed25519_strict(&challenge, &native.prove_presence_and_sign(&challenge)?)
                .map_err(|_| OperatorError::PresenceProofInvalid)?;
            let fields = OperatorBindingFieldsV1 {
                organization_id: pending.organization,
                operator_subject_id: pending.subject,
                operator_profile_commitment: pending.commitment()?,
                device_certificate_hash: request.device_certificate_hash,
                operator_role: request.role,
                os_account_binding_hash: account_hash,
                operator_instance_key_thumbprint: instance.thumbprint(),
                effective_from_sequence: event.effective_from_sequence,
                revoked_from_sequence: None,
            };
            let (binding, authorized) = self.sign(
                &OperatorTrustTarget::Binding(fields),
                ports,
                actor.proof(),
                None,
            )?;
            let new_hash = object_hash(binding.as_bytes());
            attempted_new = Some(new_hash);
            event.change = RegistryChangeV1::OperatorBinding {
                object_hash: new_hash,
            };
            if native.os_account_binding_hash(certificate.organization_id, certificate.device_id)?
                != account_hash
                || native
                    .operator_instance_public_key()?
                    .is_none_or(|k| k.thumbprint() != instance.thumbprint())
            {
                return Err(OperatorLifecycleError::FreshInstanceRequired);
            }
            Ok((
                pending,
                old,
                SignedOperatorBinding {
                    binding,
                    binding_authorization: authorized.exact_authorization,
                    authorization_use_time: authorized.intent.authorization_use_time(),
                },
            ))
        })();
        let outcome = if preparation.is_ok() {
            LocalAuditOutcomeV1::Accepted
        } else {
            LocalAuditOutcomeV1::Failed
        };
        self.binding_audit(
            actor.proof(),
            old_hash,
            attempted_new,
            event.effective_from_sequence,
            outcome,
        )?;
        let (pending, old, prepared) = preparation?;
        let persist = operator_host::persist_prepared(
            request.database,
            self.head,
            &pending,
            old.as_ref(),
            old_hash,
            prepared,
            request.window,
        );
        if let Err(error) = persist {
            self.binding_audit(
                actor.proof(),
                old_hash,
                attempted_new,
                event.effective_from_sequence,
                LocalAuditOutcomeV1::Failed,
            )?;
            return Err(error);
        }
        persist
    }

    fn sign(
        &self,
        target: &OperatorTrustTarget,
        ports: &mut OperatorMutationPorts<'_>,
        proof: &OperatorSessionProof,
        previous_authorization: Option<&[u8]>,
    ) -> Result<(ExactObjectBytes, AuthorizedOperatorIntent), OperatorLifecycleError> {
        let auth = ports.authorization.authorize(self.head, target)?;
        if let Some(previous) = previous_authorization {
            require_distinct_authorizations(previous, &auth.exact_authorization)?;
        }
        let payload = target.payload(object_hash(&auth.exact_authorization))?;
        let signed = ports
            .ceremony
            .publish_authorized_target(
                &auth.intent,
                payload,
                &auth.exact_authorization,
                ports.store,
                proof,
            )
            .map_err(OperatorLifecycleError::Ceremony)?;
        Ok((signed, auth))
    }
    /// `pub(crate)`, damit `crate::registry::RegistryEventFactory` GENAU diese
    /// Fensterpruefung und Versionsfortschreibung benutzt und keine zweite.
    pub(crate) fn registry_event(
        &self,
        window: RegistryWindow,
        change: RegistryChangeV1,
    ) -> Result<RegistryEventFieldsV1, OperatorLifecycleError> {
        let effective = window.effective_from_sequence;
        let now = self.head.preexisting_effective_now().value();
        if effective < self.head.proposed_sequence()
            || (effective > self.head.valid_through_sequence()
                && self.head.valid_through_sequence().get().checked_add(1) != Some(effective.get()))
            || window.valid_through_sequence < effective
            || window.not_after <= now
            || (i128::from(window.not_after.get()) - i128::from(now.get()))
                > i128::from(self.head.policy_fields().max_registry_age_ms)
        {
            return Err(OperatorLifecycleError::RegistryWindow);
        }
        Ok(RegistryEventFieldsV1 {
            organization_id: self.head.root_certificate_fields().organization_id,
            registry_version: RegistryVersion::new(
                self.head
                    .registry_version()
                    .get()
                    .checked_add(1)
                    .ok_or(OperatorLifecycleError::RegistryWindow)?,
            ),
            previous_registry_hash: Some(
                Hash32::try_from(self.head.registry_head_hash().as_bytes().as_slice())
                    .map_err(|_| OperatorLifecycleError::TargetMismatch)?,
            ),
            effective_from_sequence: effective,
            valid_through_sequence: window.valid_through_sequence,
            issued_at: now,
            not_before: now,
            not_after: window.not_after,
            policy_object_hash: match &change {
                RegistryChangeV1::Policy { object_hash } => *object_hash,
                _ => self.head.policy_object_hash(),
            },
            change,
            root_key_thumbprint: self.head.root_certificate_fields().root_key_thumbprint,
        })
    }
    fn binding_audit(
        &self,
        proof: &OperatorSessionProof,
        old: Option<ObjectHash>,
        new: Option<ObjectHash>,
        sequence: ChainSequence,
        outcome: LocalAuditOutcomeV1,
    ) -> Result<(), OperatorLifecycleError> {
        self.audit
            .record_signed(
                AuditActorProof::OperatorSession(proof),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::BindingChange(BindingLifecycleContextV1::new(
                        old, new, sequence,
                    )),
                    outcome,
                },
            )
            .map_err(|_| OperatorLifecycleError::AuditFailed)?;
        Ok(())
    }
}

struct SharedAccount(Arc<dyn OsAccountProvider>);
impl OsAccountProvider for SharedAccount {
    fn os_account_binding_hash(
        &self,
        o: OrganizationId,
        d: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        self.0.os_account_binding_hash(o, d)
    }
    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        self.0.operator_instance_public_key()
    }
}
struct FreshAuthenticator<'a> {
    bound: BoundOperator,
    native: &'a dyn OperatorPresence,
}
impl OperatorAuthenticator for FreshAuthenticator<'_> {
    fn bound_operator(&self) -> &BoundOperator {
        &self.bound
    }
    fn prove_presence_and_sign(&self, c: &[u8]) -> Result<[u8; 64], OperatorError> {
        self.native.prove_presence_and_sign(c)
    }
}
fn fresh() -> Result<[u8; 32], OperatorLifecycleError> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| OperatorError::LocalRng)?;
    Ok(bytes)
}

fn require_distinct_authorizations(
    first: &[u8],
    second: &[u8],
) -> Result<(), OperatorLifecycleError> {
    fn fields(
        bytes: &[u8],
    ) -> Result<ea_format::OrganizationAdminAuthorizationFieldsV1, OperatorLifecycleError> {
        let ea_format::ParsedArchiveObject::Trust(parsed) = ea_format::decode_exact_object(bytes)?
        else {
            return Err(OperatorLifecycleError::TargetMismatch);
        };
        let ea_format::DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) =
            parsed.value().decoded_payload()?
        else {
            return Err(OperatorLifecycleError::TargetMismatch);
        };
        Ok(fields)
    }
    let first = fields(first)?;
    let second = fields(second)?;
    if first.authorization_id == second.authorization_id || first.nonce == second.nonce {
        return Err(OperatorLifecycleError::Trust(TrustError::AuthReplay));
    }
    Ok(())
}

/// Writer-only native session boundary. No administration mutation methods.
pub struct WriterOperatorSessionService<'a> {
    head: ea_trust::WriterRegistryHeadRef<'a>,
    audit: &'a dyn LocalAuditService,
    local_device: VerifiedLocalDeviceIdentity,
}
impl<'a> WriterOperatorSessionService<'a> {
    pub fn new(
        head: ea_trust::WriterRegistryHeadRef<'a>,
        audit: &'a dyn LocalAuditService,
        local_device: VerifiedLocalDeviceIdentity,
    ) -> Self {
        Self {
            head,
            audit,
            local_device,
        }
    }
    pub fn verify_session(
        &self,
        request: VerifySessionRequest<'_>,
        context: Option<Hash32>,
    ) -> Result<VerifiedOperatorSession, OperatorLifecycleError> {
        verify_session_with_authority(
            SessionAuthority::Writer(self.head),
            self.audit,
            self.local_device,
            request,
            context,
        )
    }
}
#[derive(Clone, Copy)]
enum SessionAuthority<'a> {
    Current(&'a SelectedRegistryHead),
    Writer(ea_trust::WriterRegistryHeadRef<'a>),
}
impl SessionAuthority<'_> {
    fn view(&self) -> ea_trust::WriterRegistryHeadRef<'_> {
        match self {
            Self::Current(h) => (*h).into(),
            Self::Writer(h) => *h,
        }
    }
    fn check(&self, device: VerifiedLocalDeviceIdentity) -> Result<(), OperatorLifecycleError> {
        match self {
            Self::Current(head) => device.check(head),
            Self::Writer(head) => device.check_writer(*head),
        }
    }
    fn resolve(
        &self,
        binding: ObjectHash,
        role: OperatorRoleV1,
        purpose: ReauthPurpose,
    ) -> Result<BoundOperator, OperatorError> {
        match self {
            Self::Current(head) => BoundOperator::resolve(head, binding),
            Self::Writer(head) => {
                if role != OperatorRoleV1::Writer || !purpose.is_writer_purpose() {
                    return Err(OperatorError::RoleMismatch);
                }
                BoundOperator::resolve_writer(*head, binding)
            }
        }
    }
    fn verify(
        &self,
        request: &VerifySessionRequest<'_>,
        proof: &OperatorSessionProof,
    ) -> Result<(), OperatorError> {
        match self {
            Self::Current(head) => verify_current_session(
                head,
                request.device_certificate_hash,
                request.role,
                proof,
                request.purpose,
                request.account.as_ref(),
            ),
            Self::Writer(head) => ea_operator::verify_writer_session(
                *head,
                request.device_certificate_hash,
                proof,
                request.purpose,
                request.account.as_ref(),
            ),
        }
    }
}
/// Das geprüfte Gerät, unter dem eine Anmelde- oder Ablaufzeile gebucht wird,
/// und die Bindung, die ihr zugerechnet werden darf: nur eine am Kopf aktive
/// Bindung genau dieses Geräts, sonst keine.
fn audit_device(
    head: ea_trust::WriterRegistryHeadRef<'_>,
    local_device: VerifiedLocalDeviceIdentity,
    binding_object_hash: ObjectHash,
    device_certificate_hash: CertificateHash,
) -> Result<(AuthenticatedDevice, Option<ObjectHash>), OperatorLifecycleError> {
    let known = head
        .active_operator_binding_fields(binding_object_hash)
        .filter(|b| {
            b.device_certificate_hash == local_device.certificate
                && device_certificate_hash == local_device.certificate
        })
        .map(|_| binding_object_hash);
    let device = AuthenticatedDevice::new(
        local_device.organization,
        local_device.device,
        ObjectHash::try_from(local_device.certificate.as_bytes().as_slice())
            .map_err(|_| OperatorLifecycleError::TargetMismatch)?,
        known,
    );
    Ok((device, known))
}
fn verify_session_with_authority(
    authority: SessionAuthority<'_>,
    audit: &dyn LocalAuditService,
    local_device: VerifiedLocalDeviceIdentity,
    request: VerifySessionRequest<'_>,
    context_hash: Option<Hash32>,
) -> Result<VerifiedOperatorSession, OperatorLifecycleError> {
    authority.check(local_device)?;
    let head = authority.view();
    let (device, known) = audit_device(
        head,
        local_device,
        request.binding_object_hash,
        request.device_certificate_hash,
    )?;
    let result = (|| {
        head.active_certificate_fields(request.device_certificate_hash)
            .ok_or(OperatorError::DeviceCertificateNotActive)?;
        if request.device_certificate_hash != local_device.certificate {
            return Err(OperatorError::DeviceMismatch.into());
        }
        let bound =
            authority.resolve(request.binding_object_hash, request.role, request.purpose)?;
        let authenticator = FreshAuthenticator {
            bound,
            native: request.authenticator,
        };
        let account = Box::new(SharedAccount(request.account.clone()));
        let proof = match context_hash {
            Some(context) => authenticator.reauthenticate_for_context(
                account,
                request.purpose,
                head.preexisting_effective_now(),
                context,
            ),
            None => authenticator.reauthenticate(account, request.purpose),
        }?;
        authority.verify(&request, &proof)?;
        let profile = operator_profile::load(request.database)?
            .ok_or(OperatorLifecycleError::ProfileMissing)?;
        if profile.operator_binding_object_hash() != request.binding_object_hash {
            return Err(OperatorLifecycleError::ProfileCommitment);
        }
        let fields = head
            .active_operator_binding_fields(request.binding_object_hash)
            .ok_or(OperatorError::BindingNotActive)?;
        verify_operator_snapshot(&profile, fields)?;
        Ok(VerifiedOperatorSession { profile, proof })
    })();
    let outcome = if result.is_ok() {
        LocalAuditOutcomeV1::Completed
    } else {
        LocalAuditOutcomeV1::Failed
    };
    operator_host::record_local_audit_for(
        head,
        audit,
        local_device,
        &device,
        TypedLocalAuditEvent {
            action: LocalAuditActionV1::Login(GenericAuditContextV1::new(known)),
            outcome,
        },
    )?;
    if result.is_err() {
        operator_host::record_local_audit_for(
            head,
            audit,
            local_device,
            &device,
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::ReauthFailure(GenericAuditContextV1::new(known)),
                outcome: LocalAuditOutcomeV1::Failed,
            },
        )?;
    }
    result
}
