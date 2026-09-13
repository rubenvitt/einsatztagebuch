//! Purpose-only native presence for the one-use Clock Release.
use crate::{
    MAX_INACTIVITY_MS, OperatorError, OsAccountProvider, REAUTH_CHALLENGE_DOMAIN, ReauthPurpose,
};
use ea_crypto::CanonicalPublicCoseKey;
use ea_trust::ClockRepairRegistryAuthority;
use ea_types::{Hash32, ObjectHash, OperatorSubjectId, OrganizationId, UnixMillis};

/// Unverified local profile input. No profile text or salt enters the proof.
pub struct ClockRepairProfileSnapshot<'a> {
    pub organization_id: OrganizationId,
    pub operator_subject_id: OperatorSubjectId,
    pub binding_hash: ObjectHash,
    pub display_name: &'a str,
    pub function_label: &'a str,
    pub salt: &'a [u8; 32],
}

/// Borrowed purpose-only proof; cannot become a general Operator session.
/// Fresh trust, native watcher and posture checks remain required by its host.
pub struct ClockRepairSession<'a> {
    authority: &'a ClockRepairRegistryAuthority,
    nonce: [u8; 32],
    expires_at: UnixMillis,
    invalidated: bool,
}
impl ClockRepairSession<'_> {
    /// Read-only reference to the original purpose-limited proof, never a
    /// current, historical, Writer or generic signer authority.
    pub fn authority(&self) -> &ClockRepairRegistryAuthority {
        self.authority
    }
    /// Binds the Login audit to this exact purpose, nonce and frozen context.
    pub fn login_subject_hash(&self) -> ObjectHash {
        ea_crypto::object_hash(&challenge_bytes(
            self.authority,
            &self.nonce,
            self.expires_at,
        ))
    }

    pub fn context_hash(&self) -> Hash32 {
        self.authority.context_hash()
    }
    pub fn challenge_nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    pub fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
    pub fn is_valid_at(&self, now: UnixMillis) -> bool {
        !self.invalidated && now >= self.authority.raw_now() && now < self.expires_at
    }
    pub fn invalidate_on_lock(&mut self) {
        self.invalidated = true;
    }
}

/// Verifies only Clock-specific presence. It cannot admit ordinary Admin,
/// Writer, Recovery, or generic audit actions.
pub fn authenticate_clock_repair<'a>(
    authority: &'a ClockRepairRegistryAuthority,
    account: &dyn OsAccountProvider,
    local_device_public: &CanonicalPublicCoseKey,
    profile: &ClockRepairProfileSnapshot<'_>,
    presence: impl FnOnce(&[u8]) -> Result<[u8; 64], OperatorError>,
) -> Result<ClockRepairSession<'a>, OperatorError> {
    let certificate = authority.certificate_fields();
    if certificate.signing_public_cose_key.as_deref()
        != Some(local_device_public.to_deterministic_cbor().as_slice())
        || certificate.signing_key_thumbprint != Some(local_device_public.thumbprint())
    {
        return Err(OperatorError::DeviceMismatch);
    }
    let binding = authority.binding_fields();
    if profile.organization_id != authority.organization_id()
        || profile.operator_subject_id != binding.operator_subject_id
        || profile.binding_hash != authority.binding_hash()
        || ea_crypto::operator_profile_commitment(
            profile.organization_id,
            profile.operator_subject_id,
            profile.display_name,
            profile.function_label,
            profile.salt,
        ) != binding.operator_profile_commitment
    {
        return Err(OperatorError::ProofMismatch);
    }
    let instance = verify_account(authority, account)?;
    let expires_at = UnixMillis::new(
        authority
            .raw_now()
            .get()
            .checked_add(MAX_INACTIVITY_MS)
            .ok_or(OperatorError::ValidityWindowUnrepresentable)?,
    )
    .min(authority.valid_until());
    if expires_at <= authority.raw_now() {
        return Err(OperatorError::PresenceProofInvalid);
    }
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| OperatorError::LocalRng)?;
    let challenge = challenge_bytes(authority, &nonce, expires_at);
    let signature = presence(&challenge)?;
    instance
        .verify_ed25519_strict(&challenge, &signature)
        .map_err(|_| OperatorError::PresenceProofInvalid)?;
    // The blocking OS presence operation must not hide an account/key change.
    if verify_account(authority, account)? != instance {
        return Err(OperatorError::InstanceKeyMismatch);
    }
    Ok(ClockRepairSession {
        authority,
        nonce,
        expires_at,
        invalidated: false,
    })
}
fn verify_account(
    authority: &ClockRepairRegistryAuthority,
    account: &dyn OsAccountProvider,
) -> Result<CanonicalPublicCoseKey, OperatorError> {
    if account.os_account_binding_hash(authority.organization_id(), authority.device_id())?
        != authority.binding_fields().os_account_binding_hash
    {
        return Err(OperatorError::AccountMismatch);
    }
    let instance = account
        .operator_instance_public_key()?
        .ok_or(OperatorError::InstanceKeyMissing)?;
    if instance.thumbprint() != authority.binding_fields().operator_instance_key_thumbprint {
        return Err(OperatorError::InstanceKeyMismatch);
    }
    Ok(instance)
}
fn challenge_bytes(
    authority: &ClockRepairRegistryAuthority,
    nonce: &[u8; 32],
    end: UnixMillis,
) -> Vec<u8> {
    let label = ReauthPurpose::ClockSkewRelease.label().as_bytes();
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(REAUTH_CHALLENGE_DOMAIN);
    bytes.push(u8::try_from(label.len()).expect("closed purpose label"));
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(authority.organization_id().as_bytes());
    bytes.extend_from_slice(authority.device_id().as_bytes());
    bytes.extend_from_slice(authority.binding_hash().as_bytes());
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(&authority.raw_now().get().to_be_bytes());
    bytes.extend_from_slice(&end.get().to_be_bytes());
    bytes.extend_from_slice(b"\0exact-clock-repair-context-v1\0");
    bytes.extend_from_slice(authority.context_hash().as_bytes());
    bytes
}
