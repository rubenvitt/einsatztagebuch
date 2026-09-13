//! Nonproductive possession proofs. Callers supply neither a challenge nor a
//! digest: this path generates fresh entropy and exposes only the typed existing
//! recovery-test signature operation to a backup provider.
use crate::{RecoveryKeyRole, RecoveryMedium, RecoveryTestKind, ResolvedSigningKey};
use ea_crypto::{
    CanonicalPublicCoseKey, CoseSigner, CryptoError, RecoveryVerificationContext, SecretBytes,
    SignerRole, VerifiedRecoveryTest, verify_recovery_test,
};
use ea_format::CertificateKindV1;
use ea_trust::SelectedRegistryHead;
use ea_types::{CertificateHash, KeyThumbprint};
use zeroize::Zeroize;

pub trait RecoverySigningBackup {
    fn public_key(&self) -> Result<CanonicalPublicCoseKey, CryptoError>;
    fn sign_recovery_test(
        &self,
        certificate: CertificateHash,
        challenge: SecretBytes<32>,
    ) -> Result<Vec<u8>, CryptoError>;
}
impl RecoverySigningBackup for ResolvedSigningKey {
    fn public_key(&self) -> Result<CanonicalPublicCoseKey, CryptoError> {
        self.public_key()
    }
    fn sign_recovery_test(
        &self,
        certificate: CertificateHash,
        challenge: SecretBytes<32>,
    ) -> Result<Vec<u8>, CryptoError> {
        self.sign_recovery_test(certificate, challenge)
    }
}
impl RecoverySigningBackup for CoseSigner {
    fn public_key(&self) -> Result<CanonicalPublicCoseKey, CryptoError> {
        self.public_key()
    }
    fn sign_recovery_test(
        &self,
        certificate: CertificateHash,
        challenge: SecretBytes<32>,
    ) -> Result<Vec<u8>, CryptoError> {
        self.sign_recovery_test(certificate, challenge)
    }
}

/// Only a cryptographic challenge witness; it does not attest native presence,
/// inventory completeness, freshness of a runtime or durable report/audit.
pub struct VerifiedBackupChallenge(VerifiedRecoveryTest);
impl VerifiedBackupChallenge {
    pub fn key_thumbprint(&self) -> KeyThumbprint {
        self.0.key_thumbprint()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTestError {
    Archive,
    Inventory,
    Key,
    Protection,
    Role,
    Entropy,
    Payload,
    Incomplete,
    Operator,
    Audit,
    Source,
    Machine,
    Store,
}
impl RecoveryTestError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Archive => "EA-RECOVERY-TEST-ARCHIVE",
            Self::Inventory => "EA-RECOVERY-TEST-INVENTORY",
            Self::Key => "EA-RECOVERY-TEST-KEY",
            Self::Protection => "EA-RECOVERY-TEST-PROTECTION-UNVERIFIED",
            Self::Role => "EA-RECOVERY-TEST-ROLE",
            Self::Entropy => "EA-RECOVERY-TEST-ENTROPY",
            Self::Payload => "EA-RECOVERY-TEST-PAYLOAD",
            Self::Incomplete => "EA-RECOVERY-TEST-INCOMPLETE",
            Self::Operator => "EA-RECOVERY-TEST-OPERATOR",
            Self::Audit => "EA-RECOVERY-TEST-AUDIT",
            Self::Source => "EA-RECOVERY-TEST-SOURCE",
            Self::Machine => "EA-RECOVERY-TEST-MACHINE",
            Self::Store => "EA-RECOVERY-TEST-STORE",
        }
    }
}
impl std::fmt::Display for RecoveryTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for RecoveryTestError {}

pub fn verify_signing_backup(
    head: &SelectedRegistryHead,
    medium: &RecoveryMedium,
    backup: &dyn RecoverySigningBackup,
) -> Result<VerifiedBackupChallenge, RecoveryTestError> {
    if medium.test_kind() == RecoveryTestKind::RecoveryDecrypt {
        return Err(RecoveryTestError::Role);
    }
    if medium.role() == RecoveryKeyRole::Root {
        if medium.certificate().as_bytes() != head.root_certificate_object_hash().as_bytes()
            || medium.expected_thumbprint() != head.root_certificate_fields().root_key_thumbprint
        {
            return Err(RecoveryTestError::Role);
        }
    } else {
        let cert = head
            .active_certificate_fields(medium.certificate())
            .ok_or(RecoveryTestError::Role)?;
        if certificate_role(cert.certificate_kind) != medium.role()
            || cert.signing_key_thumbprint != Some(medium.expected_thumbprint())
        {
            return Err(RecoveryTestError::Role);
        }
    }
    challenge(
        head,
        medium,
        backup,
        head.policy_fields().organization_id,
        head.proposed_sequence(),
        head.registry_version(),
    )
}

/// Possession of a backup that was authorized at an exact verified historical
/// sequence. This produces only a RecoveryTestDigest witness and never a
/// current Registry authority or permission for productive signing.
pub fn verify_historical_signing_backup(
    head: &ea_trust::HistoricalRegistryAuthority,
    medium: &RecoveryMedium,
    backup: &dyn RecoverySigningBackup,
) -> Result<VerifiedBackupChallenge, RecoveryTestError> {
    if medium.test_kind() == RecoveryTestKind::RecoveryDecrypt {
        return Err(RecoveryTestError::Role);
    }
    if medium.role() != RecoveryKeyRole::Root {
        let cert = head.active_certificate_fields(medium.certificate())
            .ok_or(RecoveryTestError::Role)?;
        if certificate_role(cert.certificate_kind) != medium.role()
            || cert.signing_key_thumbprint != Some(medium.expected_thumbprint())
        {
            return Err(RecoveryTestError::Role);
        }
    }
    challenge(head, medium, backup, head.organization_id(), head.proposed_sequence(), head.registry_version())
}
fn challenge(
    resolver: &impl ea_crypto::SignerCertificateResolver,
    medium: &RecoveryMedium,
    backup: &dyn RecoverySigningBackup,
    organization: ea_types::OrganizationId,
    sequence: ea_types::ChainSequence,
    registry: ea_types::RegistryVersion,
) -> Result<VerifiedBackupChallenge, RecoveryTestError> {
    if backup
        .public_key()
        .map_err(|_| RecoveryTestError::Key)?
        .thumbprint()
        != medium.expected_thumbprint()
    {
        return Err(RecoveryTestError::Key);
    }
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| RecoveryTestError::Entropy)?;
    let to_sign = SecretBytes::new(nonce);
    let to_verify = SecretBytes::new(nonce);
    nonce.zeroize();
    let signature = backup
        .sign_recovery_test(medium.certificate(), to_sign)
        .map_err(|_| RecoveryTestError::Key)?;
    let context = RecoveryVerificationContext::new(
        medium.certificate(),
        organization,
        signer_role(medium.role()),
        sequence,
        registry,
        to_verify,
    );
    verify_recovery_test(&signature, resolver, &context)
        .map(VerifiedBackupChallenge)
        .map_err(|_| RecoveryTestError::Key)
}
pub(crate) const fn certificate_role(kind: CertificateKindV1) -> RecoveryKeyRole {
    match kind {
        CertificateKindV1::Writer => RecoveryKeyRole::Writer,
        CertificateKindV1::Reader => RecoveryKeyRole::Reader,
        CertificateKindV1::OrganizationAdmin => RecoveryKeyRole::OrganizationAdmin,
        CertificateKindV1::KeyApprover => RecoveryKeyRole::KeyApprover,
        CertificateKindV1::RecoveryRecipient => RecoveryKeyRole::RecoveryRecipient,
        CertificateKindV1::HistoricalGrantAuthority => RecoveryKeyRole::HistoricalGrantAuthority,
        CertificateKindV1::ServerReceipt => RecoveryKeyRole::ServerReceipt,
        CertificateKindV1::DeletionAttest => RecoveryKeyRole::DeletionAttest,
    }
}
const fn signer_role(role: RecoveryKeyRole) -> SignerRole {
    match role {
        RecoveryKeyRole::Root => SignerRole::Root,
        RecoveryKeyRole::OrganizationAdmin => SignerRole::OrganizationAdmin,
        RecoveryKeyRole::Writer => SignerRole::Writer,
        RecoveryKeyRole::Reader => SignerRole::Reader,
        RecoveryKeyRole::RecoveryRecipient => SignerRole::RecoveryRecipient,
        RecoveryKeyRole::ServerReceipt => SignerRole::ServerReceipt,
        RecoveryKeyRole::KeyApprover => SignerRole::KeyApprover,
        RecoveryKeyRole::HistoricalGrantAuthority => SignerRole::HistoricalGrantAuthority,
        RecoveryKeyRole::DeletionAttest => SignerRole::DeletionAttest,
    }
}
