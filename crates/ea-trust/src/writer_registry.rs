//! Writer-only context for the existing explicit stale Registry warning.
use crate::{EffectiveWriterTransitionV1, PreexistingEffectiveNow, SelectedRegistryHead};
use ea_crypto::{CryptoError, ResolvedSigner, SignerCertificateResolver};
use ea_format::{DeviceCertificateFieldsV1, OperatorBindingFieldsV1, PolicyFieldsV1};
use ea_types::{CertificateHash, ChainId, ChainSequence, ObjectHash, RegistryVersion, UnixMillis};

/// Minted from the exact persistent current pin at actual expired time.
/// This cannot enter services requiring ordinary current Registry authority.
///
/// ```compile_fail
/// use ea_trust::{SelectedRegistryHead, StaleWriterRegistryHead};
/// fn substitute(stale: StaleWriterRegistryHead) -> SelectedRegistryHead { stale.into() }
/// ```
pub struct StaleWriterRegistryHead {
    // Private reuse of the immutable verified snapshot. No SelectedRegistryHead
    // escapes this wrapper; consumers receive only the sealed Writer view.
    pub(super) snapshot: SelectedRegistryHead,
}
impl StaleWriterRegistryHead {
    pub fn as_writer(&self) -> WriterRegistryHeadRef<'_> {
        WriterRegistryHeadRef {
            snapshot: &self.snapshot,
        }
    }
}

/// A sealed read-only input to Writer finalization and Writer operator checks.
/// Possession alone never replaces current native presence or the signed
/// one-use stale acknowledgement. No public field or raw-value constructor.
#[derive(Clone, Copy)]
pub struct WriterRegistryHeadRef<'a> {
    snapshot: &'a SelectedRegistryHead,
}
impl<'a> From<&'a SelectedRegistryHead> for WriterRegistryHeadRef<'a> {
    fn from(snapshot: &'a SelectedRegistryHead) -> Self {
        Self { snapshot }
    }
}
impl WriterRegistryHeadRef<'_> {
    pub fn registry_version(&self) -> RegistryVersion {
        self.snapshot.registry_version()
    }
    pub fn registry_head_hash(&self) -> ObjectHash {
        self.snapshot.registry_head_hash()
    }
    pub fn chain_id(&self) -> ChainId {
        self.snapshot.chain_id()
    }
    pub fn policy_object_hash(&self) -> ObjectHash {
        self.snapshot.policy_object_hash()
    }
    pub fn policy_fields(&self) -> &PolicyFieldsV1 {
        self.snapshot.policy_fields()
    }
    pub fn effective_from_sequence(&self) -> ChainSequence {
        self.snapshot.effective_from_sequence()
    }
    pub fn valid_through_sequence(&self) -> ChainSequence {
        self.snapshot.valid_through_sequence()
    }
    pub fn proposed_sequence(&self) -> ChainSequence {
        self.snapshot.proposed_sequence()
    }
    pub fn not_after(&self) -> UnixMillis {
        self.snapshot.not_after()
    }
    pub fn issued_at(&self) -> UnixMillis {
        self.snapshot.issued_at()
    }
    pub fn preexisting_effective_now(&self) -> &PreexistingEffectiveNow {
        self.snapshot.preexisting_effective_now()
    }
    pub fn active_certificate_fields(
        &self,
        certificate: CertificateHash,
    ) -> Option<&DeviceCertificateFieldsV1> {
        self.snapshot.active_certificate_fields(certificate)
    }
    pub fn active_certificates(
        &self,
    ) -> impl Iterator<Item = (CertificateHash, &DeviceCertificateFieldsV1)> {
        self.snapshot.active_certificates()
    }
    pub fn known_certificate_fields(
        &self,
    ) -> impl Iterator<Item = (CertificateHash, &DeviceCertificateFieldsV1)> {
        self.snapshot.known_certificate_fields()
    }
    pub fn current_writer_certificate_hash(&self) -> Option<CertificateHash> {
        self.snapshot.current_writer_certificate_hash()
    }
    pub fn effective_writer_transition(&self) -> Option<&EffectiveWriterTransitionV1> {
        self.snapshot.effective_writer_transition()
    }
    pub fn active_operator_binding_fields(
        &self,
        hash: ObjectHash,
    ) -> Option<&OperatorBindingFieldsV1> {
        self.snapshot.active_operator_binding_fields(hash)
    }
}
impl SignerCertificateResolver for WriterRegistryHeadRef<'_> {
    fn resolve(
        &self,
        certificate: CertificateHash,
        registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        self.snapshot.resolve(certificate, registry)
    }
}
