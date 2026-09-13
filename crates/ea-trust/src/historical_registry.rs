//! Read-only authority of an exact signed historical Registry and sequence.
//! A Registry lease limits new actions; it does not erase archived signatures.
use crate::{EffectiveWriterTransitionV1, resolver::PreviousHeadState};
use ea_crypto::{CryptoError, ResolvedSigner, SignerCertificateResolver};
use ea_format::{DeviceCertificateFieldsV1, PolicyFieldsV1};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, ObjectHash, OrganizationId, RegistryVersion,
};
use std::sync::Arc;

/// Produced only by exact signed-line replay. It carries no current time or
/// permission to issue anything, and cannot become a SelectedRegistryHead.
///
/// ```compile_fail
/// fn act(head:&ea_trust::SelectedRegistryHead) {}
/// fn historical(head:&ea_trust::HistoricalRegistryAuthority) { act(head); }
/// ```
pub struct HistoricalRegistryAuthority {
    pub(crate) state: Arc<PreviousHeadState>,
    pub(crate) chain: ChainId,
    pub(crate) sequence: ChainSequence,
}
impl HistoricalRegistryAuthority {
    pub fn registry_version(&self) -> RegistryVersion {
        self.state.registry_version
    }
    pub fn registry_head_hash(&self) -> ObjectHash {
        ObjectHash::from(self.state.registry_head_hash)
    }
    pub fn organization_id(&self) -> OrganizationId {
        self.state.root.fields.organization_id
    }
    pub fn chain_id(&self) -> ChainId {
        self.chain
    }
    pub fn proposed_sequence(&self) -> ChainSequence {
        self.sequence
    }
    pub fn active_certificate_fields(
        &self,
        hash: CertificateHash,
    ) -> Option<&DeviceCertificateFieldsV1> {
        self.state
            .active_certificate(hash, self.sequence)
            .map(|c| &c.fields)
    }
    /// Historically admitted identities in this verified snapshot, including
    /// revoked holders. This iterator grants no signing or reading authority.
    pub fn known_certificate_fields(
        &self,
    ) -> impl Iterator<Item = (CertificateHash, &DeviceCertificateFieldsV1)> {
        self.state
            .certificates
            .iter()
            .map(|(hash, cert)| (*hash, &cert.fields))
    }
    pub fn effective_writer_transition(&self) -> Option<&EffectiveWriterTransitionV1> {
        self.state.writer_transition.as_ref()
    }
    pub fn active_operator_binding_fields(
        &self,
        hash: ObjectHash,
    ) -> Option<&ea_format::OperatorBindingFieldsV1> {
        self.state
            .active_operator_binding(hash, self.sequence)
            .map(|b| &b.fields)
    }
    /// Authenticate an archived independent statement with its historical role.
    /// This does not mint a current-action time token or mutate a local clock.
    pub fn verify_receipt(
        &self,
        receipt: &ea_format::Parsed<ea_format::ReceiptV1>,
    ) -> Result<(), crate::TrustError> {
        if receipt.value().core().fields().chain_id != self.chain {
            return Err(crate::TrustError::ActionMismatch);
        }
        crate::verify_receipt_time(
            &crate::PreexistingRegistryAuthority {
                inner: Arc::clone(&self.state),
            },
            receipt,
        )
        .map(|_| ())
    }
    pub fn verify_checkpoint(
        &self,
        evidence: &ea_format::Parsed<ea_format::EvidenceObjectV1>,
    ) -> Result<(), crate::TrustError> {
        let ea_format::DecodedEvidencePayloadV1::Standard { core, .. } = evidence
            .value()
            .decoded_payload()
            .map_err(|_| crate::TrustError::Signature)?
        else {
            return Err(crate::TrustError::TimeSourceUnsupported);
        };
        if core.fields().chain_id != self.chain {
            return Err(crate::TrustError::ActionMismatch);
        }
        crate::verify_checkpoint_time(
            &crate::PreexistingRegistryAuthority {
                inner: Arc::clone(&self.state),
            },
            evidence,
        )
        .map(|_| ())
    }
    pub fn policy_fields(&self) -> &PolicyFieldsV1 {
        &self
            .state
            .policy
            .as_ref()
            .expect("verified registry policy")
            .fields
    }
}
impl SignerCertificateResolver for HistoricalRegistryAuthority {
    fn resolve(
        &self,
        certificate: CertificateHash,
        registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        self.state
            .resolve_selected(certificate, registry, self.sequence)
    }
}
