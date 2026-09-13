//! Private historical routing; neither variant can mint current action authority.
use crate::{
    DestructionError as Error, VerifiedDestructionAuthorization, VerifiedDestructionEvent,
};
use ea_crypto::{CryptoError, ResolvedSigner, SignerCertificateResolver};
use ea_format::{DeviceCertificateFieldsV1, OperatorBindingFieldsV1};
use ea_trust::{HistoricalRegistryAuthority, SelectedRegistryHead};
use ea_types::{CertificateHash, ChainId, ChainSequence, ObjectHash, RegistryVersion, UnixMillis};

#[derive(Clone, Copy)]
pub(crate) enum OriginalAuthority<'a> {
    Selected(&'a SelectedRegistryHead),
    Historical(&'a HistoricalRegistryAuthority),
}
impl<'a> OriginalAuthority<'a> {
    pub(crate) fn chain_id(self) -> ChainId {
        match self {
            Self::Selected(h) => h.chain_id(),
            Self::Historical(h) => h.chain_id(),
        }
    }
    pub(crate) fn registry_version(self) -> RegistryVersion {
        match self {
            Self::Selected(h) => h.registry_version(),
            Self::Historical(h) => h.registry_version(),
        }
    }
    pub(crate) fn registry_head_hash(self) -> ObjectHash {
        match self {
            Self::Selected(h) => h.registry_head_hash(),
            Self::Historical(h) => h.registry_head_hash(),
        }
    }
    pub(crate) fn proposed_sequence(self) -> ChainSequence {
        match self {
            Self::Selected(h) => h.proposed_sequence(),
            Self::Historical(h) => h.proposed_sequence(),
        }
    }
    pub(crate) fn active_certificate_fields(
        self,
        hash: CertificateHash,
    ) -> Option<&'a DeviceCertificateFieldsV1> {
        match self {
            Self::Selected(h) => h.active_certificate_fields(hash),
            Self::Historical(h) => h.active_certificate_fields(hash),
        }
    }
    pub(crate) fn active_operator_binding_fields(
        self,
        hash: ObjectHash,
    ) -> Option<&'a OperatorBindingFieldsV1> {
        match self {
            Self::Selected(h) => h.active_operator_binding_fields(hash),
            Self::Historical(h) => h.active_operator_binding_fields(hash),
        }
    }
    pub(crate) fn authorization(
        self,
        exact: &[u8],
    ) -> Result<VerifiedDestructionAuthorization, Error> {
        match self {
            Self::Selected(h) => crate::verify_authorization(exact, h),
            Self::Historical(h) => crate::verify_authorization_historical(exact, h),
        }
    }
    pub(crate) fn event(
        self,
        exact: &[u8],
        auth: &VerifiedDestructionAuthorization,
        now: UnixMillis,
    ) -> Result<VerifiedDestructionEvent, Error> {
        match self {
            Self::Selected(h) => crate::event::verify_event_at(exact, auth, h, now),
            Self::Historical(h) => crate::verify_event_historical(exact, auth, h, now),
        }
    }
    pub(crate) fn require_binding(self, hash: ObjectHash) -> Result<(), Error> {
        match self {
            Self::Selected(h) => ea_operator::BoundOperator::resolve(h, hash)
                .map(|_| ())
                .map_err(|_| Error::Audit),
            // Exact replay already verified Root authority, binding grammar,
            // activation and exclusive successor sequence. This only attributes
            // an archived audit; no OS session is created from historical data.
            Self::Historical(h) => h
                .active_operator_binding_fields(hash)
                .map(|_| ())
                .ok_or(Error::Audit),
        }
    }
}
impl SignerCertificateResolver for OriginalAuthority<'_> {
    fn resolve(
        &self,
        certificate: CertificateHash,
        registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        match self {
            Self::Selected(h) => h.resolve(certificate, registry),
            Self::Historical(h) => h.resolve(certificate, registry),
        }
    }
}
