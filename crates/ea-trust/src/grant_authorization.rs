//! Verified authorization for historical grants, shared by issuance and opening.
use crate::SelectedRegistryHead;
use ea_crypto::{
    CryptoError, SignerCertificateResolver, VerificationContext, parse_cose_sign1,
    verify_cose_sign1,
};
use ea_format::{
    DecodedTrustPayloadV1, GrantAuthorizationFieldsV1, ParsedArchiveObject, decode_exact_object,
};
use ea_types::{CertificateHash, ObjectHash};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GrantAuthorizationError {
    Unverifiable,
    Mismatch,
    Insufficient,
    Expired,
}
impl GrantAuthorizationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unverifiable => "EA-GRANT-AUTHORIZATION-UNVERIFIABLE",
            Self::Mismatch => "EA-GRANT-AUTHORIZATION-MISMATCH",
            Self::Insufficient => "EA-GRANT-AUTHORIZATION-INSUFFICIENT",
            Self::Expired => "EA-GRANT-AUTH-EXPIRED",
        }
    }
}
/// Minted only after signature, personhood, Registry and effective-time checks.
/// Its subtype and signature domain bind the historical-regrant purpose.
///
/// ```compile_fail
/// let proof = ea_trust::VerifiedGrantAuthorization {
///     exact_bytes: Vec::new(), object_hash: panic!(), fields: panic!(),
/// };
/// ```
pub struct VerifiedGrantAuthorization {
    exact_bytes: Vec<u8>,
    object_hash: ObjectHash,
    fields: GrantAuthorizationFieldsV1,
}
impl VerifiedGrantAuthorization {
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }
    pub const fn fields(&self) -> &GrantAuthorizationFieldsV1 {
        &self.fields
    }
}
pub fn verify_grant_authorization(
    bytes: &[u8],
    head: &SelectedRegistryHead,
) -> Result<VerifiedGrantAuthorization, GrantAuthorizationError> {
    verify_authorization(
        bytes,
        head,
        head.root_certificate_fields().organization_id,
        head.registry_version(),
        head.registry_head_hash(),
        head.proposed_sequence(),
        head.preexisting_effective_now().value(),
    )
}

/// Verifies archived approval signatures and their explicit expiry. The returned
/// proof carries no current action authority; issuance rechecks its exact bytes
/// against a fresh SelectedRegistryHead.
pub fn verify_archived_grant_authorization(
    bytes: &[u8],
    head: &crate::HistoricalRegistryAuthority,
    now: ea_types::UnixMillis,
) -> Result<VerifiedGrantAuthorization, GrantAuthorizationError> {
    verify_authorization(
        bytes,
        head,
        head.organization_id(),
        head.registry_version(),
        head.registry_head_hash(),
        head.proposed_sequence(),
        now,
    )
}
#[allow(clippy::too_many_arguments)]
fn verify_authorization(
    bytes: &[u8],
    head: &impl ea_crypto::SignerCertificateResolver,
    organization: ea_types::OrganizationId,
    version: ea_types::RegistryVersion,
    hash: ObjectHash,
    sequence: ea_types::ChainSequence,
    now: ea_types::UnixMillis,
) -> Result<VerifiedGrantAuthorization, GrantAuthorizationError> {
    let ParsedArchiveObject::Trust(parsed) =
        decode_exact_object(bytes).map_err(|_| GrantAuthorizationError::Unverifiable)?
    else {
        return Err(GrantAuthorizationError::Unverifiable);
    };
    let object = parsed.value();
    let DecodedTrustPayloadV1::GrantAuthorization(fields) = object
        .decoded_payload()
        .map_err(|_| GrantAuthorizationError::Unverifiable)?
    else {
        return Err(GrantAuthorizationError::Unverifiable);
    };
    if fields.organization_id != organization
        || fields.registry_version != version
        || fields.registry_head_hash.as_bytes() != hash.as_bytes()
        || fields.authorization_sequence != sequence.get()
    {
        return Err(GrantAuthorizationError::Mismatch);
    }
    if now > fields.expires_at {
        return Err(GrantAuthorizationError::Expired);
    }
    let count = distinct_authority_subjects(
        object.signatures(),
        object.exact_digest_input(),
        head,
        VerificationContext::historical_grant_approval_trust_digest,
    )
    .map_err(|_| GrantAuthorizationError::Unverifiable)?;
    if count < 2 {
        return Err(GrantAuthorizationError::Insufficient);
    }
    Ok(VerifiedGrantAuthorization {
        exact_bytes: bytes.to_vec(),
        object_hash: parsed.object_hash(),
        fields,
    })
}

/// Shared two-person count. Every signature must verify, including role,
/// capability and active status; rotating a certificate never creates a person.
pub fn distinct_authority_subjects(
    signatures: &[Vec<u8>],
    digest: &[u8],
    resolver: &impl SignerCertificateResolver,
    context_of: impl Fn(&[u8], CertificateHash) -> Result<VerificationContext, CryptoError>,
) -> Result<usize, CryptoError> {
    let mut subjects = std::collections::BTreeSet::new();
    for signature in signatures {
        let certificate = parse_cose_sign1(signature, &[])?
            .certificate_hash()
            .ok_or(CryptoError::InvalidCose)?;
        let signer = verify_cose_sign1(signature, resolver, &context_of(digest, certificate)?)?;
        let subject = signer
            .authority_subject_id()
            .ok_or(CryptoError::InvalidCose)?;
        subjects.insert(*subject.as_bytes());
    }
    Ok(subjects.len())
}
