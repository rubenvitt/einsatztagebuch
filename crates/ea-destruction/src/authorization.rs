use crate::DestructionError as Error;
use ea_crypto::{VerificationContext, verify_cose_sign1};
use ea_format::{
    DecodedTrustPayloadV1, DestructionAuthorizationFieldsV1, EntryPackageV1, ParsedArchiveObject,
    decode_exact_object,
};
use ea_trust::SelectedRegistryHead;
use ea_types::{EntryHash, Hash32, ObjectHash};

/// Privately constructed proof; an imported target list is not a verified inventory.
#[derive(Clone)]
pub struct VerifiedDestructionAuthorization {
    exact: Vec<u8>,
    hash: ObjectHash,
    fields: DestructionAuthorizationFieldsV1,
    privacy_document: Hash32,
}
impl VerifiedDestructionAuthorization {
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub const fn object_hash(&self) -> ObjectHash {
        self.hash
    }
    pub const fn fields(&self) -> &DestructionAuthorizationFieldsV1 {
        &self.fields
    }
    pub fn verify_target(
        &self,
        entry: &EntryPackageV1,
        historical_head: &SelectedRegistryHead,
    ) -> Result<VerifiedDestructionTarget, Error> {
        let manifest = entry.manifest().fields();
        if manifest.organization_id != self.fields.organization_id
            || manifest.chain_id != historical_head.chain_id()
            || manifest.registry_version != historical_head.registry_version()
            || manifest.registry_head_hash != *historical_head.registry_head_hash().as_bytes()
            || manifest.chain_sequence != historical_head.proposed_sequence()
            || !self.fields.targets.iter().any(|target| {
                target.entry_hash() == entry.entry_hash().as_bytes()
                    && target.chain_sequence() == manifest.chain_sequence.get()
            })
        {
            return Err(Error::Target);
        }
        let context = VerificationContext::record(entry.signed_manifest().exact_bytes())?;
        verify_cose_sign1(entry.writer_signature(), historical_head, &context)?;
        Ok(VerifiedDestructionTarget {
            authorization_hash: self.hash,
            entry_hash: entry.entry_hash(),
        })
    }
    pub const fn privacy_document_hash(&self) -> Hash32 {
        self.privacy_document
    }
    /// Authenticate original target identity at its exact archived manifest
    /// context. This is not authority for any present action.
    pub fn verify_target_historical(
        &self,
        entry: &EntryPackageV1,
        historical: &ea_trust::HistoricalRegistryAuthority,
    ) -> Result<VerifiedDestructionTarget, Error> {
        let manifest = entry.manifest().fields();
        if manifest.organization_id != self.fields.organization_id
            || manifest.chain_id != historical.chain_id()
            || manifest.registry_version != historical.registry_version()
            || manifest.registry_head_hash != *historical.registry_head_hash().as_bytes()
            || manifest.chain_sequence != historical.proposed_sequence()
            || !self.fields.targets.iter().any(|target| {
                target.entry_hash() == entry.entry_hash().as_bytes()
                    && target.chain_sequence() == manifest.chain_sequence.get()
            })
        {
            return Err(Error::Target);
        }
        let context = VerificationContext::record(entry.signed_manifest().exact_bytes())?;
        verify_cose_sign1(entry.writer_signature(), historical, &context)?;
        Ok(VerifiedDestructionTarget {
            authorization_hash: self.hash,
            entry_hash: entry.entry_hash(),
        })
    }
}
impl core::fmt::Debug for VerifiedDestructionAuthorization {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifiedDestructionAuthorization(<verified>)")
    }
}

pub fn verify_authorization(
    exact: &[u8],
    head: &SelectedRegistryHead,
) -> Result<VerifiedDestructionAuthorization, Error> {
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(exact)? else {
        return Err(Error::Format);
    };
    let object = parsed.value();
    let DecodedTrustPayloadV1::DestructionAuthorization(fields) = object.decoded_payload()? else {
        return Err(Error::Format);
    };
    ea_format::validate_destruction_targets(&fields.targets)?;
    let policy = &head.policy_fields().retention_policy;
    let privacy_document = policy
        .eds_privacy_decision_document_hash
        .filter(|_| policy.destruction_enabled)
        .ok_or(Error::PrivacyGate)?;
    if fields.organization_id != head.policy_fields().organization_id
        || fields.registry_version != head.registry_version()
        || fields.registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
        || fields.authorization_sequence != head.proposed_sequence().get()
        || head.preexisting_effective_now().value() > head.not_after()
    {
        return Err(Error::Registry);
    }
    let people = ea_trust::distinct_authority_subjects(
        object.signatures(),
        object.exact_digest_input(),
        head,
        VerificationContext::destruction_approval_trust_digest,
    )?;
    if people < 2 {
        return Err(Error::Approvers);
    }
    Ok(VerifiedDestructionAuthorization {
        exact: exact.to_vec(),
        hash: parsed.object_hash(),
        fields,
        privacy_document,
    })
}

/// Verify an immutable authorization at its exact signed historical context.
/// This proof grants no current action authority.
pub fn verify_authorization_historical(
    exact: &[u8],
    head: &ea_trust::HistoricalRegistryAuthority,
) -> Result<VerifiedDestructionAuthorization, Error> {
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(exact)? else {
        return Err(Error::Format);
    };
    let object = parsed.value();
    let DecodedTrustPayloadV1::DestructionAuthorization(fields) = object.decoded_payload()? else {
        return Err(Error::Format);
    };
    ea_format::validate_destruction_targets(&fields.targets)?;
    let policy = &head.policy_fields().retention_policy;
    let privacy_document = policy
        .eds_privacy_decision_document_hash
        .filter(|_| policy.destruction_enabled)
        .ok_or(Error::PrivacyGate)?;
    if fields.organization_id != head.policy_fields().organization_id
        || fields.registry_version != head.registry_version()
        || fields.registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
        || fields.authorization_sequence != head.proposed_sequence().get()
    {
        return Err(Error::Registry);
    }
    let people = ea_trust::distinct_authority_subjects(
        object.signatures(),
        object.exact_digest_input(),
        head,
        VerificationContext::destruction_approval_trust_digest,
    )?;
    if people < 2 {
        return Err(Error::Approvers);
    }
    Ok(VerifiedDestructionAuthorization {
        exact: exact.to_vec(),
        hash: parsed.object_hash(),
        fields,
        privacy_document,
    })
}

/// A signed original whose hash AND numeric manifest sequence match the authorization.
pub struct VerifiedDestructionTarget {
    authorization_hash: ObjectHash,
    entry_hash: EntryHash,
}
impl VerifiedDestructionTarget {
    pub(crate) fn from_preflight(
        authorization: &VerifiedDestructionAuthorization,
        entry: &ea_format::Parsed<EntryPackageV1>,
        report: &ea_verify::VerificationReportV1,
    ) -> Result<Self, Error> {
        let manifest = entry.value().manifest().fields();
        if !report.is_fully_verified()
            || manifest.organization_id != authorization.fields.organization_id
            || !authorization.fields.targets.iter().any(|target| {
                target.entry_hash() == entry.value().entry_hash().as_bytes()
                    && target.chain_sequence() == manifest.chain_sequence.get()
            })
            || !report.object_results().any(|result| {
                result.object_hash() == entry.object_hash()
                    && result.object_type() == ea_format::ObjectTypeV1::Entry
                    && result.result() == ea_verify::ObjectResultKindV1::Valid
            })
        {
            return Err(Error::Target);
        }
        Ok(Self {
            authorization_hash: authorization.hash,
            entry_hash: entry.value().entry_hash(),
        })
    }
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }
    pub const fn authorization_hash(&self) -> ObjectHash {
        self.authorization_hash
    }
}
