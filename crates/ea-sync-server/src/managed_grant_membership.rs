//! Immutable ciphertext membership for removal, not opening or issuance.
//! An expired grant remains a holding; no earlier effectiveNow is fabricated.
use crate::destruction::{DestructionError as Error, DestructionPorts};
use ea_crypto::{VerificationContext, object_hash, verify_cose_sign1};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, GrantKindV1, GrantPurposeV1, GrantV1,
    ParsedArchiveObject, decode_exact_object,
};
use ea_types::{ChainSequence, ObjectHash};
pub(crate) async fn verify(
    grant: &GrantV1,
    job: &ea_destruction::VerifiedImportedPreflight,
    ports: &DestructionPorts<'_>,
) -> Result<(), Error> {
    let f = grant.grant_body().fields();
    let target = job
        .targets()
        .iter()
        .find(|t| t.entry_hash() == f.entry_hash)
        .ok_or(Error::Conflict)?;
    let org = job.authorization().fields().organization_id;
    if f.organization_id != org || f.chain_id != job.chain_id() {
        return Err(Error::Conflict);
    }
    let ParsedArchiveObject::Destroyed(stub) = decode_exact_object(target.exact_stub_bytes())?
    else {
        return Err(Error::Conflict);
    };
    let manifest = stub.value().signed_manifest().manifest().fields();
    match f.kind {
        GrantKindV1::Initial => {
            if f.issuer_certificate_hash != manifest.writer_certificate_hash
                || f.registry_version != manifest.registry_version
                || f.registry_head_hash.as_bytes() != &manifest.registry_head_hash
            {
                return Err(Error::AuthorizationUnverifiable);
            }
            let head = ports
                .heads
                .historical_registry_authority(
                    org,
                    manifest.registry_version,
                    ObjectHash::try_from(manifest.registry_head_hash.as_slice())
                        .map_err(|_| Error::AuthorizationInvalid)?,
                    manifest.chain_sequence,
                )
                .await?
                .ok_or(Error::AuthorizationUnverifiable)?;
            let recipient = head
                .active_certificate_fields(f.recipient_certificate_hash)
                .ok_or(Error::AuthorizationUnverifiable)?;
            if recipient.kem_key_thumbprint != Some(f.recipient_key_thumbprint)
                || !matches!(
                    (f.purpose, recipient.certificate_kind),
                    (GrantPurposeV1::Reader, CertificateKindV1::Reader)
                        | (
                            GrantPurposeV1::Recovery,
                            CertificateKindV1::RecoveryRecipient
                        )
                )
            {
                return Err(Error::AuthorizationUnverifiable);
            }
            verify_cose_sign1(
                grant.issuer_signature(),
                &head,
                &VerificationContext::initial_grant(
                    grant.grant_body().exact_bytes(),
                    manifest.chain_sequence,
                )?,
            )?;
        }
        GrantKindV1::Historical => {
            let hash = f
                .grant_authorization_object_hash
                .ok_or(Error::AuthorizationUnverifiable)?;
            let bytes = ports
                .objects
                .get_exact_in(ea_format::ObjectTypeV1::Trust, hash)
                .await?
                .collect()
                .await
                .map_err(|_| Error::DependencyUnavailable)?
                .into_bytes();
            if object_hash(&bytes) != hash {
                return Err(Error::Conflict);
            }
            let ParsedArchiveObject::Trust(object) = decode_exact_object(&bytes)? else {
                return Err(Error::AuthorizationInvalid);
            };
            let DecodedTrustPayloadV1::GrantAuthorization(auth) =
                object.value().decoded_payload()?
            else {
                return Err(Error::AuthorizationInvalid);
            };
            let head = ports
                .heads
                .historical_registry_authority(
                    org,
                    auth.registry_version,
                    ObjectHash::from(auth.registry_head_hash),
                    ChainSequence::new(auth.authorization_sequence),
                )
                .await?
                .ok_or(Error::AuthorizationUnverifiable)?;
            if auth.organization_id != org
                || head.chain_id() != job.chain_id()
                || f.purpose != GrantPurposeV1::Reader
                || f.registry_version != auth.registry_version
                || f.registry_head_hash != auth.registry_head_hash
                || !auth.entry_hashes.contains(&f.entry_hash)
                || auth.recipient_certificate_hash != f.recipient_certificate_hash
                || auth.recipient_key_thumbprint != f.recipient_key_thumbprint
            {
                return Err(Error::AuthorizationUnverifiable);
            }
            let recipient = head
                .active_certificate_fields(f.recipient_certificate_hash)
                .ok_or(Error::AuthorizationUnverifiable)?;
            if recipient.certificate_kind != CertificateKindV1::Reader
                || recipient.kem_key_thumbprint != Some(f.recipient_key_thumbprint)
            {
                return Err(Error::AuthorizationUnverifiable);
            }
            let count = ea_trust::distinct_authority_subjects(
                object.value().signatures(),
                object.value().exact_digest_input(),
                &head,
                VerificationContext::historical_grant_approval_trust_digest,
            )?;
            if count < 2 {
                return Err(Error::AuthorizationUnverifiable);
            }
            verify_cose_sign1(
                grant.issuer_signature(),
                &head,
                &VerificationContext::historical_grant(
                    grant.grant_body().exact_bytes(),
                    ChainSequence::new(auth.authorization_sequence),
                )?,
            )?;
        }
    }
    Ok(())
}
