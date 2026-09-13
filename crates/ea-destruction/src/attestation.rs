//! Exact v1 attribution. A signed claim alone never proves managed completion.
use crate::{DestructionError as Error, VerifiedDestructionAuthorization};
use ea_format::DeletionAttestationFieldsV1;
use ea_trust::HistoricalRegistryAuthority;
use ea_types::{CertificateHash, ObjectHash, UnixMillis};

/// Internal product mapping of the existing v1 uint, not a new wire enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u64)]
pub enum ManagedReplicaKind {
    Writer = 0,
    Reader = 1,
    SyncServer = 2,
}
impl ManagedReplicaKind {
    pub const fn code(self) -> u64 {
        self as u64
    }
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Writer),
            1 => Some(Self::Reader),
            2 => Some(Self::SyncServer),
            _ => None,
        }
    }
}
#[derive(Clone)]
pub struct VerifiedDeletionAttestation {
    fields: DeletionAttestationFieldsV1,
    exact: Vec<u8>,
    hash: ObjectHash,
    certificate: CertificateHash,
}
impl VerifiedDeletionAttestation {
    pub fn fields(&self) -> &DeletionAttestationFieldsV1 {
        &self.fields
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub const fn object_hash(&self) -> ObjectHash {
        self.hash
    }
    pub const fn certificate_hash(&self) -> CertificateHash {
        self.certificate
    }
}
pub fn verify_attestation_historical(
    exact: &[u8],
    auth: &VerifiedDestructionAuthorization,
    head: &HistoricalRegistryAuthority,
    observed_at: UnixMillis,
) -> Result<VerifiedDeletionAttestation, Error> {
    use ea_crypto::{VerificationContext, parse_cose_sign1, verify_cose_sign1};
    use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject, decode_exact_object};
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(exact)? else {
        return Err(Error::Format);
    };
    let object = parsed.value();
    let DecodedTrustPayloadV1::DeletionAttestation(fields) = object.decoded_payload()? else {
        return Err(Error::Format);
    };
    if fields.destruction_id != auth.fields().destruction_id
        || fields.destruction_authorization_object_hash != auth.object_hash()
        || auth.fields().organization_id != head.organization_id()
        || auth.fields().registry_version != head.registry_version()
        || auth.fields().registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
        || auth.fields().authorization_sequence != head.proposed_sequence().get()
        || ManagedReplicaKind::from_code(fields.replica_kind).is_none()
        || fields.executed_at.get() < 0
        || fields.executed_at > observed_at
        || fields.backup_expiry_at.is_some_and(|time| time.get() < 0)
        || fields.result == 1 && fields.backup_expiry_at.is_none()
        || fields.result == 0
            && fields
                .backup_expiry_at
                .is_some_and(|deadline| deadline > fields.executed_at)
    {
        return Err(Error::Event);
    }
    let [signature] = object.signatures() else {
        return Err(Error::Signature);
    };
    let certificate = parse_cose_sign1(signature, &[])?
        .certificate_hash()
        .ok_or(Error::Signature)?;
    let signer = head
        .active_certificate_fields(certificate)
        .ok_or(Error::Signature)?;
    if signer.device_id.as_bytes() != &fields.replica_id {
        return Err(Error::Signature);
    }
    let context = VerificationContext::deletion_attestation_trust_digest(
        object.exact_digest_input(),
        auth.exact_bytes(),
        certificate,
    )?;
    verify_cose_sign1(signature, head, &context)?;
    Ok(VerifiedDeletionAttestation {
        fields,
        exact: exact.to_vec(),
        hash: parsed.object_hash(),
        certificate,
    })
}
