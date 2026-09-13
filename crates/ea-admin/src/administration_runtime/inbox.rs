//! Self-signed enrollment requests are evidence of key possession, not certificates.
use crate::operator_runtime::OperatorRuntimeError;
use ea_sync_protocol::DeviceRegistrationRequestV1;
use ea_types::{ObjectHash, OrganizationId};

pub struct VerifiedRegistrationRequest {
    request: DeviceRegistrationRequestV1,
}
impl VerifiedRegistrationRequest {
    pub fn request_hash(&self) -> ObjectHash {
        ea_crypto::object_hash(self.request.exact_bytes())
    }
    pub fn exact_bytes(&self) -> &[u8] {
        self.request.exact_bytes()
    }
    pub fn core(&self) -> &ea_crypto::DeviceRegistrationRequestCoreV1 {
        self.request.core()
    }
}
pub fn verify_registration(
    exact: &[u8],
    organization: OrganizationId,
) -> Result<VerifiedRegistrationRequest, OperatorRuntimeError> {
    let failure = || OperatorRuntimeError::Config;
    let request = DeviceRegistrationRequestV1::decode(exact).map_err(|_| failure())?;
    let core = request.core();
    if core.organization_id != organization
        || core.requested_role > 1
        || (core.requested_role == 1 && core.kem_public_cose_key.is_none())
    {
        return Err(failure());
    }
    let exact_core =
        ea_crypto::encode_device_registration_request_core(core).map_err(|_| failure())?;
    let mut decoder = minicbor::Decoder::new(exact);
    if decoder.array().map_err(|_| failure())? != Some(2) {
        return Err(failure());
    }
    decoder.skip().map_err(|_| failure())?;
    let start = decoder.position();
    decoder.skip().map_err(|_| failure())?;
    ea_crypto::verify_enrollment_pop(
        &exact[start..decoder.position()],
        &core.signing_public_cose_key,
        &exact_core,
    )
    .map_err(|_| failure())?;
    Ok(VerifiedRegistrationRequest { request })
}
/// A verified request observed in the local durable intake journal.
pub struct ObservedRegistration {
    pub(super) request_hash: ObjectHash,
    pub(super) ceremony_id: ObjectHash,
    pub(super) certificate_kind: ea_format::CertificateKindV1,
    pub(super) received_at: ea_types::UnixMillis,
}
impl ObservedRegistration {
    pub fn request_hash(&self) -> ObjectHash {
        self.request_hash
    }
    pub fn ceremony_id(&self) -> ObjectHash {
        self.ceremony_id
    }
    pub fn certificate_kind(&self) -> ea_format::CertificateKindV1 {
        self.certificate_kind
    }
    pub fn received_at(&self) -> ea_types::UnixMillis {
        self.received_at
    }
}
/// Intake uses existing exact request/target bytes; it does not issue authority.
pub fn pending_registrations(
    runtime: &mut crate::operator_runtime::OperatorRuntime,
    directory: &std::path::Path,
) -> Result<Vec<ObservedRegistration>, OperatorRuntimeError> {
    super::inbox_directory::pending(runtime, directory)
}
#[cfg(test)]
mod tests {
    use super::*;
    use ea_crypto::{
        CanonicalPublicCoseKey, CoseSigner, DeviceRegistrationRequestCoreV1, SecretBytes,
    };
    use ea_types::{DeviceId, Id16};
    fn org(byte: u8) -> OrganizationId {
        OrganizationId::from(Id16::try_from([byte; 16].as_slice()).unwrap())
    }
    fn signed(role: u8) -> Vec<u8> {
        let signer = CoseSigner::from_secret(SecretBytes::new([0x53; 32]));
        let core = DeviceRegistrationRequestCoreV1 {
            organization_id: org(0x41),
            device_id: DeviceId::from(Id16::try_from([0x42; 16].as_slice()).unwrap()),
            requested_role: role,
            signing_public_cose_key: signer.public_key().unwrap(),
            kem_public_cose_key: Some(CanonicalPublicCoseKey::x25519([0x43; 32]).unwrap()),
            supported_format_versions: vec![1],
            supported_suite_ids: vec![ea_crypto::SUITE_ID.to_owned()],
        };
        let exact = ea_crypto::encode_device_registration_request_core(&core).unwrap();
        DeviceRegistrationRequestV1::new(core, &signer.sign_enrollment(&exact).unwrap())
            .unwrap()
            .exact_bytes()
            .to_vec()
    }
    #[test]
    fn registration_fingerprint_is_the_exact_self_signed_request_and_never_admin_issuance() {
        for role in [0, 1] {
            let exact = signed(role);
            let request = verify_registration(&exact, org(0x41)).unwrap();
            assert!(request.request_hash() == ea_crypto::object_hash(&exact));
            assert_eq!(request.exact_bytes(), exact);
            assert_eq!(request.core().requested_role, role);
            assert!(verify_registration(&exact, org(0x44)).is_err());
            let mut tampered = exact.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(verify_registration(&tampered, org(0x41)).is_err());
        }
        assert!(verify_registration(&signed(2), org(0x41)).is_err());
    }
}
