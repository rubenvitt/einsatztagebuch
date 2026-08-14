use core::fmt;

use cms::{content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, asn1::ObjectIdentifier};
use ea_cbor::{ParserLimits, validate};
use ea_types::{
    CertificateHash, ChainSequence, DeviceId, Hash32, KeyThumbprint, OrganizationId,
    RegistryVersion,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::{Decoder, Encoder, data::Type};
use x509_tsp::TstInfo;

use crate::digest::{recovery_test_digest_ref, sha256_parts};
use crate::{
    CanonicalPublicCoseKey, CryptoError, SecretBytes, grant_digest, object_hash, receipt_digest,
    record_digest, recovery_test_digest, trust_digest,
};

const COSE_SIGN1_TAG: u64 = 18;
const ED25519_ALGORITHM: i64 = -19;
const CERTIFICATE_HASH_LABEL: &str = "certificateHash";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentType {
    RecordDigest,
    GrantDigest,
    ReceiptDigest,
    TrustDigest,
    CheckpointCbor,
    EvidenceRenewalCbor,
    LocalAuditCbor,
    ChallengeResponseCbor,
    DeviceRegistrationRequestCbor,
    ReaderAckCbor,
    RecoveryTestDigest,
}

impl ContentType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordDigest => "application/vnd.einsatzarchiv.record-digest",
            Self::GrantDigest => "application/vnd.einsatzarchiv.grant-digest",
            Self::ReceiptDigest => "application/vnd.einsatzarchiv.receipt-digest",
            Self::TrustDigest => "application/vnd.einsatzarchiv.trust-digest",
            Self::CheckpointCbor => "application/vnd.einsatzarchiv.checkpoint+cbor",
            Self::EvidenceRenewalCbor => "application/vnd.einsatzarchiv.evidence-renewal+cbor",
            Self::LocalAuditCbor => "application/vnd.einsatzarchiv.local-audit+cbor",
            Self::ChallengeResponseCbor => "application/vnd.einsatzarchiv.challenge-response+cbor",
            Self::DeviceRegistrationRequestCbor => {
                "application/vnd.einsatzarchiv.device-registration-request+cbor"
            }
            Self::ReaderAckCbor => "application/vnd.einsatzarchiv.reader-ack+cbor",
            Self::RecoveryTestDigest => "application/vnd.einsatzarchiv.recovery-test-digest",
        }
    }

    #[must_use]
    pub const fn is_digest(self) -> bool {
        matches!(
            self,
            Self::RecordDigest
                | Self::GrantDigest
                | Self::ReceiptDigest
                | Self::TrustDigest
                | Self::RecoveryTestDigest
        )
    }

    #[must_use]
    pub const fn permits_ctt(self) -> bool {
        matches!(self, Self::CheckpointCbor | Self::EvidenceRenewalCbor)
    }
}

impl TryFrom<&str> for ContentType {
    type Error = CryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "application/vnd.einsatzarchiv.record-digest" => Ok(Self::RecordDigest),
            "application/vnd.einsatzarchiv.grant-digest" => Ok(Self::GrantDigest),
            "application/vnd.einsatzarchiv.receipt-digest" => Ok(Self::ReceiptDigest),
            "application/vnd.einsatzarchiv.trust-digest" => Ok(Self::TrustDigest),
            "application/vnd.einsatzarchiv.checkpoint+cbor" => Ok(Self::CheckpointCbor),
            "application/vnd.einsatzarchiv.evidence-renewal+cbor" => Ok(Self::EvidenceRenewalCbor),
            "application/vnd.einsatzarchiv.local-audit+cbor" => Ok(Self::LocalAuditCbor),
            "application/vnd.einsatzarchiv.challenge-response+cbor" => {
                Ok(Self::ChallengeResponseCbor)
            }
            "application/vnd.einsatzarchiv.device-registration-request+cbor" => {
                Ok(Self::DeviceRegistrationRequestCbor)
            }
            "application/vnd.einsatzarchiv.reader-ack+cbor" => Ok(Self::ReaderAckCbor),
            "application/vnd.einsatzarchiv.recovery-test-digest" => Ok(Self::RecoveryTestDigest),
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProtectedProfile {
    Normal,
    InitialRoot,
    Enrollment,
}

pub struct ProtectedHeader {
    profile: ProtectedProfile,
    content_type: ContentType,
    key_thumbprint: KeyThumbprint,
    certificate_hash: Option<CertificateHash>,
    exact: Vec<u8>,
}

impl ProtectedHeader {
    #[must_use]
    pub fn normal(
        content_type: ContentType,
        key_thumbprint: KeyThumbprint,
        certificate_hash: CertificateHash,
    ) -> Self {
        let exact = encode_protected(
            ProtectedProfile::Normal,
            content_type,
            key_thumbprint,
            Some(certificate_hash),
        );
        Self {
            profile: ProtectedProfile::Normal,
            content_type,
            key_thumbprint,
            certificate_hash: Some(certificate_hash),
            exact,
        }
    }

    #[must_use]
    pub fn initial_root(key_thumbprint: KeyThumbprint) -> Self {
        let content_type = ContentType::TrustDigest;
        let exact = encode_protected(
            ProtectedProfile::InitialRoot,
            content_type,
            key_thumbprint,
            None,
        );
        Self {
            profile: ProtectedProfile::InitialRoot,
            content_type,
            key_thumbprint,
            certificate_hash: None,
            exact,
        }
    }

    #[must_use]
    pub fn enrollment(key_thumbprint: KeyThumbprint) -> Self {
        let content_type = ContentType::DeviceRegistrationRequestCbor;
        let exact = encode_protected(
            ProtectedProfile::Enrollment,
            content_type,
            key_thumbprint,
            None,
        );
        Self {
            profile: ProtectedProfile::Enrollment,
            content_type,
            key_thumbprint,
            certificate_hash: None,
            exact,
        }
    }

    #[must_use]
    pub fn to_deterministic_cbor(&self) -> Vec<u8> {
        self.exact.clone()
    }

    #[must_use]
    pub fn sig_structure_bytes(&self, payload: &[u8]) -> Vec<u8> {
        encode_sig_structure(&self.exact, payload)
    }

    fn parse(exact: &[u8]) -> Result<Self, CryptoError> {
        validate(exact, ParserLimits::V1).map_err(|_| CryptoError::InvalidCose)?;
        let mut decoder = Decoder::new(exact);
        let length = exact_map_length(&mut decoder)?;
        if !matches!(length, 4 | 5) {
            return Err(CryptoError::InvalidCose);
        }

        if decoder.i64().map_err(|_| CryptoError::InvalidCose)? != 1 {
            return Err(CryptoError::InvalidCose);
        }
        let algorithm = decoder.i64().map_err(|_| CryptoError::InvalidCose)?;
        if algorithm != ED25519_ALGORITHM {
            return Err(CryptoError::UnsupportedSuite);
        }

        if decoder.i64().map_err(|_| CryptoError::InvalidCose)? != 2 {
            return Err(CryptoError::InvalidCose);
        }
        let critical_length = exact_array_length(&mut decoder)?;
        if !matches!(critical_length, 2 | 3) {
            return Err(CryptoError::InvalidCose);
        }
        if decoder.i64().map_err(|_| CryptoError::InvalidCose)? != 3
            || decoder.i64().map_err(|_| CryptoError::InvalidCose)? != 4
        {
            return Err(CryptoError::InvalidCose);
        }
        let has_certificate_hash = critical_length == 3;
        if has_certificate_hash
            && decoder.str().map_err(|_| CryptoError::InvalidCose)? != CERTIFICATE_HASH_LABEL
        {
            return Err(CryptoError::InvalidCose);
        }

        if decoder.i64().map_err(|_| CryptoError::InvalidCose)? != 3 {
            return Err(CryptoError::InvalidCose);
        }
        let content_type =
            ContentType::try_from(decoder.str().map_err(|_| CryptoError::InvalidCose)?)?;

        if decoder.i64().map_err(|_| CryptoError::InvalidCose)? != 4 {
            return Err(CryptoError::InvalidCose);
        }
        let thumbprint =
            KeyThumbprint::try_from(decoder.bytes().map_err(|_| CryptoError::InvalidCose)?)
                .map_err(|_| CryptoError::InvalidCose)?;

        let certificate_hash = if has_certificate_hash {
            if decoder.str().map_err(|_| CryptoError::InvalidCose)? != CERTIFICATE_HASH_LABEL {
                return Err(CryptoError::InvalidCose);
            }
            Some(
                CertificateHash::try_from(decoder.bytes().map_err(|_| CryptoError::InvalidCose)?)
                    .map_err(|_| CryptoError::InvalidCose)?,
            )
        } else {
            None
        };
        if decoder.position() != exact.len() {
            return Err(CryptoError::InvalidCose);
        }

        let profile = if has_certificate_hash {
            if content_type == ContentType::DeviceRegistrationRequestCbor {
                return Err(CryptoError::InvalidCose);
            }
            ProtectedProfile::Normal
        } else if content_type == ContentType::TrustDigest {
            ProtectedProfile::InitialRoot
        } else if content_type == ContentType::DeviceRegistrationRequestCbor {
            ProtectedProfile::Enrollment
        } else {
            return Err(CryptoError::InvalidCose);
        };
        if length != if has_certificate_hash { 5 } else { 4 } {
            return Err(CryptoError::InvalidCose);
        }
        let header = Self {
            profile,
            content_type,
            key_thumbprint: thumbprint,
            certificate_hash,
            exact: exact.to_vec(),
        };
        if header.to_deterministic_cbor() != exact {
            return Err(CryptoError::InvalidCose);
        }
        Ok(header)
    }
}

fn encode_protected(
    profile: ProtectedProfile,
    content_type: ContentType,
    key_thumbprint: KeyThumbprint,
    certificate_hash: Option<CertificateHash>,
) -> Vec<u8> {
    let normal = profile == ProtectedProfile::Normal;
    let mut bytes = Vec::with_capacity(192);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .map(if normal { 5 } else { 4 })
        .and_then(|encoder| encoder.i64(1))
        .and_then(|encoder| encoder.i64(ED25519_ALGORITHM))
        .and_then(|encoder| encoder.i64(2))
        .and_then(|encoder| encoder.array(if normal { 3 } else { 2 }))
        .and_then(|encoder| encoder.i64(3))
        .and_then(|encoder| encoder.i64(4))
        .expect("encoding fixed protected header fields cannot fail");
    if normal {
        encoder
            .str(CERTIFICATE_HASH_LABEL)
            .expect("encoding fixed protected label cannot fail");
    }
    encoder
        .i64(3)
        .and_then(|encoder| encoder.str(content_type.as_str()))
        .and_then(|encoder| encoder.i64(4))
        .and_then(|encoder| encoder.bytes(key_thumbprint.as_bytes()))
        .expect("encoding protected content and thumbprint cannot fail");
    if let Some(certificate_hash) = certificate_hash {
        encoder
            .str(CERTIFICATE_HASH_LABEL)
            .and_then(|encoder| encoder.bytes(certificate_hash.as_bytes()))
            .expect("encoding protected certificate hash cannot fail");
    }
    debug_assert!(validate(&bytes, ParserLimits::V1).is_ok());
    bytes
}

pub struct CoseSigner(SigningKey);

impl CoseSigner {
    #[must_use]
    pub fn from_secret(secret: SecretBytes<32>) -> Self {
        Self(SigningKey::from_bytes(secret.expose()))
    }

    fn sign_normal(
        &self,
        content_type: ContentType,
        certificate_hash: CertificateHash,
        payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if matches!(
            content_type,
            ContentType::RecoveryTestDigest | ContentType::DeviceRegistrationRequestCbor
        ) {
            return Err(CryptoError::InvalidCose);
        }
        validate_payload(content_type, payload)?;
        let public = CanonicalPublicCoseKey::ed25519(*self.0.verifying_key().as_bytes())?;
        self.sign(
            ProtectedHeader::normal(content_type, public.thumbprint(), certificate_hash),
            payload,
        )
    }

    pub fn sign_record(&self, exact_signed_manifest: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let bindings = record_bindings(exact_signed_manifest)?;
        self.sign_normal(
            ContentType::RecordDigest,
            bindings.certificate_hash,
            bindings.digest.as_bytes(),
        )
    }

    pub fn sign_initial_grant(&self, exact_grant_body: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let bindings = grant_bindings(exact_grant_body, GrantKind::Initial)?;
        self.sign_normal(
            ContentType::GrantDigest,
            bindings.certificate_hash,
            bindings.digest.as_bytes(),
        )
    }

    pub fn sign_historical_grant(&self, exact_grant_body: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let bindings = grant_bindings(exact_grant_body, GrantKind::Historical)?;
        self.sign_normal(
            ContentType::GrantDigest,
            bindings.certificate_hash,
            bindings.digest.as_bytes(),
        )
    }

    pub fn sign_receipt(&self, exact_receipt_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let bindings = receipt_bindings(exact_receipt_core)?;
        self.sign_normal(
            ContentType::ReceiptDigest,
            bindings.certificate_hash,
            bindings.digest.as_bytes(),
        )
    }

    pub fn sign_root_trust_digest(
        &self,
        certificate_hash: CertificateHash,
        exact_trust_digest_input: &[u8],
        exact_admin_authorization_object: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let bindings =
            root_trust_bindings(exact_trust_digest_input, exact_admin_authorization_object)?;
        self.sign_normal(
            ContentType::TrustDigest,
            certificate_hash,
            bindings.digest.as_bytes(),
        )
    }

    pub fn sign_organization_admin_trust_digest(
        &self,
        exact_trust_digest_input: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let bindings = organization_admin_authorization_bindings(exact_trust_digest_input)?;
        self.sign_normal(
            ContentType::TrustDigest,
            bindings.certificate_hash,
            bindings.digest.as_bytes(),
        )
    }

    pub fn sign_historical_grant_approval_digest(
        &self,
        certificate_hash: CertificateHash,
        exact_trust_digest_input: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let digest = grant_authorization_bindings(exact_trust_digest_input)?.digest;
        self.sign_normal(
            ContentType::TrustDigest,
            certificate_hash,
            digest.as_bytes(),
        )
    }

    pub fn sign_destruction_approval_digest(
        &self,
        certificate_hash: CertificateHash,
        exact_trust_digest_input: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let digest = destruction_authorization_bindings(exact_trust_digest_input)?
            .operation
            .digest;
        self.sign_normal(
            ContentType::TrustDigest,
            certificate_hash,
            digest.as_bytes(),
        )
    }

    pub fn sign_deletion_attestation_digest(
        &self,
        certificate_hash: CertificateHash,
        exact_trust_digest_input: &[u8],
        exact_destruction_authorization_object: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let attestation = deletion_attestation_bindings(exact_trust_digest_input)?;
        let authorization =
            destruction_authorization_object_bindings(exact_destruction_authorization_object)?;
        if attestation.destruction_id != authorization.destruction_id
            || attestation.authorization_object_hash
                != *object_hash(exact_destruction_authorization_object).as_bytes()
        {
            return Err(CryptoError::InvalidProtocolCore);
        }
        self.sign_normal(
            ContentType::TrustDigest,
            certificate_hash,
            attestation.digest.as_bytes(),
        )
    }

    pub fn sign_destruction_transition_digest(
        &self,
        certificate_hash: CertificateHash,
        exact_trust_digest_input: &[u8],
        exact_destruction_authorization_object: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let transition = destruction_transition_bindings(exact_trust_digest_input)?;
        let authorization =
            destruction_authorization_object_bindings(exact_destruction_authorization_object)?;
        if transition.destruction_id != authorization.destruction_id
            || transition.authorization_object_hash
                != *object_hash(exact_destruction_authorization_object).as_bytes()
        {
            return Err(CryptoError::InvalidProtocolCore);
        }
        self.sign_normal(
            ContentType::TrustDigest,
            certificate_hash,
            transition.digest.as_bytes(),
        )
    }

    pub fn sign_checkpoint(
        &self,
        certificate_hash: CertificateHash,
        core: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.sign_normal(ContentType::CheckpointCbor, certificate_hash, core)
    }

    pub fn sign_evidence_renewal(
        &self,
        certificate_hash: CertificateHash,
        core: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.sign_normal(ContentType::EvidenceRenewalCbor, certificate_hash, core)
    }

    pub fn sign_local_audit(&self, core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let certificate_hash = core_bindings(ContentType::LocalAuditCbor, core)?
            .certificate_hash
            .ok_or(CryptoError::InvalidProtocolCore)?;
        self.sign_normal(ContentType::LocalAuditCbor, certificate_hash, core)
    }

    pub fn sign_challenge_response(&self, core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let certificate_hash = core_bindings(ContentType::ChallengeResponseCbor, core)?
            .certificate_hash
            .ok_or(CryptoError::InvalidProtocolCore)?;
        self.sign_normal(ContentType::ChallengeResponseCbor, certificate_hash, core)
    }

    pub fn sign_reader_ack(&self, core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let certificate_hash = core_bindings(ContentType::ReaderAckCbor, core)?
            .certificate_hash
            .ok_or(CryptoError::InvalidProtocolCore)?;
        self.sign_normal(ContentType::ReaderAckCbor, certificate_hash, core)
    }

    pub fn sign_recovery_test(
        &self,
        certificate_hash: CertificateHash,
        challenge: SecretBytes<32>,
    ) -> Result<Vec<u8>, CryptoError> {
        let public = CanonicalPublicCoseKey::ed25519(*self.0.verifying_key().as_bytes())?;
        let digest = recovery_test_digest(challenge, public.thumbprint());
        self.sign(
            ProtectedHeader::normal(
                ContentType::RecoveryTestDigest,
                public.thumbprint(),
                certificate_hash,
            ),
            digest.as_bytes(),
        )
    }

    pub fn sign_initial_root(&self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        validate_payload(ContentType::TrustDigest, payload)?;
        let public = CanonicalPublicCoseKey::ed25519(*self.0.verifying_key().as_bytes())?;
        self.sign(ProtectedHeader::initial_root(public.thumbprint()), payload)
    }

    pub fn sign_enrollment(&self, unsigned_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
        validate_unsigned_protocol_core(ContentType::DeviceRegistrationRequestCbor, unsigned_core)?;
        let public = CanonicalPublicCoseKey::ed25519(*self.0.verifying_key().as_bytes())?;
        if registration_signing_key(unsigned_core)? != public {
            return Err(CryptoError::SignerMismatch);
        }
        self.sign(
            ProtectedHeader::enrollment(public.thumbprint()),
            unsigned_core,
        )
    }

    fn sign(&self, protected: ProtectedHeader, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig_structure = encode_sig_structure(&protected.exact, payload);
        let signature: Signature = self.0.sign(&sig_structure);
        encode_cose_sign1(&protected.exact, None, payload, &signature.to_bytes())
    }
}

pub struct ParsedCoseSign1 {
    exact: Vec<u8>,
    protected: ProtectedHeader,
    payload: Vec<u8>,
    signature: [u8; 64],
    timestamp_token: Option<Vec<u8>>,
}

pub struct UnverifiedRfc3161TimeStampToken(Vec<u8>);

impl UnverifiedRfc3161TimeStampToken {
    pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
        validate_timestamp_token_der(der)?;
        Ok(Self(der.to_vec()))
    }

    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

#[must_use]
pub fn cose_sign1_ctt_imprint(signature: &[u8; 64]) -> ea_types::Hash32 {
    sha256_parts(&[&[0x58, 0x40], signature])
}

pub fn attach_rfc3161_ctt(
    cose_sign1: &[u8],
    token: &UnverifiedRfc3161TimeStampToken,
) -> Result<Vec<u8>, CryptoError> {
    let parsed = parse_cose_sign1(cose_sign1, &[])?;
    if !parsed.protected.content_type.permits_ctt() || parsed.timestamp_token.is_some() {
        return Err(CryptoError::InvalidCose);
    }
    encode_cose_sign1(
        &parsed.protected.exact,
        Some(token.as_der()),
        &parsed.payload,
        &parsed.signature,
    )
}

impl ParsedCoseSign1 {
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn timestamp_token(&self) -> Option<&[u8]> {
        self.timestamp_token.as_deref()
    }

    pub(crate) fn verify_with_key(
        &self,
        public_key: &CanonicalPublicCoseKey,
    ) -> Result<(), CryptoError> {
        if public_key.thumbprint() != self.protected.key_thumbprint {
            return Err(CryptoError::SignerMismatch);
        }
        let key = VerifyingKey::from_bytes(public_key.ed25519_bytes()?)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(
            &encode_sig_structure(&self.protected.exact, &self.payload),
            &signature,
        )
        .map_err(|_| CryptoError::SignatureInvalid)
    }
}

pub fn parse_cose_sign1(bytes: &[u8], external_aad: &[u8]) -> Result<ParsedCoseSign1, CryptoError> {
    if !external_aad.is_empty() {
        return Err(CryptoError::InvalidCose);
    }
    validate(bytes, ParserLimits::V1).map_err(|_| CryptoError::InvalidCose)?;
    let mut decoder = Decoder::new(bytes);
    if decoder
        .tag()
        .map_err(|_| CryptoError::InvalidCose)?
        .as_u64()
        != COSE_SIGN1_TAG
        || exact_array_length(&mut decoder)? != 4
    {
        return Err(CryptoError::InvalidCose);
    }
    let protected_bytes = decoder
        .bytes()
        .map_err(|_| CryptoError::InvalidCose)?
        .to_vec();
    let protected = ProtectedHeader::parse(&protected_bytes)?;
    let timestamp_token = parse_unprotected(&mut decoder, protected.content_type)?;
    let payload = decoder
        .bytes()
        .map_err(|_| CryptoError::InvalidCose)?
        .to_vec();
    validate_payload(protected.content_type, &payload)?;
    let signature: [u8; 64] = decoder
        .bytes()
        .map_err(|_| CryptoError::InvalidCose)?
        .try_into()
        .map_err(|_| CryptoError::InvalidCose)?;
    if decoder.position() != bytes.len() {
        return Err(CryptoError::InvalidCose);
    }
    let reencoded = encode_cose_sign1(
        &protected.exact,
        timestamp_token.as_deref(),
        &payload,
        &signature,
    )?;
    if reencoded != bytes {
        return Err(CryptoError::InvalidCose);
    }
    Ok(ParsedCoseSign1 {
        exact: bytes.to_vec(),
        protected,
        payload,
        signature,
        timestamp_token,
    })
}

fn parse_unprotected(
    decoder: &mut Decoder<'_>,
    content_type: ContentType,
) -> Result<Option<Vec<u8>>, CryptoError> {
    let length = exact_map_length(decoder)?;
    match length {
        0 => Ok(None),
        1 if content_type.permits_ctt() => {
            if decoder.u64().map_err(|_| CryptoError::InvalidCose)? != 270 {
                return Err(CryptoError::InvalidCose);
            }
            let token = decoder
                .bytes()
                .map_err(|_| CryptoError::InvalidCose)?
                .to_vec();
            validate_timestamp_token_der(&token)?;
            Ok(Some(token))
        }
        _ => Err(CryptoError::InvalidCose),
    }
}

fn validate_timestamp_token_der(der: &[u8]) -> Result<(), CryptoError> {
    const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    const ID_CT_TST_INFO: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

    let content_info = ContentInfo::from_der(der).map_err(|_| CryptoError::InvalidCose)?;
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(CryptoError::InvalidCose);
    }
    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|_| CryptoError::InvalidCose)?;
    if signed_data.digest_algorithms.as_slice().is_empty()
        || signed_data.signer_infos.0.as_slice().len() != 1
        || signed_data.encap_content_info.econtent_type != ID_CT_TST_INFO
    {
        return Err(CryptoError::InvalidCose);
    }
    let tst_info_der = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(CryptoError::InvalidCose)?
        .value();
    TstInfo::from_der(tst_info_der).map_err(|_| CryptoError::InvalidCose)?;
    Ok(())
}

fn encode_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(24 + protected.len() + payload.len());
    Encoder::new(&mut bytes)
        .array(4)
        .and_then(|encoder| encoder.str("Signature1"))
        .and_then(|encoder| encoder.bytes(protected))
        .and_then(|encoder| encoder.bytes(&[]))
        .and_then(|encoder| encoder.bytes(payload))
        .expect("encoding fixed Sig_structure into Vec cannot fail");
    debug_assert!(validate(&bytes, ParserLimits::V1).is_ok());
    bytes
}

fn encode_cose_sign1(
    protected: &[u8],
    timestamp_token: Option<&[u8]>,
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::with_capacity(80 + protected.len() + payload.len());
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .tag(minicbor::data::Tag::new(COSE_SIGN1_TAG))
        .and_then(|encoder| encoder.array(4))
        .and_then(|encoder| encoder.bytes(protected))
        .and_then(|encoder| encoder.map(u64::from(timestamp_token.is_some())))
        .map_err(|_| CryptoError::InvalidCose)?;
    if let Some(token) = timestamp_token {
        encoder
            .u64(270)
            .and_then(|encoder| encoder.bytes(token))
            .map_err(|_| CryptoError::InvalidCose)?;
    }
    encoder
        .bytes(payload)
        .and_then(|encoder| encoder.bytes(signature))
        .map_err(|_| CryptoError::InvalidCose)?;
    validate(&bytes, ParserLimits::V1).map_err(|_| CryptoError::InvalidCose)?;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerRole {
    Writer,
    Reader,
    OrganizationAdmin,
    Root,
    KeyApprover,
    HistoricalGrantAuthority,
    ServerReceipt,
    DeletionAttest,
    RecoveryRecipient,
}

pub struct ResolvedSigner<'a> {
    pub exact_certificate_bytes: &'a [u8],
    pub registry_effective_from_sequence: ChainSequence,
    pub registry_revoked_from_sequence: Option<ChainSequence>,
    pub registry_revoked: bool,
    pub root_line_accepted: bool,
}

pub trait SignerCertificateResolver {
    fn resolve(
        &self,
        certificate_hash: CertificateHash,
        bound_registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError>;
}

pub struct VerificationContext {
    content_type: ContentType,
    exact_payload: Vec<u8>,
    expected_certificate_hash: CertificateHash,
    expected_key_thumbprint: Option<KeyThumbprint>,
    expected_organization_id: OrganizationId,
    expected_device_id: Option<DeviceId>,
    expected_sequence: Option<ChainSequence>,
    expected_role: SignerRole,
    expected_capability: Option<CertificateCapability>,
    require_accepted_root_line: bool,
    registry: RegistryVersion,
}

impl VerificationContext {
    pub fn record(exact_signed_manifest: &[u8]) -> Result<Self, CryptoError> {
        let bindings = record_bindings(exact_signed_manifest)?;
        Ok(Self::digest(
            ContentType::RecordDigest,
            bindings.digest,
            bindings.certificate_hash,
            None,
            bindings.organization_id,
            bindings.sequence,
            SignerRole::Writer,
            None,
            false,
            bindings.registry,
        ))
    }

    pub fn initial_grant(
        exact_grant_body: &[u8],
        sequence: ChainSequence,
    ) -> Result<Self, CryptoError> {
        let bindings = grant_bindings(exact_grant_body, GrantKind::Initial)?;
        Ok(Self::digest(
            ContentType::GrantDigest,
            bindings.digest,
            bindings.certificate_hash,
            Some(bindings.key_thumbprint),
            bindings.organization_id,
            sequence,
            SignerRole::Writer,
            Some(CertificateCapability::InitialGrant),
            false,
            bindings.registry,
        ))
    }

    pub fn historical_grant(
        exact_grant_body: &[u8],
        sequence: ChainSequence,
    ) -> Result<Self, CryptoError> {
        let bindings = grant_bindings(exact_grant_body, GrantKind::Historical)?;
        Ok(Self::digest(
            ContentType::GrantDigest,
            bindings.digest,
            bindings.certificate_hash,
            Some(bindings.key_thumbprint),
            bindings.organization_id,
            sequence,
            SignerRole::HistoricalGrantAuthority,
            Some(CertificateCapability::HistoricalGrant),
            false,
            bindings.registry,
        ))
    }

    pub fn receipt(exact_receipt_core: &[u8]) -> Result<Self, CryptoError> {
        let bindings = receipt_bindings(exact_receipt_core)?;
        Ok(Self::digest(
            ContentType::ReceiptDigest,
            bindings.digest,
            bindings.certificate_hash,
            Some(bindings.key_thumbprint),
            bindings.organization_id,
            bindings.sequence,
            SignerRole::ServerReceipt,
            Some(CertificateCapability::ServerReceipt),
            false,
            bindings.registry,
        ))
    }

    pub fn root_trust_digest(
        exact_trust_digest_input: &[u8],
        root_certificate_hash: CertificateHash,
        exact_admin_authorization_object: Option<&[u8]>,
    ) -> Result<Self, CryptoError> {
        let bindings =
            root_trust_bindings(exact_trust_digest_input, exact_admin_authorization_object)?;
        Ok(match bindings.sequence {
            Some(sequence) => Self::digest(
                ContentType::TrustDigest,
                bindings.digest,
                root_certificate_hash,
                None,
                bindings.organization_id,
                sequence,
                SignerRole::Root,
                None,
                true,
                bindings.registry,
            ),
            None => Self::digest_without_sequence(
                ContentType::TrustDigest,
                bindings.digest,
                root_certificate_hash,
                None,
                bindings.organization_id,
                SignerRole::Root,
                None,
                true,
                bindings.registry,
            ),
        })
    }

    pub fn organization_admin_trust_digest(
        exact_trust_digest_input: &[u8],
    ) -> Result<Self, CryptoError> {
        let bindings = organization_admin_authorization_bindings(exact_trust_digest_input)?;
        Ok(Self::digest_without_sequence(
            ContentType::TrustDigest,
            bindings.digest,
            bindings.certificate_hash,
            Some(bindings.key_thumbprint),
            bindings.organization_id,
            SignerRole::OrganizationAdmin,
            Some(CertificateCapability::OrganizationAdminApprove),
            false,
            bindings.registry,
        ))
    }

    pub fn historical_grant_approval_trust_digest(
        exact_trust_digest_input: &[u8],
        certificate_hash: CertificateHash,
    ) -> Result<Self, CryptoError> {
        let bindings = grant_authorization_bindings(exact_trust_digest_input)?;
        Ok(Self::digest(
            ContentType::TrustDigest,
            bindings.digest,
            certificate_hash,
            None,
            bindings.organization_id,
            bindings.sequence,
            SignerRole::KeyApprover,
            Some(CertificateCapability::HistoricalGrantApprove),
            false,
            bindings.registry,
        ))
    }

    pub fn destruction_approval_trust_digest(
        exact_trust_digest_input: &[u8],
        certificate_hash: CertificateHash,
    ) -> Result<Self, CryptoError> {
        let bindings = destruction_authorization_bindings(exact_trust_digest_input)?;
        Ok(Self::digest(
            ContentType::TrustDigest,
            bindings.operation.digest,
            certificate_hash,
            None,
            bindings.operation.organization_id,
            bindings.operation.sequence,
            SignerRole::KeyApprover,
            Some(CertificateCapability::DestructionApprove),
            false,
            bindings.operation.registry,
        ))
    }

    pub fn deletion_attestation_trust_digest(
        exact_trust_digest_input: &[u8],
        exact_destruction_authorization_object: &[u8],
        certificate_hash: CertificateHash,
    ) -> Result<Self, CryptoError> {
        let attestation = deletion_attestation_bindings(exact_trust_digest_input)?;
        let authorization =
            destruction_authorization_object_bindings(exact_destruction_authorization_object)?;
        if attestation.destruction_id != authorization.destruction_id
            || attestation.authorization_object_hash
                != *object_hash(exact_destruction_authorization_object).as_bytes()
        {
            return Err(CryptoError::InvalidProtocolCore);
        }
        Ok(Self::digest(
            ContentType::TrustDigest,
            attestation.digest,
            certificate_hash,
            None,
            authorization.operation.organization_id,
            authorization.operation.sequence,
            SignerRole::DeletionAttest,
            Some(CertificateCapability::DeletionAttest),
            false,
            authorization.operation.registry,
        ))
    }

    pub fn destruction_transition_trust_digest(
        exact_trust_digest_input: &[u8],
        exact_destruction_authorization_object: &[u8],
        certificate_hash: CertificateHash,
    ) -> Result<Self, CryptoError> {
        let transition = destruction_transition_bindings(exact_trust_digest_input)?;
        let authorization =
            destruction_authorization_object_bindings(exact_destruction_authorization_object)?;
        if transition.destruction_id != authorization.destruction_id
            || transition.authorization_object_hash
                != *object_hash(exact_destruction_authorization_object).as_bytes()
        {
            return Err(CryptoError::InvalidProtocolCore);
        }
        Ok(Self::digest(
            ContentType::TrustDigest,
            transition.digest,
            certificate_hash,
            None,
            authorization.operation.organization_id,
            authorization.operation.sequence,
            SignerRole::DeletionAttest,
            Some(CertificateCapability::DeletionAttest),
            false,
            authorization.operation.registry,
        ))
    }

    pub fn checkpoint(
        exact_core: &[u8],
        server_certificate_hash: CertificateHash,
        registry: RegistryVersion,
    ) -> Result<Self, CryptoError> {
        let bindings = core_bindings(ContentType::CheckpointCbor, exact_core)?;
        Self::core(
            ContentType::CheckpointCbor,
            exact_core,
            server_certificate_hash,
            bindings.organization_id,
            None,
            bindings.sequence.ok_or(CryptoError::InvalidProtocolCore)?,
            SignerRole::ServerReceipt,
            Some(CertificateCapability::ServerReceipt),
            registry,
        )
    }

    pub fn evidence_renewal(
        exact_core: &[u8],
        server_certificate_hash: CertificateHash,
        effective_sequence: ChainSequence,
        registry: RegistryVersion,
    ) -> Result<Self, CryptoError> {
        let bindings = core_bindings(ContentType::EvidenceRenewalCbor, exact_core)?;
        Self::core(
            ContentType::EvidenceRenewalCbor,
            exact_core,
            server_certificate_hash,
            bindings.organization_id,
            None,
            effective_sequence,
            SignerRole::ServerReceipt,
            Some(CertificateCapability::ServerReceipt),
            registry,
        )
    }

    pub fn local_audit(
        exact_core: &[u8],
        effective_sequence: ChainSequence,
        signer_role: SignerRole,
        registry: RegistryVersion,
    ) -> Result<Self, CryptoError> {
        if !matches!(
            signer_role,
            SignerRole::Writer | SignerRole::Reader | SignerRole::OrganizationAdmin
        ) {
            return Err(CryptoError::SignerUnauthorized);
        }
        let bindings = core_bindings(ContentType::LocalAuditCbor, exact_core)?;
        Self::core(
            ContentType::LocalAuditCbor,
            exact_core,
            bindings
                .certificate_hash
                .ok_or(CryptoError::InvalidProtocolCore)?,
            bindings.organization_id,
            bindings.device_id,
            effective_sequence,
            signer_role,
            None,
            registry,
        )
    }

    pub fn challenge_response(
        exact_core: &[u8],
        effective_sequence: ChainSequence,
        registry: RegistryVersion,
    ) -> Result<Self, CryptoError> {
        let bindings = core_bindings(ContentType::ChallengeResponseCbor, exact_core)?;
        Self::core(
            ContentType::ChallengeResponseCbor,
            exact_core,
            bindings
                .certificate_hash
                .ok_or(CryptoError::InvalidProtocolCore)?,
            bindings.organization_id,
            None,
            effective_sequence,
            SignerRole::ServerReceipt,
            Some(CertificateCapability::ServerReceipt),
            registry,
        )
    }

    pub fn reader_ack(exact_core: &[u8], registry: RegistryVersion) -> Result<Self, CryptoError> {
        let bindings = core_bindings(ContentType::ReaderAckCbor, exact_core)?;
        Self::core(
            ContentType::ReaderAckCbor,
            exact_core,
            bindings
                .certificate_hash
                .ok_or(CryptoError::InvalidProtocolCore)?,
            bindings.organization_id,
            None,
            bindings.sequence.ok_or(CryptoError::InvalidProtocolCore)?,
            SignerRole::Reader,
            None,
            registry,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn digest(
        content_type: ContentType,
        exact_digest: Hash32,
        expected_certificate_hash: CertificateHash,
        expected_key_thumbprint: Option<KeyThumbprint>,
        expected_organization_id: OrganizationId,
        expected_sequence: ChainSequence,
        expected_role: SignerRole,
        expected_capability: Option<CertificateCapability>,
        require_accepted_root_line: bool,
        registry: RegistryVersion,
    ) -> Self {
        Self {
            content_type,
            exact_payload: exact_digest.as_bytes().to_vec(),
            expected_certificate_hash,
            expected_key_thumbprint,
            expected_organization_id,
            expected_device_id: None,
            expected_sequence: Some(expected_sequence),
            expected_role,
            expected_capability,
            require_accepted_root_line,
            registry,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn digest_without_sequence(
        content_type: ContentType,
        exact_digest: Hash32,
        expected_certificate_hash: CertificateHash,
        expected_key_thumbprint: Option<KeyThumbprint>,
        expected_organization_id: OrganizationId,
        expected_role: SignerRole,
        expected_capability: Option<CertificateCapability>,
        require_accepted_root_line: bool,
        registry: RegistryVersion,
    ) -> Self {
        Self {
            content_type,
            exact_payload: exact_digest.as_bytes().to_vec(),
            expected_certificate_hash,
            expected_key_thumbprint,
            expected_organization_id,
            expected_device_id: None,
            expected_sequence: None,
            expected_role,
            expected_capability,
            require_accepted_root_line,
            registry,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn core(
        content_type: ContentType,
        exact_core: &[u8],
        expected_certificate_hash: CertificateHash,
        expected_organization_id: OrganizationId,
        expected_device_id: Option<DeviceId>,
        expected_sequence: ChainSequence,
        expected_role: SignerRole,
        expected_capability: Option<CertificateCapability>,
        registry: RegistryVersion,
    ) -> Result<Self, CryptoError> {
        validate_unsigned_protocol_core(content_type, exact_core)?;
        Ok(Self {
            content_type,
            exact_payload: exact_core.to_vec(),
            expected_certificate_hash,
            expected_key_thumbprint: None,
            expected_organization_id,
            expected_device_id,
            expected_sequence: Some(expected_sequence),
            expected_role,
            expected_capability,
            require_accepted_root_line: false,
            registry,
        })
    }
}

pub struct VerifiedSigner {
    certificate_hash: CertificateHash,
    key_thumbprint: KeyThumbprint,
    role: SignerRole,
    organization_id: OrganizationId,
}

pub struct RecoveryVerificationContext {
    expected_certificate_hash: CertificateHash,
    expected_organization_id: OrganizationId,
    expected_certificate_kind: SignerRole,
    expected_sequence: ChainSequence,
    registry: RegistryVersion,
    expected_challenge: SecretBytes<32>,
}

impl RecoveryVerificationContext {
    #[must_use]
    pub const fn new(
        expected_certificate_hash: CertificateHash,
        expected_organization_id: OrganizationId,
        expected_certificate_kind: SignerRole,
        expected_sequence: ChainSequence,
        registry: RegistryVersion,
        expected_challenge: SecretBytes<32>,
    ) -> Self {
        Self {
            expected_certificate_hash,
            expected_organization_id,
            expected_certificate_kind,
            expected_sequence,
            registry,
            expected_challenge,
        }
    }
}

/// A successful, nonproductive recovery-inventory proof.
///
/// It is deliberately distinct from [`VerifiedSigner`] and cannot be used as
/// productive signer authority.
///
/// ```compile_fail
/// use ea_crypto::{VerifiedRecoveryTest, VerifiedSigner};
/// fn productive_authority(_: VerifiedSigner) {}
/// fn misuse(proof: VerifiedRecoveryTest) { productive_authority(proof); }
/// ```
pub struct VerifiedRecoveryTest {
    certificate_hash: CertificateHash,
    key_thumbprint: KeyThumbprint,
    certificate_kind: SignerRole,
}

impl VerifiedRecoveryTest {
    #[must_use]
    pub const fn certificate_hash(&self) -> CertificateHash {
        self.certificate_hash
    }

    #[must_use]
    pub const fn key_thumbprint(&self) -> KeyThumbprint {
        self.key_thumbprint
    }

    #[must_use]
    pub const fn certificate_kind(&self) -> SignerRole {
        self.certificate_kind
    }
}

impl VerifiedSigner {
    #[must_use]
    pub const fn certificate_hash(&self) -> CertificateHash {
        self.certificate_hash
    }

    #[must_use]
    pub const fn key_thumbprint(&self) -> KeyThumbprint {
        self.key_thumbprint
    }

    #[must_use]
    pub const fn role(&self) -> SignerRole {
        self.role
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }
}

impl fmt::Debug for VerifiedSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSigner")
            .field(
                "certificate_hash",
                &hexless(self.certificate_hash.as_bytes()),
            )
            .field("key_thumbprint", &hexless(self.key_thumbprint.as_bytes()))
            .field("role", &self.role)
            .field("organization_id", &hexless(self.organization_id.as_bytes()))
            .finish()
    }
}

pub fn verify_cose_sign1(
    bytes: &[u8],
    resolver: &impl SignerCertificateResolver,
    context: &VerificationContext,
) -> Result<VerifiedSigner, CryptoError> {
    let parsed = parse_cose_sign1(bytes, &[])?;
    if parsed.protected.profile != ProtectedProfile::Normal
        || parsed.protected.content_type != context.content_type
    {
        return Err(CryptoError::InvalidCose);
    }
    if parsed.payload != context.exact_payload {
        return Err(CryptoError::SignerMismatch);
    }
    let certificate_hash = parsed
        .protected
        .certificate_hash
        .ok_or(CryptoError::InvalidCose)?;
    if certificate_hash != context.expected_certificate_hash
        || context
            .expected_key_thumbprint
            .is_some_and(|thumbprint| thumbprint != parsed.protected.key_thumbprint)
    {
        return Err(CryptoError::SignerMismatch);
    }
    let resolved = resolver.resolve(certificate_hash, context.registry)?;
    if CertificateHash::from(object_hash(resolved.exact_certificate_bytes)) != certificate_hash {
        return Err(CryptoError::SignerMismatch);
    }
    let certificate = parse_signer_certificate(resolved.exact_certificate_bytes)?;
    let public_key = certificate
        .public_key
        .as_ref()
        .ok_or(CryptoError::SignerUnauthorized)?;
    if public_key.thumbprint() != parsed.protected.key_thumbprint {
        return Err(CryptoError::SignerMismatch);
    }
    let inactive = context.expected_sequence.is_some_and(|expected_sequence| {
        expected_sequence < certificate.effective_from_sequence
            || expected_sequence < resolved.registry_effective_from_sequence
            || certificate
                .revoked_from_sequence
                .is_some_and(|sequence| expected_sequence >= sequence)
            || resolved
                .registry_revoked_from_sequence
                .is_some_and(|sequence| expected_sequence >= sequence)
    });
    if certificate.organization_id != context.expected_organization_id
        || context
            .expected_device_id
            .is_some_and(|device_id| certificate.device_id != Some(device_id))
        || certificate.role != context.expected_role
        || resolved.registry_revoked
        || inactive
        || context
            .expected_capability
            .is_some_and(|capability| !certificate.capabilities.contains(&capability))
        || (context.require_accepted_root_line && !resolved.root_line_accepted)
    {
        return Err(CryptoError::SignerUnauthorized);
    }
    parsed.verify_with_key(public_key)?;
    Ok(VerifiedSigner {
        certificate_hash,
        key_thumbprint: parsed.protected.key_thumbprint,
        role: certificate.role,
        organization_id: certificate.organization_id,
    })
}

pub fn verify_recovery_test(
    bytes: &[u8],
    resolver: &impl SignerCertificateResolver,
    context: &RecoveryVerificationContext,
) -> Result<VerifiedRecoveryTest, CryptoError> {
    let parsed = parse_cose_sign1(bytes, &[])?;
    if parsed.protected.profile != ProtectedProfile::Normal
        || parsed.protected.content_type != ContentType::RecoveryTestDigest
    {
        return Err(CryptoError::InvalidCose);
    }
    let certificate_hash = parsed
        .protected
        .certificate_hash
        .ok_or(CryptoError::InvalidCose)?;
    if certificate_hash != context.expected_certificate_hash {
        return Err(CryptoError::SignerMismatch);
    }
    let resolved = resolver.resolve(certificate_hash, context.registry)?;
    if CertificateHash::from(object_hash(resolved.exact_certificate_bytes)) != certificate_hash {
        return Err(CryptoError::SignerMismatch);
    }
    let certificate = parse_signer_certificate(resolved.exact_certificate_bytes)?;
    let public_key = certificate
        .public_key
        .as_ref()
        .ok_or(CryptoError::SignerUnauthorized)?;
    let thumbprint = public_key.thumbprint();
    if thumbprint != parsed.protected.key_thumbprint
        || parsed.payload
            != recovery_test_digest_ref(&context.expected_challenge, thumbprint).as_bytes()
    {
        return Err(CryptoError::SignerMismatch);
    }
    let inactive = context.expected_sequence < certificate.effective_from_sequence
        || context.expected_sequence < resolved.registry_effective_from_sequence
        || certificate
            .revoked_from_sequence
            .is_some_and(|sequence| context.expected_sequence >= sequence)
        || resolved
            .registry_revoked_from_sequence
            .is_some_and(|sequence| context.expected_sequence >= sequence);
    if certificate.organization_id != context.expected_organization_id
        || certificate.role != context.expected_certificate_kind
        || resolved.registry_revoked
        || inactive
        || (certificate.role == SignerRole::Root && !resolved.root_line_accepted)
    {
        return Err(CryptoError::SignerUnauthorized);
    }
    parsed.verify_with_key(public_key)?;
    Ok(VerifiedRecoveryTest {
        certificate_hash,
        key_thumbprint: thumbprint,
        certificate_kind: certificate.role,
    })
}

struct ParsedSignerCertificate {
    public_key: Option<CanonicalPublicCoseKey>,
    organization_id: OrganizationId,
    device_id: Option<DeviceId>,
    role: SignerRole,
    capabilities: Vec<CertificateCapability>,
    effective_from_sequence: ChainSequence,
    revoked_from_sequence: Option<ChainSequence>,
}

pub fn validate_signer_certificate(exact_certificate_bytes: &[u8]) -> Result<(), CryptoError> {
    parse_signer_certificate(exact_certificate_bytes).map(|_| ())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CertificateCapability {
    InitialGrant,
    HistoricalGrant,
    OrganizationAdminApprove,
    HistoricalGrantApprove,
    DestructionApprove,
    ServerReceipt,
    DeletionAttest,
}

fn parse_signer_certificate(bytes: &[u8]) -> Result<ParsedSignerCertificate, CryptoError> {
    validate(bytes, ParserLimits::V1).map_err(|_| CryptoError::SignerMismatch)?;
    let mut decoder = Decoder::new(bytes);
    if signer_array_length(&mut decoder)? != 5
        || decoder.bytes().map_err(|_| CryptoError::SignerMismatch)? != b"EA1\0"
        || decoder.u64().map_err(|_| CryptoError::SignerMismatch)? != 5
        || decoder.u64().map_err(|_| CryptoError::SignerMismatch)? != 1
        || signer_array_length(&mut decoder)? != 0
        || signer_array_length(&mut decoder)? != 3
    {
        return Err(CryptoError::SignerMismatch);
    }
    let subtype = decoder.str().map_err(|_| CryptoError::SignerMismatch)?;
    let certificate = match subtype {
        "deviceCertificate" => parse_device_certificate_payload(&mut decoder)?,
        "rootCertificate" => parse_root_certificate_payload(&mut decoder)?,
        _ => return Err(CryptoError::SignerMismatch),
    };
    let signatures = signer_array_length(&mut decoder)?;
    if signatures == 0 || (subtype == "rootCertificate" && signatures != 1) {
        return Err(CryptoError::SignerMismatch);
    }
    for _ in 0..signatures {
        decoder.skip().map_err(|_| CryptoError::SignerMismatch)?;
    }
    if decoder.position() != bytes.len() {
        return Err(CryptoError::SignerMismatch);
    }
    Ok(certificate)
}

fn parse_device_certificate_payload(
    decoder: &mut Decoder<'_>,
) -> Result<ParsedSignerCertificate, CryptoError> {
    let payload_length = signer_array_length(decoder)?;
    let (certificate, directly_root_signed) = if payload_length == 2 {
        let core_length = signer_array_length(decoder)?;
        let certificate = parse_device_certificate_core(decoder, core_length)?;
        signer_bstr(decoder, 32)?;
        (certificate, false)
    } else {
        (
            parse_device_certificate_core(decoder, payload_length)?,
            true,
        )
    };
    if directly_root_signed && certificate.role != SignerRole::OrganizationAdmin {
        return Err(CryptoError::SignerMismatch);
    }
    Ok(certificate)
}

fn parse_device_certificate_core(
    decoder: &mut Decoder<'_>,
    length: u64,
) -> Result<ParsedSignerCertificate, CryptoError> {
    if length != 13 || decoder.u64().map_err(|_| CryptoError::SignerMismatch)? != 1 {
        return Err(CryptoError::SignerMismatch);
    }
    let organization_id = OrganizationId::try_from(signer_bstr(decoder, 16)?)
        .map_err(|_| CryptoError::SignerMismatch)?;
    let device_id =
        DeviceId::try_from(signer_bstr(decoder, 16)?).map_err(|_| CryptoError::SignerMismatch)?;
    let kind = decoder.u64().map_err(|_| CryptoError::SignerMismatch)?;
    let role = match kind {
        0 => SignerRole::Writer,
        1 => SignerRole::Reader,
        2 => SignerRole::OrganizationAdmin,
        3 => SignerRole::KeyApprover,
        4 => SignerRole::RecoveryRecipient,
        5 => SignerRole::HistoricalGrantAuthority,
        6 => SignerRole::ServerReceipt,
        7 => SignerRole::DeletionAttest,
        8.. => return Err(CryptoError::SignerMismatch),
    };
    let signing_key = signer_optional_public_key(decoder)?;
    let kem_key = signer_optional_public_key(decoder)?;
    let signing_thumbprint = signer_optional_thumbprint(decoder)?;
    let kem_thumbprint = signer_optional_thumbprint(decoder)?;
    let signing_required = kind != 4;
    let kem_required = matches!(kind, 1 | 4);
    if signing_key.is_some() != signing_required
        || signing_thumbprint.is_some() != signing_required
        || kem_key.is_some() != kem_required
        || kem_thumbprint.is_some() != kem_required
        || signing_key
            .as_ref()
            .is_some_and(|key| !matches!(key, CanonicalPublicCoseKey::Ed25519(_)))
        || kem_key
            .as_ref()
            .is_some_and(|key| !matches!(key, CanonicalPublicCoseKey::X25519(_)))
        || signing_key
            .as_ref()
            .zip(signing_thumbprint)
            .is_some_and(|(key, thumbprint)| key.thumbprint() != thumbprint)
        || kem_key
            .as_ref()
            .zip(kem_thumbprint)
            .is_some_and(|(key, thumbprint)| key.thumbprint() != thumbprint)
    {
        return Err(CryptoError::SignerMismatch);
    }
    let public_key = signing_key;

    let capability_count = signer_array_length(decoder)?;
    let mut capabilities = Vec::with_capacity(capability_count as usize);
    let mut previous: Option<&[u8]> = None;
    for _ in 0..capability_count {
        let literal = decoder.str().map_err(|_| CryptoError::SignerMismatch)?;
        if previous.is_some_and(|value| value >= literal.as_bytes()) {
            return Err(CryptoError::SignerMismatch);
        }
        let capability = match literal {
            "initialGrant" => CertificateCapability::InitialGrant,
            "historicalGrant" => CertificateCapability::HistoricalGrant,
            "organizationAdminApprove" => CertificateCapability::OrganizationAdminApprove,
            "historicalGrantApprove" => CertificateCapability::HistoricalGrantApprove,
            "destructionApprove" => CertificateCapability::DestructionApprove,
            "serverReceipt" => CertificateCapability::ServerReceipt,
            "deletionAttest" => CertificateCapability::DeletionAttest,
            _ => return Err(CryptoError::SignerMismatch),
        };
        capabilities.push(capability);
        previous = Some(literal.as_bytes());
    }
    if decoder.u64().map_err(|_| CryptoError::SignerMismatch)? > 4 {
        return Err(CryptoError::SignerMismatch);
    }
    let effective_from_sequence =
        ChainSequence::new(decoder.u64().map_err(|_| CryptoError::SignerMismatch)?);
    let revoked_from_sequence = signer_optional_sequence(decoder)?;
    if signer_array_length(decoder)? != 0 {
        return Err(CryptoError::SignerMismatch);
    }
    Ok(ParsedSignerCertificate {
        public_key,
        organization_id,
        device_id: Some(device_id),
        role,
        capabilities,
        effective_from_sequence,
        revoked_from_sequence,
    })
}

fn parse_root_certificate_payload(
    decoder: &mut Decoder<'_>,
) -> Result<ParsedSignerCertificate, CryptoError> {
    let payload_length = signer_array_length(decoder)?;
    let core_length = if payload_length == 2 {
        let length = signer_array_length(decoder)?;
        if length != 7 {
            return Err(CryptoError::SignerMismatch);
        }
        length
    } else {
        payload_length
    };
    if core_length != 7 || decoder.u64().map_err(|_| CryptoError::SignerMismatch)? != 1 {
        return Err(CryptoError::SignerMismatch);
    }
    let organization_id = OrganizationId::try_from(signer_bstr(decoder, 16)?)
        .map_err(|_| CryptoError::SignerMismatch)?;
    let public_key_bytes = decoder.bytes().map_err(|_| CryptoError::SignerMismatch)?;
    let public_key = CanonicalPublicCoseKey::from_deterministic_cbor(public_key_bytes)
        .map_err(|_| CryptoError::SignerMismatch)?;
    if !matches!(public_key, CanonicalPublicCoseKey::Ed25519(_)) {
        return Err(CryptoError::SignerMismatch);
    }
    let stored_thumbprint = KeyThumbprint::try_from(signer_bstr(decoder, 32)?)
        .map_err(|_| CryptoError::SignerMismatch)?;
    if stored_thumbprint != public_key.thumbprint() {
        return Err(CryptoError::SignerMismatch);
    }
    match (
        payload_length == 2,
        decoder
            .datatype()
            .map_err(|_| CryptoError::SignerMismatch)?,
    ) {
        (false, Type::Null) => decoder.null().map_err(|_| CryptoError::SignerMismatch)?,
        (true, Type::Bytes) => {
            signer_bstr(decoder, 32)?;
        }
        _ => return Err(CryptoError::SignerMismatch),
    }
    decoder.u64().map_err(|_| CryptoError::SignerMismatch)?;
    if signer_array_length(decoder)? != 0 {
        return Err(CryptoError::SignerMismatch);
    }
    if payload_length == 2 {
        signer_bstr(decoder, 32)?;
    }
    Ok(ParsedSignerCertificate {
        public_key: Some(public_key),
        organization_id,
        device_id: None,
        role: SignerRole::Root,
        capabilities: Vec::new(),
        effective_from_sequence: ChainSequence::new(0),
        revoked_from_sequence: None,
    })
}

fn signer_array_length(decoder: &mut Decoder<'_>) -> Result<u64, CryptoError> {
    decoder
        .array()
        .map_err(|_| CryptoError::SignerMismatch)?
        .ok_or(CryptoError::SignerMismatch)
}

fn signer_bstr<'a>(
    decoder: &mut Decoder<'a>,
    expected_length: usize,
) -> Result<&'a [u8], CryptoError> {
    let bytes = decoder.bytes().map_err(|_| CryptoError::SignerMismatch)?;
    if bytes.len() != expected_length {
        return Err(CryptoError::SignerMismatch);
    }
    Ok(bytes)
}

fn signer_optional_public_key(
    decoder: &mut Decoder<'_>,
) -> Result<Option<CanonicalPublicCoseKey>, CryptoError> {
    match decoder
        .datatype()
        .map_err(|_| CryptoError::SignerMismatch)?
    {
        Type::Null => {
            decoder.null().map_err(|_| CryptoError::SignerMismatch)?;
            Ok(None)
        }
        Type::Bytes => CanonicalPublicCoseKey::from_deterministic_cbor(
            decoder.bytes().map_err(|_| CryptoError::SignerMismatch)?,
        )
        .map(Some)
        .map_err(|_| CryptoError::SignerMismatch),
        _ => Err(CryptoError::SignerMismatch),
    }
}

fn signer_optional_thumbprint(
    decoder: &mut Decoder<'_>,
) -> Result<Option<KeyThumbprint>, CryptoError> {
    match decoder
        .datatype()
        .map_err(|_| CryptoError::SignerMismatch)?
    {
        Type::Null => {
            decoder.null().map_err(|_| CryptoError::SignerMismatch)?;
            Ok(None)
        }
        Type::Bytes => KeyThumbprint::try_from(signer_bstr(decoder, 32)?)
            .map(Some)
            .map_err(|_| CryptoError::SignerMismatch),
        _ => Err(CryptoError::SignerMismatch),
    }
}

fn signer_optional_sequence(
    decoder: &mut Decoder<'_>,
) -> Result<Option<ChainSequence>, CryptoError> {
    match decoder
        .datatype()
        .map_err(|_| CryptoError::SignerMismatch)?
    {
        Type::Null => {
            decoder.null().map_err(|_| CryptoError::SignerMismatch)?;
            Ok(None)
        }
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => decoder
            .u64()
            .map(ChainSequence::new)
            .map(Some)
            .map_err(|_| CryptoError::SignerMismatch),
        _ => Err(CryptoError::SignerMismatch),
    }
}

pub struct CoseVerifier;

impl CoseVerifier {
    pub fn verify_normal(
        bytes: &[u8],
        resolver: &impl SignerCertificateResolver,
        context: &VerificationContext,
    ) -> Result<VerifiedSigner, CryptoError> {
        verify_cose_sign1(bytes, resolver, context)
    }

    pub fn verify_recovery_test(
        bytes: &[u8],
        resolver: &impl SignerCertificateResolver,
        context: &RecoveryVerificationContext,
    ) -> Result<VerifiedRecoveryTest, CryptoError> {
        verify_recovery_test(bytes, resolver, context)
    }

    pub fn verify_initial_root_pop(
        bytes: &[u8],
        root_key: &CanonicalPublicCoseKey,
        expected_payload: &[u8],
    ) -> Result<(), CryptoError> {
        verify_initial_root_pop(bytes, root_key, expected_payload)
    }

    pub fn verify_enrollment_pop(
        bytes: &[u8],
        request_key: &CanonicalPublicCoseKey,
        expected_unsigned_core: &[u8],
    ) -> Result<(), CryptoError> {
        verify_enrollment_pop(bytes, request_key, expected_unsigned_core)
    }
}

pub fn verify_initial_root_pop(
    bytes: &[u8],
    root_key: &CanonicalPublicCoseKey,
    expected_payload: &[u8],
) -> Result<(), CryptoError> {
    let parsed = parse_cose_sign1(bytes, &[])?;
    if parsed.protected.profile != ProtectedProfile::InitialRoot
        || parsed.payload != expected_payload
    {
        return Err(CryptoError::InvalidCose);
    }
    parsed.verify_with_key(root_key)
}

pub fn verify_enrollment_pop(
    bytes: &[u8],
    request_key: &CanonicalPublicCoseKey,
    expected_unsigned_core: &[u8],
) -> Result<(), CryptoError> {
    validate_unsigned_protocol_core(
        ContentType::DeviceRegistrationRequestCbor,
        expected_unsigned_core,
    )?;
    let parsed = parse_cose_sign1(bytes, &[])?;
    if parsed.protected.profile != ProtectedProfile::Enrollment
        || parsed.payload != expected_unsigned_core
    {
        return Err(CryptoError::InvalidCose);
    }
    let embedded_key = registration_signing_key(expected_unsigned_core)?;
    if &embedded_key != request_key {
        return Err(CryptoError::SignerMismatch);
    }
    parsed.verify_with_key(&embedded_key)
}

struct CoreBindings {
    organization_id: OrganizationId,
    device_id: Option<DeviceId>,
    certificate_hash: Option<CertificateHash>,
    sequence: Option<ChainSequence>,
}

struct RecordBindings {
    digest: Hash32,
    certificate_hash: CertificateHash,
    organization_id: OrganizationId,
    sequence: ChainSequence,
    registry: RegistryVersion,
}

fn record_bindings(exact_signed_manifest: &[u8]) -> Result<RecordBindings, CryptoError> {
    validate(exact_signed_manifest, ParserLimits::V1)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_signed_manifest);
    if protocol_array_length(&mut decoder)? != 2
        || protocol_array_length(&mut decoder)? != 16
        || decoder.u64().ok() != Some(1)
        || decoder.u64().ok() != Some(1)
        || decoder.u64().ok() != Some(1)
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let organization_id = protocol_organization(&mut decoder)?;
    protocol_bstr(&mut decoder, 16)?;
    let sequence = ChainSequence::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_optional_bstr(&mut decoder, 32)?;
    let certificate_hash = CertificateHash::try_from(protocol_bstr(&mut decoder, 32)?)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    protocol_optional_bstr(&mut decoder, 32)?;
    let registry = RegistryVersion::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_bstr(&mut decoder, 32)?;
    protocol_bstr(&mut decoder, 32)?;
    if decoder
        .str()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        != crate::SUITE_ID
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(&mut decoder, 12)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if protocol_array_length(&mut decoder)? != 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(&mut decoder, 32)?;
    if decoder.position() != exact_signed_manifest.len() {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(RecordBindings {
        digest: record_digest(exact_signed_manifest),
        certificate_hash,
        organization_id,
        sequence,
        registry,
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GrantKind {
    Initial,
    Historical,
}

struct GrantBindings {
    digest: Hash32,
    certificate_hash: CertificateHash,
    key_thumbprint: KeyThumbprint,
    organization_id: OrganizationId,
    registry: RegistryVersion,
}

fn grant_bindings(
    exact_grant_body: &[u8],
    expected_kind: GrantKind,
) -> Result<GrantBindings, CryptoError> {
    validate(exact_grant_body, ParserLimits::V1).map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_grant_body);
    if protocol_array_length(&mut decoder)? != 3
        || protocol_array_length(&mut decoder)? != 17
        || decoder.u64().ok() != Some(1)
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let organization_id = protocol_organization(&mut decoder)?;
    protocol_bstr(&mut decoder, 16)?;
    protocol_bstr(&mut decoder, 32)?;
    let kind = match decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
    {
        0 => GrantKind::Initial,
        1 => GrantKind::Historical,
        _ => return Err(CryptoError::InvalidProtocolCore),
    };
    let purpose = decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if purpose > 1 || kind != expected_kind || (kind == GrantKind::Historical && purpose != 1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(&mut decoder, 32)?;
    protocol_bstr(&mut decoder, 32)?;
    let key_thumbprint = KeyThumbprint::try_from(protocol_bstr(&mut decoder, 32)?)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let certificate_hash = CertificateHash::try_from(protocol_bstr(&mut decoder, 32)?)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let required_capability = match kind {
        GrantKind::Initial => "initialGrant",
        GrantKind::Historical => "historicalGrant",
    };
    if decoder
        .str()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        != required_capability
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let registry = RegistryVersion::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_bstr(&mut decoder, 32)?;
    if decoder
        .str()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        != crate::GRANT_SUITE_ID
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    decoder
        .i64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let original = protocol_optional_bstr(&mut decoder, 32)?;
    let authorization = protocol_optional_bstr(&mut decoder, 32)?;
    match kind {
        GrantKind::Initial if original || authorization => {
            return Err(CryptoError::InvalidProtocolCore);
        }
        GrantKind::Historical if !original || !authorization => {
            return Err(CryptoError::InvalidProtocolCore);
        }
        _ => {}
    }
    protocol_bstr(&mut decoder, 32)?;
    protocol_bstr(&mut decoder, 48)?;
    if decoder.position() != exact_grant_body.len() {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(GrantBindings {
        digest: grant_digest(exact_grant_body),
        certificate_hash,
        key_thumbprint,
        organization_id,
        registry,
    })
}

struct ReceiptBindings {
    digest: Hash32,
    certificate_hash: CertificateHash,
    key_thumbprint: KeyThumbprint,
    organization_id: OrganizationId,
    sequence: ChainSequence,
    registry: RegistryVersion,
}

struct TrustOperationBindings {
    digest: Hash32,
    organization_id: OrganizationId,
    sequence: ChainSequence,
    registry: RegistryVersion,
}

struct TrustAdminBindings {
    digest: Hash32,
    certificate_hash: CertificateHash,
    key_thumbprint: KeyThumbprint,
    organization_id: OrganizationId,
    registry: RegistryVersion,
}

struct RootTrustBindings {
    digest: Hash32,
    organization_id: OrganizationId,
    sequence: Option<ChainSequence>,
    registry: RegistryVersion,
}

fn root_trust_bindings(
    exact_trust_digest_input: &[u8],
    exact_admin_authorization_object: Option<&[u8]>,
) -> Result<RootTrustBindings, CryptoError> {
    validate(exact_trust_digest_input, ParserLimits::V1)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_trust_digest_input);
    if protocol_array_length(&mut decoder)? != 2 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let subtype = decoder
        .str()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if !matches!(
        subtype,
        "registryEvent"
            | "deviceCertificate"
            | "operatorBinding"
            | "policy"
            | "writerTransition"
            | "rootCertificate"
    ) || protocol_array_length(&mut decoder)? != 2
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let core_start = decoder.position();
    let (organization_id, sequence, core_registry, registry_change_kind) = match subtype {
        "registryEvent" => {
            let (organization_id, sequence, registry, change_kind) =
                parse_registry_event_core(&mut decoder)?;
            (
                organization_id,
                Some(sequence),
                Some(registry),
                Some(change_kind),
            )
        }
        "deviceCertificate" => {
            let core_length = protocol_array_length(&mut decoder)?;
            let certificate = parse_device_certificate_core(&mut decoder, core_length)?;
            (
                certificate.organization_id,
                Some(certificate.effective_from_sequence),
                None,
                None,
            )
        }
        "operatorBinding" => {
            let (organization_id, sequence) = parse_operator_binding_core(&mut decoder)?;
            (organization_id, Some(sequence), None, None)
        }
        "policy" => {
            let (organization_id, sequence) = parse_policy_core(&mut decoder)?;
            (organization_id, Some(sequence), None, None)
        }
        "writerTransition" => {
            let (organization_id, sequence) = parse_writer_transition_core(&mut decoder)?;
            (organization_id, Some(sequence), None, None)
        }
        "rootCertificate" => {
            let organization_id = parse_root_rotation_core(&mut decoder)?;
            (organization_id, None, None, None)
        }
        _ => return Err(CryptoError::InvalidProtocolCore),
    };
    let core_end = decoder.position();
    let authorization_hash: [u8; 32] = protocol_bstr(&mut decoder, 32)?
        .try_into()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if decoder.position() != exact_trust_digest_input.len() {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let authorization = exact_admin_authorization_object.ok_or(CryptoError::InvalidProtocolCore)?;
    if authorization_hash != *object_hash(authorization).as_bytes() {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let authorization_bindings = organization_admin_authorization_object_bindings(authorization)?;
    let mut authorized_input = Vec::with_capacity(2 + subtype.len() + core_end - core_start);
    Encoder::new(&mut authorized_input)
        .array(2)
        .and_then(|encoder| encoder.str(subtype))
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    authorized_input.extend_from_slice(&exact_trust_digest_input[core_start..core_end]);
    if authorization_bindings.target_subtype != subtype
        || authorization_bindings.authorized_core_hash
            != *crate::authorized_trust_digest(&authorized_input).as_bytes()
        || authorization_bindings.organization_id != organization_id
        || core_registry.is_some_and(|registry| authorization_bindings.registry != registry)
        || registry_change_kind.is_some_and(|change_kind| {
            !admin_action_permits_registry_change(authorization_bindings.action, change_kind)
        })
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(RootTrustBindings {
        digest: trust_digest(exact_trust_digest_input),
        organization_id,
        sequence,
        registry: authorization_bindings.registry,
    })
}

struct AdminAuthorizationObjectBindings<'a> {
    organization_id: OrganizationId,
    registry: RegistryVersion,
    target_subtype: &'a str,
    authorized_core_hash: [u8; 32],
    action: u64,
}

fn admin_action_permits_registry_change(action: u64, change_kind: u64) -> bool {
    matches!(
        (action, change_kind),
        (0, 0) | (1, 1) | (2, 2) | (3, 3) | (5, 5)
    )
}

fn admin_action_permits_target(action: u64, target_subtype: &str) -> bool {
    matches!(
        (action, target_subtype),
        (0, "deviceCertificate" | "registryEvent")
            | (1, "registryEvent")
            | (2, "policy" | "registryEvent")
            | (3, "writerTransition" | "registryEvent")
            | (4, "operatorBinding")
            | (5, "deviceCertificate" | "registryEvent")
            | (6, "rootCertificate")
    )
}

fn organization_admin_authorization_object_bindings(
    exact_object: &[u8],
) -> Result<AdminAuthorizationObjectBindings<'_>, CryptoError> {
    validate(exact_object, ParserLimits::V1).map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_object);
    if protocol_array_length(&mut decoder)? != 5
        || decoder
            .bytes()
            .map_err(|_| CryptoError::InvalidProtocolCore)?
            != b"EA1\0"
        || decoder.u64().ok() != Some(5)
        || decoder.u64().ok() != Some(1)
        || protocol_array_length(&mut decoder)? != 0
        || protocol_array_length(&mut decoder)? != 3
        || decoder
            .str()
            .map_err(|_| CryptoError::InvalidProtocolCore)?
            != "organizationAdminAuthorization"
        || protocol_array_length(&mut decoder)? != 15
        || decoder.u64().ok() != Some(1)
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(&mut decoder, 16)?;
    let organization_id = protocol_organization(&mut decoder)?;
    let registry = RegistryVersion::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_bstr(&mut decoder, 32)?;
    protocol_bstr(&mut decoder, 32)?;
    protocol_bstr(&mut decoder, 32)?;
    protocol_bstr(&mut decoder, 32)?;
    let action = decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if action > 6 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let target_subtype = decoder
        .str()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if !matches!(
        target_subtype,
        "deviceCertificate"
            | "operatorBinding"
            | "registryEvent"
            | "policy"
            | "writerTransition"
            | "rootCertificate"
    ) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    if !admin_action_permits_target(action, target_subtype) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let authorized_core_hash = protocol_bstr(&mut decoder, 32)?
        .try_into()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let issued_at = protocol_int(&mut decoder)?;
    let expires_at = protocol_int(&mut decoder)?;
    if issued_at >= expires_at {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(&mut decoder, 32)?;
    if protocol_array_length(&mut decoder)? != 0 || protocol_array_length(&mut decoder)? != 1 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    decoder
        .skip()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if decoder.position() != exact_object.len() {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(AdminAuthorizationObjectBindings {
        organization_id,
        registry,
        target_subtype,
        authorized_core_hash,
        action,
    })
}

fn parse_registry_event_core(
    decoder: &mut Decoder<'_>,
) -> Result<(OrganizationId, ChainSequence, RegistryVersion, u64), CryptoError> {
    if protocol_array_length(decoder)? != 13 || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let organization_id = protocol_organization(decoder)?;
    let registry = RegistryVersion::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_optional_bstr(decoder, 32)?;
    let sequence = ChainSequence::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    protocol_int(decoder)?;
    protocol_int(decoder)?;
    protocol_int(decoder)?;
    protocol_bstr(decoder, 32)?;
    let change_length = protocol_array_length(decoder)?;
    let change_kind = decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    match (change_kind, change_length) {
        (0 | 2 | 3 | 4 | 6, 2) => {
            protocol_bstr(decoder, 32)?;
        }
        (1, 3) => {
            if decoder
                .u64()
                .map_err(|_| CryptoError::InvalidProtocolCore)?
                > 2
            {
                return Err(CryptoError::InvalidProtocolCore);
            }
            protocol_bstr(decoder, 32)?;
        }
        (5, 3) => {
            protocol_bstr(decoder, 32)?;
            if decoder
                .u64()
                .map_err(|_| CryptoError::InvalidProtocolCore)?
                > 1
            {
                return Err(CryptoError::InvalidProtocolCore);
            }
        }
        _ => return Err(CryptoError::InvalidProtocolCore),
    }
    protocol_bstr(decoder, 32)?;
    if protocol_array_length(decoder)? != 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok((organization_id, sequence, registry, change_kind))
}

fn parse_operator_binding_core(
    decoder: &mut Decoder<'_>,
) -> Result<(OrganizationId, ChainSequence), CryptoError> {
    if protocol_array_length(decoder)? != 11 || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let organization_id = protocol_organization(decoder)?;
    protocol_bstr(decoder, 16)?;
    protocol_bstr(decoder, 32)?;
    protocol_bstr(decoder, 32)?;
    if decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        > 2
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(decoder, 32)?;
    protocol_bstr(decoder, 32)?;
    let sequence = ChainSequence::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_optional_uint(decoder)?;
    if protocol_array_length(decoder)? != 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok((organization_id, sequence))
}

fn parse_root_rotation_core(decoder: &mut Decoder<'_>) -> Result<OrganizationId, CryptoError> {
    if protocol_array_length(decoder)? != 7 || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let organization_id = protocol_organization(decoder)?;
    let public_key = CanonicalPublicCoseKey::from_deterministic_cbor(
        decoder
            .bytes()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    )
    .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if !matches!(public_key, CanonicalPublicCoseKey::Ed25519(_)) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let thumbprint = KeyThumbprint::try_from(protocol_bstr(decoder, 32)?)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if thumbprint != public_key.thumbprint() {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(decoder, 32)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if protocol_array_length(decoder)? != 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(organization_id)
}

fn parse_writer_transition_core(
    decoder: &mut Decoder<'_>,
) -> Result<(OrganizationId, ChainSequence), CryptoError> {
    if protocol_array_length(decoder)? != 9 || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let organization_id = protocol_organization(decoder)?;
    protocol_bstr(decoder, 16)?;
    protocol_bstr(decoder, 32)?;
    protocol_bstr(decoder, 32)?;
    let sequence = ChainSequence::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_bstr(decoder, 32)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if protocol_array_length(decoder)? != 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok((organization_id, sequence))
}

fn parse_policy_core(
    decoder: &mut Decoder<'_>,
) -> Result<(OrganizationId, ChainSequence), CryptoError> {
    if protocol_array_length(decoder)? != 21 || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let organization_id = protocol_organization(decoder)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    protocol_optional_bstr(decoder, 32)?;
    if decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        > 1
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    for _ in 0..2 {
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?;
    }
    if decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        > 1
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    for _ in 0..2 {
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?;
    }
    decoder
        .bool()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    protocol_sorted_nonempty_bstr32(decoder)?;
    if decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        != 0
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if protocol_array_length(decoder)? != 3 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_optional_uint(decoder)?;
    decoder
        .bool()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    protocol_optional_bstr(decoder, 32)?;
    if protocol_array_length(decoder)? != 3 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    decoder
        .bool()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    decoder
        .str()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    decoder
        .bool()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let suites = protocol_array_length(decoder)?;
    if suites == 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let mut previous_suite: Option<&[u8]> = None;
    for _ in 0..suites {
        let suite = decoder
            .str()
            .map_err(|_| CryptoError::InvalidProtocolCore)?;
        if previous_suite.is_some_and(|previous| previous >= suite.as_bytes()) {
            return Err(CryptoError::InvalidProtocolCore);
        }
        previous_suite = Some(suite.as_bytes());
    }
    let formats = protocol_array_length(decoder)?;
    if formats == 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let mut previous_format = None;
    for _ in 0..formats {
        let format = decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?;
        if previous_format.is_some_and(|previous| previous >= format) {
            return Err(CryptoError::InvalidProtocolCore);
        }
        previous_format = Some(format);
    }
    let sequence = ChainSequence::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    if protocol_array_length(decoder)? != 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok((organization_id, sequence))
}

fn organization_admin_authorization_bindings(
    exact_trust_digest_input: &[u8],
) -> Result<TrustAdminBindings, CryptoError> {
    validate(exact_trust_digest_input, ParserLimits::V1)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_trust_digest_input);
    if protocol_array_length(&mut decoder)? != 2
        || decoder
            .str()
            .map_err(|_| CryptoError::InvalidProtocolCore)?
            != "organizationAdminAuthorization"
        || protocol_array_length(&mut decoder)? != 15
        || decoder.u64().ok() != Some(1)
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(&mut decoder, 16)?;
    let organization_id = protocol_organization(&mut decoder)?;
    let registry = RegistryVersion::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_bstr(&mut decoder, 32)?;
    let key_thumbprint = KeyThumbprint::try_from(protocol_bstr(&mut decoder, 32)?)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let certificate_hash = CertificateHash::try_from(protocol_bstr(&mut decoder, 32)?)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    protocol_bstr(&mut decoder, 32)?;
    let action = decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if action > 6 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let target_subtype = decoder
        .str()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if !matches!(
        target_subtype,
        "deviceCertificate"
            | "operatorBinding"
            | "registryEvent"
            | "policy"
            | "writerTransition"
            | "rootCertificate"
    ) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    if !admin_action_permits_target(action, target_subtype) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(&mut decoder, 32)?;
    let issued_at = protocol_int(&mut decoder)?;
    let expires_at = protocol_int(&mut decoder)?;
    if issued_at >= expires_at {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(&mut decoder, 32)?;
    if protocol_array_length(&mut decoder)? != 0
        || decoder.position() != exact_trust_digest_input.len()
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(TrustAdminBindings {
        digest: trust_digest(exact_trust_digest_input),
        certificate_hash,
        key_thumbprint,
        organization_id,
        registry,
    })
}

fn grant_authorization_bindings(
    exact_trust_digest_input: &[u8],
) -> Result<TrustOperationBindings, CryptoError> {
    validate(exact_trust_digest_input, ParserLimits::V1)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_trust_digest_input);
    if protocol_array_length(&mut decoder)? != 2
        || decoder
            .str()
            .map_err(|_| CryptoError::InvalidProtocolCore)?
            != "grantAuthorization"
        || protocol_array_length(&mut decoder)? != 12
        || decoder.u64().ok() != Some(1)
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_bstr(&mut decoder, 16)?;
    let organization_id = protocol_organization(&mut decoder)?;
    let registry = RegistryVersion::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_bstr(&mut decoder, 32)?;
    let sequence = ChainSequence::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_sorted_nonempty_bstr32(&mut decoder)?;
    protocol_bstr(&mut decoder, 32)?;
    protocol_bstr(&mut decoder, 32)?;
    if decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        != 1
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_int(&mut decoder)?;
    if protocol_array_length(&mut decoder)? != 0
        || decoder.position() != exact_trust_digest_input.len()
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(TrustOperationBindings {
        digest: trust_digest(exact_trust_digest_input),
        organization_id,
        sequence,
        registry,
    })
}

struct DestructionAuthorizationBindings {
    operation: TrustOperationBindings,
    destruction_id: [u8; 16],
}

fn destruction_authorization_bindings(
    exact_trust_digest_input: &[u8],
) -> Result<DestructionAuthorizationBindings, CryptoError> {
    validate(exact_trust_digest_input, ParserLimits::V1)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_trust_digest_input);
    if protocol_array_length(&mut decoder)? != 2
        || decoder
            .str()
            .map_err(|_| CryptoError::InvalidProtocolCore)?
            != "destructionAuthorization"
        || protocol_array_length(&mut decoder)? != 10
        || decoder.u64().ok() != Some(1)
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let destruction_id: [u8; 16] = protocol_bstr(&mut decoder, 16)?
        .try_into()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let organization_id = protocol_organization(&mut decoder)?;
    let registry = RegistryVersion::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_bstr(&mut decoder, 32)?;
    let sequence = ChainSequence::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    let target_count = protocol_array_length(&mut decoder)?;
    if target_count == 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let mut previous: Option<&[u8]> = None;
    for _ in 0..target_count {
        if protocol_array_length(&mut decoder)? != 2 {
            return Err(CryptoError::InvalidProtocolCore);
        }
        let entry_hash = protocol_bstr(&mut decoder, 32)?;
        if previous.is_some_and(|value| value >= entry_hash) {
            return Err(CryptoError::InvalidProtocolCore);
        }
        previous = Some(entry_hash);
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?;
    }
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if protocol_array_length(&mut decoder)? != 0
        || decoder.position() != exact_trust_digest_input.len()
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(DestructionAuthorizationBindings {
        operation: TrustOperationBindings {
            digest: trust_digest(exact_trust_digest_input),
            organization_id,
            sequence,
            registry,
        },
        destruction_id,
    })
}

struct DeletionAttestationBindings {
    digest: Hash32,
    destruction_id: [u8; 16],
    authorization_object_hash: [u8; 32],
}

fn destruction_transition_bindings(
    exact_trust_digest_input: &[u8],
) -> Result<DeletionAttestationBindings, CryptoError> {
    validate(exact_trust_digest_input, ParserLimits::V1)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_trust_digest_input);
    if protocol_array_length(&mut decoder)? != 2
        || decoder
            .str()
            .map_err(|_| CryptoError::InvalidProtocolCore)?
            != "destructionTransition"
        || protocol_array_length(&mut decoder)? != 10
        || decoder.u64().ok() != Some(1)
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let destruction_id = protocol_bstr(&mut decoder, 16)?
        .try_into()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let authorization_object_hash = protocol_bstr(&mut decoder, 32)?
        .try_into()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    protocol_bstr(&mut decoder, 16)?;
    protocol_optional_bstr(&mut decoder, 32)?;
    protocol_optional_bounded_uint(&mut decoder, 4)?;
    if decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        > 4
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    protocol_int(&mut decoder)?;
    if protocol_array_length(&mut decoder)? != 0
        || decoder.position() != exact_trust_digest_input.len()
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(DeletionAttestationBindings {
        digest: trust_digest(exact_trust_digest_input),
        destruction_id,
        authorization_object_hash,
    })
}

fn deletion_attestation_bindings(
    exact_trust_digest_input: &[u8],
) -> Result<DeletionAttestationBindings, CryptoError> {
    validate(exact_trust_digest_input, ParserLimits::V1)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_trust_digest_input);
    if protocol_array_length(&mut decoder)? != 2
        || decoder
            .str()
            .map_err(|_| CryptoError::InvalidProtocolCore)?
            != "deletionAttestation"
        || protocol_array_length(&mut decoder)? != 10
        || decoder.u64().ok() != Some(1)
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let destruction_id = protocol_bstr(&mut decoder, 16)?
        .try_into()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let authorization_object_hash = protocol_bstr(&mut decoder, 32)?
        .try_into()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    protocol_bstr(&mut decoder, 16)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    protocol_sorted_bstr32(&mut decoder)?;
    if decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        > 2
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    protocol_optional_int(&mut decoder)?;
    protocol_int(&mut decoder)?;
    if protocol_array_length(&mut decoder)? != 0
        || decoder.position() != exact_trust_digest_input.len()
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(DeletionAttestationBindings {
        digest: trust_digest(exact_trust_digest_input),
        destruction_id,
        authorization_object_hash,
    })
}

fn destruction_authorization_object_bindings(
    exact_object: &[u8],
) -> Result<DestructionAuthorizationBindings, CryptoError> {
    validate(exact_object, ParserLimits::V1).map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_object);
    if protocol_array_length(&mut decoder)? != 5
        || decoder
            .bytes()
            .map_err(|_| CryptoError::InvalidProtocolCore)?
            != b"EA1\0"
        || decoder.u64().ok() != Some(5)
        || decoder.u64().ok() != Some(1)
        || protocol_array_length(&mut decoder)? != 0
        || protocol_array_length(&mut decoder)? != 3
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let input_start = decoder.position();
    if decoder
        .str()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        != "destructionAuthorization"
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    decoder
        .skip()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let input_end = decoder.position();
    if protocol_array_length(&mut decoder)? != 2 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    for _ in 0..2 {
        decoder
            .skip()
            .map_err(|_| CryptoError::InvalidProtocolCore)?;
    }
    if decoder.position() != exact_object.len() {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let mut exact_input = Vec::with_capacity(1 + input_end.saturating_sub(input_start));
    exact_input.push(0x82);
    exact_input.extend_from_slice(&exact_object[input_start..input_end]);
    destruction_authorization_bindings(&exact_input)
}

fn receipt_bindings(exact_receipt_core: &[u8]) -> Result<ReceiptBindings, CryptoError> {
    validate(exact_receipt_core, ParserLimits::V1).map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(exact_receipt_core);
    if protocol_array_length(&mut decoder)? != 17 || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let organization_id = protocol_organization(&mut decoder)?;
    protocol_bstr(&mut decoder, 16)?;
    let sequence = ChainSequence::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_bstr(&mut decoder, 32)?;
    protocol_bstr(&mut decoder, 32)?;
    protocol_optional_bstr(&mut decoder, 32)?;
    let registry = RegistryVersion::new(
        decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
    );
    protocol_bstr(&mut decoder, 32)?;
    protocol_bstr(&mut decoder, 32)?;
    protocol_bstr(&mut decoder, 32)?;
    let grant_hashes = protocol_array_length(&mut decoder)?;
    if grant_hashes == 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let mut previous: Option<&[u8]> = None;
    for _ in 0..grant_hashes {
        let current = protocol_bstr(&mut decoder, 32)?;
        if previous.is_some_and(|value| value >= current) {
            return Err(CryptoError::InvalidProtocolCore);
        }
        previous = Some(current);
    }
    decoder
        .i64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    match decoder
        .datatype()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
    {
        Type::Null => decoder
            .null()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
        Type::U8
        | Type::U16
        | Type::U32
        | Type::U64
        | Type::I8
        | Type::I16
        | Type::I32
        | Type::I64 => {
            decoder
                .i64()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
        }
        _ => return Err(CryptoError::InvalidProtocolCore),
    }
    let key_thumbprint = KeyThumbprint::try_from(protocol_bstr(&mut decoder, 32)?)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let certificate_hash = CertificateHash::try_from(protocol_bstr(&mut decoder, 32)?)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if protocol_array_length(&mut decoder)? != 0 || decoder.position() != exact_receipt_core.len() {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(ReceiptBindings {
        digest: receipt_digest(exact_receipt_core),
        certificate_hash,
        key_thumbprint,
        organization_id,
        sequence,
        registry,
    })
}

fn protocol_array_length(decoder: &mut Decoder<'_>) -> Result<u64, CryptoError> {
    decoder
        .array()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        .ok_or(CryptoError::InvalidProtocolCore)
}

fn protocol_sorted_nonempty_bstr32(decoder: &mut Decoder<'_>) -> Result<(), CryptoError> {
    let count = protocol_array_length(decoder)?;
    if count == 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let mut previous: Option<&[u8]> = None;
    for _ in 0..count {
        let current = protocol_bstr(decoder, 32)?;
        if previous.is_some_and(|value| value >= current) {
            return Err(CryptoError::InvalidProtocolCore);
        }
        previous = Some(current);
    }
    Ok(())
}

fn protocol_sorted_bstr32(decoder: &mut Decoder<'_>) -> Result<(), CryptoError> {
    let count = protocol_array_length(decoder)?;
    let mut previous: Option<&[u8]> = None;
    for _ in 0..count {
        let current = protocol_bstr(decoder, 32)?;
        if previous.is_some_and(|value| value >= current) {
            return Err(CryptoError::InvalidProtocolCore);
        }
        previous = Some(current);
    }
    Ok(())
}

fn protocol_int(decoder: &mut Decoder<'_>) -> Result<i64, CryptoError> {
    decoder.i64().map_err(|_| CryptoError::InvalidProtocolCore)
}

fn protocol_optional_int(decoder: &mut Decoder<'_>) -> Result<(), CryptoError> {
    match decoder
        .datatype()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
    {
        Type::Null => decoder.null().map_err(|_| CryptoError::InvalidProtocolCore),
        Type::U8
        | Type::U16
        | Type::U32
        | Type::U64
        | Type::I8
        | Type::I16
        | Type::I32
        | Type::I64 => protocol_int(decoder).map(|_| ()),
        _ => Err(CryptoError::InvalidProtocolCore),
    }
}

fn protocol_optional_bounded_uint(
    decoder: &mut Decoder<'_>,
    maximum: u64,
) -> Result<(), CryptoError> {
    match decoder
        .datatype()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
    {
        Type::Null => decoder.null().map_err(|_| CryptoError::InvalidProtocolCore),
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            if decoder
                .u64()
                .map_err(|_| CryptoError::InvalidProtocolCore)?
                > maximum
            {
                return Err(CryptoError::InvalidProtocolCore);
            }
            Ok(())
        }
        _ => Err(CryptoError::InvalidProtocolCore),
    }
}

fn protocol_optional_uint(decoder: &mut Decoder<'_>) -> Result<(), CryptoError> {
    protocol_optional_bounded_uint(decoder, u64::MAX)
}

fn protocol_optional_bstr(
    decoder: &mut Decoder<'_>,
    expected_length: usize,
) -> Result<bool, CryptoError> {
    match decoder
        .datatype()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
    {
        Type::Null => {
            decoder
                .null()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            Ok(false)
        }
        Type::Bytes => {
            protocol_bstr(decoder, expected_length)?;
            Ok(true)
        }
        _ => Err(CryptoError::InvalidProtocolCore),
    }
}

fn core_bindings(content_type: ContentType, bytes: &[u8]) -> Result<CoreBindings, CryptoError> {
    validate_unsigned_protocol_core(content_type, bytes)?;
    let mut decoder = Decoder::new(bytes);
    exact_array_length(&mut decoder).map_err(|_| CryptoError::InvalidProtocolCore)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    match content_type {
        ContentType::CheckpointCbor => {
            decoder
                .str()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            let organization_id = protocol_organization(&mut decoder)?;
            decoder
                .skip()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            decoder
                .u64()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            let sequence = ChainSequence::new(
                decoder
                    .u64()
                    .map_err(|_| CryptoError::InvalidProtocolCore)?,
            );
            Ok(CoreBindings {
                organization_id,
                device_id: None,
                certificate_hash: None,
                sequence: Some(sequence),
            })
        }
        ContentType::EvidenceRenewalCbor => {
            decoder
                .str()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            Ok(CoreBindings {
                organization_id: protocol_organization(&mut decoder)?,
                device_id: None,
                certificate_hash: None,
                sequence: None,
            })
        }
        ContentType::LocalAuditCbor => {
            decoder
                .skip()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            let organization_id = protocol_organization(&mut decoder)?;
            let device_id = DeviceId::try_from(protocol_bstr(&mut decoder, 16)?)
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            decoder
                .skip()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            let certificate_hash = CertificateHash::try_from(protocol_bstr(&mut decoder, 32)?)
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            Ok(CoreBindings {
                organization_id,
                device_id: Some(device_id),
                certificate_hash: Some(certificate_hash),
                sequence: None,
            })
        }
        ContentType::ChallengeResponseCbor => {
            let organization_id = protocol_organization(&mut decoder)?;
            decoder
                .skip()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            decoder
                .i64()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            decoder
                .i64()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            let certificate_hash = CertificateHash::try_from(protocol_bstr(&mut decoder, 32)?)
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            Ok(CoreBindings {
                organization_id,
                device_id: None,
                certificate_hash: Some(certificate_hash),
                sequence: None,
            })
        }
        ContentType::ReaderAckCbor => {
            let organization_id = protocol_organization(&mut decoder)?;
            decoder
                .skip()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            let certificate_hash = CertificateHash::try_from(protocol_bstr(&mut decoder, 32)?)
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            let sequence = ChainSequence::new(
                decoder
                    .u64()
                    .map_err(|_| CryptoError::InvalidProtocolCore)?,
            );
            Ok(CoreBindings {
                organization_id,
                device_id: None,
                certificate_hash: Some(certificate_hash),
                sequence: Some(sequence),
            })
        }
        _ => Err(CryptoError::InvalidProtocolCore),
    }
}

fn protocol_organization(decoder: &mut Decoder<'_>) -> Result<OrganizationId, CryptoError> {
    OrganizationId::try_from(protocol_bstr(decoder, 16)?)
        .map_err(|_| CryptoError::InvalidProtocolCore)
}

fn protocol_bstr<'a>(
    decoder: &mut Decoder<'a>,
    expected_length: usize,
) -> Result<&'a [u8], CryptoError> {
    let value = decoder
        .bytes()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if value.len() != expected_length {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(value)
}

fn validate_payload(content_type: ContentType, payload: &[u8]) -> Result<(), CryptoError> {
    if content_type.is_digest() {
        if payload.len() == 32 {
            return Ok(());
        }
        return Err(CryptoError::InvalidCose);
    }
    validate_unsigned_protocol_core(content_type, payload)
}

pub fn validate_unsigned_protocol_core(
    content_type: ContentType,
    bytes: &[u8],
) -> Result<(), CryptoError> {
    validate(bytes, ParserLimits::V1).map_err(|_| CryptoError::InvalidProtocolCore)?;
    let mut decoder = Decoder::new(bytes);
    let length = exact_array_length(&mut decoder)?;
    match content_type {
        ContentType::ChallengeResponseCbor => validate_challenge_core(&mut decoder, length)?,
        ContentType::DeviceRegistrationRequestCbor => {
            validate_registration_core(&mut decoder, length)?
        }
        ContentType::ReaderAckCbor => validate_reader_ack_core(&mut decoder, length)?,
        ContentType::CheckpointCbor => validate_checkpoint_core(&mut decoder, length)?,
        ContentType::EvidenceRenewalCbor => validate_renewal_core(&mut decoder, length)?,
        ContentType::LocalAuditCbor => validate_local_audit_core(&mut decoder, length)?,
        _ => return Err(CryptoError::InvalidProtocolCore),
    }
    if decoder.position() != bytes.len() {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(())
}

pub fn encode_signed_protocol_wrapper(
    content_type: ContentType,
    unsigned_core: &[u8],
    cose_sign1: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !matches!(
        content_type,
        ContentType::ChallengeResponseCbor
            | ContentType::DeviceRegistrationRequestCbor
            | ContentType::ReaderAckCbor
    ) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    validate_unsigned_protocol_core(content_type, unsigned_core)?;
    let parsed = parse_cose_sign1(cose_sign1, &[])?;
    let expected_profile = if content_type == ContentType::DeviceRegistrationRequestCbor {
        ProtectedProfile::Enrollment
    } else {
        ProtectedProfile::Normal
    };
    if parsed.protected.profile != expected_profile
        || parsed.protected.content_type != content_type
        || parsed.payload != unsigned_core
    {
        return Err(CryptoError::InvalidProtocolCore);
    }

    let mut wrapper = Vec::with_capacity(
        1_usize
            .saturating_add(unsigned_core.len())
            .saturating_add(cose_sign1.len()),
    );
    wrapper.push(0x82);
    wrapper.extend_from_slice(unsigned_core);
    wrapper.extend_from_slice(cose_sign1);
    validate(&wrapper, ParserLimits::V1).map_err(|_| CryptoError::InvalidProtocolCore)?;
    Ok(wrapper)
}

fn validate_challenge_core(decoder: &mut Decoder<'_>, length: u64) -> Result<(), CryptoError> {
    if length != 7 || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    expect_bstr(decoder, 16)?;
    expect_bstr(decoder, 32)?;
    decoder
        .i64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    decoder
        .i64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    expect_bstr(decoder, 32)?;
    expect_empty_array(decoder)
}

fn validate_registration_core(decoder: &mut Decoder<'_>, length: u64) -> Result<(), CryptoError> {
    if length != 9 || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    expect_bstr(decoder, 16)?;
    expect_bstr(decoder, 16)?;
    if decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        > 2
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let signing_key = decoder
        .bytes()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let signing_key = CanonicalPublicCoseKey::from_deterministic_cbor(signing_key)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if !matches!(signing_key, CanonicalPublicCoseKey::Ed25519(_)) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    match decoder
        .datatype()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
    {
        Type::Null => decoder
            .null()
            .map_err(|_| CryptoError::InvalidProtocolCore)?,
        Type::Bytes => {
            let key = decoder
                .bytes()
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            let key = CanonicalPublicCoseKey::from_deterministic_cbor(key)
                .map_err(|_| CryptoError::InvalidProtocolCore)?;
            if !matches!(key, CanonicalPublicCoseKey::X25519(_)) {
                return Err(CryptoError::InvalidProtocolCore);
            }
        }
        _ => return Err(CryptoError::InvalidProtocolCore),
    }
    let versions = exact_array_length(decoder)?;
    if versions == 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let mut previous = None;
    for _ in 0..versions {
        let current = decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?;
        if previous.is_some_and(|value| value >= current) {
            return Err(CryptoError::InvalidProtocolCore);
        }
        previous = Some(current);
    }
    let suites = exact_array_length(decoder)?;
    if suites == 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let mut previous: Option<&str> = None;
    for _ in 0..suites {
        let current = decoder
            .str()
            .map_err(|_| CryptoError::InvalidProtocolCore)?;
        if current != crate::SUITE_ID
            || previous.is_some_and(|value| value.as_bytes() >= current.as_bytes())
        {
            return Err(CryptoError::InvalidProtocolCore);
        }
        previous = Some(current);
    }
    expect_empty_array(decoder)
}

fn registration_signing_key(bytes: &[u8]) -> Result<CanonicalPublicCoseKey, CryptoError> {
    let mut decoder = Decoder::new(bytes);
    if exact_array_length(&mut decoder).ok() != Some(9) || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    expect_bstr(&mut decoder, 16)?;
    expect_bstr(&mut decoder, 16)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let key = decoder
        .bytes()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    let key = CanonicalPublicCoseKey::from_deterministic_cbor(key)
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if !matches!(key, CanonicalPublicCoseKey::Ed25519(_)) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(key)
}

fn validate_checkpoint_core(decoder: &mut Decoder<'_>, length: u64) -> Result<(), CryptoError> {
    if length != 11
        || decoder.u64().ok() != Some(1)
        || decoder.str().ok() != Some("EINSATZARCHIV-CHECKPOINT-v1")
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    expect_bstr(decoder, 16)?;
    expect_bstr(decoder, 16)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    expect_bstr(decoder, 32)?;
    expect_bstr(decoder, 32)?;
    decoder
        .i64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    expect_optional_bstr(decoder, 32)?;
    expect_empty_array(decoder)
}

fn validate_renewal_core(decoder: &mut Decoder<'_>, length: u64) -> Result<(), CryptoError> {
    if length != 8
        || decoder.u64().ok() != Some(1)
        || decoder.str().ok() != Some("EINSATZARCHIV-EVIDENCE-RENEWAL-v1")
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    expect_bstr(decoder, 16)?;
    expect_bstr(decoder, 16)?;
    expect_bstr(decoder, 32)?;
    expect_optional_bstr(decoder, 32)?;
    let inputs = exact_array_length(decoder).map_err(|_| CryptoError::InvalidProtocolCore)?;
    if inputs == 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let mut previous: Option<&[u8]> = None;
    for _ in 0..inputs {
        let current = decoder
            .bytes()
            .map_err(|_| CryptoError::InvalidProtocolCore)?;
        if current.len() != 32 || previous.is_some_and(|value| value >= current) {
            return Err(CryptoError::InvalidProtocolCore);
        }
        previous = Some(current);
    }
    expect_empty_array(decoder)
}

fn validate_local_audit_core(decoder: &mut Decoder<'_>, length: u64) -> Result<(), CryptoError> {
    if length != 12 || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    expect_bstr(decoder, 16)?;
    expect_bstr(decoder, 16)?;
    expect_bstr(decoder, 16)?;
    expect_optional_bstr(decoder, 32)?;
    expect_bstr(decoder, 32)?;
    let action = decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    if action > 11
        || decoder
            .u64()
            .map_err(|_| CryptoError::InvalidProtocolCore)?
            > 2
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    decoder
        .i64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    validate_local_audit_context(decoder, action)?;
    expect_bstr(decoder, 32)?;
    expect_empty_array(decoder)
}

fn validate_local_audit_context(decoder: &mut Decoder<'_>, action: u64) -> Result<(), CryptoError> {
    if exact_array_length(decoder).map_err(|_| CryptoError::InvalidProtocolCore)? != 2 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    let expected_tag = match action {
        0 | 1 | 8 => 0,
        2 | 3 => 4,
        4 => 1,
        5 => 3,
        6 => 2,
        7 => 5,
        9 => 6,
        10 => 7,
        11 => 8,
        _ => return Err(CryptoError::InvalidProtocolCore),
    };
    if decoder.u64().ok() != Some(expected_tag) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    match expected_tag {
        0 => expect_optional_bstr(decoder, 32),
        1 => validate_context_fields(
            decoder,
            6,
            &[
                Field::Bstr32,
                Field::Bstr32,
                Field::Uint,
                Field::Int,
                Field::Int,
                Field::Bstr32,
            ],
        ),
        2 => validate_context_fields(
            decoder,
            6,
            &[
                Field::Int,
                Field::Int,
                Field::Uint,
                Field::Uint,
                Field::Int,
                Field::Int,
            ],
        ),
        3 => validate_context_fields(decoder, 2, &[Field::Bstr32, Field::Uint]),
        4 => validate_context_fields(
            decoder,
            3,
            &[Field::OptionalBstr32, Field::OptionalBstr32, Field::Uint],
        ),
        5 => validate_context_fields(decoder, 3, &[Field::Bstr32, Field::Bstr32, Field::Uint]),
        6 => validate_context_fields(decoder, 5, &[Field::Bstr32; 5]),
        7 => validate_context_fields(decoder, 2, &[Field::Bstr32; 2]),
        8 => validate_context_fields(decoder, 4, &[Field::Bstr32; 4]),
        _ => Err(CryptoError::InvalidProtocolCore),
    }
}

#[derive(Clone, Copy)]
enum Field {
    Bstr32,
    OptionalBstr32,
    Uint,
    Int,
}

fn validate_context_fields(
    decoder: &mut Decoder<'_>,
    length: u64,
    fields: &[Field],
) -> Result<(), CryptoError> {
    if exact_array_length(decoder).map_err(|_| CryptoError::InvalidProtocolCore)? != length
        || usize::try_from(length).ok() != Some(fields.len())
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    for field in fields {
        match field {
            Field::Bstr32 => expect_bstr(decoder, 32)?,
            Field::OptionalBstr32 => expect_optional_bstr(decoder, 32)?,
            Field::Uint => {
                decoder
                    .u64()
                    .map_err(|_| CryptoError::InvalidProtocolCore)?;
            }
            Field::Int => {
                decoder
                    .i64()
                    .map_err(|_| CryptoError::InvalidProtocolCore)?;
            }
        }
    }
    Ok(())
}

fn expect_optional_bstr(decoder: &mut Decoder<'_>, length: usize) -> Result<(), CryptoError> {
    match decoder
        .datatype()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
    {
        Type::Null => decoder.null().map_err(|_| CryptoError::InvalidProtocolCore),
        Type::Bytes => expect_bstr(decoder, length),
        _ => Err(CryptoError::InvalidProtocolCore),
    }
}

fn validate_reader_ack_core(decoder: &mut Decoder<'_>, length: u64) -> Result<(), CryptoError> {
    if length != 8 || decoder.u64().ok() != Some(1) {
        return Err(CryptoError::InvalidProtocolCore);
    }
    expect_bstr(decoder, 16)?;
    expect_bstr(decoder, 16)?;
    expect_bstr(decoder, 32)?;
    decoder
        .u64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    expect_bstr(decoder, 32)?;
    decoder
        .i64()
        .map_err(|_| CryptoError::InvalidProtocolCore)?;
    expect_empty_array(decoder)
}

fn expect_bstr(decoder: &mut Decoder<'_>, length: usize) -> Result<(), CryptoError> {
    if decoder
        .bytes()
        .map_err(|_| CryptoError::InvalidProtocolCore)?
        .len()
        != length
    {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(())
}

fn expect_empty_array(decoder: &mut Decoder<'_>) -> Result<(), CryptoError> {
    if exact_array_length(decoder)? != 0 {
        return Err(CryptoError::InvalidProtocolCore);
    }
    Ok(())
}

fn exact_array_length(decoder: &mut Decoder<'_>) -> Result<u64, CryptoError> {
    decoder
        .array()
        .map_err(|_| CryptoError::InvalidCose)?
        .ok_or(CryptoError::InvalidCose)
}

fn exact_map_length(decoder: &mut Decoder<'_>) -> Result<u64, CryptoError> {
    decoder
        .map()
        .map_err(|_| CryptoError::InvalidCose)?
        .ok_or(CryptoError::InvalidCose)
}

struct HiddenBytes;

fn hexless(_: &[u8]) -> HiddenBytes {
    HiddenBytes
}

impl fmt::Debug for HiddenBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<bound>")
    }
}
