use core::fmt;

use ea_cbor::{ParserLimits, validate};
use ea_types::{CertificateHash, ChainSequence, KeyThumbprint, OrganizationId, RegistryVersion};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::{Decoder, Encoder, data::Type};

use crate::digest::sha256_parts;
use crate::{CanonicalPublicCoseKey, CryptoError, SecretBytes, object_hash, recovery_test_digest};

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

    pub fn sign_normal(
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

pub struct Rfc3161TimeStampToken(Vec<u8>);

impl Rfc3161TimeStampToken {
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
    token: &Rfc3161TimeStampToken,
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
    const SIGNED_DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

    let (outer_content, outer_end) = exact_der_tlv(der, 0, 0x30)?;
    if outer_end != der.len() {
        return Err(CryptoError::InvalidCose);
    }
    let (oid_content, oid_end) = exact_der_tlv(der, outer_content, 0x06)?;
    if &der[oid_content..oid_end] != SIGNED_DATA_OID {
        return Err(CryptoError::InvalidCose);
    }
    let (explicit_content, explicit_end) = exact_der_tlv(der, oid_end, 0xa0)?;
    if explicit_end != outer_end || explicit_content == explicit_end {
        return Err(CryptoError::InvalidCose);
    }
    let (_, signed_data_end) = exact_der_tlv(der, explicit_content, 0x30)?;
    if signed_data_end != explicit_end {
        return Err(CryptoError::InvalidCose);
    }
    Ok(())
}

fn exact_der_tlv(
    der: &[u8],
    offset: usize,
    expected_tag: u8,
) -> Result<(usize, usize), CryptoError> {
    if der.get(offset).copied() != Some(expected_tag) {
        return Err(CryptoError::InvalidCose);
    }
    let length_offset = offset.checked_add(1).ok_or(CryptoError::SizeLimit)?;
    let first = *der.get(length_offset).ok_or(CryptoError::InvalidCose)?;
    let (content_offset, content_length) = if first < 0x80 {
        (
            length_offset.checked_add(1).ok_or(CryptoError::SizeLimit)?,
            usize::from(first),
        )
    } else {
        let length_bytes = usize::from(first & 0x7f);
        if length_bytes == 0 || length_bytes > core::mem::size_of::<usize>() {
            return Err(CryptoError::InvalidCose);
        }
        let bytes_start = length_offset.checked_add(1).ok_or(CryptoError::SizeLimit)?;
        let content_offset = bytes_start
            .checked_add(length_bytes)
            .ok_or(CryptoError::SizeLimit)?;
        let encoded_length = der
            .get(bytes_start..content_offset)
            .ok_or(CryptoError::InvalidCose)?;
        if encoded_length.first() == Some(&0) {
            return Err(CryptoError::InvalidCose);
        }
        let mut value = 0_usize;
        for byte in encoded_length {
            value = value
                .checked_mul(256)
                .and_then(|current| current.checked_add(usize::from(*byte)))
                .ok_or(CryptoError::SizeLimit)?;
        }
        if value < 0x80 {
            return Err(CryptoError::InvalidCose);
        }
        (content_offset, value)
    };
    let end = content_offset
        .checked_add(content_length)
        .ok_or(CryptoError::SizeLimit)?;
    if end > der.len() {
        return Err(CryptoError::InvalidCose);
    }
    Ok((content_offset, end))
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
    Server,
    Component,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerCapability {
    EntryWrite,
    GrantIssue,
    ReceiptSign,
    TrustSign,
    OrganizationAdminApprove,
    CheckpointSign,
    AuditSign,
    ChallengeSign,
    ReaderAck,
    DeletionAttest,
}

pub struct ResolvedSigner<'a> {
    pub exact_certificate_bytes: &'a [u8],
    pub certificate_hash: CertificateHash,
    pub public_key: &'a CanonicalPublicCoseKey,
    pub role: SignerRole,
    pub organization_id: OrganizationId,
    pub effective_from_sequence: ChainSequence,
    pub revoked_from_sequence: Option<ChainSequence>,
    pub capabilities: &'a [SignerCapability],
    pub revoked: bool,
}

pub trait SignerCertificateResolver {
    fn resolve(
        &self,
        certificate_hash: CertificateHash,
        bound_registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError>;
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ExpectedSigner {
    pub organization_id: OrganizationId,
    pub sequence: ChainSequence,
    pub role: SignerRole,
    pub capability: SignerCapability,
}

pub struct VerificationContext {
    content_type: ContentType,
    expected: ExpectedSigner,
    registry: RegistryVersion,
}

impl VerificationContext {
    #[must_use]
    pub const fn digest(
        content_type: ContentType,
        expected: ExpectedSigner,
        registry: RegistryVersion,
    ) -> Self {
        Self {
            content_type,
            expected,
            registry,
        }
    }
}

pub struct VerifiedSigner {
    certificate_hash: CertificateHash,
    key_thumbprint: KeyThumbprint,
    role: SignerRole,
    organization_id: OrganizationId,
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
    let certificate_hash = parsed
        .protected
        .certificate_hash
        .ok_or(CryptoError::InvalidCose)?;
    let resolved = resolver.resolve(certificate_hash, context.registry)?;
    if resolved.certificate_hash != certificate_hash
        || CertificateHash::from(object_hash(resolved.exact_certificate_bytes)) != certificate_hash
        || resolved.public_key.thumbprint() != parsed.protected.key_thumbprint
    {
        return Err(CryptoError::SignerMismatch);
    }
    let expected = context.expected;
    let inactive = expected.sequence < resolved.effective_from_sequence
        || resolved
            .revoked_from_sequence
            .is_some_and(|sequence| expected.sequence >= sequence);
    if resolved.organization_id != expected.organization_id
        || resolved.role != expected.role
        || resolved.revoked
        || inactive
        || !resolved.capabilities.contains(&expected.capability)
    {
        return Err(CryptoError::SignerUnauthorized);
    }
    parsed.verify_with_key(resolved.public_key)?;
    Ok(VerifiedSigner {
        certificate_hash,
        key_thumbprint: parsed.protected.key_thumbprint,
        role: resolved.role,
        organization_id: resolved.organization_id,
    })
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
