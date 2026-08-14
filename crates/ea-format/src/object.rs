use core::fmt;

use ea_cbor::CborError;
use ea_types::ObjectHash;

use crate::{
    DestroyedEntryStubV1, EntryPackageV1, EvidenceObjectV1, GrantV1, ReceiptV1, TrustObjectV1,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FormatError {
    GlobalRawLimit,
    EipRawLimit,
    EagRawLimit,
    EsrRawLimit,
    EcpRawLimit,
    EtbRawLimit,
    EdsRawLimit,
    Prefix,
    UnknownVersion,
    CriticalExtension,
    TagMismatch,
    CiphertextLength,
    Shape,
    Cose,
    Duplicate,
    Unsorted,
    MissingRecovery,
    DuplicateRecovery,
    DuplicateRecipientKey,
    DuplicateRecipientCertificate,
    Cbor(CborError),
}

impl FormatError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::GlobalRawLimit => "EA-FORMAT-GLOBAL-RAW-LIMIT",
            Self::EipRawLimit => "EA-FORMAT-EIP-RAW-LIMIT",
            Self::EagRawLimit => "EA-FORMAT-EAG-RAW-LIMIT",
            Self::EsrRawLimit => "EA-FORMAT-ESR-RAW-LIMIT",
            Self::EcpRawLimit => "EA-FORMAT-ECP-RAW-LIMIT",
            Self::EtbRawLimit => "EA-FORMAT-ETB-RAW-LIMIT",
            Self::EdsRawLimit => "EA-FORMAT-EDS-RAW-LIMIT",
            Self::Prefix => "EA-FORMAT-PREFIX",
            Self::UnknownVersion => "EA-FORMAT-UNKNOWN-VERSION",
            Self::CriticalExtension => "EA-FORMAT-CRITICAL-EXTENSION",
            Self::TagMismatch => "EA-FORMAT-TAG-MISMATCH",
            Self::CiphertextLength => "EA-FORMAT-CIPHERTEXT-LENGTH",
            Self::Shape => "EA-FORMAT-SHAPE",
            Self::Cose => "EA-FORMAT-COSE",
            Self::Duplicate => "EA-FORMAT-DUPLICATE",
            Self::Unsorted => "EA-FORMAT-UNSORTED",
            Self::MissingRecovery => "EA-GRANT-MISSING-RECOVERY",
            Self::DuplicateRecovery => "EA-GRANT-DUPLICATE-RECOVERY",
            Self::DuplicateRecipientKey => "EA-GRANT-DUPLICATE-RECIPIENT-KEY",
            Self::DuplicateRecipientCertificate => "EA-GRANT-DUPLICATE-RECIPIENT-CERTIFICATE",
            Self::Cbor(error) => error.code(),
        }
    }
}

impl From<CborError> for FormatError {
    fn from(value: CborError) -> Self {
        Self::Cbor(value)
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for FormatError {}

#[derive(Clone, Eq, PartialEq)]
pub struct ExactObjectBytes(Vec<u8>);

impl ExactObjectBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

pub struct Parsed<T> {
    value: T,
    exact_bytes: ExactObjectBytes,
    object_hash: ObjectHash,
}

impl<T> Parsed<T> {
    pub(crate) fn new(value: T, exact_bytes: Vec<u8>, object_hash: ObjectHash) -> Self {
        Self {
            value,
            exact_bytes: ExactObjectBytes::new(exact_bytes),
            object_hash,
        }
    }

    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    #[must_use]
    pub const fn exact_bytes(&self) -> &ExactObjectBytes {
        &self.exact_bytes
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }
}

pub enum ParsedArchiveObject {
    Entry(Parsed<EntryPackageV1>),
    Grant(Parsed<GrantV1>),
    Receipt(Parsed<ReceiptV1>),
    Evidence(Parsed<EvidenceObjectV1>),
    Trust(Parsed<TrustObjectV1>),
    Destroyed(Parsed<DestroyedEntryStubV1>),
}

impl fmt::Debug for ParsedArchiveObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Entry(_) => "ParsedArchiveObject::Entry(<bound>)",
            Self::Grant(_) => "ParsedArchiveObject::Grant(<bound>)",
            Self::Receipt(_) => "ParsedArchiveObject::Receipt(<bound>)",
            Self::Evidence(_) => "ParsedArchiveObject::Evidence(<bound>)",
            Self::Trust(_) => "ParsedArchiveObject::Trust(<bound>)",
            Self::Destroyed(_) => "ParsedArchiveObject::Destroyed(<bound>)",
        })
    }
}

pub(crate) fn exact_array_length(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, FormatError> {
    decoder
        .array()
        .map_err(|_| FormatError::Shape)?
        .ok_or(FormatError::Shape)
}

pub(crate) fn expect_array_length(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), FormatError> {
    if exact_array_length(decoder)? != expected {
        return Err(FormatError::Shape);
    }
    Ok(())
}

pub(crate) fn expect_empty_array(decoder: &mut minicbor::Decoder<'_>) -> Result<(), FormatError> {
    if exact_array_length(decoder)? != 0 {
        return Err(FormatError::CriticalExtension);
    }
    Ok(())
}

pub(crate) fn exact_item<'a>(
    input: &'a [u8],
    decoder: &mut minicbor::Decoder<'a>,
) -> Result<&'a [u8], FormatError> {
    let start = decoder.position();
    decoder.skip().map_err(|_| FormatError::Shape)?;
    input
        .get(start..decoder.position())
        .ok_or(FormatError::Shape)
}

pub(crate) fn bytes_exact<'a>(
    decoder: &mut minicbor::Decoder<'a>,
    length: usize,
) -> Result<&'a [u8], FormatError> {
    let value = decoder.bytes().map_err(|_| FormatError::Shape)?;
    if value.len() != length {
        return Err(FormatError::Shape);
    }
    Ok(value)
}

pub(crate) fn optional_bytes_exact<'a>(
    decoder: &mut minicbor::Decoder<'a>,
    length: usize,
) -> Result<Option<&'a [u8]>, FormatError> {
    match decoder.datatype().map_err(|_| FormatError::Shape)? {
        minicbor::data::Type::Null => {
            decoder.null().map_err(|_| FormatError::Shape)?;
            Ok(None)
        }
        minicbor::data::Type::Bytes => bytes_exact(decoder, length).map(Some),
        _ => Err(FormatError::Shape),
    }
}

pub(crate) fn finish(decoder: &minicbor::Decoder<'_>, input: &[u8]) -> Result<(), FormatError> {
    if decoder.position() != input.len() {
        return Err(FormatError::Shape);
    }
    Ok(())
}

pub(crate) fn wrap_object(object_type: u8, body: &[u8]) -> ExactObjectBytes {
    let mut bytes = Vec::with_capacity(9_usize.saturating_add(body.len()));
    bytes.extend_from_slice(&[0x85, 0x44, b'E', b'A', b'1', 0, object_type, 1, 0x80]);
    bytes.extend_from_slice(body);
    ExactObjectBytes::new(bytes)
}
