use ea_crypto::object_hash;
use minicbor::Decoder;

use crate::{
    DestroyedEntryStubV1, EntryPackageV1, EvidenceObjectV1, GrantV1, Parsed, ParsedArchiveObject,
    ReceiptV1, TrustObjectV1,
    object::{
        ExactObjectBytes, FormatError, exact_item, expect_array_length, expect_empty_array, finish,
        wrap_object,
    },
};

pub const MAX_ARCHIVE_OBJECT_BYTES_V1: usize = 4_194_304;
pub const EIP_MAX_RAW_BYTES_V1: usize = 2_097_152;
pub const EAG_MAX_RAW_BYTES_V1: usize = 65_536;
pub const ESR_MAX_RAW_BYTES_V1: usize = 65_536;
pub const ECP_MAX_RAW_BYTES_V1: usize = 4_194_304;
pub const ETB_MAX_RAW_BYTES_V1: usize = 4_194_304;
pub const EDS_MAX_RAW_BYTES_V1: usize = 262_144;

pub const EIP_PREFIX_V1: [u8; 9] = [0x85, 0x44, b'E', b'A', b'1', 0, 1, 1, 0x80];
pub const EAG_PREFIX_V1: [u8; 9] = [0x85, 0x44, b'E', b'A', b'1', 0, 2, 1, 0x80];
pub const ESR_PREFIX_V1: [u8; 9] = [0x85, 0x44, b'E', b'A', b'1', 0, 3, 1, 0x80];
pub const ECP_PREFIX_V1: [u8; 9] = [0x85, 0x44, b'E', b'A', b'1', 0, 4, 1, 0x80];
pub const ETB_PREFIX_V1: [u8; 9] = [0x85, 0x44, b'E', b'A', b'1', 0, 5, 1, 0x80];
pub const EDS_PREFIX_V1: [u8; 9] = [0x85, 0x44, b'E', b'A', b'1', 0, 6, 1, 0x80];

/// Die sechs Objektarten des Exact-Object-Praefixes.
///
/// Die Zahlenwerte sind die Typbytes der Praefixkonstanten dieses Moduls und
/// zugleich der Wertebereich von `objectResult.objectType` (1..6) im
/// Berichtsschema. Der Typ wohnt DESHALB hier, neben den Konstanten, und nicht
/// beim Bericht: die geschlossene Menge hat genau eine Quelle, und
/// `crates/ea-verify` reicht sie mit `pub use ea_format::ObjectTypeV1;` nur
/// durch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObjectTypeV1 {
    /// `.eip` — signiertes Eintragspaket.
    Entry,
    /// `.eag` — Freigabe.
    Grant,
    /// `.esr` — Serverquittung.
    Receipt,
    /// `.ecp` — Evidence- beziehungsweise Checkpoint-Objekt.
    Evidence,
    /// `.etb` — Trust-Objekt.
    Trust,
    /// `.eds` — Stummel eines autorisiert vernichteten Eintrags.
    Destroyed,
}

impl ObjectTypeV1 {
    /// Das Typbyte, wie es im Praefix und im Bericht steht.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Entry => 1,
            Self::Grant => 2,
            Self::Receipt => 3,
            Self::Evidence => 4,
            Self::Trust => 5,
            Self::Destroyed => 6,
        }
    }
}

/// Das gepruefte Typbyte als Aufzaehlungswert.
///
/// `preflight` hat den Bereich 1..6 bereits durchgesetzt; dieser Schritt macht
/// aus der Zahl den TYP, damit der Verzweigungsbaum von
/// [`decode_exact_object`] ueber die geschlossene Menge laeuft statt ueber eine
/// Zahl mit Auffangzweig.
fn object_type_of(code: u8) -> Result<ObjectTypeV1, FormatError> {
    match code {
        1 => Ok(ObjectTypeV1::Entry),
        2 => Ok(ObjectTypeV1::Grant),
        3 => Ok(ObjectTypeV1::Receipt),
        4 => Ok(ObjectTypeV1::Evidence),
        5 => Ok(ObjectTypeV1::Trust),
        6 => Ok(ObjectTypeV1::Destroyed),
        _ => Err(FormatError::Prefix),
    }
}

pub fn decode_exact_object(bytes: &[u8]) -> Result<ParsedArchiveObject, FormatError> {
    let object_type = preflight(bytes)?;
    ea_cbor::validate(bytes, ea_cbor::ParserLimits::V1)?;
    let body = validate_outer(bytes, object_type)?;
    let hash = object_hash(bytes);
    let exact = bytes.to_vec();
    match object_type_of(object_type)? {
        ObjectTypeV1::Entry => crate::eip::parse_body(body)
            .map(|value| ParsedArchiveObject::Entry(Parsed::new(value, exact, hash))),
        ObjectTypeV1::Grant => crate::eag::parse_body(body)
            .map(|value| ParsedArchiveObject::Grant(Parsed::new(value, exact, hash))),
        ObjectTypeV1::Receipt => crate::esr::parse_body(body)
            .map(|value| ParsedArchiveObject::Receipt(Parsed::new(value, exact, hash))),
        ObjectTypeV1::Evidence => crate::ecp::parse_body(body)
            .map(|value| ParsedArchiveObject::Evidence(Parsed::new(value, exact, hash))),
        ObjectTypeV1::Trust => crate::etb::parse_body(body)
            .map(|value| ParsedArchiveObject::Trust(Parsed::new(value, exact, hash))),
        ObjectTypeV1::Destroyed => crate::eds::parse_body(body)
            .map(|value| ParsedArchiveObject::Destroyed(Parsed::new(value, exact, hash))),
    }
}

pub fn encode_entry_package(value: &EntryPackageV1) -> Result<ExactObjectBytes, FormatError> {
    encode_object(1, &value.body_bytes()?)
}

pub fn encode_grant(value: &GrantV1) -> Result<ExactObjectBytes, FormatError> {
    encode_object(2, value.body_bytes())
}

pub fn encode_receipt(value: &ReceiptV1) -> Result<ExactObjectBytes, FormatError> {
    encode_object(3, value.body_bytes())
}

pub fn encode_evidence(value: &EvidenceObjectV1) -> Result<ExactObjectBytes, FormatError> {
    encode_object(4, value.body_bytes())
}

pub fn encode_trust(value: &TrustObjectV1) -> Result<ExactObjectBytes, FormatError> {
    encode_object(5, value.body_bytes())
}

pub fn encode_destroyed_entry_stub(
    value: &DestroyedEntryStubV1,
) -> Result<ExactObjectBytes, FormatError> {
    encode_object(6, value.body_bytes())
}

fn encode_object(object_type: u8, body: &[u8]) -> Result<ExactObjectBytes, FormatError> {
    let raw_length = 9_usize
        .checked_add(body.len())
        .ok_or(FormatError::GlobalRawLimit)?;
    if raw_length > MAX_ARCHIVE_OBJECT_BYTES_V1 {
        return Err(FormatError::GlobalRawLimit);
    }
    let (family_limit, family_error) = match object_type {
        1 => (EIP_MAX_RAW_BYTES_V1, FormatError::EipRawLimit),
        2 => (EAG_MAX_RAW_BYTES_V1, FormatError::EagRawLimit),
        3 => (ESR_MAX_RAW_BYTES_V1, FormatError::EsrRawLimit),
        4 => (ECP_MAX_RAW_BYTES_V1, FormatError::EcpRawLimit),
        5 => (ETB_MAX_RAW_BYTES_V1, FormatError::EtbRawLimit),
        6 => (EDS_MAX_RAW_BYTES_V1, FormatError::EdsRawLimit),
        _ => return Err(FormatError::Prefix),
    };
    if raw_length > family_limit {
        return Err(family_error);
    }
    let exact = wrap_object(object_type, body);
    ea_cbor::validate(exact.as_bytes(), ea_cbor::ParserLimits::V1)?;
    Ok(exact)
}

fn preflight(bytes: &[u8]) -> Result<u8, FormatError> {
    if bytes.len() > MAX_ARCHIVE_OBJECT_BYTES_V1 {
        return Err(FormatError::GlobalRawLimit);
    }
    let prefix = bytes.get(..9).ok_or(FormatError::Prefix)?;
    if prefix[0..6] != [0x85, 0x44, b'E', b'A', b'1', 0] {
        return Err(FormatError::Prefix);
    }
    let object_type = prefix[6];
    if !(1..=6).contains(&object_type) {
        return Err(FormatError::Prefix);
    }
    if prefix[7] != 1 {
        return Err(FormatError::UnknownVersion);
    }
    if prefix[8] != 0x80 {
        return Err(FormatError::CriticalExtension);
    }
    let family_limit = match object_type {
        1 => EIP_MAX_RAW_BYTES_V1,
        2 => EAG_MAX_RAW_BYTES_V1,
        3 => ESR_MAX_RAW_BYTES_V1,
        4 => ECP_MAX_RAW_BYTES_V1,
        5 => ETB_MAX_RAW_BYTES_V1,
        6 => EDS_MAX_RAW_BYTES_V1,
        _ => return Err(FormatError::Prefix),
    };
    if bytes.len() > family_limit {
        return Err(match object_type {
            1 => FormatError::EipRawLimit,
            2 => FormatError::EagRawLimit,
            3 => FormatError::EsrRawLimit,
            4 => FormatError::EcpRawLimit,
            5 => FormatError::EtbRawLimit,
            6 => FormatError::EdsRawLimit,
            _ => FormatError::Prefix,
        });
    }
    Ok(object_type)
}

fn validate_outer(input: &[u8], expected_type: u8) -> Result<&[u8], FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 5)?;
    if decoder.bytes().map_err(|_| FormatError::Shape)? != b"EA1\0" {
        return Err(FormatError::Prefix);
    }
    if decoder.u64().map_err(|_| FormatError::Shape)? != u64::from(expected_type) {
        return Err(FormatError::TagMismatch);
    }
    if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
        return Err(FormatError::UnknownVersion);
    }
    expect_empty_array(&mut decoder)?;
    let body = exact_item(input, &mut decoder)?;
    finish(&decoder, input)?;
    Ok(body)
}
