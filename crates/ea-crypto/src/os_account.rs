use ea_cbor::{ParserLimits, validate};
use ea_types::{DeviceId, Hash32, OrganizationId};
use minicbor::{Decoder, Encoder};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CryptoError, digest::sha256_parts};

const OS_ACCOUNT_DOMAIN: &[u8] = b"EINSATZARCHIV-OS-ACCOUNT-v1";
const MAX_UID: u32 = u32::MAX - 1;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CanonicalOsAccountId(OsAccountKind);

#[derive(Zeroize)]
enum OsAccountKind {
    Windows(Vec<u8>),
    MacOs { guid: [u8; 16], uid: u32 },
    Linux { machine_id: [u8; 16], uid: u32 },
}

impl CanonicalOsAccountId {
    pub fn windows_sid(sid: &[u8]) -> Result<Self, CryptoError> {
        validate_sid(sid)?;
        Ok(Self(OsAccountKind::Windows(sid.to_vec())))
    }

    pub fn windows_components(
        identifier_authority: [u8; 6],
        subauthorities: &[u32],
    ) -> Result<Self, CryptoError> {
        if !(1..=15).contains(&subauthorities.len()) {
            return Err(CryptoError::InvalidOsAccount);
        }
        let length = 8_usize
            .checked_add(
                4_usize
                    .checked_mul(subauthorities.len())
                    .ok_or(CryptoError::InvalidOsAccount)?,
            )
            .ok_or(CryptoError::InvalidOsAccount)?;
        let mut sid = Vec::with_capacity(length);
        sid.push(1);
        sid.push(u8::try_from(subauthorities.len()).map_err(|_| CryptoError::InvalidOsAccount)?);
        sid.extend_from_slice(&identifier_authority);
        for subauthority in subauthorities {
            sid.extend_from_slice(&subauthority.to_le_bytes());
        }
        Self::windows_sid(&sid)
    }

    pub fn windows_sid_source(
        sid: &[u8],
        identifier_authority: [u8; 6],
        subauthorities: &[u32],
    ) -> Result<Self, CryptoError> {
        let canonical = Self::windows_components(identifier_authority, subauthorities)?;
        let OsAccountKind::Windows(expected) = &canonical.0 else {
            unreachable!("Windows component construction always yields Windows")
        };
        if sid != expected {
            return Err(CryptoError::InvalidOsAccount);
        }
        Ok(canonical)
    }

    pub fn macos_guid(guid: &str, uid: u32) -> Result<Self, CryptoError> {
        validate_uid(uid)?;
        let guid = parse_guid(guid)?;
        Ok(Self(OsAccountKind::MacOs { guid, uid }))
    }

    pub fn macos_open_directory(
        guid_values: &[&str],
        unique_id_values: &[&str],
        actual_uid: u32,
    ) -> Result<Self, CryptoError> {
        let [guid] = guid_values else {
            return Err(CryptoError::InvalidOsAccount);
        };
        let [unique_id] = unique_id_values else {
            return Err(CryptoError::InvalidOsAccount);
        };
        let parsed_uid = parse_uid_text(unique_id)?;
        if parsed_uid != actual_uid {
            return Err(CryptoError::InvalidOsAccount);
        }
        Self::macos_guid(guid, actual_uid)
    }

    pub fn linux_machine_id(machine_id: [u8; 16], uid: u32) -> Result<Self, CryptoError> {
        validate_uid(uid)?;
        if machine_id == [0; 16] {
            return Err(CryptoError::InvalidOsAccount);
        }
        Ok(Self(OsAccountKind::Linux { machine_id, uid }))
    }

    pub fn linux_machine_id_file(file: &[u8], uid: u32) -> Result<Self, CryptoError> {
        if file.len() != 33 || file[32] != b'\n' {
            return Err(CryptoError::InvalidOsAccount);
        }
        let mut machine_id = [0_u8; 16];
        for (index, pair) in file[..32].chunks_exact(2).enumerate() {
            machine_id[index] = (lower_hex(pair[0])? << 4) | lower_hex(pair[1])?;
        }
        Self::linux_machine_id(machine_id, uid)
    }

    pub fn from_deterministic_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        validate(bytes, ParserLimits::V1).map_err(|_| CryptoError::InvalidOsAccount)?;
        let mut decoder = Decoder::new(bytes);
        let length = decoder
            .array()
            .map_err(|_| CryptoError::InvalidOsAccount)?
            .ok_or(CryptoError::InvalidOsAccount)?;
        if decoder.u64().map_err(|_| CryptoError::InvalidOsAccount)? != 1 {
            return Err(CryptoError::InvalidOsAccount);
        }
        let platform = decoder.u64().map_err(|_| CryptoError::InvalidOsAccount)?;
        let result = match (platform, length) {
            (0, 3) => {
                Self::windows_sid(decoder.bytes().map_err(|_| CryptoError::InvalidOsAccount)?)?
            }
            (1, 4) => {
                let guid: [u8; 16] = decoder
                    .bytes()
                    .map_err(|_| CryptoError::InvalidOsAccount)?
                    .try_into()
                    .map_err(|_| CryptoError::InvalidOsAccount)?;
                let uid = decoder.u32().map_err(|_| CryptoError::InvalidOsAccount)?;
                validate_uid(uid)?;
                if guid == [0; 16] {
                    return Err(CryptoError::InvalidOsAccount);
                }
                Self(OsAccountKind::MacOs { guid, uid })
            }
            (2, 4) => {
                let machine_id: [u8; 16] = decoder
                    .bytes()
                    .map_err(|_| CryptoError::InvalidOsAccount)?
                    .try_into()
                    .map_err(|_| CryptoError::InvalidOsAccount)?;
                let uid = decoder.u32().map_err(|_| CryptoError::InvalidOsAccount)?;
                Self::linux_machine_id(machine_id, uid)?
            }
            _ => return Err(CryptoError::InvalidOsAccount),
        };
        if decoder.position() != bytes.len() || result.to_deterministic_cbor() != bytes {
            return Err(CryptoError::InvalidOsAccount);
        }
        Ok(result)
    }

    #[must_use]
    pub fn to_deterministic_cbor(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(72);
        let mut encoder = Encoder::new(&mut bytes);
        match &self.0 {
            OsAccountKind::Windows(sid) => {
                encoder
                    .array(3)
                    .and_then(|encoder| encoder.u8(1))
                    .and_then(|encoder| encoder.u8(0))
                    .and_then(|encoder| encoder.bytes(sid))
                    .expect("encoding validated Windows OS account cannot fail");
            }
            OsAccountKind::MacOs { guid, uid } => {
                encoder
                    .array(4)
                    .and_then(|encoder| encoder.u8(1))
                    .and_then(|encoder| encoder.u8(1))
                    .and_then(|encoder| encoder.bytes(guid))
                    .and_then(|encoder| encoder.u32(*uid))
                    .expect("encoding validated macOS account cannot fail");
            }
            OsAccountKind::Linux { machine_id, uid } => {
                encoder
                    .array(4)
                    .and_then(|encoder| encoder.u8(1))
                    .and_then(|encoder| encoder.u8(2))
                    .and_then(|encoder| encoder.bytes(machine_id))
                    .and_then(|encoder| encoder.u32(*uid))
                    .expect("encoding validated Linux account cannot fail");
            }
        }
        debug_assert!(validate(&bytes, ParserLimits::V1).is_ok());
        bytes
    }
}

#[must_use]
pub fn os_account_binding_hash(
    organization_id: OrganizationId,
    device_id: DeviceId,
    account: &CanonicalOsAccountId,
) -> Hash32 {
    let account_bytes = Zeroizing::new(account.to_deterministic_cbor());
    let mut context = Zeroizing::new(Vec::with_capacity(35 + account_bytes.len()));
    context.push(0x83);
    context.push(0x50);
    context.extend_from_slice(organization_id.as_bytes());
    context.push(0x50);
    context.extend_from_slice(device_id.as_bytes());
    context.extend_from_slice(account_bytes.as_slice());
    debug_assert!(validate(&context, ParserLimits::V1).is_ok());
    sha256_parts(&[OS_ACCOUNT_DOMAIN, context.as_slice()])
}

fn validate_sid(sid: &[u8]) -> Result<(), CryptoError> {
    if !(12..=68).contains(&sid.len()) || sid[0] != 1 || !(1..=15).contains(&sid[1]) {
        return Err(CryptoError::InvalidOsAccount);
    }
    let expected = 8_usize
        .checked_add(
            4_usize
                .checked_mul(usize::from(sid[1]))
                .ok_or(CryptoError::InvalidOsAccount)?,
        )
        .ok_or(CryptoError::InvalidOsAccount)?;
    if sid.len() != expected {
        return Err(CryptoError::InvalidOsAccount);
    }
    Ok(())
}

fn validate_uid(uid: u32) -> Result<(), CryptoError> {
    if uid > MAX_UID {
        return Err(CryptoError::InvalidOsAccount);
    }
    Ok(())
}

fn parse_uid_text(text: &str) -> Result<u32, CryptoError> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(CryptoError::InvalidOsAccount);
    }
    let uid = text
        .parse::<u32>()
        .map_err(|_| CryptoError::InvalidOsAccount)?;
    validate_uid(uid)?;
    Ok(uid)
}

fn parse_guid(text: &str) -> Result<[u8; 16], CryptoError> {
    if text.len() != 36
        || ![8, 13, 18, 23]
            .into_iter()
            .all(|index| text.as_bytes()[index] == b'-')
    {
        return Err(CryptoError::InvalidOsAccount);
    }
    let mut guid = [0_u8; 16];
    let mut output = 0;
    let mut input = 0;
    while input < text.len() {
        if [8, 13, 18, 23].contains(&input) {
            input += 1;
            continue;
        }
        let high = any_hex(text.as_bytes()[input])?;
        let low = any_hex(text.as_bytes()[input + 1])?;
        guid[output] = (high << 4) | low;
        output += 1;
        input += 2;
    }
    if output != 16 || guid == [0; 16] {
        return Err(CryptoError::InvalidOsAccount);
    }
    Ok(guid)
}

fn lower_hex(byte: u8) -> Result<u8, CryptoError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CryptoError::InvalidOsAccount),
    }
}

fn any_hex(byte: u8) -> Result<u8, CryptoError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CryptoError::InvalidOsAccount),
    }
}
