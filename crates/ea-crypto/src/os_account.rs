use ea_cbor::{ParserLimits, validate};
use ea_types::{DeviceId, Hash32, OrganizationId};
#[cfg(test)]
use minicbor::Decoder;
use minicbor::Encoder;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CryptoError, digest::sha256_parts};

const OS_ACCOUNT_DOMAIN: &[u8] = b"EINSATZARCHIV-OS-ACCOUNT-v1";
const MAX_UID: u32 = u32::MAX - 1;

#[derive(Zeroize, ZeroizeOnDrop)]
struct CanonicalOsAccountId(OsAccountKind);

#[derive(Zeroize)]
enum OsAccountKind {
    Windows(Vec<u8>),
    MacOs { guid: [u8; 16], uid: u32 },
    Linux { machine_id: [u8; 16], uid: u32 },
}

impl CanonicalOsAccountId {
    #[cfg(test)]
    fn windows_sid(sid: &[u8]) -> Result<Self, CryptoError> {
        validate_sid(sid)?;
        Ok(Self(OsAccountKind::Windows(sid.to_vec())))
    }

    fn windows_components(
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
        Ok(Self(OsAccountKind::Windows(sid)))
    }

    fn windows_sid_source(
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

    fn macos_guid(guid: &str, uid: u32) -> Result<Self, CryptoError> {
        validate_uid(uid)?;
        let guid = parse_guid(guid)?;
        Ok(Self(OsAccountKind::MacOs { guid, uid }))
    }

    fn macos_open_directory(
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

    fn linux_machine_id(machine_id: [u8; 16], uid: u32) -> Result<Self, CryptoError> {
        validate_uid(uid)?;
        if machine_id == [0; 16] {
            return Err(CryptoError::InvalidOsAccount);
        }
        Ok(Self(OsAccountKind::Linux { machine_id, uid }))
    }

    fn linux_machine_id_file(file: &[u8], uid: u32) -> Result<Self, CryptoError> {
        if file.len() != 33 || file[32] != b'\n' {
            return Err(CryptoError::InvalidOsAccount);
        }
        let mut machine_id = [0_u8; 16];
        for (index, pair) in file[..32].chunks_exact(2).enumerate() {
            machine_id[index] = (lower_hex(pair[0])? << 4) | lower_hex(pair[1])?;
        }
        Self::linux_machine_id(machine_id, uid)
    }

    #[cfg(test)]
    fn from_deterministic_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
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
    fn to_deterministic_cbor(&self) -> Vec<u8> {
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

/// Raw operating-system account identifiers are internal to this binding boundary.
///
/// ```compile_fail
/// use ea_crypto::CanonicalOsAccountId;
///
/// let account = CanonicalOsAccountId::linux_machine_id_file(
///     b"0123456789abcdef0123456789abcdef\n",
///     1000,
/// )?;
/// let raw_identifier = account.to_deterministic_cbor();
/// # Ok::<(), ea_crypto::CryptoError>(())
/// ```
pub fn windows_os_account_binding_hash(
    organization_id: OrganizationId,
    device_id: DeviceId,
    sid: &[u8],
    identifier_authority: [u8; 6],
    subauthorities: &[u32],
) -> Result<Hash32, CryptoError> {
    let account =
        CanonicalOsAccountId::windows_sid_source(sid, identifier_authority, subauthorities)?;
    Ok(os_account_binding_hash(
        organization_id,
        device_id,
        &account,
    ))
}

pub fn macos_os_account_binding_hash(
    organization_id: OrganizationId,
    device_id: DeviceId,
    guid_values: &[&str],
    unique_id_values: &[&str],
    actual_uid: u32,
) -> Result<Hash32, CryptoError> {
    let account =
        CanonicalOsAccountId::macos_open_directory(guid_values, unique_id_values, actual_uid)?;
    Ok(os_account_binding_hash(
        organization_id,
        device_id,
        &account,
    ))
}

pub fn linux_os_account_binding_hash(
    organization_id: OrganizationId,
    device_id: DeviceId,
    machine_id_file: &[u8],
    uid: u32,
) -> Result<Hash32, CryptoError> {
    let account = CanonicalOsAccountId::linux_machine_id_file(machine_id_file, uid)?;
    Ok(os_account_binding_hash(
        organization_id,
        device_id,
        &account,
    ))
}

fn os_account_binding_hash(
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

#[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn organization() -> OrganizationId {
        OrganizationId::try_from(
            hex::decode("000102030405060708090a0b0c0d0e0f")
                .unwrap()
                .as_slice(),
        )
        .unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::try_from(
            hex::decode("202122232425262728292a2b2c2d2e2f")
                .unwrap()
                .as_slice(),
        )
        .unwrap()
    }

    #[test]
    fn exact_wire_context_preimage_and_digest_kats_are_pinned() {
        let windows_sid =
            hex::decode("010500000000000515000000010000000200000003000000e8030000").unwrap();
        let cases = [
            (
                CanonicalOsAccountId::windows_sid_source(
                    &windows_sid,
                    [0, 0, 0, 0, 0, 5],
                    &[21, 1, 2, 3, 1000],
                )
                .unwrap(),
                "830100581c010500000000000515000000010000000200000003000000e8030000",
                "8350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f830100581c010500000000000515000000010000000200000003000000e8030000",
                "45494e5341545a4152434849562d4f532d4143434f554e542d76318350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f830100581c010500000000000515000000010000000200000003000000e8030000",
                "fcbb2ccb141966c57146aa6e578f56550bf86670ee9b31dea90f5a99b9f26220",
            ),
            (
                CanonicalOsAccountId::macos_open_directory(
                    &["f81d4fae-7dec-11d0-a765-00a0c91e6bf6"],
                    &["501"],
                    501,
                )
                .unwrap(),
                "84010150f81d4fae7dec11d0a76500a0c91e6bf61901f5",
                "8350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f84010150f81d4fae7dec11d0a76500a0c91e6bf61901f5",
                "45494e5341545a4152434849562d4f532d4143434f554e542d76318350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f84010150f81d4fae7dec11d0a76500a0c91e6bf61901f5",
                "0f4ed54a0330ed2bdbb5228d192d4dfa3a0853dae98aba3091f0c7c5f29fde7a",
            ),
            (
                CanonicalOsAccountId::linux_machine_id_file(
                    b"0123456789abcdef0123456789abcdef\n",
                    1000,
                )
                .unwrap(),
                "840102500123456789abcdef0123456789abcdef1903e8",
                "8350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f840102500123456789abcdef0123456789abcdef1903e8",
                "45494e5341545a4152434849562d4f532d4143434f554e542d76318350000102030405060708090a0b0c0d0e0f50202122232425262728292a2b2c2d2e2f840102500123456789abcdef0123456789abcdef1903e8",
                "bbca2d7b508415aed456efd6fc5499ddda65759250f6c8b5a1c2edd23a7883e4",
            ),
        ];

        for (account, account_hex, context_hex, preimage_hex, digest_hex) in cases {
            let account_bytes = account.to_deterministic_cbor();
            assert_eq!(hex::encode(&account_bytes), account_hex);
            let decoded = CanonicalOsAccountId::from_deterministic_cbor(&account_bytes).unwrap();
            assert_eq!(decoded.to_deterministic_cbor(), account_bytes);

            let context = hex::decode(context_hex).unwrap();
            assert_eq!(
                context,
                [
                    &[0x83, 0x50][..],
                    organization().as_bytes(),
                    &[0x50][..],
                    device().as_bytes(),
                    account_bytes.as_slice(),
                ]
                .concat()
            );
            assert_eq!(
                hex::decode(preimage_hex).unwrap(),
                [OS_ACCOUNT_DOMAIN, context.as_slice()].concat()
            );
            assert_eq!(
                hex::encode(os_account_binding_hash(organization(), device(), &account).as_bytes()),
                digest_hex
            );
        }
    }

    #[test]
    fn wire_decoder_is_exact_closed_and_uid_bounded() {
        for uid in [0, 23, 24, 255, 256, u32::MAX - 1] {
            let account = CanonicalOsAccountId::linux_machine_id([0x42; 16], uid).unwrap();
            let bytes = account.to_deterministic_cbor();
            assert_eq!(
                CanonicalOsAccountId::from_deterministic_cbor(&bytes)
                    .unwrap()
                    .to_deterministic_cbor(),
                bytes
            );
        }

        let invalid_hex = [
            "840102500123456789abcdef0123456789abcdef1affffffff",
            "840102500123456789abcdef0123456789abcdef6431303030",
            "840102500123456789abcdef0123456789abcdeff903e8",
            "840102500123456789abcdef0123456789abcdefc24903e8",
            "840102700123456789abcdef0123456789abcdef1903e8",
            "840102d8500123456789abcdef0123456789abcdef1903e8",
            "840102500123456789abcdef0123456789abcdef1903e800",
            "840002500123456789abcdef0123456789abcdef1903e8",
            "840103500123456789abcdef0123456789abcdef1903e8",
            "830102500123456789abcdef0123456789abcdef",
            "9f0102500123456789abcdef0123456789abcdef1903e8ff",
        ];
        for encoded in invalid_hex {
            assert!(
                CanonicalOsAccountId::from_deterministic_cbor(&hex::decode(encoded).unwrap())
                    .is_err(),
                "invalid fixture {encoded}"
            );
        }
    }
}
