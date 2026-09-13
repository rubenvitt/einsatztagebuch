use crate::{CborError, ParserLimits, decode::deterministic_key_cmp};

pub fn to_deterministic_vec<T>(value: &T) -> Result<Vec<u8>, CborError>
where
    T: minicbor::Encode<()>,
{
    let mut encoder = minicbor::Encoder::new(WipingBuffer::default());
    value
        .encode(&mut encoder, &mut ())
        .map_err(|_| CborError::Encode)?;
    let upstream = encoder.into_writer();
    canonical_reencode(&upstream, ParserLimits::V1)
}

pub fn canonical_reencode(input: &[u8], limits: ParserLimits) -> Result<Vec<u8>, CborError> {
    crate::decode::scan_relaxed(input, limits)?;
    let mut encoder = CanonicalEncoder::new(input);
    let result = encoder.encode_item()?;
    if encoder.position != input.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(result.into_vec())
}

struct CanonicalEncoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> CanonicalEncoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn encode_item(&mut self) -> Result<WipingBuffer, CborError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 | 1 => {
                let argument = self.read_argument(additional)?;
                encode_head(major, argument)
            }
            2 | 3 => {
                let length = self.read_argument(additional)?;
                let usize_length = usize::try_from(length).map_err(|_| CborError::ItemLimit)?;
                let payload = self.read_slice(usize_length)?;
                let mut output = encode_head(major, length)?;
                output.append(payload)?;
                Ok(output)
            }
            4 => {
                let length = self.read_argument(additional)?;
                let mut output = encode_head(major, length)?;
                for _ in 0..length {
                    output.append(&self.encode_item()?)?;
                }
                Ok(output)
            }
            5 => {
                let length = self.read_argument(additional)?;
                let capacity = usize::try_from(length).map_err(|_| CborError::ContainerLimit)?;
                let mut entries = Vec::new();
                entries
                    .try_reserve_exact(capacity)
                    .map_err(|_| CborError::ContainerLimit)?;
                for _ in 0..length {
                    entries.push((self.encode_item()?, self.encode_item()?));
                }
                entries.sort_by(|left, right| deterministic_key_cmp(&left.0, &right.0));
                if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                    return Err(CborError::DuplicateKey);
                }
                let mut output = encode_head(major, length)?;
                for (key, value) in entries {
                    output.append(&key)?;
                    output.append(&value)?;
                }
                Ok(output)
            }
            6 => {
                let tag = self.read_argument(additional)?;
                let mut output = encode_head(major, tag)?;
                output.append(&self.encode_item()?)?;
                Ok(output)
            }
            7 => match additional {
                0..=23 => WipingBuffer::from_slice(&[initial]),
                24 => WipingBuffer::from_slice(&[initial, self.read_byte()?]),
                25..=27 => Err(CborError::Float),
                31 => Err(CborError::Indefinite),
                _ => Err(CborError::Invalid),
            },
            _ => Err(CborError::Invalid),
        }
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, CborError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => Ok(u64::from(self.read_byte()?)),
            25 => self.read_uint(2),
            26 => self.read_uint(4),
            27 => self.read_uint(8),
            31 => Err(CborError::Indefinite),
            _ => Err(CborError::Invalid),
        }
    }

    fn read_uint(&mut self, width: usize) -> Result<u64, CborError> {
        let bytes = self.read_slice(width)?;
        Ok(bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)))
    }

    fn read_byte(&mut self) -> Result<u8, CborError> {
        let byte = self
            .input
            .get(self.position)
            .copied()
            .ok_or(CborError::Invalid)?;
        self.position += 1;
        Ok(byte)
    }

    fn read_slice(&mut self, length: usize) -> Result<&'a [u8], CborError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CborError::ItemLimit)?;
        let slice = self
            .input
            .get(self.position..end)
            .ok_or(CborError::Invalid)?;
        self.position = end;
        Ok(slice)
    }
}

fn encode_head(major: u8, argument: u64) -> Result<WipingBuffer, CborError> {
    let prefix = major << 5;
    let mut head = [0u8; 9];
    let length = if argument < 24 {
        head[0] = prefix | argument as u8;
        1
    } else if u8::try_from(argument).is_ok() {
        head[..2].copy_from_slice(&[prefix | 24, argument as u8]);
        2
    } else if u16::try_from(argument).is_ok() {
        head[0] = prefix | 25;
        head[1..3].copy_from_slice(&(argument as u16).to_be_bytes());
        3
    } else if u32::try_from(argument).is_ok() {
        head[0] = prefix | 26;
        head[1..5].copy_from_slice(&(argument as u32).to_be_bytes());
        5
    } else {
        head[0] = prefix | 27;
        head[1..].copy_from_slice(&argument.to_be_bytes());
        9
    };
    let output = WipingBuffer::from_slice(&head[..length]);
    zeroize::Zeroize::zeroize(&mut head);
    output
}

// Every replacement allocation wipes the old capacity before release. Ordinary
// Vec::reserve/realloc would release a prior plaintext copy without doing so.
#[derive(Default, Eq, PartialEq)]
struct WipingBuffer(Vec<u8>);
impl WipingBuffer {
    fn from_slice(bytes: &[u8]) -> Result<Self, CborError> {
        let mut value = Self::default();
        value.append(bytes)?;
        Ok(value)
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        let required = self
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or(CborError::ItemLimit)?;
        if required > self.0.capacity() {
            let mut replacement = Vec::new();
            replacement
                .try_reserve_exact(required.max(self.0.capacity().saturating_mul(2)))
                .map_err(|_| CborError::ItemLimit)?;
            replacement.extend_from_slice(&self.0);
            zeroize::Zeroize::zeroize(&mut self.0);
            self.0 = replacement;
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}
impl std::ops::Deref for WipingBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for WipingBuffer {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}
impl minicbor::encode::Write for WipingBuffer {
    type Error = CborError;
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.append(bytes)
    }
}
