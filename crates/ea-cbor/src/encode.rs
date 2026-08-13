use crate::{CborError, ParserLimits, decode::deterministic_key_cmp};

pub fn to_deterministic_vec<T>(value: &T) -> Result<Vec<u8>, CborError>
where
    T: minicbor::Encode<()>,
{
    let upstream = minicbor::to_vec(value).map_err(|_| CborError::Encode)?;
    canonical_reencode(&upstream, ParserLimits::V1)
}

pub fn canonical_reencode(input: &[u8], limits: ParserLimits) -> Result<Vec<u8>, CborError> {
    crate::decode::scan_relaxed(input, limits)?;
    let mut encoder = CanonicalEncoder::new(input);
    let result = encoder.encode_item()?;
    if encoder.position != input.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(result)
}

struct CanonicalEncoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> CanonicalEncoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn encode_item(&mut self) -> Result<Vec<u8>, CborError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 | 1 => {
                let argument = self.read_argument(additional)?;
                Ok(encode_head(major, argument))
            }
            2 | 3 => {
                let length = self.read_argument(additional)?;
                let usize_length = usize::try_from(length).map_err(|_| CborError::ItemLimit)?;
                let payload = self.read_slice(usize_length)?;
                let mut output = encode_head(major, length);
                output.extend_from_slice(payload);
                Ok(output)
            }
            4 => {
                let length = self.read_argument(additional)?;
                let mut output = encode_head(major, length);
                for _ in 0..length {
                    output.extend(self.encode_item()?);
                }
                Ok(output)
            }
            5 => {
                let length = self.read_argument(additional)?;
                let capacity = usize::try_from(length).map_err(|_| CborError::ContainerLimit)?;
                let mut entries = Vec::with_capacity(capacity);
                for _ in 0..length {
                    entries.push((self.encode_item()?, self.encode_item()?));
                }
                entries.sort_by(|left, right| deterministic_key_cmp(&left.0, &right.0));
                if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                    return Err(CborError::DuplicateKey);
                }
                let mut output = encode_head(major, length);
                for (key, value) in entries {
                    output.extend(key);
                    output.extend(value);
                }
                Ok(output)
            }
            6 => {
                let tag = self.read_argument(additional)?;
                let mut output = encode_head(major, tag);
                output.extend(self.encode_item()?);
                Ok(output)
            }
            7 => match additional {
                0..=23 => Ok(vec![initial]),
                24 => Ok(vec![initial, self.read_byte()?]),
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

fn encode_head(major: u8, argument: u64) -> Vec<u8> {
    let prefix = major << 5;
    if argument < 24 {
        vec![prefix | argument as u8]
    } else if u8::try_from(argument).is_ok() {
        vec![prefix | 24, argument as u8]
    } else if u16::try_from(argument).is_ok() {
        let mut output = vec![prefix | 25];
        output.extend_from_slice(&(argument as u16).to_be_bytes());
        output
    } else if u32::try_from(argument).is_ok() {
        let mut output = vec![prefix | 26];
        output.extend_from_slice(&(argument as u32).to_be_bytes());
        output
    } else {
        let mut output = vec![prefix | 27];
        output.extend_from_slice(&argument.to_be_bytes());
        output
    }
}
