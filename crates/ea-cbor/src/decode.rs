use core::cmp::Ordering;

use unicode_normalization::UnicodeNormalization;

use crate::{CborError, ParserLimits};

pub struct BoundedDecoder<'a> {
    input: &'a [u8],
    limits: ParserLimits,
    position: usize,
}

impl<'a> BoundedDecoder<'a> {
    #[must_use]
    pub const fn new(input: &'a [u8], limits: ParserLimits) -> Self {
        Self {
            input,
            limits,
            position: 0,
        }
    }

    pub fn validate_one(&mut self) -> Result<(), CborError> {
        let start = self.position;
        let remaining = self.input.get(start..).ok_or(CborError::Invalid)?;
        let mut scanner = Scanner::new(remaining, self.limits, true);
        scanner.scan_item(0)?;
        let consumed = scanner.position;
        let end = start.checked_add(consumed).ok_or(CborError::ItemLimit)?;
        let exact = self.input.get(start..end).ok_or(CborError::Invalid)?;
        let canonical = crate::encode::canonical_reencode(exact, self.limits)?;
        if canonical != exact {
            return Err(CborError::Invalid);
        }
        self.position += consumed;
        Ok(())
    }

    #[must_use]
    pub fn is_eof(&self) -> bool {
        self.position == self.input.len()
    }
}

pub fn validate(input: &[u8], limits: ParserLimits) -> Result<(), CborError> {
    let mut decoder = BoundedDecoder::new(input, limits);
    decoder.validate_one()?;
    if !decoder.is_eof() {
        return Err(CborError::TrailingBytes);
    }
    Ok(())
}

pub(crate) fn scan_relaxed(input: &[u8], limits: ParserLimits) -> Result<(), CborError> {
    let mut scanner = Scanner::new(input, limits, false);
    scanner.scan_item(0)?;
    if scanner.position != input.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(())
}

struct Scanner<'a> {
    input: &'a [u8],
    limits: ParserLimits,
    position: usize,
    total_items: usize,
    enforce_map_order: bool,
}

impl<'a> Scanner<'a> {
    const fn new(input: &'a [u8], limits: ParserLimits, enforce_map_order: bool) -> Self {
        Self {
            input,
            limits,
            position: 0,
            total_items: 0,
            enforce_map_order,
        }
    }

    fn scan_item(&mut self, container_depth: usize) -> Result<(), CborError> {
        if !self.limits.has_nonzero_security_budgets() {
            return Err(CborError::Invalid);
        }
        self.total_items = self
            .total_items
            .checked_add(1)
            .ok_or(CborError::TokenLimit)?;
        if self.total_items > self.limits.max_total_items {
            return Err(CborError::TokenLimit);
        }

        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 | 1 => {
                self.read_argument(additional)?;
            }
            2 | 3 => {
                let length = self.read_length(additional)?;
                if length > self.limits.max_text_or_bytes {
                    return Err(CborError::ItemLimit);
                }
                let payload = self.read_slice(length)?;
                if major == 3 {
                    let text = core::str::from_utf8(payload).map_err(|_| CborError::InvalidUtf8)?;
                    if !text.nfc().eq(text.chars()) {
                        return Err(CborError::NonNfc);
                    }
                }
            }
            4 => {
                let length = self.read_container_length(additional)?;
                self.check_container_depth(container_depth)?;
                for _ in 0..length {
                    self.scan_item(container_depth + 1)?;
                }
            }
            5 => {
                let length = self.read_container_length(additional)?;
                self.check_container_depth(container_depth)?;
                let mut previous_key: Option<(usize, usize)> = None;
                for _ in 0..length {
                    let key_start = self.position;
                    self.scan_item(container_depth + 1)?;
                    let key_end = self.position;
                    if self.enforce_map_order {
                        if let Some((previous_start, previous_end)) = previous_key {
                            match deterministic_key_cmp(
                                &self.input[previous_start..previous_end],
                                &self.input[key_start..key_end],
                            ) {
                                Ordering::Equal => return Err(CborError::DuplicateKey),
                                Ordering::Greater => return Err(CborError::MapOrder),
                                Ordering::Less => {}
                            }
                        }
                        previous_key = Some((key_start, key_end));
                    }
                    self.scan_item(container_depth + 1)?;
                }
            }
            6 => {
                self.read_argument(additional)?;
                self.check_container_depth(container_depth)?;
                self.scan_item(container_depth + 1)?;
            }
            7 => self.scan_simple(additional)?,
            _ => return Err(CborError::Invalid),
        }
        Ok(())
    }

    fn scan_simple(&mut self, additional: u8) -> Result<(), CborError> {
        match additional {
            0..=23 => Ok(()),
            24 => {
                let value = self.read_byte()?;
                match value {
                    0..=23 => return Err(CborError::NonMinimal),
                    24..=31 => return Err(CborError::Invalid),
                    _ => {}
                }
                Ok(())
            }
            25..=27 => Err(CborError::Float),
            31 => Err(CborError::Indefinite),
            _ => Err(CborError::Invalid),
        }
    }

    fn check_container_depth(&self, container_depth: usize) -> Result<(), CborError> {
        if container_depth >= self.limits.max_depth {
            return Err(CborError::DepthLimit);
        }
        Ok(())
    }

    fn read_container_length(&mut self, additional: u8) -> Result<usize, CborError> {
        let length = self.read_length(additional)?;
        if length > self.limits.max_container_items {
            return Err(CborError::ContainerLimit);
        }
        Ok(length)
    }

    fn read_length(&mut self, additional: u8) -> Result<usize, CborError> {
        let value = self.read_argument(additional)?;
        usize::try_from(value).map_err(|_| CborError::ItemLimit)
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, CborError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.read_byte()?);
                if value < 24 {
                    return Err(CborError::NonMinimal);
                }
                Ok(value)
            }
            25 => {
                let value = self.read_uint(2)?;
                if value <= u64::from(u8::MAX) {
                    return Err(CborError::NonMinimal);
                }
                Ok(value)
            }
            26 => {
                let value = self.read_uint(4)?;
                if value <= u64::from(u16::MAX) {
                    return Err(CborError::NonMinimal);
                }
                Ok(value)
            }
            27 => {
                let value = self.read_uint(8)?;
                if value <= u64::from(u32::MAX) {
                    return Err(CborError::NonMinimal);
                }
                Ok(value)
            }
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

pub(crate) fn deterministic_key_cmp(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}
