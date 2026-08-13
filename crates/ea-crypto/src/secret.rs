use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed-size secret ownership.
///
/// It deliberately has no formatting, cloning, comparison, serialization,
/// dereferencing, or generic byte-conversion implementations.
///
/// ```compile_fail
/// use ea_crypto::SecretBytes;
/// let secret = SecretBytes::<32>::new([7; 32]);
/// println!("{secret:?}");
/// ```
///
/// ```compile_fail
/// use ea_crypto::SecretBytes;
/// let secret = SecretBytes::<32>::new([7; 32]);
/// let _copy = secret.clone();
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    #[must_use]
    pub fn matches(&self, expected: &[u8; N]) -> bool {
        self.0 == *expected
    }

    pub(crate) const fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn matches(&self, expected: &[u8]) -> bool {
        self.0.as_slice() == expected
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_and_variable_secret_backing_is_observably_zeroized() {
        let mut fixed = SecretBytes::new([0x5a; 32]);
        fixed.zeroize();
        assert_eq!(fixed.0, [0; 32]);

        let mut variable = SecretVec::new(vec![0xa5; 64]);
        variable.zeroize();
        assert!(variable.0.is_empty());
    }
}
