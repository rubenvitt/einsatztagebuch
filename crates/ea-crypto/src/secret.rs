use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(test)]
std::thread_local! {
    static FIXED_DROP_OBSERVATION: std::cell::RefCell<Option<Vec<u8>>> = const {
        std::cell::RefCell::new(None)
    };
    static VARIABLE_DROP_OBSERVATION: std::cell::RefCell<Option<Vec<u8>>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Fixed-size secret ownership.
///
/// It deliberately has no formatting, cloning, comparison, serialization,
/// dereferencing, or generic byte-conversion implementations.
///
/// ```compile_fail
/// use ea_crypto::SecretBytes;
/// let secret = SecretBytes::<32>::new([7; 32]);
/// let _rendered = format!("{secret:?}");
/// ```
///
/// ```compile_fail
/// use ea_crypto::SecretBytes;
/// let secret = SecretBytes::<32>::new([7; 32]);
/// let _copy = secret.clone();
/// ```
#[derive(Zeroize)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        FIXED_DROP_OBSERVATION.with(|observation| {
            *observation.borrow_mut() = Some(self.0.to_vec());
        });
    }
}

impl<const N: usize> ZeroizeOnDrop for SecretBytes<N> {}

#[cfg(test)]
fn clear_fixed_drop_observation() {
    FIXED_DROP_OBSERVATION.with(|observation| *observation.borrow_mut() = None);
}

#[cfg(test)]
fn take_fixed_drop_observation() -> Option<Vec<u8>> {
    FIXED_DROP_OBSERVATION.with(|observation| observation.borrow_mut().take())
}

#[cfg(test)]
fn clear_variable_drop_observation() {
    VARIABLE_DROP_OBSERVATION.with(|observation| *observation.borrow_mut() = None);
}

#[cfg(test)]
fn take_variable_drop_observation() -> Option<Vec<u8>> {
    VARIABLE_DROP_OBSERVATION.with(|observation| observation.borrow_mut().take())
}

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

#[derive(Zeroize)]
pub struct SecretVec(Box<[u8]>);

impl Drop for SecretVec {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        VARIABLE_DROP_OBSERVATION.with(|observation| {
            *observation.borrow_mut() = Some(self.0.to_vec());
        });
    }
}

impl ZeroizeOnDrop for SecretVec {}

impl SecretVec {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
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
        self.0.as_ref() == expected
    }

    /// Runs `use_it` with the secret bytes, scoped to that call.
    ///
    /// This is the only way plaintext leaves the crate, and it exists because
    /// `einsatzarchiv decrypt --output` has to write it (`design.md` §16;
    /// Stage-1 plan task 10). The global constraint permits persistence exactly
    /// where "the user explicitly requests decrypted CLI output" — so the
    /// capability is required, and hiding it would only push callers into
    /// reimplementing AEAD and HPKE outside the crypto boundary.
    ///
    /// The borrow cannot outlive the call, so the bytes never become a buffer
    /// the caller owns by accident, and the zeroize-on-drop contract is
    /// untouched. Deliberate copying inside the callback is possible and is the
    /// point: the caller then owns that copy and its lifetime, which is a
    /// decision the caller must make consciously rather than inherit.
    ///
    /// The type still has no formatting, cloning, comparison, serialization,
    /// dereferencing, or generic byte-conversion implementations.
    pub fn with_exposed<R>(&self, use_it: impl FnOnce(&[u8]) -> R) -> R {
        use_it(self.0.as_ref())
    }

    pub(crate) fn expose(&self) -> &[u8] {
        self.0.as_ref()
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
        assert_eq!(variable.0.as_ref(), &[0; 64]);
    }

    #[test]
    fn fixed_secret_drop_observer_sees_only_zeroes() {
        clear_fixed_drop_observation();
        {
            let _secret = SecretBytes::new([0xa5; 32]);
        }
        assert_eq!(take_fixed_drop_observation(), Some(vec![0; 32]));
    }

    #[test]
    fn variable_secret_drop_observer_sees_only_zeroes() {
        clear_variable_drop_observation();
        {
            let _secret = SecretVec::new(b"VARIABLE-SECRET-DROP-CANARY".to_vec());
        }
        assert_eq!(take_variable_drop_observation(), Some(vec![0; 27]));
    }
}
