//! Owned schema text is wiped even when a later decoder field fails. Borrowed
//! caller input and copies deliberately returned to callers remain theirs.
use std::ops::Deref;
use zeroize::Zeroize;
#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub struct SecretText(String);
impl From<String> for SecretText {
    fn from(value: String) -> Self {
        Self(value)
    }
}
impl From<&str> for SecretText {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}
impl Deref for SecretText {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}
impl SecretText {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl PartialEq<&str> for SecretText {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}
impl Zeroize for SecretText {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for SecretText {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretText(<redacted>)")
    }
}
