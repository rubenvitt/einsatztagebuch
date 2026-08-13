pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T> Redacted<T> {
    #[must_use]
    pub fn matches<U: ?Sized>(&self, candidate: &U) -> bool
    where
        T: PartialEq<U>,
    {
        self.0.eq(candidate)
    }
}
