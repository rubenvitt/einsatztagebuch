pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    pub fn inspect<R>(&self, inspect: impl FnOnce(&T) -> R) -> R {
        inspect(&self.0)
    }
}
