#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserLimits {
    pub max_depth: usize,
    pub max_container_items: usize,
    pub max_total_items: usize,
    pub max_text_or_bytes: usize,
}

impl ParserLimits {
    pub const V1: Self = Self {
        max_depth: 16,
        max_container_items: 10_000,
        max_total_items: 10_000,
        max_text_or_bytes: 1_048_592,
    };

    pub(crate) const fn has_nonzero_security_budgets(self) -> bool {
        self.max_depth > 0 && self.max_container_items > 0 && self.max_total_items > 0
    }
}
