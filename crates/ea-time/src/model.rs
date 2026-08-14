use core::cmp::Ordering;

use ea_types::{ObjectHash, UnixMillis};

use crate::TimeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IndependentTimeKind {
    Receipt = 0,
    Checkpoint = 1,
    Tsa = 2,
}

impl IndependentTimeKind {
    const fn tag(self) -> u8 {
        self as u8
    }
}

/// Non-authoritative arithmetic input for a time proven elsewhere.
///
/// Production callers must obtain these values from verified evidence through
/// `ea-trust`; constructing one does not itself prove or grant authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IndependentTimeInput {
    kind: IndependentTimeKind,
    object_hash: ObjectHash,
    verified_time: UnixMillis,
}

impl IndependentTimeInput {
    #[must_use]
    pub const fn new(
        kind: IndependentTimeKind,
        object_hash: ObjectHash,
        verified_time: UnixMillis,
    ) -> Self {
        Self {
            kind,
            object_hash,
            verified_time,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IndependentTimeReference {
    kind: IndependentTimeKind,
    object_hash: ObjectHash,
    verified_time: UnixMillis,
}

impl IndependentTimeReference {
    pub(crate) const fn from_input(input: IndependentTimeInput) -> Self {
        Self {
            kind: input.kind,
            object_hash: input.object_hash,
            verified_time: input.verified_time,
        }
    }

    pub(crate) fn is_preferred_to(&self, other: &Self) -> bool {
        match self.verified_time.cmp(&other.verified_time) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => match self.kind.tag().cmp(&other.kind.tag()) {
                Ordering::Less => true,
                Ordering::Greater => false,
                Ordering::Equal => self.object_hash < other.object_hash,
            },
        }
    }

    #[must_use]
    pub const fn kind(&self) -> IndependentTimeKind {
        self.kind
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    #[must_use]
    pub const fn verified_time(&self) -> UnixMillis {
        self.verified_time
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TrustedTimeState {
    floor: UnixMillis,
    independent_reference: Option<IndependentTimeReference>,
}

impl TrustedTimeState {
    #[must_use]
    pub const fn initial(floor: UnixMillis) -> Self {
        Self {
            floor,
            independent_reference: None,
        }
    }

    pub fn from_persisted(
        floor: UnixMillis,
        independent_reference: Option<IndependentTimeInput>,
    ) -> Result<Self, TimeError> {
        let state = Self {
            floor,
            independent_reference: independent_reference.map(IndependentTimeReference::from_input),
        };
        state.validate()?;
        Ok(state)
    }

    pub(crate) const fn from_parts(
        floor: UnixMillis,
        independent_reference: Option<IndependentTimeReference>,
    ) -> Self {
        Self {
            floor,
            independent_reference,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), TimeError> {
        if self
            .independent_reference
            .is_some_and(|reference| reference.verified_time > self.floor)
        {
            return Err(TimeError::StateMonotonicity);
        }
        Ok(())
    }

    #[must_use]
    pub const fn floor(&self) -> UnixMillis {
        self.floor
    }

    #[must_use]
    pub const fn independent_reference(&self) -> Option<&IndependentTimeReference> {
        self.independent_reference.as_ref()
    }
}

pub struct TimeAdvance {
    state: TrustedTimeState,
    changed: bool,
}

impl TimeAdvance {
    pub(crate) const fn new(state: TrustedTimeState, changed: bool) -> Self {
        Self { state, changed }
    }

    #[must_use]
    pub const fn state(&self) -> &TrustedTimeState {
        &self.state
    }

    #[must_use]
    pub const fn changed(&self) -> bool {
        self.changed
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TimeWarnings {
    clock_rollback: bool,
    independent_time_unavailable: bool,
}

impl TimeWarnings {
    pub(crate) const fn new(clock_rollback: bool, independent_time_unavailable: bool) -> Self {
        Self {
            clock_rollback,
            independent_time_unavailable,
        }
    }

    #[must_use]
    pub const fn clock_rollback(&self) -> bool {
        self.clock_rollback
    }

    #[must_use]
    pub const fn independent_time_unavailable(&self) -> bool {
        self.independent_time_unavailable
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutureSkew {
    WithinLimit,
    UnprovableWithoutIndependentReference,
    Blocked,
}

pub struct TimeEvaluation {
    raw_now: UnixMillis,
    warnings: TimeWarnings,
    future_skew: FutureSkew,
}

impl TimeEvaluation {
    pub(crate) const fn new(
        raw_now: UnixMillis,
        warnings: TimeWarnings,
        future_skew: FutureSkew,
    ) -> Self {
        Self {
            raw_now,
            warnings,
            future_skew,
        }
    }

    #[must_use]
    pub const fn raw_now(&self) -> UnixMillis {
        self.raw_now
    }

    #[must_use]
    pub const fn warnings(&self) -> &TimeWarnings {
        &self.warnings
    }

    #[must_use]
    pub const fn future_skew(&self) -> FutureSkew {
        self.future_skew
    }
}
