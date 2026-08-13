use core::fmt;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Id16([u8; 16]);

impl Id16 {
    pub const ZERO: Self = Self([0; 16]);

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Id16 {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value
            .try_into()
            .map(Self)
            .map_err(|_| LengthError::new(16, value.len()))
    }
}

macro_rules! id_newtype {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(Id16);

        impl $name {
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl From<Id16> for $name {
            fn from(value: Id16) -> Self {
                Self(value)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = LengthError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                Id16::try_from(value).map(Self)
            }
        }
    };
}

id_newtype!(OrganizationId);
id_newtype!(ChainId);
id_newtype!(DeviceId);
id_newtype!(EventId);
id_newtype!(AuthorizationId);
id_newtype!(DestructionId);
id_newtype!(RecordId);
id_newtype!(SubjectId);
id_newtype!(OperatorSubjectId);

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Hash32([u8; 32]);

impl Hash32 {
    pub const ZERO: Self = Self([0; 32]);

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Hash32 {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value
            .try_into()
            .map(Self)
            .map_err(|_| LengthError::new(32, value.len()))
    }
}

macro_rules! hash_newtype {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(Hash32);

        impl $name {
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl From<Hash32> for $name {
            fn from(value: Hash32) -> Self {
                Self(value)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = LengthError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                Hash32::try_from(value).map(Self)
            }
        }
    };
}

hash_newtype!(EntryHash);
hash_newtype!(ObjectHash);

macro_rules! integer_newtype {
    ($name:ident, $inner:ty) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name($inner);

        impl $name {
            #[must_use]
            pub const fn new(value: $inner) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn get(self) -> $inner {
                self.0
            }
        }
    };
}

integer_newtype!(FormatVersion, u16);
integer_newtype!(ObjectVersion, u16);
integer_newtype!(SchemaVersion, u16);
integer_newtype!(ChainSequence, u64);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LengthError {
    expected: usize,
    actual: usize,
}

impl LengthError {
    #[must_use]
    pub(crate) const fn new(expected: usize, actual: usize) -> Self {
        Self { expected, actual }
    }

    #[must_use]
    pub const fn expected(self) -> usize {
        self.expected
    }

    #[must_use]
    pub const fn actual(self) -> usize {
        self.actual
    }
}

impl fmt::Display for LengthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "EA-TYPE-INVALID-LENGTH expected={} actual={}",
            self.expected, self.actual
        )
    }
}

impl fmt::Debug for LengthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for LengthError {}
