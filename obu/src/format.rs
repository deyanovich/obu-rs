//! Format combines an obu scheme with a text encoding.

use crate::{constants, Encoding, Error, Scheme};

/// Format combines a scheme with an encoding (text representation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Format {
    scheme: Scheme,
    encoding: Encoding,
}

impl Format {
    /// Create a new format with the specified scheme and encoding.
    pub const fn new(scheme: Scheme, encoding: Encoding) -> Self {
        Self { scheme, encoding }
    }

    /// Get the scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Get the encoding.
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }
}

#[cfg(feature = "upcbc")]
pub(crate) mod upcbc_formats {
    use super::{Encoding, Format, Scheme};
    pub const UPCBC_C32: Format = Format::new(Scheme::Upcbc, Encoding::C32);
    pub const UPCBC_B32: Format = Format::new(Scheme::Upcbc, Encoding::B32);
    pub const UPCBC_B64: Format = Format::new(Scheme::Upcbc, Encoding::B64);
    pub const UPCBC_HEX: Format = Format::new(Scheme::Upcbc, Encoding::Hex);
}

#[cfg(feature = "zdcbc")]
pub(crate) mod zdcbc_formats {
    use super::{Encoding, Format, Scheme};
    pub const ZDCBC_C32: Format = Format::new(Scheme::Zdcbc, Encoding::C32);
    pub const ZDCBC_B32: Format = Format::new(Scheme::Zdcbc, Encoding::B32);
    pub const ZDCBC_B64: Format = Format::new(Scheme::Zdcbc, Encoding::B64);
    pub const ZDCBC_HEX: Format = Format::new(Scheme::Zdcbc, Encoding::Hex);
}

impl Format {
    /// Parse a compact format string (e.g. "upcbc.c32", "zdcbc.hex").
    #[allow(clippy::should_implement_trait)] // inherent + `FromStr` both provided intentionally
    pub fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            #[cfg(feature = "upcbc")]
            constants::UPCBC_C32_STR => upcbc_formats::UPCBC_C32,
            #[cfg(feature = "upcbc")]
            constants::UPCBC_B32_STR => upcbc_formats::UPCBC_B32,
            #[cfg(feature = "upcbc")]
            constants::UPCBC_B64_STR => upcbc_formats::UPCBC_B64,
            #[cfg(feature = "upcbc")]
            constants::UPCBC_HEX_STR => upcbc_formats::UPCBC_HEX,

            #[cfg(feature = "zdcbc")]
            constants::ZDCBC_C32_STR => zdcbc_formats::ZDCBC_C32,
            #[cfg(feature = "zdcbc")]
            constants::ZDCBC_B32_STR => zdcbc_formats::ZDCBC_B32,
            #[cfg(feature = "zdcbc")]
            constants::ZDCBC_B64_STR => zdcbc_formats::ZDCBC_B64,
            #[cfg(feature = "zdcbc")]
            constants::ZDCBC_HEX_STR => zdcbc_formats::ZDCBC_HEX,

            // The testing-only zmock1 formats are deliberately not
            // string-parseable, even with the `mock` feature on — a
            // no-encryption scheme must never be selectable from a
            // string. Build them by value with `Format::new(Scheme::Zmock1, …)`.
            _ => return Err(Error::InvalidFormat),
        })
    }
}

impl std::str::FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Format::from_str(s)
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.scheme.as_str(), self.encoding.as_str())
    }
}

/// Trait for types that can be converted into a Format.
///
/// This trait is sealed and only implemented for `&str`, `String`,
/// `&String`, `Format`, and `&Format`.
pub trait IntoFormat: private::Sealed {
    /// Convert into a Format, possibly returning an error.
    fn into_format(self) -> Result<Format, Error>;
}

impl IntoFormat for Format {
    fn into_format(self) -> Result<Format, Error> {
        Ok(self)
    }
}

impl IntoFormat for &Format {
    fn into_format(self) -> Result<Format, Error> {
        Ok(*self)
    }
}

impl IntoFormat for &str {
    fn into_format(self) -> Result<Format, Error> {
        Format::from_str(self)
    }
}

impl IntoFormat for String {
    fn into_format(self) -> Result<Format, Error> {
        Format::from_str(&self)
    }
}

impl IntoFormat for &String {
    fn into_format(self) -> Result<Format, Error> {
        Format::from_str(self)
    }
}

// Seal the trait to prevent external implementations.
mod private {
    pub trait Sealed {}
    impl Sealed for &str {}
    impl Sealed for String {}
    impl Sealed for &String {}
    impl Sealed for super::Format {}
    impl Sealed for &super::Format {}
}
