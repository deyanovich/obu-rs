//! Text encoding identifiers for obu output.

use crate::error::Error;

/// Encoding identifier for text representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    B32,
    C32,
    B64,
    Hex,
}

impl Encoding {
    /// Convert encoding to string representation.
    pub fn as_long_str(&self) -> &'static str {
        match self {
            Encoding::C32 => "base32crockford",
            Encoding::B32 => "base32rfc",
            Encoding::B64 => "base64",
            Encoding::Hex => "hex",
        }
    }

    /// Convert encoding to abbreviated string representation (for format strings).
    pub fn as_str(&self) -> &'static str {
        match self {
            Encoding::C32 => "c32",
            Encoding::B32 => "b32",
            Encoding::B64 => "b64",
            Encoding::Hex => "hex",
        }
    }

    /// Parse encoding from string.
    #[allow(clippy::should_implement_trait)] // inherent + `FromStr` both provided intentionally
    pub fn from_str(s: &str) -> Result<Self, Error> {
        s.parse()
    }
}

impl std::str::FromStr for Encoding {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "b32" => Ok(Encoding::B32),
            "c32" => Ok(Encoding::C32),
            "b64" => Ok(Encoding::B64),
            "hex" => Ok(Encoding::Hex),
            // Long names
            "base32crockford" => Ok(Encoding::C32),
            "base32rfc" => Ok(Encoding::B32),
            "base64" => Ok(Encoding::B64),
            _ => Err(Error::UnknownEncoding),
        }
    }
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
