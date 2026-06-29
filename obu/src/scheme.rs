//! Scheme identifiers for the obu (unauthenticated / obfuscation) schemes.

use crate::error::Error;

/// Scheme identifier for obu schemes.
///
/// **WARNING**: obu schemes are unauthenticated. `upcbc` provides
/// confidentiality without integrity protection; `zdcbc` is obfuscation
/// only and is *not* cryptographically secure. Never use obu to protect
/// secrets — use the authenticated oboron core for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Unauthenticated probabilistic AES-256-CBC (confidentiality only,
    /// no integrity — vulnerable to ciphertext tampering).
    #[cfg(feature = "upcbc")]
    Upcbc,
    /// Obfuscation-only deterministic AES-128-CBC with a constant IV.
    /// **NOT** cryptographically secure.
    #[cfg(feature = "zdcbc")]
    Zdcbc,
    /// Identity scheme (no encryption, testing only).
    #[cfg(feature = "mock")]
    Zmock1,
}

impl Scheme {
    /// Convert scheme to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            #[cfg(feature = "upcbc")]
            Scheme::Upcbc => "upcbc",
            #[cfg(feature = "zdcbc")]
            Scheme::Zdcbc => "zdcbc",
            #[cfg(feature = "mock")]
            Scheme::Zmock1 => "zmock1",
        }
    }

    /// Parse scheme from string.
    #[allow(clippy::should_implement_trait)] // inherent + `FromStr` both provided intentionally
    pub fn from_str(s: &str) -> Result<Self, Error> {
        s.parse()
    }

    /// Whether this scheme is deterministic (same plaintext always
    /// produces the same obtext). `upcbc` is probabilistic (random IV);
    /// `zdcbc` and `zmock1` are deterministic.
    pub fn is_deterministic(&self) -> bool {
        match self {
            #[cfg(feature = "upcbc")]
            Scheme::Upcbc => false,
            #[cfg(feature = "zdcbc")]
            Scheme::Zdcbc => true,
            #[cfg(feature = "mock")]
            Scheme::Zmock1 => true,
        }
    }

    /// Whether this scheme is probabilistic (different output each time).
    pub fn is_probabilistic(&self) -> bool {
        !self.is_deterministic()
    }
}

impl std::str::FromStr for Scheme {
    type Err = Error;

    /// Parse a scheme from its identifier.
    ///
    /// Only the two spec schemes (`upcbc`, `zdcbc`) are parseable. The
    /// testing-only `zmock1` identity scheme is deliberately *not*
    /// selectable from a string, even when the `mock` feature is
    /// enabled: a no-encryption scheme must never be reachable through a
    /// string/config channel. Construct it explicitly via the
    /// `Scheme::Zmock1` variant when needed in tests.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "upcbc")]
            "upcbc" => Ok(Scheme::Upcbc),
            #[cfg(feature = "zdcbc")]
            "zdcbc" => Ok(Scheme::Zdcbc),
            _ => Err(Error::UnknownScheme),
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
