//! Omnibu — multi-format obu codec (format supplied per call).
//!
//! ⚠️ **WARNING**: obu schemes are unauthenticated. `upcbc` is
//! confidentiality-only; `zdcbc` is obfuscation only and not
//! cryptographically secure. Never use to protect secrets.

#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_SECRET_BYTES;
use crate::{format::IntoFormat, Error};

use super::zsecret::ZSecret;

/// An obu codec that takes the format (scheme + encoding) on every
/// `enc`/`dec` call, rather than storing one.
///
/// This is the obu equivalent of oboron's `Omnib`, working with a
/// 32-byte secret. The scheme is always supplied by the caller — obu
/// does not autodetect (OBU spec §2).
///
/// **WARNING**: obu schemes are unauthenticated; `zdcbc` is obfuscation
/// only. Never use to protect secrets.
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), obu::Error> {
/// # #[cfg(all(feature = "upcbc", feature = "zdcbc"))]
/// # {
/// # use obu::Omnibu;
/// let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"; // 64 hex chars
/// let omz = Omnibu::new(secret)?;
///
/// let ot1 = omz.enc("hello", "zdcbc.c32")?;
/// let ot2 = omz.enc("world", "upcbc.b64")?;
///
/// assert_eq!(omz.dec(&ot1, "zdcbc.c32")?, "hello");
/// assert_eq!(omz.dec(&ot2, "upcbc.b64")?, "world");
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Omnibu {
    zsecret: ZSecret,
}

impl Omnibu {
    /// Create a new Omnibu from a 64-character hex secret.
    pub fn new(secret: &str) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_string(secret)?,
        })
    }

    /// Create a new Omnibu with the hardcoded secret (testing only).
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_bytes(&HARDCODED_SECRET_BYTES)?,
        })
    }

    /// Encrypt and encode plaintext with the specified format
    /// (format string or `Format`).
    #[inline]
    pub fn enc(&self, plaintext: &str, format: impl IntoFormat) -> Result<String, Error> {
        let format = format.into_format()?;
        crate::enc_to_format_ztier(plaintext, format, self.zsecret.master_secret())
    }

    /// Decode and decrypt obtext with the specified format
    /// (format string or `Format`). The scheme is supplied by the
    /// caller — there is no autodetection.
    #[inline]
    pub fn dec(&self, obtext: &str, format: impl IntoFormat) -> Result<String, Error> {
        let format = format.into_format()?;
        crate::dec_from_format_ztier(obtext, format, self.zsecret.master_secret())
    }

    /// Create a new Omnibu from a 64-character hex secret string.
    pub fn from_hex_secret(secret_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_hex(secret_hex)?,
        })
    }

    /// Create a new Omnibu from raw secret bytes (32 bytes).
    pub fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_bytes(secret_bytes)?,
        })
    }

    /// The 64-character hex secret bound to this Omnibu.
    pub fn secret(&self) -> String {
        self.zsecret.secret_hex()
    }

    /// The secret as a 64-character hex string (alias for `secret`).
    pub fn secret_hex(&self) -> String {
        self.zsecret.secret_hex()
    }

    /// The raw 32-byte secret material.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.zsecret.secret_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "zdcbc")]
    fn test_omnibu_basic() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"; // 64 hex chars
        let omz = Omnibu::new(secret).unwrap();

        let plaintext = "hello world";
        let ot = omz.enc(plaintext, "zdcbc.b64").unwrap();
        let pt2 = omz.dec(&ot, "zdcbc.b64").unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(all(feature = "upcbc", feature = "zdcbc"))]
    fn test_omnibu_multiple_formats() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let omz = Omnibu::new(secret).unwrap();

        let plaintext = "multi format test";
        let ot1 = omz.enc(plaintext, "zdcbc.b64").unwrap();
        let ot2 = omz.enc(plaintext, "upcbc.c32").unwrap();

        assert_eq!(omz.dec(&ot1, "zdcbc.b64").unwrap(), plaintext);
        assert_eq!(omz.dec(&ot2, "upcbc.c32").unwrap(), plaintext);
    }

    #[test]
    #[cfg(feature = "zdcbc")]
    fn test_omnibu_secret_methods() {
        let secret_hex = "0".repeat(64);
        let omz = Omnibu::new(&secret_hex).unwrap();

        let retrieved = omz.secret();
        assert_eq!(retrieved, secret_hex);
        assert_eq!(retrieved.len(), 64);
        assert_eq!(omz.secret_hex().len(), 64);
        assert_eq!(omz.secret_bytes().len(), 32);
    }

    #[test]
    #[cfg(feature = "zdcbc")]
    fn test_omnibu_from_hex_secret() {
        let secret_hex = "0".repeat(64);
        let omz = Omnibu::from_hex_secret(&secret_hex).unwrap();

        let plaintext = "hex secret test";
        let ot = omz.enc(plaintext, "zdcbc.b64").unwrap();
        assert_eq!(omz.dec(&ot, "zdcbc.b64").unwrap(), plaintext);
    }

    #[test]
    #[cfg(feature = "zdcbc")]
    fn test_omnibu_rejects_non_obu_scheme() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let omz = Omnibu::new(secret).unwrap();
        // Secure-tier scheme strings are not obu formats and don't parse.
        assert!(omz.enc("test", "dsiv.b64").is_err());
    }
}
