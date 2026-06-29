//! Obu — runtime-format obu codec.
//!
//! ⚠️ **WARNING**: obu schemes are unauthenticated. `upcbc` is
//! confidentiality-only; `zdcbc` is obfuscation only and not
//! cryptographically secure. Never use to protect secrets.

#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_SECRET_BYTES;
use crate::{format::IntoFormat, Encoding, Error, Format, ObtextCodec, Scheme};

use super::zsecret::ZSecret;

/// A flexible obu codec with runtime format selection.
///
/// `Obu` is the obu equivalent of oboron's `Ob`: it stores a format
/// (scheme + encoding) that can be changed at runtime. The scheme is
/// always explicit — there is no autodetection.
///
/// **WARNING**: obu schemes are unauthenticated; `zdcbc` is obfuscation
/// only. Never use to protect secrets.
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), obu::Error> {
/// # #[cfg(feature = "zdcbc")]
/// # {
/// # use obu::Obu;
/// # let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"; // 64 hex chars
/// let obu = Obu::new("zdcbc.b64", secret)?;
/// let ot = obu.enc("hello")?;
/// let pt2 = obu.dec(&ot)?;
/// assert_eq!(pt2, "hello");
/// # }
/// # Ok(())
/// # }
/// ```
///
/// ## Dynamic format switching
///
/// ```rust
/// # fn main() -> Result<(), obu::Error> {
/// # #[cfg(all(feature = "upcbc", feature = "zdcbc"))]
/// # {
/// # use obu::Obu;
/// # use obu::{Scheme, Encoding};
/// # let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// let mut obu = Obu::new("zdcbc.c32", secret)?;
/// let _ot1 = obu.enc("hello")?;
///
/// obu.set_scheme(Scheme::Upcbc)?;     // now upcbc.c32
/// obu.set_encoding(Encoding::B64)?;   // now upcbc.b64
/// obu.set_format("zdcbc.hex")?;       // now zdcbc.hex
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Obu {
    zsecret: ZSecret,
    format: Format,
}

impl Obu {
    /// Create a new Obu with the specified format and a 64-character
    /// hex secret. The `format` argument accepts either a format string
    /// (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), obu::Error> {
    /// # #[cfg(feature = "zdcbc")]
    /// # {
    /// # use obu::Obu;
    /// # use obu::{Format, Scheme, Encoding};
    /// let secret = obu::generate_secret(); // 64-char hex
    /// let obu1 = Obu::new("zdcbc.b64", &secret)?;
    /// let obu2 = Obu::new(Format::new(Scheme::Zdcbc, Encoding::B64), &secret)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(format: impl IntoFormat, secret: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            zsecret: ZSecret::from_string(secret)?,
            format,
        })
    }

    /// Get the current format.
    pub fn format(&self) -> Format {
        self.format
    }

    /// Set the format to a new value (format string or `Format`).
    pub fn set_format(&mut self, format: impl IntoFormat) -> Result<(), Error> {
        self.format = format.into_format()?;
        Ok(())
    }

    /// Set the scheme while keeping the current encoding.
    pub fn set_scheme(&mut self, scheme: Scheme) -> Result<(), Error> {
        self.format = Format::new(scheme, self.format.encoding());
        Ok(())
    }

    /// Set the encoding while keeping the current scheme.
    pub fn set_encoding(&mut self, encoding: Encoding) -> Result<(), Error> {
        self.format = Format::new(self.format.scheme(), encoding);
        Ok(())
    }

    /// Create a new Obu with the hardcoded secret (testing only).
    #[cfg(feature = "keyless")]
    pub fn new_keyless(format: impl IntoFormat) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            zsecret: ZSecret::from_bytes(&HARDCODED_SECRET_BYTES)?,
            format,
        })
    }

    /// Create a new Obu from a 64-character hex secret string.
    pub fn from_hex_secret(format: impl IntoFormat, secret_hex: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            zsecret: ZSecret::from_hex(secret_hex)?,
            format,
        })
    }

    /// Create a new Obu from the specified format and raw secret bytes.
    pub fn from_bytes(format: impl IntoFormat, secret: &[u8; 32]) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            zsecret: ZSecret::from_bytes(secret)?,
            format,
        })
    }

    /// The 64-character hex secret bound to this codec.
    #[inline]
    pub fn secret(&self) -> String {
        self.zsecret.secret_hex()
    }

    /// The secret as a 64-character hex string (alias for `secret`).
    #[inline]
    pub fn secret_hex(&self) -> String {
        self.zsecret.secret_hex()
    }

    /// The raw 32-byte secret material.
    #[inline]
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.zsecret.secret_bytes()
    }
}

impl ObtextCodec for Obu {
    fn enc(&self, plaintext: &str) -> Result<String, Error> {
        crate::enc_to_format_ztier(plaintext, self.format, self.zsecret.master_secret())
    }

    fn dec(&self, obtext: &str) -> Result<String, Error> {
        crate::dec_from_format_ztier(obtext, self.format, self.zsecret.master_secret())
    }

    fn format(&self) -> Format {
        self.format
    }

    fn scheme(&self) -> Scheme {
        self.format.scheme()
    }

    fn encoding(&self) -> Encoding {
        self.format.encoding()
    }
}

// Inherent methods that delegate to the trait.
impl Obu {
    /// Encrypt and encode plaintext.
    #[inline]
    pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::enc(self, plaintext)
    }

    /// Decode and decrypt obtext (the scheme is the codec's current
    /// scheme — no autodetection).
    #[inline]
    pub fn dec(&self, obtext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::dec(self, obtext)
    }

    /// Get the scheme.
    #[inline]
    pub fn scheme(&self) -> Scheme {
        <Self as ObtextCodec>::scheme(self)
    }

    /// Get the encoding.
    #[inline]
    pub fn encoding(&self) -> Encoding {
        <Self as ObtextCodec>::encoding(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "zdcbc")]
    fn test_obu_basic() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"; // 64 hex chars
        let obu = Obu::new("zdcbc.b64", secret).unwrap();

        let plaintext = "hello world";
        let ot = obu.enc(plaintext).unwrap();
        let pt2 = obu.dec(&ot).unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(feature = "zdcbc")]
    fn test_obu_format_switching() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut obu = Obu::new("zdcbc.c32", secret).unwrap();

        assert_eq!(obu.encoding(), Encoding::C32);
        obu.set_encoding(Encoding::B64).unwrap();
        assert_eq!(obu.encoding(), Encoding::B64);
    }

    #[test]
    #[cfg(all(feature = "upcbc", feature = "zdcbc"))]
    fn test_obu_scheme_switching() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut obu = Obu::new("zdcbc.b64", secret).unwrap();

        assert_eq!(obu.scheme(), Scheme::Zdcbc);
        obu.set_scheme(Scheme::Upcbc).unwrap();
        assert_eq!(obu.scheme(), Scheme::Upcbc);
    }

    #[test]
    #[cfg(feature = "zdcbc")]
    fn test_obu_rejects_non_obu_scheme() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        // Secure-tier scheme strings are not obu formats and don't parse.
        assert!(Obu::new("dsiv.b64", secret).is_err());
    }
}
