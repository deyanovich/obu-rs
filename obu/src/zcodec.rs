//! Fixed-format obu codec types (one scheme + encoding per type).

#![cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]

use super::zsecret::ZSecret;
#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_SECRET_BYTES;
use crate::{error::Error, Encoding, Format, ObtextCodec, Scheme};

/// Generate a fixed-format obu codec type. `$warning` is the security
/// caveat shown in the type's docs (upcbc is unauthenticated; zdcbc is
/// obfuscation only).
macro_rules! impl_zcodec {
    ($name:ident, $scheme:expr, $encoding:expr, $format_str:literal, $warning:literal) => {
        #[doc = concat!("Codec for `", $format_str, "`.\n\n")]
        #[doc = $warning]
        #[allow(non_camel_case_types)]
        pub struct $name {
            zsecret: ZSecret,
        }

        impl $name {
            /// Create from a 64-character hex secret string.
            pub fn new(secret: &str) -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_string(secret)?,
                })
            }

            /// Create with the hardcoded secret (testing only).
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_bytes(&HARDCODED_SECRET_BYTES)?,
                })
            }

            /// Create from a 64-character hex secret string.
            pub fn from_hex_secret(secret_hex: &str) -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_hex(secret_hex)?,
                })
            }

            /// Create from a 32-byte secret.
            pub fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_bytes(secret_bytes)?,
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

        impl ObtextCodec for $name {
            fn enc(&self, plaintext: &str) -> Result<String, Error> {
                let format = Format::new($scheme, $encoding);
                crate::enc_to_format_ztier(plaintext, format, self.zsecret.master_secret())
            }

            fn dec(&self, obtext: &str) -> Result<String, Error> {
                let format = Format::new($scheme, $encoding);
                crate::dec_from_format_ztier(obtext, format, self.zsecret.master_secret())
            }

            fn format(&self) -> Format {
                Format::new($scheme, $encoding)
            }

            fn scheme(&self) -> Scheme {
                $scheme
            }

            fn encoding(&self) -> Encoding {
                $encoding
            }
        }

        impl $name {
            /// Encrypt and encode plaintext.
            #[inline]
            pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::enc(self, plaintext)
            }

            /// Decode and decrypt obtext (no scheme autodetection).
            #[inline]
            pub fn dec(&self, obtext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::dec(self, obtext)
            }

            #[inline]
            pub fn format(&self) -> Format {
                <Self as ObtextCodec>::format(self)
            }

            #[inline]
            pub fn scheme(&self) -> Scheme {
                <Self as ObtextCodec>::scheme(self)
            }

            #[inline]
            pub fn encoding(&self) -> Encoding {
                <Self as ObtextCodec>::encoding(self)
            }
        }
    };
}

// upcbc — unauthenticated probabilistic AES-256-CBC (confidentiality only).
#[cfg(feature = "upcbc")]
impl_zcodec!(UpcbcC32, Scheme::Upcbc, Encoding::C32, "upcbc.c32", "⚠️ **Unauthenticated** — confidentiality only, no integrity. Never use where authentication is required.");
#[cfg(feature = "upcbc")]
impl_zcodec!(UpcbcB32, Scheme::Upcbc, Encoding::B32, "upcbc.b32", "⚠️ **Unauthenticated** — confidentiality only, no integrity. Never use where authentication is required.");
#[cfg(feature = "upcbc")]
impl_zcodec!(UpcbcB64, Scheme::Upcbc, Encoding::B64, "upcbc.b64", "⚠️ **Unauthenticated** — confidentiality only, no integrity. Never use where authentication is required.");
#[cfg(feature = "upcbc")]
impl_zcodec!(UpcbcHex, Scheme::Upcbc, Encoding::Hex, "upcbc.hex", "⚠️ **Unauthenticated** — confidentiality only, no integrity. Never use where authentication is required.");

// zdcbc — obfuscation-only deterministic AES-128-CBC.
#[cfg(feature = "zdcbc")]
impl_zcodec!(ZdcbcC32, Scheme::Zdcbc, Encoding::C32, "zdcbc.c32", "⚠️ **Obfuscation only — NOT cryptographically secure.** Never use to protect secrets.");
#[cfg(feature = "zdcbc")]
impl_zcodec!(ZdcbcB32, Scheme::Zdcbc, Encoding::B32, "zdcbc.b32", "⚠️ **Obfuscation only — NOT cryptographically secure.** Never use to protect secrets.");
#[cfg(feature = "zdcbc")]
impl_zcodec!(ZdcbcB64, Scheme::Zdcbc, Encoding::B64, "zdcbc.b64", "⚠️ **Obfuscation only — NOT cryptographically secure.** Never use to protect secrets.");
#[cfg(feature = "zdcbc")]
impl_zcodec!(ZdcbcHex, Scheme::Zdcbc, Encoding::Hex, "zdcbc.hex", "⚠️ **Obfuscation only — NOT cryptographically secure.** Never use to protect secrets.");

// zmock1 — identity (no encryption), testing only.
#[cfg(feature = "mock")]
impl_zcodec!(Zmock1C32, Scheme::Zmock1, Encoding::C32, "zmock1.c32", "Testing-only identity scheme (no encryption).");
#[cfg(feature = "mock")]
impl_zcodec!(Zmock1B32, Scheme::Zmock1, Encoding::B32, "zmock1.b32", "Testing-only identity scheme (no encryption).");
#[cfg(feature = "mock")]
impl_zcodec!(Zmock1B64, Scheme::Zmock1, Encoding::B64, "zmock1.b64", "Testing-only identity scheme (no encryption).");
#[cfg(feature = "mock")]
impl_zcodec!(Zmock1Hex, Scheme::Zmock1, Encoding::Hex, "zmock1.hex", "Testing-only identity scheme (no encryption).");
