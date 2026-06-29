//! Errors for obu (unauthenticated / obfuscation) operations.
//!
//! obu deliberately carries its own error taxonomy rather than
//! sharing oboron's: the obu layer is unauthenticated and shares no
//! code with the secure tier.

use thiserror::Error;

/// All errors that can occur in obu operations.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    // Secret errors
    // -------------
    #[error("secret must be 32 bytes (64 hex characters)")]
    InvalidKeyLength,

    // Encoding errors
    // ---------------
    #[error("invalid hex encoding")]
    InvalidHex,
    #[error("invalid base64 encoding")]
    InvalidB64,
    #[error("invalid base32rfc encoding")]
    InvalidB32,
    #[error("invalid base32crockford encoding")]
    InvalidC32,
    #[error("invalid UTF-8")]
    InvalidUtf8,

    // Format/scheme errors
    // --------------------
    #[error("invalid format string")]
    InvalidFormat,
    #[error("invalid scheme")]
    InvalidScheme,
    #[error("unknown scheme")]
    UnknownScheme,
    #[error("unknown encoding")]
    UnknownEncoding,

    // Encryption errors
    // -----------------
    #[error("enc failed")]
    EncryptionFailed,
    #[error("enc failed: empty plaintext")]
    EmptyPlaintext,
    #[error("enc failed: plaintext must not end with the 0x01 padding byte")]
    PlaintextEndsWithPadByte,
    #[error("dec failed: empty payload")]
    EmptyPayload,
    #[error("dec failed: payload too short")]
    PayloadTooShort,

    // Decryption errors
    // -----------------
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid block length")]
    InvalidBlockLength,
}

impl From<hex::FromHexError> for Error {
    fn from(_: hex::FromHexError) -> Self {
        Error::InvalidHex
    }
}
