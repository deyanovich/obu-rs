//! Encoding pipeline for obu schemes.

#![cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]

use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    error::Error,
    Encoding, Format, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

#[cfg(feature = "mock")]
use crate::encrypt_zmock1;
#[cfg(feature = "upcbc")]
use crate::encrypt_upcbc;
#[cfg(feature = "zdcbc")]
use crate::encrypt_zdcbc;

/// obu encoding pipeline — takes a 32-byte secret.
///
/// The obtext is the text encoding of the scheme's ciphertext output
/// and nothing more: no scheme marker is appended (OBU spec §2); the
/// scheme is fixed by `format` and supplied by the caller.
#[inline(always)]
pub(crate) fn enc_to_format_ztier(
    plaintext: &str,
    format: Format,
    secret: &[u8; 32],
) -> Result<String, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    #[allow(unreachable_patterns)] // `_` guard unreachable when all scheme features are on
    let ciphertext: Vec<u8> = match format.scheme() {
        #[cfg(feature = "upcbc")]
        Scheme::Upcbc => encrypt_upcbc(secret, plaintext.as_bytes())?,
        #[cfg(feature = "zdcbc")]
        Scheme::Zdcbc => encrypt_zdcbc(secret, plaintext.as_bytes())?,
        #[cfg(feature = "mock")]
        Scheme::Zmock1 => encrypt_zmock1(secret, plaintext.as_bytes())?,
        _ => return Err(Error::InvalidScheme),
    };

    Ok(match format.encoding() {
        Encoding::C32 => BASE32_CROCKFORD.encode(&ciphertext),
        Encoding::B32 => BASE32_RFC.encode(&ciphertext),
        Encoding::B64 => BASE64URL_NOPAD.encode(&ciphertext),
        Encoding::Hex => HEXLOWER.encode(&ciphertext),
    })
}
