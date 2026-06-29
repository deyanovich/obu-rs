//! Decoding pipeline for obu schemes.

#![cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]

use crate::{error::Error, Format, Scheme};

#[cfg(feature = "mock")]
use crate::decrypt_zmock1;
#[cfg(feature = "upcbc")]
use crate::decrypt_upcbc;
#[cfg(feature = "zdcbc")]
use crate::decrypt_zdcbc;

/// obu decoding pipeline — takes a 32-byte secret.
///
/// Decodes the obtext to the scheme's ciphertext bytes and decrypts
/// directly; there is no scheme marker to strip (OBU spec §2). The
/// scheme is fixed by `format` and supplied by the caller.
#[inline(always)]
pub(crate) fn dec_from_format_ztier(
    obtext: &str,
    format: Format,
    secret: &[u8; 32],
) -> Result<String, Error> {
    let buffer = crate::dec::decode_obtext_to_payload(obtext, format.encoding())?;

    #[allow(unreachable_patterns)] // `_` guard unreachable when all scheme features are on
    let plaintext_bytes = match format.scheme() {
        #[cfg(feature = "upcbc")]
        Scheme::Upcbc => decrypt_upcbc(secret, &buffer)?,
        #[cfg(feature = "zdcbc")]
        Scheme::Zdcbc => decrypt_zdcbc(secret, &buffer)?,
        #[cfg(feature = "mock")]
        Scheme::Zmock1 => decrypt_zmock1(secret, &buffer)?,
        _ => return Err(Error::InvalidScheme),
    };

    // OBU §2.2: dec MUST reject anything that decrypts to empty. The CBC
    // schemes already enforce this inside their decrypt fns (upcbc via
    // the uniform DecryptionFailed); this backstops the identity scheme.
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPayload);
    }

    // The dec path always validates UTF-8 and never returns an
    // unchecked String.
    String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
}
