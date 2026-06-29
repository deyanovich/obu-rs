//! Shared obtext-decoding primitive (text encoding → raw bytes).

use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    error::Error,
    Encoding,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

/// Decode text encoding to raw bytes.
#[inline]
pub(crate) fn decode_obtext_to_payload(obtext: &str, encoding: Encoding) -> Result<Vec<u8>, Error> {
    match encoding {
        Encoding::B32 => BASE32_RFC
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidB32),
        Encoding::C32 => BASE32_CROCKFORD
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidC32),
        Encoding::B64 => BASE64URL_NOPAD
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidB64),
        Encoding::Hex => HEXLOWER
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidHex),
    }
}
