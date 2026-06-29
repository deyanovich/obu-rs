//! BASE32 encodings used by the obu pipelines.
//!
//! Crockford's base32 (lowercased) for `c32`, and RFC 4648 base32 for
//! `b32`.
pub(crate) use data_encoding::BASE32_NOPAD as BASE32_RFC;
use data_encoding::{Encoding, Specification};
use once_cell::sync::Lazy;

pub(crate) static BASE32_CROCKFORD: Lazy<Encoding> = Lazy::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789abcdefghjkmnpqrstvwxyz"); // <- Crockford's base32!
    spec.padding = None;
    spec.encoding().unwrap()
});

/// Lowercase RFC 4648 base32 — used only by the deprecated `legacy`
/// codec.
#[cfg(feature = "legacy")]
pub(crate) static BASE32_RFC_LOWER: Lazy<Encoding> = Lazy::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567"); // RFC 4648 lowercase
    spec.padding = None;
    spec.encoding().unwrap()
});
