//! The `ObtextCodec` trait — the common string-in/string-out
//! interface implemented by every obu codec.

use crate::{Encoding, Error, Format, Scheme};

/// Common interface for all obu codecs (`Obu`, `UpcbcC32`, `ZdcbcC32`, …).
///
/// Mirrors the secure-tier `oboron::ObtextCodec` shape, but is a
/// distinct trait: obu is unauthenticated and shares no code with the
/// secure tier.
pub trait ObtextCodec {
    /// Encode a plaintext string.
    fn enc(&self, plaintext: &str) -> Result<String, Error>;

    /// Decode an encoded string back to plaintext.
    fn dec(&self, obtext: &str) -> Result<String, Error>;

    /// Get the full format (encapsulating scheme + encoding) used by this instance.
    fn format(&self) -> Format;

    /// Get the scheme identifier.
    fn scheme(&self) -> Scheme;

    /// Get the encoding used by this instance.
    fn encoding(&self) -> Encoding;
}
