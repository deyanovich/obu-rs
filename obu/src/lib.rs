//! # obu — unauthenticated / obfuscation codecs for the oboron family
//!
//! ⚠️ **WARNING**: obu schemes are **unauthenticated**. `upcbc`
//! provides confidentiality without integrity (vulnerable to
//! ciphertext tampering); `zdcbc` is obfuscation only and is *not*
//! cryptographically secure. **Never use obu to protect secrets** —
//! use the authenticated
//! [`oboron`](https://gitlab.com/oboron/oboron-rs) core for anything
//! security-critical.
//!
//! obu provides the same string-in/string-out, scheme + encoding
//! ergonomics as `oboron`, but operating on a 32-byte secret instead
//! of the authenticated tier's 64-byte key. It deliberately shares no
//! code with the secure tier.
//!
//! # Schemes
//!
//! - `Upcbc`: unauthenticated probabilistic AES-256-CBC — confidentiality
//!   only, random IV (each encryption differs).
//! - `Zdcbc`: obfuscation-only deterministic AES-128-CBC with a constant
//!   IV — NOT cryptographically secure, but stable/referenceable.
//!
//! Each scheme is available in four encodings — `c32` (Crockford
//! base32), `b32` (RFC 4648 base32), `b64` (base64url), and `hex` — as
//! fixed-format types (`UpcbcC32`, `ZdcbcHex`, …), via the
//! runtime-format [`Obu`], or via the multi-format [`Omnibu`].
//!
//! # Quick start
//!
//! ```rust
//! # fn main() -> Result<(), obu::Error> {
//! # #[cfg(feature = "zdcbc")]
//! # {
//! use obu::{ZdcbcC32, ObtextCodec};
//! let secret = obu::generate_secret();   // 64-char hex
//! let z = ZdcbcC32::new(&secret)?;
//! let ot = z.enc("not-a-secret")?;
//! let pt = z.dec(&ot)?;
//! assert_eq!(pt, "not-a-secret");
//! # }
//! # Ok(())
//! # }
//! ```

// obu needs at least one scheme to be useful: with none enabled the
// `Scheme` enum is empty and the crate cannot encode or decode.
#[cfg(not(any(feature = "upcbc", feature = "zdcbc", feature = "mock")))]
compile_error!(
    "obu requires at least one base scheme: enable `upcbc`, `zdcbc`, and/or `mock`. \
     (The deprecated `legacy` codec rides on the z-tier foundation and is not a \
     scheme on its own — enable it alongside a base scheme.)"
);

// Foundation modules (obu's own encoding/scheme/format/error layer —
// intentionally independent of the secure tier).
mod base32;
mod codec;
mod constants;
mod dec;
mod encoding;
mod error;
mod format;
mod keygen;
mod scheme;

// Scheme pipelines and codecs.
#[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]
mod obu;
#[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]
mod omnibu;
#[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]
mod zdec;
#[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]
mod zenc;
#[cfg(any(
    feature = "upcbc",
    feature = "zdcbc",
    feature = "mock",
    feature = "legacy"
))]
mod zsecret;

#[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]
mod zcodec;

#[cfg(feature = "mock")]
mod zmock1;
#[cfg(feature = "upcbc")]
mod upcbc;
#[cfg(feature = "zdcbc")]
mod zdcbc;

// Deprecated standalone codec — isolated from the scheme machinery above.
#[cfg(feature = "legacy")]
mod legacy;

// Public foundation types.
pub use codec::ObtextCodec;
pub use encoding::Encoding;
pub use error::Error;
pub use format::{Format, IntoFormat};
pub use scheme::Scheme;

// Secret generation.
pub use keygen::generate_secret;
pub use keygen::generate_secret_bytes;

// Deprecated standalone `legacy` codec (compatibility only; isolated
// from the Scheme / Format / Omnibu machinery).
#[cfg(feature = "legacy")]
pub use legacy::Legacy;

// Internal cross-module wiring (scheme pipelines).
#[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]
pub(crate) use zdec::dec_from_format_ztier;
#[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]
pub(crate) use zenc::enc_to_format_ztier;

#[cfg(feature = "mock")]
pub(crate) use zmock1::{decrypt_zmock1, encrypt_zmock1};
#[cfg(feature = "upcbc")]
pub(crate) use upcbc::{decrypt_upcbc, encrypt_upcbc};
#[cfg(feature = "zdcbc")]
pub(crate) use zdcbc::{decrypt_zdcbc, encrypt_zdcbc};

// Public codecs.
#[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]
pub use obu::Obu;
#[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]
pub use omnibu::Omnibu;

#[cfg(feature = "mock")]
pub use zcodec::{Zmock1B32, Zmock1B64, Zmock1C32, Zmock1Hex};
#[cfg(feature = "upcbc")]
pub use zcodec::{UpcbcB32, UpcbcB64, UpcbcC32, UpcbcHex};
#[cfg(feature = "zdcbc")]
pub use zcodec::{ZdcbcB32, ZdcbcB64, ZdcbcC32, ZdcbcHex};

/// Convenience prelude for common imports.
///
/// ```rust
/// use obu::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{Encoding, Error, Format, ObtextCodec, Scheme};
    #[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "mock"))]
    pub use crate::{Obu, Omnibu};
    #[cfg(feature = "upcbc")]
    pub use crate::{UpcbcB32, UpcbcB64, UpcbcC32, UpcbcHex};
    #[cfg(feature = "zdcbc")]
    pub use crate::{ZdcbcB32, ZdcbcB64, ZdcbcC32, ZdcbcHex};
}
