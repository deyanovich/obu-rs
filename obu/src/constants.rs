//! Constants for the obu schemes: hardcoded secret, format-string
//! identifiers, and AES-CBC parameters.
//!
//! obu obtext carries no scheme marker — as in the oboron core, the
//! scheme is supplied by the caller and is not encoded in the obtext
//! (OBU spec §2).

// Hardcoded 32-byte secret for keyless constructors (testing /
// obfuscation only — NOT secure). This is the secret used by the
// canonical obu test vectors.
#[cfg(feature = "keyless")]
#[doc(hidden)]
pub const HARDCODED_SECRET_BYTES: [u8; 32] = [
    0x38, 0x12, 0x84, 0x63, 0x3d, 0x02, 0xea, 0x5f, 0x35, 0xdf, 0x85, 0x96, 0xb5, 0xcc, 0x42, 0x18,
    0x31, 0x00, 0x60, 0x46, 0x8e, 0x8b, 0x46, 0x54, 0x55, 0xa4, 0x15, 0x17, 0x4e, 0xa6, 0xe9, 0x66,
];

// Format identifiers
// ------------------
#[cfg(feature = "upcbc")]
pub(crate) const UPCBC_C32_STR: &str = "upcbc.c32";
#[cfg(feature = "upcbc")]
pub(crate) const UPCBC_B32_STR: &str = "upcbc.b32";
#[cfg(feature = "upcbc")]
pub(crate) const UPCBC_B64_STR: &str = "upcbc.b64";
#[cfg(feature = "upcbc")]
pub(crate) const UPCBC_HEX_STR: &str = "upcbc.hex";

#[cfg(feature = "zdcbc")]
pub(crate) const ZDCBC_C32_STR: &str = "zdcbc.c32";
#[cfg(feature = "zdcbc")]
pub(crate) const ZDCBC_B32_STR: &str = "zdcbc.b32";
#[cfg(feature = "zdcbc")]
pub(crate) const ZDCBC_B64_STR: &str = "zdcbc.b64";
#[cfg(feature = "zdcbc")]
pub(crate) const ZDCBC_HEX_STR: &str = "zdcbc.hex";

// AES-CBC parameters
// ------------------
#[cfg(any(feature = "upcbc", feature = "zdcbc"))]
pub(crate) const CBC_PADDING_BYTE: u8 = 0x01;
#[cfg(any(feature = "upcbc", feature = "zdcbc", feature = "legacy"))]
pub(crate) const AES_BLOCK_SIZE: usize = 16;
