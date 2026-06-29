//! Secret generation for obu (32-byte secrets).

use rand::RngCore;

/// Generate a random 32-byte secret as a 64-character lowercase hex
/// string (the canonical obu secret form; OBU spec §3).
///
/// # Examples
///
/// ```
/// use obu::generate_secret;
///
/// let secret = generate_secret();
/// assert_eq!(secret.len(), 64);
/// ```
#[must_use]
pub fn generate_secret() -> String {
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    hex::encode(secret_bytes)
}

/// Generate a random 32-byte secret as raw bytes.
///
/// # Examples
///
/// ```
/// use obu::generate_secret_bytes;
///
/// let secret_bytes = generate_secret_bytes();
/// assert_eq!(secret_bytes.len(), 32);
/// ```
#[must_use]
pub fn generate_secret_bytes() -> [u8; 32] {
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    secret_bytes
}
