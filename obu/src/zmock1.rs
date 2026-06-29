//! zmock1 - Identity scheme (no encryption, testing only)
//!
//! This scheme performs no encryption and is available by default.
//! It exists for testing and as a no-op baseline.

#![cfg(feature = "mock")]

use crate::Error;

/// "Encrypt" plaintext bytes using identity scheme (zmock1).
/// Returns the input unchanged (no actual encryption).
pub(crate) fn encrypt_zmock1(_key: &[u8; 32], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    Ok(plaintext_bytes.to_vec())
}

/// "Decrypt" ciphertext bytes using identity scheme (zmock1).
/// Returns the input unchanged (no actual decryption).
pub(crate) fn decrypt_zmock1(_key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Err(Error::EmptyPayload);
    }

    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zmock1_roundtrip() {
        let key = [0u8; 32];

        let plaintext = b"hello world";
        let ciphertext = encrypt_zmock1(&key, plaintext).unwrap();
        let decrypted = decrypt_zmock1(&key, &ciphertext).unwrap();

        // Identity: everything should be the same
        assert_eq!(ciphertext, plaintext);
        assert_eq!(decrypted, plaintext);
    }
}
