#![cfg(feature = "upcbc")]
//! `upcbc` — unauthenticated probabilistic AES-256-CBC.
//!
//! Confidentiality without integrity (OBU spec §1). The full 32-byte
//! secret is the AES-256 key; a fresh random 16-byte IV is generated
//! per encryption. Output layout is `16-byte IV || padded ciphertext`
//! (§2.2). **Unauthenticated**: vulnerable to ciphertext tampering —
//! never use where integrity matters.

use super::constants::{AES_BLOCK_SIZE, CBC_PADDING_BYTE};
use crate::Error;
use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;

const IV_LEN: usize = 16;
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Encrypt with AES-256-CBC under a fresh random IV (`upcbc`).
///
/// The 32-byte secret is the AES-256 key. Returns
/// `16-byte IV || padded ciphertext`.
#[inline]
pub fn encrypt_upcbc(secret: &[u8; 32], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    // Spec §2.1: enc MUST reject any plaintext whose final byte is the
    // 0x01 padding byte, so trailing-0x01 stripping on dec is unambiguous.
    if plaintext_bytes.last() == Some(&CBC_PADDING_BYTE) {
        return Err(Error::PlaintextEndsWithPadByte);
    }

    let data_len = plaintext_bytes.len();
    let padding_size = (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    let total_len = data_len + padding_size;

    // Fresh random IV per encryption — this is what makes upcbc probabilistic.
    let mut iv = [0u8; IV_LEN];
    rand::thread_rng().fill_bytes(&mut iv);

    let mut buffer = Vec::with_capacity(total_len);
    buffer.extend_from_slice(plaintext_bytes);
    buffer.resize(total_len, CBC_PADDING_BYTE);

    let cipher = Aes256CbcEnc::new(secret[..].into(), iv[..].into());
    cipher
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer, total_len)
        .map_err(|_| Error::EncryptionFailed)?;

    // Layout: IV || ciphertext.
    let mut out = Vec::with_capacity(IV_LEN + buffer.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&buffer);
    Ok(out)
}

/// Decrypt an `upcbc` payload (`IV || ciphertext`) with AES-256-CBC.
///
/// Unauthenticated: returns a single uniform [`Error::DecryptionFailed`]
/// for every failure (OBU spec §2.1) so padding validation cannot
/// become a distinguishing oracle.
#[inline]
pub fn decrypt_upcbc(secret: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    // Need the IV plus at least one full ciphertext block, and the
    // ciphertext portion must be a whole number of blocks.
    if data.len() < IV_LEN + AES_BLOCK_SIZE || (data.len() - IV_LEN) % AES_BLOCK_SIZE != 0 {
        return Err(Error::DecryptionFailed);
    }
    let (iv, ciphertext) = data.split_at(IV_LEN);
    let mut buffer = ciphertext.to_vec();

    let cipher = Aes256CbcDec::new(secret[..].into(), iv.into());
    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer)
        .map_err(|_| Error::DecryptionFailed)?;

    // Strip trailing 0x01 padding.
    let mut end = buffer.len();
    while end > 0 && buffer[end - 1] == CBC_PADDING_BYTE {
        end -= 1;
    }
    buffer.truncate(end);

    // OBU §2.2: dec MUST reject a payload that strips to empty. upcbc
    // returns the single uniform DecryptionFailed (§2.1), so this stays
    // indistinguishable from a padding/decrypt failure.
    if buffer.is_empty() {
        return Err(Error::DecryptionFailed);
    }
    Ok(buffer)
}
