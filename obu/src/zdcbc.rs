#![cfg(feature = "zdcbc")]
use super::constants::{AES_BLOCK_SIZE, CBC_PADDING_BYTE};
use crate::Error;
use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

const KEY_OFFSET: usize = 0;
const KEY_LEN: usize = 16;
const IV_OFFSET: usize = 16;
const IV_LEN: usize = 16;
type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

/// Encrypt plaintext bytes using deterministic AES-CBC (zdcbc scheme).
/// Returns raw ciphertext bytes **reversed** for prefix entropy maximization.
/// Not cryptographically secure - for obfuscation only.
#[inline(always)]
pub fn encrypt_zdcbc(secret: &[u8; 32], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    // Spec §2.1: enc MUST reject any plaintext whose final byte is the
    // 0x01 padding byte, so trailing-0x01 stripping on dec is unambiguous.
    if plaintext_bytes.last() == Some(&CBC_PADDING_BYTE) {
        return Err(Error::PlaintextEndsWithPadByte);
    }

    // Calculate padding to align to block size
    let data_len = plaintext_bytes.len();
    let padding_size = (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    let total_len = data_len + padding_size;

    // Allocate once with the correct size
    let mut buffer = Vec::with_capacity(total_len);
    buffer.extend_from_slice(plaintext_bytes);
    buffer.resize(total_len, CBC_PADDING_BYTE);

    // Encrypt in-place
    let cipher = Aes128CbcEnc::new(
        secret[KEY_OFFSET..KEY_OFFSET + KEY_LEN].into(),
        secret[IV_OFFSET..IV_OFFSET + IV_LEN].into(),
    );
    cipher
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer, total_len)
        .map_err(|_| Error::EncryptionFailed)?;

    // Prefix restructuring
    let len = buffer.len();

    if len > AES_BLOCK_SIZE {
        // Multiple blocks: XOR first block with last block for prefix entropy
        for i in 0..AES_BLOCK_SIZE {
            buffer[i] ^= buffer[len - AES_BLOCK_SIZE + i]
        }
    }

    Ok(buffer)
}

/// Decrypt ciphertext using deterministic AES-CBC (zdcbc scheme).
/// Expects **reversed** ciphertext.  Returns plaintext bytes with padding removed.
#[inline(always)]
pub fn decrypt_zdcbc(secret: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    // Decrypt with AES-128-CBC
    let len = data.len();

    if len % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidBlockLength);
    }

    let mut buffer = data.to_vec();

    if len > AES_BLOCK_SIZE {
        // Multiple blocks: XOR first block with last block for prefix entropy
        for i in 0..AES_BLOCK_SIZE {
            buffer[i] ^= buffer[len - AES_BLOCK_SIZE + i]
        }
    }

    let cipher = Aes128CbcDec::new(
        secret[KEY_OFFSET..KEY_OFFSET + KEY_LEN].into(),
        secret[IV_OFFSET..IV_OFFSET + IV_LEN].into(),
    );
    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer)
        .map_err(|_| Error::DecryptionFailed)?;

    // Remove CBC padding by finding the end and truncating
    let mut end = buffer.len();
    while end > 0 && buffer[end - 1] == CBC_PADDING_BYTE {
        end -= 1;
    }
    buffer.truncate(end);

    // OBU §2.2: dec MUST reject a payload that strips to empty (a
    // zero-length ciphertext, or a block that is all padding). zdcbc is
    // obfuscation-only and not anti-oracle, so a granular error is fine.
    if buffer.is_empty() {
        return Err(Error::EmptyPayload);
    }

    Ok(buffer)
}
