//! `Legacy` — a DEPRECATED, standalone obfuscation codec kept for
//! backward compatibility with pre-1.0 `legacy`-format obtext.
//!
//! ⚠️ **Not for new code, and not cryptographically secure.** It exists
//! only to decode (and reproduce) values that were produced by the old
//! `legacy` scheme.
//!
//! Algorithm: AES-128-CBC under a constant key+IV taken from the 32-byte
//! secret (key = `secret[0..16]`, IV = `secret[16..32]`), `=`-padded to
//! the block size, encoded as lowercase RFC 4648 base32, then the whole
//! string reversed for prefix entropy. It is deterministic and has a
//! single fixed form — no encoding variants.
//!
//! This codec is deliberately **isolated** from the `Scheme` / `Format`
//! / `Omnibu` machinery: there is no `Scheme::Legacy`, and it does not
//! implement `ObtextCodec`. Use it directly via [`Legacy`].
#![cfg(feature = "legacy")]

#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_SECRET_BYTES;
use crate::base32::BASE32_RFC_LOWER;
use crate::constants::AES_BLOCK_SIZE;
use crate::error::Error;
use crate::zsecret::ZSecret;

const LEGACY_PADDING_BYTE: u8 = b'=';
const KEY_OFFSET: usize = 0;
const KEY_LEN: usize = 16;
const IV_OFFSET: usize = 16;
const IV_LEN: usize = 16;

/// **DEPRECATED** legacy obfuscation codec — compatibility only.
///
/// ⚠️ Not authenticated, not secure, not for new code. Reproduces the
/// pre-1.0 `legacy` obtext format. See the [module docs](self) for the
/// algorithm and the reasoning behind its isolation from the scheme
/// machinery.
pub struct Legacy {
    zsecret: ZSecret,
}

impl Legacy {
    /// Create from a 64-character hex secret.
    pub fn new(secret: &str) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_string(secret)?,
        })
    }

    /// Create from a raw 32-byte secret.
    pub fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_bytes(secret_bytes)?,
        })
    }

    /// Create with the hardcoded built-in secret (testing / obfuscation
    /// only).
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_bytes(&HARDCODED_SECRET_BYTES)?,
        })
    }

    /// The 64-character hex secret bound to this codec.
    pub fn secret(&self) -> String {
        self.zsecret.secret_hex()
    }

    /// The secret as raw bytes.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.zsecret.secret_bytes()
    }

    /// Encrypt and encode `plaintext` to legacy obtext.
    pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
        let plaintext_bytes = plaintext.as_bytes();
        if plaintext_bytes.is_empty() {
            return Err(Error::EmptyPlaintext);
        }

        let ciphertext = encrypt_legacy(self.zsecret.master_secret(), plaintext_bytes)?;

        // lowercase RFC base32, then reverse the whole string for prefix
        // entropy. The encoding is ASCII-only, so a byte-level reverse
        // can never split a multi-byte UTF-8 sequence.
        let mut s = BASE32_RFC_LOWER.encode(&ciphertext);
        debug_assert!(s.is_ascii(), "lowercase RFC base32 must be ASCII");
        unsafe { s.as_bytes_mut() }.reverse();
        Ok(s)
    }

    /// Decode and decrypt legacy `obtext` to plaintext.
    pub fn dec(&self, obtext: &str) -> Result<String, Error> {
        // Reverse, then decode lowercase RFC base32.
        let reversed: Vec<u8> = obtext.bytes().rev().collect();
        let ciphertext = BASE32_RFC_LOWER
            .decode(&reversed)
            .map_err(|_| Error::InvalidB32)?;

        let plaintext_bytes = decrypt_legacy(self.zsecret.master_secret(), &ciphertext)?;
        String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
    }
}

/// AES-128-CBC encrypt with the legacy constant key+IV and `=` padding.
#[inline(always)]
fn encrypt_legacy(secret: &[u8; 32], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    use aes::Aes128;
    use cbc::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
    use cbc::Encryptor;
    type Aes128CbcEnc = Encryptor<Aes128>;

    let data_len = plaintext_bytes.len();
    let padding_size = (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    let total_len = data_len + padding_size;

    let mut buffer = Vec::with_capacity(total_len);
    buffer.extend_from_slice(plaintext_bytes);
    buffer.resize(total_len, LEGACY_PADDING_BYTE);

    let cipher = Aes128CbcEnc::new(
        secret[KEY_OFFSET..KEY_OFFSET + KEY_LEN].into(),
        secret[IV_OFFSET..IV_OFFSET + IV_LEN].into(),
    );
    cipher
        .encrypt_padded_mut::<NoPadding>(&mut buffer, total_len)
        .map_err(|_| Error::EncryptionFailed)?;
    Ok(buffer)
}

/// AES-128-CBC decrypt with the legacy constant key+IV, stripping `=`
/// padding.
#[inline(always)]
fn decrypt_legacy(secret: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    use aes::Aes128;
    use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;
    type Aes128CbcDec = Decryptor<Aes128>;

    if data.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidBlockLength);
    }

    let cipher = Aes128CbcDec::new(
        secret[KEY_OFFSET..KEY_OFFSET + KEY_LEN].into(),
        secret[IV_OFFSET..IV_OFFSET + IV_LEN].into(),
    );
    let mut buffer = data.to_vec();
    cipher
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| Error::DecryptionFailed)?;

    let end = buffer
        .iter()
        .rposition(|&b| b != LEGACY_PADDING_BYTE)
        .map_or(0, |i| i + 1);
    buffer.truncate(end);
    Ok(buffer)
}
