//! Secret holder for obu schemes (32-byte / 64-hex secrets).

use crate::Error;

/// Secret for obu schemes (unauthenticated; 32-byte secrets).
///
/// **WARNING**: obu schemes are unauthenticated and (for `zdcbc`) not
/// cryptographically secure. Never use to protect secrets.
pub(crate) struct ZSecret {
    secret: [u8; 32],
}

impl ZSecret {
    /// Create from a 32-byte secret.
    #[inline]
    pub(crate) fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(ZSecret {
            secret: *secret_bytes,
        })
    }

    /// Length-routed entry point used by every obu `new()` constructor.
    /// The obu secret is 64 hex characters (32 bytes); there is no
    /// base64 form (OBU spec §3).
    #[inline]
    pub(crate) fn from_string(s: &str) -> Result<Self, Error> {
        match s.len() {
            64 => Self::from_hex(s),
            _ => Err(Error::InvalidKeyLength),
        }
    }

    /// Create from a 64-character hex secret string.
    #[inline]
    pub(crate) fn from_hex(secret_hex: &str) -> Result<Self, Error> {
        let secret_bytes: [u8; 32] = hex::decode(secret_hex)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;
        Self::from_bytes(&secret_bytes)
    }

    /// Get the secret as raw bytes.
    #[inline]
    #[allow(dead_code)] // Used by Obu.secret_bytes()
    pub(crate) fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Get the secret as a 64-character hex string.
    #[inline]
    #[allow(dead_code)] // Used by Obu.secret_hex()
    pub(crate) fn secret_hex(&self) -> String {
        hex::encode(self.secret)
    }

    /// Get the secret as raw bytes (internal — passed to the scheme
    /// functions, which derive their own key/IV material from it).
    #[inline(always)]
    pub(crate) fn master_secret(&self) -> &[u8; 32] {
        &self.secret
    }
}
