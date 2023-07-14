//! Wrapper of `base64`

use base64::{DecodeError, Engine};

/// Encodes the specific bytes to a base64 string.
#[inline]
pub fn from_bytes(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

/// Decodes the base64 string to bytes as `Vec<u8>`.
#[inline]
pub fn to_bytes(s: &str) -> Result<Vec<u8>, DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}
