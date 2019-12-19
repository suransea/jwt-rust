//! Wrapper of `base64`

use base64::DecodeError;

use crate::error::Error;

/// Encodes the specific bytes to a base64 string.
///
/// This is a wrapper function of `base64::encode_config` to simplify invocation.
#[inline]
pub fn from_bytes(bytes: impl AsRef<[u8]>) -> String {
    base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD)
}

/// Converts the string as bytes, and encodes to a base64 string.
///
/// This is a wrapper function of `base64::encode_config` to simplify invocation.
#[inline]
pub fn from_string(s: String) -> String {
    from_bytes(&s)
}

/// Decodes the base64 string to bytes as `Vec<u8>`.
///
/// This is a wrapper function of `base64::decode_config` to simplify invocation.
#[inline]
pub fn to_bytes(s: &str) -> Result<Vec<u8>, DecodeError> {
    base64::decode_config(s, base64::URL_SAFE_NO_PAD)
}

/// Decodes the base64 string to bytes, and create a `String` using them.
///
/// This is a wrapper function of `base64::decode_config` to simplify invocation.
#[inline]
pub fn to_string(s: &str) -> Result<String, Error> {
    let bytes = base64::decode_config(s, base64::URL_SAFE_NO_PAD)?;
    let string = String::from_utf8(bytes)?;
    Ok(string)
}
