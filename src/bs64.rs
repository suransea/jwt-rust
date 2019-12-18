//! Wrapper of `base64`

use base64::DecodeError;

use crate::error::Error;

pub fn from_bytes(bytes: impl AsRef<[u8]>) -> String {
    base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD)
}

pub fn from_string(s: String) -> String {
    from_bytes(&s)
}

pub fn to_bytes(s: &str) -> Result<Vec<u8>, DecodeError> {
    base64::decode_config(s, base64::URL_SAFE_NO_PAD)
}

pub fn to_string(s: &str) -> Result<String, Error> {
    let bytes = base64::decode_config(s, base64::URL_SAFE_NO_PAD)?;
    let string = String::from_utf8(bytes)?;
    Ok(string)
}
