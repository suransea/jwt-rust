//! Wrapper of `base64`

use base64::DecodeError;

use crate::error::Error;

pub fn from_bytes<T: AsRef<[u8]>>(bytes: &T) -> String {
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

pub fn from_string(s: String) -> String {
    from_bytes(&s)
}

pub fn to_bytes(s: String) -> Result<Vec<u8>, DecodeError> {
    base64::decode_config(&s, base64::URL_SAFE_NO_PAD)
}

pub fn to_string(s: String) -> Result<String, Error> {
    let s = base64::decode_config(&s, base64::URL_SAFE_NO_PAD)?;
    let s = String::from_utf8(s)?;
    Ok(s)
}
