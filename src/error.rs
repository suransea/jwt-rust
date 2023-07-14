//! Errors

use std::fmt::{Display, Formatter};

/// An error that might occur when signing and decode a token
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// Token malformed
    Malformed,
    /// Signature does not match
    InvalidSignature,
    /// An invalid key provided
    InvalidKey(&'static str),
    /// Unspecific crypto error
    Crypto,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed => f.write_str("Malformed"),
            Error::InvalidSignature => f.write_str("Invalid signature"),
            Error::InvalidKey(cause) => write!(f, "Invalid key: {}", cause),
            Error::Crypto => f.write_str("Unspecific crypto error"),
        }
    }
}

impl std::error::Error for Error {}

impl From<base64::DecodeError> for Error {
    #[inline]
    fn from(_: base64::DecodeError) -> Self {
        Error::Malformed
    }
}

impl From<serde_json::Error> for Error {
    #[inline]
    fn from(_: serde_json::Error) -> Self {
        Error::Malformed
    }
}

impl From<ring::error::KeyRejected> for Error {
    #[inline]
    fn from(err: ring::error::KeyRejected) -> Self {
        Error::InvalidKey(err.description_())
    }
}

impl From<ring::error::Unspecified> for Error {
    #[inline]
    fn from(_: ring::error::Unspecified) -> Self {
        Error::Crypto
    }
}
