//! Errors

use std::string;

/// An error that might occur when signing and parsing a token
#[derive(Debug)]
pub struct Error(ErrorKind);

impl Error {
    /// Returns the error kind.
    #[inline]
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }
}

/// All error kinds in signing and parsing.
#[derive(Debug)]
pub enum ErrorKind {
    // parse
    /// Token malformed
    Malformed,

    // validate
    /// Header "alg" does not match with the validated algorithm
    InvalidAlg,
    /// Claim "iss" does not match
    InvalidIss,
    /// Claim "sub" does not match
    InvalidSub,
    /// Claim "aud" does not match
    InvalidAud,
    /// Claim "jti" does not match
    InvalidJti,
    /// Signature does not match
    InvalidSignature,
    /// Now before the issued time
    InvalidIat,
    /// Token not active
    NotBefore,
    /// Token expired by seconds
    TokenExpired(u64),

    // signing
    /// Error in signing
    Signing(SignError),
}

/// Types of signing error.
#[derive(Debug)]
pub enum SignError {
    /// An invalid key provided
    InvalidKey,
    /// An unspecific error returns from the crate `ring`
    Unspecific,
}

impl From<ErrorKind> for Error {
    #[inline]
    fn from(kind: ErrorKind) -> Self {
        Error(kind)
    }
}

impl From<SignError> for Error {
    #[inline]
    fn from(err: SignError) -> Self {
        Error(ErrorKind::Signing(err))
    }
}

impl From<base64::DecodeError> for Error {
    #[inline]
    fn from(_: base64::DecodeError) -> Self {
        Error(ErrorKind::Malformed)
    }
}

impl From<serde_json::Error> for Error {
    #[inline]
    fn from(_: serde_json::Error) -> Self {
        Error(ErrorKind::Malformed)
    }
}

impl From<string::FromUtf8Error> for Error {
    #[inline]
    fn from(_: string::FromUtf8Error) -> Self {
        Error(ErrorKind::Malformed)
    }
}

impl From<ring::error::KeyRejected> for Error {
    #[inline]
    fn from(_: ring::error::KeyRejected) -> Self {
        Error(ErrorKind::Signing(SignError::InvalidKey))
    }
}

impl From<ring::error::Unspecified> for Error {
    #[inline]
    fn from(_: ring::error::Unspecified) -> Self {
        Error(ErrorKind::Signing(SignError::Unspecific))
    }
}
