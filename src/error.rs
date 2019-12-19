//! Errors

use std::string;

/// An error that might occur when signing and parsing a token
#[derive(Debug)]
pub struct Error(ErrorKind);

impl Error {
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
    /// Header "alg" expected
    AlgorithmMiss,
    /// Header "alg" does not match with the validated algorithm
    AlgorithmMismatch,
    /// Signature does not match
    InvalidSignature,
    /// Invalid iat
    InvalidIat,
    /// Token not active
    NotBefore,
    /// Token expired by seconds
    TokenExpired(u64),

    // signing
    /// Error in signing
    Signing(SignError),
}

#[derive(Debug)]
pub enum SignError {
    InvalidKey,
    Unspecific,
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error(kind)
    }
}

impl From<SignError> for Error {
    fn from(err: SignError) -> Self {
        Error(ErrorKind::Signing(err))
    }
}

impl From<base64::DecodeError> for Error {
    fn from(_: base64::DecodeError) -> Self {
        Error(ErrorKind::Malformed)
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error(ErrorKind::Malformed)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(_: string::FromUtf8Error) -> Self {
        Error(ErrorKind::Malformed)
    }
}

impl From<ring::error::KeyRejected> for Error {
    fn from(_: ring::error::KeyRejected) -> Self {
        Error(ErrorKind::Signing(SignError::InvalidKey))
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error(ErrorKind::Signing(SignError::Unspecific))
    }
}
