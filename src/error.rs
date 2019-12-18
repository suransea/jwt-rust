//! Errors

use std::fmt;
use std::string;

#[derive(Debug)]
pub struct Error(pub ErrorKind);

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    Malformed,
    AlgorithmMismatch,
    SignatureInvalid,
    InvalidKey,
    InvalidIat,
    BeforeNbf,
    TokenExpired(u64),
    Signing,
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error(kind)
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
        Error(ErrorKind::InvalidKey)
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error(ErrorKind::Signing)
    }
}
