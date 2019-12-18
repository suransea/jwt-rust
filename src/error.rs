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
    AlgorithmNotMatched,
    SignatureInvalid,
    KeyInvalid,
    BeforeIat,
    BeforeNbf,
    Expired(u64),
    Signing,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ErrorKind::Malformed => write!(f, "malformed token"),
            ErrorKind::AlgorithmNotMatched => write!(f, "algorithm don't matched."),
            ErrorKind::SignatureInvalid => write!(f, "invalid signature."),
            ErrorKind::BeforeIat => write!(f, "token used before iat."),
            ErrorKind::BeforeNbf => write!(f, "token used before nbf."),
            ErrorKind::Expired(nsec) => write!(f, "token expired by {}s.", nsec),
            ErrorKind::KeyInvalid => write!(f, "invalid key."),
            ErrorKind::Signing => write!(f, "errors occur in signing."),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        self.0.fmt(f)
    }
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
        Error(ErrorKind::KeyInvalid)
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error(ErrorKind::Signing)
    }
}
