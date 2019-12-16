//! Errors

use std::fmt;
use std::string;

#[derive(Debug)]
pub struct Error(ErrorKind);

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    InvalidFormat(String),
    InvalidSignature,
    BeforeIat,
    BeforeNbf,
    Expired(u64),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ErrorKind::InvalidFormat(s) => write!(f, "invalid format. {}", s),
            ErrorKind::InvalidSignature => write!(f, "invalid signature."),
            ErrorKind::BeforeIat => write!(f, "token used before iat."),
            ErrorKind::BeforeNbf => write!(f, "token used before nbf."),
            ErrorKind::Expired(nsec) => write!(f, "token has expired by {}s.", nsec),
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
    fn from(err: base64::DecodeError) -> Self {
        Error(ErrorKind::InvalidFormat(err.to_string()))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error(ErrorKind::InvalidFormat(err.to_string()))
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Self {
        Error(ErrorKind::InvalidFormat(err.to_string()))
    }
}
