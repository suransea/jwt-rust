//! Claims Validate

use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::Serialize;
use serde_json as json;

use crate::time;

pub struct IssuedAtTime;

pub struct NotBeforeTime;

pub struct ExpiredTime;

pub struct ExpectIss<'a>(pub &'a str);

pub struct ExpectSub<'a>(pub &'a str);

pub struct ExpectAud<'a>(pub &'a str);

pub struct ExpectJti<'a>(pub &'a str);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ValidateError {
    /// Claim "iss" does not match
    InvalidIss,
    /// Claim "sub" does not match
    InvalidSub,
    /// Claim "aud" does not match
    InvalidAud,
    /// Claim "jti" does not match
    InvalidJti,
    /// Now before the issued time
    InvalidIat,
    /// Token not active
    NotBefore,
    /// Token expired
    TokenExpiredAt(u64),
}

impl Display for ValidateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidateError::InvalidIss => f.write_str("Invalid iss"),
            ValidateError::InvalidSub => f.write_str("Invalid sub"),
            ValidateError::InvalidAud => f.write_str("Invalid aud"),
            ValidateError::InvalidJti => f.write_str("Invalid jti"),
            ValidateError::InvalidIat => f.write_str("Invalid iat"),
            ValidateError::NotBefore => f.write_str("Used before nbf"),
            ValidateError::TokenExpiredAt(time) => write!(f, "Token expired at {}", time),
        }
    }
}

impl Error for ValidateError {}

pub trait Validation<C: ?Sized> {
    type Error;

    fn validate(&self, claims: &C) -> Result<(), Self::Error>;
}

impl<T: Serialize> Validation<T> for IssuedAtTime {
    type Error = ValidateError;

    fn validate(&self, claims: &T) -> Result<(), Self::Error> {
        let claims = json::to_value(claims).ok();
        claims.and_then(|x| x["iat"].as_u64())
            .filter(|&x| x <= time::now_secs())
            .ok_or(ValidateError::InvalidIat)
            .map(|_| ())
    }
}

impl<T: Serialize> Validation<T> for NotBeforeTime {
    type Error = ValidateError;

    fn validate(&self, claims: &T) -> Result<(), Self::Error> {
        let claims = json::to_value(claims).ok();
        claims.and_then(|x| x["nbf"].as_u64())
            .filter(|&x| x <= time::now_secs())
            .ok_or(ValidateError::NotBefore)
            .map(|_| ())
    }
}

impl<T: Serialize> Validation<T> for ExpiredTime {
    type Error = ValidateError;

    fn validate(&self, claims: &T) -> Result<(), Self::Error> {
        let claims = json::to_value(claims).ok();
        claims.and_then(|x| x["exp"].as_u64())
            .ok_or(ValidateError::TokenExpiredAt(0))
            .and_then(|x| if x <= time::now_secs() { Err(ValidateError::TokenExpiredAt(x)) } else { Ok(x) })
            .map(|_| ())
    }
}

trait ExpectValidation<'a> {
    /// (claim_name, expected_value, error)
    fn expect(&self) -> (&'static str, &'a str, ValidateError);
}

impl<'a, T: ExpectValidation<'a>, C: Serialize> Validation<C> for T {
    type Error = ValidateError;

    fn validate(&self, claims: &C) -> Result<(), Self::Error> {
        let (claim_name, expected_value, error) = self.expect();
        let claims = json::to_value(claims).ok();
        claims.as_ref()
            .and_then(|x| x[claim_name].as_str())
            .filter(|x| x == &expected_value)
            .ok_or(error)
            .map(|_| ())
    }
}

impl<'a> ExpectValidation<'a> for ExpectIss<'a> {
    #[inline]
    fn expect(&self) -> (&'static str, &'a str, ValidateError) {
        ("iss", self.0, ValidateError::InvalidIss)
    }
}

impl<'a> ExpectValidation<'a> for ExpectSub<'a> {
    #[inline]
    fn expect(&self) -> (&'static str, &'a str, ValidateError) {
        ("sub", self.0, ValidateError::InvalidSub)
    }
}

impl<'a> ExpectValidation<'a> for ExpectAud<'a> {
    #[inline]
    fn expect(&self) -> (&'static str, &'a str, ValidateError) {
        ("aud", self.0, ValidateError::InvalidAud)
    }
}

impl<'a> ExpectValidation<'a> for ExpectJti<'a> {
    #[inline]
    fn expect(&self) -> (&'static str, &'a str, ValidateError) {
        ("jti", self.0, ValidateError::InvalidJti)
    }
}

pub trait Validate {
    #[inline]
    fn validate<V: Validation<Self>>(&self, validation: V) -> Result<(), V::Error> {
        validation.validate(self)
    }
}

impl<T> Validate for T {}
