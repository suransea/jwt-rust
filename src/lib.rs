//! Rust implementation of JSON Web Tokens, see https://tools.ietf.org/html/rfc7519
//!
//! # Examples
//!
//! ## Sign
//!
//! ```rust
//! use jwts::Claims;
//! use jwts::jws::{Algorithm, Key, Token};
//!
//! let mut claims = Claims::new();
//! claims.iss = Some("sea".to_owned());
//!
//! let mut token = Token::with_payload(claims);
//!
//! // custom the header like:
//! // token.header.cty = Some("application/example".to_owned());
//!
//! let key = Key::new(b"secret", Algorithm::HS256);
//! let token = token.sign(&key).unwrap();
//!
//! assert_eq!(token, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs");
//! ```
//!
//! ## Verify
//!
//! ```rust
//! use jwts::{Claims, ValidationConfig};
//! use jwts::jws::{Algorithm, Key, Token};
//!
//! let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEiLCJleHAiOjEwNTc3MDkxMDU2LCJuYmYiOjE1NzcwOTEwNTYsImlhdCI6MTU3NzA5MTA1Nn0.4HwFlFB3LMhVc2xpsGBGSO3ut1KmnFdF8JrsL589ytw";
//!
//! let key = Key::new(b"secret", Algorithm::HS256);
//! let verified: Token<Claims> = Token::verify_with_key(token, &key).unwrap();
//!
//! // use key resolver like:
//! // let verified: Token<Claims> = Token::verify_with_key_resolver(token, |header, payload| {
//! //     // return a Key here
//! // }).unwrap();
//!
//! println!("{:?}", verified);
//!
//! // validate claims
//! let config = ValidationConfig {
//!     iat_validation: true,
//!     nbf_validation: true,
//!     exp_validation: true,
//!     expected_iss: Some("sea".to_owned()),
//!     expected_sub: None,
//!     expected_aud: None,
//!     expected_jti: None,
//! };
//! verified.validate_claims(&config).unwrap();
//! ```
//!
//! ## Custom Claims
//!
//! ```rust
//! use jwts::jws::{Algorithm, Key, Token};
//!
//! #[macro_use]
//! extern crate serde_derive;
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct CustomClaims {
//!     iss: String,
//! }
//!
//! let claims = CustomClaims {
//!     iss: "sea".to_owned(),
//! };
//!
//! let mut token = Token::with_payload(claims);
//! let key = Key::new(b"secret", Algorithm::HS256);
//! let token = token.sign(&key).unwrap();
//! let token: Token<CustomClaims> = Token::decode(&token).unwrap(); // here decode without verification for demonstration
//! println!("{:?}", token);
//! ```

#[macro_use]
extern crate serde_derive;

use serde::Serialize;
use serde_json as json;

pub use self::error::{Error, ErrorKind};

#[cfg(test)]
mod tests;

pub mod jws;
pub mod error;
mod time;
mod bs64;

/// Registered Claim Names, see https://tools.ietf.org/html/rfc7519#section-4.1
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiration Time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Not Before
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Issued At
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl Claims {
    /// Create a new `Claims`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use jwts::Claims;
    ///
    /// let mut claims = Claims::new();
    /// ```
    #[inline]
    pub fn new() -> Self {
        Claims {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
        }
    }
}

impl<T: Serialize> jws::Token<T> {
    /// Validate claims with the specific config.
    pub fn validate_claims(&self, config: &ValidationConfig) -> Result<(), Error> {
        let payload = json::to_value(&self.payload)?;

        validate_claim(&payload["iss"].as_str(), &config.expected_iss, ErrorKind::InvalidIss)?;
        validate_claim(&payload["aud"].as_str(), &config.expected_aud, ErrorKind::InvalidAud)?;
        validate_claim(&payload["sub"].as_str(), &config.expected_sub, ErrorKind::InvalidSub)?;
        validate_claim(&payload["jti"].as_str(), &config.expected_jti, ErrorKind::InvalidJti)?;

        if config.nbf_validation {
            let nbf = payload["nbf"].as_u64();
            validate_nbf(&nbf)?;
        }
        if config.iat_validation {
            let iat = payload["iat"].as_u64();
            validate_iat(&iat)?;
        }
        if config.exp_validation {
            let exp = payload["exp"].as_u64();
            validate_exp(&exp)?;
        }

        Ok(())
    }
}

/// Configs for validation.
pub struct ValidationConfig {
    pub iat_validation: bool,
    pub nbf_validation: bool,
    pub exp_validation: bool,
    pub expected_iss: Option<String>,
    pub expected_sub: Option<String>,
    pub expected_aud: Option<String>,
    pub expected_jti: Option<String>,
}

impl Default for ValidationConfig {
    #[inline]
    fn default() -> Self {
        ValidationConfig {
            iat_validation: true,
            nbf_validation: true,
            exp_validation: true,
            expected_iss: None,
            expected_sub: None,
            expected_aud: None,
            expected_jti: None,
        }
    }
}

#[inline]
fn validate_iat(iat: &Option<u64>) -> Result<(), ErrorKind> {
    if iat.is_some() && time::now_secs() < iat.unwrap() {
        return Err(ErrorKind::InvalidIat);
    }
    Ok(())
}

#[inline]
fn validate_nbf(nbf: &Option<u64>) -> Result<(), ErrorKind> {
    if nbf.is_some() && time::now_secs() < nbf.unwrap() {
        return Err(ErrorKind::NotBefore);
    }
    Ok(())
}

#[inline]
fn validate_exp(exp: &Option<u64>) -> Result<(), ErrorKind> {
    if exp.is_some() {
        let now = time::now_secs();
        let exp = exp.unwrap();
        if now >= exp {
            return Err(ErrorKind::TokenExpired(now - exp));
        }
    }
    Ok(())
}

#[inline]
fn validate_claim(val: &Option<&str>, expected: &Option<String>, or: ErrorKind) -> Result<(), ErrorKind> {
    if expected.is_some() {
        if val.is_none() || val.unwrap() != expected.as_ref().unwrap() {
            return Err(or);
        }
    }
    Ok(())
}
