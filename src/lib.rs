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
//! let token = token.sign(&key).unwrap_or_default();
//!
//! assert_eq!(token, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs");
//! ```
//!
//! ## Parse and Verify
//!
//! ```rust
//! use jwts::{Claims, jws};
//! use jwts::jws::{Algorithm, Config, Key, SignatureValidation, Token};
//!
//! let key = Key::new(b"secret", Algorithm::HS256);
//! let signature_validation = SignatureValidation::Key(key);
//!
//! // use key resolver like:
//! // let signature_validation = SignatureValidation::KeyResolver(|header, payload| {
//! //     // return a Key here
//! // });
//!
//! let config = Config {
//! signature_validation,
//! iat_validation: true,
//! nbf_validation: true,
//! exp_validation: true,
//! expected_iss: Some("sea".to_owned()),
//! expected_sub: None,
//! expected_aud: None,
//! expected_jti: None,
//! };
//!
//! let token = "a jwt token";
//!
//! let token: Option<Token<Claims>> = jws::parse(token, &config)
//! .map(Option::Some)
//! .unwrap_or_else(|err| {
//! println!("{:?}", err.kind());
//! None
//! });
//! println!("{:?}", token);
//! ```
//!
//! ## Custom Claims
//!
//! ```rust
//! use jwts::{Claims, jws};
//! use jwts::jws::{Algorithm, Key, Token};
//!
//! #[macro_use]
//! extern crate serde_derive;
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct CustomClaims {
//! iss: String,
//! }
//!
//! let claims = CustomClaims {
//! iss: "sea".to_owned(),
//! };
//!
//! let mut token = Token::with_payload(claims);
//! let key = Key::new(b"secret", Algorithm::HS256);
//! let token = token.sign(&key).unwrap_or_default();
//! let token: Token<CustomClaims> = jws::parse_validate_none(&token).unwrap();
//! println!("{:?}", token);
//! ```

#[macro_use]
extern crate serde_derive;

pub use crate::error::{Error, ErrorKind};

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
