//! Rust implementation of JSON Web Tokens, see https://tools.ietf.org/html/rfc7519
//!
//! # Examples
//!
//! ### Sign
//!
//! ```rust
//! use jwts::{Claims, jws};
//! use jwts::jws::Header;
//! use jwts::jws::alg::HS256;
//!
//! let claims = Claims {
//!     iss: Some("sea".to_owned()),
//!     ..Default::default()
//! };
//! assert_eq!(
//!     jws::sign::<HS256>(Header::default(), &claims, b"secret"),
//!     Ok("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWEifQ.L0DLtDjydcSK-c0gTyOYbmUQ_LUCZzqAGCINn2OLhFs".to_owned()),
//! );
//! ```
//!
//! ### Verify
//!
//! ```rust
//! use jwts::{Claims, jws};
//! use jwts::jws::{Header, Token};
//! use jwts::jws::alg::HS256;
//!
//! let claims = Claims {
//!     iss: Some("sea".to_owned()),
//!     ..Default::default()
//! };
//! let token = jws::sign::<HS256>(Header::default(), &claims, b"secret").unwrap();
//!
//! let result = Token::<Claims>::verify_with_key::<HS256>(&token, b"secret");
//! assert!(result.is_ok());
//! ```
//!
//! ### Validate Claims
//!
//! ```rust
//! use std::time;
//! use std::time::{Duration, SystemTime};
//! use jwts::Claims;
//! use jwts::validate::{ExpectAud, ExpectIss, ExpectJti, ExpectSub, ExpiredTime, IssuedAtTime, NotBeforeTime, Validate};
//!
//! fn now_secs() -> u64 {
//!     SystemTime::now()
//!         .duration_since(time::UNIX_EPOCH)
//!         .unwrap_or(Duration::ZERO)
//!         .as_secs()
//! }
//!
//! let claims = Claims {
//!     iss: Some("sea".to_owned()),
//!     sub: Some("subject".to_owned()),
//!     aud: Some("audience".to_owned()),
//!     jti: Some("id".to_owned()),
//!     iat: Some(now_secs()),
//!     nbf: Some(now_secs()),
//!     exp: Some(now_secs() + 1),
//! };
//! assert_eq!(claims.validate(IssuedAtTime), Ok(()));
//! assert_eq!(claims.validate(NotBeforeTime), Ok(()));
//! assert_eq!(claims.validate(ExpiredTime), Ok(()));
//! assert_eq!(claims.validate(ExpectIss("sea")), Ok(()));
//! assert_eq!(claims.validate(ExpectSub("subject")), Ok(()));
//! assert_eq!(claims.validate(ExpectAud("audience")), Ok(()));
//! assert_eq!(claims.validate(ExpectJti("id")), Ok(()));
//! ```
//!

use serde_derive::{Deserialize, Serialize};

pub use self::error::Error;

pub mod jws;
pub mod error;
pub mod validate;
mod bs64;
mod time;

/// Registered Claim Names, see https://tools.ietf.org/html/rfc7519#section-4.1
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

impl Default for Claims {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
