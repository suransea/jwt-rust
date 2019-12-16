//! Rust implementation of JSON Web Tokens, see https://tools.ietf.org/html/rfc7519

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
    pub fn new() -> Claims {
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
