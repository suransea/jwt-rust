//! JSON Web Signature, see https://tools.ietf.org/html/rfc7515

use crate::error::ErrorKind;

pub use self::sign::{Algorithm, Key};
pub use self::token::Token;

mod token;
mod sign;

/// Registered Header Parameter Names, see https://tools.ietf.org/html/rfc7515#section-4.1
#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    /// Type of JWS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// Algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Content type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
    /// JSON Key URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,
    /// Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// X.509 URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    /// X.509 certificate thumbprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
}

impl Header {
    /// Create a new `Header`, the `typ` value is "JWT".
    #[inline]
    pub fn new() -> Self {
        Header {
            typ: Some("JWT".to_string()),
            alg: None,
            cty: None,
            jku: None,
            kid: None,
            x5u: None,
            x5t: None,
        }
    }

    /// Verify that the algorithm match with `alg`
    pub fn verify_alg(&self, expected: &Algorithm) -> Result<(), ErrorKind> {
        if self.alg.is_none() || self.alg.as_ref().unwrap().as_str() != expected.to_string() {
            return Err(ErrorKind::InvalidAlg);
        }
        Ok(())
    }
}

impl Default for Header {
    #[inline]
    fn default() -> Self {
        Header::new()
    }
}
