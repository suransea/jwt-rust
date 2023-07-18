//! Header

use serde_derive::{Deserialize, Serialize};

use crate::jws::Algorithm;

/// Registered Header Parameter Names, see https://tools.ietf.org/html/rfc7515#section-4.1
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

    #[inline]
    pub fn with_algorithm<A: Algorithm>(self) -> Self {
        Header {
            alg: Some(A::name().to_owned()),
            ..self
        }
    }
}

impl Default for Header {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
