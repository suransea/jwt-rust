//! Standard Claims

use std::time::{Duration, SystemTime};

use serde_derive::{Deserialize, Serialize};

use crate::time;

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

    #[inline]
    pub fn issued_now(self) -> Self {
        Claims {
            iat: Some(time::now_secs()),
            ..self
        }
    }

    #[inline]
    pub fn expired_in(self, duration: Duration) -> Self {
        Claims {
            exp: Some(time::now_secs() + duration.as_secs()),
            ..self
        }
    }

    #[inline]
    pub fn expired_at(self, time: SystemTime) -> Self {
        Claims {
            exp: Some(time::since_unix_epoch_secs(time)),
            ..self
        }
    }

    #[inline]
    pub fn not_before(self, time: SystemTime) -> Self {
        Claims {
            nbf: Some(time::since_unix_epoch_secs(time)),
            ..self
        }
    }
}

impl Default for Claims {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
