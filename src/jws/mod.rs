//! Signed JWTs, see https://tools.ietf.org/html/rfc7515

use serde::Serialize;
use serde_json as json;

use crate::bs64;
use crate::error::Error;

pub use self::parse::{Config, parse, parse_default, parse_validate_none, SignatureValidation};
pub use self::sign::{Algorithm, Key};

mod sign;
mod parse;

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
}

impl Default for Header {
    #[inline]
    fn default() -> Self {
        Header::new()
    }
}

/// A JWS token.
#[derive(Debug)]
pub struct Token<T: Serialize> {
    /// header of token
    pub header: Header,
    /// payload of token
    pub payload: T,
    /// signature of token, default is
    /// an empty vector, assigned when signing or parsing.
    pub signature: Vec<u8>,
}

impl<T: Serialize> Token<T> {
    /// Create a `Token` with the specific payload.
    ///
    /// The payload should be `Serialize`, such as
    /// `jwts::Claims`, `HashMap`, a custom
    /// struct derived `Serialize`, etc.
    #[inline]
    pub fn with_payload(payload: T) -> Self {
        Token::with_header_and_payload(Header::new(), payload)
    }

    /// Create a `Token` with the specific header and payload.
    #[inline]
    pub fn with_header_and_payload(header: Header, payload: T) -> Self {
        Token {
            header,
            payload,
            signature: Vec::new(),
        }
    }

    /// Sign the token, and return the signed token as `String`.
    ///
    /// An error might occur with ErrorKind::Signing(SignError).
    pub fn sign(&mut self, key: &Key) -> Result<String, Error> {
        self.header.alg = Some(key.alg.to_string());
        let header = json::to_string(&self.header)
            .map(bs64::from_string)
            .unwrap();

        let payload = json::to_string(&self.payload)
            .map(bs64::from_string)
            .unwrap();

        let f2s = [header, payload].join(".");
        self.signature = key.sign(&f2s)?;

        let trd = bs64::from_bytes(&self.signature);

        Ok([f2s, trd].join("."))
    }
}
