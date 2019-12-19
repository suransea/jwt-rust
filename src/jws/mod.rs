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
    fn default() -> Self {
        Header::new()
    }
}

#[derive(Debug)]
pub struct Token<T: Serialize> {
    pub header: Header,
    pub payload: T,
    pub signature: Vec<u8>,
}

impl<T: Serialize> Token<T> {
    pub fn with_payload(payload: T) -> Self {
        Token::with_header_and_payload(Header::new(), payload)
    }

    pub fn with_header_and_payload(header: Header, payload: T) -> Self {
        Token {
            header,
            payload,
            signature: Vec::new(),
        }
    }

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