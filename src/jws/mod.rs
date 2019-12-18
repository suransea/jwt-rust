//! Signed JWTs, see https://tools.ietf.org/html/rfc7515

use serde::Serialize;
use serde_json as json;

use crate::bs64;
use crate::error::Error;

pub use self::decode::{Config, decode, decode_default, decode_verify_none, SignatureValidation};
pub use self::sign::{Algorithm, Key};

mod sign;
mod verify;
mod decode;

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

#[derive(Debug)]
pub struct Token<T: Serialize> {
    pub header: Header,
    pub claims: T,
    pub signature: Vec<u8>,
}

impl<T: Serialize> Token<T> {
    pub fn with_claims(claims: T) -> Self {
        Token::with_header_and_claims(Header::new(), claims)
    }

    pub fn with_header_and_claims(header: Header, claims: T) -> Self {
        Token {
            header,
            claims,
            signature: Default::default(),
        }
    }

    pub fn sign(&mut self, key: &Key) -> Result<(), Error> {
        self.header.alg = Some(key.alg.to_string());
        let header = json::to_string(&self.header)
            .map(bs64::from_string)
            .unwrap();

        let claims = json::to_string(&self.claims)
            .map(bs64::from_string)
            .unwrap();

        let f2s: String = [header, claims].join(".");
        self.signature = key.sign(&f2s)?;
        Ok(())
    }
}

impl<T: Serialize> ToString for Token<T> {
    fn to_string(&self) -> String {
        let header = json::to_string(&self.header)
            .map(bs64::from_string)
            .unwrap();

        let claims = json::to_string(&self.claims)
            .map(bs64::from_string)
            .unwrap();

        let signature = bs64::from_bytes(&self.signature);
        [header, claims, signature].join(".")
    }
}
