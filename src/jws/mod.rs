//! JSON Web Signature

use std::str::FromStr;

use serde::Serialize;

pub use sign::Alg;

use crate::bs64;

pub mod sign;
pub mod verify;

/// Registered Header Parameter Names, see https://tools.ietf.org/html/rfc7515#section-4.1
#[derive(Serialize, Deserialize)]
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
    pub fn new() -> Header {
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

pub struct Token<T: Serialize> {
    pub header: Header,
    pub claims: T,
    pub signature: String,
}

impl<T: Serialize> Token<T> {
    pub fn new(claims: T) -> Token<T> {
        Token::with_header(Header::new(), claims)
    }

    pub fn with_header(header: Header, claims: T) -> Token<T> {
        Token {
            header,
            claims,
            signature: "".to_string(),
        }
    }

    pub fn sign(&mut self, alg: &Alg) {
        self.header.alg = Some(alg.to_string());
        let header = serde_json::to_string(&self.header)
            .map(bs64::from_string)
            .unwrap();

        let claims = serde_json::to_string(&self.claims)
            .map(bs64::from_string)
            .unwrap();

        let f2s: String = [header, claims].join(".");
        self.signature = alg.sign(&f2s);
    }
}

impl<T: Serialize> ToString for Token<T> {
    fn to_string(&self) -> String {
        let header = serde_json::to_string(&self.header)
            .map(bs64::from_string)
            .unwrap();

        let claims = serde_json::to_string(&self.claims)
            .map(bs64::from_string)
            .unwrap();

        let sign = bs64::from_bytes(&self.signature);
        [header, claims, sign].join(".")
    }
}

impl<T: Serialize> FromStr for Token<T> {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        unimplemented!()
    }
}

pub fn parse<T: Serialize>(token: &str) -> Token<T> {
    unimplemented!()
}
