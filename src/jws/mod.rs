//! JSON Web Signature

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json as json;

use crate::bs64;
use crate::error::{Error, ErrorKind};

pub use self::sign::Alg;

pub mod sign;
pub mod verify;

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

#[derive(Debug)]
pub struct Token<T: Serialize> {
    pub header: Header,
    pub claims: T,
    pub signature: Vec<u8>,
}

impl<T: Serialize> Token<T> {
    pub fn with_claims(claims: T) -> Token<T> {
        Token::with_header_and_claims(Header::new(), claims)
    }

    pub fn with_header_and_claims(header: Header, claims: T) -> Token<T> {
        Token {
            header,
            claims,
            signature: [].to_vec(),
        }
    }

    pub fn sign(&mut self, alg: &Alg) {
        self.header.alg = Some(alg.to_string());
        let header = json::to_string(&self.header)
            .map(bs64::from_string)
            .unwrap();

        let claims = json::to_string(&self.claims)
            .map(bs64::from_string)
            .unwrap();

        let f2s: String = [header, claims].join(".");
        self.signature = alg.sign(&f2s);
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

        let sign = bs64::from_bytes(&self.signature);
        [header, claims, sign].join(".")
    }
}

fn rsplit2_dot(s: &str) -> Result<(&str, &str), ErrorKind> {
    let mut it = s.rsplitn(2, ".");
    match (it.next(), it.next()) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(ErrorKind::InvalidFormat("cannot split with a dot.".to_owned())),
    }
}

pub fn parse<T: Serialize + DeserializeOwned>(token: &str, alg: &Alg) -> Result<Token<T>, Error> {
    let (signature, f2s) = rsplit2_dot(token)?;
    let signature = bs64::to_bytes(signature.to_owned())?;

    if !verify::check_sign(f2s, &signature, alg) {
        return Err(Error::from(ErrorKind::InvalidSignature));
    }

    let (claims, header) = rsplit2_dot(f2s)?;

    let header = bs64::to_string(header.to_owned())?;
    let claims = bs64::to_string(claims.to_owned())?;

    let header = json::from_str(&header)?;
    let claims = json::from_str(&claims)?;

    Ok(Token { header, claims, signature })
}
