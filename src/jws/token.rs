//! Signed JWTs

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json as json;
use serde_json::Value;

use crate::bs64;
use crate::error::{Error, ErrorKind};

use super::Header;
use super::sign::Key;

/// A JWS token.
#[derive(Debug)]
pub struct Token<T: Serialize> {
    /// header of token
    pub header: Header,
    /// payload of token
    pub payload: T,
    /// signature of token, default is
    /// an empty vector, assigned when signing or decoding.
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

impl<T: Serialize + DeserializeOwned> Token<T> {
    /// Decode a token without verifications.
    #[inline]
    pub fn decode(token: &str) -> Result<Self, Error> {
        Token::decode_verify(token, |_, _, _, _| Ok(()))
    }

    /// Decode and verify a token with the key.
    #[inline]
    pub fn verify_with_key(token: &str, key: &Key) -> Result<Self, Error> {
        Token::decode_verify(token, |f2s, sig, header, _| {
            header.verify_alg(&key.alg)?;
            key.verify(f2s, sig)
        })
    }

    /// Decode and verify a token with the key array.
    #[inline]
    pub fn verify_with_keys(token: &str, keys: &[&Key]) -> Result<Self, Error> {
        Token::decode_verify(token, |f2s, sig, header, _| {
            for key in keys {
                if header.verify_alg(&key.alg).is_ok() &&
                    key.verify(f2s, sig).is_ok() {
                    return Ok(());
                }
            }
            Err(Error::from(ErrorKind::InvalidSignature))
        })
    }

    /// Decode and verify a token with the key resolver.
    ///
    /// The args of resolver are `header` and `payload`.
    #[inline]
    pub fn verify_with_key_resolver(token: &str, resolver: impl Fn(&Header, &Value) -> Key)
                                    -> Result<Self, Error> {
        Token::decode_verify(token, |f2s, sig, header, payload| {
            let key = resolver(header, payload);
            header.verify_alg(&key.alg)?;
            key.verify(f2s, sig)
        })
    }

    /// Decode a token, and verify with the verifier.
    fn decode_verify(token: &str, verifier: impl Fn(&str, &Vec<u8>, &Header, &Value) -> Result<(), Error>)
                     -> Result<Self, Error> {
        let (signature, f2s) = rsplit2_dot(token)?;
        let signature = bs64::to_bytes(signature)?;

        let (payload, header) = rsplit2_dot(f2s)?;

        let header = bs64::to_string(header)?;
        let payload = bs64::to_string(payload)?;

        let header: Header = json::from_str(&header)?;
        let payload: Value = json::from_str(&payload)?;

        verifier(f2s, &signature, &header, &payload)?;

        let payload = json::from_value(payload)?;

        Ok(Token { header, payload, signature })
    }
}

/// Reverse split the string to 2 sections with '.'
fn rsplit2_dot(s: &str) -> Result<(&str, &str), Error> {
    let mut it = s.rsplitn(2, ".");
    match (it.next(), it.next()) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(Error::from(ErrorKind::Malformed)),
    }
}
