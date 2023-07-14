//! Signed JWTs

use std::borrow::Borrow;

use serde::de::DeserializeOwned;
use serde_json as json;

use crate::bs64;
use crate::error::Error;
use crate::jws::Algorithm;

use super::Header;

/// A JWS token.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Token<T> {
    /// header of token
    pub header: Header,
    /// payload of token
    pub payload: T,
    /// signature of token
    pub signature: Vec<u8>,
}

impl<T: DeserializeOwned> Token<T> {
    /// Decode a token without verifications.
    #[inline]
    pub fn decode(token: &str) -> Result<Self, Error> {
        Token::decode_verify(token, |_, _, _, _| Ok(()))
    }

    /// Decode and verify a token with the key.
    #[inline]
    pub fn verify_with_key<A: Algorithm>(token: &str, key: &A::VerifyKey) -> Result<Self, Error> {
        Token::decode_verify(token, |f2s, sig, _, _| {
            A::verify(f2s, sig, &key)
        })
    }

    /// Decode and verify a token with the key resolver.
    ///
    /// The args of resolver are `header` and `payload`.
    #[inline]
    pub fn verify_with_key_resolver<A, K>(token: &str, resolver: impl Fn(&Header, &T) -> K)
                                          -> Result<Self, Error> where A: Algorithm, K: Borrow<A::VerifyKey> {
        Token::decode_verify(token, |f2s, sig, header, payload| {
            let key = resolver(header, payload);
            A::verify(f2s, sig, key.borrow())
        })
    }

    /// Decode a token, and verify with the verifier.
    fn decode_verify(token: &str, verifier: impl FnOnce(&str, &[u8], &Header, &T) -> Result<(), Error>)
                     -> Result<Self, Error> {
        let (signature, f2s) = rsplit2_dot(token)?;
        let signature = bs64::to_bytes(signature)?;

        let (payload, header) = rsplit2_dot(f2s)?;

        let header = bs64::to_bytes(header)?;
        let payload = bs64::to_bytes(payload)?;

        let header: Header = json::from_slice(&header)?;
        let payload = json::from_slice(&payload)?;

        verifier(f2s, &signature, &header, &payload)?;

        Ok(Token { header, payload, signature })
    }
}

/// Reverse split the string to 2 sections with '.'
fn rsplit2_dot(s: &str) -> Result<(&str, &str), Error> {
    let mut it = s.rsplitn(2, ".");
    match (it.next(), it.next()) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(Error::Malformed),
    }
}
