//! Decode

use serde::de::DeserializeOwned;
use serde_json as json;

use crate::bs64;
use crate::error::Error;
use crate::jws::Algorithm;

use super::Header;

/// A JWS token.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Token<P> {
    /// header of token
    pub header: Header,
    /// payload of token
    pub payload: P,
    /// signature of token
    pub signature: Vec<u8>,
}

pub trait Verify<P> {
    fn verify(&self, f2s: &str, signature: &[u8], header: &Header, payload: &P) -> Result<(), Error>;
}

pub struct NoVerify;

pub struct VerifyWith<'a, A: Algorithm>(pub &'a A::VerifyKey);

impl<P> Verify<P> for NoVerify {
    fn verify(&self, _f2s: &str, _signature: &[u8], _header: &Header, _payload: &P) -> Result<(), Error> {
        Ok(())
    }
}

impl<'a, P, A: Algorithm> Verify<P> for VerifyWith<'a, A> {
    fn verify(&self, f2s: &str, signature: &[u8], _header: &Header, _payload: &P) -> Result<(), Error> {
        A::verify(f2s, signature, self.0)
    }
}

/// Decode a token with the specific verification
pub fn decode<P: DeserializeOwned>(token: &str, verify: impl Verify<P>) -> Result<Token<P>, Error> {
    let (signature, f2s) = rsplit2_dot(token)?;
    let signature = bs64::to_bytes(signature)?;

    let (payload, header) = rsplit2_dot(f2s)?;

    let header = bs64::to_bytes(header)?;
    let payload = bs64::to_bytes(payload)?;

    let header: Header = json::from_slice(&header)?;
    let payload = json::from_slice(&payload)?;

    verify.verify(f2s, &signature, &header, &payload)?;

    Ok(Token { header, payload, signature })
}

/// Reverse split the string to 2 sections with '.'
fn rsplit2_dot(s: &str) -> Result<(&str, &str), Error> {
    let mut it = s.rsplitn(2, ".");
    match (it.next(), it.next()) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(Error::Malformed),
    }
}
