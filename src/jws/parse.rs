//! Parse

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json as json;
use serde_json::Value;

use crate::bs64;
use crate::error::{Error, ErrorKind};
use crate::jws::{Header, Token};
use crate::jws::sign::Key;
use crate::jws::verify::{verify_exp, verify_iat, verify_nbf, verify_signature};

pub enum SignatureValidation {
    Key(Key),
    KeyResolver(fn(header: &Header, claims: &Value) -> Key),
    None,
}

pub struct Config {
    pub signature_validation: SignatureValidation,
    pub iat_validation: bool,
    pub nbf_validation: bool,
    pub exp_validation: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            signature_validation: SignatureValidation::None,
            iat_validation: true,
            nbf_validation: true,
            exp_validation: true,
        }
    }
}

static VERIFY_NONE: Config = Config {
    signature_validation: SignatureValidation::None,
    iat_validation: false,
    nbf_validation: false,
    exp_validation: false,
};

fn rsplit2_dot(s: &str) -> Result<(&str, &str), Error> {
    let mut it = s.rsplitn(2, ".");
    match (it.next(), it.next()) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(Error(ErrorKind::Malformed)),
    }
}

pub fn parse<T: Serialize + DeserializeOwned>(token: &str, config: &Config) -> Result<Token<T>, Error> {
    let (signature, f2s) = rsplit2_dot(token)?;
    let signature = bs64::to_bytes(signature.to_owned())?;

    let (claims, header) = rsplit2_dot(f2s)?;

    let header = bs64::to_string(header.to_owned())?;
    let claims = bs64::to_string(claims.to_owned())?;

    let header: Header = json::from_str(&header)?;
    let claims: Value = json::from_str(&claims)?;

    let alg = &header.alg;
    match &config.signature_validation {
        SignatureValidation::Key(key) => {
            if alg.is_some() && *alg.as_ref().unwrap() != key.alg.to_string() {
                return Err(Error(ErrorKind::AlgorithmMismatch));
            }
            verify_signature(f2s, &signature, key)?;
        }
        SignatureValidation::KeyResolver(resolver) => {
            let key = (resolver)(&header, &claims);
            if alg.is_some() && *alg.as_ref().unwrap() != key.alg.to_string() {
                return Err(Error(ErrorKind::AlgorithmMismatch));
            }
            verify_signature(f2s, &signature, &key)?;
        }
        SignatureValidation::None => {}
    }

    let nbf = claims["nbf"].as_u64();
    let iat = claims["iat"].as_u64();
    let exp = claims["exp"].as_u64();
    if config.nbf_validation && nbf.is_some() {
        verify_nbf(nbf.unwrap())?;
    }
    if config.iat_validation && iat.is_some() {
        verify_iat(iat.unwrap())?;
    }
    if config.exp_validation && exp.is_some() {
        verify_exp(exp.unwrap())?;
    }

    let claims = json::from_value(claims)?;

    Ok(Token { header, claims, signature })
}

pub fn parse_default<T: Serialize + DeserializeOwned>(token: &str) -> Result<Token<T>, Error> {
    parse(token, &Config::default())
}

pub fn parse_verify_none<T: Serialize + DeserializeOwned>(token: &str) -> Result<Token<T>, Error> {
    parse(token, &VERIFY_NONE)
}
