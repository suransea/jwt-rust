//! Parse

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json as json;
use serde_json::Value;

use crate::bs64;
use crate::error::{Error, ErrorKind};
use crate::jws::{Algorithm, Header, Token};
use crate::jws::sign::Key;
use crate::time;

/// Signature validation type.
pub enum SignatureValidation {
    /// Validate a signature with the key
    Key(Key),
    /// Validate a signature with the key from the resolver
    KeyResolver(fn(header: &Header, payload: &Value) -> Key),
    /// Don't validate signatures
    None,
}


/// Configs for parsing.
pub struct Config {
    pub signature_validation: SignatureValidation,
    pub iat_validation: bool,
    pub nbf_validation: bool,
    pub exp_validation: bool,
    pub expected_iss: Option<String>,
    pub expected_sub: Option<String>,
    pub expected_aud: Option<String>,
    pub expected_jti: Option<String>,
}

impl Default for Config {
    #[inline]
    fn default() -> Self {
        Config {
            signature_validation: SignatureValidation::None,
            iat_validation: true,
            nbf_validation: true,
            exp_validation: true,
            expected_iss: None,
            expected_sub: None,
            expected_aud: None,
            expected_jti: None,
        }
    }
}

static VALIDATE_NONE: Config = Config {
    signature_validation: SignatureValidation::None,
    iat_validation: false,
    nbf_validation: false,
    exp_validation: false,
    expected_iss: None,
    expected_sub: None,
    expected_aud: None,
    expected_jti: None,
};

/// Reverse split the string to 2 sections with '.'
#[inline]
fn rsplit2_dot(s: &str) -> Result<(&str, &str), Error> {
    let mut it = s.rsplitn(2, ".");
    match (it.next(), it.next()) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(Error::from(ErrorKind::Malformed)),
    }
}

#[inline]
fn validate_alg(alg: &Option<String>, expected: &Algorithm) -> Result<(), ErrorKind> {
    if alg.is_none() || alg.as_ref().unwrap().as_str() != expected.to_string() {
        return Err(ErrorKind::InvalidAlg);
    }
    Ok(())
}

#[inline]
fn validate_iat(iat: &Option<u64>) -> Result<(), ErrorKind> {
    if iat.is_some() && time::now_secs() < iat.unwrap() {
        return Err(ErrorKind::InvalidIat);
    }
    Ok(())
}

#[inline]
fn validate_nbf(nbf: &Option<u64>) -> Result<(), ErrorKind> {
    if nbf.is_some() && time::now_secs() < nbf.unwrap() {
        return Err(ErrorKind::NotBefore);
    }
    Ok(())
}

#[inline]
fn validate_exp(exp: &Option<u64>) -> Result<(), ErrorKind> {
    if exp.is_some() {
        let now = time::now_secs();
        let exp = exp.unwrap();
        if now >= exp {
            return Err(ErrorKind::TokenExpired(now - exp));
        }
    }
    Ok(())
}

#[inline]
fn validate_claim(val: &Option<&str>, expected: &Option<String>, or: ErrorKind) -> Result<(), ErrorKind> {
    if expected.is_some() {
        if val.is_none() || val.unwrap() != expected.as_ref().unwrap() {
            return Err(or);
        }
    }
    Ok(())
}

/// Parse a token string, with the specific config.
pub fn parse<T: Serialize + DeserializeOwned>(token: &str, config: &Config) -> Result<Token<T>, Error> {
    let (signature, f2s) = rsplit2_dot(token)?;
    let signature = bs64::to_bytes(signature)?;

    let (payload, header) = rsplit2_dot(f2s)?;

    let header = bs64::to_string(header)?;
    let payload = bs64::to_string(payload)?;

    let header: Header = json::from_str(&header)?;
    let payload: Value = json::from_str(&payload)?;

    match &config.signature_validation {
        SignatureValidation::Key(key) => {
            validate_alg(&header.alg, &key.alg)?;
            key.verify(f2s, &signature)?;
        }
        SignatureValidation::KeyResolver(resolver) => {
            let key = (resolver)(&header, &payload);
            validate_alg(&header.alg, &key.alg)?;
            key.verify(f2s, &signature)?;
        }
        SignatureValidation::None => {}
    }

    validate_claim(&payload["iss"].as_str(), &config.expected_iss, ErrorKind::InvalidIss)?;
    validate_claim(&payload["aud"].as_str(), &config.expected_aud, ErrorKind::InvalidAud)?;
    validate_claim(&payload["sub"].as_str(), &config.expected_sub, ErrorKind::InvalidSub)?;
    validate_claim(&payload["jti"].as_str(), &config.expected_jti, ErrorKind::InvalidJti)?;

    if config.nbf_validation {
        let nbf = payload["nbf"].as_u64();
        validate_nbf(&nbf)?;
    }
    if config.iat_validation {
        let iat = payload["iat"].as_u64();
        validate_iat(&iat)?;
    }
    if config.exp_validation {
        let exp = payload["exp"].as_u64();
        validate_exp(&exp)?;
    }

    let payload = json::from_value(payload)?;

    Ok(Token { header, payload, signature })
}

/// Parse a token string with default config.
///
/// Validate `iat`, `nbf` and `exp`, if there are.
#[inline]
pub fn parse_default<T: Serialize + DeserializeOwned>(token: &str) -> Result<Token<T>, Error> {
    parse(token, &Config::default())
}

/// Parse a token without any validation.
#[inline]
pub fn parse_validate_none<T: Serialize + DeserializeOwned>(token: &str) -> Result<Token<T>, Error> {
    parse(token, &VALIDATE_NONE)
}
