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

pub enum SignatureValidation {
    Key(Key),
    KeyResolver(fn(header: &Header, payload: &Value) -> Key),
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

static VALIDATE_NONE: Config = Config {
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

fn validate_alg(alg: &Option<String>, compared: &Algorithm) -> Result<(), ErrorKind> {
    if alg.is_some() && alg.as_ref().unwrap().as_str() != compared.to_string() {
        return Err(ErrorKind::AlgMismatch);
    }
    Ok(())
}

fn validate_iat(iat: &Option<u64>) -> Result<(), ErrorKind> {
    if iat.is_some() && time::now_secs() < iat.unwrap() {
        return Err(ErrorKind::InvalidIat);
    }
    Ok(())
}

fn validate_nbf(nbf: &Option<u64>) -> Result<(), ErrorKind> {
    if nbf.is_some() && time::now_secs() < nbf.unwrap() {
        return Err(ErrorKind::BeforeNbf);
    }
    Ok(())
}

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

pub fn parse_default<T: Serialize + DeserializeOwned>(token: &str) -> Result<Token<T>, Error> {
    parse(token, &Config::default())
}

pub fn parse_validate_none<T: Serialize + DeserializeOwned>(token: &str) -> Result<Token<T>, Error> {
    parse(token, &VALIDATE_NONE)
}
