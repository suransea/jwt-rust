//! Signature

use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature;
use ring::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, RsaEncoding, RsaKeyPair};

use crate::error::Error;

pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    PS256,
    PS384,
    PS512,
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        match self {
            Algorithm::HS256 => "HS256".to_owned(),
            Algorithm::HS384 => "HS384".to_owned(),
            Algorithm::HS512 => "HS512".to_owned(),
            Algorithm::RS256 => "RS256".to_owned(),
            Algorithm::RS384 => "RS384".to_owned(),
            Algorithm::RS512 => "RS512".to_owned(),
            Algorithm::ES256 => "ES256".to_owned(),
            Algorithm::ES384 => "ES384".to_owned(),
            Algorithm::PS256 => "PS256".to_owned(),
            Algorithm::PS384 => "PS384".to_owned(),
            Algorithm::PS512 => "PS512".to_owned(),
        }
    }
}

pub struct Key {
    val: Vec<u8>,
    pub alg: Algorithm,
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.val.as_ref()
    }
}

impl Key {
    pub fn new(key: impl AsRef<[u8]>, alg: Algorithm) -> Self {
        Key {
            val: key.as_ref().to_owned(),
            alg,
        }
    }

    pub fn sign(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        match self.alg {
            Algorithm::HS256 => sign_hmac(data, self, hmac::HMAC_SHA256),
            Algorithm::HS384 => sign_hmac(data, self, hmac::HMAC_SHA384),
            Algorithm::HS512 => sign_hmac(data, self, hmac::HMAC_SHA512),
            Algorithm::RS256 => sign_rsa(data, self, &signature::RSA_PKCS1_SHA256),
            Algorithm::RS384 => sign_rsa(data, self, &signature::RSA_PKCS1_SHA384),
            Algorithm::RS512 => sign_rsa(data, self, &signature::RSA_PKCS1_SHA512),
            Algorithm::ES256 => sign_ecdsa(data, self, &signature::ECDSA_P256_SHA256_FIXED_SIGNING),
            Algorithm::ES384 => sign_ecdsa(data, self, &signature::ECDSA_P384_SHA384_FIXED_SIGNING),
            Algorithm::PS256 => sign_rsa(data, self, &signature::RSA_PSS_SHA256),
            Algorithm::PS384 => sign_rsa(data, self, &signature::RSA_PSS_SHA384),
            Algorithm::PS512 => sign_rsa(data, self, &signature::RSA_PSS_SHA512),
        }
    }
}

fn sign_hmac(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, alg: hmac::Algorithm) -> Result<Vec<u8>, Error> {
    let key = hmac::Key::new(alg, key.as_ref());
    let tag = hmac::sign(&key, data.as_ref());
    Ok(tag.as_ref().to_owned())
}

fn sign_rsa(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, alg: &'static dyn RsaEncoding) -> Result<Vec<u8>, Error> {
    let key_pair = RsaKeyPair::from_pkcs8(key.as_ref())?;
    let rng = SystemRandom::new();
    let mut sig = vec![0; key_pair.public_modulus_len()];
    key_pair.sign(alg, &rng, data.as_ref(), &mut sig)?;
    Ok(sig)
}

fn sign_ecdsa(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, alg: &'static EcdsaSigningAlgorithm) -> Result<Vec<u8>, Error> {
    let key_pair = EcdsaKeyPair::from_pkcs8(alg, key.as_ref())?;
    let rng = SystemRandom::new();
    let sig = key_pair.sign(&rng, data.as_ref())?;
    Ok(sig.as_ref().to_owned())
}
